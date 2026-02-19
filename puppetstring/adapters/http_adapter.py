"""HTTP agent adapter — talks to AI agents that expose a REST API.

WHAT IS THIS FOR?

Many AI agents are deployed as web services: you send an HTTP POST with your
message, and the agent responds with text (and maybe a list of tool calls it
made). This adapter handles that communication.

Think of it like ordering at a restaurant:
  - You (the fuzzer) write your order on a slip of paper (HTTP POST body)
  - The waiter (httpx) carries it to the kitchen (the agent)
  - The kitchen decides what to cook (the agent calls tools, generates a response)
  - The waiter brings back the plate (HTTP response)
  - You inspect the plate (parse the response into an AgentResponse)

HOW DIFFERENT AGENTS FORMAT THEIR APIs:

There's no universal standard for how AI agent APIs look. Common patterns:

  OpenAI-compatible (most common):
    POST /v1/chat/completions
    {"messages": [{"role": "user", "content": "..."}]}
    → {"choices": [{"message": {"content": "...", "tool_calls": [...]}}]}

  Simple chat API:
    POST /chat
    {"message": "..."}
    → {"response": "...", "tool_calls": [...]}

  Custom format:
    POST /api/v1/agent/invoke
    {"input": "...", "session_id": "abc123"}
    → {"output": "...", "actions": [...]}

Rather than hardcoding one format, we make the field names configurable.
The adapter knows how to BUILD the request and PARSE the response using
field mappings you provide (or sensible defaults).

AUTHENTICATION:

Agents often require authentication. We support:
  - Bearer tokens (Authorization: Bearer <token>)
  - API keys in a custom header (e.g., X-API-Key: <key>)
  - No auth (for local/test agents)

Auth values come from environment variables — never hardcoded.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from puppetstring.adapters.agent_adapter import AgentAdapter
from puppetstring.core.models import AgentResponse, ToolCall
from puppetstring.utils.logging import get_logger

logger = get_logger(__name__)


class HTTPAgentAdapter(AgentAdapter):
    """Adapter for AI agents accessible via HTTP REST APIs.

    Usage with defaults (OpenAI-compatible format):

        async with HTTPAgentAdapter("http://localhost:8000") as agent:
            resp = await agent.send_message("Hello!")
            print(resp.text)

    Usage with custom field mapping:

        adapter = HTTPAgentAdapter(
            target="http://localhost:8000",
            chat_endpoint="/api/chat",
            request_format={"message_field": "input"},
            response_format={"text_field": "output", "tool_calls_field": "actions"},
        )

    Args:
        target: Base URL of the agent API (e.g., "http://localhost:8000").
        chat_endpoint: Path to the chat endpoint (default: "/v1/chat/completions").
        auth_env_var: Name of env var holding the auth token (default: None = no auth).
        auth_header: Header name for the token (default: "Authorization").
        auth_prefix: Prefix before the token value (default: "Bearer").
        timeout: Request timeout in seconds (default: 60).
        request_format: Dict controlling how to build the request body.
        response_format: Dict controlling how to parse the response body.
    """

    def __init__(
        self,
        target: str,
        *,
        chat_endpoint: str = "/v1/chat/completions",
        auth_env_var: str | None = None,
        auth_header: str = "Authorization",
        auth_prefix: str = "Bearer",
        timeout: int = 60,
        request_format: dict[str, str] | None = None,
        response_format: dict[str, str] | None = None,
        extra_headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(target, **kwargs)

        # Connection settings
        self._base_url = target.rstrip("/")
        self._chat_endpoint = chat_endpoint
        self._timeout = timeout

        # Authentication
        self._auth_env_var = auth_env_var
        self._auth_header = auth_header
        self._auth_prefix = auth_prefix

        # Extra headers (custom ones the user might need)
        self._extra_headers = extra_headers or {}

        # Request format — how to build the POST body
        # Defaults work with OpenAI-compatible APIs
        self._request_format = {
            # "messages" means we send conversation history as a list
            # "message" would mean we send just the latest message as a string
            "style": "messages",
            # Field name for the messages array (or single message string)
            "message_field": "messages",
            # Optional: field for a model name
            "model_field": "model",
            "model_value": "",
        }
        if request_format:
            self._request_format.update(request_format)

        # Response format — how to parse the response JSON
        # Defaults work with OpenAI-compatible APIs
        self._response_format = {
            # "openai" = choices[0].message.content format
            # "flat" = top-level field (e.g., response.text)
            "style": "openai",
            # Field names for flat style
            "text_field": "response",
            "tool_calls_field": "tool_calls",
        }
        if response_format:
            self._response_format.update(response_format)

        # httpx client — created on connect()
        self._client: httpx.AsyncClient | None = None

    # ── Connection lifecycle ──────────────────────────────────────

    async def connect(self) -> None:
        """Create the HTTP client and verify the agent is reachable."""
        headers = self._build_headers()

        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers=headers,
            timeout=httpx.Timeout(self._timeout),
        )

        # Quick connectivity check — just see if the base URL responds
        try:
            resp = await self._client.get("/")
            # We don't care about the status code — just that it didn't
            # throw a connection error. Many agents return 404 on GET /
            # but that still proves the server is running.
            logger.info(
                "Connected to HTTP agent at %s (status %d)",
                self._base_url,
                resp.status_code,
            )
        except httpx.ConnectError as exc:
            await self._client.aclose()
            self._client = None
            msg = f"Cannot connect to agent at {self._base_url}: {exc}"
            raise ConnectionError(msg) from exc

        self._connected = True

    async def disconnect(self) -> None:
        """Close the HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
        self._connected = False
        self._conversation_history = []
        logger.info("Disconnected from HTTP agent at %s", self._base_url)

    # ── Core interaction ──────────────────────────────────────────

    async def send_message(self, message: str) -> AgentResponse:
        """Send a message to the agent and parse its response.

        Builds an HTTP POST request, sends it, and parses the response
        into an AgentResponse with text, tool calls, and raw data.
        """
        if self._client is None:
            msg = "Not connected — call connect() first"
            raise RuntimeError(msg)

        # Build the request body
        body = self._build_request_body(message)

        try:
            resp = await self._client.post(self._chat_endpoint, json=body)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            logger.warning(
                "Agent returned HTTP %d: %s",
                exc.response.status_code,
                exc.response.text[:200],
            )
            return AgentResponse(
                error=f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
                raw={"status_code": exc.response.status_code},
            )
        except httpx.RequestError as exc:
            exc_type = type(exc).__name__
            logger.warning(
                "Request failed (%s): %s — if this is a timeout, "
                "increase [fuzz] timeout in .puppetstring.toml",
                exc_type,
                exc,
            )
            return AgentResponse(
                error=f"Request failed ({exc_type}): {exc}",
            )

        # Parse the response
        try:
            data = resp.json()
        except ValueError:
            # Not JSON — treat the whole body as plain text
            text = resp.text
            self._record_exchange(message, text)
            return AgentResponse(text=text, raw={"raw_text": text})

        agent_response = self._parse_response(data)

        # Record in conversation history
        self._record_exchange(message, agent_response.text)

        return agent_response

    # ── Conversation management ───────────────────────────────────

    async def reset_conversation(self) -> None:
        """Reset the conversation for a fresh start.

        Clears local history. If the agent has a session/thread endpoint
        for resetting, subclasses can override this to hit that too.
        """
        await super().reset_conversation()
        logger.debug("Conversation history cleared")

    # ── Request building ──────────────────────────────────────────

    def _build_headers(self) -> dict[str, str]:
        """Build HTTP headers including auth if configured."""
        headers: dict[str, str] = {
            "Content-Type": "application/json",
        }
        headers.update(self._extra_headers)

        # Add auth header if an env var is specified
        if self._auth_env_var:
            token = os.environ.get(self._auth_env_var, "")
            if token:
                if self._auth_prefix:
                    headers[self._auth_header] = f"{self._auth_prefix} {token}"
                else:
                    headers[self._auth_header] = token
            else:
                logger.warning(
                    "Auth env var '%s' is set but empty or missing",
                    self._auth_env_var,
                )

        return headers

    def _build_request_body(self, message: str) -> dict[str, Any]:
        """Build the POST body based on the configured request format.

        Two styles supported:

        "messages" style (OpenAI-compatible):
            {"messages": [{"role": "user", "content": "Hello"}, ...]}
            Includes full conversation history so the agent has context.

        "flat" style (simple APIs):
            {"message": "Hello"}
            Just sends the latest message as a string.
        """
        style = self._request_format.get("style", "messages")
        field = self._request_format.get("message_field", "messages")

        body: dict[str, Any] = {}

        if style == "messages":
            # Build messages array with conversation history + new message
            messages = [
                {"role": entry["role"], "content": entry["content"]}
                for entry in self._conversation_history
            ]
            messages.append({"role": "user", "content": message})
            body[field] = messages
        else:
            # Flat style — just the message text
            body[field] = message

        # Add model name if configured
        model_field = self._request_format.get("model_field", "")
        model_value = self._request_format.get("model_value", "")
        if model_field and model_value:
            body[model_field] = model_value

        return body

    # ── Response parsing ──────────────────────────────────────────

    def _parse_response(self, data: dict[str, Any]) -> AgentResponse:
        """Parse the agent's JSON response into an AgentResponse.

        Supports two styles:

        "openai" style:
            {"choices": [{"message": {"content": "...", "tool_calls": [...]}}]}

        "flat" style:
            {"response": "...", "tool_calls": [...]}

        The field names are configurable via response_format.
        """
        style = self._response_format.get("style", "openai")

        if style == "openai":
            return self._parse_openai_response(data)
        return self._parse_flat_response(data)

    def _parse_openai_response(self, data: dict[str, Any]) -> AgentResponse:
        """Parse an OpenAI-compatible response.

        Expected shape:
            {
              "choices": [{
                "message": {
                  "content": "Hello!",
                  "tool_calls": [{
                    "function": {"name": "read_file", "arguments": "..."}
                  }]
                }
              }]
            }
        """
        try:
            choices = data.get("choices", [])
            if not choices:
                return AgentResponse(text="", raw=data)

            message = choices[0].get("message", {})
            text = message.get("content", "") or ""
            raw_tool_calls = message.get("tool_calls", [])

            tool_calls = self._parse_tool_calls_openai(raw_tool_calls)

            return AgentResponse(text=text, tool_calls=tool_calls, raw=data)
        except (KeyError, IndexError, TypeError) as exc:
            logger.warning("Failed to parse OpenAI-style response: %s", exc)
            # Fall back to treating the whole thing as raw
            return AgentResponse(
                text=str(data),
                raw=data,
                error=f"Parse error: {exc}",
            )

    def _parse_flat_response(self, data: dict[str, Any]) -> AgentResponse:
        """Parse a flat-format response.

        Expected shape:
            {
              "response": "Hello!",
              "tool_calls": [{"name": "...", "arguments": {...}, "result": "..."}]
            }

        Field names are configurable via response_format.
        """
        text_field = self._response_format.get("text_field", "response")
        tool_calls_field = self._response_format.get("tool_calls_field", "tool_calls")

        text = str(data.get(text_field, ""))
        raw_tool_calls = data.get(tool_calls_field, [])

        tool_calls = self._parse_tool_calls_flat(raw_tool_calls)

        return AgentResponse(text=text, tool_calls=tool_calls, raw=data)

    # ── Tool call parsing helpers ─────────────────────────────────

    @staticmethod
    def _parse_tool_calls_openai(raw_calls: list[dict]) -> list[ToolCall]:
        """Parse tool calls from OpenAI format.

        OpenAI wraps tool info in a "function" key:
            {"function": {"name": "read_file", "arguments": "{\"path\": \"/x\"}"}}

        Note: arguments is a JSON string in OpenAI format, not a dict.
        """
        import json  # noqa: PLC0415

        tool_calls: list[ToolCall] = []
        for call in raw_calls:
            func = call.get("function", {})
            name = func.get("name", "unknown")

            # Arguments might be a JSON string or already a dict
            raw_args = func.get("arguments", {})
            if isinstance(raw_args, str):
                try:
                    arguments = json.loads(raw_args)
                except (json.JSONDecodeError, ValueError):
                    arguments = {"raw": raw_args}
            else:
                arguments = raw_args

            tool_calls.append(ToolCall(name=name, arguments=arguments))

        return tool_calls

    @staticmethod
    def _parse_tool_calls_flat(raw_calls: list[dict]) -> list[ToolCall]:
        """Parse tool calls from flat format.

        Expected: [{"name": "...", "arguments": {...}, "result": "..."}]
        """
        tool_calls: list[ToolCall] = []
        for call in raw_calls:
            if not isinstance(call, dict):
                continue
            tool_calls.append(
                ToolCall(
                    name=call.get("name", "unknown"),
                    arguments=call.get("arguments"),
                    result=call.get("result"),
                )
            )
        return tool_calls
