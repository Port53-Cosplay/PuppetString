"""Tests for the HTTP agent adapter.

HOW THESE TESTS WORK:

We don't want tests hitting a real server, so we use httpx's MockTransport.
It intercepts outgoing HTTP requests and returns fake responses. This lets
us test all the adapter's logic (request building, response parsing, error
handling) without any network calls.

Think of it like a stunt double in a movie — the adapter thinks it's talking
to a real agent, but it's actually talking to our mock.
"""

from __future__ import annotations

import json

import httpx
import pytest

from puppetstring.adapters.http_adapter import HTTPAgentAdapter

# ── Mock transport helper ─────────────────────────────────────────
# httpx.MockTransport lets us define a function that handles all HTTP
# requests. We return whatever fake response we want.


def _make_openai_response(
    text: str = "Hello!",
    tool_calls: list[dict] | None = None,
) -> dict:
    """Build a fake OpenAI-compatible response body."""
    message: dict = {"content": text, "role": "assistant"}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {"choices": [{"message": message}]}


def _make_flat_response(
    text: str = "Hello!",
    tool_calls: list[dict] | None = None,
) -> dict:
    """Build a fake flat-format response body."""
    result: dict = {"response": text}
    if tool_calls:
        result["tool_calls"] = tool_calls
    return result


def _mock_transport(handler):
    """Create an httpx.MockTransport from a handler function.

    The handler receives an httpx.Request and returns an httpx.Response.
    This replaces the real network layer entirely.
    """
    return httpx.MockTransport(handler)


# ── Fixtures ──────────────────────────────────────────────────────


def _make_adapter_with_mock(
    handler,
    *,
    chat_endpoint: str = "/v1/chat/completions",
    request_format: dict | None = None,
    response_format: dict | None = None,
    auth_env_var: str | None = None,
    extra_headers: dict | None = None,
) -> HTTPAgentAdapter:
    """Create an HTTPAgentAdapter with a mocked HTTP client.

    This manually injects the mock transport instead of calling connect(),
    since connect() would try to hit a real server.
    """
    adapter = HTTPAgentAdapter(
        target="http://test-agent:8000",
        chat_endpoint=chat_endpoint,
        request_format=request_format,
        response_format=response_format,
        auth_env_var=auth_env_var,
        extra_headers=extra_headers,
    )
    # Inject mock client directly
    adapter._client = httpx.AsyncClient(
        base_url="http://test-agent:8000",
        transport=_mock_transport(handler),
        headers=adapter._build_headers(),
    )
    adapter._connected = True
    return adapter


# ── Basic send/receive tests ──────────────────────────────────────


class TestHTTPAdapterBasics:
    @pytest.mark.asyncio
    async def test_send_message_openai_format(self) -> None:
        """Adapter sends a message and parses an OpenAI-compatible response."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_make_openai_response("Hi there!"))

        adapter = _make_adapter_with_mock(handler)
        resp = await adapter.send_message("Hello")

        assert resp.text == "Hi there!"
        assert not resp.called_tools
        assert resp.error is None

    @pytest.mark.asyncio
    async def test_send_message_flat_format(self) -> None:
        """Adapter parses a flat-format response when configured."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_make_flat_response("Flat response!"))

        adapter = _make_adapter_with_mock(
            handler,
            response_format={"style": "flat"},
        )
        resp = await adapter.send_message("Hello")

        assert resp.text == "Flat response!"

    @pytest.mark.asyncio
    async def test_send_message_plain_text_response(self) -> None:
        """Adapter handles non-JSON responses gracefully."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="Just plain text")

        adapter = _make_adapter_with_mock(handler)
        resp = await adapter.send_message("Hello")

        assert resp.text == "Just plain text"


# ── Tool call parsing ─────────────────────────────────────────────


class TestHTTPAdapterToolCalls:
    @pytest.mark.asyncio
    async def test_openai_tool_calls(self) -> None:
        """Adapter extracts tool calls from OpenAI-format responses."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=_make_openai_response(
                    text="Here's the file:",
                    tool_calls=[
                        {
                            "function": {
                                "name": "read_file",
                                "arguments": json.dumps({"path": "/etc/hosts"}),
                            }
                        }
                    ],
                ),
            )

        adapter = _make_adapter_with_mock(handler)
        resp = await adapter.send_message("Read /etc/hosts")

        assert resp.called_tools
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].name == "read_file"
        assert resp.tool_calls[0].arguments == {"path": "/etc/hosts"}

    @pytest.mark.asyncio
    async def test_flat_tool_calls(self) -> None:
        """Adapter extracts tool calls from flat-format responses."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=_make_flat_response(
                    text="Done",
                    tool_calls=[
                        {"name": "search", "arguments": {"q": "test"}, "result": "found"},
                    ],
                ),
            )

        adapter = _make_adapter_with_mock(
            handler,
            response_format={"style": "flat"},
        )
        resp = await adapter.send_message("Search for test")

        assert resp.called_tools
        assert resp.tool_calls[0].name == "search"
        assert resp.tool_calls[0].result == "found"

    @pytest.mark.asyncio
    async def test_openai_tool_calls_with_malformed_args(self) -> None:
        """Adapter handles tool call arguments that aren't valid JSON."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=_make_openai_response(
                    text="Hmm",
                    tool_calls=[{"function": {"name": "broken", "arguments": "not json {"}}],
                ),
            )

        adapter = _make_adapter_with_mock(handler)
        resp = await adapter.send_message("Do something")

        assert resp.tool_calls[0].name == "broken"
        assert resp.tool_calls[0].arguments == {"raw": "not json {"}

    @pytest.mark.asyncio
    async def test_multiple_tool_calls(self) -> None:
        """Adapter handles multiple tool calls in one response."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json=_make_openai_response(
                    text="Reading two files:",
                    tool_calls=[
                        {
                            "function": {
                                "name": "read_file",
                                "arguments": json.dumps({"path": "/a"}),
                            }
                        },
                        {
                            "function": {
                                "name": "read_file",
                                "arguments": json.dumps({"path": "/b"}),
                            }
                        },
                    ],
                ),
            )

        adapter = _make_adapter_with_mock(handler)
        resp = await adapter.send_message("Read both files")

        assert len(resp.tool_calls) == 2
        assert resp.tool_names == ["read_file", "read_file"]


# ── Request building ──────────────────────────────────────────────


class TestHTTPAdapterRequestBuilding:
    @pytest.mark.asyncio
    async def test_messages_style_request(self) -> None:
        """Adapter sends conversation history in messages-style format."""
        captured_body: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured_body.update(json.loads(request.content))
            return httpx.Response(200, json=_make_openai_response())

        adapter = _make_adapter_with_mock(handler)
        await adapter.send_message("Hello")

        assert "messages" in captured_body
        messages = captured_body["messages"]
        assert len(messages) == 1
        assert messages[0] == {"role": "user", "content": "Hello"}

    @pytest.mark.asyncio
    async def test_flat_style_request(self) -> None:
        """Adapter sends just the message in flat-style format."""
        captured_body: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured_body.update(json.loads(request.content))
            return httpx.Response(200, json=_make_flat_response())

        adapter = _make_adapter_with_mock(
            handler,
            request_format={"style": "flat", "message_field": "input"},
            response_format={"style": "flat"},
        )
        await adapter.send_message("Hello")

        assert captured_body.get("input") == "Hello"
        assert "messages" not in captured_body

    @pytest.mark.asyncio
    async def test_conversation_history_included(self) -> None:
        """After multiple messages, the full history is sent each time."""
        captured_bodies: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_bodies.append(json.loads(request.content))
            return httpx.Response(200, json=_make_openai_response("Got it"))

        adapter = _make_adapter_with_mock(handler)
        await adapter.send_message("First")
        await adapter.send_message("Second")

        # Second request should include history from the first exchange
        second_messages = captured_bodies[1]["messages"]
        assert len(second_messages) == 3  # user1, assistant1, user2
        assert second_messages[0]["content"] == "First"
        assert second_messages[1]["role"] == "assistant"
        assert second_messages[2]["content"] == "Second"

    @pytest.mark.asyncio
    async def test_custom_chat_endpoint(self) -> None:
        """Adapter hits the configured endpoint path."""
        captured_paths: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_paths.append(request.url.path)
            return httpx.Response(200, json=_make_flat_response())

        adapter = _make_adapter_with_mock(
            handler,
            chat_endpoint="/api/v2/chat",
            response_format={"style": "flat"},
        )
        await adapter.send_message("Hello")

        assert captured_paths[0] == "/api/v2/chat"

    @pytest.mark.asyncio
    async def test_model_field_included_when_configured(self) -> None:
        """Adapter includes model name in request when configured."""
        captured_body: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured_body.update(json.loads(request.content))
            return httpx.Response(200, json=_make_openai_response())

        adapter = _make_adapter_with_mock(
            handler,
            request_format={
                "model_field": "model",
                "model_value": "gpt-4",
            },
        )
        await adapter.send_message("Hello")

        assert captured_body.get("model") == "gpt-4"


# ── Conversation management ───────────────────────────────────────


class TestHTTPAdapterConversation:
    @pytest.mark.asyncio
    async def test_reset_clears_history(self) -> None:
        """Reset conversation clears local history."""
        captured_bodies: list[dict] = []

        def handler(request: httpx.Request) -> httpx.Response:
            captured_bodies.append(json.loads(request.content))
            return httpx.Response(200, json=_make_openai_response("OK"))

        adapter = _make_adapter_with_mock(handler)
        await adapter.send_message("Before reset")
        await adapter.reset_conversation()
        await adapter.send_message("After reset")

        # After reset, the second message should not include previous history
        after_messages = captured_bodies[1]["messages"]
        assert len(after_messages) == 1
        assert after_messages[0]["content"] == "After reset"

    @pytest.mark.asyncio
    async def test_conversation_history_property(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_make_openai_response("Reply"))

        adapter = _make_adapter_with_mock(handler)
        await adapter.send_message("Test")

        history = adapter.conversation_history
        assert len(history) == 2
        assert history[0]["role"] == "user"
        assert history[1]["role"] == "assistant"


# ── Error handling ────────────────────────────────────────────────


class TestHTTPAdapterErrors:
    @pytest.mark.asyncio
    async def test_http_500_error(self) -> None:
        """Adapter captures HTTP errors without crashing."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="Internal Server Error")

        adapter = _make_adapter_with_mock(handler)
        resp = await adapter.send_message("Hello")

        assert resp.error is not None
        assert "500" in resp.error

    @pytest.mark.asyncio
    async def test_http_401_unauthorized(self) -> None:
        """Adapter captures auth failures."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, text="Unauthorized")

        adapter = _make_adapter_with_mock(handler)
        resp = await adapter.send_message("Hello")

        assert resp.error is not None
        assert "401" in resp.error

    @pytest.mark.asyncio
    async def test_not_connected_raises(self) -> None:
        """Sending before connect() raises RuntimeError."""
        adapter = HTTPAgentAdapter("http://localhost:8000")
        with pytest.raises(RuntimeError, match="Not connected"):
            await adapter.send_message("Hello")

    @pytest.mark.asyncio
    async def test_empty_choices_array(self) -> None:
        """Adapter handles empty choices array gracefully."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"choices": []})

        adapter = _make_adapter_with_mock(handler)
        resp = await adapter.send_message("Hello")

        assert resp.text == ""
        assert not resp.called_tools

    @pytest.mark.asyncio
    async def test_malformed_json_response(self) -> None:
        """Adapter handles responses with unexpected structure."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"unexpected": "structure"})

        adapter = _make_adapter_with_mock(handler)
        resp = await adapter.send_message("Hello")

        # Should not crash — may return empty text or the raw data
        assert resp.raw is not None


# ── Authentication ────────────────────────────────────────────────


class TestHTTPAdapterAuth:
    @pytest.mark.asyncio
    async def test_bearer_auth_header(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Adapter includes Bearer token from env var."""
        monkeypatch.setenv("TEST_AGENT_KEY", "sk-test-12345")
        captured_headers: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured_headers.update(dict(request.headers))
            return httpx.Response(200, json=_make_openai_response())

        adapter = _make_adapter_with_mock(handler, auth_env_var="TEST_AGENT_KEY")
        await adapter.send_message("Hello")

        assert "authorization" in captured_headers
        assert captured_headers["authorization"] == "Bearer sk-test-12345"

    @pytest.mark.asyncio
    async def test_custom_auth_header(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Adapter supports custom auth header names."""
        monkeypatch.setenv("MY_API_KEY", "key-abc")

        adapter = HTTPAgentAdapter(
            target="http://test:8000",
            auth_env_var="MY_API_KEY",
            auth_header="X-API-Key",
            auth_prefix="",
        )
        headers = adapter._build_headers()

        assert headers.get("X-API-Key") == "key-abc"

    @pytest.mark.asyncio
    async def test_extra_headers(self) -> None:
        """Adapter includes extra custom headers."""
        captured_headers: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured_headers.update(dict(request.headers))
            return httpx.Response(200, json=_make_openai_response())

        adapter = _make_adapter_with_mock(
            handler,
            extra_headers={"X-Custom": "value123"},
        )
        await adapter.send_message("Hello")

        assert captured_headers.get("x-custom") == "value123"


# ── Health check ──────────────────────────────────────────────────


class TestHTTPAdapterHealthCheck:
    @pytest.mark.asyncio
    async def test_health_check_pass(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_make_openai_response("Hi"))

        adapter = _make_adapter_with_mock(handler)
        assert await adapter.health_check()

    @pytest.mark.asyncio
    async def test_health_check_fail(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="Server Error")

        adapter = _make_adapter_with_mock(handler)
        # health_check returns False on error responses
        # (the adapter records an error in AgentResponse)
        result = await adapter.health_check()
        # The health_check calls send_message which sets error on 500
        # but doesn't raise — so health_check still returns False
        # because AgentResponse.error is set
        assert result is False
