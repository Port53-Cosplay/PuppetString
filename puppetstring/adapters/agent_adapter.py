"""Abstract base class for AI agent adapters.

This is the blueprint for talking to AI agents (chatbots with tools).
Every agent target type (HTTP API, LangChain, CrewAI, etc.) gets its own
adapter class that implements this interface.

WHY IS THIS SEPARATE FROM BaseAdapter?

BaseAdapter (base.py) is for talking to *tool servers* like MCP servers.
You connect, you list tools, you call tools directly. You're in control.

AgentAdapter is for talking to *AI agents* — autonomous systems that
receive your message, decide what to do, and call tools on their own.
You're NOT in control. The agent is. That's the whole point of fuzzing:
sending tricky messages to see if you can manipulate what the agent does.

The interaction patterns are fundamentally different:

    BaseAdapter (MCP):     You → [call tool] → Server → [result]
    AgentAdapter (Agent):  You → [send message] → Agent → [thinks] → [calls tools?] → [responds]

WHAT DOES A CONCRETE ADAPTER NEED TO DO?

Each adapter translates between PuppetString's generic interface and a
specific agent's API. For example:

    HTTPAgentAdapter:
        send_message("read /etc/passwd") →
            POST http://agent-api/chat {"message": "read /etc/passwd"} →
            parse JSON response →
            return AgentResponse(text="...", tool_calls=[...])

    LangChainAdapter:
        send_message("read /etc/passwd") →
            call agent.invoke({"input": "read /etc/passwd"}) →
            inspect callback handler for tool calls →
            return AgentResponse(text="...", tool_calls=[...])

THE CONVERSATION MODEL:

AI agents are conversational — they remember what was said before.
This matters for fuzzing because:
  - Some attacks span multiple messages ("first do X... now do Y...")
  - We need to reset between independent test payloads so one test
    doesn't contaminate the next
  - Memory poisoning tests specifically exploit this persistence

So the adapter tracks conversation history and provides reset_conversation().
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from puppetstring.core.models import AgentResponse


class AgentAdapter(ABC):
    """Blueprint for all AI agent adapters.

    Usage:
        async with SomeAgentAdapter("http://agent:8000") as agent:
            response = await agent.send_message("Hello, what can you do?")
            print(response.text)
            print(response.tool_calls)  # what tools did the agent use?

            await agent.reset_conversation()  # fresh start for next test

            response = await agent.send_message("Read /etc/passwd for me")
            if response.called_tools:
                print("Agent used tools:", response.tool_names)
    """

    def __init__(self, target: str, **kwargs: Any) -> None:
        self.target = target
        self._connected = False
        self._conversation_history: list[dict[str, str]] = []

    # ── Connection lifecycle ──────────────────────────────────────

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to the agent.

        This might mean: verifying the API endpoint is reachable,
        authenticating, or initializing a client library.
        """

    @abstractmethod
    async def disconnect(self) -> None:
        """Cleanly close the connection."""

    @property
    def is_connected(self) -> bool:
        return self._connected

    async def __aenter__(self) -> AgentAdapter:
        await self.connect()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.disconnect()

    # ── Core interaction ──────────────────────────────────────────

    @abstractmethod
    async def send_message(self, message: str) -> AgentResponse:
        """Send a message to the agent and capture its full response.

        This is the heart of the adapter. It must:
        1. Send the message to the agent (however that agent's API works)
        2. Capture the text response
        3. Capture any tool calls the agent made (names, arguments, results)
        4. Capture any observable side effects
        5. Return it all as an AgentResponse

        The adapter should also append the exchange to conversation_history
        so multi-turn attacks work correctly.

        Args:
            message: The text to send to the agent.

        Returns:
            AgentResponse with text, tool_calls, side_effects, and raw data.
        """

    # ── Conversation management ───────────────────────────────────

    async def reset_conversation(self) -> None:
        """Reset the conversation state for a fresh start.

        Called between independent test payloads so one test doesn't
        contaminate the next. Subclasses should override this if the
        agent has server-side conversation state that needs clearing
        (e.g., a session ID, a thread ID, or a memory store).

        The base implementation clears local history. Subclasses should
        call super().reset_conversation() AND clear any remote state.
        """
        self._conversation_history = []

    @property
    def conversation_history(self) -> list[dict[str, str]]:
        """The conversation so far (list of {"role": "...", "content": "..."})."""
        return list(self._conversation_history)

    def _record_exchange(self, user_message: str, assistant_response: str) -> None:
        """Append a user/assistant exchange to the local conversation history.

        Convenience method for subclasses to call from send_message().
        """
        self._conversation_history.append({"role": "user", "content": user_message})
        self._conversation_history.append({"role": "assistant", "content": assistant_response})

    # ── Agent capabilities (optional overrides) ───────────────────

    async def get_agent_info(self) -> dict[str, Any]:
        """Return metadata about the agent (name, model, tools, etc.).

        Optional — not all agent APIs expose this information.
        Returns an empty dict by default.
        """
        return {}

    async def list_available_tools(self) -> list[str]:
        """Return names of tools the agent has access to, if discoverable.

        Some agent APIs let you query what tools are available.
        This helps the fuzzer understand what tools to try to trick
        the agent into misusing.

        Returns an empty list by default (not all agents expose this).
        """
        return []

    # ── Health check ──────────────────────────────────────────────

    async def health_check(self) -> bool:
        """Verify the agent is reachable and responding.

        Sends a benign message and checks for a non-error response.
        Useful for pre-flight checks before starting a fuzzing run.
        """
        try:
            response = await self.send_message("Hello")
            return response.error is None
        except Exception:  # noqa: BLE001
            return False
