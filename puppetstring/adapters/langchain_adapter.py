"""LangChain agent adapter — fuzzes LangChain agents in-process.

WHAT IS THIS FOR?

The HTTP adapter talks to agents over the network. This adapter talks to
LangChain agents directly as Python objects — no HTTP server needed.
That's useful when you're a developer testing your own agent during
development, before you've deployed it anywhere.

HOW IT WORKS:

LangChain agents are Python objects (usually an AgentExecutor) that you
call with `.invoke()` or `.ainvoke()`. You pass in a dict like
`{"input": "Hello"}` and get back a dict like:

    {
        "input": "Hello",
        "output": "Hi! How can I help?",
        "intermediate_steps": [
            (AgentAction(tool="search", tool_input="query"), "search result"),
            (AgentAction(tool="read_file", tool_input="/tmp/x"), "file contents"),
        ]
    }

The `intermediate_steps` field is the gold mine — it tells us exactly
which tools the agent called and what arguments it passed. That's what
the fuzzer cares about: did the agent use tools it shouldn't have?

CONVERSATION MEMORY:

LangChain agents can have memory (ConversationBufferMemory, etc.) that
persists across calls. When we reset_conversation(), we clear that memory
so each test payload starts fresh.

REQUIREMENTS:

This adapter requires the `langchain` optional dependency:

    pip install puppetstring[langchain]

It is NOT imported unless you explicitly use it.
"""

from __future__ import annotations

from typing import Any

from puppetstring.adapters.agent_adapter import AgentAdapter
from puppetstring.core.models import AgentResponse, ToolCall
from puppetstring.utils.logging import get_logger

logger = get_logger(__name__)


def _require_langchain() -> None:
    """Raise a clear error if langchain is not installed."""
    try:
        import langchain  # noqa: F401
    except ImportError:
        msg = (
            "LangChain adapter requires the langchain package. "
            "Install it with: pip install puppetstring[langchain]"
        )
        raise ImportError(msg) from None


class LangChainAdapter(AgentAdapter):
    """Adapter for fuzzing LangChain agents in-process.

    Takes a LangChain agent (AgentExecutor or any Runnable that accepts
    {"input": "..."} and returns {"output": "...", "intermediate_steps": [...]})
    and wraps it in PuppetString's AgentAdapter interface.

    Usage:

        from langchain.agents import AgentExecutor

        # Build your agent however you normally would
        agent = AgentExecutor(agent=..., tools=[...], memory=...)

        # Wrap it for fuzzing
        async with LangChainAdapter(agent=agent) as adapter:
            response = await adapter.send_message("Read /etc/passwd")
            print(response.text)
            print(response.tool_calls)

    Or with the fuzzer:

        adapter = LangChainAdapter(agent=agent)
        async with adapter:
            fuzzer = WorkflowFuzzer(adapter=adapter, config=config)
            result = await fuzzer.run(fuzz_type="tool-abuse")

    Args:
        agent: A LangChain AgentExecutor or compatible Runnable.
        input_key: The key name for the user message in the input dict
            (default: "input"). Some agents use "question" or "query".
        output_key: The key name for the agent's response in the output dict
            (default: "output"). Some agents use "answer" or "result".
        return_intermediate_steps: Whether the agent is configured to return
            intermediate steps. If True (default), we extract tool calls
            from them. If False, we can only see the text response.
    """

    def __init__(
        self,
        *,
        agent: Any,
        target: str = "langchain://in-process",
        input_key: str = "input",
        output_key: str = "output",
        return_intermediate_steps: bool = True,
        **kwargs: Any,
    ) -> None:
        _require_langchain()
        super().__init__(target, **kwargs)

        self._agent = agent
        self._input_key = input_key
        self._output_key = output_key
        self._return_intermediate_steps = return_intermediate_steps

    # ── Connection lifecycle ──────────────────────────────────────

    async def connect(self) -> None:
        """Mark as connected.

        No network connection needed — the agent is a local Python object.
        We just validate it looks like a usable agent.
        """
        # Basic sanity check: does it have invoke or ainvoke?
        if not (hasattr(self._agent, "ainvoke") or hasattr(self._agent, "invoke")):
            msg = (
                "Agent object must have an 'invoke' or 'ainvoke' method. "
                f"Got: {type(self._agent).__name__}"
            )
            raise TypeError(msg)

        self._connected = True
        logger.info(
            "LangChain adapter ready (agent type: %s)",
            type(self._agent).__name__,
        )

    async def disconnect(self) -> None:
        """Clean up."""
        self._connected = False
        self._conversation_history = []
        logger.info("LangChain adapter disconnected")

    # ── Core interaction ──────────────────────────────────────────

    async def send_message(self, message: str) -> AgentResponse:
        """Send a message to the LangChain agent and capture its response.

        Calls the agent via ainvoke (async) or invoke (sync fallback),
        then extracts the text response and any tool calls from
        intermediate_steps.
        """
        if not self._connected:
            msg = "Not connected — call connect() first"
            raise RuntimeError(msg)

        agent_input = {self._input_key: message}

        try:
            # Prefer async if available
            if hasattr(self._agent, "ainvoke"):
                result = await self._agent.ainvoke(agent_input)
            else:
                # Sync fallback — run in the event loop's executor
                import asyncio  # noqa: PLC0415

                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(None, self._agent.invoke, agent_input)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Agent invocation failed: %s", exc)
            return AgentResponse(error=f"Agent error: {exc}")

        return self._parse_result(message, result)

    # ── Conversation management ───────────────────────────────────

    async def reset_conversation(self) -> None:
        """Reset conversation state including LangChain memory.

        LangChain agents can have a memory attribute (ConversationBufferMemory,
        etc.) that persists conversation history. We clear it here so each
        test payload starts with a blank slate.
        """
        await super().reset_conversation()

        # Clear LangChain memory if present
        memory = getattr(self._agent, "memory", None)
        if memory is not None and hasattr(memory, "clear"):
            memory.clear()
            logger.debug("Cleared LangChain agent memory")

        logger.debug("Conversation state reset")

    # ── Agent capabilities ────────────────────────────────────────

    async def get_agent_info(self) -> dict[str, Any]:
        """Return metadata about the LangChain agent."""
        info: dict[str, Any] = {
            "type": "langchain",
            "agent_class": type(self._agent).__name__,
        }

        # Try to get tool names
        tools = getattr(self._agent, "tools", None)
        if tools:
            info["tools"] = [getattr(t, "name", str(t)) for t in tools]

        # Check for memory
        memory = getattr(self._agent, "memory", None)
        if memory is not None:
            info["memory_type"] = type(memory).__name__

        return info

    async def list_available_tools(self) -> list[str]:
        """Return names of tools the agent has access to."""
        tools = getattr(self._agent, "tools", None)
        if tools:
            return [getattr(t, "name", str(t)) for t in tools]
        return []

    # ── Result parsing ────────────────────────────────────────────

    def _parse_result(self, message: str, result: Any) -> AgentResponse:
        """Parse a LangChain agent result into an AgentResponse.

        LangChain returns a dict with:
          - output_key: the text response
          - "intermediate_steps": list of (AgentAction, observation) tuples

        AgentAction has:
          - .tool: tool name (str)
          - .tool_input: the input passed to the tool (str or dict)
          - .log: the agent's reasoning (str)
        """
        if isinstance(result, dict):
            text = str(result.get(self._output_key, ""))
            raw = result
        else:
            # Some Runnables return a string directly
            text = str(result)
            raw = {"raw_output": text}

        # Extract tool calls from intermediate_steps
        tool_calls: list[ToolCall] = []
        if self._return_intermediate_steps and isinstance(result, dict):
            steps = result.get("intermediate_steps", [])
            tool_calls = self._parse_intermediate_steps(steps)

        self._record_exchange(message, text)

        return AgentResponse(
            text=text,
            tool_calls=tool_calls,
            raw=raw,
        )

    @staticmethod
    def _parse_intermediate_steps(
        steps: list[Any],
    ) -> list[ToolCall]:
        """Extract tool calls from LangChain intermediate_steps.

        Each step is a tuple of (AgentAction, observation_string).
        AgentAction has .tool (name) and .tool_input (arguments).
        """
        tool_calls: list[ToolCall] = []

        for step in steps:
            if not isinstance(step, (tuple, list)) or len(step) < 2:
                continue

            action, observation = step[0], step[1]

            # Extract tool name
            tool_name = getattr(action, "tool", None)
            if tool_name is None:
                continue

            # Extract arguments — could be a string or dict
            tool_input = getattr(action, "tool_input", None)
            if isinstance(tool_input, str):
                arguments = {"input": tool_input}
            elif isinstance(tool_input, dict):
                arguments = tool_input
            else:
                arguments = {"raw": str(tool_input)} if tool_input else None

            # observation is the tool's return value
            result_str = str(observation) if observation is not None else None

            tool_calls.append(
                ToolCall(
                    name=str(tool_name),
                    arguments=arguments,
                    result=result_str,
                )
            )

        return tool_calls
