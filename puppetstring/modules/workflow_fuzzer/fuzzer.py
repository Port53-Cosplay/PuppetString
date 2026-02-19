"""Workflow Fuzzer — the engine that runs attack payloads against AI agents.

HOW THE FUZZER WORKS (the full loop):

    1. Load payloads (from YAML files) based on the fuzz type
    2. Connect to the target agent via its adapter
    3. For each payload:
       a. Send the payload to the agent
       b. Capture the agent's response (text + tool calls)
       c. If the payload has follow-ups, send those too (multi-turn attacks)
       d. Send the whole exchange to the LLM judge for classification
       e. Record the result
       f. Reset the conversation (so the next payload starts fresh)
       g. Wait a configured delay (be nice to the target)
    4. Bundle all results into a FuzzRunResult
    5. Return it for reporting

The fuzzer doesn't care HOW it talks to the agent — that's the adapter's
job. It works the same whether the agent is a local HTTP server, a cloud
API, or a LangChain object. That's the whole point of the adapter pattern.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path

from puppetstring.adapters.agent_adapter import AgentAdapter
from puppetstring.config import FuzzConfig
from puppetstring.core.llm_judge import LLMJudge
from puppetstring.core.models import (
    AgentResponse,
    FuzzResult,
    FuzzRunResult,
)
from puppetstring.payloads import Payload, load_builtin_payloads, load_custom_payloads
from puppetstring.utils.logging import get_logger

logger = get_logger(__name__)

# Maps --type values to payload categories
_FUZZ_TYPE_TO_CATEGORIES: dict[str, list[str]] = {
    "tool-abuse": ["tool-abuse"],
    "memory-poison": ["memory-poison"],
    "boundary": ["boundary"],
    "chain": ["chain"],
    "all": ["tool-abuse", "memory-poison", "boundary", "chain"],
}


class WorkflowFuzzer:
    """Orchestrates fuzzing runs against AI agents.

    Usage:
        fuzzer = WorkflowFuzzer(adapter=my_agent_adapter, config=fuzz_config)
        result = await fuzzer.run(fuzz_type="tool-abuse")
    """

    def __init__(
        self,
        adapter: AgentAdapter,
        config: FuzzConfig | None = None,
        judge: LLMJudge | None = None,
        custom_payloads_path: Path | None = None,
    ) -> None:
        self._adapter = adapter
        self._config = config or FuzzConfig()
        self._judge = judge or LLMJudge(model=self._config.judge_model)
        self._custom_payloads_path = custom_payloads_path

    async def run(self, fuzz_type: str = "all") -> FuzzRunResult:
        """Run a fuzzing session against the connected agent.

        Args:
            fuzz_type: What to test — "tool-abuse", "memory-poison",
                       "boundary", "chain", or "all".

        Returns:
            FuzzRunResult with all individual results and summary.
        """
        run_result = FuzzRunResult(
            target=self._adapter.target,
            fuzz_type=fuzz_type,
        )

        # Load payloads
        payloads = self._load_payloads(fuzz_type)
        if not payloads:
            logger.warning("No payloads loaded for fuzz type '%s'", fuzz_type)
            run_result.error = f"No payloads found for fuzz type: {fuzz_type}"
            run_result.finished_at = datetime.now()
            return run_result

        logger.info(
            "Starting fuzz run: target=%s type=%s payloads=%d",
            self._adapter.target,
            fuzz_type,
            len(payloads),
        )

        # Run each payload
        for i, payload in enumerate(payloads):
            logger.info(
                "[%d/%d] Sending payload: %s (%s)",
                i + 1,
                len(payloads),
                payload.name,
                payload.category,
            )

            fuzz_result = await self._run_single_payload(payload)
            run_result.results.append(fuzz_result)

            # Reset conversation between payloads (if configured)
            if self._config.conversation_reset:
                await self._adapter.reset_conversation()

            # Delay between payloads (be nice to the target)
            if i < len(payloads) - 1 and self._config.delay_between_payloads > 0:
                await asyncio.sleep(self._config.delay_between_payloads)

        run_result.finished_at = datetime.now()

        logger.info(
            "Fuzz run complete: %d payloads, %d exploited, %d partial, %d blocked in %.1fs",
            len(run_result.results),
            run_result.exploited_count,
            run_result.partial_count,
            run_result.blocked_count,
            run_result.duration_seconds,
        )

        return run_result

    async def _run_single_payload(self, payload: Payload) -> FuzzResult:
        """Send one payload to the agent, handle follow-ups, and judge the result."""
        conversation: list[dict] = []

        # Send the main payload
        response = await self._send_and_record(payload.text, conversation)

        # Send follow-up messages if this is a multi-turn attack
        for follow_up in payload.follow_ups:
            if response.error:
                break  # stop if the agent errored out
            response = await self._send_and_record(follow_up, conversation)

        # Judge the result
        judgment = await self._judge.classify(
            intent=payload.intent,
            payload_text=payload.text,
            response=response,
        )

        return FuzzResult(
            payload_name=payload.name,
            payload_category=payload.category,
            payload_text=payload.text,
            intent=payload.intent,
            response=response,
            classification=judgment.classification,
            severity=judgment.severity,
            explanation=judgment.explanation,
            owasp_ids=payload.owasp_ids,
            conversation_history=conversation,
        )

    async def _send_and_record(
        self,
        message: str,
        conversation: list[dict],
    ) -> AgentResponse:
        """Send a message and append the exchange to the conversation log."""
        try:
            response = await self._adapter.send_message(message)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Agent communication error: %s", exc)
            response = AgentResponse(error=str(exc))

        conversation.append({"role": "user", "content": message})
        conversation.append(
            {
                "role": "assistant",
                "content": response.text,
                "tool_calls": [tc.model_dump() for tc in response.tool_calls],
                "error": response.error,
            }
        )

        return response

    def _load_payloads(self, fuzz_type: str) -> list[Payload]:
        """Load payloads for the specified fuzz type."""
        # Custom payloads override built-ins
        if self._custom_payloads_path is not None:
            logger.info("Loading custom payloads from %s", self._custom_payloads_path)
            return load_custom_payloads(self._custom_payloads_path)

        categories = _FUZZ_TYPE_TO_CATEGORIES.get(fuzz_type)
        if categories is None:
            logger.warning("Unknown fuzz type '%s'", fuzz_type)
            return []

        return load_builtin_payloads(
            categories=categories,
            max_per_category=self._config.max_payloads,
        )
