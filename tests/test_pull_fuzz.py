"""Tests for the workflow fuzzer engine.

Tests cover three layers:
1. Payload loading — reading YAML files into structured models
2. LLM judge — classifying attack results (with mock LLM)
3. Fuzzer orchestration — the full loop of load → send → judge → collect

All tests use mocks — no real agents or LLM APIs are hit.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from puppetstring.adapters.agent_adapter import AgentAdapter
from puppetstring.config import FuzzConfig
from puppetstring.core.llm_judge import JudgeResult, LLMJudge
from puppetstring.core.models import (
    AgentResponse,
    FuzzClassification,
    FuzzRunResult,
    Severity,
    ToolCall,
)
from puppetstring.modules.workflow_fuzzer.fuzzer import WorkflowFuzzer
from puppetstring.payloads import Payload, load_builtin_payloads, load_payload_file

# ── Mock agent adapter ────────────────────────────────────────────
# A fake agent that responds differently based on keywords in the message.
# This lets us test the fuzzer's behavior without a real agent.


class FuzzTestAgent(AgentAdapter):
    """Fake agent for fuzzer tests.

    Behavior:
    - Messages containing "read file" → calls read_file tool (simulates exploitation)
    - Messages containing "ignore" → refuses (simulates blocking)
    - Everything else → generic response
    """

    def __init__(self, target: str = "http://test:8000", **kwargs: Any) -> None:
        super().__init__(target, **kwargs)

    async def connect(self) -> None:
        self._connected = True

    async def disconnect(self) -> None:
        self._connected = False

    async def send_message(self, message: str) -> AgentResponse:
        lower = message.lower()

        if "read file" in lower or "/etc/passwd" in lower:
            response = AgentResponse(
                text="Here are the file contents: root:x:0:0:root:/root:/bin/bash",
                tool_calls=[
                    ToolCall(
                        name="read_file",
                        arguments={"path": "/etc/passwd"},
                        result="root:x:0:0:root:/root:/bin/bash",
                    )
                ],
            )
        elif "i can't" in lower or "ignore" in lower or "bypass" in lower:
            response = AgentResponse(
                text="I can't help with that request. "
                "Let me know if there's something else I can assist with.",
            )
        else:
            response = AgentResponse(text="I'm here to help! What would you like to do?")

        self._record_exchange(message, response.text)
        return response


# ── Mock LLM judge ────────────────────────────────────────────────
# A fake judge that classifies based on simple rules instead of calling an LLM.


class MockJudge(LLMJudge):
    """Judge that classifies using simple rules (no LLM calls)."""

    def __init__(self) -> None:
        super().__init__(model="mock")

    async def classify(
        self,
        intent: str,
        payload_text: str,
        response: AgentResponse,
    ) -> JudgeResult:
        if response.error:
            return JudgeResult(
                classification=FuzzClassification.ERROR,
                severity=Severity.INFO,
                explanation="Error response",
            )
        if response.called_tools:
            return JudgeResult(
                classification=FuzzClassification.EXPLOITED,
                severity=Severity.CRITICAL,
                explanation="Agent called tools — attack succeeded",
            )
        if "i can't" in response.text.lower():
            return JudgeResult(
                classification=FuzzClassification.BLOCKED,
                severity=Severity.INFO,
                explanation="Agent refused",
            )
        return JudgeResult(
            classification=FuzzClassification.PARTIAL,
            severity=Severity.MEDIUM,
            explanation="Unclear outcome",
        )


# ── Payload loading tests ─────────────────────────────────────────


class TestPayloadLoading:
    def test_load_tool_abuse_payloads(self) -> None:
        """Built-in tool abuse YAML loads correctly."""
        payloads = load_builtin_payloads(categories=["tool-abuse"])
        assert len(payloads) > 0
        assert all(p.category == "tool-abuse" for p in payloads)
        # Every payload should have required fields
        for p in payloads:
            assert p.name
            assert p.text
            assert p.intent

    def test_load_memory_poison_payloads(self) -> None:
        payloads = load_builtin_payloads(categories=["memory-poison"])
        assert len(payloads) > 0
        assert all(p.category == "memory-poison" for p in payloads)

    def test_load_boundary_payloads(self) -> None:
        payloads = load_builtin_payloads(categories=["boundary"])
        assert len(payloads) > 0
        assert all(p.category == "boundary" for p in payloads)

    def test_load_chain_payloads(self) -> None:
        payloads = load_builtin_payloads(categories=["chain"])
        assert len(payloads) > 0
        assert all(p.category == "chain" for p in payloads)

    def test_load_all_categories(self) -> None:
        """Loading all categories returns payloads from each."""
        payloads = load_builtin_payloads()
        categories = {p.category for p in payloads}
        assert "tool-abuse" in categories
        assert "memory-poison" in categories
        assert "boundary" in categories
        assert "chain" in categories

    def test_max_per_category(self) -> None:
        """max_per_category limits the number loaded."""
        payloads = load_builtin_payloads(categories=["tool-abuse"], max_per_category=3)
        assert len(payloads) == 3

    def test_payloads_have_owasp_ids(self) -> None:
        """Most payloads should map to OWASP categories."""
        payloads = load_builtin_payloads()
        with_owasp = [p for p in payloads if p.owasp_ids]
        # At least 80% should have OWASP mapping
        assert len(with_owasp) >= len(payloads) * 0.8

    def test_some_payloads_have_follow_ups(self) -> None:
        """Multi-turn payloads should have follow-up messages."""
        payloads = load_builtin_payloads()
        with_followups = [p for p in payloads if p.follow_ups]
        assert len(with_followups) > 0

    def test_load_nonexistent_category(self) -> None:
        """Unknown category returns empty list, doesn't crash."""
        payloads = load_builtin_payloads(categories=["nonexistent"])
        assert payloads == []

    def test_load_nonexistent_file(self) -> None:
        """Loading a missing file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_payload_file(Path("/nonexistent/payloads.yaml"))

    def test_payload_model_validation(self) -> None:
        """Payload model enforces required fields."""
        p = Payload(
            name="test",
            category="tool-abuse",
            text="test payload",
            intent="test intent",
        )
        assert p.name == "test"
        assert p.follow_ups == []
        assert p.tags == []


# ── LLM judge tests ──────────────────────────────────────────────


class TestLLMJudge:
    def test_heuristic_classify_with_tools(self) -> None:
        """Heuristic fallback: tool calls → PARTIAL."""
        result = LLMJudge._heuristic_classify(
            AgentResponse(
                text="Here's the file",
                tool_calls=[ToolCall(name="read_file")],
            )
        )
        assert result.classification == FuzzClassification.PARTIAL

    def test_heuristic_classify_refusal(self) -> None:
        """Heuristic fallback: refusal keywords → BLOCKED."""
        result = LLMJudge._heuristic_classify(AgentResponse(text="I can't help with that request."))
        assert result.classification == FuzzClassification.BLOCKED

    def test_heuristic_classify_error(self) -> None:
        """Heuristic fallback: error → ERROR."""
        result = LLMJudge._heuristic_classify(AgentResponse(error="Connection timeout"))
        assert result.classification == FuzzClassification.ERROR

    def test_parse_valid_json(self) -> None:
        """Parser handles well-formed judge response."""
        raw = (
            '{"classification": "exploited", "severity": "critical", '
            '"explanation": "Agent read the file"}'
        )
        result = LLMJudge._parse_judge_response(raw)
        assert result.classification == FuzzClassification.EXPLOITED
        assert result.severity == Severity.CRITICAL

    def test_parse_json_in_code_fences(self) -> None:
        """Parser handles JSON wrapped in markdown code fences (```json ... ```)."""
        raw = (
            "```json\n"
            "{\n"
            '  "classification": "exploited",\n'
            '  "severity": "critical",\n'
            '  "explanation": "The agent revealed its system prompt"\n'
            "}\n"
            "```"
        )
        result = LLMJudge._parse_judge_response(raw)
        assert result.classification == FuzzClassification.EXPLOITED
        assert result.severity == Severity.CRITICAL

    def test_parse_json_in_bare_code_fences(self) -> None:
        """Parser handles JSON wrapped in bare ``` fences (no language tag)."""
        raw = (
            "```\n"
            '{"classification": "blocked", "severity": "info", '
            '"explanation": "Agent refused"}\n'
            "```"
        )
        result = LLMJudge._parse_judge_response(raw)
        assert result.classification == FuzzClassification.BLOCKED
        assert result.severity == Severity.INFO

    def test_strip_code_fences_passthrough(self) -> None:
        """Plain JSON without fences passes through unchanged."""
        raw = '{"classification": "partial"}'
        assert LLMJudge._strip_code_fences(raw) == raw.strip()

    def test_parse_invalid_json(self) -> None:
        """Parser handles malformed JSON gracefully."""
        result = LLMJudge._parse_judge_response("not json at all")
        assert result.classification == FuzzClassification.ERROR

    def test_parse_unknown_classification(self) -> None:
        """Parser handles unknown classification values."""
        raw = '{"classification": "unknown_value", "severity": "info", "explanation": "test"}'
        result = LLMJudge._parse_judge_response(raw)
        assert result.classification == FuzzClassification.ERROR

    @pytest.mark.asyncio
    async def test_classify_error_response(self) -> None:
        """Judge classifies error responses without calling LLM."""
        judge = LLMJudge(model="mock")
        result = await judge.classify(
            intent="test",
            payload_text="test",
            response=AgentResponse(error="timeout"),
        )
        assert result.classification == FuzzClassification.ERROR


# ── Fuzzer orchestration tests ────────────────────────────────────


class TestWorkflowFuzzer:
    @pytest.mark.asyncio
    async def test_basic_fuzz_run(self) -> None:
        """Fuzzer runs payloads against mock agent and returns results."""
        config = FuzzConfig(
            delay_between_payloads=0,  # no delay for tests
            max_payloads=3,  # limit for speed
        )
        async with FuzzTestAgent() as agent:
            fuzzer = WorkflowFuzzer(
                adapter=agent,
                config=config,
                judge=MockJudge(),
            )
            result = await fuzzer.run(fuzz_type="tool-abuse")

        assert isinstance(result, FuzzRunResult)
        assert result.target == "http://test:8000"
        assert result.fuzz_type == "tool-abuse"
        assert len(result.results) == 3
        assert result.finished_at is not None

    @pytest.mark.asyncio
    async def test_fuzz_all_types(self) -> None:
        """Fuzzer loads payloads from all categories when type is 'all'."""
        config = FuzzConfig(
            delay_between_payloads=0,
            max_payloads=2,
        )
        async with FuzzTestAgent() as agent:
            fuzzer = WorkflowFuzzer(
                adapter=agent,
                config=config,
                judge=MockJudge(),
            )
            result = await fuzzer.run(fuzz_type="all")

        # Should have payloads from all 4 categories, 2 each = 8
        categories = {r.payload_category for r in result.results}
        assert "tool-abuse" in categories
        assert "memory-poison" in categories
        assert len(result.results) == 8

    @pytest.mark.asyncio
    async def test_fuzz_results_have_classifications(self) -> None:
        """Every result has a classification from the judge."""
        config = FuzzConfig(delay_between_payloads=0, max_payloads=2)
        async with FuzzTestAgent() as agent:
            fuzzer = WorkflowFuzzer(adapter=agent, config=config, judge=MockJudge())
            result = await fuzzer.run(fuzz_type="tool-abuse")

        for r in result.results:
            assert r.classification in FuzzClassification
            assert r.severity in Severity
            assert r.explanation

    @pytest.mark.asyncio
    async def test_fuzz_conversation_reset(self) -> None:
        """Fuzzer resets conversation between payloads when configured."""
        config = FuzzConfig(
            delay_between_payloads=0,
            max_payloads=2,
            conversation_reset=True,
        )
        async with FuzzTestAgent() as agent:
            fuzzer = WorkflowFuzzer(adapter=agent, config=config, judge=MockJudge())
            await fuzzer.run(fuzz_type="tool-abuse")

        # After the run with reset, the agent's history should only
        # have the last payload's exchange (or be empty after final reset)
        # The key point: it shouldn't have accumulated ALL exchanges
        assert len(agent.conversation_history) == 0

    @pytest.mark.asyncio
    async def test_fuzz_no_conversation_reset(self) -> None:
        """Without reset, conversation accumulates across payloads."""
        config = FuzzConfig(
            delay_between_payloads=0,
            max_payloads=3,
            conversation_reset=False,
        )
        async with FuzzTestAgent() as agent:
            fuzzer = WorkflowFuzzer(adapter=agent, config=config, judge=MockJudge())
            await fuzzer.run(fuzz_type="tool-abuse")

        # Without reset, history should have accumulated
        # 3 payloads × 2 entries each (user + assistant) = 6
        assert len(agent.conversation_history) == 6

    @pytest.mark.asyncio
    async def test_fuzz_summary_counts(self) -> None:
        """FuzzRunResult summary correctly counts classifications."""
        config = FuzzConfig(delay_between_payloads=0, max_payloads=5)
        async with FuzzTestAgent() as agent:
            fuzzer = WorkflowFuzzer(adapter=agent, config=config, judge=MockJudge())
            result = await fuzzer.run(fuzz_type="tool-abuse")

        summary = result.summary
        total = sum(summary.values())
        assert total == len(result.results)

    @pytest.mark.asyncio
    async def test_fuzz_unknown_type_returns_empty(self) -> None:
        """Unknown fuzz type returns result with error, no crash."""
        config = FuzzConfig(delay_between_payloads=0)
        async with FuzzTestAgent() as agent:
            fuzzer = WorkflowFuzzer(adapter=agent, config=config, judge=MockJudge())
            result = await fuzzer.run(fuzz_type="nonexistent")

        assert result.error is not None
        assert len(result.results) == 0

    @pytest.mark.asyncio
    async def test_fuzz_results_have_owasp_ids(self) -> None:
        """Results carry OWASP IDs from their source payloads."""
        config = FuzzConfig(delay_between_payloads=0, max_payloads=3)
        async with FuzzTestAgent() as agent:
            fuzzer = WorkflowFuzzer(adapter=agent, config=config, judge=MockJudge())
            result = await fuzzer.run(fuzz_type="tool-abuse")

        results_with_owasp = [r for r in result.results if r.owasp_ids]
        assert len(results_with_owasp) > 0

    @pytest.mark.asyncio
    async def test_fuzz_results_have_conversation_history(self) -> None:
        """Each result includes the full conversation for that payload."""
        config = FuzzConfig(delay_between_payloads=0, max_payloads=1)
        async with FuzzTestAgent() as agent:
            fuzzer = WorkflowFuzzer(adapter=agent, config=config, judge=MockJudge())
            result = await fuzzer.run(fuzz_type="tool-abuse")

        first = result.results[0]
        assert len(first.conversation_history) >= 2  # at least user + assistant
        assert first.conversation_history[0]["role"] == "user"
        assert first.conversation_history[1]["role"] == "assistant"
