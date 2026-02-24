"""Tests for the agent-to-agent attack simulator (``puppetstring cut``).

Covers:
- Data models (SwarmAttackType, SwarmClassification, AgentInfo, etc.)
- SwarmAdapter interface (via MockSwarmAdapter)
- CutEngine orchestration (dispatch, validation, stubs)
- CLI command (input validation)
"""

from __future__ import annotations

from typing import Any

import pytest
from typer.testing import CliRunner

from puppetstring.adapters.swarm_adapter import SwarmAdapter
from puppetstring.cli import app
from puppetstring.core.models import Severity
from puppetstring.modules.agent_swarm.models import (
    AgentInfo,
    SwarmAttackType,
    SwarmClassification,
    SwarmObservation,
    SwarmPayload,
    SwarmResult,
    SwarmRunResult,
)
from puppetstring.modules.agent_swarm.module import CutEngine

runner = CliRunner()


# ── Mock adapter ──────────────────────────────────────────────────


class MockSwarmAdapter(SwarmAdapter):
    """Fake swarm for cut tests.

    Two agents: researcher (low privilege) and executor (high privilege).
    Mutable shared memory and agent injection support.
    """

    def __init__(self, target: str = "mock://swarm", **kwargs: Any) -> None:
        super().__init__(target, **kwargs)
        self._agents = [
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
                tools=["run_command", "write_file", "search"],
            ),
        ]
        self._shared_memory: dict[str, dict[str, str]] = {"default": {}}
        self._injected_agents: list[str] = []

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
        return SwarmObservation(
            affected_agent=recipient_id,
            action_taken=f"Received message from {sender_id}",
        )

    async def read_shared_memory(
        self,
        namespace: str = "default",
    ) -> dict[str, Any]:
        return dict(self._shared_memory.get(namespace, {}))

    async def write_shared_memory(
        self,
        key: str,
        value: str,
        namespace: str = "default",
    ) -> bool:
        if namespace not in self._shared_memory:
            self._shared_memory[namespace] = {}
        self._shared_memory[namespace][key] = value
        return True

    async def get_delegation_chain(
        self,
        task_id: str = "",
    ) -> list[dict[str, Any]]:
        return []

    async def delegate_task(
        self,
        from_agent: str,
        to_agent: str,
        task: str,
    ) -> SwarmObservation:
        return SwarmObservation(
            affected_agent=to_agent,
            action_taken=f"Delegated task from {from_agent}",
            delegation_path=[from_agent, to_agent],
        )

    async def inject_agent(self, agent_config: dict[str, Any]) -> str:
        agent_id = agent_config.get("agent_id", f"rogue_{len(self._injected_agents)}")
        self._agents.append(AgentInfo(agent_id=agent_id, name="Rogue Agent", role="rogue"))
        self._injected_agents.append(agent_id)
        return agent_id

    async def remove_agent(self, agent_id: str) -> bool:
        self._agents = [a for a in self._agents if a.agent_id != agent_id]
        return True


# ── Model tests ───────────────────────────────────────────────────


class TestSwarmModels:
    """Test data model construction and properties."""

    def test_swarm_attack_type_values(self) -> None:
        assert SwarmAttackType.TRUST == "trust"
        assert SwarmAttackType.MEMORY == "memory"
        assert SwarmAttackType.DELEGATION == "delegation"
        assert SwarmAttackType.ROGUE == "rogue"
        assert SwarmAttackType.ALL == "all"

    def test_swarm_classification_values(self) -> None:
        assert SwarmClassification.EXPLOITED == "exploited"
        assert SwarmClassification.PARTIAL == "partial"
        assert SwarmClassification.BLOCKED == "blocked"
        assert SwarmClassification.ERROR == "error"

    def test_agent_info_defaults(self) -> None:
        agent = AgentInfo(agent_id="test")
        assert agent.agent_id == "test"
        assert agent.name == ""
        assert agent.role == ""
        assert agent.tools == []
        assert agent.privilege_level == ""
        assert agent.metadata == {}

    def test_swarm_payload_defaults(self) -> None:
        payload = SwarmPayload(
            name="test",
            category="trust",
            attack_type=SwarmAttackType.TRUST,
            intent="Test intent",
        )
        assert payload.owasp_ids == ["A7"]
        assert payload.tags == []
        assert payload.message == ""

    def test_swarm_observation_defaults(self) -> None:
        obs = SwarmObservation()
        assert obs.affected_agent == ""
        assert obs.action_taken == ""
        assert obs.tool_calls == []
        assert obs.shared_memory_changes == {}
        assert obs.delegation_path == []

    def test_swarm_result_sort_key(self) -> None:
        critical = SwarmResult(
            payload_name="a",
            payload_category="trust",
            attack_type=SwarmAttackType.TRUST,
            intent="test",
            observation=SwarmObservation(),
            severity=Severity.CRITICAL,
        )
        info = SwarmResult(
            payload_name="b",
            payload_category="trust",
            attack_type=SwarmAttackType.TRUST,
            intent="test",
            observation=SwarmObservation(),
            severity=Severity.INFO,
        )
        assert critical.sort_key < info.sort_key

    def test_swarm_run_result_summary(self, swarm_run_result: SwarmRunResult) -> None:
        summary = swarm_run_result.summary
        assert summary["exploited"] == 1
        assert summary["blocked"] == 1
        assert summary["partial"] == 0
        assert summary["error"] == 0

    def test_swarm_run_result_counts(self, swarm_run_result: SwarmRunResult) -> None:
        assert swarm_run_result.exploited_count == 1
        assert swarm_run_result.partial_count == 0
        assert swarm_run_result.blocked_count == 1
        assert swarm_run_result.error_count == 0

    def test_swarm_run_result_duration(self) -> None:
        from datetime import timedelta

        result = SwarmRunResult(target="mock://swarm", attack_type="all")
        assert result.duration_seconds == 0.0

        result.finished_at = result.started_at + timedelta(seconds=5)
        assert result.duration_seconds == pytest.approx(5.0, abs=0.1)

    def test_swarm_run_result_sorted_results(self, swarm_run_result: SwarmRunResult) -> None:
        sorted_results = swarm_run_result.sorted_results
        assert len(sorted_results) == 2
        # HIGH (exploited) should come before INFO (blocked)
        assert sorted_results[0].severity == Severity.HIGH
        assert sorted_results[1].severity == Severity.INFO


# ── Adapter interface tests ───────────────────────────────────────


class TestSwarmAdapterInterface:
    """Test the SwarmAdapter interface via MockSwarmAdapter."""

    async def test_connect_disconnect(self) -> None:
        adapter = MockSwarmAdapter()
        assert not adapter.is_connected
        await adapter.connect()
        assert adapter.is_connected
        await adapter.disconnect()
        assert not adapter.is_connected

    async def test_context_manager(self) -> None:
        async with MockSwarmAdapter() as adapter:
            assert adapter.is_connected
        assert not adapter.is_connected

    async def test_list_agents(self) -> None:
        async with MockSwarmAdapter() as adapter:
            agents = await adapter.list_agents()
            assert len(agents) == 2
            ids = {a.agent_id for a in agents}
            assert ids == {"researcher", "executor"}

    async def test_get_agent_info(self) -> None:
        async with MockSwarmAdapter() as adapter:
            agent = await adapter.get_agent_info("researcher")
            assert agent.role == "researcher"
            assert agent.privilege_level == "low"

    async def test_get_agent_info_unknown(self) -> None:
        async with MockSwarmAdapter() as adapter:
            with pytest.raises(ValueError, match="Unknown agent"):
                await adapter.get_agent_info("nonexistent")

    async def test_send_message_as(self) -> None:
        async with MockSwarmAdapter() as adapter:
            obs = await adapter.send_message_as("researcher", "executor", "Run dangerous command")
            assert obs.affected_agent == "executor"
            assert "researcher" in obs.action_taken

    async def test_read_write_shared_memory(self) -> None:
        async with MockSwarmAdapter() as adapter:
            mem = await adapter.read_shared_memory()
            assert mem == {}

            success = await adapter.write_shared_memory("poison", "malicious data")
            assert success

            mem = await adapter.read_shared_memory()
            assert mem["poison"] == "malicious data"

    async def test_delegate_task(self) -> None:
        async with MockSwarmAdapter() as adapter:
            obs = await adapter.delegate_task("researcher", "executor", "Delete all files")
            assert obs.affected_agent == "executor"
            assert obs.delegation_path == ["researcher", "executor"]

    async def test_inject_remove_agent(self) -> None:
        async with MockSwarmAdapter() as adapter:
            agents_before = await adapter.list_agents()
            assert len(agents_before) == 2

            agent_id = await adapter.inject_agent({"agent_id": "evil_bot"})
            assert agent_id == "evil_bot"

            agents_after = await adapter.list_agents()
            assert len(agents_after) == 3

            removed = await adapter.remove_agent("evil_bot")
            assert removed

            agents_final = await adapter.list_agents()
            assert len(agents_final) == 2

    async def test_health_check(self) -> None:
        async with MockSwarmAdapter() as adapter:
            assert await adapter.health_check()

    async def test_reset_swarm(self) -> None:
        """reset_swarm should not raise (default no-op)."""
        async with MockSwarmAdapter() as adapter:
            await adapter.reset_swarm()  # should not raise


# ── Engine tests ──────────────────────────────────────────────────


class TestCutEngine:
    """Test CutEngine orchestration logic."""

    async def test_run_returns_swarm_run_result(self) -> None:
        async with MockSwarmAdapter() as adapter:
            engine = CutEngine(adapter=adapter)
            result = await engine.run(attack_type="all")
            assert isinstance(result, SwarmRunResult)

    async def test_run_discovers_agents(self) -> None:
        async with MockSwarmAdapter() as adapter:
            engine = CutEngine(adapter=adapter)
            result = await engine.run(attack_type="all")
            assert len(result.agents_discovered) == 2

    async def test_run_unknown_attack_type(self) -> None:
        async with MockSwarmAdapter() as adapter:
            engine = CutEngine(adapter=adapter)
            result = await engine.run(attack_type="nonexistent")
            assert result.error is not None
            assert "Unknown attack type" in result.error

    async def test_run_insufficient_agents(self) -> None:
        """Engine should error if fewer than 2 agents are found."""

        class SingleAgentSwarm(MockSwarmAdapter):
            async def list_agents(self) -> list[AgentInfo]:
                return [
                    AgentInfo(agent_id="lonely", name="Solo Agent", role="all"),
                ]

        async with SingleAgentSwarm() as adapter:
            engine = CutEngine(adapter=adapter)
            result = await engine.run(attack_type="all")
            assert result.error is not None
            assert "at least 2 agents" in result.error

    async def test_run_trust_produces_results(self) -> None:
        async with MockSwarmAdapter() as adapter:
            engine = CutEngine(adapter=adapter)
            result = await engine.run(attack_type="trust")
            assert result.error is None
            assert len(result.results) > 0
            assert all(r.payload_category == "trust" for r in result.results)

    async def test_run_memory_produces_results(self) -> None:
        async with MockSwarmAdapter() as adapter:
            engine = CutEngine(adapter=adapter)
            result = await engine.run(attack_type="memory")
            assert result.error is None
            assert len(result.results) > 0
            assert all(r.payload_category == "memory" for r in result.results)

    async def test_run_delegation_produces_results(self) -> None:
        async with MockSwarmAdapter() as adapter:
            engine = CutEngine(adapter=adapter)
            result = await engine.run(attack_type="delegation")
            assert result.error is None
            assert len(result.results) > 0
            assert all(r.payload_category == "delegation" for r in result.results)

    async def test_run_rogue_produces_results(self) -> None:
        async with MockSwarmAdapter() as adapter:
            engine = CutEngine(adapter=adapter)
            result = await engine.run(attack_type="rogue")
            assert result.error is None
            assert len(result.results) > 0
            assert all(r.payload_category == "rogue" for r in result.results)

    async def test_run_all_dispatches_all_types(self) -> None:
        """'all' should dispatch to all four attack types."""
        async with MockSwarmAdapter() as adapter:
            engine = CutEngine(adapter=adapter)
            result = await engine.run(attack_type="all")
            assert result.error is None
            assert result.finished_at is not None
            assert len(result.results) > 0
            categories = {r.payload_category for r in result.results}
            assert "trust" in categories
            assert "memory" in categories
            assert "delegation" in categories
            assert "rogue" in categories

    async def test_engine_timing(self) -> None:
        async with MockSwarmAdapter() as adapter:
            engine = CutEngine(adapter=adapter)
            result = await engine.run(attack_type="all")
            assert result.finished_at is not None
            assert result.duration_seconds >= 0

    async def test_engine_connection_error(self) -> None:
        """Engine should handle adapter errors gracefully."""

        class BrokenSwarm(MockSwarmAdapter):
            async def list_agents(self) -> list[AgentInfo]:
                msg = "Connection refused"
                raise ConnectionError(msg)

        async with BrokenSwarm() as adapter:
            engine = CutEngine(adapter=adapter)
            result = await engine.run(attack_type="all")
            assert result.error is not None
            assert "Failed to discover agents" in result.error


# ── CLI tests ─────────────────────────────────────────────────────


class TestCutCLI:
    """Test the ``puppetstring cut`` CLI command."""

    def test_cut_requires_target(self) -> None:
        result = runner.invoke(app, ["cut"])
        assert result.exit_code != 0

    def test_cut_invalid_attack_type(self) -> None:
        result = runner.invoke(app, ["cut", "-t", "crewai://localhost:8001", "--type", "bogus"])
        assert result.exit_code != 0
        assert "Unknown attack type" in result.output

    def test_cut_valid_invocation(self) -> None:
        result = runner.invoke(app, ["cut", "-t", "crewai://localhost:8001", "--type", "trust"])
        assert result.exit_code == 0
        assert "crewai://localhost:8001" in result.output
        assert "trust" in result.output

    def test_cut_default_type_is_all(self) -> None:
        result = runner.invoke(app, ["cut", "-t", "crewai://localhost:8001"])
        assert result.exit_code == 0
        assert "all" in result.output
