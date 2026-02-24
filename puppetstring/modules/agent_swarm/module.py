"""Cut Engine — orchestrates agent-to-agent attack simulation.

Pattern mirrors WorkflowFuzzer and TangleEngine:
- ``__init__`` takes adapter + config
- ``async def run(attack_type)`` dispatches based on type
- Private ``_run_*`` methods handle each attack category
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import TYPE_CHECKING

from puppetstring.config import CutConfig

if TYPE_CHECKING:
    from puppetstring.adapters.swarm_adapter import SwarmAdapter
from puppetstring.modules.agent_swarm.judge import SwarmJudge
from puppetstring.modules.agent_swarm.models import (
    AgentInfo,
    SwarmAttackType,
    SwarmClassification,
    SwarmObservation,
    SwarmResult,
    SwarmRunResult,
)
from puppetstring.modules.agent_swarm.payload_loader import (
    load_builtin_swarm_payloads,
    resolve_agent_placeholders,
)
from puppetstring.utils.logging import get_logger

logger = get_logger(__name__)


# ── Attack type routing ───────────────────────────────────────────

_ATTACK_TYPE_MAP: dict[str, list[SwarmAttackType]] = {
    "trust": [SwarmAttackType.TRUST],
    "memory": [SwarmAttackType.MEMORY],
    "delegation": [SwarmAttackType.DELEGATION],
    "rogue": [SwarmAttackType.ROGUE],
    "all": [
        SwarmAttackType.TRUST,
        SwarmAttackType.MEMORY,
        SwarmAttackType.DELEGATION,
        SwarmAttackType.ROGUE,
    ],
}


class CutEngine:
    """Orchestrates agent-to-agent attack simulation.

    Usage:
        engine = CutEngine(adapter=swarm_adapter)
        result = await engine.run(attack_type="trust")
    """

    def __init__(
        self,
        adapter: SwarmAdapter,
        config: CutConfig | None = None,
        judge: SwarmJudge | None = None,
        delay_between_attacks: float = 1.0,
        max_attacks: int = 50,
    ) -> None:
        self._adapter = adapter
        self._config = config or CutConfig()
        self._judge = judge or SwarmJudge(model=self._config.judge_model)
        self._delay = self._config.delay_between_attacks or delay_between_attacks
        self._max_attacks = self._config.max_attacks or max_attacks

    async def run(self, attack_type: str = "all") -> SwarmRunResult:
        """Run agent-to-agent attacks against the target swarm.

        Args:
            attack_type: Which attacks to run — "trust", "memory",
                "delegation", "rogue", or "all".

        Returns:
            SwarmRunResult containing all attack results and metadata.
        """
        run_result = SwarmRunResult(
            target=self._adapter.target,
            attack_type=attack_type,
        )

        # Validate attack type
        attack_types = _ATTACK_TYPE_MAP.get(attack_type)
        if attack_types is None:
            run_result.error = f"Unknown attack type: {attack_type}"
            run_result.finished_at = datetime.now()
            return run_result

        # Discover agents in the swarm
        try:
            agents = await self._adapter.list_agents()
            run_result.agents_discovered = agents
            logger.info("Discovered %d agents in swarm", len(agents))
        except Exception as exc:
            run_result.error = f"Failed to discover agents: {exc}"
            run_result.finished_at = datetime.now()
            return run_result

        # Need at least 2 agents for cross-agent attacks
        if len(agents) < 2:
            run_result.error = f"Need at least 2 agents for swarm attacks, found {len(agents)}"
            run_result.finished_at = datetime.now()
            return run_result

        # Dispatch to per-type runners
        for at in attack_types:
            results = await self._dispatch(at, agents)
            run_result.results.extend(results)

        run_result.finished_at = datetime.now()
        return run_result

    async def _dispatch(
        self,
        attack_type: SwarmAttackType,
        agents: list[AgentInfo],
    ) -> list[SwarmResult]:
        """Route to the appropriate attack runner."""
        dispatch_map = {
            SwarmAttackType.TRUST: self._run_trust_exploitation,
            SwarmAttackType.MEMORY: self._run_shared_memory_attack,
            SwarmAttackType.DELEGATION: self._run_delegation_abuse,
            SwarmAttackType.ROGUE: self._run_rogue_agent,
        }
        handler = dispatch_map.get(attack_type)
        if handler is None:
            return []
        return await handler(agents)

    # ── Attack runners ──────────────────────────────────────────────

    async def _run_trust_exploitation(
        self,
        agents: list[AgentInfo],
    ) -> list[SwarmResult]:
        """Trust exploitation attacks — authority impersonation.

        Loads trust payloads, resolves agent placeholders, and sends
        crafted messages from low-privilege to high-privilege agents.
        """
        payloads = load_builtin_swarm_payloads(["trust"])
        payloads = resolve_agent_placeholders(payloads, agents)
        logger.info("Running %d trust exploitation payloads", len(payloads))

        results: list[SwarmResult] = []
        for payload in payloads[: self._max_attacks]:
            if self._config.reset_between_attacks:
                try:
                    await self._adapter.reset_swarm()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Failed to reset swarm: %s", exc)

            try:
                obs = await self._adapter.send_message_as(
                    payload.sender_agent,
                    payload.target_agent,
                    payload.message,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Trust attack failed for %s: %s", payload.name, exc)
                results.append(
                    SwarmResult(
                        payload_name=payload.name,
                        payload_category=payload.category,
                        attack_type=payload.attack_type,
                        intent=payload.intent,
                        description=payload.description,
                        sender_agent=payload.sender_agent,
                        target_agent=payload.target_agent,
                        observation=SwarmObservation(error=str(exc)),
                        classification=SwarmClassification.ERROR,
                        explanation=f"Adapter error: {exc}",
                        owasp_ids=payload.owasp_ids,
                    )
                )
                continue

            judgment = await self._judge.classify(payload, obs)
            results.append(
                SwarmResult(
                    payload_name=payload.name,
                    payload_category=payload.category,
                    attack_type=payload.attack_type,
                    intent=payload.intent,
                    description=payload.description,
                    sender_agent=payload.sender_agent,
                    target_agent=payload.target_agent,
                    observation=obs,
                    classification=judgment.classification,
                    severity=judgment.severity,
                    explanation=judgment.explanation,
                    owasp_ids=payload.owasp_ids,
                )
            )

            if self._delay > 0:
                await asyncio.sleep(self._delay)

        return results

    async def _run_shared_memory_attack(
        self,
        agents: list[AgentInfo],
    ) -> list[SwarmResult]:
        """Shared memory poisoning attacks.

        Writes adversarial instructions into shared memory, then sends
        a benign trigger message to cause the target to read and follow them.
        """
        payloads = load_builtin_swarm_payloads(["memory"])
        payloads = resolve_agent_placeholders(payloads, agents)
        logger.info("Running %d shared memory attack payloads", len(payloads))

        results: list[SwarmResult] = []
        for payload in payloads[: self._max_attacks]:
            if self._config.reset_between_attacks:
                try:
                    await self._adapter.reset_swarm()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Failed to reset swarm: %s", exc)

            # Step 1: Poison shared memory
            try:
                await self._adapter.write_shared_memory(
                    payload.shared_memory_key,
                    payload.shared_memory_value,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Memory write failed for %s: %s", payload.name, exc)
                results.append(
                    SwarmResult(
                        payload_name=payload.name,
                        payload_category=payload.category,
                        attack_type=payload.attack_type,
                        intent=payload.intent,
                        description=payload.description,
                        target_agent=payload.target_agent,
                        observation=SwarmObservation(error=str(exc)),
                        classification=SwarmClassification.ERROR,
                        explanation=f"Memory write error: {exc}",
                        owasp_ids=payload.owasp_ids,
                    )
                )
                continue

            # Step 2: Send benign trigger message
            try:
                obs = await self._adapter.send_message_as(
                    "system",
                    payload.target_agent,
                    payload.message,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Trigger message failed for %s: %s", payload.name, exc)
                results.append(
                    SwarmResult(
                        payload_name=payload.name,
                        payload_category=payload.category,
                        attack_type=payload.attack_type,
                        intent=payload.intent,
                        description=payload.description,
                        target_agent=payload.target_agent,
                        observation=SwarmObservation(error=str(exc)),
                        classification=SwarmClassification.ERROR,
                        explanation=f"Trigger message error: {exc}",
                        owasp_ids=payload.owasp_ids,
                    )
                )
                continue

            judgment = await self._judge.classify(payload, obs)
            results.append(
                SwarmResult(
                    payload_name=payload.name,
                    payload_category=payload.category,
                    attack_type=payload.attack_type,
                    intent=payload.intent,
                    description=payload.description,
                    target_agent=payload.target_agent,
                    observation=obs,
                    classification=judgment.classification,
                    severity=judgment.severity,
                    explanation=judgment.explanation,
                    owasp_ids=payload.owasp_ids,
                )
            )

            if self._delay > 0:
                await asyncio.sleep(self._delay)

        return results

    async def _run_delegation_abuse(
        self,
        agents: list[AgentInfo],
    ) -> list[SwarmResult]:
        """Delegation chain abuse attacks.

        Low-privilege agents delegate dangerous tasks to high-privilege
        agents, exploiting the lack of privilege checks.
        """
        payloads = load_builtin_swarm_payloads(["delegation"])
        payloads = resolve_agent_placeholders(payloads, agents)
        logger.info("Running %d delegation abuse payloads", len(payloads))

        results: list[SwarmResult] = []
        for payload in payloads[: self._max_attacks]:
            if self._config.reset_between_attacks:
                try:
                    await self._adapter.reset_swarm()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Failed to reset swarm: %s", exc)

            try:
                obs = await self._adapter.delegate_task(
                    payload.sender_agent,
                    payload.target_agent,
                    payload.delegate_task,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Delegation attack failed for %s: %s", payload.name, exc)
                results.append(
                    SwarmResult(
                        payload_name=payload.name,
                        payload_category=payload.category,
                        attack_type=payload.attack_type,
                        intent=payload.intent,
                        description=payload.description,
                        sender_agent=payload.sender_agent,
                        target_agent=payload.target_agent,
                        observation=SwarmObservation(error=str(exc)),
                        classification=SwarmClassification.ERROR,
                        explanation=f"Adapter error: {exc}",
                        owasp_ids=payload.owasp_ids,
                    )
                )
                continue

            judgment = await self._judge.classify(payload, obs)
            results.append(
                SwarmResult(
                    payload_name=payload.name,
                    payload_category=payload.category,
                    attack_type=payload.attack_type,
                    intent=payload.intent,
                    description=payload.description,
                    sender_agent=payload.sender_agent,
                    target_agent=payload.target_agent,
                    observation=obs,
                    classification=judgment.classification,
                    severity=judgment.severity,
                    explanation=judgment.explanation,
                    owasp_ids=payload.owasp_ids,
                )
            )

            if self._delay > 0:
                await asyncio.sleep(self._delay)

        return results

    async def _run_rogue_agent(
        self,
        agents: list[AgentInfo],
    ) -> list[SwarmResult]:
        """Rogue agent injection attacks.

        Injects a malicious agent into the swarm, then uses it to
        influence existing agents via messages, delegation, or memory.
        """
        payloads = load_builtin_swarm_payloads(["rogue"])
        payloads = resolve_agent_placeholders(payloads, agents)
        logger.info("Running %d rogue agent injection payloads", len(payloads))

        results: list[SwarmResult] = []
        for payload in payloads[: self._max_attacks]:
            if self._config.reset_between_attacks:
                try:
                    await self._adapter.reset_swarm()
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Failed to reset swarm: %s", exc)

            # Step 1: Inject the rogue agent
            rogue_id = ""
            if payload.agent_config:
                try:
                    rogue_id = await self._adapter.inject_agent(payload.agent_config)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Agent injection failed for %s: %s", payload.name, exc)
                    results.append(
                        SwarmResult(
                            payload_name=payload.name,
                            payload_category=payload.category,
                            attack_type=payload.attack_type,
                            intent=payload.intent,
                            description=payload.description,
                            target_agent=payload.target_agent,
                            observation=SwarmObservation(error=str(exc)),
                            classification=SwarmClassification.ERROR,
                            explanation=f"Injection error: {exc}",
                            owasp_ids=payload.owasp_ids,
                        )
                    )
                    continue

            # Step 2: Optionally poison shared memory
            if payload.shared_memory_key:
                try:
                    await self._adapter.write_shared_memory(
                        payload.shared_memory_key,
                        payload.shared_memory_value,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Memory write failed for %s: %s", payload.name, exc)

            # Step 3: Use rogue agent to attack
            sender = rogue_id or payload.sender_agent or "rogue"
            obs: SwarmObservation

            if payload.delegate_task:
                # Attack via delegation
                try:
                    obs = await self._adapter.delegate_task(
                        sender,
                        payload.target_agent,
                        payload.delegate_task,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Rogue delegation failed for %s: %s", payload.name, exc)
                    obs = SwarmObservation(error=str(exc))
            elif payload.message:
                # Attack via message
                try:
                    obs = await self._adapter.send_message_as(
                        sender,
                        payload.target_agent,
                        payload.message,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Rogue message failed for %s: %s", payload.name, exc)
                    obs = SwarmObservation(error=str(exc))
            else:
                # Injection only — observe if swarm accepted the rogue
                obs = SwarmObservation(
                    affected_agent=rogue_id,
                    action_taken=f"Rogue agent '{rogue_id}' injected into swarm",
                )

            # Step 4: Clean up rogue agent
            if rogue_id:
                try:
                    await self._adapter.remove_agent(rogue_id)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Failed to remove rogue agent %s: %s", rogue_id, exc)

            judgment = await self._judge.classify(payload, obs)
            results.append(
                SwarmResult(
                    payload_name=payload.name,
                    payload_category=payload.category,
                    attack_type=payload.attack_type,
                    intent=payload.intent,
                    description=payload.description,
                    sender_agent=sender,
                    target_agent=payload.target_agent,
                    observation=obs,
                    classification=judgment.classification,
                    severity=judgment.severity,
                    explanation=judgment.explanation,
                    owasp_ids=payload.owasp_ids,
                )
            )

            if self._delay > 0:
                await asyncio.sleep(self._delay)

        return results
