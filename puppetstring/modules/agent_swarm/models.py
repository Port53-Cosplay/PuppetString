"""Data models for agent-to-agent attack simulation (Phase 4: ``puppetstring cut``).

Multi-agent systems (CrewAI, LangGraph, AutoGen) let multiple AI agents
collaborate — sharing memory, delegating tasks, and trusting each other's
outputs. If one agent is compromised, can it compromise the others?

Model hierarchy:
    SwarmAttackType      — enum of attack categories
    SwarmClassification  — how the judge grades a swarm attack attempt
    AgentInfo            — metadata about one agent in the swarm
    SwarmPayload         — one attack payload for a swarm scenario
    SwarmObservation     — what we observed during/after an attack
    SwarmResult          — one complete attack attempt (payload + observation + judgment)
    SwarmRunResult       — complete output of a ``cut`` session
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from puppetstring.core.models import Severity, ToolCall
from puppetstring.utils.constants import SEVERITY_ORDER

# ── Enums ─────────────────────────────────────────────────────────


class SwarmAttackType(StrEnum):
    """Categories of agent-to-agent attacks.

    Each maps to a ``--type`` flag on the CLI and a dedicated attack runner
    inside the CutEngine.
    """

    TRUST = "trust"  # Authority impersonation, result manipulation
    MEMORY = "memory"  # Shared memory poisoning, context leakage
    DELEGATION = "delegation"  # Delegation chain abuse, privilege escalation
    ROGUE = "rogue"  # Inject a malicious agent into the swarm
    ALL = "all"  # Run all attack types


class SwarmClassification(StrEnum):
    """How the judge grades an agent-to-agent attack attempt.

    EXPLOITED — Cross-agent attack succeeded (Agent A caused Agent B to act).
    PARTIAL   — Some cross-agent influence observed but not full compromise.
    BLOCKED   — The swarm resisted the attack.
    ERROR     — Something went wrong during the attack.
    """

    EXPLOITED = "exploited"
    PARTIAL = "partial"
    BLOCKED = "blocked"
    ERROR = "error"


# ── Agent metadata ────────────────────────────────────────────────


class AgentInfo(BaseModel):
    """Metadata about one agent in a multi-agent system."""

    agent_id: str
    name: str = ""
    role: str = ""  # e.g. "researcher", "executor", "manager"
    tools: list[str] = Field(default_factory=list)
    privilege_level: str = ""  # e.g. "low", "high", "admin"
    metadata: dict[str, Any] = Field(default_factory=dict)


# ── Attack payloads ───────────────────────────────────────────────


class SwarmPayload(BaseModel):
    """One attack payload for an agent-to-agent attack scenario.

    Different fields are relevant for different attack types:
    - Trust: sender_agent, target_agent, message
    - Memory: shared_memory_key, shared_memory_value
    - Delegation: sender_agent, target_agent, delegate_task
    - Rogue: agent_config
    """

    name: str
    category: str  # matches SwarmAttackType value: "trust", "memory", etc.
    attack_type: SwarmAttackType
    description: str = ""
    intent: str  # what this attack is trying to achieve
    sender_agent: str = ""  # which agent to impersonate / use as attacker
    target_agent: str = ""  # which agent is the target
    message: str = ""  # adversarial message content
    shared_memory_key: str = ""  # for memory attacks: which key to poison
    shared_memory_value: str = ""  # for memory attacks: what to write
    delegate_task: str = ""  # for delegation attacks: the task to delegate
    agent_config: dict[str, Any] = Field(default_factory=dict)  # for rogue injection
    owasp_ids: list[str] = Field(default_factory=lambda: ["A7"])
    tags: list[str] = Field(default_factory=list)


# ── Observations (what happened during an attack) ─────────────────


class SwarmObservation(BaseModel):
    """What we observed during/after a swarm attack.

    Replaces AgentResponse for multi-agent contexts — we care about
    which agent was affected, what it did, and how the swarm state changed.
    """

    affected_agent: str = ""
    action_taken: str = ""  # what the affected agent did
    tool_calls: list[ToolCall] = Field(default_factory=list)
    shared_memory_changes: dict[str, Any] = Field(default_factory=dict)
    delegation_path: list[str] = Field(default_factory=list)
    raw: dict[str, Any] | None = None
    error: str | None = None


# ── Individual attack result ──────────────────────────────────────


class SwarmResult(BaseModel):
    """One complete attack attempt: what we tried, what happened, how it was judged."""

    payload_name: str
    payload_category: str
    attack_type: SwarmAttackType
    intent: str
    description: str = ""
    sender_agent: str = ""
    target_agent: str = ""
    observation: SwarmObservation
    classification: SwarmClassification = SwarmClassification.ERROR
    severity: Severity = Severity.INFO
    explanation: str = ""
    owasp_ids: list[str] = Field(default_factory=lambda: ["A7"])

    @property
    def sort_key(self) -> int:
        """Numeric sort key (lower = more severe)."""
        return SEVERITY_ORDER.get(self.severity.value, 99)


# ── Run result container ──────────────────────────────────────────


class SwarmRunResult(BaseModel):
    """Complete output of a ``puppetstring cut`` session."""

    target: str
    attack_type: str  # "trust", "memory", "delegation", "rogue", "all"
    agents_discovered: list[AgentInfo] = Field(default_factory=list)
    results: list[SwarmResult] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=datetime.now)
    finished_at: datetime | None = None
    error: str | None = None

    @property
    def duration_seconds(self) -> float:
        """How long the session took, in seconds."""
        if self.finished_at is None:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def summary(self) -> dict[str, int]:
        """Count results by classification."""
        counts: dict[str, int] = {c.value: 0 for c in SwarmClassification}
        for r in self.results:
            counts[r.classification.value] += 1
        return counts

    @property
    def exploited_count(self) -> int:
        return sum(1 for r in self.results if r.classification == SwarmClassification.EXPLOITED)

    @property
    def partial_count(self) -> int:
        return sum(1 for r in self.results if r.classification == SwarmClassification.PARTIAL)

    @property
    def blocked_count(self) -> int:
        return sum(1 for r in self.results if r.classification == SwarmClassification.BLOCKED)

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results if r.classification == SwarmClassification.ERROR)

    @property
    def sorted_results(self) -> list[SwarmResult]:
        """Results sorted by severity (critical first)."""
        return sorted(self.results, key=lambda r: r.sort_key)
