"""Agent-to-agent attack simulator — used by ``puppetstring cut``."""

from puppetstring.modules.agent_swarm.judge import SwarmJudge, SwarmJudgeResult
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
from puppetstring.modules.agent_swarm.payload_loader import load_builtin_swarm_payloads

__all__ = [
    "AgentInfo",
    "CutEngine",
    "SwarmAttackType",
    "SwarmClassification",
    "SwarmJudge",
    "SwarmJudgeResult",
    "SwarmObservation",
    "SwarmPayload",
    "SwarmResult",
    "SwarmRunResult",
    "load_builtin_swarm_payloads",
]
