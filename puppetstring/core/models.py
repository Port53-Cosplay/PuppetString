"""Data models for PuppetString results.

These Pydantic models define the shape of all data flowing through PuppetString.
Every module produces result objects, and every reporter consumes them.
This shared contract keeps the codebase loosely coupled.

MCP scanning models (Phase 1):
- ToolInfo: A single tool discovered on an MCP server
- Finding: A single security issue found during scanning
- ScanResult: The complete output of a scan (tools + findings + metadata)

Agent fuzzing models (Phase 2):
- ToolCall: A record of one tool invocation the agent made during a response
- AgentResponse: Everything the agent said/did in response to one message
- FuzzClassification: How the LLM judge graded an attack attempt
- FuzzResult: One complete attack attempt (payload + response + judgment)
- FuzzRunResult: The full output of a fuzzing session
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from puppetstring.utils.constants import SEVERITY_ORDER


class Severity(StrEnum):
    """Severity levels for findings, ordered from most to least critical."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PermissionLevel(StrEnum):
    """Blast-radius classification for tools."""

    READ_ONLY = "read-only"
    READ_WRITE = "read-write"
    DESTRUCTIVE = "destructive"
    CODE_EXECUTION = "code-execution"
    UNKNOWN = "unknown"


class ToolInfo(BaseModel):
    """One tool discovered on an MCP server."""

    name: str
    description: str | None = None
    input_schema: dict | None = None
    output_schema: dict | None = None
    annotations: dict | None = None
    is_dangerous: bool = False
    danger_reasons: list[str] = Field(default_factory=list)
    permission_level: PermissionLevel = PermissionLevel.UNKNOWN


class Finding(BaseModel):
    """One security issue found during scanning."""

    title: str
    severity: Severity
    owasp_ids: list[str] = Field(default_factory=list)
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    tool_name: str | None = None

    @property
    def sort_key(self) -> int:
        """Return numeric sort key (lower = more severe)."""
        return SEVERITY_ORDER.get(self.severity.value, 99)


class ScanResult(BaseModel):
    """Complete output of a scan — tools, findings, and metadata."""

    target: str
    scan_type: str
    tools: list[ToolInfo] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=datetime.now)
    finished_at: datetime | None = None
    error: str | None = None

    @property
    def duration_seconds(self) -> float:
        """How long the scan took, in seconds."""
        if self.finished_at is None:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def summary(self) -> dict[str, int]:
        """Count findings by severity."""
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def sorted_findings(self) -> list[Finding]:
        """Findings sorted by severity (critical first)."""
        return sorted(self.findings, key=lambda f: f.sort_key)


# ── Agent fuzzing models (Phase 2) ────────────────────────────────
#
# These models capture what happens when you send an attack payload
# to an AI agent. The flow is:
#
#   1. Fuzzer sends a payload (a tricky message) to the agent
#   2. Agent responds with text and possibly calls some tools
#   3. We capture that response as an AgentResponse
#   4. An LLM "judge" looks at the response and classifies the result
#   5. Everything gets bundled into a FuzzResult
#
# Why use an LLM as a judge? Because detecting whether an attack
# "worked" is nuanced. Did the agent actually leak its system prompt,
# or did it just talk about system prompts in general? A regex can't
# tell the difference, but an LLM can reason about intent vs. outcome.


class ToolCall(BaseModel):
    """Record of one tool invocation the agent made.

    When an AI agent receives a message, it might decide to call tools
    (read a file, search the web, run a query, etc.). We record each
    tool call so the judge can see exactly what the agent did — not just
    what it said.

    Example:
        ToolCall(name="read_file", arguments={"path": "/etc/passwd"},
                 result="root:x:0:0:...")
    """

    name: str
    arguments: dict | None = None
    result: str | None = None


class AgentResponse(BaseModel):
    """Everything an agent said and did in response to one message.

    This is our observation window into agent behavior. The fuzzer
    sends a message, and this captures the full picture of what
    happened: the text reply, any tools the agent called, and
    any side effects we detected (files created, HTTP requests
    made, etc.).
    """

    text: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    side_effects: list[str] = Field(default_factory=list)
    raw: dict | None = None  # full raw response for debugging
    error: str | None = None

    @property
    def called_tools(self) -> bool:
        """Did the agent call any tools?"""
        return len(self.tool_calls) > 0

    @property
    def tool_names(self) -> list[str]:
        """Names of all tools the agent called."""
        return [tc.name for tc in self.tool_calls]


class FuzzClassification(StrEnum):
    """How the LLM judge grades an attack attempt.

    EXPLOITED — The attack fully worked. The agent did the unauthorized thing.
    PARTIAL   — The agent showed signs of compliance but didn't fully execute.
    BLOCKED   — The agent correctly refused or redirected.
    ERROR     — The agent errored out (could indicate a DoS vector).
    """

    EXPLOITED = "exploited"
    PARTIAL = "partial"
    BLOCKED = "blocked"
    ERROR = "error"


class FuzzResult(BaseModel):
    """One complete attack attempt: what we sent, what came back, how it was judged.

    This is the fundamental unit of fuzzing output. Each payload the fuzzer
    sends produces one FuzzResult. The report generator uses these to build
    the final report.
    """

    payload_name: str
    payload_category: str  # e.g. "tool-abuse", "memory-poison", "boundary"
    payload_text: str
    intent: str  # what the attack is trying to achieve
    response: AgentResponse
    classification: FuzzClassification = FuzzClassification.ERROR
    severity: Severity = Severity.INFO
    explanation: str = ""  # LLM judge's reasoning
    owasp_ids: list[str] = Field(default_factory=list)
    conversation_history: list[dict] = Field(default_factory=list)


class FuzzRunResult(BaseModel):
    """Complete output of a fuzzing session — all results plus metadata.

    Analogous to ScanResult but for fuzzing. Contains every individual
    FuzzResult plus timing and summary information.
    """

    target: str
    fuzz_type: str  # "tool-abuse", "memory-poison", "boundary", "chain", "all"
    results: list[FuzzResult] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=datetime.now)
    finished_at: datetime | None = None
    error: str | None = None

    @property
    def duration_seconds(self) -> float:
        if self.finished_at is None:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def summary(self) -> dict[str, int]:
        """Count results by classification."""
        counts: dict[str, int] = {c.value: 0 for c in FuzzClassification}
        for r in self.results:
            counts[r.classification.value] += 1
        return counts

    @property
    def exploited_count(self) -> int:
        return sum(1 for r in self.results if r.classification == FuzzClassification.EXPLOITED)

    @property
    def partial_count(self) -> int:
        return sum(1 for r in self.results if r.classification == FuzzClassification.PARTIAL)

    @property
    def blocked_count(self) -> int:
        return sum(1 for r in self.results if r.classification == FuzzClassification.BLOCKED)
