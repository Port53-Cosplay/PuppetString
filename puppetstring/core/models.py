"""Data models for PuppetString scan results.

These Pydantic models define the shape of all data flowing through the scanner:
- ToolInfo: A single tool discovered on an MCP server
- Finding: A single security issue found during scanning
- ScanResult: The complete output of a scan (tools + findings + metadata)

Every module produces ScanResult objects, and every reporter consumes them.
This shared contract keeps the codebase loosely coupled.
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
