"""Data models for the OWASP audit (dance) and report generation (unravel).

Unified models that normalize findings from all sub-modules into a common
format, plus the OWASP coverage matrix that tracks which categories have
been tested and what was found.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from puppetstring.core.models import FuzzRunResult, ScanResult, Severity
from puppetstring.modules.agent_swarm.models import SwarmRunResult
from puppetstring.modules.prompt_injection.models import TangleRunResult
from puppetstring.utils.constants import SEVERITY_ORDER


class OWASPTestStatus(StrEnum):
    """Status of testing for a single OWASP category."""

    TESTED_PASS = "tested-pass"  # noqa: S105
    TESTED_FAIL = "tested-fail"
    NOT_TESTED = "not-tested"


class UnifiedFinding(BaseModel):
    """A normalized finding from any PuppetString module.

    Provides a common shape so the report layer doesn't need to know
    which module produced a finding — it just works with these.
    """

    title: str
    severity: Severity
    owasp_ids: list[str] = Field(default_factory=list)
    source_module: str = ""
    description: str = ""
    evidence: str = ""
    remediation: str = ""

    @property
    def sort_key(self) -> int:
        """Numeric sort key (lower = more severe)."""
        return SEVERITY_ORDER.get(self.severity.value, 99)


class OWASPCoverageItem(BaseModel):
    """Coverage status for a single OWASP category (e.g. A1)."""

    owasp_id: str
    name: str
    status: OWASPTestStatus = OWASPTestStatus.NOT_TESTED
    findings_count: int = 0
    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    highest_severity: Severity | None = None
    tested_by: list[str] = Field(default_factory=list)


class OWASPCoverage(BaseModel):
    """Full OWASP Top 10 coverage matrix."""

    categories: list[OWASPCoverageItem] = Field(default_factory=list)
    coverage_percentage: float = 0.0
    total_findings: int = 0
    risk_score: float = 0.0


class ResultManifest(BaseModel):
    """Metadata file written alongside result JSONs in the results directory."""

    version: str = "1.0"
    target: str = ""
    created_at: datetime = Field(default_factory=datetime.now)
    has_scan: bool = False
    has_fuzz: bool = False
    has_tangle: bool = False
    has_swarm: bool = False
    has_coverage: bool = False


class DanceRunResult(BaseModel):
    """Aggregate container for a full OWASP audit run."""

    target: str
    framework: str = "owasp-agentic-2026"
    passive_only: bool = False

    scan_result: ScanResult | None = None
    fuzz_result: FuzzRunResult | None = None
    tangle_result: TangleRunResult | None = None
    swarm_result: SwarmRunResult | None = None

    coverage: OWASPCoverage = Field(default_factory=OWASPCoverage)
    all_findings: list[UnifiedFinding] = Field(default_factory=list)

    started_at: datetime = Field(default_factory=datetime.now)
    finished_at: datetime | None = None
    errors: dict[str, str] = Field(default_factory=dict)

    # For report metadata
    config_snapshot: dict[str, Any] = Field(default_factory=dict)

    @property
    def duration_seconds(self) -> float:
        if self.finished_at is None:
            return 0.0
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def has_critical_or_high(self) -> bool:
        return any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.all_findings)

    @property
    def sorted_findings(self) -> list[UnifiedFinding]:
        return sorted(self.all_findings, key=lambda f: f.sort_key)

    @property
    def severity_summary(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.all_findings:
            counts[f.severity.value] += 1
        return counts
