"""OWASP Coverage Mapper — maps findings from all modules to the OWASP Top 10.

Takes raw results from scan/fuzz/tangle/cut modules, extracts normalized
UnifiedFinding objects, groups them by OWASP category, and computes the
coverage matrix (what was tested, what passed, what failed).
"""

from __future__ import annotations

from puppetstring.core.models import (
    FuzzClassification,
    FuzzRunResult,
    ScanResult,
    Severity,
)
from puppetstring.modules.agent_swarm.models import (
    SwarmClassification,
    SwarmRunResult,
)
from puppetstring.modules.owasp_audit.models import (
    OWASPCoverage,
    OWASPCoverageItem,
    OWASPTestStatus,
    UnifiedFinding,
)
from puppetstring.modules.prompt_injection.models import (
    InjectionClassification,
    TangleRunResult,
)
from puppetstring.utils.constants import (
    OWASP_AGENTIC_TOP_10,
    OWASP_MODULE_COVERAGE_MAP,
    SEVERITY_ORDER,
)

# Risk score weights per severity level
_RISK_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 5.0,
    "medium": 2.0,
    "low": 0.5,
    "info": 0.0,
}


class OWASPMapper:
    """Maps sub-module results to the OWASP Top 10 coverage matrix."""

    @staticmethod
    def map_coverage(
        scan: ScanResult | None = None,
        fuzz: FuzzRunResult | None = None,
        tangle: TangleRunResult | None = None,
        swarm: SwarmRunResult | None = None,
    ) -> tuple[OWASPCoverage, list[UnifiedFinding]]:
        """Build coverage matrix and extract unified findings.

        Returns:
            Tuple of (OWASPCoverage, list of all UnifiedFindings).
        """
        # Determine which modules actually ran
        modules_ran: set[str] = set()
        if scan is not None:
            modules_ran.add("scan")
        if fuzz is not None:
            modules_ran.add("fuzz")
        if tangle is not None:
            modules_ran.add("tangle")
        if swarm is not None:
            modules_ran.add("cut")

        # Extract unified findings from each result
        all_findings: list[UnifiedFinding] = []
        all_findings.extend(_extract_scan_findings(scan))
        all_findings.extend(_extract_fuzz_findings(fuzz))
        all_findings.extend(_extract_tangle_findings(tangle))
        all_findings.extend(_extract_swarm_findings(swarm))

        # Group findings by OWASP ID
        findings_by_owasp: dict[str, list[UnifiedFinding]] = {}
        for finding in all_findings:
            for oid in finding.owasp_ids:
                findings_by_owasp.setdefault(oid, []).append(finding)

        # Build coverage items for each OWASP category
        categories: list[OWASPCoverageItem] = []
        tested_count = 0

        for owasp_id in sorted(OWASP_AGENTIC_TOP_10.keys()):
            info = OWASP_AGENTIC_TOP_10[owasp_id]
            required_modules = OWASP_MODULE_COVERAGE_MAP.get(owasp_id, [])
            tested_by = [m for m in required_modules if m in modules_ran]
            category_findings = findings_by_owasp.get(owasp_id, [])

            # Determine status
            if not tested_by:
                status = OWASPTestStatus.NOT_TESTED
            elif category_findings:
                status = OWASPTestStatus.TESTED_FAIL
            else:
                status = OWASPTestStatus.TESTED_PASS

            if status != OWASPTestStatus.NOT_TESTED:
                tested_count += 1

            # Severity breakdown
            sev_breakdown: dict[str, int] = {}
            highest: Severity | None = None
            highest_order = 99

            for f in category_findings:
                sev_val = f.severity.value
                sev_breakdown[sev_val] = sev_breakdown.get(sev_val, 0) + 1
                order = SEVERITY_ORDER.get(sev_val, 99)
                if order < highest_order:
                    highest_order = order
                    highest = f.severity

            categories.append(
                OWASPCoverageItem(
                    owasp_id=owasp_id,
                    name=info["name"],
                    status=status,
                    findings_count=len(category_findings),
                    severity_breakdown=sev_breakdown,
                    highest_severity=highest,
                    tested_by=tested_by,
                )
            )

        total_categories = len(OWASP_AGENTIC_TOP_10)
        coverage_pct = (tested_count / total_categories * 100) if total_categories else 0.0
        risk_score = _compute_risk_score(all_findings)

        coverage = OWASPCoverage(
            categories=categories,
            coverage_percentage=coverage_pct,
            total_findings=len(all_findings),
            risk_score=risk_score,
        )

        return coverage, all_findings


def _compute_risk_score(findings: list[UnifiedFinding]) -> float:
    """Compute a weighted risk score from findings."""
    return sum(_RISK_WEIGHTS.get(f.severity.value, 0.0) for f in findings)


def _extract_scan_findings(scan: ScanResult | None) -> list[UnifiedFinding]:
    """Convert ScanResult findings into UnifiedFindings."""
    if scan is None:
        return []
    return [
        UnifiedFinding(
            title=f.title,
            severity=f.severity,
            owasp_ids=f.owasp_ids,
            source_module="scan",
            description=f.description,
            evidence=f.evidence,
            remediation=f.remediation,
        )
        for f in scan.findings
    ]


def _extract_fuzz_findings(fuzz: FuzzRunResult | None) -> list[UnifiedFinding]:
    """Convert exploited/partial FuzzResults into UnifiedFindings."""
    if fuzz is None:
        return []
    findings: list[UnifiedFinding] = []
    for r in fuzz.results:
        if r.classification not in (FuzzClassification.EXPLOITED, FuzzClassification.PARTIAL):
            continue
        findings.append(
            UnifiedFinding(
                title=r.payload_name,
                severity=r.severity,
                owasp_ids=r.owasp_ids,
                source_module="fuzz",
                description=r.intent,
                evidence=r.explanation,
            )
        )
    return findings


def _extract_tangle_findings(tangle: TangleRunResult | None) -> list[UnifiedFinding]:
    """Convert exploited/partial InjectionResults into UnifiedFindings."""
    if tangle is None:
        return []
    findings: list[UnifiedFinding] = []
    for r in tangle.results:
        if r.classification not in (
            InjectionClassification.EXPLOITED,
            InjectionClassification.PARTIAL,
        ):
            continue
        findings.append(
            UnifiedFinding(
                title=r.payload_name,
                severity=r.severity,
                owasp_ids=r.owasp_ids,
                source_module="tangle",
                description=r.goal,
                evidence=r.explanation,
            )
        )
    return findings


def _extract_swarm_findings(swarm: SwarmRunResult | None) -> list[UnifiedFinding]:
    """Convert exploited/partial SwarmResults into UnifiedFindings."""
    if swarm is None:
        return []
    findings: list[UnifiedFinding] = []
    for r in swarm.results:
        if r.classification not in (
            SwarmClassification.EXPLOITED,
            SwarmClassification.PARTIAL,
        ):
            continue
        findings.append(
            UnifiedFinding(
                title=r.payload_name,
                severity=r.severity,
                owasp_ids=r.owasp_ids,
                source_module="cut",
                description=r.intent,
                evidence=r.explanation,
            )
        )
    return findings
