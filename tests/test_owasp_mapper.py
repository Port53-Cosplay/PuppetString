"""Tests for the OWASP coverage mapper."""

from __future__ import annotations

from puppetstring.core.models import (
    AgentResponse,
    Finding,
    FuzzClassification,
    FuzzResult,
    FuzzRunResult,
    ScanResult,
    Severity,
)
from puppetstring.modules.agent_swarm.models import (
    SwarmAttackType,
    SwarmClassification,
    SwarmObservation,
    SwarmResult,
    SwarmRunResult,
)
from puppetstring.modules.owasp_audit.mapper import OWASPMapper
from puppetstring.modules.owasp_audit.models import OWASPTestStatus
from puppetstring.modules.prompt_injection.models import (
    InjectionClassification,
    InjectionResult,
    TangleRunResult,
)


class TestOWASPMapperEmptyResults:
    """Tests with no results provided."""

    def test_empty_results_all_not_tested(self) -> None:
        coverage, findings = OWASPMapper.map_coverage()
        assert len(coverage.categories) == 10
        assert all(c.status == OWASPTestStatus.NOT_TESTED for c in coverage.categories)
        assert findings == []

    def test_empty_results_zero_coverage(self) -> None:
        coverage, _ = OWASPMapper.map_coverage()
        assert coverage.coverage_percentage == 0.0

    def test_empty_results_zero_risk(self) -> None:
        coverage, _ = OWASPMapper.map_coverage()
        assert coverage.risk_score == 0.0

    def test_empty_results_zero_findings(self) -> None:
        coverage, findings = OWASPMapper.map_coverage()
        assert coverage.total_findings == 0
        assert len(findings) == 0


class TestOWASPMapperScanOnly:
    """Tests with only scan results."""

    def test_scan_only_marks_scan_categories_tested(self) -> None:
        scan = ScanResult(target="mcp://test", scan_type="scan")
        coverage, _ = OWASPMapper.map_coverage(scan=scan)

        # A1 (Excessive Agency) is tested by scan
        a1 = next(c for c in coverage.categories if c.owasp_id == "A1")
        assert a1.status == OWASPTestStatus.TESTED_PASS
        assert "scan" in a1.tested_by

    def test_scan_with_finding_marks_fail(self) -> None:
        scan = ScanResult(target="mcp://test", scan_type="scan")
        scan.findings = [
            Finding(
                title="Excessive permissions",
                severity=Severity.HIGH,
                owasp_ids=["A1"],
            )
        ]
        coverage, findings = OWASPMapper.map_coverage(scan=scan)

        a1 = next(c for c in coverage.categories if c.owasp_id == "A1")
        assert a1.status == OWASPTestStatus.TESTED_FAIL
        assert a1.findings_count == 1
        assert a1.highest_severity == Severity.HIGH
        assert len(findings) == 1

    def test_scan_coverage_percentage(self) -> None:
        scan = ScanResult(target="mcp://test", scan_type="scan")
        coverage, _ = OWASPMapper.map_coverage(scan=scan)
        # scan covers A1, A2, A8, A9, A10 = 5 categories
        assert coverage.coverage_percentage == 50.0

    def test_scan_findings_extracted_as_unified(self) -> None:
        scan = ScanResult(target="mcp://test", scan_type="scan")
        scan.findings = [
            Finding(title="Test", severity=Severity.MEDIUM, owasp_ids=["A2"]),
        ]
        _, findings = OWASPMapper.map_coverage(scan=scan)
        assert len(findings) == 1
        assert findings[0].source_module == "scan"
        assert findings[0].title == "Test"


class TestOWASPMapperSeverityAggregation:
    """Tests for severity breakdown and risk score computation."""

    def test_severity_breakdown(self) -> None:
        scan = ScanResult(target="mcp://test", scan_type="scan")
        scan.findings = [
            Finding(title="F1", severity=Severity.HIGH, owasp_ids=["A1"]),
            Finding(title="F2", severity=Severity.HIGH, owasp_ids=["A1"]),
            Finding(title="F3", severity=Severity.MEDIUM, owasp_ids=["A1"]),
        ]
        coverage, _ = OWASPMapper.map_coverage(scan=scan)

        a1 = next(c for c in coverage.categories if c.owasp_id == "A1")
        assert a1.severity_breakdown == {"high": 2, "medium": 1}

    def test_highest_severity_is_correct(self) -> None:
        scan = ScanResult(target="mcp://test", scan_type="scan")
        scan.findings = [
            Finding(title="F1", severity=Severity.MEDIUM, owasp_ids=["A1"]),
            Finding(title="F2", severity=Severity.CRITICAL, owasp_ids=["A1"]),
            Finding(title="F3", severity=Severity.LOW, owasp_ids=["A1"]),
        ]
        coverage, _ = OWASPMapper.map_coverage(scan=scan)

        a1 = next(c for c in coverage.categories if c.owasp_id == "A1")
        assert a1.highest_severity == Severity.CRITICAL

    def test_risk_score_computation(self) -> None:
        scan = ScanResult(target="mcp://test", scan_type="scan")
        scan.findings = [
            Finding(title="F1", severity=Severity.CRITICAL, owasp_ids=["A1"]),
            Finding(title="F2", severity=Severity.HIGH, owasp_ids=["A1"]),
        ]
        coverage, _ = OWASPMapper.map_coverage(scan=scan)
        # critical=10 + high=5 = 15
        assert coverage.risk_score == 15.0


class TestOWASPMapperMultiModule:
    """Tests with results from multiple modules."""

    def test_multi_owasp_id_finding(self) -> None:
        """A finding with multiple OWASP IDs should appear in each category."""
        scan = ScanResult(target="mcp://test", scan_type="scan")
        scan.findings = [
            Finding(title="Multi", severity=Severity.HIGH, owasp_ids=["A1", "A2"]),
        ]
        coverage, findings = OWASPMapper.map_coverage(scan=scan)

        a1 = next(c for c in coverage.categories if c.owasp_id == "A1")
        a2 = next(c for c in coverage.categories if c.owasp_id == "A2")
        assert a1.findings_count == 1
        assert a2.findings_count == 1
        # But the unified finding itself is only extracted once
        assert len(findings) == 1

    def test_fuzz_extracts_exploited_only(self) -> None:
        fuzz = FuzzRunResult(target="http://test", fuzz_type="all")
        fuzz.results = [
            FuzzResult(
                payload_name="exploit_1",
                payload_category="tool-abuse",
                payload_text="test",
                intent="test",
                response=AgentResponse(text="ok"),
                classification=FuzzClassification.EXPLOITED,
                severity=Severity.HIGH,
                owasp_ids=["A2"],
            ),
            FuzzResult(
                payload_name="blocked_1",
                payload_category="tool-abuse",
                payload_text="test",
                intent="test",
                response=AgentResponse(text="no"),
                classification=FuzzClassification.BLOCKED,
                severity=Severity.INFO,
                owasp_ids=["A2"],
            ),
        ]
        _, findings = OWASPMapper.map_coverage(fuzz=fuzz)
        assert len(findings) == 1
        assert findings[0].title == "exploit_1"

    def test_tangle_extracts_findings(self) -> None:
        tangle = TangleRunResult(target="http://test", vector="all")
        tangle.results = [
            InjectionResult(
                payload_name="inject_1",
                payload_category="document",
                hidden_text="test",
                goal="canary:BANANA",
                classification=InjectionClassification.EXPLOITED,
                severity=Severity.HIGH,
                owasp_ids=["A3"],
            ),
        ]
        _, findings = OWASPMapper.map_coverage(tangle=tangle)
        assert len(findings) == 1
        assert findings[0].source_module == "tangle"

    def test_swarm_extracts_findings(self) -> None:
        swarm = SwarmRunResult(target="mock://swarm", attack_type="all")
        swarm.results = [
            SwarmResult(
                payload_name="trust_1",
                payload_category="trust",
                attack_type=SwarmAttackType.TRUST,
                intent="test",
                observation=SwarmObservation(),
                classification=SwarmClassification.EXPLOITED,
                severity=Severity.HIGH,
                owasp_ids=["A7"],
            ),
        ]
        _, findings = OWASPMapper.map_coverage(swarm=swarm)
        assert len(findings) == 1
        assert findings[0].source_module == "cut"

    def test_full_coverage_with_all_modules(self) -> None:
        scan = ScanResult(target="mcp://test", scan_type="scan")
        fuzz = FuzzRunResult(target="http://test", fuzz_type="all")
        tangle = TangleRunResult(target="http://test", vector="all")
        swarm = SwarmRunResult(target="mock://swarm", attack_type="all")

        coverage, _ = OWASPMapper.map_coverage(scan=scan, fuzz=fuzz, tangle=tangle, swarm=swarm)
        # A6 has no modules, so 9/10 = 90%
        assert coverage.coverage_percentage == 90.0
