"""Tests for the unravel command (report generation)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from puppetstring.config import ReportConfig
from puppetstring.core.models import Finding, ScanResult, Severity
from puppetstring.modules.owasp_audit.models import (
    DanceRunResult,
    OWASPCoverage,
    OWASPCoverageItem,
    OWASPTestStatus,
    UnifiedFinding,
)
from puppetstring.modules.owasp_audit.serializer import ResultSerializer
from puppetstring.reporting.html_reporter import render_html_report
from puppetstring.reporting.json_reporter import render_json_report
from puppetstring.reporting.markdown_reporter import render_markdown_report
from puppetstring.reporting.report_generator import UnravelEngine


def _make_result_with_findings() -> DanceRunResult:
    """Helper to create a DanceRunResult with test findings."""
    scan = ScanResult(target="mcp://test", scan_type="scan")
    scan.findings = [
        Finding(title="Dangerous tool", severity=Severity.HIGH, owasp_ids=["A1"]),
    ]
    return DanceRunResult(
        target="mcp://test",
        scan_result=scan,
        coverage=OWASPCoverage(
            categories=[
                OWASPCoverageItem(
                    owasp_id="A1",
                    name="Excessive Agency",
                    status=OWASPTestStatus.TESTED_FAIL,
                    findings_count=1,
                    highest_severity=Severity.HIGH,
                    tested_by=["scan"],
                ),
            ],
            coverage_percentage=10.0,
            total_findings=1,
            risk_score=5.0,
        ),
        all_findings=[
            UnifiedFinding(
                title="Dangerous tool",
                severity=Severity.HIGH,
                owasp_ids=["A1"],
                source_module="scan",
                evidence="Tool has code-execution permission",
            ),
        ],
    )


class TestHTMLReporter:
    """Tests for HTML report generation."""

    def test_html_report_created(self, tmp_path: Path) -> None:
        result = _make_result_with_findings()
        config = ReportConfig()
        path = render_html_report(result, config, tmp_path)
        assert path.exists()
        assert path.suffix == ".html"

    def test_html_self_contained(self, tmp_path: Path) -> None:
        """HTML should have all CSS inline, no external links."""
        result = _make_result_with_findings()
        config = ReportConfig()
        path = render_html_report(result, config, tmp_path)
        content = path.read_text(encoding="utf-8")
        assert "<style>" in content
        assert "Dangerous tool" in content
        # No external stylesheet references
        assert 'rel="stylesheet"' not in content

    def test_html_includes_company_name(self, tmp_path: Path) -> None:
        result = _make_result_with_findings()
        config = ReportConfig(company_name="TestCorp")
        path = render_html_report(result, config, tmp_path)
        content = path.read_text(encoding="utf-8")
        assert "TestCorp" in content

    def test_html_autoescape(self, tmp_path: Path) -> None:
        """HTML should escape dangerous content (XSS prevention)."""
        result = DanceRunResult(
            target="<script>alert('xss')</script>",
            all_findings=[
                UnifiedFinding(
                    title="<img src=x onerror=alert(1)>",
                    severity=Severity.HIGH,
                    owasp_ids=["A1"],
                ),
            ],
            coverage=OWASPCoverage(
                categories=[], coverage_percentage=0, total_findings=1, risk_score=5.0
            ),
        )
        config = ReportConfig()
        path = render_html_report(result, config, tmp_path)
        content = path.read_text(encoding="utf-8")
        assert "<script>" not in content
        assert "&lt;script&gt;" in content


class TestJSONReporter:
    """Tests for JSON report generation."""

    def test_json_report_created(self, tmp_path: Path) -> None:
        result = _make_result_with_findings()
        config = ReportConfig()
        path = render_json_report(result, config, tmp_path)
        assert path.exists()
        assert path.suffix == ".json"

    def test_json_valid(self, tmp_path: Path) -> None:
        result = _make_result_with_findings()
        config = ReportConfig()
        path = render_json_report(result, config, tmp_path)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "findings" in data
        assert "summary" in data
        assert "coverage" in data

    def test_json_exit_code_1_with_findings(self, tmp_path: Path) -> None:
        result = _make_result_with_findings()
        config = ReportConfig()
        path = render_json_report(result, config, tmp_path)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["exit_code"] == 1

    def test_json_exit_code_0_without_findings(self, tmp_path: Path) -> None:
        result = DanceRunResult(
            target="http://test",
            coverage=OWASPCoverage(),
        )
        config = ReportConfig()
        path = render_json_report(result, config, tmp_path)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["exit_code"] == 0

    def test_json_includes_company_name(self, tmp_path: Path) -> None:
        result = _make_result_with_findings()
        config = ReportConfig(company_name="TestCorp")
        path = render_json_report(result, config, tmp_path)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["company_name"] == "TestCorp"


class TestMarkdownReporter:
    """Tests for Markdown report generation."""

    def test_markdown_report_created(self, tmp_path: Path) -> None:
        result = _make_result_with_findings()
        config = ReportConfig()
        path = render_markdown_report(result, config, tmp_path)
        assert path.exists()
        assert path.suffix == ".md"

    def test_markdown_contains_findings(self, tmp_path: Path) -> None:
        result = _make_result_with_findings()
        config = ReportConfig()
        path = render_markdown_report(result, config, tmp_path)
        content = path.read_text(encoding="utf-8")
        assert "Dangerous tool" in content
        assert "HIGH" in content


class TestUnravelEngine:
    """Tests for the UnravelEngine orchestrator."""

    @pytest.mark.asyncio
    async def test_unravel_from_saved_results(self, tmp_path: Path) -> None:
        # Save results first
        result = _make_result_with_findings()
        results_dir = tmp_path / "results"
        ResultSerializer.save(results_dir, result)

        # Generate report
        output_dir = tmp_path / "reports"
        engine = UnravelEngine()
        report_path = await engine.run(
            results_dir=results_dir,
            output_format="json",
            output_dir=output_dir,
        )
        assert report_path.exists()
        data = json.loads(report_path.read_text(encoding="utf-8"))
        assert data["target"] == "mcp://test"

    @pytest.mark.asyncio
    async def test_unravel_missing_results_dir(self, tmp_path: Path) -> None:
        engine = UnravelEngine()
        with pytest.raises(FileNotFoundError):
            await engine.run(
                results_dir=tmp_path / "nonexistent",
                output_format="html",
                output_dir=tmp_path / "reports",
            )

    @pytest.mark.asyncio
    async def test_unravel_invalid_format(self, tmp_path: Path) -> None:
        results_dir = tmp_path / "results"
        results_dir.mkdir()
        engine = UnravelEngine()
        with pytest.raises(ValueError, match="Unknown report format"):
            await engine.run(
                results_dir=results_dir,
                output_format="pdf",
                output_dir=tmp_path / "reports",
            )
