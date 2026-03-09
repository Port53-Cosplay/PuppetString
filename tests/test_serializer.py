"""Tests for the result serializer (save/load round-trip)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from puppetstring.core.models import Finding, ScanResult, Severity
from puppetstring.modules.owasp_audit.models import (
    DanceRunResult,
    OWASPCoverage,
    OWASPCoverageItem,
    OWASPTestStatus,
    UnifiedFinding,
)
from puppetstring.modules.owasp_audit.serializer import ResultSerializer


class TestResultSerializerSave:
    """Tests for saving results to disk."""

    def test_save_creates_directory(self, tmp_path: Path) -> None:
        result = DanceRunResult(target="http://test")
        out = tmp_path / "results"
        ResultSerializer.save(out, result)
        assert out.is_dir()

    def test_save_creates_manifest(self, tmp_path: Path) -> None:
        result = DanceRunResult(target="http://test")
        ResultSerializer.save(tmp_path, result)
        assert (tmp_path / "manifest.json").is_file()

    def test_save_with_scan_result(self, tmp_path: Path) -> None:
        scan = ScanResult(target="mcp://test", scan_type="scan")
        result = DanceRunResult(target="mcp://test", scan_result=scan)
        ResultSerializer.save(tmp_path, result)
        assert (tmp_path / "scan_result.json").is_file()

        manifest = json.loads((tmp_path / "manifest.json").read_text())
        assert manifest["has_scan"] is True

    def test_save_with_findings(self, tmp_path: Path) -> None:
        finding = UnifiedFinding(title="Test", severity=Severity.HIGH, owasp_ids=["A3"])
        result = DanceRunResult(target="http://test", all_findings=[finding])
        ResultSerializer.save(tmp_path, result)
        assert (tmp_path / "findings.json").is_file()


class TestResultSerializerLoad:
    """Tests for loading results from disk."""

    def test_load_nonexistent_dir_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            ResultSerializer.load(tmp_path / "nonexistent")

    def test_load_empty_dir(self, tmp_path: Path) -> None:
        result = ResultSerializer.load(tmp_path)
        assert result.target == ""
        assert result.scan_result is None
        assert result.fuzz_result is None

    def test_round_trip_scan_result(self, tmp_path: Path) -> None:
        scan = ScanResult(target="mcp://test", scan_type="scan")
        scan.findings = [
            Finding(title="Found it", severity=Severity.HIGH, owasp_ids=["A1"]),
        ]
        original = DanceRunResult(target="mcp://test", scan_result=scan)
        ResultSerializer.save(tmp_path, original)

        loaded = ResultSerializer.load(tmp_path)
        assert loaded.scan_result is not None
        assert loaded.scan_result.target == "mcp://test"
        assert len(loaded.scan_result.findings) == 1
        assert loaded.scan_result.findings[0].title == "Found it"

    def test_round_trip_coverage(self, tmp_path: Path) -> None:
        coverage = OWASPCoverage(
            categories=[
                OWASPCoverageItem(
                    owasp_id="A1",
                    name="Excessive Agency",
                    status=OWASPTestStatus.TESTED_PASS,
                )
            ],
            coverage_percentage=10.0,
            total_findings=0,
            risk_score=0.0,
        )
        original = DanceRunResult(target="http://test", coverage=coverage)
        ResultSerializer.save(tmp_path, original)

        loaded = ResultSerializer.load(tmp_path)
        assert len(loaded.coverage.categories) == 1
        assert loaded.coverage.categories[0].owasp_id == "A1"

    def test_round_trip_findings(self, tmp_path: Path) -> None:
        finding = UnifiedFinding(
            title="Test Finding",
            severity=Severity.MEDIUM,
            owasp_ids=["A3"],
            source_module="tangle",
        )
        original = DanceRunResult(target="http://test", all_findings=[finding])
        ResultSerializer.save(tmp_path, original)

        loaded = ResultSerializer.load(tmp_path)
        assert len(loaded.all_findings) == 1
        assert loaded.all_findings[0].title == "Test Finding"
        assert loaded.all_findings[0].source_module == "tangle"

    def test_partial_results_load_gracefully(self, tmp_path: Path) -> None:
        """Only manifest + scan, no fuzz/tangle/swarm files."""
        scan = ScanResult(target="mcp://test", scan_type="scan")
        original = DanceRunResult(target="mcp://test", scan_result=scan)
        ResultSerializer.save(tmp_path, original)

        loaded = ResultSerializer.load(tmp_path)
        assert loaded.scan_result is not None
        assert loaded.fuzz_result is None
        assert loaded.tangle_result is None
        assert loaded.swarm_result is None

    def test_corrupt_json_handled_gracefully(self, tmp_path: Path) -> None:
        """Corrupt JSON should not crash the loader."""
        (tmp_path / "manifest.json").write_text("not valid json", encoding="utf-8")
        (tmp_path / "scan_result.json").write_text("{broken", encoding="utf-8")

        result = ResultSerializer.load(tmp_path)
        # Should return a result with None sub-results
        assert result.scan_result is None

    def test_manifest_target_preserved(self, tmp_path: Path) -> None:
        original = DanceRunResult(target="http://example.com:8000")
        ResultSerializer.save(tmp_path, original)

        loaded = ResultSerializer.load(tmp_path)
        assert loaded.target == "http://example.com:8000"
