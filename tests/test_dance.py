"""Tests for the dance command (OWASP audit engine)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from puppetstring.config import PuppetStringConfig
from puppetstring.core.models import Finding, ScanResult, Severity
from puppetstring.modules.owasp_audit.engine import DanceEngine
from puppetstring.modules.owasp_audit.models import (
    DanceRunResult,
)
from puppetstring.modules.owasp_audit.serializer import ResultSerializer


class TestDanceEnginePassive:
    """Tests for passive-only mode."""

    @pytest.mark.asyncio
    async def test_passive_no_existing_results(self, tmp_path: Path) -> None:
        config = PuppetStringConfig()
        config.dance.results_dir = str(tmp_path / "results")

        engine = DanceEngine(target="http://test", config=config)
        result = await engine.run(passive_only=True)

        assert result.passive_only is True
        assert result.scan_result is None
        assert result.fuzz_result is None
        assert result.coverage is not None

    @pytest.mark.asyncio
    async def test_passive_loads_existing_results(self, tmp_path: Path) -> None:
        # Save some results first
        results_dir = tmp_path / "results"
        scan = ScanResult(target="mcp://test", scan_type="scan")
        scan.findings = [
            Finding(title="Test", severity=Severity.HIGH, owasp_ids=["A1"]),
        ]
        original = DanceRunResult(target="mcp://test", scan_result=scan)
        ResultSerializer.save(results_dir, original)

        config = PuppetStringConfig()
        config.dance.results_dir = str(results_dir)

        engine = DanceEngine(target="mcp://test", config=config)
        result = await engine.run(passive_only=True)

        assert result.scan_result is not None
        assert len(result.scan_result.findings) == 1

    @pytest.mark.asyncio
    async def test_passive_computes_coverage(self, tmp_path: Path) -> None:
        results_dir = tmp_path / "results"
        scan = ScanResult(target="mcp://test", scan_type="scan")
        original = DanceRunResult(target="mcp://test", scan_result=scan)
        ResultSerializer.save(results_dir, original)

        config = PuppetStringConfig()
        config.dance.results_dir = str(results_dir)

        engine = DanceEngine(target="mcp://test", config=config)
        result = await engine.run(passive_only=True)

        assert result.coverage.coverage_percentage > 0
        assert len(result.coverage.categories) == 10


class TestDanceEngineActive:
    """Tests for active mode with mocked sub-engines."""

    @pytest.mark.asyncio
    async def test_active_mcp_target_runs_scan(self, tmp_path: Path) -> None:
        config = PuppetStringConfig()
        config.dance.results_dir = str(tmp_path / "results")

        scan_result = ScanResult(target="mcp://test:3000", scan_type="scan")

        with patch(
            "puppetstring.modules.owasp_audit.engine.DanceEngine._run_scan",
            new_callable=AsyncMock,
            return_value=scan_result,
        ):
            engine = DanceEngine(target="mcp://test:3000", config=config)
            result = await engine.run(passive_only=False)

        assert result.scan_result is not None
        assert result.fuzz_result is None  # MCP targets don't run fuzz

    @pytest.mark.asyncio
    async def test_active_http_target_runs_fuzz_and_tangle(self, tmp_path: Path) -> None:
        config = PuppetStringConfig()
        config.dance.results_dir = str(tmp_path / "results")

        from puppetstring.core.models import FuzzRunResult  # noqa: PLC0415
        from puppetstring.modules.prompt_injection.models import TangleRunResult  # noqa: PLC0415

        fuzz_result = FuzzRunResult(target="http://test:8000", fuzz_type="all")
        tangle_result = TangleRunResult(target="http://test:8000", vector="all")

        with (
            patch(
                "puppetstring.modules.owasp_audit.engine.DanceEngine._run_fuzz",
                new_callable=AsyncMock,
                return_value=fuzz_result,
            ),
            patch(
                "puppetstring.modules.owasp_audit.engine.DanceEngine._run_tangle",
                new_callable=AsyncMock,
                return_value=tangle_result,
            ),
        ):
            engine = DanceEngine(target="http://test:8000", config=config)
            result = await engine.run(passive_only=False)

        assert result.scan_result is None  # HTTP targets don't run scan
        assert result.fuzz_result is not None
        assert result.tangle_result is not None

    @pytest.mark.asyncio
    async def test_module_failure_continues(self, tmp_path: Path) -> None:
        """If one module fails, others should still run."""
        config = PuppetStringConfig()
        config.dance.results_dir = str(tmp_path / "results")

        from puppetstring.core.models import FuzzRunResult  # noqa: PLC0415
        from puppetstring.modules.prompt_injection.models import TangleRunResult  # noqa: PLC0415

        # Fuzz fails, tangle succeeds
        fuzz_result = FuzzRunResult(
            target="http://test", fuzz_type="all", error="Connection refused"
        )
        tangle_result = TangleRunResult(target="http://test", vector="all")

        with (
            patch(
                "puppetstring.modules.owasp_audit.engine.DanceEngine._run_fuzz",
                new_callable=AsyncMock,
                return_value=fuzz_result,
            ),
            patch(
                "puppetstring.modules.owasp_audit.engine.DanceEngine._run_tangle",
                new_callable=AsyncMock,
                return_value=tangle_result,
            ),
        ):
            engine = DanceEngine(target="http://test", config=config)
            result = await engine.run(passive_only=False)

        assert result.fuzz_result is not None
        assert result.tangle_result is not None
        assert "fuzz" in result.errors

    @pytest.mark.asyncio
    async def test_results_saved_to_disk(self, tmp_path: Path) -> None:
        config = PuppetStringConfig()
        results_dir = tmp_path / "results"
        config.dance.results_dir = str(results_dir)

        scan_result = ScanResult(target="mcp://test:3000", scan_type="scan")

        with patch(
            "puppetstring.modules.owasp_audit.engine.DanceEngine._run_scan",
            new_callable=AsyncMock,
            return_value=scan_result,
        ):
            engine = DanceEngine(target="mcp://test:3000", config=config)
            await engine.run(passive_only=False)

        assert results_dir.is_dir()
        assert (results_dir / "manifest.json").is_file()


class TestDanceRunResult:
    """Tests for DanceRunResult properties."""

    def test_has_critical_or_high_true(self) -> None:
        result = DanceRunResult(
            target="test",
            all_findings=[
                UnifiedFinding(title="T", severity=Severity.HIGH, owasp_ids=["A1"]),
            ],
        )
        assert result.has_critical_or_high is True

    def test_has_critical_or_high_false(self) -> None:
        result = DanceRunResult(
            target="test",
            all_findings=[
                UnifiedFinding(title="T", severity=Severity.LOW, owasp_ids=["A1"]),
            ],
        )
        assert result.has_critical_or_high is False

    def test_severity_summary(self) -> None:
        result = DanceRunResult(
            target="test",
            all_findings=[
                UnifiedFinding(title="T1", severity=Severity.HIGH, owasp_ids=["A1"]),
                UnifiedFinding(title="T2", severity=Severity.HIGH, owasp_ids=["A1"]),
                UnifiedFinding(title="T3", severity=Severity.LOW, owasp_ids=["A1"]),
            ],
        )
        summary = result.severity_summary
        assert summary["high"] == 2
        assert summary["low"] == 1
        assert summary["critical"] == 0


# Import needed for inline fixtures
from puppetstring.modules.owasp_audit.models import UnifiedFinding  # noqa: E402
