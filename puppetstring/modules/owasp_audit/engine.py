"""Dance engine — orchestrates all PuppetString modules for a full OWASP audit.

Runs sub-modules in sequence (scan -> fuzz -> tangle -> cut), collects results,
maps to the OWASP Top 10 coverage matrix, and saves results to disk.
Each module runs in a try/except so one failure doesn't abort the whole audit.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from puppetstring.config import PuppetStringConfig
from puppetstring.modules.owasp_audit.mapper import OWASPMapper
from puppetstring.modules.owasp_audit.models import DanceRunResult
from puppetstring.modules.owasp_audit.serializer import ResultSerializer
from puppetstring.utils.logging import get_logger

logger = get_logger(__name__)


class DanceEngine:
    """Orchestrates all PuppetString modules for a comprehensive OWASP audit."""

    def __init__(
        self,
        target: str,
        config: PuppetStringConfig | None = None,
    ) -> None:
        self._target = target
        self._config = config or PuppetStringConfig()

    async def run(self, passive_only: bool = False) -> DanceRunResult:
        """Run the full OWASP audit.

        Args:
            passive_only: If True, load existing results from disk instead
                of running active tests. Produces a coverage gap report.

        Returns:
            DanceRunResult with all sub-results, OWASP coverage, and findings.
        """
        result = DanceRunResult(
            target=self._target,
            passive_only=passive_only,
            started_at=datetime.now(),
        )

        if passive_only:
            result = await self._run_passive(result)
        else:
            result = await self._run_active(result)

        # Map findings to OWASP coverage
        coverage, all_findings = OWASPMapper.map_coverage(
            scan=result.scan_result,
            fuzz=result.fuzz_result,
            tangle=result.tangle_result,
            swarm=result.swarm_result,
        )
        result.coverage = coverage
        result.all_findings = all_findings
        result.finished_at = datetime.now()

        # Save results to disk
        results_dir = self._config.dance.results_dir
        try:
            ResultSerializer.save(results_dir, result)
        except OSError as exc:
            logger.warning("Failed to save results: %s", exc)
            result.errors["serializer"] = str(exc)

        return result

    async def _run_passive(self, result: DanceRunResult) -> DanceRunResult:
        """Load existing results from disk."""
        results_dir = Path(self._config.dance.results_dir)
        if not results_dir.is_dir():
            logger.info("No existing results found at %s", results_dir)
            return result

        try:
            loaded = ResultSerializer.load(results_dir)
            result.scan_result = loaded.scan_result
            result.fuzz_result = loaded.fuzz_result
            result.tangle_result = loaded.tangle_result
            result.swarm_result = loaded.swarm_result
        except FileNotFoundError:
            logger.info("Results directory not found: %s", results_dir)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to load existing results: %s", exc)
            result.errors["loader"] = str(exc)

        return result

    async def _run_active(self, result: DanceRunResult) -> DanceRunResult:
        """Run all enabled sub-modules actively."""
        dance_config = self._config.dance

        # Determine which modules to run based on target URL
        is_mcp = self._target.startswith("mcp://")

        # MCP scan
        if dance_config.run_scan and is_mcp:
            result.scan_result = await self._run_scan()
            if result.scan_result and result.scan_result.error:
                result.errors["scan"] = result.scan_result.error

        # Workflow fuzz (HTTP targets)
        if dance_config.run_fuzz and not is_mcp:
            result.fuzz_result = await self._run_fuzz()
            if result.fuzz_result and result.fuzz_result.error:
                result.errors["fuzz"] = result.fuzz_result.error

        # Tangle (HTTP targets for live mode)
        if dance_config.run_tangle and not is_mcp:
            result.tangle_result = await self._run_tangle()
            if result.tangle_result and result.tangle_result.error:
                result.errors["tangle"] = result.tangle_result.error

        # Cut (needs swarm adapter — skip if no swarm target)
        # Agent-to-agent attacks need a multi-agent target; skip for
        # simple HTTP/MCP targets since no SwarmAdapter is available yet.

        return result

    async def _run_scan(self):
        """Run MCP scanner."""
        from puppetstring.modules.mcp_scanner.scanner import MCPScanner  # noqa: PLC0415

        try:
            scanner = MCPScanner(target=self._target, scan_config=self._config.scan)
            return await scanner.run(scan_type="scan")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Scan module failed: %s", exc)
            from puppetstring.core.models import ScanResult  # noqa: PLC0415

            return ScanResult(target=self._target, scan_type="scan", error=str(exc))

    async def _run_fuzz(self):
        """Run workflow fuzzer."""
        from puppetstring.adapters.http_adapter import HTTPAgentAdapter  # noqa: PLC0415
        from puppetstring.modules.workflow_fuzzer.fuzzer import WorkflowFuzzer  # noqa: PLC0415

        try:
            adapter = HTTPAgentAdapter(target=self._target, timeout=self._config.fuzz.timeout)
            async with adapter:
                fuzzer = WorkflowFuzzer(adapter=adapter, config=self._config.fuzz)
                return await fuzzer.run(fuzz_type="all")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Fuzz module failed: %s", exc)
            from puppetstring.core.models import FuzzRunResult  # noqa: PLC0415

            return FuzzRunResult(target=self._target, fuzz_type="all", error=str(exc))

    async def _run_tangle(self):
        """Run prompt injection engine."""
        from puppetstring.adapters.http_adapter import HTTPAgentAdapter  # noqa: PLC0415
        from puppetstring.modules.prompt_injection.engine import TangleEngine  # noqa: PLC0415

        try:
            adapter = HTTPAgentAdapter(target=self._target, timeout=self._config.fuzz.timeout)
            async with adapter:
                engine = TangleEngine(
                    adapter=adapter,
                    judge_model=self._config.inject.judge_model,
                    delay_between_injections=self._config.inject.delay_between_injections,
                    max_injections=self._config.inject.max_injections,
                )
                return await engine.run_live_mode(vector="all", goal="")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Tangle module failed: %s", exc)
            from puppetstring.modules.prompt_injection.models import (  # noqa: PLC0415
                TangleRunResult,
            )

            return TangleRunResult(target=self._target, vector="all", error=str(exc))
