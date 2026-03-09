"""Report generator — orchestrator for the `unravel` command.

Loads results from disk, optionally generates remediation, and dispatches
to the appropriate renderer (HTML, JSON, or Markdown).
"""

from __future__ import annotations

from pathlib import Path

from puppetstring.config import PuppetStringConfig, ReportConfig
from puppetstring.modules.owasp_audit.mapper import OWASPMapper
from puppetstring.modules.owasp_audit.models import DanceRunResult
from puppetstring.modules.owasp_audit.serializer import ResultSerializer
from puppetstring.reporting.html_reporter import render_html_report
from puppetstring.reporting.json_reporter import render_json_report
from puppetstring.reporting.markdown_reporter import render_markdown_report
from puppetstring.reporting.remediation import RemediationGenerator
from puppetstring.utils.logging import get_logger

logger = get_logger(__name__)


class UnravelEngine:
    """Top-level orchestrator for report generation."""

    def __init__(self, config: PuppetStringConfig | None = None) -> None:
        self._config = config or PuppetStringConfig()

    async def run(
        self,
        results_dir: str | Path,
        output_format: str = "html",
        output_dir: str | Path = "./puppetstring_reports",
        include_transcripts: bool = True,
    ) -> Path:
        """Generate a report from results on disk.

        Args:
            results_dir: Directory containing PuppetString result JSON files.
            output_format: Report format — "html", "json", or "markdown".
            output_dir: Directory to write the report to.
            include_transcripts: Whether to include conversation transcripts.

        Returns:
            Path to the generated report file.
        """
        # Load results from disk
        result = ResultSerializer.load(results_dir)

        # Re-compute coverage if not present
        if not result.coverage.categories:
            coverage, findings = OWASPMapper.map_coverage(
                scan=result.scan_result,
                fuzz=result.fuzz_result,
                tangle=result.tangle_result,
                swarm=result.swarm_result,
            )
            result.coverage = coverage
            result.all_findings = findings

        # Generate remediation for findings that don't have it
        report_config = self._config.report
        if report_config.include_remediation:
            await self._add_remediation(result)

        # Override transcript setting
        effective_report_config = ReportConfig(
            include_full_transcripts=include_transcripts,
            include_remediation=report_config.include_remediation,
            company_name=report_config.company_name,
        )

        # Dispatch to renderer
        if output_format == "html":
            return render_html_report(result, effective_report_config, output_dir)
        elif output_format == "json":
            return render_json_report(result, effective_report_config, output_dir)
        elif output_format == "markdown":
            return render_markdown_report(result, effective_report_config, output_dir)
        else:
            msg = f"Unknown report format: {output_format}"
            raise ValueError(msg)

    async def _add_remediation(self, result: DanceRunResult) -> None:
        """Add remediation text to findings that don't have it."""
        gen = RemediationGenerator(model=self._config.general.llm_model)
        for finding in result.all_findings:
            if not finding.remediation:
                try:
                    finding.remediation = await gen.generate(finding)
                except Exception as exc:  # noqa: BLE001
                    logger.debug("Remediation generation failed: %s", exc)
                    finding.remediation = gen.generate_sync(finding)
