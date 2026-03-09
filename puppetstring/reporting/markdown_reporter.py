"""Markdown report renderer — produces a Markdown report."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from puppetstring import __version__
from puppetstring.config import ReportConfig
from puppetstring.modules.owasp_audit.models import DanceRunResult

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def render_markdown_report(
    result: DanceRunResult,
    report_config: ReportConfig,
    output_dir: str | Path,
) -> Path:
    """Render a Markdown report.

    Args:
        result: The full audit result to render.
        report_config: Report configuration.
        output_dir: Directory to write the Markdown file to.

    Returns:
        Path to the generated Markdown file.
    """
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATES_DIR)),
        autoescape=False,  # noqa: S701 — Markdown output, not HTML
    )
    template = env.get_template("report.md.j2")

    context = _build_template_context(result, report_config)
    md = template.render(**context)

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"puppetstring_report_{datetime.now():%Y%m%d_%H%M%S}.md"
    out_path.write_text(md, encoding="utf-8")

    return out_path


def _build_template_context(
    result: DanceRunResult,
    report_config: ReportConfig,
) -> dict:
    """Build the Jinja2 template context."""
    categories = []
    for cat in result.coverage.categories:
        categories.append(
            {
                "owasp_id": cat.owasp_id,
                "name": cat.name,
                "status": cat.status.value,
                "findings_count": cat.findings_count,
                "highest_severity": cat.highest_severity.value if cat.highest_severity else None,
                "tested_by": cat.tested_by,
            }
        )

    findings = []
    for f in result.sorted_findings:
        findings.append(
            {
                "title": f.title,
                "severity": f.severity.value,
                "owasp_ids": f.owasp_ids,
                "source_module": f.source_module,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
            }
        )

    return {
        "target": result.target,
        "framework": result.framework,
        "report_date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "passive_only": result.passive_only,
        "company_name": report_config.company_name,
        "version": __version__,
        "risk_score": result.coverage.risk_score,
        "coverage_pct": result.coverage.coverage_percentage,
        "total_findings": result.coverage.total_findings,
        "severity_counts": result.severity_summary,
        "categories": categories,
        "findings": findings,
        "include_transcripts": report_config.include_full_transcripts,
        "transcripts": {},
    }
