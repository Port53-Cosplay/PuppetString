"""JSON report renderer — produces a CI-friendly JSON report."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from puppetstring import __version__
from puppetstring.config import ReportConfig
from puppetstring.modules.owasp_audit.models import DanceRunResult


def render_json_report(
    result: DanceRunResult,
    report_config: ReportConfig,
    output_dir: str | Path,
) -> Path:
    """Render a CI-friendly JSON report.

    Includes an exit_code field (0 = no critical/high findings, 1 = has them)
    for GitHub Actions and other CI systems.

    Args:
        result: The full audit result to render.
        report_config: Report configuration.
        output_dir: Directory to write the JSON file to.

    Returns:
        Path to the generated JSON file.
    """
    report_data = _build_report_data(result, report_config)

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"puppetstring_report_{datetime.now():%Y%m%d_%H%M%S}.json"
    out_path.write_text(
        json.dumps(report_data, indent=2, default=str),
        encoding="utf-8",
    )

    return out_path


def _build_report_data(
    result: DanceRunResult,
    report_config: ReportConfig,
) -> dict:
    """Build the JSON report data structure."""
    severity_counts = result.severity_summary

    findings = []
    for f in result.sorted_findings:
        finding_data = {
            "title": f.title,
            "severity": f.severity.value,
            "owasp_ids": f.owasp_ids,
            "source_module": f.source_module,
            "description": f.description,
            "evidence": f.evidence,
        }
        if f.remediation:
            finding_data["remediation"] = f.remediation
        findings.append(finding_data)

    coverage_items = []
    for cat in result.coverage.categories:
        coverage_items.append(
            {
                "owasp_id": cat.owasp_id,
                "name": cat.name,
                "status": cat.status.value,
                "findings_count": cat.findings_count,
                "highest_severity": cat.highest_severity.value if cat.highest_severity else None,
                "tested_by": cat.tested_by,
            }
        )

    return {
        "version": __version__,
        "report_date": datetime.now().isoformat(),
        "target": result.target,
        "framework": result.framework,
        "passive_only": result.passive_only,
        "company_name": report_config.company_name,
        "exit_code": 1 if result.has_critical_or_high else 0,
        "summary": {
            "risk_score": result.coverage.risk_score,
            "coverage_percentage": result.coverage.coverage_percentage,
            "total_findings": result.coverage.total_findings,
            "severity_counts": severity_counts,
        },
        "coverage": coverage_items,
        "findings": findings,
    }
