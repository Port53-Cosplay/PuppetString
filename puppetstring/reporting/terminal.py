"""Terminal reporter — renders ScanResult as formatted Rich output.

Produces:
    - Header panel with target info
    - Tools summary table
    - Findings table (color-coded by severity)
    - Summary panel with counts and scan duration
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from puppetstring.core.models import Finding, ScanResult, Severity

console = Console()

_SEVERITY_STYLES: dict[str, str] = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}


def render_scan_result(result: ScanResult) -> None:
    """Print a full scan report to the terminal."""
    _render_header(result)

    if result.error:
        console.print(f"\n[bold red]Scan error:[/bold red] {result.error}\n")
        return

    if result.tools:
        _render_tools_table(result)

    if result.findings:
        _render_findings_table(result)

    _render_summary(result)


def _render_header(result: ScanResult) -> None:
    """Print the scan header panel."""
    console.print()
    console.print(
        Panel(
            f"[bold]Target:[/bold] {result.target}\n"
            f"[bold]Scan type:[/bold] {result.scan_type}\n"
            f"[bold]Started:[/bold] {result.started_at:%Y-%m-%d %H:%M:%S}",
            title="[bold magenta]PuppetString MCP Scan[/bold magenta]",
            border_style="magenta",
            expand=False,
        )
    )


def _render_tools_table(result: ScanResult) -> None:
    """Print the discovered tools table."""
    table = Table(
        title=f"\n[bold]Discovered Tools ({len(result.tools)})[/bold]",
        show_header=True,
        header_style="bold cyan",
        expand=False,
    )
    table.add_column("Tool", style="bold")
    table.add_column("Description", max_width=50)
    table.add_column("Permission")
    table.add_column("Dangerous?")

    for tool in result.tools:
        danger_text = (
            Text("YES", style="bold red") if tool.is_dangerous else Text("no", style="green")
        )
        perm_style = {
            "code-execution": "bold red",
            "destructive": "red",
            "read-write": "yellow",
            "read-only": "green",
            "unknown": "dim",
        }.get(tool.permission_level.value, "dim")

        table.add_row(
            tool.name,
            (tool.description or "[dim]no description[/dim]")[:50],
            Text(tool.permission_level.value, style=perm_style),
            danger_text,
        )

    console.print(table)


def _render_findings_table(result: ScanResult) -> None:
    """Print the findings table, sorted by severity."""
    table = Table(
        title=f"\n[bold]Security Findings ({len(result.findings)})[/bold]",
        show_header=True,
        header_style="bold cyan",
        expand=False,
    )
    table.add_column("#", style="dim", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Finding")
    table.add_column("OWASP", width=10)
    table.add_column("Tool", width=15)

    for i, finding in enumerate(result.sorted_findings, 1):
        sev_style = _SEVERITY_STYLES.get(finding.severity.value, "")
        owasp = ", ".join(finding.owasp_ids) if finding.owasp_ids else "-"

        table.add_row(
            str(i),
            Text(finding.severity.value.upper(), style=sev_style),
            finding.title,
            owasp,
            finding.tool_name or "-",
        )

    console.print(table)

    # Print details for critical and high findings
    for finding in result.sorted_findings:
        if finding.severity in (Severity.CRITICAL, Severity.HIGH):
            _render_finding_detail(finding)


def _render_finding_detail(finding: Finding) -> None:
    """Print expanded detail for a single high/critical finding."""
    sev_style = _SEVERITY_STYLES.get(finding.severity.value, "")
    border = "red" if finding.severity == Severity.CRITICAL else "yellow"

    lines = [f"[{sev_style}]{finding.severity.value.upper()}[/{sev_style}] {finding.title}"]
    if finding.description:
        lines.append(f"\n{finding.description}")
    if finding.evidence:
        lines.append(f"\n[bold]Evidence:[/bold] {finding.evidence}")
    if finding.remediation:
        lines.append(f"\n[bold]Remediation:[/bold] {finding.remediation}")

    console.print(
        Panel(
            "\n".join(lines),
            border_style=border,
            expand=False,
        )
    )


def _render_summary(result: ScanResult) -> None:
    """Print the summary panel with counts and timing."""
    counts = result.summary
    total = sum(counts.values())

    summary_lines = [
        f"[bold]Tools discovered:[/bold] {len(result.tools)}",
        f"[bold]Total findings:[/bold] {total}",
        "",
        f"  [bold red]Critical:[/bold red] {counts.get('critical', 0)}",
        f"  [red]High:[/red] {counts.get('high', 0)}",
        f"  [yellow]Medium:[/yellow] {counts.get('medium', 0)}",
        f"  [blue]Low:[/blue] {counts.get('low', 0)}",
        f"  [dim]Info:[/dim] {counts.get('info', 0)}",
        "",
        f"[bold]Scan duration:[/bold] {result.duration_seconds:.1f}s",
    ]

    console.print()
    console.print(
        Panel(
            "\n".join(summary_lines),
            title="[bold]Scan Summary[/bold]",
            border_style="green" if counts.get("critical", 0) == 0 else "red",
            expand=False,
        )
    )
    console.print()
