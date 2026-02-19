"""PuppetString CLI — the main entry point for all commands.

Commands use a puppet metaphor:
    pull     — Pull the strings: MCP scanning + workflow fuzzing
    tangle   — Tangle the inputs: indirect prompt injection testing
    cut      — Cut the strings: agent-to-agent attack simulation
    dance    — Make it dance: full OWASP agentic AI audit
    unravel  — Unravel the findings: generate reports
    stage    — Set the stage: deploy/teardown vulnerable test targets
"""

import asyncio

import typer
from rich.console import Console
from rich.panel import Panel

from puppetstring import __version__
from puppetstring.modules.mcp_scanner.scanner import MCP_SCAN_TYPES

# ── App setup ──────────────────────────────────────────────────────
# Typer() creates the root CLI app. Each function decorated with
# @app.command() becomes a subcommand (e.g., `puppetstring pull`).
# rich_markup_mode="rich" lets us use Rich formatting in help text.
app = typer.Typer(
    name="puppetstring",
    help=(
        "[bold]PuppetString[/bold] — Red team toolkit for AI agents, "
        "agentic workflows, and MCP servers.\n\n"
        '[italic]"Because your AI agent shouldn\'t be your biggest insider threat."[/italic]'
    ),
    rich_markup_mode="rich",
    no_args_is_help=True,
)

console = Console()

# ── Responsible use warning ────────────────────────────────────────
_RESPONSIBLE_USE_WARNING = (
    "[yellow bold]WARNING:[/yellow bold] PuppetString is a security testing tool.\n"
    "Only use it against systems you own or have explicit authorization to test.\n"
    "Run [bold]puppetstring --responsible-use[/bold] for our full policy."
)


def _show_banner() -> None:
    """Display the PuppetString banner with version and responsible use notice."""
    console.print(
        Panel(
            f"[bold magenta]PuppetString[/bold magenta] v{__version__}\n\n"
            f"{_RESPONSIBLE_USE_WARNING}",
            border_style="magenta",
            expand=False,
        )
    )


def _version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"PuppetString v{__version__}")
        raise typer.Exit()


def _responsible_use_callback(value: bool) -> None:
    """Print responsible use policy and exit."""
    if value:
        console.print(
            Panel(
                "[bold]Responsible Use Policy[/bold]\n\n"
                "PuppetString is designed for [bold]authorized security testing only[/bold].\n\n"
                "1. Only test systems you own or have written authorization to test.\n"
                "2. Start with the included vulnerable test targets (puppetstring stage).\n"
                "3. Never run against production systems without stakeholder approval.\n"
                "4. Follow responsible disclosure for any vulnerabilities you discover.\n"
                "5. Handle captured data (system prompts, tool configs, logs) per your\n"
                "   organization's data classification policies.\n\n"
                "See RESPONSIBLE_USE.md for the full policy.",
                title="PuppetString Responsible Use",
                border_style="yellow",
                expand=False,
            )
        )
        raise typer.Exit()


# ── Global options ─────────────────────────────────────────────────
# These are flags that work on the root command itself, before any subcommand.
# The callback= on the Typer app lets us define them.
@app.callback()
def main(
    version: bool | None = typer.Option(
        None,
        "--version",
        "-v",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
    responsible_use: bool | None = typer.Option(
        None,
        "--responsible-use",
        help="Show the responsible use policy and exit.",
        callback=_responsible_use_callback,
        is_eager=True,
    ),
) -> None:
    """PuppetString — Red team toolkit for AI agents and MCP servers."""


# ── Commands ───────────────────────────────────────────────────────
# Each command is a placeholder right now. In later phases, they'll call into
# the actual module logic. For Phase 0 we just need `puppetstring --help`
# to show all commands and each command to print "not implemented yet."


@app.command()
def pull(
    target: str = typer.Option(
        ...,
        "--target",
        "-t",
        help="Target to test (e.g., mcp://localhost:3000, http://localhost:8000).",
    ),
    scan_type: str = typer.Option(
        "all",
        "--type",
        help=(
            "What to test. For MCP scanning: scan, tools, auth, permissions, inputs, config. "
            "For workflow fuzzing: tool-abuse, memory-poison, boundary, chain, all."
        ),
    ),
    payloads: str | None = typer.Option(
        None,
        "--payloads",
        "-p",
        help="Path to a custom YAML payloads file.",
    ),
    output: str = typer.Option(
        "terminal",
        "--output",
        "-o",
        help="Output format: terminal, html, json, markdown.",
    ),
) -> None:
    """[bold magenta]Pull the strings[/bold magenta] — MCP scanning + workflow fuzzing.

    Connects to a target (MCP server or AI agent), discovers its tools and
    capabilities, and tests them for security weaknesses.

    \b
    Examples:
        puppetstring pull -t mcp://localhost:3000
        puppetstring pull -t mcp://localhost:3000 --type auth
        puppetstring pull -t http://localhost:8000 --type tool-abuse
        puppetstring pull -t http://localhost:8000 --type all --payloads ./custom.yaml
    """
    _show_banner()
    console.print(f"\n[bold]Target:[/bold] {target}")
    console.print(f"[bold]Type:[/bold] {scan_type}")

    valid_fuzz_types = {"tool-abuse", "memory-poison", "boundary", "chain"}
    all_valid_types = MCP_SCAN_TYPES | valid_fuzz_types | {"all"}

    if scan_type not in all_valid_types:
        console.print(
            f"\n[bold red]Unknown scan type:[/bold red] '{scan_type}'\n"
            f"[bold]Valid types:[/bold] {', '.join(sorted(all_valid_types))}"
        )
        raise typer.Exit(code=1)

    if scan_type in MCP_SCAN_TYPES:
        # MCP scanning — Phase 1
        from puppetstring.config import load_config  # noqa: PLC0415
        from puppetstring.modules.mcp_scanner.scanner import MCPScanner  # noqa: PLC0415
        from puppetstring.reporting.terminal import render_scan_result  # noqa: PLC0415
        from puppetstring.utils.logging import setup_logging  # noqa: PLC0415

        setup_logging(verbose=False)
        config = load_config()
        scanner = MCPScanner(target=target, scan_config=config.scan)

        try:
            result = asyncio.run(scanner.run(scan_type=scan_type))
        except KeyboardInterrupt:
            console.print("\n[yellow]Scan interrupted by user.[/yellow]")
            raise typer.Exit(code=1) from None

        if output == "terminal":
            render_scan_result(result)
        else:
            console.print(f"\n[yellow]Output format '{output}' not implemented yet.[/yellow]")

        if result.error:
            raise typer.Exit(code=1)
    else:
        # Workflow fuzzing — Phase 2
        from pathlib import Path  # noqa: PLC0415

        from puppetstring.adapters.http_adapter import HTTPAgentAdapter  # noqa: PLC0415
        from puppetstring.config import load_config  # noqa: PLC0415
        from puppetstring.modules.workflow_fuzzer.fuzzer import WorkflowFuzzer  # noqa: PLC0415
        from puppetstring.reporting.terminal import render_fuzz_result  # noqa: PLC0415
        from puppetstring.utils.logging import setup_logging  # noqa: PLC0415

        setup_logging(verbose=False)
        config = load_config()

        custom_path = Path(payloads) if payloads else None

        async def _run_fuzz() -> None:
            adapter = HTTPAgentAdapter(target=target, timeout=config.fuzz.timeout)
            async with adapter:
                fuzzer = WorkflowFuzzer(
                    adapter=adapter,
                    config=config.fuzz,
                    custom_payloads_path=custom_path,
                )
                fuzz_result = await fuzzer.run(fuzz_type=scan_type)

            if output == "terminal":
                render_fuzz_result(fuzz_result)
            else:
                console.print(f"\n[yellow]Output format '{output}' not implemented yet.[/yellow]")

            if fuzz_result.exploited_count > 0:
                raise typer.Exit(code=1)

        try:
            asyncio.run(_run_fuzz())
        except KeyboardInterrupt:
            console.print("\n[yellow]Fuzzing interrupted by user.[/yellow]")
            raise typer.Exit(code=1) from None
        except ConnectionError as exc:
            console.print(f"\n[bold red]Connection failed:[/bold red] {exc}")
            raise typer.Exit(code=1) from None


@app.command()
def tangle(
    target: str = typer.Option(
        ...,
        "--target",
        "-t",
        help="Target agent to test (e.g., http://localhost:8000, langchain://localhost:8000).",
    ),
    vector: str = typer.Option(
        "all",
        "--vector",
        help="Injection vector: document, tool-output, database, all.",
    ),
    goal: str | None = typer.Option(
        None,
        "--goal",
        "-g",
        help='What the injection should achieve (e.g., "exfiltrate the system prompt").',
    ),
    document: str | None = typer.Option(
        None,
        "--document",
        "-d",
        help="Path to a document to inject into (for --vector document).",
    ),
    output: str = typer.Option(
        "terminal",
        "--output",
        "-o",
        help="Output format: terminal, html, json, markdown.",
    ),
) -> None:
    """[bold magenta]Tangle the inputs[/bold magenta] — indirect prompt injection testing.

    Tests whether an AI agent can be manipulated through adversarial content
    hidden in the data sources it consumes — documents, tool outputs, databases.

    \b
    Examples:
        puppetstring tangle -t http://localhost:8000 --vector document -d ./test.pdf
        puppetstring tangle -t mcp://localhost:3000 --vector tool-output --goal "exfiltrate data"
        puppetstring tangle -t http://localhost:8000 --vector all
    """
    _show_banner()
    console.print(f"\n[bold]Target:[/bold] {target}")
    console.print(f"[bold]Vector:[/bold] {vector}")
    if goal:
        console.print(f"[bold]Goal:[/bold] {goal}")
    console.print("\n[yellow]Not implemented yet — coming in Phase 3.[/yellow]")


@app.command()
def cut(
    target: str = typer.Option(
        ...,
        "--target",
        "-t",
        help="Target multi-agent system (e.g., crewai://localhost:8001).",
    ),
    attack_type: str = typer.Option(
        "all",
        "--type",
        help="Attack type: trust, memory, delegation, rogue, all.",
    ),
    output: str = typer.Option(
        "terminal",
        "--output",
        "-o",
        help="Output format: terminal, html, json, markdown.",
    ),
) -> None:
    """[bold magenta]Cut the strings[/bold magenta] — agent-to-agent attack simulation.

    Tests multi-agent systems for cross-agent attacks: trust exploitation,
    shared memory poisoning, delegation abuse, and rogue agent injection.

    \b
    Examples:
        puppetstring cut -t crewai://localhost:8001 --type trust
        puppetstring cut -t crewai://localhost:8001 --type all
    """
    _show_banner()
    console.print(f"\n[bold]Target:[/bold] {target}")
    console.print(f"[bold]Attack type:[/bold] {attack_type}")
    console.print("\n[yellow]Not implemented yet — coming in Phase 4.[/yellow]")


@app.command()
def dance(
    target: str = typer.Option(
        ...,
        "--target",
        "-t",
        help="Target to audit (e.g., mcp://localhost:3000).",
    ),
    framework: str = typer.Option(
        "owasp-agentic-2026",
        "--framework",
        "-f",
        help="Audit framework to use.",
    ),
    passive_only: bool = typer.Option(
        False,
        "--passive-only",
        help="Only generate a coverage gap report — no active testing.",
    ),
    output: str = typer.Option(
        "terminal",
        "--output",
        "-o",
        help="Output format: terminal, html, json, markdown.",
    ),
) -> None:
    """[bold magenta]Make it dance[/bold magenta] — full OWASP agentic AI audit.

    Runs a comprehensive security audit covering all 10 items from the OWASP
    Top 10 for Agentic AI Applications (2026). Orchestrates the other modules
    and produces a unified coverage report.

    \b
    Examples:
        puppetstring dance -t mcp://localhost:3000
        puppetstring dance -t mcp://localhost:3000 --passive-only
    """
    _show_banner()
    console.print(f"\n[bold]Target:[/bold] {target}")
    console.print(f"[bold]Framework:[/bold] {framework}")
    if passive_only:
        console.print("[bold]Mode:[/bold] Passive only (no active testing)")
    console.print("\n[yellow]Not implemented yet — coming in Phase 5.[/yellow]")


@app.command()
def unravel(
    results_dir: str = typer.Option(
        "./puppetstring_results",
        "--results",
        "-r",
        help="Path to PuppetString results directory.",
    ),
    output_format: str = typer.Option(
        "html",
        "--format",
        "-f",
        help="Report format: html, json, markdown.",
    ),
    output_dir: str = typer.Option(
        "./puppetstring_reports",
        "--output",
        "-o",
        help="Directory to write reports to.",
    ),
    include_transcripts: bool = typer.Option(
        True,
        "--transcripts/--no-transcripts",
        help="Include full conversation transcripts in the report.",
    ),
) -> None:
    """[bold magenta]Unravel the findings[/bold magenta] — generate reports.

    Takes raw PuppetString results and generates professional reports in
    HTML, JSON, or Markdown format with OWASP mapping, severity ratings,
    and remediation suggestions.

    \b
    Examples:
        puppetstring unravel -r ./puppetstring_results -f html
        puppetstring unravel -r ./puppetstring_results -f json --no-transcripts
    """
    _show_banner()
    console.print(f"\n[bold]Results:[/bold] {results_dir}")
    console.print(f"[bold]Format:[/bold] {output_format}")
    console.print(f"[bold]Output:[/bold] {output_dir}")
    console.print("\n[yellow]Not implemented yet — coming in Phase 5.[/yellow]")


@app.command()
def stage(
    action: str = typer.Argument(
        help="What to do: up (deploy targets), down (teardown), status (check what's running).",
    ),
    target: str = typer.Option(
        "all",
        "--target",
        "-t",
        help="Which test target: mcp, agent, swarm, all.",
    ),
) -> None:
    """[bold magenta]Set the stage[/bold magenta] — deploy/teardown vulnerable test targets.

    Manages the intentionally vulnerable test targets that ship with
    PuppetString. These are practice dummies for testing — an insecure
    MCP server, a vulnerable AI agent, and a vulnerable multi-agent system.

    \b
    Examples:
        puppetstring stage up                  # Deploy all test targets
        puppetstring stage up -t mcp           # Deploy only the MCP server
        puppetstring stage down                # Teardown all targets
        puppetstring stage status              # Check what's running
    """
    _show_banner()
    console.print(f"\n[bold]Action:[/bold] {action}")
    console.print(f"[bold]Target:[/bold] {target}")
    console.print("\n[yellow]Not implemented yet — coming in Phase 1.[/yellow]")
