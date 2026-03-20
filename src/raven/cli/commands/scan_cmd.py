"""
RAVEN ``scan`` CLI command.

Performs vulnerability scanning on a binary using the Analyst agent
and pattern matching engine.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from raven.cli.output import (
    output_console,
    print_error,
    print_info,
    print_success,
    print_warning,
)
from raven.core.logger import get_logger

logger = get_logger("cli.scan")


# ---------------------------------------------------------------------------
# Severity display helpers
# ---------------------------------------------------------------------------

_SEVERITY_STYLES = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "dim yellow",
    "info": "dim cyan",
}

_SEVERITY_ICONS = {
    "critical": "[!!!]",
    "high": "[!!]",
    "medium": "[!]",
    "low": "[~]",
    "info": "[i]",
}


# ---------------------------------------------------------------------------
# Scan command
# ---------------------------------------------------------------------------

@click.command("scan")
@click.argument("binary", type=click.Path(exists=True))
@click.option(
    "--type", "vuln_type",
    type=click.Choice([
        "memory-corruption", "buffer-overflow", "format-string",
        "integer-overflow", "use-after-free", "command-injection",
        "race-condition", "logic", "all",
    ]),
    default="all",
    help="Vulnerability type to scan for.",
)
@click.option("--exploitable", is_flag=True, default=False, help="Only show exploitable findings.")
@click.option("--ai-powered", is_flag=True, default=False, help="Use AI for semantic analysis.")
@click.option("--confidence", "min_confidence", type=float, default=0.0, help="Minimum confidence score (0-100).")
@click.option(
    "--severity", "min_severity",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    default=None,
    help="Minimum severity level.",
)
@click.option("--output", "output_path", type=click.Path(), default=None, help="Export results to file.")
@click.option(
    "--format", "output_format",
    type=click.Choice(["text", "json", "markdown"]),
    default=None,
    help="Output format.",
)
@click.pass_context
def scan_cmd(
    ctx: click.Context,
    binary: str,
    vuln_type: str,
    exploitable: bool,
    ai_powered: bool,
    min_confidence: float,
    min_severity: str | None,
    output_path: str | None,
    output_format: str | None,
) -> None:
    """Scan a binary for vulnerabilities.

    Performs pattern-based vulnerability scanning with optional AI-powered
    semantic analysis. Detects buffer overflows, format string bugs,
    integer overflows, use-after-free, and more.

    \b
    Examples:
      raven scan ./vulnerable_app
      raven scan ./app --type memory-corruption --exploitable
      raven scan ./app --ai-powered --severity high
      raven scan ./app --format json --output results.json
    """
    from raven.core.config import RavenConfig
    from raven.core.logger import AuditLogger

    config: RavenConfig = ctx.obj["config"]
    audit = AuditLogger()

    fmt = output_format or config.get("output.format", "text")
    binary_path = Path(binary).resolve()

    logger.info("Scanning binary: %s", binary_path)
    audit.log_analysis(str(binary_path), scan=True, vuln_type=vuln_type)

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=output_console,
            transient=True,
        ) as progress:
            progress.add_task("Loading binary...", total=None)

            from raven.analysis.binary_loader import load_binary

            binary_info = load_binary(binary_path)

            progress.add_task("Running vulnerability scan...", total=None)

            from raven.agents.analyst import AnalystAgent

            analyst = AnalystAgent(config=config)
            report = analyst.scan(
                binary_info,
                vuln_type=vuln_type if vuln_type != "all" else None,
                min_confidence=min_confidence,
                min_severity=min_severity,
                exploitable_only=exploitable,
                ai_powered=ai_powered,
            )

        # Output results
        if output_path:
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            with open(out, "w") as fh:
                json.dump(report, fh, indent=2, default=str)
            print_success(f"Scan results written to {out}")
        else:
            _print_scan_report(report, output_format=fmt)

    except FileNotFoundError:
        print_error(f"Binary not found: {binary_path}")
        sys.exit(1)
    except Exception as exc:
        logger.exception("Scan failed")
        print_error(f"Scan failed: {exc}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Report formatters
# ---------------------------------------------------------------------------

def _print_scan_report(report: dict, output_format: str = "text") -> None:
    """Print a scan report in the specified format."""
    if output_format == "json":
        output_console.print_json(json.dumps(report, indent=2, default=str))
        return
    if output_format == "markdown":
        _print_scan_markdown(report)
        return

    # --- Rich text output ---
    summary = report.get("scan_summary", {})
    security = report.get("security", {})
    vulns = report.get("vulnerabilities", [])

    # Header panel
    header_lines = [
        f"[bold]File:[/bold]       {report.get('file', 'N/A')}",
        f"[bold]Format:[/bold]     {report.get('format', 'N/A')}",
        f"[bold]Architecture:[/bold] {report.get('arch', 'N/A')}",
    ]
    output_console.print(Panel(
        "\n".join(header_lines),
        title=Text("Vulnerability Scan Report", style="bold cyan"),
        border_style="cyan",
        expand=False,
    ))

    # Summary table
    output_console.print()
    sum_table = Table(title="Scan Summary", border_style="cyan")
    sum_table.add_column("Metric", style="bold")
    sum_table.add_column("Value", justify="right")
    sum_table.add_row("Patterns Checked", str(summary.get("total_patterns_checked", 0)))
    sum_table.add_row("Total Matches", str(summary.get("total_matches", 0)))

    for sev in ("critical", "high", "medium", "low", "info"):
        count = summary.get(sev, 0)
        style = _SEVERITY_STYLES.get(sev, "")
        if count > 0:
            sum_table.add_row(f"[{style}]{sev.upper()}[/{style}]", f"[{style}]{count}[/{style}]")
        else:
            sum_table.add_row(sev.upper(), str(count))

    exploitable_count = summary.get("exploitable", 0)
    exp_style = "bold red" if exploitable_count > 0 else ""
    sum_table.add_row(
        f"[{exp_style}]Exploitable[/{exp_style}]" if exp_style else "Exploitable",
        f"[{exp_style}]{exploitable_count}[/{exp_style}]" if exp_style else str(exploitable_count),
    )
    output_console.print(sum_table)

    # Vulnerability details
    if vulns:
        output_console.print()
        for v in vulns:
            sev = v.get("severity", "info")
            style = _SEVERITY_STYLES.get(sev, "")
            icon = _SEVERITY_ICONS.get(sev, "[?]")
            exploitable_mark = " [bold red]EXPLOITABLE[/bold red]" if v.get("exploitable") else ""

            header = (
                f"[{style}]{icon} {v.get('pattern_name', 'Unknown')}[/{style}]"
                f" ({v.get('pattern_id', '')}){exploitable_mark}"
            )
            output_console.print(header)
            output_console.print(f"  [dim]Category:[/dim]     {v.get('category', '')}")
            output_console.print(f"  [dim]Confidence:[/dim]   {v.get('confidence', 0):.0f}%")
            output_console.print(f"  [dim]Exploitability:[/dim] {v.get('exploitability', '')}")

            matched_imports = v.get("matched_imports", [])
            if matched_imports:
                output_console.print(f"  [dim]Imports:[/dim]      {', '.join(matched_imports)}")

            mitigations = v.get("mitigations_absent", [])
            if mitigations:
                output_console.print(
                    f"  [dim]Missing:[/dim]      [bold red]{', '.join(mitigations)}[/bold red]"
                )

            cwes = v.get("cwe_ids", [])
            if cwes:
                output_console.print(f"  [dim]CWE:[/dim]          {', '.join(f'CWE-{c}' for c in cwes)}")

            output_console.print(f"  {v.get('description', '')[:200]}")
            output_console.print()
    else:
        output_console.print()
        print_info("No vulnerabilities detected.")

    # Control flow summary
    cf = report.get("control_flow", {})
    if cf:
        output_console.print()
        cf_table = Table(title="Control Flow Analysis", border_style="cyan")
        cf_table.add_column("Property", style="bold")
        cf_table.add_column("Value")
        cf_table.add_row("Entry Points", ", ".join(cf.get("entry_points", [])) or "None found")
        cf_table.add_row("Total Functions", str(cf.get("total_functions", 0)))
        cf_table.add_row("Dangerous Functions", ", ".join(cf.get("dangerous_functions", [])) or "None")
        cf_table.add_row("Input Sources", ", ".join(cf.get("input_sources", [])) or "None")
        cf_table.add_row("Output Sinks", ", ".join(cf.get("output_sinks", [])) or "None")
        cf_table.add_row("Potential Taint Paths", str(cf.get("potential_taint_paths", 0)))
        output_console.print(cf_table)

    # LLM analysis
    llm = report.get("llm_analysis", "")
    if llm:
        output_console.print()
        output_console.print(Panel(
            llm,
            title=Text("AI-Powered Analysis", style="bold magenta"),
            border_style="magenta",
            expand=False,
        ))


def _print_scan_markdown(report: dict) -> None:
    """Render a scan report as Markdown."""
    summary = report.get("scan_summary", {})
    vulns = report.get("vulnerabilities", [])

    lines = [
        "# Vulnerability Scan Report",
        "",
        f"**File:** `{report.get('file', 'N/A')}`",
        f"**Format:** {report.get('format', 'N/A')}",
        f"**Architecture:** {report.get('arch', 'N/A')}",
        "",
        "## Summary",
        "",
        f"- Patterns Checked: {summary.get('total_patterns_checked', 0)}",
        f"- Total Matches: {summary.get('total_matches', 0)}",
        f"- Critical: {summary.get('critical', 0)}",
        f"- High: {summary.get('high', 0)}",
        f"- Medium: {summary.get('medium', 0)}",
        f"- Low: {summary.get('low', 0)}",
        f"- Exploitable: {summary.get('exploitable', 0)}",
        "",
        "## Vulnerabilities",
        "",
    ]

    for v in vulns:
        exp = " **EXPLOITABLE**" if v.get("exploitable") else ""
        lines.append(
            f"### [{v.get('severity', '').upper()}] "
            f"{v.get('pattern_name', 'Unknown')} ({v.get('pattern_id', '')}){exp}"
        )
        lines.append("")
        lines.append(f"- Category: {v.get('category', '')}")
        lines.append(f"- Confidence: {v.get('confidence', 0):.0f}%")
        lines.append(f"- Exploitability: {v.get('exploitability', '')}")
        matched = v.get("matched_imports", [])
        if matched:
            lines.append(f"- Imports: {', '.join(matched)}")
        cwes = v.get("cwe_ids", [])
        if cwes:
            lines.append(f"- CWE: {', '.join(f'CWE-{c}' for c in cwes)}")
        lines.append("")
        lines.append(v.get("description", "")[:300])
        lines.append("")

    output_console.print("\n".join(lines))
