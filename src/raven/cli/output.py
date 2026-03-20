"""
RAVEN CLI Output Formatters.

Provides consistent, beautiful output for analysis results using Rich.
Supports text, JSON, and Markdown output formats.
"""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from raven.core.logger import RAVEN_THEME

# Output console goes to stdout (unlike the logging console which goes to stderr)
output_console = Console(theme=RAVEN_THEME)


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

RAVEN_BANNER = r"""
[bold cyan]  ____      ___     _______ _   _
 |  _ \    / \ \   / / ____| \ | |
 | |_) |  / _ \ \ / /|  _| |  \| |
 |  _ <  / ___ \ V / | |___| |\  |
 |_| \_\/_/   \_\_/  |_____|_| \_|[/bold cyan]

[dim]Reverse Analysis & Vulnerability Exploitation Network[/dim]
"""


def print_banner() -> None:
    """Print the RAVEN ASCII banner."""
    output_console.print(RAVEN_BANNER)


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

_SEVERITY_STYLES = {
    "critical": "raven.vuln.critical",
    "high": "raven.vuln.high",
    "medium": "raven.vuln.medium",
    "low": "raven.vuln.low",
}

_SECURITY_CHECK_MARK = "[raven.security.enabled]\u2713[/]"
_SECURITY_CROSS_MARK = "[raven.security.disabled]\u2717[/]"


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------


def print_analysis_report(report: dict[str, Any], output_format: str = "text") -> None:
    """Print a binary analysis report in the specified format.

    Args:
        report: A dict with keys like ``file``, ``format``, ``arch``,
                ``entry_point``, ``security``, ``functions``, etc.
        output_format: ``text``, ``json``, or ``markdown``.
    """
    if output_format == "json":
        output_console.print_json(json.dumps(report, indent=2, default=str))
        return
    if output_format == "markdown":
        _print_analysis_markdown(report)
        return

    # -- Rich text panel output ---------------------------------------------
    title = Text("Binary Analysis Report", style="raven.title")
    info_lines: list[str] = [
        f"[bold]File:[/bold]          {report.get('file', 'N/A')}",
        f"[bold]Format:[/bold]        {report.get('format', 'N/A')}",
        f"[bold]Architecture:[/bold]  {report.get('arch', 'N/A')}",
        f"[bold]Endian:[/bold]        {report.get('endian', 'N/A')}",
        f"[bold]Entry Point:[/bold]   {report.get('entry_point', 'N/A')}",
    ]
    info_block = "\n".join(info_lines)

    # Security mechanisms
    security = report.get("security", {})
    sec_lines: list[str] = []
    for mech, enabled in security.items():
        mark = _SECURITY_CHECK_MARK if enabled else _SECURITY_CROSS_MARK
        label = mech.upper()
        sec_lines.append(f"  {mark} {label}: {'Enabled' if enabled else 'Disabled'}")
    sec_block = "\n".join(sec_lines) if sec_lines else "  No data"

    # Statistics
    stats = report.get("stats", {})
    stat_lines: list[str] = [
        f"  Functions: {stats.get('functions', 0)}",
        f"  Strings:   {stats.get('strings', 0)}",
        f"  Imports:   {stats.get('imports', 0)}",
        f"  Exports:   {stats.get('exports', 0)}",
        f"  Sections:  {stats.get('sections', 0)}",
    ]
    stat_block = "\n".join(stat_lines)

    body = (
        f"{info_block}\n\n"
        f"[bold]Security Mechanisms:[/bold]\n{sec_block}\n\n"
        f"[bold]Statistics:[/bold]\n{stat_block}"
    )

    output_console.print(Panel(body, title=title, border_style="cyan", expand=False))

    # Key functions table
    functions = report.get("functions", [])
    if functions:
        output_console.print()
        tbl = Table(title="Key Functions", border_style="cyan")
        tbl.add_column("Address", style="raven.address")
        tbl.add_column("Name", style="bold")
        tbl.add_column("Size", justify="right")
        tbl.add_column("Type")
        for fn in functions[:30]:  # cap display
            tbl.add_row(
                fn.get("address", ""),
                fn.get("name", ""),
                str(fn.get("size", "")),
                fn.get("type", ""),
            )
        output_console.print(tbl)

    # Interesting strings
    strings = report.get("interesting_strings", [])
    if strings:
        output_console.print()
        tree = Tree("[bold]Interesting Strings[/bold]")
        for s in strings[:25]:
            tree.add(f"[dim]{s}[/dim]")
        output_console.print(tree)


def _print_analysis_markdown(report: dict[str, Any]) -> None:
    """Render an analysis report as Markdown to stdout."""
    lines = [
        f"# Binary Analysis Report",
        "",
        f"| Property | Value |",
        f"|----------|-------|",
        f"| File | `{report.get('file', 'N/A')}` |",
        f"| Format | {report.get('format', 'N/A')} |",
        f"| Architecture | {report.get('arch', 'N/A')} |",
        f"| Entry Point | `{report.get('entry_point', 'N/A')}` |",
        "",
        "## Security Mechanisms",
        "",
    ]
    for mech, enabled in report.get("security", {}).items():
        status = "Enabled" if enabled else "**Disabled**"
        lines.append(f"- {mech.upper()}: {status}")

    lines.append("")
    lines.append("## Functions")
    lines.append("")
    for fn in report.get("functions", [])[:30]:
        lines.append(f"- `{fn.get('address', '')}` {fn.get('name', '')} ({fn.get('size', '')} bytes)")

    output_console.print("\n".join(lines))


def print_error(message: str) -> None:
    """Print an error message."""
    output_console.print(f"[raven.error]Error:[/raven.error] {message}")


def print_success(message: str) -> None:
    """Print a success message."""
    output_console.print(f"[raven.success]Success:[/raven.success] {message}")


def print_warning(message: str) -> None:
    """Print a warning message."""
    output_console.print(f"[raven.warning]Warning:[/raven.warning] {message}")


def print_info(message: str) -> None:
    """Print an informational message."""
    output_console.print(f"[raven.info]{message}[/raven.info]")
