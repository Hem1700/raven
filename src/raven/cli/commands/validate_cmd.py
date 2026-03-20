"""
RAVEN ``validate`` CLI command.

Tests exploits against target binaries in safe, isolated environments
with detailed success rate reporting and failure analysis.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn
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

logger = get_logger("cli.validate")


@click.command("validate")
@click.argument("exploit", type=click.Path(exists=True))
@click.option("--target", "target_binary", type=click.Path(exists=True), required=True,
              help="Target binary to test against.")
@click.option("--iterations", "-n", type=int, default=1, help="Number of test iterations.")
@click.option(
    "--env", "environment",
    type=click.Choice(["local", "docker", "qemu"]),
    default="local",
    help="Test environment.",
)
@click.option("--timeout", type=int, default=30, help="Timeout per iteration (seconds).")
@click.option("--output", "output_path", type=click.Path(), default=None, help="Export report to file.")
@click.option(
    "--format", "output_format",
    type=click.Choice(["text", "json", "markdown"]),
    default=None,
    help="Output format.",
)
@click.option("--learn", is_flag=True, default=False,
              help="Record results in the learning system for future improvement.")
@click.option("--report", "show_report", is_flag=True, default=False,
              help="Generate a detailed validation report.")
@click.pass_context
def validate_cmd(
    ctx: click.Context,
    exploit: str,
    target_binary: str,
    iterations: int,
    environment: str,
    timeout: int,
    output_path: str | None,
    output_format: str | None,
    learn: bool,
    show_report: bool,
) -> None:
    """Validate an exploit against a target binary.

    Tests the exploit in a safe environment and reports success rate,
    reliability, and failure analysis.

    \b
    Examples:
      raven validate exploit.py --target ./binary
      raven validate exploit.py --target ./binary --iterations 100
      raven validate exploit.py --target ./binary --env docker
      raven validate exploit.py --target ./binary --learn --report
    """
    from raven.core.config import RavenConfig

    config: RavenConfig = ctx.obj["config"]
    fmt = output_format or config.get("output.format", "text")

    exploit_path = Path(exploit).resolve()
    target_path = Path(target_binary).resolve()

    logger.info("Validating exploit %s against %s", exploit_path, target_path)

    try:
        from raven.agents.validator import ValidatorAgent

        validator = ValidatorAgent(config=config)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            console=output_console,
            transient=True,
        ) as progress:
            task = progress.add_task(
                "Running validation...", total=iterations,
            )

            # Run validation (the agent handles iteration internally)
            report = validator.validate(
                exploit_path=str(exploit_path),
                target_binary=str(target_path),
                environment=environment,
                iterations=iterations,
                timeout=timeout,
            )

            progress.update(task, completed=iterations)

        # Learning integration
        if learn:
            try:
                from raven.core.learning import LearningSystem
                ls = LearningSystem()
                ls.record_validation(
                    technique=report.exploit_path,
                    binary_hash="",
                    success_rate=report.success_rate,
                    iterations=report.iterations,
                    environment=report.environment,
                    metadata=report.failure_analysis,
                )
                print_info("Results recorded in learning system.")
            except Exception as exc:
                logger.warning("Failed to record in learning system: %s", exc)

        # Output results
        if output_path:
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            with open(out, "w") as fh:
                json.dump(report.to_dict(), fh, indent=2, default=str)
            print_success(f"Validation report written to {out}")
        elif fmt == "json":
            output_console.print_json(json.dumps(report.to_dict(), indent=2, default=str))
        elif fmt == "markdown":
            _print_validate_markdown(report)
        else:
            _print_validate_report(report, show_detail=show_report)

    except Exception as exc:
        logger.exception("Validation failed")
        print_error(f"Validation failed: {exc}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Report formatters
# ---------------------------------------------------------------------------

def _print_validate_report(report, show_detail: bool = False) -> None:
    """Print validation report in rich text format."""
    # Header
    rate = report.success_rate
    if rate >= 90:
        rate_style = "bold green"
        status_text = "RELIABLE"
    elif rate >= 50:
        rate_style = "bold yellow"
        status_text = "PARTIAL"
    elif rate > 0:
        rate_style = "bold red"
        status_text = "UNRELIABLE"
    else:
        rate_style = "bold red"
        status_text = "FAILED"

    header = (
        f"[bold]Exploit:[/bold]     {report.exploit_path}\n"
        f"[bold]Target:[/bold]      {report.target_binary}\n"
        f"[bold]Environment:[/bold] {report.environment}\n"
        f"[bold]Iterations:[/bold]  {report.iterations}\n"
        f"[bold]Status:[/bold]      [{rate_style}]{status_text}[/{rate_style}]"
    )
    output_console.print(Panel(
        header,
        title=Text("Exploit Validation Report", style="bold cyan"),
        border_style="cyan",
        expand=False,
    ))

    # Statistics table
    output_console.print()
    stats = Table(title="Validation Statistics", border_style="cyan")
    stats.add_column("Metric", style="bold")
    stats.add_column("Value", justify="right")
    stats.add_row("Success Rate", f"[{rate_style}]{rate:.1f}%[/{rate_style}]")
    stats.add_row("Reliability Score", f"{report.reliability_score:.1f}")
    stats.add_row("Avg Duration", f"{report.avg_duration:.3f}s")
    stats.add_row("Total Iterations", str(report.iterations))

    # Failure breakdown
    fa = report.failure_analysis
    status_counts = fa.get("status_counts", {})
    for status, count in status_counts.items():
        style = "green" if status == "success" else "red"
        stats.add_row(f"  {status}", f"[{style}]{count}[/{style}]")

    output_console.print(stats)

    # Recommendations
    if report.recommendations:
        output_console.print()
        output_console.print("[bold]Recommendations:[/bold]")
        for rec in report.recommendations:
            output_console.print(f"  - {rec}")

    # Detailed run results (if requested)
    if show_detail and report.runs:
        output_console.print()
        runs_table = Table(title="Individual Runs", border_style="dim")
        runs_table.add_column("#", justify="right")
        runs_table.add_column("Status")
        runs_table.add_column("Duration", justify="right")
        runs_table.add_column("Exit Code", justify="right")
        runs_table.add_column("Notes")

        for run in report.runs[:50]:  # cap display
            status_style = "green" if str(run.status) == "success" else "red"
            notes = run.error_message[:60] if run.error_message else ""
            runs_table.add_row(
                str(run.iteration),
                f"[{status_style}]{run.status}[/{status_style}]",
                f"{run.duration_seconds:.3f}s",
                str(run.exit_code),
                notes,
            )
        output_console.print(runs_table)


def _print_validate_markdown(report) -> None:
    """Print validation report in markdown format."""
    rate = report.success_rate
    status = "RELIABLE" if rate >= 90 else "PARTIAL" if rate >= 50 else "FAILED"

    lines = [
        "# Exploit Validation Report",
        "",
        f"- **Exploit:** `{report.exploit_path}`",
        f"- **Target:** `{report.target_binary}`",
        f"- **Environment:** {report.environment}",
        f"- **Iterations:** {report.iterations}",
        f"- **Status:** {status}",
        "",
        "## Statistics",
        "",
        f"- Success Rate: {rate:.1f}%",
        f"- Reliability Score: {report.reliability_score:.1f}",
        f"- Average Duration: {report.avg_duration:.3f}s",
        "",
    ]

    if report.recommendations:
        lines.append("## Recommendations")
        lines.append("")
        for rec in report.recommendations:
            lines.append(f"- {rec}")
        lines.append("")

    fa = report.failure_analysis
    if fa.get("primary_failure_mode"):
        lines.append(f"## Failure Analysis")
        lines.append(f"")
        lines.append(f"Primary failure mode: **{fa['primary_failure_mode']}**")

    output_console.print("\n".join(lines))
