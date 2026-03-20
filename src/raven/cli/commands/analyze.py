"""
RAVEN ``analyze`` CLI command.

Performs binary analysis with optional deep (LLM-powered) semantic understanding.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.progress import Progress, SpinnerColumn, TextColumn

from raven.cli.output import (
    output_console,
    print_analysis_report,
    print_error,
    print_info,
    print_success,
)
from raven.core.logger import get_logger

logger = get_logger("cli.analyze")


@click.command("analyze")
@click.argument("binary", type=click.Path(exists=True))
@click.option("--deep", is_flag=True, default=False, help="Deep analysis with LLM semantic understanding.")
@click.option("--function", "function_name", default=None, help="Analyze a specific function by name.")
@click.option("--output", "output_path", type=click.Path(), default=None, help="Export results to file.")
@click.option("--format", "output_format", type=click.Choice(["text", "json", "markdown"]), default=None, help="Output format.")
@click.option("--arch", default=None, help="Override architecture detection.")
@click.option("--base", "base_address", default=None, help="Set base address (hex).")
@click.pass_context
def analyze_cmd(
    ctx: click.Context,
    binary: str,
    deep: bool,
    function_name: str | None,
    output_path: str | None,
    output_format: str | None,
    arch: str | None,
    base_address: str | None,
) -> None:
    """Analyze a binary file.

    Performs static binary analysis including metadata extraction,
    security mechanism detection, function identification, and
    string extraction. Use --deep for LLM-powered semantic analysis.
    """
    from raven.core.config import RavenConfig
    from raven.core.logger import AuditLogger

    config: RavenConfig = ctx.obj["config"]
    audit = AuditLogger()

    # Resolve output format: CLI flag > config > "text"
    fmt = output_format or config.get("output.format", "text")

    binary_path = Path(binary).resolve()
    logger.info("Analyzing binary: %s", binary_path)
    audit.log_analysis(str(binary_path), deep=deep, function=function_name)

    # -- run analysis -------------------------------------------------------
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=output_console,
            transient=True,
        ) as progress:
            progress.add_task("Loading binary...", total=None)

            from raven.analysis.binary_loader import load_binary

            binary_info = load_binary(binary_path, arch_override=arch, base_address=base_address)

            progress.add_task("Extracting metadata...", total=None)

            from raven.agents.scout import ScoutAgent

            scout = ScoutAgent(config=config)
            report = scout.analyze(binary_info, deep=deep, function_name=function_name)

        # -- output ---------------------------------------------------------
        if output_path:
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            with open(out, "w") as fh:
                json.dump(report, fh, indent=2, default=str)
            print_success(f"Analysis results written to {out}")
        else:
            print_analysis_report(report, output_format=fmt)

    except FileNotFoundError:
        print_error(f"Binary not found: {binary_path}")
        sys.exit(1)
    except Exception as exc:
        logger.exception("Analysis failed")
        print_error(f"Analysis failed: {exc}")
        sys.exit(1)
