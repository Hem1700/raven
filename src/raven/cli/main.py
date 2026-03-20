"""
RAVEN CLI Entry Point.

This module defines the top-level Click group and wires together
all sub-commands. The ``raven`` console script points here.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click

import raven
from raven.core.config import RavenConfig
from raven.core.logger import setup_logging


# ---------------------------------------------------------------------------
# Top-level group
# ---------------------------------------------------------------------------


class RavenGroup(click.Group):
    """Custom Click group that prints a short banner on ``--help``."""

    def format_help(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        from raven.cli.output import print_banner

        print_banner()
        super().format_help(ctx, formatter)


@click.group(cls=RavenGroup)
@click.version_option(version=raven.__version__, prog_name="raven")
@click.option("--config", "config_path", type=click.Path(), default=None, help="Custom config file path.")
@click.option("-v", "--verbose", is_flag=True, default=False, help="Verbose output.")
@click.option("--debug", is_flag=True, default=False, help="Debug mode with detailed logs.")
@click.option("-q", "--quiet", is_flag=True, default=False, help="Minimal output.")
@click.option("--no-color", is_flag=True, default=False, help="Disable colored output.")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json", "markdown"]),
    default=None,
    help="Output format.",
)
@click.option("--local-llm", is_flag=True, default=False, help="Use local LLM only.")
@click.pass_context
def cli(
    ctx: click.Context,
    config_path: str | None,
    verbose: bool,
    debug: bool,
    quiet: bool,
    no_color: bool,
    output_format: str | None,
    local_llm: bool,
) -> None:
    """RAVEN -- Reverse Analysis & Vulnerability Exploitation Network.

    An AI-powered offensive security research platform.
    """
    ctx.ensure_object(dict)

    # -- load config --------------------------------------------------------
    cp = Path(config_path) if config_path else None
    config = RavenConfig(config_path=cp)
    ctx.obj["config"] = config

    # Apply CLI-level overrides into config (do not persist)
    if output_format:
        config.set("output.format", output_format)
    if no_color:
        config.set("output.color", False)
    if local_llm:
        config.set("llm.local", True)
        config.set("llm.provider", "ollama")
    if verbose:
        config.set("output.verbose", True)

    # -- setup logging ------------------------------------------------------
    log_file = config.get("logging.file", "")
    use_rich = config.get("output.color", True) and not no_color
    setup_logging(
        level=config.get("logging.level", "INFO"),
        log_file=log_file,
        use_rich=use_rich,
        verbose=verbose,
        debug=debug,
        quiet=quiet,
    )


# ---------------------------------------------------------------------------
# Register sub-commands
# ---------------------------------------------------------------------------

from raven.cli.commands.analyze import analyze_cmd  # noqa: E402
from raven.cli.commands.config_cmd import config_cmd  # noqa: E402
from raven.cli.commands.agent_cmd import agent_cmd  # noqa: E402
from raven.cli.commands.scan_cmd import scan_cmd  # noqa: E402
from raven.cli.commands.exploit_cmd import exploit_cmd  # noqa: E402
from raven.cli.commands.validate_cmd import validate_cmd  # noqa: E402

cli.add_command(analyze_cmd)
cli.add_command(config_cmd)
cli.add_command(agent_cmd)
cli.add_command(scan_cmd)
cli.add_command(exploit_cmd)
cli.add_command(validate_cmd)


# ---------------------------------------------------------------------------
# Main guard
# ---------------------------------------------------------------------------

def main() -> None:
    """Convenience entry point for ``python -m raven``."""
    cli()


if __name__ == "__main__":
    main()
