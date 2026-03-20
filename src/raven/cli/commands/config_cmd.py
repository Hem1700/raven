"""
RAVEN ``config`` CLI command group.

Manage RAVEN configuration (init, show, get, set).
"""

from __future__ import annotations

import click
import yaml

from raven.cli.output import output_console, print_error, print_info, print_success
from raven.core.config import RavenConfig, get_config_dir
from raven.core.logger import get_logger

logger = get_logger("cli.config")


@click.group("config")
def config_cmd() -> None:
    """Manage RAVEN configuration."""


@config_cmd.command("init")
@click.pass_context
def config_init(ctx: click.Context) -> None:
    """Initialize a default configuration file."""
    config_path = get_config_dir() / "config.yaml"
    if config_path.exists():
        if not click.confirm(f"Config already exists at {config_path}. Overwrite?"):
            print_info("Aborted.")
            return
    cfg = RavenConfig.init_default(config_path)
    print_success(f"Configuration initialized at {cfg.config_path}")


@config_cmd.command("show")
@click.pass_context
def config_show(ctx: click.Context) -> None:
    """Display the current configuration."""
    config: RavenConfig = ctx.obj["config"]
    data = config.as_dict()
    # Mask API keys for safety
    if "llm" in data and data["llm"].get("api_key"):
        key = data["llm"]["api_key"]
        data["llm"]["api_key"] = key[:4] + "****" + key[-4:] if len(key) > 8 else "****"
    output_console.print_json(data=data)


@config_cmd.command("get")
@click.argument("key")
@click.pass_context
def config_get(ctx: click.Context, key: str) -> None:
    """Get a configuration value by dot-separated KEY."""
    config: RavenConfig = ctx.obj["config"]
    value = config.get(key)
    if value is None:
        print_error(f"Key not found: {key}")
        return
    # Mask API keys
    if "api_key" in key and isinstance(value, str) and value:
        value = value[:4] + "****" + value[-4:] if len(value) > 8 else "****"
    output_console.print(f"[bold]{key}[/bold] = {value}")


@config_cmd.command("set")
@click.argument("key")
@click.argument("value")
@click.pass_context
def config_set(ctx: click.Context, key: str, value: str) -> None:
    """Set a configuration value. KEY is dot-separated (e.g. llm.provider)."""
    config: RavenConfig = ctx.obj["config"]
    config.set(key, value, persist=True)
    # Mask API keys in output
    display = value
    if "api_key" in key and len(value) > 8:
        display = value[:4] + "****" + value[-4:]
    print_success(f"Set {key} = {display}")
