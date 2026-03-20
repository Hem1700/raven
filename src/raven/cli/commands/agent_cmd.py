"""
RAVEN ``agent`` CLI command group.

Manage AI agents (list, status).
"""

from __future__ import annotations

import click
from rich.table import Table

from raven.cli.output import output_console, print_info
from raven.core.logger import get_logger

logger = get_logger("cli.agent")

# Registry of available agents and their descriptions
_AGENT_REGISTRY = {
    "scout": {
        "description": "Reconnaissance and attack surface mapping",
        "status": "available",
        "phase": "1",
    },
    "analyst": {
        "description": "Deep binary analysis and vulnerability discovery",
        "status": "available",
        "phase": "2",
    },
    "weaponizer": {
        "description": "Exploit generation and payload creation",
        "status": "available",
        "phase": "2",
    },
    "validator": {
        "description": "Exploit testing and validation",
        "status": "planned",
        "phase": "3",
    },
    "coordinator": {
        "description": "Workflow orchestration and decision making",
        "status": "planned",
        "phase": "2",
    },
}


@click.group("agent")
def agent_cmd() -> None:
    """Manage RAVEN AI agents."""


@agent_cmd.command("list")
def agent_list() -> None:
    """List all available agents."""
    table = Table(title="RAVEN Agents", border_style="cyan")
    table.add_column("Agent", style="bold")
    table.add_column("Description")
    table.add_column("Status", justify="center")
    table.add_column("Phase", justify="center")

    for name, info in _AGENT_REGISTRY.items():
        status_style = "green" if info["status"] == "available" else "dim"
        table.add_row(
            name,
            info["description"],
            f"[{status_style}]{info['status']}[/{status_style}]",
            info["phase"],
        )

    output_console.print(table)


@agent_cmd.command("status")
def agent_status() -> None:
    """Show the status of all agents."""
    print_info("Agent status:")
    for name, info in _AGENT_REGISTRY.items():
        icon = "[green]ON[/green]" if info["status"] == "available" else "[dim]OFF[/dim]"
        output_console.print(f"  {icon}  [bold]{name}[/bold]: {info['description']}")
