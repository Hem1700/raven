"""
RAVEN Logging Infrastructure.

Provides structured logging with Rich console output, file logging,
and audit trail support for security-sensitive operations.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# ---------------------------------------------------------------------------
# RAVEN Rich theme
# ---------------------------------------------------------------------------

RAVEN_THEME = Theme(
    {
        "raven.title": "bold cyan",
        "raven.success": "bold green",
        "raven.warning": "bold yellow",
        "raven.error": "bold red",
        "raven.info": "dim cyan",
        "raven.highlight": "bold magenta",
        "raven.binary": "bold blue",
        "raven.address": "green",
        "raven.vuln.critical": "bold white on red",
        "raven.vuln.high": "bold red",
        "raven.vuln.medium": "bold yellow",
        "raven.vuln.low": "dim yellow",
        "raven.security.enabled": "bold green",
        "raven.security.disabled": "bold red",
    }
)

# Shared Rich console used across the entire application
console = Console(theme=RAVEN_THEME, stderr=True)

# ---------------------------------------------------------------------------
# Logger setup
# ---------------------------------------------------------------------------

_CONFIGURED = False


def setup_logging(
    level: str = "INFO",
    log_file: str | Path = "",
    use_rich: bool = True,
    verbose: bool = False,
    debug: bool = False,
    quiet: bool = False,
) -> logging.Logger:
    """Configure the root ``raven`` logger.

    Args:
        level: Logging level name (``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``).
        log_file: Optional path to a log file.
        use_rich: Use Rich formatting for console output.
        verbose: Shorthand for ``INFO`` level with extra context.
        debug: Shorthand for ``DEBUG`` level (overrides *level*).
        quiet: Shorthand for ``WARNING`` level (overrides *level*).

    Returns:
        The configured ``raven`` logger.
    """
    global _CONFIGURED

    if debug:
        level = "DEBUG"
    elif quiet:
        level = "WARNING"
    elif verbose:
        level = "INFO"

    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger = logging.getLogger("raven")
    logger.setLevel(numeric_level)

    # Prevent duplicate handlers on repeated calls
    if _CONFIGURED:
        return logger

    logger.handlers.clear()

    # -- Console handler ----------------------------------------------------
    if use_rich:
        handler = RichHandler(
            console=console,
            show_time=debug,
            show_path=debug,
            rich_tracebacks=True,
            tracebacks_show_locals=debug,
            markup=True,
        )
        handler.setLevel(numeric_level)
        logger.addHandler(handler)
    else:
        handler_plain = logging.StreamHandler(sys.stderr)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler_plain.setFormatter(formatter)
        handler_plain.setLevel(numeric_level)
        logger.addHandler(handler_plain)

    # -- File handler (optional) --------------------------------------------
    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(path, encoding="utf-8")
        fh.setLevel(logging.DEBUG)  # always capture everything to file
        fh.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s (%(filename)s:%(lineno)d): %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(fh)

    _CONFIGURED = True
    return logger


def get_logger(name: str = "raven") -> logging.Logger:
    """Return a child logger under the ``raven`` namespace.

    Args:
        name: Dot-separated logger name (e.g. ``raven.agents.scout``).
              If it does not start with ``raven``, it is automatically prefixed.

    Returns:
        A :class:`logging.Logger`.
    """
    if not name.startswith("raven"):
        name = f"raven.{name}"
    return logging.getLogger(name)


# ---------------------------------------------------------------------------
# Audit logger for security-sensitive operations
# ---------------------------------------------------------------------------


class AuditLogger:
    """Records security-sensitive operations for compliance and review.

    Every action that analyses a binary, generates exploit code, or
    interacts with an LLM is logged through this class.
    """

    def __init__(self) -> None:
        self._logger = get_logger("raven.audit")

    def log_analysis(self, binary_path: str, **kwargs: Any) -> None:
        """Record a binary analysis operation."""
        self._logger.info(
            "AUDIT: analyze binary=%s %s",
            binary_path,
            self._fmt_kwargs(kwargs),
        )

    def log_agent_action(self, agent_name: str, action: str, **kwargs: Any) -> None:
        """Record an agent action."""
        self._logger.info(
            "AUDIT: agent=%s action=%s %s",
            agent_name,
            action,
            self._fmt_kwargs(kwargs),
        )

    def log_llm_call(self, provider: str, model: str, **kwargs: Any) -> None:
        """Record an LLM API call."""
        self._logger.info(
            "AUDIT: llm provider=%s model=%s %s",
            provider,
            model,
            self._fmt_kwargs(kwargs),
        )

    @staticmethod
    def _fmt_kwargs(kwargs: dict[str, Any]) -> str:
        return " ".join(f"{k}={v!r}" for k, v in kwargs.items()) if kwargs else ""
