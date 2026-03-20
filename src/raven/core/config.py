"""
RAVEN Configuration System.

Provides hierarchical configuration management with support for:
- Default values (built-in)
- YAML configuration file (~/.config/raven/config.yaml)
- Environment variable overrides (RAVEN_*)
- CLI argument overrides

Configuration keys use dot-notation (e.g., ``llm.provider``).
"""

from __future__ import annotations

import os
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Directory defaults
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG_DIR = Path.home() / ".config" / "raven"
_DEFAULT_DATA_DIR = Path.home() / ".local" / "share" / "raven"


def _resolve_dir(env_var: str, fallback: Path) -> Path:
    """Return the directory path from *env_var* or *fallback*."""
    raw = os.environ.get(env_var)
    if raw:
        return Path(raw)
    return fallback


def get_config_dir() -> Path:
    """Return the RAVEN configuration directory, creating it if needed."""
    d = _resolve_dir("RAVEN_CONFIG_DIR", _DEFAULT_CONFIG_DIR)
    d.mkdir(parents=True, exist_ok=True)
    return d


def get_data_dir() -> Path:
    """Return the RAVEN data directory, creating it if needed."""
    d = _resolve_dir("RAVEN_DATA_DIR", _DEFAULT_DATA_DIR)
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------

DEFAULT_CONFIG: dict[str, Any] = {
    "llm": {
        "provider": "none",  # "openai" | "anthropic" | "ollama" | "none"
        "model": "gpt-4",
        "api_key": "",
        "base_url": "",
        "local": False,
        "local_model": "llama3",
        "ollama_host": "http://localhost:11434",
        "temperature": 0.2,
        "max_tokens": 4096,
        "timeout": 60,
    },
    "analysis": {
        "default_plugins": ["basic"],
        "deep_analysis": False,
        "timeout": 300,
        "max_functions": 500,
    },
    "agents": {
        "coordinator": True,
        "max_concurrent": 4,
        "timeout": 600,
    },
    "output": {
        "format": "text",
        "color": True,
        "verbose": False,
    },
    "security": {
        "require_confirmation": True,
        "log_operations": True,
        "sandbox_validation": True,
    },
    "logging": {
        "level": "INFO",
        "file": "",  # empty = no file logging
        "format": "rich",  # "rich" | "plain"
    },
}


# ---------------------------------------------------------------------------
# Configuration class
# ---------------------------------------------------------------------------


class RavenConfig:
    """
    Hierarchical configuration manager for RAVEN.

    Resolution order (highest priority wins):
        1. Runtime overrides (set via ``set()``)
        2. Environment variables (``RAVEN_LLM_PROVIDER`` -> ``llm.provider``)
        3. YAML config file
        4. Built-in defaults
    """

    def __init__(self, config_path: Path | None = None) -> None:
        self._data: dict[str, Any] = deepcopy(DEFAULT_CONFIG)
        self._overrides: dict[str, Any] = {}
        self._config_path = config_path or get_config_dir() / "config.yaml"
        self._load_file()
        self._apply_env_overrides()

    # -- persistence --------------------------------------------------------

    def _load_file(self) -> None:
        """Load the YAML config file if it exists and merge into defaults."""
        if self._config_path.is_file():
            with open(self._config_path, "r") as fh:
                raw = yaml.safe_load(fh) or {}
            self._deep_merge(self._data, raw)

    def save(self) -> None:
        """Persist the current configuration to the YAML file."""
        self._config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._config_path, "w") as fh:
            yaml.dump(self._data, fh, default_flow_style=False, sort_keys=False)

    # -- env vars -----------------------------------------------------------

    def _apply_env_overrides(self) -> None:
        """Apply ``RAVEN_*`` environment variables as overrides.

        The mapping is: ``RAVEN_LLM_PROVIDER`` -> key ``llm.provider``.
        """
        prefix = "RAVEN_"
        for key, value in os.environ.items():
            if key.startswith(prefix) and key not in ("RAVEN_CONFIG_DIR", "RAVEN_DATA_DIR"):
                config_key = key[len(prefix):].lower().replace("_", ".", 1)
                # Only apply if the key path exists in defaults
                if self._key_exists(config_key):
                    self._set_nested(self._overrides, config_key, self._coerce(config_key, value))

    # -- get / set ----------------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve a configuration value by dot-separated *key*.

        Args:
            key: Dot-separated key (e.g. ``llm.provider``).
            default: Fallback if the key does not exist anywhere.

        Returns:
            The resolved value.
        """
        # 1. Runtime overrides
        val = self._get_nested(self._overrides, key)
        if val is not None:
            return val
        # 2. Merged data (file + defaults)
        val = self._get_nested(self._data, key)
        if val is not None:
            return val
        return default

    def set(self, key: str, value: Any, *, persist: bool = False) -> None:
        """Set a configuration value.

        Args:
            key: Dot-separated key.
            value: New value.
            persist: If ``True``, also write to the YAML file.
        """
        coerced = self._coerce(key, value)
        self._set_nested(self._data, key, coerced)
        if persist:
            self.save()

    def as_dict(self) -> dict[str, Any]:
        """Return the full merged configuration as a plain dict."""
        merged = deepcopy(self._data)
        self._deep_merge(merged, self._overrides)
        return merged

    # -- initialization helpers ---------------------------------------------

    @classmethod
    def init_default(cls, config_path: Path | None = None) -> "RavenConfig":
        """Create a new default config file and return the instance."""
        path = config_path or get_config_dir() / "config.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as fh:
            yaml.dump(DEFAULT_CONFIG, fh, default_flow_style=False, sort_keys=False)
        return cls(config_path=path)

    # -- internal helpers ---------------------------------------------------

    @staticmethod
    def _get_nested(data: dict[str, Any], key: str) -> Any:
        """Walk *data* using dot-separated *key* and return the value or ``None``."""
        parts = key.split(".")
        current: Any = data
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None
        return current

    @staticmethod
    def _set_nested(data: dict[str, Any], key: str, value: Any) -> None:
        """Set a value in a nested dict using dot-separated *key*."""
        parts = key.split(".")
        current = data
        for part in parts[:-1]:
            current = current.setdefault(part, {})
        current[parts[-1]] = value

    def _key_exists(self, key: str) -> bool:
        """Check if *key* resolves to an existing path in defaults."""
        return self._get_nested(DEFAULT_CONFIG, key) is not None

    @staticmethod
    def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> None:
        """Recursively merge *override* into *base* in place."""
        for k, v in override.items():
            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                RavenConfig._deep_merge(base[k], v)
            else:
                base[k] = v

    def _coerce(self, key: str, value: Any) -> Any:
        """Coerce *value* to match the type of the default for *key*."""
        default = self._get_nested(DEFAULT_CONFIG, key)
        if default is None:
            return value
        if isinstance(default, bool):
            if isinstance(value, str):
                return value.lower() in ("true", "1", "yes")
            return bool(value)
        if isinstance(default, int) and not isinstance(default, bool):
            return int(value)
        if isinstance(default, float):
            return float(value)
        if isinstance(default, list) and isinstance(value, str):
            return [v.strip() for v in value.split(",")]
        return value

    @property
    def config_path(self) -> Path:
        """Return the path to the underlying YAML file."""
        return self._config_path
