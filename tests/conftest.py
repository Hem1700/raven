"""Shared test fixtures for RAVEN test suite."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Generator

import pytest


@pytest.fixture
def tmp_dir() -> Generator[Path, None, None]:
    """Provide a temporary directory that is cleaned up after the test."""
    with tempfile.TemporaryDirectory(prefix="raven_test_") as d:
        yield Path(d)


@pytest.fixture
def sample_config_dir(tmp_dir: Path) -> Path:
    """Provide a temporary config directory."""
    config_dir = tmp_dir / ".config" / "raven"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


@pytest.fixture
def fixtures_dir() -> Path:
    """Return the path to the test fixtures directory."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _isolate_config(tmp_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure tests never touch the real user config directory."""
    monkeypatch.setenv("RAVEN_CONFIG_DIR", str(tmp_dir / ".config" / "raven"))
    monkeypatch.setenv("RAVEN_DATA_DIR", str(tmp_dir / ".local" / "share" / "raven"))
