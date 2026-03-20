"""Tests for RAVEN Phase 3 CLI commands (validate) and agent registry updates."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from raven.cli.main import cli


@pytest.fixture
def runner() -> CliRunner:
    """Create a Click CLI test runner."""
    return CliRunner()


class TestValidateCommand:
    """Tests for the ``raven validate`` CLI command."""

    def test_validate_registered(self, runner: CliRunner) -> None:
        """validate command should be registered with the CLI."""
        result = runner.invoke(cli, ["validate", "--help"])
        assert result.exit_code == 0
        assert "Validate an exploit" in result.output

    def test_validate_help_shows_options(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["validate", "--help"])
        assert "--target" in result.output
        assert "--iterations" in result.output
        assert "--env" in result.output
        assert "--timeout" in result.output
        assert "--output" in result.output
        assert "--format" in result.output
        assert "--learn" in result.output
        assert "--report" in result.output

    def test_validate_requires_exploit_argument(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["validate"])
        assert result.exit_code != 0
        assert "Missing argument" in result.output or "Error" in result.output

    def test_validate_requires_target_option(self, runner: CliRunner, tmp_dir: Path) -> None:
        exploit = tmp_dir / "exploit.py"
        exploit.write_text("import sys; sys.exit(0)\n")
        result = runner.invoke(cli, ["validate", str(exploit)])
        assert result.exit_code != 0
        assert "Missing" in result.output or "required" in result.output.lower()

    def test_validate_success_text_output(self, runner: CliRunner, tmp_dir: Path) -> None:
        exploit = tmp_dir / "exploit.py"
        exploit.write_text("import sys; sys.exit(0)\n")
        target = tmp_dir / "target"
        target.write_bytes(b"binary")

        result = runner.invoke(cli, [
            "validate", str(exploit),
            "--target", str(target),
            "--iterations", "2",
            "--timeout", "10",
        ])
        assert result.exit_code == 0
        assert "Validation" in result.output or "success" in result.output.lower()

    def test_validate_json_output(self, runner: CliRunner, tmp_dir: Path) -> None:
        exploit = tmp_dir / "exploit.py"
        exploit.write_text("import sys; sys.exit(0)\n")
        target = tmp_dir / "target"
        target.write_bytes(b"binary")

        result = runner.invoke(cli, [
            "validate", str(exploit),
            "--target", str(target),
            "--iterations", "1",
            "--timeout", "10",
            "--format", "json",
        ])
        assert result.exit_code == 0
        # Should be valid JSON in output
        # The output may include Rich formatting chars, so check for key data
        assert "success_rate" in result.output

    def test_validate_markdown_output(self, runner: CliRunner, tmp_dir: Path) -> None:
        exploit = tmp_dir / "exploit.py"
        exploit.write_text("import sys; sys.exit(0)\n")
        target = tmp_dir / "target"
        target.write_bytes(b"binary")

        result = runner.invoke(cli, [
            "validate", str(exploit),
            "--target", str(target),
            "--iterations", "1",
            "--timeout", "10",
            "--format", "markdown",
        ])
        assert result.exit_code == 0
        assert "# Exploit Validation Report" in result.output

    def test_validate_file_output(self, runner: CliRunner, tmp_dir: Path) -> None:
        exploit = tmp_dir / "exploit.py"
        exploit.write_text("import sys; sys.exit(0)\n")
        target = tmp_dir / "target"
        target.write_bytes(b"binary")
        outfile = tmp_dir / "report.json"

        result = runner.invoke(cli, [
            "validate", str(exploit),
            "--target", str(target),
            "--iterations", "1",
            "--timeout", "10",
            "--output", str(outfile),
        ])
        assert result.exit_code == 0
        assert outfile.exists()
        data = json.loads(outfile.read_text())
        assert "success_rate" in data
        assert data["success_rate"] == 100.0

    def test_validate_failure_output(self, runner: CliRunner, tmp_dir: Path) -> None:
        exploit = tmp_dir / "exploit.py"
        exploit.write_text("import sys; sys.exit(1)\n")
        target = tmp_dir / "target"
        target.write_bytes(b"binary")

        result = runner.invoke(cli, [
            "validate", str(exploit),
            "--target", str(target),
            "--iterations", "1",
            "--timeout", "10",
        ])
        assert result.exit_code == 0  # Command succeeds even if exploit fails
        assert "FAILED" in result.output or "Validation" in result.output

    def test_validate_with_report_flag(self, runner: CliRunner, tmp_dir: Path) -> None:
        exploit = tmp_dir / "exploit.py"
        exploit.write_text("import sys; sys.exit(0)\n")
        target = tmp_dir / "target"
        target.write_bytes(b"binary")

        result = runner.invoke(cli, [
            "validate", str(exploit),
            "--target", str(target),
            "--iterations", "2",
            "--timeout", "10",
            "--report",
        ])
        assert result.exit_code == 0


class TestAgentRegistryUpdated:
    """Tests that the agent registry reflects Phase 3 changes."""

    def test_validator_is_available(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["agent", "list"])
        assert result.exit_code == 0
        assert "validator" in result.output
        assert "available" in result.output

    def test_agent_status_shows_validator(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["agent", "status"])
        assert result.exit_code == 0
        assert "validator" in result.output


class TestAllCommandsRegistered:
    """Verify all CLI commands are registered after Phase 3."""

    def test_help_lists_all_commands(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        # All expected commands
        for cmd_name in ["analyze", "config", "agent", "scan", "exploit", "validate"]:
            assert cmd_name in result.output, f"Command '{cmd_name}' not found in help output"
