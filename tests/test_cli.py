"""Tests for the RAVEN CLI."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from raven.cli.main import cli


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class TestCLIMain:
    """Tests for the top-level CLI group."""

    def test_version(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "raven" in result.output.lower()

    def test_help(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "RAVEN" in result.output or "analyze" in result.output

    def test_unknown_command(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["nonexistent"])
        assert result.exit_code != 0


class TestConfigCommand:
    """Tests for the config subcommand."""

    def test_config_init(self, runner: CliRunner, tmp_dir: Path) -> None:
        cfg = tmp_dir / "test_config.yaml"
        result = runner.invoke(cli, ["--config", str(cfg), "config", "init"])
        assert result.exit_code == 0

    def test_config_show(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["config", "show"])
        assert result.exit_code == 0

    def test_config_set_and_get(self, runner: CliRunner, tmp_dir: Path) -> None:
        cfg = tmp_dir / "test_config.yaml"
        # Init first
        runner.invoke(cli, ["--config", str(cfg), "config", "init"])
        # Set
        result = runner.invoke(cli, ["--config", str(cfg), "config", "set", "llm.provider", "openai"])
        assert result.exit_code == 0
        # Get
        result = runner.invoke(cli, ["--config", str(cfg), "config", "get", "llm.provider"])
        assert result.exit_code == 0
        assert "openai" in result.output


class TestAgentCommand:
    """Tests for the agent subcommand."""

    def test_agent_list(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["agent", "list"])
        assert result.exit_code == 0
        assert "scout" in result.output.lower()

    def test_agent_status(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["agent", "status"])
        assert result.exit_code == 0


class TestAnalyzeCommand:
    """Tests for the analyze subcommand."""

    def test_analyze_nonexistent_file(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["analyze", "/tmp/nonexistent_binary_xyz"])
        assert result.exit_code != 0

    def test_analyze_elf(self, runner: CliRunner, fixtures_dir: Path) -> None:
        elf = fixtures_dir / "test_elf64"
        if not elf.exists():
            pytest.skip("Test ELF fixture not found")
        result = runner.invoke(cli, ["analyze", str(elf)])
        assert result.exit_code == 0
        assert "ELF" in result.output

    def test_analyze_json_output(self, runner: CliRunner, fixtures_dir: Path) -> None:
        elf = fixtures_dir / "test_elf64"
        if not elf.exists():
            pytest.skip("Test ELF fixture not found")
        result = runner.invoke(cli, ["analyze", str(elf), "--format", "json"])
        assert result.exit_code == 0
        assert "x86_64" in result.output

    def test_analyze_output_to_file(
        self, runner: CliRunner, fixtures_dir: Path, tmp_dir: Path
    ) -> None:
        elf = fixtures_dir / "test_elf64"
        if not elf.exists():
            pytest.skip("Test ELF fixture not found")
        out = tmp_dir / "report.json"
        result = runner.invoke(cli, ["analyze", str(elf), "--output", str(out)])
        assert result.exit_code == 0
        assert out.is_file()

    def test_analyze_markdown_output(self, runner: CliRunner, fixtures_dir: Path) -> None:
        elf = fixtures_dir / "test_elf64"
        if not elf.exists():
            pytest.skip("Test ELF fixture not found")
        result = runner.invoke(cli, ["analyze", str(elf), "--format", "markdown"])
        assert result.exit_code == 0
        assert "Binary Analysis Report" in result.output

    def test_analyze_function_filter(self, runner: CliRunner, fixtures_dir: Path) -> None:
        elf = fixtures_dir / "test_elf64"
        if not elf.exists():
            pytest.skip("Test ELF fixture not found")
        result = runner.invoke(cli, ["analyze", str(elf), "--function", "main"])
        assert result.exit_code == 0
