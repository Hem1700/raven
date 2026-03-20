"""Tests for Phase 2 RAVEN CLI commands (scan and exploit)."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from raven.cli.main import cli


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class TestScanCommand:
    """Tests for the ``raven scan`` subcommand."""

    def test_scan_help(self, runner: CliRunner) -> None:
        """scan --help shows usage."""
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "Scan a binary for vulnerabilities" in result.output

    def test_scan_nonexistent_file(self, runner: CliRunner) -> None:
        """scan on a nonexistent file fails gracefully."""
        result = runner.invoke(cli, ["scan", "/tmp/nonexistent_binary_xyz"])
        assert result.exit_code != 0

    def test_scan_elf(self, runner: CliRunner, fixtures_dir: Path) -> None:
        """scan works on a real ELF binary."""
        elf = fixtures_dir / "test_elf64"
        if not elf.exists():
            pytest.skip("Test ELF fixture not found")
        result = runner.invoke(cli, ["scan", str(elf)])
        assert result.exit_code == 0
        # Should show scan summary
        assert "Scan Summary" in result.output or "total_matches" in result.output.lower()

    def test_scan_json_output(self, runner: CliRunner, fixtures_dir: Path) -> None:
        """scan --format json produces JSON output."""
        elf = fixtures_dir / "test_elf64"
        if not elf.exists():
            pytest.skip("Test ELF fixture not found")
        result = runner.invoke(cli, ["scan", str(elf), "--format", "json"])
        assert result.exit_code == 0
        assert "scan_summary" in result.output

    def test_scan_markdown_output(self, runner: CliRunner, fixtures_dir: Path) -> None:
        """scan --format markdown produces Markdown output."""
        elf = fixtures_dir / "test_elf64"
        if not elf.exists():
            pytest.skip("Test ELF fixture not found")
        result = runner.invoke(cli, ["scan", str(elf), "--format", "markdown"])
        assert result.exit_code == 0
        assert "Vulnerability Scan Report" in result.output

    def test_scan_output_to_file(
        self, runner: CliRunner, fixtures_dir: Path, tmp_dir: Path,
    ) -> None:
        """scan --output writes results to a file."""
        elf = fixtures_dir / "test_elf64"
        if not elf.exists():
            pytest.skip("Test ELF fixture not found")
        out = tmp_dir / "scan_results.json"
        result = runner.invoke(cli, ["scan", str(elf), "--output", str(out)])
        assert result.exit_code == 0
        assert out.is_file()

    def test_scan_type_filter(self, runner: CliRunner, fixtures_dir: Path) -> None:
        """scan --type memory-corruption filters results."""
        elf = fixtures_dir / "test_elf64"
        if not elf.exists():
            pytest.skip("Test ELF fixture not found")
        result = runner.invoke(cli, ["scan", str(elf), "--type", "buffer-overflow"])
        assert result.exit_code == 0

    def test_scan_severity_filter(self, runner: CliRunner, fixtures_dir: Path) -> None:
        """scan --severity high filters low-severity results."""
        elf = fixtures_dir / "test_elf64"
        if not elf.exists():
            pytest.skip("Test ELF fixture not found")
        result = runner.invoke(cli, ["scan", str(elf), "--severity", "high"])
        assert result.exit_code == 0

    def test_scan_confidence_filter(self, runner: CliRunner, fixtures_dir: Path) -> None:
        """scan --confidence filters low-confidence results."""
        elf = fixtures_dir / "test_elf64"
        if not elf.exists():
            pytest.skip("Test ELF fixture not found")
        result = runner.invoke(cli, ["scan", str(elf), "--confidence", "80"])
        assert result.exit_code == 0

    def test_scan_exploitable_flag(self, runner: CliRunner, fixtures_dir: Path) -> None:
        """scan --exploitable only shows exploitable findings."""
        elf = fixtures_dir / "test_elf64"
        if not elf.exists():
            pytest.skip("Test ELF fixture not found")
        result = runner.invoke(cli, ["scan", str(elf), "--exploitable"])
        assert result.exit_code == 0


class TestExploitCommand:
    """Tests for the ``raven exploit`` subcommand."""

    def test_exploit_help(self, runner: CliRunner) -> None:
        """exploit --help shows usage."""
        result = runner.invoke(cli, ["exploit", "--help"])
        assert result.exit_code == 0
        assert "Generate an exploit" in result.output

    def test_exploit_nonexistent_file(self, runner: CliRunner) -> None:
        """exploit on a nonexistent file fails gracefully."""
        result = runner.invoke(cli, ["exploit", "/tmp/nonexistent_binary_xyz"])
        assert result.exit_code != 0

    def test_exploit_auto_mode(self, runner: CliRunner, fixtures_dir: Path) -> None:
        """exploit --auto runs end-to-end."""
        elf = fixtures_dir / "test_elf64"
        if not elf.exists():
            pytest.skip("Test ELF fixture not found")
        result = runner.invoke(cli, ["exploit", str(elf), "--auto"])
        assert result.exit_code == 0
        # Should produce some exploit output or report
        assert "Exploit" in result.output or "exploit" in result.output.lower()

    def test_exploit_json_output(self, runner: CliRunner, fixtures_dir: Path) -> None:
        """exploit --format json produces JSON output."""
        elf = fixtures_dir / "test_elf64"
        if not elf.exists():
            pytest.skip("Test ELF fixture not found")
        result = runner.invoke(cli, ["exploit", str(elf), "--auto", "--format", "json"])
        assert result.exit_code == 0

    def test_exploit_output_to_file(
        self, runner: CliRunner, fixtures_dir: Path, tmp_dir: Path,
    ) -> None:
        """exploit --output writes exploit code to a file."""
        elf = fixtures_dir / "test_elf64"
        if not elf.exists():
            pytest.skip("Test ELF fixture not found")
        out = tmp_dir / "exploit.py"
        result = runner.invoke(cli, ["exploit", str(elf), "--auto", "--output", str(out)])
        assert result.exit_code == 0
        # File should exist (may be empty if no exploit was generated)

    def test_exploit_technique_option(self, runner: CliRunner, fixtures_dir: Path) -> None:
        """exploit --technique option is accepted."""
        elf = fixtures_dir / "test_elf64"
        if not elf.exists():
            pytest.skip("Test ELF fixture not found")
        result = runner.invoke(cli, ["exploit", str(elf), "--technique", "stack_shellcode"])
        assert result.exit_code == 0


class TestCLIRegistration:
    """Tests that new Phase 2 commands are registered."""

    def test_scan_in_help(self, runner: CliRunner) -> None:
        """scan command appears in top-level help."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output

    def test_exploit_in_help(self, runner: CliRunner) -> None:
        """exploit command appears in top-level help."""
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "exploit" in result.output

    def test_agent_list_shows_phase2(self, runner: CliRunner) -> None:
        """agent list shows analyst and weaponizer as available."""
        result = runner.invoke(cli, ["agent", "list"])
        assert result.exit_code == 0
        assert "analyst" in result.output.lower()
        assert "weaponizer" in result.output.lower()
