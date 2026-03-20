"""Tests for the RAVEN Scout agent."""

from __future__ import annotations

from pathlib import Path

import pytest

from raven.agents.scout import ScoutAgent
from raven.analysis.binary_loader import BinaryInfo, load_binary
from raven.core.config import RavenConfig
from raven.core.memory import SessionMemory


class TestScoutAgent:
    """Tests for the Scout agent analysis pipeline."""

    @pytest.fixture
    def config(self, tmp_dir: Path) -> RavenConfig:
        return RavenConfig(config_path=tmp_dir / "cfg.yaml")

    @pytest.fixture
    def session(self) -> SessionMemory:
        return SessionMemory()

    @pytest.fixture
    def scout(self, config: RavenConfig, session: SessionMemory) -> ScoutAgent:
        return ScoutAgent(config=config, session=session)

    @pytest.fixture
    def elf_info(self, fixtures_dir: Path) -> BinaryInfo:
        p = fixtures_dir / "test_elf64"
        if not p.exists():
            pytest.skip("Test ELF fixture not found")
        return load_binary(p)

    def test_analyze_returns_report(self, scout: ScoutAgent, elf_info: BinaryInfo) -> None:
        """analyze() returns a dict with expected top-level keys."""
        report = scout.analyze(elf_info)
        assert "file" in report
        assert "format" in report
        assert "arch" in report
        assert "security" in report
        assert "stats" in report
        assert "functions" in report
        assert "attack_surface" in report

    def test_security_assessment(self, scout: ScoutAgent, elf_info: BinaryInfo) -> None:
        """Security mechanisms are reported correctly."""
        report = scout.analyze(elf_info)
        sec = report["security"]
        assert "pie" in sec
        assert "nx" in sec
        assert "canary" in sec
        assert "relro" in sec

    def test_functions_listed(self, scout: ScoutAgent, elf_info: BinaryInfo) -> None:
        """Functions from the binary are included in the report."""
        report = scout.analyze(elf_info)
        func_names = [f["name"] for f in report["functions"]]
        assert "main" in func_names

    def test_findings_recorded(self, scout: ScoutAgent, elf_info: BinaryInfo) -> None:
        """The Scout agent produces findings in session memory."""
        scout.analyze(elf_info)
        findings = scout.session.findings.all()
        # Our test binary has NX disabled and no canary, so there should be findings
        assert len(findings) > 0

    def test_attack_surface(self, scout: ScoutAgent, elf_info: BinaryInfo) -> None:
        """Attack surface mapping produces a structured result."""
        report = scout.analyze(elf_info)
        surface = report["attack_surface"]
        assert "input_vectors" in surface
        assert "is_network" in surface
        assert "has_symbols" in surface

    def test_stats_populated(self, scout: ScoutAgent, elf_info: BinaryInfo) -> None:
        """Statistics are populated from the binary info."""
        report = scout.analyze(elf_info)
        stats = report["stats"]
        assert stats["functions"] >= 0
        assert stats["sections"] > 0

    def test_function_filter(self, scout: ScoutAgent, elf_info: BinaryInfo) -> None:
        """Passing function_name filters the function list."""
        report = scout.analyze(elf_info, function_name="main")
        func_names = [f["name"] for f in report["functions"]]
        assert func_names == ["main"]

    def test_deep_without_llm(self, scout: ScoutAgent, elf_info: BinaryInfo) -> None:
        """Deep analysis with no LLM configured returns empty string, no crash."""
        report = scout.analyze(elf_info, deep=True)
        # Should succeed even without an LLM; llm_analysis will be absent or empty
        assert report["file"]  # basic fields are still present
