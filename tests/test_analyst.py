"""Tests for the RAVEN Analyst agent."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from raven.agents.analyst import AnalystAgent
from raven.analysis.binary_loader import BinaryInfo, SymbolInfo, load_binary
from raven.core.config import RavenConfig
from raven.core.knowledge_base import KnowledgeBase
from raven.core.memory import SessionMemory


class TestAnalystAgent:
    """Tests for the Analyst agent vulnerability scanning."""

    @pytest.fixture
    def config(self, tmp_dir: Path) -> RavenConfig:
        return RavenConfig(config_path=tmp_dir / "cfg.yaml")

    @pytest.fixture
    def session(self) -> SessionMemory:
        return SessionMemory()

    @pytest.fixture
    def kb(self, tmp_dir: Path) -> KnowledgeBase:
        kb = KnowledgeBase(db_path=tmp_dir / "analyst_test.db")
        kb.initialize()
        return kb

    @pytest.fixture
    def analyst(
        self, config: RavenConfig, session: SessionMemory, kb: KnowledgeBase,
    ) -> AnalystAgent:
        return AnalystAgent(config=config, session=session, knowledge_base=kb)

    @pytest.fixture
    def vulnerable_binary(self, tmp_dir: Path) -> BinaryInfo:
        """A binary with many dangerous imports and weak security."""
        return BinaryInfo(
            path=tmp_dir / "vuln_test",
            file_format="ELF",
            arch="x86_64",
            bits=64,
            entry_point=0x401000,
            pie=False,
            nx=False,
            canary=False,
            relro="none",
            fortify=False,
            imports=[
                "gets", "strcpy", "printf", "malloc", "free",
                "system", "recv", "scanf",
            ],
            strings=["/bin/sh", "password", "%n", "admin"],
            symbols=[
                SymbolInfo(name="main", address=0x401000, size=100, sym_type="function"),
                SymbolInfo(name="_start", address=0x400000, size=20, sym_type="function"),
            ],
        )

    @pytest.fixture
    def safe_binary(self, tmp_dir: Path) -> BinaryInfo:
        """A binary with safe imports and strong security."""
        return BinaryInfo(
            path=tmp_dir / "safe_test",
            file_format="ELF",
            arch="x86_64",
            bits=64,
            entry_point=0x401000,
            pie=True,
            nx=True,
            canary=True,
            relro="full",
            fortify=True,
            imports=["fgets", "strncpy", "snprintf"],
            strings=["Hello, World!"],
            symbols=[
                SymbolInfo(name="main", address=0x401000, size=50, sym_type="function"),
            ],
        )

    def test_scan_returns_report(self, analyst: AnalystAgent, vulnerable_binary: BinaryInfo) -> None:
        """scan() returns a dict with expected top-level keys."""
        report = analyst.scan(vulnerable_binary)
        assert "file" in report
        assert "format" in report
        assert "security" in report
        assert "scan_summary" in report
        assert "vulnerabilities" in report
        assert "control_flow" in report

    def test_scan_summary_counts(self, analyst: AnalystAgent, vulnerable_binary: BinaryInfo) -> None:
        """scan_summary contains correct match counts."""
        report = analyst.scan(vulnerable_binary)
        summary = report["scan_summary"]
        assert summary["total_matches"] > 0
        assert summary["total_patterns_checked"] >= 15  # all patterns checked
        # Check that sum of severities equals total
        total = (
            summary.get("critical", 0)
            + summary.get("high", 0)
            + summary.get("medium", 0)
            + summary.get("low", 0)
            + summary.get("info", 0)
        )
        assert total == summary["total_matches"]

    def test_scan_creates_findings(self, analyst: AnalystAgent, vulnerable_binary: BinaryInfo) -> None:
        """scan() records findings in session memory."""
        analyst.scan(vulnerable_binary)
        findings = analyst.session.findings.all()
        assert len(findings) > 0
        # Check that findings have agent set
        for f in findings:
            assert f.agent == "analyst"

    def test_scan_vuln_type_filter(self, analyst: AnalystAgent, vulnerable_binary: BinaryInfo) -> None:
        """scan() with vuln_type filters to specific categories."""
        all_report = analyst.scan(vulnerable_binary)
        # Reset session for clean findings
        analyst2 = AnalystAgent(
            config=analyst.config,
            session=SessionMemory(),
            knowledge_base=analyst._kb,
        )
        fmt_report = analyst2.scan(vulnerable_binary, vuln_type="format-string")

        all_vulns = all_report["vulnerabilities"]
        fmt_vulns = fmt_report["vulnerabilities"]
        assert len(fmt_vulns) <= len(all_vulns)
        for v in fmt_vulns:
            assert v["category"] == "format_string"

    def test_scan_min_confidence(self, analyst: AnalystAgent, vulnerable_binary: BinaryInfo) -> None:
        """scan() with min_confidence filters low-confidence results."""
        report = analyst.scan(vulnerable_binary, min_confidence=80.0)
        for v in report["vulnerabilities"]:
            assert v["confidence"] >= 80.0

    def test_scan_min_severity(self, analyst: AnalystAgent, vulnerable_binary: BinaryInfo) -> None:
        """scan() with min_severity filters lower severities."""
        report = analyst.scan(vulnerable_binary, min_severity="high")
        for v in report["vulnerabilities"]:
            assert v["severity"] in ("critical", "high")

    def test_scan_exploitable_only(self, analyst: AnalystAgent, vulnerable_binary: BinaryInfo) -> None:
        """scan() with exploitable_only filters non-exploitable findings."""
        report = analyst.scan(vulnerable_binary, exploitable_only=True)
        for v in report["vulnerabilities"]:
            assert v["exploitable"] is True

    def test_scan_safe_binary(self, analyst: AnalystAgent, safe_binary: BinaryInfo) -> None:
        """A safe binary produces fewer or no findings."""
        report = analyst.scan(safe_binary)
        # Safe binary with safe imports should have few matches
        vulns = report["vulnerabilities"]
        # Even if there are some matches, they should be low severity/confidence
        for v in vulns:
            assert v["confidence"] < 80.0

    def test_control_flow_analysis(self, analyst: AnalystAgent, vulnerable_binary: BinaryInfo) -> None:
        """Control flow analysis produces expected structure."""
        report = analyst.scan(vulnerable_binary)
        cf = report["control_flow"]
        assert "entry_points" in cf
        assert "total_functions" in cf
        assert "dangerous_functions" in cf
        assert "input_sources" in cf
        assert "output_sinks" in cf
        assert "potential_taint_paths" in cf
        assert "main" in cf["entry_points"]

    def test_control_flow_dangerous_detection(
        self, analyst: AnalystAgent, vulnerable_binary: BinaryInfo,
    ) -> None:
        """Control flow analysis identifies dangerous functions."""
        report = analyst.scan(vulnerable_binary)
        cf = report["control_flow"]
        assert "gets" in cf["dangerous_functions"]
        assert "strcpy" in cf["dangerous_functions"]

    def test_deep_without_llm(self, analyst: AnalystAgent, vulnerable_binary: BinaryInfo) -> None:
        """AI-powered scan with no LLM configured does not crash."""
        report = analyst.scan(vulnerable_binary, ai_powered=True)
        # Should succeed without LLM; llm_analysis will be absent or empty
        assert report["scan_summary"]["total_matches"] > 0

    def test_scan_with_real_elf(
        self, config: RavenConfig, fixtures_dir: Path, tmp_dir: Path,
    ) -> None:
        """Analyst scan works with a real ELF binary fixture."""
        p = fixtures_dir / "test_elf64"
        if not p.exists():
            pytest.skip("Test ELF fixture not found")
        kb = KnowledgeBase(db_path=tmp_dir / "real_elf_test.db")
        analyst = AnalystAgent(config=config, knowledge_base=kb)
        binary_info = load_binary(p)
        report = analyst.scan(binary_info)
        assert report["scan_summary"]["total_matches"] > 0
        # Our test ELF has NX disabled and no canary
        pattern_ids = {v["pattern_id"] for v in report["vulnerabilities"]}
        assert "BOF-005" in pattern_ids

    def test_analyst_name_and_description(self, analyst: AnalystAgent) -> None:
        """Agent has correct name and description."""
        assert analyst.name == "analyst"
        assert "analysis" in analyst.description.lower() or "vulnerability" in analyst.description.lower()
