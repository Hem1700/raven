"""Tests for the RAVEN Weaponizer agent and exploit templates."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from raven.agents.weaponizer import ExploitResult, WeaponizerAgent
from raven.analysis.binary_loader import BinaryInfo, SymbolInfo
from raven.core.config import RavenConfig
from raven.core.knowledge_base import KnowledgeBase
from raven.core.memory import SessionMemory
from raven.exploitation.templates import (
    BUILTIN_TEMPLATES,
    FORMAT_STRING_X86_64,
    ROP_CHAIN_X86_64,
    STACK_BOF_RET2LIBC_X86_64,
    STACK_BOF_X86_64,
    get_template_by_technique,
    get_templates_for_match,
)


class TestExploitTemplates:
    """Tests for the built-in exploit template library."""

    def test_builtin_template_count(self) -> None:
        """There are at least 4 built-in templates."""
        assert len(BUILTIN_TEMPLATES) >= 4

    def test_stack_bof_template(self) -> None:
        """Stack buffer overflow template has correct metadata."""
        assert STACK_BOF_X86_64.technique == "stack_shellcode"
        assert STACK_BOF_X86_64.arch == "x86_64"
        assert "shellcode" in STACK_BOF_X86_64.template_code
        assert STACK_BOF_X86_64.prerequisites.get("nx") is False

    def test_ret2libc_template(self) -> None:
        """ret2libc template has correct metadata."""
        assert STACK_BOF_RET2LIBC_X86_64.technique == "stack_buffer_overflow"
        assert "system" in STACK_BOF_RET2LIBC_X86_64.template_code
        assert STACK_BOF_RET2LIBC_X86_64.prerequisites.get("canary") is False

    def test_format_string_template(self) -> None:
        """Format string template has correct metadata."""
        assert FORMAT_STRING_X86_64.technique == "format_string"
        assert "fmtstr_payload" in FORMAT_STRING_X86_64.template_code

    def test_rop_chain_template(self) -> None:
        """ROP chain template has correct metadata."""
        assert ROP_CHAIN_X86_64.technique == "rop"
        assert "pop_rdi" in ROP_CHAIN_X86_64.template_code

    def test_template_to_dict(self) -> None:
        """Templates serialize to dict correctly."""
        d = STACK_BOF_X86_64.to_dict()
        assert d["id"] == "TMPL-BOF-001"
        assert d["technique"] == "stack_shellcode"
        assert "variables" in d
        assert "prerequisites" in d

    def test_get_template_by_technique(self) -> None:
        """get_template_by_technique() finds matching templates."""
        tmpl = get_template_by_technique("rop")
        assert tmpl is not None
        assert tmpl.technique == "rop"

    def test_get_template_by_technique_not_found(self) -> None:
        """get_template_by_technique() returns None for unknown techniques."""
        assert get_template_by_technique("nonexistent_technique") is None

    def test_get_templates_for_match_with_security(self) -> None:
        """get_templates_for_match() filters by security prerequisites."""
        # Binary with NX disabled should match shellcode template
        security = {"nx": False, "canary": False, "pie": False, "relro": "none"}
        templates = get_templates_for_match("stack_shellcode", "x86_64", security)
        assert len(templates) >= 1
        assert any(t.id == "TMPL-BOF-001" for t in templates)

    def test_get_templates_for_match_excludes_incompatible(self) -> None:
        """get_templates_for_match() excludes templates when prerequisites fail."""
        # Binary with NX enabled should NOT match shellcode template
        security = {"nx": True, "canary": True, "pie": True, "relro": "full"}
        templates = get_templates_for_match("stack_shellcode", "x86_64", security)
        assert len(templates) == 0

    def test_all_templates_have_required_fields(self) -> None:
        """All built-in templates have required fields populated."""
        for tmpl in BUILTIN_TEMPLATES:
            assert tmpl.id, f"Template missing id"
            assert tmpl.name, f"Template {tmpl.id} missing name"
            assert tmpl.technique, f"Template {tmpl.id} missing technique"
            assert tmpl.arch, f"Template {tmpl.id} missing arch"
            assert tmpl.template_code, f"Template {tmpl.id} missing template_code"
            assert tmpl.description, f"Template {tmpl.id} missing description"


class TestExploitResult:
    """Tests for the ExploitResult data class."""

    def test_default_values(self) -> None:
        """ExploitResult has sensible defaults."""
        r = ExploitResult()
        assert r.success is False
        assert r.technique == ""
        assert r.code == ""
        assert r.parameters == {}
        assert r.notes == []

    def test_to_dict(self) -> None:
        """to_dict() serializes all fields."""
        r = ExploitResult(
            success=True,
            technique="rop",
            template_id="TMPL-001",
            code="print('exploit')",
            notes=["Note 1"],
        )
        d = r.to_dict()
        assert d["success"] is True
        assert d["technique"] == "rop"
        assert d["code"] == "print('exploit')"


class TestWeaponizerAgent:
    """Tests for the Weaponizer agent."""

    @pytest.fixture
    def config(self, tmp_dir: Path) -> RavenConfig:
        return RavenConfig(config_path=tmp_dir / "cfg.yaml")

    @pytest.fixture
    def session(self) -> SessionMemory:
        return SessionMemory()

    @pytest.fixture
    def kb(self, tmp_dir: Path) -> KnowledgeBase:
        kb = KnowledgeBase(db_path=tmp_dir / "weap_test.db")
        kb.initialize()
        return kb

    @pytest.fixture
    def weaponizer(
        self, config: RavenConfig, session: SessionMemory, kb: KnowledgeBase,
    ) -> WeaponizerAgent:
        return WeaponizerAgent(config=config, session=session, knowledge_base=kb)

    @pytest.fixture
    def vulnerable_binary(self, tmp_dir: Path) -> BinaryInfo:
        """A vulnerable binary suitable for exploitation."""
        return BinaryInfo(
            path=tmp_dir / "exploit_target",
            file_format="ELF",
            arch="x86_64",
            bits=64,
            entry_point=0x401000,
            pie=False,
            nx=False,
            canary=False,
            relro="none",
            imports=["gets", "strcpy", "printf", "system"],
            strings=["/bin/sh"],
            symbols=[
                SymbolInfo(name="main", address=0x401000, size=100, sym_type="function"),
            ],
        )

    @pytest.fixture
    def sample_vulns(self) -> list[dict[str, Any]]:
        """Sample vulnerability scan results."""
        return [
            {
                "pattern_id": "BOF-001",
                "pattern_name": "Unbounded gets() Usage",
                "category": "buffer_overflow",
                "severity": "critical",
                "confidence": 95.0,
                "exploitability": "trivial",
                "exploitable": True,
                "technique": "stack_shellcode",
                "matched_imports": ["gets"],
            },
            {
                "pattern_id": "BOF-005",
                "pattern_name": "Stack BOF No Canary No NX",
                "category": "buffer_overflow",
                "severity": "critical",
                "confidence": 90.0,
                "exploitability": "trivial",
                "exploitable": True,
                "technique": "stack_shellcode",
                "matched_imports": [],
            },
            {
                "pattern_id": "FMT-001",
                "pattern_name": "printf Format String",
                "category": "format_string",
                "severity": "high",
                "confidence": 60.0,
                "exploitability": "moderate",
                "exploitable": True,
                "technique": "format_string",
                "matched_imports": ["printf"],
            },
        ]

    def test_generate_with_technique(
        self,
        weaponizer: WeaponizerAgent,
        vulnerable_binary: BinaryInfo,
        sample_vulns: list[dict],
    ) -> None:
        """generate() with explicit technique produces exploit code."""
        results = weaponizer.generate(
            vulnerable_binary,
            vulnerabilities=sample_vulns,
            technique="stack_shellcode",
        )
        assert len(results) == 1
        assert results[0].success is True
        assert "pwn" in results[0].code.lower() or "shellcode" in results[0].code.lower()

    def test_generate_with_vuln_id(
        self,
        weaponizer: WeaponizerAgent,
        vulnerable_binary: BinaryInfo,
        sample_vulns: list[dict],
    ) -> None:
        """generate() targeting a specific vulnerability ID."""
        results = weaponizer.generate(
            vulnerable_binary,
            vulnerabilities=sample_vulns,
            vuln_id="BOF-001",
        )
        assert len(results) == 1
        assert results[0].success is True
        assert results[0].vuln_id == "BOF-001"

    def test_generate_with_nonexistent_vuln(
        self,
        weaponizer: WeaponizerAgent,
        vulnerable_binary: BinaryInfo,
        sample_vulns: list[dict],
    ) -> None:
        """generate() with unknown vuln_id returns failure."""
        results = weaponizer.generate(
            vulnerable_binary,
            vulnerabilities=sample_vulns,
            vuln_id="NONEXISTENT",
        )
        assert len(results) == 1
        assert results[0].success is False

    def test_generate_auto_mode(
        self,
        weaponizer: WeaponizerAgent,
        vulnerable_binary: BinaryInfo,
        sample_vulns: list[dict],
    ) -> None:
        """generate() in auto mode picks the best vulnerability."""
        results = weaponizer.generate(
            vulnerable_binary,
            vulnerabilities=sample_vulns,
            auto_mode=True,
        )
        assert any(r.success for r in results)

    def test_generate_no_vulnerabilities(
        self,
        weaponizer: WeaponizerAgent,
        vulnerable_binary: BinaryInfo,
    ) -> None:
        """generate() with empty vulnerability list returns failure."""
        results = weaponizer.generate(
            vulnerable_binary,
            vulnerabilities=[],
        )
        assert len(results) == 1
        assert results[0].success is False

    def test_generate_creates_findings(
        self,
        weaponizer: WeaponizerAgent,
        vulnerable_binary: BinaryInfo,
        sample_vulns: list[dict],
    ) -> None:
        """Successful generation records findings in session memory."""
        weaponizer.generate(
            vulnerable_binary,
            vulnerabilities=sample_vulns,
            technique="stack_shellcode",
        )
        findings = weaponizer.session.findings.by_agent("weaponizer")
        assert len(findings) > 0

    def test_exploit_notes_security_warnings(
        self,
        weaponizer: WeaponizerAgent,
        sample_vulns: list[dict],
        tmp_dir: Path,
    ) -> None:
        """Exploit generation includes security-related notes."""
        # Binary with canary enabled
        binary = BinaryInfo(
            path=tmp_dir / "canary_target",
            file_format="ELF",
            arch="x86_64",
            bits=64,
            pie=True,
            nx=False,
            canary=True,
            relro="none",
            imports=["gets"],
        )
        results = weaponizer.generate(
            binary,
            vulnerabilities=sample_vulns,
            technique="stack_shellcode",
        )
        if results[0].success:
            notes_text = " ".join(results[0].notes)
            assert "canary" in notes_text.lower() or "WARNING" in notes_text

    def test_weaponizer_name(self, weaponizer: WeaponizerAgent) -> None:
        """Agent has correct name."""
        assert weaponizer.name == "weaponizer"
