"""Tests for the RAVEN Knowledge Base (SQLite storage)."""

from __future__ import annotations

from pathlib import Path

import pytest

from raven.core.knowledge_base import (
    CVERecord,
    ExploitTemplate,
    KnowledgeBase,
)


class TestKnowledgeBase:
    """Tests for the KnowledgeBase class."""

    @pytest.fixture
    def kb(self, tmp_dir: Path) -> KnowledgeBase:
        db_path = tmp_dir / "test_kb.db"
        kb = KnowledgeBase(db_path=db_path)
        kb.initialize()
        return kb

    def test_initialize_creates_db(self, tmp_dir: Path) -> None:
        """initialize() creates the database file."""
        db_path = tmp_dir / "new_kb.db"
        kb = KnowledgeBase(db_path=db_path)
        kb.initialize()
        assert db_path.exists()

    def test_initialize_idempotent(self, kb: KnowledgeBase) -> None:
        """initialize() can be called multiple times without error."""
        kb.initialize()
        kb.initialize()
        assert kb.db_path.exists()


class TestCVEOperations:
    """Tests for CVE record operations."""

    @pytest.fixture
    def kb(self, tmp_dir: Path) -> KnowledgeBase:
        kb = KnowledgeBase(db_path=tmp_dir / "cve_test.db")
        kb.initialize()
        return kb

    def test_add_and_get_cve(self, kb: KnowledgeBase) -> None:
        """A CVE can be added and retrieved."""
        cve = CVERecord(
            cve_id="CVE-2024-1234",
            description="Buffer overflow in example_app",
            severity="high",
            cvss_score=8.5,
            cwe_ids=[120, 787],
        )
        kb.add_cve(cve)
        result = kb.get_cve("CVE-2024-1234")
        assert result is not None
        assert result.cve_id == "CVE-2024-1234"
        assert result.severity == "high"
        assert result.cvss_score == 8.5
        assert 120 in result.cwe_ids

    def test_get_nonexistent_cve(self, kb: KnowledgeBase) -> None:
        """get_cve() returns None for unknown IDs."""
        assert kb.get_cve("CVE-9999-9999") is None

    def test_search_cves(self, kb: KnowledgeBase) -> None:
        """search_cves() finds CVEs by description text."""
        kb.add_cve(CVERecord(
            cve_id="CVE-2024-1001",
            description="Stack buffer overflow in network daemon",
            severity="critical",
            cvss_score=9.8,
        ))
        kb.add_cve(CVERecord(
            cve_id="CVE-2024-1002",
            description="Integer overflow in parser",
            severity="high",
            cvss_score=7.5,
        ))
        kb.add_cve(CVERecord(
            cve_id="CVE-2024-1003",
            description="Format string in logging module",
            severity="medium",
            cvss_score=6.0,
        ))

        results = kb.search_cves("buffer overflow")
        assert len(results) == 1
        assert results[0].cve_id == "CVE-2024-1001"

    def test_search_cves_severity_filter(self, kb: KnowledgeBase) -> None:
        """search_cves() filters by severity."""
        kb.add_cve(CVERecord(
            cve_id="CVE-2024-2001",
            description="Overflow bug A",
            severity="critical",
            cvss_score=9.0,
        ))
        kb.add_cve(CVERecord(
            cve_id="CVE-2024-2002",
            description="Overflow bug B",
            severity="low",
            cvss_score=3.0,
        ))

        results = kb.search_cves("Overflow", severity="critical")
        assert len(results) == 1
        assert results[0].cve_id == "CVE-2024-2001"

    def test_search_cves_by_cwe(self, kb: KnowledgeBase) -> None:
        """search_cves_by_cwe() finds CVEs by CWE ID."""
        kb.add_cve(CVERecord(
            cve_id="CVE-2024-3001",
            description="CWE-120 related",
            cwe_ids=[120],
        ))
        kb.add_cve(CVERecord(
            cve_id="CVE-2024-3002",
            description="CWE-134 related",
            cwe_ids=[134],
        ))

        results = kb.search_cves_by_cwe(120)
        assert len(results) >= 1
        assert any(r.cve_id == "CVE-2024-3001" for r in results)

    def test_count_cves(self, kb: KnowledgeBase) -> None:
        """count_cves() returns the total count."""
        assert kb.count_cves() == 0
        kb.add_cve(CVERecord(cve_id="CVE-2024-4001", description="Test"))
        assert kb.count_cves() == 1
        kb.add_cve(CVERecord(cve_id="CVE-2024-4002", description="Test 2"))
        assert kb.count_cves() == 2

    def test_upsert_cve(self, kb: KnowledgeBase) -> None:
        """add_cve() updates an existing record on duplicate ID."""
        kb.add_cve(CVERecord(cve_id="CVE-2024-5001", description="Original"))
        kb.add_cve(CVERecord(cve_id="CVE-2024-5001", description="Updated"))
        result = kb.get_cve("CVE-2024-5001")
        assert result is not None
        assert result.description == "Updated"
        assert kb.count_cves() == 1

    def test_cve_to_dict(self) -> None:
        """CVERecord.to_dict() serializes correctly."""
        cve = CVERecord(
            cve_id="CVE-2024-TEST",
            description="Test",
            severity="high",
            cvss_score=8.0,
            cwe_ids=[120],
        )
        d = cve.to_dict()
        assert d["cve_id"] == "CVE-2024-TEST"
        assert d["severity"] == "high"


class TestExploitTemplateOperations:
    """Tests for exploit template storage."""

    @pytest.fixture
    def kb(self, tmp_dir: Path) -> KnowledgeBase:
        kb = KnowledgeBase(db_path=tmp_dir / "template_test.db")
        kb.initialize()
        return kb

    def test_add_and_get_template(self, kb: KnowledgeBase) -> None:
        """A template can be stored and retrieved."""
        tmpl = ExploitTemplate(
            id="TMPL-TEST-001",
            name="Test Template",
            technique="stack_buffer_overflow",
            arch="x86_64",
            description="A test exploit template",
            template_code="from pwn import *\n# exploit code here",
            variables={"offset": "Buffer offset"},
        )
        kb.add_template(tmpl)
        result = kb.get_template("TMPL-TEST-001")
        assert result is not None
        assert result.name == "Test Template"
        assert result.technique == "stack_buffer_overflow"
        assert result.variables["offset"] == "Buffer offset"

    def test_get_nonexistent_template(self, kb: KnowledgeBase) -> None:
        """get_template() returns None for unknown IDs."""
        assert kb.get_template("NONEXISTENT") is None

    def test_search_templates_by_technique(self, kb: KnowledgeBase) -> None:
        """search_templates() filters by technique."""
        kb.add_template(ExploitTemplate(id="T1", name="BOF", technique="stack_buffer_overflow"))
        kb.add_template(ExploitTemplate(id="T2", name="FMT", technique="format_string"))
        kb.add_template(ExploitTemplate(id="T3", name="ROP", technique="rop"))

        bof = kb.search_templates(technique="stack_buffer_overflow")
        assert len(bof) == 1
        assert bof[0].id == "T1"

    def test_search_templates_by_arch(self, kb: KnowledgeBase) -> None:
        """search_templates() filters by architecture."""
        kb.add_template(ExploitTemplate(id="A1", name="x64", technique="rop", arch="x86_64"))
        kb.add_template(ExploitTemplate(id="A2", name="arm", technique="rop", arch="arm64"))

        x64 = kb.search_templates(arch="x86_64")
        assert len(x64) == 1
        assert x64[0].id == "A1"

    def test_count_templates(self, kb: KnowledgeBase) -> None:
        """count_templates() returns correct count."""
        assert kb.count_templates() == 0
        kb.add_template(ExploitTemplate(id="CT1", name="Test", technique="test"))
        assert kb.count_templates() == 1

    def test_template_to_dict(self) -> None:
        """ExploitTemplate.to_dict() serializes correctly."""
        tmpl = ExploitTemplate(
            id="DICT-001",
            name="Dict Test",
            technique="rop",
            arch="x86_64",
            tags=["test"],
        )
        d = tmpl.to_dict()
        assert d["id"] == "DICT-001"
        assert d["technique"] == "rop"
        assert "test" in d["tags"]


class TestAnalysisCache:
    """Tests for the analysis result cache."""

    @pytest.fixture
    def kb(self, tmp_dir: Path) -> KnowledgeBase:
        kb = KnowledgeBase(db_path=tmp_dir / "cache_test.db")
        kb.initialize()
        return kb

    def test_cache_and_retrieve(self, kb: KnowledgeBase) -> None:
        """Results can be cached and retrieved."""
        data = {"findings": [{"id": "F1", "severity": "high"}]}
        kb.cache_result("abc123hash", "/path/to/binary", "scan", data)
        result = kb.get_cached_result("abc123hash", "scan")
        assert result is not None
        assert result["findings"][0]["id"] == "F1"

    def test_cache_miss(self, kb: KnowledgeBase) -> None:
        """get_cached_result() returns None for missing entries."""
        assert kb.get_cached_result("nonexistent", "scan") is None

    def test_cache_different_types(self, kb: KnowledgeBase) -> None:
        """Different result types are stored separately."""
        kb.cache_result("hash1", "/path", "scan", {"type": "scan"})
        kb.cache_result("hash1", "/path", "analyze", {"type": "analyze"})

        scan = kb.get_cached_result("hash1", "scan")
        analyze = kb.get_cached_result("hash1", "analyze")
        assert scan is not None
        assert analyze is not None
        assert scan["type"] == "scan"
        assert analyze["type"] == "analyze"


class TestVulnPatternStorage:
    """Tests for vulnerability pattern storage in the KB."""

    @pytest.fixture
    def kb(self, tmp_dir: Path) -> KnowledgeBase:
        kb = KnowledgeBase(db_path=tmp_dir / "pattern_test.db")
        kb.initialize()
        return kb

    def test_store_and_retrieve_patterns(self, kb: KnowledgeBase) -> None:
        """Patterns can be stored and retrieved by category."""
        pattern = {
            "id": "STORED-001",
            "category": "buffer_overflow",
            "severity": "high",
            "description": "A stored pattern",
        }
        kb.store_pattern(pattern)
        results = kb.get_patterns_by_category("buffer_overflow")
        assert len(results) == 1
        assert results[0]["id"] == "STORED-001"


class TestRAGContext:
    """Tests for RAG context retrieval."""

    @pytest.fixture
    def kb(self, tmp_dir: Path) -> KnowledgeBase:
        kb = KnowledgeBase(db_path=tmp_dir / "rag_test.db")
        kb.initialize()
        return kb

    def test_empty_context(self, kb: KnowledgeBase) -> None:
        """get_rag_context() returns empty string when no data matches."""
        ctx = kb.get_rag_context(cwe_ids=[99999])
        assert ctx == ""

    def test_rag_context_with_cves(self, kb: KnowledgeBase) -> None:
        """get_rag_context() includes CVE data when available."""
        kb.add_cve(CVERecord(
            cve_id="CVE-2024-RAG1",
            description="Buffer overflow in rag test",
            cwe_ids=[120],
        ))
        ctx = kb.get_rag_context(cwe_ids=[120])
        assert "CVE-2024-RAG1" in ctx

    def test_rag_context_with_templates(self, kb: KnowledgeBase) -> None:
        """get_rag_context() includes template data when available."""
        kb.add_template(ExploitTemplate(
            id="RAG-TMPL-001",
            name="RAG Test Template",
            technique="rop",
            description="A template for RAG testing",
        ))
        ctx = kb.get_rag_context(technique="rop")
        assert "RAG Test Template" in ctx
