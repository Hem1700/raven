"""Tests for the RAVEN Heap Exploitation module."""

from __future__ import annotations

import pytest

from raven.exploitation.heap import (
    DOUBLE_FREE_TEMPLATE,
    HEAP_OVERFLOW_TEMPLATE,
    HEAP_PRIMITIVES,
    HEAP_TEMPLATES,
    UAF_TEMPLATE,
    HeapAllocator,
    HeapPrimitive,
    HeapVulnerability,
    HeapVulnType,
    detect_heap_vulns,
)


class TestHeapVulnType:
    """Tests for heap vulnerability type enum."""

    def test_enum_values(self) -> None:
        assert str(HeapVulnType.HEAP_OVERFLOW) == "heap_overflow"
        assert str(HeapVulnType.USE_AFTER_FREE) == "use_after_free"
        assert str(HeapVulnType.DOUBLE_FREE) == "double_free"
        assert str(HeapVulnType.HEAP_SPRAY) == "heap_spray"

    def test_allocator_enum(self) -> None:
        assert str(HeapAllocator.GLIBC_PTMALLOC2) == "ptmalloc2"
        assert str(HeapAllocator.JEMALLOC) == "jemalloc"
        assert str(HeapAllocator.UNKNOWN) == "unknown"


class TestHeapVulnerability:
    """Tests for the HeapVulnerability dataclass."""

    def test_creation(self) -> None:
        v = HeapVulnerability(
            vuln_type=HeapVulnType.HEAP_OVERFLOW,
            description="Test overflow",
            severity="high",
            confidence=75.0,
        )
        assert v.vuln_type == HeapVulnType.HEAP_OVERFLOW
        assert v.severity == "high"
        assert v.confidence == 75.0

    def test_to_dict(self) -> None:
        v = HeapVulnerability(
            vuln_type=HeapVulnType.USE_AFTER_FREE,
            description="UAF in widget",
            exploit_primitives=["type-confusion"],
        )
        d = v.to_dict()
        assert d["vuln_type"] == "use_after_free"
        assert "type-confusion" in d["exploit_primitives"]

    def test_default_values(self) -> None:
        v = HeapVulnerability(vuln_type=HeapVulnType.DOUBLE_FREE)
        assert v.allocator == HeapAllocator.UNKNOWN
        assert v.related_imports == []
        assert v.prerequisites == []


class TestHeapPrimitive:
    """Tests for the HeapPrimitive dataclass."""

    def test_primitive_creation(self) -> None:
        p = HeapPrimitive(
            name="Test Primitive",
            description="A test primitive",
            technique="test_technique",
            code_template="# code here",
        )
        assert p.name == "Test Primitive"
        assert p.technique == "test_technique"

    def test_primitive_to_dict(self) -> None:
        p = HeapPrimitive(
            name="Tcache Poison",
            description="Corrupt tcache",
            technique="tcache_poison",
            code_template="# code",
            requirements=["glibc >= 2.26"],
        )
        d = p.to_dict()
        assert d["name"] == "Tcache Poison"
        assert "glibc >= 2.26" in d["requirements"]


class TestDetectHeapVulns:
    """Tests for heap vulnerability detection from imports."""

    def test_detect_heap_overflow(self) -> None:
        imports = ["malloc", "strcpy", "free"]
        vulns = detect_heap_vulns(imports)
        types = {v.vuln_type for v in vulns}
        assert HeapVulnType.HEAP_OVERFLOW in types

    def test_heap_overflow_not_detected_with_safe_copy(self) -> None:
        imports = ["malloc", "strcpy", "strncpy", "free"]
        vulns = detect_heap_vulns(imports)
        overflow_vulns = [v for v in vulns if v.vuln_type == HeapVulnType.HEAP_OVERFLOW]
        # Safe copy (strncpy) present means no heap overflow detection
        assert len(overflow_vulns) == 0

    def test_detect_uaf(self) -> None:
        imports = ["malloc", "free"]
        vulns = detect_heap_vulns(imports)
        uaf_vulns = [v for v in vulns if v.vuln_type == HeapVulnType.USE_AFTER_FREE]
        assert len(uaf_vulns) >= 1

    def test_detect_double_free(self) -> None:
        imports = ["free"]
        vulns = detect_heap_vulns(imports)
        df_vulns = [v for v in vulns if v.vuln_type == HeapVulnType.DOUBLE_FREE]
        assert len(df_vulns) >= 1

    def test_detect_realloc_stale_pointer(self) -> None:
        imports = ["realloc"]
        vulns = detect_heap_vulns(imports)
        realloc_vulns = [v for v in vulns if "realloc" in v.related_imports]
        assert len(realloc_vulns) >= 1

    def test_no_vulns_without_heap_imports(self) -> None:
        imports = ["printf", "puts", "exit"]
        vulns = detect_heap_vulns(imports)
        assert len(vulns) == 0

    def test_detect_allocator_glibc(self) -> None:
        imports = ["malloc", "free", "__libc_malloc"]
        vulns = detect_heap_vulns(imports)
        glibc_vulns = [v for v in vulns if v.allocator == HeapAllocator.GLIBC_PTMALLOC2]
        assert len(glibc_vulns) > 0

    def test_detect_allocator_jemalloc(self) -> None:
        imports = ["malloc", "free", "je_malloc"]
        vulns = detect_heap_vulns(imports)
        je_vulns = [v for v in vulns if v.allocator == HeapAllocator.JEMALLOC]
        assert len(je_vulns) > 0

    def test_strip_version_from_imports(self) -> None:
        # Imports with @version suffix (from ELF dynamic linking)
        imports = ["malloc@GLIBC_2.17", "strcpy@GLIBC_2.17", "free@GLIBC_2.17"]
        vulns = detect_heap_vulns(imports)
        types = {v.vuln_type for v in vulns}
        assert HeapVulnType.HEAP_OVERFLOW in types

    def test_multiple_unsafe_copy_functions(self) -> None:
        imports = ["malloc", "strcpy", "strcat", "memcpy", "sprintf"]
        vulns = detect_heap_vulns(imports)
        overflow_vulns = [v for v in vulns if v.vuln_type == HeapVulnType.HEAP_OVERFLOW]
        assert len(overflow_vulns) == 1
        # All unsafe functions should be listed
        all_imports = overflow_vulns[0].related_imports
        assert len(all_imports) >= 3


class TestHeapPrimitives:
    """Tests for the pre-built heap exploitation primitives."""

    def test_tcache_poison_exists(self) -> None:
        assert "tcache_poison" in HEAP_PRIMITIVES
        p = HEAP_PRIMITIVES["tcache_poison"]
        assert "tcache" in p.description.lower()

    def test_fastbin_dup_exists(self) -> None:
        assert "fastbin_dup" in HEAP_PRIMITIVES
        p = HEAP_PRIMITIVES["fastbin_dup"]
        assert p.technique == "fastbin_dup"

    def test_house_of_force_exists(self) -> None:
        assert "house_of_force" in HEAP_PRIMITIVES
        p = HEAP_PRIMITIVES["house_of_force"]
        assert "wilderness" in p.description.lower() or "top chunk" in p.description.lower()

    def test_unlink_exists(self) -> None:
        assert "unlink" in HEAP_PRIMITIVES

    def test_all_primitives_have_code_template(self) -> None:
        for name, prim in HEAP_PRIMITIVES.items():
            assert prim.code_template, f"Primitive {name} has no code template"


class TestHeapTemplates:
    """Tests for the heap exploit templates."""

    def test_template_count(self) -> None:
        assert len(HEAP_TEMPLATES) == 3

    def test_heap_overflow_template(self) -> None:
        assert HEAP_OVERFLOW_TEMPLATE.id == "TMPL-HEAP-001"
        assert "heap" in HEAP_OVERFLOW_TEMPLATE.tags

    def test_uaf_template(self) -> None:
        assert UAF_TEMPLATE.id == "TMPL-HEAP-002"
        assert "uaf" in UAF_TEMPLATE.tags

    def test_double_free_template(self) -> None:
        assert DOUBLE_FREE_TEMPLATE.id == "TMPL-HEAP-003"
        assert "double-free" in DOUBLE_FREE_TEMPLATE.tags

    def test_all_templates_have_code(self) -> None:
        for tmpl in HEAP_TEMPLATES:
            assert tmpl.template_code, f"Template {tmpl.id} has no code"
            assert tmpl.variables, f"Template {tmpl.id} has no variables"
