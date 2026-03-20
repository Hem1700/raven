"""Tests for the RAVEN vulnerability pattern matching engine."""

from __future__ import annotations

from pathlib import Path

import pytest

from raven.analysis.binary_loader import BinaryInfo, SymbolInfo, load_binary
from raven.analysis.matcher import MatchResult, PatternMatcher, scan_binary
from raven.analysis.patterns import PatternCategory, PatternDatabase


class TestPatternMatcher:
    """Tests for the PatternMatcher engine."""

    @pytest.fixture
    def db(self) -> PatternDatabase:
        db = PatternDatabase()
        db.load_defaults()
        return db

    @pytest.fixture
    def matcher(self, db: PatternDatabase) -> PatternMatcher:
        return PatternMatcher(db)

    @pytest.fixture
    def vulnerable_binary(self, tmp_dir: Path) -> BinaryInfo:
        """Create a BinaryInfo that looks like a vulnerable binary."""
        return BinaryInfo(
            path=tmp_dir / "vuln_app",
            file_format="ELF",
            arch="x86_64",
            bits=64,
            endian="little",
            entry_point=0x401000,
            pie=False,
            nx=False,
            canary=False,
            relro="none",
            fortify=False,
            stripped=False,
            imports=[
                "gets", "strcpy", "printf", "malloc", "free",
                "system", "recv", "scanf",
            ],
            strings=["/bin/sh", "password", "%n"],
            symbols=[
                SymbolInfo(name="main", address=0x401000, size=100, sym_type="function"),
                SymbolInfo(name="vulnerable", address=0x401100, size=50, sym_type="function"),
            ],
        )

    @pytest.fixture
    def hardened_binary(self, tmp_dir: Path) -> BinaryInfo:
        """Create a BinaryInfo that looks like a hardened binary."""
        return BinaryInfo(
            path=tmp_dir / "hardened_app",
            file_format="ELF",
            arch="x86_64",
            bits=64,
            endian="little",
            entry_point=0x401000,
            pie=True,
            nx=True,
            canary=True,
            relro="full",
            fortify=True,
            stripped=False,
            imports=["fgets", "strncpy", "snprintf", "calloc", "free"],
            strings=["Hello, World!"],
        )

    def test_match_vulnerable_binary(self, matcher: PatternMatcher, vulnerable_binary: BinaryInfo) -> None:
        """A vulnerable binary triggers many pattern matches."""
        results = matcher.match(vulnerable_binary)
        assert len(results) > 0
        # Should match BOF-001 (gets), BOF-002 (strcpy), FMT-001 (printf), etc.
        pattern_ids = {r.pattern_id for r in results}
        assert "BOF-001" in pattern_ids  # gets()
        assert "BOF-005" in pattern_ids  # no canary + no NX

    def test_match_hardened_binary(self, matcher: PatternMatcher, hardened_binary: BinaryInfo) -> None:
        """A hardened binary with safe functions triggers fewer matches."""
        results = matcher.match(hardened_binary)
        # Should have fewer matches because safe alternatives are used
        # and security mechanisms are present
        # UAF-001 should match (malloc+free -> but we have calloc not malloc)
        # Most patterns should not match since imports use safe versions
        for r in results:
            # Any matches should have reduced confidence
            assert r.confidence <= 80.0

    def test_match_gets_critical(self, matcher: PatternMatcher, vulnerable_binary: BinaryInfo) -> None:
        """gets() triggers a critical severity match."""
        results = matcher.match(vulnerable_binary)
        gets_match = next((r for r in results if r.pattern_id == "BOF-001"), None)
        assert gets_match is not None
        assert gets_match.severity == "critical"
        assert "gets" in gets_match.matched_imports

    def test_match_no_nx_no_canary(self, matcher: PatternMatcher, vulnerable_binary: BinaryInfo) -> None:
        """Security flag pattern BOF-005 triggers when NX and canary are disabled."""
        results = matcher.match(vulnerable_binary)
        bof005 = next((r for r in results if r.pattern_id == "BOF-005"), None)
        assert bof005 is not None
        assert bof005.severity == "critical"
        assert bof005.exploitable is True

    def test_category_filter(self, matcher: PatternMatcher, vulnerable_binary: BinaryInfo) -> None:
        """Filtering by category restricts results."""
        all_results = matcher.match(vulnerable_binary)
        fmt_only = matcher.match(
            vulnerable_binary,
            categories=[PatternCategory.FORMAT_STRING],
        )
        assert len(fmt_only) < len(all_results)
        for r in fmt_only:
            assert r.category == "format_string"

    def test_min_confidence_filter(self, matcher: PatternMatcher, vulnerable_binary: BinaryInfo) -> None:
        """Minimum confidence filter removes low-confidence matches."""
        all_results = matcher.match(vulnerable_binary)
        high_conf = matcher.match(vulnerable_binary, min_confidence=80.0)
        assert len(high_conf) <= len(all_results)
        for r in high_conf:
            assert r.confidence >= 80.0

    def test_min_severity_filter(self, matcher: PatternMatcher, vulnerable_binary: BinaryInfo) -> None:
        """Minimum severity filter removes lower-severity matches."""
        all_results = matcher.match(vulnerable_binary)
        critical_only = matcher.match(vulnerable_binary, min_severity="critical")
        assert len(critical_only) <= len(all_results)
        for r in critical_only:
            assert r.severity == "critical"

    def test_results_sorted_by_severity(self, matcher: PatternMatcher, vulnerable_binary: BinaryInfo) -> None:
        """Results are sorted by severity (most severe first)."""
        results = matcher.match(vulnerable_binary)
        if len(results) < 2:
            pytest.skip("Need at least 2 results for sort test")
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for i in range(len(results) - 1):
            a = severity_order.get(results[i].severity, 5)
            b = severity_order.get(results[i + 1].severity, 5)
            assert a <= b

    def test_match_result_to_dict(self, matcher: PatternMatcher, vulnerable_binary: BinaryInfo) -> None:
        """MatchResult.to_dict() produces valid serialization."""
        results = matcher.match(vulnerable_binary)
        assert len(results) > 0
        d = results[0].to_dict()
        assert "pattern_id" in d
        assert "severity" in d
        assert "confidence" in d
        assert "exploitable" in d

    def test_mitigation_reduces_confidence(self, matcher: PatternMatcher, tmp_dir: Path) -> None:
        """Presence of mitigations reduces confidence scores."""
        # Binary with gets() but WITH canary and NX
        hardened = BinaryInfo(
            path=tmp_dir / "partial_hardened",
            file_format="ELF",
            arch="x86_64",
            bits=64,
            pie=True,
            nx=True,
            canary=True,
            relro="full",
            imports=["gets"],
        )
        unprotected = BinaryInfo(
            path=tmp_dir / "unprotected",
            file_format="ELF",
            arch="x86_64",
            bits=64,
            pie=False,
            nx=False,
            canary=False,
            relro="none",
            imports=["gets"],
        )
        r_hardened = matcher.match(hardened)
        r_unprotected = matcher.match(unprotected)

        # Both should match BOF-001 (gets is always dangerous)
        h_bof = next((r for r in r_hardened if r.pattern_id == "BOF-001"), None)
        u_bof = next((r for r in r_unprotected if r.pattern_id == "BOF-001"), None)

        assert h_bof is not None
        assert u_bof is not None
        # Hardened should have lower confidence
        assert h_bof.confidence < u_bof.confidence

    def test_command_injection_match(self, matcher: PatternMatcher, vulnerable_binary: BinaryInfo) -> None:
        """system() import triggers command injection pattern."""
        results = matcher.match(vulnerable_binary)
        cmd_match = next((r for r in results if r.pattern_id == "CMD-001"), None)
        assert cmd_match is not None
        assert cmd_match.category == "command_injection"

    def test_uaf_pattern_match(self, matcher: PatternMatcher, vulnerable_binary: BinaryInfo) -> None:
        """malloc+free triggers use-after-free pattern."""
        results = matcher.match(vulnerable_binary)
        uaf = next((r for r in results if r.pattern_id == "UAF-001"), None)
        assert uaf is not None
        assert uaf.category == "use_after_free"


class TestScanBinary:
    """Tests for the convenience scan_binary() function."""

    def test_scan_binary_returns_results(self, tmp_dir: Path) -> None:
        """scan_binary() returns a list of MatchResult objects."""
        info = BinaryInfo(
            path=tmp_dir / "test",
            file_format="ELF",
            arch="x86_64",
            bits=64,
            nx=False,
            canary=False,
            imports=["gets", "strcpy"],
        )
        results = scan_binary(info)
        assert isinstance(results, list)
        assert all(isinstance(r, MatchResult) for r in results)
        assert len(results) > 0

    def test_scan_binary_with_real_elf(self, fixtures_dir: Path) -> None:
        """scan_binary() works with a real ELF fixture."""
        p = fixtures_dir / "test_elf64"
        if not p.exists():
            pytest.skip("Test ELF fixture not found")
        info = load_binary(p)
        results = scan_binary(info)
        assert isinstance(results, list)
        # The test ELF has NX disabled, so BOF-005 should match
        pattern_ids = {r.pattern_id for r in results}
        assert "BOF-005" in pattern_ids
