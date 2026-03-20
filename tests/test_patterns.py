"""Tests for the RAVEN vulnerability pattern database."""

from __future__ import annotations

import pytest

from raven.analysis.patterns import (
    ExploitDifficulty,
    PatternCategory,
    PatternDatabase,
    PatternType,
    VulnPattern,
)


class TestVulnPattern:
    """Tests for the VulnPattern data class."""

    def test_pattern_creation(self) -> None:
        """A pattern can be created with minimal arguments."""
        p = VulnPattern(
            id="TEST-001",
            name="Test Pattern",
            category=PatternCategory.BUFFER_OVERFLOW,
            pattern_type=PatternType.IMPORT_PRESENCE,
            description="A test pattern",
        )
        assert p.id == "TEST-001"
        assert p.category == PatternCategory.BUFFER_OVERFLOW
        assert p.severity == "medium"  # default
        assert p.base_confidence == 50.0  # default

    def test_pattern_to_dict(self) -> None:
        """to_dict() serializes all fields."""
        p = VulnPattern(
            id="TEST-002",
            name="Serialization Test",
            category=PatternCategory.FORMAT_STRING,
            pattern_type=PatternType.IMPORT_PRESENCE,
            description="Tests serialization",
            severity="high",
            imports=["printf"],
            cwe_ids=[134],
        )
        d = p.to_dict()
        assert d["id"] == "TEST-002"
        assert d["category"] == "format_string"
        assert d["severity"] == "high"
        assert d["imports"] == ["printf"]
        assert d["cwe_ids"] == [134]

    def test_pattern_defaults(self) -> None:
        """Default field values are correct."""
        p = VulnPattern(
            id="DEF-001",
            name="Defaults",
            category=PatternCategory.BUFFER_OVERFLOW,
            pattern_type=PatternType.IMPORT_PRESENCE,
            description="Checking defaults",
        )
        assert p.required_all is False
        assert p.imports == []
        assert p.absent_imports == []
        assert p.mitigations == []
        assert p.exploitability == ExploitDifficulty.MODERATE


class TestPatternCategory:
    """Tests for the PatternCategory enum."""

    def test_str_representation(self) -> None:
        assert str(PatternCategory.BUFFER_OVERFLOW) == "buffer_overflow"
        assert str(PatternCategory.FORMAT_STRING) == "format_string"
        assert str(PatternCategory.USE_AFTER_FREE) == "use_after_free"

    def test_all_categories_exist(self) -> None:
        expected = {
            "buffer_overflow", "format_string", "integer_overflow",
            "use_after_free", "command_injection", "race_condition",
            "heap_corruption", "logic_bug",
        }
        actual = {str(c) for c in PatternCategory}
        assert expected == actual


class TestPatternDatabase:
    """Tests for the PatternDatabase registry."""

    @pytest.fixture
    def db(self) -> PatternDatabase:
        db = PatternDatabase()
        db.load_defaults()
        return db

    def test_load_defaults(self, db: PatternDatabase) -> None:
        """Default patterns are loaded correctly."""
        assert db.count() >= 15  # 5 BOF + 3 FMT + 3 INT + 2 UAF + 1 CMD + 1 RACE

    def test_get_pattern_by_id(self, db: PatternDatabase) -> None:
        """Patterns can be retrieved by ID."""
        p = db.get("BOF-001")
        assert p is not None
        assert p.name == "Unbounded gets() Usage"
        assert p.category == PatternCategory.BUFFER_OVERFLOW

    def test_get_nonexistent(self, db: PatternDatabase) -> None:
        """get() returns None for unknown IDs."""
        assert db.get("NONEXISTENT") is None

    def test_by_category_buffer_overflow(self, db: PatternDatabase) -> None:
        """Filter by buffer overflow category returns 5 patterns."""
        bof = db.by_category(PatternCategory.BUFFER_OVERFLOW)
        assert len(bof) == 5

    def test_by_category_format_string(self, db: PatternDatabase) -> None:
        """Filter by format string category returns 3 patterns."""
        fmt = db.by_category(PatternCategory.FORMAT_STRING)
        assert len(fmt) == 3

    def test_by_category_integer_overflow(self, db: PatternDatabase) -> None:
        """Filter by integer overflow returns 3 patterns."""
        intof = db.by_category(PatternCategory.INTEGER_OVERFLOW)
        assert len(intof) == 3

    def test_by_category_use_after_free(self, db: PatternDatabase) -> None:
        """Filter by use-after-free returns 2 patterns."""
        uaf = db.by_category(PatternCategory.USE_AFTER_FREE)
        assert len(uaf) == 2

    def test_by_severity(self, db: PatternDatabase) -> None:
        """Filter by severity returns correct patterns."""
        critical = db.by_severity("critical")
        assert len(critical) >= 2  # BOF-001, BOF-005
        for p in critical:
            assert p.severity == "critical"

    def test_by_technique(self, db: PatternDatabase) -> None:
        """Filter by exploitation technique."""
        rop_patterns = db.by_technique("stack_buffer_overflow")
        assert len(rop_patterns) >= 2

    def test_by_tag(self, db: PatternDatabase) -> None:
        """Filter by tag."""
        ctf = db.by_tag("ctf")
        assert len(ctf) >= 1

    def test_add_custom_pattern(self) -> None:
        """Custom patterns can be added."""
        db = PatternDatabase()
        p = VulnPattern(
            id="CUSTOM-001",
            name="Custom Pattern",
            category=PatternCategory.LOGIC_BUG,
            pattern_type=PatternType.IMPORT_PRESENCE,
            description="A custom pattern",
        )
        db.add(p)
        assert db.count() == 1
        assert db.get("CUSTOM-001") is p

    def test_add_duplicate_raises(self) -> None:
        """Adding a pattern with a duplicate ID raises ValueError."""
        db = PatternDatabase()
        p1 = VulnPattern(
            id="DUP-001", name="First", category=PatternCategory.LOGIC_BUG,
            pattern_type=PatternType.IMPORT_PRESENCE, description="First",
        )
        p2 = VulnPattern(
            id="DUP-001", name="Second", category=PatternCategory.LOGIC_BUG,
            pattern_type=PatternType.IMPORT_PRESENCE, description="Second",
        )
        db.add(p1)
        with pytest.raises(ValueError, match="already exists"):
            db.add(p2)

    def test_categories_returns_unique_list(self, db: PatternDatabase) -> None:
        """categories() returns a deduplicated sorted list."""
        cats = db.categories()
        assert len(cats) >= 5
        assert len(cats) == len(set(cats))

    def test_all_returns_sorted(self, db: PatternDatabase) -> None:
        """all() returns patterns sorted by ID."""
        all_p = db.all()
        ids = [p.id for p in all_p]
        assert ids == sorted(ids)

    def test_to_list(self, db: PatternDatabase) -> None:
        """to_list() returns serializable dicts."""
        lst = db.to_list()
        assert isinstance(lst, list)
        assert all(isinstance(d, dict) for d in lst)
        assert all("id" in d for d in lst)
