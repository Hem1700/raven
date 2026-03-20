"""Tests for the RAVEN Learning and Adaptation System."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from raven.core.learning import (
    LearningSystem,
    TechniqueRecommendation,
    TechniqueStats,
    ValidationRecord,
    _suggest_fix,
)


class TestValidationRecord:
    """Tests for the ValidationRecord dataclass."""

    def test_creation(self) -> None:
        rec = ValidationRecord(
            technique="stack_buffer_overflow",
            binary_hash="abc123",
            success_rate=85.0,
            iterations=100,
        )
        assert rec.technique == "stack_buffer_overflow"
        assert rec.success_rate == 85.0

    def test_to_dict(self) -> None:
        rec = ValidationRecord(
            technique="rop",
            binary_hash="def456",
            success_rate=50.0,
            iterations=10,
            environment="docker",
            metadata={"key": "value"},
        )
        d = rec.to_dict()
        assert d["technique"] == "rop"
        assert d["success_rate"] == 50.0
        assert d["environment"] == "docker"
        assert d["metadata"]["key"] == "value"


class TestTechniqueStats:
    """Tests for the TechniqueStats dataclass."""

    def test_creation(self) -> None:
        stats = TechniqueStats(
            technique="rop",
            total_validations=10,
            avg_success_rate=75.0,
        )
        assert stats.technique == "rop"
        assert stats.avg_success_rate == 75.0

    def test_to_dict(self) -> None:
        stats = TechniqueStats(
            technique="rop",
            total_validations=10,
            avg_success_rate=75.5,
            best_success_rate=100.0,
            worst_success_rate=50.0,
            total_iterations=500,
            avg_duration=1.234,
            common_failure_modes=["timeout"],
            environments_tested=["local", "docker"],
        )
        d = stats.to_dict()
        assert d["avg_success_rate"] == 75.5
        assert d["best_success_rate"] == 100.0
        assert "timeout" in d["common_failure_modes"]


class TestTechniqueRecommendation:
    """Tests for the TechniqueRecommendation dataclass."""

    def test_to_dict(self) -> None:
        rec = TechniqueRecommendation(
            technique="stack_bof",
            score=85.5,
            reason="High success rate",
            avg_success_rate=90.0,
            sample_size=20,
        )
        d = rec.to_dict()
        assert d["technique"] == "stack_bof"
        assert d["score"] == 85.5
        assert d["sample_size"] == 20


class TestLearningSystem:
    """Tests for the LearningSystem class."""

    @pytest.fixture
    def ls(self, tmp_dir: Path) -> LearningSystem:
        """Create a LearningSystem with a temp database."""
        ls = LearningSystem(db_path=tmp_dir / "test_learning.db")
        ls.initialize()
        return ls

    def test_initialization(self, ls: LearningSystem) -> None:
        assert ls.db_path.exists()

    def test_record_validation(self, ls: LearningSystem) -> None:
        row_id = ls.record_validation(
            technique="stack_bof",
            binary_hash="abc123",
            success_rate=85.0,
            iterations=100,
            environment="docker",
        )
        assert row_id > 0

    def test_count_records(self, ls: LearningSystem) -> None:
        assert ls.count_records() == 0
        ls.record_validation(
            technique="rop", binary_hash="abc", success_rate=50.0, iterations=10,
        )
        assert ls.count_records() == 1
        ls.record_validation(
            technique="rop", binary_hash="def", success_rate=75.0, iterations=10,
        )
        assert ls.count_records() == 2

    def test_get_validation_records_all(self, ls: LearningSystem) -> None:
        ls.record_validation(
            technique="rop", binary_hash="a", success_rate=80.0, iterations=10,
        )
        ls.record_validation(
            technique="bof", binary_hash="b", success_rate=60.0, iterations=5,
        )
        records = ls.get_validation_records()
        assert len(records) == 2

    def test_get_validation_records_filter_technique(self, ls: LearningSystem) -> None:
        ls.record_validation(
            technique="rop", binary_hash="a", success_rate=80.0, iterations=10,
        )
        ls.record_validation(
            technique="bof", binary_hash="b", success_rate=60.0, iterations=5,
        )
        records = ls.get_validation_records(technique="rop")
        assert len(records) == 1
        assert records[0].technique == "rop"

    def test_get_validation_records_filter_binary(self, ls: LearningSystem) -> None:
        ls.record_validation(
            technique="rop", binary_hash="hash1", success_rate=80.0, iterations=10,
        )
        ls.record_validation(
            technique="rop", binary_hash="hash2", success_rate=60.0, iterations=5,
        )
        records = ls.get_validation_records(binary_hash="hash1")
        assert len(records) == 1
        assert records[0].binary_hash == "hash1"

    def test_get_validation_records_filter_environment(self, ls: LearningSystem) -> None:
        ls.record_validation(
            technique="rop", binary_hash="a", success_rate=80.0,
            iterations=10, environment="docker",
        )
        ls.record_validation(
            technique="rop", binary_hash="b", success_rate=60.0,
            iterations=5, environment="local",
        )
        records = ls.get_validation_records(environment="docker")
        assert len(records) == 1
        assert records[0].environment == "docker"

    def test_get_technique_stats(self, ls: LearningSystem) -> None:
        ls.record_validation(
            technique="bof", binary_hash="a", success_rate=80.0, iterations=10,
            avg_duration=1.5, failure_mode="segfault",
        )
        ls.record_validation(
            technique="bof", binary_hash="b", success_rate=100.0, iterations=20,
            avg_duration=0.5,
        )
        stats = ls.get_technique_stats("bof")
        assert stats.technique == "bof"
        assert stats.total_validations == 2
        assert stats.avg_success_rate == 90.0
        assert stats.best_success_rate == 100.0
        assert stats.worst_success_rate == 80.0
        assert stats.total_iterations == 30
        assert stats.avg_duration == 1.0
        assert "segfault" in stats.common_failure_modes

    def test_get_technique_stats_empty(self, ls: LearningSystem) -> None:
        stats = ls.get_technique_stats("nonexistent")
        assert stats.total_validations == 0
        assert stats.avg_success_rate == 0.0

    def test_get_all_technique_stats(self, ls: LearningSystem) -> None:
        ls.record_validation(
            technique="bof", binary_hash="a", success_rate=90.0, iterations=10,
        )
        ls.record_validation(
            technique="rop", binary_hash="b", success_rate=60.0, iterations=10,
        )
        all_stats = ls.get_all_technique_stats()
        assert len(all_stats) == 2
        # Sorted by avg_success_rate descending
        assert all_stats[0].avg_success_rate >= all_stats[1].avg_success_rate

    def test_recommend_techniques(self, ls: LearningSystem) -> None:
        ls.record_validation(
            technique="bof", binary_hash="a", success_rate=95.0, iterations=50,
        )
        ls.record_validation(
            technique="rop", binary_hash="b", success_rate=60.0, iterations=10,
        )
        ls.record_validation(
            technique="format_string", binary_hash="c", success_rate=30.0, iterations=5,
        )
        recs = ls.recommend_techniques()
        assert len(recs) >= 2
        # Best technique should be first
        assert recs[0].technique == "bof"
        assert recs[0].score > recs[1].score

    def test_recommend_techniques_min_sample(self, ls: LearningSystem) -> None:
        ls.record_validation(
            technique="bof", binary_hash="a", success_rate=95.0, iterations=50,
        )
        # Require min 2 samples - bof only has 1
        recs = ls.recommend_techniques(min_sample_size=2)
        assert len(recs) == 0

    def test_recommend_techniques_top_n(self, ls: LearningSystem) -> None:
        for i in range(10):
            ls.record_validation(
                technique=f"tech_{i}", binary_hash="a", success_rate=50.0 + i,
                iterations=10,
            )
        recs = ls.recommend_techniques(top_n=3)
        assert len(recs) == 3

    def test_get_failure_patterns(self, ls: LearningSystem) -> None:
        # Record multiple failures with the same mode
        for _ in range(3):
            ls.record_validation(
                technique="bof", binary_hash="a", success_rate=20.0,
                iterations=10, failure_mode="segfault",
            )
        ls.record_validation(
            technique="bof", binary_hash="b", success_rate=0.0,
            iterations=5, failure_mode="timeout",
        )
        patterns = ls.get_failure_patterns(min_occurrences=2)
        assert len(patterns) >= 1
        segfault_patterns = [p for p in patterns if p["failure_mode"] == "segfault"]
        assert len(segfault_patterns) == 1
        assert segfault_patterns[0]["occurrences"] == 3

    def test_get_failure_patterns_by_technique(self, ls: LearningSystem) -> None:
        for _ in range(3):
            ls.record_validation(
                technique="bof", binary_hash="a", success_rate=20.0,
                iterations=10, failure_mode="segfault",
            )
        for _ in range(3):
            ls.record_validation(
                technique="rop", binary_hash="b", success_rate=10.0,
                iterations=10, failure_mode="crash",
            )
        patterns = ls.get_failure_patterns(technique="bof", min_occurrences=2)
        assert all(p["technique"] == "bof" for p in patterns)

    def test_get_tuning_hints_no_data(self, ls: LearningSystem) -> None:
        hints = ls.get_tuning_hints("nonexistent")
        assert any("no historical data" in h.lower() for h in hints)

    def test_get_tuning_hints_low_success(self, ls: LearningSystem) -> None:
        ls.record_validation(
            technique="bof", binary_hash="a", success_rate=10.0, iterations=50,
        )
        hints = ls.get_tuning_hints("bof")
        assert any("very low" in h.lower() for h in hints)

    def test_get_tuning_hints_moderate_success(self, ls: LearningSystem) -> None:
        ls.record_validation(
            technique="bof", binary_hash="a", success_rate=50.0, iterations=50,
        )
        hints = ls.get_tuning_hints("bof")
        assert any("moderate" in h.lower() for h in hints)

    def test_get_tuning_hints_with_timeout(self, ls: LearningSystem) -> None:
        ls.record_validation(
            technique="bof", binary_hash="a", success_rate=50.0,
            iterations=10, failure_mode="timeout",
        )
        hints = ls.get_tuning_hints("bof")
        assert any("timeout" in h.lower() for h in hints)

    def test_get_tuning_hints_with_segfault(self, ls: LearningSystem) -> None:
        ls.record_validation(
            technique="bof", binary_hash="a", success_rate=50.0,
            iterations=10, failure_mode="segfault",
        )
        hints = ls.get_tuning_hints("bof")
        assert any("segfault" in h.lower() for h in hints)

    def test_get_tuning_hints_high_variance(self, ls: LearningSystem) -> None:
        ls.record_validation(
            technique="bof", binary_hash="a", success_rate=100.0, iterations=10,
        )
        ls.record_validation(
            technique="bof", binary_hash="b", success_rate=10.0, iterations=10,
        )
        hints = ls.get_tuning_hints("bof")
        assert any("variance" in h.lower() for h in hints)

    def test_get_tuning_hints_local_only(self, ls: LearningSystem) -> None:
        ls.record_validation(
            technique="bof", binary_hash="a", success_rate=90.0,
            iterations=10, environment="local",
        )
        hints = ls.get_tuning_hints("bof")
        assert any("docker" in h.lower() for h in hints)

    def test_get_tuning_hints_good_performance(self, ls: LearningSystem) -> None:
        ls.record_validation(
            technique="bof", binary_hash="a", success_rate=95.0,
            iterations=100, environment="docker",
        )
        hints = ls.get_tuning_hints("bof")
        assert any("performing well" in h.lower() for h in hints)

    def test_purge_old_records(self, ls: LearningSystem) -> None:
        ls.record_validation(
            technique="bof", binary_hash="a", success_rate=80.0, iterations=10,
        )
        # Records just created shouldn't be purged with 90-day window
        deleted = ls.purge_old_records(days=90)
        assert deleted == 0
        assert ls.count_records() == 1

    def test_record_with_metadata(self, ls: LearningSystem) -> None:
        metadata = {"failure_analysis": {"primary": "segfault"}, "version": 1}
        row_id = ls.record_validation(
            technique="bof", binary_hash="abc", success_rate=50.0,
            iterations=10, metadata=metadata,
        )
        records = ls.get_validation_records(technique="bof")
        assert len(records) == 1
        assert records[0].metadata["version"] == 1

    def test_auto_initialization(self, tmp_dir: Path) -> None:
        """LearningSystem should auto-initialize on first operation."""
        ls = LearningSystem(db_path=tmp_dir / "auto_init.db")
        # _ensure_init should be called automatically
        ls.record_validation(
            technique="test", binary_hash="a", success_rate=50.0, iterations=1,
        )
        assert ls.count_records() == 1


class TestSuggestFix:
    """Tests for the failure fix suggestion function."""

    def test_timeout_suggestion(self) -> None:
        suggestion = _suggest_fix("timeout")
        assert "timeout" in suggestion.lower()

    def test_segfault_suggestion(self) -> None:
        suggestion = _suggest_fix("segfault")
        assert "offset" in suggestion.lower() or "segfault" in suggestion.lower()

    def test_crash_suggestion(self) -> None:
        suggestion = _suggest_fix("crash")
        assert "crash" in suggestion.lower() or "canary" in suggestion.lower()

    def test_unknown_suggestion(self) -> None:
        suggestion = _suggest_fix("unknown")
        assert "unknown" in suggestion.lower()

    def test_unrecognized_mode(self) -> None:
        suggestion = _suggest_fix("custom_failure")
        assert "custom_failure" in suggestion
