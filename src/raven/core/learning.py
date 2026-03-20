"""
RAVEN Learning and Adaptation System.

Provides a feedback loop that improves exploit generation over time:
  - Records validation results (success rate, environment, technique)
  - Tracks per-technique and per-binary reliability statistics
  - Recommends techniques based on historical success data
  - Detects patterns in failures for auto-tuning
  - Stores all data in a local SQLite database

The learning system is separate from the Knowledge Base to keep
operational data (what worked) distinct from reference data (CVEs,
templates).
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

from raven.core.logger import get_logger

logger = get_logger("core.learning")

# Default database location
_DEFAULT_DB_DIR = Path.home() / ".local" / "share" / "raven"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ValidationRecord:
    """A recorded validation result for learning.

    Attributes:
        id: Auto-assigned row ID (0 if not yet stored).
        technique: Exploitation technique used.
        binary_hash: SHA256 hash of the target binary.
        success_rate: Percentage of successful runs (0-100).
        iterations: Number of test iterations.
        environment: Validation environment (local/docker/qemu).
        avg_duration: Average run duration in seconds.
        failure_mode: Primary failure mode if any.
        metadata: Additional data (failure analysis, etc.).
        recorded_at: ISO timestamp of when this was recorded.
    """

    id: int = 0
    technique: str = ""
    binary_hash: str = ""
    success_rate: float = 0.0
    iterations: int = 0
    environment: str = "local"
    avg_duration: float = 0.0
    failure_mode: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    recorded_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "technique": self.technique,
            "binary_hash": self.binary_hash,
            "success_rate": self.success_rate,
            "iterations": self.iterations,
            "environment": self.environment,
            "avg_duration": self.avg_duration,
            "failure_mode": self.failure_mode,
            "metadata": self.metadata,
            "recorded_at": self.recorded_at,
        }


@dataclass
class TechniqueStats:
    """Aggregate statistics for an exploitation technique.

    Attributes:
        technique: Name of the technique.
        total_validations: Number of times this technique was validated.
        avg_success_rate: Average success rate across all validations.
        best_success_rate: Highest success rate achieved.
        worst_success_rate: Lowest success rate observed.
        total_iterations: Total iterations run.
        avg_duration: Average execution duration.
        common_failure_modes: Most common failure modes.
        environments_tested: Set of environments tested in.
    """

    technique: str = ""
    total_validations: int = 0
    avg_success_rate: float = 0.0
    best_success_rate: float = 0.0
    worst_success_rate: float = 100.0
    total_iterations: int = 0
    avg_duration: float = 0.0
    common_failure_modes: list[str] = field(default_factory=list)
    environments_tested: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique": self.technique,
            "total_validations": self.total_validations,
            "avg_success_rate": round(self.avg_success_rate, 1),
            "best_success_rate": round(self.best_success_rate, 1),
            "worst_success_rate": round(self.worst_success_rate, 1),
            "total_iterations": self.total_iterations,
            "avg_duration": round(self.avg_duration, 3),
            "common_failure_modes": self.common_failure_modes,
            "environments_tested": self.environments_tested,
        }


@dataclass
class TechniqueRecommendation:
    """A technique recommendation based on historical data.

    Attributes:
        technique: Recommended technique name.
        score: Recommendation score (0-100, higher is better).
        reason: Why this technique is recommended.
        avg_success_rate: Historical average success rate.
        sample_size: Number of past validations informing this recommendation.
    """

    technique: str = ""
    score: float = 0.0
    reason: str = ""
    avg_success_rate: float = 0.0
    sample_size: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique": self.technique,
            "score": round(self.score, 1),
            "reason": self.reason,
            "avg_success_rate": round(self.avg_success_rate, 1),
            "sample_size": self.sample_size,
        }


# ---------------------------------------------------------------------------
# Learning System
# ---------------------------------------------------------------------------

class LearningSystem:
    """Feedback-driven learning system backed by SQLite.

    Records validation results, computes technique statistics, and
    recommends techniques based on historical success data.

    Example::

        ls = LearningSystem()
        ls.record_validation(
            technique="stack_buffer_overflow",
            binary_hash="abc123...",
            success_rate=85.0,
            iterations=100,
            environment="docker",
        )
        stats = ls.get_technique_stats("stack_buffer_overflow")
        recs = ls.recommend_techniques(arch="x86_64")
    """

    def __init__(self, db_path: Path | str | None = None) -> None:
        """Initialize the learning system.

        Args:
            db_path: Path to the SQLite database. If None, uses the
                     default location under ``~/.local/share/raven/``.
        """
        if db_path is None:
            import os
            data_dir = os.environ.get("RAVEN_DATA_DIR", str(_DEFAULT_DB_DIR))
            self._db_path = Path(data_dir) / "learning.db"
        else:
            self._db_path = Path(db_path)
        self._initialized = False

    @property
    def db_path(self) -> Path:
        """Return the path to the learning database."""
        return self._db_path

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for database connections."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def initialize(self) -> None:
        """Create the database schema if it does not exist."""
        with self._connect() as conn:
            conn.executescript(_LEARNING_SCHEMA)
        self._initialized = True
        logger.info("Learning system initialized at %s", self._db_path)

    def _ensure_init(self) -> None:
        """Ensure the database is initialized before operations."""
        if not self._initialized:
            self.initialize()

    # ------------------------------------------------------------------
    # Record validation results
    # ------------------------------------------------------------------

    def record_validation(
        self,
        technique: str,
        binary_hash: str,
        success_rate: float,
        iterations: int,
        environment: str = "local",
        avg_duration: float = 0.0,
        failure_mode: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> int:
        """Record a validation result in the learning database.

        Args:
            technique: Exploitation technique used.
            binary_hash: SHA256 hash of the target binary.
            success_rate: Percentage of successful runs (0-100).
            iterations: Number of test iterations.
            environment: Validation environment.
            avg_duration: Average run duration in seconds.
            failure_mode: Primary failure mode, if any.
            metadata: Additional metadata (failure analysis, etc.).

        Returns:
            The row ID of the new record.
        """
        self._ensure_init()
        now = datetime.now(timezone.utc).isoformat()
        meta_json = json.dumps(metadata or {})

        with self._connect() as conn:
            cursor = conn.execute(
                """INSERT INTO validation_records
                   (technique, binary_hash, success_rate, iterations,
                    environment, avg_duration, failure_mode, metadata, recorded_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    technique, binary_hash, success_rate, iterations,
                    environment, avg_duration, failure_mode, meta_json, now,
                ),
            )
            row_id = cursor.lastrowid or 0

        logger.info(
            "Recorded validation: technique=%s, success=%.1f%%, iterations=%d",
            technique, success_rate, iterations,
        )
        return row_id

    def get_validation_records(
        self,
        *,
        technique: str | None = None,
        binary_hash: str | None = None,
        environment: str | None = None,
        limit: int = 100,
    ) -> list[ValidationRecord]:
        """Retrieve validation records with optional filters.

        Args:
            technique: Filter by technique.
            binary_hash: Filter by binary hash.
            environment: Filter by environment.
            limit: Maximum records to return.

        Returns:
            A list of :class:`ValidationRecord` ordered by most recent first.
        """
        self._ensure_init()
        sql = "SELECT * FROM validation_records WHERE 1=1"
        params: list[Any] = []

        if technique:
            sql += " AND technique = ?"
            params.append(technique)
        if binary_hash:
            sql += " AND binary_hash = ?"
            params.append(binary_hash)
        if environment:
            sql += " AND environment = ?"
            params.append(environment)

        sql += " ORDER BY recorded_at DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()

        return [self._row_to_record(r) for r in rows]

    def count_records(self) -> int:
        """Return total number of validation records."""
        self._ensure_init()
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM validation_records").fetchone()
        return row[0] if row else 0

    # ------------------------------------------------------------------
    # Statistics computation
    # ------------------------------------------------------------------

    def get_technique_stats(self, technique: str) -> TechniqueStats:
        """Compute aggregate statistics for a specific technique.

        Args:
            technique: The technique to compute statistics for.

        Returns:
            A :class:`TechniqueStats` with aggregated data.
        """
        self._ensure_init()
        records = self.get_validation_records(technique=technique, limit=1000)

        if not records:
            return TechniqueStats(technique=technique)

        success_rates = [r.success_rate for r in records]
        durations = [r.avg_duration for r in records if r.avg_duration > 0]
        failure_modes = [r.failure_mode for r in records if r.failure_mode]
        environments = list({r.environment for r in records})

        # Count failure mode frequencies
        mode_counts: dict[str, int] = {}
        for mode in failure_modes:
            mode_counts[mode] = mode_counts.get(mode, 0) + 1
        common_modes = sorted(mode_counts.keys(), key=lambda m: -mode_counts[m])

        return TechniqueStats(
            technique=technique,
            total_validations=len(records),
            avg_success_rate=sum(success_rates) / len(success_rates),
            best_success_rate=max(success_rates),
            worst_success_rate=min(success_rates),
            total_iterations=sum(r.iterations for r in records),
            avg_duration=sum(durations) / len(durations) if durations else 0.0,
            common_failure_modes=common_modes[:5],
            environments_tested=environments,
        )

    def get_all_technique_stats(self) -> list[TechniqueStats]:
        """Compute statistics for all techniques with recorded data.

        Returns:
            A list of :class:`TechniqueStats`, sorted by average success rate.
        """
        self._ensure_init()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT technique FROM validation_records"
            ).fetchall()

        techniques = [r["technique"] for r in rows]
        stats = [self.get_technique_stats(t) for t in techniques]
        stats.sort(key=lambda s: -s.avg_success_rate)
        return stats

    # ------------------------------------------------------------------
    # Technique recommendations
    # ------------------------------------------------------------------

    def recommend_techniques(
        self,
        *,
        arch: str | None = None,
        min_sample_size: int = 1,
        top_n: int = 5,
    ) -> list[TechniqueRecommendation]:
        """Recommend techniques based on historical success data.

        Scores techniques by their average success rate, weighted by
        sample size (more data = more confidence).

        Args:
            arch: Optional architecture filter (currently informational).
            min_sample_size: Minimum validations required for a recommendation.
            top_n: Number of top recommendations to return.

        Returns:
            A list of :class:`TechniqueRecommendation`, best first.
        """
        all_stats = self.get_all_technique_stats()

        recommendations: list[TechniqueRecommendation] = []
        for stats in all_stats:
            if stats.total_validations < min_sample_size:
                continue

            # Score: base is avg_success_rate, with confidence bonus for sample size
            confidence_factor = min(1.0, stats.total_validations / 10.0)
            score = stats.avg_success_rate * (0.7 + 0.3 * confidence_factor)

            # Build reason string
            reason_parts: list[str] = []
            reason_parts.append(
                f"Avg success: {stats.avg_success_rate:.0f}%"
            )
            reason_parts.append(
                f"over {stats.total_validations} validation(s)"
            )
            if stats.best_success_rate == 100.0:
                reason_parts.append("achieved 100% in at least one test")

            recommendations.append(TechniqueRecommendation(
                technique=stats.technique,
                score=score,
                reason="; ".join(reason_parts),
                avg_success_rate=stats.avg_success_rate,
                sample_size=stats.total_validations,
            ))

        recommendations.sort(key=lambda r: -r.score)
        return recommendations[:top_n]

    # ------------------------------------------------------------------
    # Failure pattern analysis
    # ------------------------------------------------------------------

    def get_failure_patterns(
        self,
        technique: str | None = None,
        min_occurrences: int = 2,
    ) -> list[dict[str, Any]]:
        """Identify recurring failure patterns from validation history.

        Groups failures by mode and technique, returning patterns that
        occur more than ``min_occurrences`` times.

        Args:
            technique: Optional filter to a single technique.
            min_occurrences: Minimum occurrences to be considered a pattern.

        Returns:
            A list of dicts describing each failure pattern.
        """
        self._ensure_init()
        sql = """
            SELECT technique, failure_mode, COUNT(*) as count,
                   AVG(success_rate) as avg_rate
            FROM validation_records
            WHERE failure_mode != ''
        """
        params: list[Any] = []
        if technique:
            sql += " AND technique = ?"
            params.append(technique)

        sql += " GROUP BY technique, failure_mode HAVING count >= ?"
        params.append(min_occurrences)
        sql += " ORDER BY count DESC"

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()

        patterns: list[dict[str, Any]] = []
        for row in rows:
            suggestion = _suggest_fix(row["failure_mode"])
            patterns.append({
                "technique": row["technique"],
                "failure_mode": row["failure_mode"],
                "occurrences": row["count"],
                "avg_success_rate_when_failing": round(row["avg_rate"], 1),
                "suggestion": suggestion,
            })

        return patterns

    # ------------------------------------------------------------------
    # Auto-tuning hints
    # ------------------------------------------------------------------

    def get_tuning_hints(self, technique: str) -> list[str]:
        """Generate auto-tuning hints for a technique based on history.

        Analyzes past failures and successes to suggest parameter
        adjustments that may improve reliability.

        Args:
            technique: The technique to generate hints for.

        Returns:
            A list of tuning suggestion strings.
        """
        stats = self.get_technique_stats(technique)
        hints: list[str] = []

        if stats.total_validations == 0:
            hints.append("No historical data. Run validation to collect baseline data.")
            return hints

        if stats.avg_success_rate < 25:
            hints.append(
                "Very low success rate. Verify the vulnerability exists and "
                "offset calculations are correct."
            )

        if stats.avg_success_rate >= 25 and stats.avg_success_rate < 75:
            hints.append(
                "Moderate success rate. Consider ASLR brute-forcing or "
                "info leak to improve reliability."
            )

        if "timeout" in stats.common_failure_modes:
            hints.append("Timeouts detected. Increase timeout or optimize exploit speed.")

        if "segfault" in stats.common_failure_modes:
            hints.append(
                "Segfaults detected. Check buffer offset, return address, "
                "and stack alignment."
            )

        if "crash" in stats.common_failure_modes:
            hints.append(
                "Crashes detected. Verify exploit payload does not corrupt "
                "critical structures."
            )

        if stats.best_success_rate == 100.0 and stats.worst_success_rate < 50.0:
            hints.append(
                "High variance in results. The exploit may be sensitive to "
                "ASLR, timing, or environment differences."
            )

        if len(stats.environments_tested) == 1:
            env = stats.environments_tested[0]
            if env == "local":
                hints.append(
                    "Only tested locally. Validate in Docker for proper isolation."
                )

        if stats.avg_duration > 10.0:
            hints.append(
                "Average duration is high. Optimize exploit to run faster."
            )

        if not hints:
            hints.append(
                f"Technique is performing well ({stats.avg_success_rate:.0f}% avg)."
            )

        return hints

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def purge_old_records(self, days: int = 90) -> int:
        """Delete validation records older than the specified number of days.

        Args:
            days: Records older than this many days will be deleted.

        Returns:
            The number of records deleted.
        """
        self._ensure_init()
        cutoff = datetime.now(timezone.utc)
        # Simple approach: compare ISO date strings
        from datetime import timedelta
        cutoff_str = (cutoff - timedelta(days=days)).isoformat()

        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM validation_records WHERE recorded_at < ?",
                (cutoff_str,),
            )
            deleted = cursor.rowcount

        logger.info("Purged %d records older than %d days", deleted, days)
        return deleted

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ValidationRecord:
        """Convert a database row to a ValidationRecord."""
        return ValidationRecord(
            id=row["id"],
            technique=row["technique"],
            binary_hash=row["binary_hash"],
            success_rate=row["success_rate"],
            iterations=row["iterations"],
            environment=row["environment"],
            avg_duration=row["avg_duration"],
            failure_mode=row["failure_mode"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            recorded_at=row["recorded_at"],
        )


# ---------------------------------------------------------------------------
# Fix suggestions for common failure modes
# ---------------------------------------------------------------------------

def _suggest_fix(failure_mode: str) -> str:
    """Return a fix suggestion for a known failure mode."""
    suggestions: dict[str, str] = {
        "timeout": (
            "Exploit timed out. Consider increasing the timeout, "
            "optimizing the payload, or checking for deadlocks."
        ),
        "segfault": (
            "Segmentation fault detected. The buffer offset or return address "
            "may be incorrect. Use a cyclic pattern to verify the offset."
        ),
        "crash": (
            "Target crashed. Check for stack canary detection, "
            "NX enforcement, or incorrect address calculations."
        ),
        "unknown": (
            "Unknown failure mode. Enable debug output for more details."
        ),
    }
    return suggestions.get(failure_mode, f"Unrecognized failure mode: {failure_mode}")


# ---------------------------------------------------------------------------
# Database schema
# ---------------------------------------------------------------------------

_LEARNING_SCHEMA = """
CREATE TABLE IF NOT EXISTS validation_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    technique TEXT NOT NULL DEFAULT '',
    binary_hash TEXT NOT NULL DEFAULT '',
    success_rate REAL NOT NULL DEFAULT 0.0,
    iterations INTEGER NOT NULL DEFAULT 0,
    environment TEXT NOT NULL DEFAULT 'local',
    avg_duration REAL NOT NULL DEFAULT 0.0,
    failure_mode TEXT NOT NULL DEFAULT '',
    metadata TEXT NOT NULL DEFAULT '{}',
    recorded_at TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_vr_technique
    ON validation_records(technique);
CREATE INDEX IF NOT EXISTS idx_vr_binary_hash
    ON validation_records(binary_hash);
CREATE INDEX IF NOT EXISTS idx_vr_environment
    ON validation_records(environment);
CREATE INDEX IF NOT EXISTS idx_vr_recorded_at
    ON validation_records(recorded_at);
"""
