"""
RAVEN Vulnerability Pattern Matching Engine.

Takes a :class:`~raven.analysis.binary_loader.BinaryInfo` and runs it against
the :class:`~raven.analysis.patterns.PatternDatabase` to produce a set of
:class:`MatchResult` objects representing potential vulnerabilities.

The engine adjusts confidence scores based on:
  - Whether security mitigations are present
  - How many pattern conditions are satisfied
  - Whether safe alternatives to dangerous functions are also present
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from raven.analysis.binary_loader import BinaryInfo
from raven.analysis.patterns import (
    ExploitDifficulty,
    PatternCategory,
    PatternDatabase,
    PatternType,
    VulnPattern,
)
from raven.core.logger import get_logger

logger = get_logger("analysis.matcher")


# ---------------------------------------------------------------------------
# Match result model
# ---------------------------------------------------------------------------

@dataclass
class MatchResult:
    """The result of matching a single vulnerability pattern against a binary.

    Attributes:
        pattern_id: ID of the matched pattern.
        pattern_name: Human-readable name of the pattern.
        category: Vulnerability category.
        severity: Final severity after mitigation adjustments.
        confidence: Adjusted confidence (0-100).
        exploitability: Adjusted exploitation difficulty.
        matched_imports: Specific imports that triggered the match.
        matched_strings: Specific strings that triggered the match.
        matched_conditions: Security conditions that were satisfied.
        mitigations_present: Mitigations that reduce exploitability.
        mitigations_absent: Mitigations that are missing.
        description: Pattern description.
        cwe_ids: Associated CWE identifiers.
        technique: Suggested exploitation technique.
        exploitable: Whether the pattern is considered exploitable.
    """

    pattern_id: str
    pattern_name: str
    category: str
    severity: str
    confidence: float
    exploitability: str
    matched_imports: list[str] = field(default_factory=list)
    matched_strings: list[str] = field(default_factory=list)
    matched_conditions: dict[str, bool] = field(default_factory=dict)
    mitigations_present: list[str] = field(default_factory=list)
    mitigations_absent: list[str] = field(default_factory=list)
    description: str = ""
    cwe_ids: list[int] = field(default_factory=list)
    technique: str = ""
    exploitable: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize match result to a dictionary."""
        return {
            "pattern_id": self.pattern_id,
            "pattern_name": self.pattern_name,
            "category": self.category,
            "severity": self.severity,
            "confidence": round(self.confidence, 1),
            "exploitability": self.exploitability,
            "matched_imports": self.matched_imports,
            "matched_strings": self.matched_strings,
            "matched_conditions": self.matched_conditions,
            "mitigations_present": self.mitigations_present,
            "mitigations_absent": self.mitigations_absent,
            "description": self.description,
            "cwe_ids": self.cwe_ids,
            "technique": self.technique,
            "exploitable": self.exploitable,
        }


# ---------------------------------------------------------------------------
# Severity ordering (for comparisons and downgrade logic)
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

_SEVERITY_DOWNGRADE: dict[str, str] = {
    "critical": "high",
    "high": "medium",
    "medium": "low",
    "low": "info",
    "info": "info",
}


# ---------------------------------------------------------------------------
# Exploitability adjustments
# ---------------------------------------------------------------------------

_EXPLOIT_DIFFICULTY_ORDER = {
    ExploitDifficulty.TRIVIAL: 0,
    ExploitDifficulty.EASY: 1,
    ExploitDifficulty.MODERATE: 2,
    ExploitDifficulty.HARD: 3,
    ExploitDifficulty.VERY_HARD: 4,
}

_EXPLOIT_DIFFICULTY_UPGRADE: dict[ExploitDifficulty, ExploitDifficulty] = {
    ExploitDifficulty.TRIVIAL: ExploitDifficulty.EASY,
    ExploitDifficulty.EASY: ExploitDifficulty.MODERATE,
    ExploitDifficulty.MODERATE: ExploitDifficulty.HARD,
    ExploitDifficulty.HARD: ExploitDifficulty.VERY_HARD,
    ExploitDifficulty.VERY_HARD: ExploitDifficulty.VERY_HARD,
}


# ---------------------------------------------------------------------------
# Pattern matching engine
# ---------------------------------------------------------------------------

class PatternMatcher:
    """Matches vulnerability patterns against a loaded binary.

    Usage::

        db = PatternDatabase()
        db.load_defaults()
        matcher = PatternMatcher(db)
        results = matcher.match(binary_info)

    The matcher evaluates each pattern in the database against the binary's
    imports, strings, and security flags. It adjusts severity and confidence
    based on present mitigations.
    """

    def __init__(self, database: PatternDatabase) -> None:
        self._db = database

    def match(
        self,
        binary_info: BinaryInfo,
        *,
        categories: list[PatternCategory] | None = None,
        min_confidence: float = 0.0,
        min_severity: str | None = None,
    ) -> list[MatchResult]:
        """Run all applicable patterns against the binary.

        Args:
            binary_info: Loaded binary metadata.
            categories: If set, only match patterns in these categories.
            min_confidence: Discard results below this confidence threshold.
            min_severity: Discard results below this severity level.

        Returns:
            A list of :class:`MatchResult`, sorted by severity then confidence.
        """
        # Prepare the binary's import set for fast lookup
        clean_imports = {imp.split("@")[0] for imp in binary_info.imports}
        security = binary_info.security_summary

        patterns = self._db.all()
        if categories:
            cat_set = set(categories)
            patterns = [p for p in patterns if p.category in cat_set]

        results: list[MatchResult] = []
        for pattern in patterns:
            result = self._evaluate_pattern(pattern, binary_info, clean_imports, security)
            if result is None:
                continue

            # Apply filters
            if result.confidence < min_confidence:
                continue
            if min_severity and _SEVERITY_ORDER.get(result.severity, 5) > _SEVERITY_ORDER.get(
                min_severity, 5
            ):
                continue

            results.append(result)

        # Sort by severity (most severe first), then by confidence (highest first)
        results.sort(
            key=lambda r: (_SEVERITY_ORDER.get(r.severity, 5), -r.confidence)
        )

        logger.info(
            "Pattern matching complete: %d matches from %d patterns",
            len(results),
            len(patterns),
        )
        return results

    def _evaluate_pattern(
        self,
        pattern: VulnPattern,
        binary_info: BinaryInfo,
        clean_imports: set[str],
        security: dict[str, Any],
    ) -> MatchResult | None:
        """Evaluate a single pattern against the binary.

        Returns:
            A :class:`MatchResult` if the pattern matches, or ``None``.
        """
        matched_imports: list[str] = []
        matched_strings: list[str] = []
        matched_conditions: dict[str, bool] = {}

        # --- Evaluate based on pattern type ---

        if pattern.pattern_type == PatternType.IMPORT_PRESENCE:
            matched_imports = [imp for imp in pattern.imports if imp in clean_imports]
            if not matched_imports:
                return None

        elif pattern.pattern_type == PatternType.IMPORT_COMBINATION:
            matched_imports = [imp for imp in pattern.imports if imp in clean_imports]
            if pattern.required_all:
                if len(matched_imports) != len(pattern.imports):
                    return None
            else:
                if not matched_imports:
                    return None

        elif pattern.pattern_type == PatternType.IMPORT_ABSENCE:
            # Match if specified imports are NOT present
            present = [imp for imp in pattern.imports if imp in clean_imports]
            if present:
                return None
            matched_imports = pattern.imports  # they are all absent, which is the trigger

        elif pattern.pattern_type == PatternType.SECURITY_FLAG:
            for flag_name, expected_value in pattern.security_conditions.items():
                actual = security.get(flag_name)
                if actual is None:
                    return None
                # Handle RELRO specially (string comparison)
                if flag_name == "relro":
                    if expected_value is False:
                        if actual not in ("none", "partial"):
                            return None
                        matched_conditions[flag_name] = actual in ("none", "partial")
                    else:
                        if actual == "none":
                            return None
                        matched_conditions[flag_name] = actual != "none"
                else:
                    if bool(actual) != bool(expected_value):
                        return None
                    matched_conditions[flag_name] = bool(actual)

        elif pattern.pattern_type == PatternType.STRING_MATCH:
            # Must also have matching imports if specified
            if pattern.imports:
                import_matches = [imp for imp in pattern.imports if imp in clean_imports]
                if not import_matches:
                    return None
                matched_imports = import_matches

            # Check string patterns
            for regex in pattern.string_patterns:
                for s in binary_info.strings:
                    if re.search(regex, s):
                        matched_strings.append(s)
                        break  # one match per pattern is sufficient

            if not matched_strings and not matched_imports:
                return None

        # --- Check absent imports (safe alternatives) ---
        absent_check_passed = True
        if pattern.absent_imports:
            safe_present = [imp for imp in pattern.absent_imports if imp in clean_imports]
            if safe_present:
                # Safe alternatives are present -- reduce confidence significantly
                absent_check_passed = False

        # --- Calculate adjusted confidence ---
        confidence = pattern.base_confidence

        if not absent_check_passed:
            confidence *= 0.5  # Safe alternatives halve confidence

        # --- Calculate mitigation impact ---
        mitigations_present: list[str] = []
        mitigations_absent: list[str] = []
        severity = pattern.severity
        exploit_difficulty = pattern.exploitability

        for mitigation in pattern.mitigations:
            flag_value = security.get(mitigation)
            if flag_value is None:
                continue

            # Handle RELRO specially
            if mitigation == "relro":
                if flag_value == "full":
                    mitigations_present.append("relro (full)")
                elif flag_value == "partial":
                    mitigations_present.append("relro (partial)")
                else:
                    mitigations_absent.append(mitigation)
            elif bool(flag_value):
                mitigations_present.append(mitigation)
            else:
                mitigations_absent.append(mitigation)

        # Each present mitigation increases difficulty and reduces confidence
        for _ in mitigations_present:
            confidence -= 5.0
            exploit_difficulty = _EXPLOIT_DIFFICULTY_UPGRADE.get(
                exploit_difficulty, exploit_difficulty
            )

        # If many mitigations are absent, boost confidence
        if mitigations_absent:
            confidence += len(mitigations_absent) * 3.0

        # If NX is disabled and pattern is a buffer overflow, boost confidence
        if pattern.category == PatternCategory.BUFFER_OVERFLOW and not security.get("nx"):
            confidence += 10.0

        # Clamp confidence
        confidence = max(0.0, min(100.0, confidence))

        # Downgrade severity if many mitigations are present
        if len(mitigations_present) >= 3:
            severity = _SEVERITY_DOWNGRADE.get(severity, severity)

        # --- Determine exploitability ---
        exploitable = confidence >= 30.0 and _EXPLOIT_DIFFICULTY_ORDER.get(
            exploit_difficulty, 4
        ) <= 3

        return MatchResult(
            pattern_id=pattern.id,
            pattern_name=pattern.name,
            category=str(pattern.category),
            severity=severity,
            confidence=confidence,
            exploitability=str(exploit_difficulty),
            matched_imports=matched_imports,
            matched_strings=matched_strings,
            matched_conditions=matched_conditions,
            mitigations_present=mitigations_present,
            mitigations_absent=mitigations_absent,
            description=pattern.description,
            cwe_ids=pattern.cwe_ids,
            technique=pattern.technique,
            exploitable=exploitable,
        )


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def scan_binary(
    binary_info: BinaryInfo,
    *,
    categories: list[PatternCategory] | None = None,
    min_confidence: float = 0.0,
    min_severity: str | None = None,
) -> list[MatchResult]:
    """Scan a binary for vulnerability patterns.

    This is the primary public API for the pattern matching engine.
    It loads the default pattern database and runs the matcher.

    Args:
        binary_info: Loaded binary metadata.
        categories: Optional category filter.
        min_confidence: Minimum confidence threshold.
        min_severity: Minimum severity level.

    Returns:
        A list of :class:`MatchResult`, sorted by severity then confidence.
    """
    db = PatternDatabase()
    db.load_defaults()
    matcher = PatternMatcher(db)
    return matcher.match(
        binary_info,
        categories=categories,
        min_confidence=min_confidence,
        min_severity=min_severity,
    )
