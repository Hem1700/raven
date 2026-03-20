"""
RAVEN Vulnerability Pattern Database.

Defines vulnerability patterns as structured data that the pattern matching
engine uses to detect potential security issues in binaries. Patterns are
organised by category (buffer overflow, format string, integer overflow,
use-after-free) and include metadata for severity, confidence, and
exploitability assessment.

Each pattern specifies:
  - What to look for (import names, sequences, byte signatures)
  - How severe the issue is (severity + confidence baseline)
  - How exploitable it is likely to be (exploitability score)
  - What mitigations affect it (PIE, NX, canary, RELRO, FORTIFY)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Pattern types and categories
# ---------------------------------------------------------------------------

class PatternCategory(str, Enum):
    """High-level vulnerability category."""

    BUFFER_OVERFLOW = "buffer_overflow"
    FORMAT_STRING = "format_string"
    INTEGER_OVERFLOW = "integer_overflow"
    USE_AFTER_FREE = "use_after_free"
    COMMAND_INJECTION = "command_injection"
    RACE_CONDITION = "race_condition"
    HEAP_CORRUPTION = "heap_corruption"
    LOGIC_BUG = "logic_bug"

    def __str__(self) -> str:
        return self.value


class PatternType(str, Enum):
    """How the pattern is matched against the binary."""

    IMPORT_PRESENCE = "import_presence"
    IMPORT_COMBINATION = "import_combination"
    IMPORT_ABSENCE = "import_absence"
    STRING_MATCH = "string_match"
    SECURITY_FLAG = "security_flag"

    def __str__(self) -> str:
        return self.value


class ExploitDifficulty(str, Enum):
    """Estimated difficulty of exploiting a matched pattern."""

    TRIVIAL = "trivial"
    EASY = "easy"
    MODERATE = "moderate"
    HARD = "hard"
    VERY_HARD = "very_hard"

    def __str__(self) -> str:
        return self.value


# ---------------------------------------------------------------------------
# Pattern data model
# ---------------------------------------------------------------------------

@dataclass
class VulnPattern:
    """A single vulnerability detection pattern.

    Attributes:
        id: Unique pattern identifier (e.g. ``BOF-001``).
        name: Human-readable pattern name.
        category: Vulnerability category.
        pattern_type: How the pattern is matched.
        description: Detailed description of the vulnerability.
        severity: Default severity (critical/high/medium/low/info).
        base_confidence: Baseline confidence score (0-100).
        exploitability: Estimated exploitation difficulty.
        imports: Import names that trigger this pattern.
        required_all: If True, *all* imports must be present; otherwise *any*.
        absent_imports: Imports whose presence *negates* the pattern (safe versions).
        string_patterns: Regex patterns to match in binary strings.
        security_conditions: Security flags that affect severity.
        mitigations: Security mechanisms that reduce exploitability.
        cwe_ids: Associated CWE identifiers.
        references: External reference URLs or identifiers.
        technique: Suggested exploitation technique.
        tags: Arbitrary tags for filtering.
    """

    id: str
    name: str
    category: PatternCategory
    pattern_type: PatternType
    description: str
    severity: str = "medium"
    base_confidence: float = 50.0
    exploitability: ExploitDifficulty = ExploitDifficulty.MODERATE
    imports: list[str] = field(default_factory=list)
    required_all: bool = False
    absent_imports: list[str] = field(default_factory=list)
    string_patterns: list[str] = field(default_factory=list)
    security_conditions: dict[str, bool] = field(default_factory=dict)
    mitigations: list[str] = field(default_factory=list)
    cwe_ids: list[int] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    technique: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize pattern to a dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "category": str(self.category),
            "pattern_type": str(self.pattern_type),
            "description": self.description,
            "severity": self.severity,
            "base_confidence": self.base_confidence,
            "exploitability": str(self.exploitability),
            "imports": self.imports,
            "required_all": self.required_all,
            "absent_imports": self.absent_imports,
            "string_patterns": self.string_patterns,
            "security_conditions": self.security_conditions,
            "mitigations": self.mitigations,
            "cwe_ids": self.cwe_ids,
            "references": self.references,
            "technique": self.technique,
            "tags": self.tags,
        }


# ---------------------------------------------------------------------------
# Built-in pattern library
# ---------------------------------------------------------------------------

# ---- Buffer Overflow Patterns (5 patterns) --------------------------------

_BUFFER_OVERFLOW_PATTERNS: list[VulnPattern] = [
    VulnPattern(
        id="BOF-001",
        name="Unbounded gets() Usage",
        category=PatternCategory.BUFFER_OVERFLOW,
        pattern_type=PatternType.IMPORT_PRESENCE,
        description=(
            "The binary imports gets(), which reads user input into a buffer "
            "with no length limit. This is always exploitable for stack buffer "
            "overflow when the function is reachable with attacker-controlled input."
        ),
        severity="critical",
        base_confidence=95.0,
        exploitability=ExploitDifficulty.TRIVIAL,
        imports=["gets"],
        absent_imports=["fgets"],
        mitigations=["canary", "nx", "pie"],
        cwe_ids=[120, 787],
        technique="stack_buffer_overflow",
        tags=["classic", "ctf", "easy-win"],
    ),
    VulnPattern(
        id="BOF-002",
        name="Unsafe strcpy/strcat Without Bounds Checking",
        category=PatternCategory.BUFFER_OVERFLOW,
        pattern_type=PatternType.IMPORT_COMBINATION,
        description=(
            "The binary uses strcpy() or strcat() without corresponding "
            "bounds-checked alternatives (strncpy, strncat, strlcpy, strlcat). "
            "If the source is attacker-controlled, this leads to a stack or "
            "heap buffer overflow."
        ),
        severity="high",
        base_confidence=80.0,
        exploitability=ExploitDifficulty.EASY,
        imports=["strcpy", "strcat"],
        required_all=False,
        absent_imports=["strncpy", "strncat", "strlcpy", "strlcat"],
        mitigations=["canary", "nx", "pie", "fortify"],
        cwe_ids=[120, 787, 121],
        technique="stack_buffer_overflow",
        tags=["classic", "common"],
    ),
    VulnPattern(
        id="BOF-003",
        name="Unsafe sprintf Without Bounds Checking",
        category=PatternCategory.BUFFER_OVERFLOW,
        pattern_type=PatternType.IMPORT_COMBINATION,
        description=(
            "The binary uses sprintf() or vsprintf() without corresponding "
            "bounds-checked alternatives (snprintf, vsnprintf). Formatted "
            "output without length limits can overflow the destination buffer."
        ),
        severity="high",
        base_confidence=75.0,
        exploitability=ExploitDifficulty.EASY,
        imports=["sprintf", "vsprintf"],
        required_all=False,
        absent_imports=["snprintf", "vsnprintf"],
        mitigations=["canary", "nx", "pie", "fortify"],
        cwe_ids=[120, 787, 134],
        technique="stack_buffer_overflow",
        tags=["classic", "common"],
    ),
    VulnPattern(
        id="BOF-004",
        name="Network Input Without Bounds Checking",
        category=PatternCategory.BUFFER_OVERFLOW,
        pattern_type=PatternType.IMPORT_COMBINATION,
        description=(
            "The binary receives network input (recv/recvfrom) and also uses "
            "unsafe copy functions (strcpy/strcat/sprintf). Network data is "
            "untrusted and may be used to overflow buffers."
        ),
        severity="high",
        base_confidence=70.0,
        exploitability=ExploitDifficulty.MODERATE,
        imports=["recv", "recvfrom"],
        required_all=False,
        mitigations=["canary", "nx", "pie", "fortify"],
        cwe_ids=[120, 787, 20],
        technique="stack_buffer_overflow",
        tags=["network", "remote"],
    ),
    VulnPattern(
        id="BOF-005",
        name="Stack Buffer Overflow with No Canary and No NX",
        category=PatternCategory.BUFFER_OVERFLOW,
        pattern_type=PatternType.SECURITY_FLAG,
        description=(
            "The binary has no stack canary protection and an executable stack (NX disabled). "
            "Any stack buffer overflow can directly overwrite the return address "
            "and execute shellcode on the stack. This is the simplest exploitation "
            "scenario."
        ),
        severity="critical",
        base_confidence=90.0,
        exploitability=ExploitDifficulty.TRIVIAL,
        security_conditions={"canary": False, "nx": False},
        mitigations=[],
        cwe_ids=[121, 787],
        technique="stack_shellcode",
        tags=["easy-win", "ctf", "no-mitigations"],
    ),
]

# ---- Format String Patterns (3 patterns) ----------------------------------

_FORMAT_STRING_PATTERNS: list[VulnPattern] = [
    VulnPattern(
        id="FMT-001",
        name="printf Family Without Format String Constant",
        category=PatternCategory.FORMAT_STRING,
        pattern_type=PatternType.IMPORT_PRESENCE,
        description=(
            "The binary imports printf/fprintf/sprintf without FORTIFY_SOURCE "
            "protection. If any call passes user-controlled data as the format "
            "argument, the binary is vulnerable to format string attacks "
            "allowing arbitrary read/write."
        ),
        severity="high",
        base_confidence=60.0,
        exploitability=ExploitDifficulty.MODERATE,
        imports=["printf", "fprintf", "sprintf"],
        required_all=False,
        mitigations=["fortify", "pie", "relro"],
        cwe_ids=[134],
        technique="format_string",
        tags=["classic", "common"],
    ),
    VulnPattern(
        id="FMT-002",
        name="syslog Format String",
        category=PatternCategory.FORMAT_STRING,
        pattern_type=PatternType.IMPORT_PRESENCE,
        description=(
            "The binary uses syslog(), which takes a format string argument. "
            "If user-controlled data is passed as the format string, this "
            "enables remote format string exploitation."
        ),
        severity="high",
        base_confidence=55.0,
        exploitability=ExploitDifficulty.MODERATE,
        imports=["syslog"],
        mitigations=["fortify", "pie", "relro"],
        cwe_ids=[134],
        technique="format_string",
        tags=["daemon", "logging"],
    ),
    VulnPattern(
        id="FMT-003",
        name="Format Specifier Strings in Binary",
        category=PatternCategory.FORMAT_STRING,
        pattern_type=PatternType.STRING_MATCH,
        description=(
            "The binary contains strings with format specifiers (%s, %x, %n, %p) "
            "combined with printf-family imports. The presence of %n is "
            "particularly interesting as it enables arbitrary memory writes."
        ),
        severity="medium",
        base_confidence=45.0,
        exploitability=ExploitDifficulty.MODERATE,
        imports=["printf", "fprintf", "sprintf", "snprintf"],
        required_all=False,
        string_patterns=[r"%n", r"%[0-9]*\$n", r"%[0-9]*\$x", r"%[0-9]*\$p"],
        mitigations=["fortify", "pie", "relro"],
        cwe_ids=[134],
        technique="format_string",
        tags=["deep-analysis"],
    ),
]

# ---- Integer Overflow Patterns (3 patterns) --------------------------------

_INTEGER_OVERFLOW_PATTERNS: list[VulnPattern] = [
    VulnPattern(
        id="INT-001",
        name="Integer to Allocation Size",
        category=PatternCategory.INTEGER_OVERFLOW,
        pattern_type=PatternType.IMPORT_COMBINATION,
        description=(
            "The binary uses malloc/calloc/realloc alongside arithmetic or "
            "user input functions. Integer overflow in size calculations "
            "before allocation can lead to undersized buffers and subsequent "
            "heap overflows."
        ),
        severity="high",
        base_confidence=50.0,
        exploitability=ExploitDifficulty.HARD,
        imports=["malloc", "calloc", "realloc"],
        required_all=False,
        mitigations=["fortify"],
        cwe_ids=[190, 680],
        technique="heap_overflow",
        tags=["heap", "subtle"],
    ),
    VulnPattern(
        id="INT-002",
        name="atoi/strtol Input Conversion",
        category=PatternCategory.INTEGER_OVERFLOW,
        pattern_type=PatternType.IMPORT_COMBINATION,
        description=(
            "The binary converts string input to integers (atoi/atol/strtol) "
            "and also uses memory allocation. Unchecked integer conversion "
            "can yield negative or very large values that cause integer "
            "overflow when used as sizes or indices."
        ),
        severity="medium",
        base_confidence=45.0,
        exploitability=ExploitDifficulty.HARD,
        imports=["atoi", "atol", "strtol", "strtoul"],
        required_all=False,
        mitigations=[],
        cwe_ids=[190, 191, 681],
        technique="integer_overflow",
        tags=["input-handling"],
    ),
    VulnPattern(
        id="INT-003",
        name="read() Size Controlled by User Input",
        category=PatternCategory.INTEGER_OVERFLOW,
        pattern_type=PatternType.IMPORT_COMBINATION,
        description=(
            "The binary reads from file descriptors or network sockets and "
            "also converts user input to integers. If the size argument to "
            "read()/recv() is derived from user input, an integer overflow "
            "could cause a buffer overflow."
        ),
        severity="medium",
        base_confidence=40.0,
        exploitability=ExploitDifficulty.HARD,
        imports=["read", "recv"],
        required_all=False,
        mitigations=["canary", "nx"],
        cwe_ids=[190, 805],
        technique="integer_overflow",
        tags=["input-handling", "subtle"],
    ),
]

# ---- Use-After-Free Patterns (2 patterns) ----------------------------------

_USE_AFTER_FREE_PATTERNS: list[VulnPattern] = [
    VulnPattern(
        id="UAF-001",
        name="malloc/free Without Use-After-Free Protection",
        category=PatternCategory.USE_AFTER_FREE,
        pattern_type=PatternType.IMPORT_COMBINATION,
        description=(
            "The binary uses both malloc() and free(). Without careful pointer "
            "management, freed memory may be accessed (use-after-free) or freed "
            "twice (double-free), both of which are exploitable on the heap."
        ),
        severity="high",
        base_confidence=40.0,
        exploitability=ExploitDifficulty.HARD,
        imports=["malloc", "free"],
        required_all=True,
        mitigations=[],
        cwe_ids=[416, 415],
        technique="heap_exploit",
        tags=["heap", "advanced"],
    ),
    VulnPattern(
        id="UAF-002",
        name="realloc with Stale Pointer Risk",
        category=PatternCategory.USE_AFTER_FREE,
        pattern_type=PatternType.IMPORT_COMBINATION,
        description=(
            "The binary uses realloc(), which may return a different pointer "
            "if the block cannot grow in place. If the old pointer is not "
            "updated, this creates a use-after-free / stale-pointer condition."
        ),
        severity="medium",
        base_confidence=35.0,
        exploitability=ExploitDifficulty.HARD,
        imports=["realloc"],
        required_all=False,
        mitigations=[],
        cwe_ids=[416, 761],
        technique="heap_exploit",
        tags=["heap", "subtle"],
    ),
]

# ---- Command Injection Patterns -------------------------------------------

_COMMAND_INJECTION_PATTERNS: list[VulnPattern] = [
    VulnPattern(
        id="CMD-001",
        name="system() / popen() Command Execution",
        category=PatternCategory.COMMAND_INJECTION,
        pattern_type=PatternType.IMPORT_PRESENCE,
        description=(
            "The binary uses system() or popen() to execute shell commands. "
            "If any part of the command string is derived from user input, "
            "this allows arbitrary command injection."
        ),
        severity="high",
        base_confidence=65.0,
        exploitability=ExploitDifficulty.EASY,
        imports=["system", "popen"],
        required_all=False,
        mitigations=[],
        cwe_ids=[78, 77],
        technique="command_injection",
        tags=["shell", "common"],
    ),
]

# ---- Race Condition Patterns -----------------------------------------------

_RACE_CONDITION_PATTERNS: list[VulnPattern] = [
    VulnPattern(
        id="RACE-001",
        name="TOCTOU File Access Race",
        category=PatternCategory.RACE_CONDITION,
        pattern_type=PatternType.IMPORT_COMBINATION,
        description=(
            "The binary uses access() alongside open()/fopen(). This creates "
            "a time-of-check to time-of-use (TOCTOU) race condition where "
            "the file state can change between the check and the use."
        ),
        severity="medium",
        base_confidence=45.0,
        exploitability=ExploitDifficulty.HARD,
        imports=["access", "open", "fopen"],
        required_all=False,
        mitigations=[],
        cwe_ids=[362, 367],
        technique="race_condition",
        tags=["filesystem", "subtle"],
    ),
]


# ---------------------------------------------------------------------------
# Pattern registry
# ---------------------------------------------------------------------------

class PatternDatabase:
    """Registry of all known vulnerability patterns.

    Provides lookup by ID, category, and severity. Supports adding custom
    patterns at runtime.

    Example::

        db = PatternDatabase()
        db.load_defaults()
        bof_patterns = db.by_category(PatternCategory.BUFFER_OVERFLOW)
    """

    def __init__(self) -> None:
        self._patterns: dict[str, VulnPattern] = {}

    def load_defaults(self) -> None:
        """Load all built-in vulnerability patterns."""
        all_patterns = (
            _BUFFER_OVERFLOW_PATTERNS
            + _FORMAT_STRING_PATTERNS
            + _INTEGER_OVERFLOW_PATTERNS
            + _USE_AFTER_FREE_PATTERNS
            + _COMMAND_INJECTION_PATTERNS
            + _RACE_CONDITION_PATTERNS
        )
        for p in all_patterns:
            self._patterns[p.id] = p

    def add(self, pattern: VulnPattern) -> None:
        """Add a custom pattern to the database.

        Args:
            pattern: The pattern to register.

        Raises:
            ValueError: If a pattern with the same ID already exists.
        """
        if pattern.id in self._patterns:
            raise ValueError(f"Pattern ID already exists: {pattern.id}")
        self._patterns[pattern.id] = pattern

    def get(self, pattern_id: str) -> VulnPattern | None:
        """Retrieve a pattern by its ID."""
        return self._patterns.get(pattern_id)

    def all(self) -> list[VulnPattern]:
        """Return all registered patterns, sorted by ID."""
        return sorted(self._patterns.values(), key=lambda p: p.id)

    def by_category(self, category: PatternCategory) -> list[VulnPattern]:
        """Return all patterns in a given category."""
        return [p for p in self._patterns.values() if p.category == category]

    def by_severity(self, severity: str) -> list[VulnPattern]:
        """Return all patterns matching a severity level."""
        return [p for p in self._patterns.values() if p.severity == severity]

    def by_technique(self, technique: str) -> list[VulnPattern]:
        """Return all patterns that suggest a given exploitation technique."""
        return [p for p in self._patterns.values() if p.technique == technique]

    def by_tag(self, tag: str) -> list[VulnPattern]:
        """Return all patterns tagged with *tag*."""
        return [p for p in self._patterns.values() if tag in p.tags]

    def count(self) -> int:
        """Return the total number of registered patterns."""
        return len(self._patterns)

    def categories(self) -> list[PatternCategory]:
        """Return a deduplicated list of categories with registered patterns."""
        seen: set[PatternCategory] = set()
        for p in self._patterns.values():
            seen.add(p.category)
        return sorted(seen, key=lambda c: c.value)

    def to_list(self) -> list[dict[str, Any]]:
        """Serialize all patterns to a list of dicts."""
        return [p.to_dict() for p in self.all()]
