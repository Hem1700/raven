"""
RAVEN Knowledge Base.

Provides persistent SQLite storage for:
  - CVE records (id, description, severity, affected software, references)
  - Vulnerability patterns (serialized from :mod:`raven.analysis.patterns`)
  - Exploit templates (name, technique, architecture, template code)
  - Analysis results cache (binary hash -> previous findings)

The knowledge base also supports a basic RAG (Retrieval-Augmented Generation)
interface for LLM-powered queries: relevant context is retrieved from the
database and injected into LLM prompts.
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

logger = get_logger("core.knowledge_base")

# Default database path
_DEFAULT_DB_DIR = Path.home() / ".local" / "share" / "raven"
_DEFAULT_DB_PATH = _DEFAULT_DB_DIR / "knowledge.db"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class CVERecord:
    """A CVE vulnerability record."""

    cve_id: str
    description: str = ""
    severity: str = "medium"
    cvss_score: float = 0.0
    affected_software: str = ""
    cwe_ids: list[int] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    published_date: str = ""
    last_modified: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "affected_software": self.affected_software,
            "cwe_ids": self.cwe_ids,
            "references": self.references,
            "published_date": self.published_date,
            "last_modified": self.last_modified,
        }


@dataclass
class ExploitTemplate:
    """A reusable exploit template.

    Attributes:
        id: Unique template identifier.
        name: Human-readable name.
        technique: Exploitation technique (stack_buffer_overflow, rop, etc.).
        arch: Target architecture (x86_64, x86, arm64, etc.).
        description: What this template does.
        template_code: The exploit template (Python/pwntools code with placeholders).
        variables: Required template variables and their descriptions.
        prerequisites: Conditions that must be met for this template.
        tags: Arbitrary tags for filtering.
    """

    id: str
    name: str
    technique: str
    arch: str = "x86_64"
    description: str = ""
    template_code: str = ""
    variables: dict[str, str] = field(default_factory=dict)
    prerequisites: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "technique": self.technique,
            "arch": self.arch,
            "description": self.description,
            "template_code": self.template_code,
            "variables": self.variables,
            "prerequisites": self.prerequisites,
            "tags": self.tags,
        }


# ---------------------------------------------------------------------------
# Knowledge Base
# ---------------------------------------------------------------------------

class KnowledgeBase:
    """Persistent knowledge storage backed by SQLite.

    Example::

        kb = KnowledgeBase()
        kb.initialize()
        kb.add_cve(CVERecord(cve_id="CVE-2024-1234", ...))
        results = kb.search_cves("buffer overflow")
    """

    def __init__(self, db_path: Path | str | None = None) -> None:
        if db_path is None:
            import os
            data_dir = os.environ.get("RAVEN_DATA_DIR", str(_DEFAULT_DB_DIR))
            self._db_path = Path(data_dir) / "knowledge.db"
        else:
            self._db_path = Path(db_path)
        self._initialized = False

    @property
    def db_path(self) -> Path:
        """Return the path to the SQLite database file."""
        return self._db_path

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for database connections."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
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
            conn.executescript(_SCHEMA_SQL)
        self._initialized = True
        logger.info("Knowledge base initialized at %s", self._db_path)

    # -- CVE operations ------------------------------------------------------

    def add_cve(self, cve: CVERecord) -> None:
        """Insert or update a CVE record."""
        if not self._initialized:
            self.initialize()
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO cves
                   (cve_id, description, severity, cvss_score, affected_software,
                    cwe_ids, references_, published_date, last_modified)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    cve.cve_id,
                    cve.description,
                    cve.severity,
                    cve.cvss_score,
                    cve.affected_software,
                    json.dumps(cve.cwe_ids),
                    json.dumps(cve.references),
                    cve.published_date,
                    cve.last_modified,
                ),
            )

    def get_cve(self, cve_id: str) -> CVERecord | None:
        """Retrieve a CVE record by ID."""
        if not self._initialized:
            self.initialize()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM cves WHERE cve_id = ?", (cve_id,)
            ).fetchone()
        if row is None:
            return None
        return self._row_to_cve(row)

    def search_cves(
        self,
        query: str,
        *,
        severity: str | None = None,
        limit: int = 50,
    ) -> list[CVERecord]:
        """Search CVE records by description text and optional severity filter.

        Args:
            query: Text to search for in the CVE description.
            severity: Optional severity filter.
            limit: Maximum number of results.
        """
        if not self._initialized:
            self.initialize()
        sql = "SELECT * FROM cves WHERE description LIKE ?"
        params: list[Any] = [f"%{query}%"]
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY cvss_score DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_cve(r) for r in rows]

    def search_cves_by_cwe(self, cwe_id: int, limit: int = 50) -> list[CVERecord]:
        """Find CVEs associated with a specific CWE ID."""
        if not self._initialized:
            self.initialize()
        # cwe_ids is stored as JSON array, so we search with LIKE
        pattern = f"%{cwe_id}%"
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM cves WHERE cwe_ids LIKE ? ORDER BY cvss_score DESC LIMIT ?",
                (pattern, limit),
            ).fetchall()
        return [self._row_to_cve(r) for r in rows]

    def count_cves(self) -> int:
        """Return the total number of CVE records."""
        if not self._initialized:
            self.initialize()
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM cves").fetchone()
        return row[0] if row else 0

    # -- Exploit template operations -----------------------------------------

    def add_template(self, template: ExploitTemplate) -> None:
        """Insert or update an exploit template."""
        if not self._initialized:
            self.initialize()
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO exploit_templates
                   (id, name, technique, arch, description, template_code,
                    variables, prerequisites, tags)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    template.id,
                    template.name,
                    template.technique,
                    template.arch,
                    template.description,
                    template.template_code,
                    json.dumps(template.variables),
                    json.dumps(template.prerequisites),
                    json.dumps(template.tags),
                ),
            )

    def get_template(self, template_id: str) -> ExploitTemplate | None:
        """Retrieve an exploit template by ID."""
        if not self._initialized:
            self.initialize()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM exploit_templates WHERE id = ?", (template_id,)
            ).fetchone()
        if row is None:
            return None
        return self._row_to_template(row)

    def search_templates(
        self,
        *,
        technique: str | None = None,
        arch: str | None = None,
        limit: int = 50,
    ) -> list[ExploitTemplate]:
        """Search exploit templates by technique and/or architecture."""
        if not self._initialized:
            self.initialize()
        sql = "SELECT * FROM exploit_templates WHERE 1=1"
        params: list[Any] = []
        if technique:
            sql += " AND technique = ?"
            params.append(technique)
        if arch:
            sql += " AND arch = ?"
            params.append(arch)
        sql += " ORDER BY name LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_template(r) for r in rows]

    def count_templates(self) -> int:
        """Return the total number of exploit templates."""
        if not self._initialized:
            self.initialize()
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) FROM exploit_templates").fetchone()
        return row[0] if row else 0

    # -- Analysis cache operations -------------------------------------------

    def cache_result(
        self,
        binary_hash: str,
        binary_path: str,
        result_type: str,
        result_data: dict[str, Any],
    ) -> None:
        """Cache an analysis result for a binary.

        Args:
            binary_hash: SHA256 hash of the binary.
            binary_path: Original file path.
            result_type: Type of result (e.g. ``scan``, ``analyze``).
            result_data: Serialized result data.
        """
        if not self._initialized:
            self.initialize()
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO analysis_cache
                   (binary_hash, binary_path, result_type, result_data, cached_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    binary_hash,
                    binary_path,
                    result_type,
                    json.dumps(result_data),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

    def get_cached_result(
        self, binary_hash: str, result_type: str
    ) -> dict[str, Any] | None:
        """Retrieve a cached analysis result.

        Args:
            binary_hash: SHA256 hash of the binary.
            result_type: Type of result to retrieve.

        Returns:
            The cached result dict, or ``None`` if not found.
        """
        if not self._initialized:
            self.initialize()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT result_data FROM analysis_cache WHERE binary_hash = ? AND result_type = ?",
                (binary_hash, result_type),
            ).fetchone()
        if row is None:
            return None
        return json.loads(row[0])

    # -- Vulnerability pattern storage (serialized) --------------------------

    def store_pattern(self, pattern_data: dict[str, Any]) -> None:
        """Store a serialized vulnerability pattern."""
        if not self._initialized:
            self.initialize()
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO vuln_patterns
                   (pattern_id, category, severity, pattern_data)
                   VALUES (?, ?, ?, ?)""",
                (
                    pattern_data["id"],
                    pattern_data.get("category", ""),
                    pattern_data.get("severity", ""),
                    json.dumps(pattern_data),
                ),
            )

    def get_patterns_by_category(self, category: str) -> list[dict[str, Any]]:
        """Retrieve stored patterns by category."""
        if not self._initialized:
            self.initialize()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT pattern_data FROM vuln_patterns WHERE category = ?",
                (category,),
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    # -- RAG context retrieval -----------------------------------------------

    def get_rag_context(
        self,
        *,
        cwe_ids: list[int] | None = None,
        technique: str | None = None,
        keywords: list[str] | None = None,
        max_items: int = 10,
    ) -> str:
        """Retrieve relevant context for LLM-powered analysis (RAG).

        Builds a text context block from the knowledge base containing
        relevant CVEs, patterns, and exploit templates for the given query.

        Args:
            cwe_ids: CWE identifiers to search for.
            technique: Exploitation technique to match templates.
            keywords: Keywords to search CVE descriptions.
            max_items: Maximum items per section.

        Returns:
            A formatted text string suitable for injection into an LLM prompt.
        """
        if not self._initialized:
            self.initialize()

        sections: list[str] = []

        # CVE context
        if cwe_ids:
            cves: list[CVERecord] = []
            for cwe_id in cwe_ids[:5]:  # cap to avoid huge queries
                cves.extend(self.search_cves_by_cwe(cwe_id, limit=max_items))
            if cves:
                cve_lines = [f"- {c.cve_id}: {c.description[:200]}" for c in cves[:max_items]]
                sections.append("Related CVEs:\n" + "\n".join(cve_lines))

        if keywords:
            for kw in keywords[:3]:
                kw_cves = self.search_cves(kw, limit=3)
                for c in kw_cves:
                    sections.append(f"- {c.cve_id} ({c.severity}): {c.description[:150]}")

        # Template context
        if technique:
            templates = self.search_templates(technique=technique, limit=max_items)
            if templates:
                tmpl_lines = [f"- {t.name} ({t.arch}): {t.description[:150]}" for t in templates]
                sections.append("Related Exploit Templates:\n" + "\n".join(tmpl_lines))

        if not sections:
            return ""

        return "\n\n".join(sections)

    # -- Helpers -------------------------------------------------------------

    @staticmethod
    def _row_to_cve(row: sqlite3.Row) -> CVERecord:
        """Convert a database row to a CVERecord."""
        return CVERecord(
            cve_id=row["cve_id"],
            description=row["description"],
            severity=row["severity"],
            cvss_score=row["cvss_score"],
            affected_software=row["affected_software"],
            cwe_ids=json.loads(row["cwe_ids"]) if row["cwe_ids"] else [],
            references=json.loads(row["references_"]) if row["references_"] else [],
            published_date=row["published_date"],
            last_modified=row["last_modified"],
        )

    @staticmethod
    def _row_to_template(row: sqlite3.Row) -> ExploitTemplate:
        """Convert a database row to an ExploitTemplate."""
        return ExploitTemplate(
            id=row["id"],
            name=row["name"],
            technique=row["technique"],
            arch=row["arch"],
            description=row["description"],
            template_code=row["template_code"],
            variables=json.loads(row["variables"]) if row["variables"] else {},
            prerequisites=json.loads(row["prerequisites"]) if row["prerequisites"] else {},
            tags=json.loads(row["tags"]) if row["tags"] else [],
        )


# ---------------------------------------------------------------------------
# Database schema
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'medium',
    cvss_score REAL NOT NULL DEFAULT 0.0,
    affected_software TEXT NOT NULL DEFAULT '',
    cwe_ids TEXT NOT NULL DEFAULT '[]',
    references_ TEXT NOT NULL DEFAULT '[]',
    published_date TEXT NOT NULL DEFAULT '',
    last_modified TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS exploit_templates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    technique TEXT NOT NULL DEFAULT '',
    arch TEXT NOT NULL DEFAULT 'x86_64',
    description TEXT NOT NULL DEFAULT '',
    template_code TEXT NOT NULL DEFAULT '',
    variables TEXT NOT NULL DEFAULT '{}',
    prerequisites TEXT NOT NULL DEFAULT '{}',
    tags TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS vuln_patterns (
    pattern_id TEXT PRIMARY KEY,
    category TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT '',
    pattern_data TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS analysis_cache (
    binary_hash TEXT NOT NULL,
    binary_path TEXT NOT NULL DEFAULT '',
    result_type TEXT NOT NULL,
    result_data TEXT NOT NULL DEFAULT '{}',
    cached_at TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (binary_hash, result_type)
);

CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cves_cvss ON cves(cvss_score);
CREATE INDEX IF NOT EXISTS idx_templates_technique ON exploit_templates(technique);
CREATE INDEX IF NOT EXISTS idx_templates_arch ON exploit_templates(arch);
CREATE INDEX IF NOT EXISTS idx_patterns_category ON vuln_patterns(category);
CREATE INDEX IF NOT EXISTS idx_cache_hash ON analysis_cache(binary_hash);
"""
