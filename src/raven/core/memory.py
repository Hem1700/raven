"""
RAVEN Memory Management System.

Provides in-process memory for agents to store and retrieve findings,
analysis results, and contextual state across the lifecycle of a session.

The memory is hierarchical:
  - **SessionMemory**: Top-level session state (one per ``raven`` invocation).
  - **AgentMemory**: Per-agent working memory within a session.
  - **FindingsStore**: Structured store for vulnerability findings.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Severity enum
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __str__(self) -> str:
        return self.value


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single security finding or observation."""

    id: str = field(default_factory=lambda: f"FIND-{uuid.uuid4().hex[:8].upper()}")
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    confidence: float = 0.0  # 0-100
    location: str = ""  # e.g., function name or address
    agent: str = ""  # agent that produced this finding
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": str(self.severity),
            "confidence": self.confidence,
            "location": self.location,
            "agent": self.agent,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


@dataclass
class AgentMemory:
    """Working memory for a single agent.

    Stores key-value context, a scratchpad for intermediate reasoning,
    and references to findings the agent has produced.
    """

    agent_name: str
    context: dict[str, Any] = field(default_factory=dict)
    scratchpad: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)

    def remember(self, key: str, value: Any) -> None:
        """Store a key-value pair in context."""
        self.context[key] = value

    def recall(self, key: str, default: Any = None) -> Any:
        """Retrieve a value from context."""
        return self.context.get(key, default)

    def note(self, text: str) -> None:
        """Append a note to the scratchpad."""
        self.scratchpad.append(text)

    def clear(self) -> None:
        """Wipe all memory."""
        self.context.clear()
        self.scratchpad.clear()
        self.finding_ids.clear()


class FindingsStore:
    """Thread-safe store for :class:`Finding` instances within a session."""

    def __init__(self) -> None:
        self._findings: dict[str, Finding] = {}

    def add(self, finding: Finding) -> str:
        """Add a finding and return its ID."""
        self._findings[finding.id] = finding
        return finding.id

    def get(self, finding_id: str) -> Finding | None:
        """Retrieve a finding by ID."""
        return self._findings.get(finding_id)

    def all(self) -> list[Finding]:
        """Return all findings, sorted by severity then confidence."""
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return sorted(
            self._findings.values(),
            key=lambda f: (severity_order.get(f.severity, 5), -f.confidence),
        )

    def by_severity(self, severity: Severity) -> list[Finding]:
        """Return findings filtered by severity."""
        return [f for f in self._findings.values() if f.severity == severity]

    def by_agent(self, agent_name: str) -> list[Finding]:
        """Return findings produced by a specific agent."""
        return [f for f in self._findings.values() if f.agent == agent_name]

    def count(self) -> int:
        return len(self._findings)

    def to_list(self) -> list[dict[str, Any]]:
        """Serialize all findings to a list of dicts."""
        return [f.to_dict() for f in self.all()]


class SessionMemory:
    """Top-level memory container for an entire RAVEN session.

    Holds:
      - Per-agent :class:`AgentMemory` instances
      - A shared :class:`FindingsStore`
      - Session-level metadata
    """

    def __init__(self, session_id: str | None = None) -> None:
        self.session_id: str = session_id or uuid.uuid4().hex[:12]
        self.created_at: str = datetime.now(timezone.utc).isoformat()
        self.findings = FindingsStore()
        self._agent_memories: dict[str, AgentMemory] = {}
        self.metadata: dict[str, Any] = {}

    def get_agent_memory(self, agent_name: str) -> AgentMemory:
        """Return (or create) the memory for *agent_name*."""
        if agent_name not in self._agent_memories:
            self._agent_memories[agent_name] = AgentMemory(agent_name=agent_name)
        return self._agent_memories[agent_name]

    def add_finding(self, finding: Finding) -> str:
        """Add a finding to the shared store and link it to the agent."""
        fid = self.findings.add(finding)
        mem = self.get_agent_memory(finding.agent)
        mem.finding_ids.append(fid)
        return fid

    def summary(self) -> dict[str, Any]:
        """Return a summary dict of the session state."""
        return {
            "session_id": self.session_id,
            "created_at": self.created_at,
            "findings_count": self.findings.count(),
            "agents": list(self._agent_memories.keys()),
            "metadata": self.metadata,
        }
