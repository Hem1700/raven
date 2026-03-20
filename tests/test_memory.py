"""Tests for the RAVEN memory management system."""

from __future__ import annotations

import pytest

from raven.core.memory import (
    AgentMemory,
    Finding,
    FindingsStore,
    SessionMemory,
    Severity,
)


class TestFinding:
    """Tests for the Finding data class."""

    def test_default_id_generated(self) -> None:
        f = Finding(title="Test")
        assert f.id.startswith("FIND-")

    def test_to_dict(self) -> None:
        f = Finding(title="Buffer Overflow", severity=Severity.HIGH, confidence=95.0)
        d = f.to_dict()
        assert d["title"] == "Buffer Overflow"
        assert d["severity"] == "high"
        assert d["confidence"] == 95.0


class TestFindingsStore:
    """Tests for the FindingsStore."""

    def test_add_and_get(self) -> None:
        store = FindingsStore()
        f = Finding(title="Test Finding")
        fid = store.add(f)
        assert store.get(fid) is f

    def test_all_sorted_by_severity(self) -> None:
        store = FindingsStore()
        store.add(Finding(title="Low", severity=Severity.LOW, confidence=50.0))
        store.add(Finding(title="Critical", severity=Severity.CRITICAL, confidence=90.0))
        store.add(Finding(title="High", severity=Severity.HIGH, confidence=80.0))

        all_findings = store.all()
        severities = [f.severity for f in all_findings]
        assert severities == [Severity.CRITICAL, Severity.HIGH, Severity.LOW]

    def test_by_severity(self) -> None:
        store = FindingsStore()
        store.add(Finding(title="A", severity=Severity.HIGH))
        store.add(Finding(title="B", severity=Severity.LOW))
        store.add(Finding(title="C", severity=Severity.HIGH))

        high = store.by_severity(Severity.HIGH)
        assert len(high) == 2

    def test_by_agent(self) -> None:
        store = FindingsStore()
        store.add(Finding(title="A", agent="scout"))
        store.add(Finding(title="B", agent="analyst"))

        scout = store.by_agent("scout")
        assert len(scout) == 1
        assert scout[0].title == "A"

    def test_count(self) -> None:
        store = FindingsStore()
        assert store.count() == 0
        store.add(Finding(title="A"))
        assert store.count() == 1


class TestAgentMemory:
    """Tests for AgentMemory."""

    def test_remember_and_recall(self) -> None:
        mem = AgentMemory(agent_name="scout")
        mem.remember("target", "/bin/ls")
        assert mem.recall("target") == "/bin/ls"

    def test_recall_default(self) -> None:
        mem = AgentMemory(agent_name="scout")
        assert mem.recall("missing") is None
        assert mem.recall("missing", "default") == "default"

    def test_scratchpad(self) -> None:
        mem = AgentMemory(agent_name="scout")
        mem.note("Step 1")
        mem.note("Step 2")
        assert len(mem.scratchpad) == 2

    def test_clear(self) -> None:
        mem = AgentMemory(agent_name="scout")
        mem.remember("k", "v")
        mem.note("test")
        mem.finding_ids.append("FIND-001")
        mem.clear()
        assert mem.context == {}
        assert mem.scratchpad == []
        assert mem.finding_ids == []


class TestSessionMemory:
    """Tests for SessionMemory."""

    def test_session_id(self) -> None:
        session = SessionMemory()
        assert len(session.session_id) > 0

    def test_get_agent_memory(self) -> None:
        session = SessionMemory()
        mem = session.get_agent_memory("scout")
        assert mem.agent_name == "scout"
        # Same reference on second call
        assert session.get_agent_memory("scout") is mem

    def test_add_finding(self) -> None:
        session = SessionMemory()
        f = Finding(title="Test", agent="scout")
        fid = session.add_finding(f)
        assert session.findings.get(fid) is f
        assert fid in session.get_agent_memory("scout").finding_ids

    def test_summary(self) -> None:
        session = SessionMemory()
        session.add_finding(Finding(title="A", agent="scout"))
        summary = session.summary()
        assert summary["findings_count"] == 1
        assert "scout" in summary["agents"]
