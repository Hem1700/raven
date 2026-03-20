"""Tests for the RAVEN base agent framework."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from raven.agents.base import (
    AgentOrchestrator,
    AgentResult,
    AgentTask,
    BaseAgent,
    TaskStatus,
)
from raven.core.config import RavenConfig
from raven.core.memory import Finding, SessionMemory, Severity


class DummyAgent(BaseAgent):
    """Minimal agent for testing the base class."""

    name = "dummy"
    description = "Test agent"

    def execute(self, task: AgentTask) -> AgentResult:
        if task.parameters.get("fail"):
            raise RuntimeError("Intentional failure")
        return AgentResult(
            task_id=task.id,
            agent=self.name,
            success=True,
            data={"processed": True},
        )


class TestBaseAgent:
    """Tests for BaseAgent functionality."""

    @pytest.fixture
    def config(self, tmp_dir: Path) -> RavenConfig:
        return RavenConfig(config_path=tmp_dir / "cfg.yaml")

    @pytest.fixture
    def agent(self, config: RavenConfig) -> DummyAgent:
        return DummyAgent(config=config)

    def test_agent_has_memory(self, agent: DummyAgent) -> None:
        assert agent.memory is not None
        assert agent.memory.agent_name == "dummy"

    def test_add_finding(self, agent: DummyAgent) -> None:
        f = Finding(title="Test", severity=Severity.HIGH)
        fid = agent.add_finding(f)
        assert fid.startswith("FIND-")
        assert f.agent == "dummy"
        assert agent.session.findings.get(fid) is f

    def test_execute(self, agent: DummyAgent) -> None:
        task = AgentTask(name="test_task", agent="dummy")
        result = agent.execute(task)
        assert result.success is True
        assert result.data["processed"] is True


class TestAgentOrchestrator:
    """Tests for the AgentOrchestrator."""

    @pytest.fixture
    def config(self, tmp_dir: Path) -> RavenConfig:
        return RavenConfig(config_path=tmp_dir / "cfg.yaml")

    @pytest.fixture
    def orchestrator(self, config: RavenConfig) -> AgentOrchestrator:
        orch = AgentOrchestrator(config=config)
        orch.register(DummyAgent(config=config, session=orch.session, bus=orch.bus))
        return orch

    def test_register_and_get(self, orchestrator: AgentOrchestrator) -> None:
        assert orchestrator.get_agent("dummy") is not None
        assert orchestrator.get_agent("nonexistent") is None

    def test_dispatch_success(self, orchestrator: AgentOrchestrator) -> None:
        task = AgentTask(name="test", agent="dummy")
        result = orchestrator.dispatch(task)
        assert result.success is True
        assert result.duration_seconds >= 0

    def test_dispatch_unknown_agent(self, orchestrator: AgentOrchestrator) -> None:
        task = AgentTask(name="test", agent="unknown")
        result = orchestrator.dispatch(task)
        assert result.success is False
        assert "Unknown agent" in result.errors[0]

    def test_dispatch_failure(self, orchestrator: AgentOrchestrator) -> None:
        task = AgentTask(name="test", agent="dummy", parameters={"fail": True})
        result = orchestrator.dispatch(task)
        assert result.success is False
        assert len(result.errors) > 0
