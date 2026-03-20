"""
RAVEN Base Agent Framework.

Defines the abstract :class:`BaseAgent` that all RAVEN agents extend,
plus the :class:`AgentOrchestrator` that manages agent lifecycles.
"""

from __future__ import annotations

import abc
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from raven.core.config import RavenConfig
from raven.core.llm import BaseLLMProvider, create_llm_provider
from raven.core.logger import get_logger
from raven.core.memory import AgentMemory, Finding, SessionMemory
from raven.core.message_bus import AgentMessage, MessageBus, MessageType

logger = get_logger("agents.base")


# ---------------------------------------------------------------------------
# Task / Result data classes
# ---------------------------------------------------------------------------

class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class AgentTask:
    """A unit of work assigned to an agent."""

    id: str = field(default_factory=lambda: f"TASK-{uuid.uuid4().hex[:8].upper()}")
    name: str = ""
    description: str = ""
    agent: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "agent": self.agent,
            "parameters": self.parameters,
            "status": self.status.value,
            "created_at": self.created_at,
        }


@dataclass
class AgentResult:
    """The outcome of an agent executing a task."""

    task_id: str
    agent: str
    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    completed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "agent": self.agent,
            "success": self.success,
            "data": self.data,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "duration_seconds": self.duration_seconds,
            "completed_at": self.completed_at,
        }


# ---------------------------------------------------------------------------
# Base Agent
# ---------------------------------------------------------------------------

class BaseAgent(abc.ABC):
    """Abstract base class for all RAVEN agents.

    Subclasses must implement:
      - :meth:`execute` -- perform the assigned task.
      - :attr:`name` -- agent identifier.
      - :attr:`description` -- human-readable purpose.

    The base class provides:
      - Access to an LLM provider
      - Per-agent memory
      - Message-bus publishing helpers
    """

    name: str = "base"
    description: str = "Base agent"

    def __init__(
        self,
        config: RavenConfig,
        session: SessionMemory | None = None,
        bus: MessageBus | None = None,
        llm: BaseLLMProvider | None = None,
    ) -> None:
        self.config = config
        self.session = session or SessionMemory()
        self.bus = bus or MessageBus()
        self.llm = llm or create_llm_provider(config)
        self.memory: AgentMemory = self.session.get_agent_memory(self.name)
        self._logger = get_logger(f"agents.{self.name}")

    # -- abstract interface -------------------------------------------------

    @abc.abstractmethod
    def execute(self, task: AgentTask) -> AgentResult:
        """Execute the given task and return a result.

        Subclasses must implement the actual analysis / exploitation logic here.
        """

    # -- helpers ------------------------------------------------------------

    def add_finding(self, finding: Finding) -> str:
        """Record a finding in session memory and publish it to the bus."""
        finding.agent = self.name
        fid = self.session.add_finding(finding)
        self.bus.publish(
            AgentMessage(
                sender=self.name,
                topic=MessageType.FINDING,
                data=finding.to_dict(),
            )
        )
        self._logger.info("Finding recorded: %s - %s", finding.id, finding.title)
        return fid

    def publish_status(self, status: str, **extra: Any) -> None:
        """Publish a status update to the bus."""
        self.bus.publish(
            AgentMessage(
                sender=self.name,
                topic=MessageType.STATUS_UPDATE,
                data={"status": status, **extra},
            )
        )

    def publish_error(self, error: str) -> None:
        """Publish an error message to the bus."""
        self._logger.error(error)
        self.bus.publish(
            AgentMessage(
                sender=self.name,
                topic=MessageType.ERROR,
                data={"error": error},
            )
        )


# ---------------------------------------------------------------------------
# Agent Orchestrator
# ---------------------------------------------------------------------------

class AgentOrchestrator:
    """Manages multiple agents and dispatches tasks.

    In Phase 1 the orchestrator runs agents sequentially. Later phases
    will add parallel execution and a proper coordinator agent.
    """

    def __init__(
        self,
        config: RavenConfig,
        session: SessionMemory | None = None,
    ) -> None:
        self.config = config
        self.session = session or SessionMemory()
        self.bus = MessageBus()
        self._agents: dict[str, BaseAgent] = {}
        self._logger = get_logger("agents.orchestrator")

    def register(self, agent: BaseAgent) -> None:
        """Register an agent with the orchestrator."""
        self._agents[agent.name] = agent
        self._logger.info("Registered agent: %s", agent.name)

    def get_agent(self, name: str) -> BaseAgent | None:
        """Retrieve a registered agent by name."""
        return self._agents.get(name)

    def dispatch(self, task: AgentTask) -> AgentResult:
        """Dispatch a task to the appropriate agent and return the result."""
        agent = self._agents.get(task.agent)
        if agent is None:
            self._logger.error("No agent registered for: %s", task.agent)
            return AgentResult(
                task_id=task.id,
                agent=task.agent,
                success=False,
                errors=[f"Unknown agent: {task.agent}"],
            )

        self._logger.info("Dispatching task %s to agent %s", task.id, task.agent)
        task.status = TaskStatus.RUNNING

        import time

        start = time.monotonic()
        try:
            result = agent.execute(task)
            result.duration_seconds = time.monotonic() - start
            task.status = TaskStatus.COMPLETED if result.success else TaskStatus.FAILED
        except Exception as exc:
            task.status = TaskStatus.FAILED
            result = AgentResult(
                task_id=task.id,
                agent=task.agent,
                success=False,
                errors=[str(exc)],
                duration_seconds=time.monotonic() - start,
            )
            self._logger.exception("Agent %s failed on task %s", task.agent, task.id)

        return result
