"""
RAVEN Agent Communication Bus.

Provides an in-process publish/subscribe message bus for inter-agent
communication. Messages are typed and routed by topic.

In Phase 1 this is synchronous; future phases may add async and
distributed (Redis-backed) support.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable

from raven.core.logger import get_logger

logger = get_logger("core.message_bus")


# ---------------------------------------------------------------------------
# Message types
# ---------------------------------------------------------------------------

class MessageType(str, Enum):
    """Well-known message topics."""

    TASK_REQUEST = "task.request"
    TASK_RESULT = "task.result"
    FINDING = "finding"
    STATUS_UPDATE = "status.update"
    ERROR = "error"
    BROADCAST = "broadcast"


@dataclass
class AgentMessage:
    """A single message on the bus."""

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    sender: str = ""
    receiver: str = ""  # empty = broadcast
    topic: str = MessageType.BROADCAST
    data: dict[str, Any] = field(default_factory=dict)
    priority: int = 5  # 1 (highest) .. 10 (lowest)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "sender": self.sender,
            "receiver": self.receiver,
            "topic": self.topic,
            "data": self.data,
            "priority": self.priority,
            "timestamp": self.timestamp,
        }


# Type alias for subscriber callbacks
Subscriber = Callable[[AgentMessage], None]


# ---------------------------------------------------------------------------
# Message Bus
# ---------------------------------------------------------------------------

class MessageBus:
    """Simple in-process pub/sub message bus.

    Agents subscribe to topics and receive messages synchronously when
    another agent publishes to that topic.

    Example::

        bus = MessageBus()
        bus.subscribe("finding", my_handler)
        bus.publish(AgentMessage(sender="scout", topic="finding", data={...}))
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Subscriber]] = defaultdict(list)
        self._history: list[AgentMessage] = []

    def subscribe(self, topic: str, callback: Subscriber) -> None:
        """Register *callback* to receive messages on *topic*."""
        self._subscribers[topic].append(callback)
        logger.debug("Subscriber added for topic '%s'", topic)

    def unsubscribe(self, topic: str, callback: Subscriber) -> None:
        """Remove *callback* from *topic* subscriptions."""
        try:
            self._subscribers[topic].remove(callback)
        except ValueError:
            pass

    def publish(self, message: AgentMessage) -> None:
        """Publish *message* to all subscribers of its topic.

        Messages are also stored in the history for later review.
        """
        self._history.append(message)
        logger.debug(
            "Message published: %s -> topic=%s",
            message.sender,
            message.topic,
        )

        for callback in self._subscribers.get(message.topic, []):
            try:
                callback(message)
            except Exception:
                logger.exception(
                    "Subscriber error on topic '%s' from sender '%s'",
                    message.topic,
                    message.sender,
                )

        # Also deliver to broadcast subscribers
        if message.topic != MessageType.BROADCAST:
            for callback in self._subscribers.get(MessageType.BROADCAST, []):
                try:
                    callback(message)
                except Exception:
                    logger.exception("Broadcast subscriber error")

    def history(self, topic: str | None = None, limit: int = 50) -> list[AgentMessage]:
        """Return recent message history, optionally filtered by *topic*."""
        msgs = self._history if topic is None else [m for m in self._history if m.topic == topic]
        return msgs[-limit:]

    def clear_history(self) -> None:
        """Clear the message history."""
        self._history.clear()
