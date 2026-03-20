"""Tests for the RAVEN agent communication bus."""

from __future__ import annotations

from raven.core.message_bus import AgentMessage, MessageBus, MessageType


class TestMessageBus:
    """Tests for the MessageBus pub/sub system."""

    def test_publish_subscribe(self) -> None:
        """Subscribers receive published messages."""
        bus = MessageBus()
        received: list[AgentMessage] = []
        bus.subscribe("test.topic", received.append)

        msg = AgentMessage(sender="scout", topic="test.topic", data={"key": "value"})
        bus.publish(msg)

        assert len(received) == 1
        assert received[0].data["key"] == "value"

    def test_multiple_subscribers(self) -> None:
        """Multiple subscribers all receive the message."""
        bus = MessageBus()
        results_a: list[AgentMessage] = []
        results_b: list[AgentMessage] = []
        bus.subscribe("topic", results_a.append)
        bus.subscribe("topic", results_b.append)

        bus.publish(AgentMessage(sender="x", topic="topic"))
        assert len(results_a) == 1
        assert len(results_b) == 1

    def test_topic_isolation(self) -> None:
        """Subscribers only receive messages from their topic."""
        bus = MessageBus()
        received: list[AgentMessage] = []
        bus.subscribe("topicA", received.append)

        bus.publish(AgentMessage(sender="x", topic="topicB"))
        assert len(received) == 0

    def test_broadcast_receives_all(self) -> None:
        """Broadcast subscribers receive messages from all topics."""
        bus = MessageBus()
        received: list[AgentMessage] = []
        bus.subscribe(MessageType.BROADCAST, received.append)

        bus.publish(AgentMessage(sender="a", topic="finding"))
        bus.publish(AgentMessage(sender="b", topic="error"))

        assert len(received) == 2

    def test_history(self) -> None:
        """Published messages are recorded in history."""
        bus = MessageBus()
        bus.publish(AgentMessage(sender="a", topic="t1"))
        bus.publish(AgentMessage(sender="b", topic="t2"))

        assert len(bus.history()) == 2
        assert len(bus.history(topic="t1")) == 1

    def test_unsubscribe(self) -> None:
        """Unsubscribed callbacks no longer receive messages."""
        bus = MessageBus()
        received: list[AgentMessage] = []
        bus.subscribe("t", received.append)
        bus.unsubscribe("t", received.append)

        bus.publish(AgentMessage(sender="x", topic="t"))
        assert len(received) == 0

    def test_subscriber_error_does_not_break_bus(self) -> None:
        """An exception in one subscriber does not prevent others."""
        bus = MessageBus()
        results: list[AgentMessage] = []

        def bad_handler(msg: AgentMessage) -> None:
            raise RuntimeError("oops")

        bus.subscribe("t", bad_handler)
        bus.subscribe("t", results.append)

        bus.publish(AgentMessage(sender="x", topic="t"))
        assert len(results) == 1  # second subscriber still ran
