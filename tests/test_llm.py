"""Tests for the RAVEN LLM interface."""

from __future__ import annotations

from pathlib import Path

import pytest

from raven.core.config import RavenConfig
from raven.core.llm import (
    LLMMessage,
    LLMResponse,
    PromptTemplate,
    StubProvider,
    create_llm_provider,
)


class TestPromptTemplate:
    """Tests for prompt template rendering."""

    def test_render(self) -> None:
        tpl = PromptTemplate(
            name="test",
            system="You are a {role}.",
            user="Analyze: {code}",
        )
        messages = tpl.render(role="security analyst", code="int main() {}")
        assert len(messages) == 2
        assert messages[0].role == "system"
        assert "security analyst" in messages[0].content
        assert messages[1].role == "user"
        assert "int main()" in messages[1].content


class TestStubProvider:
    """Tests for the no-op stub provider."""

    def test_chat_returns_empty(self) -> None:
        provider = StubProvider(model="none")
        response = provider.chat([LLMMessage(role="user", content="hello")])
        assert response.content == ""
        assert response.provider == "none"

    def test_prompt_returns_empty(self) -> None:
        provider = StubProvider(model="none")
        tpl = PromptTemplate(name="test", system="sys", user="usr")
        response = provider.prompt(tpl)
        assert not response.ok


class TestLLMResponse:
    """Tests for the LLMResponse data class."""

    def test_ok_true(self) -> None:
        r = LLMResponse(content="result")
        assert r.ok is True

    def test_ok_false(self) -> None:
        r = LLMResponse(content="")
        assert r.ok is False


class TestCreateProvider:
    """Tests for the provider factory."""

    def test_none_provider(self, tmp_dir: Path) -> None:
        """Default config produces a StubProvider."""
        config = RavenConfig(config_path=tmp_dir / "cfg.yaml")
        provider = create_llm_provider(config)
        assert provider.provider_name == "none"

    def test_openai_without_key_falls_back(self, tmp_dir: Path) -> None:
        """OpenAI without an API key falls back to StubProvider."""
        config = RavenConfig(config_path=tmp_dir / "cfg.yaml")
        config.set("llm.provider", "openai")
        config.set("llm.api_key", "")
        provider = create_llm_provider(config)
        assert provider.provider_name == "none"

    def test_anthropic_without_key_falls_back(self, tmp_dir: Path) -> None:
        """Anthropic without an API key falls back to StubProvider."""
        config = RavenConfig(config_path=tmp_dir / "cfg.yaml")
        config.set("llm.provider", "anthropic")
        config.set("llm.api_key", "")
        provider = create_llm_provider(config)
        assert provider.provider_name == "none"

    def test_ollama_provider(self, tmp_dir: Path) -> None:
        """Ollama provider is created correctly."""
        config = RavenConfig(config_path=tmp_dir / "cfg.yaml")
        config.set("llm.provider", "ollama")
        provider = create_llm_provider(config)
        assert provider.provider_name == "ollama"
