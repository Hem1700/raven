"""
RAVEN LLM Interface.

Provides a unified interface for interacting with multiple LLM providers:
  - OpenAI (GPT-4, etc.)
  - Anthropic (Claude)
  - Ollama (local models)
  - Stub/None (no LLM, for offline analysis)

Each provider implements :class:`BaseLLMProvider`. The factory function
:func:`create_llm_provider` returns the correct provider based on configuration.
"""

from __future__ import annotations

import abc
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from raven.core.logger import AuditLogger, get_logger

logger = get_logger("core.llm")
audit = AuditLogger()


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class LLMMessage:
    """A single message in a conversation."""

    role: str  # "system", "user", "assistant"
    content: str


@dataclass
class LLMResponse:
    """Structured response from an LLM call."""

    content: str
    model: str = ""
    provider: str = ""
    usage: dict[str, int] = field(default_factory=dict)
    raw: Any = None

    @property
    def ok(self) -> bool:
        return bool(self.content)


@dataclass
class PromptTemplate:
    """Reusable prompt with variable substitution.

    Example::

        tpl = PromptTemplate(
            name="analyze_function",
            system="You are a binary analysis expert.",
            user="Analyze the following decompiled function:\\n\\n{code}",
        )
        messages = tpl.render(code="int main() { ... }")
    """

    name: str
    system: str
    user: str
    variables: list[str] = field(default_factory=list)

    def render(self, **kwargs: str) -> list[LLMMessage]:
        """Render the template with the given variables.

        Returns:
            A list of :class:`LLMMessage` ready for an LLM call.
        """
        return [
            LLMMessage(role="system", content=self.system.format(**kwargs)),
            LLMMessage(role="user", content=self.user.format(**kwargs)),
        ]


# ---------------------------------------------------------------------------
# Prompt library (Phase 1 prompts)
# ---------------------------------------------------------------------------

PROMPTS: dict[str, PromptTemplate] = {
    "analyze_binary": PromptTemplate(
        name="analyze_binary",
        system=(
            "You are RAVEN, an expert binary security analyst. "
            "You provide precise, technical analysis of binary executables. "
            "Focus on security-relevant observations."
        ),
        user=(
            "Analyze this binary metadata and provide a security assessment:\n\n"
            "File: {filename}\n"
            "Format: {file_format}\n"
            "Architecture: {arch}\n"
            "Security: {security}\n"
            "Imports: {imports}\n"
            "Strings (sample): {strings}\n\n"
            "Provide:\n"
            "1. Overall security posture assessment\n"
            "2. Potential attack vectors based on imports and strings\n"
            "3. Recommended areas for deeper analysis"
        ),
    ),
    "analyze_function": PromptTemplate(
        name="analyze_function",
        system=(
            "You are RAVEN, an expert in reverse engineering and vulnerability research. "
            "Analyze decompiled code for security vulnerabilities."
        ),
        user=(
            "Analyze this decompiled function for security vulnerabilities:\n\n"
            "```c\n{code}\n```\n\n"
            "Look for: buffer overflows, format strings, integer overflows, "
            "use-after-free, race conditions, and logic bugs.\n"
            "Rate each finding as CRITICAL / HIGH / MEDIUM / LOW."
        ),
    ),
    "summarize_findings": PromptTemplate(
        name="summarize_findings",
        system="You are RAVEN, summarizing binary analysis findings concisely.",
        user=(
            "Summarize the following analysis findings into a concise report:\n\n"
            "{findings}\n\n"
            "Format as a bullet-point list of key observations, sorted by severity."
        ),
    ),
}


# ---------------------------------------------------------------------------
# Provider base class
# ---------------------------------------------------------------------------

class BaseLLMProvider(abc.ABC):
    """Abstract base class for LLM providers."""

    provider_name: str = "base"

    def __init__(self, model: str, **kwargs: Any) -> None:
        self.model = model
        self._kwargs = kwargs

    @abc.abstractmethod
    def chat(
        self,
        messages: list[LLMMessage],
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Send a chat-completion request and return the response.

        Args:
            messages: Conversation history.
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in the response.

        Returns:
            An :class:`LLMResponse`.
        """

    def prompt(self, template: PromptTemplate, **kwargs: str) -> LLMResponse:
        """Render a :class:`PromptTemplate` and send it.

        This is the primary high-level interface for agent code.
        """
        messages = template.render(**kwargs)
        audit.log_llm_call(
            provider=self.provider_name,
            model=self.model,
            template=template.name,
        )
        return self.chat(messages)


# ---------------------------------------------------------------------------
# OpenAI provider
# ---------------------------------------------------------------------------

class OpenAIProvider(BaseLLMProvider):
    """LLM provider backed by the OpenAI API (or compatible)."""

    provider_name = "openai"

    def __init__(self, model: str, api_key: str, base_url: str = "", **kwargs: Any) -> None:
        super().__init__(model, **kwargs)
        try:
            import openai
        except ImportError:
            raise ImportError(
                "The 'openai' package is required for the OpenAI provider. "
                "Install it with: pip install raven-security[llm]"
            )
        client_kwargs: dict[str, Any] = {"api_key": api_key}
        if base_url:
            client_kwargs["base_url"] = base_url
        self._client = openai.OpenAI(**client_kwargs)

    def chat(
        self,
        messages: list[LLMMessage],
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        raw_msgs = [{"role": m.role, "content": m.content} for m in messages]
        try:
            resp = self._client.chat.completions.create(
                model=self.model,
                messages=raw_msgs,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            content = resp.choices[0].message.content or ""
            usage = {}
            if resp.usage:
                usage = {
                    "prompt_tokens": resp.usage.prompt_tokens,
                    "completion_tokens": resp.usage.completion_tokens,
                    "total_tokens": resp.usage.total_tokens,
                }
            return LLMResponse(
                content=content,
                model=self.model,
                provider=self.provider_name,
                usage=usage,
                raw=resp,
            )
        except Exception as exc:
            logger.error("OpenAI API call failed: %s", exc)
            return LLMResponse(content="", model=self.model, provider=self.provider_name)


# ---------------------------------------------------------------------------
# Anthropic provider
# ---------------------------------------------------------------------------

class AnthropicProvider(BaseLLMProvider):
    """LLM provider backed by the Anthropic API (Claude)."""

    provider_name = "anthropic"

    def __init__(self, model: str, api_key: str, **kwargs: Any) -> None:
        super().__init__(model, **kwargs)
        try:
            import anthropic
        except ImportError:
            raise ImportError(
                "The 'anthropic' package is required for the Anthropic provider. "
                "Install it with: pip install raven-security[llm]"
            )
        self._client = anthropic.Anthropic(api_key=api_key)

    def chat(
        self,
        messages: list[LLMMessage],
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        # Anthropic expects system message separately
        system_msg = ""
        chat_msgs: list[dict[str, str]] = []
        for m in messages:
            if m.role == "system":
                system_msg = m.content
            else:
                chat_msgs.append({"role": m.role, "content": m.content})

        try:
            resp = self._client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system_msg,
                messages=chat_msgs,
                temperature=temperature,
            )
            content = ""
            if resp.content:
                content = resp.content[0].text
            usage = {}
            if resp.usage:
                usage = {
                    "input_tokens": resp.usage.input_tokens,
                    "output_tokens": resp.usage.output_tokens,
                }
            return LLMResponse(
                content=content,
                model=self.model,
                provider=self.provider_name,
                usage=usage,
                raw=resp,
            )
        except Exception as exc:
            logger.error("Anthropic API call failed: %s", exc)
            return LLMResponse(content="", model=self.model, provider=self.provider_name)


# ---------------------------------------------------------------------------
# Ollama provider (local)
# ---------------------------------------------------------------------------

class OllamaProvider(BaseLLMProvider):
    """LLM provider backed by a local Ollama instance."""

    provider_name = "ollama"

    def __init__(self, model: str, host: str = "http://localhost:11434", **kwargs: Any) -> None:
        super().__init__(model, **kwargs)
        self._host = host.rstrip("/")

    def chat(
        self,
        messages: list[LLMMessage],
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        import requests

        url = f"{self._host}/api/chat"
        raw_msgs = [{"role": m.role, "content": m.content} for m in messages]
        payload = {
            "model": self.model,
            "messages": raw_msgs,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        try:
            resp = requests.post(url, json=payload, timeout=120)
            resp.raise_for_status()
            data = resp.json()
            content = data.get("message", {}).get("content", "")
            return LLMResponse(
                content=content,
                model=self.model,
                provider=self.provider_name,
                usage=data.get("eval_count", {}),
                raw=data,
            )
        except requests.ConnectionError:
            logger.error("Cannot connect to Ollama at %s. Is it running?", self._host)
            return LLMResponse(content="", model=self.model, provider=self.provider_name)
        except Exception as exc:
            logger.error("Ollama API call failed: %s", exc)
            return LLMResponse(content="", model=self.model, provider=self.provider_name)


# ---------------------------------------------------------------------------
# Stub provider (no LLM)
# ---------------------------------------------------------------------------

class StubProvider(BaseLLMProvider):
    """No-op provider used when no LLM is configured.

    All calls return an empty response. This allows RAVEN to perform
    purely static analysis without requiring an LLM backend.
    """

    provider_name = "none"

    def chat(
        self,
        messages: list[LLMMessage],
        temperature: float = 0.2,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        logger.debug("StubProvider: LLM call skipped (no provider configured)")
        return LLMResponse(content="", model="none", provider="none")


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create_llm_provider(config: Any) -> BaseLLMProvider:
    """Create an LLM provider from RAVEN configuration.

    Args:
        config: A :class:`~raven.core.config.RavenConfig` instance.

    Returns:
        A concrete :class:`BaseLLMProvider`.
    """
    provider = config.get("llm.provider", "none")
    model = config.get("llm.model", "")
    api_key = config.get("llm.api_key", "")

    if provider == "openai":
        if not api_key:
            logger.warning("OpenAI API key not set. Falling back to stub provider.")
            return StubProvider(model="none")
        return OpenAIProvider(
            model=model or "gpt-4",
            api_key=api_key,
            base_url=config.get("llm.base_url", ""),
        )

    if provider == "anthropic":
        if not api_key:
            logger.warning("Anthropic API key not set. Falling back to stub provider.")
            return StubProvider(model="none")
        return AnthropicProvider(
            model=model or "claude-sonnet-4-20250514",
            api_key=api_key,
        )

    if provider == "ollama":
        return OllamaProvider(
            model=config.get("llm.local_model", "llama3"),
            host=config.get("llm.ollama_host", "http://localhost:11434"),
        )

    # Default: no LLM
    return StubProvider(model="none")
