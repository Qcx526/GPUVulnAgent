# -*- coding: utf-8 -*-
"""Provider abstraction: one call shape the runtime can rely on.

The runtime speaks in messages and receives a :class:`ProviderResponse`. Whether the
provider reached that response through native ``tool_calls`` or through a JSON blob in
the text is recorded on the response, not inferred later, because "the model used tools"
has to be a fact about what the endpoint returned.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

NATIVE = "native"
JSON_FALLBACK = "json_fallback"
PROSE = "prose"


class ProviderError(RuntimeError):
    """A provider call failed in a way the runtime must not silently absorb."""

    def __init__(self, message: str, *, retryable: bool = False,
                 status: Optional[int] = None) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.status = status


@dataclass
class Usage:
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    total_tokens: Optional[int] = None

    def to_dict(self) -> dict:
        return {"prompt_tokens": self.prompt_tokens,
                "completion_tokens": self.completion_tokens,
                "total_tokens": self.total_tokens}

    def add(self, other: "Usage") -> "Usage":
        def plus(a, b):
            if a is None and b is None:
                return None
            return (a or 0) + (b or 0)
        return Usage(plus(self.prompt_tokens, other.prompt_tokens),
                     plus(self.completion_tokens, other.completion_tokens),
                     plus(self.total_tokens, other.total_tokens))


@dataclass
class ToolCall:
    """One function call requested by the model.

    ``arguments`` is the parsed mapping; ``raw_arguments`` is exactly what the provider
    sent, kept because a malformed argument string is itself evidence.
    """
    id: str
    name: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    raw_arguments: str = ""
    parse_error: str = ""

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "arguments": self.arguments,
                "raw_arguments": self.raw_arguments, "parse_error": self.parse_error}


@dataclass
class ProviderResponse:
    content: str = ""
    tool_calls: List[ToolCall] = field(default_factory=list)
    usage: Usage = field(default_factory=Usage)
    finish_reason: str = ""
    model: str = ""
    mode: str = PROSE
    latency_ms: int = 0
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def has_tool_calls(self) -> bool:
        return bool(self.tool_calls)

    def assistant_message(self) -> dict:
        """The assistant turn, replayable into the next request.

        DeepSeek (like OpenAI) rejects a tool call that is not answered by a ``tool``
        message with the same id, so the ids are preserved verbatim.
        """
        message: Dict[str, Any] = {"role": "assistant", "content": self.content or ""}
        if self.tool_calls:
            message["tool_calls"] = [
                {"id": call.id, "type": "function",
                 "function": {"name": call.name, "arguments": call.raw_arguments or "{}"}}
                for call in self.tool_calls]
        return message


def tool_message(call_id: str, name: str, payload: Any, limit: int = 8000) -> dict:
    """Render a tool result as the ``tool`` role message the model expects."""
    if isinstance(payload, str):
        text = payload
    else:
        text = json.dumps(payload, ensure_ascii=False)
    header = ""
    if isinstance(payload, dict) and payload.get("evidence_id"):
        # The id goes on its own line, ahead of anything that can be cut. A model that cannot
        # see the id guesses one, and a guessed id is worse than no citation at all.
        header = "evidence_id=%s\n" % payload["evidence_id"]
        limit = max(200, limit - len(header))
    if len(text) > limit:
        text = text[:limit] + "\n...[truncated; use artifact_read for the full body]"
    return {"role": "tool", "tool_call_id": call_id, "name": name,
            "content": header + text}


class Provider:
    """Base class. Subclasses implement :meth:`chat`."""

    name = "provider"

    def __init__(self, *, model: str, timeout: int = 300, max_attempts: int = 3) -> None:
        self.model = model
        self.timeout = timeout
        self.max_attempts = max_attempts

    def chat(self, messages: List[dict], *, tools: Optional[List[dict]] = None,
             temperature: Optional[float] = None, json_mode: bool = False,
             timeout: Optional[int] = None) -> ProviderResponse:
        raise NotImplementedError

    def describe(self) -> dict:
        return {"provider": self.name, "model": self.model, "timeout": self.timeout,
                "max_attempts": self.max_attempts}
