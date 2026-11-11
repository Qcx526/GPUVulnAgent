# -*- coding: utf-8 -*-
"""Test doubles: a scripted provider and helpers to build runs without an API key."""

from __future__ import annotations

import json
from typing import Dict, List, Optional

from gpuvulnagent.providers.base import Provider, ProviderResponse, ToolCall, Usage


class ScriptedProvider(Provider):
    """Plays back a fixed list of responses and records what it was asked."""

    name = "scripted"

    def __init__(self, script: Optional[List[dict]] = None, *, model: str = "scripted",
                 timeout: int = 30) -> None:
        super().__init__(model=model, timeout=timeout)
        self.script = list(script or [])
        self.calls: List[dict] = []
        self.usage = Usage(prompt_tokens=10, completion_tokens=5, total_tokens=15)

    def push(self, item: dict) -> None:
        self.script.append(item)

    def chat(self, messages, *, tools=None, temperature=None, json_mode=False,
             timeout=None) -> ProviderResponse:
        self.calls.append({"messages": list(messages), "tools": tools,
                           "json_mode": json_mode, "timeout": timeout})
        if not self.script:
            return ProviderResponse(content="没有更多脚本化回复。", mode="prose",
                                    usage=self.usage)
        item = self.script.pop(0)
        if isinstance(item, ProviderResponse):
            return item
        calls = [ToolCall(id=c.get("id", "call_%d" % index), name=c["name"],
                          arguments=c.get("arguments", {}),
                          raw_arguments=json.dumps(c.get("arguments", {})),
                          parse_error=c.get("parse_error", ""))
                 for index, c in enumerate(item.get("tool_calls") or [])]
        return ProviderResponse(content=item.get("content", ""), tool_calls=calls,
                                usage=item.get("usage", self.usage),
                                finish_reason=item.get("finish_reason", "stop"),
                                model=self.model,
                                mode="native" if calls else item.get("mode", "prose"))


class RaisingProvider(Provider):
    name = "raising"

    def __init__(self, error: Exception) -> None:
        super().__init__(model="raising", timeout=5)
        self.error = error

    def chat(self, messages, *, tools=None, temperature=None, json_mode=False,
             timeout=None) -> ProviderResponse:
        raise self.error


def tool_call(name: str, arguments: Optional[dict] = None, call_id: str = "call_1") -> dict:
    return {"id": call_id, "name": name, "arguments": arguments or {}}


def native(*tool_calls: dict, content: str = "") -> dict:
    return {"content": content, "tool_calls": list(tool_calls)}


def prose(text: str) -> dict:
    return {"content": text, "tool_calls": [], "mode": "prose"}


def json_action(action: Dict) -> dict:
    return {"content": json.dumps(action, ensure_ascii=False), "tool_calls": [],
            "mode": "json_fallback"}


def read_records(path) -> List[dict]:
    return [json.loads(line) for line in open(path, encoding="utf-8").read().splitlines()
            if line.strip()]
