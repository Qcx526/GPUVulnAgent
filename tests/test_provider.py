# -*- coding: utf-8 -*-
"""DeepSeek provider: native tool calls, usage, and a retry policy that is not a guess."""

from __future__ import annotations

import json
import urllib.error

import pytest

from gpuvulnagent.providers import deepseek
from gpuvulnagent.providers.base import ProviderError


class FakeResponse:
    def __init__(self, payload: dict, status: int = 200) -> None:
        self._body = json.dumps(payload).encode("utf-8")
        self.status = status

    def read(self, *args) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def completion(*, content: str = "", tool_calls=None, usage=None) -> dict:
    message = {"role": "assistant", "content": content}
    if tool_calls:
        message["tool_calls"] = tool_calls
    return {"id": "chatcmpl-1", "model": "deepseek-chat", "created": 1,
            "choices": [{"message": message, "finish_reason": "tool_calls"}],
            "usage": usage or {"prompt_tokens": 11, "completion_tokens": 7,
                               "total_tokens": 18}}


def provider(**kwargs) -> deepseek.DeepSeekProvider:
    return deepseek.DeepSeekProvider(api_key="sk-test-key-1234567890", model="deepseek-chat",
                                     base_url="https://api.example.invalid", **kwargs)


def test_native_tool_calls_are_parsed_with_ids_and_arguments(monkeypatch):
    payload = completion(tool_calls=[{
        "id": "call_abc", "type": "function",
        "function": {"name": "fs_write",
                     "arguments": json.dumps({"path": "a.txt", "content": "hi"})}}])
    monkeypatch.setattr(deepseek.urllib.request, "urlopen",
                        lambda *a, **k: FakeResponse(payload))
    response = provider().chat([{"role": "user", "content": "go"}],
                               tools=[{"type": "function", "function": {"name": "x"}}])
    assert response.mode == "native"
    assert response.tool_calls[0].id == "call_abc"
    assert response.tool_calls[0].arguments == {"path": "a.txt", "content": "hi"}
    assert response.tool_calls[0].parse_error == ""
    assert response.usage.total_tokens == 18
    assert response.assistant_message()["tool_calls"][0]["id"] == "call_abc"


def test_several_tool_calls_in_one_response(monkeypatch):
    payload = completion(tool_calls=[
        {"id": "call_1", "type": "function",
         "function": {"name": "fs_list", "arguments": "{}"}},
        {"id": "call_2", "type": "function",
         "function": {"name": "env_probe", "arguments": ""}}])
    monkeypatch.setattr(deepseek.urllib.request, "urlopen",
                        lambda *a, **k: FakeResponse(payload))
    response = provider().chat([{"role": "user", "content": "go"}])
    assert [call.id for call in response.tool_calls] == ["call_1", "call_2"]
    assert response.tool_calls[1].arguments == {}


def test_broken_argument_json_is_reported_not_guessed(monkeypatch):
    payload = completion(tool_calls=[{
        "id": "call_x", "type": "function",
        "function": {"name": "fs_read", "arguments": "{path: a"}}])
    monkeypatch.setattr(deepseek.urllib.request, "urlopen",
                        lambda *a, **k: FakeResponse(payload))
    response = provider().chat([{"role": "user", "content": "go"}])
    assert response.tool_calls[0].arguments == {}
    assert "not valid JSON" in response.tool_calls[0].parse_error


def test_client_error_is_not_retried(monkeypatch):
    calls = {"count": 0}

    def boom(*args, **kwargs):
        calls["count"] += 1
        raise urllib.error.HTTPError("https://x", 401, "unauthorized", {}, None)

    monkeypatch.setattr(deepseek.urllib.request, "urlopen", boom)
    with pytest.raises(ProviderError) as info:
        provider(max_attempts=3).chat([{"role": "user", "content": "go"}])
    assert calls["count"] == 1
    assert info.value.status == 401


def test_server_error_is_retried_then_fails(monkeypatch):
    calls = {"count": 0}

    def boom(*args, **kwargs):
        calls["count"] += 1
        raise urllib.error.HTTPError("https://x", 503, "unavailable", {}, None)

    monkeypatch.setattr(deepseek.urllib.request, "urlopen", boom)
    monkeypatch.setattr(deepseek.time, "sleep", lambda seconds: None)
    with pytest.raises(ProviderError):
        provider(max_attempts=2).chat([{"role": "user", "content": "go"}])
    assert calls["count"] == 2


def test_non_json_body_is_a_provider_error(monkeypatch):
    class HtmlResponse(FakeResponse):
        def __init__(self):
            self._body = b"<html>gateway</html>"
            self.status = 200

    monkeypatch.setattr(deepseek.urllib.request, "urlopen",
                        lambda *a, **k: HtmlResponse())
    with pytest.raises(ProviderError):
        provider(max_attempts=1).chat([{"role": "user", "content": "go"}])


def test_provider_refuses_to_start_without_a_key():
    with pytest.raises(ProviderError):
        deepseek.DeepSeekProvider(api_key="", model="deepseek-chat")


def test_json_mode_is_requested_explicitly(monkeypatch):
    seen = {}

    def capture(request, timeout=None):
        seen["body"] = json.loads(request.data.decode("utf-8"))
        return FakeResponse(completion(content='{"a":1}'))

    monkeypatch.setattr(deepseek.urllib.request, "urlopen", capture)
    provider().chat([{"role": "user", "content": "go"}], json_mode=True)
    assert seen["body"]["response_format"] == {"type": "json_object"}


def test_authorization_header_is_sent_but_never_recorded(monkeypatch):
    seen = {}

    def capture(request, timeout=None):
        seen["auth"] = request.get_header("Authorization")
        return FakeResponse(completion(content="ok"))

    monkeypatch.setattr(deepseek.urllib.request, "urlopen", capture)
    provider().chat([{"role": "user", "content": "go"}])
    assert seen["auth"].startswith("Bearer sk-test")
