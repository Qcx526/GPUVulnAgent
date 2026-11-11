# -*- coding: utf-8 -*-
"""DeepSeek provider over the OpenAI-compatible Chat Completions endpoint.

Deliberately dependency-free: one HTTPS POST, explicit timeouts, bounded retries. The
previous project reached the same API through a framework whose retry, timeout and
message-shape behaviour had to be re-checked every upgrade; the agent needs three
things from a provider - text, tool calls, usage - and none of them require a framework.

Retry policy: transport failures, 408, 429 and 5xx are retried with bounded backoff.
400/401/403/404 are deterministic (bad model, bad key, content policy) and fail
immediately, because retrying them only burns budget.
"""

from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from ..evidence.redact import redact
from .base import JSON_FALLBACK, NATIVE, PROSE, Provider, ProviderError, ProviderResponse, \
    ToolCall, Usage

RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504, 529}


class DeepSeekProvider(Provider):
    name = "deepseek"

    def __init__(self, *, api_key: str, model: str, base_url: str = "https://api.deepseek.com",
                 timeout: int = 300, max_attempts: int = 3, temperature: float = 0.2,
                 max_tokens: int = 8192) -> None:
        super().__init__(model=model, timeout=timeout, max_attempts=max_attempts)
        if not api_key:
            raise ProviderError("DEEPSEEK_API_KEY is not set; LLM calls cannot start")
        self._api_key = api_key.strip()
        self.base_url = base_url.rstrip("/")
        self.temperature = temperature
        self.max_tokens = max_tokens

    # -- public -----------------------------------------------------------
    def chat(self, messages: List[dict], *, tools: Optional[List[dict]] = None,
             temperature: Optional[float] = None, json_mode: bool = False,
             timeout: Optional[int] = None) -> ProviderResponse:
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature if temperature is None else temperature,
            "max_tokens": self.max_tokens,
            "stream": False,
        }
        if tools:
            payload["tools"] = tools
            # "auto" lets the model answer without a tool when it has a conclusion; the
            # runtime treats a tool-free turn as a candidate final answer.
            payload["tool_choice"] = "auto"
        if json_mode:
            payload["response_format"] = {"type": "json_object"}
        return self._post(payload, timeout=timeout)

    def describe(self) -> dict:
        described = super().describe()
        described.update({"base_url": self.base_url, "api_key_present": True,
                          "max_tokens": self.max_tokens})
        return described

    # -- transport --------------------------------------------------------
    def _post(self, payload: Dict[str, Any],
              timeout: Optional[int] = None) -> ProviderResponse:
        url = self.base_url + "/chat/completions"
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        limit = int(timeout) if timeout else self.timeout
        last_error: Optional[Exception] = None
        for attempt in range(1, self.max_attempts + 1):
            started = time.time()
            request = urllib.request.Request(
                url, data=body, method="POST",
                headers={"Content-Type": "application/json",
                         "Accept": "application/json",
                         # Some relays hide the model behind a custom header; the key never
                         # leaves this function and is never written anywhere.
                         "Authorization": "Bearer " + self._api_key})
            try:
                with urllib.request.urlopen(request, timeout=limit) as response:
                    raw = response.read()
                    status = getattr(response, "status", 200)
            except urllib.error.HTTPError as exc:
                detail, _ = redact(_short(exc.read()))
                if exc.code in RETRYABLE_STATUS and attempt < self.max_attempts:
                    last_error = exc
                    time.sleep(_backoff(attempt))
                    continue
                raise ProviderError(
                    "deepseek HTTP %s: %s" % (exc.code, detail),
                    retryable=exc.code in RETRYABLE_STATUS, status=exc.code) from None
            except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:
                last_error = exc
                if attempt < self.max_attempts:
                    time.sleep(_backoff(attempt))
                    continue
                raise ProviderError("deepseek transport failure after %d attempts: %s"
                                    % (attempt, type(exc).__name__), retryable=True) from None
            decoded = _decode(raw, started)
            decoded.latency_ms = int((time.time() - started) * 1000)
            decoded.raw["http_status"] = status
            return decoded
        raise ProviderError("deepseek exhausted %d attempts (%s)"
                            % (self.max_attempts, type(last_error).__name__), retryable=True)


def _backoff(attempt: int) -> float:
    return float(min(2 ** attempt, 20))


def _short(data: bytes, limit: int = 400) -> str:
    text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else str(data)
    return text[:limit]


def _decode(raw: bytes, started: float) -> ProviderResponse:
    try:
        data = json.loads(raw.decode("utf-8"))
    except ValueError:
        # A gateway HTML page is not JSON; report the shape, not the body.
        raise ProviderError("provider returned non-JSON response (%d bytes)"
                            % len(raw), retryable=True) from None
    if not isinstance(data, dict):
        raise ProviderError("provider returned a non-object JSON document")
    choices = data.get("choices") or []
    if not choices:
        error = data.get("error") or {}
        message = error.get("message") if isinstance(error, dict) else str(error)
        raise ProviderError("provider returned no choices: %s" % (message or "unknown"))
    message = choices[0].get("message") or {}
    content = message.get("content") or ""
    if not isinstance(content, str):
        content = json.dumps(content, ensure_ascii=False)
    calls = []
    for index, item in enumerate(message.get("tool_calls") or []):
        function = item.get("function") or {}
        raw_args = function.get("arguments")
        if not isinstance(raw_args, str):
            raw_args = json.dumps(raw_args or {}, ensure_ascii=False)
        arguments, parse_error = _parse_arguments(raw_args)
        calls.append(ToolCall(id=str(item.get("id") or "call_%d" % index),
                              name=str(function.get("name") or ""),
                              arguments=arguments, raw_arguments=raw_args,
                              parse_error=parse_error))
    usage = _usage(data.get("usage"))
    mode = NATIVE if calls else PROSE
    return ProviderResponse(content=content, tool_calls=calls, usage=usage,
                            finish_reason=str(choices[0].get("finish_reason") or ""),
                            model=str(data.get("model") or ""), mode=mode,
                            raw={"id": data.get("id"), "created": data.get("created"),
                                 "usage": usage.to_dict()})


def _parse_arguments(raw: str) -> tuple:
    """Parse the JSON argument string. Never guesses: a broken string is reported."""
    text = (raw or "").strip()
    if not text:
        return {}, ""
    try:
        parsed = json.loads(text)
    except ValueError as exc:
        return {}, "arguments are not valid JSON: %s" % exc
    if not isinstance(parsed, dict):
        return {}, "arguments must be a JSON object, got %s" % type(parsed).__name__
    return parsed, ""


def _usage(node: Any) -> Usage:
    if not isinstance(node, dict):
        return Usage()
    prompt = node.get("prompt_tokens")
    completion = node.get("completion_tokens")
    total = node.get("total_tokens")
    if total is None and prompt is not None and completion is not None:
        total = prompt + completion
    return Usage(prompt_tokens=prompt, completion_tokens=completion, total_tokens=total)


def json_fallback_mode() -> str:
    """Name used in evidence when a turn was reconstructed from text, not tool_calls."""
    return JSON_FALLBACK
