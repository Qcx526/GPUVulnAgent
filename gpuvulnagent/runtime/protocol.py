# -*- coding: utf-8 -*-
"""Action protocol: the JSON fallback channel, parsed strictly.

Native tool calling is the primary path. This parser exists for providers or endpoints
that answer in text, and for a model that emits a JSON action even though tools were
offered. It never guesses intent: a malformed action is rejected with the reason, and the
caller decides whether to retry or stop.
"""

from __future__ import annotations

import json
import re
from typing import List, Tuple

ALLOWED_KEYS = {"thought", "tool", "args", "final"}


def parse_action(raw: str, known_tools: List[str]) -> Tuple[dict, str]:
    """Return ``(action, error)``. Exactly one of ``tool``/``final`` must be present."""
    text = (raw or "").strip()
    if not text:
        return {}, "empty response"
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    candidate = (fence.group(1) if fence else text).strip()
    start, end = candidate.find("{"), candidate.rfind("}")
    if start < 0 or end <= start:
        return {}, "no JSON object in response"
    try:
        action = json.loads(candidate[start:end + 1])
    except ValueError as exc:
        return {}, "invalid JSON: %s" % exc
    if not isinstance(action, dict):
        return {}, "action must be a JSON object"

    unknown = set(action) - ALLOWED_KEYS
    if unknown:
        return {}, "unknown fields: %s" % ", ".join(sorted(unknown))
    if "thought" in action and not isinstance(action["thought"], str):
        return {}, "thought must be a string"
    has_tool, has_final = "tool" in action, "final" in action
    if has_tool == has_final:
        return {}, "exactly one of 'tool' or 'final' is required"
    if has_final:
        if not isinstance(action["final"], str) or not action["final"].strip():
            return {}, "final must be a non-empty string"
        return action, ""
    if not isinstance(action["tool"], str):
        return {}, "tool must be a string"
    if action["tool"] not in known_tools:
        return {}, "unknown tool %r; registered: %s" % (action["tool"], ", ".join(known_tools))
    args = action.get("args", {})
    if not isinstance(args, dict):
        return {}, "args must be a JSON object"
    action["args"] = args
    return action, ""


def looks_like_action(text: str) -> bool:
    """Cheap check used to decide whether prose should be parsed at all."""
    stripped = (text or "").strip()
    if not stripped:
        return False
    if stripped.startswith("{") or stripped.startswith("```"):
        return '"tool"' in stripped or '"final"' in stripped
    return False
