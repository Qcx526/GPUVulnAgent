# -*- coding: utf-8 -*-
"""Observation rendering: how much of a tool result the model sees.

A single truncation length threw away whatever a tool had just fetched - a search lost its
result list, an extract lost its body, an artifact read lost the text it was asked for.
Each tool family is rendered by what it actually returns, and the full body stays in an
artifact with a pointer the model can follow.
"""

from __future__ import annotations

import json


def render(observation, budget: int = 2400) -> str:
    if not isinstance(observation, dict):
        return str(observation)[:budget]
    summary = observation.get("summary")
    if not isinstance(summary, dict):
        return _json(observation, budget)

    parts = []
    if "termination" in summary:
        parts.append("exit=%s termination=%s timeout=%s"
                     % (summary.get("exit"), summary.get("termination"),
                        summary.get("timed_out")))
        if summary.get("argv"):
            parts.append("argv: " + " ".join(str(a) for a in summary["argv"])[:300])
        if summary.get("stdout"):
            parts.append("stdout:\n" + str(summary["stdout"])[:budget])
        if summary.get("stderr"):
            parts.append("stderr:\n" + str(summary["stderr"])[:800])
    elif "items" in summary:
        parts.append("results=%s" % summary.get("results"))
        for item in (summary.get("items") or [])[:6]:
            if not isinstance(item, dict):
                parts.append("- %s" % str(item)[:200])
                continue
            label = item.get("name") or item.get("title") or item.get("id") or ""
            extra = item.get("purpose") or item.get("content") or ""
            available = item.get("available")
            flag = "" if available is None else (" [runnable]" if available else " [not runnable]")
            parts.append("- %s%s | %s" % (label, flag, str(extra)[:220]))
        if summary.get("catalog"):
            cat = summary["catalog"]
            parts.append("catalog: total=%s available=%s by_kind=%s"
                         % (cat.get("total"), cat.get("available"), cat.get("by_kind")))
    elif "content" in summary:
        parts.append("artifact=%s offset=%s has_more=%s total=%s"
                     % (summary.get("artifact"), summary.get("offset"),
                        summary.get("has_more"), summary.get("total_bytes")))
        parts.append(str(summary.get("content") or "")[:budget])
    elif "content_preview" in summary:
        parts.append("chars=%s truncated=%s"
                     % (summary.get("chars"), summary.get("truncated")))
        parts.append(str(summary["content_preview"])[:budget])
    elif "entries" in summary:
        parts.append("dir=%s" % summary.get("path"))
        for entry in (summary.get("entries") or [])[:40]:
            parts.append("- %s%s%s" % (entry.get("name"), "/" if entry.get("dir") else "",
                                       "" if entry.get("dir") else
                                       " (%s bytes)" % entry.get("bytes")))
    elif "tools" in summary and "manifest" in summary:
        parts.append("toolchain manifest: %s" % summary.get("manifest"))
        parts.append("tools: " + ", ".join(summary.get("tools") or []))
    elif "error" in summary:
        parts.append("error: " + str(summary["error"])[:500])
    else:
        parts.append(_json(summary, budget))

    for key in ("did_you_mean", "note", "how_to_run"):
        if summary.get(key):
            parts.append("%s: %s" % (key, str(summary[key])[:300]))
    if observation.get("artifacts"):
        refs = [a.get("artifact") for a in observation["artifacts"][:4] if isinstance(a, dict)]
        if refs:
            parts.append("artifacts: " + ", ".join(refs))
    if not observation.get("ok", True):
        parts.insert(0, "STATUS=failed")
    return "\n".join(parts)[:budget + 900]


def compact(observation, limit: int = 900) -> dict:
    """Shrink an observation for the transcript without losing its shape."""
    text = _json(observation, limit)
    return {"truncated": len(_json(observation, 10 ** 9)) > limit, "preview": text}


def _json(value, limit: int) -> str:
    try:
        text = json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        text = str(value)
    return text if len(text) <= limit else text[:limit] + "..."
