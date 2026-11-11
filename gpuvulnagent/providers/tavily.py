# -*- coding: utf-8 -*-
"""Tavily provider: web search and readable extraction, exposed as tools.

Unconfigured is a normal state: the tools are simply absent from the registry and
``status()`` says exactly why. The runtime knows nothing about Tavily.
"""

from __future__ import annotations

import json
from typing import List, Optional

from ..evidence.redact import redact
from ..registry.spec import ParamSpec, ToolSpec

PROVIDER = "tavily"
SNIPPET_CHARS = 600


def status(api_key: str) -> dict:
    key = (api_key or "").strip()
    try:
        import tavily  # noqa: F401
        sdk, sdk_reason = True, ""
    except Exception as exc:  # noqa: BLE001 - optional dependency
        sdk, sdk_reason = False, "%s: %s" % (type(exc).__name__, exc)
    available = bool(key) and sdk
    if available:
        reason = "ready"
    elif not key and not sdk:
        reason = "TAVILY_API_KEY is not set and tavily-python is not installed"
    elif not key:
        reason = "TAVILY_API_KEY is not set"
    else:
        reason = "tavily-python is not installed (%s)" % sdk_reason
    return {"provider": PROVIDER, "sdk_installed": sdk, "key_present": bool(key),
            "available": available, "reason": reason}


def build_tools(*, api_key: str, log) -> List[ToolSpec]:
    state = status(api_key)
    if not state["available"]:
        return []
    artifacts = log.artifacts
    client_ref = {}

    def client():
        if "client" not in client_ref:
            from tavily import TavilyClient
            client_ref["client"] = TavilyClient(api_key=api_key.strip())
        return client_ref["client"]

    def web_search(query: str, max_results: int = 5, search_depth: str = "basic") -> dict:
        try:
            payload = client().search(query=query, max_results=int(max_results),
                                      search_depth=str(search_depth))
        except Exception as exc:  # noqa: BLE001 - a failed call is an observation
            message, _ = redact("%s: %s" % (type(exc).__name__, exc))
            entry = {"query": query, "error": message}
            log.append("search", entry, status="failed")
            return {"ok": False, "status": "failed", "summary": entry, "artifacts": []}

        results = payload.get("results", []) if isinstance(payload, dict) else []
        ref = artifacts.save("http", "tavily-search.json",
                             json.dumps(payload, ensure_ascii=False)) if artifacts else None
        digest = (ref or {}).get("sha256")
        items = []
        for item in results[:10]:
            body = item.get("content") or ""
            items.append({"title": (item.get("title") or "")[:120],
                          "url": item.get("url", ""), "score": item.get("score"),
                          "content": body[:SNIPPET_CHARS],
                          "content_truncated": len(body) > SNIPPET_CHARS})
        status_ = "empty" if not items else "success"
        summary = {"query": query, "results": len(results), "payload_sha256": digest,
                   "search_depth": search_depth, "items": items,
                   "note": "content is the engine's snippet, not the page body"}
        log.append("search", {"query": query, "results": len(results),
                              "payload_sha256": digest, "search_depth": search_depth,
                              "artifacts": [ref] if ref else []}, status=status_)
        return {"ok": True, "status": status_, "summary": summary,
                "artifacts": [ref] if ref else []}

    def web_extract(url: str) -> dict:
        try:
            payload = client().extract(urls=[url])
        except Exception as exc:  # noqa: BLE001
            message, _ = redact("%s: %s" % (type(exc).__name__, exc))
            entry = {"url": url, "error": message}
            log.append("extract", entry, status="failed")
            return {"ok": False, "status": "failed", "summary": entry, "artifacts": []}

        items = payload.get("results", []) if isinstance(payload, dict) else []
        failed = payload.get("failed_results", []) if isinstance(payload, dict) else []
        content = (items[0].get("raw_content") or "") if items else ""
        ref = artifacts.save("http", "tavily-extract.json",
                             json.dumps(payload, ensure_ascii=False)) if artifacts else None
        digest = (ref or {}).get("sha256")
        refs = [ref] if ref else []
        # API success is not extraction success.
        if not items or not content.strip():
            entry = {"url": url,
                     "error": "extraction returned no readable body" if items else
                              "extraction returned no results",
                     "failed_results": len(failed), "payload_sha256": digest,
                     "artifacts": refs}
            log.append("extract", entry, status="failed")
            return {"ok": False, "status": "failed", "summary": entry, "artifacts": refs}

        status_ = "partial" if failed else "success"
        summary = {"url": url, "chars": len(content), "payload_sha256": digest,
                   "failed_results": failed[:5], "truncated": len(content) > 4000,
                   "content_preview": content[:4000]}
        log.append("extract", {"url": url, "chars": len(content),
                               "payload_sha256": digest, "failed_results": len(failed),
                               "artifacts": refs}, status=status_)
        return {"ok": True, "status": status_, "summary": summary, "artifacts": refs}

    return [
        ToolSpec(name="web_search", description=(
            "Search the web for advisories, documentation and prior work. Returns titles, "
            "URLs, scores and snippets; the full payload is stored as an artifact."),
            handler=web_search, category="research", source=PROVIDER,
            location="gpuvulnagent/providers/tavily.py:web_search",
            usage="web_search(query='NVIDIA nvJPEG CVE-2024-0124 advisory', max_results=5)",
            parameters=[ParamSpec("query", "string", "Search query."),
                        ParamSpec("max_results", "integer", "1..20 results.",
                                  required=False, default=5, minimum=1, maximum=20),
                        ParamSpec("search_depth", "string", "Search effort.",
                                  required=False, default="basic",
                                  enum=("basic", "advanced"))],
            side_effects=("network", "third_party_api"), tags=("web", "research")),

        ToolSpec(name="web_extract", description=(
            "Fetch and extract the readable text of one URL. Long pages are truncated in "
            "the reply; the full payload is an artifact."),
            handler=web_extract, category="research", source=PROVIDER,
            location="gpuvulnagent/providers/tavily.py:web_extract",
            parameters=[ParamSpec("url", "string", "Absolute URL.")],
            side_effects=("network", "third_party_api"), tags=("web", "research")),
    ]


def build_specs(*, api_key: str, log) -> List[ToolSpec]:
    return build_tools(api_key=api_key, log=log)


def describe_status(api_key: str) -> str:
    state = status(api_key)
    return "%s available=%s (%s)" % (state["provider"], state["available"], state["reason"])


def _unused(_: Optional[dict]) -> None:  # pragma: no cover - keeps imports honest
    return None
