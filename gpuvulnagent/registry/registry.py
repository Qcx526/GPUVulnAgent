# -*- coding: utf-8 -*-
"""Tool registry: register, describe, validate, dispatch, and never guess.

A name clash is an error rather than an import-order accident. Dispatch separates two
different facts that used to be merged into one ``ok``:

``dispatched``  the tool exists, its dependencies are present and the arguments passed
                validation - i.e. the handler actually ran
``ok``          the operation succeeded according to the tool's own report

A shell command that exits 1 was dispatched and failed; a tool that needs ``nvcc`` on a
machine without it was never dispatched at all. Reports need both bits.
"""

from __future__ import annotations

import shutil
from typing import Dict, List, Optional

from .spec import ToolSpec, coerce_arguments


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: Dict[str, ToolSpec] = {}
        self.conflicts: List[dict] = []

    # -- registration ----------------------------------------------------
    def register(self, spec: ToolSpec, allow_override: bool = False) -> None:
        if spec.name in self._tools and not allow_override:
            existing = self._tools[spec.name]
            raise ValueError("tool %r already registered (source=%s); refusing to replace it "
                             "with source=%s" % (spec.name, existing.source, spec.source))
        self._tools[spec.name] = spec

    def register_many(self, specs: List[ToolSpec]) -> List[str]:
        added = []
        for spec in specs:
            self.register(spec)
            added.append(spec.name)
        return added

    def extend(self, specs: List[ToolSpec]) -> List[str]:
        """Add optional tools; a clash is recorded and skipped, never resolved silently."""
        added = []
        for spec in specs:
            if spec.name in self._tools:
                self.conflicts.append({"name": spec.name, "source": spec.source,
                                       "kept": self._tools[spec.name].source})
                continue
            self.register(spec)
            added.append(spec.name)
        return added

    # -- inspection ------------------------------------------------------
    def get(self, name: str) -> Optional[ToolSpec]:
        return self._tools.get(name)

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def __len__(self) -> int:
        return len(self._tools)

    def names(self) -> List[str]:
        return sorted(self._tools)

    def all(self) -> List[ToolSpec]:
        return [self._tools[name] for name in sorted(self._tools)]

    def describe(self) -> List[dict]:
        return [self._describe(spec) for spec in self.all()]

    def _describe(self, spec: ToolSpec) -> dict:
        available, missing = availability(spec)
        return {"name": spec.name, "description": spec.description,
                "category": spec.category, "parameters": spec.json_schema(),
                "signature": spec.signature(), "source": spec.source,
                "location": spec.location, "formats": list(spec.formats),
                "tags": list(spec.tags), "side_effects": list(spec.side_effects),
                "available": available, "missing": missing}

    def menu(self) -> List[dict]:
        return self.describe()

    def openai_tools(self) -> List[dict]:
        return [spec.openai_schema() for spec in self.all()]

    def summary_line(self, spec: ToolSpec) -> str:
        available, missing = availability(spec)
        state = "ok" if available else "missing:%s" % ",".join(missing)
        return "- %s [%s] %s" % (spec.signature(), state, _one_line(spec.description, 200))

    # -- dispatch --------------------------------------------------------
    def call(self, name: str, arguments: dict, *, tool_call_id: str = "",
             via: str = "native") -> dict:
        spec = self.get(name)
        if spec is None:
            known = ", ".join(self.names())
            return envelope(False, False, None,
                            "unknown tool %r; registered: %s" % (name, known or "(none)"),
                            tool_call_id=tool_call_id, via=via)
        available, missing = availability(spec)
        if not available:
            return envelope(False, False, None,
                            "tool %r requires %s, which is not on PATH"
                            % (name, ", ".join(missing)), tool_call_id=tool_call_id, via=via)

        values, errors, coercions = coerce_arguments(spec, arguments)
        if errors:
            return envelope(False, False, None, "bad arguments for %s: %s"
                            % (name, "; ".join(errors)), tool_call_id=tool_call_id, via=via,
                            arguments=values, coercions=coercions)
        try:
            payload = spec.handler(**values)
        except TypeError as exc:
            # Signature binding already passed, so this is the tool's own fault.
            return envelope(True, False, None, "tool raised TypeError (internal fault): %s"
                            % exc, tool_call_id=tool_call_id, via=via, arguments=values,
                            coercions=coercions)
        except Exception as exc:  # noqa: BLE001 - a tool failure is data, not a crash
            return envelope(True, False, None, "%s: %s" % (type(exc).__name__, exc),
                            tool_call_id=tool_call_id, via=via, arguments=values,
                            coercions=coercions)
        return envelope(True, True, payload, None, tool_call_id=tool_call_id, via=via,
                        arguments=values, coercions=coercions)


def availability(spec: ToolSpec) -> tuple:
    missing = [item for item in spec.requires if shutil.which(item) is None]
    return (not missing), missing


def envelope(dispatched: bool, operation_ok: bool, payload, error: str, *,
             tool_call_id: str = "", via: str = "native", arguments: Optional[dict] = None,
             coercions: Optional[List[str]] = None) -> dict:
    result = payload if isinstance(payload, dict) else {"value": payload}
    reported = result.get("ok") if isinstance(payload, dict) and "ok" in result else None
    ok = bool(reported) if reported is not None else bool(operation_ok)
    if error:
        status = "dispatch_error" if not dispatched else "failed"
    elif ok:
        status = result.get("status", "success") if isinstance(payload, dict) else "success"
    else:
        status = "failed"
    return {"dispatched": dispatched, "ok": ok, "status": status, "result": payload,
            "summary": result.get("summary") if isinstance(payload, dict) else None,
            "artifacts": result.get("artifacts", []) if isinstance(payload, dict) else [],
            "error": error or (result.get("error") if isinstance(payload, dict) else None),
            "tool_call_id": tool_call_id, "via": via, "arguments": arguments or {},
            "coercions": coercions or []}


def _one_line(text: str, limit: int) -> str:
    flat = " ".join((text or "").split())
    return flat if len(flat) <= limit else flat[:limit - 3] + "..."
