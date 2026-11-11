# -*- coding: utf-8 -*-
"""Tool capability catalog: what exists, what it is for, where it lives, whether it runs.

P18 exposed the failure this module exists to prevent: the agent could not find
``jpeg_adapter.py`` because registration was the only way to become visible, and nothing
was registered from that file. The agent then concluded no JPEG tooling existed.

The catalog is therefore a separate index from the registry. It holds:

* every registered tool, with the parameter contract the provider sees,
* every adapter the project ships, *including the ones that cannot run here* - with the
  reason, so the agent can decide to install a dependency or work around it,
* every binary in the toolchain manifest, with version, hash and runnability.

Searching covers name, purpose, supported file formats and dependencies, which are the
four questions an agent actually asks before choosing a tool.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from ..discovery.manifest import ToolchainManifest
from ..registry.registry import ToolRegistry, availability
from ..registry.spec import ToolSpec


@dataclass
class Capability:
    name: str
    kind: str                      # tool | adapter | binary
    purpose: str = ""
    location: str = ""
    formats: List[str] = field(default_factory=list)
    requires: List[str] = field(default_factory=list)
    available: bool = False
    reason: str = ""
    usage: str = ""
    tags: List[str] = field(default_factory=list)
    parameters: Dict[str, str] = field(default_factory=dict)
    version: str = ""
    sha256: str = ""
    registered: bool = False

    def to_dict(self) -> dict:
        return {"name": self.name, "kind": self.kind, "purpose": self.purpose,
                "location": self.location, "formats": list(self.formats),
                "requires": list(self.requires), "available": self.available,
                "reason": self.reason, "usage": self.usage, "tags": list(self.tags),
                "parameters": dict(self.parameters), "version": self.version,
                "sha256": self.sha256, "registered": self.registered}

    def haystack(self) -> str:
        return " ".join([self.name, self.purpose, self.usage, " ".join(self.tags),
                         " ".join(self.formats), " ".join(self.requires),
                         self.kind]).lower()


class CapabilityCatalog:
    def __init__(self, *, registry: Optional[ToolRegistry] = None,
                 manifest: Optional[ToolchainManifest] = None) -> None:
        self.entries: Dict[str, Capability] = {}
        self.registry = registry
        self.manifest = manifest

    # -- population ------------------------------------------------------
    def add_registry(self, registry: ToolRegistry) -> List[str]:
        self.registry = registry
        added = []
        for spec in registry.all():
            added.append(self._add_from_spec(spec, registry))
        return added

    def add_specs(self, specs: Iterable[ToolSpec], *, registered: bool = False,
                  reason: str = "") -> List[str]:
        """Adapters announce themselves even when their dependencies are absent."""
        added = []
        for spec in specs:
            entry = self._add_from_spec(spec, self.registry)
            entry.registered = registered and entry.registered
            if not entry.available and reason:
                entry.reason = reason
            added.append(entry.name)
        return added

    def add_unavailable(self, *, name: str, kind: str, purpose: str, location: str,
                        requires: List[str], reason: str, formats: Optional[List[str]] = None,
                        usage: str = "", tags: Optional[List[str]] = None) -> str:
        """Index something that exists on disk but cannot run in this environment."""
        self.entries[name] = Capability(
            name=name, kind=kind, purpose=purpose, location=location,
            formats=list(formats or []), requires=list(requires), available=False,
            reason=reason, usage=usage, tags=list(tags or []), registered=False)
        return name

    def add_manifest(self, manifest: ToolchainManifest) -> List[str]:
        self.manifest = manifest
        added = []
        for name in manifest.names():
            entry = manifest.get(name)
            resolved = manifest.path_of(name)
            is_binary = entry.kind == "binary"
            runnable = manifest.runnable(name) if (resolved and is_binary) else False
            if not resolved:
                reason = "recorded in the manifest but the file is missing"
            elif not is_binary:
                reason = "%s is a %s, not an executable" % (Path(entry.path).name, entry.kind)
            elif not runnable:
                reason = "the binary exists but did not run"
            else:
                reason = ""
            capability = Capability(
                name=name, kind="binary", purpose=entry.notes or "%s (%s)" % (name, entry.kind),
                location=str(resolved or (manifest.root / entry.path)),
                formats=list(entry.capabilities), requires=list(entry.depends),
                available=runnable, version=entry.version, sha256=entry.sha256,
                reason=reason, tags=list(entry.capabilities) + [entry.kind])
            self.entries[name] = capability
            added.append(name)
        return added

    def _add_from_spec(self, spec: ToolSpec, registry: Optional[ToolRegistry]) -> Capability:
        available, missing = availability(spec)
        registered = bool(registry and spec.name in registry)
        # An adapter is a project-owned capability over a format or a binary; keeping that
        # distinction in the catalog makes "what ships with this project" answerable.
        is_adapter = spec.category == "adapter" or spec.source.startswith("adapter:")
        existing = self.entries.get(spec.name)
        capability = Capability(
            name=spec.name, kind="adapter" if is_adapter else "tool",
            purpose=spec.description, location=spec.location or spec.source,
            formats=list(spec.formats), requires=list(spec.requires), available=available,
            reason="" if available else "requires %s on PATH" % ", ".join(missing),
            usage=spec.usage, tags=list(spec.tags) + [spec.category],
            parameters={p.name: p.type for p in spec.parameters}, registered=registered)
        if existing and existing.kind == "binary":
            # A manifest binary that also has a tool wrapper keeps the wrapper's contract
            # but must not lose its version/hash.
            capability.version = existing.version
            capability.sha256 = existing.sha256
        self.entries[spec.name] = capability
        return capability

    # -- queries ---------------------------------------------------------
    def names(self) -> List[str]:
        return sorted(self.entries)

    def get(self, name: str) -> Optional[Capability]:
        return self.entries.get(name)

    def search(self, query: str = "", *, formats: Optional[str] = None,
               requires: Optional[str] = None, available_only: bool = False,
               kind: Optional[str] = None, limit: int = 20) -> List[dict]:
        words = [w for w in _tokens(query)]
        format_filter = (formats or "").lower().lstrip("*")
        require_filter = (requires or "").lower()
        scored = []
        for entry in self.entries.values():
            if available_only and not entry.available:
                continue
            if kind and entry.kind != kind:
                continue
            if format_filter and not any(format_filter in f.lower() for f in entry.formats):
                continue
            if require_filter and not any(require_filter in r.lower() or
                                          require_filter in entry.name.lower()
                                          for r in entry.requires + [entry.name]):
                continue
            haystack = entry.haystack()
            score = sum(haystack.count(word) for word in words) if words else 0.0
            if words and score == 0:
                continue
            score += 0.5 if entry.available else 0.0
            score += 0.5 if entry.kind == "tool" else 0.0
            scored.append((score, entry))
        scored.sort(key=lambda pair: (-pair[0], pair[1].name))
        return [entry.to_dict() for _, entry in scored[:limit]]

    def describe(self, name: str) -> Optional[dict]:
        entry = self.get(name)
        if entry is None:
            nearby = [item["name"] for item in self.search(name, limit=5)]
            return {"error": "no capability named %r" % name,
                    "did_you_mean": nearby}
        info = entry.to_dict()
        info["usage"] = entry.usage or _auto_usage(entry)
        info["runnable"] = entry.available
        info["how_to_run"] = (
            entry.location if entry.kind == "binary"
            else "call it through the tool registry by name" if entry.registered
            else "not registered here; its location is given so it can be invoked from "
                 "the shell or inspected")
        if entry.kind == "adapter" and not entry.registered:
            info["note"] = ("this adapter exists but is not registered as a tool in this "
                            "run: %s" % (entry.reason or "no reason recorded"))
        return info

    def by_format(self, extension: str) -> List[dict]:
        return self.search("", formats=extension)

    def missing_dependencies(self) -> Dict[str, List[str]]:
        """Everything indexed but unavailable, keyed by what it needs."""
        out: Dict[str, List[str]] = {}
        for entry in self.entries.values():
            if entry.available:
                continue
            for requirement in entry.requires or ["(no dependency declared)"]:
                out.setdefault(requirement, []).append(entry.name)
        return out

    def summary(self) -> dict:
        total = len(self.entries)
        available = sum(1 for e in self.entries.values() if e.available)
        by_kind: Dict[str, int] = {}
        for entry in self.entries.values():
            by_kind[entry.kind] = by_kind.get(entry.kind, 0) + 1
        return {"total": total, "available": available, "by_kind": by_kind,
                "unavailable": sorted(name for name, e in self.entries.items()
                                      if not e.available)}


def _tokens(text: str) -> List[str]:
    return [t for t in (text or "").lower().replace(",", " ").split() if len(t) > 1]


def _auto_usage(entry: Capability) -> str:
    parts = [entry.purpose or "(no description)"]
    if entry.formats:
        parts.append("handles: " + ", ".join(entry.formats))
    if entry.requires:
        parts.append("needs: " + ", ".join(entry.requires))
    parts.append("location: " + (entry.location or "unknown"))
    return " | ".join(parts)
