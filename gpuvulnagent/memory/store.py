# -*- coding: utf-8 -*-
"""Three memory scopes, because "memory" meant three different things.

P18 kept everything in ``<run>/memory.jsonl``. That file dies with the run: the next run
started from zero and re-walked dead ends the previous run had already paid for.

Here the scopes are explicit and physically separate:

``run``     the current investigation; lives in the run directory, dies with it
``case``    everything learned about one case (one CVE, one target), across runs
``global``  method-level lessons that apply to the next case: what tools work, what
            classes of experiment are a waste on this machine

All three are append-only JSONL. Nothing is overwritten: a correction is a new entry with
``supersedes`` or ``refutes`` pointing at the old id, and both remain readable.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .models import MemoryEntry, MemoryError_, make_id, now, summarise, validate_entry

SCOPE_WEIGHT = {"run": 1.4, "case": 1.2, "global": 1.0}
TYPE_WEIGHT = {"failed": 3.0, "open": 2.0, "finding": 1.0, "hypothesis": 0.8, "attempt": 0.5}


class MemoryStore:
    """One append-only JSONL file."""

    def __init__(self, path: Path, scope: str) -> None:
        self.path = Path(path)
        self.scope = scope
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")

    def entries(self) -> List[MemoryEntry]:
        out: List[MemoryEntry] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(MemoryEntry.from_dict(json.loads(line)))
        return out

    def has(self, entry_id: str) -> bool:
        return any(item.id == entry_id for item in self.entries())

    def append(self, entry: MemoryEntry) -> MemoryEntry:
        # Append-only: an id that already exists is returned as-is instead of rewritten.
        for existing in self.entries():
            if existing.id == entry.id:
                return existing
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry.to_dict(), ensure_ascii=False) + "\n")
        return entry


class LayeredMemory:
    def __init__(self, *, run_dir: Path, research_root: Path, run_id: str,
                 case_id: str = "", resolver=None) -> None:
        self.run_id = run_id
        self.case_id = case_id
        self.resolver = resolver
        self.run_store = MemoryStore(Path(run_dir) / "memory.jsonl", "run")
        self.research_root = Path(research_root)
        self.case_store: Optional[MemoryStore] = None
        self.global_store = MemoryStore(self.research_root / "memory" / "global" /
                                        "memory.jsonl", "global")
        if case_id:
            self.case_store = MemoryStore(self.research_root / "memory" / "cases" /
                                          ("%s.jsonl" % _safe(case_id)), "case")

    # -- writing ---------------------------------------------------------
    def add(self, kind: str, content: str, *, tags: Optional[List[str]] = None,
            evidence: Optional[List[str]] = None, scope: str = "run", source: str = "agent",
            refutes: str = "", supersedes: str = "") -> MemoryEntry:
        store = self._store(scope)
        entry = MemoryEntry(id=make_id(store.scope, self.case_id, self.run_id, kind, content),
                            type=kind, content=content.strip(), run_id=self.run_id,
                            case_id=self.case_id, evidence=list(evidence or []),
                            tags=list(tags or []), source=source, scope=store.scope,
                            refutes=refutes, supersedes=supersedes, created_at=now())
        validate_entry(entry, self.resolver if kind == "finding" else None)
        stored = store.append(entry)
        # A case memory always leaves a trail in the run so the transcript stays linear.
        if store.scope != "run":
            self.run_store.append(MemoryEntry(
                id=make_id("run", self.case_id, self.run_id, "attempt",
                           "promoted %s to %s memory: %s" % (entry.id, store.scope, content)),
                type="attempt", content="promoted %s to %s memory: %s"
                % (entry.id, store.scope, content[:200]), run_id=self.run_id,
                case_id=self.case_id, evidence=list(evidence or []), source=source,
                scope="run", created_at=now()))
        return stored

    def refute(self, entry_id: str, reason: str, *, evidence: Optional[List[str]] = None,
               scope: str = "case") -> MemoryEntry:
        """Record that a direction is dead without editing the original entry."""
        return self.add("failed", "refuted %s: %s" % (entry_id, reason),
                        evidence=list(evidence or []), scope=scope, refutes=entry_id)

    def promote(self, entry_id: str, scope: str = "case") -> Optional[MemoryEntry]:
        """Copy a run finding upward so the next run can find it."""
        for item in self.run_store.entries():
            if item.id == entry_id:
                return self.add(item.type, item.content, tags=item.tags,
                                evidence=item.evidence, scope=scope, source=item.source,
                                supersedes=item.id)
        return None

    def _store(self, scope: str) -> MemoryStore:
        if scope == "run":
            return self.run_store
        if scope == "case":
            if self.case_store is None:
                raise MemoryError_("case memory requires a case id")
            return self.case_store
        if scope == "global":
            return self.global_store
        raise MemoryError_("unknown scope %r" % scope)

    # -- reading ---------------------------------------------------------
    def stores(self, scopes: Iterable[str] = ("run", "case", "global")) -> List[MemoryStore]:
        out = []
        for scope in scopes:
            if scope == "run":
                out.append(self.run_store)
            elif scope == "case" and self.case_store is not None:
                out.append(self.case_store)
            elif scope == "global":
                out.append(self.global_store)
        return out

    def entries(self, scopes: Iterable[str] = ("run", "case", "global")) -> List[MemoryEntry]:
        out: List[MemoryEntry] = []
        seen = set()
        for store in self.stores(scopes):
            for item in store.entries():
                if item.id in seen:
                    continue
                seen.add(item.id)
                out.append(item)
        return out

    def search(self, query: str, *, limit: int = 8,
               scopes: Iterable[str] = ("run", "case", "global"),
               types: Optional[Iterable[str]] = None,
               case_id: str = "") -> List[MemoryEntry]:
        words = [w.lower() for w in (query or "").replace("\n", " ").split() if len(w) > 2]
        allowed = set(types) if types else None
        scored = []
        for entry in self.entries(scopes):
            if allowed is not None and entry.type not in allowed:
                continue
            if case_id and entry.case_id and entry.case_id != case_id:
                continue
            haystack = (entry.content + " " + " ".join(entry.tags)).lower()
            score = sum(haystack.count(word) for word in words) if words else 0.0
            if words and not score:
                # Unrelated text is not a match; but a refuted direction is always worth
                # showing, because repeating it is the expensive mistake.
                if entry.status != "refuted":
                    continue
            score += TYPE_WEIGHT.get(entry.type, 0.3) + SCOPE_WEIGHT.get(entry.scope, 1.0)
            if entry.status == "refuted":
                score += 1.5
            if entry.case_id and entry.case_id == self.case_id:
                score += 1.0
            scored.append((score, entry))
        scored.sort(key=lambda pair: -pair[0])
        return [entry for _, entry in scored[:limit]]

    def digest(self, goal: str = "", limit: int = 8, include_global: bool = True) -> str:
        """Bounded recap for the prompt: matches first, then refuted directions, then open."""
        seen, lines = set(), []
        scopes = ("run", "case", "global") if include_global else ("run", "case")
        candidates = self.search(goal, limit=limit, scopes=scopes) if goal else []
        entries = self.entries(scopes)
        candidates += [e for e in entries if e.status == "refuted"][-5:]
        candidates += [e for e in entries if e.type == "open"][-4:]
        candidates += entries[-6:]
        for entry in candidates:
            if entry.id in seen:
                continue
            seen.add(entry.id)
            lines.append(summarise(entry))
            if len(lines) >= limit + 6:
                break
        return "\n".join(lines)

    def refuted_directions(self, case_id: str = "") -> List[MemoryEntry]:
        out = [e for e in self.entries() if e.status == "refuted" or e.type == "failed"]
        if case_id:
            out = [e for e in out if not e.case_id or e.case_id == case_id]
        return out


def _safe(name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in name)[:80] or "case"
