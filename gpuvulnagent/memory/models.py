# -*- coding: utf-8 -*-
"""Memory entries and the rules that keep them honest.

Five types, and the difference between them is enforced rather than suggested:

``finding``     a claim the tools actually established; must cite evidence that resolves
``hypothesis``  a claim the model believes but has not established
``attempt``     something that was tried and what came back
``failed``      something that did not work, or a direction now known to be wrong
``open``        a question still unanswered

Only ``finding`` may be read as fact. A model opinion stays a ``hypothesis`` until
evidence is attached, and nothing here can be edited in place - a correction is a new
entry that points at the old one.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

TYPES = ("attempt", "finding", "hypothesis", "failed", "open")
SCOPES = ("run", "case", "global")
SOURCE_KINDS = ("agent", "operator", "import")


class MemoryError_(ValueError):
    """An entry would misrepresent what is known."""


@dataclass
class MemoryEntry:
    id: str
    type: str
    content: str
    run_id: str = ""
    case_id: str = ""
    evidence: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    source: str = "agent"
    scope: str = "run"
    status: str = "active"
    refutes: str = ""
    supersedes: str = ""
    created_at: str = ""

    def to_dict(self) -> dict:
        return {"schema": "gpuvulnagent-memory/v1", "id": self.id, "type": self.type,
                "content": self.content, "run_id": self.run_id, "case_id": self.case_id,
                "evidence": list(self.evidence), "tags": list(self.tags),
                "source": self.source, "scope": self.scope, "status": self.status,
                "refutes": self.refutes, "supersedes": self.supersedes,
                "created_at": self.created_at}

    @classmethod
    def from_dict(cls, data: Dict) -> "MemoryEntry":
        return cls(id=data.get("id", ""), type=data.get("type", ""),
                   content=data.get("content", ""), run_id=data.get("run_id", ""),
                   case_id=data.get("case_id", ""), evidence=list(data.get("evidence") or []),
                   tags=list(data.get("tags") or []), source=data.get("source", "agent"),
                   scope=data.get("scope", "run"), status=data.get("status", "active"),
                   refutes=data.get("refutes", ""), supersedes=data.get("supersedes", ""),
                   created_at=data.get("created_at", ""))


def make_id(scope: str, case_id: str, run_id: str, kind: str, content: str) -> str:
    """Stable across retries: the same claim from the same run gets the same id."""
    normalised = " ".join((content or "").split()).lower()
    material = "|".join([scope, case_id or "", run_id or "", kind, normalised])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def validate_entry(entry: MemoryEntry, resolver=None) -> None:
    if entry.type not in TYPES:
        raise MemoryError_("unknown memory type %r (allowed: %s)"
                           % (entry.type, ", ".join(TYPES)))
    if entry.scope not in SCOPES:
        raise MemoryError_("unknown scope %r (allowed: %s)" % (entry.scope, ", ".join(SCOPES)))
    if not (entry.content or "").strip():
        raise MemoryError_("memory content must not be empty")
    if entry.type == "finding":
        if not entry.evidence:
            raise MemoryError_("a finding must cite evidence ids; "
                               "use 'hypothesis' if nothing was established")
        if resolver is not None:
            unresolved = [ref for ref in entry.evidence if resolver.resolve(ref) is None]
            if unresolved:
                raise MemoryError_("a finding must cite evidence that exists; "
                                   "unresolved: %s" % ", ".join(unresolved))


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def summarise(entry: MemoryEntry, limit: int = 200) -> str:
    suffix = ""
    if entry.status == "refuted":
        suffix += " (REFUTED)"
    if entry.refutes:
        suffix += " (REFUTES %s)" % entry.refutes
    if entry.case_id:
        suffix += " {%s}" % entry.case_id
    text = (entry.content or "").replace("\n", " ")
    return "- [%s]%s %s" % (entry.type, suffix, text[:limit])


def optional(value: Optional[str]) -> str:
    return value or ""
