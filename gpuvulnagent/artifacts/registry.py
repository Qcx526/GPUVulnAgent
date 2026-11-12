# -*- coding: utf-8 -*-
"""Artifact registry: append-only, versioned, never overwriting.

Two rules drive everything here:

1. **A path is a name, not an identity.** Writing new bytes to an existing name produces a
   new version (``poc_v002.cu``) and a new artifact; the old one stays where it is.
2. **A record is appended, never edited.** The JSONL file is the audit log; the JSON index
   is a materialised view that can always be rebuilt from it.

The registry can answer the questions a report needs: who produced this file, from what
parent, with which tool, in which execution, and under which evidence record.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from ..evidence.hashing import sha256_file
from .model import (UNKNOWN, Artifact, classify, make_id, media_type, normalise_language,
                    now, versioned_name)


class ArtifactError(RuntimeError):
    """A registration that would lose or misrepresent a produced file."""


class ArtifactRegistry:
    def __init__(self, trial_root: Path, trial_id: str) -> None:
        self.root = Path(trial_root).resolve()
        self.trial_id = trial_id
        self.evidence_dir = self.root / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.journal = self.evidence_dir / "artifact_index.jsonl"
        self.index_path = self.evidence_dir / "artifact_index.json"
        self._items: Dict[str, Artifact] = {}
        self._load()

    # -- persistence -----------------------------------------------------
    def _load(self) -> None:
        if not self.journal.is_file():
            return
        for line in self.journal.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                item = Artifact.from_dict(json.loads(line))
            except (ValueError, TypeError):
                continue
            self._items[item.artifact_id] = item

    def _append(self, item: Artifact) -> None:
        self.journal.parent.mkdir(parents=True, exist_ok=True)
        with self.journal.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(item.to_dict(), ensure_ascii=False) + "\n")
        self._items[item.artifact_id] = item
        self.refresh_index()

    def refresh_index(self) -> dict:
        payload = {"schema": "gpuvulnagent-artifact-index/v1", "trial_id": self.trial_id,
                   "generated_at": now(),
                   "counts": self._counts(),
                   "artifacts": [item.to_dict() for item in
                                 sorted(self._items.values(), key=lambda a: a.created_at)]}
        self.index_path.write_text(json.dumps(payload, ensure_ascii=False, indent=1),
                                   encoding="utf-8")
        return payload

    def _counts(self) -> dict:
        counts: Dict[str, int] = {}
        for item in self._items.values():
            counts[item.artifact_type] = counts.get(item.artifact_type, 0) + 1
        return counts

    # -- registration ----------------------------------------------------
    def register(self, path: Path, *, origin: str = "generated",
                 artifact_type: str = "", language: str = "",
                 producer_tool: str = UNKNOWN, evidence_id: str = UNKNOWN,
                 turn: int = -1, execution_id: str = "", parents: Iterable[str] = (),
                 intent: str = "", dedupe: bool = True) -> Artifact:
        path = Path(path)
        if not path.is_file():
            raise ArtifactError("cannot register a missing file: %s" % path)
        resolved = path.resolve()
        if not str(resolved).startswith(str(self.root) + "\\") and \
                not str(resolved).startswith(str(self.root) + "/"):
            raise ArtifactError("artifact is outside the trial: %s" % resolved)

        digest = sha256_file(resolved)
        relative = resolved.relative_to(self.root).as_posix()
        if dedupe:
            for item in self._items.values():
                if item.relative_path == relative and item.sha256 == digest:
                    return item

        kind, guessed_language = classify(resolved, resolved.read_bytes()[:64])
        parents = list(parents) or self._infer_parents(relative, artifact_type or kind)
        version = 1 + max([item.version for item in self._items.values()
                           if item.relative_path == relative], default=0)
        item = Artifact(
            artifact_id=make_id(self.trial_id, relative, digest), trial_id=self.trial_id,
            artifact_type=artifact_type or kind,
            relative_path=relative, filename=resolved.name, sha256=digest,
            size=resolved.stat().st_size, media_type=media_type(resolved),
            language=normalise_language(language or guessed_language),
            origin=origin, parent_artifact_ids=parents, producer_tool=producer_tool,
            producer_evidence_id=evidence_id, producer_turn=turn,
            execution_id=execution_id, created_at=now(), version=version,
            status="active", intent=intent)
        self._append(item)
        return item

    def register_bytes(self, name: str, payload: bytes, *, section: str = "poc/generated",
                       origin: str = "generated", **kwargs) -> Artifact:
        """Write bytes into a section, versioning the name if it already exists."""
        target = self.root / section / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.read_bytes() != payload:
            target = versioned_name(target, max(
                [item.version for item in self._items.values()
                 if item.relative_path.startswith(section + "/")], default=0) + 1)
        target.write_bytes(payload)
        return self.register(target, origin=origin, **kwargs)

    def register_text(self, name: str, text: str, *, section: str = "poc/generated",
                      language: str = "", **kwargs) -> Artifact:
        return self.register_bytes(name, text.encode("utf-8"), section=section,
                                   language=language, **kwargs)

    def version_of(self, name: str) -> Artifact:
        """Write a new version of a logical name, never touching the earlier file."""
        candidates = [item for item in self._items.values()
                      if Path(item.relative_path).name == Path(name).name]
        if not candidates:
            raise ArtifactError("no earlier artifact named %r" % name)
        latest = max(candidates, key=lambda item: item.version)
        return latest

    def _infer_parents(self, relative: str, kind: str) -> List[str]:
        """A binary produced next to a source is linked to it, but never guessed further."""
        if kind not in ("binary", "object"):
            return []
        stem = Path(relative).stem.split("_v")[0]
        parents = []
        for item in self._items.values():
            if item.artifact_type in ("source", "script") and \
                    Path(item.relative_path).stem.split("_v")[0] == stem:
                parents.append(item.artifact_id)
        return parents[-3:]

    # -- queries ---------------------------------------------------------
    def get(self, artifact_id: str) -> Optional[Artifact]:
        return self._items.get(artifact_id)

    def all(self) -> List[Artifact]:
        return sorted(self._items.values(), key=lambda item: (item.created_at, item.version))

    def find(self, *, artifact_type: str = "", name: str = "", sha256: str = "") -> List[Artifact]:
        out = []
        for item in self.all():
            if artifact_type and item.artifact_type != artifact_type:
                continue
            if name and name not in item.filename:
                continue
            if sha256 and not item.sha256.startswith(sha256):
                continue
            out.append(item)
        return out

    def children(self, artifact_id: str) -> List[Artifact]:
        return [item for item in self.all() if artifact_id in item.parent_artifact_ids]

    def history(self, artifact_id: str) -> List[Artifact]:
        """Ancestors first, oldest to newest, including the artifact itself."""
        chain, seen, cursor = [], set(), [artifact_id]
        while cursor:
            current = cursor.pop(0)
            if current in seen:
                continue
            seen.add(current)
            item = self._items.get(current)
            if item is None:
                continue
            chain.append(item)
            cursor.extend(item.parent_artifact_ids)
        return sorted(chain, key=lambda item: (item.created_at, item.version))

    def for_execution(self, execution_id: str) -> List[Artifact]:
        return [item for item in self.all() if item.execution_id == execution_id]

    # -- integrity -------------------------------------------------------
    def verify(self) -> dict:
        missing, changed, ok = [], [], 0
        for item in self.all():
            path = self.root / item.relative_path
            if not path.is_file():
                missing.append(item.relative_path)
                continue
            if sha256_file(path) != item.sha256:
                changed.append(item.relative_path)
                continue
            ok += 1
        return {"ok": not missing and not changed, "checked": ok,
                "missing": missing, "changed": changed,
                "counts": self._counts(), "index": str(self.index_path)}

    def summary(self) -> dict:
        return {"trial_id": self.trial_id, "root": str(self.root),
                "artifacts": len(self._items), "counts": self._counts(),
                "index": str(self.index_path), "journal": str(self.journal)}
