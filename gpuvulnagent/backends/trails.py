# -*- coding: utf-8 -*-
"""Trails: one directory per experiment, human-readable names, SHA256 for identity.

A run is a sequence of attempts, and every attempt needs its own place to keep inputs,
outputs and logs. ``trail0``, ``trail1``, ... are allocated inside the run and never
reused: re-running an experiment creates the next trail instead of overwriting the last
evidence.

Names carry meaning (``poc.cu``, ``stdout.txt``, ``candidate.cubin``); hashes carry
identity. Hashes are recorded in the manifest, not used as file names, because a directory
called ``a3f9c1`` tells a human nothing about what the experiment did.

Allocation is ``mkdir`` in a loop, which is atomic on both NTFS and Linux, so two
concurrent callers can never receive the same trail.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ..evidence.hashing import sha256_bytes

SCHEMA = "gpuvulnagent-trail/v1"
TRAIL_PATTERN = re.compile(r"^trail(\d+)$")


class TrailError(RuntimeError):
    """A trail operation that would lose or misrepresent evidence."""


@dataclass
class TrailFile:
    name: str
    sha256: str
    bytes: int
    kind: str = "input"           # input | output | log | manifest
    source: str = "agent"
    added_at: str = ""
    relation: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "sha256": self.sha256, "bytes": self.bytes,
                "kind": self.kind, "source": self.source, "added_at": self.added_at,
                "relation": self.relation}


@dataclass
class Trail:
    root: Path
    run_id: str
    trail_id: str
    purpose: str = ""
    parent_trail: str = ""
    created_at: str = ""
    files: List[TrailFile] = field(default_factory=list)
    executions: List[dict] = field(default_factory=list)

    # -- paths -----------------------------------------------------------
    @property
    def inputs(self) -> Path:
        return self.root / "inputs"

    @property
    def outputs(self) -> Path:
        return self.root / "outputs"

    @property
    def logs(self) -> Path:
        return self.root / "logs"

    @property
    def manifest_path(self) -> Path:
        return self.root / "manifest.json"

    def relative(self) -> str:
        """Project-independent identity: ``<run_id>/trail0``."""
        return "%s/%s" % (self.run_id, self.trail_id)

    # -- writing ---------------------------------------------------------
    def add_file(self, name: str, data, *, kind: str = "input", source: str = "agent",
                 relation: str = "") -> TrailFile:
        relative = _in_section(name, kind)
        target = self.root / relative
        if target.exists():
            raise TrailError("trail %s already holds %r; trails are append-only"
                             % (self.trail_id, relative))
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        target.write_bytes(payload)
        record = TrailFile(name=relative, sha256=sha256_bytes(payload), bytes=len(payload),
                           kind=kind, source=source, added_at=_now(), relation=relation)
        self.files.append(record)
        self.save()
        return record

    def register_file(self, relative: str, *, kind: str = "output",
                      source: str = "backend", relation: str = "") -> TrailFile:
        """Record a file that was written by something else (worker, container)."""
        path = self.root / _safe_relative(relative)
        if not path.is_file():
            raise TrailError("cannot register %r: file is missing" % relative)
        payload = path.read_bytes()
        record = TrailFile(name=str(Path(relative)).replace("\\", "/"),
                           sha256=sha256_bytes(payload), bytes=len(payload), kind=kind,
                           source=source, added_at=_now(), relation=relation)
        self.files = [item for item in self.files if item.name != record.name] + [record]
        self.save()
        return record

    def record_execution(self, entry: dict) -> dict:
        entry = dict(entry)
        entry.setdefault("index", len(self.executions))
        entry.setdefault("recorded_at", _now())
        self.executions.append(entry)
        self.save()
        return entry

    def save(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        payload = {"schema": SCHEMA, "run_id": self.run_id, "trail": self.trail_id,
                   "purpose": self.purpose, "parent_trail": self.parent_trail,
                   "created_at": self.created_at, "updated_at": _now(),
                   "files": [item.to_dict() for item in self.files],
                   "executions": self.executions}
        self.manifest_path.write_text(json.dumps(payload, ensure_ascii=False, indent=1),
                                      encoding="utf-8")

    # -- reading ---------------------------------------------------------
    def list_files(self) -> List[dict]:
        return [item.to_dict() for item in self.files]

    def read_file(self, name: str, *, offset: int = 0, limit: int = 8000) -> dict:
        relative = _safe_relative(name)
        path = self.root / relative
        if not path.is_file():
            # Accept a bare name: search inputs, then each execution (newest first).
            candidates = [self.root / "inputs" / relative]
            execs = sorted((self.root / "execs").glob("exec[0-9][0-9]"), reverse=True) \
                if (self.root / "execs").is_dir() else []
            for exec_dir in execs:
                candidates.append(exec_dir / "outputs" / relative)
                candidates.append(exec_dir / "logs" / relative)
            candidates += [self.root / "outputs" / relative, self.root / "logs" / relative]
            for candidate in candidates:
                if candidate.is_file():
                    path = candidate
                    relative = candidate.relative_to(self.root).as_posix()
                    break
        if not path.is_file():
            raise TrailError("trail %s has no file %r" % (self.trail_id, relative))
        data = path.read_bytes()
        start = max(0, int(offset))
        chunk = data[start:start + max(1, min(int(limit), 262144))]
        text = chunk.decode("utf-8", errors="replace")
        end = start + len(chunk)
        return {"trail": self.trail_id, "name": relative, "total_bytes": len(data),
                "offset": start, "read_bytes": len(chunk), "next_offset": end,
                "has_more": end < len(data), "sha256": sha256_bytes(data),
                "text": text}

    def exec_dir(self, index: int) -> Path:
        """Directory of one execution; created on demand, never shared between indices."""
        path = self.root / "execs" / ("exec%02d" % int(index))
        path.mkdir(parents=True, exist_ok=True)
        return path

    def exec_dirs(self) -> List[Path]:
        root = self.root / "execs"
        if not root.is_dir():
            return []
        return sorted(path for path in root.iterdir()
                      if path.is_dir() and path.name.startswith("exec"))

    def manifest(self) -> dict:
        if not self.manifest_path.is_file():
            return {}
        return json.loads(self.manifest_path.read_text(encoding="utf-8"))


class TrailStore:
    """Allocates trails inside one run directory and never reuses a number."""

    def __init__(self, root: Path, run_id: str) -> None:
        self.root = Path(root).resolve()
        self.run_id = run_id
        self.root.mkdir(parents=True, exist_ok=True)

    def allocate(self, purpose: str = "", parent_trail: str = "") -> Trail:
        index = self._next_index()
        while True:
            candidate = self.root / ("trail%d" % index)
            try:
                # Atomic on NTFS and ext4: exactly one caller can win this name.
                candidate.mkdir(parents=True, exist_ok=False)
            except FileExistsError:
                index += 1
                continue
            (candidate / "inputs").mkdir()
            (candidate / "outputs").mkdir()
            (candidate / "logs").mkdir()
            trail = Trail(root=candidate, run_id=self.run_id,
                          trail_id="trail%d" % index, purpose=purpose,
                          parent_trail=parent_trail, created_at=_now())
            trail.save()
            return trail

    def open(self, trail_id: str) -> Trail:
        if not TRAIL_PATTERN.match(trail_id or ""):
            raise TrailError("invalid trail id %r" % trail_id)
        root = self.root / trail_id
        if not root.is_dir():
            raise TrailError("no trail %r in %s" % (trail_id, self.root))
        data = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
        trail = Trail(root=root, run_id=data.get("run_id", self.run_id), trail_id=trail_id,
                      purpose=data.get("purpose", ""),
                      parent_trail=data.get("parent_trail", ""),
                      created_at=data.get("created_at", ""),
                      executions=data.get("executions", []))
        trail.files = [TrailFile(**item) for item in data.get("files", [])]
        return trail

    def get_or_allocate(self, trail_id: str = "", *, purpose: str = "",
                        parent_trail: str = "") -> Trail:
        if trail_id:
            return self.open(trail_id)
        return self.allocate(purpose=purpose, parent_trail=parent_trail)

    def list_trails(self) -> List[dict]:
        out = []
        for path in sorted(self.root.iterdir()):
            match = TRAIL_PATTERN.match(path.name)
            if not (match and path.is_dir()):
                continue
            manifest = path / "manifest.json"
            data = json.loads(manifest.read_text(encoding="utf-8")) if manifest.is_file() else {}
            out.append({"trail": path.name, "purpose": data.get("purpose", ""),
                        "parent_trail": data.get("parent_trail", ""),
                        "files": len(data.get("files", [])),
                        "executions": len(data.get("executions", [])),
                        "created_at": data.get("created_at", "")})
        out.sort(key=lambda item: int(TRAIL_PATTERN.match(item["trail"]).group(1)))
        return out

    def _next_index(self) -> int:
        highest = -1
        for path in self.root.iterdir():
            match = TRAIL_PATTERN.match(path.name)
            if match:
                highest = max(highest, int(match.group(1)))
        return highest + 1


def _safe_relative(name: str) -> str:
    """Reject absolute paths, traversal and separators that would escape the trail."""
    if not isinstance(name, str) or not name.strip():
        raise TrailError("a trail file needs a name")
    normalised = name.replace("\\", "/").strip()
    if normalised.startswith("/") or re.match(r"^[A-Za-z]:", normalised):
        raise TrailError("trail file names are relative: %r" % name)
    parts = [part for part in normalised.split("/") if part not in ("", ".")]
    if any(part == ".." for part in parts):
        raise TrailError("trail file names cannot traverse upward: %r" % name)
    if not parts:
        raise TrailError("trail file names cannot be empty: %r" % name)
    return "/".join(parts)


def _in_section(name: str, kind: str) -> str:
    """Place inputs under ``inputs/`` and outputs under ``outputs/``, exactly once.

    Paths that already name a section (``inputs/``, ``outputs/``, ``logs/`` or
    ``execs/execNN/...``) are kept as they are: an execution's artifacts live inside its
    own execution directory and must not be re-prefixed.
    """
    section = {"input": "inputs", "output": "outputs", "log": "logs"}.get(kind, "")
    relative = _safe_relative(name)
    if not section:
        return relative
    for existing in ("inputs/", "outputs/", "logs/", "execs/"):
        if relative.startswith(existing):
            return relative
    return section + "/" + relative


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def trail_root_for(run_dir: Path) -> Path:
    return Path(run_dir) / "trails"


def new_trail_dir(run_dir: Path) -> Path:
    """Kept for callers that only need a directory, not a manifest."""
    return TrailStore(trail_root_for(run_dir), Path(run_dir).name).allocate().root
