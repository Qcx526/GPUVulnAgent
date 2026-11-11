# -*- coding: utf-8 -*-
"""Toolchain manifest: the only place that knows where a binary lives.

Nothing in the runtime hardcodes ``C:\\Program Files\\NVIDIA GPU Computing Toolkit`` or a
drive letter. The manifest records, per tool, its name, version, workspace-relative path,
SHA256, where it came from, its dependencies and whether it was actually executed during
installation. ``toolchain_verify`` re-hashes the files and reports drift.
"""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from ..evidence.hashing import sha256_file

SCHEMA = "gpuvulnagent-toolchain/v1"


@dataclass
class ToolchainEntry:
    name: str
    path: str                      # relative to the toolchain root
    version: str = ""
    kind: str = "binary"           # binary | library | installer | header
    sha256: str = ""
    source: str = ""               # where it was copied from
    depends: List[str] = field(default_factory=list)
    status: str = "unverified"     # verified | present | missing | drifted
    notes: str = ""
    capabilities: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"name": self.name, "path": self.path, "version": self.version,
                "kind": self.kind, "sha256": self.sha256, "source": self.source,
                "depends": list(self.depends), "status": self.status,
                "notes": self.notes, "capabilities": list(self.capabilities)}

    @classmethod
    def from_dict(cls, data: dict) -> "ToolchainEntry":
        return cls(name=data.get("name", ""), path=data.get("path", ""),
                   version=data.get("version", ""), kind=data.get("kind", "binary"),
                   sha256=data.get("sha256", ""), source=data.get("source", ""),
                   depends=list(data.get("depends") or []),
                   status=data.get("status", "unverified"),
                   notes=data.get("notes", ""),
                   capabilities=list(data.get("capabilities") or []))


class ToolchainManifest:
    def __init__(self, root: Path, path: Optional[Path] = None) -> None:
        self.root = Path(root)
        self.path = Path(path) if path else self.root / "manifests" / "toolchain_manifest.json"
        self.entries: Dict[str, ToolchainEntry] = {}
        self.meta: dict = {}
        self.load_error = ""
        self._load()

    def _load(self) -> None:
        if not self.path.is_file():
            self.load_error = "manifest not found: %s" % self.path
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except ValueError as exc:
            self.load_error = "manifest is not valid JSON: %s" % exc
            return
        self.meta = {k: v for k, v in data.items() if k != "tools"}
        for item in data.get("tools") or []:
            entry = ToolchainEntry.from_dict(item)
            self.entries[entry.name] = entry

    # -- lookup ----------------------------------------------------------
    def names(self) -> List[str]:
        return sorted(self.entries)

    def get(self, name: str) -> Optional[ToolchainEntry]:
        return self.entries.get(name)

    def path_of(self, name: str) -> Optional[Path]:
        entry = self.get(name)
        if entry is None:
            return None
        candidate = (self.root / entry.path).resolve()
        return candidate if candidate.is_file() else None

    def describe(self, name: str) -> Optional[dict]:
        entry = self.get(name)
        if entry is None:
            return None
        resolved = self.path_of(name)
        info = entry.to_dict()
        info.update({"absolute_path": str(resolved) if resolved else "",
                     "exists": resolved is not None,
                     "runnable": self.runnable(name)})
        return info

    def runnable(self, name: str) -> bool:
        entry = self.get(name)
        resolved = self.path_of(name)
        if entry is None or resolved is None or entry.kind != "binary":
            return False
        try:
            completed = subprocess.run([str(resolved), "--version"], capture_output=True,
                                       text=True, timeout=20,
                                       env=_env_with_deps(self.root, entry))
        except (OSError, subprocess.SubprocessError):
            return False
        return completed.returncode == 0 or bool(completed.stdout or completed.stderr)

    def env(self) -> dict:
        """Environment for running a manifest binary: its dependency directories first."""
        return {"PATH": os.pathsep.join(
            [str(self.root / "compilers" / "cuda-12.4" / "bin"),
             str(self.root / "cuda" / "cuda-12.4" / "bin"),
             str(self.root / "binary_tools" / "cuda-12.4"),
             os.environ.get("PATH", "")])}

    # -- integrity -------------------------------------------------------
    def verify(self) -> dict:
        results = []
        for name in self.names():
            entry = self.entries[name]
            resolved = self.path_of(name)
            actual = sha256_file(resolved) if resolved else None
            if resolved is None:
                status = "missing"
            elif entry.sha256 and actual != entry.sha256:
                status = "drifted"
            else:
                status = "verified" if entry.sha256 else "present"
            results.append({"name": name, "path": entry.path, "status": status,
                            "expected_sha256": entry.sha256, "actual_sha256": actual})
        ok = all(item["status"] in ("verified", "present") for item in results)
        return {"ok": ok, "manifest": str(self.path), "tools": results,
                "load_error": self.load_error}


def _env_with_deps(root: Path, entry: ToolchainEntry) -> dict:
    env = dict(os.environ)
    deps = [str((root / dep).resolve()) for dep in entry.depends]
    if deps:
        env["PATH"] = os.pathsep.join(deps + [env.get("PATH", "")])
    return env


def write_manifest(root: Path, entries: List[ToolchainEntry], meta: dict,
                   path: Optional[Path] = None) -> Path:
    target = Path(path) if path else Path(root) / "manifests" / "toolchain_manifest.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {"schema": SCHEMA, **meta,
               "tools": [entry.to_dict() for entry in sorted(entries, key=lambda e: e.name)]}
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
    return target
