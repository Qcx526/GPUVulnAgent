# -*- coding: utf-8 -*-
"""Artifact model: one record per produced file, with parents and provenance.

An artifact is not "a file that exists". It is a file *someone produced*, and the record has
to answer: which trial, which tool, which decision, which evidence record, which earlier
artifact it came from. Anything less and a final report cannot be traced back.

Fields that cannot be known are stored as ``UNKNOWN`` rather than guessed. A wrong parent is
worse than a missing one: it makes a provenance claim that is not true.
"""

from __future__ import annotations

import mimetypes
import re
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional

UNKNOWN = "UNKNOWN"
SCHEMA = "gpuvulnagent-artifact/v1"

# extension -> (artifact_type, language)
KINDS = {
    ".cu": ("source", "cuda"), ".cuh": ("header", "cuda"),
    ".c": ("source", "c"), ".h": ("header", "c"),
    ".cpp": ("source", "cpp"), ".cc": ("source", "cpp"), ".hpp": ("header", "cpp"),
    ".py": ("script", "python"), ".sh": ("script", "bash"),
    ".cubin": ("binary", "cubin"), ".ptx": ("binary", "ptx"),
    ".so": ("binary", "elf"), ".elf": ("binary", "elf"), ".o": ("object", "elf"),
    ".jpg": ("input", "jpeg"), ".jpeg": ("input", "jpeg"), ".png": ("input", "png"),
    ".bin": ("input", "binary"), ".raw": ("input", "binary"),
    ".json": ("data", "json"), ".jsonl": ("data", "jsonl"),
    ".md": ("document", "markdown"), ".txt": ("log", "text"),
    ".log": ("log", "text"), ".pdb": ("dump", "pdb"), ".dmp": ("dump", "minidump"),
}

ORIGINS = ("generated", "copied", "downloaded", "modified", "compiled", UNKNOWN)
STATUSES = ("active", "superseded", "missing")

ELF_MAGIC = b"\x7fELF"


def classify(path: Path, head: bytes = b"") -> tuple:
    """(artifact_type, language) from the extension, then from magic as a fallback."""
    suffix = path.suffix.lower()
    if suffix in KINDS:
        return KINDS[suffix]
    if head.startswith(ELF_MAGIC):
        return "binary", "elf"
    return "file", UNKNOWN


def media_type(path: Path) -> str:
    guessed, _ = mimetypes.guess_type(str(path))
    return guessed or "application/octet-stream"


def normalise_language(value: str) -> str:
    return (value or UNKNOWN).lower()


@dataclass
class Artifact:
    artifact_id: str
    trial_id: str
    artifact_type: str
    relative_path: str
    filename: str
    sha256: str
    size: int
    media_type: str = "application/octet-stream"
    language: str = UNKNOWN
    origin: str = UNKNOWN
    parent_artifact_ids: List[str] = field(default_factory=list)
    producer_tool: str = UNKNOWN
    producer_evidence_id: str = UNKNOWN
    producer_turn: int = -1
    execution_id: str = ""
    created_at: str = ""
    version: int = 1
    status: str = "active"
    intent: str = ""
    schema: str = SCHEMA

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["parent_artifact_ids"] = list(self.parent_artifact_ids)
        return payload

    @classmethod
    def from_dict(cls, data: dict) -> "Artifact":
        known = {key: value for key, value in data.items()
                 if key in cls.__dataclass_fields__}
        return cls(**known)

    def summary_line(self) -> str:
        return ("%s %-8s v%d %-40s %s %d B %s"
                % (self.artifact_id, self.artifact_type, self.version,
                   self.relative_path, self.sha256[:12], self.size, self.origin))


def make_id(trial_id: str, relative_path: str, sha256: str) -> str:
    """Stable for the same (trial, path, content); different when content changes."""
    import hashlib
    digest = hashlib.sha256(("%s|%s|%s" % (trial_id, relative_path, sha256))
                            .encode("utf-8")).hexdigest()
    return "art-" + digest[:12]


def versioned_name(path: Path, version: int) -> Path:
    """``poc.cu`` -> ``poc_v002.cu``; keeps the extension so tools still recognise it."""
    stem = re.sub(r"_v\d{3}$", "", path.stem)
    return path.with_name("%s_v%03d%s" % (stem, version, path.suffix))


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")
