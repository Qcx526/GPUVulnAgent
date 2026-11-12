# -*- coding: utf-8 -*-
"""Stage an existing file into a trail without putting its bytes through the model.

The gap this closes: a 700 KB ``cuobjdump`` cannot be written through ``trail_write`` - the
model would have to emit a megabyte of base64 - and ``shell`` on Windows mangles quoting. The
agent could therefore prepare a PoC but never get the tools and the binary into the container.

``trail_stage`` takes a *reference*, not content: a whitelisted root plus a relative path. The
bytes travel from disk to disk, and the model only ever sees a hash and a size.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional, Tuple

MAX_BYTES = 64 * 1024 * 1024
ROOTS = ("toolchains", "research_archive")


class StageError(RuntimeError):
    """A staging request that is unsafe, ambiguous or unverifiable."""


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _relative(spec_path: str) -> str:
    cleaned = (spec_path or "").strip().replace("\\", "/")
    if not cleaned:
        raise StageError("a relative source path is required")
    parts = cleaned.split("/")
    if cleaned.startswith("/") or ".." in parts or "" in parts:
        raise StageError("path traversal is not allowed: %r" % spec_path)
    return cleaned


def _check_regular(path: Path) -> None:
    if path.is_symlink():
        raise StageError("source is a symlink: %s" % path)
    if not path.exists():
        raise StageError("source does not exist: %s" % path)
    if not path.is_file():
        raise StageError("source is not a regular file: %s" % path)


def resolve_source(spec: str, *, repo_root: Path, wsl_root: Optional[Path]) -> Tuple[Path, str]:
    """``wsl-ref:dir/file`` or ``repo:toolchains/...`` -> (path, human origin)."""
    spec = (spec or "").strip()
    if spec.startswith("wsl-ref:"):
        if wsl_root is None:
            raise StageError("this environment has no wsl refs root")
        relative = _relative(spec.split(":", 1)[1])
        path = Path(wsl_root) / relative
        return path, "wsl-ref:%s" % relative
    if spec.startswith("repo:"):
        relative = _relative(spec.split(":", 1)[1])
        top = relative.split("/")[0]
        if top not in ROOTS:
            raise StageError("repo sources are limited to %s" % ", ".join(ROOTS))
        path = Path(repo_root) / relative
        resolved = path.resolve()
        root = (Path(repo_root) / top).resolve()
        if not str(resolved).startswith(str(root)):
            raise StageError("resolved path escapes %s" % top)
        return path, "repo:%s" % relative
    raise StageError("source must start with wsl-ref: or repo:")


def stage_copy(source: Path, destination: Path) -> dict:
    """Copy with an atomic rename and a before/after hash; refuse if the source moved."""
    _check_regular(source)
    before = _sha(source)
    size = source.stat().st_size
    if size > MAX_BYTES:
        raise StageError("source is larger than the %d byte limit" % MAX_BYTES)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        existing = _sha(destination)
        if existing == before:
            return {"sha256": before, "bytes": size, "written": False}
        raise StageError("destination %s already holds different bytes (%s)"
                         % (destination.name, existing[:12]))
    handle, temp = tempfile.mkstemp(prefix=".stage-", dir=str(destination.parent))
    os.close(handle)
    temp_path = Path(temp)
    try:
        shutil.copy2(source, temp_path)
        if _sha(temp_path) != before:
            raise StageError("copy does not match the source hash")
        if _sha(source) != before:
            raise StageError("source changed while it was being copied")
        os.replace(temp_path, destination)
    finally:
        if temp_path.exists():
            temp_path.unlink()
    return {"sha256": before, "bytes": size, "written": True}
