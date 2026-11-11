# -*- coding: utf-8 -*-
"""Run workspace: the one directory the agent may write to.

Path containment is not a formality. An agent that can rewrite the project source can
also destroy the evidence of what it did, so writes are refused outside the run workspace
and the refusal is returned rather than silently retried.

The project tree is readable (the agent must be able to read its own tools) but never
writable through these helpers; anything it creates goes here.
"""

from __future__ import annotations

from pathlib import Path


class WorkspaceError(PermissionError):
    """A path left the run workspace."""


class Workspace:
    def __init__(self, root: Path) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def resolve(self, relative: str) -> Path:
        raw = Path(relative)
        candidate = (raw if raw.is_absolute() else self.root / raw).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise WorkspaceError("path escapes the run workspace: %s" % relative)
        return candidate

    def write(self, relative: str, content) -> dict:
        path = self.resolve(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = content.encode("utf-8") if isinstance(content, str) else bytes(content)
        path.write_bytes(data)
        return {"path": str(path.relative_to(self.root)).replace("\\", "/"),
                "bytes": len(data)}

    def read(self, relative: str, limit: int = 20000) -> dict:
        path = self.resolve(relative)
        if not path.is_file():
            raise FileNotFoundError("no such file in workspace: %s" % relative)
        text = path.read_text(encoding="utf-8", errors="replace")
        return {"path": str(path.relative_to(self.root)).replace("\\", "/"),
                "bytes": len(text.encode("utf-8")), "truncated": len(text) > limit,
                "content": text[:limit]}

    def listdir(self, relative: str = ".") -> dict:
        path = self.resolve(relative)
        if not path.is_dir():
            raise NotADirectoryError("not a directory: %s" % relative)
        entries = []
        for child in sorted(path.iterdir()):
            try:
                size = child.stat().st_size if child.is_file() else None
            except OSError:
                size = None
            entries.append({"name": child.name, "dir": child.is_dir(), "bytes": size})
        return {"path": str(path.relative_to(self.root)).replace("\\", "/") or ".",
                "entries": entries[:200], "truncated": len(entries) > 200}

    def free_bytes(self) -> int:
        import shutil
        return shutil.disk_usage(self.root).free
