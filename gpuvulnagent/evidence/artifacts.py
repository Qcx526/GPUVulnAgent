# -*- coding: utf-8 -*-
"""Content-addressed artifact store.

The prompt only ever sees a preview plus a reference; the bytes stay here with their own
hash. Two runs writing the same bytes produce the same file name, which is a feature:
identical evidence collides instead of duplicating.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from .hashing import sha256_bytes

CATEGORIES = ("stdout", "stderr", "http", "files", "tools", "process")


class ArtifactStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root).resolve()
        for category in CATEGORIES:
            (self.root / category).mkdir(parents=True, exist_ok=True)

    def save(self, category: str, name: str, payload) -> dict:
        category = category if category in CATEGORIES else "files"
        data = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
        digest = sha256_bytes(data)
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:80] or "blob"
        relative = "%s/%s-%s" % (category, digest[:12], safe)
        path = self.root / relative
        if not path.is_file():
            path.write_bytes(data)
        return {"artifact": relative, "sha256": digest, "bytes": len(data)}

    def resolve(self, relative: str) -> Path:
        """Refuse any reference that escapes the store."""
        candidate = (self.root / relative).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise PermissionError("artifact path escapes the store: %s" % relative)
        return candidate

    def read(self, relative: str) -> Optional[bytes]:
        path = self.resolve(relative)
        return path.read_bytes() if path.is_file() else None

    def exists(self, relative: str) -> bool:
        try:
            return self.resolve(relative).is_file()
        except PermissionError:
            return False
