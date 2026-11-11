# -*- coding: utf-8 -*-
"""Hashing helpers shared by evidence, artifacts and toolchain manifests."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Optional

GENESIS = "0" * 64
CHUNK = 1024 * 1024


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(path: Path) -> Optional[str]:
    """Stream a file so multi-hundred-megabyte binaries do not have to fit in memory."""
    path = Path(path)
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(CHUNK)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()
