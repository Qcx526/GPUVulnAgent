# -*- coding: utf-8 -*-
"""Adapter discovery.

Adapters are project-owned capabilities over a file format or a toolchain binary. They are
announced to the capability catalog *before* they are imported, so an adapter that cannot
run in this environment is still visible - with its location and the reason. That is the
P18 defect this module answers: the agent never learned the JPEG adapter existed.

Import is lazy and guarded: a broken adapter degrades to a catalog entry, never to a
failed run.
"""

from __future__ import annotations

import importlib
from typing import Dict, List, Tuple

ADAPTERS: Dict[str, dict] = {
    "elf_cubin": {
        "module": "gpuvulnagent.adapters.elf_cubin.tools",
        "purpose": "Read ELF/CUBIN structure and drive cuobjdump/nvdisasm from the "
                   "toolchain manifest.",
        "location": "gpuvulnagent/adapters/elf_cubin/",
        "formats": [".cubin", ".elf", ".o", ".so", ".fatbin", ".bin"],
        "requires": [],
        "tags": ["nvidia", "cuda", "binary"],
    },
    "jpeg": {
        "module": "gpuvulnagent.adapters.jpeg.tools",
        "purpose": "Parse JPEG marker structure, apply one field-level mutation and build "
                   "the paired control.",
        "location": "gpuvulnagent/adapters/jpeg/",
        "formats": [".jpg", ".jpeg"],
        "requires": [],
        "tags": ["image", "parser", "nvjpeg"],
    },
}


def adapter_capabilities() -> List[dict]:
    """Adapter descriptions, usable without importing the adapter."""
    return [{"name": name, **{k: v for k, v in spec.items() if k != "module"}}
            for name, spec in ADAPTERS.items()]


def load_adapter(name: str, **kwargs) -> Tuple[List, str]:
    """Return ``(tool_specs, error)``. Never raises."""
    spec = ADAPTERS.get(name)
    if spec is None:
        return [], "unknown adapter %r" % name
    try:
        module = importlib.import_module(spec["module"])
    except Exception as exc:  # noqa: BLE001 - optional dependency or syntax error
        return [], "%s: %s" % (type(exc).__name__, exc)
    builder = getattr(module, "build_tools", None)
    if builder is None:
        return [], "adapter module exposes no build_tools()"
    try:
        return list(builder(**kwargs)), ""
    except Exception as exc:  # noqa: BLE001
        return [], "adapter failed to build its tools: %s: %s" % (type(exc).__name__, exc)
