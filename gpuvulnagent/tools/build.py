# -*- coding: utf-8 -*-
"""Assemble a registry and a capability catalog for one run.

Order is fixed and additive: builtins first, then adapters, then optional providers. A
name clash is recorded and skipped rather than resolved by import order. Everything that
exists but cannot run is still indexed in the catalog - that is the difference between
"this project has no JPEG tool" and "this project has a JPEG tool that needs Pillow".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from ..adapters import adapter_capabilities, load_adapter
from ..discovery.catalog import CapabilityCatalog
from ..discovery.manifest import ToolchainManifest
from ..providers import tavily as tavily_provider
from ..registry.registry import ToolRegistry
from .builtin import build_builtin_tools


@dataclass
class Assembly:
    registry: ToolRegistry
    catalog: CapabilityCatalog
    manifest: Optional[ToolchainManifest]
    providers: List[dict] = field(default_factory=list)
    conflicts: List[dict] = field(default_factory=list)
    adapter_errors: dict = field(default_factory=dict)

    def describe(self) -> dict:
        return {"tools": self.registry.names(), "conflicts": self.conflicts,
                "providers": self.providers, "adapter_errors": self.adapter_errors,
                "catalog": self.catalog.summary()}


def build_assembly(*, workspace, runner, log, memory, toolchain_root: Optional[Path] = None,
                   manifest_path: Optional[Path] = None, tavily_api_key: str = "",
                   enable_search: bool = True,
                   include_adapters: bool = True) -> Assembly:
    manifest = _load_manifest(toolchain_root, manifest_path)
    # The catalog exists before the tools so tool_search can close over it; it is populated
    # after registration, which is safe because the tools hold the object, not a snapshot.
    catalog = CapabilityCatalog(manifest=manifest)
    registry = ToolRegistry()
    registry.register_many(build_builtin_tools(workspace=workspace, runner=runner, log=log,
                                               memory=memory, catalog=catalog,
                                               manifest=manifest))

    providers: List[dict] = []
    adapter_errors: dict = {}
    unavailable: List[dict] = []

    if include_adapters:
        for item in adapter_capabilities():
            specs, error = load_adapter(item["name"], workspace=workspace, runner=runner,
                                        log=log, manifest=manifest)
            if error:
                adapter_errors[item["name"]] = error
                unavailable.append({"name": item["name"], "kind": "adapter",
                                    "purpose": item["purpose"], "location": item["location"],
                                    "requires": item["requires"], "formats": item["formats"],
                                    "usage": item["purpose"], "tags": item["tags"],
                                    "reason": error})
                continue
            registry.extend(specs)

    if enable_search:
        state = tavily_provider.status(tavily_api_key)
        providers.append(state)
        if state["available"]:
            registry.extend(tavily_provider.build_specs(api_key=tavily_api_key, log=log))
    else:
        providers.append({"provider": "tavily", "sdk_installed": None, "key_present": None,
                          "available": False, "reason": "search disabled for this run"})

    catalog.registry = registry
    if manifest is not None:
        catalog.add_manifest(manifest)
    catalog.add_registry(registry)
    for item in unavailable:
        catalog.add_unavailable(**item)

    return Assembly(registry=registry, catalog=catalog, manifest=manifest,
                    providers=providers, conflicts=list(registry.conflicts),
                    adapter_errors=adapter_errors)


def _load_manifest(toolchain_root: Optional[Path],
                   manifest_path: Optional[Path]) -> Optional[ToolchainManifest]:
    if toolchain_root is None and manifest_path is None:
        return None
    if manifest_path is not None:
        path = Path(manifest_path)
        root = path.parents[1] if len(path.parents) > 1 else path.parent
        return ToolchainManifest(root, path)
    return ToolchainManifest(Path(toolchain_root))
