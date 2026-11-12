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
    backend: Optional[object] = None
    backend_status: dict = field(default_factory=dict)

    def describe(self) -> dict:
        return {"tools": self.registry.names(), "conflicts": self.conflicts,
                "providers": self.providers, "adapter_errors": self.adapter_errors,
                "backend": self.backend_status,
                "catalog": self.catalog.summary()}


def build_assembly(*, workspace, runner, log, memory, toolchain_root: Optional[Path] = None,
                   manifest_path: Optional[Path] = None, tavily_api_key: str = "",
                   enable_search: bool = True, include_adapters: bool = True,
                   enable_gpu_backend: bool = True,
                   backend_config=None) -> Assembly:
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

    # The Linux GPU backend. Registered even when WSL is absent: the tools then answer
    # "backend unavailable" with the reason, which is a finding the agent can use, instead
    # of the capability silently not existing.
    backend = None
    backend_status: dict = {"enabled": bool(enable_gpu_backend)}
    if enable_gpu_backend:
        try:
            from ..backends.wsl_docker import WslConfig, WslDockerBackend
            from .gpu import build_gpu_tools

            backend = WslDockerBackend(backend_config or WslConfig())
            specs = build_gpu_tools(backend=backend,
                                    trail_root=Path(log.path).parent / "trails",
                                    run_id=getattr(log, "run_id", ""), log=log,
                                    workspace=workspace)
            registry.extend(specs)
            backend_status.update({"registered": True, "tools": [spec.name for spec in specs],
                                   "config": backend.describe()})
        except Exception as exc:  # noqa: BLE001 - a missing backend must not break a run
            backend_status.update({"registered": False,
                                   "error": "%s: %s" % (type(exc).__name__, exc)})
            adapter_errors["wsl_docker"] = backend_status["error"]
            unavailable.append({"name": "linux_gpu_backend", "kind": "adapter",
                                "purpose": "Run Linux/CUDA experiments in Docker on WSL2.",
                                "location": "gpuvulnagent/backends/",
                                "requires": ["wsl.exe", "docker"],
                                "formats": [".cu", ".cubin", ".so"],
                                "usage": "container_exec(...)", "tags": ["gpu", "docker"],
                                "reason": backend_status["error"]})

    # Track B: findings live in the trial, next to the evidence chain that supports them.
    try:
        from .findings import build_finding_tools
        evidence_path = Path(log.path)
        trial_root = evidence_path.parent.parent if evidence_path.parent.name == "evidence"             else evidence_path.parent
        registry.extend(build_finding_tools(trial_root=trial_root,
                                            trial_id=getattr(log, "run_id", "trial"),
                                            log=log))
    except Exception as exc:  # noqa: BLE001 - finding tools must not break a run
        adapter_errors["findings"] = "findings unavailable: %s" % exc

    catalog.registry = registry
    if manifest is not None:
        catalog.add_manifest(manifest)
    catalog.add_registry(registry)
    for item in unavailable:
        catalog.add_unavailable(**item)

    return Assembly(registry=registry, catalog=catalog, manifest=manifest,
                    providers=providers, conflicts=list(registry.conflicts),
                    adapter_errors=adapter_errors, backend=backend,
                    backend_status=backend_status)


def _load_manifest(toolchain_root: Optional[Path],
                   manifest_path: Optional[Path]) -> Optional[ToolchainManifest]:
    if toolchain_root is None and manifest_path is None:
        return None
    if manifest_path is not None:
        path = Path(manifest_path)
        root = path.parents[1] if len(path.parents) > 1 else path.parent
        return ToolchainManifest(root, path)
    return ToolchainManifest(Path(toolchain_root))
