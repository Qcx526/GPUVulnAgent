# -*- coding: utf-8 -*-
"""trail_stage: reference-based delivery of an existing file into a trail."""

from __future__ import annotations

from pathlib import Path
from typing import List

from ..registry.spec import ParamSpec, ToolSpec
from .stage import StageError, resolve_source, stage_copy


def build_stage_tools(*, trail_root: Path, log, wsl_refs: str = "",
                      repo_root=None) -> List[ToolSpec]:
    from ..backends.trails import TrailStore

    store = TrailStore(Path(trail_root), getattr(log, "run_id", "run"))

    def trail_stage(trail: str, source: str, destination_name: str = "") -> dict:
        try:
            handle = store.open(trail)
            root_dir = Path(repo_root) if repo_root else Path.cwd()
            wsl_root = Path(wsl_refs) if wsl_refs else None
            path, origin = resolve_source(source, repo_root=root_dir, wsl_root=wsl_root)
            name = destination_name.strip() or path.name
            if "/" in name or ".." in name or not name:
                raise StageError("destination_name must be a plain file name")
            if origin.startswith("wsl-ref:") and not path.exists():
                # A Linux path is not visible to Windows directly: reach it over the WSL share.
                distro = "Ubuntu-22.04"
                try:
                    from ..backends.wsl_docker import WslConfig as _WC
                    distro = _WC().distro
                except Exception:  # noqa: BLE001
                    pass
                path = Path("//wsl.localhost/%s%s" % (distro, str(path)))
            destination = handle.inputs / name
            result = stage_copy(path, destination)
            record = handle.register_file("inputs/" + name, kind="input", source="staged",
                                          relation=origin)
        except StageError as exc:
            return {"ok": False, "status": "rejected", "summary": {"error": str(exc)},
                    "artifacts": []}
        except Exception as exc:  # noqa: BLE001 - a trail error is an observation
            return {"ok": False, "status": "failed",
                    "summary": {"error": "%s: %s" % (type(exc).__name__, exc)},
                    "artifacts": []}
        evidence = log.append("staging", {"tool_name": "trail_stage", "trail": trail,
                                          "source": origin, "destination": str(destination),
                                          "sha256": result["sha256"],
                                          "bytes": result["bytes"],
                                          "written": result["written"]})
        return {"ok": True, "status": "success",
                "summary": {"name": name, "bytes": result["bytes"],
                            "sha256": result["sha256"], "source": origin,
                            "destination": "inputs/" + name,
                            "artifact": getattr(record, "name", "inputs/" + name),
                            "evidence": evidence.get("evidence_id", ""),
                            "written": result["written"],
                            "note": "content is not returned; it is on disk in the trail"},
                "artifacts": []}

    return [ToolSpec(
        name="trail_stage", description=(
            "Copy an existing file into a trail's inputs without passing its bytes through the "
            "model. Use it for binaries too large to write (cuobjdump, nvdisasm, cubins). "
            "source is 'wsl-ref:<relative path under the WSL refs root>' or "
            "'repo:toolchains/...' / 'repo:research_archive/...'. Returns size, sha256 and the "
            "trail file name only."),
        handler=trail_stage, category="gpu", source="builtin",
        location="gpuvulnagent/tools/stage.py",
        usage="trail_stage(trail='trail0', source='wsl-ref:cuobjdump-13-0-13.0.85-1/"
              "usr/local/cuda-13.0/bin/cuobjdump', destination_name='cuobjdump-13.0.85')",
        parameters=[ParamSpec("trail", "string", "Trail id, e.g. trail0."),
                    ParamSpec("source", "string", "wsl-ref:<relative> or repo:<root>/<path>."),
                    ParamSpec("destination_name", "string",
                              "Plain file name inside the trail inputs (optional).",
                              required=False, default="")],
        side_effects=("writes_workspace",),
        tags=("gpu", "trail", "staging", "binary"))]
