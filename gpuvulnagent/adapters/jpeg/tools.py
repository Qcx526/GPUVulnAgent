# -*- coding: utf-8 -*-
"""JPEG tools: make the adapter callable by the agent."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from ...registry.spec import ParamSpec, ToolSpec
from . import adapter as jpeg_adapter


def build_tools(*, workspace=None, log=None, **_unused) -> List[ToolSpec]:
    artifacts = log.artifacts if log is not None else None

    def _resolve(path: str) -> Path:
        candidate = Path(path)
        if not candidate.is_absolute() and workspace is not None:
            candidate = workspace.root / candidate
        return candidate

    def jpeg_inspect(path: str) -> dict:
        try:
            info = jpeg_adapter.inspect_file(_resolve(path))
        except jpeg_adapter.AdapterError as exc:
            return {"ok": False, "status": "failed",
                    "summary": {"error": str(exc), "path": path}, "artifacts": []}
        frame = info["frame"]
        return {"ok": True,
                "summary": {"path": info["path"], "bytes": info["bytes"],
                            "sha256": info["sha256"], "markers": info["markers"],
                            "scans": info["scan_count"],
                            "width": frame["width"], "height": frame["height"],
                            "precision": frame["precision"],
                            "components": frame["components"],
                            "editable": True},
                "artifacts": []}

    def jpeg_mutate_dimensions(path: str, width: int, height: int,
                               out_dir: str = "jpeg") -> dict:
        """Produce a mutated JPEG plus its control; both are stored as artifacts."""
        source = _resolve(path)
        try:
            data = source.read_bytes()
            plan = jpeg_adapter.plan_dimensions(width, height)
            mutated, control, details = jpeg_adapter.apply_plan(data, plan)
        except (OSError, jpeg_adapter.AdapterError) as exc:
            return {"ok": False, "status": "failed",
                    "summary": {"error": str(exc), "path": path}, "artifacts": []}
        refs = []
        if workspace is not None:
            name = source.stem
            target = "%s/%s-mutated.jpg" % (out_dir, name)
            control_path = "%s/%s-control.jpg" % (out_dir, name)
            workspace.write(target, mutated)
            workspace.write(control_path, control)
            details["mutated_path"] = target
            details["control_path"] = control_path
        if artifacts is not None:
            refs.append(artifacts.save("files", source.stem + "-mutated.jpg", mutated))
            refs.append(artifacts.save("files", source.stem + "-control.jpg", control))
        validation = jpeg_adapter.validate_pair(mutated, control, path=str(source))
        return {"ok": True,
                "summary": {"plan": details["plan"], "original": details["original"],
                            "mutated": details["mutated"],
                            "mutated_sha256": jpeg_adapter.sha256(mutated),
                            "control_sha256": jpeg_adapter.sha256(control),
                            "same_length": len(mutated) == len(control) == len(data),
                            "validation": validation,
                            "mutated_path": details.get("mutated_path", ""),
                            "control_path": details.get("control_path", "")},
                "artifacts": refs}

    return [
        ToolSpec(name="jpeg_inspect", description=(
            "Read a JPEG's marker structure: SOI/APP/DQT/DHT/SOF/SOS/EOI, frame size, "
            "precision, component count and scan count. Fails closed on progressive or "
            "arithmetic files. Use this before crafting any JPEG input."),
            handler=jpeg_inspect, category="adapter", source="adapter:jpeg",
            location="gpuvulnagent/adapters/jpeg/adapter.py:inspect_file",
            usage="jpeg_inspect(path='samples/small.jpg')",
            formats=(".jpg", ".jpeg"), tags=("jpeg", "parser", "image"),
            parameters=[ParamSpec("path", "string", "JPEG path (workspace-relative ok).")],
            side_effects=("read_only",)),

        ToolSpec(name="jpeg_mutate_dimensions", description=(
            "Write one plan: set the SOF frame width/height. Produces the mutated file and "
            "a paired control rebuilt from the original values, stores both as artifacts "
            "and validates them with the segment walker plus Pillow when available."),
            handler=jpeg_mutate_dimensions, category="adapter", source="adapter:jpeg",
            location="gpuvulnagent/adapters/jpeg/adapter.py:apply_plan",
            usage="jpeg_mutate_dimensions(path='samples/small.jpg', width=1, height=1)",
            formats=(".jpg", ".jpeg"), tags=("jpeg", "mutate", "control"),
            parameters=[ParamSpec("path", "string", "Source JPEG."),
                        ParamSpec("width", "integer", "New frame width (1..65535).",
                                  minimum=1, maximum=65535),
                        ParamSpec("height", "integer", "New frame height (1..65535).",
                                  minimum=1, maximum=65535),
                        ParamSpec("out_dir", "string", "Workspace subdirectory for outputs.",
                                  required=False, default="jpeg")],
            side_effects=("writes_workspace",)),
    ]
