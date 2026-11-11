# -*- coding: utf-8 -*-
"""ELF / CUBIN tools: structure first, then the toolchain disassembler.

Binary locations come from the manifest, never from a hardcoded drive letter. When the
manifest is absent or the binary has moved, the tool says so and falls back to ``PATH``
before giving up.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import List, Optional

from ...registry.spec import ParamSpec, ToolSpec
from . import reader


def _resolve_binary(name: str, manifest) -> tuple:
    if manifest is not None:
        found = manifest.path_of(name)
        if found is not None:
            return found, "manifest"
    on_path = shutil.which(name)
    if on_path:
        return Path(on_path), "PATH"
    return None, "missing"


def build_tools(*, workspace=None, runner=None, log=None, manifest=None) -> List[ToolSpec]:
    artifacts = log.artifacts if log is not None else None

    def _path(raw: str) -> Path:
        candidate = Path(raw)
        if not candidate.is_absolute() and workspace is not None:
            candidate = workspace.root / candidate
        return candidate

    def cubin_header(path: str) -> dict:
        try:
            info = reader.summarise(_path(path))
        except (OSError, reader.ElfError) as exc:
            return {"ok": False, "status": "failed",
                    "summary": {"error": str(exc), "path": path}, "artifacts": []}
        header = info["header"]
        return {"ok": True,
                "summary": {"path": info["path"], "size": info["size"],
                            "class": header["class"], "machine": header["machine_name"],
                            "type": header["type"], "verdict": info["verdict"],
                            "section_count": info["section_count"],
                            "cuda_sections": info["cuda_sections"][:20],
                            "sections": [s["name"] for s in info["sections"][:40]]},
                "artifacts": []}

    def _run_cuobjdump(path: str, mode: str, timeout: int, limit: int) -> dict:
        if runner is None:
            return {"ok": False, "status": "failed",
                    "summary": {"error": "no runner available"}, "artifacts": []}
        binary, origin = _resolve_binary("cuobjdump", manifest)
        if binary is None:
            return {"ok": False, "status": "dispatch_error",
                    "summary": {"error": "cuobjdump not found in the toolchain manifest or "
                                         "on PATH; run toolchain_lookup to inspect the "
                                         "manifest", "manifest_origin": origin},
                    "artifacts": []}
        target = _path(path)
        argv = [str(binary), mode, str(target)]
        record = runner.run(argv, timeout=timeout, label="cuobjdump", via="cubin_tool")
        refs = record["artifacts"]
        summary = {"binary": str(binary), "binary_source": origin, "argv": argv,
                   "exit": record["exit"],
                   "termination": record["termination"]["kind"],
                   "crash": record["termination"]["crash"],
                   "stdout": record["stdout_preview"][:limit],
                   "stderr": record["stderr_preview"][:800]}
        return {"ok": record["termination"]["kind"] == "success",
                "status": record["status"], "summary": summary, "artifacts": refs}

    def cubin_dump(path: str, mode: str = "-elf", timeout: int = 300,
                   limit: int = 4000) -> dict:
        return _run_cuobjdump(path, mode, timeout, limit)

    def cubin_disassemble(path: str, timeout: int = 600, limit: int = 4000) -> dict:
        if runner is None:
            return {"ok": False, "status": "failed",
                    "summary": {"error": "no runner available"}, "artifacts": []}
        binary, origin = _resolve_binary("nvdisasm", manifest)
        if binary is None:
            return {"ok": False, "status": "dispatch_error",
                    "summary": {"error": "nvdisasm not found in the toolchain manifest or "
                                         "on PATH", "manifest_origin": origin},
                    "artifacts": []}
        argv = [str(binary), str(_path(path))]
        record = runner.run(argv, timeout=timeout, label="nvdisasm", via="cubin_tool")
        return {"ok": record["termination"]["kind"] == "success",
                "status": record["status"],
                "summary": {"binary": str(binary), "binary_source": origin, "argv": argv,
                            "exit": record["exit"],
                            "termination": record["termination"]["kind"],
                            "crash": record["termination"]["crash"],
                            "stdout": record["stdout_preview"][:limit],
                            "stderr": record["stderr_preview"][:800]},
                "artifacts": record["artifacts"]}

    return [
        ToolSpec(name="cubin_header", description=(
            "Parse ELF/CUBIN structure without any external tool: class, endianness, "
            "machine (EM_CUDA marks a cubin), type, section names and the .nv.* sections "
            "that carry SASS/metadata. Refuses to guess on malformed files."),
            handler=cubin_header, category="adapter", source="adapter:elf_cubin",
            location="gpuvulnagent/adapters/elf_cubin/reader.py:summarise",
            usage="cubin_header(path='samples/kernel.cubin')",
            formats=(".cubin", ".elf", ".o", ".so", ".bin"),
            tags=("elf", "cubin", "nvidia", "parser"),
            parameters=[ParamSpec("path", "string", "File path (workspace-relative ok).")],
            side_effects=("read_only",)),

        ToolSpec(name="cubin_dump", description=(
            "Run cuobjdump from the toolchain manifest with a chosen mode: -elf (headers, "
            "sections, symbols), -sass (disassembly), -ptx, -res-usage. The full output is "
            "an artifact; the reply carries a preview and the exit classification."),
            handler=cubin_dump, category="adapter", source="adapter:elf_cubin",
            location="gpuvulnagent/adapters/elf_cubin/tools.py:cubin_dump",
            usage="cubin_dump(path='a.cubin', mode='-elf')",
            formats=(".cubin", ".elf", ".o", ".so", ".fatbin"),
            tags=("cuda", "disassembly", "toolchain"),
            requires=(),
            parameters=[ParamSpec("path", "string", "Target binary."),
                        ParamSpec("mode", "string", "cuobjdump mode flag.",
                                  required=False, default="-elf",
                                  enum=("-elf", "-sass", "-ptx", "-res-usage", "-lptx")),
                        ParamSpec("timeout", "integer", "Seconds.", required=False,
                                  default=300, minimum=1, maximum=3600),
                        ParamSpec("limit", "integer", "Preview characters.", required=False,
                                  default=4000, minimum=200, maximum=20000)],
            side_effects=("executes",)),

        ToolSpec(name="cubin_disassemble", description=(
            "Run nvdisasm from the toolchain manifest on one cubin and return the SASS "
            "listing preview; the full listing is an artifact."),
            handler=cubin_disassemble, category="adapter", source="adapter:elf_cubin",
            location="gpuvulnagent/adapters/elf_cubin/tools.py:cubin_disassemble",
            usage="cubin_disassemble(path='a.cubin')",
            formats=(".cubin", ".elf"), tags=("cuda", "disassembly", "toolchain"),
            parameters=[ParamSpec("path", "string", "Target cubin."),
                        ParamSpec("timeout", "integer", "Seconds.", required=False,
                                  default=600, minimum=1, maximum=3600),
                        ParamSpec("limit", "integer", "Preview characters.", required=False,
                                  default=4000, minimum=200, maximum=20000)],
            side_effects=("executes",)),
    ]
