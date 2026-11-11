# -*- coding: utf-8 -*-
"""Builtin tools: the minimum an agent needs to investigate, plus discovery and memory.

Every tool answers with the same envelope - ``ok``, a short ``summary`` for the prompt, and
``artifacts`` pointing at the full body - so one evidence record covers all of them.

Tool discovery is a tool (``tool_search`` / ``tool_describe``) rather than a hidden
registry the model cannot see: an adapter it has never heard of is one search away.
"""

from __future__ import annotations

import json
import os
import platform
import urllib.error
import urllib.request
from pathlib import Path
from typing import List, Optional

from ..evidence.hashing import sha256_bytes
from ..evidence.outcome import classify_termination
from ..evidence.redact import redact
from ..registry.spec import ParamSpec, ToolSpec

TEXT_TYPES = ("application/json", "text/plain", "text/html", "application/xml",
              "text/xml", "text/markdown")


def build_builtin_tools(*, workspace, runner, log, memory, catalog,
                        manifest=None) -> List[ToolSpec]:
    artifacts = log.artifacts
    is_windows = os.name == "nt"

    # -- execution ------------------------------------------------------
    def shell(command: str, timeout: int = 300, working_dir: str = ".") -> dict:
        cwd = workspace.resolve(working_dir)
        argv = ["cmd", "/c", command] if is_windows else ["sh", "-c", command]
        record = runner.run(argv, cwd=cwd, timeout=timeout, label="shell", via="shell")
        termination = record["termination"]
        return {"ok": termination["kind"] == "success",
                "status": record["status"],
                "summary": {"exit": record["exit"], "timed_out": record["timed_out"],
                            "termination": termination["kind"],
                            "stdout": record["stdout_preview"][:2500],
                            "stderr": record["stderr_preview"][:1200]},
                "artifacts": record["artifacts"],
                "timeout_seconds": record["timeout_seconds"]}

    def run_program(program: str, args: Optional[list] = None, timeout: int = 300) -> dict:
        """Run one program directly. Args are a real array, not a shell string."""
        argv = [program] + [str(a) for a in (args or [])]
        record = runner.run(argv, timeout=timeout, label=Path(program).name,
                            via="run_program")
        termination = record["termination"]
        return {"ok": termination["kind"] == "success", "status": record["status"],
                "summary": {"argv": argv, "exit": record["exit"],
                            "termination": termination["kind"],
                            "crash": termination["crash"],
                            "stdout": record["stdout_preview"][:2500],
                            "stderr": record["stderr_preview"][:1200]},
                "artifacts": record["artifacts"]}

    # -- workspace files ------------------------------------------------
    def fs_list(path: str = ".") -> dict:
        listing = workspace.listdir(path)
        return {"ok": True, "summary": listing, "artifacts": []}

    def fs_read(path: str, limit: int = 20000) -> dict:
        content = workspace.read(path, limit=limit)
        ref = artifacts.save("files", Path(path).name, content["content"]) if artifacts else None
        return {"ok": True,
                "summary": {"path": content["path"], "bytes": content["bytes"],
                            "truncated": content["truncated"],
                            "content": content["content"][:6000]},
                "artifacts": [ref] if ref else []}

    def fs_write(path: str, content: str) -> dict:
        written = workspace.write(path, content)
        ref = artifacts.save("files", Path(path).name, content) if artifacts else None
        return {"ok": True, "summary": written, "artifacts": [ref] if ref else []}

    # -- network --------------------------------------------------------
    def http_get(url: str, mode: str = "text", limit: int = 4000, timeout: int = 30) -> dict:
        request = urllib.request.Request(url, headers={"User-Agent": "gpuvulnagent/0.1"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status = getattr(response, "status", None)
                content_type = response.headers.get("Content-Type", "")
                final_url = response.geturl()
                body = response.read(4 * 1024 * 1024)
        except urllib.error.HTTPError as exc:
            body = exc.read()[:2000]
            entry = {"url": url, "http_status": exc.code, "error": str(exc),
                     "bytes": len(body)}
            log.append("http", entry, status="failed")
            return {"ok": False, "summary": entry, "artifacts": []}
        except Exception as exc:  # noqa: BLE001 - a network failure is an observation
            entry = {"url": url, "http_status": None,
                     "error": "%s: %s" % (type(exc).__name__, exc)}
            log.append("http", entry, status="failed")
            return {"ok": False, "summary": entry, "artifacts": []}

        text, hits = redact(body.decode("utf-8", errors="replace"))
        digest = sha256_bytes(body)
        ref = artifacts.save("http", _slug(url), body) if artifacts else None
        extracted = text
        if mode == "json":
            try:
                extracted = json.dumps(json.loads(text), ensure_ascii=False, indent=1)
            except ValueError:
                extracted = text
        elif mode == "text" and "html" in content_type.lower():
            extracted = strip_html(text)
        summary = {"url": url, "final_url": final_url, "http_status": status,
                   "content_type": content_type, "bytes": len(body), "sha256": digest,
                   "mode": mode, "truncated": len(extracted) > limit,
                   "redactions": hits, "body_preview": extracted[:limit]}
        log.append("http", {k: v for k, v in summary.items() if k != "body_preview"},
                   status="success")
        return {"ok": 200 <= (status or 0) < 400, "summary": summary,
                "artifacts": [ref] if ref else []}

    # -- artifacts ------------------------------------------------------
    def artifact_read(artifact: str, offset: int = 0, limit: int = 4000) -> dict:
        if artifacts is None:
            return {"ok": False, "status": "failed",
                    "summary": {"error": "no artifact store"}, "artifacts": []}
        try:
            path = artifacts.resolve(artifact)
        except PermissionError:
            return {"ok": False, "status": "failed",
                    "summary": {"error": "artifact path escapes the store",
                                "artifact": artifact}, "artifacts": []}
        if not path.is_file():
            return {"ok": False, "status": "failed",
                    "summary": {"error": "artifact not found", "artifact": artifact},
                    "artifacts": []}
        start = max(0, int(offset))
        span = max(1, min(int(limit), 64000))
        data = path.read_bytes()
        chunk = data[start:start + span]
        text = chunk.decode("utf-8", errors="replace")
        end = start + len(chunk)
        summary = {"artifact": artifact, "total_bytes": len(data), "offset": start,
                   "read_bytes": len(chunk), "next_offset": end, "has_more": end < len(data),
                   "truncated": len(text) < len(chunk), "content": text}
        return {"ok": True, "summary": summary, "artifacts": [],
                "status": "success" if not summary["has_more"] else "partial"}

    # -- environment ----------------------------------------------------
    def env_probe() -> dict:
        probes = {
            "os": ("cmd", "/c", "ver") if is_windows else ("sh", "-c", "uname -a"),
            "python": ("python", "--version"),
            "gpu": ("nvidia-smi", "--query-gpu=name,driver_version,memory.total",
                    "--format=csv,noheader"),
            "cuda_manifest": ("manifest",),
        }
        found, refs = {}, []
        for name, argv in probes.items():
            if argv == ("manifest",):
                found[name] = {"tools": list(manifest.names()) if manifest else [],
                               "manifest": str(manifest.path) if manifest else "absent"}
                continue
            record = runner.run(list(argv), timeout=30, label="env_" + name, via="env_probe")
            found[name] = {"exit": record["exit"],
                           "termination": record["termination"]["kind"],
                           "stdout": record["stdout_preview"][:400],
                           "stderr": record["stderr_preview"][:200]}
            refs.extend(record["artifacts"])
        found["platform"] = {"system": platform.system(), "release": platform.release()}
        return {"ok": True, "summary": found, "artifacts": refs}

    # -- memory ---------------------------------------------------------
    def memory_note(kind: str, text: str, tags: Optional[list] = None,
                    evidence: Optional[list] = None, scope: str = "run") -> dict:
        try:
            entry = memory.add(kind, text, tags=tags or [], evidence=evidence or [],
                               scope=scope, source="agent")
        except Exception as exc:  # noqa: BLE001 - a rejected memory is an observation
            return {"ok": False, "status": "rejected",
                    "summary": {"error": "%s: %s" % (type(exc).__name__, exc)},
                    "artifacts": []}
        record = log.append("memory", {"memory_id": entry.id, "type": entry.type,
                                       "scope": entry.scope, "evidence": entry.evidence,
                                       "content": entry.content[:600]})
        return {"ok": True, "status": "success",
                "summary": {"id": entry.id, "type": entry.type, "scope": entry.scope,
                            "evidence_record": record.get("evidence_id")},
                "artifacts": []}

    def memory_search(query: str, limit: int = 8, types: Optional[list] = None) -> dict:
        found = memory.search(query, limit=limit, types=types)
        return {"ok": True,
                "summary": {"query": query, "results": len(found),
                            "items": [{"id": e.id, "type": e.type, "scope": e.scope,
                                       "status": e.status, "run": e.run_id,
                                       "content": e.content[:400]} for e in found]},
                "artifacts": []}

    def memory_refute(entry_id: str, reason: str, evidence: Optional[list] = None) -> dict:
        try:
            entry = memory.refute(entry_id, reason, evidence=evidence or [])
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "status": "rejected",
                    "summary": {"error": "%s: %s" % (type(exc).__name__, exc)},
                    "artifacts": []}
        log.append("memory", {"memory_id": entry.id, "type": "failed",
                              "refutes": entry_id, "content": reason[:400]})
        return {"ok": True, "summary": {"id": entry.id, "refutes": entry_id}, "artifacts": []}

    # -- discovery ------------------------------------------------------
    def tool_search(query: str = "", formats: str = "", requires: str = "",
                    available_only: bool = False, limit: int = 15) -> dict:
        hits = catalog.search(query, formats=formats, requires=requires,
                              available_only=available_only, limit=limit)
        return {"ok": True,
                "summary": {"query": query, "formats": formats, "requires": requires,
                            "results": len(hits),
                            "items": [{"name": h["name"], "kind": h["kind"],
                                       "available": h["available"],
                                       "purpose": (h["purpose"] or "")[:220],
                                       "formats": h["formats"],
                                       "location": h["location"]} for h in hits],
                            "catalog": catalog.summary()},
                "artifacts": []}

    def tool_describe(name: str) -> dict:
        info = catalog.describe(name)
        if info is None or "error" in info:
            return {"ok": False, "status": "failed",
                    "summary": info or {"error": "no capability named %r" % name},
                    "artifacts": []}
        return {"ok": True, "summary": info, "artifacts": []}

    def toolchain_lookup(name: str = "") -> dict:
        if manifest is None or manifest.load_error:
            return {"ok": False, "status": "failed",
                    "summary": {"error": (manifest.load_error if manifest
                                          else "no manifest configured")},
                    "artifacts": []}
        if name:
            info = manifest.describe(name)
            if info is None:
                return {"ok": False, "status": "failed",
                        "summary": {"error": "tool %r is not in the manifest" % name,
                                    "known": manifest.names()}, "artifacts": []}
            return {"ok": True, "summary": info, "artifacts": []}
        return {"ok": True,
                "summary": {"root": str(manifest.root), "tools": manifest.names(),
                            "meta": manifest.meta}, "artifacts": []}

    return [
        ToolSpec(name="shell", description=(
            "Run a shell command inside the run workspace. Full stdout/stderr is saved as "
            "an artifact; the reply carries a preview and the exit status. A timeout kills "
            "the whole process tree."),
            handler=shell, category="execution", source="builtin",
            location="gpuvulnagent/tools/builtin.py:shell",
            usage="shell(command='cuobjdump --dump-elf a.cubin', timeout=120)",
            parameters=[ParamSpec("command", "string", "Command line to run."),
                        ParamSpec("timeout", "integer", "Seconds before the tree is killed.",
                                  required=False, default=300, minimum=1, maximum=3600),
                        ParamSpec("working_dir", "string", "Workspace-relative directory.",
                                  required=False, default=".")],
            side_effects=("executes", "writes_workspace"), tags=("exec", "shell")),

        ToolSpec(name="run_program", description=(
            "Run one executable directly with an argument array (no shell quoting). Use "
            "this for crafted inputs and for tools such as cuobjdump/nvdisasm; the "
            "termination is classified as success, timeout, not_found or a signal/crash."),
            handler=run_program, category="execution", source="builtin",
            location="gpuvulnagent/tools/builtin.py:run_program",
            parameters=[ParamSpec("program", "string", "Executable path or PATH name."),
                        ParamSpec("args", "array", "Argument vector, one element per arg.",
                                  required=False, items_type="string"),
                        ParamSpec("timeout", "integer", "Seconds before the tree is killed.",
                                  required=False, default=300, minimum=1, maximum=3600)],
            side_effects=("executes",), tags=("exec", "target")),

        ToolSpec(name="fs_list", description="List a directory in the run workspace.",
                 handler=fs_list, category="files", source="builtin",
                 location="gpuvulnagent/tools/builtin.py:fs_list",
                 parameters=[ParamSpec("path", "string", "Workspace-relative path.",
                                       required=False, default=".")],
                 tags=("files",)),

        ToolSpec(name="fs_read", description=(
            "Read a text file from the workspace; the full content is also stored as an "
            "artifact so a truncated reply never loses evidence."),
                 handler=fs_read, category="files", source="builtin",
                 location="gpuvulnagent/tools/builtin.py:fs_read",
                 parameters=[ParamSpec("path", "string", "Workspace-relative path."),
                             ParamSpec("limit", "integer", "Max characters returned.",
                                       required=False, default=20000, minimum=1)],
                 tags=("files",)),

        ToolSpec(name="fs_write", description="Write a text file into the run workspace.",
                 handler=fs_write, category="files", source="builtin",
                 location="gpuvulnagent/tools/builtin.py:fs_write",
                 parameters=[ParamSpec("path", "string", "Workspace-relative path."),
                             ParamSpec("content", "string", "File content.")],
                 side_effects=("writes_workspace",), tags=("files",)),

        ToolSpec(name="http_get", description=(
            "Fetch a URL. mode=text strips HTML, json pretty-prints, raw keeps the body. "
            "Records status, content type, final URL, size and sha256."),
                 handler=http_get, category="research", source="builtin",
                 location="gpuvulnagent/tools/builtin.py:http_get",
                 parameters=[ParamSpec("url", "string", "Absolute URL."),
                             ParamSpec("mode", "string", "How to render the body.",
                                       required=False, default="text",
                                       enum=("text", "json", "raw")),
                             ParamSpec("limit", "integer", "Preview characters.",
                                       required=False, default=4000, minimum=1),
                             ParamSpec("timeout", "integer", "Seconds.",
                                       required=False, default=30, minimum=1)],
                 side_effects=("network",), tags=("web", "research")),

        ToolSpec(name="artifact_read", description=(
            "Read a stored artifact in chunks by its reference (e.g. "
            "'stdout/ab12cd34ef56-shell-101500-123.out'). Returns total size, bytes read, "
            "next offset and whether more remains."),
                 handler=artifact_read, category="files", source="builtin",
                 location="gpuvulnagent/tools/builtin.py:artifact_read",
                 parameters=[ParamSpec("artifact", "string", "Artifact reference."),
                             ParamSpec("offset", "integer", "Byte offset.",
                                       required=False, default=0, minimum=0),
                             ParamSpec("limit", "integer", "Bytes to read.",
                                       required=False, default=4000, minimum=1,
                                       maximum=64000)],
                 tags=("files", "evidence")),

        ToolSpec(name="env_probe", description=(
            "Report OS, python, GPU/driver and the toolchain manifest as they really are."),
                 handler=env_probe, category="research", source="builtin",
                 location="gpuvulnagent/tools/builtin.py:env_probe",
                 parameters=[], tags=("environment",)),

        ToolSpec(name="memory_note", description=(
            "Record what you learned. Types: attempt, finding, hypothesis, failed, open. A "
            "finding MUST cite evidence ids (e.g. 'run-abc#7'); without them use "
            "hypothesis. scope=run stays in this run, case is shared with every run on "
            "this case, global is for method-level lessons."),
                 handler=memory_note, category="memory", source="builtin",
                 location="gpuvulnagent/tools/builtin.py:memory_note",
                 parameters=[ParamSpec("kind", "string", "Memory type.",
                                       enum=("attempt", "finding", "hypothesis", "failed",
                                             "open")),
                             ParamSpec("text", "string", "The claim or observation."),
                             ParamSpec("tags", "array", "Free-form tags.", required=False,
                                       items_type="string"),
                             ParamSpec("evidence", "array", "Evidence ids such as run-x#12.",
                                       required=False, items_type="string"),
                             ParamSpec("scope", "string", "Where the entry lives.",
                                       required=False, default="run",
                                       enum=("run", "case", "global"))],
                 side_effects=("writes_memory",), tags=("memory",)),

        ToolSpec(name="memory_search", description=(
            "Search run, case and global memory - including refuted directions - before "
            "repeating an experiment."),
                 handler=memory_search, category="memory", source="builtin",
                 location="gpuvulnagent/tools/builtin.py:memory_search",
                 parameters=[ParamSpec("query", "string", "Terms to look for."),
                             ParamSpec("limit", "integer", "Max entries.",
                                       required=False, default=8, minimum=1, maximum=50),
                             ParamSpec("types", "array", "Restrict to these types.",
                                       required=False, items_type="string")],
                 tags=("memory",)),

        ToolSpec(name="memory_refute", description=(
            "Mark an earlier memory entry as refuted. The original stays readable; a new "
            "failed entry points at it so no future run repeats the dead end."),
                 handler=memory_refute, category="memory", source="builtin",
                 location="gpuvulnagent/tools/builtin.py:memory_refute",
                 parameters=[ParamSpec("entry_id", "string", "Id of the entry to refute."),
                             ParamSpec("reason", "string", "Why it is wrong or dead."),
                             ParamSpec("evidence", "array", "Evidence ids.", required=False,
                                       items_type="string")],
                 side_effects=("writes_memory",), tags=("memory",)),

        ToolSpec(name="tool_search", description=(
            "Search every capability the project has: registered tools, adapters that ship "
            "with the project (even when their dependencies are missing) and toolchain "
            "binaries. Match on name, purpose, supported file format or dependency."),
                 handler=tool_search, category="discovery", source="builtin",
                 location="gpuvulnagent/tools/builtin.py:tool_search",
                 usage="tool_search(query='jpeg', formats='.jpg')",
                 parameters=[ParamSpec("query", "string", "Free-text terms.", required=False,
                                       default=""),
                             ParamSpec("formats", "string", "File format filter, e.g. .cubin "
                                       "or jpeg.", required=False, default=""),
                             ParamSpec("requires", "string", "Dependency filter, e.g. nvcc.",
                                       required=False, default=""),
                             ParamSpec("available_only", "boolean",
                                       "Only capabilities that can run now.", required=False,
                                       default=False),
                             ParamSpec("limit", "integer", "Max results.", required=False,
                                       default=15, minimum=1, maximum=50)],
                 tags=("discovery", "catalog")),

        ToolSpec(name="tool_describe", description=(
            "Full description of one capability: purpose, parameters, usage, location and "
            "whether it can run here (with the reason when it cannot)."),
                 handler=tool_describe, category="discovery", source="builtin",
                 location="gpuvulnagent/tools/builtin.py:tool_describe",
                 parameters=[ParamSpec("name", "string", "Capability name.")],
                 tags=("discovery", "catalog")),

        ToolSpec(name="toolchain_lookup", description=(
            "Look up a toolchain binary from the manifest: version, sha256, workspace path "
            "and whether it runs. Call with no name to list everything."),
                 handler=toolchain_lookup, category="discovery", source="builtin",
                 location="gpuvulnagent/tools/builtin.py:toolchain_lookup",
                 parameters=[ParamSpec("name", "string", "Manifest tool name.",
                                       required=False, default="")],
                 tags=("discovery", "toolchain")),
    ]


def strip_html(text: str) -> str:
    import re
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"[ \t]+", " ", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def _slug(url: str) -> str:
    import re
    tail = re.sub(r"[^A-Za-z0-9]+", "-", url.split("//")[-1])[:60]
    return (tail or "response") + ".body"


def classify_exit(exit_code, timed_out: bool = False, launch_error: str = "") -> dict:
    """Re-exported for callers that only want the classification."""
    return classify_termination(exit_code, timed_out=timed_out, launch_error=launch_error)
