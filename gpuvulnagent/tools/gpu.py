# -*- coding: utf-8 -*-
"""GPU execution tools: probe, stage, run, collect - and nothing about *what* to run.

These tools give the agent a Linux GPU machine it can drive. They do not know what a
vulnerability is, what a PoC looks like, or which command should come next. The agent
chooses the image, the argv, the inputs and the experiment order; the tools report what
actually happened and put the bytes somewhere it can read them back.

Evidence is written through the same hash-chained log as every other tool, with the
container-specific facts (image digest, container id, exit status, OOM flag) added.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import List, Optional

from ..backends.base import BackendError, BackendUnavailable
from ..backends.trails import Trail, TrailError, TrailStore
from ..backends.wsl_docker import WslDockerBackend
from ..evidence.redact import redact
from ..registry.spec import ParamSpec, ToolSpec

MAX_ARGV = 64


def build_gpu_tools(*, backend: WslDockerBackend, trail_root, run_id: str, log,
                    workspace=None) -> List[ToolSpec]:
    store = TrailStore(Path(trail_root), run_id)
    artifacts = getattr(log, "artifacts", None)

    # -- environment -----------------------------------------------------
    def gpu_environment_probe(deep: bool = False) -> dict:
        try:
            report = backend.probe(deep=deep, force=deep)
        except (BackendUnavailable, BackendError) as exc:
            log.append("probe", {"backend": backend.name, "error": str(exc)}, status="failed")
            return {"ok": False, "status": "backend_unavailable",
                    "summary": {"error": str(exc), "backend": backend.name,
                                "hint": "the Linux GPU backend is not reachable; GPU work "
                                        "cannot run, but the rest of the tools still can"},
                    "artifacts": []}
        payload = report.to_dict()
        record = log.append("probe", {"backend": backend.name, "available": report.available,
                                      "distro": report.distro, "docker": report.docker_version,
                                      "gpu": report.gpu_name,
                                      "compute_capability": report.compute_capability,
                                      "cuda": report.cuda_version,
                                      "problems": report.problems},
                            status="success" if report.available else "failed")
        return {"ok": report.available, "status": "success" if report.available else "partial",
                "summary": _probe_summary(payload),
                "probe": payload, "evidence_id": record.get("evidence_id"),
                "artifacts": []}

    def gpu_toolchain_discover(name: str = "") -> dict:
        try:
            report = backend.probe()
        except (BackendUnavailable, BackendError) as exc:
            return {"ok": False, "status": "backend_unavailable",
                    "summary": {"error": str(exc)}, "artifacts": []}
        tools = {key: value.to_dict() for key, value in report.tools.items()}
        if name:
            tools = {key: value for key, value in tools.items() if key == name}
            if not tools:
                return {"ok": False, "status": "failed",
                        "summary": {"error": "no tool %r on the Linux side" % name,
                                    "known": sorted(report.tools)}, "artifacts": []}
        return {"ok": True,
                "summary": {"tools": tools, "cuda": report.cuda_version,
                            "counts": {status: sum(1 for item in tools.values()
                                                   if item["status"] == status)
                                       for status in ("ok", "missing", "not_runnable")},
                            "note": "status comes from executing the tool, not from the "
                                    "file name"},
                "artifacts": []}

    # -- trails ----------------------------------------------------------
    def trail_new(purpose: str = "", parent_trail: str = "") -> dict:
        try:
            trail = store.allocate(purpose=purpose, parent_trail=parent_trail)
        except (TrailError, OSError) as exc:
            return {"ok": False, "status": "failed", "summary": {"error": str(exc)},
                    "artifacts": []}
        log.append("trail", {"trail": trail.trail_id, "purpose": purpose,
                             "parent_trail": parent_trail, "root": str(trail.root)})
        return {"ok": True,
                "summary": {"trail": trail.trail_id, "run_id": run_id,
                            "path": str(trail.root), "purpose": purpose,
                            "parent_trail": parent_trail,
                            "hint": "write inputs with trail_write, then run container_exec"},
                "artifacts": []}

    def trail_write(trail: str, name: str, content: str = "", base64_data: str = "",
                    relation: str = "") -> dict:
        try:
            handle = store.open(trail)
            if base64_data:
                import base64
                payload = base64.b64decode(base64_data)
            else:
                payload = content
            record = handle.add_file(name, payload, kind="input", source="agent",
                                     relation=relation)
        except (TrailError, OSError, ValueError) as exc:
            return {"ok": False, "status": "failed",
                    "summary": {"error": str(exc), "trail": trail}, "artifacts": []}
        return {"ok": True,
                "summary": {"trail": trail, "name": record.name, "sha256": record.sha256,
                            "bytes": record.bytes, "path": str(handle.root / record.name)},
                "artifacts": []}

    def trail_read(trail: str, name: str, offset: int = 0, limit: int = 8000) -> dict:
        try:
            payload = store.open(trail).read_file(name, offset=offset, limit=limit)
        except (TrailError, OSError) as exc:
            return {"ok": False, "status": "failed",
                    "summary": {"error": str(exc), "trail": trail, "name": name},
                    "artifacts": []}
        return {"ok": True, "status": "success" if not payload["has_more"] else "partial",
                "summary": payload, "artifacts": []}

    def trail_list() -> dict:
        return {"ok": True, "summary": {"run_id": run_id, "trails": store.list_trails()},
                "artifacts": []}

    def trail_manifest(trail: str) -> dict:
        try:
            handle = store.open(trail)
        except (TrailError, OSError) as exc:
            return {"ok": False, "status": "failed", "summary": {"error": str(exc)},
                    "artifacts": []}
        return {"ok": True, "summary": handle.manifest(), "artifacts": []}

    # -- execution -------------------------------------------------------
    def container_exec(trail: str = "", image: str = "", argv: Optional[list] = None,
                       gpu: bool = True, gpus: str = "all", network: str = "none",
                       timeout_s: int = 600, pull_policy: str = "",
                       workdir: str = "/work", env: Optional[dict] = None,
                       memory: str = "", cpus: str = "", as_root: bool = False,
                       collect_paths: Optional[list] = None,
                       purpose: str = "") -> dict:
        command = [str(item) for item in (argv or [])]
        if not command:
            return {"ok": False, "status": "rejected",
                    "summary": {"error": "argv must be a non-empty array, e.g. "
                                         "[\"bash\",\"-lc\",\"nvcc -O2 poc.cu -o poc && ./poc\"]"},
                    "artifacts": []}
        if len(command) > MAX_ARGV:
            return {"ok": False, "status": "rejected",
                    "summary": {"error": "argv has %d elements, limit is %d"
                                         % (len(command), MAX_ARGV)}, "artifacts": []}
        try:
            handle = store.get_or_allocate(trail, purpose=purpose or " ".join(command)[:120])
        except (TrailError, OSError) as exc:
            return {"ok": False, "status": "failed", "summary": {"error": str(exc)},
                    "artifacts": []}
        try:
            result = backend.exec(handle, image=image, argv=command, gpu=gpu, gpus=gpus,
                                  network=network, timeout_s=timeout_s,
                                  pull_policy=pull_policy,
                                  workdir=workdir, env=env or {}, memory=memory, cpus=cpus,
                                  as_root=as_root, collect_paths=collect_paths or [])
        except BackendUnavailable as exc:
            log.append("exec", {"backend": backend.name, "trail": handle.trail_id,
                                "argv": command, "error": str(exc)}, status="dispatch_error")
            return {"ok": False, "status": "backend_unavailable",
                    "summary": {"error": str(exc), "trail": handle.trail_id,
                                "backend": backend.name}, "artifacts": []}
        except (BackendError, TrailError, OSError) as exc:
            log.append("exec", {"backend": backend.name, "trail": handle.trail_id,
                                "argv": command, "error": str(exc)}, status="failed")
            return {"ok": False, "status": "failed",
                    "summary": {"error": "%s: %s" % (type(exc).__name__, exc),
                                "trail": handle.trail_id}, "artifacts": []}

        stdout_ref = _save_text(artifacts, "stdout", "container-%s.out" % handle.trail_id,
                                result.stdout)
        stderr_ref = _save_text(artifacts, "stderr", "container-%s.err" % handle.trail_id,
                                result.stderr)
        record = log.append("exec", _evidence_payload(result, handle, backend,
                                                      stdout_ref, stderr_ref),
                            status=_status_for(result))
        summary = {
            "trail": handle.trail_id, "image": result.image,
            "image_digest": result.image_digest, "container_id": result.container_id[:12],
            "exit": result.exit_code, "termination": result.termination["kind"],
            "crash": result.termination["crash"], "timed_out": result.timed_out,
            "oom_killed": result.oom_killed, "duration_ms": result.duration_ms,
            "stdout": result.stdout[:6000], "stderr": result.stderr[:3000],
            "exec_dir": result.exec_dir,
            "signal_verified": result.signal_verified,
            "signaled": result.signaled,
            "signal": result.signal_name,
            "snapshot": {key: (result.snapshot.get(key) or [])[:20] if key != "unchanged_count"
                         else result.snapshot.get(key)
                         for key in ("created", "changed", "deleted", "unchanged_count",
                                     "skipped_symlinks")},
            "pull_policy": result.pull_policy,
            "image_pull": {k: result.image_pull.get(k) for k in
                           ("policy", "present_before", "pulled", "ok", "error")},
            "cleanup_ok": result.cleanup_ok,
            "cleanup": result.cleanup,
            "artifacts": [{"artifact": "trails/%s/%s" % (handle.trail_id, item.name),
                           "sha256": item.sha256, "bytes": item.bytes}
                          for item in result.artifacts if item.kind != "input"],
            "evidence": record.get("evidence_id"),
            "stdout_artifact": stdout_ref.get("artifact", ""),
            "note": _hint_for(result),
        }
        refs = [ref for ref in (stdout_ref, stderr_ref) if ref and ref.get("artifact")]
        return {"ok": result.ok, "status": _status_for(result), "summary": summary,
                "artifacts": refs}

    def gpu_cleanup(run_id_filter: str = "") -> dict:
        try:
            removed = backend.cleanup(run_id_filter or run_id)
        except (BackendUnavailable, BackendError) as exc:
            return {"ok": False, "status": "failed", "summary": {"error": str(exc)},
                    "artifacts": []}
        return {"ok": True, "summary": removed, "artifacts": []}

    return [
        ToolSpec(name="gpu_environment_probe", description=(
            "Report the real Linux GPU environment through WSL2 + Docker: distro, kernel, "
            "docker version, GPU model, compute capability, driver, CUDA toolkit and which "
            "tools actually execute. deep=true also proves GPU access from inside a "
            "container."),
            handler=gpu_environment_probe, category="gpu", source="backend:wsl2_docker", requires=["wsl.exe"],
            location="gpuvulnagent/backends/wsl_docker.py:probe",
            usage="gpu_environment_probe(deep=True)",
            parameters=[ParamSpec("deep", "boolean",
                                  "Also start a container and query the GPU there.",
                                  required=False, default=False)],
            side_effects=("starts_container",), tags=("gpu", "environment", "wsl", "docker")),

        ToolSpec(name="gpu_toolchain_discover", description=(
            "List CUDA/Linux tools on the execution side (nvcc, nvdisasm, cuobjdump) with the "
            "result of actually running each one: ok, missing, or present-but-not-runnable."),
            handler=gpu_toolchain_discover, category="gpu", source="backend:wsl2_docker", requires=["wsl.exe"],
            location="gpuvulnagent/backends/worker/gpu_worker.py:op_probe",
            usage="gpu_toolchain_discover(name='nvcc')",
            parameters=[ParamSpec("name", "string", "Only this tool.", required=False,
                                  default="")],
            tags=("gpu", "toolchain", "discovery")),

        ToolSpec(name="trail_new", description=(
            "Start a new experiment trail in this run (trail0, trail1, ...). Trails are "
            "never reused: re-running an experiment needs a new trail. Use parent_trail to "
            "record that this attempt derives from an earlier one."),
            handler=trail_new, category="gpu", source="backend:wsl2_docker",
            location="gpuvulnagent/backends/trails.py:allocate",
            parameters=[ParamSpec("purpose", "string", "What this attempt is for.",
                                  required=False, default=""),
                        ParamSpec("parent_trail", "string",
                                  "Trail this one derives from (e.g. 'trail0').",
                                  required=False, default="")],
            side_effects=("writes_workspace",), tags=("gpu", "trail", "evidence")),

        ToolSpec(name="trail_write", description=(
            "Write an input file (source, header, sample) into a trail with a readable "
            "name. The SHA256 is recorded in the trail manifest."),
            handler=trail_write, category="gpu", source="backend:wsl2_docker",
            location="gpuvulnagent/backends/trails.py:Trail.add_file",
            usage="trail_write(trail='trail0', name='poc.cu', content=open(...))",
            parameters=[ParamSpec("trail", "string", "Trail id."),
                        ParamSpec("name", "string", "Relative file name, e.g. poc.cu."),
                        ParamSpec("content", "string", "Text content.", required=False,
                                  default=""),
                        ParamSpec("base64_data", "string",
                                  "Binary content, base64 encoded (used instead of content).",
                                  required=False, default=""),
                        ParamSpec("relation", "string",
                                  "How this input was produced (e.g. mutated from trail0).",
                                  required=False, default="")],
            side_effects=("writes_workspace",), tags=("gpu", "trail", "input")),

        ToolSpec(name="trail_read", description=(
            "Read a file from a trail in chunks (inputs, outputs or logs). Returns total "
            "size, bytes read, next offset and the SHA256 of the whole file."),
            handler=trail_read, category="gpu", source="backend:wsl2_docker",
            location="gpuvulnagent/backends/trails.py:Trail.read_file",
            parameters=[ParamSpec("trail", "string", "Trail id."),
                        ParamSpec("name", "string", "File name inside the trail."),
                        ParamSpec("offset", "integer", "Byte offset.", required=False,
                                  default=0, minimum=0),
                        ParamSpec("limit", "integer", "Bytes to return.", required=False,
                                  default=8000, minimum=1, maximum=262144)],
            tags=("gpu", "trail", "read")),

        ToolSpec(name="trail_list", description="List the trails in this run and what each "
                                                "contains.",
                 handler=trail_list, category="gpu", source="backend:wsl2_docker",
                 location="gpuvulnagent/backends/trails.py:list_trails",
                 parameters=[], tags=("gpu", "trail")),

        ToolSpec(name="trail_manifest", description=(
            "Show one trail's manifest: every file with its SHA256, size and source, plus "
            "each recorded execution (argv, image, container, exit, termination)."),
            handler=trail_manifest, category="gpu", source="backend:wsl2_docker",
            location="gpuvulnagent/backends/trails.py:Trail.manifest",
            parameters=[ParamSpec("trail", "string", "Trail id.")],
            tags=("gpu", "trail", "evidence")),

        ToolSpec(name="container_exec", description=(
            "Run one argv inside a Docker container on the GPU machine. The trail directory "
            "is mounted at /work. Only files written with trail_write are staged, copied FLAT into "
            "/work (subdirectories are not preserved); files written with fs_write live in the "
            "agent workspace and are NOT visible inside the container. Everything written "
            "under /work is copied back as an artifact. Exit status, termination kind, image "
            "digest, pull policy and container id are recorded. Each call writes its own "
            "artifact snapshot under execs/execNN/, so an earlier binary or log is never "
            "overwritten. A supervisor records whether the program exited or was killed by "
            "a signal, so exit 139 alone is not treated as a crash. Timeouts kill the "
            "container. Use argv "
            "arrays: [\"nvcc\",\"-O2\",\"poc.cu\",\"-o\",\"poc\"] or for shell syntax "
            "[\"bash\",\"-lc\",\"...\"]. No privileged mode, no host mounts, no docker "
            "socket, network=none by default."),
            handler=container_exec, category="gpu", source="backend:wsl2_docker", requires=["wsl.exe"],
            location="gpuvulnagent/backends/wsl_docker.py:exec",
            usage="container_exec(trail='trail0', argv=['bash','-lc','nvcc -O2 poc.cu -o poc && ./poc'])",
            formats=(".cu", ".cubin", ".ptx", ".so", ".bin"),
            parameters=[ParamSpec("trail", "string",
                                  "Trail id; empty allocates a new trail.", required=False,
                                  default=""),
                        ParamSpec("image", "string",
                                  "Docker image; empty uses the configured default.",
                                  required=False, default=""),
                        ParamSpec("argv", "array", "Command and arguments, one element each.",
                                  items_type="string"),
                        ParamSpec("gpu", "boolean", "Request --gpus all.", required=False,
                                  default=True),
                        ParamSpec("gpus", "string",
                                  "Which GPUs docker exposes, e.g. 'all' or 'device=0'.",
                                  required=False, default="all"),
                        ParamSpec("network", "string", "Container network mode.",
                                  required=False, default="none",
                                  enum=("none", "bridge", "host")),
                        ParamSpec("timeout_s", "integer", "Kill the container after this.",
                                  required=False, default=600, minimum=1, maximum=3600),
                        ParamSpec("pull_policy", "string",
                                  "Image pull policy: missing (default), always, never. "
                                  "network=none limits the container, not the engine.",
                                  required=False, default="missing",
                                  enum=("missing", "always", "never")),
                        ParamSpec("workdir", "string", "Working directory inside the container.",
                                  required=False, default="/work"),
                        ParamSpec("env", "object",
                                  "Environment variables. Secret-shaped names are refused.",
                                  required=False, default=None),
                        ParamSpec("memory", "string", "Memory limit, e.g. '8g'.",
                                  required=False, default=""),
                        ParamSpec("cpus", "string", "CPU limit, e.g. '4'.",
                                  required=False, default=""),
                        ParamSpec("as_root", "boolean",
                                  "Run as root inside the container (default: the WSL user).",
                                  required=False, default=False),
                        ParamSpec("collect_paths", "array",
                                  "Extra absolute paths inside the container to copy out.",
                                  required=False, items_type="string"),
                        ParamSpec("purpose", "string",
                                  "Why this experiment runs (recorded on a new trail).",
                                  required=False, default="")],
            side_effects=("executes", "starts_container", "writes_workspace"),
            tags=("gpu", "docker", "execution", "cuda")),

        ToolSpec(name="gpu_cleanup", description=(
            "Force-remove any container still labelled with this run id. Normal runs clean "
            "up after themselves; this is the recovery path after an interruption."),
            handler=gpu_cleanup, category="gpu", source="backend:wsl2_docker", requires=["wsl.exe"],
            location="gpuvulnagent/backends/worker/gpu_worker.py:op_cleanup",
            parameters=[ParamSpec("run_id_filter", "string",
                                  "Remove containers for this run id instead of the current "
                                  "run.", required=False, default="")],
            side_effects=("starts_container",), tags=("gpu", "docker", "cleanup")),
    ]


# --------------------------------------------------------------------------- helpers
def _probe_summary(payload: dict) -> dict:
    gpu = payload.get("gpu", {})
    return {
        "available": payload.get("available"),
        "distro": "%s (%s)" % (payload.get("distro", ""), payload.get("distro_version", "")),
        "kernel": payload.get("kernel", ""),
        "docker": payload.get("docker", {}).get("version", ""),
        "gpu": "%s %s" % (gpu.get("name", "unknown"), gpu.get("memory", "")),
        "compute_capability": gpu.get("compute_capability", ""),
        "driver": gpu.get("driver", ""),
        "cuda": payload.get("cuda", {}).get("toolkit", ""),
        "tools": {name: item.get("status") for name, item in
                  (payload.get("tools") or {}).items()},
        "gpu_in_container": payload.get("gpu_in_container", {}),
        "problems": payload.get("problems", []),
        "images": (payload.get("images") or [])[:8],
    }


def _evidence_payload(result, trail: Trail, backend, stdout_ref: dict,
                      stderr_ref: dict) -> dict:
    return {
        "tool_name": "container_exec",
        "via": "container_exec",
        "backend": backend.name,
        "trail": trail.trail_id,
        "image": result.image,
        "image_id": result.image_id,
        "image_digest": result.image_digest,
        "container_id": result.container_id,
        "container_name": result.container_name,
        "argv": result.argv,
        "cwd": result.cwd,
        "workdir": result.workdir,
        "network": result.network,
        "gpu": result.gpu,
        "gpu_name": result.gpu_name,
        "cuda": result.cuda_version,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "duration_ms": result.duration_ms,
        "exit": result.exit_code,
        "timed_out": result.timed_out,
        "oom_killed": result.oom_killed,
        "state": result.state,
        "termination": result.termination,
        "crash": result.termination.get("crash", False),
        "signal_verified": result.signal_verified,
        "signaled": result.signaled,
        "signal": result.signal_name,
        "exec_dir": result.exec_dir,
        "snapshot": {key: len(result.snapshot.get(key) or []) if key != "unchanged_count"
                     else result.snapshot.get(key)
                     for key in ("created", "changed", "deleted", "skipped_symlinks",
                                 "unchanged_count")},
        "pull_policy": result.pull_policy,
        "image_pull": dict(result.image_pull),
        "cleanup": dict(result.cleanup),
        "cleanup_ok": result.cleanup_ok,
        "stdout_preview": result.stdout[:4000],
        "stderr_preview": result.stderr[:2000],
        "stdout_bytes": len(result.stdout),
        "stderr_bytes": len(result.stderr),
        "stdout_artifact": stdout_ref,
        "stderr_artifact": stderr_ref,
        "artifact_hashes": [{"name": item.name, "sha256": item.sha256,
                             "bytes": item.bytes, "kind": item.kind}
                            for item in result.artifacts],
        "trail_manifest": "trails/%s/manifest.json" % trail.trail_id,
    }


def _status_for(result) -> str:
    kind = result.termination.get("kind", "")
    if kind == "success":
        return "success"
    if kind == "timeout":
        return "timeout"
    if kind in ("not_found", "not_runnable"):
        return "launch_failed"
    if kind == "container_error":
        return "container_error"
    if kind == "oom_killed":
        return "oom_killed"
    if result.termination.get("crash"):
        return "crashed"
    return "failed"


def _hint_for(result) -> str:
    kind = result.termination.get("kind", "")
    return {
        "timeout": "the harness killed the container; this is a budget event, not a bug",
        "oom_killed": "the kernel OOM killer ended the process; raise memory or reduce input",
        "not_found": "the binary or command does not exist in this image",
        "not_runnable": "the command exists but cannot be executed in this image",
        "container_error": "docker failed to run the container; read stderr",
        "error_exit": "normal non-zero exit: read stdout/stderr before concluding anything",
    }.get(kind, "")


def _save_text(artifacts, category: str, name: str, text: str) -> dict:
    if artifacts is None or not text:
        return {}
    try:
        payload, _ = redact(text)
        return artifacts.save(category, name, payload)
    except OSError:
        return {}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")
