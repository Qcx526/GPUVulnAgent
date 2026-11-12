# -*- coding: utf-8 -*-
"""Windows side of the execution backend: WSL launcher + Docker orchestration.

The agent runs on Windows; the only Linux it can reach is WSL2. This module is the bridge
and it is deliberately thin:

    Windows agent  ->  wsl.exe -d <distro> -u <user> -- python3 worker.py
                   ->  one JSON request on stdin, one JSON response on stdout
    worker (Linux)  ->  docker run <allow-listed options> -- <argv array>

Nothing is passed as a shell string. The request is a dict, the container command is an
argv array, and every Docker option is chosen by the worker from an allowlist, so an
argument containing spaces, quotes or ``;`` cannot become a second command.

What this module adds on top of the worker:

* provisioning: the worker file is copied into WSL and its SHA256 is verified there;
* trails: each attempt owns a directory, and every copied artifact is re-hashed on the
  Windows side so a truncated transfer is caught instead of trusted;
* classification: docker exit codes are mapped to explicit termination kinds, so a timeout
  or an OOM kill is never reported as a crash.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional

from ..evidence.container_outcome import classify_container_exit
from ..evidence.hashing import sha256_file
from .base import Artifact, BackendError, BackendUnavailable, EnvironmentReport, ExecResult, \
    ToolStatus
from .trails import Trail, TrailError

WORKER_SOURCE = Path(__file__).resolve().parent / "worker" / "gpu_worker.py"
DEFAULT_IMAGE = "nvidia/cuda:12.8.0-devel-ubuntu22.04"
BEGIN = "GPUVULNAGENT_JSON_BEGIN"
END = "GPUVULNAGENT_JSON_END"
SECRET_ENV = re.compile(r"(API[_-]?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", re.I)


class WslConfig:
    """Where the Linux side lives. Defaults match the machine this backend was built on."""

    def __init__(self, *, distro: str = "Ubuntu-22.04", user: str = "pocdev",
                 worker_root: str = "/home/pocdev/gpuvulnagent-worker",
                 image: str = DEFAULT_IMAGE, wsl_exe: str = "",
                 call_timeout: int = 300) -> None:
        self.distro = distro
        self.user = user
        self.worker_root = worker_root.rstrip("/") or "/home/pocdev/gpuvulnagent-worker"
        self.image = image
        self.wsl_exe = wsl_exe or shutil.which("wsl.exe") or r"C:\Windows\System32\wsl.exe"
        self.call_timeout = call_timeout

    @property
    def worker_path(self) -> str:
        return self.worker_root + "/worker.py"

    def describe(self) -> dict:
        return {"distro": self.distro, "user": self.user,
                "worker_root": self.worker_root, "worker_path": self.worker_path,
                "default_image": self.image, "wsl_exe": self.wsl_exe}

    @classmethod
    def from_settings(cls, settings) -> "WslConfig":
        backend = getattr(getattr(settings, "settings", settings), "backend", None)
        if backend is None:
            return cls()
        return cls(distro=backend.wsl_distro, user=backend.wsl_user,
                   worker_root=backend.wsl_worker_root, image=backend.gpu_image,
                   call_timeout=backend.call_timeout)


class WslDockerBackend:
    name = "wsl2_docker"

    def __init__(self, config: Optional[WslConfig] = None, *,
                 probe_cache_seconds: int = 30) -> None:
        self.config = config or WslConfig()
        self.probe_cache_seconds = probe_cache_seconds
        self._probe_cache: Optional[tuple] = None
        self._provisioned = False
        self._worker_sha = sha256_file(WORKER_SOURCE) or ""

    # -- transport -------------------------------------------------------
    def available(self) -> bool:
        return Path(self.config.wsl_exe).is_file() or shutil.which("wsl.exe") is not None

    def _wsl(self, argv: List[str], *, timeout: int, stdin: Optional[str] = None) -> dict:
        if not self.available():
            raise BackendUnavailable("wsl.exe is not available on this host")
        command = [self.config.wsl_exe, "-d", self.config.distro, "-u", self.config.user,
                   "--"] + argv
        # Bytes, not str: the pipes are binary, and a str payload would be rejected by the
        # writer thread, leaving stdin open and the call hanging until the timeout.
        payload = stdin.encode("utf-8") if isinstance(stdin, str) else stdin
        try:
            completed = subprocess.run(command, input=payload, capture_output=True,
                                       timeout=timeout, cwd=os.environ.get("SystemRoot",
                                                                          r"C:\Windows"))
        except FileNotFoundError as exc:
            raise BackendUnavailable("wsl.exe could not be started: %s" % exc) from None
        except subprocess.TimeoutExpired:
            raise BackendError("wsl call timed out after %ss: %s" % (timeout, argv)) from None
        stdout = (completed.stdout or b"").replace(b"\x00", b"").decode("utf-8", "replace")
        stderr = (completed.stderr or b"").replace(b"\x00", b"").decode("utf-8", "replace")
        return {"exit": completed.returncode, "stdout": stdout, "stderr": stderr}

    def _call(self, op: str, params: Optional[dict] = None, *, timeout: int = 120) -> dict:
        self._provision()
        request = json.dumps({"protocol": "gpuvulnagent-worker/1", "op": op,
                              "params": params or {}}, ensure_ascii=False)
        result = self._wsl(["/usr/bin/python3", self.config.worker_path],
                           timeout=timeout, stdin=request)
        payload = _extract(result["stdout"])
        if payload is None:
            raise BackendError("worker returned no structured response for %r (exit=%s): %s"
                               % (op, result["exit"],
                                  (result["stderr"] or result["stdout"])[:400]))
        if not payload.get("ok"):
            raise BackendError("worker %r failed: %s" % (op, payload.get("error", "unknown")))
        return payload.get("result") or {}

    # -- provisioning ----------------------------------------------------
    def _provision(self) -> None:
        if self._provisioned:
            return
        ping = self._ping_raw()
        if ping and ping.get("worker_sha256") == self._worker_sha:
            self._provisioned = True
            return
        self._wsl(["mkdir", "-p", self.config.worker_root], timeout=60)
        payload = WORKER_SOURCE.read_bytes()
        written = self._write_worker(payload)
        if not written:
            raise BackendError("could not place the worker at %s" % self.config.worker_path)
        check = self._ping_raw()
        if not check:
            raise BackendError("worker was written but does not answer ping")
        if check.get("worker_sha256") and check["worker_sha256"] != self._worker_sha:
            raise BackendError("worker hash mismatch inside WSL: %s != %s"
                               % (check["worker_sha256"], self._worker_sha))
        self._provisioned = True

    def _write_worker(self, payload: bytes) -> bool:
        unc = self._unc_path(self.config.worker_path)
        if unc is not None:
            try:
                unc.parent.mkdir(parents=True, exist_ok=True)
                unc.write_bytes(payload)
                if sha256_file(unc) == self._worker_sha:
                    return True
            except OSError:
                pass
        # Fallback: stream the file through the worker's own interpreter.
        script = ("import sys;open(sys.argv[1],'wb').write(sys.stdin.buffer.read())")
        result = self._wsl(["/usr/bin/python3", "-c", script, self.config.worker_path],
                           timeout=120, stdin=payload.decode("utf-8"))
        return result["exit"] == 0

    def _unc_path(self, linux_path: str) -> Optional[Path]:
        """\\\\wsl.localhost\\<distro>\\<linux path> when the share is reachable."""
        for host in ("wsl.localhost", "wsl$"):
            candidate = Path(r"\\%s\%s%s" % (host, self.config.distro,
                                             linux_path.replace("/", "\\")))
            if candidate.parent.exists():
                return candidate
        return None

    def _ping_raw(self) -> dict:
        result = self._wsl(["/usr/bin/python3", self.config.worker_path], timeout=60,
                           stdin=json.dumps({"op": "ping"}))
        payload = _extract(result["stdout"])
        if payload and payload.get("ok"):
            return payload.get("result") or {}
        return {}

    # -- operations ------------------------------------------------------
    def ping(self) -> dict:
        return self._call("ping", timeout=60)

    def probe(self, *, deep: bool = False, force: bool = False) -> EnvironmentReport:
        if not force and self._probe_cache:
            stamp, report = self._probe_cache
            if time.time() - stamp < self.probe_cache_seconds and (deep is False):
                return report
        raw = self._call("probe", {"deep": deep, "image": self.config.image}, timeout=300)
        report = _to_report(raw, self.name)
        if deep:
            self._probe_cache = (time.time(), report)
        elif not self._probe_cache:
            self._probe_cache = (time.time(), report)
        return report

    def exec(self, trail: Trail, *, image: str = "", argv: List[str],
             gpu: bool = True, gpus: str = "all", network: str = "none",
             timeout_s: int = 600, env: Optional[Dict[str, str]] = None,
             workdir: str = "/work", memory: str = "", cpus: str = "",
             collect_paths: Optional[List[str]] = None,
             as_root: bool = False) -> ExecResult:
        image = image or self.config.image
        if not image or not re.match(r"^[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,200}$", image):
            raise BackendError("image name is not acceptable: %r" % image)
        if not argv:
            raise BackendError("argv must not be empty")
        refused = [key for key in (env or {}) if SECRET_ENV.search(key or "")]
        if refused:
            raise BackendError("refusing to put secret-shaped variables into a container: %s"
                               % ", ".join(sorted(refused)))

        inputs = sorted(path.relative_to(trail.inputs).as_posix()
                        for path in trail.inputs.rglob("*") if path.is_file())
        run_id, trail_id = trail.run_id, trail.trail_id
        wsl_trail = windows_to_wsl(trail.root)
        prepare = self._call("prepare", {
            "run_id": run_id, "trail": trail_id,
            "source_dir": windows_to_wsl(trail.inputs), "files": inputs}, timeout=120)

        index = len(trail.executions)
        raw = self._call("exec", {
            "run_id": run_id, "trail": trail_id, "image": image, "argv": list(argv),
            "gpu": bool(gpu), "gpus": gpus, "network": network, "timeout_s": int(timeout_s),
            "env": dict(env or {}), "workdir": workdir, "memory": memory, "cpus": cpus,
            "collect_paths": list(collect_paths or []), "as_root": bool(as_root),
            "host_output_dir": wsl_trail, "exec_index": index,
        }, timeout=int(timeout_s) + 420)

        termination = classify_container_exit(
            raw.get("exit_code"), timed_out=bool(raw.get("timed_out")),
            oom_killed=bool(raw.get("oom_killed")), state=raw.get("state", ""),
            started=bool(raw.get("container_id")) or raw.get("exit_code") is not None,
            daemon_error=_daemon_error(raw.get("stderr", "")))
        result = ExecResult(
            ok=termination["kind"] == "success",
            exit_code=raw.get("exit_code"), timed_out=bool(raw.get("timed_out")),
            oom_killed=bool(raw.get("oom_killed")), termination=termination,
            duration_ms=int(raw.get("duration_ms") or 0),
            started_at=raw.get("started_at", ""), finished_at=raw.get("finished_at", ""),
            image=raw.get("image", image), image_id=raw.get("image_id", ""),
            image_digest=raw.get("image_digest", ""),
            container_id=raw.get("container_id", ""),
            container_name=raw.get("container_name", ""), argv=list(argv),
            cwd=workdir, workdir=workdir, network=raw.get("network", network),
            gpu=bool(raw.get("gpu")),
            gpu_name=self._gpu_name(), cuda_version=self._cuda_version(),
            stdout=raw.get("stdout", ""), stderr=raw.get("stderr", ""),
            trail=trail_id, run_id=run_id, state=raw.get("state", ""),
            error="" if raw.get("exit_code") is not None else raw.get("docker_error", ""))

        self._register_artifacts(trail, raw.get("copied_to_host") or [], index)
        result.artifacts = [Artifact(name=item.name, sha256=item.sha256, bytes=item.bytes,
                                     kind=item.kind, source=item.source)
                            for item in trail.files]
        result.stdout_artifact = _log_ref(trail, "logs/stdout.txt" if index == 0
                                          else "logs/stdout.%d.txt" % index)
        result.stderr_artifact = _log_ref(trail, "logs/stderr.txt" if index == 0
                                          else "logs/stderr.%d.txt" % index)
        self._write_result(trail, result, index)
        self._append_execution(trail, result, raw)
        return result

    def _register_artifacts(self, trail: Trail, copied: List[dict], index: int) -> None:
        input_hashes = {item.sha256: item.name for item in trail.files if item.kind == "input"}
        for item in copied:
            name = item.get("name", "")
            if not name:
                continue
            local = trail.root / name
            if not local.is_file():
                raise BackendError("worker reported %r but it is not on disk" % name)
            actual = sha256_file(local)
            if item.get("sha256") and actual != item["sha256"]:
                raise BackendError("artifact %r changed in transfer (%s != %s)"
                                   % (name, actual, item["sha256"]))
            if name.startswith("logs/"):
                kind = "log"
            elif actual in input_hashes:
                # The mounted work directory still holds the staged inputs; they are not
                # new findings, so they are recorded as inputs rather than as products.
                kind = "input"
            else:
                kind = "output"
            trail.register_file(name, kind=kind, source="container",
                                relation="execution %d" % index)

    def _write_result(self, trail: Trail, result: ExecResult, index: int) -> None:
        payload = result.to_dict()
        payload["execution_index"] = index
        name = "result.json" if index == 0 else "result.%d.json" % index
        target = trail.root / name
        if target.exists():
            name = "result.%d.%d.json" % (index, int(time.time()))
            target = trail.root / name
        target.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
        trail.register_file(name, kind="log", source="backend",
                            relation="execution %d" % index)

    def _append_execution(self, trail: Trail, result: ExecResult, raw: dict) -> None:
        trail.record_execution({
            "argv": result.argv, "image": result.image, "image_id": result.image_id,
            "image_digest": result.image_digest, "container_id": result.container_id,
            "exit_code": result.exit_code, "termination": result.termination["kind"],
            "crash": result.termination["crash"], "timed_out": result.timed_out,
            "oom_killed": result.oom_killed, "duration_ms": result.duration_ms,
            "started_at": result.started_at, "finished_at": result.finished_at,
            "network": result.network, "gpu": result.gpu,
            "stdout": "logs/stdout.txt" if len(trail.executions) == 0
                      else "logs/stdout.%d.txt" % len(trail.executions),
            "stderr": "logs/stderr.txt" if len(trail.executions) == 0
                      else "logs/stderr.%d.txt" % len(trail.executions),
            "artifacts": [item.get("name") for item in raw.get("copied_to_host") or []],
        })

    def _gpu_name(self) -> str:
        report = self.probe()
        return report.gpu_name

    def _cuda_version(self) -> str:
        report = self.probe()
        return report.cuda_version

    def cleanup(self, run_id: str) -> dict:
        return self._call("cleanup", {"run_id": run_id}, timeout=180)

    def describe(self) -> dict:
        return {"backend": self.name, **self.config.describe(),
                "worker_sha256": self._worker_sha}


# --------------------------------------------------------------------------- helpers
def windows_to_wsl(path) -> str:
    """``F:\\qcx\\x`` -> ``/mnt/f/qcx/x``. Used only for inputs and collected artifacts."""
    raw = str(path).replace("\\", "/")
    match = re.match(r"^([A-Za-z]):/(.*)$", raw)
    if match:
        return "/mnt/%s/%s" % (match.group(1).lower(), match.group(2))
    if raw.startswith("/"):
        return raw
    raise TrailError("cannot map a Windows path into WSL: %r" % path)


def _extract(stdout: str) -> Optional[dict]:
    if not stdout:
        return None
    start = stdout.find(BEGIN)
    end = stdout.find(END, start + 1) if start >= 0 else -1
    if start < 0 or end < 0:
        return None
    try:
        return json.loads(stdout[start + len(BEGIN):end])
    except ValueError:
        return None


def _to_report(raw: dict, backend_name: str) -> EnvironmentReport:
    docker = raw.get("docker") or {}
    gpu = raw.get("gpu") or {}
    tools = {}
    for name, item in (raw.get("tools") or {}).items():
        tools[name] = ToolStatus(name=name, status=item.get("status", "missing"),
                                 path=item.get("path", ""), version=item.get("version", ""),
                                 detail=item.get("detail", ""))
    available = bool(docker.get("running")) and not gpu.get("error")
    return EnvironmentReport(
        backend=backend_name, available=available,
        distro=raw.get("distro", ""), distro_version=raw.get("distro_version", ""),
        kernel=raw.get("kernel", ""), user=raw.get("user", ""),
        docker_version=(docker.get("version") or "").strip(),
        docker_running=bool(docker.get("running")),
        gpu_name=gpu.get("name", ""), gpu_memory=gpu.get("memory", ""),
        compute_capability=gpu.get("compute_capability", ""),
        driver_version=gpu.get("driver", ""),
        cuda_version=(raw.get("cuda") or {}).get("toolkit", ""),
        tools=tools, images=list(raw.get("images") or []),
        gpu_in_container=dict(raw.get("gpu_in_container") or {}),
        problems=list(raw.get("problems") or []), raw=raw)


def _log_ref(trail: Trail, name: str) -> dict:
    path = trail.root / name
    if not path.is_file():
        return {}
    return {"artifact": name, "sha256": sha256_file(path), "bytes": path.stat().st_size}


def _daemon_error(stderr: str) -> bool:
    """Docker/runtime failures that happen before the target program runs."""
    markers = ("error response from daemon", "oci runtime create failed", "runc create failed",
               "failed to create task for container", "nvidia-container-cli",
               "is not running", "no such image", "pull access denied")
    lowered = (stderr or "").lower()
    return any(marker in lowered for marker in markers)


def worker_digest() -> str:
    return hashlib.sha256(WORKER_SOURCE.read_bytes()).hexdigest()
