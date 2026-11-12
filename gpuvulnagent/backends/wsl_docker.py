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

What this module adds on top of the worker (P19-R1):

* provisioning: worker and supervisor sources are copied into WSL and verified by SHA256;
* trails: each execution owns ``execs/execNN/`` and never writes into an earlier one;
* artifact integrity: every copied file is re-hashed here, and a symlink is never accepted
  as an artifact;
* classification: the supervisor's wait status decides signalled-vs-exited; the docker
  exit code alone never does.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional

from ..evidence.container_outcome import classify_container_result
from ..evidence.hashing import sha256_file
from .base import Artifact, BackendError, BackendUnavailable, EnvironmentReport, ExecResult, \
    ToolStatus
from .trails import Trail, TrailError

WORKER_SOURCE = Path(__file__).resolve().parent / "worker" / "gpu_worker.py"
SUPERVISOR_SOURCE = Path(__file__).resolve().parent / "worker" / "gpuvuln_supervise.c"
DEFAULT_IMAGE = "nvidia/cuda:12.8.0-devel-ubuntu22.04"
PROTOCOL = "gpuvulnagent-worker/2"
BEGIN = "GPUVULNAGENT_JSON_BEGIN"
END = "GPUVULNAGENT_JSON_END"
SECRET_ENV = re.compile(r"(API[_-]?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", re.I)
IMAGE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,200}$")
PULL_POLICIES = ("missing", "always", "never")


class WslConfig:
    """Where the Linux side lives. Defaults match the machine this backend was built on."""

    def __init__(self, *, distro: str = "Ubuntu-22.04", user: str = "pocdev",
                 worker_root: str = "/home/pocdev/gpuvulnagent-worker",
                 image: str = DEFAULT_IMAGE, wsl_exe: str = "",
                 call_timeout: int = 300, pull_policy: str = "missing") -> None:
        self.distro = distro
        self.user = user
        self.worker_root = worker_root.rstrip("/") or "/home/pocdev/gpuvulnagent-worker"
        self.image = image
        self.wsl_exe = wsl_exe or shutil.which("wsl.exe") or r"C:\Windows\System32\wsl.exe"
        self.call_timeout = call_timeout
        self.pull_policy = pull_policy if pull_policy in PULL_POLICIES else "missing"

    @property
    def worker_path(self) -> str:
        return self.worker_root + "/worker.py"

    @property
    def supervisor_source_path(self) -> str:
        return self.worker_root + "/gpuvuln_supervise.c"

    def describe(self) -> dict:
        return {"distro": self.distro, "user": self.user,
                "worker_root": self.worker_root, "worker_path": self.worker_path,
                "default_image": self.image, "wsl_exe": self.wsl_exe,
                "call_timeout": self.call_timeout, "pull_policy": self.pull_policy}

    @classmethod
    def from_settings(cls, settings) -> "WslConfig":
        backend = getattr(getattr(settings, "settings", settings), "backend", None)
        if backend is None:
            return cls()
        return cls(distro=backend.wsl_distro, user=backend.wsl_user,
                   worker_root=backend.wsl_worker_root, image=backend.gpu_image,
                   call_timeout=backend.call_timeout, pull_policy=backend.pull_policy)


class WslDockerBackend:
    name = "wsl2_docker"

    def __init__(self, config: Optional[WslConfig] = None, *,
                 probe_cache_seconds: int = 30) -> None:
        self.config = config or WslConfig()
        self.probe_cache_seconds = probe_cache_seconds
        self._probe_cache: Optional[tuple] = None
        self._provisioned = False
        self._worker_sha = sha256_file(WORKER_SOURCE) or ""
        self._supervisor_sha = sha256_file(SUPERVISOR_SOURCE) or ""
        self._last_wsl: dict = {}

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
        self._last_wsl = {"exit": completed.returncode, "stdout": stdout, "stderr": stderr}
        return self._last_wsl

    def _call(self, op: str, params: Optional[dict] = None,
              *, timeout: Optional[int] = None) -> dict:
        """One structured round trip. ``timeout`` defaults to the configured call timeout."""
        self._provision()
        limit = int(timeout or self.config.call_timeout)
        request = json.dumps({"protocol": PROTOCOL, "op": op, "params": params or {}},
                             ensure_ascii=False)
        result = self._wsl(["/usr/bin/python3", self.config.worker_path],
                           timeout=limit, stdin=request)
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
        if not self._write_remote(self.config.worker_path, WORKER_SOURCE, self._worker_sha):
            raise BackendError("could not place the worker at %s" % self.config.worker_path)
        # The supervisor source is only data until the worker compiles it; a failure here
        # is reported later as "signal_verified=false", never silently ignored.
        self._write_remote(self.config.supervisor_source_path, SUPERVISOR_SOURCE,
                           self._supervisor_sha)
        check = self._ping_raw()
        if not check:
            # The stderr of the failed attempt is the difference between "something is
            # wrong" and "your WSL_USER does not exist".
            detail = " ".join((self._last_wsl.get("stderr") or "").split())[:300]
            raise BackendError("worker was written but does not answer ping%s"
                               % (": " + detail if detail else ""))
        if check.get("worker_sha256") and check["worker_sha256"] != self._worker_sha:
            raise BackendError("worker hash mismatch inside WSL: %s != %s"
                               % (check["worker_sha256"], self._worker_sha))
        self._provisioned = True

    def _write_remote(self, linux_path: str, source: Path, expected: str) -> bool:
        payload = source.read_bytes()
        unc = self._unc_path(linux_path)
        if unc is not None:
            try:
                unc.parent.mkdir(parents=True, exist_ok=True)
                unc.write_bytes(payload)
                if sha256_file(unc) == expected:
                    return True
            except OSError:
                pass
        # Fallback: stream the file through the worker's own interpreter.
        script = "import sys;open(sys.argv[1],'wb').write(sys.stdin.buffer.read())"
        result = self._wsl(["/usr/bin/python3", "-c", script, linux_path],
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
        result = self._wsl(["/usr/bin/python3", self.config.worker_path],
                           timeout=self.config.call_timeout,
                           stdin=json.dumps({"op": "ping"}))
        payload = _extract(result["stdout"])
        if payload and payload.get("ok"):
            return payload.get("result") or {}
        return {}

    # -- operations ------------------------------------------------------
    def ping(self) -> dict:
        return self._call("ping", timeout=60)

    def supervisor(self) -> dict:
        """Build (or reuse) the wait-status supervisor inside WSL."""
        return self._call("supervisor", {}, timeout=240)

    def probe(self, *, deep: bool = False, force: bool = False) -> EnvironmentReport:
        if not force and self._probe_cache:
            stamp, report = self._probe_cache
            if time.time() - stamp < self.probe_cache_seconds and (deep is False):
                return report
        raw = self._call("probe", {"deep": deep, "image": self.config.image,
                                   "with_supervisor": deep},
                         timeout=max(self.config.call_timeout, 300))
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
             collect_paths: Optional[List[str]] = None, as_root: bool = False,
             pull_policy: str = "", supervise: bool = True) -> ExecResult:
        image = image or self.config.image
        if not image or not IMAGE_PATTERN.match(image):
            raise BackendError("image name is not acceptable: %r" % image)
        pull_policy = pull_policy or self.config.pull_policy
        if pull_policy not in PULL_POLICIES:
            raise BackendError("pull_policy must be one of %s" % ", ".join(PULL_POLICIES))
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
        index = len(trail.executions)
        self._call("prepare", {"run_id": run_id, "trail": trail_id,
                               "source_dir": windows_to_wsl(trail.inputs),
                               "files": inputs}, timeout=120)
        raw = self._call("exec", {
            "run_id": run_id, "trail": trail_id, "image": image, "argv": list(argv),
            "gpu": bool(gpu), "gpus": gpus, "network": network, "timeout_s": int(timeout_s),
            "env": dict(env or {}), "workdir": workdir, "memory": memory, "cpus": cpus,
            "collect_paths": list(collect_paths or []), "as_root": bool(as_root),
            "pull_policy": pull_policy, "supervise": bool(supervise),
            "host_output_dir": wsl_trail, "exec_index": index,
        }, timeout=int(timeout_s) + 900)

        supervision = raw.get("supervision") or {}
        termination = classify_container_result(
            exit_code=raw.get("exit_code"), timed_out=bool(raw.get("timed_out")),
            oom_killed=bool(raw.get("oom_killed")), state=raw.get("state", ""),
            started=bool(raw.get("container_id")) or raw.get("exit_code") is not None,
            daemon_error=_daemon_error(raw.get("stderr", "")),
            supervision=supervision)
        result = ExecResult(
            ok=termination["kind"] == "success",
            exit_code=raw.get("exit_code"), timed_out=bool(raw.get("timed_out")),
            oom_killed=bool(raw.get("oom_killed")), termination=termination,
            duration_ms=int(raw.get("duration_ms") or 0),
            started_at=raw.get("started_at", ""), finished_at=raw.get("finished_at", ""),
            image=raw.get("image", image), image_id=raw.get("image_id", ""),
            image_digest=raw.get("image_digest", ""), pull_policy=pull_policy,
            image_pull=dict(raw.get("image_pull") or {}),
            container_id=raw.get("container_id", ""),
            container_name=raw.get("container_name", ""), argv=list(argv),
            cwd=workdir, workdir=workdir, network=raw.get("network", network),
            gpu=bool(raw.get("gpu")),
            gpu_name=self._cached_field("gpu_name"),
            cuda_version=self._cached_field("cuda_version"),
            stdout=raw.get("stdout", ""), stderr=raw.get("stderr", ""),
            trail=trail_id, exec_index=index, exec_dir="execs/exec%02d" % index,
            snapshot=dict(raw.get("snapshot") or {}), supervision=dict(supervision),
            signal_verified=bool(termination.get("signal_verified")),
            signaled=bool(termination.get("signaled")),
            signal=int(termination.get("signal") or 0),
            signal_name=termination.get("signal_name", ""),
            cleanup=dict(raw.get("cleanup") or {}),
            cleanup_ok=bool(raw.get("cleanup_ok", False)),
            run_id=run_id, state=raw.get("state", ""),
            error=raw.get("error", "") or "")

        self._accept_artifacts(trail, raw.get("copied_to_host") or [], index)
        result.artifacts = [Artifact(name=item.name, sha256=item.sha256, bytes=item.bytes,
                                     kind=item.kind, source=item.source)
                            for item in trail.files
                            if item.name.startswith(result.exec_dir)]
        result.stdout_artifact = _log_ref(trail, "%s/logs/docker_run.stdout" % result.exec_dir)
        result.stderr_artifact = _log_ref(trail, "%s/logs/docker_run.stderr" % result.exec_dir)
        self._write_result(trail, result, raw, index)
        self._append_execution(trail, result, raw, index)
        return result

    def _accept_artifacts(self, trail: Trail, copied: List[dict], index: int) -> None:
        input_hashes = {item.sha256: item.name for item in trail.files if item.kind == "input"}
        for item in copied:
            name = item.get("name", "")
            if not name:
                continue
            local = trail.root / name
            if local.is_symlink() or not local.is_file():
                raise BackendError("artifact %r is missing or is a symlink" % name)
            info = local.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise BackendError("artifact %r is not a regular file" % name)
            actual = sha256_file(local)
            if item.get("sha256") and actual != item["sha256"]:
                raise BackendError("artifact %r changed in transfer (%s != %s)"
                                   % (name, actual, item["sha256"]))
            if name.endswith("/logs/" + Path(name).name):
                kind = "log"
            elif actual in input_hashes:
                kind = "input"
            else:
                kind = "output"
            trail.register_file(name, kind=kind, source="container",
                                relation="execution %d" % index)

    def _write_result(self, trail: Trail, result: ExecResult, raw: dict, index: int) -> None:
        directory = trail.root / ("execs/exec%02d" % index)
        directory.mkdir(parents=True, exist_ok=True)
        payload = result.to_dict()
        payload["docker_argv"] = raw.get("docker_argv")
        payload["collect_paths"] = raw.get("collect_paths")
        payload["worker_error"] = raw.get("error", "")
        target = directory / "result.json"
        target.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
        snapshot = raw.get("snapshot") or {}
        if snapshot:
            (directory / "snapshot.json").write_text(
                json.dumps(snapshot, ensure_ascii=False, indent=1), encoding="utf-8")
            trail.register_file("execs/exec%02d/snapshot.json" % index, kind="log",
                                source="backend", relation="execution %d" % index)
        trail.register_file("execs/exec%02d/result.json" % index, kind="log",
                            source="backend", relation="execution %d" % index)

    def _append_execution(self, trail: Trail, result: ExecResult, raw: dict,
                          index: int) -> None:
        trail.record_execution({
            "argv": result.argv, "image": result.image, "image_id": result.image_id,
            "image_digest": result.image_digest, "pull_policy": result.pull_policy,
            "image_pull": result.image_pull,
            "container_id": result.container_id, "exit_code": result.exit_code,
            "termination": result.termination.get("kind"),
            "crash": result.termination.get("crash"),
            "signal_verified": result.signal_verified,
            "signaled": result.signaled, "signal": result.signal_name,
            "timed_out": result.timed_out, "oom_killed": result.oom_killed,
            "duration_ms": result.duration_ms, "started_at": result.started_at,
            "finished_at": result.finished_at, "network": result.network,
            "gpu": result.gpu, "exec_dir": result.exec_dir,
            "snapshot": {key: len(result.snapshot.get(key) or [])
                         for key in ("created", "changed", "deleted", "skipped_symlinks")},
            "cleanup": result.cleanup, "cleanup_ok": result.cleanup_ok,
            "stdout": "%s/logs/docker_run.stdout" % result.exec_dir,
            "stderr": "%s/logs/docker_run.stderr" % result.exec_dir,
            "artifacts": [item.get("name") for item in raw.get("copied_to_host") or []],
        })

    def _cached_field(self, field: str) -> str:
        """Probe once and reuse: the GPU and CUDA version do not change mid-run."""
        try:
            report = self.probe()
        except (BackendUnavailable, BackendError):
            return ""
        return getattr(report, field, "") or ""

    def cleanup(self, run_id: str) -> dict:
        return self._call("cleanup", {"run_id": run_id}, timeout=180)

    def describe(self) -> dict:
        return {"backend": self.name, **self.config.describe(),
                "worker_sha256": self._worker_sha,
                "supervisor_source_sha256": self._supervisor_sha}


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
    if start < 0:
        return None
    end = stdout.find(END, start + len(BEGIN))
    if end < 0:
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
    if path.is_symlink() or not path.is_file():
        return {}
    return {"artifact": name, "sha256": sha256_file(path), "bytes": path.stat().st_size}


def _daemon_error(stderr: str) -> bool:
    """Docker/runtime failures that happen before the target program runs."""
    markers = ("error response from daemon", "oci runtime create failed", "runc create failed",
               "failed to create task for container", "nvidia-container-cli",
               "is not running", "no such image", "pull access denied")
    lowered = (stderr or "").lower()
    return any(marker in lowered for marker in markers)
