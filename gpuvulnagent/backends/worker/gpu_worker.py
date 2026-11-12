#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GPUVulnAgent worker: the Linux side of the execution backend.

Runs inside WSL as an ordinary user. Reads one JSON request on stdin, writes one JSON
response on stdout, and does nothing else.

Why a worker instead of calling ``wsl.exe docker ...`` from Windows:

* the request is a structured object, not a shell string, so no argument can be re-parsed
  by bash and nothing needs quoting;
* every docker option the agent can reach is chosen here from an allowlist, so a tool
  argument cannot ask for ``--privileged``, a host mount or the docker socket;
* the container id, exit status, OOM flag and image digest are read from the daemon;
* cleanup happens in the same process that started the container, in a ``finally`` block,
  so a collection error cannot leave an orphan running.

Evidence rules enforced here (P19-R1):

* every execution owns ``execs/execNN/`` and never writes into an earlier one;
* the artifact snapshot contains only files this execution created or modified, plus a
  full before/after listing so "it did not change" is also provable;
* a symlink in the work directory is never followed, so a container cannot smuggle
  ``/etc/shadow`` or a host file into the evidence;
* the wait status comes from an independent supervisor, not from the docker exit code,
  because ``exit(139)`` and SIGSEGV are indistinguishable in an exit status.

Python 3.8+ standard library only. Nothing is imported from the Windows package.
"""

import glob
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time

PROTOCOL = "gpuvulnagent-worker/2"
BEGIN = "GPUVULNAGENT_JSON_BEGIN"
END = "GPUVULNAGENT_JSON_END"

DEFAULT_WORKER_ROOT = "/home/pocdev/gpuvulnagent-worker"
MAX_TIMEOUT = 3600
MAX_ARTIFACTS = 400
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
SECRET_NAME = re.compile(r"(API[_-]?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", re.I)
IMAGE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,200}$")
NETWORKS = ("none", "bridge", "host")
PULL_POLICIES = ("missing", "always", "never")
HARNESS_DIR = ".gpuvulnagent"
SUPERVISOR_NAME = "gpuvuln_supervise"
# Linux defines O_NOFOLLOW; the Windows test host does not. The real worker runs on Linux,
# where the flag is what stops a planted symlink from being followed.
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
# Linux defines O_NOFOLLOW; the Windows test host does not. The real worker runs on Linux,
# where the flag is what stops a planted symlink from being followed.
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


# --------------------------------------------------------------------------- helpers
def worker_root():
    return os.environ.get("GPUVULN_WORKER_ROOT", DEFAULT_WORKER_ROOT)


def run(argv, timeout=60, cwd=None, env=None):
    """Run one program; return a dict, never raise for a normal non-zero exit."""
    started = time.monotonic()
    try:
        completed = subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                                   timeout=timeout, env=env, errors="replace")
        return {"argv": list(argv), "exit": completed.returncode,
                "stdout": completed.stdout or "", "stderr": completed.stderr or "",
                "duration_ms": int((time.monotonic() - started) * 1000), "timed_out": False,
                "error": ""}
    except FileNotFoundError as exc:
        return {"argv": list(argv), "exit": None, "stdout": "", "stderr": str(exc),
                "duration_ms": int((time.monotonic() - started) * 1000), "timed_out": False,
                "error": "not_found"}
    except subprocess.TimeoutExpired as exc:
        return {"argv": list(argv), "exit": None, "stdout": exc.stdout or "",
                "stderr": (exc.stderr or "") + "\nworker: command timed out",
                "duration_ms": int((time.monotonic() - started) * 1000), "timed_out": True,
                "error": "timeout"}
    except OSError as exc:
        return {"argv": list(argv), "exit": None, "stdout": "", "stderr": str(exc),
                "duration_ms": int((time.monotonic() - started) * 1000), "timed_out": False,
                "error": "os_error"}


def first_line(text, limit=200):
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            return line[:limit]
    return ""


def sha256_file(path, chunk=1024 * 1024):
    """Hash a regular file without following a symlink."""
    fd, error = _open_regular(path)
    if fd < 0:
        raise _WorkerFault("cannot hash %r: %s" % (path, error))
    digest = hashlib.sha256()
    try:
        while True:
            block = os.read(fd, chunk)
            if not block:
                break
            digest.update(block)
    finally:
        os.close(fd)
    return digest.hexdigest()


def _open_regular(path):
    """Open a regular file with O_NOFOLLOW. Returns ``(fd, error)``; fd is -1 on failure."""
    try:
        info = os.lstat(path)
    except OSError as exc:
        return -1, exc.strerror or str(exc)
    if not stat.S_ISREG(info.st_mode):
        return -1, "not a regular file"
    try:
        fd = os.open(path, os.O_RDONLY | O_NOFOLLOW)
    except OSError as exc:
        return -1, exc.strerror or str(exc)
    info2 = os.fstat(fd)
    if not stat.S_ISREG(info2.st_mode):
        os.close(fd)
        return -1, "not a regular file"
    if (info.st_dev, info.st_ino) != (info2.st_dev, info2.st_ino):
        # The path was swapped between lstat and open: exactly the race this guards.
        os.close(fd)
        return -1, "file changed during open"
    return fd, ""


def write_regular(path, text, mode=0o644):
    """Create a file with O_NOFOLLOW so a planted symlink cannot redirect the write."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | O_NOFOLLOW, mode)
    except OSError as exc:
        raise _WorkerFault("cannot write %r: %s" % (path, exc.strerror or exc))
    try:
        os.write(fd, text.encode("utf-8", "replace"))
    finally:
        os.close(fd)
    os.chmod(path, mode)


def os_release():
    data = {}
    try:
        with open("/etc/os-release", encoding="utf-8") as handle:
            for line in handle:
                if "=" in line:
                    key, value = line.rstrip("\n").split("=", 1)
                    data[key] = value.strip('"')
    except OSError:
        pass
    return data


def find_binary(name):
    found = shutil.which(name)
    if found:
        return found
    for pattern in ("/usr/local/cuda/bin/%s", "/usr/local/cuda-*/bin/%s",
                    "/usr/bin/%s", "/opt/nvidia/*/bin/%s"):
        for candidate in sorted(glob.glob(pattern % name), reverse=True):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    return ""


def tool_status(name, version_args=("--version",)):
    """Execute the tool. "Exists" is not the same fact as "runs"."""
    path = find_binary(name)
    if not path:
        return {"name": name, "status": "missing", "path": "", "version": "",
                "detail": "not on PATH and not under /usr/local/cuda*"}
    result = run([path] + list(version_args), timeout=30)
    text = (result["stdout"] or "") + (result["stderr"] or "")
    if result["exit"] == 0 and text.strip():
        return {"name": name, "status": "ok", "path": path,
                "version": _version_from(text), "detail": first_line(text)}
    return {"name": name, "status": "not_runnable", "path": path, "version": "",
            "detail": (result.get("error") or "exit %s" % result["exit"]) + ": "
                      + (first_line(text) or "no output")}


def _version_from(text):
    match = re.search(r"\bV([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b", text or "")
    if match:
        return match.group(1)
    match = re.search(r"release\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)", text or "", re.I)
    if match:
        return match.group(1)
    return first_line(text)


def nvidia_smi_query(fields="name,memory.total,compute_cap,driver_version"):
    path = find_binary("nvidia-smi") or "/usr/bin/nvidia-smi"
    result = run([path, "--query-gpu=" + fields, "--format=csv,noheader"], timeout=30)
    if result["exit"] != 0:
        return {"ok": False, "detail": first_line(result["stderr"]) or "nvidia-smi failed"}
    values = [part.strip() for part in (result["stdout"] or "").split(",")]
    names = fields.split(",")
    return {"ok": True, "values": dict(zip(names, values)), "raw": result["stdout"].strip()}


# --------------------------------------------------------------------------- supervisor
def _supervisor_paths():
    root = worker_root()
    return {"source": os.path.join(root, "gpuvuln_supervise.c"),
            "binary": os.path.join(root, "bin", SUPERVISOR_NAME)}


def ensure_supervisor(params):
    """Build the wait-status supervisor once, statically, on the WSL host."""
    paths = _supervisor_paths()
    if not os.path.isfile(paths["source"]):
        return {"ok": False, "error": "supervisor source missing at %s" % paths["source"]}
    source_hash = sha256_file(paths["source"])
    marker = paths["binary"] + ".sha256"
    if os.path.isfile(paths["binary"]) and os.path.isfile(marker):
        try:
            with open(marker, encoding="utf-8") as handle:
                if handle.read().strip() == source_hash:
                    return {"ok": True, "path": paths["binary"],
                            "sha256": sha256_file(paths["binary"]), "built": False,
                            "static": _is_static(paths["binary"])}
        except OSError:
            pass
    os.makedirs(os.path.dirname(paths["binary"]), exist_ok=True)
    attempts = []
    for flags in (["-static"], []):
        command = ["gcc", "-O2"] + flags + ["-o", paths["binary"], paths["source"]]
        result = run(command, timeout=180)
        attempts.append({"flags": flags, "exit": result["exit"],
                         "stderr": first_line(result["stderr"])})
        if result["exit"] == 0 and os.path.isfile(paths["binary"]):
            binary_hash = sha256_file(paths["binary"])
            write_regular(marker, source_hash + "\n")
            return {"ok": True, "path": paths["binary"], "sha256": binary_hash,
                    "built": True, "static": bool(flags), "attempts": attempts}
    return {"ok": False, "error": "gcc could not build the supervisor",
            "attempts": attempts}


def _is_static(path):
    result = run(["file", "-b", path], timeout=30)
    return "statically linked" in (result["stdout"] or "")


def _read_supervision(path):
    """Read the supervisor's status file without following a symlink."""
    if os.path.islink(path):
        return {"readable": False, "reason": "status path is a symlink"}
    if not os.path.isfile(path):
        return {"readable": False, "reason": "status file was not written"}
    fd, error = _open_regular(path)
    if fd < 0:
        return {"readable": False, "reason": error}
    raw = b""
    try:
        while True:
            block = os.read(fd, 4096)
            if not block:
                break
            raw += block
    finally:
        os.close(fd)
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return {"readable": False, "reason": "status file is not JSON"}
    data["readable"] = True
    return data


# --------------------------------------------------------------------------- ops
def op_ping(params):
    supervisor = _supervisor_paths()
    return {"pong": True, "python": sys.version.split()[0], "user": _current_user(),
            "worker_root": worker_root(), "kernel": _uname(),
            "worker_sha256": sha256_file(os.path.abspath(__file__)),
            "supervisor_present": os.path.isfile(supervisor["binary"]),
            "protocol": PROTOCOL}


def op_probe(params):
    deep = bool(params.get("deep"))
    image = params.get("image") or ""
    osr = os_release()
    docker = run(["docker", "version", "--format", "{{.Server.Version}}"], timeout=30)
    smi = nvidia_smi_query()
    tools = {}
    for name in ("nvcc", "nvdisasm", "cuobjdump"):
        tools[name] = tool_status(name)
    cuda_version = tools["nvcc"].get("version", "")
    images = []
    listing = run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"], timeout=30)
    if listing["exit"] == 0:
        images = [line for line in (listing["stdout"] or "").splitlines() if line.strip()][:40]
    problems = []
    if docker["exit"] != 0:
        problems.append("docker daemon is not reachable for this user: %s"
                        % (first_line(docker["stderr"]) or "no output"))
    if not smi["ok"]:
        problems.append("nvidia-smi on the host: %s" % smi.get("detail", "failed"))
    gpu_in_container = {}
    if deep and image:
        gpu_in_container = _probe_gpu_in_container(image)
        if gpu_in_container.get("ok") is False:
            problems.append("GPU inside the container: %s"
                            % gpu_in_container.get("detail", "failed"))
    return {
        "distro": osr.get("PRETTY_NAME", ""), "distro_version": osr.get("VERSION_ID", ""),
        "kernel": _uname(), "user": _current_user(),
        "docker": {"version": (docker["stdout"] or "").strip(),
                   "running": docker["exit"] == 0,
                   "detail": first_line(docker["stderr"]) if docker["exit"] != 0 else ""},
        "gpu": ({"name": smi["values"].get("name", ""),
                 "memory": smi["values"].get("memory.total", ""),
                 "compute_capability": smi["values"].get("compute_cap", ""),
                 "driver": smi["values"].get("driver_version", ""),
                 "raw": smi.get("raw", "")} if smi["ok"] else {"error": smi.get("detail", "")}),
        "cuda": {"toolkit": cuda_version},
        "tools": tools, "images": images, "gpu_in_container": gpu_in_container,
        "supervisor": (ensure_supervisor({}) if params.get("with_supervisor")
                       else {"ok": os.path.isfile(_supervisor_paths()["binary"])}),
        "problems": problems,
    }


def op_prepare(params):
    run_id, trail = _ids(params)
    workdir = _workdir(run_id, trail)
    os.makedirs(workdir, exist_ok=True)
    source_dir = params.get("source_dir", "")
    names = params.get("files") or []
    staged = []
    for name in names:
        safe = _safe_name(name)
        source = os.path.join(source_dir, safe)
        if os.path.islink(source) or not os.path.isfile(source):
            raise _WorkerFault("input %r is not a readable regular file at %s"
                               % (safe, source))
        target = os.path.join(workdir, safe)
        os.makedirs(os.path.dirname(target) or workdir, exist_ok=True)
        shutil.copy2(source, target)
        staged.append({"name": safe, "sha256": sha256_file(target),
                       "bytes": os.path.getsize(target)})
    return {"workdir": workdir, "files": staged, "run_id": run_id, "trail": trail}


def op_exec(params):
    run_id, trail = _ids(params)
    index = _clamp(params.get("exec_index", 0), 0, 999)
    image = params.get("image", "")
    if not IMAGE_PATTERN.match(image or ""):
        raise _WorkerFault("image name is not acceptable: %r" % image)
    argv = params.get("argv") or []
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise _WorkerFault("argv must be a non-empty array of strings")
    network = params.get("network") or "none"
    if network not in NETWORKS:
        raise _WorkerFault("network must be one of %s" % ", ".join(NETWORKS))
    pull_policy = params.get("pull_policy") or "missing"
    if pull_policy not in PULL_POLICIES:
        raise _WorkerFault("pull_policy must be one of %s" % ", ".join(PULL_POLICIES))
    timeout_s = _clamp(params.get("timeout_s", 600), 1, MAX_TIMEOUT)
    env_pairs, refused = _filter_env(params.get("env") or {})
    gpu = bool(params.get("gpu"))

    workdir = _workdir(run_id, trail)
    exec_dir = os.path.join(_trail_dir(run_id, trail), "execs", "exec%02d" % index)
    artifacts_dir = os.path.join(exec_dir, "artifacts")
    logs_dir = os.path.join(exec_dir, "logs")
    os.makedirs(workdir, exist_ok=True)
    os.makedirs(artifacts_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)
    harness_dir = os.path.join(workdir, HARNESS_DIR)
    os.makedirs(harness_dir, exist_ok=True)
    status_path = os.path.join(harness_dir, "status.json")
    if os.path.lexists(status_path):
        os.remove(status_path)

    payload = {
        "run_id": run_id, "trail": trail, "exec_index": index,
        "workdir": workdir, "exec_dir": exec_dir,
        "image": image, "argv": list(argv), "network": network, "gpu": gpu,
        "pull_policy": pull_policy, "env_keys": [key for key, _ in env_pairs],
        "refused_env": refused, "as_root": bool(params.get("as_root")),
        "supervision": {"used": False, "readable": False},
        "cleanup": {}, "cleanup_ok": False, "error": "",
    }

    command_argv = list(argv)
    if params.get("supervise", True):
        supervisor = ensure_supervisor(params)
        payload["supervisor"] = supervisor
        if supervisor.get("ok"):
            local = os.path.join(harness_dir, SUPERVISOR_NAME)
            shutil.copy2(supervisor["path"], local)
            os.chmod(local, 0o755)
            command_argv = ["/work/%s/%s" % (HARNESS_DIR, SUPERVISOR_NAME),
                            "/work/%s/status.json" % HARNESS_DIR] + list(argv)
            payload["supervision"]["used"] = True
        else:
            payload["supervision"]["reason"] = supervisor.get("error", "no supervisor")

    image_state = _ensure_image(image, pull_policy, timeout_s)
    payload["image_pull"] = image_state

    name = _container_name(run_id, trail)
    cidfile = os.path.join(exec_dir, "container.cid")
    if os.path.lexists(cidfile):
        os.remove(cidfile)

    inner_workdir = params.get("workdir") or "/work"
    pre_state = _scan_workdir(workdir)
    started_at = _now()
    started = time.monotonic()
    container_id = ""

    try:
        if not image_state.get("ok", True):
            raise _WorkerFault(image_state.get("error") or "image is not available")

        command = _docker_command(
            run_id=run_id, trail=trail, image=image, name=name, cidfile=cidfile,
            workdir=workdir, workdir_inner=inner_workdir, network=network, gpu=gpu,
            gpus=params.get("gpus") or "all", env_pairs=env_pairs,
            memory=params.get("memory"), cpus=params.get("cpus"),
            as_root=bool(params.get("as_root")), argv=command_argv)
        payload["docker_argv"] = command
        result = _run_container(command, name, timeout_s)
        payload["timed_out"] = bool(result.get("timed_out"))
        if payload["timed_out"]:
            # _run_container already killed it; killing again is cheap and makes the
            # ownership explicit if a future runner changes that.
            _kill(name, "")
        if payload["timed_out"]:
            # _run_container already killed it; killing again is cheap and makes the
            # ownership explicit if a future runner changes that.
            _kill(name, "")
        container_id = _read_cid(cidfile)
        payload["container_id"] = container_id
        payload["container_name"] = name

        inspect = _inspect(container_id or name)
        state = inspect.get("State", {}) if isinstance(inspect, dict) else {}
        exit_code = state.get("ExitCode")
        if exit_code is None and result.get("exit") is not None and not result.get("timed_out"):
            exit_code = result.get("exit")
        payload.update({
            "exit_code": exit_code,
            "oom_killed": bool(state.get("OOMKilled")),
            "state": state.get("Status", ""),
            "started_at": started_at, "finished_at": _now(),
            "duration_ms": int((time.monotonic() - started) * 1000),
            "docker_error": result.get("error", ""),
        })
        image_meta = _image_meta(image)
        payload["image_id"] = image_meta.get("id", "")
        payload["image_digest"] = image_meta.get("digest", "")

        payload["supervision"] = _merge_supervision(
            payload["supervision"], _read_supervision(status_path), exit_code)

        raw_stdout = os.path.join(logs_dir, "docker_run.stdout")
        raw_stderr = os.path.join(logs_dir, "docker_run.stderr")
        write_regular(raw_stdout, result.get("stdout") or "")
        write_regular(raw_stderr, result.get("stderr") or "")
        payload["stdout_sha256"] = sha256_file(raw_stdout)
        payload["stderr_sha256"] = sha256_file(raw_stderr)
        payload["stdout_bytes"] = os.path.getsize(raw_stdout)
        payload["stderr_bytes"] = os.path.getsize(raw_stderr)
        payload["response_trimmed"] = len(result.get("stdout") or "") > 200000
        payload["stdout"] = _head_tail(result.get("stdout") or "")
        payload["stderr"] = _head_tail(result.get("stderr") or "")

        post_state = _scan_workdir(workdir)
        snapshot = _snapshot(workdir, artifacts_dir, pre_state, post_state, index)
        payload["snapshot"] = snapshot
        extra = _collect_paths(container_id, artifacts_dir,
                               params.get("collect_paths") or [])
        if extra:
            payload["collect_paths"] = extra
        host_dir = params.get("host_output_dir") or ""
        payload["copied_to_host"] = (_copy_to_host(artifacts_dir, logs_dir, host_dir, index)
                                     if host_dir else [])
        write_regular(os.path.join(exec_dir, "snapshot.json"),
                      json.dumps(snapshot, ensure_ascii=False, indent=1) + "\n")
    except _WorkerFault as exc:
        payload["error"] = str(exc)
    except Exception as exc:  # noqa: BLE001 - a collection fault must not skip cleanup
        payload["error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        cleanup = _remove(container_id, name)
        payload["cleanup"] = cleanup
        payload["cleanup_ok"] = bool(cleanup.get("exit") == 0)
        payload.setdefault("duration_ms", int((time.monotonic() - started) * 1000))
        try:
            write_regular(os.path.join(exec_dir, "worker_result.json"),
                          json.dumps(payload, ensure_ascii=False, indent=1) + "\n")
        except Exception:  # noqa: BLE001 - never mask the original failure
            pass

    return payload


def op_collect(params):
    run_id, trail = _ids(params)
    index = _clamp(params.get("exec_index", 0), 0, 999)
    exec_dir = os.path.join(_trail_dir(run_id, trail), "execs", "exec%02d" % index)
    host_dir = params.get("host_output_dir") or ""
    if not host_dir:
        raise _WorkerFault("host_output_dir is required")
    copied = _copy_to_host(os.path.join(exec_dir, "artifacts"),
                           os.path.join(exec_dir, "logs"), host_dir, index)
    return {"copied": copied, "host_output_dir": host_dir}


def op_cleanup(params):
    name = params.get("container_name") or ""
    run_id = params.get("run_id") or ""
    removed = []
    if name:
        removed.append(_remove("", name))
    if run_id:
        listing = run(["docker", "ps", "-aq", "--filter",
                       "label=gpuvulnagent.run_id=" + run_id], timeout=30)
        for cid in (listing.get("stdout") or "").split():
            removed.append(_remove(cid, ""))
    return {"removed": [item for item in removed if item]}


# --------------------------------------------------------------------------- docker
def _docker_command(*, run_id, trail, image, name, cidfile, workdir, workdir_inner,
                    network, gpu, gpus, env_pairs, memory, cpus, as_root, argv):
    command = ["docker", "run", "--name", name, "--cidfile", cidfile,
               "--label", "gpuvulnagent.run_id=" + run_id,
               "--label", "gpuvulnagent.trail=" + trail,
               "--security-opt", "no-new-privileges",
               "--network", network,
               "-v", "%s:/work" % workdir,
               "-w", workdir_inner]
    # Run as the invoking user by default: a container that writes as root leaves files in
    # the trail that the trail owner can no longer remove or overwrite.
    if not as_root:
        uid, gid = _uid_gid()
        command += ["--user", "%d:%d" % (uid, gid)]
    if gpu:
        command += ["--gpus", gpus]
    if memory:
        command += ["--memory", str(memory)]
    if cpus:
        command += ["--cpus", str(cpus)]
    for key, value in env_pairs:
        command += ["-e", "%s=%s" % (key, value)]
    return command + [image] + list(argv)


def _ensure_image(image, policy, timeout_s):
    """Apply the pull policy. ``network=none`` constrains the container, not the engine."""
    state = {"policy": policy, "present_before": False, "pulled": False,
             "duration_ms": 0, "error": "", "ok": True,
             "note": "network=none applies to the container; the engine may still pull"}
    inspect = run(["docker", "image", "inspect", image], timeout=60)
    state["present_before"] = inspect["exit"] == 0
    needs_pull = policy == "always" or (policy == "missing" and not state["present_before"])
    if needs_pull and policy != "never":
        started = time.monotonic()
        pull = run(["docker", "pull", image], timeout=min(MAX_TIMEOUT, timeout_s + 900))
        state["duration_ms"] = int((time.monotonic() - started) * 1000)
        state["pulled"] = pull["exit"] == 0
        if not state["pulled"]:
            state["ok"] = False
            state["error"] = "docker pull failed: %s" % (first_line(pull["stderr"])
                                                         or "no output")
    elif policy == "never" and not state["present_before"]:
        state["ok"] = False
        state["error"] = "image %r is not present and pull_policy=never" % image
    return state


def _run_container(command, name, timeout_s):
    started = time.monotonic()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, errors="replace")
    try:
        stdout, stderr = process.communicate(timeout=timeout_s)
        return {"stdout": stdout or "", "stderr": stderr or "", "timed_out": False,
                "exit": process.returncode,
                "duration_ms": int((time.monotonic() - started) * 1000)}
    except subprocess.TimeoutExpired:
        # Kill the client and the container; the container would otherwise keep running.
        _kill(name, "")
        try:
            stdout, stderr = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = "", ""
        limit = "worker: container exceeded %ss and was killed" % timeout_s
        return {"stdout": stdout or "", "stderr": (stderr or "") + "\n" + limit,
                "timed_out": True, "exit": None,
                "duration_ms": int((time.monotonic() - started) * 1000)}


def _kill(name, container_id):
    target = container_id or name
    if target:
        run(["docker", "kill", target], timeout=60)


def _remove(container_id, name):
    target = container_id or name
    if not target:
        return {"attempted": False, "exit": None, "detail": "no container to remove"}
    result = run(["docker", "rm", "-f", target], timeout=60)
    return {"attempted": True, "target": target, "exit": result["exit"],
            "detail": "removed" if result["exit"] == 0
                      else (first_line(result["stderr"]) or "docker rm failed")}


def _inspect(reference):
    if not reference:
        return {}
    result = run(["docker", "inspect", reference], timeout=60)
    if result["exit"] != 0:
        return {}
    try:
        data = json.loads(result["stdout"])
    except ValueError:
        return {}
    return data[0] if data else {}


def _image_meta(image):
    result = run(["docker", "image", "inspect", image], timeout=60)
    if result["exit"] != 0:
        return {}
    try:
        data = json.loads(result["stdout"])
    except ValueError:
        return {}
    if not data:
        return {}
    entry = data[0]
    digests = entry.get("RepoDigests") or []
    return {"id": entry.get("Id", ""), "digest": digests[0] if digests else ""}


def _probe_gpu_in_container(image):
    result = run(["docker", "run", "--rm", "--gpus", "all", image,
                  "nvidia-smi", "--query-gpu=name,compute_cap,memory.total",
                  "--format=csv,noheader"], timeout=180)
    if result["exit"] != 0:
        return {"ok": False, "detail": first_line(result["stderr"]) or "no output"}
    return {"ok": True, "raw": (result["stdout"] or "").strip()}


# --------------------------------------------------------------------------- snapshot
def _scan_workdir(workdir):
    """State of the work directory: regular files only; symlinks recorded, never entered."""
    root = os.path.realpath(workdir)
    state = {"files": {}, "symlinks": [], "special": [], "errors": []}
    for current, dirs, files in os.walk(workdir, followlinks=False):
        rel_dir = os.path.relpath(current, workdir)
        if rel_dir == ".":
            rel_dir = ""
        keep = []
        for name in sorted(dirs):
            full = os.path.join(current, name)
            rel = ("%s/%s" % (rel_dir, name)) if rel_dir else name
            if rel == HARNESS_DIR:
                continue
            if os.path.islink(full):
                state["symlinks"].append({"name": rel, "target": os.readlink(full),
                                          "reason": "symlinked directory was not entered"})
                continue
            if not _inside(root, full):
                state["errors"].append({"name": rel,
                                        "reason": "directory escaped the work root"})
                continue
            keep.append(name)
        dirs[:] = keep
        for name in sorted(files):
            full = os.path.join(current, name)
            rel = ("%s/%s" % (rel_dir, name)) if rel_dir else name
            if rel.split("/")[0] == HARNESS_DIR:
                continue
            try:
                info = os.lstat(full)
            except OSError as exc:
                state["errors"].append({"name": rel, "reason": str(exc)})
                continue
            if stat.S_ISLNK(info.st_mode):
                state["symlinks"].append({"name": rel, "target": os.readlink(full),
                                          "reason": "symlink was not followed"})
                continue
            if not stat.S_ISREG(info.st_mode):
                state["special"].append({"name": rel, "reason": "not a regular file"})
                continue
            if not _inside(root, full):
                state["errors"].append({"name": rel, "reason": "file escaped the work root"})
                continue
            try:
                state["files"][rel] = {"sha256": sha256_file(full), "bytes": info.st_size}
            except _WorkerFault as exc:
                state["errors"].append({"name": rel, "reason": str(exc)})
    return state


def _inside(root, path):
    try:
        real = os.path.realpath(path)
    except OSError:
        return False
    return real == root or real.startswith(root + os.sep)


def _snapshot(workdir, artifacts_dir, pre, post, index):
    """Copy files this execution created or changed into its own artifact directory."""
    created, changed, unchanged = [], [], []
    for name, info in sorted(post["files"].items()):
        before = pre["files"].get(name)
        if before is None:
            created.append(name)
        elif before["sha256"] != info["sha256"]:
            changed.append(name)
        else:
            unchanged.append(name)
            continue
        source = os.path.join(workdir, name)
        target = os.path.join(artifacts_dir, name)
        copied, reason = _safe_copy(source, target, os.path.realpath(workdir))
        if not copied:
            post["errors"].append({"name": name, "reason": reason})
    deleted = sorted(set(pre["files"]) - set(post["files"]))
    return {
        "execution_index": index,
        "created": created, "changed": changed, "deleted": deleted,
        "unchanged_count": len(unchanged),
        "pre_files": {name: info["sha256"] for name, info in sorted(pre["files"].items())},
        "post_files": {name: info["sha256"] for name, info in sorted(post["files"].items())},
        "skipped_symlinks": post["symlinks"], "special": post["special"],
        "errors": post["errors"],
        "policy": ("snapshot holds files this execution created or modified; the full "
                   "before/after listing proves what did not change; symlinks are never "
                   "followed"),
    }


def _safe_copy(source, target, root_real):
    """Copy one regular file without following symlinks, verifying the boundary."""
    if not _inside(root_real, source):
        return False, "source is outside the root"
    try:
        info = os.lstat(source)
    except OSError as exc:
        return False, exc.strerror or str(exc)
    if stat.S_ISLNK(info.st_mode):
        return False, "source is a symlink"
    if not stat.S_ISREG(info.st_mode):
        return False, "source is not a regular file"
    fd, error = _open_regular(source)
    if fd < 0:
        return False, error
    try:
        os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
        out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | O_NOFOLLOW, 0o644)
        try:
            while True:
                block = os.read(fd, 1024 * 1024)
                if not block:
                    break
                os.write(out, block)
        finally:
            os.close(out)
    finally:
        os.close(fd)
    return True, ""


def _collect_paths(container_id, artifacts_dir, paths):
    """Copy explicitly requested container paths out, as regular files only."""
    results = []
    for raw in paths[:20]:
        path = str(raw or "").strip()
        if not container_id or not path.startswith("/"):
            results.append({"path": path, "ok": False,
                            "detail": "an absolute container path is required"})
            continue
        name = path.strip("/").replace("/", "_") or "root"
        target = os.path.join(artifacts_dir, "_container", name)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if os.path.lexists(target):
            os.remove(target)
        copied = run(["docker", "cp", "%s:%s" % (container_id, path), target], timeout=120)
        if copied["exit"] != 0:
            results.append({"path": path, "ok": False,
                            "detail": first_line(copied["stderr"]) or "docker cp failed"})
            continue
        if os.path.isdir(target):
            results.append({"path": path, "ok": False,
                            "detail": "directory copies are not supported; name a file"})
            continue
        fd, error = _open_regular(target)
        if fd < 0:
            results.append({"path": path, "ok": False, "detail": error})
            continue
        os.close(fd)
        results.append({"path": path, "ok": True, "name": "_container/" + name,
                        "sha256": sha256_file(target),
                        "bytes": os.path.getsize(target)})
    return results


def _copy_to_host(artifacts_dir, logs_dir, host_dir, exec_index):
    """Copy this execution's snapshot and logs to the Windows side."""
    copied = []
    if not host_dir:
        return copied
    exec_name = "exec%02d" % exec_index
    outputs = os.path.join(host_dir, "execs", exec_name, "outputs")
    logs = os.path.join(host_dir, "execs", exec_name, "logs")
    os.makedirs(outputs, exist_ok=True)
    os.makedirs(logs, exist_ok=True)
    for current, dirs, files in os.walk(artifacts_dir, followlinks=False):
        dirs[:] = [name for name in dirs
                   if not os.path.islink(os.path.join(current, name))]
        for name in sorted(files):
            source = os.path.join(current, name)
            if os.path.islink(source):
                continue
            relative = os.path.relpath(source, artifacts_dir).replace(os.sep, "/")
            target = os.path.join(outputs, relative)
            ok, reason = _safe_copy(source, target, os.path.realpath(artifacts_dir))
            label = "execs/%s/outputs/%s" % (exec_name, relative)
            if not ok:
                copied.append({"name": label, "sha256": "", "bytes": 0, "skipped": reason})
                continue
            copied.append({"name": label, "sha256": sha256_file(target),
                           "bytes": os.path.getsize(target), "skipped": ""})
    if os.path.isdir(logs_dir):
        for name in sorted(os.listdir(logs_dir)):
            source = os.path.join(logs_dir, name)
            if os.path.islink(source) or not os.path.isfile(source):
                continue
            target = os.path.join(logs, name)
            ok, reason = _safe_copy(source, target, os.path.realpath(logs_dir))
            label = "execs/%s/logs/%s" % (exec_name, name)
            if not ok:
                copied.append({"name": label, "sha256": "", "bytes": 0, "skipped": reason})
                continue
            copied.append({"name": label, "sha256": sha256_file(target),
                           "bytes": os.path.getsize(target), "skipped": ""})
    return copied


# --------------------------------------------------------------------------- misc
def _trail_dir(run_id, trail):
    return os.path.join(worker_root(), "runs", _safe_component(run_id), _safe_component(trail))


def _workdir(run_id, trail):
    return os.path.join(_trail_dir(run_id, trail), "work")


def _ids(params):
    run_id = str(params.get("run_id") or "")
    trail = str(params.get("trail") or "")
    if not run_id or not trail:
        raise _WorkerFault("run_id and trail are required")
    _safe_component(run_id)
    _safe_component(trail)
    return run_id, trail


def _safe_component(value):
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$", value or ""):
        raise _WorkerFault("unsafe identifier: %r" % value)
    return value


def _safe_name(name):
    normalised = str(name).replace("\\", "/").strip()
    if normalised.startswith("/") or ".." in normalised.split("/"):
        raise _WorkerFault("unsafe file name: %r" % name)
    return normalised


def _container_name(run_id, trail):
    stamp = str(int(time.time()))[-6:]
    raw = "gpuvulnagent-%s-%s-%s" % (run_id, trail, stamp)
    return re.sub(r"[^A-Za-z0-9_.-]", "-", raw)[:120]


def _read_cid(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError:
        return ""


def _filter_env(values):
    allowed, refused = [], []
    for key, value in (values or {}).items():
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]{0,60}$", key):
            refused.append(key)
            continue
        if SECRET_NAME.search(key):
            refused.append(key)
            continue
        allowed.append((key, str(value)[:4000]))
    return allowed, refused


def _clamp(value, low, high):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return low
    return max(low, min(high, number))


def _merge_supervision(base, status, exit_code):
    merged = dict(base)
    merged.update(status)
    if not merged.get("used"):
        merged["reason"] = merged.get("reason") or "supervision was not requested"
    elif not merged.get("readable"):
        merged["reason"] = merged.get("reason") or "no supervision status was recorded"
    merged["exit_code"] = exit_code
    return merged


def _current_user():
    return os.environ.get("USER") or os.environ.get("LOGNAME") or "unknown"


def _uid_gid():
    getuid = getattr(os, "getuid", None)
    getgid = getattr(os, "getgid", None)
    if callable(getuid) and callable(getgid):
        return getuid(), getgid()
    return 1000, 1000


def _uname():
    result = run(["uname", "-r"], timeout=10)
    return (result.get("stdout") or "").strip() or "unknown"


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _head_tail(text, head=4000, tail=196000):
    if len(text) <= head + tail:
        return text
    return (text[:head] + "\n...[trimmed in the response; the full text is in the "
            "artifact]...\n" + text[-tail:])


def _fail(message):
    raise _WorkerFault(message)


class _WorkerFault(Exception):
    pass


OPS = {"ping": op_ping, "probe": op_probe, "prepare": op_prepare, "exec": op_exec,
       "collect": op_collect, "cleanup": op_cleanup,
       "supervisor": lambda params: ensure_supervisor(params)}


def handle(request):
    op = request.get("op")
    handler = OPS.get(op)
    if handler is None:
        return {"ok": False, "error": "unknown op %r" % op, "known": sorted(OPS)}
    try:
        result = handler(request.get("params") or {})
        ok = not (isinstance(result, dict) and result.get("ok") is False)
        return {"ok": ok, "op": op, "result": result}
    except _WorkerFault as exc:
        return {"ok": False, "op": op, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 - a worker fault is data, not a crash
        return {"ok": False, "op": op, "error": "%s: %s" % (type(exc).__name__, exc)}


def main():
    raw = sys.stdin.read()
    try:
        request = json.loads(raw)
    except ValueError as exc:
        payload = {"ok": False, "error": "request is not JSON: %s" % exc}
    else:
        request.setdefault("protocol", PROTOCOL)
        payload = handle(request)
    sys.stdout.write(BEGIN + json.dumps(payload, ensure_ascii=False) + END + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
