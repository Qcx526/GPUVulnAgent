#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GPUVulnAgent worker: the Linux side of the execution backend.

Runs inside WSL as an ordinary user. Reads one JSON request on stdin, writes one JSON
response on stdout, and does nothing else.

Why a worker instead of calling ``wsl.exe docker ...`` from Windows:

* the request is a structured object, not a shell string, so no argument can be re-parsed
  by bash and nothing needs quoting;
* every docker option the agent can reach is chosen here from an allowlist, so the agent
  cannot ask for ``--privileged``, a host mount or the docker socket;
* the container id, exit status, OOM flag and image digest are read from the daemon, not
  inferred from text;
* cleanup happens in the same process that started the container, so a timeout cannot
  leave an orphan behind.

Python 3.8+ standard library only. No imports from the Windows package: this file is
copied into the WSL home and executed there.
"""

import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time

PROTOCOL = "gpuvulnagent-worker/1"
BEGIN = "GPUVULNAGENT_JSON_BEGIN"
END = "GPUVULNAGENT_JSON_END"

DEFAULT_WORKER_ROOT = "/home/pocdev/gpuvulnagent-worker"
MAX_TIMEOUT = 3600
MAX_ARTIFACTS = 200
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
SECRET_NAME = re.compile(r"(API[_-]?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)", re.I)
IMAGE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@+-]{0,200}$")
NETWORKS = ("none", "bridge", "host")


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
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            block = handle.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


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
    """Locate a tool the way a user's shell would, then fall back to the CUDA roots."""
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
    """``Cuda compilation tools, release 12.8, V12.8.93`` -> ``12.8.93``."""
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


# --------------------------------------------------------------------------- ops
def op_ping(params):
    return {"pong": True, "python": sys.version.split()[0], "user": _current_user(),
            "worker_root": worker_root(), "kernel": _uname(),
            "worker_sha256": sha256_file(os.path.abspath(__file__)),
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
        if not os.path.isfile(source):
            return _fail("input %r is not readable at %s" % (safe, source))
        target = os.path.join(workdir, safe)
        os.makedirs(os.path.dirname(target) or workdir, exist_ok=True)
        shutil.copy2(source, target)
        staged.append({"name": safe, "sha256": sha256_file(target),
                       "bytes": os.path.getsize(target)})
    return {"workdir": workdir, "files": staged, "run_id": run_id, "trail": trail}


def op_exec(params):
    run_id, trail = _ids(params)
    image = params.get("image", "")
    if not IMAGE_PATTERN.match(image or ""):
        return _fail("image name is not acceptable: %r" % image)
    argv = params.get("argv") or []
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        return _fail("argv must be a non-empty array of strings")
    network = params.get("network") or "none"
    if network not in NETWORKS:
        return _fail("network must be one of %s" % ", ".join(NETWORKS))
    timeout_s = _clamp(params.get("timeout_s", 600), 1, MAX_TIMEOUT)
    env_pairs, refused = _filter_env(params.get("env") or {})
    gpu = bool(params.get("gpu"))
    workdir = _workdir(run_id, trail)
    os.makedirs(workdir, exist_ok=True)
    artifacts_dir = os.path.join(_trail_dir(run_id, trail), "artifacts")
    os.makedirs(artifacts_dir, exist_ok=True)
    cidfile = os.path.join(_trail_dir(run_id, trail), "container.cid")
    for stale in (cidfile,):
        if os.path.exists(stale):
            os.remove(stale)

    inner_workdir = params.get("workdir") or "/work"
    name = _container_name(run_id, trail)
    command = ["docker", "run", "--name", name, "--cidfile", cidfile,
               "--label", "gpuvulnagent.run_id=" + run_id,
               "--label", "gpuvulnagent.trail=" + trail,
               "--security-opt", "no-new-privileges",
               "--network", network,
               "-v", "%s:/work" % workdir,
               "-w", inner_workdir]
    # Run as the invoking user by default: a container that writes as root leaves files in
    # the trail that the trail owner can no longer remove or overwrite.
    if not params.get("as_root"):
        uid, gid = _uid_gid()
        command += ["--user", "%d:%d" % (uid, gid)]
    if gpu:
        command += ["--gpus", params.get("gpus") or "all"]
    if params.get("memory"):
        command += ["--memory", str(params["memory"])]
    if params.get("cpus"):
        command += ["--cpus", str(params["cpus"])]
    for key, value in env_pairs:
        command += ["-e", "%s=%s" % (key, value)]
    command += [image] + list(argv)

    started_at = _now()
    # Monotonic, not wall clock: WSL2 resyncs its clock after a suspend, and a duration
    # measured across that step can be negative, which is worse than useless in evidence.
    started = time.monotonic()
    result = _run_container(command, name, timeout_s)
    duration_ms = int((time.monotonic() - started) * 1000)
    finished_at = _now()
    container_id = _read_cid(cidfile)
    inspect = _inspect(container_id or name)
    state = inspect.get("State", {}) if isinstance(inspect, dict) else {}
    exit_code = state.get("ExitCode")
    oom = bool(state.get("OOMKilled"))
    timed_out = bool(result.get("timed_out"))
    if timed_out:
        _kill(name, container_id)

    stdout_path = os.path.join(_trail_dir(run_id, trail), "docker_run.stdout")
    stderr_path = os.path.join(_trail_dir(run_id, trail), "docker_run.stderr")
    _write(stdout_path, result.get("stdout") or "")
    _write(stderr_path, result.get("stderr") or "")

    collected = _collect_artifacts(workdir, artifacts_dir, container_id,
                                   params.get("collect_paths") or [])
    host_dir = params.get("host_output_dir") or ""
    exec_index = _clamp(params.get("exec_index", 0), 0, 999)
    copied = (_copy_to_host(artifacts_dir, stdout_path, stderr_path, host_dir, exec_index)
              if host_dir else [])

    _remove(container_id, name)
    image_meta = _image_meta(image)
    if exit_code is None and result.get("exit") is not None and not timed_out:
        # Docker itself failed (125) or the client died: the client code is the only fact.
        exit_code = result["exit"]
    stdout_text = _head_tail(result.get("stdout") or "")
    stderr_text = _head_tail(result.get("stderr") or "")
    return {
        "exit_code": exit_code, "timed_out": timed_out, "oom_killed": oom,
        "state": state.get("Status", ""), "duration_ms": duration_ms,
        "started_at": started_at, "finished_at": finished_at,
        "container_id": container_id, "container_name": name,
        "image": image, "image_id": image_meta.get("id", ""),
        "image_digest": image_meta.get("digest", ""),
        "argv": list(argv), "workdir": inner_workdir, "network": network,
        "gpu": gpu, "env_keys": [key for key, _ in env_pairs],
        "refused_env": refused, "as_root": bool(params.get("as_root")),
        "stdout": stdout_text, "stderr": stderr_text,
        "stdout_sha256": sha256_file(stdout_path), "stderr_sha256": sha256_file(stderr_path),
        "stdout_bytes": os.path.getsize(stdout_path),
        "stderr_bytes": os.path.getsize(stderr_path),
        "response_trimmed": len(result.get("stdout") or "") > len(stdout_text),
        "artifacts": collected, "copied_to_host": copied,
        "host_output_dir": host_dir,
        "docker_error": result.get("error", ""),
    }


def op_collect(params):
    run_id, trail = _ids(params)
    artifacts_dir = os.path.join(_trail_dir(run_id, trail), "artifacts")
    stdout_path = os.path.join(_trail_dir(run_id, trail), "docker_run.stdout")
    stderr_path = os.path.join(_trail_dir(run_id, trail), "docker_run.stderr")
    host_dir = params.get("host_output_dir") or ""
    if not host_dir:
        return _fail("host_output_dir is required")
    copied = _copy_to_host(artifacts_dir, stdout_path, stderr_path, host_dir,
                           _clamp(params.get("exec_index", 0), 0, 999))
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
def _run_container(command, name, timeout_s):
    started = time.monotonic()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, errors="replace")
    try:
        stdout, stderr = process.communicate(timeout=timeout_s)
        return {"stdout": stdout or "", "stderr": stderr or "", "timed_out": False,
                "exit": process.returncode}
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
                "timed_out": True, "exit": None}


def _kill(name, container_id):
    target = container_id or name
    if target:
        run(["docker", "kill", target], timeout=60)


def _remove(container_id, name):
    target = container_id or name
    if not target:
        return None
    result = run(["docker", "rm", "-f", target], timeout=60)
    return {"target": target, "exit": result["exit"],
            "detail": first_line(result["stderr"]) if result["exit"] != 0 else "removed"}


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


# --------------------------------------------------------------------------- files
def _collect_artifacts(workdir, artifacts_dir, container_id, extra_paths):
    """Copy container-visible files into the trail, hashing each one."""
    collected = []
    for root, _dirs, files in os.walk(workdir):
        for name in sorted(files):
            source = os.path.join(root, name)
            relative = os.path.relpath(source, workdir).replace(os.sep, "/")
            if len(collected) >= MAX_ARTIFACTS:
                break
            try:
                size = os.path.getsize(source)
            except OSError:
                continue
            if size > MAX_ARTIFACT_BYTES:
                collected.append({"name": relative, "sha256": "", "bytes": size,
                                  "skipped": "larger than %d bytes" % MAX_ARTIFACT_BYTES})
                continue
            target = os.path.join(artifacts_dir, relative)
            os.makedirs(os.path.dirname(target) or artifacts_dir, exist_ok=True)
            shutil.copy2(source, target)
            collected.append({"name": relative, "sha256": sha256_file(target),
                              "bytes": size, "skipped": ""})
    for path in extra_paths:
        if not container_id or not path:
            continue
        target = os.path.join(artifacts_dir, "_container", path.lstrip("/").replace("/", "_"))
        os.makedirs(os.path.dirname(target) or artifacts_dir, exist_ok=True)
        result = run(["docker", "cp", "%s:%s" % (container_id, path), target], timeout=120)
        if result["exit"] == 0 and os.path.isfile(target):
            collected.append({"name": "_container/" + os.path.basename(target),
                              "sha256": sha256_file(target),
                              "bytes": os.path.getsize(target), "skipped": ""})
        else:
            collected.append({"name": "_container/" + os.path.basename(target), "sha256": "",
                              "bytes": 0, "skipped": first_line(result["stderr"])
                              or "docker cp failed"})
    return collected


def _copy_to_host(artifacts_dir, stdout_path, stderr_path, host_dir, exec_index=0):
    copied = []
    if not host_dir:
        return copied
    outputs = os.path.join(host_dir, "outputs")
    logs = os.path.join(host_dir, "logs")
    os.makedirs(outputs, exist_ok=True)
    os.makedirs(logs, exist_ok=True)
    for root, _dirs, files in os.walk(artifacts_dir):
        for name in sorted(files):
            source = os.path.join(root, name)
            relative = os.path.relpath(source, artifacts_dir).replace(os.sep, "/")
            target = os.path.join(outputs, relative)
            os.makedirs(os.path.dirname(target) or outputs, exist_ok=True)
            shutil.copy2(source, target)
            copied.append({"name": "outputs/" + relative, "sha256": sha256_file(target),
                           "bytes": os.path.getsize(target)})
    # One execution per trail is the common case, so the first run gets the plain name and
    # later runs in the same trail are suffixed instead of overwriting the earlier log.
    for source, base in ((stdout_path, "stdout"), (stderr_path, "stderr")):
        if not os.path.isfile(source):
            continue
        target_name = (base + ".txt") if exec_index == 0 else ("%s.%d.txt" % (base, exec_index))
        target = os.path.join(logs, target_name)
        shutil.copy2(source, target)
        copied.append({"name": "logs/" + target_name, "sha256": sha256_file(target),
                       "bytes": os.path.getsize(target)})
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
        raise WorkerError("run_id and trail are required")
    _safe_component(run_id)
    _safe_component(trail)
    return run_id, trail


def _safe_component(value):
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$", value or ""):
        raise WorkerError("unsafe identifier: %r" % value)
    return value


def _safe_name(name):
    normalised = str(name).replace("\\", "/").strip()
    if normalised.startswith("/") or ".." in normalised.split("/"):
        raise WorkerError("unsafe file name: %r" % name)
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


def _current_user():
    return os.environ.get("USER") or os.environ.get("LOGNAME") or "unknown"


def _uid_gid():
    """The invoking user's ids; the fallback only exists for tests on Windows."""
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


def _write(path, text):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", errors="replace") as handle:
        handle.write(text or "")


def _head_tail(text, head=4000, tail=196000):
    """Keep the first error lines and the end of the output; the file keeps everything."""
    if len(text) <= head + tail:
        return text
    return (text[:head] + "\n...[trimmed in the response; the full text is in the "
            "artifact]...\n" + text[-tail:])


def _fail(message):
    raise WorkerError(message)


class WorkerError(Exception):
    pass


OPS = {"ping": op_ping, "probe": op_probe, "prepare": op_prepare, "exec": op_exec,
       "collect": op_collect, "cleanup": op_cleanup}


def handle(request):
    op = request.get("op")
    handler = OPS.get(op)
    if handler is None:
        return {"ok": False, "error": "unknown op %r" % op, "known": sorted(OPS)}
    try:
        result = handler(request.get("params") or {})
        return {"ok": True, "op": op, "result": result}
    except WorkerError as exc:
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
