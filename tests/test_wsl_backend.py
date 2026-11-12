# -*- coding: utf-8 -*-
"""Windows-side backend: request shape, classification, artifact integrity, snapshots.

The transport is replaced, so these tests are offline. The real WSL/Docker/GPU runs are
gated behind ``GPUVULNAGENT_LIVE=1`` in ``test_live_gpu_backend.py``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from gpuvulnagent.backends.base import BackendError
from gpuvulnagent.backends.trails import TrailStore
from gpuvulnagent.backends.wsl_docker import WslConfig, WslDockerBackend, windows_to_wsl
from gpuvulnagent.evidence.hashing import sha256_bytes

IMAGE = "nvidia/cuda:12.8.0-devel-ubuntu22.04"


def probe_payload() -> dict:
    return {"distro": "Ubuntu 22.04.5 LTS", "distro_version": "22.04",
            "kernel": "6.6.87.2-microsoft-standard-WSL2", "user": "pocdev",
            "docker": {"version": "29.8.2", "running": True, "detail": ""},
            "gpu": {"name": "NVIDIA GeForce GTX 1660", "memory": "6144 MiB",
                    "compute_capability": "7.5", "driver": "610.47"},
            "cuda": {"toolkit": "12.8.93"},
            "tools": {"nvcc": {"status": "ok", "path": "/usr/local/cuda/bin/nvcc",
                               "version": "12.8.93", "detail": ""}},
            "images": ["nvidia/cuda:12.8.0-devel-ubuntu22.04"], "problems": [],
            "gpu_in_container": {"ok": True, "raw": "NVIDIA GeForce GTX 1660, 7.5, 6144 MiB"},
            "supervisor": {"ok": True, "built": False, "static": True}}


def exec_payload(index=0, **overrides) -> dict:
    payload = {"exit_code": 0, "timed_out": False, "oom_killed": False, "state": "exited",
               "duration_ms": 2100, "started_at": "2026-11-12T10:00:00",
               "finished_at": "2026-11-12T10:00:02", "container_id": "abc123def4567890",
               "container_name": "gpuvulnagent-run-x-trail0-1", "image": IMAGE,
               "image_id": "sha256:image", "image_digest": "nvidia/cuda@sha256:digest",
               "argv": ["nvcc", "-O2", "poc.cu", "-o", "poc"], "workdir": "/work",
               "network": "none", "gpu": True, "env_keys": [], "refused_env": [],
               "as_root": False, "stdout": "GPU: NVIDIA GeForce GTX 1660\nRESULT=30\n",
               "stderr": "", "stdout_sha256": "a" * 64, "stderr_sha256": "b" * 64,
               "stdout_bytes": 42, "stderr_bytes": 0, "response_trimmed": False,
               "snapshot": {"execution_index": index, "created": ["poc"], "changed": [],
                            "deleted": [], "unchanged_count": 1, "skipped_symlinks": [],
                            "errors": [], "pre_files": {}, "post_files": {}},
               "image_pull": {"policy": "missing", "present_before": True, "pulled": False,
                              "ok": True, "error": "", "duration_ms": 0},
               "supervision": {"used": True, "readable": True, "exited": True,
                               "exit_code": 0, "signaled": False, "signal": 0,
                               "signal_name": ""},
               "cleanup": {"attempted": True, "exit": 0, "detail": "removed"},
               "cleanup_ok": True, "copied_to_host": [], "error": ""}
    payload.update(overrides)
    return payload


def make_backend(monkeypatch, script) -> tuple:
    backend = WslDockerBackend(WslConfig(distro="Test", user="tester",
                                         worker_root="/home/tester/worker"))
    calls = []

    def fake_call(op, params=None, timeout=None):
        calls.append({"op": op, "params": params or {}, "timeout": timeout})
        if op == "prepare":
            return {"workdir": "/home/tester/worker/runs/run-x/trail0/work", "files": []}
        if op == "probe":
            return probe_payload()
        if op == "cleanup":
            return {"removed": []}
        return script(op, params or {}, calls)

    monkeypatch.setattr(backend, "_call", fake_call)
    return backend, calls


def trail(tmp_path: Path):
    return TrailStore(tmp_path / "trails", "run-x").allocate(purpose="unit")


def add_artifact(trail_obj, name: str, text: str) -> dict:
    path = trail_obj.root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    payload = text.encode("utf-8")
    return {"name": name, "sha256": sha256_bytes(payload), "bytes": len(payload),
            "skipped": ""}


def test_probe_maps_the_report(monkeypatch):
    backend, _ = make_backend(monkeypatch, lambda op, params, calls: probe_payload())
    report = backend.probe()
    assert report.available is True
    assert report.distro == "Ubuntu 22.04.5 LTS"
    assert report.docker_version == "29.8.2"
    assert report.gpu_name == "NVIDIA GeForce GTX 1660"
    assert report.compute_capability == "7.5"
    assert report.cuda_version == "12.8.93"
    assert report.tools["nvcc"].status == "ok"


def test_exec_registers_this_executions_artifacts_only(monkeypatch, tmp_path):
    handle = trail(tmp_path)
    holder = {}

    def script(op, params, calls):
        holder["item"] = add_artifact(handle, "execs/exec00/outputs/poc", "binary-bytes")
        return exec_payload(copied_to_host=[holder["item"]])

    backend, calls = make_backend(monkeypatch, script)
    result = backend.exec(handle, argv=["nvcc", "-O2", "poc.cu", "-o", "poc"])

    assert [call["op"] for call in calls][:2] == ["prepare", "exec"]
    params = calls[1]["params"]
    assert params["pull_policy"] == "missing"
    assert params["supervise"] is True
    assert params["exec_index"] == 0
    assert params["host_output_dir"].startswith("/mnt/")

    assert result.ok is True
    assert result.exec_dir == "execs/exec00"
    assert result.termination["kind"] == "success"
    assert result.signal_verified is True
    assert result.image_digest == "nvidia/cuda@sha256:digest"
    assert result.cleanup_ok is True

    registered = {item.name: item for item in handle.files}
    assert registered["execs/exec00/outputs/poc"].kind == "output"
    assert "execs/exec00/result.json" in registered
    assert "execs/exec00/snapshot.json" in registered
    assert result.artifacts and all(item.name.startswith("execs/exec00/")
                                    for item in result.artifacts)

    manifest = handle.manifest()
    assert manifest["executions"][0]["exec_dir"] == "execs/exec00"
    assert (handle.root / "execs/exec00/result.json").is_file()
    assert (handle.root / "execs/exec00/snapshot.json").is_file()


def test_a_second_execution_gets_its_own_directory(monkeypatch, tmp_path):
    handle = trail(tmp_path)
    versions = ["version-A", "version-B"]

    def script(op, params, calls):
        index = params["exec_index"]
        item = add_artifact(handle, "execs/exec%02d/outputs/poc.cu" % index, versions[index])
        return exec_payload(index=index, copied_to_host=[item])

    backend, _ = make_backend(monkeypatch, script)
    first = backend.exec(handle, argv=["true"])
    second = backend.exec(handle, argv=["true"])

    assert first.exec_dir == "execs/exec00"
    assert second.exec_dir == "execs/exec01"
    assert (handle.root / "execs/exec00/outputs/poc.cu").read_text() == "version-A"
    assert (handle.root / "execs/exec01/outputs/poc.cu").read_text() == "version-B"
    names = [item.name for item in handle.files]
    assert "execs/exec00/outputs/poc.cu" in names
    assert "execs/exec01/outputs/poc.cu" in names
    assert len(handle.manifest()["executions"]) == 2


def test_artifact_tampering_is_caught(monkeypatch, tmp_path):
    handle = trail(tmp_path)
    item = add_artifact(handle, "execs/exec00/outputs/poc", "real-bytes")

    def script(op, params, calls):
        return exec_payload(copied_to_host=[dict(item, sha256="0" * 64)])

    backend, _ = make_backend(monkeypatch, script)
    with pytest.raises(BackendError):
        backend.exec(handle, argv=["true"])


def test_a_symlinked_artifact_is_refused(monkeypatch, tmp_path):
    handle = trail(tmp_path)
    target = tmp_path / "outside.txt"
    target.write_text("outside", encoding="utf-8")
    link = handle.root / "execs/exec00/outputs/link"
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.symlink(str(target), str(link))
    except (OSError, NotImplementedError):
        pytest.skip("this host cannot create symlinks")

    def script(op, params, calls):
        return exec_payload(copied_to_host=[{"name": "execs/exec00/outputs/link",
                                             "sha256": sha256_bytes(b"outside"),
                                             "bytes": 7}])

    backend, _ = make_backend(monkeypatch, script)
    with pytest.raises(BackendError):
        backend.exec(handle, argv=["true"])


def test_signalled_child_is_a_crash(monkeypatch, tmp_path):
    handle = trail(tmp_path)

    def script(op, params, calls):
        return exec_payload(exit_code=139, supervision={
            "used": True, "readable": True, "exited": False, "signaled": True,
            "signal": 11, "signal_name": "SIGSEGV"})

    backend, _ = make_backend(monkeypatch, script)
    result = backend.exec(handle, argv=["./poc"])
    assert result.termination["kind"] == "sigsegv"
    assert result.termination["crash"] is True
    assert result.signal_verified is True


def test_normal_exit_with_code_139_is_not_a_crash(monkeypatch, tmp_path):
    handle = trail(tmp_path)

    def script(op, params, calls):
        return exec_payload(exit_code=139, supervision={
            "used": True, "readable": True, "exited": True, "exit_code": 139,
            "signaled": False, "signal": 0, "signal_name": ""})

    backend, _ = make_backend(monkeypatch, script)
    result = backend.exec(handle, argv=["./returns_139"])
    assert result.termination["kind"] == "error_exit"
    assert result.termination["crash"] is False
    assert result.signal_verified is True


def test_exit_139_without_supervision_is_unverified_not_a_crash(monkeypatch, tmp_path):
    handle = trail(tmp_path)

    def script(op, params, calls):
        return exec_payload(exit_code=139, supervision={"used": False, "readable": False},
                            supervise_error="supervisor unavailable")

    backend, _ = make_backend(monkeypatch, script)
    result = backend.exec(handle, argv=["./poc"], supervise=False)
    assert result.termination["kind"] == "unverified_signal"
    assert result.termination["crash"] is False
    assert result.signal_verified is False


def test_timeout_payload_is_classified_as_timeout(monkeypatch, tmp_path):
    handle = trail(tmp_path)

    def script(op, params, calls):
        return exec_payload(exit_code=137, timed_out=True,
                            supervision={"used": True, "readable": False})

    backend, _ = make_backend(monkeypatch, script)
    result = backend.exec(handle, argv=["bash", "-lc", "sleep 60"], timeout_s=5)
    assert result.timed_out is True
    assert result.termination["kind"] == "timeout"
    assert result.termination["crash"] is False


def test_daemon_failure_is_a_container_error(monkeypatch, tmp_path):
    handle = trail(tmp_path)

    def script(op, params, calls):
        return exec_payload(exit_code=128, container_id="",
                            stderr="docker: Error response from daemon: OCI runtime create failed")

    backend, _ = make_backend(monkeypatch, script)
    result = backend.exec(handle, argv=["nvidia-smi", "-L"], gpus="device=99")
    assert result.termination["kind"] == "container_error"
    assert result.termination["crash"] is False


def test_pull_policy_is_passed_and_recorded(monkeypatch, tmp_path):
    handle = trail(tmp_path)

    def script(op, params, calls):
        return exec_payload(image_pull={"policy": params["pull_policy"],
                                        "present_before": False, "pulled": True,
                                        "ok": True, "error": "", "duration_ms": 1200})

    backend, calls = make_backend(monkeypatch, script)
    result = backend.exec(handle, argv=["true"], pull_policy="always")
    assert calls[1]["params"]["pull_policy"] == "always"
    assert result.pull_policy == "always"
    assert result.image_pull["pulled"] is True
    with pytest.raises(BackendError):
        backend.exec(handle, argv=["true"], pull_policy="sometimes")


def test_secret_environment_is_refused_before_any_call(monkeypatch, tmp_path):
    handle = trail(tmp_path)
    backend, calls = make_backend(monkeypatch, lambda op, params, calls: exec_payload())
    with pytest.raises(BackendError):
        backend.exec(handle, argv=["true"], env={"DEEPSEEK_API_KEY": "sk-test"})
    assert calls == []


def test_bad_image_and_empty_argv_are_refused(monkeypatch, tmp_path):
    handle = trail(tmp_path)
    backend, calls = make_backend(monkeypatch, lambda op, params, calls: exec_payload())
    with pytest.raises(BackendError):
        backend.exec(handle, argv=["true"], image="not a valid image; rm -rf /")
    with pytest.raises(BackendError):
        backend.exec(handle, argv=[])
    assert calls == []


def test_config_from_settings_and_describe():
    class Backend:
        wsl_distro = "Ubuntu-24.04"
        wsl_user = "researcher"
        wsl_worker_root = "/home/researcher/gpuvulnagent"
        gpu_image = "nvidia/cuda:13.0.0-devel-ubuntu24.04"
        call_timeout = 42
        pull_policy = "always"

    class Settings:
        backend = Backend()

    config = WslConfig.from_settings(Settings())
    assert config.distro == "Ubuntu-24.04"
    assert config.user == "researcher"
    assert config.image == "nvidia/cuda:13.0.0-devel-ubuntu24.04"
    assert config.call_timeout == 42
    assert config.pull_policy == "always"

    described = WslDockerBackend(config).describe()
    assert described["distro"] == "Ubuntu-24.04"
    assert described["pull_policy"] == "always"
    assert "supervisor_source_sha256" in described
    assert "key" not in json.dumps(described).lower()


def test_windows_paths_map_into_wsl():
    assert windows_to_wsl(r"F:\qcx\code\GPUVulnAgent\.local") == \
        "/mnt/f/qcx/code/GPUVulnAgent/.local"
    assert windows_to_wsl("/home/pocdev/x") == "/home/pocdev/x"
    with pytest.raises(Exception):
        windows_to_wsl("relative/path")
