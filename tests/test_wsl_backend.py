# -*- coding: utf-8 -*-
"""Windows-side backend: request shape, classification, artifact integrity.

The transport is replaced, so these tests are offline. The real WSL/Docker/GPU runs are
gated behind ``GPUVULNAGENT_LIVE=1`` in ``test_live_gpu_backend.py``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gpuvulnagent.backends.base import BackendError
from gpuvulnagent.backends.trails import TrailStore
from gpuvulnagent.backends.wsl_docker import WslConfig, WslDockerBackend, windows_to_wsl
from gpuvulnagent.evidence.hashing import sha256_bytes

IMAGE = "nvidia/cuda:12.8.0-devel-ubuntu22.04"


def make_backend(monkeypatch, script) -> tuple:
    backend = WslDockerBackend(WslConfig(distro="Test", user="tester",
                                         worker_root="/home/tester/worker"))
    calls = []

    def fake_call(op, params=None, timeout=120):
        calls.append({"op": op, "params": params or {}, "timeout": timeout})
        if op == "prepare":
            return {"workdir": "/home/tester/worker/runs/run-x/trail0/work", "files": []}
        if op == "probe":
            return probe_payload()
        if op == "cleanup":
            return {"removed": []}
        return script(op, params or {}, calls)

    monkeypatch.setattr(backend, "_call", fake_call)
    monkeypatch.setattr(backend, "_gpu_name", lambda: "NVIDIA GeForce GTX 1660")
    monkeypatch.setattr(backend, "_cuda_version", lambda: "12.8.93")
    return backend, calls


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
            "gpu_in_container": {"ok": True, "raw": "NVIDIA GeForce GTX 1660, 7.5, 6144 MiB"}}


def exec_payload(**overrides) -> dict:
    payload = {"exit_code": 0, "timed_out": False, "oom_killed": False, "state": "exited",
               "duration_ms": 2100, "started_at": "2026-11-12T10:00:00",
               "finished_at": "2026-11-12T10:00:02", "container_id": "abc123def4567890",
               "container_name": "gpuvulnagent-run-x-trail0-1", "image": IMAGE,
               "image_id": "sha256:image", "image_digest": "nvidia/cuda@sha256:digest",
               "argv": ["nvcc", "-O2", "poc.cu", "-o", "poc"], "workdir": "/work",
               "network": "none", "gpu": True, "env_keys": [], "refused_env": [],
               "stdout": "GPU: NVIDIA GeForce GTX 1660\nRESULT=30\n", "stderr": "",
               "stdout_sha256": "", "stderr_sha256": "", "stdout_bytes": 42,
               "stderr_bytes": 0, "response_trimmed": False, "artifacts": [],
               "copied_to_host": [], "host_output_dir": "/mnt/f/x", "docker_error": ""}
    payload.update(overrides)
    return payload


def trail(tmp_path: Path):
    return TrailStore(tmp_path / "trails", "run-x").allocate(purpose="unit")


def add_output(trail_obj, name: str, text: str) -> dict:
    path = trail_obj.root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return {"name": name, "sha256": sha256_bytes(text.encode("utf-8")),
            "bytes": len(text.encode("utf-8"))}


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


def test_exec_returns_the_evidence_fields_and_registers_artifacts(monkeypatch, tmp_path):
    handle = trail(tmp_path)
    copied_holder = {}

    def script(op, params, calls):
        copied_holder["item"] = add_output(handle, "outputs/poc", "binary-bytes")
        return exec_payload(copied_to_host=[copied_holder["item"]])

    backend, calls = make_backend(monkeypatch, script)
    result = backend.exec(handle, argv=["nvcc", "-O2", "poc.cu", "-o", "poc"])

    assert calls[0]["op"] == "prepare"
    assert calls[1]["op"] == "exec"
    assert calls[1]["params"]["gpu"] is True
    assert calls[1]["params"]["image"] == IMAGE
    assert calls[1]["params"]["host_output_dir"].startswith("/mnt/")

    assert result.ok is True
    assert result.exit_code == 0
    assert result.termination["kind"] == "success"
    assert result.image_digest == "nvidia/cuda@sha256:digest"
    assert result.container_id == "abc123def4567890"
    assert result.gpu_name == "NVIDIA GeForce GTX 1660"

    registered = {item.name: item for item in handle.files}
    assert registered["outputs/poc"].kind == "output"
    assert registered["outputs/poc"].sha256 == copied_holder["item"]["sha256"]
    manifest = handle.manifest()
    assert manifest["executions"][0]["exit_code"] == 0
    assert manifest["executions"][0]["image_digest"] == "nvidia/cuda@sha256:digest"
    assert (handle.root / "result.json").is_file()


def test_second_execution_in_one_trail_does_not_overwrite_the_first(monkeypatch, tmp_path):
    handle = trail(tmp_path)

    def script(op, params, calls):
        index = params["exec_index"]
        item = add_output(handle, "logs/stdout.txt" if index == 0
                          else "logs/stdout.1.txt", "run %d" % index)
        return exec_payload(copied_to_host=[item])

    backend, _ = make_backend(monkeypatch, script)
    backend.exec(handle, argv=["nvcc", "--version"])
    second = backend.exec(handle, argv=["./poc"])
    assert len(second.trail) > 0
    assert (handle.root / "result.json").is_file()
    assert (handle.root / "result.1.json").is_file()
    assert len(handle.manifest()["executions"]) == 2


def test_artifact_tampering_is_caught(monkeypatch, tmp_path):
    handle = trail(tmp_path)
    item = add_output(handle, "outputs/poc", "real-bytes")

    def script(op, params, calls):
        return exec_payload(copied_to_host=[dict(item, sha256="0" * 64)])

    backend, _ = make_backend(monkeypatch, script)
    with pytest.raises(BackendError):
        backend.exec(handle, argv=["true"])


def test_timeout_payload_is_classified_as_timeout(monkeypatch, tmp_path):
    handle = trail(tmp_path)

    def script(op, params, calls):
        return exec_payload(exit_code=137, timed_out=True, state="exited")

    backend, _ = make_backend(monkeypatch, script)
    result = backend.exec(handle, argv=["bash", "-lc", "sleep 60"], timeout_s=5)
    assert result.timed_out is True
    assert result.termination["kind"] == "timeout"
    assert result.termination["crash"] is False


def test_target_segfault_is_a_crash(monkeypatch, tmp_path):
    handle = trail(tmp_path)

    def script(op, params, calls):
        return exec_payload(exit_code=139, stderr="Segmentation fault")

    backend, _ = make_backend(monkeypatch, script)
    result = backend.exec(handle, argv=["./poc"])
    assert result.termination["kind"] == "sigsegv"
    assert result.termination["crash"] is True


def test_daemon_failure_is_a_container_error(monkeypatch, tmp_path):
    handle = trail(tmp_path)

    def script(op, params, calls):
        return exec_payload(exit_code=128, container_id="",
                            stderr="docker: Error response from daemon: OCI runtime create failed")

    backend, _ = make_backend(monkeypatch, script)
    result = backend.exec(handle, argv=["nvidia-smi", "-L"], gpus="device=99")
    assert result.termination["kind"] == "container_error"
    assert result.termination["crash"] is False


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


def test_windows_paths_map_into_wsl():
    assert windows_to_wsl(r"F:\qcx\code\GPUVulnAgent\.local") == \
        "/mnt/f/qcx/code/GPUVulnAgent/.local"
    assert windows_to_wsl("/home/pocdev/x") == "/home/pocdev/x"
    with pytest.raises(Exception):
        windows_to_wsl("relative/path")


def test_describe_exposes_config_without_secrets():
    described = WslDockerBackend(WslConfig()).describe()
    assert described["distro"]
    assert "worker_sha256" in described
    assert "key" not in json.dumps(described).lower()
