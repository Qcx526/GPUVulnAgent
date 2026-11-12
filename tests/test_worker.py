# -*- coding: utf-8 -*-
"""The in-WSL worker: what command it builds, what it refuses, what it cleans up.

These tests run on Windows against the worker module directly. The docker calls are
replaced, so nothing here needs WSL - the real end-to-end runs live in
``test_live_gpu_backend.py``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gpuvulnagent.backends.worker import gpu_worker


@pytest.fixture
def worker_root(tmp_path, monkeypatch):
    root = tmp_path / "worker"
    monkeypatch.setenv("GPUVULN_WORKER_ROOT", str(root))
    return root


def test_version_extraction_prefers_the_full_build():
    text = "nvcc: NVIDIA (R) Cuda compiler driver\nCuda compilation tools, release 12.8, V12.8.93\n"
    assert gpu_worker._version_from(text) == "12.8.93"
    assert gpu_worker._version_from("release 12.4") == "12.4"


def test_tool_status_reports_missing_runnable_and_broken(monkeypatch):
    monkeypatch.setattr(gpu_worker, "find_binary", lambda name: "")
    assert gpu_worker.tool_status("nvcc")["status"] == "missing"

    monkeypatch.setattr(gpu_worker, "find_binary", lambda name: "/usr/local/cuda/bin/" + name)
    monkeypatch.setattr(gpu_worker, "run",
                        lambda argv, **kw: {"exit": 0, "stdout": "release 12.8, V12.8.93",
                                            "stderr": "", "error": ""})
    assert gpu_worker.tool_status("nvcc")["status"] == "ok"

    monkeypatch.setattr(gpu_worker, "run",
                        lambda argv, **kw: {"exit": 126, "stdout": "", "stderr": "denied",
                                            "error": ""})
    broken = gpu_worker.tool_status("nvdisasm")
    assert broken["status"] == "not_runnable"
    assert "denied" in broken["detail"]


def build_command(monkeypatch, worker_root, **overrides):
    captured = {}

    def fake_run_container(command, name, timeout_s):
        captured["command"] = command
        captured["name"] = name
        captured["timeout"] = timeout_s
        return {"stdout": "ok", "stderr": "", "timed_out": False, "exit": 0}

    monkeypatch.setattr(gpu_worker, "_run_container", fake_run_container)
    monkeypatch.setattr(gpu_worker, "_inspect",
                        lambda reference: {"State": {"ExitCode": 0, "OOMKilled": False,
                                                     "Status": "exited"}})
    monkeypatch.setattr(gpu_worker, "_image_meta",
                        lambda image: {"id": "sha256:abc", "digest": "repo@sha256:def"})
    monkeypatch.setattr(gpu_worker, "_collect_artifacts", lambda *a, **k: [])
    monkeypatch.setattr(gpu_worker, "_copy_to_host", lambda *a, **k: [])
    monkeypatch.setattr(gpu_worker, "_remove", lambda *a, **k: {"removed": True})
    monkeypatch.setattr(gpu_worker, "_kill", lambda *a, **k: None)
    monkeypatch.setattr(gpu_worker, "_read_cid", lambda path: "deadbeef")

    params = {"run_id": "run-x", "trail": "trail0", "image": "nvidia/cuda:12.8.0-devel-ubuntu22.04",
              "argv": ["nvcc", "-O2", "poc.cu", "-o", "poc"], "gpu": True,
              "timeout_s": 120}
    params.update(overrides)
    result = gpu_worker.op_exec(params)
    return captured, result


def test_exec_builds_an_allow_listed_command(monkeypatch, worker_root):
    captured, result = build_command(monkeypatch, worker_root)
    command = captured["command"]
    assert command[:2] == ["docker", "run"]
    assert "--privileged" not in command
    assert "--security-opt" in command and "no-new-privileges" in command
    assert "-v" in command
    mount = command[command.index("-v") + 1]
    assert mount.endswith(":/work")
    assert "/var/run/docker.sock" not in " ".join(command)
    assert "--gpus" in command and "all" in command
    assert "--user" in command          # files stay owned by the WSL user
    image_index = command.index("nvidia/cuda:12.8.0-devel-ubuntu22.04")
    assert command[image_index + 1:] == ["nvcc", "-O2", "poc.cu", "-o", "poc"]
    assert result["exit_code"] == 0
    assert result["image_digest"] == "repo@sha256:def"


def test_network_is_allow_listed(monkeypatch, worker_root):
    _, _ = build_command(monkeypatch, worker_root, network="bridge")
    with pytest.raises(gpu_worker.WorkerError):
        gpu_worker.op_exec({"run_id": "r", "trail": "trail0",
                            "image": "nvidia/cuda:12.8.0-devel-ubuntu22.04",
                            "argv": ["true"], "network": "host2"})


def test_bad_image_and_empty_argv_are_refused(monkeypatch, worker_root):
    with pytest.raises(gpu_worker.WorkerError):
        gpu_worker.op_exec({"run_id": "r", "trail": "trail0",
                            "image": "bad image; rm -rf /", "argv": ["true"]})
    with pytest.raises(gpu_worker.WorkerError):
        gpu_worker.op_exec({"run_id": "r", "trail": "trail0",
                            "image": "nvidia/cuda:12.8.0-devel-ubuntu22.04", "argv": []})


def test_secret_shaped_environment_is_refused(monkeypatch, worker_root):
    _, result = build_command(monkeypatch, worker_root,
                              env={"FOO": "1", "DEEPSEEK_API_KEY": "sk-x", "GH_TOKEN": "t"})
    assert result["env_keys"] == ["FOO"]
    assert set(result["refused_env"]) == {"DEEPSEEK_API_KEY", "GH_TOKEN"}


def test_timeout_marks_the_run_and_kills_the_container(monkeypatch, worker_root):
    killed = []

    def fake_run_container(command, name, timeout_s):
        return {"stdout": "", "stderr": "", "timed_out": True, "exit": None}

    monkeypatch.setattr(gpu_worker, "_run_container", fake_run_container)
    monkeypatch.setattr(gpu_worker, "_kill", lambda name, cid: killed.append(name))
    monkeypatch.setattr(gpu_worker, "_inspect",
                        lambda reference: {"State": {"ExitCode": 137, "OOMKilled": False,
                                                     "Status": "exited"}})
    monkeypatch.setattr(gpu_worker, "_image_meta", lambda image: {})
    monkeypatch.setattr(gpu_worker, "_collect_artifacts", lambda *a, **k: [])
    monkeypatch.setattr(gpu_worker, "_copy_to_host", lambda *a, **k: [])
    monkeypatch.setattr(gpu_worker, "_remove", lambda *a, **k: {"removed": True})
    monkeypatch.setattr(gpu_worker, "_read_cid", lambda path: "cid")

    result = gpu_worker.op_exec({"run_id": "run-t", "trail": "trail0",
                                 "image": "nvidia/cuda:12.8.0-devel-ubuntu22.04",
                                 "argv": ["bash", "-lc", "sleep 60"], "timeout_s": 1})
    assert result["timed_out"] is True
    assert killed, "a timed-out container must be killed"
    assert result["exit_code"] == 137


def test_prepare_copies_files_and_hashes_them(monkeypatch, worker_root, tmp_path):
    source = tmp_path / "inputs"
    source.mkdir()
    (source / "poc.cu").write_text("__global__ void k(){}", encoding="utf-8")

    result = gpu_worker.op_prepare({"run_id": "run-p", "trail": "trail0",
                                    "source_dir": str(source), "files": ["poc.cu"]})
    staged = Path(result["workdir"]) / "poc.cu"
    assert staged.is_file()
    assert result["files"][0]["sha256"] == gpu_worker.sha256_file(str(staged))


def test_prepare_refuses_traversal(monkeypatch, worker_root, tmp_path):
    with pytest.raises(gpu_worker.WorkerError):
        gpu_worker.op_prepare({"run_id": "run-p", "trail": "trail0",
                               "source_dir": str(tmp_path), "files": ["../secret.txt"]})


def test_unsafe_identifiers_are_refused(monkeypatch, worker_root):
    with pytest.raises(gpu_worker.WorkerError):
        gpu_worker.op_prepare({"run_id": "../escape", "trail": "trail0",
                               "source_dir": "/tmp", "files": []})


def test_handle_wraps_errors_and_reports_unknown_ops():
    payload = gpu_worker.handle({"op": "nope"})
    assert payload["ok"] is False
    assert "unknown op" in payload["error"]


def test_response_is_wrapped_in_a_sentinel(monkeypatch, capsys):
    monkeypatch.setattr(gpu_worker.sys, "stdin", _Stdin('{"op": "ping"}'))
    gpu_worker.main()
    out = capsys.readouterr().out
    assert gpu_worker.BEGIN in out and gpu_worker.END in out
    body = out.split(gpu_worker.BEGIN)[1].split(gpu_worker.END)[0]
    assert json.loads(body)["op"] == "ping"


class _Stdin:
    def __init__(self, text):
        self._text = text

    def read(self):
        return self._text
