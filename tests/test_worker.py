# -*- coding: utf-8 -*-
"""The in-WSL worker: command allowlist, snapshot, symlinks, cleanup, pull policy.

These tests run on Windows against the worker module directly. Docker is replaced, but the
snapshot and scanning code paths are the real ones - that is where the evidence bugs would
live - so they run against real temporary directories.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from gpuvulnagent.backends.worker import gpu_worker

IMAGE = "nvidia/cuda:12.8.0-devel-ubuntu22.04"


@pytest.fixture
def worker_root(tmp_path, monkeypatch):
    root = tmp_path / "worker"
    monkeypatch.setenv("GPUVULN_WORKER_ROOT", str(root))
    return root


def workdir_for(worker_root: Path, run_id: str = "run-x", trail: str = "trail0") -> Path:
    return worker_root / "runs" / run_id / trail / "work"


def _mount_source(command):
    if "-v" in command:
        spec = command[command.index("-v") + 1]
        return spec.split(":/work")[0]
    return ""


def base_params(**overrides):
    params = {"run_id": "run-x", "trail": "trail0", "image": IMAGE,
              "argv": ["nvcc", "-O2", "poc.cu", "-o", "poc"], "timeout_s": 60}
    params.update(overrides)
    return params


class Harness:
    """Replaces docker with a function that can touch the work directory."""

    def __init__(self, monkeypatch, worker_root, *, behaviour=None, inspect=None,
                 cleanup_exit=0, timed_out=False):
        self.commands = []
        self.killed = []
        self.removed = []
        self.worker_root = worker_root

        def fake_run_container(command, name, timeout_s):
            self.commands.append({"command": list(command), "name": name,
                                  "timeout": timeout_s})
            if behaviour:
                behaviour(_mount_source(command))
            if timed_out:
                return {"stdout": "started\n", "stderr": "", "timed_out": True,
                        "exit": None, "duration_ms": 3000}
            return {"stdout": "container stdout\n", "stderr": "", "timed_out": False,
                    "exit": 0, "duration_ms": 12}

        monkeypatch.setattr(gpu_worker, "_run_container", fake_run_container)
        monkeypatch.setattr(gpu_worker, "_inspect", lambda ref: inspect or
                            {"State": {"ExitCode": 0, "OOMKilled": False, "Status": "exited"}})
        monkeypatch.setattr(gpu_worker, "_image_meta",
                            lambda image: {"id": "sha256:image", "digest": "repo@sha256:def"})
        monkeypatch.setattr(gpu_worker, "_read_cid", lambda path: "cid123")
        monkeypatch.setattr(gpu_worker, "_kill", lambda name, cid: self.killed.append(name))
        monkeypatch.setattr(gpu_worker, "_remove",
                            lambda cid, name: self.removed.append(cid or name) or
                            {"attempted": True, "target": cid or name, "exit": cleanup_exit,
                             "detail": "removed" if cleanup_exit == 0 else "still running"})
        monkeypatch.setattr(gpu_worker, "ensure_supervisor",
                            lambda params: {"ok": False, "error": "not built in tests"})
        monkeypatch.setattr(gpu_worker, "_ensure_image", lambda image, policy, timeout:
                            {"policy": policy, "present_before": True, "pulled": False,
                             "duration_ms": 0, "error": "", "ok": True})


def _fake_supervisor(worker_root: Path) -> str:
    path = worker_root / "bin" / "gpuvuln_supervise"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(path, 0o755)
    return str(path)


def test_command_is_allow_listed(monkeypatch, worker_root):
    harness = Harness(monkeypatch, worker_root)
    result = gpu_worker.op_exec(base_params(gpu=True))

    command = harness.commands[0]["command"]
    assert command[:2] == ["docker", "run"]
    assert "--privileged" not in command
    assert "--security-opt" in command and "no-new-privileges" in command
    assert "/var/run/docker.sock" not in " ".join(command)
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--gpus") + 1] == "all"
    assert "--user" in command
    assert command[command.index("-v") + 1].endswith(":/work")
    assert any("gpuvulnagent.run_id=run-x" in str(item) for item in command)
    image_index = command.index(IMAGE)
    assert command[image_index + 1:] == ["nvcc", "-O2", "poc.cu", "-o", "poc"]
    assert result["image_digest"] == "repo@sha256:def"
    assert result["cleanup_ok"] is True


def test_network_and_pull_policy_are_allow_listed(monkeypatch, worker_root):
    Harness(monkeypatch, worker_root)
    with pytest.raises(gpu_worker._WorkerFault):
        gpu_worker.op_exec(base_params(network="host2"))
    with pytest.raises(gpu_worker._WorkerFault):
        gpu_worker.op_exec(base_params(pull_policy="sometimes"))


def test_bad_image_and_empty_argv_are_refused(monkeypatch, worker_root):
    Harness(monkeypatch, worker_root)
    with pytest.raises(gpu_worker._WorkerFault):
        gpu_worker.op_exec(base_params(image="bad image; rm -rf /"))
    with pytest.raises(gpu_worker._WorkerFault):
        gpu_worker.op_exec(base_params(argv=[]))


def test_secret_environment_is_refused(monkeypatch, worker_root):
    Harness(monkeypatch, worker_root)
    result = gpu_worker.op_exec(base_params(env={"FOO": "1", "DEEPSEEK_API_KEY": "sk-x",
                                                "GH_TOKEN": "t"}))
    assert result["env_keys"] == ["FOO"]
    assert set(result["refused_env"]) == {"DEEPSEEK_API_KEY", "GH_TOKEN"}


def test_supervisor_wraps_the_command_when_it_is_available(monkeypatch, worker_root):
    harness = Harness(monkeypatch, worker_root)
    monkeypatch.setattr(gpu_worker, "ensure_supervisor",
                        lambda params: {"ok": True, "path": _fake_supervisor(worker_root),
                                        "sha256": "x", "built": True, "static": True})
    gpu_worker.op_exec(base_params())
    command = harness.commands[0]["command"]
    image_index = command.index(IMAGE)
    assert command[image_index + 1] == "/work/.gpuvulnagent/gpuvuln_supervise"
    assert command[image_index + 2] == "/work/.gpuvulnagent/status.json"
    assert command[image_index + 3:] == ["nvcc", "-O2", "poc.cu", "-o", "poc"]


def test_snapshot_records_created_changed_and_deleted(monkeypatch, worker_root):
    workdir = workdir_for(worker_root)
    workdir.mkdir(parents=True)
    (workdir / "keep.txt").write_text("unchanged", encoding="utf-8")
    (workdir / "gone.txt").write_text("will vanish", encoding="utf-8")

    def behaviour(path):
        (Path(path) / "new.bin").write_bytes(b"\x00\x01\x02")
        (Path(path) / "mutated.cu").write_text("version A", encoding="utf-8")
        (Path(path) / "gone.txt").unlink()

    Harness(monkeypatch, worker_root, behaviour=behaviour)
    result = gpu_worker.op_exec(base_params())

    snapshot = result["snapshot"]
    assert "new.bin" in snapshot["created"]
    assert "mutated.cu" in snapshot["created"]
    assert snapshot["deleted"] == ["gone.txt"]
    assert snapshot["unchanged_count"] == 1
    artifacts = Path(result["exec_dir"]) / "artifacts"
    assert (artifacts / "new.bin").is_file()
    assert not (artifacts / "gone.txt").exists()


def test_two_executions_with_the_same_name_keep_both_versions(monkeypatch, worker_root):
    workdir = workdir_for(worker_root)
    workdir.mkdir(parents=True)
    versions = [b"version-A", b"version-B"]

    def behaviour(path):
        (Path(path) / "poc.cu").write_bytes(versions.pop(0))

    Harness(monkeypatch, worker_root, behaviour=behaviour)
    first = gpu_worker.op_exec(base_params(exec_index=0))
    second = gpu_worker.op_exec(base_params(exec_index=1))

    first_file = Path(first["exec_dir"]) / "artifacts" / "poc.cu"
    second_file = Path(second["exec_dir"]) / "artifacts" / "poc.cu"
    assert first_file.read_bytes() == b"version-A"
    assert second_file.read_bytes() == b"version-B"
    assert first["snapshot"]["changed"] == []
    assert second["snapshot"]["changed"] == ["poc.cu"]
    # The first snapshot is untouched by the second run.
    assert first["snapshot"]["post_files"]["poc.cu"] != second["snapshot"]["post_files"]["poc.cu"]


def test_symlink_out_of_the_work_root_is_not_collected(monkeypatch, worker_root, tmp_path):
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("host secret", encoding="utf-8")
    workdir = workdir_for(worker_root)
    workdir.mkdir(parents=True)

    def behaviour(path):
        os.symlink(str(outside), str(Path(path) / "leak.txt"))
        (Path(path) / "real.txt").write_text("real output", encoding="utf-8")

    Harness(monkeypatch, worker_root, behaviour=behaviour)
    result = gpu_worker.op_exec(base_params())

    skipped = {item["name"]: item for item in result["snapshot"]["skipped_symlinks"]}
    assert "leak.txt" in skipped
    assert "symlink" in skipped["leak.txt"]["reason"]
    # Windows reports readlink with an extended-length prefix; compare the name.
    assert Path(skipped["leak.txt"]["target"]).name == outside.name
    artifacts = Path(result["exec_dir"]) / "artifacts"
    assert not (artifacts / "leak.txt").exists()
    assert (artifacts / "real.txt").is_file()
    for path in artifacts.rglob("*"):
        if path.is_file():
            assert b"host secret" not in path.read_bytes()


def test_symlinked_directory_is_not_entered(monkeypatch, worker_root, tmp_path):
    outside = tmp_path / "outside-dir"
    outside.mkdir()
    (outside / "secret.txt").write_text("nested secret", encoding="utf-8")
    workdir = workdir_for(worker_root)
    workdir.mkdir(parents=True)

    def behaviour(path):
        os.symlink(str(outside), str(Path(path) / "linkdir"))

    Harness(monkeypatch, worker_root, behaviour=behaviour)
    result = gpu_worker.op_exec(base_params())
    names = [item["name"] for item in result["snapshot"]["skipped_symlinks"]]
    assert "linkdir" in names
    assert not (Path(result["exec_dir"]) / "artifacts" / "linkdir").exists()


def test_timeout_kills_the_container(monkeypatch, worker_root):
    harness = Harness(monkeypatch, worker_root, timed_out=True)
    result = gpu_worker.op_exec(base_params(timeout_s=3))
    assert result["timed_out"] is True
    assert harness.killed, "a timed-out container must be killed"
    assert result["cleanup_ok"] is True


def test_cleanup_runs_even_when_the_snapshot_fails(monkeypatch, worker_root):
    harness = Harness(monkeypatch, worker_root)

    def broken_snapshot(*args, **kwargs):
        raise RuntimeError("disk exploded during snapshot")

    monkeypatch.setattr(gpu_worker, "_snapshot", broken_snapshot)
    result = gpu_worker.op_exec(base_params())

    assert "disk exploded" in result["error"]
    assert harness.removed, "the container must be removed even when collection fails"
    assert result["cleanup_ok"] is True


def test_cleanup_failure_is_recorded(monkeypatch, worker_root):
    Harness(monkeypatch, worker_root, cleanup_exit=1)
    result = gpu_worker.op_exec(base_params())
    assert result["cleanup_ok"] is False
    assert result["cleanup"]["exit"] == 1


def test_prepare_copies_files_and_hashes_them(monkeypatch, worker_root, tmp_path):
    source = tmp_path / "inputs"
    source.mkdir()
    (source / "poc.cu").write_text("__global__ void k(){}", encoding="utf-8")
    result = gpu_worker.op_prepare({"run_id": "run-p", "trail": "trail0",
                                    "source_dir": str(source), "files": ["poc.cu"]})
    staged = Path(result["workdir"]) / "poc.cu"
    assert staged.is_file()
    assert result["files"][0]["sha256"] == gpu_worker.sha256_file(str(staged))


def test_prepare_refuses_traversal_and_symlinked_inputs(monkeypatch, worker_root, tmp_path):
    (tmp_path / "real.txt").write_text("x", encoding="utf-8")
    with pytest.raises(gpu_worker._WorkerFault):
        gpu_worker.op_prepare({"run_id": "run-p", "trail": "trail0",
                               "source_dir": str(tmp_path), "files": ["../secret.txt"]})
    os.symlink(str(tmp_path / "real.txt"), str(tmp_path / "link.txt"))
    with pytest.raises(gpu_worker._WorkerFault):
        gpu_worker.op_prepare({"run_id": "run-p", "trail": "trail0",
                               "source_dir": str(tmp_path), "files": ["link.txt"]})


def test_unsafe_identifiers_are_refused(monkeypatch, worker_root):
    with pytest.raises(gpu_worker._WorkerFault):
        gpu_worker.op_prepare({"run_id": "../escape", "trail": "trail0",
                               "source_dir": "/tmp", "files": []})


def test_pull_policy_missing_pulls_only_when_absent(monkeypatch):
    calls = []
    state = {"present": True}

    def fake_run(argv, timeout=60, cwd=None, env=None):
        calls.append(list(argv))
        if argv[:3] == ["docker", "image", "inspect"]:
            return {"exit": 0 if state["present"] else 1, "stdout": "", "stderr": "",
                    "error": ""}
        return {"exit": 0, "stdout": "pulled", "stderr": "", "error": ""}

    monkeypatch.setattr(gpu_worker, "run", fake_run)

    result = gpu_worker._ensure_image(IMAGE, "missing", 60)
    assert result["pulled"] is False and result["ok"] is True
    assert not any(call[:2] == ["docker", "pull"] for call in calls)

    calls.clear()
    state["present"] = False
    result = gpu_worker._ensure_image(IMAGE, "missing", 60)
    assert result["pulled"] is True
    assert any(call[:2] == ["docker", "pull"] for call in calls)

    calls.clear()
    result = gpu_worker._ensure_image(IMAGE, "never", 60)
    assert result["ok"] is False
    assert "pull_policy=never" in result["error"]
    assert not any(call[:2] == ["docker", "pull"] for call in calls)


def test_pull_failure_is_reported_not_swallowed(monkeypatch):
    def fake_run(argv, timeout=60, cwd=None, env=None):
        if argv[:3] == ["docker", "image", "inspect"]:
            return {"exit": 1, "stdout": "", "stderr": "", "error": ""}
        return {"exit": 1, "stdout": "", "stderr": "manifest unknown", "error": ""}

    monkeypatch.setattr(gpu_worker, "run", fake_run)
    result = gpu_worker._ensure_image(IMAGE, "always", 60)
    assert result["ok"] is False
    assert "manifest unknown" in result["error"]


def test_version_extraction_and_tool_status(monkeypatch):
    assert gpu_worker._version_from("release 12.8, V12.8.93") == "12.8.93"
    monkeypatch.setattr(gpu_worker, "find_binary", lambda name: "")
    assert gpu_worker.tool_status("nvcc")["status"] == "missing"
    monkeypatch.setattr(gpu_worker, "find_binary", lambda name: "/usr/local/cuda/bin/" + name)
    monkeypatch.setattr(gpu_worker, "run",
                        lambda argv, **kw: {"exit": 0, "stdout": "release 12.8, V12.8.93",
                                            "stderr": "", "error": ""})
    assert gpu_worker.tool_status("nvcc")["status"] == "ok"


def test_handle_reports_unknown_ops_and_wraps_faults():
    payload = gpu_worker.handle({"op": "nope"})
    assert payload["ok"] is False and "unknown op" in payload["error"]
    payload = gpu_worker.handle({"op": "exec", "params": {"run_id": "../x", "trail": "t"}})
    assert payload["ok"] is False and "unsafe identifier" in payload["error"]


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
