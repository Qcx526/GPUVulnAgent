# -*- coding: utf-8 -*-
"""Real WSL2 + Docker + GPU tests. Skipped unless ``GPUVULNAGENT_LIVE=1``.

These are the tests that prove the backend is not a wrapper around a mock:

    GPUVULNAGENT_LIVE=1 .venv/Scripts/python.exe -m pytest tests/test_live_gpu_backend.py -q

They compile and run a CUDA kernel on the real GPU, kill a container at a deadline, and
check that the evidence chain written by the tool layer verifies.
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

import pytest

from gpuvulnagent.backends.trails import TrailStore
from gpuvulnagent.backends.wsl_docker import WslConfig, WslDockerBackend
from gpuvulnagent.config import ConfigLoader
from gpuvulnagent.evidence import ArtifactStore, EvidenceLog, Runner, verify_chain
from gpuvulnagent.memory.store import LayeredMemory
from gpuvulnagent.runtime.workspace import Workspace
from gpuvulnagent.tools.build import build_assembly

LIVE = os.environ.get("GPUVULNAGENT_LIVE") == "1"
pytestmark = pytest.mark.skipif(not LIVE, reason="set GPUVULNAGENT_LIVE=1 to run real "
                                                "WSL/Docker/GPU tests")

VECTOR_ADD = Path(__file__).resolve().parents[1] / "data" / "cases" / "cuda_smoke" / "vector_add.cu"
IMAGE = "nvidia/cuda:12.8.0-devel-ubuntu22.04"


@pytest.fixture(scope="module")
def backend() -> WslDockerBackend:
    return WslDockerBackend(WslConfig.from_settings(ConfigLoader()))


@pytest.fixture
def trail(tmp_path: Path):
    return TrailStore(tmp_path / "trails", "run-live").allocate(purpose="live test")


def test_probe_reports_the_real_environment(backend):
    report = backend.probe(deep=True, force=True)
    assert report.available is True
    assert "22.04" in report.distro
    assert report.docker_running is True
    assert report.docker_version.count(".") >= 1
    assert "GTX 1660" in report.gpu_name
    assert report.compute_capability == "7.5"
    assert report.cuda_version.startswith("12.8")
    assert report.tools["nvcc"].status == "ok"
    assert report.gpu_in_container.get("ok") is True


def test_cuda_kernel_compiles_and_runs_on_the_gpu(backend, trail):
    trail.add_file("vector_add.cu", VECTOR_ADD.read_text(encoding="utf-8"))
    result = backend.exec(
        trail, image=IMAGE, gpu=True, timeout_s=600,
        argv=["bash", "-lc", "nvcc -O2 -arch=sm_75 vector_add.cu -o vector_add && ./vector_add"])
    assert result.exit_code == 0, result.stderr
    assert result.termination["kind"] == "success"
    assert "GPU: NVIDIA GeForce GTX 1660" in result.stdout
    assert "Compute Capability: 7.5" in result.stdout
    assert "CUDA_KERNEL=PASS" in result.stdout
    assert "ELEMENTS=1048576" in result.stdout
    assert "RESULT=30" in result.stdout
    assert result.image_digest.startswith("nvidia/cuda@sha256:")
    assert result.container_id

    outputs = {item.name: item for item in result.artifacts}
    assert "execs/exec00/outputs/vector_add" in outputs
    assert outputs["execs/exec00/outputs/vector_add"].bytes > 100_000
    assert outputs["execs/exec00/outputs/vector_add"].sha256
    assert result.exec_dir == "execs/exec00"
    assert result.signal_verified is True
    assert result.cleanup_ok is True


def test_timeout_kills_the_container_and_leaves_nothing_behind(backend, tmp_path):
    store = TrailStore(tmp_path / "trails", "run-live-timeout")
    trail = store.allocate(purpose="timeout")
    result = backend.exec(trail, image=IMAGE, gpu=True, timeout_s=3,
                          argv=["bash", "-lc", "echo started; sleep 60; echo finished"])
    assert result.timed_out is True
    assert result.termination["kind"] == "timeout"
    assert result.termination["crash"] is False
    assert "started" in result.stdout
    assert "finished" not in result.stdout

    listing = backend._call("cleanup", {"run_id": "run-live-timeout"}, timeout=120)
    assert listing.get("removed") == []


def test_container_exec_tool_writes_verifiable_evidence(tmp_path, monkeypatch):
    for name in ("DEEPSEEK_API_KEY", "TAVILY_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    workspace = Workspace(tmp_path / "ws")
    artifacts = ArtifactStore(tmp_path / "artifacts")
    run_id = "run-live-tool-" + uuid.uuid4().hex[:8]
    log = EvidenceLog(tmp_path / "evidence.jsonl", run_id, artifacts)
    runner = Runner(workspace.root, log, timeout=30)
    memory = LayeredMemory(run_dir=tmp_path, research_root=tmp_path / "archive",
                           run_id=run_id)
    assembly = build_assembly(workspace=workspace, runner=runner, log=log, memory=memory,
                              toolchain_root=None, enable_search=False)

    created = assembly.registry.call("trail_new", {"purpose": "tool-level cuda run"})
    trail_id = created["summary"]["trail"]
    assembly.registry.call("trail_write", {
        "trail": trail_id, "name": "vector_add.cu",
        "content": VECTOR_ADD.read_text(encoding="utf-8")})
    outcome = assembly.registry.call("container_exec", {
        "trail": trail_id, "image": IMAGE,
        "argv": ["bash", "-lc",
                 "nvcc -O2 -arch=sm_75 vector_add.cu -o vector_add && ./vector_add"],
        "timeout_s": 600})

    assert outcome["ok"] is True, outcome.get("error")
    summary = outcome["summary"]
    assert summary["exit"] == 0
    assert summary["termination"] == "success"
    assert summary["image_digest"].startswith("nvidia/cuda@sha256:")
    assert "RESULT=30" in summary["stdout"]
    assert summary["trail"] == trail_id

    records = [json.loads(line) for line in
               (tmp_path / "evidence.jsonl").read_text(encoding="utf-8").splitlines()
               if line.strip()]
    execs = [record for record in records if record["kind"] == "exec"]
    assert len(execs) == 1
    record = execs[0]
    for field in ("run_id", "backend", "image", "image_digest", "container_id", "argv",
                  "cwd", "gpu_name", "cuda", "started_at", "finished_at", "duration_ms",
                  "exit", "timed_out", "oom_killed", "termination", "artifact_hashes",
                  "trail", "stdout_artifact"):
        assert record.get(field) not in (None, ""), field
    assert record["termination"]["kind"] == "success"
    assert any(item["name"].endswith("vector_add") for item in record["artifact_hashes"])
    assert record["signal_verified"] is True
    assert record["cleanup_ok"] is True
    assert record["exec_dir"] == "execs/exec00"
    assert record["snapshot"]["created"]
    assert verify_chain(tmp_path / "evidence.jsonl")["ok"] is True

    manifest = json.loads((tmp_path / "trails" / trail_id / "manifest.json")
                          .read_text(encoding="utf-8"))
    assert manifest["run_id"] == run_id
    assert manifest["executions"][0]["exit_code"] == 0


def test_exit139_and_sigsegv_are_distinguished(backend, tmp_path):
    from gpuvulnagent.backends.trails import TrailStore

    store = TrailStore(tmp_path / "trails", "run-live-signals-" + uuid.uuid4().hex[:8])
    trail = store.allocate(purpose="signal evidence")
    trail.add_file("returns139.c", "int main(void){return 139;}\n")
    trail.add_file("segfaults.c", "int main(){int *p=0;*p=1;return 0;}\n")
    build = backend.exec(trail, image=IMAGE, timeout_s=300, argv=[
        "bash", "-lc",
        "gcc -O0 returns139.c -o returns139 && gcc -O0 segfaults.c -o segfaults && echo ok"])
    assert build.exit_code == 0, build.stderr

    normal = backend.exec(trail, image=IMAGE, timeout_s=120, argv=["./returns139"])
    assert normal.exit_code == 139
    assert normal.termination["kind"] == "error_exit"
    assert normal.termination["crash"] is False
    assert normal.signal_verified is True

    crashed = backend.exec(trail, image=IMAGE, timeout_s=120, argv=["./segfaults"])
    assert crashed.termination["kind"] == "sigsegv"
    assert crashed.termination["crash"] is True
    assert crashed.signal_name == "SIGSEGV"


def test_a_symlink_to_a_host_file_is_not_collected(backend, tmp_path):
    from gpuvulnagent.backends.trails import TrailStore

    store = TrailStore(tmp_path / "trails", "run-live-symlink-" + uuid.uuid4().hex[:8])
    trail = store.allocate(purpose="symlink")
    result = backend.exec(trail, image=IMAGE, timeout_s=300, argv=[
        "bash", "-lc",
        "ln -s /etc/passwd /work/leak.txt; echo kept > /work/real.txt"])
    skipped = {item["name"]: item for item in result.snapshot.get("skipped_symlinks") or []}
    assert "leak.txt" in skipped
    assert not (trail.root / "execs/exec00/outputs/leak.txt").exists()
    assert (trail.root / "execs/exec00/outputs/real.txt").is_file()
    for path in (trail.root / "execs/exec00/outputs").rglob("*"):
        if path.is_file():
            assert b"root:x:" not in path.read_bytes()


def test_exit139_and_sigsegv_are_distinguished(backend, tmp_path):
    from gpuvulnagent.backends.trails import TrailStore

    store = TrailStore(tmp_path / "trails", "run-live-signals-" + uuid.uuid4().hex[:8])
    trail = store.allocate(purpose="signal evidence")
    trail.add_file("returns139.c", "int main(void){return 139;}\n")
    trail.add_file("segfaults.c", "int main(){int *p=0;*p=1;return 0;}\n")
    build = backend.exec(trail, image=IMAGE, timeout_s=300, argv=[
        "bash", "-lc",
        "gcc -O0 returns139.c -o returns139 && gcc -O0 segfaults.c -o segfaults && echo ok"])
    assert build.exit_code == 0, build.stderr

    normal = backend.exec(trail, image=IMAGE, timeout_s=120, argv=["./returns139"])
    assert normal.exit_code == 139
    assert normal.termination["kind"] == "error_exit"
    assert normal.termination["crash"] is False
    assert normal.signal_verified is True

    crashed = backend.exec(trail, image=IMAGE, timeout_s=120, argv=["./segfaults"])
    assert crashed.termination["kind"] == "sigsegv"
    assert crashed.termination["crash"] is True
    assert crashed.signal_name == "SIGSEGV"


def test_two_mutations_of_the_same_name_are_both_kept(backend, tmp_path):
    from gpuvulnagent.backends.trails import TrailStore

    store = TrailStore(tmp_path / "trails", "run-live-versions-" + uuid.uuid4().hex[:8])
    trail = store.allocate(purpose="versions")
    command = ["bash", "-lc",
               "printf '%s' \"$SRC\" > /work/poc.cu && nvcc -O2 /work/poc.cu -o /work/poc"]
    first = backend.exec(trail, image=IMAGE, timeout_s=300, argv=command,
                         env={"SRC": "int main(){return 0;}\n"})
    second = backend.exec(trail, image=IMAGE, timeout_s=300, argv=command,
                          env={"SRC": "int main(){return 1;}\n"})
    v1 = trail.root / "execs/exec00/outputs/poc.cu"
    v2 = trail.root / "execs/exec01/outputs/poc.cu"
    assert v1.read_text() == "int main(){return 0;}\n"
    assert v2.read_text() == "int main(){return 1;}\n"
    assert (trail.root / "execs/exec00/outputs/poc").is_file()
    assert (trail.root / "execs/exec01/outputs/poc").is_file()
    assert "poc.cu" in (first.snapshot.get("created") or [])
    assert "poc.cu" in (second.snapshot.get("changed") or [])


def test_a_symlink_to_a_host_file_is_not_collected(backend, tmp_path):
    from gpuvulnagent.backends.trails import TrailStore

    store = TrailStore(tmp_path / "trails", "run-live-symlink-" + uuid.uuid4().hex[:8])
    trail = store.allocate(purpose="symlink")
    result = backend.exec(trail, image=IMAGE, timeout_s=300, argv=[
        "bash", "-lc",
        "ln -s /etc/passwd /work/leak.txt; echo kept > /work/real.txt"])
    skipped = {item["name"]: item for item in result.snapshot.get("skipped_symlinks") or []}
    assert "leak.txt" in skipped
    assert not (trail.root / "execs/exec00/outputs/leak.txt").exists()
    assert (trail.root / "execs/exec00/outputs/real.txt").is_file()
    for path in (trail.root / "execs/exec00/outputs").rglob("*"):
        if path.is_file():
            assert b"root:x:" not in path.read_bytes()
