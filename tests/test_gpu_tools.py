# -*- coding: utf-8 -*-
"""GPU tools as the agent sees them: discoverable, typed, and honest about failure."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gpuvulnagent.evidence import ArtifactStore, EvidenceLog, Runner
from gpuvulnagent.memory.store import LayeredMemory
from gpuvulnagent.runtime.workspace import Workspace
from gpuvulnagent.tools.build import build_assembly

GPU_TOOLS = {"gpu_environment_probe", "gpu_toolchain_discover", "trail_new", "trail_write",
             "trail_read", "trail_list", "trail_manifest", "container_exec", "gpu_cleanup"}


@pytest.fixture
def assembly(tmp_path: Path, monkeypatch):
    for name in ("DEEPSEEK_API_KEY", "TAVILY_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    workspace = Workspace(tmp_path / "ws")
    artifacts = ArtifactStore(tmp_path / "artifacts")
    log = EvidenceLog(tmp_path / "evidence.jsonl", "run-tools", artifacts)
    runner = Runner(workspace.root, log, timeout=30)
    memory = LayeredMemory(run_dir=tmp_path, research_root=tmp_path / "archive",
                           run_id="run-tools")
    return build_assembly(workspace=workspace, runner=runner, log=log, memory=memory,
                          toolchain_root=None, enable_search=False)


def test_gpu_tools_are_registered_and_discoverable(assembly):
    names = set(assembly.registry.names())
    assert GPU_TOOLS <= names
    hits = {item["name"] for item in assembly.catalog.search("docker")}
    assert "container_exec" in hits
    by_format = {item["name"] for item in assembly.catalog.search("", formats=".cu")}
    assert "container_exec" in by_format


def test_parameters_carry_real_schema_types(assembly):
    schema = assembly.registry.get("container_exec").json_schema()
    properties = schema["properties"]
    assert properties["argv"]["type"] == "array"
    assert properties["argv"]["items"]["type"] == "string"
    assert properties["gpu"]["type"] == "boolean"
    assert properties["timeout_s"]["type"] == "integer"
    assert properties["env"]["type"] == "object"
    assert properties["network"]["enum"] == ["none", "bridge", "host"]
    assert set(schema["required"]) == {"argv"}


def test_trail_tools_roundtrip_through_the_registry(assembly):
    created = assembly.registry.call("trail_new", {"purpose": "unit test"})
    assert created["ok"] is True
    trail_id = created["summary"]["trail"]
    assert trail_id == "trail0"

    written = assembly.registry.call("trail_write", {"trail": trail_id, "name": "poc.cu",
                                                     "content": "__global__ void k(){}"})
    assert written["ok"] is True
    assert written["summary"]["name"] == "inputs/poc.cu"
    assert written["summary"]["sha256"]

    read = assembly.registry.call("trail_read", {"trail": trail_id, "name": "poc.cu"})
    assert read["ok"] is True
    assert "__global__" in read["summary"]["text"]

    manifest = assembly.registry.call("trail_manifest", {"trail": trail_id})
    assert manifest["ok"] is True
    assert manifest["summary"]["files"][0]["name"] == "inputs/poc.cu"

    listed = assembly.registry.call("trail_list", {})
    assert listed["summary"]["trails"][0]["trail"] == "trail0"


def test_trail_write_refuses_escape_and_missing_trail(assembly):
    assembly.registry.call("trail_new", {})
    escaped = assembly.registry.call("trail_write", {"trail": "trail0", "name": "../x",
                                                     "content": "nope"})
    assert escaped["ok"] is False
    missing = assembly.registry.call("trail_write", {"trail": "trail9", "name": "x",
                                                     "content": "nope"})
    assert missing["ok"] is False


def test_container_exec_rejects_empty_argv_without_touching_the_backend(assembly):
    outcome = assembly.registry.call("container_exec", {"argv": []})
    assert outcome["dispatched"] is True
    assert outcome["ok"] is False
    assert outcome["status"] == "rejected"
    assert "argv" in outcome["error"]


def test_container_exec_validates_argument_types(assembly):
    outcome = assembly.registry.call("container_exec", {"argv": ["true"], "timeout_s": "soon"})
    assert outcome["ok"] is False
    assert outcome["dispatched"] is False
    assert "timeout_s" in outcome["error"]

    # A bare string for argv is not a command line; it must be reported, not guessed.
    loose = assembly.registry.call("container_exec", {"argv": 5})
    assert loose["ok"] is False


def test_probe_tool_reports_backend_state_without_crashing(assembly, monkeypatch):
    backend = assembly.backend
    monkeypatch.setattr(backend, "probe", _raise_unavailable)
    outcome = assembly.registry.call("gpu_environment_probe", {})
    assert outcome["ok"] is False
    assert outcome["status"] == "backend_unavailable"
    assert "wsl" in outcome["summary"]["error"].lower() or "unavailable" in \
        outcome["summary"]["error"].lower()


def _raise_unavailable(*args, **kwargs):
    from gpuvulnagent.backends.base import BackendUnavailable
    raise BackendUnavailable("wsl.exe is not available on this host")


def test_backend_status_is_part_of_the_assembly(assembly):
    described = assembly.describe()
    assert described["backend"]["enabled"] is True
    assert described["backend"]["registered"] is True
    assert described["backend"]["config"]["distro"]


def test_observation_render_survives_empty_artifact_refs():
    """A tool may return placeholder refs; the prompt renderer must not crash on them."""
    from gpuvulnagent.context.observation import render

    text = render({"ok": True, "summary": {"exit": 0, "stdout": "hello"},
                   "artifacts": [{}, {"artifact": "stdout/abc.out"}, {"artifact": None}]})
    assert "stdout/abc.out" in text
    assert "hello" in text


def test_tool_manifest_records_trail_relationship(assembly):
    assembly.registry.call("trail_new", {"purpose": "baseline"})
    assembly.registry.call("trail_new", {"purpose": "mutant", "parent_trail": "trail0"})
    child = assembly.registry.call("trail_manifest", {"trail": "trail1"})
    assert child["summary"]["parent_trail"] == "trail0"
    payload = json.dumps(child["summary"], ensure_ascii=False)
    assert "\"run_id\": \"run-tools\"" in payload


def test_pull_policy_is_part_of_the_contract(assembly):
    schema = assembly.registry.get("container_exec").json_schema()
    assert schema["properties"]["pull_policy"]["enum"] == ["missing", "always", "never"]
    assert schema["properties"]["pull_policy"]["default"] == "missing"


def test_container_exec_summary_carries_snapshot_and_supervision(assembly, monkeypatch):
    from gpuvulnagent.backends.base import Artifact, ExecResult

    def fake_exec(trail, **kwargs):
        result = ExecResult(ok=True, exit_code=0, termination={"kind": "success",
                                                              "crash": False,
                                                              "signal_verified": True},
                            image=kwargs.get("image", "img"), image_digest="repo@sha256:x",
                            pull_policy="missing",
                            image_pull={"policy": "missing", "present_before": True,
                                        "pulled": False, "ok": True, "error": ""},
                            container_id="abc", argv=list(kwargs.get("argv") or []),
                            trail=trail.trail_id, exec_index=0, exec_dir="execs/exec00",
                            snapshot={"created": ["poc"], "changed": [], "deleted": [],
                                      "unchanged_count": 2, "skipped_symlinks": []},
                            supervision={"used": True, "readable": True},
                            signal_verified=True, signaled=False,
                            cleanup={"attempted": True, "exit": 0}, cleanup_ok=True,
                            stdout="ok", stderr="")
        result.artifacts = [Artifact(name="execs/exec00/outputs/poc", sha256="a" * 64,
                                     bytes=10, kind="output")]
        return result

    monkeypatch.setattr(assembly.backend, "exec", fake_exec)
    outcome = assembly.registry.call("container_exec", {"argv": ["true"], "image": "img"})
    summary = outcome["summary"]
    assert outcome["ok"] is True
    assert summary["exec_dir"] == "execs/exec00"
    assert summary["signal_verified"] is True
    assert summary["snapshot"]["created"] == ["poc"]
    assert summary["cleanup_ok"] is True
    assert summary["pull_policy"] == "missing"
