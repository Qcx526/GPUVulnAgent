# -*- coding: utf-8 -*-
"""Artifact registry: versioning, parentage, dedupe, integrity, trial allocation."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from gpuvulnagent.artifacts.model import Artifact, classify, make_id, versioned_name
from gpuvulnagent.artifacts.registry import ArtifactError, ArtifactRegistry
from gpuvulnagent.artifacts.trial import TrialSession


@pytest.fixture
def trial(tmp_path: Path) -> TrialSession:
    return TrialSession.allocate(tmp_path / "runs", goal="unit", case_id="CASE-1")


def test_trials_are_numbered_and_never_reused(tmp_path):
    first = TrialSession.allocate(tmp_path / "runs", goal="a")
    second = TrialSession.allocate(tmp_path / "runs", goal="b")
    assert (first.trial_id, second.trial_id) == ("trial0", "trial1")
    for section in ("session", "poc/manifests", "evidence", "report"):
        assert (first.root / section).is_dir()


def test_concurrent_trial_allocation_does_not_collide(tmp_path):
    ids, errors = [], []

    def worker():
        try:
            ids.append(TrialSession.allocate(tmp_path / "runs", goal="x").trial_id)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    assert len(ids) == len(set(ids)) == 8


def test_registering_changed_bytes_creates_a_new_version(trial, tmp_path):
    source = trial.root / "workspace" / "poc.cu"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("int main(){return 0;}\n", encoding="utf-8")
    first = trial.registry.register(source, producer_tool="shell", evidence_id="run-1#3")

    source.write_text("int main(){return 1;}\n", encoding="utf-8")
    second = trial.registry.register(source, producer_tool="shell", evidence_id="run-1#5",
                                     parents=[first.artifact_id])
    assert first.artifact_id != second.artifact_id
    assert second.version == 2
    assert second.parent_artifact_ids == [first.artifact_id]
    # Both records point at the same path but different content: nothing was overwritten.
    assert first.sha256 != second.sha256
    assert trial.registry.verify()["ok"] is False  # the old hash no longer matches the file


def test_identical_bytes_are_deduplicated(trial):
    source = trial.root / "workspace" / "same.cu"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("same", encoding="utf-8")
    first = trial.registry.register(source)
    second = trial.registry.register(source)
    assert first.artifact_id == second.artifact_id
    assert len(trial.registry.all()) == 1


def test_a_binary_is_linked_to_its_source_by_name(trial):
    workspace = trial.root / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "poc.cu").write_text("int main(){return 0;}\n", encoding="utf-8")
    source = trial.registry.register(workspace / "poc.cu", origin="generated")

    outputs = trial.root / "trails" / "trail0" / "execs" / "exec00" / "outputs"
    outputs.mkdir(parents=True, exist_ok=True)
    (outputs / "poc").write_bytes(b"\x7fELF" + b"\x00" * 64)
    binary = trial.registry.register(outputs / "poc", origin="compiled",
                                     execution_id="trail0/exec00")
    assert binary.artifact_type == "binary"
    assert binary.language == "elf"
    assert binary.parent_artifact_ids == [source.artifact_id]


def test_history_and_children_walk_the_chain(trial):
    workspace = trial.root / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    path = workspace / "v.cu"
    path.write_text("v1", encoding="utf-8")
    a = trial.registry.register(path)
    path.write_text("v2", encoding="utf-8")
    b = trial.registry.register(path, parents=[a.artifact_id])
    path.write_text("v3", encoding="utf-8")
    c = trial.registry.register(path, parents=[b.artifact_id])

    assert [item.artifact_id for item in trial.registry.history(c.artifact_id)] == \
        [a.artifact_id, b.artifact_id, c.artifact_id]
    assert [item.artifact_id for item in trial.registry.children(a.artifact_id)] == \
        [b.artifact_id]


def test_verify_reports_missing_and_tampered_files_separately(trial):
    workspace = trial.root / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    good = workspace / "good.cu"
    good.write_text("ok", encoding="utf-8")
    bad = workspace / "bad.cu"
    bad.write_text("before", encoding="utf-8")
    gone = workspace / "gone.cu"
    gone.write_text("bye", encoding="utf-8")
    for path in (good, bad, gone):
        trial.registry.register(path)

    bad.write_text("after", encoding="utf-8")
    gone.unlink()
    report = trial.registry.verify()
    assert report["ok"] is False
    assert report["changed"] == ["workspace/bad.cu"] or "workspace/bad.cu" in report["changed"]
    assert "workspace/gone.cu" in report["missing"]


def test_files_outside_the_trial_are_refused(trial, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("x", encoding="utf-8")
    with pytest.raises(ArtifactError):
        trial.registry.register(outside)


def test_register_text_versions_on_collision(trial):
    first = trial.registry.register_text("poc.cu", "v1", section="poc/generated")
    second = trial.registry.register_text("poc.cu", "v2", section="poc/generated")
    assert first.relative_path.endswith("poc/generated/poc.cu")
    assert second.relative_path != first.relative_path
    assert "v002" in second.relative_path
    assert (trial.root / first.relative_path).read_text() == "v1"
    assert (trial.root / second.relative_path).read_text() == "v2"


def test_harvest_registers_shell_written_files_once(trial):
    workspace = trial.root / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "from_shell.cu").write_text("__global__ void k(){}", encoding="utf-8")
    first = trial.harvest([workspace], tool="shell", evidence_id="run-1#7", turn=1)
    second = trial.harvest([workspace], tool="shell", evidence_id="run-1#8", turn=2)
    assert len(first) == 1
    assert second == []            # nothing changed, nothing re-registered
    assert first[0].producer_tool == "shell"
    assert first[0].producer_evidence_id == "run-1#7"


def test_index_and_manifests_match_the_records(trial):
    workspace = trial.root / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "a.cu").write_text("a", encoding="utf-8")
    item = trial.harvest([workspace], tool="fs_write", evidence_id="run-1#2")[0]

    index = json.loads((trial.root / "evidence" / "artifact_index.json").read_text("utf-8"))
    assert index["counts"]["source"] == 1
    assert index["artifacts"][0]["artifact_id"] == item.artifact_id

    manifest = json.loads((trial.root / "poc" / "manifests" /
                           ("%s.json" % item.artifact_id)).read_text("utf-8"))
    assert manifest["sha256"] == item.sha256
    assert Path(manifest["path_on_disk"]).is_file()
    assert "INDEX.md" in [p.name for p in (trial.root / "poc").iterdir()]


def test_classification_prefers_extension_then_magic():
    assert classify(Path("x.cu")) == ("source", "cuda")
    assert classify(Path("x.cubin")) == ("binary", "cubin")
    assert classify(Path("x.jpg")) == ("input", "jpeg")
    assert classify(Path("noext"), b"\x7fELF\x02") == ("binary", "elf")
    assert classify(Path("noext"), b"plain") == ("file", "UNKNOWN")


def test_ids_and_versioned_names_are_stable():
    assert make_id("trial0", "poc/a.cu", "deadbeef") == make_id("trial0", "poc/a.cu", "deadbeef")
    assert make_id("trial0", "poc/a.cu", "deadbeef") != make_id("trial1", "poc/a.cu", "deadbeef")
    assert versioned_name(Path("poc.cu"), 2).name == "poc_v002.cu"
    assert versioned_name(Path("poc_v001.cu"), 3).name == "poc_v003.cu"


def test_report_and_session_files_are_written(trial):
    trial.record_turn({"step": 1, "index": 1, "thought": "t", "tool": "fs_write",
                       "status": "success", "evidence_id": "run-1#2", "at": "10:00:00",
                       "args": {"path": "a"}, "tool_call_id": "c1", "via": "native",
                       "mode": "native", "observation": {"ok": True}})
    trial.finish("conclusion text", stopped="final", extra={"evidence_records": 3})
    session = trial.root / "session"
    assert (session / "task.json").is_file()
    assert (session / "transcript.jsonl").read_text(encoding="utf-8").strip()
    assert (session / "decisions.jsonl").read_text(encoding="utf-8").strip()
    assert (session / "tool_calls.jsonl").read_text(encoding="utf-8").strip()
    report = (trial.root / "report" / "final_report.md").read_text(encoding="utf-8")
    assert "conclusion text" in report and "trial0" in report


def test_registry_reloads_from_the_journal(trial):
    workspace = trial.root / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "x.cu").write_text("x", encoding="utf-8")
    item = trial.harvest([workspace])[0]
    reloaded = ArtifactRegistry(trial.root, "trial0")
    assert reloaded.get(item.artifact_id) is not None
    assert reloaded.verify()["ok"] is True


def test_trial_records_who_did_what(trial):
    import json as _json
    payload = _json.loads((trial.root / "session" / "provenance.json").read_text("utf-8"))
    assert payload["defaults"]["poc_source"] == "agent"
    assert payload["defaults"]["cve_selection"] == "human"
    assert payload["defaults"]["runtime_fixes"] == "workbuddy"
    trial.record_turn({"step": 1, "index": 1, "thought": "t", "tool": "shell",
                       "status": "success", "evidence_id": "r#2", "at": "10:00"})
    line = (trial.root / "session" / "decisions.jsonl").read_text("utf-8").splitlines()[0]
    assert _json.loads(line)["origin"] == "agent"


def test_trial_records_who_did_what(trial):
    import json as _json
    payload = _json.loads((trial.root / "session" / "provenance.json").read_text("utf-8"))
    assert payload["defaults"]["poc_source"] == "agent"
    assert payload["defaults"]["cve_selection"] == "human"
    assert payload["defaults"]["runtime_fixes"] == "workbuddy"
    trial.record_turn({"step": 1, "index": 1, "thought": "t", "tool": "shell",
                       "status": "success", "evidence_id": "r#2", "at": "10:00"})
    line = (trial.root / "session" / "decisions.jsonl").read_text("utf-8").splitlines()[0]
    assert _json.loads(line)["origin"] == "agent"
