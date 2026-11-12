# -*- coding: utf-8 -*-
"""Evidence resolution across both layouts, without weakening fail-closed.

Layouts that exist in this project:
  old run:   <root>/evidence.jsonl
  trial:     <root>/evidence/evidence.jsonl
  parent of runs: <root>/<run_id>/evidence.jsonl

Rules tested here: the id decides, the run id must match, ambiguity is refused, a fabricated
id is refused, and tampering breaks verification rather than being ignored.
"""

from __future__ import annotations

import json

import pytest

from gpuvulnagent.evidence import ArtifactStore, EvidenceLog, verify_chain
from gpuvulnagent.evidence.log import EvidenceResolver
from gpuvulnagent.memory.models import MemoryError_
from gpuvulnagent.memory.store import LayeredMemory


def build_log(root, run_id, count=3):
    root.mkdir(parents=True, exist_ok=True)
    log = EvidenceLog(root / "evidence.jsonl", run_id, ArtifactStore(root / "artifacts"))
    ids = [log.append("tool", {"tool_name": "fs_list", "n": index})["evidence_id"]
           for index in range(count)]
    return log, ids


def test_old_run_layout_resolves(tmp_path):
    log, ids = build_log(tmp_path / "run-a", "run-a")
    resolver = EvidenceResolver([tmp_path / "run-a"])
    record = resolver.resolve(ids[1])
    assert record and record["evidence_id"] == ids[1]
    assert record["tool_name"] == "fs_list"


def test_trial_layout_resolves(tmp_path):
    trial = tmp_path / "trial0"
    (trial / "evidence").mkdir(parents=True)
    log = EvidenceLog(trial / "evidence" / "evidence.jsonl", "run-t",
                      ArtifactStore(trial / "artifacts"))
    real = log.append("tool", {"tool_name": "container_exec", "exit": 0})["evidence_id"]
    resolver = EvidenceResolver([trial])
    record = resolver.resolve(real)
    assert record and record["tool_name"] == "container_exec"
    assert record["run_id"] == "run-t"


def test_same_id_under_a_wrong_run_id_is_refused(tmp_path):
    _, ids = build_log(tmp_path / "run-a", "run-a")
    resolver = EvidenceResolver([tmp_path / "run-a"])
    sequence = ids[0].split("#")[1]
    assert resolver.resolve("run-other#%s" % sequence) is None


def test_fabricated_id_and_bad_shapes_are_refused(tmp_path):
    _, ids = build_log(tmp_path / "run-a", "run-a", count=2)
    resolver = EvidenceResolver([tmp_path / "run-a"])
    assert resolver.resolve("run-a#999") is None
    assert resolver.resolve("#2") is None
    assert resolver.resolve("run-a#two") is None
    assert resolver.resolve("") is None


def test_several_logs_do_not_cross_match(tmp_path):
    _, left = build_log(tmp_path / "left", "run-left", count=2)
    _, right = build_log(tmp_path / "right", "run-right", count=2)
    resolver = EvidenceResolver([tmp_path])
    # Same sequence number in two runs: the id decides, not the position.
    assert resolver.resolve(left[1])["run_id"] == "run-left"
    assert resolver.resolve(right[1])["run_id"] == "run-right"
    assert resolver.resolve("run-left#9") is None


def test_ambiguous_duplicate_ids_are_refused(tmp_path):
    log, ids = build_log(tmp_path / "run-a", "run-a", count=2)
    # A second copy of the "same" run with a different record: two files, one id.
    forged = tmp_path / "copy" / "evidence.jsonl"
    forged.parent.mkdir(parents=True)
    record = json.loads(( log.path).read_text(encoding="utf-8").splitlines()[1])
    record["record_sha256"] = "0" * 64
    forged.write_text(json.dumps(record) + "\n", encoding="utf-8")
    resolver = EvidenceResolver([tmp_path / "run-a", tmp_path / "copy"])
    assert resolver.resolve(ids[1]) is None


def test_tampered_evidence_fails_verification(tmp_path):
    root = tmp_path / "trial0"
    (root / "evidence").mkdir(parents=True)
    log = EvidenceLog(root / "evidence" / "evidence.jsonl", "run-t",
                      ArtifactStore(root / "artifacts"))
    ids = [log.append("tool", {"n": index})["evidence_id"] for index in range(2)]
    assert verify_chain(log.path)["ok"] is True

    lines = log.path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["kind"] = "memory"          # flip a field, keep the old hash
    lines[0] = json.dumps(record, ensure_ascii=False)
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert verify_chain(log.path)["ok"] is False
    # The resolver still finds the id by position and run id; integrity is a separate verdict.
    assert EvidenceResolver([root]).resolve(ids[0]) is not None


def test_memory_written_in_a_trial_is_readable_from_a_new_run(tmp_path):
    trial = tmp_path / "trial0"
    (trial / "evidence").mkdir(parents=True)
    log = EvidenceLog(trial / "evidence" / "evidence.jsonl", "run-t",
                      ArtifactStore(trial / "artifacts"))
    real = log.append("tool", {"tool_name": "container_exec", "exit": 0})["evidence_id"]

    writer = LayeredMemory(run_dir=trial, research_root=tmp_path / "archive",
                           run_id="run-t", case_id="CASE-1",
                           resolver=EvidenceResolver([trial]))
    entry = writer.add("finding", "container_exec succeeded on the baseline",
                       evidence=[real], scope="case", source="agent")

    reader = LayeredMemory(run_dir=tmp_path / "other-run", research_root=tmp_path / "archive",
                           run_id="run-2", case_id="CASE-1",
                           resolver=EvidenceResolver([trial]))
    found = [item for item in reader.entries(scopes=("case",)) if item.id == entry.id]
    assert found and found[0].evidence == [real]
    assert verify_chain(log.path)["ok"] is True


def test_memory_still_refuses_a_fabricated_id_in_a_trial(tmp_path):
    trial = tmp_path / "trial0"
    (trial / "evidence").mkdir(parents=True)
    EvidenceLog(trial / "evidence" / "evidence.jsonl", "run-t",
                ArtifactStore(trial / "artifacts")).append("tool", {"n": 0})
    memory = LayeredMemory(run_dir=trial, research_root=tmp_path / "archive",
                           run_id="run-t", case_id="CASE-1",
                           resolver=EvidenceResolver([trial]))
    with pytest.raises(MemoryError_):
        memory.add("finding", "made up", evidence=["run-t#77"], scope="case")
