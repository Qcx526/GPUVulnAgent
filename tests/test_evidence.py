# -*- coding: utf-8 -*-
"""Evidence: the chain detects edits and deletions, artifacts are content addressed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gpuvulnagent.evidence import ArtifactStore, EvidenceLog, EvidenceResolver, verify_chain
from gpuvulnagent.evidence.redact import redact


def _log(tmp_path: Path) -> EvidenceLog:
    artifacts = ArtifactStore(tmp_path / "artifacts")
    return EvidenceLog(tmp_path / "evidence.jsonl", "run-test", artifacts)


def test_chain_links_records_and_verifies(tmp_path):
    log = _log(tmp_path)
    first = log.append("start", {"goal_sha256": "abc"})
    second = log.append("tool", {"tool_name": "shell"})
    assert second["previous_record_sha256"] == first["record_sha256"]
    assert second["sequence"] == 2
    assert log.verify()["ok"]
    assert first["evidence_id"] == "run-test#1"


def test_payload_cannot_relabel_its_own_outcome(tmp_path):
    log = _log(tmp_path)
    record = log.append("tool", {"status": "success", "kind": "finish", "sequence": 99},
                        status="failed")
    assert record["status"] == "failed"
    assert record["kind"] == "tool"
    assert record["sequence"] == 1


def test_editing_a_record_breaks_the_chain(tmp_path):
    path = tmp_path / "evidence.jsonl"
    log = EvidenceLog(path, "run-test", ArtifactStore(tmp_path / "artifacts"))
    log.append("tool", {"tool_name": "shell"})
    log.append("tool", {"tool_name": "fs_read"})
    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["tool_name"] = "something-else"
    lines[0] = json.dumps(tampered, ensure_ascii=False)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    check = verify_chain(path)
    assert check["ok"] is False
    assert any("does not match its hash" in error for error in check["errors"])


def test_deleting_a_record_breaks_the_chain(tmp_path):
    path = tmp_path / "evidence.jsonl"
    log = EvidenceLog(path, "run-test", ArtifactStore(tmp_path / "artifacts"))
    for index in range(3):
        log.append("tool", {"tool_name": "shell", "index": index})
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    check = verify_chain(path)
    assert check["ok"] is False
    assert any("sequence" in error or "previous hash" in error for error in check["errors"])


def test_evidence_id_survives_a_round_trip(tmp_path):
    """A memory entry cites an id; the citation must still resolve after a restart."""
    path = tmp_path / "evidence.jsonl"
    log = EvidenceLog(path, "run-test", ArtifactStore(tmp_path / "artifacts"))
    log.append("exec", {"argv": ["x"], "exit": 0})
    on_disk = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert on_disk[0]["evidence_id"] == "run-test#1"
    resolver = EvidenceResolver()
    assert resolver.resolve("run-test#1", EvidenceLog(path)) is not None


def test_artifacts_are_content_addressed_and_contained(tmp_path):
    store = ArtifactStore(tmp_path / "artifacts")
    first = store.save("stdout", "same.txt", "identical body")
    second = store.save("stdout", "same.txt", "identical body")
    assert first["artifact"] == second["artifact"]
    assert first["sha256"] == second["sha256"]
    with pytest.raises(PermissionError):
        store.resolve("../../outside.txt")
    assert store.read(first["artifact"]) == b"identical body"


def test_redaction_removes_key_shaped_strings():
    text = ("key sk-abcdefghijklmnopqrstuvwx and tvly-abcdefgh1234 "
            "Authorization: Bearer abcdefghijklmnopqrstuv")
    clean, hits = redact(text)
    assert hits >= 3
    assert "sk-abcdefghijklmnopqrstuvwx" not in clean
    assert "tvly-abcdefgh1234" not in clean


def test_resolver_finds_records_by_id_and_hash(tmp_path):
    log = _log(tmp_path)
    record = log.append("tool", {"tool_name": "shell"})
    resolver = EvidenceResolver([tmp_path])
    assert resolver.resolve("run-test#1", log)["sequence"] == 1
    assert resolver.resolve("sha256:%s" % record["record_sha256"], log) is not None
    assert resolver.resolve("run-test#99", log) is None
    assert resolver.resolve("nonsense", log) is None
