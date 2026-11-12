# -*- coding: utf-8 -*-
"""Evidence visibility: the id must survive truncation and must be checkable.

Three facts, tested separately:

1. a huge tool result still shows its evidence id, because the id is a header, not a field
   somewhere in 8000 characters of JSON;
2. the rendered observation shows the id first, so a 900-character budget keeps it;
3. memory accepts a citation that resolves to a real record, refuses a fabricated one, and
   the reference survives a reload with the hash chain intact.
"""

from __future__ import annotations

import json

import pytest

from gpuvulnagent.context.observation import render
from gpuvulnagent.evidence import ArtifactStore, EvidenceLog, verify_chain
from gpuvulnagent.evidence.log import EvidenceResolver
from gpuvulnagent.memory.store import LayeredMemory
from gpuvulnagent.memory.models import MemoryError_
from gpuvulnagent.providers.base import tool_message


def test_evidence_id_survives_tool_message_truncation():
    huge = {"evidence_id": "run-abc#42", "stdout": "x" * 20000,
            "summary": {"artifacts": ["a" * 200] * 50}}
    message = tool_message("call_1", "container_exec", huge, limit=600)
    content = message["content"]
    assert content.startswith("evidence_id=run-abc#42\n")
    assert "[truncated" in content
    # The body was cut, the id was not: it is outside the truncated region by construction.
    assert "run-abc#42" in content.split("\n")[0]


def test_render_puts_the_id_first_under_truncation():
    observation = {"evidence_id": "run-abc#42", "ok": True,
                   "summary": {"stdout": "y" * 5000}}
    text = render(observation, 200)
    assert text.startswith("evidence_id: run-abc#42")


@pytest.fixture
def memory_with_evidence(tmp_path):
    artifacts = ArtifactStore(tmp_path / "artifacts")
    log = EvidenceLog(tmp_path / "evidence.jsonl", "run-mem", artifacts)
    first = log.append("tool", {"tool_name": "container_exec", "exit": 0})
    second = log.append("tool", {"tool_name": "fs_list", "exit": 0})
    memory = LayeredMemory(run_dir=tmp_path, research_root=tmp_path / "archive",
                           run_id="run-mem", case_id="CASE-1",
                           resolver=EvidenceResolver([tmp_path]))
    return {"memory": memory, "log": log, "ids": [first["evidence_id"],
                                                  second["evidence_id"]],
            "path": tmp_path / "evidence.jsonl", "root": tmp_path}


def test_memory_accepts_a_real_evidence_id(memory_with_evidence):
    memory = memory_with_evidence["memory"]
    real = memory_with_evidence["ids"][0]
    entry = memory.add("finding", "container_exec returned exit 0 on the baseline input",
                       evidence=[real], scope="case", source="agent")
    assert entry.evidence == [real]
    assert real in entry.to_dict()["evidence"]


def test_memory_refuses_a_fabricated_id(memory_with_evidence):
    memory = memory_with_evidence["memory"]
    with pytest.raises(MemoryError_):
        memory.add("finding", "invented citation", evidence=["run-mem#999"], scope="case")
    with pytest.raises(MemoryError_):
        memory.add("finding", "malformed citation", evidence=["#12"], scope="case")


def test_reference_survives_reload_and_the_chain_still_verifies(memory_with_evidence):
    memory = memory_with_evidence["memory"]
    real = memory_with_evidence["ids"][0]
    entry = memory.add("finding", "reload check", evidence=[real], scope="case")

    reread = LayeredMemory(run_dir=memory_with_evidence["root"],
                           research_root=memory_with_evidence["root"] / "archive",
                           run_id="run-mem", case_id="CASE-1",
                           resolver=EvidenceResolver([memory_with_evidence["root"]]))
    found = [item for item in reread.entries(scopes=("case",)) if item.id == entry.id]
    assert found and found[0].evidence == [real]
    assert verify_chain(memory_with_evidence["path"])["ok"] is True
    # The cited record really exists and is the tool record that produced the observation.
    record = [json.loads(line) for line in
              memory_with_evidence["path"].read_text(encoding="utf-8").splitlines()][0]
    assert record["evidence_id"] == real
    assert record["tool_name"] == "container_exec"
