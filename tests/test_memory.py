# -*- coding: utf-8 -*-
"""Research memory: three scopes, evidence-backed findings, refutation without rewriting."""

from __future__ import annotations

from pathlib import Path

import pytest

from gpuvulnagent.evidence import ArtifactStore, EvidenceLog, EvidenceResolver
from gpuvulnagent.memory import LayeredMemory, MemoryError_


def build(tmp_path: Path, run_id: str, case_id: str = "CVE-2024-0124", resolver=None):
    return LayeredMemory(run_dir=tmp_path / run_id, research_root=tmp_path / "archive",
                         run_id=run_id, case_id=case_id, resolver=resolver)


def test_run_memory_dies_with_the_run_but_case_and_global_survive(tmp_path):
    first = build(tmp_path, "run-one")
    first.add("attempt", "试了 cuobjdump -sass，输出为空", scope="run")
    first.add("failed", "nvdisasm 在这个 cubin 上直接退出", scope="case")
    first.add("hypothesis", "nvJPEG 解码器对奇数宽度处理异常", scope="global")

    second = build(tmp_path, "run-two")
    run_only = [e.content for e in second.entries(scopes=("run",))]
    case_entries = [e.content for e in second.entries(scopes=("case",))]
    global_entries = [e.content for e in second.entries(scopes=("global",))]
    assert not any("cuobjdump -sass" in text for text in run_only)
    assert any("nvdisasm" in text for text in case_entries)
    assert any("奇数宽度" in text for text in global_entries)


def test_findings_require_evidence(tmp_path):
    memory = build(tmp_path, "run-a")
    with pytest.raises(MemoryError_):
        memory.add("finding", "存在越界写", scope="run")


def test_findings_must_cite_evidence_that_exists(tmp_path):
    artifacts = ArtifactStore(tmp_path / "artifacts")
    log = EvidenceLog(tmp_path / "run-a" / "evidence.jsonl", "run-a", artifacts)
    record = log.append("exec", {"argv": ["x"], "exit": 0})
    resolver = EvidenceResolver([tmp_path / "run-a"])
    memory = build(tmp_path, "run-a", resolver=resolver)

    good = memory.add("finding", "目标进程正常退出", evidence=[record["evidence_id"]])
    assert good.type == "finding"

    with pytest.raises(MemoryError_):
        memory.add("finding", "目标崩溃了", evidence=["run-a#999"])


def test_refutation_keeps_the_original(tmp_path):
    memory = build(tmp_path, "run-b")
    original = memory.add("hypothesis", "宽度为 0 会触发除零", scope="case")
    memory.refute(original.id, "把宽度设为 0 后 nvJPEG 直接拒绝输入，没有进入解码器", scope="case")

    entries = memory.entries(scopes=("case",))
    still_there = [e for e in entries if e.id == original.id]
    assert still_there and still_there[0].type == "hypothesis"
    refutations = [e for e in entries if e.refutes == original.id]
    assert refutations and refutations[0].type == "failed"
    assert any(e.refutes == original.id for e in memory.refuted_directions())


def test_search_prefers_failures_and_refuted_directions(tmp_path):
    memory = build(tmp_path, "run-c")
    memory.add("attempt", "nvjpeg 解码正常样本", scope="case")
    memory.add("failed", "nvjpeg 用 -1 宽度调用被参数校验拦下", scope="case")
    hits = memory.search("nvjpeg 宽度")
    assert hits[0].type == "failed"


def test_append_only_no_silent_overwrite(tmp_path):
    memory = build(tmp_path, "run-d")
    first = memory.add("attempt", "读 /tmp/x 失败", scope="case")
    second = memory.add("attempt", "读 /tmp/x 失败", scope="case")
    assert first.id == second.id
    assert len([e for e in memory.entries(scopes=("case",)) if e.id == first.id]) == 1


def test_promotion_copies_a_run_entry_upward(tmp_path):
    memory = build(tmp_path, "run-e")
    entry = memory.add("open", "还不确定 nvdisasm 是否支持 sm_75", scope="run")
    promoted = memory.promote(entry.id, scope="case")
    assert promoted is not None
    assert promoted.supersedes == entry.id
    assert any(item.id == promoted.id for item in memory.entries(scopes=("case",)))


def test_digest_mentions_refuted_directions(tmp_path):
    memory = build(tmp_path, "run-f")
    entry = memory.add("hypothesis", "通过 SOF 高度 0 触发溢出", scope="case")
    memory.refute(entry.id, "高度 0 被解码器在接受阶段拒绝", scope="case")
    digest = memory.digest("SOF 高度", limit=8)
    assert "REFUTES %s" % entry.id in digest


def test_unknown_type_and_scope_are_refused(tmp_path):
    memory = build(tmp_path, "run-g")
    with pytest.raises(MemoryError_):
        memory.add("rumour", "未经证实的说法")
    with pytest.raises(MemoryError_):
        memory.add("attempt", "x", scope="universe")
