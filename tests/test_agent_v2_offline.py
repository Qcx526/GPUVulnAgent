import json
from pathlib import Path

import pytest

from gpuvulnagent.agents.langgraph_agent import (build_tools, build_graph,
                                                  _campaign_note, _wsl_ls, extra_tools)
from gpuvulnagent.evidence import ArtifactStore, EvidenceLog, Runner
from gpuvulnagent.memory.store import LayeredMemory
from gpuvulnagent.runtime.workspace import Workspace
from gpuvulnagent.tools.build import build_assembly


def assembly(tmp_path):
    log = EvidenceLog(tmp_path / "evidence.jsonl", "run-x", ArtifactStore(tmp_path / "a"))
    ws = Workspace(tmp_path / "ws")
    return build_assembly(workspace=ws, runner=Runner(ws.root, log, 30), log=log,
                          memory=LayeredMemory(run_dir=tmp_path, research_root=tmp_path / "ar",
                                               run_id="run-x"),
                          toolchain_root=None, enable_search=False)


def test_tools_are_visible_and_evidence_linked(tmp_path):
    asm = assembly(tmp_path)
    graph = build_graph(asm.registry, None or EvidenceLog(tmp_path / "e.jsonl", "run-x",
                                                          ArtifactStore(tmp_path / "a")),
                        model="m", base_url="b", api_key="k")
    tools = build_tools(asm.registry, EvidenceLog(tmp_path / "e.jsonl", "run-x",
                                                  ArtifactStore(tmp_path / "a")))
    names = {t.name for t in tools + extra_tools()}
    assert "trail_stage" in names
    assert {"campaign_note", "wsl_ls"} <= names


def test_claim_without_exec_evidence_is_not_promoted(tmp_path):
    asm = assembly(tmp_path)
    log = EvidenceLog(tmp_path / "e.jsonl", "run-x", ArtifactStore(tmp_path / "a"))
    graph = build_graph(asm.registry, log, model="m", base_url="b", api_key="k")
    by_name = {t.name: t for t in build_tools(asm.registry, log)}
    note = json.loads(_campaign_note(None, log, "FACT_CLAIM", "x", ["run-x#99"]))
    assert note["promoted"] is False


def test_wsl_ls_rejects_traversal(tmp_path):
    asm = assembly(tmp_path)
    log = EvidenceLog(tmp_path / "e.jsonl", "run-x", ArtifactStore(tmp_path / "a"))
    by_name = {t.name: t for t in build_tools(asm.registry, log)}
    graph = build_graph(asm.registry, log, model="m", base_url="b", api_key="k")
    result = json.loads(_wsl_ls("../etc"))
    assert result["ok"] is False
