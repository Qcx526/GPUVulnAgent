# -*- coding: utf-8 -*-
"""Capability catalog: an adapter the agent has never heard of must be findable."""

from __future__ import annotations

from pathlib import Path

import pytest

from gpuvulnagent.adapters import ADAPTERS, adapter_capabilities, load_adapter
from gpuvulnagent.evidence import ArtifactStore, EvidenceLog, Runner
from gpuvulnagent.memory.store import LayeredMemory
from gpuvulnagent.runtime.workspace import Workspace
from gpuvulnagent.tools.build import build_assembly


@pytest.fixture
def assembly(tmp_path: Path, monkeypatch):
    for name in ("DEEPSEEK_API_KEY", "TAVILY_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    workspace = Workspace(tmp_path / "ws")
    artifacts = ArtifactStore(tmp_path / "artifacts")
    log = EvidenceLog(tmp_path / "evidence.jsonl", "run-cat", artifacts)
    runner = Runner(workspace.root, log, timeout=30)
    memory = LayeredMemory(run_dir=tmp_path, research_root=tmp_path / "archive",
                           run_id="run-cat")
    return build_assembly(workspace=workspace, runner=runner, log=log, memory=memory,
                          toolchain_root=None, enable_search=False)


def test_jpeg_adapter_is_registered_and_findable(assembly):
    assert "jpeg_inspect" in assembly.registry.names()
    hits = assembly.catalog.search("jpeg")
    names = [item["name"] for item in hits]
    assert "jpeg_inspect" in names
    assert "jpeg_mutate_dimensions" in names


def test_search_by_file_format(assembly):
    hits = assembly.catalog.search("", formats=".jpg")
    assert {item["name"] for item in hits} >= {"jpeg_inspect", "jpeg_mutate_dimensions"}
    cubin = assembly.catalog.search("", formats=".cubin")
    assert "cubin_header" in {item["name"] for item in cubin}


def test_search_by_dependency_and_purpose(assembly):
    assert assembly.catalog.search("elf") != []
    assert assembly.catalog.search("disassembly") != []
    assert assembly.catalog.search("no-such-capability-anywhere") == []


def test_describe_reports_parameters_location_and_runnability(assembly):
    info = assembly.catalog.describe("jpeg_inspect")
    assert info["available"] is True
    assert info["runnable"] is True
    assert info["location"].endswith("adapter.py:inspect_file")
    assert info["parameters"]["path"] == "string"
    assert "usage" in info


def test_unknown_capability_suggests_nearby_names(assembly):
    info = assembly.catalog.describe("jpeg_inspec")
    assert "error" in info
    assert "jpeg_inspect" in info["did_you_mean"]


def test_unavailable_adapter_is_still_indexed(assembly):
    assembly.catalog.add_unavailable(name="ghost_adapter", kind="adapter",
                                     purpose="parses ghost files", location="adapters/ghost/",
                                     requires=["libghost"], reason="libghost is not installed",
                                     formats=[".ghost"], tags=["ghost"])
    info = assembly.catalog.describe("ghost_adapter")
    assert info["available"] is False
    assert "libghost" in info["reason"]
    assert "not registered" in info["note"]
    assert assembly.catalog.missing_dependencies()["libghost"] == ["ghost_adapter"]


def test_tool_search_tool_returns_the_catalog(assembly):
    outcome = assembly.registry.call("tool_search", {"query": "jpeg"})
    assert outcome["ok"] is True
    names = [item["name"] for item in outcome["summary"]["items"]]
    assert "jpeg_inspect" in names
    assert outcome["summary"]["catalog"]["total"] >= 10


def test_tool_describe_tool_explains_why_something_cannot_run(assembly):
    outcome = assembly.registry.call("tool_describe", {"name": "jpeg_mutate_dimensions"})
    assert outcome["ok"] is True
    assert outcome["summary"]["registered"] is True


def test_loading_a_broken_adapter_degrades_instead_of_failing():
    specs, error = load_adapter("does-not-exist")
    assert specs == [] and "unknown adapter" in error
    assert {item["name"] for item in adapter_capabilities()} == set(ADAPTERS)


def test_catalog_summary_counts_kinds(assembly):
    summary = assembly.catalog.summary()
    assert summary["total"] >= len(assembly.registry)
    assert summary["available"] >= 1
