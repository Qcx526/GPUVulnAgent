# -*- coding: utf-8 -*-
"""Toolchain manifest: the only source of binary locations, and it must verify."""

from __future__ import annotations

from pathlib import Path

import pytest

from gpuvulnagent.discovery.manifest import ToolchainEntry, ToolchainManifest, write_manifest

ROOT = Path(__file__).resolve().parents[1]
TOOLCHAIN = ROOT / "toolchains"


def test_manifest_of_this_workspace_verifies():
    manifest = ToolchainManifest(TOOLCHAIN)
    if manifest.load_error:
        pytest.skip("no toolchain manifest in this checkout: %s" % manifest.load_error)
    assert manifest.names()
    result = manifest.verify()
    assert result["ok"] is True
    assert all(item["status"] in ("verified", "present") for item in result["tools"])


def test_manifest_paths_are_relative_and_inside_the_workspace():
    manifest = ToolchainManifest(TOOLCHAIN)
    if manifest.load_error:
        pytest.skip("no toolchain manifest in this checkout")
    for name in manifest.names():
        entry = manifest.get(name)
        assert not Path(entry.path).is_absolute()
        resolved = manifest.path_of(name)
        assert resolved is not None
        assert TOOLCHAIN.resolve() in resolved.parents


def test_manifest_reports_a_missing_binary(tmp_path: Path):
    write_manifest(tmp_path, [ToolchainEntry(name="ghost", path="cuda/ghost.exe",
                                             sha256="0" * 64, kind="binary")],
                   {"generated_by": "test"})
    manifest = ToolchainManifest(tmp_path)
    assert manifest.load_error == ""
    result = manifest.verify()
    assert result["ok"] is False
    assert result["tools"][0]["status"] == "missing"
    assert manifest.describe("ghost")["exists"] is False


def test_manifest_detects_drift(tmp_path: Path):
    binary = tmp_path / "cuda" / "tool.exe"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"payload")
    write_manifest(tmp_path, [ToolchainEntry(name="tool", path="cuda/tool.exe",
                                             sha256="deadbeef", kind="binary")],
                   {"generated_by": "test"})
    manifest = ToolchainManifest(tmp_path)
    assert manifest.verify()["tools"][0]["status"] == "drifted"
    binary.write_bytes(b"changed")
    assert manifest.verify()["ok"] is False


def test_missing_manifest_is_reported_not_raised(tmp_path: Path):
    manifest = ToolchainManifest(tmp_path)
    assert "not found" in manifest.load_error
    assert manifest.names() == []
    assert manifest.path_of("cuobjdump") is None
