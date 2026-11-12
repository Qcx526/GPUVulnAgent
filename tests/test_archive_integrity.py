# -*- coding: utf-8 -*-
"""Every archived bundle must pass the integrity checker in CI, not just by hand."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BUNDLES = sorted((ROOT / "research_archive" / "experiments").glob("*/bundle_manifest.json"))


def test_bundles_exist():
    assert BUNDLES, "no experiment bundles found"


@pytest.mark.parametrize("manifest", BUNDLES, ids=[path.parent.name for path in BUNDLES])
def test_bundle_is_internally_consistent(manifest: Path):
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        from check_archive_integrity import check_bundle
    finally:
        sys.path.pop(0)

    report = check_bundle(manifest.parent)
    assert report["ok"], report["errors"]
    assert report["checked"] == report["declared"]
    data = json.loads(manifest.read_text(encoding="utf-8"))
    for item in data.get("files") or []:
        assert item.get("sha256"), item
        assert item.get("bytes", 0) >= 0


def test_skipped_entries_always_explain_themselves():
    for manifest in BUNDLES:
        data = json.loads(manifest.read_text(encoding="utf-8"))
        for item in data.get("skipped") or []:
            assert item.get("reason"), (manifest, item)
