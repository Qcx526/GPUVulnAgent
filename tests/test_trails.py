# -*- coding: utf-8 -*-
"""Trails: readable names, atomic numbering, no overwrite, hashes in the manifest."""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from gpuvulnagent.backends.trails import TrailError, TrailStore


def store(tmp_path: Path) -> TrailStore:
    return TrailStore(tmp_path / "trails", "run-test")


def test_trails_are_numbered_in_order_and_never_reused(tmp_path):
    trails = store(tmp_path)
    first = trails.allocate(purpose="first")
    second = trails.allocate(purpose="second")
    assert (first.trail_id, second.trail_id) == ("trail0", "trail1")
    assert (first.root / "inputs").is_dir()
    assert (first.root / "outputs").is_dir()
    assert (first.root / "logs").is_dir()


def test_allocating_again_after_a_gap_does_not_reuse_a_number(tmp_path):
    trails = store(tmp_path)
    trails.allocate()
    (tmp_path / "trails" / "trail9").mkdir()          # a gap left by another process
    trail = trails.allocate()
    assert trail.trail_id == "trail10"


def test_concurrent_allocation_never_collides(tmp_path):
    trails = store(tmp_path)
    results, errors = [], []

    def worker():
        try:
            results.append(trails.allocate().trail_id)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    assert len(results) == len(set(results)) == 12


def test_inputs_land_in_the_inputs_section_with_a_hash(tmp_path):
    trail = store(tmp_path).allocate()
    record = trail.add_file("poc.cu", "__global__ void k(){}")
    assert record.name == "inputs/poc.cu"
    assert (trail.root / "inputs" / "poc.cu").is_file()
    assert record.sha256 and record.bytes == len("__global__ void k(){}")
    manifest = json.loads((trail.root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["files"][0]["name"] == "inputs/poc.cu"
    assert manifest["files"][0]["sha256"] == record.sha256


def test_a_file_cannot_be_written_twice(tmp_path):
    trail = store(tmp_path).allocate()
    trail.add_file("poc.cu", "one")
    with pytest.raises(TrailError):
        trail.add_file("poc.cu", "two")


def test_path_traversal_and_absolute_names_are_refused(tmp_path):
    trail = store(tmp_path).allocate()
    for bad in ("../escape.txt", "/etc/passwd", r"C:\Windows\win.ini", "a/../../b"):
        with pytest.raises(TrailError):
            trail.add_file(bad, "x")


def test_manifest_records_parent_and_executions(tmp_path):
    trails = store(tmp_path)
    parent = trails.allocate(purpose="baseline")
    child = trails.allocate(purpose="mutation", parent_trail=parent.trail_id)
    child.add_file("poc.cu", "variant")
    child.record_execution({"argv": ["nvcc", "poc.cu"], "exit_code": 0,
                            "termination": "success"})
    manifest = child.manifest()
    assert manifest["parent_trail"] == "trail0"
    assert manifest["executions"][0]["exit_code"] == 0
    assert manifest["files"][0]["sha256"]


def test_read_file_supports_sections_offsets_and_has_more(tmp_path):
    trail = store(tmp_path).allocate()
    trail.add_file("log.txt", "0123456789")
    chunk = trail.read_file("inputs/log.txt", offset=2, limit=4)
    assert chunk["text"] == "2345"
    assert chunk["has_more"] is True
    assert chunk["next_offset"] == 6
    # A bare name resolves inside the section too.
    assert trail.read_file("log.txt")["text"] == "0123456789"


def test_list_and_open_roundtrip(tmp_path):
    trails = store(tmp_path)
    first = trails.allocate(purpose="one")
    first.add_file("a.cu", "x")
    listing = trails.list_trails()
    assert listing[0]["trail"] == "trail0"
    assert listing[0]["purpose"] == "one"
    reopened = trails.open("trail0")
    assert reopened.files[0].name == "inputs/a.cu"
    assert reopened.manifest()["run_id"] == "run-test"


def test_unknown_trail_and_bad_ids_are_refused(tmp_path):
    trails = store(tmp_path)
    with pytest.raises(TrailError):
        trails.open("trail7")
    with pytest.raises(TrailError):
        trails.open("../../etc")
