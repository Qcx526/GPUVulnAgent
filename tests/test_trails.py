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


def test_execution_artifacts_are_not_reprefixed(tmp_path):
    trail = store(tmp_path).allocate()
    directory = trail.exec_dir(0) / "outputs"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "poc.cu").write_text("version-A", encoding="utf-8")
    record = trail.register_file("execs/exec00/outputs/poc.cu", kind="output",
                                 source="container")
    assert record.name == "execs/exec00/outputs/poc.cu"
    assert (trail.root / "execs/exec00/outputs/poc.cu").is_file()
    assert trail.exec_dirs() == [trail.root / "execs" / "exec00"]


def test_bare_name_reads_the_latest_execution(tmp_path):
    trail = store(tmp_path).allocate()
    for index, text in enumerate(("version-A", "version-B")):
        directory = trail.exec_dir(index) / "outputs"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "poc.cu").write_text(text, encoding="utf-8")
        trail.register_file("execs/exec%02d/outputs/poc.cu" % index)

    assert trail.read_file("poc.cu")["text"] == "version-B"
    assert trail.read_file("execs/exec00/outputs/poc.cu")["text"] == "version-A"
    assert trail.read_file("execs/exec01/outputs/poc.cu")["text"] == "version-B"


def test_two_executions_keep_two_manifest_entries_and_two_dirs(tmp_path):
    trail = store(tmp_path).allocate()
    trail.exec_dir(0)
    trail.exec_dir(1)
    trail.record_execution({"argv": ["true"], "exit_code": 0})
    trail.record_execution({"argv": ["true"], "exit_code": 0})
    manifest = trail.manifest()
    assert len(manifest["executions"]) == 2
    assert [item["index"] for item in manifest["executions"]] == [0, 1]
    assert len([path for path in (trail.root / "execs").iterdir() if path.is_dir()]) == 2
