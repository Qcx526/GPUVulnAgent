# -*- coding: utf-8 -*-
"""Adapters: a real JPEG survives a plan, and the ELF reader refuses to guess."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from gpuvulnagent.adapters.elf_cubin import ElfError, parse_header, summarise
from gpuvulnagent.adapters.jpeg import AdapterError, apply_plan, inspect_bytes, \
    plan_dimensions, walk_segments


def synthetic_jpeg(width: int = 32, height: int = 24) -> bytes:
    """A structurally valid baseline JPEG header: SOI, APP0, DQT, SOF0, DHT, SOS, data."""
    app0 = b"\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00" + bytes([1, 1, 0]) + \
        struct.pack(">HH", 1, 1) + bytes([0, 0])
    dqt = b"\xff\xdb" + struct.pack(">H", 4) + bytes([0]) + b"\x00"
    sof = b"\xff\xc0" + struct.pack(">H", 17) + bytes([8]) + struct.pack(">HH", height,
                                                                        width) + \
        bytes([3]) + b"\x01\x11\x00\x02\x11\x00\x03\x11\x00"
    dht = b"\xff\xc4" + struct.pack(">H", 4) + b"\x00\x00"
    sos = b"\xff\xda" + struct.pack(">H", 12) + bytes([3]) + b"\x01\x00\x02\x11\x03\x11" + \
        b"\x00\x3f\x00"
    entropy = b"\x12\x34\x56\x78"
    return b"\xff\xd8" + app0 + dqt + sof + dht + sos + entropy


def test_walk_segments_reads_the_marker_stream():
    segments = walk_segments(synthetic_jpeg())
    names = [segment["name"] for segment in segments]
    assert names[0] == "SOI"
    assert "SOF0" in names and names[-1] == "SOS"


def test_inspect_reports_frame_and_scans():
    info = inspect_bytes(synthetic_jpeg(64, 48))
    assert info["frame"]["width"] == 64
    assert info["frame"]["height"] == 48
    assert info["frame"]["precision"] == 8
    assert info["scan_count"] == 1


def test_plan_produces_mutated_and_control_of_equal_length():
    data = synthetic_jpeg(64, 48)
    mutated, control, details = apply_plan(data, plan_dimensions(1, 1))
    assert len(mutated) == len(control) == len(data)
    assert details["original"] == {"width": 64, "height": 48}
    assert inspect_bytes(mutated)["frame"]["width"] == 1
    assert inspect_bytes(mutated)["frame"]["height"] == 1
    # The control restores the original bytes exactly.
    assert control == data


def test_plan_refuses_out_of_range_and_non_baseline():
    with pytest.raises(AdapterError):
        plan_dimensions(0, 10)
    with pytest.raises(AdapterError):
        plan_dimensions(70000, 10)

    progressive = bytearray(synthetic_jpeg())
    index = progressive.find(b"\xff\xc0")
    progressive[index + 1] = 0xC2
    with pytest.raises(AdapterError):
        inspect_bytes(bytes(progressive))


def test_not_a_jpeg_is_refused():
    with pytest.raises(AdapterError):
        walk_segments(b"not a jpeg at all")


def elffile(machine: int = 190) -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    header = struct.pack("<HHIQQQIHHHHHH", 2, machine, 1, 0, 0, 0, 0, 64, 56, 0, 64, 0, 0)
    return ident + header


def test_elf_header_identifies_a_cubin():
    header = parse_header(elffile())
    assert header["class"] == "ELF64"
    assert header["machine"] == 190
    assert header["machine_name"] == "EM_CUDA"
    assert header["is_cuda"] is True


def test_elf_summary_reports_verdict(tmp_path: Path):
    path = tmp_path / "kernel.cubin"
    path.write_bytes(elffile())
    info = summarise(path)
    assert info["verdict"] == "cubin (EM_CUDA)"
    assert info["section_count"] == 0


def test_elf_reader_refuses_non_elf(tmp_path: Path):
    path = tmp_path / "notelf.bin"
    path.write_bytes(b"MZ\x90\x00" + b"\x00" * 64)
    with pytest.raises(ElfError):
        summarise(path)


def test_jpeg_tools_write_results_into_the_workspace(tmp_path: Path):
    from gpuvulnagent.adapters.jpeg.tools import build_tools
    from gpuvulnagent.evidence import ArtifactStore, EvidenceLog
    from gpuvulnagent.runtime.workspace import Workspace

    workspace = Workspace(tmp_path / "ws")
    workspace.write("samples/small.jpg", synthetic_jpeg(40, 30))
    log = EvidenceLog(tmp_path / "evidence.jsonl", "run-j",
                      ArtifactStore(tmp_path / "artifacts"))
    specs = {spec.name: spec for spec in build_tools(workspace=workspace, log=log)}
    inspect_out = specs["jpeg_inspect"].handler(path="samples/small.jpg")
    assert inspect_out["ok"] and inspect_out["summary"]["width"] == 40

    mutate_out = specs["jpeg_mutate_dimensions"].handler(path="samples/small.jpg",
                                                         width=1, height=1)
    assert mutate_out["ok"]
    assert mutate_out["summary"]["same_length"] is True
    assert (workspace.root / "jpeg" / "small-mutated.jpg").is_file()
    assert (workspace.root / "jpeg" / "small-control.jpg").is_file()
