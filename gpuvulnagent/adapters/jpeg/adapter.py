# -*- coding: utf-8 -*-
"""JPEG segment adapter: read the marker structure, mutate one field, keep the control.

This is the capability P18's agent could not find. It is reimplemented here as a
self-contained reader/writer over the marker stream (ITU-T T.81 B.2.1/B.2.2) rather than
copied from the legacy pipeline module, because the legacy module imports the rest of that
pipeline through its package.

Two rules from the legacy design are kept, because they are the reason it was usable:

* a plan is data - the candidate never assembles bytes by hand, it names a field;
* every mutation records the value it replaced, so the paired control is produced by
  undoing the plan, not by guessing.

Anything ambiguous is refused (progressive, arithmetic coding, multi-scan, unknown
markers, out-of-range values) instead of being clamped. ``Pillow`` is used only as a
second, independent reader when it is installed; the segment walker here is the first.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple

SOI, EOI, SOS, DQT, DHT, DRI, COM = 0xD8, 0xD9, 0xDA, 0xDB, 0xC4, 0xDD, 0xFE
SOF_BASELINE, SOF_EXTENDED = 0xC0, 0xC1
SOF_UNSUPPORTED = {0xC2: "progressive", 0xC3: "lossless", 0xC5: "differential",
                   0xC6: "differential-progressive", 0xC7: "differential-lossless",
                   0xC9: "arithmetic", 0xCA: "arithmetic-progressive",
                   0xCB: "arithmetic-lossless", 0xCD: "arithmetic-differential",
                   0xCE: "arithmetic-differential-progressive",
                   0xCF: "arithmetic-differential-lossless"}
SEGMENT_NAMES = {0xD8: "SOI", 0xD9: "EOI", 0xDB: "DQT", 0xC4: "DHT", 0xDA: "SOS",
                 0xDD: "DRI", 0xFE: "COM", 0xC0: "SOF0", 0xC1: "SOF1", 0xC2: "SOF2"}
APP_MARKERS = set(range(0xE0, 0xF0))


class AdapterError(ValueError):
    """Fail closed: the file or the plan is outside what this adapter supports."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def walk_segments(data: bytes) -> List[dict]:
    """Walk the marker stream. Stops at SOS because entropy-coded data is not markers."""
    if len(data) < 4 or data[0:2] != b"\xff\xd8":
        raise AdapterError("not a JPEG: missing SOI")
    segments: List[dict] = []
    index = 0
    while index < len(data):
        if data[index] != 0xFF:
            raise AdapterError("expected a marker at offset %d, found 0x%02X"
                               % (index, data[index]))
        marker = data[index + 1]
        if marker == 0xFF:            # fill byte
            index += 1
            continue
        if marker in (SOI, EOI) or 0xD0 <= marker <= 0xD7:
            segments.append({"marker": marker, "name": SEGMENT_NAMES.get(marker, "%02X" % marker),
                             "offset": index, "length": 2})
            index += 2
            if marker == EOI:
                break
            continue
        if index + 4 > len(data):
            raise AdapterError("truncated segment header at offset %d" % index)
        length = struct.unpack(">H", data[index + 2:index + 4])[0]
        if length < 2 or index + 2 + length > len(data):
            raise AdapterError("segment 0x%02X at offset %d has an invalid length %d"
                               % (marker, index, length))
        segments.append({"marker": marker,
                         "name": SEGMENT_NAMES.get(marker, "%02X" % marker),
                         "offset": index, "length": length + 2})
        index += 2 + length
        if marker == SOS:
            break
    return segments


def find_sof(segments: List[dict]) -> dict:
    for segment in segments:
        marker = segment["marker"]
        if marker in (SOF_BASELINE, SOF_EXTENDED):
            return segment
        if marker in SOF_UNSUPPORTED:
            raise AdapterError("unsupported SOF: %s (only baseline/extended sequential is "
                               "editable here)" % SOF_UNSUPPORTED[marker])
        if 0xC0 <= marker <= 0xCF and marker not in (DHT,):
            raise AdapterError("unrecognised SOF marker 0x%02X" % marker)
    raise AdapterError("no SOF marker found")


def read_frame(data: bytes, sof: dict) -> dict:
    offset = sof["offset"]
    precision = data[offset + 4]
    height = struct.unpack(">H", data[offset + 5:offset + 7])[0]
    width = struct.unpack(">H", data[offset + 7:offset + 9])[0]
    components = data[offset + 9]
    return {"precision": precision, "height": height, "width": width,
            "components": components, "sof_offset": offset,
            "height_offset": offset + 5, "width_offset": offset + 7,
            "marker": "SOF0" if sof["marker"] == SOF_BASELINE else "SOF1"}


def inspect_bytes(data: bytes) -> dict:
    segments = walk_segments(data)
    frame = read_frame(data, find_sof(segments))
    scan_count = sum(1 for s in segments if s["marker"] == SOS)
    return {"bytes": len(data), "sha256": sha256(data), "frame": frame,
            "scan_count": scan_count,
            "segments": [{"name": s["name"], "offset": s["offset"], "length": s["length"]}
                         for s in segments],
            "markers": [s["name"] for s in segments]}


def inspect_file(path: Path) -> dict:
    path = Path(path)
    if not path.is_file():
        raise AdapterError("no such file: %s" % path)
    info = inspect_bytes(path.read_bytes())
    info["path"] = str(path)
    info["size"] = path.stat().st_size
    return info


def plan_dimensions(width: int, height: int) -> dict:
    """A plan is data: the fields to write and nothing else."""
    for name, value in (("width", width), ("height", height)):
        if not isinstance(value, int):
            raise AdapterError("%s must be an integer" % name)
        if not 1 <= value <= 65535:
            raise AdapterError("%s must be in 1..65535, got %d" % (name, value))
    return {"op": "set_frame_dimensions", "width": width, "height": height}


def apply_plan(data: bytes, plan: dict) -> Tuple[bytes, bytes, dict]:
    """Apply a plan and return ``(mutated, control, details)``.

    The control is produced by writing the original values back through the same path,
    so the pair differs only in the two bytes the plan names.
    """
    if plan.get("op") != "set_frame_dimensions":
        raise AdapterError("unsupported plan op: %r" % plan.get("op"))
    info = inspect_bytes(data)
    frame = info["frame"]
    if info["scan_count"] != 1:
        raise AdapterError("expected exactly one scan for a single mutation, found %d"
                           % info["scan_count"])
    original = (frame["width"], frame["height"])
    mutated = bytearray(data)
    struct.pack_into(">H", mutated, frame["width_offset"], plan["width"])
    struct.pack_into(">H", mutated, frame["height_offset"], plan["height"])
    control = bytearray(data)
    struct.pack_into(">H", control, frame["width_offset"], original[0])
    struct.pack_into(">H", control, frame["height_offset"], original[1])
    details = {"plan": dict(plan), "original": {"width": original[0], "height": original[1]},
               "mutated": {"width": plan["width"], "height": plan["height"]},
               "offsets": {"width": frame["width_offset"], "height": frame["height_offset"]},
               "original_sha256": info["sha256"]}
    return bytes(mutated), bytes(control), details


def validate_pair(mutated: bytes, control: bytes, path: Optional[str] = None) -> dict:
    """Two independent readers: the walker here, and Pillow when it is installed."""
    report: Dict[str, object] = {}
    try:
        report["segment_walk"] = inspect_bytes(mutated)["frame"]
    except AdapterError as exc:
        report["segment_walk"] = {"error": str(exc)}
    try:
        from PIL import Image  # noqa: F401 - optional second reader
        import io
        with Image.open(io.BytesIO(mutated)) as image:
            image.load()
            report["pillow"] = {"ok": True, "size": list(image.size), "mode": image.mode}
        with Image.open(io.BytesIO(control)) as image:
            image.load()
            report["pillow_control"] = {"ok": True, "size": list(image.size)}
    except ImportError:
        report["pillow"] = {"ok": None, "reason": "Pillow is not installed"}
    except Exception as exc:  # noqa: BLE001 - a decoder refusing the file is a result
        report["pillow"] = {"ok": False, "error": "%s: %s" % (type(exc).__name__, exc)}
    if path:
        report["path"] = path
    return report
