# -*- coding: utf-8 -*-
"""Crash detection over evidence records.

The P18 runner treated any negative exit code as a crash. That counted a missing
executable (-2) and a killed timeout (-9) as memory corruption, and it counted a shell
wrapper's exit status as if the target had produced it.

Two entry points:

* :func:`classify_record` - the classification recorded by the runner, or a derived one
  for records written before classification existed;
* :func:`crash_events` - only records whose termination is an actual fault.

``legacy=True`` marks a derived classification so an audit of an old run can be told apart
from a fresh measurement.
"""

from __future__ import annotations

from typing import List, Optional

from ..evidence.outcome import CRASH_KINDS, classify_termination


def classify_record(record: dict) -> dict:
    stored = record.get("termination")
    if isinstance(stored, dict) and stored.get("kind"):
        return {"kind": stored["kind"], "crash": bool(stored.get("crash")),
                "detail": stored.get("detail", ""), "derived": False}
    derived = classify_termination(record.get("exit"),
                                   timed_out=bool(record.get("timed_out")))
    derived["derived"] = True
    return derived


def crash_events(records: List[dict], *, include_derived: bool = True) -> List[dict]:
    events = []
    for record in records:
        if record.get("kind") != "exec":
            continue
        info = classify_record(record)
        if not info["crash"]:
            continue
        if info["derived"] and not include_derived:
            continue
        events.append({"sequence": record.get("sequence"),
                       "evidence_id": record.get("evidence_id"),
                       "exit": record.get("exit"), "kind": info["kind"],
                       "detail": info["detail"], "argv": record.get("argv"),
                       "via": record.get("via"), "derived": info["derived"]})
    return events


def termination_histogram(records: List[dict]) -> dict:
    histogram: dict = {}
    for record in records:
        if record.get("kind") != "exec":
            continue
        info = classify_record(record)
        histogram[info["kind"]] = histogram.get(info["kind"], 0) + 1
    return dict(sorted(histogram.items()))


def is_crash_kind(kind: Optional[str]) -> bool:
    return bool(kind) and kind in CRASH_KINDS
