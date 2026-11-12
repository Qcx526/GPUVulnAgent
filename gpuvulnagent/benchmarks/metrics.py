# -*- coding: utf-8 -*-
"""Execution metrics, counted by what actually ran.

P18 reported one ``executions`` number that mixed three different things: tool dispatches,
OS processes the harness started, and invocations of the target tool. A report built on
that number cannot answer "did the target run, and did it crash", which is the only
question the benchmark exists to answer.

The counters here are disjoint:

``tool_calls``               every dispatched tool call, whatever it was
``process_invocations``      every OS process the harness started (including env probes)
``target_tool_invocations``  processes whose program is the target tool (cuobjdump,
                             nvdisasm, a built PoC binary), whether started directly or
                             through a shell
``target_tool_crashes``      subset of the above that died of a fault
``timeout_count``            processes the harness had to kill
``dispatch_errors``          tool calls that never ran (unknown tool, bad args, missing dep)
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Iterable, List, Optional

from .crash import classify_record, crash_events, termination_histogram

DEFAULT_TARGET_TOOLS = ("cuobjdump", "nvdisasm", "nvcc", "nvjpeg", "nvJitLink")


def read_records(run_dir: Path) -> List[dict]:
    path = Path(run_dir) / "evidence.jsonl"
    if not path.is_file():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def target_program(record: dict, targets: Iterable[str]) -> str:
    """Which program this process record actually ran.

    A shell call is inspected too: ``cmd /c "cuobjdump -elf a.cubin"`` is a cuobjdump
    invocation wrapped in a shell, and pretending otherwise would undercount the target.

    A container record (``backend`` set) is the target environment by construction: the
    agent started a container in order to run something. Its program is the first real
    token of the command, including when that command is inside ``bash -lc``.
    """
    names = {os.path.basename(t).lower() for t in targets}
    argv = record.get("argv") or []
    if not argv:
        return ""
    first = _program_name(str(argv[0]))
    if first in names:
        return first
    if first in ("cmd", "sh", "bash", "powershell", "pwsh"):
        command = " ".join(str(a) for a in argv[1:])
        tokens = _tokens(command)
        for token in tokens:
            base = _program_name(token)
            if base in names:
                return base
        if record.get("backend") and tokens:
            # Inside a container the command string *is* the experiment.
            return _program_name(tokens[0]) or first
    if record.get("backend"):
        return first
    return ""


def _program_name(token: str) -> str:
    base = os.path.basename(token).lower().strip("\"'")
    if base.endswith(".exe"):
        base = base[:-4]
    return base


def compute_metrics(run_dir: Path, *, targets: Iterable[str] = DEFAULT_TARGET_TOOLS) -> dict:
    records = read_records(run_dir)
    tool_records = [r for r in records if r.get("kind") == "tool"]
    execs = [r for r in records if r.get("kind") == "exec"]
    targets = tuple(targets)

    target_invocations = []
    for record in execs:
        program = target_program(record, targets)
        if program:
            target_invocations.append((program, record))

    target_crashes = [{"program": program, "evidence_id": record.get("evidence_id"),
                       "sequence": record.get("sequence"),
                       "kind": classify_record(record)["kind"],
                       "exit": record.get("exit"), "argv": record.get("argv")}
                      for program, record in target_invocations
                      if classify_record(record)["crash"]]

    dispatch_errors = [r for r in tool_records
                       if r.get("status") == "dispatch_error" or r.get("dispatched") is False]
    timeouts = [r for r in execs if classify_record(r)["kind"] == "timeout"]
    crashed_all = crash_events(records)

    return {
        "tool_calls": len(tool_records),
        "process_invocations": len(execs),
        "target_tool_invocations": len(target_invocations),
        "target_tools_used": sorted({program for program, _ in target_invocations}),
        "target_tool_crashes": len(target_crashes),
        "target_crash_events": target_crashes,
        "crash_events": crashed_all,
        "crash_observed": bool(target_crashes),
        "crash_observed_any_process": bool(crashed_all),
        "timeout_count": len(timeouts),
        "dispatch_errors": len(dispatch_errors),
        "unique_tools": sorted({r.get("tool_name") for r in tool_records
                                if r.get("tool_name")}),
        "terminations": termination_histogram(records),
        "evidence_records": len(records),
        "artifacts": _count_artifacts(run_dir),
    }


def verdict(metrics: dict, *, mode: str, case_id: str, run_id: str,
            wall_clock_exceeded: bool = False) -> dict:
    """A verdict states what was established, and defaults to NOT_ESTABLISHED."""
    return {
        "case_id": case_id,
        "run_id": run_id,
        "mode": mode,
        "CRASH_OBSERVED": "OBSERVED" if metrics["target_tool_crashes"] else "NOT_OBSERVED",
        "DIFFERENTIAL_SUPPORTED": "NOT_ESTABLISHED",
        "MECHANISM_SUPPORTED": "NOT_ESTABLISHED",
        "CVE_ATTRIBUTED": "NOT_ESTABLISHED",
        "wall_clock_exceeded": wall_clock_exceeded,
        "metrics": metrics,
        "note": ("崩溃只按目标进程的异常终止计数：超时被杀、程序不存在、普通非零退出都不算。"
                 "差值与机制需要配对对照与根因证据，没有就是 NOT_ESTABLISHED。"),
    }


def compare_legacy(records: List[dict], *, targets: Iterable[str] = DEFAULT_TARGET_TOOLS) -> dict:
    """Audit-only view of an old run: what the old rule counted versus what was real.

    This never rewrites history. It reports the difference so a report can say "P18
    counted N crash events; under explicit classification M of them were launches or
    timeouts".
    """
    old_rule = [r for r in records if r.get("kind") == "exec"
                and isinstance(r.get("exit"), int)
                and (r["exit"] < 0 or r["exit"] >= 0xC0000000)]
    classified = crash_events(records)
    launches = [r for r in old_rule
                if classify_record(r)["kind"] in ("not_found", "not_runnable")]
    timeouts = [r for r in old_rule if classify_record(r)["kind"] == "timeout"]
    return {"old_rule_events": len(old_rule), "classified_events": len(classified),
            "old_rule_launch_failures": len(launches),
            "old_rule_timeouts": len(timeouts),
            "note": "audit only; historical verdicts are not modified"}


def _tokens(command: str) -> List[str]:
    return [token for token in command.replace('"', " ").split() if token]


def _count_artifacts(run_dir: Path) -> int:
    root = Path(run_dir) / "artifacts"
    if not root.is_dir():
        return 0
    return sum(1 for path in root.rglob("*") if path.is_file())


def summarize_metrics(metrics: dict) -> str:
    return ("tools=%d processes=%d target=%d target_crashes=%d timeouts=%d dispatch_errors=%d"
            % (metrics["tool_calls"], metrics["process_invocations"],
               metrics["target_tool_invocations"], metrics["target_tool_crashes"],
               metrics["timeout_count"], metrics["dispatch_errors"]))
