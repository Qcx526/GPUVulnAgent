# -*- coding: utf-8 -*-
"""Benchmark runner: no overwrite, explicit identity, honest metrics, real budget."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from gpuvulnagent.benchmarks import BenchmarkRunner, compute_metrics, read_records, \
    rebuild_summary
from gpuvulnagent.benchmarks.metrics import compare_legacy, summarize_metrics
from tests.support import ScriptedProvider, native, prose, tool_call


def write_evidence(run_dir: Path, records) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    lines = []
    for index, record in enumerate(records, start=1):
        entry = {"schema": "test", "run_id": "run-x", "sequence": index, "at": "now", **record}
        entry["evidence_id"] = "run-x#%d" % index
        lines.append(json.dumps(entry, ensure_ascii=False))
    (run_dir / "evidence.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_metrics_are_disjoint_and_target_scoped(tmp_path):
    run_dir = tmp_path / "run"
    write_evidence(run_dir, [
        {"kind": "tool", "tool_name": "shell", "status": "success"},
        {"kind": "tool", "tool_name": "fs_write", "status": "dispatch_error",
         "dispatched": False},
        {"kind": "exec", "via": "env_probe", "argv": ["nvidia-smi"], "exit": 0,
         "termination": {"kind": "success", "crash": False}},
        {"kind": "exec", "via": "shell", "argv": ["cmd", "/c", "cuobjdump -elf a.cubin"],
         "exit": 0, "termination": {"kind": "success", "crash": False}},
        {"kind": "exec", "via": "run_program", "argv": ["cuobjdump", "-elf", "a.cubin"],
         "exit": 0xC0000005, "termination": {"kind": "sigsegv", "crash": True}},
        {"kind": "exec", "via": "run_program", "argv": ["nvdisasm", "a.cubin"],
         "exit": -9, "timed_out": True,
         "termination": {"kind": "timeout", "crash": False}},
    ])
    metrics = compute_metrics(run_dir, targets=("cuobjdump", "nvdisasm"))
    assert metrics["tool_calls"] == 2
    assert metrics["process_invocations"] == 4
    assert metrics["target_tool_invocations"] == 3         # env_probe is not the target
    assert metrics["target_tool_crashes"] == 1             # only the access violation
    assert metrics["target_tools_used"] == ["cuobjdump", "nvdisasm"]
    assert metrics["timeout_count"] == 1
    assert metrics["dispatch_errors"] == 1
    assert metrics["crash_observed"] is True
    assert "target" in summarize_metrics(metrics)


def test_timeout_and_missing_binary_are_not_crashes(tmp_path):
    run_dir = tmp_path / "run"
    write_evidence(run_dir, [
        {"kind": "exec", "via": "shell", "argv": ["cmd", "/c", "cuobjdump x"], "exit": -9,
         "timed_out": True, "termination": {"kind": "timeout", "crash": False}},
        {"kind": "exec", "via": "shell", "argv": ["cmd", "/c", "cuobjdump y"], "exit": -2,
         "termination": {"kind": "not_found", "crash": False}},
        {"kind": "exec", "via": "shell", "argv": ["cmd", "/c", "cuobjdump z"], "exit": 1,
         "termination": {"kind": "error_exit", "crash": False}},
    ])
    metrics = compute_metrics(run_dir, targets=("cuobjdump",))
    assert metrics["target_tool_invocations"] == 3
    assert metrics["target_tool_crashes"] == 0
    assert metrics["crash_observed"] is False


def test_legacy_rule_audit_shows_the_old_overcount(tmp_path):
    run_dir = tmp_path / "run"
    write_evidence(run_dir, [
        {"kind": "exec", "via": "shell", "argv": ["cmd", "/c", "x"], "exit": -9,
         "timed_out": True, "termination": {"kind": "timeout", "crash": False}},
        {"kind": "exec", "via": "shell", "argv": ["cmd", "/c", "y"], "exit": -2,
         "termination": {"kind": "not_found", "crash": False}},
    ])
    audit = compare_legacy(read_records(run_dir))
    assert audit["old_rule_events"] == 2
    assert audit["classified_events"] == 0
    assert audit["old_rule_timeouts"] == 1
    assert audit["old_rule_launch_failures"] == 1


def make_runner(tmp_path: Path, provider_script=None, **kwargs) -> BenchmarkRunner:
    provider_script = provider_script or [prose("这是本次实验的结论。")]
    return BenchmarkRunner(
        cases_root=tmp_path / "cases", summary_root=tmp_path / "summary",
        provider_factory=lambda: ScriptedProvider(provider_script),
        research_root=tmp_path / "research", toolchain_root=None, manifest=None,
        max_turns=kwargs.pop("max_turns", 3), wall_clock=kwargs.pop("wall_clock", 60),
        enable_search=False)


def test_runs_never_overwrite_each_other(tmp_path):
    runner = make_runner(tmp_path)
    first = runner.run_case(case_id="CVE-2024-0124", mode="blind")
    second = runner.run_case(case_id="CVE-2024-0124", mode="blind")
    assert first["run_id"] != second["run_id"]
    assert Path(first["run_dir"]) != Path(second["run_dir"])
    assert Path(first["run_dir"]).is_dir() and Path(second["run_dir"]).is_dir()
    index = json.loads((tmp_path / "summary" / "index.json").read_text(encoding="utf-8"))
    assert {item["run_id"] for item in index["runs"]} == {first["run_id"], second["run_id"]}


def test_case_identity_is_recorded_as_separate_fields(tmp_path):
    runner = make_runner(tmp_path)
    record = runner.run_case(case_id="CVE-2025-23346", mode="seed", tag="r2", seed="poc/seed.c")
    assert record["case_id"] == "CVE-2025-23346"
    assert record["mode"] == "seed"
    case = json.loads((Path(record["run_dir"]) / "case.json").read_text(encoding="utf-8"))
    assert case["case_id"] == "CVE-2025-23346"
    assert case["mode"] == "seed"
    assert case["run_id"] == record["run_id"]
    assert case["seed_provided"] is True
    assert "CVE-2025-23346" in case["case_id"]
    assert (Path(record["run_dir"]) / "report.md").is_file()


def test_verdict_defaults_to_not_established(tmp_path):
    runner = make_runner(tmp_path)
    record = runner.run_case(case_id="CVE-2024-0111", mode="blind")
    assert record["DIFFERENTIAL_SUPPORTED"] == "NOT_ESTABLISHED"
    assert record["MECHANISM_SUPPORTED"] == "NOT_ESTABLISHED"
    assert record["CVE_ATTRIBUTED"] == "NOT_ESTABLISHED"
    assert record["CRASH_OBSERVED"] == "NOT_OBSERVED"
    assert record["metrics"]["target_tool_crashes"] == 0


def test_wall_clock_really_stops_the_run(tmp_path):
    class SlowProvider(ScriptedProvider):
        def chat(self, messages, **kwargs):
            time.sleep(1.2)
            return super().chat(messages, **kwargs)

    runner = BenchmarkRunner(
        cases_root=tmp_path / "cases", summary_root=tmp_path / "summary",
        provider_factory=lambda: SlowProvider([native(tool_call("fs_list", {}, "c1")),
                                               prose("不该走到这里")]),
        research_root=tmp_path / "research", toolchain_root=None, manifest=None,
        max_turns=5, wall_clock=1, enable_search=False)
    record = runner.run_case(case_id="CVE-2024-0125", mode="blind", wall_clock=1)
    assert record["wall_clock_exceeded"] is True
    assert record["stopped"] == "wall_clock"
    assert record["wall_clock_s"] >= 1


def test_summary_can_be_rebuilt_from_verdicts(tmp_path):
    runner = make_runner(tmp_path)
    for case in ("CVE-2024-0124", "CVE-2024-0125"):
        runner.run_case(case_id=case, mode="blind")
    rebuilt = rebuild_summary(tmp_path / "cases", tmp_path / "summary")
    assert len(rebuilt["runs"]) == 2
    assert {item["case_id"] for item in rebuilt["runs"]} == {"CVE-2024-0124", "CVE-2024-0125"}


def test_existing_directory_is_refused(tmp_path):
    runner = make_runner(tmp_path)
    record = runner.run_case(case_id="CVE-X", mode="blind")
    with pytest.raises(Exception):
        # Asking for the same identity twice must not silently reuse the directory.
        from gpuvulnagent.runtime.state import RunState
        from gpuvulnagent.runtime.state import RunPaths
        RunState(RunPaths.under(Path(record["run_dir"]))).create(goal="g")
