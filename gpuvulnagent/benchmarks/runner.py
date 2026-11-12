# -*- coding: utf-8 -*-
"""Benchmark runner: hand the agent a case, measure what actually happened.

Design rules, each of which answers a specific P18 defect:

* **A. Never overwrite an experiment.** Each run gets a fresh ``run_id`` and its own
  directory; an existing directory is refused instead of removed.
* **B. Case identity is explicit.** ``case_id``, ``mode`` and ``run_id`` are separate
  fields; ``run_dir.name`` is never used as the case.
* **C. Termination is classified.** Only a target process dying of a fault counts.
* **D. Metrics are disjoint** - see :mod:`gpuvulnagent.benchmarks.metrics`.
* **E. The wall clock is enforced**, by the runtime and by every process it starts.
* **F. Results accumulate.** The index keeps every run id and can be rebuilt.

The verdict is computed from evidence, not from the model's final text.
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import time
from pathlib import Path
from typing import Callable, List, Optional

from ..evidence.hashing import sha256_file
from ..runtime.loop import AgentRuntime
from ..runtime.state import new_run_id
from .metrics import DEFAULT_TARGET_TOOLS, compute_metrics, summarize_metrics, verdict
from .summary import SummaryIndex

BLIND_GOAL = """# 研究目标

样本标识：{case}

请把这个问题研究到"有证据的结论"：
- 查清它属于哪个组件、影响哪些版本、触发面是什么；
- 判断本机是否具备可评价的实验条件；能测就测，不能测就说清缺什么；
- 任何你声称的异常，必须是你实际执行并留下可核验证据的；
- 结束时写清：做了什么、看到什么、哪些是推测、哪些有证据、还缺什么。

环境事实（不是方法建议）：
{environment}

工作区就是你当前目录，可以写文件、编译、运行。允许联网。不要修改系统驱动，
不要安装需要管理员权限的组件。
"""

SEED_GOAL = BLIND_GOAL + """
历史候选（上一代工程产出，仅供参考，不是答案）：
{seed}

你可以读它、分析它、决定是否采用、部分采用，或完全另起思路。
如果沿用它的输入，请说明你复用了什么、改了什么。
"""


class BenchmarkError(RuntimeError):
    """The benchmark refused to run rather than corrupt an existing experiment."""


def environment_facts(*, toolchain_root: Optional[Path] = None,
                      manifest=None) -> dict:
    """What this machine really has, read from the manifest rather than hardcoded paths."""
    tools = {}
    if manifest is not None:
        for name in manifest.names():
            entry = manifest.describe(name)
            if entry:
                tools[name] = {"path": entry.get("absolute_path", ""),
                               "version": entry.get("version", ""),
                               "sha256": entry.get("sha256", ""),
                               "runnable": entry.get("runnable", False)}
    else:
        for name in ("cuobjdump", "nvdisasm", "nvcc"):
            found = shutil.which(name)
            tools[name] = {"path": found or "", "version": "", "sha256": "",
                           "runnable": bool(found)}
    try:
        smi = subprocess.run(["nvidia-smi", "--query-gpu=name,driver_version,memory.total",
                              "--format=csv,noheader"], capture_output=True, text=True,
                             timeout=20).stdout.strip()
    except Exception:  # noqa: BLE001
        smi = "unavailable"
    return {"os": platform.platform(), "gpu": smi, "python": platform.python_version(),
            "toolchain_root": str(toolchain_root or ""), "tools": tools}


def facts_text(facts: dict) -> str:
    lines = ["- 操作系统：%s" % facts["os"], "- GPU/驱动：%s" % facts["gpu"],
             "- Python：%s" % facts["python"]]
    for name, info in (facts.get("tools") or {}).items():
        lines.append("- %s：%s%s" % (name, info.get("path") or "未找到",
                                     "" if info.get("runnable") else "（不可运行）"))
    if facts.get("toolchain_root"):
        lines.append("- 工具链根目录：%s" % facts["toolchain_root"])
    return "\n".join(lines)


class BenchmarkRunner:
    def __init__(self, *, cases_root: Path, summary_root: Path,
                 provider_factory: Callable[[], object], research_root: Path,
                 toolchain_root: Optional[Path] = None, manifest=None,
                 target_tools=DEFAULT_TARGET_TOOLS, max_turns: int = 8,
                 wall_clock: int = 1800, enable_search: bool = True,
                 include_adapters: bool = True, enable_gpu_backend: bool = True,
                 backend_config=None) -> None:
        self.cases_root = Path(cases_root)
        self.summary = SummaryIndex(summary_root)
        self.provider_factory = provider_factory
        self.research_root = Path(research_root)
        self.toolchain_root = toolchain_root
        self.manifest = manifest
        self.target_tools = tuple(target_tools)
        self.max_turns = max_turns
        self.wall_clock = wall_clock
        self.enable_search = enable_search
        self.include_adapters = include_adapters
        self.enable_gpu_backend = enable_gpu_backend
        self.backend_config = backend_config

    # -- one case --------------------------------------------------------
    def run_case(self, *, case_id: str, mode: str = "blind", turns: Optional[int] = None,
                 wall_clock: Optional[int] = None, seed: str = "", goal_file: str = "",
                 tag: str = "") -> dict:
        if mode not in ("blind", "seed"):
            raise BenchmarkError("mode must be blind or seed, got %r" % mode)
        run_id = new_run_id()
        run_dir = self.cases_root / case_id / mode / (tag or "default") / run_id
        # A. Refuse to reuse a directory. The id is unique, so this can only fire if a
        # caller passes a path it already owns - which is exactly when silent overwrite
        # used to destroy an experiment.
        if run_dir.exists():
            raise BenchmarkError("run directory already exists: %s" % run_dir)
        # The runtime creates and owns its own root; pre-creating it here would trip the
        # "refusing to overwrite an existing run" guard it is supposed to raise.
        run_dir.parent.mkdir(parents=True, exist_ok=True)

        budget_turns = int(turns or self.max_turns)
        budget_seconds = int(wall_clock or self.wall_clock)
        facts = environment_facts(toolchain_root=self.toolchain_root, manifest=self.manifest)
        goal = self._goal(case_id, mode, seed, goal_file, facts)
        # B. Identity is recorded as three separate fields, never inferred from a path.
        case_record = {"case_id": case_id, "mode": mode, "run_id": run_id,
                       "tag": tag, "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                       "budget": {"turns": budget_turns, "wall_clock_s": budget_seconds},
                       "seed_provided": bool(seed),
                       "goal_sha256": __import__("hashlib").sha256(
                           goal.encode("utf-8")).hexdigest()}

        deadline = time.monotonic() + budget_seconds
        provider = self.provider_factory()
        started = time.time()
        wall_clock_exceeded = False
        error = ""
        runtime = None
        try:
            runtime = AgentRuntime(
                goal=goal, root=run_dir, provider=provider, max_turns=budget_turns,
                run_timeout=budget_seconds, case_id=case_id,
                research_root=self.research_root, toolchain_root=self.toolchain_root,
                manifest_path=(self.manifest.path if self.manifest is not None else None),
                enable_search=self.enable_search,
                include_adapters=self.include_adapters,
                enable_gpu_backend=self.enable_gpu_backend,
                backend_config=self.backend_config, deadline=deadline)
            result = runtime.run()
            final_text, stopped = result.final, result.stopped
            usage = result.usage.to_dict()
            decisions = result.decisions
        except Exception as exc:  # noqa: BLE001 - a failed case is a result, not a crash
            error = "%s: %s" % (type(exc).__name__, exc)
            final_text, stopped, usage, decisions = "", "error", {}, 0
        elapsed = time.time() - started
        wall_clock_exceeded = elapsed > budget_seconds or stopped == "wall_clock"

        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "environment.json").write_text(
            json.dumps(facts, ensure_ascii=False, indent=1), encoding="utf-8")
        (run_dir / "case.json").write_text(
            json.dumps(case_record, ensure_ascii=False, indent=1), encoding="utf-8")

        metrics = compute_metrics(run_dir, targets=self.target_tools)
        record = verdict(metrics, mode=mode, case_id=case_id, run_id=run_id,
                         wall_clock_exceeded=wall_clock_exceeded)
        record.update({"stopped": stopped, "error": error,
                       "wall_clock_s": round(elapsed, 1),
                       "budget": case_record["budget"],
                       "usage": usage, "decisions": decisions,
                       "final_claim": (final_text or "")[:4000],
                       "environment_sha256": sha256_file(run_dir / "environment.json"),
                       "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                       "run_dir": str(run_dir)})
        (run_dir / "verdict.json").write_text(json.dumps(record, ensure_ascii=False, indent=1),
                                              encoding="utf-8")
        (run_dir / "report.md").write_text(self._report(record), encoding="utf-8")
        self.summary.record(record)
        return record

    # -- helpers ---------------------------------------------------------
    def _goal(self, case_id: str, mode: str, seed: str, goal_file: str, facts: dict) -> str:
        environment = facts_text(facts)
        if goal_file:
            template = Path(goal_file).read_text(encoding="utf-8")
            return template.format(case=case_id, environment=environment, seed=seed)
        template = SEED_GOAL if mode == "seed" else BLIND_GOAL
        return template.format(case=case_id, environment=environment, seed=seed)

    def _report(self, record: dict) -> str:
        metrics = record["metrics"]
        lines = ["# %s / %s" % (record["case_id"], record["mode"]), "",
                 "- run_id：%s" % record["run_id"],
                 "- 目标版本/结论：%s" % record["CRASH_OBSERVED"],
                 "- 工具调用：%d" % metrics["tool_calls"],
                 "- 进程启动：%d" % metrics["process_invocations"],
                 "- 目标工具调用：%d" % metrics["target_tool_invocations"],
                 "- 目标工具崩溃：%d" % metrics["target_tool_crashes"],
                 "- 超时：%d" % metrics["timeout_count"],
                 "- 调度失败：%d" % metrics["dispatch_errors"],
                 "- 使用工具：%s" % ", ".join(metrics["unique_tools"]),
                 "- 终止分布：%s" % metrics["terminations"],
                 "- 耗时：%ss / 预算 %ss%s"
                 % (record["wall_clock_s"], record["budget"]["wall_clock_s"],
                    "（超出预算）" if record["wall_clock_exceeded"] else ""),
                 "- Token：%s" % record["usage"].get("total_tokens"),
                 "- 停止原因：%s" % record["stopped"]]
        if record.get("error"):
            lines.append("- 运行错误：%s" % record["error"])
        lines += ["", "## 结论（模型自述，未验证）", "", record["final_claim"] or "(无)"]
        return "\n".join(lines)


def rebuild_summary(cases_root: Path, summary_root: Path) -> dict:
    return SummaryIndex(summary_root).rebuild(cases_root)


def list_runs(summary_root: Path) -> str:
    return SummaryIndex(summary_root).table()


def case_dirs(cases_root: Path) -> List[Path]:
    return sorted({path.parent.parent.parent for path in Path(cases_root).rglob("verdict.json")})
