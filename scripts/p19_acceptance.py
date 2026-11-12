# -*- coding: utf-8 -*-
"""P19 acceptance: environment probe, container execution, failure feedback, autonomy.

Four checks, all against the real machine:

A. environment probe through the agent's own tool, not a manual shell command;
B. compile and run `vector_add.cu` on the GTX 1660 through the tool layer;
C. the failure matrix - missing binary, compile error, ordinary non-zero exit, timeout,
   bad GPU spec - must all come back as themselves and none of them as a crash;
D. one short autonomous run where the agent is given only the goal.

    python scripts/p19_acceptance.py [--turns 12] [--skip-agent]

Writes ``.local/logs/p19_acceptance.json`` and prints one line per check.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gpuvulnagent.config import ConfigLoader  # noqa: E402
from gpuvulnagent.evidence import ArtifactStore, EvidenceLog, Runner, verify_chain  # noqa: E402
from gpuvulnagent.memory.store import LayeredMemory  # noqa: E402
from gpuvulnagent.providers.deepseek import DeepSeekProvider  # noqa: E402
from gpuvulnagent.runtime.loop import AgentRuntime  # noqa: E402
from gpuvulnagent.runtime.state import new_run_id  # noqa: E402
from gpuvulnagent.runtime.workspace import Workspace  # noqa: E402
from gpuvulnagent.tools.build import build_assembly  # noqa: E402

IMAGE = "nvidia/cuda:12.8.0-devel-ubuntu22.04"
VECTOR_ADD = ROOT / "data" / "cases" / "cuda_smoke" / "vector_add.cu"
RESULTS: dict = {}


def record(name: str, payload: dict) -> None:
    RESULTS[name] = payload
    print("[%-26s] %-6s %s" % (name, payload.get("status", "?").upper(),
                               json.dumps({k: v for k, v in payload.items()
                                           if k not in ("status", "stdout", "stderr")},
                                          ensure_ascii=False)[:320]))


def make_assembly(run_dir: Path, run_id: str):
    workspace = Workspace(run_dir / "workspace")
    artifacts = ArtifactStore(run_dir / "artifacts")
    log = EvidenceLog(run_dir / "evidence.jsonl", run_id, artifacts)
    runner = Runner(workspace.root, log, timeout=60)
    memory = LayeredMemory(run_dir=run_dir, research_root=ROOT / "research_archive",
                           run_id=run_id, case_id="P19-ACCEPTANCE")
    return build_assembly(workspace=workspace, runner=runner, log=log, memory=memory,
                          toolchain_root=ROOT / "toolchains",
                          enable_search=False)


def check_a(assembly) -> None:
    started = time.time()
    outcome = assembly.registry.call("gpu_environment_probe", {"deep": True})
    summary = outcome.get("summary") or {}
    ok = bool(outcome["ok"] and summary.get("available"))
    record("A_environment_probe", {
        "status": "ok" if ok else "failed",
        "distro": summary.get("distro"), "docker": summary.get("docker"),
        "gpu": summary.get("gpu"), "compute_capability": summary.get("compute_capability"),
        "cuda": summary.get("cuda"), "tools": summary.get("tools"),
        "gpu_in_container": summary.get("gpu_in_container"),
        "seconds": round(time.time() - started, 1)})


def check_b(assembly) -> dict:
    trail = assembly.registry.call("trail_new", {"purpose": "P19 acceptance vector_add"})
    trail_id = trail["summary"]["trail"]
    assembly.registry.call("trail_write", {
        "trail": trail_id, "name": "vector_add.cu",
        "content": VECTOR_ADD.read_text(encoding="utf-8")})
    started = time.time()
    outcome = assembly.registry.call("container_exec", {
        "trail": trail_id, "image": IMAGE, "timeout_s": 600,
        "argv": ["bash", "-lc",
                 "nvcc -O2 -arch=sm_75 vector_add.cu -o vector_add && ./vector_add"]})
    summary = outcome.get("summary") or {}
    stdout = summary.get("stdout", "")
    expected = ["GPU: NVIDIA GeForce GTX 1660", "Compute Capability: 7.5",
                "CUDA_KERNEL=PASS", "ELEMENTS=1048576", "RESULT=30"]
    missing = [line for line in expected if line not in stdout]
    payload = {
        "status": "ok" if outcome["ok"] and not missing else "failed",
        "trail": trail_id, "image": summary.get("image"),
        "image_digest": summary.get("image_digest"),
        "container_id": summary.get("container_id"),
        "exit": summary.get("exit"), "termination": summary.get("termination"),
        "evidence": summary.get("evidence"),
        "missing_expected_lines": missing,
        "expected_lines": expected,
        "stdout_tail": stdout[-400:],
        "artifacts": summary.get("artifacts"),
        "seconds": round(time.time() - started, 1)}
    record("B_container_exec", payload)
    return payload


def check_c(assembly) -> None:
    cases = []
    binary = ROOT / "toolchains" / "binary_tools" / "cuda-12.4" / "bin" / "cuobjdump.exe"
    checks = [
        ("missing_binary", {"argv": ["this-binary-does-not-exist-xyz"], "timeout_s": 60},
         "not_found", {}),
        ("ordinary_nonzero", {"argv": ["bash", "-lc", "echo out; echo err >&2; exit 3"],
                              "timeout_s": 60}, "error_exit", {}),
        ("timeout", {"argv": ["bash", "-lc", "echo started; sleep 60"], "timeout_s": 3},
         "timeout", {}),
        ("bad_gpu_spec", {"argv": ["nvidia-smi", "-L"], "gpus": "device=99",
                          "timeout_s": 60}, "container_error", {}),
    ]
    for name, params, expected_kind, extra in checks:
        outcome = assembly.registry.call("container_exec", dict(params, image=IMAGE, **extra))
        summary = outcome.get("summary") or {}
        kind = summary.get("termination")
        cases.append({"case": name, "expected_kind": expected_kind, "kind": kind,
                      "crash": summary.get("crash"), "exit": summary.get("exit"),
                      "timed_out": summary.get("timed_out"),
                      "ok": bool(kind == expected_kind and summary.get("crash") is not True)})

    # Compile failure: a source that cannot build.
    trail = assembly.registry.call("trail_new", {"purpose": "P19 compile failure"})
    trail_id = trail["summary"]["trail"]
    assembly.registry.call("trail_write", {"trail": trail_id, "name": "bad.cu",
                                           "content": "__global__ void k( { not cuda }\n"})
    outcome = assembly.registry.call("container_exec", {
        "trail": trail_id, "image": IMAGE, "timeout_s": 300,
        "argv": ["bash", "-lc", "nvcc -O2 bad.cu -o bad"]})
    summary = outcome.get("summary") or {}
    cases.append({"case": "compile_failure", "expected_kind": "error_exit",
                  "kind": summary.get("termination"), "crash": summary.get("crash"),
                  "exit": summary.get("exit"),
                  "ok": summary.get("termination") == "error_exit"
                        and summary.get("crash") is not True,
                  "stderr_head": (summary.get("stderr") or "")[:200]})

    leftovers = assembly.backend.cleanup("P19-ACCEPTANCE") \
        if hasattr(assembly, "backend") else {}
    record("C_failure_feedback", {
        "status": "ok" if all(item["ok"] for item in cases) else "failed",
        "cases": cases, "leftover_containers": leftovers})


def check_d(settings, turns: int) -> None:
    run_dir = ROOT / ".local" / "runs" / ("p19-autonomy-" + new_run_id())
    goal = (
        "请检查当前 GPU 环境，并使用现有工具完成一次 CUDA 向量加法实验。"
        "验证计算结果，保存完整实验产物，并给出结论。\n"
        "要求：结论必须引用真实 evidence id；区分「工具输出显示」与「推测」；"
        "把实验记录写入 case 记忆（scope=case）。工作区 samples/ 里有一个参考程序，"
        "你可以读、改或完全自己写。"
    )
    provider = DeepSeekProvider(api_key=settings.llm.api_key, model=settings.llm.model,
                                base_url=settings.llm.base_url, timeout=settings.llm.timeout,
                                max_attempts=settings.llm.max_attempts,
                                temperature=settings.llm.temperature,
                                max_tokens=settings.llm.max_tokens)
    runtime = AgentRuntime(goal=goal, root=run_dir, provider=provider, max_turns=turns,
                           run_timeout=1200, shell_timeout=120, case_id="P19-AUTONOMY",
                           research_root=ROOT / "research_archive",
                           toolchain_root=ROOT / "toolchains",
                           enable_search=bool(settings.tavily_api_key))
    # The sample is staged, not prescribed: the agent may read it, rewrite it, or ignore it.
    # It is written after the runtime owns the directory, because the runtime refuses to
    # adopt a directory that already has content.
    runtime.workspace.write("samples/vector_add.cu", VECTOR_ADD.read_text(encoding="utf-8"))
    started = time.time()
    result = runtime.run()
    check = verify_chain(run_dir / "evidence.jsonl")
    execs = 0
    trails = set()
    for line in (run_dir / "evidence.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if rec.get("kind") == "exec":
            execs += 1
        if rec.get("trail"):
            trails.add(rec["trail"])
    record("D_autonomous_run", {
        # A run that spent its decision budget and then answered in the closing turn is a
        # successful autonomous run: it concluded, it just did not stop by itself.
        "status": "ok" if execs and check["ok"] and len(result.final or "") > 200
                  and result.stopped in ("final", "max_turns") else "failed",
        "run_id": result.run_id, "run_dir": str(run_dir), "stopped": result.stopped,
        "decisions": result.decisions, "executions": len(result.turns),
        "container_execs": execs, "trails": sorted(trails),
        "tools_used": sorted({turn.tool for turn in result.turns}),
        "evidence_records": check["records"], "evidence_ok": check["ok"],
        "usage": result.usage.to_dict(), "seconds": round(time.time() - started, 1),
        "final_head": result.final[:700]})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--turns", type=int, default=12)
    parser.add_argument("--skip-agent", action="store_true")
    parser.add_argument("--only", default="all", choices=("all", "a", "b", "c", "d"),
                        help="Run one check only; useful when re-testing the agent.")
    args = parser.parse_args()

    settings = ConfigLoader()
    if not settings.llm.api_key:
        print("error: DEEPSEEK_API_KEY is not set; check D cannot run", file=sys.stderr)
        return 3

    run_id = new_run_id()
    run_dir = ROOT / ".local" / "runs" / ("p19-acceptance-" + run_id)
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)
    assembly = make_assembly(run_dir, run_id)
    record("backend", {"status": "ok", "run_id": run_id, "run_dir": str(run_dir),
                       "config": assembly.backend.describe()})

    only = args.only
    if only in ("all", "a"):
        check_a(assembly)
    if only in ("all", "b"):
        check_b(assembly)
    if only in ("all", "c"):
        check_c(assembly)
    if only == "d" or (only == "all" and not args.skip_agent):
        check_d(settings, args.turns)

    out = ROOT / ".local" / "logs" / "p19_acceptance.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(RESULTS, ensure_ascii=False, indent=1), encoding="utf-8")
    print("\nwritten: %s" % out)
    failures = [name for name, item in RESULTS.items() if item.get("status") == "failed"]
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
