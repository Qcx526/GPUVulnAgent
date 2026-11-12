# -*- coding: utf-8 -*-
"""Command line entry point.

    gpuvulnagent run     --goal "..." | --goal-file FILE  [--root DIR] [--resume]
    gpuvulnagent tools   [--search TEXT] [--describe NAME] [--formats .cubin]
    gpuvulnagent doctor  [--verify-toolchain]
    gpuvulnagent memory  --search TEXT [--case ID]
    gpuvulnagent bench   --cases CVE-... [--mode blind|seed]
    gpuvulnagent verify  --run DIR

The CLI never fabricates a result: if a credential is missing it says which one and stops.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .benchmarks.runner import BenchmarkRunner, rebuild_summary
from .benchmarks.summary import SummaryIndex
from .config import ConfigLoader
from .discovery.manifest import ToolchainManifest
from .evidence.artifacts import ArtifactStore
from .evidence.log import EvidenceLog, EvidenceResolver, verify_chain
from .memory.store import LayeredMemory
from .providers.deepseek import DeepSeekProvider
from .runtime.loop import AgentRuntime
from .runtime.workspace import Workspace
from .backends.wsl_docker import WslConfig
from .tools.build import build_assembly


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="gpuvulnagent", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--project-root", default="")
    subparsers = parser.add_subparsers(dest="command")

    run_p = subparsers.add_parser("run", help="run the agent on one goal")
    run_p.add_argument("--goal", default="")
    run_p.add_argument("--goal-file", default="")
    run_p.add_argument("--root", default="")
    run_p.add_argument("--case", default="")
    run_p.add_argument("--turns", type=int, default=0)
    run_p.add_argument("--timeout", type=int, default=0)
    run_p.add_argument("--resume", action="store_true")
    run_p.add_argument("--no-search", action="store_true")
    run_p.add_argument("--no-adapters", action="store_true")
    run_p.add_argument("--max-tokens", type=int, default=0,
                       help="Hard token budget for this run (0 = no limit).")
    run_p.add_argument("--research-root", default="",
                       help="Isolate cross-run memory (blind runs use a fresh directory).")
    run_p.add_argument("--sessions-dir", default="",
                       help="Put this run in the next runs/trialN under this directory.")
    run_p.add_argument("--no-gpu-backend", action="store_true",
                       help="do not register the WSL/Docker GPU tools for this run")

    tools_p = subparsers.add_parser("tools", help="inspect the capability catalog")
    tools_p.add_argument("--search", default="")
    tools_p.add_argument("--describe", default="")
    tools_p.add_argument("--formats", default="")
    tools_p.add_argument("--available", action="store_true")

    doctor_p = subparsers.add_parser("doctor", help="environment, providers, toolchain")
    doctor_p.add_argument("--verify-toolchain", action="store_true")

    memory_p = subparsers.add_parser("memory", help="search research memory")
    memory_p.add_argument("--search", default="")
    memory_p.add_argument("--case", default="")
    memory_p.add_argument("--limit", type=int, default=10)

    bench_p = subparsers.add_parser("bench", help="run benchmark cases")
    bench_p.add_argument("--cases", nargs="*", default=[])
    bench_p.add_argument("--mode", choices=("blind", "seed"), default="blind")
    bench_p.add_argument("--turns", type=int, default=8)
    bench_p.add_argument("--wall-clock", type=int, default=1800)
    bench_p.add_argument("--seed", default="")
    bench_p.add_argument("--goal-file", default="")
    bench_p.add_argument("--tag", default="")
    bench_p.add_argument("--cases-root", default="data/benchmarks/runs")
    bench_p.add_argument("--summary-root", default="data/benchmarks/summary")
    bench_p.add_argument("--rebuild", action="store_true")

    verify_p = subparsers.add_parser("verify", help="verify one run's evidence chain")
    verify_p.add_argument("--run", required=True)

    args = parser.parse_args(argv)
    settings = ConfigLoader(project_root=Path(args.project_root) if args.project_root else None)
    if not args.command:
        parser.print_help()
        return 2
    return {
        "run": _cmd_run, "tools": _cmd_tools, "doctor": _cmd_doctor, "memory": _cmd_memory,
        "bench": _cmd_bench, "verify": _cmd_verify,
    }[args.command](args, settings)


# ---------------------------------------------------------------- run
def _cmd_run(args, settings) -> int:
    goal = (Path(args.goal_file).read_text(encoding="utf-8") if args.goal_file
            else args.goal)
    if not goal.strip():
        print("error: --goal or --goal-file is required", file=sys.stderr)
        return 2
    if not settings.llm.api_key:
        missing = settings.missing_credentials()
        print("error: %s is not set; copy .env.example to .env and fill it in.\n"
              "       (%s)" % ("DEEPSEEK_API_KEY", missing.get("DEEPSEEK_API_KEY", "")),
              file=sys.stderr)
        return 3
    trial_root = None
    if args.sessions_dir:
        from .artifacts.trial import TrialSession
        trial = TrialSession.allocate(Path(args.sessions_dir), goal=goal,
                                      case_id=args.case)
        trial_root = trial.root
        root = trial.root / "session" / "run"
    else:
        root = Path(args.root) if args.root else settings.paths.runs_root / "cli"
    provider = DeepSeekProvider(api_key=settings.llm.api_key, model=settings.llm.model,
                                base_url=settings.llm.base_url, timeout=settings.llm.timeout,
                                max_attempts=settings.llm.max_attempts,
                                temperature=settings.llm.temperature,
                                max_tokens=settings.llm.max_tokens)
    runtime = AgentRuntime(goal=goal, root=root, provider=provider,
                           max_turns=args.turns or settings.agent.max_turns,
                           max_tokens=args.max_tokens,
                           run_timeout=args.timeout or settings.agent.run_timeout,
                           shell_timeout=settings.agent.shell_timeout,
                           case_id=args.case,
                           research_root=(Path(args.research_root) if args.research_root
                                          else settings.paths.research_data_root),
                           toolchain_root=settings.paths.toolchain_root,
                           tavily_api_key=settings.tavily_api_key,
                           enable_search=not args.no_search,
                           include_adapters=not args.no_adapters,
                           enable_gpu_backend=(settings.backend.enabled
                                               and not args.no_gpu_backend),
                           backend_config=WslConfig.from_settings(settings),
                           trial_root=trial_root, resume=args.resume)
    for provider_state in runtime.assembly.providers:
        print("[provider] %s available=%s (%s)"
              % (provider_state["provider"], provider_state["available"],
                 provider_state["reason"]))
    print("[catalog] %s" % json.dumps(runtime.catalog.summary(), ensure_ascii=False))
    result = runtime.run()
    print(json.dumps({"run_id": result.run_id, "stopped": result.stopped,
                      "decisions": result.decisions, "executions": len(result.turns),
                      "evidence_ok": result.evidence_ok,
                      "usage": result.usage.to_dict(),
                      "final": result.final[:3000]}, ensure_ascii=False, indent=1))
    return 0 if result.evidence_ok else 4


# -------------------------------------------------------------- tools
def _cmd_tools(args, settings) -> int:
    assembly = _inspect_assembly(settings)
    if args.describe:
        print(json.dumps(assembly.catalog.describe(args.describe), ensure_ascii=False,
                         indent=1))
        return 0
    hits = assembly.catalog.search(args.search, formats=args.formats,
                                   available_only=args.available, limit=40)
    for item in hits:
        print("%-22s %-8s %-5s %s" % (item["name"], item["kind"],
                                      "ok" if item["available"] else "no",
                                      (item["purpose"] or "")[:80]))
        if not item["available"]:
            print("%-22s %-8s %-5s   reason: %s" % ("", "", "", item["reason"][:100]))
    print("\n%s" % json.dumps(assembly.catalog.summary(), ensure_ascii=False))
    return 0


# ------------------------------------------------------------- doctor
def _cmd_doctor(args, settings) -> int:
    report = {"project_root": str(settings.project_root),
              "settings": settings.public_dict(),
              "missing_credentials": settings.missing_credentials(),
              "python": sys.version.split()[0]}
    manifest = ToolchainManifest(settings.paths.toolchain_root)
    report["toolchain"] = {"manifest": str(manifest.path), "load_error": manifest.load_error,
                           "tools": manifest.names()}
    if args.verify_toolchain:
        report["toolchain"]["verification"] = manifest.verify()
    assembly = _inspect_assembly(settings, manifest=manifest)
    report["catalog"] = assembly.catalog.summary()
    report["providers"] = assembly.providers
    report["adapters"] = assembly.adapter_errors
    print(json.dumps(report, ensure_ascii=False, indent=1))
    ok = not manifest.load_error and settings.llm.api_key
    return 0 if ok else 1


# ------------------------------------------------------------- memory
def _cmd_memory(args, settings) -> int:
    root = settings.paths.research_data_root
    resolver = EvidenceResolver([root])
    memory = LayeredMemory(run_dir=settings.paths.runs_root / "cli-memory",
                           research_root=root, run_id="cli", case_id=args.case,
                           resolver=resolver)
    for entry in memory.search(args.search, limit=args.limit, case_id=args.case):
        print("[%s/%s] %s  %s" % (entry.type, entry.scope, entry.id, entry.content[:220]))
        if entry.evidence:
            print("    evidence: %s" % ", ".join(entry.evidence))
    return 0


# -------------------------------------------------------------- bench
def _cmd_bench(args, settings) -> int:
    cases_root = Path(args.cases_root)
    summary_root = Path(args.summary_root)
    if args.rebuild:
        index = rebuild_summary(cases_root, summary_root)
        print(json.dumps(index, ensure_ascii=False, indent=1))
        return 0
    if not args.cases:
        print("error: --cases is required (or use --rebuild)", file=sys.stderr)
        return 2
    if not settings.llm.api_key:
        print("error: DEEPSEEK_API_KEY is not set; a benchmark cannot be faked.",
              file=sys.stderr)
        return 3
    manifest = ToolchainManifest(settings.paths.toolchain_root)
    runner = BenchmarkRunner(
        cases_root=cases_root, summary_root=summary_root,
        provider_factory=lambda: DeepSeekProvider(
            api_key=settings.llm.api_key, model=settings.llm.model,
            base_url=settings.llm.base_url, timeout=settings.llm.timeout,
            max_attempts=settings.llm.max_attempts, temperature=settings.llm.temperature,
            max_tokens=settings.llm.max_tokens),
        research_root=settings.paths.research_data_root,
        toolchain_root=settings.paths.toolchain_root, manifest=manifest,
        max_turns=args.turns, wall_clock=args.wall_clock,
        enable_gpu_backend=settings.backend.enabled,
        backend_config=WslConfig.from_settings(settings))
    for case in args.cases:
        record = runner.run_case(case_id=case, mode=args.mode, turns=args.turns,
                                 wall_clock=args.wall_clock, seed=args.seed,
                                 goal_file=args.goal_file, tag=args.tag)
        metrics = record["metrics"]
        print("%-18s %-5s run=%s tools=%d proc=%d target=%d crash=%d %.0fs"
              % (case, args.mode, record["run_id"], metrics["tool_calls"],
                 metrics["process_invocations"], metrics["target_tool_invocations"],
                 metrics["target_tool_crashes"], record["wall_clock_s"]))
    print()
    print(SummaryIndex(summary_root).table())
    return 0


# ------------------------------------------------------------- verify
def _cmd_verify(args, settings) -> int:
    run_dir = Path(args.run)
    check = verify_chain(run_dir / "evidence.jsonl")
    print(json.dumps(check, ensure_ascii=False, indent=1))
    return 0 if check["ok"] else 5


# ------------------------------------------------------------ helpers
def _inspect_assembly(settings, manifest=None):
    """A registry/catalog built outside a run, for listing and diagnosing."""
    tmp = settings.project_root / ".local" / "tmp" / "inspect"
    artifacts = ArtifactStore(tmp / "artifacts")
    log = EvidenceLog(tmp / "evidence.jsonl", "inspect", artifacts)
    workspace = Workspace(tmp / "workspace")
    from .evidence.runner import Runner
    runner = Runner(workspace.root, log, timeout=settings.agent.shell_timeout)
    memory = LayeredMemory(run_dir=tmp, research_root=settings.paths.research_data_root,
                           run_id="inspect", resolver=EvidenceResolver([tmp]))
    return build_assembly(workspace=workspace, runner=runner, log=log, memory=memory,
                          toolchain_root=settings.paths.toolchain_root,
                          tavily_api_key=settings.tavily_api_key,
                          enable_gpu_backend=settings.backend.enabled,
                          backend_config=WslConfig.from_settings(settings))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
