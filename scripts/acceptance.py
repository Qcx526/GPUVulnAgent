# -*- coding: utf-8 -*-
"""Acceptance: real endpoints, real processes, no mocks.

Every check prints what actually happened and writes a machine-readable record to
``.local/logs/acceptance.json``. A failure is reported as a failure - nothing here falls
back to a stub, and no credential is printed or written.

    python scripts/acceptance.py [--turns 6] [--skip-search]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gpuvulnagent.config import ConfigLoader  # noqa: E402
from gpuvulnagent.evidence import verify_chain  # noqa: E402
from gpuvulnagent.memory.store import LayeredMemory  # noqa: E402
from gpuvulnagent.providers.deepseek import DeepSeekProvider  # noqa: E402
from gpuvulnagent.providers import tavily as tavily_provider  # noqa: E402
from gpuvulnagent.runtime.loop import AgentRuntime  # noqa: E402
from gpuvulnagent.runtime.state import new_run_id  # noqa: E402
from gpuvulnagent.tools.build import build_assembly  # noqa: E402
from gpuvulnagent.evidence.artifacts import ArtifactStore  # noqa: E402
from gpuvulnagent.evidence.log import EvidenceLog, EvidenceResolver  # noqa: E402
from gpuvulnagent.evidence.runner import Runner  # noqa: E402
from gpuvulnagent.runtime.workspace import Workspace  # noqa: E402

RESULTS: dict = {}


def record(name: str, payload: dict) -> None:
    RESULTS[name] = payload
    status = payload.get("status", "unknown")
    print("[%-28s] %s %s" % (name, status.upper(),
                             json.dumps({k: v for k, v in payload.items() if k != "status"},
                                        ensure_ascii=False)[:300]))


def build_provider(settings) -> DeepSeekProvider:
    return DeepSeekProvider(api_key=settings.llm.api_key, model=settings.llm.model,
                            base_url=settings.llm.base_url, timeout=settings.llm.timeout,
                            max_attempts=settings.llm.max_attempts,
                            temperature=settings.llm.temperature,
                            max_tokens=settings.llm.max_tokens)


def check_provider_smoke(settings) -> None:
    provider = build_provider(settings)
    started = time.time()
    try:
        response = provider.chat([{"role": "user", "content": "只回答两个字：收到"}],
                                 temperature=0.0)
    except Exception as exc:  # noqa: BLE001
        record("provider_smoke", {"status": "failed",
                                  "error": "%s: %s" % (type(exc).__name__, exc)})
        return
    record("provider_smoke", {"status": "ok", "model": response.model,
                              "content_head": response.content[:60],
                              "usage": response.usage.to_dict(),
                              "latency_ms": int((time.time() - started) * 1000)})


def check_native_tools(settings) -> None:
    provider = build_provider(settings)
    tools = [{"type": "function", "function": {
        "name": "env_probe", "description": "Report OS, python and GPU facts.",
        "parameters": {"type": "object", "properties": {}, "required": []}}},
        {"type": "function", "function": {
            "name": "fs_list", "description": "List a directory in the workspace.",
            "parameters": {"type": "object",
                           "properties": {"path": {"type": "string"}},
                           "required": ["path"]}}}]
    try:
        response = provider.chat(
            [{"role": "system", "content": "你需要调用工具，不要直接回答。"},
             {"role": "user", "content": "先探测一下运行环境，用 env_probe。"}],
            tools=tools, temperature=0.0)
    except Exception as exc:  # noqa: BLE001
        record("native_tool_calling", {"status": "failed",
                                       "error": "%s: %s" % (type(exc).__name__, exc)})
        return
    record("native_tool_calling", {
        "status": "ok" if response.tool_calls else "failed",
        "mode": response.mode,
        "tool_calls": [call.to_dict() for call in response.tool_calls],
        "finish_reason": response.finish_reason,
        "usage": response.usage.to_dict(),
        "note": "" if response.tool_calls else "endpoint returned no tool_calls"})


def check_tavily(settings, skip: bool) -> None:
    if skip:
        record("tavily", {"status": "skipped"})
        return
    state = tavily_provider.status(settings.tavily_api_key)
    if not state["available"]:
        record("tavily", {"status": "unavailable", "reason": state["reason"]})
        return
    tmp = ROOT / ".local" / "logs" / "tavily"
    log = EvidenceLog(tmp / "evidence.jsonl", new_run_id(),
                      ArtifactStore(tmp / "artifacts"))
    specs = {spec.name: spec for spec in
             tavily_provider.build_specs(api_key=settings.tavily_api_key, log=log)}
    search = specs["web_search"].handler(query="NVIDIA nvJPEG CVE-2024-0124 advisory",
                                         max_results=3)
    if not search.get("ok"):
        record("tavily", {"status": "failed", "search": search.get("summary")})
        return
    items = search["summary"]["items"]
    extract = specs["web_extract"].handler(url=items[0]["url"]) if items else {}
    record("tavily", {"status": "ok", "results": search["summary"]["results"],
                      "first_url": items[0]["url"] if items else "",
                      "extract_chars": extract.get("summary", {}).get("chars", 0),
                      "extract_status": extract.get("status")})


def check_agent_smoke(settings, turns: int, skip_search: bool) -> dict:
    goal = (
        "# 研究目标\n\n"
        "用不超过 6 次工具调用，探测这台机器上真实的 GPU 研究条件，然后收敛到结论：\n"
        "- 本机有什么 GPU、驱动版本是多少；\n"
        "- 工作区里能用的工具链（cuobjdump / nvdisasm）是什么版本、能否运行；\n"
        "- 是否存在可用于验证的 JPEG 样本或 cubin 样本；没有就如实说没有。\n\n"
        "要求：每个结论都对应一次真实工具调用；把关键观测写入 case 记忆（scope=case），"
        "finding 必须引用真实 evidence id。第 4 轮之后请停止探索并给出结论。"
        "最后用中文给出结论，区分「工具输出显示」与「推测」。"
    )
    root = ROOT / ".local" / "runs" / ("acceptance-" + new_run_id())
    runtime = AgentRuntime(goal=goal, root=root, provider=build_provider(settings),
                           max_turns=turns, run_timeout=600, case_id="ACCEPTANCE-SMOKE",
                           research_root=settings.paths.research_data_root,
                           toolchain_root=settings.paths.toolchain_root,
                           tavily_api_key=settings.tavily_api_key,
                           enable_search=not skip_search)
    result = runtime.run()
    check = verify_chain(root / "evidence.jsonl")
    records = [json.loads(line) for line in
               (root / "evidence.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    artifact_count = sum(1 for path in (root / "artifacts").rglob("*") if path.is_file())
    payload = {
        "status": "ok" if check["ok"] and result.turns else "failed",
        "run_id": result.run_id,
        "run_dir": str(root),
        "stopped": result.stopped,
        "decisions": result.decisions,
        "executions": len(result.turns),
        "tools_used": sorted({turn.tool for turn in result.turns}),
        "tool_call_ids": [turn.tool_call_id for turn in result.turns],
        "via": sorted({turn.via for turn in result.turns}),
        "evidence_records": check["records"],
        "evidence_ok": check["ok"],
        "artifacts": artifact_count,
        "usage": result.usage.to_dict(),
        "provider_modes": sorted({r.get("mode") for r in records if r.get("kind") == "assistant"}),
        "final_head": result.final[:400],
    }
    record("agent_smoke_run", payload)
    return {"root": root, "run_id": result.run_id, "payload": payload}


def check_memory_across_runs(settings, smoke: dict) -> None:
    """Promote a real finding into case memory and read it from a different run."""
    root = Path(smoke["root"])
    resolver = EvidenceResolver([root])
    first = LayeredMemory(run_dir=root, research_root=settings.paths.research_data_root,
                          run_id=smoke["run_id"], case_id="ACCEPTANCE-SMOKE",
                          resolver=resolver)
    evidence_id = None
    for line in (root / "evidence.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record_ = json.loads(line)
        if record_.get("kind") == "exec":
            evidence_id = record_.get("evidence_id")
            break
    if evidence_id is None:
        record("memory_across_runs", {"status": "skipped",
                                      "reason": "the smoke run produced no exec record"})
        return
    entry = first.add("finding", "工具链二进制可以在这台机器上真实执行（见所引证据）",
                      evidence=[evidence_id], scope="case", source="operator")
    second_root = ROOT / ".local" / "runs" / ("memory-reader-" + new_run_id())
    reader = LayeredMemory(run_dir=second_root, research_root=settings.paths.research_data_root,
                           run_id="memory-reader", case_id="ACCEPTANCE-SMOKE",
                           resolver=resolver)
    found = [e for e in reader.entries(scopes=("case",)) if e.id == entry.id]
    record("memory_across_runs", {"status": "ok" if found else "failed",
                                  "memory_id": entry.id, "evidence": entry.evidence,
                                  "visible_from_new_run": bool(found),
                                  "case_file": str(first.case_store.path)})


def check_benchmark_no_overwrite(settings) -> None:
    from gpuvulnagent.benchmarks import BenchmarkRunner, rebuild_summary
    cases = ROOT / ".local" / "tmp" / "acceptance-bench" / "cases"
    summary = ROOT / ".local" / "tmp" / "acceptance-bench" / "summary"
    runner = BenchmarkRunner(cases_root=cases, summary_root=summary,
                             provider_factory=lambda: ScriptedDone(),
                             research_root=settings.paths.research_data_root,
                             toolchain_root=settings.paths.toolchain_root,
                             manifest=None, max_turns=2, wall_clock=60,
                             enable_search=False)
    first = runner.run_case(case_id="ACCEPTANCE-BENCH", mode="blind")
    second = runner.run_case(case_id="ACCEPTANCE-BENCH", mode="blind")
    rebuilt = rebuild_summary(cases, summary)
    run_ids = {item["run_id"] for item in rebuilt["runs"]}
    kept = first["run_id"] in run_ids and second["run_id"] in run_ids
    record("benchmark_no_overwrite", {
        "status": "ok" if first["run_id"] != second["run_id"] and kept else "failed",
        "run_ids": [first["run_id"], second["run_id"]],
        "index_runs": len(rebuilt["runs"]),
        "cases_kept": [first["run_dir"], second["run_dir"]]})


class ScriptedDone:
    """A local provider for the benchmark plumbing check: no API budget, no claims."""

    name = "local-scripted"
    model = "local-scripted"
    timeout = 30

    def __init__(self) -> None:
        from gpuvulnagent.providers.base import ProviderResponse, Usage
        self._response = ProviderResponse(content="（本地脚本化回复，仅用于校验基准流程）",
                                          usage=Usage(1, 1, 2), mode="prose")
        self.calls = 0

    def chat(self, messages, **kwargs):
        self.calls += 1
        return self._response


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--turns", type=int, default=6)
    parser.add_argument("--skip-search", action="store_true")
    parser.add_argument("--skip-agent", action="store_true")
    args = parser.parse_args()

    settings = ConfigLoader()
    print("project root: %s" % settings.project_root)
    print("credentials present: %s" % json.dumps(
        {k: bool(v) for k, v in {"deepseek": settings.llm.api_key,
                                 "tavily": settings.tavily_api_key}.items()}))
    missing = settings.missing_credentials()
    if missing:
        record("credentials", {"status": "incomplete", "missing": list(missing)})
        return 3
    record("credentials", {"status": "ok", "model": settings.llm.model,
                           "base_url": settings.llm.base_url})

    check_provider_smoke(settings)
    check_native_tools(settings)
    check_tavily(settings, args.skip_search)
    smoke = {} if args.skip_agent else check_agent_smoke(settings, args.turns,
                                                         args.skip_search)
    if smoke:
        check_memory_across_runs(settings, smoke)
    check_benchmark_no_overwrite(settings)

    out = ROOT / ".local" / "logs" / "acceptance.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(RESULTS, ensure_ascii=False, indent=1), encoding="utf-8")
    print("\nwritten: %s" % out)
    failures = [name for name, payload in RESULTS.items() if payload.get("status") == "failed"]
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
