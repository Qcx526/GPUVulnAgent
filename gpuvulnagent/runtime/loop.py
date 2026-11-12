# -*- coding: utf-8 -*-
"""Single-agent runtime: the model decides, the runtime records, and a run can resume.

There is no stage list. Each decision the model may call one or more tools; the runtime
validates the call, executes it, records the evidence and feeds the result back into the
conversation. Native ``tool_calls`` are the primary channel; a JSON action in the text is
accepted as a fallback and the channel used is recorded on every turn.

Two budgets are real, not advisory: the decision budget and the wall-clock budget. Both
are enforced here, and the wall clock is also handed to the process runner so a single
command cannot outlive the run.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from ..context.observation import compact, render
from ..context.prompts import SYSTEM, budget_note, initial_message, resume_section
from ..evidence.artifacts import ArtifactStore
from ..evidence.log import EvidenceLog, EvidenceResolver
from ..evidence.runner import Runner
from ..memory.store import LayeredMemory
from ..providers.base import Provider, ProviderError, Usage, tool_message
from ..tools.build import Assembly, build_assembly
from .protocol import looks_like_action, parse_action
from .state import RunPaths, RunState
from .workspace import Workspace


@dataclass
class Turn:
    step: int
    index: int
    thought: str
    tool: str
    args: dict
    observation: dict
    status: str = "success"
    tool_call_id: str = ""
    via: str = "native"
    mode: str = "native"
    evidence_id: str = ""
    at: str = ""

    def to_dict(self) -> dict:
        return {"step": self.step, "index": self.index, "thought": self.thought,
                "tool": self.tool, "args": self.args, "status": self.status,
                "tool_call_id": self.tool_call_id, "via": self.via, "mode": self.mode,
                "evidence_id": self.evidence_id, "at": self.at,
                "observation": compact(self.observation)}


@dataclass
class RunResult:
    run_id: str
    goal: str
    final: str
    turns: List[Turn] = field(default_factory=list)
    stopped: str = "final"
    decisions: int = 0
    usage: Usage = field(default_factory=Usage)
    workspace: str = ""
    resume_state: str = "NEW"
    case_id: str = ""
    evidence_ok: bool = False

    def to_dict(self) -> dict:
        return {"run_id": self.run_id, "case_id": self.case_id, "goal": self.goal,
                "final": self.final, "stopped": self.stopped,
                "decisions": self.decisions, "executions": len(self.turns),
                "usage": self.usage.to_dict(), "resume_state": self.resume_state,
                "workspace": self.workspace, "evidence_ok": self.evidence_ok,
                "turns": [t.to_dict() for t in self.turns]}


class AgentRuntime:
    def __init__(self, *, goal: str, root: Path, provider: Provider,
                 max_turns: int = 12, run_timeout: int = 900, shell_timeout: int = 300,
                 case_id: str = "", research_root: Optional[Path] = None,
                 toolchain_root: Optional[Path] = None,
                 manifest_path: Optional[Path] = None, tavily_api_key: str = "",
                 enable_search: bool = True, include_adapters: bool = True,
                 enable_gpu_backend: bool = True, backend_config=None,
                 resume: bool = False, assembly: Optional[Assembly] = None,
                 deadline: Optional[float] = None) -> None:
        if not goal or not goal.strip():
            raise ValueError("a run needs a goal")
        self.goal = goal.strip()
        self.provider = provider
        self.max_turns = max_turns
        self.case_id = case_id
        self.paths = RunPaths.under(Path(root))
        self.state = RunState(self.paths)
        self.resume = resume
        if resume:
            self.state.resume(goal=self.goal)
        else:
            self.state.create(goal=self.goal, case_id=case_id)

        self.run_id = self.state.run_id
        self.workspace = Workspace(self.paths.workspace)
        self.artifacts = ArtifactStore(self.paths.artifacts)
        self.log = EvidenceLog(self.paths.evidence, self.run_id, self.artifacts)

        # The budget starts when the runtime starts; a caller may pass an earlier deadline
        # so a benchmark can bound the whole case, not just one run.
        self.deadline = deadline if deadline is not None else time.monotonic() + run_timeout
        self.run_timeout = run_timeout
        self.runner = Runner(self.workspace.root, self.log, timeout=shell_timeout,
                             deadline=self.deadline)

        self.resolver = EvidenceResolver([self.paths.root])
        self.memory = LayeredMemory(run_dir=self.paths.root,
                                    research_root=Path(research_root or
                                                       self.paths.root.parent),
                                    run_id=self.run_id, case_id=case_id,
                                    resolver=self.resolver)

        self.assembly = assembly or build_assembly(
            workspace=self.workspace, runner=self.runner, log=self.log, memory=self.memory,
            toolchain_root=toolchain_root, manifest_path=manifest_path,
            tavily_api_key=tavily_api_key, enable_search=enable_search,
            include_adapters=include_adapters, enable_gpu_backend=enable_gpu_backend,
            backend_config=backend_config)
        self.registry = self.assembly.registry
        self.catalog = self.assembly.catalog
        self.backend = getattr(self.assembly, "backend", None)

        self.turns: List[Turn] = self._load_turns() if resume else []
        self.decisions = int(self.state.data.get("decisions", 0)) if resume else 0
        self.usage = Usage()
        self._log_start()

    # -- evidence --------------------------------------------------------
    def _log_start(self) -> None:
        self.log.append("start", {
            "goal_sha256": self.state.data.get("goal_sha256"),
            "case_id": self.case_id,
            "tools": self.registry.names(),
            "conflicts": self.assembly.conflicts,
            "providers": self.assembly.providers,
            "adapter_errors": self.assembly.adapter_errors,
            "mode": "resume" if self.resume else "new",
            "resume_state": self.state.data.get("resume_state", "NEW"),
            "catalog": self.catalog.summary(),
        })

    # -- prompt ----------------------------------------------------------
    def _menu(self) -> List[str]:
        return [self.registry.summary_line(spec) for spec in self.registry.all()]

    def _seed_messages(self) -> List[dict]:
        digest = self.memory.digest(self.goal, limit=8)
        body = initial_message(goal=self.goal, workspace=str(self.workspace.root),
                               digest=digest, menu=self._menu(),
                               remaining=self.max_turns - self.decisions,
                               case_id=self.case_id,
                               evidence_path=str(self.paths.evidence))
        messages = [{"role": "system", "content": SYSTEM},
                    {"role": "user", "content": body}]
        if self.resume and self.turns:
            messages.append({"role": "user",
                             "content": resume_section([t.to_dict() for t in self.turns])})
        return messages

    # -- loop ------------------------------------------------------------
    def run(self) -> RunResult:
        messages = self._seed_messages()
        final_text, stopped = "", "max_turns"

        while self.decisions < self.max_turns:
            remaining_s = self.deadline - time.monotonic()
            if remaining_s <= 0:
                stopped = "wall_clock"
                final_text = final_text or self._timeout_text()
                break
            # As the budget runs out, say so once per remaining step: a model that keeps
            # exploring until it is cut off produces no conclusion, and an exploration
            # without a conclusion wastes the whole run.
            remaining_turns = self.max_turns - self.decisions
            if remaining_turns <= 2 and getattr(self, "_last_budget_note", None) != remaining_turns:
                messages.append({"role": "user", "content": budget_note(remaining_turns)})
                self._last_budget_note = remaining_turns
            self.decisions += 1
            try:
                response = self.provider.chat(
                    messages, tools=self.registry.openai_tools(),
                    timeout=int(max(5, min(remaining_s, getattr(self.provider, "timeout", 300)))))
            except ProviderError as exc:
                self.log.append("provider_error", {"error": str(exc),
                                                   "status": getattr(exc, "status", None)},
                                status="failed")
                stopped = "provider_error"
                final_text = "LLM 调用失败，run 在决策 %d 中止：%s" % (self.decisions, exc)
                break
            except Exception as exc:  # noqa: BLE001 - a provider fault must be recorded
                self.log.append("provider_error", {"error": "%s: %s"
                                                   % (type(exc).__name__, exc)},
                                status="failed")
                stopped = "provider_error"
                final_text = "LLM 调用异常，run 中止：%s: %s" % (type(exc).__name__, exc)
                break

            self.usage = self.usage.add(response.usage)
            self.log.append("assistant", {
                "decision": self.decisions,
                "mode": response.mode,
                "content_preview": (response.content or "")[:800],
                "tool_call_ids": [call.id for call in response.tool_calls],
                "tool_names": [call.name for call in response.tool_calls],
                "finish_reason": response.finish_reason,
                "usage": response.usage.to_dict(),
                "latency_ms": response.latency_ms,
                "model": response.model or getattr(self.provider, "model", ""),
            })

            if response.tool_calls:
                messages.append(response.assistant_message())
                for call in response.tool_calls:
                    if call.parse_error:
                        outcome = {"dispatched": False, "ok": False, "status": "dispatch_error",
                                   "result": None, "summary": None, "artifacts": [],
                                   "error": "%s: %s" % (call.name, call.parse_error),
                                   "tool_call_id": call.id, "via": "native",
                                   "arguments": {}, "coercions": []}
                    else:
                        outcome = self.registry.call(call.name, call.arguments,
                                                     tool_call_id=call.id, via="native")
                    turn = self._record(call.name, call.arguments, outcome,
                                        thought=(response.content or "")[:400],
                                        tool_call_id=call.id, via="native", mode="native")
                    messages.append(tool_message(call.id, call.name,
                                                 outcome["result"] if outcome["dispatched"]
                                                 else {"error": outcome["error"]}))
                    if time.monotonic() >= self.deadline:
                        stopped = "wall_clock"
                        break
                self.state.save(decisions=self.decisions, executions=len(self.turns))
                if stopped == "wall_clock":
                    final_text = self._timeout_text()
                    break
                continue

            # No native tool call: either a JSON action in text, or the final answer.
            action, error = parse_action(response.content, self.registry.names())
            if action.get("tool"):
                messages.append({"role": "assistant", "content": response.content})
                outcome = self.registry.call(action["tool"], action.get("args") or {},
                                             tool_call_id="json-fallback-%d" % self.decisions,
                                             via="json_fallback")
                turn = self._record(action["tool"], action.get("args") or {}, outcome,
                                    thought=action.get("thought", ""),
                                    tool_call_id=turn_id(self.decisions), via="json_fallback",
                                    mode="json_fallback")
                # The fallback channel has no tool role to answer: the result is a user turn.
                messages.append({"role": "user", "content":
                                 "工具 %s 的真实结果：\n%s"
                                 % (turn.tool, render(turn.observation, 2400))})
                self.state.save(decisions=self.decisions, executions=len(self.turns))
                continue
            if action.get("final"):
                final_text, stopped = action["final"], "final"
                break
            if (response.content or "").strip():
                # A tool-free answer in prose is a legitimate final answer in native mode.
                final_text, stopped = response.content.strip(), "final"
                break
            if response.finish_reason == "length":
                stopped = "truncated"
                final_text = ("模型在输出文本前耗尽 token 预算（finish_reason=length）；"
                              "提高 LLM_MAX_TOKENS 后重试。")
                break
            self.log.append("action_rejected", {"error": error or "empty response",
                                                "decision": self.decisions},
                            status="rejected")
            messages.append({"role": "user", "content":
                             "上一次回复没有工具调用也没有结论（%s）。请调用工具，"
                             "或在结束时直接给出结论。" % (error or "empty response")})

        if not final_text:
            # The budget ran out mid-investigation. Asking for the conclusion with tools
            # withheld is the difference between "no result" and "a result plus the list
            # of what was not established" - and it cannot invent new evidence, because it
            # cannot call anything.
            final_text = self._closing_turn(messages) or self._fallback_text()
        if stopped == "max_turns":
            final_text = final_text or self._fallback_text()

        check = self.log.verify()
        self.log.append("finish", {"stopped": stopped, "decisions": self.decisions,
                                   "executions": len(self.turns),
                                   "usage": self.usage.to_dict(),
                                   "evidence_ok": check["ok"]})
        self.state.finish(status="finished", stop_reason=stopped,
                          decisions=self.decisions, executions=len(self.turns))

        result = RunResult(run_id=self.run_id, goal=self.goal, final=final_text,
                           turns=self.turns, stopped=stopped, decisions=self.decisions,
                           usage=self.usage, workspace=str(self.workspace.root),
                           resume_state=self.state.data.get("resume_state", "NEW"),
                           case_id=self.case_id, evidence_ok=check["ok"])
        self.paths.result.write_text(json.dumps(result.to_dict(), ensure_ascii=False,
                                                indent=1), encoding="utf-8")
        return result

    # -- one execution ---------------------------------------------------
    def _record(self, tool: str, args: dict, outcome: dict, *, thought: str,
                tool_call_id: str, via: str, mode: str) -> Turn:
        dispatched, ok = outcome["dispatched"], outcome["ok"]
        observation = (outcome["result"] if dispatched
                       else {"error": outcome["error"], "status": "dispatch_error"})
        status = "success" if ok else ("rejected" if not dispatched else "failed")
        # Evidence keeps the vocabulary the benchmark counts; the turn keeps the one a
        # reader expects ("rejected" reads better than "dispatch_error" in a transcript).
        evidence_status = ("dispatch_error" if not dispatched
                           else ("success" if ok else "failed"))
        record = self.log.append("tool", {
            "tool_name": tool,
            "tool_call_id": tool_call_id,
            "via": via,
            "mode": mode,
            "arguments": args,
            "coerced_arguments": outcome.get("arguments"),
            "coercions": outcome.get("coercions", []),
            "dispatched": dispatched,
            "operation_ok": ok,
            "summary": _shrink(outcome.get("summary"), 1200),
            "error": outcome.get("error"),
            "artifacts": outcome.get("artifacts", []),
        }, status=evidence_status)

        turn = Turn(step=self.decisions, index=len(self.turns) + 1, thought=thought,
                    tool=tool, args=args, observation=observation, status=status,
                    tool_call_id=tool_call_id, via=via, mode=mode,
                    evidence_id=record.get("evidence_id", ""),
                    at=time.strftime("%H:%M:%S"))
        self.turns.append(turn)
        self._append_transcript({"decision": self.decisions, "step": turn.index,
                                 "tool": tool, "status": status, "via": via,
                                 "evidence_id": turn.evidence_id,
                                 "observation": render(observation, 900)})
        try:
            self.memory.add("attempt", "%s %s -> %s" % (
                tool, json.dumps(args, ensure_ascii=False)[:180],
                (turn.evidence_id or status)), evidence=[turn.evidence_id] if turn.evidence_id
                else [], scope="run")
        except Exception:  # noqa: BLE001 - memory must never break a run
            pass
        return turn

    # -- closing ---------------------------------------------------------
    def _closing_turn(self, messages: List[dict]) -> str:
        """One tool-free call that asks for the conclusion, and records that it happened."""
        if not self.turns:
            return ""
        remaining = self.deadline - time.monotonic()
        if remaining <= 5:
            return ""
        request = list(messages) + [{"role": "user", "content": (
            "决策预算已用完，本轮不再提供工具。请只输出最终结论：做了什么、实际观测到什么、"
            "哪些结论有证据（引用 evidence id）、哪些仍是推测、还缺什么条件。"
            "不要输出 JSON，不要调用工具。")}]
        try:
            response = self.provider.chat(request, tools=None,
                                          timeout=int(max(5, min(remaining, 120))))
        except Exception as exc:  # noqa: BLE001 - a failed closing turn is not a crash
            self.log.append("closing_error", {"error": "%s: %s" % (type(exc).__name__, exc)},
                            status="failed")
            return ""
        self.usage = self.usage.add(response.usage)
        self.log.append("assistant", {"decision": self.decisions + 1, "closing": True,
                                      "mode": response.mode,
                                      "content_preview": (response.content or "")[:800],
                                      "tool_call_ids": [], "tool_names": [],
                                      "finish_reason": response.finish_reason,
                                      "usage": response.usage.to_dict(),
                                      "latency_ms": response.latency_ms,
                                      "model": response.model or getattr(self.provider, "model", "")})
        return (response.content or "").strip()

    # -- persistence -----------------------------------------------------
    def _append_transcript(self, entry: dict) -> None:
        with self.paths.transcript.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def _load_turns(self) -> List[Turn]:
        if not self.paths.transcript.is_file():
            return []
        turns: List[Turn] = []
        for line in self.paths.transcript.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            entry = json.loads(line)
            turns.append(Turn(step=int(entry.get("decision", 0)),
                              index=int(entry.get("step", len(turns) + 1)),
                              thought="", tool=entry.get("tool", ""), args={},
                              observation={"preview": entry.get("observation", "")},
                              status=entry.get("status", ""),
                              via=entry.get("via", ""),
                              evidence_id=entry.get("evidence_id", "")))
        return turns

    # -- messages --------------------------------------------------------
    def _fallback_text(self) -> str:
        if not self.turns:
            return "在 %d 个决策内没有产生任何工具调用。" % self.decisions
        last = self.turns[-1]
        return ("未在 %d 个决策内得出结论。最后一次执行：%s（%s）\n观测：%s"
                % (self.decisions, last.tool, last.status,
                   render(last.observation, 800)))

    def _timeout_text(self) -> str:
        return ("墙钟预算（%ds）用尽，run 在决策 %d 中止。已执行 %d 次工具调用，"
                "证据见 %s。" % (self.run_timeout, self.decisions, len(self.turns),
                                 self.paths.evidence))

    def summary(self) -> dict:
        return {"run_id": self.run_id, "case_id": self.case_id, "goal": self.goal,
                "tools": self.registry.names(), "catalog": self.catalog.summary(),
                "providers": self.assembly.providers,
                "adapter_errors": self.assembly.adapter_errors,
                "conflicts": self.assembly.conflicts,
                "evidence": str(self.paths.evidence),
                "workspace": str(self.workspace.root),
                "memory": {"run": str(self.memory.run_store.path),
                           "global": str(self.memory.global_store.path),
                           "case": str(self.memory.case_store.path)
                           if self.memory.case_store else ""}}


def turn_id(decision: int) -> str:
    return "json-fallback-%d" % decision


def _shrink(value, limit: int) -> dict:
    text = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    if len(text) <= limit:
        return value if isinstance(value, dict) else {"value": value}
    return {"truncated": True, "preview": text[:limit]}
