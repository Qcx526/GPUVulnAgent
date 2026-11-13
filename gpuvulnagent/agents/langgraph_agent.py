# -*- coding: utf-8 -*-
"""LangGraph-based research agent (v2), replacing the hand-written loop.

Why this exists: the hand-written AgentRuntime lost cross-run state, re-explored the
environment every run and kept every tool result in context. LangGraph gives durable state
(SqliteSaver), resume-by-thread-id and a clean tool node; LangChain gives the model adapter.
What stays ours: the GPU tools, the backend, Evidence/Artifact/Trail and the finding rules.

A Campaign is the long-lived unit: one CVE or research goal, many runs, one checkpoint file.
A Run is one invocation of the graph on the same thread; resuming is invoking again.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Annotated, Any, Dict, List, Optional, TypedDict

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import StructuredTool
from langchain_openai import ChatOpenAI
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

SYSTEM = """You are GPUVulnAgent, a GPU/CUDA vulnerability researcher.

Rules that matter:
- Every claim needs a tool result behind it. Never infer a crash from an exit code.
- The tool result carries evidence_id and, for executions, signal_verified/signaled. Cite them.
- Deliver files with trail_stage (wsl-ref:... or repo:...), never by writing base64.
- Container has no Python; run mutators on the WSL host through run_program with argv.
- Register unrelated anomalies with finding_new; never call a finding a CVE.
- Keep the campaign facts file current: write what is verified, what failed, what is next.

Work in small steps: act, read the result, then decide. Do not narrate a plan you cannot execute.
"""



def _campaign_note(campaign, log, kind: str, text: str, evidence_ids=None) -> str:
    ids = list(evidence_ids or [])
    result = {"kind": kind, "text": text, "evidence_ids": ids}
    if kind.upper() == "FACT_CLAIM":
        resolved = [i for i in ids
                    if any(r.get("evidence_id") == i and r.get("kind") == "exec"
                           for r in log.records())]
        result["promoted"] = bool(ids) and len(resolved) == len(ids)
        if campaign is not None:
            campaign.claim(kind, text, ids, promoted=result["promoted"])
            if result["promoted"]:
                campaign.fact(text, ids)
    elif kind.upper() == "NEXT_STEP" and campaign is not None:
        campaign.next_step(text)
    elif campaign is not None:
        campaign.claim(kind, text, ids, promoted=False)
    return json.dumps(result, ensure_ascii=False)


def _wsl_ls(relpath: str = "") -> str:
    import subprocess
    from gpuvulnagent.backends.wsl_docker import WslConfig
    base = str(Path(WslConfig().worker_root) / "refs")
    target = (Path(base) / relpath).as_posix() if relpath else base
    if ".." in Path(target).parts:
        return json.dumps({"ok": False, "error": "path traversal refused"})
    out = subprocess.run(["wsl.exe", "-e", "ls", "-1", target],
                         capture_output=True, text=True, timeout=60)
    return json.dumps({"ok": out.returncode == 0, "root": target,
                       "entries": out.stdout.split()[:40]}, ensure_ascii=False)



class AgentState(TypedDict):
    messages: Annotated[List[BaseMessage], add_messages]
    spent_tokens: int
    steps: int


KEEP = ("evidence_id", "dispatched", "exit", "termination", "signal_verified",
        "signaled", "signal", "artifacts", "exec_dir", "image", "cuda", "gpu_name")


def _summary_of(result: dict, limit: int = 2500) -> str:
    payload = {key: result[key] for key in KEEP if key in result}
    payload["ok"] = result.get("ok")
    payload["status"] = result.get("status")
    if result.get("error"):
        payload["error"] = result.get("error")
    payload["summary"] = result.get("summary")
    text = json.dumps(payload, ensure_ascii=False, default=str)
    return text if len(text) <= limit else text[:limit] + "...[offloaded]"


campaign_auto: List[dict] = []
campaign_facts: List[dict] = []
campaign_claims: List[dict] = []
campaign_steps: List[str] = []


def extra_tools(campaign=None, log=None) -> List[StructuredTool]:
    """The two agent-facing extras; used by both the graph and the offline tests."""
    def campaign_note(kind: str, text: str, evidence_ids: list | None = None) -> str:
        return _campaign_note(campaign, log, kind, text, evidence_ids)

    def wsl_ls(relpath: str = "") -> str:
        return _wsl_ls(relpath)

    return [StructuredTool.from_function(func=campaign_note, name="campaign_note",
                description="Record HYPOTHESIS / NEXT_STEP / FACT_CLAIM with evidence ids."),
            StructuredTool.from_function(func=wsl_ls, name="wsl_ls",
                description="List the WSL refs directory before trail_stage.")]


def dispatch(registry, log, name: str, args: dict, tool_call_id: str = "") -> dict:
    """Call a tool AND append its evidence record, so the two are linked by tool_call_id."""
    result = registry.call(name, args)
    record = log.append("tool", {"tool_name": name, "tool_call_id": tool_call_id,
                                 "ok": result.get("ok"), "status": result.get("status"),
                                 "error": result.get("error")})
    result = dict(result)
    result["evidence_id"] = record.get("evidence_id")
    result["tool_call_id"] = tool_call_id
    return result


def build_tools(registry, log, campaign=None) -> List[StructuredTool]:
    """Existing ToolSpec -> LangChain tools. Schema comes from the spec, not from guesses."""
    from pydantic import create_model

    tools = []
    for spec in registry.all():
        fields = {}
        for param in spec.parameters:
            python_type = {"string": str, "integer": int, "number": float,
                           "boolean": bool, "array": list, "object": dict}.get(param.type, str)
            default = param.default if not param.required else ...
            fields[param.name] = (python_type, default)
        schema = create_model(spec.name + "_args", **fields)

        def make(spec_name: str):
            def caller(**kwargs):
                result = dispatch(registry, log, spec_name, kwargs,
                                  tool_call_id=kwargs.get("tool_call_id", ""))
                if campaign is not None:
                    campaign.observation(spec_name, result.get("ok"),
                                         result.get("evidence_id"))
                return _summary_of(result)
            return caller

        tools.append(StructuredTool.from_function(
            func=make(spec.name), name=spec.name, description=spec.description[:900],
            args_schema=schema))
    return tools


def _budget_exceeded(state: AgentState, max_tokens: int) -> bool:
    return bool(max_tokens) and state.get("spent_tokens", 0) >= max_tokens


def build_graph(registry, log, *, model: str, base_url: str, api_key: str,
                max_tokens: int = 300_000, max_steps: int = 40,
                campaign_dir: Optional[Path] = None, campaign=None):
    tools = build_tools(registry, log, campaign) + extra_tools(campaign, log)
    by_name = {tool.name: tool for tool in tools}

    llm = ChatOpenAI(model=model, base_url=base_url, api_key=api_key,
                     temperature=0, timeout=180).bind_tools(tools)

    def agent_node(state: AgentState):
        if _budget_exceeded(state, max_tokens) or state.get("steps", 0) >= max_steps:
            return {"messages": [AIMessage(content="BUDGET_OR_STEPS_REACHED: stopping without "
                                                   "new work; report what is verified so far.")]}
        response = llm.invoke(state["messages"])
        spent = state.get("spent_tokens", 0) + int(
            (response.usage_metadata or {}).get("total_tokens", 0))
        return {"messages": [response], "spent_tokens": spent,
                "steps": state.get("steps", 0) + 1}

    def tool_node(state: AgentState):
        last = state["messages"][-1]
        outputs = []
        for call in getattr(last, "tool_calls", []) or []:
            tool = by_name.get(call["name"])
            if tool is None:
                outputs.append(ToolMessage(content="unknown tool %s" % call["name"],
                                           tool_call_id=call["id"]))
                continue
            try:
                content = tool.invoke(call.get("args") or {})
            except Exception as exc:  # noqa: BLE001 - a rejected call is an observation
                content = json.dumps({"ok": False, "error": "%s: %s"
                                      % (type(exc).__name__, exc)})
            outputs.append(ToolMessage(content=str(content), tool_call_id=call["id"]))
        return {"messages": outputs}

    def route(state: AgentState) -> str:
        if _budget_exceeded(state, max_tokens) or state.get("steps", 0) >= max_steps:
            return END
        last = state["messages"][-1]
        return "tools" if getattr(last, "tool_calls", None) else END

    graph = StateGraph(AgentState)
    graph.add_node("agent", agent_node)
    graph.add_node("tools", tool_node)
    graph.add_edge(START, "agent")
    graph.add_conditional_edges("agent", route, {"tools": "tools", END: END})
    graph.add_edge("tools", "agent")

    if campaign_dir is not None:
        campaign_dir.mkdir(parents=True, exist_ok=True)
        import sqlite3
        conn = sqlite3.connect(str(Path(campaign_dir) / "checkpoint.sqlite"),
                               check_same_thread=False)
        saver = SqliteSaver(conn)
    else:
        from langgraph.checkpoint.memory import MemorySaver
        saver = MemorySaver()
    app = graph.compile(checkpointer=saver)
    app._checkpoint_conn = locals().get("conn")   # keep the connection alive
    return app


class Campaign:
    """The durable unit above a run: what is verified, what failed, what is next."""

    def __init__(self, root: Path, *, campaign_id: str, goal: str, case: str = "") -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "campaign.json"
        self.data = json.loads(self.path.read_text(encoding="utf-8")) if self.path.is_file() else {
            "campaign_id": campaign_id, "goal": goal, "case": case,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"), "runs": 0,
            "facts": [], "failed_hypotheses": [], "next_steps": [], "spent_tokens": 0}
        self.data["runs"] = int(self.data.get("runs", 0)) + 1
        self.save()

    def save(self) -> None:
        self.path.write_text(json.dumps(self.data, ensure_ascii=False, indent=1),
                             encoding="utf-8")

    def fact(self, text, evidence_ids=None):
        entry = {"text": text, "evidence_ids": list(evidence_ids or []),
                 "run": self.data.get("runs", 0)}
        if text and all(e["text"] != text for e in self.data["facts"]):
            self.data["facts"].append(entry)
            self.save()

    def observation(self, tool, ok, evidence_id):
        self.data.setdefault("observations", []).append(
            {"tool": tool, "ok": ok, "evidence_id": evidence_id,
             "run": self.data.get("runs", 0)})
        self.save()

    def claim(self, kind, text, evidence_ids=None, promoted=False):
        self.data.setdefault("claims", []).append(
            {"kind": kind, "text": text, "evidence_ids": list(evidence_ids or []),
             "promoted": promoted, "run": self.data.get("runs", 0)})
        self.save()

    def next_step(self, text):
        if text and text not in self.data["next_steps"]:
            self.data["next_steps"].append(text)
            self.save()

    def prompt(self) -> str:
        facts = "\n".join("- %s" % item for item in self.data["facts"][-40:]) or "- (none yet)"
        nxt = "\n".join("- %s" % item for item in self.data["next_steps"][-10:]) or "- (none)"
        return ("CAMPAIGN %s (run #%d)\nGOAL: %s\n\nVERIFIED FACTS:\n%s\n\nNEXT STEPS:\n%s\n"
                % (self.data["campaign_id"], self.data["runs"], self.data["goal"], facts, nxt))


def run_campaign(*, registry, log, campaign_dir: Path, goal: str, campaign_id: str,
                 model: str, base_url: str, api_key: str, max_tokens: int, max_steps: int,
                 resume: bool = True) -> dict:
    campaign = Campaign(campaign_dir, campaign_id=campaign_id, goal=goal)
    app = build_graph(registry, log, model=model, base_url=base_url, api_key=api_key,
                      max_tokens=max_tokens, max_steps=max_steps, campaign_dir=campaign_dir, campaign=campaign)
    config = {"configurable": {"thread_id": campaign_id}}
    snapshot = app.get_state(config)
    has_history = bool(snapshot and snapshot.values.get("messages"))
    inputs = None if (resume and has_history) else {
        "messages": [SystemMessage(content=SYSTEM), HumanMessage(content=campaign.prompt())],
        "spent_tokens": 0, "steps": 0}
    result = app.invoke(inputs, config)
    campaign.data["spent_tokens"] = result.get("spent_tokens", 0)
    campaign.save()
    messages = result.get("messages", [])
    return {"campaign": campaign.data, "messages": messages,
            "spent_tokens": result.get("spent_tokens", 0),
            "steps": result.get("steps", 0), "resumed": bool(resume and has_history)}
