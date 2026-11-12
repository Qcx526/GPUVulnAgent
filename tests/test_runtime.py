# -*- coding: utf-8 -*-
"""Runtime: native tool calling, multi-call turns, JSON fallback, budgets, resume."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from gpuvulnagent.evidence import verify_chain
from gpuvulnagent.providers.base import ProviderError
from gpuvulnagent.runtime import AgentRuntime
from tests.support import RaisingProvider, ScriptedProvider, json_action, native, prose, \
    read_records, tool_call


def make_runtime(tmp_path: Path, script, *, provider=None, **kwargs) -> AgentRuntime:
    provider = provider or ScriptedProvider(script)
    return AgentRuntime(goal="把目标推进到有证据的结论", root=tmp_path / "run", provider=provider,
                        max_turns=kwargs.pop("max_turns", 3), run_timeout=60,
                        shell_timeout=30, research_root=tmp_path / "archive",
                        toolchain_root=None, enable_search=False, **kwargs)


def test_native_tool_call_records_id_and_feeds_result_back(tmp_path):
    provider = ScriptedProvider([
        native(tool_call("fs_write", {"path": "notes/a.txt", "content": "hi"}, "call_A")),
        prose("已完成。"),
    ])
    runtime = make_runtime(tmp_path, [], provider=provider, max_turns=3)
    result = runtime.run()

    assert result.stopped == "final"
    assert len(result.turns) == 1
    assert result.turns[0].tool == "fs_write"
    assert result.turns[0].tool_call_id == "call_A"
    assert (tmp_path / "run" / "workspace" / "notes" / "a.txt").read_text() == "hi"

    records = read_records(tmp_path / "run" / "evidence.jsonl")
    tool_records = [r for r in records if r["kind"] == "tool"]
    assert tool_records[0]["tool_call_id"] == "call_A"
    assert tool_records[0]["via"] == "native"
    assistant = [r for r in records if r["kind"] == "assistant"][0]
    assert assistant["mode"] == "native"
    assert assistant["tool_call_ids"] == ["call_A"]

    # The second request must contain the tool result message with the same id.
    second_call = provider.calls[1]["messages"]
    tool_messages = [m for m in second_call if m.get("role") == "tool"]
    assert tool_messages and tool_messages[0]["tool_call_id"] == "call_A"
    assert verify_chain(tmp_path / "run" / "evidence.jsonl")["ok"]


def test_one_response_may_contain_several_tool_calls(tmp_path):
    provider = ScriptedProvider([
        native(tool_call("fs_write", {"path": "a.txt", "content": "1"}, "call_1"),
               tool_call("fs_write", {"path": "b.txt", "content": "2"}, "call_2")),
        prose("两个文件都写了。"),
    ])
    runtime = make_runtime(tmp_path, [], provider=provider, max_turns=3)
    result = runtime.run()
    assert len(result.turns) == 2
    assert {t.tool_call_id for t in result.turns} == {"call_1", "call_2"}
    assert (tmp_path / "run" / "workspace" / "b.txt").read_text() == "2"
    assert result.decisions == 2


def test_json_action_fallback_is_recorded_as_such(tmp_path):
    provider = ScriptedProvider([
        json_action({"thought": "先看目录", "tool": "fs_list", "args": {"path": "."}}),
        prose("目录看过了。"),
    ])
    runtime = make_runtime(tmp_path, [], provider=provider, max_turns=3)
    result = runtime.run()
    assert result.turns and result.turns[0].via == "json_fallback"
    records = read_records(tmp_path / "run" / "evidence.jsonl")
    assert any(r.get("via") == "json_fallback" for r in records if r["kind"] == "tool")


def test_plain_prose_answer_ends_the_run(tmp_path):
    provider = ScriptedProvider([prose("这是一份不需要工具就能给出的结论。")])
    runtime = make_runtime(tmp_path, [], provider=provider, max_turns=3)
    result = runtime.run()
    assert result.stopped == "final"
    assert "结论" in result.final
    assert result.decisions == 1


def test_budget_exhaustion_is_closed_with_a_tool_free_conclusion(tmp_path):
    provider = ScriptedProvider([native(tool_call("fs_list", {}, "c1")),
                                 prose("已探测目录，结论如下：工作区为空。")])
    runtime = make_runtime(tmp_path, [], provider=provider, max_turns=1)
    result = runtime.run()
    assert result.stopped == "max_turns"
    assert "结论" in result.final
    # The closing request must offer no tools at all: a conclusion cannot add evidence.
    assert provider.calls[-1]["tools"] is None
    records = read_records(tmp_path / "run" / "evidence.jsonl")
    assert any(r.get("closing") for r in records if r["kind"] == "assistant")


def test_decision_budget_is_enforced(tmp_path):
    script = [native(tool_call("fs_list", {}, "c%d" % i)) for i in range(10)]
    runtime = make_runtime(tmp_path, [], provider=ScriptedProvider(script), max_turns=2)
    result = runtime.run()
    assert result.stopped == "max_turns"
    assert result.decisions == 2


def test_wall_clock_budget_is_enforced(tmp_path):
    provider = ScriptedProvider([prose("不该被调用")])
    runtime = AgentRuntime(goal="g", root=tmp_path / "run", provider=provider, max_turns=2,
                           run_timeout=60, research_root=tmp_path / "archive",
                           toolchain_root=None, enable_search=False,
                           deadline=time.monotonic() - 1)
    result = runtime.run()
    assert result.stopped == "wall_clock"
    assert provider.calls == []


def test_bad_arguments_are_rejected_without_dispatching(tmp_path):
    provider = ScriptedProvider([
        native(tool_call("fs_write", {"path": "a.txt"}, "call_bad")),
        prose("参数错了，我重来。"),
    ])
    runtime = make_runtime(tmp_path, [], provider=provider, max_turns=3)
    result = runtime.run()
    assert result.turns[0].status == "rejected"
    records = read_records(tmp_path / "run" / "evidence.jsonl")
    tool_records = [r for r in records if r["kind"] == "tool"]
    assert tool_records[0]["status"] == "dispatch_error"
    assert tool_records[0]["dispatched"] is False


def test_provider_failure_stops_the_run_and_is_recorded(tmp_path):
    runtime = make_runtime(tmp_path, [], provider=RaisingProvider(ProviderError("boom")),
                           max_turns=2)
    result = runtime.run()
    assert result.stopped == "provider_error"
    records = read_records(tmp_path / "run" / "evidence.jsonl")
    assert any(r["kind"] == "provider_error" for r in records)


def test_resume_continues_and_marks_state(tmp_path):
    first = make_runtime(tmp_path, [], provider=ScriptedProvider(
        [native(tool_call("fs_list", {}, "c1"))]), max_turns=1)
    first_result = first.run()
    assert first_result.stopped == "max_turns"
    assert first_result.decisions == 1

    second_provider = ScriptedProvider([prose("续跑后的结论。")])
    second = AgentRuntime(goal=first.goal, root=tmp_path / "run", provider=second_provider,
                          max_turns=3, run_timeout=60, research_root=tmp_path / "archive",
                          toolchain_root=None, enable_search=False, resume=True)
    result = second.run()
    assert result.stopped == "final"
    assert result.resume_state in ("RESUMED", "INTERRUPTED")
    assert result.decisions == 2
    assert verify_chain(tmp_path / "run" / "evidence.jsonl")["ok"]


def test_resume_refuses_a_different_goal(tmp_path):
    make_runtime(tmp_path, [], provider=ScriptedProvider([prose("done")]), max_turns=1).run()
    with pytest.raises(Exception):
        AgentRuntime(goal="另一个完全不同的目标", root=tmp_path / "run",
                     provider=ScriptedProvider([]), max_turns=1, run_timeout=60,
                     research_root=tmp_path / "archive", toolchain_root=None,
                     enable_search=False, resume=True)


def test_run_directory_is_never_overwritten(tmp_path):
    make_runtime(tmp_path, [], provider=ScriptedProvider([prose("done")]), max_turns=1).run()
    with pytest.raises(Exception):
        make_runtime(tmp_path, [], provider=ScriptedProvider([prose("again")]), max_turns=1)


def test_result_and_transcript_are_written(tmp_path):
    runtime = make_runtime(tmp_path, [], provider=ScriptedProvider(
        [native(tool_call("fs_list", {}, "c1")), prose("结束")]), max_turns=3)
    runtime.run()
    payload = json.loads((tmp_path / "run" / "result.json").read_text(encoding="utf-8"))
    assert payload["run_id"] == runtime.run_id
    assert payload["case_id"] == ""
    assert payload["executions"] == 1
    assert (tmp_path / "run" / "transcript.jsonl").is_file()
    assert (tmp_path / "run" / "run.json").is_file()


def test_every_observation_carries_its_evidence_id(tmp_path):
    """A model that cannot see the id will invent one; show it on the observation."""
    provider = ScriptedProvider([native(tool_call("fs_list", {}, "c1")), prose("done")])
    runtime = make_runtime(tmp_path, [], provider=provider, max_turns=3)
    runtime.run()
    second_request = provider.calls[1]["messages"]
    tool_messages = [m for m in second_request if m.get("role") == "tool"]
    assert tool_messages
    assert "evidence_id" in tool_messages[0]["content"]
    assert ("%s#" % runtime.run_id) in tool_messages[0]["content"]


def test_every_observation_carries_its_evidence_id(tmp_path):
    """A model that cannot see the id will invent one; show it on the observation."""
    provider = ScriptedProvider([native(tool_call("fs_list", {}, "c1")), prose("done")])
    runtime = make_runtime(tmp_path, [], provider=provider, max_turns=3)
    runtime.run()
    second_request = provider.calls[1]["messages"]
    tool_messages = [m for m in second_request if m.get("role") == "tool"]
    assert tool_messages
    assert "evidence_id" in tool_messages[0]["content"]
    assert ("%s#" % runtime.run_id) in tool_messages[0]["content"]
