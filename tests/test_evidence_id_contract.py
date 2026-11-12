# -*- coding: utf-8 -*-
"""The evidence id contract: what the model sees must match what the log holds.

Three separate facts, three tests:

* the native tool message carries the id, so the model can cite it;
* the rendered observation prints it exactly once (a duplicate is a prompt bug);
* the id the model sees is a record that actually exists in ``evidence.jsonl``.

The third one is the point. An id that is well-formed but unresolvable is worse than no id,
because a memory entry citing it will be rejected later - or, worse, accepted by a check
that only looks at the shape.
"""

from __future__ import annotations

import json
from pathlib import Path

from gpuvulnagent.context.observation import render
from gpuvulnagent.evidence import verify_chain
from gpuvulnagent.runtime import AgentRuntime
from tests.support import ScriptedProvider, native, prose, read_records, tool_call


def _content_of(message: dict) -> str:
    """Tool messages may carry an `evidence_id=` header line; the body is JSON."""
    text = message["content"]
    if not text.startswith("evidence_id="):
        return text
    _, _, body = text.partition(chr(10))
    return body


def make_runtime(tmp_path: Path, provider) -> AgentRuntime:
    return AgentRuntime(goal="evidence id contract", root=tmp_path / "run", provider=provider,
                        max_turns=3, run_timeout=60, research_root=tmp_path / "archive",
                        toolchain_root=None, enable_search=False)


def test_native_tool_message_carries_the_evidence_id(tmp_path):
    provider = ScriptedProvider([native(tool_call("fs_list", {}, "call_1")), prose("done")])
    runtime = make_runtime(tmp_path, provider)
    result = runtime.run()

    tool_messages = [m for m in provider.calls[1]["messages"] if m.get("role") == "tool"]
    assert len(tool_messages) == 1
    payload = json.loads(_content_of(tool_messages[0]))
    assert payload["evidence_id"] == result.turns[0].evidence_id
    assert payload["evidence_id"].startswith(runtime.run_id + "#")


def test_rendered_observation_prints_the_id_once(tmp_path):
    provider = ScriptedProvider([native(tool_call("fs_list", {}, "call_1")), prose("done")])
    runtime = make_runtime(tmp_path, provider)
    runtime.run()

    observation = dict(runtime.turns[0].observation)
    observation["evidence_id"] = runtime.turns[0].evidence_id
    text = render(observation, 800)
    assert text.count("evidence_id:") == 1
    assert runtime.turns[0].evidence_id in text


def test_the_visible_id_resolves_to_a_real_record(tmp_path):
    provider = ScriptedProvider([native(tool_call("fs_list", {}, "call_1")), prose("done")])
    runtime = make_runtime(tmp_path, provider)
    result = runtime.run()

    records = read_records(tmp_path / "run" / "evidence.jsonl")
    by_id = {record.get("evidence_id"): record for record in records}
    tool_message = [m for m in provider.calls[1]["messages"] if m.get("role") == "tool"][0]
    visible = json.loads(_content_of(tool_message))["evidence_id"]
    assert visible in by_id, "the model was shown an id that is not in the log"
    assert by_id[visible]["kind"] == "tool"
    assert by_id[visible]["tool_name"] == "fs_list"
    assert by_id[visible]["tool_call_id"] == "call_1"
    assert by_id[visible]["run_id"] == result.run_id
    assert verify_chain(tmp_path / "run" / "evidence.jsonl")["ok"] is True
