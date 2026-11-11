# -*- coding: utf-8 -*-
"""Run state on disk: create once, resume only if it is still trustworthy.

A run id is unique by construction (UTC timestamp + random suffix), so two runs can never
share a directory and a benchmark can never silently overwrite an experiment.

Resume is conservative. It refuses when the goal changed, when the evidence chain is
broken, or when the recorded head hash no longer matches the tail of the log. If the
process died between a tool record and its completion, the run is marked
``INTERRUPTED / EXECUTION_STATE_UNKNOWN`` rather than replaying an action whose outcome is
unknown.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..evidence.hashing import sha256_text
from ..evidence.log import verify_chain


class RunStateError(RuntimeError):
    """Run-level misuse: existing directory, changed goal, corrupt evidence."""


@dataclass
class RunPaths:
    root: Path
    workspace: Path
    artifacts: Path
    evidence: Path
    transcript: Path
    memory: Path
    state: Path
    result: Path

    @classmethod
    def under(cls, root: Path) -> "RunPaths":
        root = Path(root)
        return cls(root=root, workspace=root / "workspace", artifacts=root / "artifacts",
                   evidence=root / "evidence.jsonl", transcript=root / "transcript.jsonl",
                   memory=root / "memory.jsonl", state=root / "run.json",
                   result=root / "result.json")


def new_run_id() -> str:
    """Sortable and unique: ``run-20261111T090500Z-1a2b3c``."""
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return "run-%s-%s" % (stamp, secrets.token_hex(3))


class RunState:
    def __init__(self, paths: RunPaths) -> None:
        self.paths = paths
        self.data: dict = {}

    # -- lifecycle -------------------------------------------------------
    def create(self, *, goal: str, case_id: str = "", mode: str = "agent",
               allow_existing: bool = False) -> dict:
        root = self.paths.root
        if root.exists() and any(root.iterdir()) and not allow_existing:
            existing = {}
            if self.paths.state.is_file():
                try:
                    existing = json.loads(self.paths.state.read_text(encoding="utf-8"))
                except ValueError:
                    existing = {}
            raise RunStateError("run directory already holds a run (%s); refusing to "
                                "overwrite it - choose another --root or use --resume"
                                % existing.get("run_id", str(root)))
        root.mkdir(parents=True, exist_ok=True)
        self.data = {
            "run_id": new_run_id(),
            "goal": goal.strip(),
            "goal_sha256": sha256_text(goal.strip()),
            "case_id": case_id,
            "mode": mode,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "status": "running",
            "decisions": 0,
            "executions": 0,
            "resume_state": "NEW",
            "evidence_head": "",
            "evidence_sequence": 0,
        }
        self.save()
        return self.data

    def load(self) -> dict:
        if not self.paths.state.is_file():
            raise RunStateError("no run.json in %s" % self.paths.root)
        self.data = json.loads(self.paths.state.read_text(encoding="utf-8"))
        return self.data

    def resume(self, *, goal: str) -> dict:
        state = self.load()
        if state.get("goal_sha256") != sha256_text(goal.strip()):
            raise RunStateError("goal differs from the recorded run; refusing to resume")
        check = verify_chain(self.paths.evidence)
        if not check["ok"]:
            raise RunStateError("evidence chain is broken: %s"
                                % "; ".join(check["errors"][:3]))
        anchored = state.get("evidence_head")
        if anchored and check["last_record_sha256"] != anchored:
            raise RunStateError("evidence tail does not match the recorded head "
                                "(records were removed after the run)")
        last = _tail(self.paths.evidence)
        interrupted = bool(last and last.get("kind") in ("tool", "exec", "assistant"))
        state.update({"status": "running",
                      "resume_state": "INTERRUPTED" if interrupted else "RESUMED",
                      "resumed_at": time.strftime("%Y-%m-%dT%H:%M:%S")})
        if interrupted:
            state["interrupt_reason"] = "EXECUTION_STATE_UNKNOWN"
        self.data = state
        self.save()
        return state

    def save(self, **updates) -> None:
        self.data.update(updates)
        tail = _tail(self.paths.evidence)
        if tail:
            # Anchor the head so a truncated tail cannot look like a shorter valid chain.
            self.data["evidence_head"] = tail.get("record_sha256")
            self.data["evidence_sequence"] = tail.get("sequence")
        self.paths.root.mkdir(parents=True, exist_ok=True)
        self.paths.state.write_text(json.dumps(self.data, ensure_ascii=False, indent=1),
                                    encoding="utf-8")

    def finish(self, *, status: str, stop_reason: str, decisions: int,
               executions: int) -> None:
        self.save(status=status, stop_reason=stop_reason, decisions=decisions,
                  executions=executions,
                  finished_at=time.strftime("%Y-%m-%dT%H:%M:%S"))

    @property
    def run_id(self) -> str:
        return self.data.get("run_id", "")


def _tail(path: Path) -> Optional[dict]:
    path = Path(path)
    if not path.is_file():
        return None
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return json.loads(lines[-1]) if lines else None


def goal_digest(goal: str) -> str:
    return hashlib.sha256(goal.strip().encode("utf-8")).hexdigest()
