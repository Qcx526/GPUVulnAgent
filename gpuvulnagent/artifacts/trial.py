# -*- coding: utf-8 -*-
"""Trial: one research attempt, laid out so a human can read it later.

```
runs/trial0/
  session/    task.json, transcript.jsonl, decisions.jsonl, tool_calls.jsonl
  research/   notes written by the agent (or empty)
  poc/        manifests/<artifact>.json + INDEX.md  (single copy of every file, see below)
  executions/ execNN/  (mirror of trails/<id>/execNN for quick reading)
  evidence/   evidence.jsonl (hash chain) + artifact_index.json + journal
  report/     final_report.md
```

**Why poc/ has manifests instead of copies.** Every produced file already exists once, in the
workspace it was written to or in the trail that collected it. Copying sources into
``poc/generated`` would create a second copy that can drift from the first, and a provenance
record that points at the copy rather than at the bytes that were actually compiled. So the
file stays where it was produced and ``poc/manifests`` holds one JSON per artifact with its
hash, parents and producer. ``poc/INDEX.md`` is the human-readable view.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .model import UNKNOWN, Artifact, now
from .registry import ArtifactError, ArtifactRegistry

TRIAL_PATTERN = re.compile(r"^trial(\d+)$")
SECTIONS = ("session", "research", "poc/manifests", "poc/original", "poc/generated",
            "poc/mutations", "evidence", "report", "executions", "workspace", "artifacts")

DOWNLOAD_TOOLS = {"http_get", "web_fetch", "web_extract", "web_search"}


class TrialSession:
    def __init__(self, root: Path, *, trial_id: str, goal: str, case_id: str = "") -> None:
        self.root = Path(root).resolve()
        self.trial_id = trial_id
        self.goal = goal
        self.case_id = case_id
        for section in SECTIONS:
            (self.root / section).mkdir(parents=True, exist_ok=True)
        self.registry = ArtifactRegistry(self.root, trial_id)
        self._seen: Dict[str, str] = {}
        self.turns: List[dict] = []
        self._write_task()
        self._write_provenance()
        self._write_provenance()

    # -- allocation ------------------------------------------------------
    @classmethod
    def allocate(cls, sessions_root: Path, *, goal: str, case_id: str = "") -> "TrialSession":
        sessions_root = Path(sessions_root)
        sessions_root.mkdir(parents=True, exist_ok=True)
        index = 0
        while True:
            candidate = sessions_root / ("trial%d" % index)
            try:
                candidate.mkdir()
            except FileExistsError:
                index += 1
                continue
            return cls(candidate, trial_id="trial%d" % index, goal=goal, case_id=case_id)

    # -- session records -------------------------------------------------
    def _write_task(self) -> None:
        payload = {"schema": "gpuvulnagent-trial/v1", "trial_id": self.trial_id,
                   "case_id": self.case_id, "goal": self.goal, "created_at": now(),
                   "root": str(self.root)}
        (self.root / "session" / "task.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")

    # Who did what. A research result is only the agent's if the agent produced it; the
    # engineer's fixes to the harness are recorded separately and never counted as findings.
    PROVENANCE = {
        "cve_selection": "human",
        "research_goal": "human",
        "cve_reading": "agent",
        "version_acquisition": "agent",
        "hypothesis": "agent",
        "poc_source": "agent",
        "mutation": "agent",
        "compilation": "agent",
        "execution": "agent",
        "crash_analysis": "agent",
        "finding_registration": "agent",
        "runtime_fixes": "workbuddy",
        "environment_setup": "workbuddy",
        "final_audit": "workbuddy",
    }

    def _write_provenance(self) -> None:
        payload = {"schema": "gpuvulnagent-provenance/v1", "trial_id": self.trial_id,
                   "defaults": dict(self.PROVENANCE),
                   "overrides": {},
                   "note": ("Every tool call in this trial was produced by the agent loop; "
                            "workbuddy entries describe repairs to the harness, not research "
                            "results.")}
        (self.root / "session" / "provenance.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")

    # Who did what. A research result is only the agent's if the agent produced it; the
    # engineer's fixes to the harness are recorded separately and never counted as findings.
    PROVENANCE = {
        "cve_selection": "human",
        "research_goal": "human",
        "cve_reading": "agent",
        "version_acquisition": "agent",
        "hypothesis": "agent",
        "poc_source": "agent",
        "mutation": "agent",
        "compilation": "agent",
        "execution": "agent",
        "crash_analysis": "agent",
        "finding_registration": "agent",
        "runtime_fixes": "workbuddy",
        "environment_setup": "workbuddy",
        "final_audit": "workbuddy",
    }

    def _write_provenance(self) -> None:
        payload = {"schema": "gpuvulnagent-provenance/v1", "trial_id": self.trial_id,
                   "defaults": dict(self.PROVENANCE),
                   "overrides": {},
                   "note": ("Every tool call in this trial was produced by the agent loop; "
                            "workbuddy entries describe repairs to the harness, not research "
                            "results.")}
        (self.root / "session" / "provenance.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")

    def _append_jsonl(self, name: str, payload: dict) -> None:
        path = self.root / "session" / name
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def record_turn(self, turn, *, usage: Optional[dict] = None) -> None:
        """Mirror one decision: what was asked, what ran, what came back."""
        entry = turn.to_dict() if hasattr(turn, "to_dict") else dict(turn)
        self.turns.append(entry)
        self._append_jsonl("transcript.jsonl", entry)
        self._append_jsonl("decisions.jsonl", {
            "step": entry.get("step"), "index": entry.get("index"), "origin": "agent", "origin": "agent",
            "thought": entry.get("thought", ""), "tool": entry.get("tool"),
            "status": entry.get("status"), "evidence_id": entry.get("evidence_id"),
            "at": entry.get("at"), "usage": usage or {}})
        self._append_jsonl("tool_calls.jsonl", {
            "index": entry.get("index"), "tool": entry.get("tool"),
            "arguments": entry.get("args"), "tool_call_id": entry.get("tool_call_id"),
            "via": entry.get("via"), "mode": entry.get("mode"),
            "evidence_id": entry.get("evidence_id"),
            "observation": entry.get("observation")})

    # -- artifact harvesting ---------------------------------------------
    def harvest(self, roots: Iterable[Path], *, tool: str = UNKNOWN,
                evidence_id: str = UNKNOWN, turn: int = -1) -> List[Artifact]:
        """Register files that appeared or changed since the last harvest.

        This is the part that makes "the agent wrote it with a shell heredoc" work: the shell
        string is not parsed, the workspace is diffed. Whatever the mechanism was, the bytes
        are on disk and get registered with the tool and evidence id that produced them.
        """
        produced = []
        for root in roots:
            root = Path(root)
            if not root.is_dir():
                continue
            for path in sorted(root.rglob("*")):
                if not path.is_file() or path.name.endswith(".pyc"):
                    continue
                try:
                    resolved = path.resolve()
                    relative = resolved.relative_to(self.root).as_posix()
                except (ValueError, OSError):
                    continue
                digest = _sha(resolved)
                if self._seen.get(relative) == digest:
                    continue
                self._seen[relative] = digest
                origin, execution_id = self._classify_origin(relative, tool)
                parents = self._parents_for(resolved, digest)
                try:
                    item = self.registry.register(
                        resolved, origin=origin, producer_tool=tool,
                        evidence_id=evidence_id, turn=turn, execution_id=execution_id,
                        parents=parents)
                except ArtifactError:
                    continue
                produced.append(item)
                self._write_manifest(item)
        if produced:
            self._write_index()
        return produced

    def _classify_origin(self, relative: str, tool: str) -> tuple:
        if "/execs/" in relative and "/outputs/" in relative:
            execution = relative.split("/execs/")[1].split("/")[0]
            trail_id = relative.split("/")[1] if relative.startswith("trails/") else "trail"
            kind = self.registry.find(name=Path(relative).name)
            is_binary = any(item.artifact_type == "binary" for item in kind)
            return ("compiled" if is_binary else "generated"), "%s/%s" % (trail_id, execution)
        if tool in DOWNLOAD_TOOLS:
            return "downloaded", ""
        if relative.startswith("workspace/"):
            return "generated", ""
        return "generated", ""

    def _parents_for(self, path: Path, digest: str) -> List[str]:
        for item in self.registry.all():
            if item.sha256 == digest:
                return [item.artifact_id]
        return []

    def _write_manifest(self, item: Artifact) -> None:
        payload = item.to_dict()
        payload["path_on_disk"] = str(self.root / item.relative_path)
        payload["parents"] = [parent.to_dict() for parent in
                              (self.registry.get(pid) for pid in item.parent_artifact_ids)
                              if parent is not None]
        target = self.root / "poc" / "manifests" / ("%s.json" % item.artifact_id)
        target.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")

    def _write_index(self) -> None:
        lines = ["# PoC artifacts in %s" % self.trial_id, "",
                 "| artifact | type | v | origin | sha256 | path | parents |",
                 "|---|---|---|---|---|---|---|"]
        for item in self.registry.all():
            parents = ", ".join(item.parent_artifact_ids) or "-"
            lines.append("| `%s` | %s | %d | %s | `%s` | `%s` | %s |"
                         % (item.artifact_id, item.artifact_type, item.version, item.origin,
                            item.sha256[:16], item.relative_path, parents))
        (self.root / "poc" / "INDEX.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    # -- close out -------------------------------------------------------
    def finish(self, final_text: str, *, stopped: str = "", usage: Optional[dict] = None,
               extra: Optional[dict] = None) -> Path:
        self._write_index()
        report = self.registry.refresh_index()
        lines = [
            "# %s — final report" % self.trial_id, "",
            "**Goal.** %s" % self.goal, "",
            "**Status.** stopped=%s, artifacts=%d (%s), evidence records=%s"
            % (stopped or "unknown", len(self.registry.all()),
               ", ".join("%s=%d" % item for item in sorted(report["counts"].items())),
               (extra or {}).get("evidence_records", "?")), "",
            "## Artifacts", "",
            "| id | type | v | origin | sha256 | path |",
            "|---|---|---|---|---|---|",
        ]
        for item in self.registry.all():
            lines.append("| `%s` | %s | %d | %s | `%s` | `%s` |"
                         % (item.artifact_id, item.artifact_type, item.version, item.origin,
                            item.sha256[:16], item.relative_path))
        lines += ["", "## Conclusions", "", final_text or "(no conclusion text)", ""]
        target = self.root / "report" / "final_report.md"
        target.write_text("\n".join(lines), encoding="utf-8")
        return target


def _sha(path: Path) -> str:
    import hashlib
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
