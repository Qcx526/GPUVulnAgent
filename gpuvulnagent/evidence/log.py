# -*- coding: utf-8 -*-
"""Append-only, hash-chained evidence log.

Each record carries the previous record's hash and its own, so a deleted, reordered or
edited record is detectable. The chain is tamper-*evident*, not tamper-proof: an actor
with write access can rebuild a consistent file, which is why run state also anchors the
head hash.

Record kinds used by the runtime:

``start``            goal hash, tool menu, providers, mode
``assistant``        one model turn: mode (native/json_fallback/prose), tool call ids
``tool``             one dispatch: arguments, envelope, artifacts, tool_call_id
``exec``             one OS process: argv, exit, duration, termination classification
``memory``           a memory entry written by the agent
``resume``           a resumed run and why it was marked interrupted
``finish``           stop reason, turn count and the evidence check result
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, List, Optional

from .artifacts import ArtifactStore
from .hashing import GENESIS, sha256_bytes

SCHEMA = "gpuvulnagent-evidence/v1"

# Payload keys a tool must not be able to overwrite: the log owns sequence, kind and status.
RESERVED = ("schema", "run_id", "sequence", "kind", "status", "at",
            "previous_record_sha256", "record_sha256", "evidence_id")


def evidence_id(run_id: str, sequence: int) -> str:
    """Stable, human-readable reference to one record: ``run-abc#7``."""
    return "%s#%d" % (run_id, int(sequence))


class EvidenceLog:
    def __init__(self, path: Path, run_id: str = "",
                 artifacts: Optional[ArtifactStore] = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.artifacts = artifacts
        if not self.path.exists():
            self.path.write_text("", encoding="utf-8")
        # A log opened read-only (audit, memory validation) must still know whose run it
        # is, otherwise every record it holds looks like it belongs to nobody.
        self.run_id = run_id or self._infer_run_id()

    def _infer_run_id(self) -> str:
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    return json.loads(line).get("run_id", "") or ""
                except ValueError:
                    return ""
        return ""

    # -- reading ---------------------------------------------------------
    def records(self) -> List[dict]:
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

    def _last(self) -> tuple:
        records = self.records()
        if not records:
            return 0, GENESIS
        last = records[-1]
        return int(last.get("sequence", len(records))), last.get("record_sha256", GENESIS)

    def tail(self, count: int = 10) -> List[dict]:
        return self.records()[-count:]

    def get(self, sequence: int) -> Optional[dict]:
        for record in self.records():
            if record.get("sequence") == sequence:
                return record
        return None

    def find_by_hash(self, record_sha256: str) -> Optional[dict]:
        for record in self.records():
            if record.get("record_sha256") == record_sha256:
                return record
        return None

    # -- writing ---------------------------------------------------------
    def append(self, kind: str, payload: Dict, status: str = "success") -> dict:
        sequence, previous = self._last()
        entry: Dict = {
            "schema": SCHEMA,
            "run_id": self.run_id,
            "sequence": sequence + 1,
            "kind": kind,
            "status": status,
            "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "previous_record_sha256": previous,
        }
        for key, value in (payload or {}).items():
            if key not in RESERVED:
                entry[key] = value
        # Reserved fields are written last so a payload cannot relabel its own outcome.
        entry["kind"] = kind
        entry["status"] = status
        # The id is part of the record, not a convenience added after writing: memory
        # entries cite it, and a citation has to survive a restart.
        entry["evidence_id"] = evidence_id(self.run_id, entry["sequence"])
        digest = sha256_bytes(json.dumps(entry, sort_keys=True,
                                        ensure_ascii=False).encode("utf-8"))
        entry["record_sha256"] = digest
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def verify(self) -> dict:
        return verify_chain(self.path)


def verify_chain(path: Path) -> dict:
    """Recompute the whole chain: sequence continuity, links and record hashes."""
    path = Path(path)
    if not path.is_file():
        return {"ok": False, "errors": ["evidence log missing"], "records": 0,
                "last_record_sha256": None}
    errors: List[str] = []
    expected, previous, count = 1, GENESIS, 0
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        count += 1
        try:
            entry = json.loads(raw)
        except ValueError as exc:
            errors.append("record %d: not JSON (%s)" % (count, exc))
            continue
        stored = entry.pop("record_sha256", None)
        if entry.get("sequence") != expected:
            errors.append("record %d: sequence is %r, expected %d"
                          % (count, entry.get("sequence"), expected))
        if entry.get("previous_record_sha256") != previous:
            errors.append("record %d: previous hash does not match the chain" % count)
        recomputed = sha256_bytes(json.dumps(entry, sort_keys=True,
                                            ensure_ascii=False).encode("utf-8"))
        if recomputed != stored:
            errors.append("record %d: content does not match its hash" % count)
        previous = stored or ""
        expected += 1
    return {"ok": not errors, "errors": errors, "records": count,
            "last_record_sha256": previous or None}


class EvidenceResolver:
    """Answers "does this evidence id exist" for memory entries.

    A finding that cites an id nobody can look up is a claim, not a finding, so memory
    validation goes through here rather than trusting the model's string.
    """

    def __init__(self, search_roots: Optional[List[Path]] = None) -> None:
        self.search_roots = [Path(p) for p in (search_roots or [])]

    def add_root(self, root: Path) -> None:
        root = Path(root)
        if root not in self.search_roots:
            self.search_roots.append(root)

    def resolve(self, reference: str, log: Optional[EvidenceLog] = None) -> Optional[dict]:
        """``run-abc#7`` or ``sha256:...`` -> the record, or None."""
        reference = (reference or "").strip()
        if not reference:
            return None
        if reference.startswith("sha256:"):
            wanted = reference.split(":", 1)[1]
            for log_obj in self._logs(log):
                found = log_obj.find_by_hash(wanted)
                if found:
                    return found
            return None
        if "#" not in reference:
            return None
        run_id, _, raw_sequence = reference.partition("#")
        try:
            sequence = int(raw_sequence)
        except ValueError:
            return None
        for log_obj in self._logs(log):
            if log_obj.run_id != run_id:
                continue
            record = log_obj.get(sequence)
            if record:
                return record
        return None

    def _logs(self, log: Optional[EvidenceLog]) -> List[EvidenceLog]:
        logs: List[EvidenceLog] = []
        if log is not None:
            logs.append(log)
        for root in self.search_roots:
            candidate = Path(root)
            path = candidate if candidate.name.endswith(".jsonl") else candidate / "evidence.jsonl"
            if path.is_file():
                try:
                    logs.append(EvidenceLog(path))
                except Exception:  # noqa: BLE001 - a foreign log must not break validation
                    continue
        return logs
