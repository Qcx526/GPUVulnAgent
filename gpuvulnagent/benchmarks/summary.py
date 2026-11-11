# -*- coding: utf-8 -*-
"""Result index: every run is kept, and the summary is derived, never overwritten.

P18 wrote ``summary_<mode>.json`` on every invocation. Running the same mode twice replaced
the first result, so the report could only ever describe the last attempt.

Here each run has its own verdict file and the index is an append-only list of run ids.
``rebuild()`` recomputes the index from the verdict files (and their evidence) so the
summary can always be reconstructed instead of trusted.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, List, Optional

SCHEMA = "gpuvulnagent-benchmark-summary/v1"


class SummaryIndex:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.runs_dir = self.root / "runs"
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "index.json"

    # -- writing ---------------------------------------------------------
    def record(self, entry: dict) -> Path:
        run_id = entry.get("run_id")
        if not run_id:
            raise ValueError("a summary entry needs a run_id")
        per_run = self.runs_dir / ("%s.json" % run_id)
        per_run.write_text(json.dumps(entry, ensure_ascii=False, indent=1), encoding="utf-8")
        index = self.load()
        known = {item["run_id"] for item in index["runs"]}
        if run_id not in known:
            index["runs"].append({"run_id": run_id, "case_id": entry.get("case_id", ""),
                                  "mode": entry.get("mode", ""),
                                  "verdict": entry.get("CRASH_OBSERVED", ""),
                                  "recorded_at": entry.get("recorded_at",
                                                           time.strftime("%Y-%m-%dT%H:%M:%S")),
                                  "path": str(per_run)})
            index["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            self.path.write_text(json.dumps(index, ensure_ascii=False, indent=1),
                                 encoding="utf-8")
        return per_run

    def load(self) -> dict:
        if not self.path.is_file():
            return {"schema": SCHEMA, "updated_at": "", "runs": []}
        data = json.loads(self.path.read_text(encoding="utf-8"))
        data.setdefault("runs", [])
        return data

    def run_ids(self) -> List[str]:
        return [item["run_id"] for item in self.load()["runs"]]

    # -- rebuilding ------------------------------------------------------
    def rebuild(self, cases_root: Path) -> dict:
        """Recompute the index from verdict files on disk. Nothing is trusted blindly."""
        cases_root = Path(cases_root)
        entries = []
        for verdict_path in sorted(cases_root.rglob("verdict.json")):
            try:
                verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
            except ValueError:
                continue
            run_id = verdict.get("run_id") or verdict_path.parent.name
            entries.append({"run_id": run_id,
                            "case_id": verdict.get("case_id", ""),
                            "mode": verdict.get("mode", ""),
                            "verdict": verdict.get("CRASH_OBSERVED", ""),
                            "recorded_at": verdict.get("recorded_at", ""),
                            "path": str(self.runs_dir / ("%s.json" % run_id))})
            target = self.runs_dir / ("%s.json" % run_id)
            if not target.is_file():
                target.write_text(json.dumps(verdict, ensure_ascii=False, indent=1),
                                  encoding="utf-8")
        index = {"schema": SCHEMA, "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                 "runs": entries}
        self.path.write_text(json.dumps(index, ensure_ascii=False, indent=1),
                             encoding="utf-8")
        return index

    def table(self) -> str:
        index = self.load()
        if not index["runs"]:
            return "(no runs recorded)"
        lines = ["%-34s %-6s %-16s %s" % ("run_id", "mode", "case", "crash")]
        for item in index["runs"]:
            lines.append("%-34s %-6s %-16s %s" % (item["run_id"], item["mode"],
                                                  item["case_id"], item["verdict"]))
        return "\n".join(lines)


def load_entry(root: Path, run_id: str) -> Optional[dict]:
    path = Path(root) / "runs" / ("%s.json" % run_id)
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
