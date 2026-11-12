# -*- coding: utf-8 -*-
"""Finding store: append-only JSONL, one JSON and one advisory-style report per finding.

Layout (inside a trial):

```
research/findings.jsonl          the journal
research/findings/<id>.json      the record
research/findings/<id>.md        the report a human reads
```
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List, Optional

from .model import Finding, next_id, now, render_report


class FindingError(RuntimeError):
    """A finding operation that would lose or misrepresent an anomaly."""


class FindingStore:
    def __init__(self, trial_root: Path, trial_id: str) -> None:
        self.root = Path(trial_root)
        self.trial_id = trial_id
        self.directory = self.root / "research" / "findings"
        self.directory.mkdir(parents=True, exist_ok=True)
        self.journal = self.root / "research" / "findings.jsonl"
        self._items: Dict[str, Finding] = {}
        self._load()

    def _load(self) -> None:
        if not self.journal.is_file():
            return
        for line in self.journal.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                item = Finding.from_dict(json.loads(line))
            except (ValueError, TypeError):
                continue
            self._items[item.finding_id] = item

    # -- write -----------------------------------------------------------
    def create(self, title: str, **fields) -> Finding:
        finding_id = fields.pop("finding_id", "") or next_id(self.trial_id,
                                                             list(self._items))
        finding = Finding(finding_id=finding_id, title=title, trial_id=self.trial_id,
                          created_at=now(), **fields)
        if finding_id in self._items:
            raise FindingError("finding %s already exists; findings are append-only"
                               % finding_id)
        self._write(finding)
        return finding

    def update(self, finding_id: str, **changes) -> Finding:
        """Append a new revision; the earlier JSON stays on disk untouched."""
        current = self._items.get(finding_id)
        if current is None:
            raise FindingError("no finding %r" % finding_id)
        data = current.to_dict()
        data.update(changes)
        data["finding_id"] = finding_id
        revised = Finding.from_dict(data)
        self.root.joinpath("research", "findings", "history").mkdir(parents=True, exist_ok=True)
        stamp = now().replace(":", "")
        (self.root / "research" / "findings" / "history" /
         ("%s.%s.json" % (finding_id, stamp))).write_text(
            json.dumps(current.to_dict(), ensure_ascii=False, indent=1), encoding="utf-8")
        self._write(revised)
        return revised

    def _write(self, finding: Finding) -> None:
        payload = finding.to_dict()
        (self.directory / ("%s.json" % finding.finding_id)).write_text(
            json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
        (self.directory / ("%s.md" % finding.finding_id)).write_text(
            render_report(finding), encoding="utf-8")
        with self.journal.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self._items[finding.finding_id] = finding

    # -- read ------------------------------------------------------------
    def get(self, finding_id: str) -> Optional[Finding]:
        return self._items.get(finding_id)

    def all(self) -> List[Finding]:
        return sorted(self._items.values(), key=lambda item: item.created_at)

    def tally(self) -> dict:
        """Track B statistics, kept separate from any CVE-reproduction count."""
        items = self.all()
        return {
            "findings": len(items),
            "stable": sum(1 for item in items if item.verification_status == "stable"),
            "root_cause_done": sum(1 for item in items
                                   if item.root_cause_status in ("confirmed", "partial")),
            "linked_to_known_cve": sum(1 for item in items if item.related_cves),
            "unattributed": sum(1 for item in items if not item.related_cves),
            "by_component": _count(item.component for item in items),
            "by_crash_class": _count(item.crash_class for item in items),
        }


def _count(values) -> dict:
    out: Dict[str, int] = {}
    for value in values:
        out[value] = out.get(value, 0) + 1
    return out
