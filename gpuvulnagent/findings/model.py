# -*- coding: utf-8 -*-
"""A finding is an anomaly the agent noticed that no assigned CVE explains.

Two tracks, never mixed: track A is "reproduce the CVE you were given", track B is "something
odd happened, record it and investigate". A finding is deliberately *not* a CVE: the id is
``FND-<trial>-<seq>`` so it can never be mistaken for an assigned number, and the report says
plainly what is proven and what is not.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

SCHEMA = "gpuvulnagent-finding/v1"
ID_PATTERN = re.compile(r"^FND-[a-z0-9]+-\d{4}$")
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

# Crash classes we are willing to name. Anything else stays UNKNOWN.
CRASH_CLASSES = ("SIGSEGV", "SIGABRT", "SIGBUS", "SIGILL", "SIGFPE", "TIMEOUT", "OOM",
                 "EXIT_NONZERO", "UNKNOWN")

STATUSES = ("new", "triaged", "root_cause_in_progress", "root_cause_partial",
            "stable", "unstable", "duplicate_of_known_cve", "closed_no_impact")


@dataclass
class Finding:
    finding_id: str
    title: str
    component: str = "UNKNOWN"
    trial_id: str = ""
    created_at: str = ""
    source_evidence_ids: List[str] = field(default_factory=list)
    input_path: str = ""
    input_sha256: str = ""
    parent_artifact_ids: List[str] = field(default_factory=list)
    mutation: str = ""
    target_versions: Dict[str, str] = field(default_factory=dict)
    reproduction_command: str = ""
    stdout_ref: str = ""
    stderr_ref: str = ""
    crash_class: str = "UNKNOWN"
    signal: str = ""
    exit_code: Optional[int] = None
    differential: Dict[str, str] = field(default_factory=dict)
    stability: Dict[str, object] = field(default_factory=dict)
    cwe: str = "UNKNOWN"
    related_cves: List[str] = field(default_factory=list)
    root_cause_status: str = "not_started"
    impact: str = "UNKNOWN"
    verification_status: str = "new"
    open_questions: List[str] = field(default_factory=list)
    notes: str = ""
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if not ID_PATTERN.match(self.finding_id):
            raise ValueError("finding ids look like FND-<trial>-0001, got %r" % self.finding_id)
        if CVE_PATTERN.search(self.finding_id):
            raise ValueError("a finding id must not look like a CVE number")
        if self.crash_class not in CRASH_CLASSES:
            self.crash_class = "UNKNOWN"
        if self.verification_status not in STATUSES:
            self.verification_status = "new"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def next_id(trial_id: str, existing: List[str]) -> str:
    numbers = [int(item.rsplit("-", 1)[1]) for item in existing
               if ID_PATTERN.match(item) and item.rsplit("-", 1)[1].isdigit()]
    return "FND-%s-%04d" % (trial_id.replace("trial", "t"), max(numbers, default=0) + 1)


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def render_report(finding: Finding) -> str:
    """A report shaped like an advisory, with the unproven parts marked as unproven."""
    versions = "\n".join("| %s | `%s` |" % (k, v) for k, v in
                         (finding.target_versions or {"UNKNOWN": "UNKNOWN"}).items())
    diff = "\n".join("| %s | %s |" % (k, v) for k, v in
                     (finding.differential or {"UNKNOWN": "UNKNOWN"}).items())
    stable = finding.stability or {"runs": "UNKNOWN"}
    related = ", ".join(finding.related_cves) or "none identified"
    questions = "\n".join("- %s" % item for item in finding.open_questions) or "- none recorded"
    return f"""# {finding.finding_id}: {finding.title}

> Internal finding, **not** an assigned CVE. Do not cite it as one.

| field | value |
|---|---|
| finding id | `{finding.finding_id}` |
| component | {finding.component} |
| trial | {finding.trial_id} |
| created | {finding.created_at} |
| crash class | {finding.crash_class}{" (" + finding.signal + ")" if finding.signal else ""} |
| exit code | {finding.exit_code} |
| CWE | {finding.cwe} |
| root cause | {finding.root_cause_status} |
| verification | {finding.verification_status} |
| impact | {finding.impact} |

## Input

| field | value |
|---|---|
| path | `{finding.input_path}` |
| sha256 | `{finding.input_sha256}` |
| parents | {", ".join(finding.parent_artifact_ids) or "none"} |
| mutation | {finding.mutation or "UNKNOWN"} |

## Target versions

| build | identity |
|---|---|
{versions}

## Reproduction

```
{finding.reproduction_command or "UNKNOWN"}
```

stdout: `{finding.stdout_ref or "UNKNOWN"}`
stderr: `{finding.stderr_ref or "UNKNOWN"}`

## Cross-version behaviour

| build | result |
|---|---|
{diff}

## Stability

{stable}

## Evidence

{", ".join("`%s`" % item for item in finding.source_evidence_ids) or "none recorded"}

## Known-CVE relationship

{related}

## Open questions

{questions}

## Notes

{finding.notes or "(none)"}
"""
