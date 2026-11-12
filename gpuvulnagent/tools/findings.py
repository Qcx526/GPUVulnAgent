# -*- coding: utf-8 -*-
"""Tools for track B: record an anomaly without pretending it is the assigned CVE."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from ..findings import FindingError, FindingStore
from ..registry.spec import ParamSpec, ToolSpec


def build_finding_tools(*, trial_root: Path, trial_id: str, log) -> List[ToolSpec]:
    store = FindingStore(Path(trial_root), trial_id)

    def finding_new(title: str, component: str = "UNKNOWN", crash_class: str = "UNKNOWN",
                    input_path: str = "", input_sha256: str = "",
                    reproduction_command: str = "", cwe: str = "UNKNOWN",
                    evidence_ids: Optional[list] = None, related_cves: Optional[list] = None,
                    target_versions: Optional[dict] = None,
                    differential: Optional[dict] = None, stability: Optional[dict] = None,
                    impact: str = "UNKNOWN", root_cause_status: str = "not_started",
                    verification_status: str = "new", notes: str = "",
                    mutation: str = "", parent_artifact_ids: Optional[list] = None) -> dict:
        try:
            finding = store.create(
                title, component=component, crash_class=crash_class,
                input_path=input_path, input_sha256=input_sha256,
                reproduction_command=reproduction_command, cwe=cwe,
                source_evidence_ids=list(evidence_ids or []),
                related_cves=list(related_cves or []),
                target_versions=dict(target_versions or {}),
                differential=dict(differential or {}), stability=dict(stability or {}),
                impact=impact, root_cause_status=root_cause_status,
                verification_status=verification_status, notes=notes, mutation=mutation,
                parent_artifact_ids=list(parent_artifact_ids or []))
        except (FindingError, ValueError) as exc:
            return {"ok": False, "status": "rejected",
                    "summary": {"error": "%s: %s" % (type(exc).__name__, exc)},
                    "artifacts": []}
        record = log.append("finding", {
            "finding_id": finding.finding_id, "title": finding.title,
            "component": finding.component, "crash_class": finding.crash_class,
            "input_sha256": finding.input_sha256,
            "target_versions": finding.target_versions,
            "related_cves": finding.related_cves,
            "verification_status": finding.verification_status})
        return {"ok": True, "status": "success",
                "summary": {"finding_id": finding.finding_id, "component": finding.component,
                            "crash_class": finding.crash_class,
                            "report": str(store.directory / ("%s.md" % finding.finding_id)),
                            "record": str(store.directory / ("%s.json" % finding.finding_id)),
                            "evidence": record.get("evidence_id"),
                            "note": "internal finding id, not a CVE number"},
                "artifacts": []}

    def finding_update(finding_id: str, **changes) -> dict:
        allowed = {"root_cause_status", "verification_status", "impact", "cwe",
                   "related_cves", "open_questions", "notes", "stability", "differential"}
        payload = {key: value for key, value in changes.items() if key in allowed}
        if not payload:
            return {"ok": False, "status": "rejected",
                    "summary": {"error": "nothing to update; allowed: %s"
                                         % ", ".join(sorted(allowed))}, "artifacts": []}
        try:
            finding = store.update(finding_id, **payload)
        except (FindingError, ValueError) as exc:
            return {"ok": False, "status": "failed",
                    "summary": {"error": "%s: %s" % (type(exc).__name__, exc)},
                    "artifacts": []}
        return {"ok": True, "summary": {"finding_id": finding.finding_id,
                                        "verification_status": finding.verification_status,
                                        "root_cause_status": finding.root_cause_status},
                "artifacts": []}

    def finding_list() -> dict:
        return {"ok": True, "summary": {"tally": store.tally(),
                                        "findings": [item.to_dict() for item in store.all()]},
                "artifacts": []}

    return [
        ToolSpec(name="finding_new", description=(
            "Record an anomaly that the assigned CVE does not explain, as an internal finding "
            "with its own id (FND-...). Use it whenever a crash, hang or differential shows up "
            "that is not the thing you were asked to reproduce. The finding gets a JSON record "
            "and an advisory-style report; it is never reported as a CVE."),
            handler=finding_new, category="research", source="builtin",
            location="gpuvulnagent/findings/store.py",
            usage="finding_new(title='nvdisasm 12.6.68 SIGSEGV on REL offset', "
                  "component='nvdisasm', crash_class='SIGSEGV', input_path=..., "
                  "input_sha256=..., differential={'12.6.68': 'SIGSEGV', '12.8.55': 'exit 1'})",
            parameters=[
                ParamSpec("title", "string", "One line, what happened."),
                ParamSpec("component", "string", "nvdisasm / cuobjdump / nvjpeg / ...",
                          required=False, default="UNKNOWN"),
                ParamSpec("crash_class", "string", "Observed class, or UNKNOWN.",
                          required=False, default="UNKNOWN"),
                ParamSpec("input_path", "string", "Input file inside the trial.",
                          required=False, default=""),
                ParamSpec("input_sha256", "string", "Hash of the exact input bytes.",
                          required=False, default=""),
                ParamSpec("reproduction_command", "string", "The command that reproduced it.",
                          required=False, default=""),
                ParamSpec("cwe", "string", "CWE if you can defend it, else UNKNOWN.",
                          required=False, default="UNKNOWN"),
                ParamSpec("evidence_ids", "array", "Evidence ids supporting the finding.",
                          required=False, items_type="string"),
                ParamSpec("related_cves", "array",
                          "Known CVEs this might belong to (analysis, not attribution).",
                          required=False, items_type="string"),
                ParamSpec("target_versions", "object", "build -> identity.",
                          required=False),
                ParamSpec("differential", "object", "build -> observed result.",
                          required=False),
                ParamSpec("stability", "object", "runs / crashes / notes.",
                          required=False),
                ParamSpec("impact", "string", "What an attacker gets, if known.",
                          required=False, default="UNKNOWN"),
                ParamSpec("root_cause_status", "string",
                          "not_started / in_progress / partial / confirmed.",
                          required=False, default="not_started"),
                ParamSpec("verification_status", "string",
                          "new / triaged / stable / unstable / duplicate_of_known_cve / "
                          "closed_no_impact.", required=False, default="new"),
                ParamSpec("notes", "string", "Anything a reader needs.", required=False,
                          default=""),
                ParamSpec("mutation", "string", "How the input was derived.", required=False,
                          default=""),
                ParamSpec("parent_artifact_ids", "array", "Artifacts this input came from.",
                          required=False, items_type="string")],
            side_effects=("writes_workspace",), tags=("research", "finding", "triage")),

        ToolSpec(name="finding_update", description=(
            "Append a new revision of a finding (root cause progress, stability, CVE link). "
            "The earlier revision is kept under research/findings/history/."),
            handler=finding_update, category="research", source="builtin",
            location="gpuvulnagent/findings/store.py",
            parameters=[ParamSpec("finding_id", "string", "FND-... id."),
                        ParamSpec("root_cause_status", "string", "", required=False,
                                  default=""),
                        ParamSpec("verification_status", "string", "", required=False,
                                  default=""),
                        ParamSpec("impact", "string", "", required=False, default=""),
                        ParamSpec("cwe", "string", "", required=False, default=""),
                        ParamSpec("related_cves", "array", "", required=False,
                                  items_type="string"),
                        ParamSpec("open_questions", "array", "", required=False,
                                  items_type="string"),
                        ParamSpec("notes", "string", "", required=False, default=""),
                        ParamSpec("stability", "object", "", required=False),
                        ParamSpec("differential", "object", "", required=False)],
            side_effects=("writes_workspace",), tags=("research", "finding")),

        ToolSpec(name="finding_list", description=(
            "List findings in this trial with the track-B tally (stable, root-caused, linked "
            "to a known CVE, still unattributed)."),
            handler=finding_list, category="research", source="builtin",
            location="gpuvulnagent/findings/store.py",
            parameters=[], tags=("research", "finding")),
    ]
