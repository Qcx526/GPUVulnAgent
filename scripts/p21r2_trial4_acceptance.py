# -*- coding: utf-8 -*-
"""Acceptance on the real trial4: four genuine citations, through the agent's own tool path.

    python scripts/p21r2_trial4_acceptance.py

Not a resolver unit test: it builds the same assembly the runtime builds and calls
``memory_note`` exactly as the agent does, then reads the case memory from a *different* run.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gpuvulnagent.evidence import ArtifactStore, EvidenceLog, Runner, verify_chain  # noqa: E402
from gpuvulnagent.evidence.log import EvidenceResolver  # noqa: E402
from gpuvulnagent.memory.store import LayeredMemory  # noqa: E402
from gpuvulnagent.runtime.workspace import Workspace  # noqa: E402
from gpuvulnagent.tools.build import build_assembly  # noqa: E402

TRIAL = ROOT / "runs" / "trial4"
RUN_ID = "run-20261112T084744Z-31e7fd"
CASE = "P21R2-CLOSE"
CITED = ["#6", "#7", "#14", "#21"]


def make_assembly(memory_run_id: str):
    workspace = Workspace(TRIAL / "session" / "run" / "workspace")
    log = EvidenceLog(TRIAL / "evidence" / "evidence.jsonl", RUN_ID,
                      ArtifactStore(TRIAL / "artifacts"))
    runner = Runner(workspace.root, log, timeout=30)
    memory = LayeredMemory(run_dir=TRIAL, research_root=ROOT / "research_archive",
                           run_id=memory_run_id, case_id=CASE,
                           resolver=EvidenceResolver([TRIAL]))
    return build_assembly(workspace=workspace, runner=runner, log=log, memory=memory,
                          toolchain_root=None, enable_search=False)


def main() -> int:
    result = {"trial": str(TRIAL), "run_id": RUN_ID, "case": CASE}
    resolver = EvidenceResolver([TRIAL])
    result["resolved"] = {}
    for suffix in CITED:
        reference = RUN_ID + suffix
        record = resolver.resolve(reference)
        result["resolved"][reference] = None if record is None else {
            "kind": record.get("kind"), "tool": record.get("tool_name"),
            "status": record.get("status"), "sequence": record.get("sequence"),
            "record_sha256": record.get("record_sha256")}
    missing = [ref for ref, value in result["resolved"].items() if value is None]
    result["all_four_exist"] = not missing

    assembly = make_assembly(RUN_ID)
    citations = [RUN_ID + suffix for suffix in CITED]
    written = assembly.registry.call("memory_note", {
        "kind": "finding", "scope": "case",
        "text": ("P21R2-CLOSE trial4: v1 (scale 2.0) and v2 (scale 5.0) both compiled with "
                 "nvcc -arch=sm_75 and ran on the GTX 1660; both container_exec runs exited 0."),
        "tags": ["acceptance", "cuda"], "evidence": citations})
    result["memory_write"] = {"ok": written["ok"], "status": written["status"],
                              "error": written.get("error"),
                              "summary": written.get("summary")}
    memory_id = (written.get("summary") or {}).get("id")

    rejected = assembly.registry.call("memory_note", {
        "kind": "finding", "scope": "case",
        "text": "this citation is fabricated and must be refused",
        "evidence": [RUN_ID + "#9999"]})
    result["fabricated_refused"] = {"ok": rejected["ok"], "status": rejected["status"],
                                    "error": str(rejected.get("error"))[:160]}

    reader = LayeredMemory(run_dir=ROOT / ".local" / "tmp" / "trial4-reader",
                           research_root=ROOT / "research_archive",
                           run_id="run-reader-p21r2", case_id=CASE,
                           resolver=EvidenceResolver([TRIAL]))
    entries = reader.entries(scopes=("case",))
    inherited = [item for item in entries if item.id == memory_id]
    result["cross_run"] = {"found": bool(inherited), "memory_id": memory_id,
                           "evidence": inherited[0].evidence if inherited else [],
                           "visible_to_other_runs": len(entries)}

    chain = verify_chain(TRIAL / "evidence" / "evidence.jsonl")
    result["chain"] = {"ok": chain["ok"], "records": chain["records"],
                       "errors": chain["errors"][:3]}

    result["verdict"] = {
        "all_four_exist": result["all_four_exist"],
        "write_accepted": bool(written["ok"]),
        "citations_match": bool(inherited and inherited[0].evidence == citations),
        "fabricated_refused": (not rejected["ok"]) and rejected["status"] == "rejected",
        "chain_ok": chain["ok"],
    }
    result["verdict"]["passed"] = all(result["verdict"].values())
    print(json.dumps(result, ensure_ascii=False, indent=1))
    return 0 if result["verdict"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
