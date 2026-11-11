# -*- coding: utf-8 -*-
"""Copy P17/P18 research data into the new workspace, byte for byte, and hash it.

Rules this script follows:

* **Copy, never move, never edit.** The source tree is a read-only git worktree at a fixed
  commit; the destination is ``research_archive/``.
* **Verify every copy** by comparing the SHA256 of source and destination.
* **Record provenance** - source commit, source path, destination path, hash, size - in one
  machine-readable manifest plus a plain ``SHA256SUMS`` file that ``sha256sum -c`` accepts.
* **Never rewrite a verdict.** If a historical result is wrong, that belongs in the audit
  document, not in the archived file.

    python scripts/archive_p18.py [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gpuvulnagent.evidence.hashing import sha256_file  # noqa: E402

SOURCE_TREE = ROOT / ".local" / "migration_source" / "tree"
ARCHIVE = ROOT / "research_archive"

COMMITS = {
    "main": "0e299aff954e797b94d3b48bec666ca5d92df423",
    "archive_branch": "archive/pre-agent-runtime-2026-11-11",
    "archive_commit": "0a119a0dc017141fc7478f0317c39d89fe149f01",
    "agent_branch": "research/autonomous-agent-completion",
    "agent_commit": "c80efe18fcb60a1986f7d3dc570268356866d73c",
}

# (source relative to the old repo, destination relative to research_archive/)
TREES = [
    ("data/agent/archive", "p17/runs"),
    ("data/agent/r2_acceptance", "p17/r2_acceptance"),
    ("data/agent/benchmarks/p18", "p18/original"),
]

FILES = [
    ("data/agent/goal_nvjpeg.md", "p18/goals/goal_nvjpeg.md"),
    ("data/agent/goal_nvjpeg2.md", "p18/goals/goal_nvjpeg2.md"),
    ("docs/P18_AUTONOMOUS_AGENT_FINAL_REPORT.md", "p18/P18_AUTONOMOUS_AGENT_FINAL_REPORT.md"),
    ("docs/P17_AGENT_ARCHITECTURE.md", "p17/P17_AGENT_ARCHITECTURE.md"),
    ("docs/P17_LEGACY_AUDIT.md", "p17/P17_LEGACY_AUDIT.md"),
    ("docs/P17_R1_BASELINE_AUDIT.md", "p17/P17_R1_BASELINE_AUDIT.md"),
    ("docs/P17_R1_EVIDENCE_ARCHIVE.md", "p17/P17_R1_EVIDENCE_ARCHIVE.md"),
    ("docs/P17_R1_EVIDENCE_DESIGN.md", "p17/P17_R1_EVIDENCE_DESIGN.md"),
    ("docs/P17_R1_IMPLEMENTATION.md", "p17/P17_R1_IMPLEMENTATION.md"),
    ("docs/P17_R1_LIMITATIONS.md", "p17/P17_R1_LIMITATIONS.md"),
    ("docs/P17_R1_TAVILY.md", "p17/P17_R1_TAVILY.md"),
    ("docs/P17_R1_VALIDATION.md", "p17/P17_R1_VALIDATION.md"),
    ("docs/P17_R2_IMPLEMENTATION.md", "p17/P17_R2_IMPLEMENTATION.md"),
    ("docs/P17_R2_LIMITATIONS.md", "p17/P17_R2_LIMITATIONS.md"),
    ("docs/P17_R2_TOOL_CONTRACT.md", "p17/P17_R2_TOOL_CONTRACT.md"),
    ("docs/P17_R2_VALIDATION.md", "p17/P17_R2_VALIDATION.md"),
]


def git(*args: str) -> str:
    completed = subprocess.run(["git", *args], cwd=str(SOURCE_TREE), capture_output=True,
                               text=True)
    return (completed.stdout or completed.stderr).strip()


def copy_tree(source: Path, destination: Path, records: list, dry_run: bool) -> int:
    count = 0
    for path in sorted(source.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(source)
        target = destination / relative
        if not dry_run:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            if sha256_file(path) != sha256_file(target):
                raise SystemExit("copy verification failed: %s" % target)
        records.append({"source": str(path.relative_to(SOURCE_TREE)).replace("\\", "/"),
                        "destination": str(target.relative_to(ROOT)).replace("\\", "/"),
                        "sha256": sha256_file(path), "bytes": path.stat().st_size})
        count += 1
    return count


def copy_file(source: Path, destination: Path, records: list, dry_run: bool) -> None:
    if not source.is_file():
        print("  MISSING %s" % source)
        return
    if not dry_run:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        if sha256_file(source) != sha256_file(destination):
            raise SystemExit("copy verification failed: %s" % destination)
    records.append({"source": str(source.relative_to(SOURCE_TREE)).replace("\\", "/"),
                    "destination": str(destination.relative_to(ROOT)).replace("\\", "/"),
                    "sha256": sha256_file(source), "bytes": source.stat().st_size})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not SOURCE_TREE.is_dir():
        print("migration source missing: %s" % SOURCE_TREE, file=sys.stderr)
        return 2

    head = git("rev-parse", "HEAD")
    if head != COMMITS["agent_commit"]:
        print("refusing to archive from %s; expected %s" % (head, COMMITS["agent_commit"]),
              file=sys.stderr)
        return 3
    print("source HEAD verified: %s" % head)

    records: list = []
    for source_relative, destination_relative in TREES:
        source = SOURCE_TREE / source_relative
        destination = ARCHIVE / destination_relative
        count = copy_tree(source, destination, records, args.dry_run)
        print("  %-40s -> %-30s %4d files" % (source_relative, destination_relative, count))
    for source_relative, destination_relative in FILES:
        copy_file(SOURCE_TREE / source_relative, ARCHIVE / destination_relative, records,
                  args.dry_run)
        print("  %-40s -> %s" % (source_relative, destination_relative))

    if args.dry_run:
        print("dry run: %d files would be archived" % len(records))
        return 0

    migration_dir = ARCHIVE / "migration"
    migration_dir.mkdir(parents=True, exist_ok=True)
    sums = ["# SHA256 of every archived file, relative to the project root.",
            "# Verify from the project root with:  sha256sum -c research_archive/migration/SHA256SUMS.txt",
            ""]
    for record in sorted(records, key=lambda r: r["destination"]):
        sums.append("%s  %s" % (record["sha256"], record["destination"]))
    (migration_dir / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="utf-8")

    manifest = {
        "schema": "gpuvulnagent-migration/v1",
        "generated_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%S%z"),
        "source_repository": "https://github.com/Qcx526/cuda_poc_generator",
        "source_commits": COMMITS,
        "source_commit_verified": head,
        "source_branch_verified": git("rev-parse", "--abbrev-ref", "HEAD") or "detached",
        "policy": ("copied byte for byte; original verdicts, evidence and artifacts are not "
                   "edited; historical conclusions are audited separately"),
        "file_count": len(records),
        "total_bytes": sum(r["bytes"] for r in records),
        "files": sorted(records, key=lambda r: r["destination"]),
    }
    (migration_dir / "migration_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    print("\narchived %d files (%.1f MB)" % (len(records), manifest["total_bytes"] / 1e6))
    print("manifest: %s" % (migration_dir / "migration_manifest.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
