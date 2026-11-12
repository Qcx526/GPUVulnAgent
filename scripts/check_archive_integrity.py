# -*- coding: utf-8 -*-
"""Check that an experiment bundle means what its manifest says.

A manifest is a promise: "these files exist, with these hashes, and they are in the
repository". This script verifies the promise instead of trusting it:

* every declared file exists on disk and its SHA256 matches;
* every skipped entry explains why;
* every declared file is tracked by git (a bundle that is only on the machine that made it
  is not archived);
* nothing in the bundle is an unlisted regular file.

    python scripts/check_archive_integrity.py            [all bundles]
    python scripts/check_archive_integrity.py --bundle research_archive/experiments/P20
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def tracked(path: Path) -> bool:
    relative = str(path.relative_to(ROOT)).replace("\\", "/")
    result = subprocess.run(["git", "ls-files", "--error-unmatch", relative],
                            cwd=str(ROOT), capture_output=True, text=True)
    return result.returncode == 0


def check_bundle(bundle_dir: Path) -> dict:
    manifest_path = bundle_dir / "bundle_manifest.json"
    report = {"bundle": str(bundle_dir.relative_to(ROOT)).replace("\\", "/"),
              "ok": True, "errors": [], "checked": 0, "declared": 0}
    if not manifest_path.is_file():
        report["ok"] = False
        report["errors"].append("missing bundle_manifest.json")
        return report

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    declared = manifest.get("files") or []
    report["declared"] = len(declared)
    listed = set()

    for item in declared:
        relative = item.get("path") or item.get("destination") or ""
        if not relative:
            report["ok"] = False
            report["errors"].append("entry without a path")
            continue
        path = ROOT / relative
        listed.add(relative)
        report["checked"] += 1
        if not path.is_file():
            report["ok"] = False
            report["errors"].append("missing file: %s (declared %s bytes)"
                                    % (relative, item.get("bytes")))
            continue
        actual = sha256(path)
        if actual != item.get("sha256"):
            report["ok"] = False
            report["errors"].append("hash mismatch: %s (%s != %s)"
                                    % (relative, actual, item.get("sha256")))
        if path.stat().st_size != item.get("bytes"):
            report["ok"] = False
            report["errors"].append("size mismatch: %s" % relative)
        if not tracked(path):
            report["ok"] = False
            report["errors"].append("not tracked by git: %s" % relative)

    for item in manifest.get("skipped") or []:
        if not item.get("reason"):
            report["ok"] = False
            report["errors"].append("skipped entry without a reason: %s" % item.get("path"))
        if item.get("path") in listed:
            report["ok"] = False
            report["errors"].append("both declared and skipped: %s" % item.get("path"))

    unlisted = []
    for path in sorted(bundle_dir.rglob("*")):
        if not path.is_file():
            continue
        relative = str(path.relative_to(ROOT)).replace("\\", "/")
        if relative in listed or path.name in ("bundle_manifest.json", "SHA256SUMS.txt"):
            continue
        unlisted.append(relative)
    if unlisted:
        report["ok"] = False
        report["errors"].append("files present but not in the manifest: %s"
                                % ", ".join(unlisted[:5]))
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", default="")
    args = parser.parse_args()

    base = ROOT / "research_archive" / "experiments"
    if args.bundle:
        bundles = [Path(args.bundle).resolve()]
    else:
        bundles = sorted(path.parent for path in base.glob("*/bundle_manifest.json"))
    if not bundles:
        print("no bundles found under %s" % base)
        return 2

    failures = 0
    for bundle in bundles:
        report = check_bundle(bundle)
        status = "ok" if report["ok"] else "FAILED"
        print("[%-6s] %-52s declared=%d checked=%d"
              % (status, report["bundle"], report["declared"], report["checked"]))
        for error in report["errors"][:10]:
            print("         - %s" % error)
        failures += 0 if report["ok"] else 1
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
