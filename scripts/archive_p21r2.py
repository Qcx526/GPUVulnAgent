# -*- coding: utf-8 -*-
"""Archive trial2 (P21-R2) into research_archive/experiments/P21R2/, under 300 KB.

Copies the smallest set that still proves the claim: the two sources, the two cubins, the
compile/execute logs, the SASS evidence records, the artifact index, the session records and
the final report. Executables (~1 MB each) are named as skipped with their size and hash.

    python scripts/archive_p21r2.py [--trial runs/trial2]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "research_archive" / "experiments" / "P21R2"
LIMIT_BYTES = 300 * 1024


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trial", default="runs/trial2")
    args = parser.parse_args()
    trial = (ROOT / args.trial).resolve()
    if not trial.is_dir():
        raise SystemExit("no trial at %s" % trial)
    if DEST.exists():
        shutil.rmtree(DEST)
    DEST.mkdir(parents=True)

    files, skipped = [], []

    def take(source: Path, relative: str, max_bytes: int = 120_000) -> None:
        if not source.is_file():
            return
        size = source.stat().st_size
        if size > max_bytes:
            skipped.append({"path": str(source.relative_to(trial)).replace("\\", "/"),
                            "bytes": size, "sha256": sha(source),
                            "reason": "larger than the %d byte per-file budget" % max_bytes})
            return
        target = DEST / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        files.append({"path": str(target.relative_to(ROOT)).replace("\\", "/"),
                      "sha256": sha(target), "bytes": target.stat().st_size,
                      "source": str(source.relative_to(trial)).replace("\\", "/")})

    build = trial / "session/run/workspace/cuda_p21r2"
    take(build / "vector_scale_v1.cu", "sources/vector_scale_v1.cu")
    take(build / "vector_scale_v2.cu", "sources/vector_scale_v2.cu")
    take(build / "build/vector_scale_v1.cubin", "artifacts/vector_scale_v1.cubin")
    take(build / "build/vector_scale_v2.cubin", "artifacts/vector_scale_v2.cubin")
    for name in ("diff_v1_v2.txt", "nvcc_version.txt", "sha256sums.txt",
                 "nvcc_cubin_v1.log", "nvcc_cubin_v2.log", "nvcc_exe_v1.log",
                 "nvcc_exe_v2.log", "run_v1.exit", "run_v2.exit", "run_v1.stdout",
                 "run_v2.stdout", "run_v1.stderr", "run_v2.stderr"):
        take(build / "build" / name, "build/" + name)
    take(build / "build/vector_scale_v1", "artifacts/vector_scale_v1.exe", 200_000)
    take(build / "build/vector_scale_v2", "artifacts/vector_scale_v2.exe", 200_000)

    take(trial / "report/final_report.md", "report/final_report.md")
    take(trial / "session/task.json", "session/task.json")
    take(trial / "evidence/artifact_index.json", "evidence/artifact_index.json")
    for name in ("transcript.jsonl", "decisions.jsonl", "tool_calls.jsonl"):
        take(trial / "session" / name, "session/" + name, 200_000)

    # SASS evidence: the two cuobjdump records, trimmed to the instruction window.
    excerpt = []
    for line in (trial / "evidence/evidence.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if record.get("tool_name") != "cubin_disassemble" and "cuobjdump" not in str(
                record.get("argv", "")):
            continue
        text = record.get("stdout_preview") or ""
        keep = [row for row in text.splitlines()
                if "FADD" in row or "FMUL" in row or "vec_scale" in row][:12]
        excerpt.append({"evidence_id": record.get("evidence_id"),
                        "argv": record.get("argv"), "exit": record.get("exit"),
                        "lines": keep})
    (DEST / "sass_evidence.json").write_text(
        json.dumps(excerpt, ensure_ascii=False, indent=1), encoding="utf-8")
    files.append({"path": str((DEST / "sass_evidence.json").relative_to(ROOT)).replace("\\", "/"),
                  "sha256": sha(DEST / "sass_evidence.json"),
                  "bytes": (DEST / "sass_evidence.json").stat().st_size,
                  "source": "derived from evidence.jsonl (verbatim record fields)"})

    environment = {"gpu": "NVIDIA GeForce GTX 1660", "compute_capability": "7.5",
                   "cuda_toolkit": "12.8.93", "image":
                   "nvidia/cuda:12.8.0-devel-ubuntu22.04",
                   "image_digest": "nvidia/cuda@sha256:54f18e2a8e1b3d03f77b9a6dc905533da46ac93a5513f10e8ba8e560db9fa5ab",
                   "compile": "nvcc -arch=sm_75", "trial": args.trial,
                   "note": "values recorded by the tool calls in evidence.jsonl"}
    (DEST / "environment.json").write_text(json.dumps(environment, ensure_ascii=False, indent=1),
                                           encoding="utf-8")
    files.append({"path": str((DEST / "environment.json").relative_to(ROOT)).replace("\\", "/"),
                  "sha256": sha(DEST / "environment.json"),
                  "bytes": (DEST / "environment.json").stat().st_size, "source": "run context"})

    total = sum(item["bytes"] for item in files)
    bundle = {"schema": "gpuvulnagent-experiment-bundle/v1", "experiment": "P21R2",
              "case": "P21R2-CUDA", "trial": args.trial,
              "total_bytes": total, "limit_bytes": LIMIT_BYTES,
              "within_limit": total <= LIMIT_BYTES,
              "files": files, "skipped": skipped,
              "note": "executables are skipped only if they exceed the per-file budget; "
                      "nothing was truncated or re-hashed to fit"}
    (DEST / "bundle_manifest.json").write_text(json.dumps(bundle, ensure_ascii=False, indent=1),
                                               encoding="utf-8")
    sums = ["# SHA256 of every file in this bundle, relative to the project root.", ""]
    sums += ["%s  %s" % (item["sha256"], item["path"]) for item in files]
    (DEST / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="utf-8")
    print("files=%d bytes=%d (%.1f KB) within_limit=%s skipped=%d"
          % (len(files), total, total / 1024.0, total <= LIMIT_BYTES, len(skipped)))
    for item in skipped:
        print("  skipped %s (%d B): %s" % (item["path"], item["bytes"], item["reason"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
