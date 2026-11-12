# -*- coding: utf-8 -*-
"""Archive a trimmed P19-R1 evidence bundle into research_archive/experiments/P19/.

What goes in: the environment probe, the acceptance results, and for each check the trail
manifest, the execution record, stdout/stderr and the small artifacts (sources, logs,
probe output). What does not: the toolchain, the container images, the full WSL work
directories, and anything resembling a credential.

Every archived file is hashed into ``bundle_manifest.json`` and ``SHA256SUMS.txt``, so the
bundle can be checked later without the original run directory.

    python scripts/archive_p19.py [--run-dir .local/runs/p19r1-acceptance-...]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gpuvulnagent.backends.trails import TrailStore  # noqa: E402
from gpuvulnagent.backends.wsl_docker import WslConfig, WslDockerBackend  # noqa: E402
from gpuvulnagent.config import ConfigLoader  # noqa: E402

ARCHIVE = ROOT / "research_archive" / "experiments" / "P19"
MAX_FILE_BYTES = 1_500_000
SECRET_PATTERNS = [re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
                   re.compile(r"tvly-[A-Za-z0-9_\-]{8,}"),
                   re.compile(r"(?i)authorization:\s*bearer\s+[A-Za-z0-9\-_.]{12,}")]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def assert_clean(path: Path) -> None:
    """Refuse to archive a file that appears to carry a credential."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return
    for pattern in SECRET_PATTERNS:
        if pattern.search(text):
            raise SystemExit("refusing to archive %s: it looks like it contains a credential"
                             % path)


def copy_file(source: Path, destination: Path, records: list) -> None:
    if not source.is_file():
        return
    if source.stat().st_size > MAX_FILE_BYTES:
        records.append({"source": str(source.relative_to(ROOT)).replace("\\", "/"),
                        "destination": "", "sha256": sha256(source),
                        "bytes": source.stat().st_size, "skipped": "too large"})
        return
    assert_clean(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    records.append({"source": str(source.relative_to(ROOT)).replace("\\", "/"),
                    "destination": str(destination.relative_to(ROOT)).replace("\\", "/"),
                    "sha256": sha256(destination), "bytes": destination.stat().st_size})


def pick_run_dir(explicit: str) -> Path:
    if explicit:
        return Path(explicit).resolve()
    candidates = sorted((ROOT / ".local" / "runs").glob("p19r1-acceptance-*"),
                        key=lambda path: path.stat().st_mtime, reverse=True)
    if not candidates:
        raise SystemExit("no acceptance run found; run scripts/p19r1_acceptance.py first")
    return candidates[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", default="")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    run_dir = pick_run_dir(args.run_dir)
    results_path = ROOT / ".local" / "logs" / "p19r1_acceptance.json"
    if not results_path.is_file():
        raise SystemExit("missing %s" % results_path)
    results = json.loads(results_path.read_text(encoding="utf-8"))

    if ARCHIVE.exists() and args.force:
        shutil.rmtree(ARCHIVE)
    ARCHIVE.mkdir(parents=True, exist_ok=True)
    records: list = []

    # 1. environment: probe now, so the bundle states what the machine was at archive time.
    backend = WslDockerBackend(WslConfig.from_settings(ConfigLoader()))
    probe = backend.probe(deep=True, force=True).to_dict()
    (ARCHIVE / "environment.json").write_text(
        json.dumps({"probe": probe, "backend": backend.describe(),
                    "run_dir": str(run_dir)}, ensure_ascii=False, indent=1),
        encoding="utf-8")
    records.append({"source": "probe", "destination": "research_archive/experiments/P19/"
                    "environment.json", "sha256": sha256(ARCHIVE / "environment.json"),
                    "bytes": (ARCHIVE / "environment.json").stat().st_size})

    # 2. acceptance summary (already secret-free: no keys are ever recorded there).
    copy_file(results_path, ARCHIVE / "acceptance.json", records)

    # 3. per-check evidence, taken from the trails that produced it.
    wanted = {
        "C_snapshot_two_versions": ("C_snapshot_two_versions", ["execs/exec00", "execs/exec01"]),
        "D_symlink_escape": ("D_symlink_escape", ["execs/exec00"]),
        "E_exit139_vs_sigsegv": ("E_exit139_vs_sigsegv",
                                 ["execs/exec00", "execs/exec01", "execs/exec02",
                                  "execs/exec03"]),
        "F_timeout_cleanup": ("F_timeout_cleanup", ["execs/exec00"]),
    }
    trails_root = run_dir / "trails"
    for check, (folder, exec_names) in wanted.items():
        payload = results.get(check) or {}
        trail_id = payload.get("trail")
        if not trail_id:
            continue
        trail = TrailStore(trails_root, "archive").open(trail_id)
        target_dir = ARCHIVE / "evidence" / folder / trail_id
        copy_file(trail.manifest_path, target_dir / "manifest.json", records)
        for exec_name in exec_names:
            exec_dir = trail.root / exec_name
            if not exec_dir.is_dir():
                continue
            for name in ("result.json", "snapshot.json"):
                copy_file(exec_dir / name, target_dir / exec_name / name, records)
            for log_name in ("docker_run.stdout", "docker_run.stderr"):
                copy_file(exec_dir / "logs" / log_name,
                          target_dir / exec_name / "logs" / log_name, records)
            outputs = exec_dir / "outputs"
            if outputs.is_dir():
                for path in sorted(outputs.rglob("*")):
                    if path.is_file():
                        copy_file(path, target_dir / exec_name / "outputs" /
                                  path.relative_to(outputs), records)

    # 4. the agent run: evidence log, result and final answer, no toolchain.
    agent = results.get("H_agent_end_to_end") or {}
    agent_dir = Path(agent.get("run_dir") or "")
    if agent_dir.is_dir():
        copy_file(agent_dir / "result.json", ARCHIVE / "agent" / "result.json", records)
        copy_file(agent_dir / "evidence.jsonl", ARCHIVE / "agent" / "evidence.jsonl", records)
        for trail_path in sorted((agent_dir / "trails").glob("trail*/manifest.json")):
            copy_file(trail_path, ARCHIVE / "agent" / "trails" / trail_path.parent.name /
                      "manifest.json", records)

    # 5. bundle manifest + sums
    bundle = {
        "schema": "gpuvulnagent-experiment-bundle/v1",
        "experiment": "P19-R1",
        "archived_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%S"),
        "source_run_dir": str(run_dir),
        "host": {"os": probe.get("distro"), "kernel": probe.get("kernel"),
                 "docker": (probe.get("docker") or {}).get("version"),
                 "gpu": (probe.get("gpu") or {}).get("name"),
                 "compute_capability": (probe.get("gpu") or {}).get("compute_capability"),
                 "cuda": (probe.get("cuda") or {}).get("toolkit")},
        "checks": {key: {"status": value.get("status")}
                   for key, value in results.items() if isinstance(value, dict)},
        "files": [item for item in records if item.get("destination")],
        "skipped": [item for item in records if not item.get("destination")],
        "policy": ("trimmed bundle: environment, acceptance results, trail manifests, "
                   "execution records, stdout/stderr and small artifacts; no toolchain, "
                   "no container filesystem, no credentials"),
    }
    (ARCHIVE / "bundle_manifest.json").write_text(
        json.dumps(bundle, ensure_ascii=False, indent=1), encoding="utf-8")
    lines = ["# SHA256 of every file in this bundle, relative to the project root.", ""]
    for item in sorted(bundle["files"], key=lambda entry: entry["destination"]):
        lines.append("%s  %s" % (item["sha256"], item["destination"]))
    (ARCHIVE / "SHA256SUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("archived %d files (%.1f KB) into %s"
          % (len(bundle["files"]),
             sum(item["bytes"] for item in bundle["files"]) / 1024.0, ARCHIVE))
    print("skipped %d large files" % len(bundle["skipped"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
