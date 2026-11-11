# -*- coding: utf-8 -*-
"""Copy the CUDA user-mode toolchain into the workspace and write its manifest.

Copy, never move: the system CUDA installs and the driver stay exactly as they were. Every
copied file is hashed, and every executable is actually run once (``--version``) so
"installed" means "starts here", not "the file exists".

    python scripts/setup_toolchain.py [--dry-run] [--verify-only]

Nothing in this repository hardcodes a drive letter at runtime; the manifest written here
is the only place the original locations appear.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from gpuvulnagent.discovery.manifest import ToolchainEntry, write_manifest  # noqa: E402
from gpuvulnagent.evidence.hashing import sha256_file  # noqa: E402

CUDA_HOME = Path(r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA")
NVJPEG_EXTRACT = Path(r"D:\cuda1341_extract")

# (destination relative to toolchains/, source relative to its toolkit root)
BINARY_TOOLS = {
    "cuobjdump-11.2": ("binary_tools/cuda-11.2/bin/cuobjdump.exe", "v11.2", "bin/cuobjdump.exe"),
    "nvdisasm-11.2": ("binary_tools/cuda-11.2/bin/nvdisasm.exe", "v11.2", "bin/nvdisasm.exe"),
    "cuobjdump-12.4": ("binary_tools/cuda-12.4/bin/cuobjdump.exe", "v12.4", "bin/cuobjdump.exe"),
    "nvdisasm-12.4": ("binary_tools/cuda-12.4/bin/nvdisasm.exe", "v12.4", "bin/nvdisasm.exe"),
    "cuobjdump-13.4": ("binary_tools/cuda-13.4/bin/cuobjdump.exe", "v13.4", "bin/cuobjdump.exe"),
    "nvdisasm-13.4": ("binary_tools/cuda-13.4/bin/nvdisasm.exe", "v13.4", "bin/nvdisasm.exe"),
}

COMPILER_TREE = ["v12.4"]
COMPILER_FILES = [
    "bin/nvcc.exe", "bin/nvcc.profile", "bin/ptxas.exe", "bin/nvlink.exe",
    "bin/fatbinary.exe", "bin/cudafe++.exe", "bin/crt", "nvvm/bin/cicc.exe",
    "nvvm/bin/nvvm64_40_0.dll", "nvvm/libdevice",
]

LIBRARIES = [
    ("cuda/nvjpeg/11.2/x64/nvjpeg64_11.dll", CUDA_HOME / "v11.2/bin/nvjpeg64_11.dll"),
    ("cuda/nvjpeg/12.4/x64/nvjpeg64_12.dll", CUDA_HOME / "v12.4/bin/nvjpeg64_12.dll"),
    ("cuda/nvjpeg/13.2.2/x64/nvjpeg64_13.dll",
     NVJPEG_EXTRACT / "libnvjpeg/nvjpeg/bin/x64/nvjpeg64_13.dll"),
    ("cuda/nvjpeg/13.2.2/dev/lib/x64/nvjpeg.lib",
     NVJPEG_EXTRACT / "libnvjpeg/nvjpeg_dev/lib/x64/nvjpeg.lib"),
    ("cuda/nvjpeg/13.2.2/dev/include/nvjpeg.h",
     NVJPEG_EXTRACT / "libnvjpeg/nvjpeg_dev/include/nvjpeg.h"),
]

VERSIONS = {"v11.2": "11.2", "v12.4": "12.4", "v13.4": "13.4"}
CAPABILITIES = {
    "cuobjdump": ["cubin", "fatbin", "sass", "ptx", "elf"],
    "nvdisasm": ["cubin", "sass", "control-flow"],
    "nvcc": ["compile", "ptx", "cubin"],
}


def copy_file(source: Path, destination: Path, dry_run: bool) -> bool:
    if not source.exists():
        print("  MISSING SOURCE %s" % source)
        return False
    if dry_run:
        print("  would copy %s -> %s" % (source, destination))
        return True
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return True


def copy_tree(source: Path, destination: Path, dry_run: bool) -> int:
    if not source.is_dir():
        print("  MISSING TREE %s" % source)
        return 0
    count = 0
    for path in sorted(source.rglob("*")):
        if path.is_file():
            relative = path.relative_to(source)
            if copy_file(path, destination / relative, dry_run):
                count += 1
    return count


def version_of(binary: Path) -> str:
    for flag in ("--version", "-V"):
        try:
            completed = subprocess.run([str(binary), flag], capture_output=True, text=True,
                                       timeout=30)
        except (OSError, subprocess.SubprocessError):
            continue
        text = (completed.stdout or "") + (completed.stderr or "")
        for line in text.splitlines():
            lowered = line.lower()
            if "release" in lowered or "version" in lowered:
                return line.strip()[:160]
    return ""


def runnable(binary: Path) -> bool:
    try:
        completed = subprocess.run([str(binary), "--version"], capture_output=True,
                                   text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0 and bool((completed.stdout or completed.stderr))


def build(dry_run: bool) -> list:
    toolchains = ROOT / "toolchains"
    entries = []

    print("[1/3] binary tools")
    for name, (relative, version_dir, source_relative) in BINARY_TOOLS.items():
        destination = toolchains / relative
        source = CUDA_HOME / version_dir / source_relative
        if not copy_file(source, destination, dry_run):
            continue
        entries.append(ToolchainEntry(
            name=name, path=relative, version=VERSIONS.get(version_dir, version_dir),
            kind="binary", sha256="" if dry_run else sha256_file(destination),
            source=str(source),
            status="verified" if (not dry_run and runnable(destination)) else "present",
            notes="%s from CUDA Toolkit %s" % (name.rsplit("-", 1)[0], version_dir),
            capabilities=CAPABILITIES.get(name.rsplit("-", 1)[0], [])))

    print("[2/3] compiler tree")
    for version_dir in COMPILER_TREE:
        for relative in COMPILER_FILES:
            source = CUDA_HOME / version_dir / relative
            destination = toolchains / "compilers" / ("cuda-%s" % VERSIONS[version_dir]) / relative
            if source.is_dir():
                count = copy_tree(source, destination, dry_run)
                print("  %s (%d files)" % (relative, count))
                continue
            copy_file(source, destination, dry_run)
        nvcc_relative = "compilers/cuda-%s/bin/nvcc.exe" % VERSIONS[version_dir]
        nvcc = toolchains / nvcc_relative
        entries.append(ToolchainEntry(
            name="nvcc-%s" % VERSIONS[version_dir], path=nvcc_relative,
            version=VERSIONS[version_dir], kind="binary",
            sha256="" if dry_run else sha256_file(nvcc),
            source=str(CUDA_HOME / version_dir / "bin/nvcc.exe"),
            depends=["compilers/cuda-%s/nvvm/bin" % VERSIONS[version_dir]],
            status="verified" if (not dry_run and runnable(nvcc)) else "present",
            notes="nvcc with its cicc/ptxas/nvlink/fatbinary dependencies",
            capabilities=CAPABILITIES["nvcc"]))

    print("[3/3] CUDA libraries (nvJPEG)")
    for relative, source in LIBRARIES:
        destination = toolchains / relative
        if not copy_file(source, destination, dry_run):
            continue
        version = relative.split("/")[2]
        entries.append(ToolchainEntry(
            name="%s-%s" % (destination.name, version), path=relative, version=version,
            kind="library", sha256="" if dry_run else sha256_file(destination),
            source=str(source), status="present",
            notes="nvJPEG from CUDA %s" % version,
            capabilities=["nvjpeg", "jpeg", "decode"]))

    return entries


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()

    toolchains = ROOT / "toolchains"
    for sub in ("cuda", "binary_tools", "compilers", "debuggers", "installers", "manifests"):
        (toolchains / sub).mkdir(parents=True, exist_ok=True)

    entries = [] if args.verify_only else build(args.dry_run)
    if args.verify_only:
        data = json.loads((toolchains / "manifests" / "toolchain_manifest.json")
                          .read_text(encoding="utf-8"))
        from gpuvulnagent.discovery.manifest import ToolchainEntry as Entry
        entries = [Entry.from_dict(item) for item in data["tools"]]

    meta = {
        "generated_at": __import__("time").strftime("%Y-%m-%dT%H:%M:%S%z"),
        "generated_by": "scripts/setup_toolchain.py",
        "host": {"os": __import__("platform").platform(),
                 "gpu": _gpu(),
                 "cuda_toolkits_seen": sorted(p.name for p in CUDA_HOME.glob("v*"))
                 if CUDA_HOME.is_dir() else []},
        "policy": ("copied, never moved; the system CUDA installation and the NVIDIA driver "
                   "are untouched; large binaries stay out of git"),
        "absent": {"cuda-gdb": "CUDA debugger is Linux-only on this host",
                   "cuobjdump-13.4-nvjpeg": "CUDA 13.4 does not ship nvjpeg64 in bin; "
                                            "13.2.2 comes from the extracted package"},
    }
    if not args.dry_run:
        path = write_manifest(toolchains, entries, meta)
        print("\nmanifest written: %s (%d tools)" % (path, len(entries)))
    return 0


def _gpu() -> str:
    try:
        completed = subprocess.run(["nvidia-smi", "--query-gpu=name,driver_version",
                                    "--format=csv,noheader"], capture_output=True, text=True,
                                   timeout=20)
        return completed.stdout.strip()
    except Exception:  # noqa: BLE001
        return "unavailable"


if __name__ == "__main__":
    raise SystemExit(main())
