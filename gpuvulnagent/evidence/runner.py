# -*- coding: utf-8 -*-
"""Process runner: start a command, capture what actually happened, classify how it ended.

Three facts are recorded separately because they answer different questions:

* did the executable start at all (``termination.kind == not_found``),
* did the harness stop it (``timeout``),
* did the process die of a fault (``sigsegv`` and friends).

The runner also honours a wall-clock deadline handed down from the runtime: a benchmark
budget is only real if something enforces it.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

from .log import EvidenceLog
from .outcome import LAUNCH_FAILED, TIMEOUT_KILLED, classify_termination
from .redact import redact

DEFAULT_TIMEOUT = 300
MAX_TIMEOUT = 3600
PREVIEW_STDOUT = 4000
PREVIEW_STDERR = 2000


class Runner:
    def __init__(self, workspace: Path, log: EvidenceLog, timeout: int = DEFAULT_TIMEOUT,
                 deadline: Optional[float] = None) -> None:
        self.workspace = Path(workspace)
        self.log = log
        self.timeout = clamp_timeout(timeout) or DEFAULT_TIMEOUT
        # monotonic deadline shared with the runtime, so the loop and the processes it
        # spawns agree on when the budget is gone
        self.deadline = deadline

    def remaining(self) -> Optional[float]:
        if self.deadline is None:
            return None
        return self.deadline - time.monotonic()

    def run(self, argv: List[str], cwd: Optional[Path] = None,
            env_extra: Optional[dict] = None, timeout: Optional[int] = None,
            label: str = "shell", via: str = "shell") -> dict:
        limit = clamp_timeout(timeout) or self.timeout
        remaining = self.remaining()
        if remaining is not None:
            # Never let one command outlive the run budget.
            limit = max(1, int(min(limit, remaining))) if remaining > 0 else 1
        cwd_path = Path(cwd or self.workspace)
        env = dict(os.environ)
        env.update(env_extra or {})
        started = time.time()
        timed_out, launch_error, exit_code = False, "", None
        stdout, stderr = "", ""

        try:
            proc = subprocess.Popen([str(a) for a in argv], cwd=str(cwd_path),
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    text=True, errors="replace", env=env)
        except FileNotFoundError as exc:
            proc, launch_error, exit_code = None, str(exc), LAUNCH_FAILED
        except OSError as exc:
            proc, launch_error, exit_code = None, "%s: %s" % (type(exc).__name__, exc), LAUNCH_FAILED

        if proc is not None:
            try:
                stdout, stderr = proc.communicate(timeout=limit)
                exit_code = proc.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill_tree(proc)
                try:
                    stdout, stderr = proc.communicate(timeout=15)
                except subprocess.TimeoutExpired:
                    # The tree refused to die; keep what we have rather than blocking.
                    stdout, stderr = stdout or "", stderr or ""
                exit_code = TIMEOUT_KILLED
                stderr = (stderr or "") + "\ntimeout after %ds; process tree killed" % limit

        stdout, out_hits = redact(stdout or "")
        stderr, err_hits = redact(stderr or "")
        termination = classify_termination(exit_code, timed_out=timed_out,
                                           launch_error=launch_error)
        status = _status_for(termination["kind"])

        artifacts = []
        if self.log.artifacts is not None:
            stamp = time.strftime("%H%M%S") + "-%03d" % (int(time.time() * 1000) % 1000)
            artifacts.append(self.log.artifacts.save(
                "stdout", "%s-%s.out" % (label, stamp), stdout))
            artifacts.append(self.log.artifacts.save(
                "stderr", "%s-%s.err" % (label, stamp), stderr))

        duration_ms = int((time.time() - started) * 1000)
        record = {
            "tool_name": label,
            "via": via,
            "argv": [str(a) for a in argv],
            "cwd": str(cwd_path),
            "exit": exit_code,
            "duration_ms": duration_ms,
            "timed_out": timed_out,
            "timeout_seconds": limit,
            "termination": termination,
            "crash": bool(termination["crash"]),
            "stdout_preview": stdout[:PREVIEW_STDOUT],
            "stderr_preview": stderr[:PREVIEW_STDERR],
            "stdout_bytes": len(stdout),
            "stderr_bytes": len(stderr),
            "truncated": len(stdout) > PREVIEW_STDOUT or len(stderr) > PREVIEW_STDERR,
            "redactions": out_hits + err_hits,
            "artifacts": artifacts,
            "environment": {"os": platform.platform(), "python": sys.version.split()[0]},
        }
        return self.log.append("exec", record, status=status)


def _status_for(kind: str) -> str:
    if kind == "success":
        return "success"
    if kind == "timeout":
        return "timeout"
    if kind in ("not_found", "not_runnable"):
        return "launch_failed"
    if kind in ("sigsegv", "sigabrt", "sigbus", "sigill", "sigfpe", "windows_seh",
                "other_signal"):
        return "crashed"
    return "failed"


def _kill_tree(proc) -> None:
    """Kill the process and everything it spawned; a shell wrapper leaks children."""
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                       capture_output=True, check=False)
        return
    try:
        proc.kill()
    except Exception:  # noqa: BLE001 - already gone
        pass


def clamp_timeout(value) -> Optional[int]:
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    return min(seconds, MAX_TIMEOUT)
