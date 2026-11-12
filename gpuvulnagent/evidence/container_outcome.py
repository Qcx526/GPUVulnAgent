# -*- coding: utf-8 -*-
"""Container termination classification.

Docker exits with ``128 + N`` when the process inside the container died of signal ``N``,
and reserves a few low codes for its own failures. Treating "not zero" as a crash is the
same mistake P18 made on the Windows side, one layer down: a ``docker run`` that could not
find the program (127), a command that was not executable (126), a daemon error (125) and a
container we killed at the deadline (137) all look like failures and none of them is a
target crash.

Only a signal that means the *target* faulted counts: SIGSEGV, SIGABRT, SIGBUS, SIGILL,
SIGFPE. OOM kills and harness timeouts are reported separately, because they say something
about the budget or the machine, not about the vulnerability.
"""

from __future__ import annotations

from typing import Optional

from .outcome import CRASH_KINDS

DOCKER_DAEMON_ERROR = 125
COMMAND_NOT_EXECUTABLE = 126
COMMAND_NOT_FOUND = 127

# 128 + signal -> kind
CONTAINER_SIGNALS = {
    4: "sigill",          # SIGILL
    6: "sigabrt",         # SIGABRT
    7: "sigbus",          # SIGBUS
    8: "sigfpe",          # SIGFPE
    9: "killed",          # SIGKILL: timeout, OOM, or an operator
    11: "sigsegv",        # SIGSEGV
    13: "other_signal",   # SIGPIPE
    15: "other_signal",   # SIGTERM
}

CONTAINER_KINDS = frozenset({"success", "timeout", "oom_killed", "container_error",
                             "not_found", "not_runnable", "killed", "error_exit",
                             "other_signal", "unknown"} | set(CRASH_KINDS))


def classify_container_exit(exit_code: Optional[int], *, timed_out: bool = False,
                            oom_killed: bool = False, state: str = "",
                            started: bool = True, daemon_error: bool = False) -> dict:
    """Classify one container run. Never returns ``crash`` for a harness-side event."""
    if not started:
        return {"kind": "container_error", "crash": False,
                "detail": state or "the container did not start"}
    if timed_out:
        return {"kind": "timeout", "crash": False,
                "detail": "harness killed the container at the deadline"}
    if oom_killed:
        return {"kind": "oom_killed", "crash": False,
                "detail": "the kernel OOM killer ended the container (limit, not a bug)"}
    if daemon_error:
        # A hook/runtime failure aborts the container before the target runs; its exit code
        # says nothing about the program under test.
        return {"kind": "container_error", "crash": False,
                "detail": "docker could not start the container (runtime or GPU hook error)"}
    if exit_code is None:
        return {"kind": "unknown", "crash": False,
                "detail": "no exit status was reported by the daemon"}

    code = int(exit_code)
    if code == 0:
        return {"kind": "success", "crash": False, "detail": "exit 0"}
    if code == DOCKER_DAEMON_ERROR:
        return {"kind": "container_error", "crash": False,
                "detail": "docker could not run the container (125)"}
    if code == COMMAND_NOT_EXECUTABLE:
        return {"kind": "not_runnable", "crash": False,
                "detail": "the command inside the container is not executable (126)"}
    if code == COMMAND_NOT_FOUND:
        return {"kind": "not_found", "crash": False,
                "detail": "the command was not found inside the container (127)"}
    if 128 < code <= 128 + 64:
        signal_number = code - 128
        kind = CONTAINER_SIGNALS.get(signal_number, "other_signal")
        return {"kind": kind, "crash": kind in CRASH_KINDS,
                "detail": "container process terminated by signal %d" % signal_number}
    return {"kind": "error_exit", "crash": False,
            "detail": "normal non-zero exit %d" % code}


def is_container_crash(kind: str) -> bool:
    return kind in CRASH_KINDS


# Signal numbers as they appear in the supervisor's status file.
SIGNAL_KINDS = {
    4: "sigill", 6: "sigabrt", 7: "sigbus", 8: "sigfpe", 11: "sigsegv",
    9: "killed", 13: "other_signal", 15: "other_signal",
}


def classify_container_result(*, exit_code: Optional[int], timed_out: bool = False,
                              oom_killed: bool = False, state: str = "",
                              started: bool = True, daemon_error: bool = False,
                              supervision: Optional[dict] = None) -> dict:
    """Classify a run using the supervisor's evidence, not just the exit status.

    ``exit(139)`` and SIGSEGV both leave 139 behind. If the supervisor reported that the
    child *exited* with 139, that is a normal exit and is recorded as one. If the
    supervisor is missing, the number proves nothing, so the run is marked
    ``unverified_signal`` and is never reported as a crash.
    """
    supervision = supervision or {}
    base = classify_container_exit(exit_code, timed_out=timed_out, oom_killed=oom_killed,
                                   state=state, started=started, daemon_error=daemon_error)
    base.setdefault("signal_verified", False)
    if base["kind"] in ("timeout", "oom_killed", "container_error", "unknown"):
        return base

    used = bool(supervision.get("used"))
    readable = bool(supervision.get("readable"))
    if used and readable:
        if supervision.get("signaled"):
            number = int(supervision.get("signal") or 0)
            kind = SIGNAL_KINDS.get(number, "other_signal")
            return {"kind": kind, "crash": kind in CRASH_KINDS,
                    "detail": "supervisor: child terminated by signal %d (%s)"
                              % (number, supervision.get("signal_name") or "?"),
                    "signal_verified": True, "signaled": True, "signal": number,
                    "signal_name": supervision.get("signal_name") or ""}
        code = supervision.get("exit_code")
        if code is None:
            code = exit_code
        # A reported normal exit is authoritative, including 139.
        detail = "supervisor: child exited with code %s" % code
        if code in (139, 134, 132, 135, 136):
            detail += " (a normal exit, not a signal)"
        return {"kind": "success" if code == 0 else "error_exit", "crash": False,
                "detail": detail, "signal_verified": True, "signaled": False,
                "signal": 0, "signal_name": ""}

    if isinstance(exit_code, int) and 128 < exit_code < 160:
        return {"kind": "unverified_signal", "crash": False,
                "detail": ("exit %d is in the signal range but no supervisor status was "
                           "recorded; refusing to call it a crash" % exit_code),
                "signal_verified": False, "signaled": False, "signal": 0,
                "signal_name": ""}

    return base
