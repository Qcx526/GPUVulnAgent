# -*- coding: utf-8 -*-
"""Termination classification.

P18 counted every negative exit code as a crash, which made a missing executable (-2) and
a killed timeout (-9) look like memory corruption. Classification is now explicit:

===============  =====================================================================
kind             meaning
===============  =====================================================================
not_found        the executable could not be started at all
not_runnable     the file exists but the OS refused to execute it
timeout          the harness killed the process tree at the deadline
sigsegv          SIGSEGV / 0xC0000005 access violation - the crash we care about
sigabrt          SIGABRT / 0xC0000409 fast fail / abort()
sigbus           SIGBUS / misaligned or bad address
sigill           SIGILL / 0xC000001D illegal instruction
sigfpe           SIGFPE / 0xC0000094 integer division by zero
windows_seh      other Windows structured exceptions (stack overflow, heap corruption)
other_signal     any other terminating signal
disk_error       exit code planted by the runner itself when output capture failed
error_exit       a normal non-zero exit: a failed check, not a crash
success          exit code 0
===============  =====================================================================

Only ``sigsegv``, ``sigabrt``, ``sigbus``, ``sigill``, ``sigfpe`` and ``windows_seh``
count as ``CRASH_OBSERVED``. Timeouts and launch failures are reported separately,
because they say something about the harness, not about the target.
"""

from __future__ import annotations

import platform
from typing import Optional

CRASH_KINDS = frozenset({"sigsegv", "sigabrt", "sigbus", "sigill", "sigfpe", "windows_seh"})

# exit code planted by Runner when the OS refuses to start the process
LAUNCH_FAILED = -2
# exit code planted by Runner after killing a timed-out process tree
TIMEOUT_KILLED = -9

WINDOWS_SEH = {
    0xC0000005: "sigsegv",          # access violation
    0xC0000006: "sigsegv",          # in-page error
    0xC000001D: "sigill",           # illegal instruction
    0xC0000025: "sigabrt",          # noncontinuable exception
    0xC000008C: "sigsegv",          # array bounds exceeded
    0xC0000094: "sigfpe",           # integer division by zero
    0xC0000095: "sigfpe",           # integer overflow
    0xC0000096: "windows_seh",      # privileged instruction
    0xC00000FD: "windows_seh",      # stack overflow
    0xC0000135: "not_runnable",     # DLL not found
    0xC0000139: "not_runnable",     # entry point not found
    0xC0000142: "not_runnable",     # DLL initialisation failed
    0xC0000374: "windows_seh",      # heap corruption
    0xC0000409: "sigabrt",          # stack buffer overrun / fast fail
    0xC000041D: "windows_seh",      # unhandled exception in callback
    0xC0000602: "windows_seh",      # fail-fast exception
}

POSIX_SIGNALS = {
    4: "sigill",
    6: "sigabrt",
    7: "sigbus",
    8: "sigfpe",
    9: "timeout",                   # SIGKILL is how the harness ends a timeout
    11: "sigsegv",
    15: "other_signal",
}


def classify_termination(exit_code: Optional[int], *, timed_out: bool = False,
                         launch_error: str = "", os_name: Optional[str] = None) -> dict:
    """Map an exit status to one explicit kind plus a human-readable detail."""
    os_name = os_name or platform.system().lower()
    if launch_error:
        kind = "not_found" if "No such file" in launch_error or "not found" in launch_error.lower() \
            else "not_runnable"
        return {"kind": kind, "crash": False, "detail": launch_error[:200]}
    if timed_out:
        return {"kind": "timeout", "crash": False,
                "detail": "harness killed the process tree at the deadline"}

    if exit_code is None:
        return {"kind": "disk_error", "crash": False, "detail": "no exit status recorded"}

    code = int(exit_code)
    if code == 0:
        return {"kind": "success", "crash": False, "detail": "exit 0"}
    if code == LAUNCH_FAILED:
        return {"kind": "not_found", "crash": False,
                "detail": "executable could not be started"}
    if code == TIMEOUT_KILLED:
        return {"kind": "timeout", "crash": False, "detail": "process tree killed"}

    if code < 0:
        signal_number = -code
        kind = POSIX_SIGNALS.get(signal_number, "other_signal")
        return {"kind": kind, "crash": kind in CRASH_KINDS,
                "detail": "terminated by signal %d" % signal_number}

    if os_name.startswith("win") or code >= 0xC0000000:
        if code >= 0xC0000000:
            kind = WINDOWS_SEH.get(code, "windows_seh")
            return {"kind": kind, "crash": kind in CRASH_KINDS,
                    "detail": "windows exception 0x%08X" % code}
    return {"kind": "error_exit", "crash": False, "detail": "normal non-zero exit %d" % code}


def is_crash(kind: str) -> bool:
    return kind in CRASH_KINDS
