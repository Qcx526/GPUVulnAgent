# -*- coding: utf-8 -*-
"""Container exit classification: only a target fault is a crash."""

from __future__ import annotations

import pytest

from gpuvulnagent.evidence.container_outcome import classify_container_exit, is_container_crash
from gpuvulnagent.evidence.outcome import CRASH_KINDS


def test_success_is_success():
    result = classify_container_exit(0)
    assert result["kind"] == "success"
    assert result["crash"] is False


def test_docker_and_shell_codes_are_not_crashes():
    assert classify_container_exit(125)["kind"] == "container_error"
    assert classify_container_exit(126)["kind"] == "not_runnable"
    assert classify_container_exit(127)["kind"] == "not_found"
    for code in (125, 126, 127, 1, 2, 3):
        assert classify_container_exit(code)["crash"] is False


def test_timeout_and_oom_are_not_crashes():
    timeout = classify_container_exit(137, timed_out=True)
    assert timeout["kind"] == "timeout"
    assert timeout["crash"] is False

    oom = classify_container_exit(137, oom_killed=True)
    assert oom["kind"] == "oom_killed"
    assert oom["crash"] is False


def test_sigkill_without_a_reason_is_not_a_crash():
    result = classify_container_exit(137)
    assert result["kind"] == "killed"
    assert result["crash"] is False


def test_target_signals_are_crashes():
    expectations = {139: "sigsegv", 134: "sigabrt", 135: "sigbus", 132: "sigill", 136: "sigfpe"}
    for code, kind in expectations.items():
        result = classify_container_exit(code)
        assert result["kind"] == kind, (code, result)
        assert result["crash"] is True
        assert kind in CRASH_KINDS


def test_runtime_hook_failure_is_a_container_error_not_a_crash():
    result = classify_container_exit(128, daemon_error=True)
    assert result["kind"] == "container_error"
    assert result["crash"] is False


def test_missing_status_and_missing_container():
    assert classify_container_exit(None)["kind"] == "unknown"
    assert classify_container_exit(None, started=False)["kind"] == "container_error"


def test_plain_nonzero_is_an_error_exit():
    result = classify_container_exit(42)
    assert result["kind"] == "error_exit"
    assert result["crash"] is False


@pytest.mark.parametrize("code", [0, 1, 125, 126, 127, 137, 143])
def test_non_fault_codes_never_report_crash(code):
    assert is_container_crash(classify_container_exit(code)["kind"]) is False
