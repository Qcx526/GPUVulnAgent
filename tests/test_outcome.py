# -*- coding: utf-8 -*-
"""Termination classification: the P18 crash-counting defect, pinned by tests."""

from __future__ import annotations

import pytest

from gpuvulnagent.evidence.outcome import CRASH_KINDS, classify_termination


def test_success_and_plain_failure():
    assert classify_termination(0)["kind"] == "success"
    plain = classify_termination(1)
    assert plain["kind"] == "error_exit"
    assert plain["crash"] is False


def test_timeout_is_not_a_crash():
    result = classify_termination(-9, timed_out=True)
    assert result["kind"] == "timeout"
    assert result["crash"] is False


def test_missing_executable_is_not_a_crash():
    result = classify_termination(-2, launch_error="[WinError 2] No such file or directory")
    assert result["kind"] == "not_found"
    assert result["crash"] is False


def test_real_signals_are_crashes():
    assert classify_termination(-11)["kind"] == "sigsegv"
    assert classify_termination(-6)["kind"] == "sigabrt"
    assert classify_termination(-7)["kind"] == "sigbus"
    for code in (-11, -6, -7):
        assert classify_termination(code)["crash"] is True


def test_windows_structured_exceptions():
    assert classify_termination(0xC0000005)["kind"] == "sigsegv"
    assert classify_termination(0xC0000409)["kind"] == "sigabrt"
    assert classify_termination(0xC00000FD)["kind"] == "windows_seh"
    assert classify_termination(0xC00000FD)["crash"] is True
    assert classify_termination(0xC0000135)["kind"] == "not_runnable"
    assert classify_termination(0xC0000135)["crash"] is False


def test_every_crash_kind_is_in_the_allowed_set():
    for code in (-11, -6, -7, -4, -8, 0xC0000005, 0xC0000409):
        kind = classify_termination(code)["kind"]
        if classify_termination(code)["crash"]:
            assert kind in CRASH_KINDS


@pytest.mark.parametrize("code", [-9, -2, 0, 1, 2, 127, 0xC0000135])
def test_non_fault_terminations_are_never_crashes(code):
    assert classify_termination(code)["crash"] is False
