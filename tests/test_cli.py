# -*- coding: utf-8 -*-
"""CLI: usable without credentials, honest when credentials are missing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gpuvulnagent.cli import main


def test_tools_lists_the_catalog_without_any_credential(project: Path, capsys, monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    code = main(["--project-root", str(project), "tools", "--search", "jpeg"])
    output = capsys.readouterr().out
    assert code == 0
    assert "jpeg_inspect" in output


def test_run_without_credentials_fails_loudly(project: Path, capsys, monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    code = main(["--project-root", str(project), "run", "--goal", "试一试"])
    captured = capsys.readouterr()
    assert code == 3
    assert "DEEPSEEK_API_KEY" in captured.err


def test_doctor_reports_missing_credentials_and_toolchain(project: Path, capsys,
                                                          monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    code = main(["--project-root", str(project), "doctor"])
    report = json.loads(capsys.readouterr().out)
    assert code == 1
    assert "DEEPSEEK_API_KEY" in report["missing_credentials"]
    assert report["toolchain"]["tools"] == []
    assert "catalog" in report


def test_verify_reports_a_clean_chain(project: Path, capsys):
    from gpuvulnagent.evidence import ArtifactStore, EvidenceLog

    run_dir = project / ".local" / "runs" / "verify-me"
    log = EvidenceLog(run_dir / "evidence.jsonl", "run-v",
                      ArtifactStore(run_dir / "artifacts"))
    log.append("start", {"goal_sha256": "x"})
    code = main(["--project-root", str(project), "verify", "--run", str(run_dir)])
    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert report["ok"] is True


def test_no_command_prints_help(project: Path, capsys):
    assert main(["--project-root", str(project)]) == 2
    assert "usage" in capsys.readouterr().out.lower()
