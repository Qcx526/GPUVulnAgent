# -*- coding: utf-8 -*-
"""Shared test fixtures: a throwaway project root, no network, no real credentials."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from gpuvulnagent.config import ConfigLoader  # noqa: E402


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A minimal project root: configs, research archive, toolchain root, data."""
    for relative in ("configs", "research_archive/memory/global", "research_archive/memory/cases",
                     "toolchains/manifests", "data/cases", ".local/runs"):
        (tmp_path / relative).mkdir(parents=True, exist_ok=True)
    (tmp_path / "configs" / "default.yaml").write_text(
        "llm:\n  model: test-model\n  base_url: https://example.invalid\n"
        "agent:\n  max_turns: 3\n  run_timeout: 60\n  shell_timeout: 30\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def settings(project: Path) -> ConfigLoader:
    return ConfigLoader(project_root=project)


@pytest.fixture
def no_credentials(monkeypatch: pytest.MonkeyPatch):
    """Make sure a developer's own .env cannot leak into a unit test."""
    for name in ("DEEPSEEK_API_KEY", "TAVILY_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    return True
