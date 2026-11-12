# -*- coding: utf-8 -*-
"""Configuration: one .env, explicit precedence, no secret ever echoed."""

from __future__ import annotations

from pathlib import Path

import pytest

from gpuvulnagent.config import ConfigLoader
from gpuvulnagent.config.loader import parse_env_file


def test_dotenv_is_read_and_environment_wins(project: Path, monkeypatch):
    (project / ".env").write_text("DEEPSEEK_API_KEY=from-dotenv\nLLM_MODEL=model-from-dotenv\n",
                                  encoding="utf-8")
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    loader = ConfigLoader(project_root=project)
    assert loader.llm.api_key == "from-dotenv"
    assert loader.llm.model == "model-from-dotenv"
    assert loader.settings.sources["DEEPSEEK_API_KEY"] == "dotenv"

    monkeypatch.setenv("DEEPSEEK_API_KEY", "from-process-env")
    assert ConfigLoader(project_root=project).llm.api_key == "from-process-env"
    assert ConfigLoader(project_root=project).settings.sources["DEEPSEEK_API_KEY"] == "environment"


def test_yaml_is_the_third_source(project: Path, monkeypatch):
    for name in ("LLM_MODEL", "LLM_TIMEOUT"):
        monkeypatch.delenv(name, raising=False)
    loader = ConfigLoader(project_root=project)
    assert loader.llm.model == "test-model"          # from configs/default.yaml
    assert loader.llm.timeout == 300                  # from built-in default


def test_env_parser_handles_quotes_comments_and_export(tmp_path: Path):
    path = tmp_path / ".env"
    path.write_text("\n".join([
        "# comment",
        "export DEEPSEEK_API_KEY='sk-quoted-value'",
        'LLM_MODEL="model with spaces"',
        "EMPTY=",
        "PLAIN=value  # trailing comment",
        "not a pair",
    ]), encoding="utf-8")
    values = parse_env_file(path)
    assert values["DEEPSEEK_API_KEY"] == "sk-quoted-value"
    assert values["LLM_MODEL"] == "model with spaces"
    assert values["PLAIN"] == "value"
    assert "not a pair" not in values


def test_missing_credentials_are_reported_not_invented(project: Path, monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("TAVILY_API_KEY", raising=False)
    loader = ConfigLoader(project_root=project)
    missing = loader.missing_credentials()
    assert "DEEPSEEK_API_KEY" in missing
    assert "TAVILY_API_KEY" in missing
    assert loader.llm.configured is False
    # describe() must never contain the value
    assert "api_key" not in loader.llm.describe()
    assert loader.llm.describe()["api_key_present"] is False


def test_bad_number_is_an_error_not_a_silent_default(project: Path, monkeypatch):
    monkeypatch.setenv("LLM_TIMEOUT", "not-a-number")
    with pytest.raises(ValueError):
        ConfigLoader(project_root=project)


def test_paths_resolve_against_project_root(project: Path):
    loader = ConfigLoader(project_root=project)
    assert loader.settings.paths.toolchain_root == project / "toolchains"
    assert loader.settings.paths.research_data_root == project / "research_archive"


def test_backend_settings_come_from_the_environment(project: Path, monkeypatch):
    monkeypatch.setenv("WSL_DISTRO", "Ubuntu-24.04")
    monkeypatch.setenv("WSL_USER", "researcher")
    monkeypatch.setenv("GPU_IMAGE", "nvidia/cuda:13.0.0-devel-ubuntu24.04")
    monkeypatch.setenv("WSL_CALL_TIMEOUT", "77")
    monkeypatch.setenv("GPU_PULL_POLICY", "always")
    monkeypatch.setenv("GPU_BACKEND_ENABLED", "0")
    loader = ConfigLoader(project_root=project)
    assert loader.backend.wsl_distro == "Ubuntu-24.04"
    assert loader.backend.wsl_user == "researcher"
    assert loader.backend.gpu_image.endswith("13.0.0-devel-ubuntu24.04")
    assert loader.backend.call_timeout == 77
    assert loader.backend.pull_policy == "always"
    assert loader.backend.enabled is False
    assert loader.settings.public_dict()["backend"]["pull_policy"] == "always"


def test_invalid_pull_policy_is_rejected(project: Path, monkeypatch):
    monkeypatch.setenv("GPU_PULL_POLICY", "sometimes")
    with pytest.raises(ValueError):
        ConfigLoader(project_root=project)
