# -*- coding: utf-8 -*-
"""Configuration: one project root, one ``.env``, explicit precedence.

Precedence, highest first:

1. process environment variables,
2. ``.env`` in the project root,
3. ``configs/default.yaml``,
4. built-in defaults.

A ``.env`` value never overrides an environment variable that is already set, so
exporting a key in a shell is always the strongest signal. Nothing here reads a second
config file and nothing reads the legacy project.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

PROJECT_MARKERS = ("pyproject.toml", "gpuvulnagent")

DEFAULTS: Dict[str, str] = {
    "LLM_MODEL": "deepseek-chat",
    "LLM_BASE_URL": "https://api.deepseek.com",
    "LLM_TEMPERATURE": "0.2",
    "LLM_MAX_TOKENS": "8192",
    "LLM_TIMEOUT": "300",
    "LLM_MAX_ATTEMPTS": "3",
    "TOOLCHAIN_ROOT": "toolchains",
    "RESEARCH_DATA_ROOT": "research_archive",
    "ARTIFACT_ROOT": ".local/artifacts",
    "AGENT_MAX_TURNS": "12",
    "AGENT_RUN_TIMEOUT": "900",
    "SHELL_TIMEOUT": "300",
}

SECRET_NAMES = ("DEEPSEEK_API_KEY", "TAVILY_API_KEY", "LLM_API_KEY")


def find_project_root(start: Optional[Path] = None) -> Path:
    """Walk up from this file (or ``start``) to the directory holding pyproject.toml."""
    candidate = Path(start) if start is not None else Path(__file__).resolve()
    candidate = candidate.resolve()
    for parent in [candidate, *candidate.parents]:
        if all((parent / marker).exists() for marker in PROJECT_MARKERS):
            return parent
    # Editable installs and tests can live elsewhere; fall back to the package parent.
    return Path(__file__).resolve().parents[2]


def parse_env_file(path: Path) -> Dict[str, str]:
    """Minimal ``.env`` parser: KEY=VALUE, optional quotes, ``#`` comments.

    Written here rather than pulled from a dependency so the loader has no import-time
    failure mode, and so the parsing rules are visible and testable.
    """
    values: Dict[str, str] = {}
    if not Path(path).is_file():
        return values
    for raw in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or not key.replace("_", "").isalnum():
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        values[key] = value
    return values


def load_yaml_defaults(path: Path) -> Dict[str, object]:
    """Load ``configs/default.yaml`` when PyYAML and the file are both present."""
    if not Path(path).is_file():
        return {}
    try:
        import yaml
    except Exception:  # noqa: BLE001 - YAML is optional at import time
        return {}
    try:
        loaded = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise ValueError("configs/default.yaml is not valid YAML (%s)" % type(exc).__name__)
    return loaded if isinstance(loaded, dict) else {}


@dataclass
class LLMSettings:
    model: str = DEFAULTS["LLM_MODEL"]
    base_url: str = DEFAULTS["LLM_BASE_URL"]
    api_key: str = ""
    temperature: float = float(DEFAULTS["LLM_TEMPERATURE"])
    max_tokens: int = int(DEFAULTS["LLM_MAX_TOKENS"])
    timeout: int = int(DEFAULTS["LLM_TIMEOUT"])
    max_attempts: int = int(DEFAULTS["LLM_MAX_ATTEMPTS"])

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def describe(self) -> dict:
        """Never includes the key itself - only whether one is present."""
        return {"model": self.model, "base_url": self.base_url,
                "api_key_present": bool(self.api_key), "temperature": self.temperature,
                "max_tokens": self.max_tokens, "timeout": self.timeout,
                "max_attempts": self.max_attempts}


@dataclass
class PathSettings:
    project_root: Path
    toolchain_root: Path
    research_data_root: Path
    artifact_root: Path
    configs_root: Path
    data_root: Path
    runs_root: Path


@dataclass
class AgentSettings:
    max_turns: int = int(DEFAULTS["AGENT_MAX_TURNS"])
    run_timeout: int = int(DEFAULTS["AGENT_RUN_TIMEOUT"])
    shell_timeout: int = int(DEFAULTS["SHELL_TIMEOUT"])


@dataclass
class Settings:
    project_root: Path
    llm: LLMSettings = field(default_factory=LLMSettings)
    tavily_api_key: str = ""
    paths: Optional[PathSettings] = None
    agent: AgentSettings = field(default_factory=AgentSettings)
    sources: Dict[str, str] = field(default_factory=dict)

    def path(self, name: str) -> Path:
        return getattr(self.paths, name)

    def public_dict(self) -> dict:
        """Safe summary for logs and reports; no secret values."""
        return {"project_root": str(self.project_root),
                "llm": self.llm.describe(),
                "tavily": {"api_key_present": bool(self.tavily_api_key)},
                "agent": {"max_turns": self.agent.max_turns,
                          "run_timeout": self.agent.run_timeout,
                          "shell_timeout": self.agent.shell_timeout},
                "paths": {k: str(v) for k, v in vars(self.paths).items()},
                "sources": dict(self.sources)}


class ConfigLoader:
    """Resolve settings for one project root."""

    def __init__(self, project_root: Optional[Path] = None,
                 config_path: Optional[Path] = None,
                 env_path: Optional[Path] = None) -> None:
        self.project_root = Path(project_root or find_project_root()).resolve()
        self.env_path = Path(env_path) if env_path else self.project_root / ".env"
        self.config_path = (Path(config_path) if config_path
                            else self.project_root / "configs" / "default.yaml")
        self.file_values = parse_env_file(self.env_path)
        self.yaml = load_yaml_defaults(self.config_path)
        self.settings = self._build()

    # -- value resolution ------------------------------------------------
    def _get(self, name: str) -> tuple:
        """Return (value, source). Process env wins, then .env, then YAML, then default."""
        if name in os.environ and os.environ[name] != "":
            return os.environ[name], "environment"
        if self.file_values.get(name):
            return self.file_values[name], "dotenv"
        yaml_value = self._yaml_lookup(name)
        if yaml_value not in (None, ""):
            return str(yaml_value), "yaml"
        return DEFAULTS.get(name, ""), "default"

    def _yaml_lookup(self, name: str):
        flat = {"LLM_MODEL": ("llm", "model"), "LLM_BASE_URL": ("llm", "base_url"),
                "LLM_TEMPERATURE": ("llm", "temperature"),
                "LLM_MAX_TOKENS": ("llm", "max_tokens"),
                "LLM_TIMEOUT": ("llm", "timeout"),
                "LLM_MAX_ATTEMPTS": ("llm", "max_attempts"),
                "TOOLCHAIN_ROOT": ("paths", "toolchain_root"),
                "RESEARCH_DATA_ROOT": ("paths", "research_data_root"),
                "ARTIFACT_ROOT": ("paths", "artifact_root"),
                "AGENT_MAX_TURNS": ("agent", "max_turns"),
                "AGENT_RUN_TIMEOUT": ("agent", "run_timeout"),
                "SHELL_TIMEOUT": ("agent", "shell_timeout")}
        section, key = flat.get(name, ("", ""))
        node = self.yaml.get(section) if section else None
        return node.get(key) if isinstance(node, dict) else None

    def _number(self, name: str, cast, minimum=None):
        raw, source = self._get(name)
        try:
            value = cast(float(raw)) if cast is int else cast(raw)
        except (TypeError, ValueError):
            raise ValueError("%s must be a number, got %r (from %s)" % (name, raw, source))
        if minimum is not None and value < minimum:
            raise ValueError("%s must be >= %s, got %r" % (name, minimum, value))
        return value, source

    def _path(self, name: str) -> tuple:
        raw, source = self._get(name)
        candidate = Path(raw)
        return (candidate if candidate.is_absolute()
                else self.project_root / candidate), source

    def _build(self) -> Settings:
        sources: Dict[str, str] = {}
        llm = LLMSettings()
        key, llm.api_key = self._secret("DEEPSEEK_API_KEY")
        sources["DEEPSEEK_API_KEY"] = key
        llm.model, sources["LLM_MODEL"] = self._get("LLM_MODEL")
        llm.base_url, sources["LLM_BASE_URL"] = self._get("LLM_BASE_URL")
        llm.temperature, _ = self._number("LLM_TEMPERATURE", float, minimum=0)
        llm.max_tokens, _ = self._number("LLM_MAX_TOKENS", int, minimum=1)
        llm.timeout, _ = self._number("LLM_TIMEOUT", int, minimum=1)
        llm.max_attempts, _ = self._number("LLM_MAX_ATTEMPTS", int, minimum=1)

        tavily_source, tavily_key = self._secret("TAVILY_API_KEY")

        toolchain, _ = self._path("TOOLCHAIN_ROOT")
        research, _ = self._path("RESEARCH_DATA_ROOT")
        artifacts, _ = self._path("ARTIFACT_ROOT")
        paths = PathSettings(project_root=self.project_root, toolchain_root=toolchain,
                             research_data_root=research, artifact_root=artifacts,
                             configs_root=self.project_root / "configs",
                             data_root=self.project_root / "data",
                             runs_root=self.project_root / ".local" / "runs")
        agent = AgentSettings()
        agent.max_turns, _ = self._number("AGENT_MAX_TURNS", int, minimum=1)
        agent.run_timeout, _ = self._number("AGENT_RUN_TIMEOUT", int, minimum=1)
        agent.shell_timeout, _ = self._number("SHELL_TIMEOUT", int, minimum=1)
        sources["TAVILY_API_KEY"] = tavily_source
        return Settings(project_root=self.project_root, llm=llm, tavily_api_key=tavily_key,
                        paths=paths, agent=agent, sources=sources)

    def _secret(self, name: str) -> tuple:
        """Secrets are looked up but never echoed: the source is reported, not the value."""
        if os.environ.get(name):
            return "environment", os.environ[name].strip()
        if self.file_values.get(name):
            return "dotenv", self.file_values[name].strip()
        return "missing", ""

    # -- accessors --------------------------------------------------------
    @property
    def llm(self) -> LLMSettings:
        return self.settings.llm

    @property
    def agent(self) -> AgentSettings:
        return self.settings.agent

    # Convenience proxies: the CLI talks to the loader, the loader holds the settings.
    @property
    def paths(self) -> PathSettings:
        return self.settings.paths

    @property
    def tavily_api_key(self) -> str:
        return self.settings.tavily_api_key

    def public_dict(self) -> dict:
        return self.settings.public_dict()

    def missing_credentials(self) -> Dict[str, str]:
        missing = {}
        if not self.settings.llm.api_key:
            missing["DEEPSEEK_API_KEY"] = "LLM calls cannot start without it"
        if not self.settings.tavily_api_key:
            missing["TAVILY_API_KEY"] = "web_search / web_extract tools stay unregistered"
        return missing
