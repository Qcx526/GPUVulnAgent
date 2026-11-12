# -*- coding: utf-8 -*-
"""Execution backend contract.

A backend answers three questions and nothing else:

1. what can this machine actually run (``probe``),
2. run this argv in that environment and tell me exactly what happened (``exec``),
3. where did the bytes go (``stage`` / ``collect``).

It deliberately has no notion of a vulnerability, a PoC generator or a test plan. Those
belong to the agent. Anything a backend decides about *what* to run would make the agent a
pipeline again, which is the thing this project exists to avoid.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Protocol


class BackendError(RuntimeError):
    """The backend could not carry out the request at all (transport, configuration)."""


class BackendUnavailable(BackendError):
    """The environment the backend needs is not present. Not a target failure."""


@dataclass
class ToolStatus:
    name: str
    status: str = "missing"          # ok | missing | not_runnable
    path: str = ""
    version: str = ""
    detail: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "status": self.status, "path": self.path,
                "version": self.version, "detail": self.detail}


@dataclass
class EnvironmentReport:
    backend: str = "wsl2_docker"
    available: bool = False
    distro: str = ""
    distro_version: str = ""
    kernel: str = ""
    user: str = ""
    docker_version: str = ""
    docker_running: bool = False
    gpu_name: str = ""
    gpu_memory: str = ""
    compute_capability: str = ""
    driver_version: str = ""
    cuda_version: str = ""
    tools: Dict[str, ToolStatus] = field(default_factory=dict)
    images: List[str] = field(default_factory=list)
    gpu_in_container: Dict = field(default_factory=dict)
    problems: List[str] = field(default_factory=list)
    raw: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"backend": self.backend, "available": self.available,
                "distro": self.distro, "distro_version": self.distro_version,
                "kernel": self.kernel, "user": self.user,
                "docker": {"version": self.docker_version, "running": self.docker_running},
                "gpu": {"name": self.gpu_name, "memory": self.gpu_memory,
                        "compute_capability": self.compute_capability,
                        "driver": self.driver_version},
                "cuda": {"toolkit": self.cuda_version},
                "tools": {name: tool.to_dict() for name, tool in self.tools.items()},
                "images": list(self.images), "gpu_in_container": dict(self.gpu_in_container),
                "problems": list(self.problems)}


@dataclass
class Artifact:
    name: str
    sha256: str
    bytes: int
    kind: str = "output"             # input | output | log
    source: str = "container"

    def to_dict(self) -> dict:
        return {"name": self.name, "sha256": self.sha256, "bytes": self.bytes,
                "kind": self.kind, "source": self.source}


@dataclass
class ExecResult:
    ok: bool = False
    exit_code: Optional[int] = None
    timed_out: bool = False
    oom_killed: bool = False
    termination: Dict = field(default_factory=dict)
    duration_ms: int = 0
    started_at: str = ""
    finished_at: str = ""
    image: str = ""
    image_id: str = ""
    image_digest: str = ""
    container_id: str = ""
    container_name: str = ""
    argv: List[str] = field(default_factory=list)
    cwd: str = ""
    workdir: str = ""
    network: str = "none"
    gpu: bool = False
    gpu_name: str = ""
    cuda_version: str = ""
    stdout: str = ""
    stderr: str = ""
    stdout_artifact: Dict = field(default_factory=dict)
    stderr_artifact: Dict = field(default_factory=dict)
    artifacts: List[Artifact] = field(default_factory=list)
    trail: str = ""
    run_id: str = ""
    state: str = ""
    error: str = ""

    def to_dict(self) -> dict:
        return {"ok": self.ok, "exit_code": self.exit_code, "timed_out": self.timed_out,
                "oom_killed": self.oom_killed, "termination": self.termination,
                "duration_ms": self.duration_ms, "started_at": self.started_at,
                "finished_at": self.finished_at, "image": self.image,
                "image_id": self.image_id, "image_digest": self.image_digest,
                "container_id": self.container_id, "container_name": self.container_name,
                "argv": list(self.argv), "cwd": self.cwd, "workdir": self.workdir,
                "network": self.network, "gpu": self.gpu, "gpu_name": self.gpu_name,
                "cuda_version": self.cuda_version,
                "stdout_preview": self.stdout[:4000], "stderr_preview": self.stderr[:2000],
                "stdout_artifact": dict(self.stdout_artifact),
                "stderr_artifact": dict(self.stderr_artifact),
                "artifacts": [item.to_dict() for item in self.artifacts],
                "trail": self.trail, "run_id": self.run_id, "state": self.state,
                "error": self.error}


class Backend(Protocol):
    name: str

    def probe(self, *, deep: bool = False) -> EnvironmentReport: ...
    def exec(self, **kwargs) -> ExecResult: ...
