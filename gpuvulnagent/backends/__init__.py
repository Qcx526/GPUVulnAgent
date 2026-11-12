# -*- coding: utf-8 -*-
"""Execution backends: where an experiment physically runs.

Windows cannot run a CUDA Linux binary, and an agent that can only run Windows commands
cannot study GPU user-space code. The backend in this package reaches WSL2, drives Docker
with an allow-listed option set, and returns the same evidence shape as the local runner,
so the agent does not need to know which machine a tool executed on.
"""

from .base import Artifact, Backend, BackendError, BackendUnavailable, EnvironmentReport, \
    ExecResult, ToolStatus
from .trails import Trail, TrailError, TrailStore
from .wsl_docker import WslConfig, WslDockerBackend, windows_to_wsl

__all__ = ["Artifact", "Backend", "BackendError", "BackendUnavailable",
           "EnvironmentReport", "ExecResult", "ToolStatus", "Trail", "TrailError",
           "TrailStore", "WslConfig", "WslDockerBackend", "windows_to_wsl"]
