# -*- coding: utf-8 -*-
"""JPEG adapter package."""

from .adapter import AdapterError, apply_plan, inspect_bytes, inspect_file, plan_dimensions, \
    validate_pair, walk_segments
from .tools import build_tools

__all__ = ["AdapterError", "apply_plan", "build_tools", "inspect_bytes", "inspect_file",
           "plan_dimensions", "validate_pair", "walk_segments"]
