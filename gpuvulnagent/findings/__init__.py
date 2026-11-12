# -*- coding: utf-8 -*-
"""Findings: the second research track.

The agent is given a CVE to reproduce. While doing that it may see something the CVE does
not explain. That observation must not be folded into the CVE result, and it must not be
thrown away either, so it becomes a finding with its own id, its own report and its own
statistics.
"""

from .model import CRASH_CLASSES, Finding, render_report
from .store import FindingError, FindingStore

__all__ = ["CRASH_CLASSES", "Finding", "FindingError", "FindingStore", "render_report"]
