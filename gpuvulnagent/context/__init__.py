# -*- coding: utf-8 -*-
"""Context package: prompt assembly and observation rendering."""

from .observation import compact, render
from .prompts import SYSTEM, budget_note, initial_message, resume_section

__all__ = ["SYSTEM", "budget_note", "compact", "initial_message", "render", "resume_section"]
