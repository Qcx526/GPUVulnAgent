# -*- coding: utf-8 -*-
"""Secret redaction: nothing key-shaped reaches disk, a prompt or a report."""

from __future__ import annotations

import re

SECRET_PATTERNS = [
    (re.compile(r"sk-[A-Za-z0-9_\-]{16,}"), "sk-***REDACTED***"),
    (re.compile(r"tvly-[A-Za-z0-9_\-]{8,}"), "tvly-***REDACTED***"),
    (re.compile(r"(api[_-]?key\s*[=:]\s*[\"']?)[A-Za-z0-9\-_]{12,}", re.I),
     r"\1***REDACTED***"),
    (re.compile(r"(Authorization:\s*Bearer\s+)[A-Za-z0-9\-_.]{12,}", re.I),
     r"\1***REDACTED***"),
    (re.compile(r"(\"?(?:api_key|apikey|token)\"?\s*:\s*\")[A-Za-z0-9\-_.]{16,}", re.I),
     r'\1***REDACTED***'),
]


def redact(text: str) -> tuple:
    """Return ``(clean_text, hit_count)``."""
    if not isinstance(text, str):
        return text, 0
    hits = 0
    for pattern, replacement in SECRET_PATTERNS:
        text, count = pattern.subn(replacement, text)
        hits += count
    return text, hits
