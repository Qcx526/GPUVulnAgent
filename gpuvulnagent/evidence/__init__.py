# -*- coding: utf-8 -*-
"""Evidence package: hash-chained records, content-addressed artifacts, process capture."""

from .artifacts import ArtifactStore
from .hashing import GENESIS, sha256_bytes, sha256_file, sha256_text
from .log import SCHEMA, EvidenceLog, EvidenceResolver, evidence_id, verify_chain
from .outcome import CRASH_KINDS, classify_termination, is_crash
from .redact import redact
from .runner import Runner, clamp_timeout

__all__ = ["ArtifactStore", "CRASH_KINDS", "EvidenceLog", "EvidenceResolver", "GENESIS",
           "Runner", "SCHEMA", "classify_termination", "clamp_timeout", "evidence_id",
           "is_crash", "redact", "sha256_bytes", "sha256_file", "sha256_text",
           "verify_chain"]
