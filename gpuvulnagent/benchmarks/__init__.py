# -*- coding: utf-8 -*-
"""Benchmark package: runner, crash classification, metrics, cumulative summary."""

from .crash import classify_record, crash_events, termination_histogram
from .metrics import DEFAULT_TARGET_TOOLS, compare_legacy, compute_metrics, read_records, \
    summarize_metrics, verdict
from .runner import BenchmarkError, BenchmarkRunner, environment_facts, facts_text, \
    rebuild_summary
from .summary import SummaryIndex

__all__ = ["BenchmarkError", "BenchmarkRunner", "DEFAULT_TARGET_TOOLS", "SummaryIndex",
           "classify_record", "compare_legacy", "compute_metrics", "crash_events",
           "environment_facts", "facts_text", "read_records", "rebuild_summary",
           "summarize_metrics", "termination_histogram", "verdict"]
