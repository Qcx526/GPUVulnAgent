# -*- coding: utf-8 -*-
"""Findings: the second research track must be recorded, not folded into the first."""

from __future__ import annotations

import json

import pytest

from gpuvulnagent.findings import FindingError, FindingStore
from gpuvulnagent.findings.model import Finding, render_report


@pytest.fixture
def store(tmp_path):
    return FindingStore(tmp_path / "trial0", "trial0")


def test_a_finding_gets_an_id_that_cannot_be_mistaken_for_a_cve(store):
    finding = store.create("nvdisasm crash on REL offset", component="nvdisasm",
                           crash_class="SIGSEGV")
    assert finding.finding_id == "FND-t0-0001"
    assert "CVE" not in finding.finding_id
    assert finding.trial_id == "trial0"


def test_a_cve_shaped_id_is_refused(tmp_path):
    with pytest.raises(ValueError):
        Finding(finding_id="CVE-2025-23308", title="nope")


def test_unknown_crash_class_falls_back_instead_of_inventing_one(store):
    finding = store.create("odd behaviour", crash_class="SPONTANEOUS_COMBUSTION")
    assert finding.crash_class == "UNKNOWN"


def test_record_and_advisory_style_report_are_written(store, tmp_path):
    finding = store.create(
        "nvdisasm 12.6.68 dies on a REL offset outside every section",
        component="nvdisasm", crash_class="SIGSEGV", cwe="UNKNOWN",
        input_path="inputs/rel_offset_huge.cubin", input_sha256="a" * 64,
        reproduction_command="nvdisasm rel_offset_huge.cubin",
        target_versions={"12.6.68": "V12.6.68", "12.8.55": "V12.8.55"},
        differential={"12.6.68": "SIGSEGV", "12.8.55": "exit 1"},
        stability={"runs": 1, "crashes": 1},
        related_cves=["CVE-2025-23308"], verification_status="stable",
        impact="local DoS of the disassembler", notes="no stack yet")
    record = tmp_path / "trial0/research/findings" / ("%s.json" % finding.finding_id)
    report = tmp_path / "trial0/research/findings" / ("%s.md" % finding.finding_id)
    assert record.is_file() and report.is_file()
    payload = json.loads(record.read_text(encoding="utf-8"))
    assert payload["crash_class"] == "SIGSEGV"
    assert payload["related_cves"] == ["CVE-2025-23308"]
    text = report.read_text(encoding="utf-8")
    assert "Internal finding" in text and "an assigned CVE" in text
    assert "SIGSEGV" in text and "12.6.68" in text
    assert "no stack yet" in text


def test_update_keeps_the_previous_revision(store, tmp_path):
    finding = store.create("t", component="cuobjdump")
    store.update(finding.finding_id, root_cause_status="partial",
                 notes="narrowed to the section table")
    history = list((tmp_path / "trial0/research/findings/history").glob("*.json"))
    assert history, "the earlier revision must be kept"
    current = store.get(finding.finding_id)
    assert current.root_cause_status == "partial"


def test_tally_separates_attributed_from_unattributed(store):
    store.create("a", component="nvdisasm", crash_class="SIGSEGV",
                 related_cves=["CVE-2025-23308"], verification_status="stable")
    store.create("b", component="nvdisasm", crash_class="SIGABRT")
    tally = store.tally()
    assert tally["findings"] == 2
    assert tally["linked_to_known_cve"] == 1
    assert tally["unattributed"] == 1
    assert tally["stable"] == 1
    assert tally["by_component"] == {"nvdisasm": 2}


def test_store_reloads_from_the_journal(store, tmp_path):
    first = store.create("reload", component="nvdisasm")
    reloaded = FindingStore(tmp_path / "trial0", "trial0")
    assert reloaded.get(first.finding_id) is not None
    assert reloaded.tally()["findings"] == 1


def test_duplicate_ids_are_refused(store):
    store.create("first", finding_id="FND-t0-0007")
    with pytest.raises(FindingError):
        store.create("second", finding_id="FND-t0-0007")


def test_report_marks_unknown_fields_as_unknown():
    text = render_report(Finding(finding_id="FND-t0-0001", title="x"))
    assert "UNKNOWN" in text
    assert "Internal finding" in text and "an assigned CVE" in text
