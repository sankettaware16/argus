"""The report's files (AR7, D-190): the CSVs carry the hand-made case's columns, a UTF-8 byte order
mark and cells a spreadsheet cannot read as formulas; the PDF opens, has the sections, the evidence
and its queries as text, is the same bytes for the same report, and shows a character its font lacks
as a question mark rather than a box."""

from __future__ import annotations

import csv
import io
from pathlib import Path

import pytest
from pypdf import PdfReader

from argus.incident import files
from argus.incident import model as m
from argus.incident.build import build
from tests.unit.incident import kit

pytestmark = pytest.mark.unit


def rows(text: str) -> list[list[str]]:
    assert text.startswith("﻿")
    return list(csv.reader(io.StringIO(text[1:])))


def pdf_text(data: bytes) -> tuple[int, str]:
    reader = PdfReader(io.BytesIO(data))
    return len(reader.pages), "\n".join(p.extract_text() for p in reader.pages)


def test_the_csvs_have_the_hand_made_cases_columns_and_the_cases_rows() -> None:
    report = build(kit.amadey(devices=4), kit.ctx())
    ind = rows(files.indicators_csv(report))
    assert ind[0] == ["indicator", "type", "role", "evidence"]
    assert {(r[0], r[1], r[2]) for r in ind[1:]} == {
        (i.value, i.kind, "actor" if i.role == "actor" else "command-and-control")
        for i in kit.amadey(devices=4).indicators
    }
    aff = rows(files.affected_csv(report))
    assert aff[0] == ["device_ip", "domain", "days_with_alert", "first_day_ist", "last_day_ist"]
    assert len(aff) == 5
    assert all(r[2] == "5" for r in aff[1:])
    assert aff[1][3] == "2026-10-23"
    assert aff[1][4] == "2026-10-28"
    assert aff[1][1] == "" or "." in aff[1][1]


def test_a_cell_a_spreadsheet_could_run_is_neutralised_and_the_file_has_a_byte_order_mark() -> None:
    report = build(kit.amadey(), kit.ctx())
    hostile = report.model_copy(
        update={
            "indicators": (
                m.ReportIndicator(
                    kind="domain",
                    value='=HYPERLINK("http://x")',
                    role="c2",
                    role_words="x",
                    source="threat_intel",
                    evidence="@SUM(A1)",
                ),
                m.ReportIndicator(
                    kind="user",
                    value="-2+3",
                    role="actor",
                    role_words="x",
                    source="person",
                    evidence="+cmd|' /C calc'!A0",
                ),
            ),
            "assets": (m.ReportAsset(kind="device", value="\t=1+1", label="@x", days=1),),
        }
    )
    raw = files.indicators_csv(hostile).encode("utf-8")
    assert raw.startswith(b"\xef\xbb\xbf")
    cells = [c for r in rows(files.indicators_csv(hostile))[1:] for c in r]
    assert '\'=HYPERLINK("http://x")' in cells
    assert "'@SUM(A1)" in cells
    assert "'-2+3" in cells
    assert not any(c[:1] in "=+-@\t\r" for c in cells if c and c not in ("domain", "user", "actor"))
    affected = rows(files.affected_csv(hostile))
    assert affected[1][0] == "'\t=1+1"
    assert affected[1][1] == "'@x"


def test_the_pdf_opens_has_the_sections_and_says_the_evidence_with_its_query() -> None:
    report = build(kit.amadey(devices=40), kit.ctx())
    data = files.pdf(report)
    assert data.startswith(b"%PDF-")
    pages, text = pdf_text(data)
    assert pages >= 3
    for heading in (
        "Incident Report ACME-IR-2026-1026-01",
        "1. Summary",
        "2. Timeline (IST)",
        "3. Actors and roles",
        "4. Indicators",
        "5. Evidence",
        "6. Hypotheses",
        "7. Affected assets",
        "8. Recommended actions",
        "9. Queries to verify",
        "10. Scope and limits",
    ):
        assert heading in text, heading
    assert "TLP:AMBER" in text
    assert "Page 1" in text
    assert "40 campus devices contacted 4 servers" in text
    assert "and 15 more in the CSV" in text  # 25 devices shown of 40
    squashed = text.replace("\n", "")
    assert "FROM acme-logs-squid-*" in squashed
    for line in report.evidence:
        assert line.id in text


def test_the_same_report_is_the_same_pdf() -> None:
    report = build(kit.amadey(), kit.ctx())
    assert files.pdf(report) == files.pdf(report)
    assert files.pdf(report) != files.pdf(build(kit.git(), kit.ctx()))


def test_a_character_the_font_lacks_is_a_question_mark_and_control_characters_are_dropped() -> None:
    report = build(kit.amadey(), kit.ctx())
    odd = report.model_copy(
        update={
            "header": report.header.model_copy(
                update={"detected_by": "Rules: café \u6f22 \x00 end"}
            )
        }
    )
    _, text = pdf_text(files.pdf(odd))
    assert "café ? end" in text.replace("\n", " ")
    assert "\x00" not in text
    assert "\u6f22" not in text


def test_without_dejavu_the_pdf_uses_the_font_reportlab_ships(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    report = build(kit.amadey(), kit.ctx())
    monkeypatch.setattr(files, "DEJAVU", tmp_path / "missing")
    files._fonts.cache_clear()
    try:
        pages, text = pdf_text(files.pdf(report))
    finally:
        monkeypatch.undo()
        files._fonts.cache_clear()
    assert pages >= 1
    assert "1. Summary" in text
    assert "ACME-IR-2026-1026-01" in text


def test_the_bundle_has_the_four_files_by_name() -> None:
    report = build(kit.amadey(), kit.ctx())
    got = files.bundle(report)
    assert set(got) == {
        "ACME-IR-2026-1026-01_Incident_Report.pdf",
        "ACME-IR-2026-1026-01_dashboard.pdf",
        "ACME-IR-2026-1026-01_indicators.csv",
        "ACME-IR-2026-1026-01_affected_devices.csv",
    }
    assert got[files.indicators_name(report)] == files.indicators_csv(report).encode("utf-8")


def test_a_prose_summary_is_marked_as_a_model_s() -> None:
    report = build(kit.amadey(), kit.ctx())
    fact = next(f for f in report.facts if f.safe)
    worded = report.summary.model_copy(
        update={
            "prose": (m.ReportSentence(text="A model said this.", cites=(fact.id,), by="model"),)
        }
    )
    _, text = pdf_text(files.pdf(report.model_copy(update={"summary": worded})))
    assert "A model said this." in text
    assert "written by a model" in text
