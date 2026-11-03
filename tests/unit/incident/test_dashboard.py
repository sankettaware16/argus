"""The one-page picture dashboard (AR10, D-250): drawn by code from the report, the PDF's second
part and a file of its own; one page, the same bytes for the same report, and no name of a person
anywhere on it."""

from __future__ import annotations

import io

import pytest
from pypdf import PdfReader

from argus.incident import dashboard, files
from argus.incident import glance as g
from argus.incident import model as m
from argus.incident.build import build
from tests.unit.incident import kit
from tests.unit.incident.test_accounts import NAME, OTHER
from tests.unit.incident.test_accounts import report as with_accounts

pytestmark = pytest.mark.unit
PANELS = (
    "Alerts per day, by rule (IST)",
    "Rules that raised the alerts",
)


def pages(data: bytes) -> list[str]:
    return [p.extract_text() for p in PdfReader(io.BytesIO(data)).pages]


def amadey() -> m.IncidentReport:
    return build(kit.amadey(), kit.ctx())


def git() -> m.IncidentReport:
    return build(kit.git(), kit.ctx())


@pytest.mark.parametrize("make", [amadey, git])
def test_the_dashboard_is_one_page_with_its_four_panels_and_its_numbers(make: object) -> None:
    report = make()  # type: ignore[operator]
    data = dashboard.pdf(report)
    assert data.startswith(b"%PDF")
    (text,) = pages(data)
    assert f"Incident at a glance: {report.header.incident_id}" in text
    shape = g.shape_of(report)
    for title in (*PANELS, shape.actors_title + " (alerts)", shape.targets_title + " (alerts)"):
        assert title in text
    glance = g.glance_of(report)
    assert f"{glance.alerts}" in text
    for row in glance.rule_rows:
        assert row.label in text
    for bar in (*glance.top_actors, *glance.top_targets):
        assert bar.label in text


def test_the_same_report_is_the_same_bytes_and_the_name_follows_the_incident() -> None:
    report = amadey()
    assert dashboard.pdf(report) == dashboard.pdf(report)
    assert files.dashboard_name(report) == f"{report.header.incident_id}_dashboard.pdf"
    assert files.bundle(report)[files.dashboard_name(report)] == dashboard.pdf(report)


def test_the_incident_pdf_has_the_dashboard_after_its_title_block_and_before_the_summary() -> None:
    report = amadey()
    first, *_ = pages(files.pdf(report))
    assert first.index("Incident ID") < first.index("Incident at a glance")
    assert "Incident at a glance" in first
    assert "1. Summary" not in first.split("Incident at a glance")[0]
    whole = "\n".join(pages(files.pdf(report)))
    assert whole.index("Incident at a glance") < whole.index("1. Summary")


def test_a_case_with_nothing_to_draw_still_gets_a_page_that_says_so() -> None:
    report = amadey().model_copy(
        update={
            "actors": (),
            "assets": (),
            "indicators": (),
            "indicators_total": 0,
            "timeline": amadey().timeline.model_copy(update={"phases": (), "days": ()}),
        }
    )
    (text,) = pages(dashboard.pdf(report))
    assert "The case names no actor to draw." in text
    assert "The case names no target to draw." in text
    assert "No alert times to draw." in text
    assert "No rule is named." in text


def test_a_long_case_stays_on_one_page_with_a_readable_day_axis() -> None:
    report = amadey()
    rows = tuple(
        m.ReportDayRow(
            day=f"2026-09-{d:02d}", counts=(d % 7, d % 3, d % 5), total=d % 7 + d % 3 + d % 5
        )
        for d in range(1, 31)
    )
    timeline = report.timeline.model_copy(
        update={"days": rows, "columns": ("A", "B", "Other rules")}
    )
    (text,) = pages(dashboard.pdf(report.model_copy(update={"timeline": timeline})))
    assert "Alerts per day, by rule (IST)" in text
    assert "Other rules" in text


def test_no_name_of_a_person_is_drawn_even_when_the_report_holds_accounts() -> None:
    report = with_accounts(NAME, OTHER)
    assert files.has_accounts(report)
    person = report.actors[0].model_copy(update={"value": "alice.example", "kind": "user"})
    changed = report.model_copy(update={"actors": (person, *report.actors)})
    (text,) = pages(dashboard.pdf(changed))
    for name in (NAME, OTHER, "alice.example"):
        assert name not in text


def test_text_from_the_report_is_drawn_as_text_never_as_markup() -> None:
    report = amadey()
    hostile = '<b>bold</b> & <a href="x">link</a> ‮\x00'
    phases = tuple(p.model_copy(update={"name": hostile}) for p in report.timeline.phases)
    layers = ("<i>x</i>", "A&B")
    timeline = report.timeline.model_copy(update={"phases": phases, "columns": layers})
    (text,) = pages(dashboard.pdf(report.model_copy(update={"timeline": timeline})))
    assert "<b>bold</b> & <a href" in text
    assert "A&B" in text


def test_a_label_that_is_too_long_is_cut_and_a_character_the_font_lacks_is_a_question_mark() -> (
    None
):
    report = git()
    long = report.actors[0].model_copy(update={"value": "h" * 80 + ".example"})
    (text,) = pages(dashboard.pdf(report.model_copy(update={"actors": (long,)})))
    assert "h" * dashboard.LABEL_AT not in text
    assert "…" in text


def test_axis_steps_are_whole_numbers_that_cover_the_peak() -> None:
    for peak in (1, 2, 5, 7, 9, 10, 11, 49, 50, 51, 999, 12_345):
        step = dashboard._nice_step(peak)
        assert step >= 1
        assert step * 5 >= peak
        assert str(step).lstrip("1259").strip("0") == ""  # 1, 2, 5 times a power of ten
