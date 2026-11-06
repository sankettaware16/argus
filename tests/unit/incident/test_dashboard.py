"""The one-page picture dashboard (AR10, D-250): drawn by code from the report, the PDF's second
part and a file of its own; one page, the same bytes for the same report, and no name of a person
anywhere on it."""

from __future__ import annotations

import io
import re
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pypdf import PdfReader

from argus import site
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
    glance = g.glance_of(report)
    shape = glance.shape
    said = {True: " (alerts of their investigations)", False: ""}
    flat = " ".join(text.split())  # a long panel title takes two lines
    for title in (
        *PANELS,
        shape.actors_title + said[g.bars(glance.top_actors)],
        shape.targets_title + said[g.bars(glance.top_targets)],
    ):
        assert title in flat
    assert f"{glance.alerts}" in text
    for row in glance.rule_rows:
        assert row.label in text
    for bar in (*glance.top_actors, *glance.top_targets):
        assert bar.label in text
    for value in (glance.severity, glance.activity, glance.dwell):
        assert value in text


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
    other = report.actors[1]
    (text,) = pages(dashboard.pdf(report.model_copy(update={"actors": (long, other)})))
    assert "h" * dashboard.LABEL_AT not in text  # a bar's label
    assert "…" in text
    (alone,) = pages(dashboard.pdf(report.model_copy(update={"actors": (long,)})))
    assert "h" * dashboard.LIST_LABEL_AT not in alone.replace("\n", "")  # a list's label
    assert "…" in alone


def test_axis_steps_are_whole_numbers_that_cover_the_peak() -> None:
    for peak in (1, 2, 5, 7, 9, 10, 11, 49, 50, 51, 999, 12_345):
        step = dashboard._nice_step(peak)
        assert step >= 1
        assert step * 5 >= peak
        assert str(step).lstrip("1259").strip("0") == ""  # 1, 2, 5 times a power of ten


# --------------------------------------------------------------------------- P4-F V0, V2, V4


TOKEN = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*(?::[^{}]*)?\}")


@pytest.mark.parametrize("make", [amadey, git])
def test_the_dashboards_foot_names_the_incident_the_organisation_and_the_page(make: object) -> None:
    """V0: the foot printed the literal ``{noun}``; it now reads as the report's pages do."""
    report = make()  # type: ignore[operator]
    org = site.organisation()
    (text,) = pages(dashboard.pdf(report))
    foot = files.footer_text(report)
    assert foot in text
    assert f"{report.header.incident_id} · {org.short_name}, {org.name} · " in foot
    assert site.say(files.FOOTER) in foot
    assert "Page 1" in text
    assert not TOKEN.search(text)
    meta = PdfReader(io.BytesIO(dashboard.pdf(report))).metadata
    assert meta is not None
    assert meta.author == files.pdf_author()


def test_both_pdfs_share_one_foot() -> None:
    report = amadey()
    whole = pages(files.pdf(report))
    assert all(files.footer_text(report) in page for page in whole)
    assert all(f"Page {n}" in page for n, page in enumerate(whole, 1))


def test_the_status_row_says_the_severity_the_call_the_activity_and_the_dwell() -> None:
    (text,) = pages(dashboard.pdf(amadey()))
    flat = " ".join(text.split())
    for label in ("Severity", "Call", "Activity", "Dwell (first to last alert)"):
        assert label in flat
    assert "True positive, 80% sure (ARGUS's call, not confirmed by a person)" in flat
    assert "Still active" in flat
    (quiet,) = pages(dashboard.pdf(git()))
    assert "No call yet" in quiet
    assert "Quiet" in quiet


def test_a_quiet_day_has_its_place_on_the_day_axis() -> None:
    (text,) = pages(dashboard.pdf(git()))
    assert "Sat 24 Oct" in text  # no alert that day: still a bar's place


def test_a_long_case_is_drawn_by_weeks_and_says_so() -> None:
    report = amadey()
    rows = tuple(
        m.ReportDayRow(day=f"2026-{month:02d}-01", counts=(1, 1), total=2) for month in (1, 4, 8)
    )
    timeline = report.timeline.model_copy(update={"days": rows})
    (text,) = pages(dashboard.pdf(report.model_copy(update={"timeline": timeline})))
    assert "Alerts per week, by rule (IST)" in text


def test_one_actor_is_a_line_of_a_list_not_a_bar_and_servers_without_counts_are_listed() -> None:
    """V4: no single-bar panels; F3: the servers are the list the count is made from."""
    report = amadey()
    (text,) = pages(dashboard.pdf(report))
    flat = " ".join(text.split())
    assert "Top campus devices (alerts of their investigations)" not in flat
    assert "Top campus devices" in flat
    assert "Alerts of its investigations" in flat
    assert "Servers reached (alerts of their investigations)" not in flat
    assert "4 servers reached" in flat
    for server in kit.SERVERS:
        assert server in flat


def test_many_listed_servers_keep_the_dashboard_on_one_page() -> None:
    report = amadey()
    c2 = report.indicators[1]
    servers = tuple(
        c2.model_copy(update={"value": f"198.51.100.{n}", "evidence": "VirusTotal: " + "x" * 300})
        for n in range(40)
    )
    many = report.model_copy(
        update={"indicators": (report.indicators[0], *servers), "indicators_total": 41}
    )
    (text,) = pages(dashboard.pdf(many))  # one page
    assert "and 4 more" in text  # the glance shows the top ten, the list six of them


@settings(max_examples=30, deadline=None)
@given(
    n_actors=st.integers(min_value=0, max_value=12),
    n_days=st.integers(min_value=1, max_value=400),
    alerts=st.integers(min_value=0, max_value=100_000),
)
def test_any_case_is_one_page_with_its_foot_and_no_token(
    n_actors: int, n_days: int, alerts: int
) -> None:
    report = git()
    actors = tuple(
        report.actors[0].model_copy(update={"value": f"203.0.113.{n}", "alerts": n + 1})
        for n in range(n_actors)
    )
    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = tuple(
        m.ReportDayRow(day=(start + timedelta(days=d)).date().isoformat(), counts=(d,), total=d)
        for d in (0, n_days // 2, n_days - 1)
    )
    changed = report.model_copy(
        update={
            "actors": actors,
            "meta": report.meta.model_copy(update={"alerts_total": alerts}),
            "timeline": report.timeline.model_copy(update={"days": rows}),
        }
    )
    (text,) = pages(dashboard.pdf(changed))
    assert files.footer_text(changed) in text
    assert not TOKEN.search(text)


def test_a_case_with_long_names_everywhere_still_fits_one_page() -> None:
    """The second row of panels is one table row: it cannot split, so a page too full sends it
    whole to a second page. Titles, rule names, lists and notes are cut to keep it on one."""
    report = amadey()
    p0 = report.timeline.phases[0]
    phases = tuple(
        p0.model_copy(update={"name": f"Rule {n} " + "w" * 250, "alerts": 100 - n})
        for n in range(14)
    )
    c2 = report.indicators[1]
    servers = tuple(
        c2.model_copy(
            update={
                "value": f"very-long-host-name-{n}-" + "x" * 60 + ".example",
                "kind": "domain",
                "evidence": "VirusTotal: " + "y" * 400,
            }
        )
        for n in range(30)
    )
    verdict = report.verdict.model_copy(
        update={
            "outcome": "benign_expected",
            "words": "benign: expected activity",
            "kind": "reading",
            "confidence": 0.61,
        }
    )
    columns = (*(f"Rule {n} " + "w" * 250 for n in range(4)), "Other rules")
    days = tuple(d.model_copy(update={"counts": (1, 2, 3, 4, 5)}) for d in report.timeline.days)
    timeline = report.timeline.model_copy(
        update={"phases": phases, "columns": columns, "days": days}
    )
    title = report.header.title.split(" · ")[0] + " · " + "A very long title " * 15
    actors = tuple(
        report.actors[0].model_copy(update={"value": f"10.1.{n}.{n}", "alerts": n + 1})
        for n in range(25)
    )
    worst = report.model_copy(
        update={
            "timeline": timeline,
            "indicators": (report.indicators[0], *servers),
            "indicators_total": 31,
            "verdict": verdict,
            "header": report.header.model_copy(update={"title": title}),
            "actors": actors,
        }
    )
    (text,) = pages(dashboard.pdf(worst))  # one page
    assert "and 6 more" in text  # of the rules
    assert "and 4 more" in text  # of the servers listed
    assert "Page 1" in text
