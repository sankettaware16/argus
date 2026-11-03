"""The Reporter's small parts (Q-H3): the period, the text, the figures' arithmetic, a name from
SIEM data inside a key, and the prose door."""

from __future__ import annotations

import json
import re
from datetime import UTC, date, datetime, timedelta
from fractions import Fraction

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from argus.agent import registry
from argus.reporter import prose, render, sections
from argus.reporter.build import last_complete_day
from argus.reporter.model import KINDS, Metric, Numbers, Section, window_for

pytestmark = pytest.mark.unit

NOW = datetime(2026, 10, 21, 6, 0, tzinfo=UTC)


def metric(key: str, value: object, unit: str = "count", label: str = "A figure") -> Metric:
    return Metric(key=key, label=label, value=value, unit=unit, definition="how")  # type: ignore[arg-type]


def numbers(*metrics: Metric, kind: str = "daily") -> Numbers:
    start = datetime(2026, 10, 20, tzinfo=UTC)
    days = 1 if kind == "daily" else 7
    return Numbers(
        kind=kind,  # type: ignore[arg-type]
        period_start=start,
        period_end=start + timedelta(days=days),
        as_at=NOW,
        sections=(Section(id="s", title="A section", metrics=metrics),),
    )


# --------------------------------------------------------------------------- the period


def test_a_daily_report_is_one_utc_day_and_a_weekly_one_is_seven_ending_with_the_date() -> None:
    day = window_for("daily", date(2026, 10, 20), NOW)
    assert (day.start, day.end, day.days) == (
        datetime(2026, 10, 20, tzinfo=UTC), datetime(2026, 10, 21, tzinfo=UTC), 1,
    )  # fmt: skip
    week = window_for("weekly", date(2026, 10, 20), NOW)
    assert (week.start, week.end, week.days) == (
        datetime(2026, 10, 14, tzinfo=UTC), datetime(2026, 10, 21, tzinfo=UTC), 7,
    )  # fmt: skip
    assert KINDS == ("daily", "weekly")


@given(
    moment=st.datetimes(
        min_value=datetime(2001, 1, 2),  # noqa: DTZ001
        max_value=datetime(2099, 1, 1),  # noqa: DTZ001
    )
)
def test_the_default_day_has_ended_and_is_the_latest_that_has(moment: datetime) -> None:
    now = moment.replace(tzinfo=UTC)
    last = last_complete_day(now)
    assert window_for("daily", last, now).end <= now
    assert window_for("daily", last + timedelta(days=1), now).end > now


# --------------------------------------------------------------------------- figures


@given(part=st.integers(0, 10**6), whole=st.integers(1, 10**6))
def test_a_percentage_is_to_one_decimal_halves_up(part: int, whole: int) -> None:
    got = sections.percent(part, whole)
    assert got is not None
    exact = Fraction(part * 100, whole)
    assert abs(Fraction(str(got)) - exact) <= Fraction(5, 100)
    assert Fraction(str(got)) * 10 == int(Fraction(str(got)) * 10)  # one decimal place
    tenths = exact * 10
    assert Fraction(str(got)) * 10 == int(tenths + Fraction(1, 2))  # halves up


def test_a_percentage_of_nothing_is_none_and_edges_are_exact() -> None:
    assert sections.percent(0, 0) is None
    assert sections.percent(5, 0) is None
    assert sections.percent(0, 7) == 0.0
    assert sections.percent(1, 8) == 12.5
    assert sections.percent(1, 16) == 6.3  # 6.25 rounds up
    assert sections.percent(2, 3) == 66.7
    assert sections.percent(7, 7) == 100.0


@given(text=st.text(max_size=300))
@settings(max_examples=300, deadline=None)
def test_a_name_from_the_siem_always_makes_a_valid_key_and_a_one_line_label(text: str) -> None:
    if not text:
        return
    key = f"active_hosts.host.{sections.slug(text)}"
    shown = sections.plain(text)
    m = metric(key, 1, label=shown)
    assert "\n" not in m.label
    assert len(m.label) <= 80
    assert re.fullmatch(r"\S+", m.key)


def test_names_that_become_one_key_are_told_apart() -> None:
    taken: set[str] = set()
    keys = [sections.unique(f"k.{sections.slug(v)}", taken) for v in ("a b", "a_b", "a  b", "x")]
    assert keys == ["k.a_b", "k.a_b~2", "k.a_b~3", "k.x"]


def test_a_metric_refuses_a_key_or_unit_the_page_does_not_know() -> None:
    for key in ("", "Cases", "1cases", "a b", "a.b c", "a.\n"):
        with pytest.raises(ValidationError):
            metric(key, 1)
    with pytest.raises(ValidationError):
        Metric(key="a.b", label="x", value=1, unit="kilos", definition="d")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- the text


@given(n=st.integers(0, 10**7))
def test_a_duration_in_text_is_exact(n: int) -> None:
    text = render.duration(n)
    parts = {u: int(v) for v, u in re.findall(r"(\d+) (h|min|s)", text)}
    assert parts.get("h", 0) * 3600 + parts.get("min", 0) * 60 + parts.get("s", 0) == n


@given(n=st.integers(0, 10**10))
def test_a_duration_in_milliseconds_in_text_is_exact(n: int) -> None:
    text = render.duration_ms(n)
    parts = {u: int(v) for v, u in re.findall(r"(\d+) (h|min|s|ms)", text)}
    total = (parts.get("h", 0) * 3600 + parts.get("min", 0) * 60 + parts.get("s", 0)) * 1000
    assert total + parts.get("ms", 0) == n


@pytest.mark.parametrize(
    ("value", "unit", "text"),
    [
        (0, "count", "0"), (12, "count", "12"), (66.7, "percent", "66.7%"),
        (0.0, "percent", "0.0%"), (0, "ms", "0 ms"), (999, "ms", "999 ms"), (1000, "ms", "1 s"),
        (3_903_250, "ms", "1 h 5 min 3 s 250 ms"),
        (0, "seconds", "0 s"), (3903, "seconds", "1 h 5 min 3 s"),
        (1, "hours", "1 hour"), (0, "hours", "0 hours"), (26, "hours", "26 hours"),
        (None, "count", "n/a"), (None, "hours", "n/a"), ("ab12", "text", "ab12"),
    ],
)  # fmt: skip
def test_each_unit_is_said_the_same_way_every_time(value: object, unit: str, text: str) -> None:
    assert render.shown(metric("a.b", value, unit)) == text


def test_the_text_says_the_period_in_ist_and_which_figures_are_as_at_the_making() -> None:
    body = render.text_of(numbers(metric("a.b", 3, label="Three things")))
    lines = body.splitlines()
    assert lines[0] == "ARGUS daily report for the UTC day 20 Oct 2026"
    assert lines[1] == "Covers 5:30 AM IST on 20 Oct 2026 to 5:30 AM IST on 21 Oct 2026."
    assert lines[2].startswith("Made 11:30 AM IST on 21 Oct 2026. Figures of what is waiting")
    assert "== A section ==" in body
    assert "- Three things: 3" in body
    assert body.rstrip().endswith("a.b: how")
    week = render.text_of(numbers(metric("a.b", 1), kind="weekly")).splitlines()[0]
    assert week == "ARGUS weekly report for the UTC days 20 Oct 2026 to 26 Oct 2026"


# --------------------------------------------------------------------------- the prose door


def facts_report() -> Numbers:
    return numbers(
        metric("cases.waiting", 17, label="Cases waiting"),
        metric("approvals.rate", 66.7, "percent", "Share approved"),
        metric("kibana.lag", 120, "ms", "Median lag"),
        metric("active_hosts.host.ws-017", 5, label="ws-017"),
        metric("audit.head", "ab12cd34" * 8, "text", "Chain head"),
        metric("cases.none", None, label="Nothing here"),
    )


def paragraph(text: str) -> str:
    return json.dumps({"paragraph": text})


def test_the_reporter_is_off_and_hosts_hashes_and_nothing_are_never_shown_to_it() -> None:
    assert registry.ENABLED["reporter"] is None
    assert prose.enabled() is False
    shown = prose.prompt(facts_report())
    assert "Cases waiting" in shown
    assert "ws-017" not in shown
    assert "ab12cd34" not in shown
    assert "Nothing here" not in shown
    assert json.loads(shown)["period"] == "5:30 AM IST on 20 Oct 2026 to 5:30 AM IST on 21 Oct 2026"


@pytest.mark.parametrize(
    "text",
    [
        "17 cases are waiting for a person.",
        "Seventeen cases are waiting, and 66.7% of the requests were approved.",
        "The median lag was 120 ms on 20 Oct 2026.",
    ],
)
def test_a_paragraph_whose_numbers_are_given_is_taken_whole(text: str) -> None:
    assert prose.accept(facts_report(), paragraph(text)) == text
    assert prose.accept(facts_report(), {"paragraph": text}) == text


@pytest.mark.parametrize(
    "answer",
    [
        paragraph("18 cases are waiting."),  # one invented number
        paragraph("Eighteen cases are waiting."),
        paragraph("67% were approved."),
        paragraph("The lag was 120 minutes."),
        paragraph("The host ws-017 is active 5 days."),  # 5 is a host's day count: never shown
        paragraph("Cases: see https://example.org/17"),  # a link
        paragraph("**17** cases"),  # markup
        paragraph("17 cases <script>"),
        paragraph("17 cases `x`"),
        paragraph("mail me at a@b.c about 17 cases"),
        paragraph(""),
        paragraph("   "),
        paragraph("x" * 1501),
        paragraph("17 cases\x00"),
        paragraph("17 cases\x1b[2K"),
        json.dumps({"paragraph": "17 cases", "extra": "no"}),
        json.dumps({"text": "17 cases"}),
        json.dumps({"paragraph": 17}),
        json.dumps(["17 cases"]),
        json.dumps("17 cases"),
        "17 cases",  # not JSON
        "{",
        "",
        None,
        17,
    ],
)
def test_anything_else_is_refused_and_the_deterministic_text_stands(answer: object) -> None:
    assert prose.accept(facts_report(), answer) is None


@given(
    n=st.integers(0, 10**9).filter(lambda n: Fraction(n) not in prose.allowed(facts_report()).units)
)
@settings(max_examples=200, deadline=None)
def test_one_invented_number_anywhere_refuses_the_whole_paragraph(n: int) -> None:
    for style in (str(n), f"{n:,}", f"{n}%", f"{n} ms"):
        assert (
            prose.accept(facts_report(), paragraph(f"17 cases are waiting. Also {style}.")) is None
        )
        assert prose.accept(facts_report(), paragraph(f"{style} first. 17 cases.")) is None
