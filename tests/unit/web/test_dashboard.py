"""The SOC dashboard's filters and words (D-103), without a database."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from itertools import pairwise
from zoneinfo import ZoneInfo

import pytest

from argus import site
from argus.site import SiteSettings, zone
from argus.web.dashboard import Filters, _fill, duration

pytestmark = pytest.mark.unit
IST = zone()  # the suite runs on ACME's site section (tests/conftest.py)
NOW = datetime(2026, 10, 21, 9, 30, tzinfo=UTC)


def test_the_span() -> None:
    assert Filters().span(NOW) == (NOW - timedelta(days=7), NOW)
    assert Filters(range="24h").span(NOW) == (NOW - timedelta(hours=24), NOW)
    assert Filters(range="90d").span(NOW)[0] == NOW - timedelta(days=90)
    custom = Filters(start=date(2026, 10, 20), end=date(2026, 10, 18))  # either order
    assert custom.span(NOW) == (
        datetime(2026, 10, 17, 18, 30, tzinfo=UTC),  # 18 Oct 00:00 IST
        datetime(2026, 10, 20, 18, 30, tzinfo=UTC),  # 21 Oct 00:00 IST: the last day whole
    )
    assert Filters(start=date(2026, 10, 20)).span(NOW)[0] == NOW - timedelta(days=7)  # one date


def test_urls_keep_every_filter_and_drop_the_defaults() -> None:
    assert Filters().url() == "/dashboard"
    f = Filters(range="24h", severity=("high", "critical"), state=("unreviewed",),
                verdict=("none",), ai=("proposed_tp",), rule="r 1&x", kind="ip",
                value="10.0.0.1")  # fmt: skip
    assert f.url() == (
        "/dashboard?range=24h&severity=high&severity=critical&state=unreviewed&verdict=none"
        "&ai=proposed_tp&rule=r+1%26x&kind=ip&value=10.0.0.1"
    )
    dated = Filters(range="30d", start=date(2026, 10, 1), end=date(2026, 10, 2))
    assert dated.url() == "/dashboard?start=2026-10-01&end=2026-10-02"  # dates win over range
    assert f.url(severity=(), rule=None) == (
        "/dashboard?range=24h&state=unreviewed&verdict=none&ai=proposed_tp&kind=ip&value=10.0.0.1"
    )
    assert Filters(kind="ip").url() == "/dashboard"  # a kind without a value is no filter


def test_adding_a_filter_from_a_click() -> None:
    f = Filters(severity=("high",))
    assert f.adding("severity", "low") == "/dashboard?severity=high&severity=low"
    assert f.adding("severity", "high") == "/dashboard?severity=high"  # never twice
    assert f.adding("state", "reviewed") == "/dashboard?severity=high&state=reviewed"
    assert Filters(rule="a").adding("rule", "b") == "/dashboard?rule=b"
    assert f.adding("kind", "ip") == "/dashboard?severity=high"


def test_chips_name_each_filter_with_the_url_that_removes_it() -> None:
    f = Filters(severity=("high", "low"), state=("follow_up",), verdict=("true_positive",),
                ai=("none",), rule="R", kind="host", value="h1")  # fmt: skip
    assert f.chips() == [
        ("severity: high", f.url(severity=("low",))),
        ("severity: low", f.url(severity=("high",))),
        ("state: Follow-up", f.url(state=())),
        ("verdict: true positive", f.url(verdict=())),
        ("ai: Not assessed", f.url(ai=())),
        ("rule: R", f.url(rule=None)),
        ("host: h1", f.url(kind=None, value=None)),
    ]
    assert Filters().chips() == []


@pytest.mark.parametrize(
    ("seconds", "words"),
    [(None, "—"), (0, "0 min"), (59 * 60 + 59, "59 min"), (3600, "1 h"), (3600 + 60, "1 h 1 min"),
     (47 * 3600 + 59 * 60, "47 h 59 min"), (48 * 3600, "2 days"), (49 * 3600 + 1, "2 days 1 h")],
)  # fmt: skip
def test_durations_in_plain_words(seconds: float | None, words: str) -> None:
    assert duration(seconds) == words


def test_buckets_cover_the_span_in_ist() -> None:
    start, end = NOW - timedelta(hours=24), NOW
    hours = _fill({}, start, end, hourly=True)
    assert len(hours) == 24  # 15:00 IST yesterday to 14:00 today: the span ends at 15:00
    assert hours[0][0] == datetime(2026, 10, 20, 15, 0, tzinfo=IST)
    late = _fill({}, start + timedelta(minutes=20), end + timedelta(minutes=20), hourly=True)
    assert (len(late), late[0][0].hour, late[-1][0].hour) == (25, 15, 15)  # partial hours count
    assert all(b - a == timedelta(hours=1) for (a, _), (b, _) in pairwise(hours))
    days = _fill({datetime(2026, 10, 15, tzinfo=IST): {"low": 3}}, NOW - timedelta(days=7), NOW,
                 hourly=False)  # fmt: skip
    assert [d.day for d, _ in days] == [14, 15, 16, 17, 18, 19, 20, 21]
    assert days[1][1] == {"low": 3}
    assert days[0][1] == {}


def hour_apart(a: datetime, b: datetime) -> bool:
    return b.astimezone(UTC) - a.astimezone(UTC) == timedelta(
        hours=1
    )  # same-zone '-' is wall-clock


def test_hourly_buckets_follow_the_clock_changes_of_the_sites_zone() -> None:
    new_york = ZoneInfo("America/New_York")
    with site.using(SiteSettings(timezone="America/New_York")):
        # spring forward (8 Mar 2026): 02:00 does not exist; 5 UTC hours are 5 buckets, not 6
        start = datetime(2026, 3, 8, 4, 0, tzinfo=UTC)  # 23:00 EST on the 7th
        spring = _fill({}, start, start + timedelta(hours=5), hourly=True)
        assert [b.strftime("%H:%M") for b, _ in spring] == [
            "23:00",
            "00:00",
            "01:00",
            "03:00",
            "04:00",
        ]
        assert all(hour_apart(a, b) for (a, _), (b, _) in pairwise(spring))
        # fall back (1 Nov 2026): 01:00 happens twice; the report merges the two into one bar,
        # which is counted once (the first), so the total is kept
        start = datetime(2026, 11, 1, 4, 0, tzinfo=UTC)  # 00:00 EDT
        counts = {datetime(2026, 11, 1, 1, 0, tzinfo=new_york): {"low": 7}}
        fall = _fill(counts, start, start + timedelta(hours=4), hourly=True)
        assert [b.strftime("%H:%M") for b, _ in fall] == ["00:00", "01:00", "01:00", "02:00"]
        assert [c for _, c in fall] == [{}, {"low": 7}, {}, {}]
        # a day is a date: the 25-hour day of the fall change is one bucket, and so is the next
        days = _fill({}, datetime(2026, 10, 31, 12, 0, tzinfo=UTC),
                     datetime(2026, 11, 3, 12, 0, tzinfo=UTC), hourly=False)  # fmt: skip
        assert [d.strftime("%m-%d %H:%M") for d, _ in days] == [
            "10-31 00:00", "11-01 00:00", "11-02 00:00", "11-03 00:00"]  # fmt: skip
    with site.using(SiteSettings(timezone="Australia/Lord_Howe")):  # a half-hour clock change
        start = datetime(2026, 4, 4, 12, 0, tzinfo=UTC)
        got = _fill({}, start, start + timedelta(hours=30), hourly=True)
        assert len(got) == 30
        assert all(hour_apart(a, b) for (a, _), (b, _) in pairwise(got))


def test_filters_and_cases_are_frozen_and_half_set_filters_are_none() -> None:
    import dataclasses

    from argus.web.dashboard import Case

    with pytest.raises(dataclasses.FrozenInstanceError):
        Filters().range = "24h"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        Case("i", "r", None, 1, None, "unreviewed", None, "none").rule = "x"  # type: ignore[misc]
    assert Filters(range="24h", start=date(2026, 10, 1)).params() == [("range", "24h")]
    assert Filters(kind="ip").chips() == Filters(value="x").chips() == []
    assert Filters(range="30d").span(NOW) == (NOW - timedelta(days=30), NOW)
