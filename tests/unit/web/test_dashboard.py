"""The SOC dashboard's filters, words and charts (D-103), without a database."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from itertools import pairwise
from zoneinfo import ZoneInfo

import pytest

from argus import site
from argus.site import SiteSettings, zone
from argus.web import charts
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


@pytest.mark.parametrize(("top", "nice"), [(0, 5), (5, 5), (6, 6), (7, 8), (9, 10), (11, 12),
                                           (13, 15), (21, 25), (31, 40), (40, 40), (41, 50),
                                           (51, 60), (24_999, 25_000),
                                           (25_001, 30_000), (81, 100)])  # fmt: skip
def test_axis_tops_are_round(top: int, nice: int) -> None:
    assert charts._nice(top) == nice


def test_the_stacked_chart() -> None:
    at = datetime(2026, 10, 21, tzinfo=IST)
    series = [(at, {"low": 2, "high": 1}), (at + timedelta(days=1), {})]
    svg = str(charts.stacked(series, ["low", "high"], 'Alerts <"x">', hourly=False))
    assert svg.startswith('<svg class="chart" viewBox="0 0 960 220" role="img" '
                          'aria-label="Alerts &lt;&#34;x&#34;&gt;">')  # fmt: skip
    assert "<title>Wed 21 Oct IST: 3 alerts, 2 low, 1 high</title>" in svg
    assert "<title>Thu 22 Oct IST: 0 alerts</title>" in svg
    assert svg.count('class="bar-low"') == 1
    assert svg.count('class="bar-high"') == 1
    assert svg.count('class="bar-empty"') == 1  # an empty day still has a tooltip target
    assert ">21 Oct</text>" in svg
    assert svg.endswith("</svg>")
    assert "<script" not in svg
    assert "style=" not in svg  # the CSP allows no style attribute


def test_bars_are_drawn_to_scale() -> None:
    at = datetime(2026, 10, 21, tzinfo=IST)
    svg = str(charts.stacked([(at, {"low": 5})], ["low"], "x", hourly=True))
    plot_h = charts.H - charts.PAD_B - charts.PAD_T
    assert f'height="{plot_h:.1f}"/>' in svg  # 5 of an axis to 5: the whole height
    assert ">12 AM</text>" in svg


def test_the_split_bar() -> None:
    parts = charts.parts({"b": 1, "a": 3, "z": 0}, {"a": "Alpha <1>"}, "st")
    assert parts == [("Alpha <1>", 3, "st-a"), ("b", 1, "st-b"), ("z", 0, "st-z")]
    svg = str(charts.split(parts, "State"))
    assert '<rect class="st-a" x="0.00" y="0" width="750.00" height="18">' in svg
    assert "<title>Alpha &lt;1&gt;: 3</title>" in svg
    assert '<rect class="st-b" x="750.00" y="0" width="250.00"' in svg
    assert "st-z" not in svg  # nothing drawn for a zero
    assert 'aria-label="State"' in svg
    assert str(charts.split([], "empty")).endswith("</svg>")


def test_the_stacked_chart_exactly() -> None:
    """Every coordinate, worked out by hand: a 908 by 184 plot (960 by 220 less the margins),
    two slots of 454 with bars of 48 (72 % of a slot, at most 48), an axis to 5 for a top of 3."""
    at = datetime(2026, 10, 21, tzinfo=IST)
    series = [(at, {"low": 2, "high": 1}), (at + timedelta(days=1), {})]
    grid = "".join(
        f'<line class="grid" x1="44" x2="952" y1="{y}.0" y2="{y}.0"/>'
        f'<text class="axis" x="38" y="{y + 4}.0" text-anchor="end">{label}</text>'
        for y, label in ((194, 0), (148, 1), (102, 2), (56, 3), (10, 5))
    )
    want = (
        '<svg class="chart" viewBox="0 0 960 220" role="img" aria-label="A">' + grid
        + "<g><title>Wed 21 Oct IST: 3 alerts, 2 low, 1 high</title>"
        '<rect class="bar-low" x="247.0" y="120.4" width="48.0" height="73.6"/>'
        '<rect class="bar-high" x="247.0" y="83.6" width="48.0" height="36.8"/></g>'
        '<text class="axis" x="271.0" y="212" text-anchor="middle">21 Oct</text>'
        "<g><title>Thu 22 Oct IST: 0 alerts</title>"
        '<rect class="bar-empty" x="701.0" y="10" width="48.0" height="184"/></g>'
        '<text class="axis" x="725.0" y="212" text-anchor="middle">22 Oct</text></svg>'
    )  # fmt: skip
    assert str(charts.stacked(series, ["low", "high"], "A", hourly=False)) == want
    assert (charts.W, charts.H, charts.PAD_L, charts.PAD_B, charts.PAD_T) == (960, 220, 44, 26, 10)


def test_many_buckets_thin_bars_and_every_other_tick() -> None:
    at = datetime(2026, 10, 21, tzinfo=IST)
    hours = [(at + timedelta(hours=k), {"low": 1}) for k in range(24)]
    svg = str(charts.stacked(hours, ["low"], "x", hourly=True))
    assert svg.count('text-anchor="middle"') == 12  # 24 bars: a tick on every second one
    assert ">2 AM</text>" in svg
    assert ">1 AM</text>" not in svg
    assert "<title>21 Oct 1 AM IST: 1 alerts, 1 low</title>" in svg
    assert 'width="27.2"' in svg  # 908 / 24 * 0.72
    many = [(at + timedelta(hours=k), {}) for k in range(1000)]
    assert 'width="1.5"' in str(charts.stacked(many, ["low"], "x", hourly=True))  # the least


def test_the_split_bar_exactly_and_its_parts_in_order() -> None:
    parts = charts.parts({"b_x": 1, "a": 1, "c": 2}, {}, "vd")
    assert parts == [("c", 2, "vd-c"), ("a", 1, "vd-a"), ("b x", 1, "vd-b_x")]  # ties by key
    assert str(charts.split(parts[:2], "S")) == (
        '<svg class="split" viewBox="0 0 1000 18" preserveAspectRatio="none" role="img" '
        'aria-label="S"><rect class="vd-c" x="0.00" y="0" width="666.67" height="18">'
        '<title>c: 2</title></rect><rect class="vd-a" x="666.67" y="0" width="333.33" '
        'height="18"><title>a: 1</title></rect></svg>'
    )
    assert str(charts.split([("z", 0, "vd-z")], "none")).endswith('aria-label="none"></svg>')


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


def test_ticks_thin_out_with_the_bucket_count() -> None:
    at = datetime(2026, 10, 21, tzinfo=IST)
    for n, ticks in ((12, 12), (18, 9), (30, 15), (48, 12)):  # one in round(n / 12)
        svg = str(charts.stacked([(at + timedelta(hours=k), {}) for k in range(n)], ["low"], "x",
                                 hourly=True))  # fmt: skip
        assert svg.count('text-anchor="middle"') == ticks, n
