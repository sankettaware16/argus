"""The rules of a verified zero (Q-F1, plan §7.3 point 1): table tests for every reason, the
gate's properties (no known zero without continuity; watermarks only advance), the bridge
over the quiet hours, the 72-hour windows, and the scenarios of lag, gaps and a late
sub-stream."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.freshness.model import (
    COMPLETE,
    EMPTY,
    FAILED,
    OK,
    REASONS,
    REFUSED,
    Check,
    Reading,
    Windows,
    advance,
    lags,
    quiet_nights,
    verify,
    windows,
)

pytestmark = pytest.mark.unit
T0 = datetime(2026, 10, 23, 6, 0, tzinfo=UTC)
MIN = timedelta(minutes=1)
M = 3 * MIN  # the margin in these tests
GAP = 10 * MIN
SEC = timedelta(seconds=1)


def ok(at: datetime, lag: timedelta = timedelta(seconds=5), source: str = "squid") -> Reading:
    """A reading at ``at`` whose newest document is ``lag`` behind (ingested just now)."""
    return Reading(source, at, OK, at - timedelta(seconds=1), at - lag)


def every(start: datetime, end: datetime, step: timedelta = 5 * MIN, **kw: object) -> list[Reading]:
    out, t = [], start
    while t <= end:
        out.append(ok(t, **kw))  # type: ignore[arg-type]
        t += step
    return out


def check(
    readings: list[Reading],
    start: datetime = T0,
    end: datetime | None = None,
    asked: datetime | None = None,
    margin: timedelta | None = M,
    **kw: object,
) -> Check:
    end = start + 30 * MIN if end is None else end
    asked = end + 30 * MIN if asked is None else asked
    return verify(start, end, asked, readings, margin, gap=GAP, **kw)  # type: ignore[arg-type]


FLOWING = every(T0 - 20 * MIN, T0 + 70 * MIN)


def test_a_flowing_source_verifies_the_zero_and_says_how_far() -> None:
    got = check(FLOWING)
    assert got.known
    assert got.reason == COMPLETE
    assert not got.bridged
    # the earliest reading past end + margin: 06:35 (ingested 06:34:59) less 3 minutes
    assert got.complete_to == T0 + 35 * MIN - timedelta(seconds=1) - M


@pytest.mark.parametrize(
    ("readings", "kw", "reason"),
    [
        (FLOWING, {"margin": None}, "no_margin"),
        # the search was sent before any reading showed the source past the end
        (FLOWING, {"asked": T0 + 32 * MIN}, "not_past_end"),
        (every(T0 - 20 * MIN, T0 + 30 * MIN), {}, "not_past_end"),
        # nothing at or before the start (within the gap)
        (every(T0 + 1 * MIN, T0 + 70 * MIN), {}, "no_anchor"),
        (every(T0 - 40 * MIN, T0 - 11 * MIN) + every(T0 + 4 * MIN, T0 + 70 * MIN), {}, "no_anchor"),
        # a reading behind by more than the margin across the window
        ([*FLOWING, ok(T0 + 12 * MIN, lag=4 * MIN)], {}, "late"),
        ([*FLOWING, Reading("squid", T0 + 12 * MIN, EMPTY)], {}, "silent"),
        # 15 minutes without a reading inside the window
        (
            [r for r in FLOWING if not T0 + 5 * MIN <= r.at <= T0 + 15 * MIN]
            + [Reading("squid", T0 + 10 * MIN, FAILED), Reading("squid", T0 + 12 * MIN, REFUSED)],
            {},
            "gap",
        ),
    ],
)
def test_every_reason_to_say_could_not_tell(
    readings: list[Reading], kw: dict[str, object], reason: str
) -> None:
    got = check(readings, **kw)  # type: ignore[arg-type]
    assert (got.known, got.reason, got.complete_to) == (False, reason, None)


def test_a_failed_or_refused_reading_is_only_a_gap() -> None:
    noisy = [
        *FLOWING,
        Reading("squid", T0 + 7 * MIN, FAILED),
        Reading("squid", T0 + 8 * MIN, REFUSED),
    ]
    assert check(noisy).known


def test_the_window_edges_count_exactly() -> None:
    anchor_at_gap = [ok(T0 - GAP), *every(T0 - GAP + 5 * MIN, T0 + 70 * MIN)]
    assert check(anchor_at_gap).known
    early = [ok(T0 - GAP - timedelta(seconds=1)), *every(T0 + 5 * MIN, T0 + 70 * MIN)]
    assert check(early).reason == "no_anchor"
    lag_at_margin = [*FLOWING, ok(T0 + 12 * MIN, lag=M)]
    assert check(lag_at_margin).known
    # a gap of exactly ``gap`` passes, a second more does not
    exact = [r for r in FLOWING if not T0 + 1 * MIN <= r.at <= T0 + 9 * MIN]
    assert check(exact).known
    over = [r for r in exact if r.at != T0 + 10 * MIN] + [ok(T0 + 10 * MIN + timedelta(seconds=1))]
    assert check(over).reason == "gap"


def test_the_clock_that_is_earlier_wins() -> None:
    """An ingest node whose clock runs ahead never stretches how far the logs are complete."""
    ahead = [Reading("squid", r.at, OK, r.at + 20 * MIN, r.event_at) for r in FLOWING]
    got = check(ahead)
    assert got.known
    assert got.complete_to == T0 + 35 * MIN - M  # the reading's own time, not the ingest node's


def test_a_reading_after_the_search_never_counts() -> None:
    """The search must come after the reading that shows the logs complete."""
    asked = T0 + 34 * MIN
    assert check(FLOWING, asked=asked).reason == "not_past_end"
    assert check(FLOWING, asked=T0 + 35 * MIN).known


# --------------------------------------------------------------------------- the quiet hours

NIGHT = datetime(2026, 10, 24, 0, 0, tzinfo=UTC)
ACROSS = every(NIGHT - 40 * MIN, NIGHT - 5 * MIN) + every(NIGHT + 90 * MIN, NIGHT + 150 * MIN)


def test_quiet_hours_make_a_gap_and_the_edges_bridge_it() -> None:
    start, end = NIGHT - 30 * MIN, NIGHT + 100 * MIN
    strict = verify(start, end, NIGHT + 150 * MIN, ACROSS, M, gap=GAP)
    assert (strict.known, strict.reason) == (False, "quiet_hours")
    bridged = verify(start, end, NIGHT + 150 * MIN, ACROSS, M, gap=GAP, bridge="edges")
    assert bridged.known
    assert bridged.bridged


@pytest.mark.parametrize(
    "readings",
    [
        # the last reading before 00:00 is more than ``gap`` before it
        every(NIGHT - 40 * MIN, NIGHT - 15 * MIN) + every(NIGHT + 90 * MIN, NIGHT + 150 * MIN),
        # the first reading after 01:30 is more than ``gap`` after it
        every(NIGHT - 40 * MIN, NIGHT - 5 * MIN) + every(NIGHT + 101 * MIN, NIGHT + 150 * MIN),
        # an edge is late
        [
            *every(NIGHT - 40 * MIN, NIGHT - 10 * MIN),
            ok(NIGHT - 5 * MIN, lag=10 * MIN),
            *every(NIGHT + 90 * MIN, NIGHT + 150 * MIN),
        ],
    ],
)
def test_the_bridge_needs_both_edges_close_and_within_the_margin(readings: list[Reading]) -> None:
    got = verify(
        NIGHT - 30 * MIN, NIGHT + 100 * MIN, NIGHT + 150 * MIN, readings, M, gap=GAP, bridge="edges"
    )
    assert not got.known


def test_the_bridge_never_spans_more_than_one_night_or_a_day_gap() -> None:
    day_gap = every(T0 - 20 * MIN, T0 + 5 * MIN) + every(T0 + 40 * MIN, T0 + 90 * MIN)
    got = verify(T0, T0 + 30 * MIN, T0 + 90 * MIN, day_gap, M, gap=GAP, bridge="edges")
    assert got.reason == "gap"
    two_nights = every(NIGHT - 20 * MIN, NIGHT - 5 * MIN) + every(
        NIGHT + timedelta(days=1, minutes=90), NIGHT + timedelta(days=1, minutes=150)
    )
    got = verify(
        NIGHT - 10 * MIN,
        NIGHT + timedelta(days=1, minutes=95),
        NIGHT + timedelta(days=1, minutes=150),
        two_nights,
        M,
        gap=GAP,
        bridge="edges",
    )
    assert not got.known


def test_quiet_nights() -> None:
    assert quiet_nights(T0, T0 + 5 * MIN) == []
    assert quiet_nights(NIGHT - MIN, NIGHT + MIN) == [(NIGHT, NIGHT + 90 * MIN)]
    assert quiet_nights(NIGHT + 90 * MIN, NIGHT + 91 * MIN) == []
    assert len(quiet_nights(NIGHT - MIN, NIGHT + timedelta(days=2))) == 2  # open at the end
    assert len(quiet_nights(NIGHT - MIN, NIGHT + timedelta(days=2, minutes=1))) == 3


# --------------------------------------------------------------------------- properties

readings_st = st.lists(
    st.tuples(
        st.integers(min_value=-60, max_value=200),  # minutes from T0
        st.sampled_from([OK, OK, OK, EMPTY, FAILED, REFUSED]),
        st.integers(min_value=0, max_value=600),  # lag in seconds
    ),
    max_size=60,
)


def build(raw: list[tuple[int, str, int]]) -> list[Reading]:
    out = []
    for minute, outcome, lag in raw:
        at = T0 + minute * MIN
        if outcome == OK:
            out.append(Reading("squid", at, OK, at, at - timedelta(seconds=lag)))
        else:
            out.append(Reading("squid", at, outcome))
    return out


@given(
    raw=readings_st,
    start=st.integers(min_value=-30, max_value=120),
    length=st.integers(min_value=0, max_value=60),
    asked=st.integers(min_value=0, max_value=240),
    bridge=st.sampled_from(["none", "edges"]),
)
def test_no_known_zero_without_continuity(
    raw: list[tuple[int, str, int]], start: int, length: int, asked: int, bridge: str
) -> None:
    """Whenever a zero is verified: a reading within the margin before the search shows the
    logs complete past the end; one sits within the gap before the start; from it to that
    reading, the readings within the margin are never more than the gap apart (or the bridge
    crossed one night) and none that answered was late or silent."""
    readings = build(raw)
    a, b, s = T0 + start * MIN, T0 + (start + length) * MIN, T0 + asked * MIN
    got = verify(a, b, s, readings, M, gap=GAP, bridge=bridge)  # type: ignore[arg-type]
    assert got.reason in REASONS
    if not got.known:
        return
    usable = sorted((r for r in readings if r.at <= s), key=lambda r: r.at)
    confirm = next(r for r in usable if r.within(M) and r.complete_to(M) >= b)  # type: ignore[operator]
    assert got.complete_to == confirm.complete_to(M) >= b  # type: ignore[operator]
    anchors = [r for r in usable if r.within(M) and a - GAP <= r.at <= a]
    assert anchors
    span = [r for r in usable if anchors[-1].at <= r.at <= confirm.at]
    assert all(r.outcome != EMPTY for r in span)
    assert all(r.within(M) for r in span if r.outcome == OK)
    good = [r.at for r in span if r.within(M)]
    gaps = [later - earlier for earlier, later in itertools.pairwise(good)]
    long = [g for g in gaps if g > GAP]
    if bridge == "none":
        assert not long
    else:
        assert len(long) <= len(quiet_nights(a - GAP, confirm.at))
        assert got.bridged == bool(long)


@given(
    raw=readings_st,
    start=st.integers(-30, 120),
    length=st.integers(0, 60),
    asked=st.integers(0, 240),
)
def test_the_bridge_never_loses_a_zero_and_more_readings_after_the_search_change_nothing(
    raw: list[tuple[int, str, int]], start: int, length: int, asked: int
) -> None:
    readings = build(raw)
    a, b, s = T0 + start * MIN, T0 + (start + length) * MIN, T0 + asked * MIN
    strict = verify(a, b, s, readings, M, gap=GAP)
    edged = verify(a, b, s, readings, M, gap=GAP, bridge="edges")
    if strict.known:
        assert edged.known
        assert edged.complete_to == strict.complete_to
    later = [ok(s + MIN), Reading("squid", s + 2 * MIN, EMPTY)]
    assert verify(a, b, s, readings + later, M, gap=GAP) == strict


@given(raw=readings_st)
def test_a_watermark_only_advances(raw: list[tuple[int, str, int]]) -> None:
    mark = None
    seen = []
    for reading in build(raw):
        before = mark
        mark = advance(mark, reading)
        if before is not None:
            assert mark is not None
            assert mark.ingested >= before.ingested  # type: ignore[operator]
        if reading.ingested is not None:
            seen.append(reading.ingested)
    assert (mark.ingested if mark else None) == (max(seen) if seen else None)


def test_a_reading_is_consistent() -> None:
    with pytest.raises(ValueError, match="document"):
        Reading("squid", T0, OK)
    with pytest.raises(ValueError, match="document"):
        Reading("squid", T0, EMPTY, T0, T0)
    with pytest.raises(ValueError, match="unknown"):
        Reading("squid", T0, "maybe")
    with pytest.raises(ValueError, match="aware"):
        Reading("squid", T0.replace(tzinfo=None), REFUSED)
    with pytest.raises(ValueError, match="aware"):
        Reading("squid", T0, OK, T0.replace(tzinfo=None), T0)
    with pytest.raises(ValueError, match=r"\w"):
        Check(True, "gap")
    with pytest.raises(ValueError, match=r"\w"):
        Check(False, COMPLETE)
    with pytest.raises(ValueError, match=r"\w"):
        Check(True, COMPLETE)  # a known check says how far
    with pytest.raises(ValueError, match=r"\w"):
        Check(False, "gap", bridged=True)
    with pytest.raises(ValueError, match=r"\w"):
        verify(T0, T0 - MIN, T0, [], M)
    with pytest.raises(ValueError, match=r"\w"):
        verify(T0, T0, T0, [], -M)
    with pytest.raises(ValueError, match=r"\w"):
        verify(T0, T0, T0, [], M, gap=timedelta(0))
    with pytest.raises(ValueError, match=r"\w"):
        verify(T0, T0, T0, [], M, bridge="always")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match=r"\w"):
        verify(T0.replace(tzinfo=None), T0, T0, [], M)


# --------------------------------------------------------------------------- scenarios


def test_a_source_lagging_behind_is_could_not_tell_until_it_catches_up() -> None:
    """Lag: the source runs 20 minutes behind across the window, then catches up."""
    all_behind = every(T0 - 20 * MIN, T0 + 60 * MIN, lag=20 * MIN)
    assert check(all_behind).reason == "not_past_end"  # nothing shows it past the end
    behind = [r for r in FLOWING if not T0 + 5 * MIN <= r.at <= T0 + 20 * MIN]
    behind += every(T0 + 5 * MIN, T0 + 20 * MIN, lag=20 * MIN)
    assert check(behind).reason == "late"
    caught_up = every(T0 - 20 * MIN, T0 + 70 * MIN)
    assert check(caught_up).known


def test_an_outage_inside_the_window_is_a_gap_even_when_the_source_recovers() -> None:
    outage = every(T0 - 20 * MIN, T0 + 5 * MIN) + every(T0 + 45 * MIN, T0 + 90 * MIN)
    assert check(outage).reason == "gap"


def test_a_late_sub_stream_inside_a_flowing_source_is_the_known_limit() -> None:
    """A sub-stream 30-120 minutes late while the rest flows: the readings see the flowing part
    (the newest document by ingest time), so the zero passes. The documented, measured limit
    (plan §5 Q-F1); the shadow audit is what bounds it."""
    flowing_with_a_late_part = FLOWING  # the late part never becomes the newest document
    assert check(flowing_with_a_late_part).known
    # if the newest document by ingest time is from the late part, the reading is late
    late_doc = [*FLOWING, ok(T0 + 20 * MIN, lag=45 * MIN)]
    assert check(late_doc).reason == "late"


# --------------------------------------------------------------------------- 72-hour windows


def test_72_hour_windows_strict_and_bridged() -> None:
    start = datetime(2026, 10, 20, 2, 0, tzinfo=UTC)
    readings: list[Reading] = []
    t = start
    while t < start + timedelta(days=5):
        if not (t.hour == 0 or (t.hour == 1 and t.minute < 30)):
            readings.append(ok(t))
        t += 5 * MIN
    got = windows(readings, M, gap=GAP)
    assert got.judged > 0
    assert got.strict == 0  # every 72-hour window crosses the pause
    # windows that start inside the pause (01:00) have no reading at their start
    starts = [start + timedelta(hours=h) for h in range(1, 200)]
    judged = [b for b in starts if b + timedelta(hours=72) + M + GAP <= readings[-1].at]
    assert got.judged == len(judged)
    assert got.judged - got.bridged == sum(b.hour == 1 for b in judged) == 2
    assert got.share(False) == 0.0
    assert got.share(True) == got.bridged / got.judged
    assert windows(readings, None) == Windows(0, 0, 0)
    assert windows([], M) == Windows(0, 0, 0)
    assert Windows(0, 0, 0).share(True) is None


def test_lags_only_from_recent_readings_that_answered() -> None:
    now = T0 + 4 * MIN
    newest = {
        "squid": ok(T0, lag=MIN),  # its own lag at the reading: ingested - event time
        "dns": Reading("dns", T0, FAILED),  # unknown, and no earlier document: no lag
        "nginx": Reading("nginx", T0, EMPTY),  # silent: silence is not lateness (review F5)
        "postfix": ok(T0 - 31 * MIN - 4 * MIN),  # too old to say anything now
    }
    last_ok = {"nginx": Reading("nginx", T0 - 40 * MIN, OK, T0 - 40 * MIN, T0 - 41 * MIN)}
    assert lags(newest, last_ok, now) == {"squid": MIN - SEC}  # ok(): ingested a second before
    # a refused or failed newest reading keeps the last known lag while that document is
    # recent, so a stopped lane neither sets nor releases DEGRADED (review F5)
    failed = {"dns": Reading("dns", T0, FAILED), "squid": Reading("squid", T0, REFUSED)}
    recent = {"dns": ok(T0 - 10 * MIN, lag=20 * MIN), "squid": ok(T0 - 40 * MIN, lag=MIN)}
    assert lags(failed, recent, now) == {"dns": 20 * MIN - SEC}  # squid's document is too old
    assert lags({"nginx": Reading("nginx", T0, EMPTY)}, {}, now) == {}  # never had a document
    future = {"nginx": Reading("nginx", T0, OK, T0, T0 + 10 * MIN)}
    assert lags(future, {}, T0) == {"nginx": timedelta(0)}
    edge = {"squid": ok(T0, lag=MIN)}
    assert lags(edge, {}, T0 + 30 * MIN) == {"squid": MIN - SEC}
    assert lags(edge, {}, T0 + 30 * MIN + timedelta(seconds=1)) == {}
