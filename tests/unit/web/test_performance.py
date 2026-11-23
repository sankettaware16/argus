"""The Dashboards' response figures (D-340): the times to detect, to a person's first decision
and to close, each against the targets by priority; what is past its target now. An incident
still waiting is missed once its target has passed and pending before that, never met."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from argus.config.settings import SlaSettings
from argus.web import performance
from argus.web.performance import Incident, Kept, build, times
from argus.web.v1 import perf_models

pytestmark = pytest.mark.unit

NOW = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
START = NOW - timedelta(days=7)
SLA = SlaSettings()
H = timedelta(hours=1)


def incident(number: int, band: str = "P2", *, raised: timedelta, alert: timedelta | None = None,
             decided: timedelta | None = None, confirmed: bool = False,
             closed: timedelta | None = None, state: str | None = None,
             by_argus: bool = True) -> Incident:  # fmt: skip
    """An incident raised ``raised`` before NOW; ``alert`` before that its first alert;
    ``decided`` after the raise a person's decision (a confirmation with ``confirmed``);
    ``closed`` after the confirmation its closure."""
    raised_at = NOW - raised
    decided_at = raised_at + decided if decided is not None else None
    opened_at = decided_at if confirmed else None
    closed_at = opened_at + closed if opened_at is not None and closed is not None else None
    if state is None:
        state = ("closed" if closed_at or (decided_at and not confirmed) else
                 "open" if opened_at else "suspected")  # fmt: skip
    return Incident(
        id=uuid.UUID(int=number), number=number, title=f"Incident {number}", state=state,
        band=band, raised_at=raised_at, raised_by_argus=by_argus,
        first_alert_at=raised_at - alert if alert is not None else None,
        decided_at=decided_at, opened_at=opened_at, closed_at=closed_at,
    )  # fmt: skip


def test_times_are_the_median_the_mean_and_the_ninth_decile() -> None:
    assert times([]) == performance.Times(0, None, None, None)
    assert times([30.0]) == performance.Times(1, 30.0, 30.0, 30.0)
    assert times([40.0, 10.0, 20.0]).median_s == 20.0
    assert times([10.0, 20.0, 30.0, 40.0]).median_s == 25.0
    ten = times([float(n) for n in range(1, 11)])
    assert (ten.count, ten.mean_s, ten.p90_s) == (10, 5.5, 9.0)
    assert times([1.0, 100.0]).p90_s == 100.0


def test_the_three_times_are_counted_between_recorded_moments() -> None:
    rows = [
        incident(
            1,
            raised=48 * H,
            alert=2 * H,
            decided=30 * 60 * timedelta(seconds=1),
            confirmed=True,
            closed=10 * H,
        ),
        incident(2, raised=24 * H, alert=4 * H, decided=3 * H),  # dismissed
        incident(3, raised=2 * H, alert=H),  # still waiting
        incident(4, raised=3 * H, by_argus=False, decided=timedelta(0), confirmed=True),
    ]
    got = build(rows, START, NOW, NOW, SLA)
    assert (got.raised, got.confirmed, got.dismissed, got.waiting) == (4, 2, 1, 1)
    assert got.detect == times([7200.0, 14400.0, 3600.0])
    assert got.triage == times([1800.0, 10800.0])  # the one a person opened is not triage
    assert got.resolve == times([36000.0])
    assert (got.detect.mean_s, got.triage.median_s) == (8400.0, 6300.0)


def test_a_time_before_its_start_counts_as_nothing_not_as_negative() -> None:
    late = incident(1, raised=H, alert=-2 * H)  # its first alert is after the raise
    assert build([late], START, NOW, NOW, SLA).detect.median_s == 0.0


@pytest.mark.parametrize(
    ("row", "kept"),
    [
        (incident(1, "P1", raised=5 * H, decided=59 * timedelta(minutes=1)), Kept(1, 0, 0)),
        (incident(1, "P1", raised=5 * H, decided=H), Kept(1, 0, 0)),  # at the target: kept
        (incident(1, "P1", raised=5 * H, decided=61 * timedelta(minutes=1)), Kept(0, 1, 0)),
        (incident(1, "P1", raised=30 * timedelta(minutes=1)), Kept(0, 0, 1)),  # still in time
        (incident(1, "P1", raised=2 * H), Kept(0, 1, 0)),  # waiting past it: missed already
        (incident(1, "P4", raised=2 * H), Kept(0, 0, 1)),  # the same wait, a P4's 72 hours
    ],
)
def test_a_target_is_met_missed_or_still_pending(row: Incident, kept: Kept) -> None:
    got = build([row], START, NOW, NOW, SLA)
    assert got.triage_kept == kept
    band = next(b for b in got.bands if b.band == row.band)
    assert band.triage == kept
    assert band.raised == 1


def test_the_share_is_of_those_settled_and_null_with_none() -> None:
    assert Kept(3, 1, 5).share == 0.75
    assert Kept(0, 0, 4).share is None
    assert Kept(0, 2, 0).share == 0.0


def test_closing_has_its_own_target_from_the_confirmation() -> None:
    rows = [
        incident(1, "P1", raised=60 * H, decided=H, confirmed=True, closed=20 * H),  # in 24 h
        incident(2, "P1", raised=60 * H, decided=H, confirmed=True, closed=30 * H),  # late
        incident(3, "P1", raised=60 * H, decided=H, confirmed=True),  # open for 59 h: missed
        incident(4, "P1", raised=10 * H, decided=H, confirmed=True),  # open for 9 h: in time
        incident(5, "P1", raised=10 * H, decided=H),  # dismissed: no closing target
    ]
    got = build(rows, START, NOW, NOW, SLA)
    assert got.resolve_kept == Kept(1, 2, 1)
    assert got.triage_kept == Kept(5, 0, 0)
    assert next(b for b in got.bands if b.band == "P1").resolve_target_s == 86400.0


def test_what_is_overdue_now_is_listed_the_furthest_past_first_whenever_it_was_raised() -> None:
    old = incident(7, "P2", raised=30 * 24 * H)  # raised before the span: still listed
    rows = [
        incident(1, "P1", raised=3 * H),  # 3x its hour
        incident(2, "P2", raised=6 * H),  # 1.5x its four hours
        incident(3, "P3", raised=20 * H),  # 20 of 24 hours: due soon
        incident(4, "P4", raised=2 * H),  # in time
        incident(5, "P1", raised=80 * H, decided=H, confirmed=True),  # open 79 h of 24
        incident(6, "P1", raised=9 * H, decided=H),  # dismissed: nothing waits
        old,
    ]
    got = build(rows, START, NOW, NOW, SLA)
    assert [(o.number, o.kind) for o in got.overdue] == [
        (7, "triage"), (5, "resolve"), (1, "triage"), (2, "triage"),
    ]  # fmt: skip
    assert got.overdue_total == 4
    assert got.due_soon == 1
    assert got.raised == 6  # the old one is not of this span
    first = got.overdue[0]
    assert (first.waited_s, first.target_s, first.state) == (30 * 86400.0, 4 * 3600.0, "suspected")


def test_the_list_is_cut_and_the_total_still_says_how_many() -> None:
    rows = [incident(n, "P1", raised=(n + 2) * H) for n in range(1, 15)]
    got = build(rows, START, NOW, NOW, SLA)
    assert (len(got.overdue), got.overdue_total) == (performance.OVERDUE_SHOWN, 14)
    assert got.overdue[0].number == 14


def test_the_sites_own_targets_decide() -> None:
    strict = SlaSettings(triage_p4=timedelta(minutes=30))
    row = incident(1, "P4", raised=H)
    assert build([row], START, NOW, NOW, SLA).triage_kept == Kept(0, 0, 1)
    assert build([row], START, NOW, NOW, strict).triage_kept == Kept(0, 1, 0)
    assert strict.triage("P9") == timedelta(minutes=30)  # an unknown band has P4's


def test_the_api_shape_carries_every_figure() -> None:
    rows = [incident(1, "P1", raised=3 * H), incident(2, "P2", raised=5 * H, decided=H)]
    out = perf_models.out(build(rows, START, NOW, NOW, SLA))
    assert [b.band for b in out.bands] == ["P1", "P2", "P3", "P4"]
    assert out.triage_kept.model_dump() == {"met": 1, "missed": 1, "pending": 0, "share": 0.5}
    assert out.overdue[0].model_dump(mode="json")["kind"] == "triage"
    assert out.triage.median_s == 3600.0


def test_a_span_is_the_ranges_days_back_from_now() -> None:
    assert performance.span_of("24h", NOW) == (NOW - timedelta(days=1), NOW)
    assert performance.span_of("90d", NOW)[0] == NOW - timedelta(days=90)
