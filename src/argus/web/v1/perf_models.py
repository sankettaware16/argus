"""The response figures' shapes (``GET /api/v1/performance``, D-340)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from argus.web import performance
from argus.web.v1.models import Out


class TimesOut(Out):
    """A set of durations, in seconds: how many there were, their median, their mean and the
    value 90 % of them stayed at or under. With none, the three are null."""

    count: int
    median_s: float | None
    mean_s: float | None
    p90_s: float | None


class KeptOut(Out):
    """How a target was kept. ``met`` and ``missed`` are settled (an incident still waiting past
    its target is missed already); ``pending`` still has time. ``share``: met of those settled,
    0 to 1, or null with nothing settled."""

    met: int
    missed: int
    pending: int
    share: float | None


class BandOut(Out):
    """One priority: what was raised in the span, its two targets and how each was kept."""

    band: Literal["P1", "P2", "P3", "P4"]
    raised: int
    triage_target_s: float
    resolve_target_s: float
    triage: KeptOut
    resolve: KeptOut
    triage_median_s: float | None


class OverdueOut(Out):
    """An incident past its target now: undecided past its time to a first decision
    (``triage``), or confirmed and not closed past its time to close (``resolve``)."""

    id: uuid.UUID
    number: int
    title: str
    state: Literal["suspected", "open", "assigned", "contained"]
    band: Literal["P1", "P2", "P3", "P4"]
    kind: Literal["triage", "resolve"]
    waited_s: float
    target_s: float


class PerformanceOut(Out):
    """How fast alerts became decisions for the incidents raised in the span. ``detect``: from
    an incident's first alert to ARGUS raising it (the mean is the mean time to detect);
    ``triage``: from there to a person's first decision (to acknowledge); ``resolve``: from a
    confirmation to the closure (to resolve). ``overdue`` is what is past its target now,
    whenever it was raised, the furthest past first; ``due_soon`` counts those with three
    quarters of their time used."""

    start: datetime
    end: datetime
    raised: int
    confirmed: int
    dismissed: int
    waiting: int
    detect: TimesOut
    triage: TimesOut
    resolve: TimesOut
    triage_kept: KeptOut
    resolve_kept: KeptOut
    bands: list[BandOut]
    overdue: list[OverdueOut]
    overdue_total: int
    due_soon: int


def _times(t: performance.Times) -> TimesOut:
    return TimesOut(count=t.count, median_s=t.median_s, mean_s=t.mean_s, p90_s=t.p90_s)


def _kept(k: performance.Kept) -> KeptOut:
    return KeptOut(met=k.met, missed=k.missed, pending=k.pending, share=k.share)


def out(p: performance.Performance) -> PerformanceOut:
    return PerformanceOut(
        start=p.start, end=p.end, raised=p.raised, confirmed=p.confirmed,
        dismissed=p.dismissed, waiting=p.waiting, detect=_times(p.detect),
        triage=_times(p.triage), resolve=_times(p.resolve), triage_kept=_kept(p.triage_kept),
        resolve_kept=_kept(p.resolve_kept),
        bands=[
            BandOut(band=b.band, raised=b.raised, triage_target_s=b.triage_target_s,  # type: ignore[arg-type]
                    resolve_target_s=b.resolve_target_s, triage=_kept(b.triage),
                    resolve=_kept(b.resolve), triage_median_s=b.triage_median_s)
            for b in p.bands
        ],
        overdue=[
            OverdueOut(id=o.id, number=o.number, title=o.title, state=o.state,  # type: ignore[arg-type]
                       band=o.band, kind=o.kind, waited_s=o.waited_s, target_s=o.target_s)  # type: ignore[arg-type]
            for o in p.overdue
        ],
        overdue_total=p.overdue_total, due_soon=p.due_soon,
    )  # fmt: skip
