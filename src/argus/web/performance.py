"""How fast alerts become decisions (the Dashboards' response figures, D-340): for the incidents
raised in a span, the time to detect (from an incident's first alert to ARGUS raising it), the
time to a person's first decision, and the time to close a confirmed one; each held against the
site's targets by priority (``sla.*``); and, whatever the span, what is past its target now.

Read from ARGUS's own tables: nothing is asked of the SIEM. A time is counted only between two
moments ARGUS recorded; an incident still waiting counts as missed once its target has passed,
and as "in time so far" before that, never as met."""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.config.settings import SlaSettings

BANDS = ("P1", "P2", "P3", "P4")
WAITING = ("suspected",)  # a possible incident nobody has decided
OPEN = ("open", "assigned", "contained")  # confirmed, not closed
OVERDUE_SHOWN = 10
SOON = 0.75  # this share of the target used: due soon

_ROWS = text(
    """
SELECT c.id, c.number, c.title, c.state, c.created_at, c.opened_at, c.closed_at,
       COALESCE(r.band, 'P4') AS band, a.first_alert,
       EXISTS (SELECT 1 FROM case_events e WHERE e.case_id = c.id AND e.kind = 'suspected')
         AS raised,
       d.decided_at
FROM cases c
LEFT JOIN LATERAL (SELECT band FROM risk_incidents r WHERE r.case_id = c.id
                   ORDER BY r.id DESC LIMIT 1) r ON true
LEFT JOIN LATERAL (SELECT min(i.first_event_at) AS first_alert FROM case_members m
                   JOIN investigations i ON i.id = m.investigation_id
                   WHERE m.case_id = c.id) a ON true
LEFT JOIN LATERAL (SELECT e.occurred_at AS decided_at FROM case_events e
                   WHERE e.case_id = c.id AND e.actor_user_id IS NOT NULL
                     AND e.kind IN ('confirmed', 'dismissed', 'merged_into')
                   ORDER BY e.occurred_at, e.id LIMIT 1) d ON true
WHERE (c.created_at >= :start AND c.created_at < :end)
   OR c.state IN ('suspected', 'open', 'assigned', 'contained')
ORDER BY c.number
"""
)


@dataclass(frozen=True, slots=True)
class Incident:
    """What the figures need of one incident."""

    id: uuid.UUID
    number: int
    title: str
    state: str
    band: str
    raised_at: datetime
    raised_by_argus: bool  # it began as a possible incident (a person did not open it)
    first_alert_at: datetime | None
    decided_at: datetime | None  # a person's first confirm, dismissal or merge
    opened_at: datetime | None  # confirmed
    closed_at: datetime | None


@dataclass(frozen=True, slots=True)
class Times:
    """A set of durations in seconds; with none, every figure is None."""

    count: int
    median_s: float | None
    mean_s: float | None
    p90_s: float | None


@dataclass(frozen=True, slots=True)
class Kept:
    """How a target was kept: ``met`` and ``missed`` are settled; ``pending`` still has time."""

    met: int = 0
    missed: int = 0
    pending: int = 0

    @property
    def share(self) -> float | None:
        """The share kept of those settled, 0 to 1; None with nothing settled."""
        settled = self.met + self.missed
        return self.met / settled if settled else None


@dataclass(frozen=True, slots=True)
class BandRow:
    band: str
    raised: int
    triage_target_s: float
    resolve_target_s: float
    triage: Kept
    resolve: Kept
    triage_median_s: float | None


@dataclass(frozen=True, slots=True)
class Overdue:
    """An incident past its target now."""

    id: uuid.UUID
    number: int
    title: str
    state: str
    band: str
    kind: Literal["triage", "resolve"]
    waited_s: float
    target_s: float


@dataclass(frozen=True, slots=True)
class Performance:
    start: datetime
    end: datetime
    raised: int  # incidents raised in the span, by ARGUS or by a person
    confirmed: int
    dismissed: int  # decided by a person and not confirmed
    waiting: int  # of the span's, still undecided
    detect: Times
    triage: Times
    resolve: Times
    triage_kept: Kept
    resolve_kept: Kept
    bands: tuple[BandRow, ...]
    overdue: tuple[Overdue, ...]
    overdue_total: int
    due_soon: int


def times(seconds: Iterable[float]) -> Times:
    """The median, the mean and the 90th percentile (the value at or above 90 % of them)."""
    values = sorted(seconds)
    n = len(values)
    if n == 0:
        return Times(0, None, None, None)
    middle = values[n // 2] if n % 2 else (values[n // 2 - 1] + values[n // 2]) / 2
    ninth = values[min(n - 1, max(0, -(-9 * n // 10) - 1))]
    return Times(n, middle, sum(values) / n, ninth)


def _kept(durations: Iterable[tuple[float, bool]], target_s: float) -> Kept:
    """``durations``: (seconds so far, settled). A settled one is met at or under the target; an
    unsettled one is missed once past it, else pending."""
    met = missed = pending = 0
    for seconds, settled in durations:
        if seconds > target_s:
            missed += 1
        elif settled:
            met += 1
        else:
            pending += 1
    return Kept(met, missed, pending)


def _sum(parts: Iterable[Kept]) -> Kept:
    parts = list(parts)
    return Kept(
        sum(p.met for p in parts), sum(p.missed for p in parts), sum(p.pending for p in parts)
    )


def _seconds(later: datetime, earlier: datetime) -> float:
    return max(0.0, (later - earlier).total_seconds())


def build(
    incidents: Sequence[Incident], start: datetime, end: datetime, now: datetime, sla: SlaSettings
) -> Performance:
    """The figures for the incidents raised in ``[start, end)``, and what is overdue at ``now``
    among all of ``incidents``."""
    cohort = [i for i in incidents if start <= i.raised_at < end]
    raised = [i for i in cohort if i.raised_by_argus]
    decided = [i for i in raised if i.decided_at is not None]
    confirmed = [i for i in cohort if i.opened_at is not None]
    bands = []
    for band in BANDS:
        triage_s = sla.triage(band).total_seconds()
        resolve_s = sla.resolve(band).total_seconds()
        mine = [i for i in raised if i.band == band]
        settled = [(_seconds(i.decided_at, i.raised_at), True) for i in mine if i.decided_at]
        waiting = [(_seconds(now, i.raised_at), False) for i in mine
                   if i.decided_at is None and i.state in WAITING]  # fmt: skip
        opened = [i for i in confirmed if i.band == band and i.opened_at is not None]
        closed = [(_seconds(i.closed_at, i.opened_at), True) for i in opened
                  if i.closed_at and i.opened_at]  # fmt: skip
        still = [(_seconds(now, i.opened_at), False) for i in opened
                 if i.closed_at is None and i.opened_at and i.state in OPEN]  # fmt: skip
        bands.append(BandRow(
            band, len([i for i in cohort if i.band == band]), triage_s, resolve_s,
            _kept([*settled, *waiting], triage_s), _kept([*closed, *still], resolve_s),
            times(s for s, _ in settled).median_s,
        ))  # fmt: skip
    overdue: list[Overdue] = []
    due_soon = 0
    for i in incidents:
        if i.state in WAITING and i.decided_at is None and i.raised_by_argus:
            kind, since, target = "triage", i.raised_at, sla.triage(i.band)
        elif i.state in OPEN and i.opened_at is not None and i.closed_at is None:
            kind, since, target = "resolve", i.opened_at, sla.resolve(i.band)
        else:
            continue
        waited, target_s = _seconds(now, since), target.total_seconds()
        if waited > target_s:
            overdue.append(Overdue(i.id, i.number, i.title, i.state, i.band,
                                   kind, waited, target_s))  # type: ignore[arg-type]  # fmt: skip
        elif waited >= SOON * target_s:
            due_soon += 1
    overdue.sort(key=lambda o: (-(o.waited_s / o.target_s), o.number))
    return Performance(
        start=start, end=end, raised=len(cohort), confirmed=len(confirmed),
        dismissed=len([i for i in decided if i.opened_at is None]),
        waiting=len([i for i in raised if i.decided_at is None and i.state in WAITING]),
        detect=times(_seconds(i.raised_at, i.first_alert_at) for i in raised if i.first_alert_at),
        triage=times(_seconds(i.decided_at, i.raised_at) for i in decided if i.decided_at),
        resolve=times(_seconds(i.closed_at, i.opened_at) for i in confirmed
                      if i.closed_at and i.opened_at),
        triage_kept=_sum(b.triage for b in bands), resolve_kept=_sum(b.resolve for b in bands),
        bands=tuple(bands), overdue=tuple(overdue[:OVERDUE_SHOWN]), overdue_total=len(overdue),
        due_soon=due_soon,
    )  # fmt: skip


async def read(conn: AsyncConnection, start: datetime, end: datetime) -> list[Incident]:
    """The incidents raised in the span, and every one that is undecided or open now."""
    rows = await conn.execute(_ROWS, {"start": start, "end": end})
    return [
        Incident(
            id=r.id, number=int(r.number), title=r.title, state=r.state, band=r.band,
            raised_at=r.created_at, raised_by_argus=bool(r.raised), first_alert_at=r.first_alert,
            decided_at=r.decided_at, opened_at=r.opened_at, closed_at=r.closed_at,
        )
        for r in rows
    ]  # fmt: skip


def span_of(range_name: str, now: datetime) -> tuple[datetime, datetime]:
    days = {"24h": 1, "7d": 7, "30d": 30, "90d": 90}.get(range_name, 7)
    return now - timedelta(days=days), now
