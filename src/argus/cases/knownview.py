"""What the pages, the API and the reports say about notified cases (AR4b, D-169 points 4, 5 and 8):
read-only. A notified case is "still active, N alerts in D days since notice" (or, once a block is
recorded, "blocked at the network; the device is still infected; owner notified on <date>"), with
its alerts a day, the notices and blocks a person recorded, the reminders ARGUS suggested that
nobody has answered, and the changes since the notice that nobody has looked at.

The alerts counted are those of the case's member investigations that came after the notice: the
known infection's investigations join the case silently (:mod:`argus.cases.knownrun`), so this is
the count of what ARGUS did not raise. The days are IST days, as the rest of the reports. A change
stays in the list until a person reviews it (D-181), and the destinations the case's devices
reached that nobody flags and the case did not hold are listed as new since the notice.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date, datetime

from sqlalchemy import TextClause, text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus import site
from argus.cases import known

CHANGES_SHOWN = 20
NEW_SHOWN = 50  # new destinations listed (the count is of all that are kept)
# the notices a person recorded since the last one they withdrew (``n`` is the notice's alias)
AFTER_WITHDRAWAL = (
    "n.case_version > coalesce((SELECT max(w.case_version) FROM case_events w"
    " WHERE w.case_id = n.case_id AND w.kind = 'notice_withdrawn'), 0)"
)


@dataclass(frozen=True)
class NoticeRow:
    """What a person recorded: ``owner`` (who was told, how) or ``block`` (who, where)."""

    kind: str
    at: datetime
    told: str  # who was told, or who blocked
    how: str  # the way, or where it was blocked
    managed: bool | None
    note: str | None
    by_user_id: int
    case_version: int
    withdrawn: bool = False  # the person who recorded it withdrew it (it was a mistake)


@dataclass(frozen=True)
class ReminderRow:
    kind: str
    why: str
    suggested_at: datetime


@dataclass(frozen=True)
class ChangeRow:
    investigation_id: uuid.UUID
    rule: str
    why: str
    last_event_at: datetime | None


@dataclass(frozen=True)
class NewDestination:
    """A destination a notified device reached after the notice that nobody flags and the case did
    not hold (D-181): counted, not raised."""

    kind: str
    value: str
    added_at: datetime


@dataclass(frozen=True)
class KnownCase:
    case_id: uuid.UUID
    number: int
    title: str
    state: str
    severity: str
    notified_at: datetime
    blocked_at: datetime | None
    managed: bool | None  # the first notice's word: the machines are campus-managed
    devices: int
    owner_notices: int
    blocks: int
    alerts: int  # since the notice
    days: int  # whole days since the notice, at least 1
    per_day: dict[str, int] = field(default_factory=dict)  # IST day -> alerts, since the notice
    last_alert_at: datetime | None = None
    reminders: tuple[ReminderRow, ...] = ()  # suggested, not answered
    changes: tuple[ChangeRow, ...] = ()  # raised since the notice, not reviewed
    new_destinations: tuple[NewDestination, ...] = ()  # the first ``NEW_SHOWN``, newest last
    new_total: int = 0  # all the case keeps (it stops at ``known.NEW_PER_CASE``)

    @property
    def trend(self) -> str:
        return known.trend(self.per_day)

    def line(self, stamp: Callable[[datetime], str]) -> str:
        return known.still_active_line(
            self.alerts, self.days, self.notified_at, self.blocked_at, stamp
        )


_CASES = text(
    "SELECT c.id, c.number, c.title, c.state, c.severity, c.notified_at, c.blocked_at,"  # noqa: S608 - constant fragments; every value is bound
    " (SELECT n.managed FROM case_notices n WHERE n.case_id = c.id AND n.kind = 'owner'"
    f"  AND {AFTER_WITHDRAWAL} ORDER BY n.case_version LIMIT 1) AS managed,"
    " (SELECT count(*) FROM case_indicators i WHERE i.case_id = c.id AND i.removed_at IS NULL"
    "  AND i.role = 'actor' AND i.kind IN ('ip', 'host')) AS devices,"
    " (SELECT count(*) FROM case_notices n WHERE n.case_id = c.id AND n.kind = 'owner'"
    f"  AND {AFTER_WITHDRAWAL}) AS owner_notices,"
    " (SELECT count(*) FROM case_notices n WHERE n.case_id = c.id AND n.kind = 'block') AS blocks"
    " FROM cases c WHERE c.notified_at IS NOT NULL AND c.state IN ('open', 'assigned')"
    " AND (CAST(:only AS uuid) IS NULL OR c.id = CAST(:only AS uuid)) ORDER BY c.number"
)


def _alerts() -> TextClause:
    """The alert counts per day; the days are the site's days (``site.timezone``), as the other
    reports count them."""
    return text(
        "SELECT m.case_id,"  # noqa: S608 - constant fragments; every value is bound
        f" (COALESCE(a.event_time, a.detected_at) AT TIME ZONE {site.zone_sql()})::date AS day,"
        " count(*) AS n, max(COALESCE(a.event_time, a.detected_at)) AS last"
        " FROM cases c JOIN case_members m ON m.case_id = c.id AND m.removed_at IS NULL"
        " JOIN investigation_alerts l ON l.investigation_id = m.investigation_id"
        " JOIN alert_records a ON a.alert_id = l.alert_id"
        " WHERE c.notified_at IS NOT NULL AND c.state IN ('open', 'assigned')"
        " AND COALESCE(a.event_time, a.detected_at) >= c.notified_at"
        " AND COALESCE(a.event_time, a.detected_at) < :end"
        " AND (CAST(:only AS uuid) IS NULL OR c.id = CAST(:only AS uuid)) GROUP BY 1, 2"
    )


_REMINDERS = text(
    "SELECT case_id, kind, why, suggested_at FROM case_reminders WHERE dismissed_at IS NULL"
    " AND (CAST(:only AS uuid) IS NULL OR case_id = CAST(:only AS uuid))"
    " ORDER BY suggested_at"
)
_CHANGES = text(
    "SELECT k.case_id, i.id, coalesce(i.rule_name, i.rule_id) AS rule, k.why, i.last_event_at"
    " FROM case_known_matches k JOIN investigations i ON i.id = k.investigation_id"
    " WHERE k.outcome = 'changed' AND NOT EXISTS (SELECT 1 FROM review_state s"
    " WHERE s.investigation_id = i.id AND s.action = 'reviewed'"
    " AND s.version >= k.changed_version) AND (CAST(:only AS uuid) IS NULL"
    " OR k.case_id = CAST(:only AS uuid))"
    " ORDER BY i.last_event_at DESC NULLS LAST, i.id"
)
_NEW = text(
    "SELECT x.case_id, x.value, x.added_at, count(*) OVER (PARTITION BY x.case_id) AS total"
    " FROM case_known_keys x JOIN cases c ON c.id = x.case_id"
    " WHERE x.kind = 'new_destination' AND x.source = 'change' AND c.notified_at IS NOT NULL"
    " AND c.state IN ('open', 'assigned')"
    " AND (CAST(:only AS uuid) IS NULL OR x.case_id = CAST(:only AS uuid))"
    " ORDER BY x.case_id, x.added_at, x.value"
)
_NOTICES = text(
    "SELECT n.kind, n.at, n.told, n.how, n.managed, n.note, n.by_user_id, n.case_version,"  # noqa: S608 - constant fragments; every value is bound
    f" NOT ({AFTER_WITHDRAWAL}) AS withdrawn FROM case_notices n"
    " WHERE n.case_id = :c ORDER BY n.at, n.case_version"
)


async def notified(
    conn: AsyncConnection, now: datetime, *, case_id: uuid.UUID | None = None
) -> list[KnownCase]:
    """The cases whose owner was told and that are still open or assigned (one case with
    ``case_id``), their alerts since the notice as at ``now``."""
    only = None if case_id is None else str(case_id)
    cases = (await conn.execute(_CASES, {"only": only})).all()
    if not cases:
        return []
    alerts: dict[uuid.UUID, dict[date, tuple[int, datetime]]] = defaultdict(dict)
    for r in await conn.execute(_alerts(), {"only": only, "end": now}):
        alerts[r.case_id][r.day] = (int(r.n), r.last)
    held: dict[uuid.UUID, list[ReminderRow]] = defaultdict(list)
    for r in await conn.execute(_REMINDERS, {"only": only}):
        held[r.case_id].append(ReminderRow(r.kind, r.why, r.suggested_at))
    changes: dict[uuid.UUID, list[ChangeRow]] = defaultdict(list)
    for r in await conn.execute(_CHANGES, {"only": only}):
        changes[r.case_id].append(ChangeRow(r.id, r.rule, r.why, r.last_event_at))
    new: dict[uuid.UUID, list[NewDestination]] = defaultdict(list)
    totals: dict[uuid.UUID, int] = {}
    for r in await conn.execute(_NEW, {"only": only}):
        totals[r.case_id] = int(r.total)
        key = known.split(r.value)
        if key is not None and len(new[r.case_id]) < NEW_SHOWN:
            new[r.case_id].append(NewDestination(key[0], key[1], r.added_at))
    out = []
    for c in cases:
        per_day = alerts.get(c.id, {})
        days = max((now - c.notified_at).days, 1)
        pending = tuple(
            p
            for p in held.get(c.id, [])
            if not (
                (p.kind == "notify_again" and c.owner_notices >= 2)
                or (p.kind == "network_action" and c.blocked_at is not None)
            )
        )
        out.append(
            KnownCase(
                c.id, int(c.number), c.title, c.state, c.severity, c.notified_at, c.blocked_at,
                c.managed, int(c.devices), int(c.owner_notices), int(c.blocks),
                sum(n for n, _ in per_day.values()), days,
                {d.isoformat(): n for d, (n, _) in sorted(per_day.items())},
                max((last for _, last in per_day.values()), default=None), pending,
                tuple(changes.get(c.id, [])[:CHANGES_SHOWN]),
                tuple(new.get(c.id, ())), totals.get(c.id, 0),
            )
        )  # fmt: skip
    return out


async def notices(conn: AsyncConnection, case_id: uuid.UUID) -> list[NoticeRow]:
    """Everything a person recorded about the case, oldest first."""
    return [
        NoticeRow(
            r.kind,
            r.at,
            r.told,
            r.how,
            r.managed,
            r.note,
            int(r.by_user_id),
            int(r.case_version),
            bool(r.withdrawn) and r.kind == "owner",
        )
        for r in await conn.execute(_NOTICES, {"c": case_id})
    ]
