"""Needs you: the one set of cases that wait for a person (UI v2 spec §3.1 term 4, §6.3), and the
marks people leave on it (A1 "I'm checking", A2 "last looked").

**Needs you** is, for one viewer, every possible incident (a suspected case) nobody else is
checking, and every confirmed incident nobody has taken (open, no owner, the owner of the device not
told). The Incidents tab (``GET /cases?view=queue``), its count (``CasePage.counts.queue``) and
Today's ``needs_you`` + ``more_waiting`` are this set: :data:`NEEDS_YOU` is its only definition, and
:func:`needs_you` is how a page that sends a part of it (Today's cards) asks for it.

**A hold** (``case_holds``) is a person's "I'm checking": the case leaves everyone else's Needs you
until ``until``, until the person stops, until the case leaves ``suspected`` (any change of state
after the hold ends it, so an undone dismissal does not bring an old hold back), or until the
incident engine ends it on a material change or P1 (:func:`end_holds`, ``changed`` / ``p1``).

**Last looked** (``case_seen``) is per person: the engine's version they last saw (their
``changed`` list empties) and the case's.

Postgres only; every query is bounded by the ids it is given or by the page it serves."""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.web.v1 import case_models as m

HOLD_ENDINGS = ("released", "replaced", "expired", "decided", "changed", "p1")

# a hold that still holds, on the case ``c`` (``h`` is the hold)
ACTIVE_HOLD = (
    "h.ended_at IS NULL AND h.until > now() AND c.state = 'suspected'"
    " AND NOT EXISTS (SELECT 1 FROM case_events e WHERE e.case_id = h.case_id"
    " AND e.occurred_at > h.created_at AND e.from_state IS DISTINCT FROM e.to_state)"
)
HELD_BY_OTHER = (
    "EXISTS (SELECT 1 FROM case_holds h WHERE h.case_id = c.id AND h.user_id <> :me"  # noqa: S608
    f" AND {ACTIVE_HOLD})"
)
HELD_BY_ME = (
    "EXISTS (SELECT 1 FROM case_holds h WHERE h.case_id = c.id AND h.user_id = :me"  # noqa: S608
    f" AND {ACTIVE_HOLD})"
)
# Kibana has the case ``c``, or will: ARGUS planned its create (a create skipped unsent does not
# count), or the case team's post read back the Kibana case it opened (D-322)
IN_KIBANA = (
    "(EXISTS (SELECT 1 FROM kibana_outbox x WHERE x.case_id = c.id AND x.op = 'create'"
    " AND NOT (x.state = 'skipped' AND x.sent_count = 0))"
    " OR EXISTS (SELECT 1 FROM case_team_posts p WHERE p.case_id = c.id"
    " AND p.kibana_case_id IS NOT NULL))"
)
# a confirmed incident nobody took (a notified one is watched quietly: it asks for no owner)
NOT_TAKEN = "(c.state = 'open' AND c.owner_user_id IS NULL AND c.notified_at IS NULL)"
NEEDS_YOU = f"((c.state = 'suspected' AND NOT {HELD_BY_OTHER}) OR {NOT_TAKEN})"
WAITING_STATE = f"(c.state = 'suspected' OR {NOT_TAKEN})"
# what the person owns, and what they are checking
MINE = f"((c.owner_user_id = :me AND c.state <> 'closed') OR {HELD_BY_ME})"

_HOLDS = text(
    "SELECT h.case_id, h.reason, h.until, h.created_at, h.user_id, u.username,"  # noqa: S608
    " coalesce(nullif(u.display_name, ''), u.username) AS name"
    " FROM case_holds h JOIN cases c ON c.id = h.case_id JOIN users u ON u.id = h.user_id"
    f" WHERE h.case_id = ANY(CAST(:ids AS uuid[])) AND {ACTIVE_HOLD}"
)
# since when each case waits: when it entered its state, or when the last hold on it ended
WAITING_SINCE = (
    "greatest((SELECT max(e.occurred_at) FROM case_events e WHERE e.case_id = c.id"
    " AND e.to_state = c.state AND e.from_state IS DISTINCT FROM e.to_state),"
    " (SELECT max(least(coalesce(h.ended_at, h.until), h.until)) FROM case_holds h"
    " WHERE h.case_id = c.id AND (h.ended_why IS DISTINCT FROM 'replaced')"
    " AND (h.ended_at IS NOT NULL OR h.until <= now())))"
)
_WAITING = text(
    f"SELECT c.id, {WAITING_SINCE} AS since FROM cases c"  # noqa: S608
    f" WHERE c.id = ANY(CAST(:ids AS uuid[])) AND {WAITING_STATE}"
)
_SEEN = text(
    "SELECT case_id, engine_version, case_version, seen_at FROM case_seen"
    " WHERE user_id = :me AND case_id = ANY(CAST(:ids AS uuid[]))"
)
_ORDER = (
    "ORDER BY (c.state = 'suspected'),"
    " CASE c.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,"
    " c.updated_at DESC, c.number DESC"
)


def _ids(case_ids: Iterable[uuid.UUID]) -> list[uuid.UUID]:
    return sorted(set(case_ids), key=str)


async def holds_for(
    conn: AsyncConnection, case_ids: Iterable[uuid.UUID], me_id: int
) -> dict[uuid.UUID, m.HoldOut]:
    """The holds that still hold on these cases, as the pages show them."""
    ids = _ids(case_ids)
    if not ids:
        return {}
    rows = await conn.execute(_HOLDS, {"ids": ids})
    return {
        r.case_id: m.HoldOut(
            by=m.HolderOut(username=r.username, name=r.name), reason=r.reason, until=r.until,
            since=r.created_at, mine=int(r.user_id) == me_id,
        )
        for r in rows
    }  # fmt: skip


async def waiting_since(
    conn: AsyncConnection, case_ids: Iterable[uuid.UUID]
) -> dict[uuid.UUID, datetime]:
    """Since when each of these cases waits for a person (only the ones that do: a possible
    incident, or a confirmed one nobody took)."""
    ids = _ids(case_ids)
    if not ids:
        return {}
    rows = await conn.execute(_WAITING, {"ids": ids})
    return {r.id: r.since for r in rows if r.since is not None}


async def seen_for(
    conn: AsyncConnection, case_ids: Iterable[uuid.UUID], me_id: int
) -> dict[uuid.UUID, m.SeenOut]:
    """What this person last looked at of these cases."""
    ids = _ids(case_ids)
    if not ids:
        return {}
    rows = await conn.execute(_SEEN, {"ids": ids, "me": me_id})
    return {
        r.case_id: m.SeenOut(
            engine_version=r.engine_version, case_version=int(r.case_version), at=r.seen_at
        )
        for r in rows
    }


async def decorate(
    conn: AsyncConnection, rows: Sequence[m.CaseRowOut], me_id: int
) -> list[m.CaseRowOut]:
    """The rows with their hold, waiting time and this person's last look (three queries for
    the page, none per row)."""
    if not rows:
        return []
    ids = [r.id for r in rows]
    holds = await holds_for(conn, ids, me_id)
    waits = await waiting_since(conn, ids)
    seen = await seen_for(conn, ids, me_id)
    return [
        r.model_copy(update={"hold": holds.get(r.id), "waiting_since": waits.get(r.id),
                             "seen": seen.get(r.id)})
        for r in rows
    ]  # fmt: skip


async def needs_you(
    conn: AsyncConnection, me_id: int, *, limit: int, offset: int = 0
) -> tuple[list[uuid.UUID], int]:
    """The ids of this viewer's Needs you, in the queue's order (``limit`` of them from
    ``offset``), and how many there are in all: a page that sends ``limit`` cards says
    ``total - limit`` more wait, so its number is the Incidents tab's."""
    rows = (
        await conn.execute(
            text(
                f"SELECT c.id, count(*) OVER () AS total FROM cases c WHERE {NEEDS_YOU}"  # noqa: S608
                f" {_ORDER} OFFSET :off LIMIT :lim"
            ),
            {"me": me_id, "off": offset, "lim": limit},
        )
    ).all()
    if rows:
        return [r.id for r in rows], int(rows[0].total)
    total = await conn.scalar(
        text(f"SELECT count(*) FROM cases c WHERE {NEEDS_YOU}"),  # noqa: S608 - constant
        {"me": me_id},
    )
    return [], int(total or 0)


async def end_holds(conn: AsyncConnection, case_id: uuid.UUID, why: str) -> int:
    """End the open hold on a case (the engine on a material change or P1, a decision): the
    case comes back to everyone's Needs you. Returns how many ended (0 or 1)."""
    if why not in HOLD_ENDINGS:
        raise ValueError(f"not a way a hold ends: {why!r}")
    done = await conn.execute(
        text(
            "UPDATE case_holds SET ended_at = now(), ended_why = :w"
            " WHERE case_id = :c AND ended_at IS NULL"
        ),
        {"c": case_id, "w": why},
    )
    return int(getattr(done, "rowcount", 0) or 0)


async def tidy_holds(conn: AsyncConnection, case_id: uuid.UUID) -> None:
    """Close an open hold row that no longer holds (its date passed, or the case changed state
    since), so the case's one open row can be a new hold."""
    await conn.execute(
        text(
            "UPDATE case_holds h SET ended_at = least(now(), h.until),"  # noqa: S608
            " ended_why = CASE WHEN h.until <= now() THEN 'expired' ELSE 'decided' END"
            " FROM cases c WHERE c.id = h.case_id AND h.case_id = :c AND h.ended_at IS NULL"
            f" AND NOT ({ACTIVE_HOLD})"
        ),
        {"c": case_id},
    )


def hold_row(row: Any) -> m.HoldOut:
    """A hold as the API shows it, from a row with the hold's and the holder's columns."""
    return m.HoldOut(
        by=m.HolderOut(username=row.username, name=row.name), reason=row.reason,
        until=row.until, since=row.created_at, mine=bool(row.mine),
    )  # fmt: skip
