"""The decision bar's own sentences from the server (UI v2 spec A6, A7) and the undo of one's own
dismissal (A8). Each sentence says what the server does, never more: confirming never promises
a Kibana post, and the dismissal's memory is the suggester's own window."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, time, timedelta
from pathlib import Path
from typing import Any

from dotenv import dotenv_values
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus import site
from argus.cases.suggest import DISMISSAL_STANDS
from argus.llm.providers import ROOT

UNDO_WINDOW = timedelta(minutes=15)  # how long a person may undo their own dismissal (A8)
_DAYS = {7: "a week", 14: "two weeks", 21: "three weeks", 30: "30 days"}


def dismiss_effect(stands: timedelta = DISMISSAL_STANDS) -> str:
    """What "not an incident" does to what ARGUS suggests next (A6)."""
    days = stands.days
    span = _DAYS.get(days, f"{days} day{'s' if days != 1 else ''}")
    return (
        f"ARGUS does not suggest the same activity again for {span} unless something new appears."
    )


def _day(now: datetime) -> tuple[datetime, datetime]:
    zone = site.zone()
    start = datetime.combine(now.astimezone(zone).date(), time(0), zone)
    return start.astimezone(UTC), (start + timedelta(days=1)).astimezone(UTC)


async def posts_today(conn: AsyncConnection, now: datetime) -> int:
    """Kibana cases the case team opened today (the site's day), the way its cap counts them."""
    from argus.caseteam import store

    start, end = _day(now)
    return await store.opened_between(conn, start, end)


# The case team's own switches (D-214): its unit reads them from this file, never the shared .env,
# so the web reads them here too (read only; the file holds switches, never a key).
SWITCHES = Path("local") / "argus-writer.env"


def team_switches(team: Any, root: Path | None = None) -> tuple[bool, int]:
    """Whether the case team posts, and its cap a day: the web's settings, overlaid by the case
    team's switches file when this installation has one (that is what its unit runs with)."""
    post = bool(getattr(team, "post", False)) if team is not None else False
    per_day = int(getattr(team, "per_day", 0)) if team is not None else 0
    try:
        env = dotenv_values((root or ROOT) / SWITCHES)
    except OSError:
        return post, per_day
    raw = (env.get("ARGUS_CASE_TEAM__POST") or "").strip().lower()
    if raw in ("true", "1", "yes", "on"):
        post = True
    elif raw in ("false", "0", "no", "off"):
        post = False
    cap = (env.get("ARGUS_CASE_TEAM__PER_DAY") or "").strip()
    if cap.isdigit():
        per_day = int(cap)
    return post, per_day


async def kibana_after_confirm(
    conn: AsyncConnection, team: Any, now: datetime, root: Path | None = None
) -> str:
    """What confirming does about Kibana, today (A7): it opens nothing there. The case team
    posts a confirmed incident once a person confirms its incident report, within the day's
    cap; with posting off, nothing goes to Kibana from ARGUS."""
    first = "It becomes an open incident and waits for someone to take it."
    post, per_day = team_switches(team, root)
    if not post:
        return site.say(
            f"{first} Posting to Kibana is off on this server, so ARGUS sends nothing there:"
            " {team} opens it in Kibana by hand."
        )
    left = max(0, per_day - await posts_today(conn, now))
    room = (
        f"{left} of today's {per_day} posts are left"
        if left
        else f"today's {per_day} posts are used up, so it waits for tomorrow"
    )
    return (
        f"{first} Kibana gets it once a person confirms its incident report on the Report tab"
        f" ({room})."
    )


_LAST = text(
    "SELECT e.kind, e.actor, e.case_version, e.occurred_at, c.version, c.state"
    " FROM cases c JOIN case_events e ON e.case_id = c.id AND e.case_version = c.version"
    " WHERE c.id = :c"
)


async def undo_until(conn: AsyncConnection, case_id: uuid.UUID, me_id: int) -> datetime | None:
    """Until when this person may undo their own dismissal of the case (A8): its newest event is
    their dismissal, at most :data:`UNDO_WINDOW` old, and nothing happened to it since."""
    row = (await conn.execute(_LAST, {"c": case_id})).first()
    if row is None or row.kind != "dismissed" or row.state != "closed":
        return None
    if row.actor != f"user:{me_id}":
        return None
    until: datetime = row.occurred_at + UNDO_WINDOW
    now: datetime = (await conn.execute(text("SELECT now()"))).scalar_one()
    return until if now < until else None
