"""Building the soak gate's report: read each line's facts as the runtime login, in a transaction
that cannot write, and judge them.

Each line is read in a transaction of its own (``SET TRANSACTION READ ONLY``, a statement timeout),
so a table the runtime login may not select fails one line, not the report: that line becomes an
OPEN check that names the table, and the report says so in its notes.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.config.settings import Settings
from argus.db.errors import short_db_error
from argus.soakgate import fetch, judge
from argus.soakgate.model import Check, Line, Report, Verdict, Window

GATE = "phase3"
PHASE3_CLOSE = datetime(2026, 10, 30, 12, 45, tzinfo=UTC)  # the gate counts from here
INSUFFICIENT_PRIVILEGE = "42501"
UNDEFINED_TABLE = "42P01"
STATEMENT_TIMEOUT = "60s"

Producer = Callable[[AsyncConnection], Awaitable[list[Check]]]


def window_of(now: datetime, *, since: datetime | None = None, days: float | None = None) -> Window:
    """The window: from ``since`` (or ``days`` back from now), to now. ValueError if both are
    given, or the window is empty or in the future."""
    if since is not None and days is not None:
        raise ValueError("give --since or --days, not both")
    if days is not None:
        if days <= 0:
            raise ValueError("--days is more than 0")
        start = now.timestamp() - days * 86_400
        since = datetime.fromtimestamp(start, UTC)
    since = since or PHASE3_CLOSE
    if since.tzinfo is None:
        raise ValueError("the window starts at a time with a zone (UTC)")
    since = since.astimezone(UTC)
    if since >= now:
        raise ValueError(f"the window starts at {since:%Y-%m-%d %H:%M} UTC, not before now")
    return Window(since, now)


async def _read(engine: AsyncEngine, produce: Producer) -> list[Check]:
    async with engine.connect() as conn:
        await conn.execute(text("SET TRANSACTION READ ONLY"))
        await conn.execute(text(f"SET LOCAL statement_timeout = '{STATEMENT_TIMEOUT}'"))
        checks = await produce(conn)
        await conn.rollback()
        return checks


def _unreadable(number: int, exc: DBAPIError) -> Check:
    what = short_db_error(exc)
    state = getattr(exc.orig, "sqlstate", None)
    if state == INSUFFICIENT_PRIVILEGE:
        what = f"the runtime login may not read a table this line needs ({what})"
        needs = "a grant on that table for argus_runtime (a migration: never this command)"
    elif state == UNDEFINED_TABLE:
        needs = "`argus db upgrade`: the database is behind the code"
    else:
        needs = "the database error above"
    return Check(f"{number}x", "The line's facts could be read", Verdict.OPEN, what, needs=needs)


def lines(settings: Settings, w: Window) -> list[tuple[int, str, Producer]]:
    """The gate's lines, each with how it is read."""

    async def one(conn: AsyncConnection) -> list[Check]:
        return judge.judge_lifecycle(await fetch.lifecycle(conn, w, w.until))

    async def two(conn: AsyncConnection) -> list[Check]:
        return judge.judge_person_only(await fetch.opened_cases(conn, w))

    async def three(conn: AsyncConnection) -> list[Check]:
        return judge.judge_writes(await fetch.writes(conn, w, settings))

    async def four(conn: AsyncConnection) -> list[Check]:
        return judge.judge_coverage(await fetch.confirmed(conn, w, settings), w.until)

    async def five(conn: AsyncConnection) -> list[Check]:
        return judge.judge_closures(await fetch.closures(conn, w))

    async def six(conn: AsyncConnection) -> list[Check]:
        return judge.judge_reconciliation(await fetch.reconcile(conn, w))

    async def seven(conn: AsyncConnection) -> list[Check]:
        return judge.judge_notified(await fetch.notified(conn, w, w.until))

    async def eight(conn: AsyncConnection) -> list[Check]:
        return judge.judge_load(await fetch.load(conn, w, settings))

    async def nine(conn: AsyncConnection) -> list[Check]:
        found = await fetch.signins(conn, w, settings)
        return judge.judge_signins(found, fetch.sweep(settings), w.since)

    async def ten(conn: AsyncConnection) -> list[Check]:
        return judge.judge_analysis(await fetch.analysis(conn, w))

    async def eleven(conn: AsyncConnection) -> list[Check]:
        return judge.judge_health(await fetch.health(conn, w), fetch.backups(settings, w))

    return [
        (1, "Case-team lifecycle", one),
        (2, "Only what a person confirmed", two),
        (3, "Production writes", three),
        (4, "Coverage", four),
        (5, "Closures", five),
        (6, "Reconciliation", six),
        (7, "Notified cases", seven),
        (8, "Load", eight),
        (9, "Sign-ins", nine),
        (10, "Analysis", ten),
        (11, "Health", eleven),
    ]


async def build(
    engine: AsyncEngine, settings: Settings, w: Window, *, now: datetime | None = None
) -> Report:
    """The report for window ``w``: every line judged from the store, read-only."""
    made: list[Line] = []
    notes: list[str] = []
    for number, title, produce in lines(settings, w):
        try:
            checks = await _read(engine, produce)
        except DBAPIError as exc:
            checks = [_unreadable(number, exc)]
            notes.append(f"line {number}: {checks[0].detail}")
        made.append(Line(number, title, tuple(checks)))
    notes += _notes(made)
    return Report(GATE, now or datetime.now(UTC), w, tuple(made), tuple(notes))


def _notes(made: list[Line]) -> list[str]:
    out = []
    for line in made:
        for check in line.checks:
            if check.id == "6d" and check.verdict is Verdict.PENDING and check.n:
                out.append(
                    "the read-back mirror does not cover the case team's cases yet: line 6"
                    " cannot see a person's edit, close or delete of them"
                )
    return out


def write_report(report: Report, folder: Path) -> Path:
    """Save the report as ``<folder>/<UTC timestamp>.json`` (mode 0600; the folder 0700)."""
    import json
    import os

    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = folder / f"{report.generated_at.astimezone(UTC):%Y%m%dT%H%M%SZ}.json"
    body: Any = json.dumps(report.as_json(), indent=2, sort_keys=True) + "\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(body)
    return path
