"""Making a report: the period, the sections, the text. Reads ARGUS's database only, in one
read-only snapshot so the sections agree with each other; asks no model and no SIEM."""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from datetime import UTC, date, datetime, timedelta

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.db.errors import short_db_error
from argus.reporter import render
from argus.reporter.model import Kind, Numbers, Section, Window, window_for
from argus.reporter.sections import BUILDERS, Builder
from argus.responder.machine import ist12

log = logging.getLogger("argus.reporter")
DAILY_BACKFILL = 7  # a missed daily report is made later, within this many last days
WEEKLY_BACKFILL = 4  # a missed weekly report is made later, within this many last weeks
_AT_MAKING = re.compile(r"as at the (?:making|moment the report was made)")


def last_complete_day(now: datetime) -> date:
    """The last UTC day that has ended by ``now`` (the default period of a daily report)."""
    return (now.astimezone(UTC) - timedelta(days=1)).date()


def last_complete_week_end(now: datetime) -> date:
    """The Sunday that ends the last complete Monday-to-Sunday UTC week by ``now`` (the default
    period of a weekly report, whatever day the service runs: after downtime it still gives a
    whole week, never one that starts on another weekday)."""
    today = now.astimezone(UTC).date()
    return today - timedelta(days=today.weekday() + 1)


def default_days(kind: Kind, now: datetime) -> list[date]:
    """The last days of the periods a run without ``--date`` should have made, oldest first: the
    last complete one and the ones before it that a missed run left out."""
    if kind == "daily":
        last, step, count = last_complete_day(now), 1, DAILY_BACKFILL
    else:
        last, step, count = last_complete_week_end(now), 7, WEEKLY_BACKFILL
    return [last - timedelta(days=step * i) for i in reversed(range(count))]


def _stamped(section: Section, as_at: datetime) -> Section:
    """A figure of what is waiting says in its definition the moment it is as at (local time)."""
    when = ist12(as_at)
    return section.model_copy(
        update={
            "metrics": tuple(
                m.model_copy(
                    update={
                        "definition": _AT_MAKING.sub(lambda f: f"{f[0]} ({when})", m.definition)
                    }
                )
                for m in section.metrics
            )
        }
    )


@asynccontextmanager
async def snapshot(engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    """A connection whose reads all see one moment (REPEATABLE READ, read only)."""
    async with engine.connect() as conn:
        conn = await conn.execution_options(
            isolation_level="REPEATABLE READ", postgresql_readonly=True
        )
        async with conn.begin():
            yield conn


async def build(
    conn: AsyncConnection,
    kind: Kind,
    last_day: date,
    as_at: datetime,
    builders: Sequence[Builder] = BUILDERS,
) -> Numbers:
    """The numbers of the report that ends with ``last_day``. A section that cannot be read is
    in the report as a note saying so and the others stand: a report is never held back, and a
    stored report is never rewritten."""
    window = window_for(kind, last_day, as_at)
    sections: list[Section] = []
    for builder in builders:
        try:
            async with conn.begin_nested():
                sections.append(_stamped(await builder(conn, window), as_at))
        except SQLAlchemyError as exc:
            name = builder.__name__
            log.warning("report section %s could not be read: %s", name, short_db_error(exc))
            sections.append(
                Section(
                    id=name,
                    title=name.replace("_", " ").capitalize(),
                    metrics=(),
                    notes=(f"This section could not be read: {short_db_error(exc)}",),
                )
            )
    return Numbers(
        kind=kind,
        period_start=window.start,
        period_end=window.end,
        as_at=as_at,
        sections=tuple(sections),
    )


async def make(
    engine: AsyncEngine, kind: Kind, last_day: date, as_at: datetime
) -> tuple[Numbers, str]:
    """The numbers and the deterministic text of one report, from one snapshot."""
    async with snapshot(engine) as conn:
        numbers = await build(conn, kind, last_day, as_at)
    return numbers, render.text_of(numbers)


def window_of(numbers: Numbers) -> Window:
    return Window(numbers.kind, numbers.period_start, numbers.period_end, numbers.as_at)
