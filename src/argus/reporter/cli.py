"""``argus report daily|weekly`` (Q-H3): make the day's or the week's report from ARGUS's own
database (no SIEM request, no model call), store it once, or with ``--dry-run`` print it and
store nothing. Added to the ``argus report`` group of :mod:`argus.report.cli`."""

from __future__ import annotations

import asyncio
from datetime import UTC, date, datetime
from typing import Annotated

import typer
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from argus.db.audit import record_audit
from argus.db.errors import DB_ERRORS, short_db_error
from argus.gateway.cli import ConfigOption, engine_for, load
from argus.reporter import build, prose, store
from argus.reporter.model import Kind, window_for

DateOption = Annotated[
    str | None,
    typer.Option(
        "--date",
        help="the last UTC day the report covers, YYYY-MM-DD, to make that one period only"
        " (a week is this day and the six before it). Without it: the last complete day (daily)"
        " or the last complete Monday-to-Sunday week (weekly), and any of the periods before it"
        " that a missed run left out (daily: within the last 7 days, weekly: within the last 4"
        " weeks)",
    ),
]
DryRun = Annotated[
    bool,
    typer.Option("--dry-run", help="make the newest report and print it: store and audit nothing"),
]


def last_day_of(text: str | None, now: datetime) -> date:
    """The ``--date`` given (a UTC day that has ended) or the last day that has ended."""
    last = build.last_complete_day(now)
    if text is None:
        return last
    try:
        day = date.fromisoformat(text)
    except ValueError:
        typer.echo(f"error: --date {text!r} is not a date (YYYY-MM-DD)", err=True)
        raise typer.Exit(2) from None
    if day > last:
        typer.echo(
            f"error: {day} has not ended yet (UTC): the last day that has is {last}", err=True
        )
        raise typer.Exit(2)
    return day


def days_to_make(kind: Kind, day_text: str | None, now: datetime) -> list[date]:
    """The last days of the periods a run makes, oldest first: the one ``--date`` names, or (no
    ``--date``) the last complete period and the missed ones before it."""
    if day_text is not None:
        return [last_day_of(day_text, now)]
    return build.default_days(kind, now)


def make_report(kind: Kind, day_text: str | None, dry_run: bool, config: ConfigOption) -> None:
    settings = load(config)

    async def go() -> None:
        engine = engine_for(settings)
        try:
            now = datetime.now(UTC)
            days = days_to_make(kind, day_text, now)
            if prose.enabled():
                typer.echo(
                    "note: the reporter agent is switched on but no model call is wired in this"
                    " build: the deterministic text stands",
                    err=True,
                )
            if dry_run:
                numbers, body = await build.make(engine, kind, days[-1], now)
                typer.echo(body)
                typer.echo(
                    f"(dry run: {kind} report of {len(numbers.metrics())} figures, nothing stored)"
                )
                return
            stored = 0
            for day in days:
                stored += await _make_one(engine, kind, day, now, loud=day == days[-1])
            if stored == 0 and len(days) > 1:
                typer.echo(f"no {kind} report is missing")
        except DB_ERRORS as exc:
            typer.echo(f"error: {short_db_error(exc)}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()

    asyncio.run(go())


async def _make_one(
    engine: AsyncEngine, kind: Kind, day: date, now: datetime, *, loud: bool
) -> int:
    """Make and store the report that ends with ``day`` unless it exists (1 when stored); an
    existing one is mentioned only when ``loud`` (the newest period, or the one asked for)."""
    window = window_for(kind, day, now)
    async with engine.connect() as probe:
        made_already = await store.exists(probe, kind, window.end) is not None
    if made_already:
        if loud:
            typer.echo(
                f"the {kind} report ending {window.end:%Y-%m-%d} UTC is already made; a report"
                " is never rewritten"
            )
        return 0
    numbers, body = await build.make(engine, kind, day, now)
    count = len(numbers.metrics())
    async with engine.begin() as conn:
        made = await store.save(conn, numbers, body)
        if made is None:
            return 0
        session = AsyncSession(bind=conn)
        try:
            await record_audit(
                session,
                actor=store.ACTOR,
                action="report.made",
                target_type="report",
                target_id=str(made),
                details={
                    "kind": kind,
                    "period_start": numbers.period_start.isoformat(),
                    "period_end": numbers.period_end.isoformat(),
                    "figures": count,
                },
            )
        finally:
            await session.close()
    typer.echo(f"{kind} report {made} stored: {count} figures")
    return 1


def register(app: typer.Typer) -> None:
    """Add ``daily`` and ``weekly`` to the ``argus report`` group."""

    @app.command("daily")
    def report_daily(
        date_: DateOption = None, dry_run: DryRun = False, config: ConfigOption = None
    ) -> None:
        """Make the daily report (one UTC day) and store it; a day already made is left as it
        is, and a day of the last 7 that a missed run left out is made now. Every day:
        argus-report-daily.timer."""
        make_report("daily", date_, dry_run, config)

    @app.command("weekly")
    def report_weekly(
        date_: DateOption = None, dry_run: DryRun = False, config: ConfigOption = None
    ) -> None:
        """Make the weekly report (the last complete Monday-to-Sunday week, or the seven UTC days
        ending with --date) and store it; a week of the last 4 that a missed run left out is made
        now. Every Monday: argus-report-weekly.timer."""
        make_report("weekly", date_, dry_run, config)
