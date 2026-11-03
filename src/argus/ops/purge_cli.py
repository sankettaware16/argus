"""``argus purge ...``: the retention purge. Local only: nothing reaches the SIEM.

``plan`` counts what a purge would remove (read only). ``run`` is a dry run unless ``--apply``,
which deletes only with ``--expect PLAN`` (the counts a person reviewed, re-counted at the plan's
own time and refused if anything differs, after a restore drill within 24 hours) or with
``--scheduled`` (the timer: only once ``retention.scheduled`` is on, with exactly the periods of
the last reviewed purge, after a restore drill within 8 days). The purge logs in as the owner and
works as ``argus_purge``; every ``--apply`` is an audit event, whether it deletes, fails or is
refused."""

from __future__ import annotations

import asyncio
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import typer

from argus.config.durations import format_duration
from argus.config.errors import ConfigError
from argus.config.settings import Settings
from argus.db.audit import AuditError
from argus.db.engine import create_engine
from argus.db.errors import DB_ERRORS, short_db_error
from argus.gateway.cli import ConfigOption, load
from argus.ops import backup, purge
from argus.ops.purge import Counts, Cutoffs, PurgeError

_RUN_FAILURES: tuple[type[Exception], ...] = (PurgeError, *DB_ERRORS)
_AUDIT_FAILURES: tuple[type[Exception], ...] = (AuditError, *DB_ERRORS)
FRESH_DRILL = timedelta(hours=24)  # before a purge a person runs: a drill of today's data
SCHEDULED_DRILL = backup.DRILL_STALE  # the weekly drill, as doctor counts it
CLOCK_SKEW = timedelta(minutes=5)  # a drill record this far ahead of the clock is still believed
PLAN_FORMAT = 2

purge_app = typer.Typer(
    no_args_is_help=True,
    help="The retention purge: dry-run counts, and the purge itself.",
)

AtOption = Annotated[
    str | None,
    typer.Option("--at", help="the time to purge as of (ISO 8601 with a zone; default: now)"),
]


def _at(value: str | None, now: datetime) -> datetime:
    if value is None:
        return now
    try:
        at = datetime.fromisoformat(value)
    except ValueError:
        raise typer.BadParameter(
            "--at is an ISO 8601 time, e.g. 2026-11-10T22:30:00+00:00"
        ) from None
    if at.tzinfo is None:
        raise typer.BadParameter("--at needs a time zone (e.g. +00:00)")
    at = at.astimezone(UTC)
    if at > now:
        raise typer.BadParameter("--at is in the future")
    return at


def _plan_json(cut: Cutoffs, counts: Counts, database: str) -> dict[str, Any]:
    return {
        "format": PLAN_FORMAT,
        "database": database,
        "at": cut.at.isoformat(),
        "periods": {name: format_duration(p) for name, p in cut.periods.items()},
        "counts": counts.as_json(),
    }


def read_plan(path: Path, settings: Settings) -> tuple[Cutoffs, Counts]:
    """The reviewed plan: its time (the run's cutoffs) and its counts. PurgeError unless it is
    a plan of this database, made with the periods configured now."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PurgeError(f"cannot read the plan {path.name}: {type(exc).__name__}") from None
    if not isinstance(data, dict) or data.get("format") != PLAN_FORMAT:
        raise PurgeError(f"{path.name} is not a purge plan (argus purge plan --output)")
    if data.get("database") != settings.database.name:
        raise PurgeError(f"{path.name} is a plan of another database")
    try:
        at = datetime.fromisoformat(str(data.get("at")))
        counts = Counts.from_json(data.get("counts") or {})
    except ValueError as exc:
        raise PurgeError(f"{path.name}: {exc}") from None
    if at.tzinfo is None:
        raise PurgeError(f"{path.name}: its time has no zone")
    if at > datetime.now(UTC):
        raise PurgeError(f"{path.name}: its time is in the future")
    cut = purge.cutoffs(settings, at)
    periods = {name: format_duration(p) for name, p in cut.periods.items()}
    if data.get("periods") != periods:
        raise PurgeError(
            f"{path.name} was made with other retention periods than are configured now: make"
            " a new plan and review it"
        )
    return cut, counts


def check_drill(base: Path, now: datetime, within: timedelta) -> str:
    """The last restore drill, if it passed within ``within``; PurgeError otherwise (a purge
    cannot be undone: the backup it would be undone from must be proven first)."""
    last = backup.status(base).last_drill
    if last is None:
        raise PurgeError("no restore drill has run: run `argus backup check` first")
    try:
        at = datetime.fromisoformat(str(last.get("at")))
    except ValueError:
        raise PurgeError("the last restore drill's record has no time") from None
    if last.get("passed") is not True:
        raise PurgeError("the last restore drill failed: fix the backups first")
    if at.tzinfo is not None and at - now > CLOCK_SKEW:
        raise PurgeError(
            "the last restore drill's record is dated in the future (the clock or the record is"
            " wrong): run `argus backup check` first"
        )
    if at.tzinfo is None or now - at > within:
        raise PurgeError(
            f"the last restore drill is older than {format_duration(within)}: run `argus backup"
            " check` first"
        )
    return f"{last.get('dump')} at {at.isoformat()}"


async def check_schedule(engine: Any, cut: Cutoffs) -> None:
    """PurgeError unless the configured periods are those of the last reviewed purge: the
    schedule was approved for them, and a changed period is a new decision to review."""
    reviewed = await purge.reviewed_periods(engine)
    periods = {name: format_duration(p) for name, p in cut.periods.items()}
    if reviewed is None:
        raise PurgeError(
            "no reviewed purge has succeeded yet: the first purge is a reviewed plan (argus purge"
            " plan --output PLAN, then argus purge run --apply --expect PLAN)"
        )
    if reviewed != periods:
        changed = ", ".join(
            f"{name} {reviewed.get(name, '?')} -> {periods[name]}"
            for name in periods
            if reviewed.get(name) != periods[name]
        )
        raise PurgeError(
            f"the retention periods changed since the last reviewed purge ({changed}): a changed"
            " period needs a reviewed plan first (argus purge plan --output PLAN, then argus"
            " purge run --apply --expect PLAN)"
        )


def _owner(settings: Settings) -> Any:
    from argus.cli import _engine  # argus.cli imports this module: import at call time

    return _engine(settings, "owner")


@purge_app.command("plan")
def purge_plan(
    at: AtOption = None,
    output: Annotated[
        Path | None, typer.Option(help="write the counts here, for `argus purge run --expect`")
    ] = None,
    config: ConfigOption = None,
) -> None:
    """Count what the purge would remove at this time (read only), per class and table, and
    what the holds keep."""
    settings = load(config)
    cut = purge.cutoffs(settings, _at(at, datetime.now(UTC)))
    engine = _owner(settings)

    async def go() -> Counts:
        try:
            await purge.preflight(engine)
            return await purge.plan(engine, cut)
        finally:
            await engine.dispose()

    try:
        counts = asyncio.run(go())
    except PurgeError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None
    for line in purge.lines(counts, cut, settings.retention.app_logs):
        typer.echo(line)
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(descriptor, 0o600)  # also when the file was there already
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(_plan_json(cut, counts, settings.database.name), handle, indent=2)
            handle.write("\n")
        typer.echo(f"plan written to {output}: review it, then `argus purge run --apply"
                   f" --expect {output}`")  # fmt: skip


@purge_app.command("run")
def purge_run(
    apply: Annotated[bool, typer.Option("--apply", help="delete (else: a dry run)")] = False,
    expect: Annotated[
        Path | None, typer.Option(help="the reviewed plan (argus purge plan --output)")
    ] = None,
    scheduled: Annotated[
        bool, typer.Option("--scheduled", help="the timer's run (needs retention.scheduled)")
    ] = False,
    at: AtOption = None,
    config: ConfigOption = None,
) -> None:
    """The purge. A dry run unless --apply; with --apply, either --expect (a reviewed plan) or
    --scheduled (the approved schedule)."""
    settings = load(config)
    now = datetime.now(UTC)
    if not apply:
        if expect is not None or scheduled:
            typer.echo("error: --expect and --scheduled go with --apply", err=True)
            raise typer.Exit(2)
        typer.echo("dry run (nothing is deleted; --apply deletes):")
        purge_plan(at=at, output=None, config=config)
        return
    if (expect is None) == (not scheduled):
        why = (
            "--apply needs --expect PLAN (a plan a person reviewed) or --scheduled (the approved"
            " schedule), not both"
        )
        _refused(settings, why, scheduled)
        typer.echo(f"error: {why}", err=True)
        raise typer.Exit(2)
    try:
        if scheduled:
            if at is not None:
                raise PurgeError("a scheduled purge runs as of now: no --at")
            if not settings.retention.scheduled:
                raise PurgeError(
                    "the schedule is not approved (retention.scheduled is off): the first purge"
                    " and its schedule are the user's (D-109)"
                )
            cut, expected = purge.cutoffs(settings, now), None
            drill = check_drill(settings.backup.dir, now, SCHEDULED_DRILL)
        else:
            assert expect is not None
            cut, reviewed = read_plan(expect, settings)
            if at is not None:
                try:
                    given = _at(at, now)
                except typer.BadParameter as exc:
                    raise PurgeError(exc.message) from None
                if given != cut.at:
                    raise PurgeError("--at differs from the plan's own time")
            expected = reviewed
            drill = check_drill(settings.backup.dir, now, FRESH_DRILL)
    except PurgeError as exc:
        _refused(settings, str(exc), scheduled)
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None
    engine = _owner(settings)

    async def go() -> purge.Outcome:
        try:
            if scheduled:
                try:
                    await purge.preflight(engine)
                    await check_schedule(engine, cut)
                except PurgeError as exc:
                    await _audit(engine, "denied", cut, {"refused": str(exc), "scheduled": True})
                    raise
            try:
                outcome = await purge.run(engine, cut, expect=expected)
            except _RUN_FAILURES as exc:
                why = str(exc) if isinstance(exc, PurgeError) else short_db_error(exc)
                await _audit(engine, "failure", cut, {"error": why, "scheduled": scheduled,
                                                      "drill": drill})  # fmt: skip
                raise
            good = outcome.matched and outcome.holds_intact
            await _audit(
                engine,
                "success" if good else "failure",
                cut,
                {
                    "scheduled": scheduled,
                    "drill": drill,
                    "planned": outcome.planned.as_json(),
                    "done": outcome.done.as_json(),
                    "differences": purge.differences(outcome.planned, outcome.done),
                    "holds_before": dict(outcome.holds_before),
                    "holds_after": dict(outcome.holds_after),
                    "holds_changed": dict(outcome.holds_changed),
                },
            )
            return outcome
        finally:
            await engine.dispose()

    try:
        outcome = asyncio.run(go())
    except PurgeError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)} (what was committed stays; run again)", err=True)
        raise typer.Exit(1) from None
    typer.echo("purged:")
    for line in purge.lines(outcome.done, cut, settings.retention.app_logs)[1:]:
        typer.echo(line)
    problems = purge.differences(outcome.planned, outcome.done)
    for line in problems:
        typer.echo(f"DIFFERS FROM THE PLAN: {line}", err=True)
    if not outcome.holds_intact:
        changed = ", ".join(f"{k} {n}" for k, n in outcome.holds_changed.items() if n)
        typer.echo(
            f"HOLDS CHANGED (held rows that are no longer as they were): {changed}", err=True
        )
    if problems or not outcome.holds_intact:
        raise typer.Exit(1)
    typer.echo("every count as planned; the held rows are untouched")


async def _audit(engine: Any, outcome: str, cut: Cutoffs, details: dict[str, Any]) -> None:
    try:
        await purge.audit(engine, outcome=outcome, cut=cut, details=details)
    except _AUDIT_FAILURES as exc:
        typer.echo(f"note: the audit event was not recorded ({short_db_error(exc)})", err=True)


def _refused(settings: Settings, why: str, scheduled: bool) -> None:
    """A refused --apply is audited too (best effort)."""
    try:
        engine = create_engine(settings.database, role="owner")
    except ConfigError:
        return  # no owner login configured: the refusal is printed only
    cut = purge.cutoffs(settings, datetime.now(UTC))

    async def go() -> None:
        try:
            await _audit(engine, "denied", cut, {"refused": why, "scheduled": scheduled})
        finally:
            await engine.dispose()

    asyncio.run(go())
