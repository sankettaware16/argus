"""``argus writer run`` (the service) and ``argus kibana plan|diff|run|ramp|compensate`` (the
operator's side, run in the writer's account: ``sudo argus-owner --as writer kibana ...``).

* ``plan --class W1``: what is waiting and what stops it (the database only).
* ``diff --class W1``: the same, each row planned against the Kibana case as it is now (reads only).
* ``run --class W1``: one run of the class at a terminal with the class name typed, up to the
  class's ramp step (1 at the canary, then 5, then 10); a person checks a canary in Kibana.
* ``ramp --class W1 --to 5``: raise the step once the runs so far allow it and a person has checked.
* ``skip --outbox N --reason ...``: decide that a write in doubt, paused or in conflict is not
  wanted (never a way to send). ``compensate --outbox N``: the compensating write for a W2/W3 row.
* ``argus writer run``: each class in ``kibana.writer.scheduled`` runs every
  ``kibana.writer.interval`` at its ramp step, with the lane's own gates; due lookups every 30 s.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Annotated

import typer
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.errors import ConfigError
from argus.config.settings import Settings, operator_of
from argus.db.engine import create_engine
from argus.gateway.cli import ConfigOption, _human_at_a_terminal, _run, load
from argus.writer import compensation, ramp, store
from argus.writer.sender import Writer
from argus.writer.service import build_writer, gate_problems

log = logging.getLogger("argus.writer")
writer_app = typer.Typer(
    no_args_is_help=True, help="argus-writer: Kibana case writes from the outbox."
)
CLASSES = ("W1", "W2", "W3")
TICK = 30  # seconds between the service's looks at due lookups
ClassOption = Annotated[str, typer.Option("--class", help="W1, W2 or W3")]


def _class(value: str) -> str:
    if value not in CLASSES:
        typer.echo(f"error: --class is one of {', '.join(CLASSES)}", err=True)
        raise typer.Exit(2)
    return value


def _engine(settings: Settings, *, writes: bool) -> AsyncEngine:
    """The writer's own login; reading commands may fall back to the runtime login."""
    try:
        return create_engine(settings.database, role="writer")
    except ConfigError:
        if writes:
            typer.echo(
                "error: the writer's database login is not set up here: run this in the"
                " writer's account (sudo argus-owner --as writer ...) after `argus db bootstrap`"
                " with ARGUS_DATABASE__WRITER_PASSWORD",
                err=True,
            )
            raise typer.Exit(2) from None
        return create_engine(settings.database, role="app")


def _need_kibana(settings: Settings, write_class: str) -> None:
    problems = gate_problems(settings, write_class)
    if problems:
        for problem in problems:
            typer.echo(f"cannot run {write_class}: {problem}", err=True)
        raise typer.Exit(2)


def _confirm(word: str, what: str) -> None:
    if not _human_at_a_terminal():
        typer.echo("error: this is done by a person at a terminal", err=True)
        raise typer.Exit(2)
    typer.echo(what)
    if typer.prompt(f"Type {word} to confirm") != word:
        typer.echo("not confirmed", err=True)
        raise typer.Exit(1)


async def plan_lines(engine: AsyncEngine, settings: Settings, write_class: str) -> list[str]:
    now = datetime.now(UTC)
    out: list[str] = []
    async with engine.connect() as conn:
        step = await store.ramp_step(conn, write_class)
        evidence = await ramp.evidence(conn, write_class, now)
        order = await ramp.first_use_problem(conn, write_class)
        unattended = await ramp.scheduled_problem(conn, write_class)
        rows = await store.eligible_rows(conn, write_class, 100)
        steps = await store.eligible_steps(conn, write_class, 100)
        doubt = [r for r in await store.rows_in(conn, "ambiguous") if r.write_class == write_class]
    out.append(
        f"{write_class}: step {step} ({'canary' if step == 1 else f'{step} units a run'}),"
        f" {evidence.runs} runs on {evidence.days} days at this step"
    )
    problems = [*gate_problems(settings, write_class), *([order] if order else [])]
    out += [f"  stopped: {problem}" for problem in problems]
    if not problems:
        out.append("  nothing stops it here (the lane still checks the window, health and caps)")
    if unattended:
        out.append(f"  the service would not run it: {unattended}")
    out.append(f"  waiting: {len(rows)} rows, {len(steps)} steps")
    for row in rows[:20]:
        out.append(f"    outbox {row.id} case {row.case_id} {row.op} ({row.state})")
    for item in steps[:20]:
        out.append(f"    step {item.id} case {item.case_id} {item.kind} ({item.state})")
    for row in doubt:
        out.append(f"  in doubt: outbox {row.id} case {row.case_id} {row.op}")
    return out


async def skip_item(
    engine: AsyncEngine, *, table: str, item_id: int, reason: str, by: str, now: datetime
) -> str:
    """A person decides a write in doubt, paused or in conflict is not wanted (or was done by
    hand in Kibana): it becomes ``skipped`` and its case goes on with the rows after it. Returns
    what happened, in words."""
    async with engine.begin() as conn:
        found = (
            await conn.execute(
                text(f"SELECT case_id, state FROM {table} WHERE id = :i"),  # noqa: S608 - fixed name
                {"i": item_id},
            )
        ).first()
        if found is None:
            return "no such row"
        if not await store.move(
            conn, table, item_id, "skipped", f"skipped by {by}: {reason}"[:1000],
            only_from=["planned", "approved", "paused", "conflict", "ambiguous"],
        ):  # fmt: skip
            return f"a {found.state} write is not skipped (it is sent, verified or skipped already)"
        subject = "outbox" if table == store.OUTBOX else "step"
        await store.close_lookups(conn, subject, item_id, now)
        await store.audit(
            conn, "kibana.write.skipped_by_person", found.case_id,
            {"item": item_id, "table": table, "was": found.state, "by": by, "reason": reason[:300]},
        )  # fmt: skip
    return f"{table} {item_id} is skipped (it was {found.state})"


@writer_app.callback()
def _callback() -> None:
    """argus-writer."""


def register(kibana_app: typer.Typer) -> None:
    """The operator's commands, added to ``argus kibana``."""

    @kibana_app.command("plan")
    def plan(write_class: ClassOption, config: ConfigOption = None) -> None:
        """What a run of the class would take up and what stops it. Reads the database only."""
        write_class = _class(write_class)
        settings = load(config)

        async def go() -> list[str]:
            engine = _engine(settings, writes=False)
            try:
                return await plan_lines(engine, settings, write_class)
            finally:
                await engine.dispose()

        for line in _run(go()):
            typer.echo(line)

    @kibana_app.command("diff")
    def diff(write_class: ClassOption, config: ConfigOption = None) -> None:
        """Each waiting row planned against the Kibana case as it is now. Reads Kibana; writes
        nothing there and changes nothing here."""
        write_class = _class(write_class)
        settings = load(config)
        _need_kibana(settings, write_class)

        async def go() -> list[str]:
            engine = _engine(settings, writes=False)
            try:
                writer = build_writer(settings, engine, wait_for_gaps=False)
                return await writer.preview(write_class)
            finally:
                await engine.dispose()

        lines = _run(go())
        for line in lines:
            typer.echo(line)
        typer.echo(f"dry run: {len(lines)} items, nothing was written")

    @kibana_app.command("run")
    def run(write_class: ClassOption, config: ConfigOption = None) -> None:
        """One run of the class at its ramp step (1 at the canary), at a terminal, with the
        class name typed. Prints what was written and read back."""
        write_class = _class(write_class)
        settings = load(config)
        _need_kibana(settings, write_class)

        async def go() -> list[str]:
            engine = _engine(settings, writes=True)
            try:
                async with engine.connect() as conn:
                    step = await store.ramp_step(conn, write_class)
                    order = await ramp.first_use_problem(conn, write_class)
                    cleared = await ramp.canary_done(conn, write_class)
                if order:
                    typer.echo(f"cannot run {write_class}: {order}", err=True)
                    raise typer.Exit(2)
                kind = "ramp" if cleared else "canary"  # a canary until one has gone clean
                _confirm(
                    write_class,
                    f"This sends up to {step} {write_class} unit(s) to Kibana on production"
                    f" ({kind}). Be ready to look at the case in Kibana's UI afterwards.",
                )
                writer = build_writer(settings, engine, wait_for_gaps=True)
                report = await writer.run_class(
                    write_class, limit=step, kind=kind, by=operator_of(settings)
                )
                lines = report.lines()
                if kind == "canary":
                    lines.append(
                        "Now look at the case in Kibana's UI (title, description, tags, comment,"
                        " attached alerts, Sync alerts off) and run this again: a second run"
                        " writes nothing."
                    )
                return lines
            finally:
                await engine.dispose()

        for line in _run(go()):
            typer.echo(line)

    @kibana_app.command("ramp")
    def ramp_up(
        write_class: ClassOption,
        checked: Annotated[
            bool, typer.Option("--checked-in-kibana", help="I looked at the cases in Kibana's UI")
        ] = False,
        note: Annotated[str, typer.Option(help="what was checked")] = "",
        config: ConfigOption = None,
    ) -> None:
        """Raise the class's step (1, then 5, then 10) when its runs allow it, at a terminal."""
        write_class = _class(write_class)
        settings = load(config)

        async def go() -> str:
            engine = _engine(settings, writes=True)
            try:
                now = datetime.now(UTC)
                async with engine.connect() as conn:
                    seen = await ramp.evidence(conn, write_class, now)
                lines = [
                    f"{write_class} is at step {seen.step}: {seen.runs} runs on {seen.days} days,"
                    f" {seen.alarms} alarms"
                ]
                for why in seen.why_not:
                    lines.append(f"  not yet: {why}")
                if not seen.ready:
                    return "\n".join(lines)
                if not checked:
                    return "\n".join([*lines, "  add --checked-in-kibana once you looked"])
                to = ramp.STEPS[ramp.STEPS.index(seen.step) + 1]
                _confirm(write_class, f"This raises {write_class} from step {seen.step} to {to}.")
                async with engine.begin() as conn:
                    await ramp.raise_step(conn, write_class, to, operator_of(settings), note, now)
                return "\n".join([*lines, f"{write_class} is at step {to} now"])
            finally:
                await engine.dispose()

        typer.echo(_run(go()))

    @kibana_app.command("skip")
    def skip(
        reason: Annotated[str, typer.Option(help="why (kept in the audit trail)")],
        outbox: Annotated[int | None, typer.Option(help="the outbox row")] = None,
        step: Annotated[int | None, typer.Option(help="the step")] = None,
        config: ConfigOption = None,
    ) -> None:
        """Decide that a write in doubt, paused or in conflict is not wanted (or was done by
        hand in Kibana), at a terminal: it is skipped and its case goes on. Never a way to send."""
        if (outbox is None) == (step is None):
            typer.echo("error: give --outbox or --step", err=True)
            raise typer.Exit(2)
        settings = load(config)
        table, item_id = (store.OUTBOX, outbox) if outbox is not None else (store.STEPS, step)
        assert item_id is not None

        async def go() -> str:
            engine = _engine(settings, writes=True)
            try:
                _confirm("skip", f"This skips {table} {item_id}: it will never be sent.")
                return await skip_item(
                    engine, table=table, item_id=item_id, reason=reason,
                    by=operator_of(settings), now=datetime.now(UTC),
                )  # fmt: skip
            finally:
                await engine.dispose()

        typer.echo(_run(go()))

    @kibana_app.command("compensate")
    def compensate(
        outbox: Annotated[int, typer.Option(help="the W2 or W3 outbox row to undo")],
        config: ConfigOption = None,
    ) -> None:
        """The compensating write for a verified W2 or W3 row, exactly as an approval of it
        binds (a person asks for it in ARGUS; the writer sends it once it is approved)."""
        settings = load(config)

        async def go() -> list[str]:
            engine = _engine(settings, writes=False)
            try:
                async with engine.connect() as conn:
                    row = await store.get_row(conn, outbox)
                    before = await compensation.before_image(conn, outbox)
                if row is None or row.state != "verified" or row.op not in ("update", "close"):
                    return [f"outbox {outbox} is not a verified W2 or W3 change"]
                payload = compensation.build(row, before)
                if payload is None:
                    return [f"outbox {outbox} has no before-image to put back"]
                return [f"payload hash {compensation.hashed(payload)}", str(payload)]
            finally:
                await engine.dispose()

        for line in _run(go()):
            typer.echo(line)


@writer_app.command("run")
def writer_run(config: ConfigOption = None) -> None:
    """The service: lookups for writes in doubt every 30 seconds, and each scheduled class
    every ``kibana.writer.interval`` at its ramp step. While nothing is scheduled it says so and
    exits 0 (the unit restarts only after a failure)."""
    settings = load(config)
    scheduled = settings.kibana.writer.scheduled
    if not settings.kibana.enabled or not scheduled:
        typer.echo(
            "no class is scheduled (kibana.enabled and kibana.writer.scheduled): the writer"
            " does not run (a canary and a ramp are the terminal's: `argus kibana run`)"
        )
        raise typer.Exit(0)
    _run(serve(settings))


async def serve(settings: Settings, *, once: bool = False) -> None:
    from argus.gateway.errors import GatewayError

    engine = _engine(settings, writes=True)
    writer = build_writer(settings, engine, wait_for_gaps=False)
    interval = settings.kibana.writer.interval
    last: dict[str, datetime] = {}
    try:
        while True:
            now = datetime.now(UTC)
            try:
                await writer.run_lookups()
                for write_class in settings.kibana.writer.scheduled:
                    if write_class in last and now - last[write_class] < interval:
                        continue
                    last[write_class] = now
                    await _scheduled(settings, writer, engine, write_class)
            except GatewayError as exc:
                log.warning("writer: %s", exc)
            except Exception:  # keep serving: the next pass tries again
                log.exception("writer pass failed")
            if once:
                return
            await asyncio.sleep(TICK)
    finally:
        await engine.dispose()


async def _scheduled(
    settings: Settings, writer: Writer, engine: AsyncEngine, write_class: str
) -> None:
    problems = gate_problems(settings, write_class)
    async with engine.connect() as conn:
        step = await store.ramp_step(conn, write_class)
        order = await ramp.first_use_problem(conn, write_class)
        unattended = await ramp.scheduled_problem(conn, write_class)
    problems += [p for p in (order, unattended) if p]
    if problems:
        log.warning("writer: %s not run: %s", write_class, "; ".join(problems))
        return
    report = await writer.run_class(write_class, limit=step, kind="scheduled", by="service")
    for line in report.lines():
        log.info("writer: %s", line)
