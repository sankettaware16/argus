"""``argus investigation ...``: the gaps of a dossier, the deterministic wave and "Check more".
Everything here that can send a request to the SIEM says so first, asks for a typed
confirmation word and spends the investigation lane; ``--dry-run`` and ``gaps`` send nothing."""

from __future__ import annotations

import asyncio
import getpass
import json
import os
import secrets
import socket
import uuid
from collections.abc import Coroutine
from datetime import UTC, datetime
from typing import Annotated, Any

import typer

from argus.assets.classify import IpClassifier
from argus.assets.store import load_asset_map
from argus.config.errors import ConfigError
from argus.context import batch1
from argus.db.errors import DB_ERRORS, short_db_error
from argus.gateway.cli import CONFIRM_WORDS, ConfigOption, engine_for, load
from argus.gateway.errors import GatewayError
from argus.investigation import checks, measure, service, store, wave
from argus.investigation.gaps import Gap
from argus.investigation.plan import Plan

investigation_app = typer.Typer(
    no_args_is_help=True,
    help="Deep investigation: the gaps in a dossier, the deterministic wave and Check more.",
)
Id = Annotated[str, typer.Argument(help="The investigation's id.")]


FAILURES: tuple[type[Exception], ...] = (*DB_ERRORS, GatewayError, ConfigError)


def _now() -> datetime:
    return datetime.now(UTC)


def _run[T](work: Coroutine[Any, Any, T]) -> T:
    try:
        return asyncio.run(work)
    except FAILURES as exc:
        typer.echo(f"error: {short_db_error(exc) if isinstance(exc, DB_ERRORS) else exc}",
                   err=True)  # fmt: skip
        raise typer.Exit(1) from None


def _uuid(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError:
        typer.echo(f"error: {value!r} is not an investigation id", err=True)
        raise typer.Exit(2) from None


def _classifier(settings: Any) -> IpClassifier | None:
    assets = load_asset_map(settings.assets.map_path)
    return None if assets is None else IpClassifier(assets, settings.site.own_networks)


def _gap_lines(gaps: tuple[Gap, ...]) -> list[str]:
    out = []
    for g in gaps:
        closers = ", ".join(f"{c}{' (asked)' if c in g.exhausted else ''}" for c in g.closers)
        state = "closable" if g.closable else f"not closable: {g.blocker}"
        out.append(
            f"{g.rank:>2}. [{g.kind.value}{', floor' if g.floor else ''}] {g.what}"
            f" Why: {g.why}. {state}." + (f" Checks: {closers}." if closers else "")
        )
    return out


def _plan_lines(plan: Plan) -> list[str]:
    out = []
    for p in plan.checks:
        window = ""
        if p.task is not None:
            window = batch1.describe(p.task.template.plan(p.task.params).window)
        what = {"send": "would ask", "reuse": "has the answer", "skip": "leaves"}[p.mode]
        extra = f" ({p.why_not})" if p.why_not else ""
        out.append(f"  - {what}: {p.template} [{'heavy' if p.heavy else 'light'}] {window}{extra}")
        out.append(f"      because: {p.reason}")
    out += [f"  - no check for {key}: {why}" for key, why in plan.left]
    return out


def _confirm(what: str) -> None:
    typer.echo(f"{what} It spends the investigation lane (400 ms of SIEM time a minute) and"
               " sends read-only requests to the SIEM (production).")  # fmt: skip
    word = secrets.choice(CONFIRM_WORDS)
    if typer.prompt(f"Type '{word}' to confirm") != word:
        typer.echo("not confirmed: nothing was sent", err=True)
        raise typer.Exit(2)


@investigation_app.command("gaps")
def gaps_cmd(
    investigation_id: Id,
    as_json: Annotated[bool, typer.Option("--json", help="Print JSON.")] = False,
    config: ConfigOption = None,
) -> None:
    """The gaps in an investigation's newest dossier, ranked: what is unknown, which checks
    could close it (found by what they answer and the rule's own indices, never its name),
    which were asked already, and why one cannot be asked. Sends nothing."""
    settings = load(config)
    inv = _uuid(investigation_id)

    async def use() -> tuple[wave.Prepared | None, Any]:
        engine = engine_for(settings)
        try:
            env = service.dry_env(settings, engine, _classifier(settings))
            async with engine.connect() as conn:
                prep = await wave.prepare(env, conn, inv, _now())
            return prep, env
        finally:
            await engine.dispose()

    prep, _env = _run(use())
    if prep is None:
        typer.echo("no dossier for this investigation yet", err=True)
        raise typer.Exit(1)
    if as_json:
        typer.echo(json.dumps([{
            "rank": g.rank, "kind": g.kind.value, "key": g.key, "what": g.what, "why": g.why,
            "closers": list(g.closers), "asked": list(g.exhausted), "blocker": g.blocker,
            "floor": g.floor} for g in prep.gaps], indent=2))  # fmt: skip
        return
    cur = prep.current
    typer.echo(
        f"dossier {cur.pack} (version {cur.version}); the rule: type"
        f" {prep.profile.rule_type or 'unknown'}, reads {sorted(prep.profile.sources) or 'no log'}"
    )
    typer.echo(f"{len(prep.gaps)} gaps, {sum(g.closable for g in prep.gaps)} closable")
    for line in _gap_lines(prep.gaps):
        typer.echo(line)


@investigation_app.command("wave")
def wave_cmd(
    investigation_id: Annotated[
        str | None, typer.Option("--id", help="One investigation (required without --dry-run).")
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what a wave would do; send nothing.")
    ] = False,
    limit: Annotated[int, typer.Option(min=1, max=50, help="Investigations to show.")] = 10,
    config: ConfigOption = None,
) -> None:
    """The deterministic wave. With --dry-run: for the undecided investigations the service
    would take next (or --id), the gaps, the checks it would ask and why, and what it leaves;
    nothing is sent. Without it: one wave for --id, now, after you confirm (the first live wave
    is yours; the service's own waves wait for investigation.wave)."""
    settings = load(config)
    if not dry_run and investigation_id is None:
        typer.echo("error: a live wave needs --id (or use --dry-run)", err=True)
        raise typer.Exit(2)
    if dry_run:
        _run(_dry(settings, None if investigation_id is None else _uuid(investigation_id), limit))
        return
    assert investigation_id is not None
    _confirm(f"This runs one wave for investigation {investigation_id}.")
    _run(_live(settings, _uuid(investigation_id), "wave", "", ""))


async def _dry(settings: Any, inv: uuid.UUID | None, limit: int) -> None:
    engine = engine_for(settings)
    try:
        env = service.dry_env(settings, engine, _classifier(settings))
        now = _now()
        typer.echo(f"dry run: nothing is sent. investigation.wave is"
                   f" {'on' if settings.investigation.wave else 'off'}; caps {env.caps}; at most"
                   f" {env.per_day} waves a day")  # fmt: skip
        async with engine.connect() as conn:
            if not await wave.ready(env, now):
                typer.echo("the SIEM is not NORMAL, it is the quiet hours, or the investigation"
                           " lane is stopped or tripped: a wave would wait")  # fmt: skip
            chosen = (
                [p for p in [await wave.prepare(env, conn, inv, now)] if p is not None]
                if inv is not None else await wave.select(env, conn, now, limit)
            )  # fmt: skip
            typer.echo(f"{len(chosen)} investigations")
            for prep in chosen:
                plan = await wave.plan_wave(env, conn, prep, now)
                cur = prep.current
                typer.echo(f"\n{cur.investigation_id} ({cur.pack}, severity {cur.severity}):"
                           f" {sum(g.closable for g in plan.gaps)} closable gaps of"
                           f" {len(plan.gaps)}; {len(plan.sends)} requests"
                           f" ({sum(p.heavy for p in plan.sends)} heavy)")  # fmt: skip
                for line in _plan_lines(plan):
                    typer.echo(line)
    finally:
        await engine.dispose()


async def _live(settings: Any, inv: uuid.UUID, kind: str, template: str, entity: str) -> None:
    """Queue the request as a person's (recorded, one open request at a time), claim it and run
    it here, so the record and the audit are what the service's would be."""
    engine = engine_for(settings)
    opened = await service.open_env(settings, engine, _classifier(settings))
    if opened is None:
        await engine.dispose()
        raise ConfigError("the SIEM is not set up here (no key or pinned certificate)")
    env, close = opened
    try:
        now = _now()
        async with engine.connect() as conn:
            prep = await wave.prepare(env, conn, inv, now)
        if prep is None:
            raise ConfigError("no dossier for this investigation yet")
        who = f"cli:{getpass.getuser()}"[:120]
        async with engine.begin() as conn:
            queued = await store.enqueue(
                conn, inv, prep.current.version, kind, "person", now,
                template=template, entity=entity, requested_by=who,
            )  # fmt: skip
        if queued is None:
            raise ConfigError("the same request is open already")
        owner = f"{socket.gethostname()}:{os.getpid()}"
        async with engine.begin() as conn:
            claimed = await store.claim(conn, owner, now, 1, only=[queued])  # no one else's
        for request in claimed:
            status, outcome = await wave.run_request(env, request)
            if status == "later":  # the SIEM cannot serve it now: the service will, later
                async with engine.begin() as conn:
                    progress = {k: outcome.get(k, 0) for k in ("requests", "heavy", "server_ms")}
                    await store.requeue(conn, request.id, _now(), progress)
                why = (outcome.get("later") or {}).get("reason")
                typer.echo(f"waiting: the SIEM cannot serve it now ({why}); it stays queued for"
                           " ARGUS's service, which runs it when it can")  # fmt: skip
                continue
            async with engine.begin() as conn:
                await store.finish(conn, request.id, status, outcome, _now())
            typer.echo(f"{status}: {outcome.get('requests', 0)} requests"
                       f" ({outcome.get('heavy', 0)} heavy), {outcome.get('server_ms', 0)} ms of"
                       f" SIEM time; dossier {outcome.get('dossier') or 'unchanged'}")  # fmt: skip
            for c in outcome.get("checks", []):
                said = c.get("status") or c.get("why_not")
                typer.echo(f"  - {c['template']}: {said} {c.get('eid', '')}"
                           f"{' (asked)' if c.get('sent') else ''}")  # fmt: skip
            if outcome.get("error"):
                typer.echo(f"  {outcome['error']}")
    finally:
        await close()
        await engine.dispose()


WAITS = (
    "it stays queued, and ARGUS's service runs it once the SIEM is back to normal and outside"
    " its busy hours"
)


@investigation_app.command("check-more")
def check_more_cmd(
    investigation_id: Id,
    template: Annotated[str, typer.Argument(help=f"One of: {', '.join(checks.APPROVED)}.")],
    entity: Annotated[str, typer.Argument(help="An address or a domain.")],
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show the request and its cost class; queue nothing.")
    ] = False,
    now: Annotated[
        bool, typer.Option("--now", help="Run it here, after you confirm, instead of queueing.")
    ] = False,
    config: ConfigOption = None,
) -> None:
    """One approved template about one address or domain (what the Check more button asks).
    By default the request is queued for ARGUS's service, as a person's (audited, with its
    cost shown once done)."""
    settings = load(config)
    inv = _uuid(investigation_id)
    problem = checks.validate(template, entity)
    if problem is not None:
        typer.echo(f"error: {problem}", err=True)
        raise typer.Exit(2)
    if now:
        _confirm(f"This runs {template} about {entity} for investigation {inv}.")
        _run(_live(settings, inv, "check", template, checks.clean(entity) or entity))
        return

    async def use() -> list[str]:
        engine = engine_for(settings)
        try:
            env = service.dry_env(settings, engine, _classifier(settings))
            when = _now()
            async with engine.connect() as conn:
                prep = await wave.prepare(env, conn, inv, when)
                if prep is None:
                    return ["no dossier for this investigation yet"]
                plan = await wave.plan_check(env, conn, prep, template, entity, when)
            waits = plan.waits is not None  # the SIEM not NORMAL, the quiet hours: not refused
            if dry_run:
                lines = ["dry run: nothing is queued or sent", *_plan_lines(plan)]
                return [*lines, WAITS] if waits else lines
            if plan.checks[0].mode == "skip" and not waits:
                return [f"refused: {plan.checks[0].why_not}"]
            async with engine.begin() as conn:
                state, detail = await checks.request(
                    conn, inv, prep.current.version, template, entity,
                    f"cli:{getpass.getuser()}", when,
                )  # fmt: skip
            if state == "queued" and waits:
                return [f"queued: {plan.checks[0].why_not}; {WAITS}"]
            if state == "queued":
                return ["queued: ARGUS's service runs it when the SIEM is normal"]
            return [f"the same request is open already: {detail}"]
        finally:
            await engine.dispose()

    for line in _run(use()):
        typer.echo(line)


@investigation_app.command("run")
def run_cmd(
    once: Annotated[bool, typer.Option(help="One pass, then stop.")] = False,
    every: Annotated[int, typer.Option(min=10, help="Seconds between passes.")] = 60,
    config: ConfigOption = None,
) -> None:
    """Run the queued requests (a person's first) and, with investigation.wave on, queue and
    run the engine's waves, in passes. ``argus assess run`` does this beside the decision
    engine; this runs it alone. Nothing is claimed while the SIEM is not NORMAL."""
    settings = load(config)
    owner = f"{socket.gethostname()}:{os.getpid()}"

    async def loop() -> None:
        engine = engine_for(settings)
        opened = await service.open_env(settings, engine, _classifier(settings))
        if opened is None:
            await engine.dispose()
            raise ConfigError("the SIEM is not set up here (no key or pinned certificate)")
        env, close = opened
        try:
            while True:
                done = await wave.run_pass(env, owner, wave=settings.investigation.wave)
                typer.echo("investigation: " + " ".join(f"{k} {v}" for k, v in done.items()))
                if once:
                    return
                await asyncio.sleep(every)
        finally:
            await close()
            await engine.dispose()

    _run(loop())


@investigation_app.command("measure")
def measure_cmd(
    repeats: Annotated[int, typer.Option(min=1, max=5, help="Runs of the wave arm.")] = 2,
    live: Annotated[
        bool, typer.Option("--live", help="Run the wave for the undecided items (the lead's).")
    ] = False,
    split: Annotated[
        str, typer.Option(help="test (the default: the only split that measures), dev or all.")
    ] = "test",
    config: ConfigOption = None,
) -> None:
    """The gold measurement: how often the decision engine cannot decide a gold item,
    before the wave and after it (paired, repeated), and that no true positive is proposed
    benign. Without --live nothing is sent: it shows the baseline and what a wave would ask.
    The decision engine learns the gold set's dev answers, so only the test split measures
    anything; the report is per split."""
    settings = load(config)
    if split not in ("test", "dev", "all"):
        typer.echo("error: --split is test, dev or all", err=True)
        raise typer.Exit(2)
    if live:
        _confirm("This runs the wave for every undecided gold item.")

    async def use() -> list[str]:
        engine = engine_for(settings)
        opened = await service.open_env(settings, engine, _classifier(settings)) if live else None
        if live and opened is None:
            await engine.dispose()
            raise ConfigError("the SIEM is not set up here (no key or pinned certificate)")
        env = opened[0] if opened else service.dry_env(settings, engine, _classifier(settings))
        try:
            async with engine.connect() as conn:
                got = await measure.measure(env, conn, split=None if split == "all" else split,
                                            repeats=repeats, live=live)  # fmt: skip
            return measure.report(got)
        finally:
            if opened is not None:
                await opened[1]()
            await engine.dispose()

    for line in _run(use()):
        typer.echo(line)
