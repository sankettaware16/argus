"""``argus siem ...`` and ``argus live ...``: the operator's side of the Elastic Gateway."""

from __future__ import annotations

import asyncio
import secrets
import sys
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import site
from argus.config.errors import ConfigError
from argus.config.settings import Settings
from argus.db.errors import DB_ERRORS, short_db_error
from argus.gateway.errors import GatewayError
from argus.gateway.health import HealthConfig, HealthState, effective, scale
from argus.gateway.lanes import Lane
from argus.gateway.pgstore import SWITCHES, PgStore
from argus.gateway.service import (
    build_gateway,
    collector_config,
    health_config,
    lane_plan,
    probe,
    selftest,
)

siem_app = typer.Typer(
    no_args_is_help=True, help="The Elastic Gateway: kill switches, health, budget."
)
live_app = typer.Typer(
    no_args_is_help=True, help="Live-test sessions against the SIEM, started by a person."
)
lanes_app = typer.Typer(no_args_is_help=True, help="The lanes' server-time buckets.")
siem_app.add_typer(lanes_app, name="lanes")

ConfigOption = Annotated[
    Path | None,
    typer.Option("--config", "-c", help="YAML config file (default: config/argus.yaml)."),
]
CONFIRM_WORDS = ("amber", "birch", "cedar", "delta", "ember", "fjord", "grove", "harbor")


def load(config: Path | None) -> Settings:
    """Settings the way every argus command loads them (secrets registered for redaction)."""
    from argus.cli import _load  # argus.cli imports this module: import at call time

    return _load(config)


def engine_for(settings: Settings) -> AsyncEngine:
    from argus.cli import _engine

    return _engine(settings, "app")


RESUME_NEEDS_OWNER = (
    "resuming needs the database owner (Q-A5): services and the runtime login may stop a"
    " switch, only the owner resumes it. Run it where the owner's password is configured"
    " (ARGUS_DATABASE__OWNER_PASSWORD), or in the custody layout as"
    " `sudo argus-owner {command}`"
)


def owner_engine_for(settings: Settings, command: str) -> AsyncEngine:
    """The owner's engine, for a resume (the database refuses one from any other role); exit
    code 2 with how to run it when the owner's password is not configured here."""
    from argus.db.engine import create_engine

    try:
        return create_engine(settings.database, role="owner")
    except ConfigError:
        typer.echo("error: " + RESUME_NEEDS_OWNER.format(command=command), err=True)
        raise typer.Exit(2) from None


def _run[T](coro: Coroutine[Any, Any, T]) -> T:
    return asyncio.run(coro)


async def _with_store[T](
    settings: Settings,
    use: Callable[[PgStore], Coroutine[Any, Any, T]],
    engine: AsyncEngine | None = None,
) -> T:
    engine = engine_for(settings) if engine is None else engine
    try:
        return await use(PgStore(engine))
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None
    finally:
        await engine.dispose()


def _switch(component: str, stopped: bool, reason: str | None, config: Path | None) -> None:
    if component not in SWITCHES:
        typer.echo(f"error: --component is one of {', '.join(SWITCHES)}", err=True)
        raise typer.Exit(2)
    settings = load(config)
    # a stop runs as the runtime login; a resume only as the owner (the database enforces it)
    command = f"siem resume --component {component}"
    engine = None if stopped else owner_engine_for(settings, command)

    async def use(store: PgStore) -> bool:
        return await store.set_switch(component, stopped=stopped, actor="cli", reason=reason)

    changed = _run(_with_store(settings, use, engine))
    verb = "stopped" if stopped else "resumed"
    typer.echo(f"{component}: {verb}" + ("" if changed else " (it already was)"))


@siem_app.command("stop")
def siem_stop(
    component: Annotated[str, typer.Option(help="global or one component")] = "global",
    reason: Annotated[str | None, typer.Option(help="why (kept in the audit trail)")] = None,
    config: ConfigOption = None,
) -> None:
    """Stop ARGUS's requests to the SIEM (health probes keep running); effective at once."""
    _switch(component, True, reason, config)


@siem_app.command("resume")
def siem_resume(
    component: Annotated[str, typer.Option(help="global or one component")] = "global",
    reason: Annotated[str | None, typer.Option(help="why (kept in the audit trail)")] = None,
    config: ConfigOption = None,
) -> None:
    """Allow ARGUS's requests again (the health state still decides how many)."""
    _switch(component, False, reason, config)


@siem_app.command("status")
def siem_status(config: ConfigOption = None) -> None:
    """Kill switches, health state, breaker, today's budget and the last requests (no SIEM
    request is made)."""
    settings = load(config)

    async def use(store: PgStore) -> list[str]:
        now = datetime.now(UTC)
        switches = await store.switches()
        cfg = health_config(settings.siem)
        memory = effective(await store.health(), now, cfg)
        breaker = await store.breaker()
        budget = await store.budget()
        lines = [
            "stopped: " + (", ".join(sorted(switches.stopped)) or "nothing"),
            f"health: {memory.state}"
            + (f" ({', '.join(memory.reasons)})" if memory.reasons else "")
            + (f" since {memory.since:%Y-%m-%d %H:%M} UTC" if memory.since else "")
            + (f"; last probe {memory.probed_at:%Y-%m-%d %H:%M} UTC" if memory.probed_at else ""),
            f"budget share now: {scale(memory, now, cfg) * 100:.0f}%",
            "breaker: "
            + (f"open until {breaker.open_until:%H:%M} UTC" if breaker.is_open(now) else "closed")
            + (f", level {breaker.level}" if breaker.level else ""),
            f"server time today: {budget.day_used_ms / 1000:.1f} s of "
            f"{settings.siem.budget.took_per_day_ms / 1000:.0f} s"
            + (f" ({budget.day})" if budget.day else ""),
            f"heavy queries today: {budget.heavy_day}; requests in flight: {len(budget.leases)}",
        ]
        day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        checking = lane_plan(settings.siem).spec(Lane.CHECKING)
        async with store.engine.connect() as conn:
            took, sent = (
                await conn.execute(
                    text(
                        "SELECT coalesce(sum(took_ms), 0), count(*) FROM siem_requests"
                        " WHERE lane = 'checking' AND at >= :day"
                    ),
                    {"day": day},
                )
            ).one()
            lines.append(
                f"checking lane today: {int(took) / 1000:.1f} s of"
                f" {checking.per_day_ms / 1000:.0f} s ({int(sent)} requests; NORMAL only,"
                " never in the quiet hours)"
            )
            rows = await conn.execute(
                text(
                    "SELECT at, template, outcome, took_ms FROM siem_requests"
                    " ORDER BY id DESC LIMIT 5"
                )
            )
            for at, template, outcome, took in rows:
                lines.append(f"  {at:%Y-%m-%d %H:%M:%S} {template} {outcome} {took} ms")
        return lines

    for line in _run(_with_store(settings, use)):
        typer.echo(line)


async def _on_siem[T](
    settings: Settings, use: Callable[[Any, PgStore], Coroutine[Any, Any, T]]
) -> T:
    engine = engine_for(settings)
    try:
        gateway, store = build_gateway(settings.siem, engine)
    except ConfigError as exc:
        await engine.dispose()
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from None
    try:
        return await use(gateway, store)
    except GatewayError as exc:
        typer.echo(f"error: {exc.reason}: {exc}", err=True)
        raise typer.Exit(1) from None
    finally:
        await gateway.transport.aclose()  # type: ignore[attr-defined]
        await engine.dispose()


@siem_app.command("probe")
def siem_probe(config: ConfigOption = None) -> None:
    """One health probe (two tiny requests to the SIEM); prints and stores the new state."""
    settings = load(config)

    async def use(gateway: Any, store: PgStore) -> str:
        memory = await probe(gateway, store, settings.siem)
        return f"health: {memory.state}" + (
            f" ({', '.join(memory.reasons)})" if memory.reasons else ""
        )

    typer.echo(_run(_on_siem(settings, use)))


@siem_app.command("selftest")
def siem_selftest(config: ConfigOption = None) -> None:
    """A health probe, then check the TLS pin, the server version and the API key's
    privileges (five small requests)."""
    settings = load(config)

    async def use(gateway: Any, store: PgStore) -> list[str]:
        await probe(gateway, store, settings.siem)
        return await selftest(gateway, settings.siem)

    problems = _run(_on_siem(settings, use))
    for problem in problems:
        typer.echo(f"problem: {problem}", err=True)
    if problems:
        raise typer.Exit(1)
    typer.echo("selftest passed: TLS pinned, a supported server version, read-only API key")


def _human_at_a_terminal() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _who() -> str:
    """The person at the terminal as an audit actor (``host:<login>``)."""
    import getpass
    import re

    try:
        login = getpass.getuser()
    except (KeyError, OSError):
        login = "unknown"
    return "host:" + (re.sub(r"[^A-Za-z0-9_.@/-]", "_", login)[:100] or "unknown")


@lanes_app.command("fill")
def lanes_fill(
    lane: Annotated[str, typer.Argument(help="the lane to top up, e.g. kibana_write")],
    reason: Annotated[str, typer.Option(help="why (kept in the audit trail)")] = (
        "the deploy of the lane's burst (D-243)"
    ),
    config: ConfigOption = None,
) -> None:
    """Top one lane's bucket up to its capacity (a person's command). A bucket stored
    before a lane had a burst holds a minute's share and takes hours to grow into it, so the 60 s
    burst of the Kibana write lane would not exist after the deploy until then. Allowed only
    while the SIEM's stored health is NORMAL at full scale (the burst exists only then); never over
    a debt. It writes ARGUS's own database only (nothing is sent to the SIEM or Kibana) and is kept
    in the audit trail with who and when."""
    if lane not in {item.value for item in Lane}:
        typer.echo(f"error: the lane is one of {', '.join(item.value for item in Lane)}", err=True)
        raise typer.Exit(2)
    if not _human_at_a_terminal():
        typer.echo("error: a bucket is topped up by a person at a terminal", err=True)
        raise typer.Exit(2)
    settings = load(config)
    chosen = Lane(lane)

    async def use() -> tuple[float, float]:
        engine = engine_for(settings)
        try:
            try:
                store = PgStore(engine, collector_config(settings.siem), lane_plan(settings.siem))
            except ValueError as exc:
                typer.echo(f"error: {exc}", err=True)
                raise typer.Exit(2) from None
            now = datetime.now(UTC)
            cfg = health_config(settings.siem)
            memory = effective(await store.health(), now, cfg)
            factor = scale(memory, now, cfg)
            if memory.state is not HealthState.NORMAL or factor < 1.0:
                typer.echo(
                    f"error: the SIEM is {memory.state}"
                    + (f" at {factor * 100:.0f}% of the budget" if factor < 1.0 else "")
                    + "; a bucket is topped up only while it is NORMAL at full scale"
                    " (run `argus siem probe` first if the last probe is old)",
                    err=True,
                )
                raise typer.Exit(1)
            typer.echo(f"This sets the {lane} lane's bucket to its capacity (ARGUS's database).")
            if typer.prompt(f"Type '{lane}' to confirm") != lane:
                typer.echo("not confirmed", err=True)
                raise typer.Exit(1)
            try:
                return await store.lane_fill(
                    chosen,
                    actor=_who(),
                    now=now,
                    scale=factor,
                    health=str(memory.state),
                    reason=reason[:300],
                )
            except ValueError as exc:
                typer.echo(f"error: {exc}", err=True)
                raise typer.Exit(1) from None
        finally:
            await engine.dispose()

    try:
        before, after = _run(use())
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None
    typer.echo(f"{lane}: {before / 1000:.1f} s of server time -> {after / 1000:.1f} s (audited)")


@live_app.command("start")
def live_start(
    max_requests: Annotated[int, typer.Option(min=1, max=50)] = 50,
    minutes: Annotated[int, typer.Option(min=1, max=60)] = 20,
    config: ConfigOption = None,
) -> None:
    """Open a live-test session: only a person at a terminal can, outside the quiet hours."""
    if not _human_at_a_terminal():
        typer.echo("error: a live session is started by a person at a terminal", err=True)
        raise typer.Exit(2)
    now = datetime.now(UTC)
    if site.in_quiet_hours(now):
        quiet = site.quiet_hours()
        typer.echo(
            f"error: no live tests between {quiet.start} and {quiet.end} UTC (ILM and new indices)",
            err=True,
        )
        raise typer.Exit(2)
    settings = load(config)
    word = secrets.choice(CONFIRM_WORDS)
    typer.echo(
        f"This allows up to {max_requests} read-only requests to the SIEM (production) for"
        f" {minutes} minutes."
    )
    if typer.prompt(f"Type '{word}' to confirm") != word:
        typer.echo("not confirmed", err=True)
        raise typer.Exit(1)
    session_id = secrets.token_hex(8)

    async def use(store: PgStore) -> None:
        await store.start_live_session(
            session_id, actor="cli", now=now, minutes=minutes, max_requests=max_requests
        )

    _run(_with_store(settings, use))
    # not ARGUS_LIVE_SESSION: ARGUS refuses ARGUS_ variables that are not settings, so exporting
    # that would stop every argus command (and the live tests, tests/live/conftest.py)
    typer.echo(f"export SIEM_LIVE_SESSION={session_id}")


@live_app.command("stop")
def live_stop(
    session_id: Annotated[str, typer.Argument(help="the session to end")],
    config: ConfigOption = None,
) -> None:
    """End a live-test session now."""
    settings = load(config)

    async def use(store: PgStore) -> bool:
        return await store.end_live_session(session_id, actor="cli", now=datetime.now(UTC))

    ended = _run(_with_store(settings, use))
    typer.echo("ended" if ended else "no such open session")
    if not ended:
        raise typer.Exit(1)


__all__ = ["HealthConfig", "live_app", "siem_app"]
