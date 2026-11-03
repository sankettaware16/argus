"""``argus rules ...`` and ``argus ti ...``: the rules registry and threat intelligence.
Everything reads the local store except ``ti sync`` (only with ``reference.ti_sync`` on) and
``ti check`` (only inside a human-issued live-test session)."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from sqlalchemy import text

from argus import site
from argus.config.errors import ConfigError
from argus.db.errors import DB_ERRORS, short_db_error
from argus.gateway.cli import ConfigOption, engine_for, load
from argus.gateway.errors import GatewayError
from argus.gateway.gateway import LiveLimits
from argus.gateway.service import build_gateway, probe
from argus.reference import jobs, knowledge, store
from argus.reference.templates import (
    NewestParams,
    TiLookup,
    TiMirrorPage,
    TiNewest,
    lookup_params,
    mirror_params,
)
from argus.reference.ti import Freshness, Indicator, answer, canonical, from_document

FAILURES: tuple[type[Exception], ...] = (
    *DB_ERRORS,
    GatewayError,
    ConfigError,
    store.IncompleteAnswer,
)
rules_app = typer.Typer(no_args_is_help=True, help="The rules registry.")
ti_app = typer.Typer(no_args_is_help=True, help="Threat intelligence.")
ABSENT = "192.0.2.1"  # TEST-NET-1 (RFC 5737): in no feed
NO_SOURCES = "no threat-intel source is configured (site.ti_sources): threat intel is off"


def _fail(exc: BaseException) -> typer.Exit:
    if isinstance(exc, GatewayError):
        typer.echo(f"error: {exc.reason}: {exc}", err=True)
    elif isinstance(exc, ConfigError):
        typer.echo(f"error: {exc}", err=True)
    else:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
    return typer.Exit(1)


@rules_app.command("refresh")
def rules_refresh(config: ConfigOption = None) -> None:
    """Rebuild the registry from the stored alerts (no SIEM request)."""
    settings = load(config)

    async def use() -> dict[str, int]:
        engine = engine_for(settings)
        try:
            return await jobs.refresh_rules(engine)
        except DB_ERRORS as exc:
            raise _fail(exc) from None
        finally:
            await engine.dispose()

    got = asyncio.run(use())
    typer.echo(
        f"{got['rules']} rules; {got['new_revisions']} new revisions;"
        f" {got['new_truncated']} executions newly found truncated"
    )


@rules_app.command("list")
def rules_list(config: ConfigOption = None) -> None:
    """The rules ARGUS knows, from their alerts."""
    settings = load(config)

    async def use() -> list[Any]:
        engine = engine_for(settings)
        try:
            async with engine.connect() as conn:
                rows = await conn.execute(
                    text(
                        "SELECT r.rule_id, r.name, r.type, r.revision, r.interval, r.alerts,"
                        " r.last_alert_at, r.execution_status, (SELECT count(*) FROM"
                        " coverage_gaps g WHERE g.kind = 'truncated_execution'"
                        " AND g.subject LIKE 'rule:' || r.rule_id || ':%') AS truncated"
                        " FROM rules r ORDER BY r.alerts DESC, r.rule_id"
                    )
                )
                return list(rows.all())
        except DB_ERRORS as exc:
            raise _fail(exc) from None
        finally:
            await engine.dispose()

    for r in asyncio.run(use()):
        last = f"{r.last_alert_at:%Y-%m-%d %H:%M} UTC" if r.last_alert_at else "never"
        typer.echo(
            f"{r.alerts:>7}  {str(r.name)[:60]:<60}  {r.type} rev {r.revision} every"
            f" {r.interval}, last alert {last}, {r.truncated} truncated runs,"
            f" execution {r.execution_status}"
        )


@ti_app.command("status")
def ti_status(config: ConfigOption = None) -> None:
    """How fresh each threat-intel source is, and what the mirrors hold (no SIEM request)."""
    settings = load(config)

    async def use() -> tuple[list[Freshness], Any]:
        engine = engine_for(settings)
        try:
            async with engine.connect() as conn:
                sources = await store.freshness(conn)
                kinds = (
                    await conn.execute(
                        text(
                            "SELECT kind, count(*) FROM ti_indicators WHERE removed_at IS NULL"
                            " GROUP BY kind ORDER BY kind"
                        )
                    )
                ).all()
                return sources, kinds
        except DB_ERRORS as exc:
            raise _fail(exc) from None
        finally:
            await engine.dispose()

    sources, kinds = asyncio.run(use())
    now = datetime.now(UTC)
    if not sources:
        typer.echo(NO_SOURCES)
        return
    for s in sources:
        newest = f"{s.newest:%Y-%m-%d %H:%M} UTC" if s.newest else "unknown"
        state = "STALE (newest older than 7 days)" if s.stale(now) else "fresh"
        typer.echo(f"{s.source}: newest indicator {newest}: {state}")
    if site.active().ti_mirrors:
        typer.echo("mirror: " + (", ".join(f"{n} {k}" for k, n in kinds) or "empty"))
    if not settings.reference.ti_sync:
        typer.echo("sync is off (reference.ti_sync: false) until the live check passes")


@ti_app.command("lookup")
def ti_lookup(
    values: Annotated[list[str], typer.Argument(help="IPs, domains, URLs or hashes")],
    config: ConfigOption = None,
) -> None:
    """What ARGUS knows about each value: the mirrors, the cache, and (with sync on) a fresh
    lookup of the looked-up sources."""
    settings = load(config)
    pairs = []
    for raw in values:
        kind = next((k for k in ("ip", "domain") if canonical(k, raw)), "url" if "/" in raw
                    else "hash")  # fmt: skip
        value = canonical(kind, raw)
        if value is None:
            typer.echo(f"error: {raw[:80]!r} is not an IP, domain, URL or hash", err=True)
            raise typer.Exit(2)
        pairs.append((kind, value))

    async def use() -> list[dict[str, Any]]:
        engine = engine_for(settings)
        gateway = None
        try:
            if settings.reference.ti_sync:
                gateway, _ = build_gateway(settings.siem, engine)
            run = jobs.runner_for(gateway) if gateway is not None else None
            async with engine.begin() as conn:
                return await store.lookup(conn, run, pairs, datetime.now(UTC))
        except FAILURES as exc:
            raise _fail(exc) from None
        finally:
            if gateway is not None:
                await gateway.transport.aclose()  # type: ignore[attr-defined]
            await engine.dispose()

    for got in asyncio.run(use()):
        typer.echo(json.dumps(got, indent=2))


@ti_app.command("sync")
def ti_sync(config: ConfigOption = None) -> None:
    """Mirror the mirror sources and read how fresh the looked-up ones are (only with
    ``reference.ti_sync`` on: after the live check)."""
    settings = load(config)
    if not settings.reference.ti_sync:
        typer.echo("error: reference.ti_sync is off; run `argus ti check` in a live session"
                   " first (docs/runbooks/reference.md)", err=True)  # fmt: skip
        raise typer.Exit(2)

    async def use() -> dict[str, Any]:
        engine = engine_for(settings)
        gateway, _ = build_gateway(settings.siem, engine)
        try:
            await probe(gateway, gateway.state, settings.siem)
            return await jobs.sync_ti(engine, gateway)
        except FAILURES as exc:
            raise _fail(exc) from None
        finally:
            await gateway.transport.aclose()  # type: ignore[attr-defined]
            await engine.dispose()

    typer.echo(json.dumps(asyncio.run(use()), default=str))


@ti_app.command("check")
def ti_check(
    session: Annotated[str, typer.Option(help="from `argus live start`")],
    config: ConfigOption = None,
) -> None:
    """The live check, inside a live-test session (about 3 requests per source, size ≤ 10,
    read-only): each source's newest indicator, 10 documents of each mirror normalised, and a
    lookup of one known value of each looked-up source and one absent IP. Stores nothing."""
    settings = load(config)

    async def use() -> list[str]:
        engine = engine_for(settings)
        gateway, state = build_gateway(settings.siem, engine, live=LiveLimits(session))
        run = jobs.runner_for(gateway)
        lines: list[str] = []
        profile = site.active()
        try:
            health = await probe(gateway, state, settings.siem)
            lines.append(f"SIEM health: {health.state}")
            if not profile.ti_sources:
                lines.append(NO_SOURCES)
                return lines
            sources: list[Freshness] = []
            known: dict[str, tuple[str, str]] = {}
            for src in profile.ti_sources:
                result = await run(TiNewest(), NewestParams(index=src.index))
                hits = result.body.get("hits", {}).get("hits", [])
                doc = hits[0].get("_source", {}) if hits else {}
                stamp = store.newest_of(result)
                sources.append(Freshness(src.index, stamp, datetime.now(UTC)))
                lines.append(f"{src.index}: newest {stamp}")
                rows = from_document(src.schema_, src.index, doc) if src.mode == "lookup" else []
                if rows:
                    known[src.index] = (rows[0].kind, rows[0].value)
            parsed: list[Indicator] = []
            ok = True
            for src in profile.ti_mirrors:
                page = await run(TiMirrorPage(), mirror_params(src, size=10))
                hits = page.body.get("hits", {}).get("hits", [])
                got = [
                    i
                    for h in hits
                    for i in from_document(src.schema_, src.index, h.get("_source") or {})
                ]
                parsed += got
                kinds = sorted({i.kind for i in got})
                total = page.body.get("hits", {}).get("total", {}).get("value")
                lines.append(f"{src.index}: {total} documents; 10 read, {len(got)} indicators"
                             f" ({', '.join(kinds) or 'none'})")  # fmt: skip
                ok = ok and bool(got)
            found: list[Indicator] = []
            asked: list[str] = [ABSENT]
            for src in profile.ti_lookups:
                wanted = [v for _, v in ([known[src.index]] if src.index in known else [])]
                values = (*wanted, ABSENT)
                looked = await run(TiLookup(), lookup_params([src], values, size=10))
                rows = [
                    i
                    for h in looked.body.get("hits", {}).get("hits", [])
                    for i in from_document(src.schema_, src.index, h.get("_source") or {})
                ]
                found += rows
                asked = list(dict.fromkeys([*wanted, *asked]))
                ok = ok and (not wanted or any(i.value == wanted[0] for i in rows))
                if not wanted:
                    lines.append(f"note: {src.index} returned no readable newest row to look up")
            now = datetime.now(UTC)
            for value in asked:
                lines.append(json.dumps(answer(value, found + parsed, sources, now)))
            absent = answer(ABSENT, found + parsed, sources, now)["sources"]
            ok = ok and all("no_match" in v for v in absent.values())
            lines.append("LIVE CHECK " + ("PASSED" if ok else "FAILED"))
            return lines
        except FAILURES as exc:
            raise _fail(exc) from None
        finally:
            await gateway.transport.aclose()  # type: ignore[attr-defined]
            await engine.dispose()

    for line in asyncio.run(use()):
        typer.echo(line)


knowledge_app = typer.Typer(no_args_is_help=True, help="The knowledge store.")


@knowledge_app.command("load")
def knowledge_load(
    path: Annotated[str, typer.Argument(help="the seeds file")] = str(knowledge.SEEDS),
    config: ConfigOption = None,
) -> None:
    """Add the seeds that are new (existing keys are kept as reviewers left them)."""
    settings = load(config)
    try:
        items = knowledge.read(Path(path))
    except (OSError, ValueError) as exc:
        typer.echo(f"error: {str(exc)[:300]}", err=True)
        raise typer.Exit(2) from None

    async def use() -> int:
        engine = engine_for(settings)
        try:
            async with engine.begin() as conn:
                return await knowledge.load(conn, items, path)
        except FAILURES as exc:
            raise _fail(exc) from None
        finally:
            await engine.dispose()

    typer.echo(f"{asyncio.run(use())} of {len(items)} items added")
