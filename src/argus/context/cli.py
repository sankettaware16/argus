"""``argus worker ...``: run the context graph on the job queue, see how it is
doing, prune old checkpoints, and measure capacity against the load budget."""

from __future__ import annotations

import asyncio
import json
import logging
import signal
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import psycopg
import psycopg_pool
import typer
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assets import load_asset_map
from argus.assets.classify import IpClassifier
from argus.config.errors import ConfigError
from argus.config.settings import Settings
from argus.context import capacity, checkpoints
from argus.context.packs import default_registry
from argus.context.worker import Worker, WorkerConfig
from argus.db.errors import DB_ERRORS, short_db_error
from argus.freshness.reader import policy_of
from argus.gateway.budget import BudgetConfig
from argus.gateway.cli import ConfigOption, engine_for, load
from argus.gateway.service import build_gateway, collector_config, health_config

FIRST_RUN_NAMES = frozenset(
    {"proxy.pair", "proxy.contact", "dns.host_domains", "web.path_outcomes", "logs.source_events"}
)
worker_app = typer.Typer(
    no_args_is_help=True, help="The worker: dossiers for the queued investigations."
)
log = logging.getLogger("argus.worker")
# The checkpoint saver talks psycopg directly (its pool), not through SQLAlchemy.
WORKER_DB_ERRORS: tuple[type[Exception], ...] = (
    *DB_ERRORS,
    psycopg.Error,
    psycopg_pool.PoolTimeout,
)


async def _with_worker[T](
    settings: Settings, use: Callable[[Worker], Coroutine[Any, Any, T]], *, concurrency: int
) -> T:
    engine = engine_for(settings)
    gateway = None
    try:
        gateway, _ = build_gateway(settings.siem, engine)
    except ConfigError as exc:  # the stub pack never asks the SIEM; remote tasks would defer
        log.info("no SIEM gateway (%s): remote evidence tasks are deferred", exc)
    try:
        async with checkpoints.open_saver(settings.database) as saver:
            config = WorkerConfig(
                concurrency=concurrency,
                history=settings.history.window,
                freshness=policy_of(settings),
            )
            assets = load_asset_map(settings.assets.map_path)
            classifier = IpClassifier(assets, settings.site.own_networks)
            packs = default_registry(
                classifier,
                remote_ti=settings.reference.ti_sync,
                log_queries=settings.enrichment.log_queries,
                proxy_aggregations=settings.enrichment.proxy_aggregations,
            )
            return await use(Worker(engine, saver, packs=packs, gateway=gateway, config=config))
    except WORKER_DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None
    finally:
        if gateway is not None:
            await gateway.transport.aclose()  # type: ignore[attr-defined]
        await engine.dispose()


Concurrency = Annotated[int, typer.Option(min=1, max=16, help="jobs at once")]


@worker_app.command("run")
def worker_run(concurrency: Concurrency = 4, config: ConfigOption = None) -> None:
    """Run the worker until stopped (Ctrl-C or SIGTERM): claim due jobs, write dossiers,
    prune checkpoints hourly. Running jobs finish first; a killed worker's jobs are taken
    over when their leases expire."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    async def use(worker: Worker) -> None:
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        await worker.run_forever(stop)

    asyncio.run(_with_worker(load(config), use, concurrency=concurrency))


@worker_app.command("once")
def worker_once(
    limit: Annotated[int, typer.Option(min=1, max=10_000, help="jobs to run")] = 10,
    config: ConfigOption = None,
) -> None:
    """Run up to LIMIT due jobs, then stop."""

    async def use(worker: Worker) -> dict[str, int]:
        outcomes: dict[str, int] = {}
        left = limit
        while left > 0:
            results = await worker.run_once(min(left, worker.config.concurrency))
            if not results:
                break
            left -= len(results)
            for result in results:
                outcomes[result.outcome] = outcomes.get(result.outcome, 0) + 1
        return outcomes

    outcomes = asyncio.run(_with_worker(load(config), use, concurrency=4))
    summary = ", ".join(f"{n} {outcome}" for outcome, n in sorted(outcomes.items()))
    typer.echo(f"jobs: {summary or 'none due'}")


async def status_lines(engine: AsyncEngine) -> list[str]:
    async with engine.connect() as conn:
        jobs = (
            await conn.execute(
                text(
                    "SELECT status, count(*), count(*) FILTER (WHERE deferred_since IS NOT NULL),"
                    " count(*) FILTER (WHERE status = 'queued' AND run_after <= now())"
                    " FROM jobs GROUP BY status ORDER BY status"
                )
            )
        ).all()
        dossiers = (
            await conn.execute(
                text("SELECT status, count(*) FROM dossiers GROUP BY status ORDER BY status")
            )
        ).all()
        failed = (
            await conn.execute(
                text(
                    "SELECT error, count(*) FROM jobs WHERE status = 'failed'"
                    " GROUP BY error ORDER BY count(*) DESC LIMIT 5"
                )
            )
        ).all()
    usage = await checkpoints.usage(engine)
    lines = ["jobs:"]
    for state, n, deferred, due in jobs:
        extra = []
        if deferred:
            extra.append(f"{deferred} waiting for the SIEM or Postgres")
        if state == "queued":
            extra.append(f"{due} due now")
        lines.append(f"  {state}: {n}" + (f" ({', '.join(extra)})" if extra else ""))
    lines.append("dossiers:")
    lines += [f"  {state}: {n}" for state, n in dossiers] or ["  none yet"]
    if failed:
        lines.append("failed jobs, by error:")
        lines += [f"  {n}x {str(error)[:120]}" for error, n in failed]
    lines.append(f"checkpoints: {usage['threads']} threads, {usage['bytes'] // 1024} KiB")
    return lines


@worker_app.command("status")
def worker_status(config: ConfigOption = None) -> None:
    """The queue, the dossiers and the checkpoints (no SIEM request)."""
    settings = load(config)

    async def use() -> list[str]:
        engine = engine_for(settings)
        try:
            return await status_lines(engine)
        except DB_ERRORS as exc:
            typer.echo(f"error: {short_db_error(exc)}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()

    for line in asyncio.run(use()):
        typer.echo(line)


@worker_app.command("prune")
def worker_prune(
    hours: Annotated[int, typer.Option(min=1, max=24 * 30, help="keep threads this long")] = 48,
    config: ConfigOption = None,
) -> None:
    """Delete checkpoint threads not touched for HOURS (failed, deferred or superseded runs)."""
    settings = load(config)

    async def use() -> int:
        engine = engine_for(settings)
        try:
            return await checkpoints.prune(engine, datetime.now(UTC), timedelta(hours=hours))
        except DB_ERRORS as exc:
            typer.echo(f"error: {short_db_error(exc)}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()

    typer.echo(f"pruned {asyncio.run(use())} checkpoint threads")


async def load_changes(engine: AsyncEngine) -> list[tuple[datetime, int]]:
    """Every stored original alert as (when the rule wrote it, investigation number): the
    material changes the job stream comes from. No identifiers leave the database."""
    async with engine.connect() as conn:
        rows = await conn.execute(
            text(
                "SELECT a.detected_at, dense_rank() OVER (ORDER BY l.investigation_id)"
                " FROM investigation_alerts l JOIN alert_records a ON a.alert_id = l.alert_id"
                " WHERE l.duplicate_of IS NULL AND a.detected_at IS NOT NULL"
            )
        )
        return [(at, int(n)) for at, n in rows]


def capacity_rows(
    changes: list[tuple[datetime, int]],
    profiles: list[str],
    outage: timedelta,
    budget: BudgetConfig,
) -> list[dict[str, Any]]:
    days = capacity.full_days(changes)
    start = capacity.busiest_start(changes, outage) if outage else None
    rows = []
    for name in profiles:
        profile = capacity.PROFILES[name]
        steady = capacity.simulate(
            changes, capacity.Scenario(profile, capacity.LATENCY, budget=budget)
        )
        row: dict[str, Any] = {
            "profile": name,
            "first_run": [c.value for c in profile.first],
            "rerun": [c.value for c in profile.rerun],
            "runs": steady.runs,
            "requests": steady.requests,
            "skipped_budget": steady.skipped,
            "share_of_daily_cap": round(steady.share(budget, days), 4),
            "busiest_day_minutes": round(
                max(steady.enrich_ms_by_day.values(), default=0) / 60_000, 1
            ),
            "p95_wait_s": round(steady.p95_wait_s),
            "max_wait_s": round(steady.max_wait_s),
            "unfinished": steady.unfinished,
        }
        if start is not None:
            hit = capacity.simulate(
                changes,
                capacity.Scenario(profile, capacity.LATENCY, budget=budget,
                                  outage=(start, start + outage)),
            )  # fmt: skip
            drained = hit.drained_after
            row.update(
                outage_start=start.isoformat(),
                outage_hours=outage.total_seconds() / 3600,
                drained_hours=None if drained is None else round(drained.total_seconds() / 3600, 2),
                outage_backlog_peak=hit.backlog_peak,
                outage_unfinished=hit.unfinished,
            )
        rows.append(row)
    return rows


@worker_app.command("capacity")
def worker_capacity(
    profile: Annotated[
        list[str] | None, typer.Option(help=f"one of {', '.join(capacity.PROFILES)}")
    ] = None,
    outage_hours: Annotated[float, typer.Option(min=0, max=24)] = 3.0,
    output: Annotated[Path | None, typer.Option(help="write the rows as JSON here")] = None,
    config: ConfigOption = None,
) -> None:
    """Replay the stored alerts' job stream through the real budget code for each per-run
    request profile, with an outage at the busiest time. Reads only the local
    database; no SIEM request."""
    settings = load(config)
    names = profile or list(capacity.PROFILES)
    unknown = [n for n in names if n not in capacity.PROFILES]
    if unknown:
        typer.echo(f"error: unknown profile {', '.join(unknown)}", err=True)
        raise typer.Exit(2)

    async def use() -> list[tuple[datetime, int]]:
        engine = engine_for(settings)
        try:
            return await load_changes(engine)
        except DB_ERRORS as exc:
            typer.echo(f"error: {short_db_error(exc)}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()

    changes = asyncio.run(use())
    if not changes:
        typer.echo("no stored alerts to replay")
        raise typer.Exit(1)
    rows = capacity_rows(  # the collector's lane: the collector and enrichment share it
        changes, names, timedelta(hours=outage_hours), collector_config(settings.siem)
    )
    first, last = min(changes)[0], max(changes)[0]
    typer.echo(f"{len(changes)} changes, {first:%Y-%m-%d %H:%M} to {last:%Y-%m-%d %H:%M} UTC")
    for row in rows:
        line = (
            f"  {row['profile']:<14} {row['share_of_daily_cap']:>6.1%} of the daily cap,"
            f" busiest day {row['busiest_day_minutes']} min, p95 wait {row['p95_wait_s']} s"
        )
        if "drained_hours" in row:
            line += f", {outage_hours:g} h outage drained in {row['drained_hours']} h"
        typer.echo(line)
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(rows, indent=2) + "\n")
        typer.echo(f"written to {output}")


async def queue_rederive(engine: AsyncEngine, pack: str) -> int:
    """Queue a job for each investigation whose newest dossier is not from ``pack`` (or that
    has none); one already queued or running is left as it is. An investigation whose raw
    alerts or evidence snapshots the retention purge removed keeps the dossier it has:
    a re-derivation would read what is no longer there."""
    async with engine.begin() as conn:
        rows = await conn.execute(
            text(
                "INSERT INTO jobs (investigation_id, trigger, run_after)"
                " SELECT i.id, 'rederive', now() FROM investigations i"
                " WHERE NOT EXISTS (SELECT 1 FROM dossiers d WHERE d.investigation_id = i.id"
                "  AND d.version = i.version AND d.pack = :pack)"
                " AND NOT EXISTS (SELECT 1 FROM evidence e WHERE e.investigation_id = i.id"
                "  AND e.snapshot_purged_at IS NOT NULL)"
                " AND NOT EXISTS (SELECT 1 FROM investigation_alerts l JOIN alert_records a"
                "  ON a.alert_id = l.alert_id WHERE l.investigation_id = i.id"
                "  AND a.raw_purged_at IS NOT NULL)"
                " ON CONFLICT (investigation_id) WHERE status IN ('queued', 'running')"
                " DO NOTHING RETURNING 1"
            ),
            {"pack": pack},
        )
        return len(rows.all())


@worker_app.command("rederive")
def worker_rederive(config: ConfigOption = None) -> None:
    """Queue the investigations whose dossier came from an older pack (or none): the worker
    writes a new dossier for each with the current pack (no SIEM request)."""
    settings = load(config)

    async def use() -> int:
        engine = engine_for(settings)
        try:
            return await queue_rederive(engine, default_registry().resolve({}).ident)
        except DB_ERRORS as exc:
            typer.echo(f"error: {short_db_error(exc)}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()

    typer.echo(f"{asyncio.run(use())} investigations queued")


def _log_check(config: ConfigOption, part: str, session: str | None) -> None:
    """Run one part of the log templates' first production run."""
    from argus.context import live_check
    from argus.gateway.errors import GatewayError
    from argus.gateway.gateway import LiveLimits
    from argus.gateway.health import HealthState
    from argus.gateway.service import probe
    from argus.gateway.templates import Params, Purpose, Template

    settings = load(config)
    failures: tuple[type[Exception], ...] = (*DB_ERRORS, GatewayError, ConfigError)

    async def use() -> list[str]:
        engine = engine_for(settings)
        live = LiveLimits(session) if session else None
        gateway, state = build_gateway(settings.siem, engine, live=live)
        try:
            health = await probe(gateway, state, settings.siem)
            if health.state != HealthState.NORMAL:
                return [f"SIEM health: {health.state}: not now", "LIVE CHECK FAILED"]

            async def run(template: Template, params: Params) -> Any:
                deadline = datetime.now(UTC) + timedelta(seconds=60)
                return await gateway.run(template, params, purpose=Purpose.ENRICH,
                                         component="enrichment", deadline=deadline)  # fmt: skip

            async with engine.connect() as conn:
                return [f"SIEM health: {health.state}",
                        *await live_check.check(conn, run, part=part)]  # fmt: skip
        except failures as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(1) from None
        finally:
            await gateway.transport.aclose()  # type: ignore[attr-defined]
            await engine.dispose()

    lines = asyncio.run(use())
    for line in lines:
        typer.echo(line)
    if lines[-1] != "LIVE CHECK PASSED":
        raise typer.Exit(1)


@worker_app.command("live-check")
def worker_live_check(
    session: Annotated[str, typer.Option(help="from `argus live start`")],
    config: ConfigOption = None,
) -> None:
    """The web follow-up template's first live run, inside a live-test session: one
    search over 15 minutes of nginx, at most 10 rows. Read-only."""
    _log_check(config, "web", session)


@worker_app.command("proxy-check")
def worker_proxy_check(config: ConfigOption = None) -> None:
    """The proxy aggregations' first production run: live tests never aggregate, so
    this is a one-off job you confirm here, under the normal budget and health gate: one
    proxy.host and one proxy.destination aggregation over one hour of squid. Read-only."""
    import secrets

    from argus.gateway.cli import CONFIRM_WORDS

    typer.echo("This runs 2 read-only aggregations over one hour of squid logs on the SIEM"
               " (production), within ARGUS's budget.")  # fmt: skip
    word = secrets.choice(CONFIRM_WORDS)
    if typer.prompt(f"Type '{word}' to confirm") != word:
        typer.echo("not confirmed: nothing was sent", err=True)
        raise typer.Exit(2)
    _log_check(config, "proxy", None)


@worker_app.command("template-check")
def worker_template_check(
    name: Annotated[str, typer.Argument(help="one of " + ", ".join(sorted(FIRST_RUN_NAMES)))],
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="print the request it would send; send nothing")
    ] = False,
    config: ConfigOption = None,
) -> None:
    """A batch-1 template's first production run: one read-only request about the
    newest stored alerts' subjects, which you confirm here, under the normal budget, health
    gate and the template's own rules. Passed within its limit, you may switch it on
    (enrichment.templates); over it, it stays off. --dry-run prints the exact request."""
    import secrets

    from argus.context import batch1
    from argus.gateway.cli import CONFIRM_WORDS
    from argus.gateway.errors import GatewayError
    from argus.gateway.service import probe, targets
    from argus.gateway.templates import Params, Purpose, Template

    if name not in FIRST_RUN_NAMES:
        typer.echo(f"error: {name} is not a batch-1 template", err=True)
        raise typer.Exit(2)
    settings = load(config)
    failures: tuple[type[Exception], ...] = (*DB_ERRORS, GatewayError, ConfigError)
    now = datetime.now(UTC)
    if dry_run:

        async def show() -> list[str]:
            engine = engine_for(settings)
            try:
                async with engine.connect() as conn:
                    task = batch1.first_task(name, await batch1.subjects(conn), now)
                if isinstance(task, batch1.Refusal):
                    return [f"{name}: {task.sentence} ({task.detail or 'no subject'})"]
                final = batch1.final_request(task, targets(settings.siem), now)
            except failures as exc:
                typer.echo(f"error: {exc}", err=True)
                raise typer.Exit(1) from None
            finally:
                await engine.dispose()
            return [
                f"dry run: nothing sent. {name}@{final.spec.version}, cost {final.spec.cost},"
                f" limit {batch1.FIRST_RUN_MS[name]} ms, window"
                f" {batch1.describe(task.template.plan(task.params).window)}",
                f"POST /{','.join(final.indices)}/_search?"
                + "&".join(f"{k}={v}" for k, v in final.url_params),
                json.dumps(final.body, indent=2, sort_keys=True),
            ]

        for line in asyncio.run(show()):
            typer.echo(line)
        return
    typer.echo(f"This runs 1 read-only {name} request on the SIEM (production), within ARGUS's"
               " budget.")  # fmt: skip
    word = secrets.choice(CONFIRM_WORDS)
    if typer.prompt(f"Type '{word}' to confirm") != word:
        typer.echo("not confirmed: nothing was sent", err=True)
        raise typer.Exit(2)

    async def use() -> list[str]:
        engine = engine_for(settings)
        gateway, state = build_gateway(settings.siem, engine)
        try:
            health = await probe(gateway, state, settings.siem)
            assets = load_asset_map(settings.assets.map_path)
            classifier = IpClassifier(assets, settings.site.own_networks)

            async def run(template: Template, params: Params) -> Any:
                deadline = datetime.now(UTC) + timedelta(seconds=60)
                # NORMAL only and the quiet hours hold until it is sent, after any wait
                check = batch1.send_check(state, health_config(settings.siem))
                return await gateway.run(template, params, purpose=Purpose.ENRICH,
                                         component=batch1.PURPOSE_COMPONENT,
                                         deadline=deadline, check=check)  # fmt: skip

            async with engine.connect() as conn:

                async def gate(task: Any) -> Any:
                    return await batch1.admit(
                        conn, state, task, enabled={name}, now=datetime.now(UTC),
                        history=settings.history.window,
                        is_campus=batch1.private_or(lambda v: classifier.classify(v).ip_class),
                        health_config=health_config(settings.siem),
                    )  # fmt: skip

                lines = await batch1.first_run(conn, run, name, datetime.now(UTC), gate)
                return [f"SIEM health: {health.state}", *lines]
        except failures as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(1) from None
        finally:
            await gateway.transport.aclose()  # type: ignore[attr-defined]
            await engine.dispose()

    lines = asyncio.run(use())
    for line in lines:
        typer.echo(line)
    if lines[-1] != "FIRST RUN PASSED":  # FAILED or INCONCLUSIVE: it stays off
        raise typer.Exit(1)
