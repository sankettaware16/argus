"""``argus collect ...``: run the collector, or one of its jobs by hand (R5, D-050)."""

from __future__ import annotations

import asyncio
import logging
import signal
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import typer
from sqlalchemy import text

from argus.collector.collector import Collector
from argus.collector.runner import Runner
from argus.config.errors import ConfigError
from argus.config.settings import Settings
from argus.db.errors import DB_ERRORS, short_db_error
from argus.gateway.cli import ConfigOption, engine_for, load
from argus.gateway.errors import GatewayError
from argus.gateway.service import build_gateway, probe

log = logging.getLogger("argus.collector")

collect_app = typer.Typer(
    no_args_is_help=True, help="The collector: the SIEM's alerts into the store (R5)."
)


async def _with_collector[T](
    settings: Settings, use: Callable[[Collector, Any], Coroutine[Any, Any, T]]
) -> T:
    engine = engine_for(settings)
    try:
        gateway, state = build_gateway(settings.siem, engine)
    except ConfigError as exc:
        await engine.dispose()
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from None
    last_probe: list[datetime] = []

    async def fresh_probe() -> Any:
        last_probe[:] = [datetime.now(UTC)]
        lag = None
        if settings.freshness.mode == "on":  # the trip wire's input (Q-F1, DQ19)
            from argus.freshness.reader import current_lags

            try:
                lag = await current_lags(engine, last_probe[0])
            except DB_ERRORS as exc:
                log.warning("freshness lags not read: %s", short_db_error(exc))
        return await probe(gateway, state, settings.siem, ingest_lag=lag)

    async def keep_fresh() -> None:
        """Long manual runs probe at most once a minute, so the health state never goes stale
        (D-049) in the middle of a backfill or reconciliation."""
        if not last_probe or datetime.now(UTC) - last_probe[0] >= timedelta(minutes=1):
            await fresh_probe()

    collector = Collector(gateway, engine, window=settings.history.window, before_chunk=keep_fresh)

    try:
        return await use(collector, fresh_probe)
    except GatewayError as exc:
        typer.echo(f"error: {exc.reason}: {exc}", err=True)
        raise typer.Exit(1) from None
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None
    finally:
        await gateway.transport.aclose()  # type: ignore[attr-defined]
        await engine.dispose()


def _go[T](config: Path | None, use: Callable[[Collector, Any], Coroutine[Any, Any, T]]) -> T:
    return asyncio.run(_with_collector(load(config), use))


@collect_app.command("run")
def collect_run(config: ConfigOption = None) -> None:
    """Run the collector until stopped (Ctrl-C or SIGTERM): probe and poll every minute,
    workflow states every 15 minutes, reconciliation hourly, backfill until the history window
    is covered."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    async def use(collector: Collector, fresh_probe: Any) -> None:
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        from argus.freshness.reader import jobs as freshness_jobs
        from argus.reference.jobs import jobs

        settings = load(config)
        extra = jobs(collector.engine, collector.gateway, ti_sync=settings.reference.ti_sync)
        extra += freshness_jobs(settings, collector.engine, collector.gateway)
        await Runner(collector, fresh_probe, extra=extra).run(stop)

    _go(config, use)


@collect_app.command("once")
def collect_once(config: ConfigOption = None) -> None:
    """One health probe and one poll."""

    async def use(collector: Collector, fresh_probe: Any) -> str:
        await fresh_probe()
        result = await collector.poll()
        return f"poll: {result.new} new alerts, cursor {result.cursor:%Y-%m-%d %H:%M:%S} UTC"

    typer.echo(_go(config, use))


@collect_app.command("backfill")
def collect_backfill(config: ConfigOption = None) -> None:
    """Backfill the history window, newest hours first (resumes where it stopped)."""

    async def use(collector: Collector, fresh_probe: Any) -> int:
        await fresh_probe()
        total = 0
        while (step := await collector.backfill_step()) is not None:
            total += step.recovered
            typer.echo(f"  {step.hours} hours checked, {step.recovered} alerts stored")
        return total

    typer.echo(f"backfill complete: {_go(config, use)} alerts stored")


@collect_app.command("reconcile")
def collect_reconcile(
    hours: Annotated[int, typer.Option(min=1, max=24 * 30, help="how far back")] = 24,
    config: ConfigOption = None,
) -> None:
    """Compare the SIEM's alerts with the store over the last whole hours and repair the store."""

    async def use(collector: Collector, fresh_probe: Any) -> str:
        await fresh_probe()
        now = datetime.now(UTC)
        result = await collector.reconcile(now - timedelta(hours=hours), now)
        return (
            f"{result.hours} hours: {len(result.mismatched)} differed,"
            f" {result.recovered} recovered, {result.missing_in_es} gone from the SIEM"
        )

    typer.echo(_go(config, use))


@collect_app.command("status")
def collect_status(config: ConfigOption = None) -> None:
    """What the store holds (no SIEM request)."""
    settings = load(config)

    async def use() -> list[str]:
        engine = engine_for(settings)
        try:
            async with engine.connect() as conn:
                count = (
                    await conn.execute(
                        text(
                            "SELECT count(*), count(*) FILTER (WHERE status = 'quarantined'),"
                            " count(*) FILTER (WHERE source_missing_at IS NOT NULL),"
                            " min(detected_at), max(detected_at) FROM alert_records"
                        )
                    )
                ).one()
                cursors = (await conn.execute(text("SELECT name, at FROM collector_cursors"))).all()
                gaps = (
                    await conn.execute(
                        text(
                            "SELECT kind, start_at, detail FROM coverage_gaps WHERE end_at IS NULL"
                        )
                    )
                ).all()
                run = (
                    await conn.execute(
                        text(
                            "SELECT finished_at, hours, hours_mismatched, recovered, outcome"
                            " FROM reconciliation_runs ORDER BY id DESC LIMIT 1"
                        )
                    )
                ).first()
        except DB_ERRORS as exc:
            typer.echo(f"error: {short_db_error(exc)}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()
        total, quarantined, missing, oldest, newest = count
        lines = [
            f"alerts stored: {total} ({quarantined} quarantined, {missing} gone from the SIEM)"
        ]
        if oldest is not None:
            lines.append(f"  written {oldest:%Y-%m-%d %H:%M} to {newest:%Y-%m-%d %H:%M} UTC")
        lines += [f"cursor {name}: {at:%Y-%m-%d %H:%M:%S} UTC" for name, at in sorted(cursors)]
        lines += [f"open gap: {kind} since {start:%Y-%m-%d %H:%M} UTC ({detail})"
                  for kind, start, detail in gaps]  # fmt: skip
        if run is not None:
            finished, hours, differed, recovered, outcome = run
            lines.append(
                f"last reconciliation {finished:%Y-%m-%d %H:%M} UTC: {hours} hours,"
                f" {differed} differed, {recovered} recovered, {outcome}"
            )
        return lines

    for line in asyncio.run(use()):
        typer.echo(line)
