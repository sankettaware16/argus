"""``argus soak ...``: the soak's samples and exit reports; local store only."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import Annotated

import typer

from argus import soak
from argus.db.errors import DB_ERRORS, short_db_error
from argus.gateway.cli import ConfigOption, engine_for, load

soak_app = typer.Typer(
    no_args_is_help=True, help="The soak: samples, exit reports and the exit gate."
)


@soak_app.command("sample")
def soak_sample(config: ConfigOption = None) -> None:
    """Take one sample now (the collector takes one every hour)."""
    settings = load(config)

    async def use() -> dict[str, object]:
        engine = engine_for(settings)
        try:
            async with engine.begin() as conn:
                return await soak.sample(conn, datetime.now(UTC))
        except DB_ERRORS as exc:
            typer.echo(f"error: {short_db_error(exc)}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()

    for key, value in asyncio.run(use()).items():
        typer.echo(f"{key}: {value}")


@soak_app.command("report")
def soak_report(config: ConfigOption = None) -> None:
    """The exit criteria over the last 72 h of samples: PASS, FAIL or PENDING."""
    settings = load(config)

    async def use() -> list[dict[str, str]]:
        engine = engine_for(settings)
        try:
            async with engine.connect() as conn:
                return await soak.report(conn)
        except DB_ERRORS as exc:
            typer.echo(f"error: {short_db_error(exc)}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()

    for item in asyncio.run(use()):
        typer.echo(f"{item['result']:<8} {item['criterion']}: {item['why']}")


SOAK2_START = "2026-10-16T15:25:00+00:00"


@soak_app.command("phase2")
def soak_phase2(
    start: Annotated[str, typer.Option(help="Window start (ISO time).")] = SOAK2_START,
    end: Annotated[str | None, typer.Option(help="Window end (ISO time; default now).")] = None,
    config: ConfigOption = None,
) -> None:
    """The second soak report: each exit criterion judged from the store; also written to
    data/gate/p9/soak-report.txt."""
    from pathlib import Path

    from argus import soak2
    from argus.llm.providers import load_config

    settings = load(config)
    begin = datetime.fromisoformat(start)
    finish = datetime.fromisoformat(end) if end else datetime.now(UTC)

    async def use() -> list[str]:
        engine = engine_for(settings)
        try:
            async with engine.connect() as conn:
                return soak2.render(await soak2.report(conn, load_config(), begin, finish))
        finally:
            await engine.dispose()

    lines = [
        f"Phase 2 soak {begin:%Y-%m-%d %H:%M} to {finish:%Y-%m-%d %H:%M} UTC",
        *asyncio.run(use()),
    ]
    out = Path("data/gate/p9")
    out.mkdir(parents=True, exist_ok=True)
    (out / "soak-report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    for line in lines:
        typer.echo(line)


def _moment(value: str, option: str) -> datetime:
    try:
        at = datetime.fromisoformat(value)
    except ValueError:
        raise typer.BadParameter(f"{value!r} is not an ISO time", param_hint=option) from None
    return at if at.tzinfo else at.replace(tzinfo=UTC)


@soak_app.command("phase3")
def soak_phase3(
    since: Annotated[
        str | None,
        typer.Option(
            help="Window start (ISO time, UTC). Default: the Phase 3 close, 2026-10-30 12:45."
        ),
    ] = None,
    days: Annotated[float | None, typer.Option(help="The last N days instead of --since.")] = None,
    as_json: Annotated[bool, typer.Option("--json", help="The full result as JSON.")] = False,
    write: Annotated[
        bool, typer.Option("--write", help="Also save it as <soak.dir>/<UTC timestamp>.json.")
    ] = False,
    config: ConfigOption = None,
) -> None:
    """The exit gate, each of its 11 lines judged from the store: PASS, FAIL, PENDING (not enough
    data yet) or OPEN (only a person can say), with the numbers and their n. Read-only; sends
    nothing to the SIEM. Exit 1 if a line FAILs."""
    from argus.soakgate import render, run
    from argus.soakgate.model import Report

    settings = load(config)
    now = datetime.now(UTC)
    try:
        window = run.window_of(
            now,
            since=None if since is None else _moment(since, "--since"),
            days=days,
        )
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from None

    async def use() -> Report:
        engine = engine_for(settings)
        try:
            return await run.build(engine, settings, window, now=now)
        except DB_ERRORS as exc:
            typer.echo(f"error: {short_db_error(exc)}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()

    report = asyncio.run(use())
    if write:
        saved = run.write_report(report, settings.soak.dir)
        typer.echo(f"saved {saved}", err=True)
    if as_json:
        typer.echo(json.dumps(report.as_json(), indent=2, sort_keys=True))
    else:
        for line in render.render(report):
            typer.echo(line)
    if report.failed:
        raise typer.Exit(1)
