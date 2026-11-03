"""``argus freshness ...``: the watermarks and the shadow of verified zeros (Q-F1).

Only ``read`` (without ``--dry-run``) sends anything to the SIEM: one size-1 search per source
through the freshness lane. The readings themselves run in the collector's process while
``freshness.mode`` is ``shadow`` or ``on``.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Coroutine
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import typer

from argus import site
from argus.config.errors import ConfigError
from argus.db.errors import DB_ERRORS, short_db_error
from argus.freshness import report, store
from argus.freshness.reader import Reader, policy_of
from argus.freshness.template import Watermark, WatermarkParams
from argus.gateway.cli import ConfigOption, engine_for, load
from argus.gateway.service import build_gateway

freshness_app = typer.Typer(
    no_args_is_help=True,
    help="Watermarks and the shadow of verified zeros (Q-F1): nothing here is shown to people.",
)


def _run[T](work: Coroutine[Any, Any, T]) -> T:
    try:
        return asyncio.run(work)
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None
    except ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from None


def _iso(moment: datetime | None) -> str:
    return "-" if moment is None else f"{moment.astimezone(UTC):%Y-%m-%d %H:%M:%S} UTC"


@freshness_app.command("status")
def freshness_status(config: ConfigOption = None) -> None:
    """The mode, the margins and each source's watermark and newest reading (no SIEM)."""
    settings = load(config)

    async def go() -> list[str]:
        policy = policy_of(settings)
        engine = engine_for(settings)
        try:
            async with engine.connect() as conn:
                marks = await store.watermarks(conn)
                newest = await store.latest(conn)
        finally:
            await engine.dispose()
        lines = [f"mode: {policy.mode}; bridge: {policy.bridge}; gap {policy.gap}"]
        for source in site.active().watched_sources:
            margin = policy.margins.get(source)
            mark = marks.get(source)
            last = newest.get(source)
            lines.append(
                f"  {source}: margin {margin or 'none (no verified zeros)'};"
                f" watermark {_iso(mark[0] if mark else None)};"
                f" last reading {_iso(last.at if last else None)}"
                f" ({last.outcome if last else 'never'})"
            )
        return lines

    for line in _run(go()):
        typer.echo(line)


@freshness_app.command("read")
def freshness_read(
    session: Annotated[
        str | None, typer.Option(help="the live-test session (from `argus live start`)")
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="print the requests; send nothing")
    ] = False,
    config: ConfigOption = None,
) -> None:
    """The first live reads (production step 18): a health probe, then one reading of every
    log source, inside a person's live-test session (its stricter limits apply on top of the
    freshness lane's switches, health, quiet hours and budget), stored like the shadow's.
    ``--dry-run`` prints the exact requests the validator accepted and sends nothing. The
    routine readings run in the collector's process once ``freshness.mode`` is shadow."""
    settings = load(config)
    now = datetime.now(UTC)
    if dry_run:
        from argus.gateway.gateway import Gateway, Targets
        from argus.gateway.validator import encode_body

        sources = site.active().watched_sources
        targets = Targets(log_sources=frozenset(sources))
        preview = Gateway(None, None, targets=targets)  # type: ignore[arg-type]  # sends nothing
        for source in sources:
            final = preview.preview(
                Watermark(),
                WatermarkParams(source=source, now=now),
                deadline=now + timedelta(seconds=20),
            )
            body = encode_body(final.body).decode()
            typer.echo(f"POST /{','.join(final.indices)}/_search {body}")
        return
    if session is None:
        typer.echo("error: a live read needs --session (from `argus live start`)", err=True)
        raise typer.Exit(2)

    async def go() -> list[str]:
        from argus.gateway.gateway import LiveLimits
        from argus.gateway.service import probe

        engine = engine_for(settings)
        gateway, state = build_gateway(settings.siem, engine, live=LiveLimits(session))
        try:
            health = await probe(gateway, state, settings.siem)
            reader = Reader(gateway, engine, site.active().watched_sources)
            got = await reader.step()
        finally:
            await gateway.transport.aclose()  # type: ignore[attr-defined]
            await engine.dispose()
        lines = [f"SIEM health: {health.state}"]
        for s in got:
            line = f"{s.reading.source}: {s.reading.outcome}"
            if s.reason:
                line += f" ({s.reason})"
            if s.reading.lag is not None:
                line += f"; newest ingested {_iso(s.reading.ingested)}, lag {s.reading.lag}"
            if s.took_ms is not None:
                line += f"; took {s.took_ms} ms"
            lines.append(line)
        if not got:
            lines.append("nothing read (STOP or the quiet hours)")
        return lines

    for line in _run(go()):
        typer.echo(line)


@freshness_app.command("report")
def freshness_report(
    days: Annotated[int, typer.Option(min=1, max=60, help="how many days back")] = 14,
    config: ConfigOption = None,
) -> None:
    """The shadow's numbers as JSON: readings and lag per source, the share of 72-hour windows
    proved with and without the bridge, the verdicts, the would-be proposals."""
    settings = load(config)

    async def go() -> dict[str, Any]:
        policy = policy_of(settings)
        engine = engine_for(settings)
        now = datetime.now(UTC)
        try:
            async with engine.connect() as conn:
                return await report.build(conn, policy, now - timedelta(days=days), now)
        finally:
            await engine.dispose()

    typer.echo(json.dumps(_run(go()), indent=1, sort_keys=True, default=str))


@freshness_app.command("export")
def freshness_export(
    out: Annotated[Path, typer.Option(help="JSON lines file to write")],
    days: Annotated[int, typer.Option(min=1, max=60)] = 14,
    config: ConfigOption = None,
) -> None:
    """The readings as JSON lines, for ``scripts/derive_margin.py --readings``."""
    settings = load(config)

    async def go() -> int:
        engine = engine_for(settings)
        now = datetime.now(UTC)
        try:
            async with engine.connect() as conn:
                rows = await store.export(conn, now - timedelta(days=days), now)
        finally:
            await engine.dispose()
        with out.open("w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
        out.chmod(0o600)
        return len(rows)

    typer.echo(f"{_run(go())} readings written to {out}")


@freshness_app.command("assess")
def freshness_assess(
    bridged: Annotated[
        bool, typer.Option("--bridged", help="use the zeros the candidate bridge would verify")
    ] = False,
    config: ConfigOption = None,
) -> None:
    """The deterministic engine on every dossier with a would-be verified zero, with and
    without them: the would-be proposals are stored for the audit (never used or shown);
    prints the counts, and the gold set's true positives that would be proposed benign
    (the gate: 0)."""
    settings = load(config)

    async def go() -> dict[str, Any]:
        engine = engine_for(settings)
        try:
            async with engine.begin() as conn:
                return await report.assess(conn, datetime.now(UTC), bridged=bridged)
        finally:
            await engine.dispose()

    result = _run(go())
    typer.echo(json.dumps(result, indent=1, sort_keys=True))
    if result["gold_tp_benign"]:
        raise typer.Exit(1)


@freshness_app.command("audit-sheet")
def freshness_audit_sheet(
    out: Annotated[Path, typer.Option(help="CSV file to write (mode 0600)")],
    bridged: Annotated[bool, typer.Option("--bridged", help="the bridge's zeros")] = False,
    config: ConfigOption = None,
) -> None:
    """The user's audit sheet (production step 25): every would-be benign proposal stored by
    ``argus freshness assess``, with ``correct`` and ``true_positive`` to answer yes or no.
    Open each investigation in the Inbox to judge it."""
    import csv
    import os

    settings = load(config)

    async def go() -> list[dict[str, str]]:
        engine = engine_for(settings)
        try:
            async with engine.connect() as conn:
                return report.sheet(await store.proposals(conn), bridged=bridged)
        finally:
            await engine.dispose()

    rows = _run(go())
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=report.SHEET)
        writer.writeheader()
        writer.writerows(rows)
    typer.echo(f"{len(rows)} would-be benign proposals written to {out}")


def _stored_sheet(settings: Any, bridged: bool) -> list[dict[str, str]]:
    """The audit sheet as the store would write it now (audit-score checks the CSV against it)."""

    async def go() -> list[dict[str, str]]:
        engine = engine_for(settings)
        try:
            async with engine.connect() as conn:
                return report.sheet(await store.proposals(conn), bridged=bridged)
        finally:
            await engine.dispose()

    return _run(go())


@freshness_app.command("audit-score")
def freshness_audit_score(
    sheet: Annotated[Path, typer.Argument(help="the answered audit sheet (CSV)")],
    bridged: Annotated[bool, typer.Option("--bridged", help="the bridge's zeros")] = False,
    config: ConfigOption = None,
) -> None:
    """Score an answered audit sheet against the switch-on's bar: every item answered, 0 true
    positives, a Wilson lower bound of at least 90 % at n >= 37 (D-092). The sheet must hold
    exactly the stored would-be proposals (review F4: a row cannot be left out). Exit 1 below
    the bar, 2 when the sheet does not match the store."""
    import csv

    with sheet.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    from collections import Counter

    key = ("investigation_id", "version", "pack")
    expected = Counter(tuple(r[k] for k in key) for r in _stored_sheet(load(config), bridged))
    given = Counter(tuple(r.get(k, "") for k in key) for r in rows)
    if given != expected:  # a multiset: a row left out is missing even if another shares its key
        missing, unknown = expected - given, given - expected
        typer.echo(
            f"the sheet does not match the stored proposals ({sum(missing.values())} missing,"
            f" {sum(unknown.values())} unknown): write it again with audit-sheet"
            f"{' --bridged' if bridged else ''} and answer every row",
            err=True,
        )
        raise typer.Exit(2)
    result = report.score(rows)
    typer.echo(json.dumps(result, indent=1, sort_keys=True))
    if not result["passes"]:
        raise typer.Exit(1)
