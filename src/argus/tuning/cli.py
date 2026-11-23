"""``argus tune ...``: the weekly rule-tuning reports."""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from datetime import UTC, datetime
from typing import Annotated, Any

import typer

from argus.db.errors import DB_ERRORS, short_db_error
from argus.gateway.cli import ConfigOption, engine_for, load
from argus.llm.gateway import NoCapacity
from argus.tuning import advise, report, store

tune_app = typer.Typer(no_args_is_help=True, help="Rule tuning: weekly reports.")


def _run[T](work: Coroutine[Any, Any, T]) -> T:
    try:
        return asyncio.run(work)
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None


async def run(settings: Any, model: bool, rule: str | None = None) -> list[str]:
    """Build every rule's report for the week before now and store it with the model's
    suggestions (or none, without ``model``)."""
    from argus.assess.cli import _privacy
    from argus.llm.providers import load_config
    from argus.llm.service import build_gateway
    from argus.llm.wire import HttpxLlmTransport

    db = engine_for(settings)
    llm = load_config() if model else None
    transport = HttpxLlmTransport(llm) if llm is not None else None
    lines = []
    try:
        async with db.connect() as conn:
            reports = await report.build(conn, datetime.now(UTC))
        reports = [r for r in reports if rule is None or r.rule == rule]
        privacy = _privacy(settings) if model else None
        gateway = build_gateway(db, llm, transport) if llm is not None else None
        for rep in reports:
            got = advise.Advice()
            if gateway is not None and privacy is not None:
                try:
                    got = await advise.advise(rep, privacy, gateway.complete)
                except NoCapacity as wait:
                    got.dropped.append(f"no model capacity until {wait.until:%H:%M} UTC")
            async with db.begin() as conn:
                stored = await store.save(conn, rep, got)
            lines.append(
                f"{rep.rule[:60]}: {len(got.suggestions)} suggestions, {len(got.dropped)} dropped"
                + ("" if stored else " (already stored)")
            )
    finally:
        if transport is not None:
            await transport.aclose()
        await db.dispose()
    return lines


@tune_app.command("run")
def tune_run(
    model: Annotated[bool, typer.Option(help="Ask the model for suggestions.")] = True,
    rule: Annotated[str | None, typer.Option(help="Only this rule (its name).")] = None,
    config: ConfigOption = None,
) -> None:
    """This week's report for every rule, with suggestions kept only with evidence."""
    for line in _run(run(load(config), model, rule)):
        typer.echo(line)


@tune_app.command("show")
def tune_show(
    rule: Annotated[str | None, typer.Option(help="Only this rule (its name).")] = None,
    config: ConfigOption = None,
) -> None:
    """Each rule's newest report: the numbers and the suggestions."""
    settings = load(config)

    async def use() -> list[dict[str, Any]]:
        db = engine_for(settings)
        try:
            async with db.connect() as conn:
                return await store.latest(conn)
        finally:
            await db.dispose()

    for r in _run(use()):
        if rule is not None and r["rule"] != rule:
            continue
        rep = r["report"]
        typer.echo(f"{r['rule']} (week to {r['week_end']:%Y-%m-%d %H:%M} UTC, {r['model']})")
        typer.echo(f"  alerts {rep['alerts']}, investigations {rep['investigations']},"
                   f" runs at the limit {rep['runs_at_limit']} of {rep['runs']}")  # fmt: skip
        for s in r["suggestions"]:
            target = f" {s['path']} = {s['value']}" if s["value"] else ""
            typer.echo(f"  - {s['kind']}{target}: {s['change']}")
            typer.echo(f"    why: {s['why']}; risk: {s['risk']}")
        for d in r["dropped"]:
            typer.echo(f"  (not kept: {d})")
