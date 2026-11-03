"""``argus report ...``: report@2 of an investigation. Read-only: nothing is written to the
database, nothing is asked of the SIEM or a model."""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from collections.abc import Coroutine
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer
from sqlalchemy import text

from argus.db.errors import DB_ERRORS, short_db_error
from argus.gateway.cli import ConfigOption, engine_for, load
from argus.report import render, store
from argus.report.model import Report

report_app = typer.Typer(
    no_args_is_help=True, help="Reports (report@2): what ARGUS found, and where from."
)

# A fixed sample of assessed investigations at their current version, half of them (when
# there are enough) assessed by the AI investigator: its reports hold the most.
_SAMPLE = """
SELECT i.id, bool_or(a.assessor LIKE 'agent%') AS agent
FROM investigations i JOIN assessments a ON a.investigation_id = i.id AND a.version = i.version
WHERE a.status IN ('proposed', 'no_decision')
GROUP BY i.id
ORDER BY md5(i.id::text || :seed), i.id
"""


def _run[T](work: Coroutine[Any, Any, T]) -> T:
    try:
        return asyncio.run(work)
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None


def _shown(report: Report, as_json: bool, hide_logs: bool) -> str:
    """The text form shows control and bidi characters as U+XXXX; the JSON form escapes
    every character outside ASCII, so neither can reorder a terminal's text."""
    if hide_logs:
        report = render.hide_logs(report)
    if as_json:
        return json.dumps(report.model_dump(mode="json"), indent=1, ensure_ascii=True) + "\n"
    return render.text(report)


@report_app.command("show")
def report_show(
    investigation: Annotated[str, typer.Argument(help="The investigation's id.")],
    assessment: Annotated[
        int | None, typer.Option(help="One assessment's report (default: each assessor's).")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="The report@2 JSON.")] = False,
    hide_logs: Annotated[
        bool, typer.Option(help="As a person without log access in ELK sees it.")
    ] = False,
    config: ConfigOption = None,
) -> None:
    """The report of each assessor's newest assessment of an investigation (or of one
    assessment, or of the newest dossier when nothing assessed it)."""
    try:
        inv = uuid.UUID(investigation)
    except ValueError:
        typer.echo("error: not an investigation id", err=True)
        raise typer.Exit(2) from None
    settings = load(config)

    async def use() -> list[Report]:
        db = engine_for(settings)
        try:
            async with db.connect() as conn:
                if assessment is not None:
                    one = await store.report(conn, inv, assessment)
                    return [] if one is None else [one]
                return await store.current(conn, inv)
        finally:
            await db.dispose()

    reports = _run(use())
    if not reports:
        typer.echo("error: no such investigation, dossier or assessment", err=True)
        raise typer.Exit(1)
    for n, report in enumerate(reports):
        if n:
            typer.echo("")
        typer.echo(_shown(report, as_json, hide_logs), nl=False)


@report_app.command("sample")
def report_sample(
    out: Annotated[Path, typer.Option(help="The directory to write the reports into.")],
    count: Annotated[int, typer.Option(min=1, max=200, help="How many investigations.")] = 10,
    seed: Annotated[
        str | None, typer.Option(help="Picks the sample (default: today's UTC date).")
    ] = None,
    hide_logs: Annotated[
        bool, typer.Option(help="As a person without log access in ELK sees them.")
    ] = False,
    config: ConfigOption = None,
) -> None:
    """Write the reports of a fixed random sample of assessed investigations, one text file
    each (mode 0600: they hold internal addresses and names), for a person to read."""
    settings = load(config)
    picked = seed or datetime.now(UTC).date().isoformat()

    async def use() -> list[tuple[uuid.UUID, list[Report]]]:
        db = engine_for(settings)
        try:
            async with db.connect() as conn:
                rows = (await conn.execute(text(_SAMPLE), {"seed": picked})).all()
                agents = [r.id for r in rows if r.agent][: (count + 1) // 2]
                chosen = set(agents)
                rest = [r.id for r in rows if r.id not in chosen][: count - len(agents)]
                found = []
                for inv in [*agents, *rest]:
                    found.append((inv, await store.current(conn, inv)))
                return found
        finally:
            await db.dispose()

    found = _run(use())
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    for n, (inv, reports) in enumerate(found, start=1):
        path = out / f"{n:02d}-{inv}.txt"
        body = "\n".join(_shown(r, False, hide_logs) for r in reports)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(body)
    typer.echo(f"{len(found)} investigations' reports written to {out} (sample {picked!r})")
