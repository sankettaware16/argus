"""``argus signins ...`` (AR6, D-216): the sign-in pass by hand, and what is stored.

``run`` is the assessment loop's sign-in pass, once: ``--dry-run`` plans the requests and validates
them against the gateway's contract without sending anything (it reads ARGUS's own database only),
``--max-requests`` caps the requests of this run (at most ``signins.max_requests_per_pass``), and
``--backfill`` lifts that cap up to ``--max-requests`` (the gap between requests stays) and waits
for the investigation lane's budget instead of stopping at once. ``show`` prints what is stored for
an investigation, a case or an address: **account names are personal data**, so it is for the
operator's terminal and says so.

See ``docs/runbooks/signins.md``.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

import typer
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.assets import load_asset_map
from argus.assets.classify import IpClassifier
from argus.config.errors import ConfigError
from argus.config.settings import Settings
from argus.db.errors import DB_ERRORS, short_db_error
from argus.gateway.cli import ConfigOption, engine_for, load
from argus.gateway.service import build_gateway, health_config
from argus.signins import model as m
from argus.signins import run, store, view
from argus.signins.attribute import LEAD, Attribution, entry_words, sentence
from argus.signins.ua import device_words

signins_app = typer.Typer(
    no_args_is_help=True,
    help="Who was behind an internal address: SSO sign-ins kept per address and day (AR6).",
)
BACKFILL_MAX = 500
BACKFILL_ASK = timedelta(minutes=5)
BACKFILL_BUDGET = timedelta(hours=12)


def shown(value: object) -> str:
    """``value`` on one line, unprintable characters escaped (a name from the logs must not write
    to the operator's terminal)."""
    return "".join(
        char if char.isprintable() else char.encode("unicode_escape").decode("ascii")
        for char in str(value)
    )


def _classifier(settings: Settings) -> IpClassifier:
    return IpClassifier(load_asset_map(settings.assets.map_path), settings.site.own_networks)


@signins_app.command("run")
def signins_run(
    max_requests: Annotated[
        int | None,
        typer.Option("--max-requests", min=0, help="requests this run may send at most"),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option("--dry-run", help="plan and validate the requests; send and store nothing"),
    ] = False,
    backfill: Annotated[
        bool,
        typer.Option(
            "--backfill",
            help="lift the per-pass cap up to --max-requests (default 60, at most 500); the"
            " 3 s gap stays and the lane's budget is waited for",
        ),
    ] = False,
    config: ConfigOption = None,
) -> None:
    """One sign-in pass: look up the internal addresses of the investigations active in the days
    the logs are kept. Needs ``signins.enabled`` (a dry run does not)."""
    settings = load(config)
    cfg = settings.signins
    cap = cfg.max_requests_per_pass
    if backfill:
        asked = 60 if max_requests is None else max_requests
        limit = min(asked, BACKFILL_MAX)
    else:
        limit = cap if max_requests is None else min(max_requests, cap)
    ask_deadline = BACKFILL_ASK if backfill else run.ASK_DEADLINE
    budget = BACKFILL_BUDGET if backfill else run.PASS_BUDGET

    async def go() -> run.Report:
        engine = engine_for(settings)
        close = None
        try:
            gateway = state = None
            if not dry_run and cfg.enabled:
                try:
                    gateway, state = build_gateway(settings.siem, engine)
                    close = gateway.transport.aclose  # type: ignore[attr-defined]
                except ConfigError as exc:
                    typer.echo(f"warning: the SIEM is not set up here: {shown(exc)}", err=True)
            return await run.run_pass(
                engine, gateway, state, settings, _classifier(settings),
                max_requests=limit, dry_run=dry_run, health_config=health_config(settings.siem),
                ask_deadline=ask_deadline, budget=budget,
            )  # fmt: skip
        except DB_ERRORS as exc:
            typer.echo(f"error: {short_db_error(exc)}", err=True)
            raise typer.Exit(1) from None
        finally:
            if close is not None:
                await close()
            await engine.dispose()

    report = asyncio.run(go())
    for line in report.said:
        typer.echo(line)
    for line in report.warned:
        typer.echo(line, err=True)


async def _case_id(conn: AsyncConnection, ref: str) -> uuid.UUID | None:
    try:
        number = int(ref)
        found = await conn.scalar(text("SELECT id FROM cases WHERE number = :n"), {"n": number})
    except ValueError:
        try:
            found = await conn.scalar(
                text("SELECT id FROM cases WHERE id = :i"), {"i": uuid.UUID(ref)}
            )
        except ValueError:
            return None
    return found  # type: ignore[no-any-return]


def _lines(att: Attribution) -> list[str]:
    out = [f"{att.address}: {att.state}. {shown(sentence(att))}"]
    for a in att.accounts:
        devices = ", ".join(a.devices) or device_words(None)
        out.append(
            f"    {shown(a.user)}: {a.events} events ({a.successes} ok, {a.failures} failed),"
            f" {a.first_at:%Y-%m-%d %H:%M}Z to {a.last_at:%Y-%m-%d %H:%M}Z, {devices}"
        )
    return out


@signins_app.command("show")
def signins_show(
    investigation: Annotated[uuid.UUID | None, typer.Option(help="an investigation's id")] = None,
    case: Annotated[str | None, typer.Option(help="a case's number or id")] = None,
    address: Annotated[str | None, typer.Option(help="an internal IPv4 address")] = None,
    config: ConfigOption = None,
) -> None:
    """What is stored for an investigation's devices, a case's devices, or one address.
    **Account names are personal data**; this is for the operator's terminal."""
    if sum(x is not None for x in (investigation, case, address)) != 1:
        typer.echo("error: give exactly one of --investigation, --case, --address", err=True)
        raise typer.Exit(2)
    settings = load(config)

    async def go() -> list[str]:
        engine = engine_for(settings)
        now = datetime.now(UTC)
        reading = view.reading_of(settings, _classifier(settings))
        try:
            async with engine.connect() as conn:
                if address is not None:
                    return await _address(conn, address, now, settings)
                if investigation is not None:
                    users = await view.for_investigation(conn, reading, investigation, now)
                else:
                    assert case is not None
                    case_id = await _case_id(conn, case)
                    if case_id is None:
                        return [f"no such case: {shown(case)}"]
                    users = await view.for_case(conn, reading, case_id, now)
        except DB_ERRORS as exc:
            typer.echo(f"error: {short_db_error(exc)}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()
        lines = ["personal data: account names below are for the operator only", LEAD]
        if not users.attributions:
            return [*lines, "no internal device is known for it, or it has no alerts yet"]
        for att in users.attributions:
            lines += _lines(att)
        lines += [f"  entry: {shown(entry_words(e))}" for e in users.entries[:40]]
        if users.devices_total > len(users.attributions):
            lines.append(f"{users.devices_total - len(users.attributions)} more devices not shown")
        return lines

    for line in asyncio.run(go()):
        typer.echo(line)


def _lookup_words(lk: m.Lookup) -> str:
    """What a stored lookup says, without a name: its state, and for an incomplete one its reason
    (``unnamed_events``: how many events had no name; ``store_failed``: how many tries)."""
    if lk.complete:
        return f"complete, {lk.accounts} accounts"
    detail = ""
    if lk.reason == m.UNNAMED:
        detail = f", {lk.unnamed} sign-in events without an account name"
    elif lk.reason == m.STORE_FAILED:
        detail = f", {lk.store_failures} of {m.MAX_STORE_FAILURES} tries"
    return f"incomplete ({lk.reason}{detail})"


async def _address(
    conn: AsyncConnection, address: str, now: datetime, settings: Settings
) -> list[str]:
    addresses = store.ipv4([address])
    if not addresses:
        raise typer.BadParameter("not an IPv4 address", param_hint="--address")
    rules = m.rules_of(settings.signins)
    today = m.utc_day(now)
    found = await store.records(conn, addresses, today - timedelta(days=rules.keep_days), today)
    lines = ["personal data: account names below are for the operator only", LEAD]
    if not found:
        return [*lines, f"{addresses[0]}: nothing stored (never looked up)"]
    for (_, day), record in sorted(found.items(), key=lambda kv: kv[0][1]):
        lk = record.lookup
        state = "no lookup row" if lk is None else _lookup_words(lk)
        lines.append(f"{addresses[0]} {day}: {state}")
        for s in record.sightings:
            lines.append(
                f"    {shown(s.user)}: {s.events} events ({s.successes} ok, {s.failures} failed),"
                f" hours {','.join(str(h) for h in s.hours)}"
            )
    return lines
