"""``argus notices ...`` (Q-H4): the pass, what is on, and the user's test message.

Everything is computed from ARGUS's own database; nothing here asks the SIEM. Nothing is e-mailed
unless ``notices.enabled`` is true, a recipient is named and the relay is set: without them
``run`` stores what it computes and prints what it would send ("not switched on, by your
choice"). See ``docs/runbooks/notices.md``.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Annotated

import typer

from argus.assets import load_asset_map
from argus.assets.classify import IpClassifier
from argus.config.errors import ConfigError
from argus.config.settings import Settings
from argus.db.errors import DB_ERRORS, short_db_error
from argus.gateway.cli import ConfigOption, engine_for, load
from argus.gateway.service import health_config
from argus.notices import mail, run, triggers

notices_app = typer.Typer(
    no_args_is_help=True,
    help="Minimal notices: a link, a severity and a count by e-mail (Q-H4). Off until you switch"
    " them on.",
)


def _classifier(settings: Settings) -> IpClassifier:
    return IpClassifier(load_asset_map(settings.assets.map_path), settings.site.own_networks)


def shown(value: object) -> str:
    """``value`` on one line, unprintable characters escaped (as ``argus.cases.cli``)."""
    return "".join(
        char if char.isprintable() else char.encode("unicode_escape").decode("ascii")
        for char in str(value)
    )


@notices_app.command("run")
def notices_run(
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run", help="compute and show what would go out: store and send nothing"
        ),
    ] = False,
    config: ConfigOption = None,
) -> None:
    """One pass: compute what is worth a notice from ARGUS's own database, deduplicate it
    against what was sent, and send what is due if notices are switched on (at most 10 e-mails
    an hour). Every 10 minutes: argus-notices.timer."""
    settings = load(config)
    cfg = run.config_of(settings)

    async def go() -> run.Report:
        engine = engine_for(settings)
        try:
            now = datetime.now(UTC)
            found = await triggers.compute(
                engine,
                now,
                classifier=_classifier(settings),
                watch_mode=settings.cases.watch,
                health=health_config(settings.siem),
            )
            return await run.run(engine, cfg, found, now=now, apply=not dry_run)
        except DB_ERRORS as exc:
            typer.echo(f"error: {shown(short_db_error(exc))}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()

    try:
        report = asyncio.run(go())
    except ConfigError as exc:
        typer.echo(f"error: {shown(exc)}", err=True)
        raise typer.Exit(1) from None
    for line in _report_lines(report, cfg):
        typer.echo(shown(line))
    if report.failed or report.problems:
        raise typer.Exit(1)


def _report_lines(report: run.Report, cfg: run.Config) -> list[str]:
    if report.busy:
        return ["another pass of the notices is in progress: nothing was done"]
    head = {
        "sent": "notices: ON",
        "not_on": f"notices: {cfg.why_not}",
        "dry_run": "dry run: nothing stored or sent",
    }[report.mode]
    lines = [
        head,
        f"found {report.conditions} thing(s) worth a notice; {report.inserted} new,"
        f" {report.updated} still there, {report.resolved} over; {report.due} notice(s) due",
    ]
    if report.unreadable:
        lines.append("could not read: " + ", ".join(report.unreadable) + " (not marked resolved)")
    lines += [f"  {line}" for line in report.lines]
    if report.mode == "sent":
        lines.append(
            f"sent {report.sent}, folded {report.folded}, failed {report.failed},"
            f" waiting for the hour's room {report.deferred}"
        )
    elif report.mode == "not_on" and report.lines:
        lines.append(f"{cfg.why_not}: none of the above was sent")
    lines += [f"problem: {problem}" for problem in report.problems]
    return lines


@notices_app.command("status")
def notices_status(config: ConfigOption = None) -> None:
    """Whether notices are on, who gets them, when a pass last ran and what it holds."""
    settings = load(config)
    cfg = run.config_of(settings)

    async def go() -> list[str]:
        engine = engine_for(settings)
        try:
            async with engine.connect() as conn:
                return await run.status(conn, cfg, datetime.now(UTC))
        except DB_ERRORS as exc:
            typer.echo(f"error: {shown(short_db_error(exc))}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()

    for line in asyncio.run(go()):
        typer.echo(shown(line))


@notices_app.command("test")
def notices_test(
    to: Annotated[str, typer.Option("--to", help="the address to send the test message to")],
    config: ConfigOption = None,
) -> None:
    """Send one test message (one line) through the same relay. Refused while notices are off."""
    settings = load(config)
    cfg = run.config_of(settings)

    async def go() -> None:
        engine = engine_for(settings)
        try:
            await run.send_test(engine, cfg, to)
        except DB_ERRORS as exc:
            typer.echo(f"error: {shown(short_db_error(exc))}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()

    try:
        asyncio.run(go())
    except (run.Refused, mail.MailError) as exc:
        typer.echo(f"error: {shown(exc)}", err=True)
        raise typer.Exit(1) from None
    typer.echo("the test message was handed to the relay: check the inbox of that address")
