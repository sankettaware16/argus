"""``argus writeback ...`` (R17 v2, Q-D5, D-061): plan and diff locally; a real run sends alert
status changes to Kibana. It is refused until the user switches write-back on, the alert
writer's key is installed, WA is switched on at the host, and a person at a terminal types the
confirmation. Run it in the writer's account (``sudo argus-owner --as writer writeback run``):
only that login holds the alert writer's key and may move the outbox rows.

* ``plan [--older]``: new decisions and approved closures become planned changes (local). With
  ``--older``, a person's reviews made without an alert-write check are planned too, as rows only
  an operator's run can send.
* ``diff``: what a run would change, per status (local).
* ``run [--operator NAME] [--limit N]``: send. ``--operator`` asks for that person's own ELK
  password (``getpass``), checks it live through the identity lane and, if it shows the
  alert-status privileges, lets the run send the rows that need an operator.

Exit codes: 0 done; 1 the run stopped (a pause, a health state, a refusal by the lane); 2 refused
before anything was sent.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import typer
from sqlalchemy import text

from argus import writeback
from argus.config.errors import ConfigError
from argus.config.settings import Settings
from argus.db.errors import DB_ERRORS, short_db_error
from argus.gateway.cli import ConfigOption, _human_at_a_terminal, engine_for, load
from argus.identity.cli import read_password
from argus.identity.lane import IdentityError
from argus.identity.names import Credential
from argus.identity.transport import authorization
from argus.observability.redaction import register_secret
from argus.writeback_sender import AlertSender, Operator, operator_of, problems_of
from argus.writer.cli import _engine as writer_engine

writeback_app = typer.Typer(no_args_is_help=True, help="Write reviews back to Kibana (R17 v2).")
CONFIRM = "WA"
CHECK_DEADLINE = timedelta(seconds=20)


def _go(config: ConfigOption, use: Any) -> Any:
    settings = load(config)

    async def wrapped() -> Any:
        engine = engine_for(settings)
        try:
            async with engine.begin() as conn:
                return await use(conn)
        except DB_ERRORS as exc:
            typer.echo(f"error: {short_db_error(exc)}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()

    return asyncio.run(wrapped())


@writeback_app.command("plan")
def writeback_plan(
    older: Annotated[
        bool,
        typer.Option("--older", help="also plan earlier reviews (sent only through an operator)"),
    ] = False,
    config: ConfigOption = None,
) -> None:
    """Turn new reviews and approved closures into planned status changes (local; nothing is
    sent)."""

    async def use(conn: Any) -> int:
        return await writeback.plan(conn, older=older)

    typer.echo(f"{_go(config, use)} items planned")


@writeback_app.command("diff")
def writeback_diff(config: ConfigOption = None) -> None:
    """What a run would change in Kibana (local; nothing is sent)."""
    typer.echo(json.dumps(_go(config, writeback.diff), indent=2))


@writeback_app.command("run")
def writeback_run(
    operator: Annotated[
        str | None,
        typer.Option("--operator", help="your own ELK username: checked live, getpass"),
    ] = None,
    limit: Annotated[int | None, typer.Option("--limit", min=1, max=1000)] = None,
    config: ConfigOption = None,
) -> None:
    """Send the planned changes. Needs writeback.enabled, WA switched on, the alert writer's
    key, and a person at the terminal who types the confirmation (D-061)."""
    settings = load(config)
    terminal = _human_at_a_terminal()
    try:
        writeback.refuse_unless_ready(
            settings.writeback.enabled, settings.kibana.alert_writer_api_key, True,
            terminal=terminal,
        )  # fmt: skip
    except writeback.WritebackRefused as exc:
        typer.echo(f"refused: {exc}", err=True)
        raise typer.Exit(2) from None
    problems = problems_of(settings, datetime.now(UTC))
    for problem in problems:
        typer.echo(f"refused: {problem}", err=True)
    if problems:
        raise typer.Exit(2)
    if operator is not None:
        from argus.identity.service import names

        early = names(settings).refusal(operator)
        if early is not None:
            typer.echo(f"refused before any request: {early}", err=True)
            raise typer.Exit(2)
    raise typer.Exit(asyncio.run(_main(settings, writer_engine(settings, writes=True),
                                       operator, limit)))  # fmt: skip


async def _main(settings: Settings, engine: Any, operator: str | None, limit: int | None) -> int:
    """The diff, the typed confirmation, the operator's sign-in, then the run: one event loop,
    because the engine's connections belong to it."""
    credential: Credential | None = None
    try:
        async with engine.connect() as conn:
            typer.echo(json.dumps(await writeback.diff(conn), indent=2))
            first = (
                await conn.execute(text("SELECT 1 FROM writeback_outbox WHERE written_count > 0"))
            ).first()
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        await engine.dispose()
        return 1
    if first is None:
        typer.echo(
            f"nothing was ever written: this run writes at most {writeback.FIRST_RUN} alerts"
        )
    if typer.prompt(f"Type {CONFIRM} to send the planned changes to Kibana") != CONFIRM:
        typer.echo("not confirmed", err=True)
        await engine.dispose()
        return 1
    if operator is not None:
        password = read_password(f"ELK password for {operator}: ")
        credential = Credential(operator, password)
        register_secret(password.get_secret_value())
        register_secret(authorization(credential).get_secret_value().split(" ", 1)[1])
    return await _run(settings, engine, credential, limit)


async def _run(
    settings: Settings, engine: Any, credential: Credential | None, limit: int | None
) -> int:
    from argus.gateway.kibana.service import build_kibana_gateway
    from argus.gateway.service import build_gateway
    from argus.identity.service import build_identity_lane

    senders: list[object] = []
    try:
        operator: Operator | None = None
        try:
            es, store = build_gateway(settings.siem, engine)
            senders.append(es.transport)
            kibana = build_kibana_gateway(settings, store, es_gateway=es)
            senders.append(kibana.transport)
            if credential is not None:
                lane = build_identity_lane(settings, store, es_gateway=es)
                senders.append(lane.transport)
                checked = await lane.check(credential, deadline=datetime.now(UTC) + CHECK_DEADLINE)
                operator = operator_of(checked)
                typer.echo(f"signed in as {operator.username}: may change alert status in Kibana")
        except (ConfigError, ValueError) as exc:
            typer.echo(f"error: {exc}", err=True)
            return 2
        except IdentityError as exc:
            typer.echo(f"operator check failed ({exc.reason}): nothing was sent", err=True)
            return 2
        except writeback.WritebackRefused as exc:
            typer.echo(f"refused: {exc}", err=True)
            return 2
        sender = AlertSender(
            engine, kibana, es=es,
            run_limit=limit or settings.writeback.run_limit,
            f1_audited=settings.writeback.f1_audited,
            operator=operator,
            accepted_residual=settings.kibana.accepted_residual,
        )  # fmt: skip
        try:
            result = await sender.run()
        except writeback.WritebackRefused as exc:
            typer.echo(f"refused: {exc}", err=True)
            return 2
        except DB_ERRORS as exc:
            typer.echo(f"error: {short_db_error(exc)}", err=True)
            return 1
        for line in result.lines():
            typer.echo(line)
        return 1 if result.paused else 0
    finally:
        for closing in senders:
            close = getattr(closing, "aclose", None)
            if close is not None:
                await close()
        await engine.dispose()
