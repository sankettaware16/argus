"""``argus identity ...``: the identity lane at a terminal (Q-E1).

- ``check --user NAME``: one ``_authenticate`` and one ``_has_privileges`` with that person's
  own ELK account, the password read with ``getpass`` (never an argument, an environment
  variable or a file, so it is never in the process table or the shell history). Prints who
  the account is and what it may do in ARGUS, or why not. ``--dry-run`` prints the two
  requests and sends nothing (no password asked). Plan §5: the first live run is the user's,
  with their personal account, never ``elastic`` or a superuser.
- ``map``: the capability map, in plain words (no request).
- ``state``: the identity gate (open or closed, and why) and the ``identity`` switch.
- ``link USER --elk NAME``, ``cutover status``, ``disable-local USER``, ``enable-local USER``: the
  cutover from local passwords to ELK sign-in (Q-E3, ``argus.web.cutover``). Terminal commands
  on ARGUS's own database; none of them sends a request to the SIEM.

Exit codes: 0 the account may use ARGUS; 1 refused or denied; 2 a usage or configuration
error; 3 ARGUS could not tell (the SIEM unreachable, overloaded, the lane stopped or busy).
"""

from __future__ import annotations

import getpass
import json
import sys
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import typer
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.config.errors import ConfigError
from argus.config.settings import Settings, operator_of
from argus.db.errors import DB_ERRORS, short_db_error
from argus.gateway.cli import ConfigOption, _run, _with_store, engine_for, load
from argus.gateway.pgstore import PgStore
from argus.identity import capmap
from argus.identity.lane import (
    IdentityDeniedError,
    IdentityError,
    IdentityRefusedError,
    IdentityUnavailableError,
)
from argus.identity.names import Credential
from argus.identity.transport import ROUTES, Route, authorization
from argus.observability.redaction import register_secret
from argus.web.capabilities import LABELS, ordered

identity_app = typer.Typer(
    no_args_is_help=True, help="The identity lane: check an ELK account, the capability map (Q-E1)."
)
cutover_app = typer.Typer(
    no_args_is_help=True,
    help="Where each account stands on the way from local passwords to ELK sign-in (Q-E3).",
)
identity_app.add_typer(cutover_app, name="cutover")
CHECK_DEADLINE = timedelta(seconds=20)  # two calls, their admissions and the index check


def read_password(prompt: str) -> SecretStr:
    """The password from the terminal, never echoed (``getpass``)."""
    return SecretStr(getpass.getpass(prompt))


def _at_a_terminal() -> bool:
    return sys.stdin.isatty()


@identity_app.command("check")
def identity_check(
    user: Annotated[str, typer.Option("--user", help="your own ELK username")],
    dry_run: Annotated[bool, typer.Option("--dry-run", help="print, send nothing")] = False,
    config: ConfigOption = None,
) -> None:
    """Check one ELK account through the identity lane: who it is and what it may do in ARGUS
    (the password is asked for, never passed)."""
    settings = load(config)
    from argus.identity.service import names, targets

    early = names(settings).refusal(user)
    if early is not None:
        typer.echo(f"refused before any request: {early}", err=True)
        raise typer.Exit(1)
    if dry_run:
        for n, route in enumerate(Route, 1):
            method, path = ROUTES[route]
            typer.echo(f"{n}. Elasticsearch {method} {settings.siem.shown_url}{path} (as {user})")
        typer.echo(json.dumps(capmap.request_body(targets(settings)), indent=2))
        typer.echo("dry run: nothing was sent, no password was asked for")
        return
    if not _at_a_terminal():
        typer.echo("error: the password is typed at a terminal (getpass)", err=True)
        raise typer.Exit(2)
    password = read_password(f"ELK password for {user}: ")
    credential = Credential(user, password)
    # this process's logs mask it, and its Basic header, from now on (a terminal command:
    # one person's password for the life of the process)
    register_secret(password.get_secret_value())
    register_secret(authorization(credential).get_secret_value().split(" ", 1)[1])
    raise typer.Exit(_run(_check(settings, credential)))


async def _check(settings: object, credential: Credential) -> int:
    from argus.config.settings import Settings
    from argus.gateway.service import build_gateway, collector_config, lane_plan
    from argus.identity.service import build_identity_lane

    assert isinstance(settings, Settings)
    engine = engine_for(settings)
    senders: list[object] = []
    try:
        try:
            store = PgStore(engine, collector_config(settings.siem), lane_plan(settings.siem))
            es_gateway = None
            try:  # ARGUS's own key, for the security-index check after a 401
                es_gateway, store = build_gateway(settings.siem, engine)
                senders.append(es_gateway.transport)
            except ConfigError:
                typer.echo("note: no siem.api_key here: a 401 cannot be confirmed", err=True)
            lane = build_identity_lane(settings, store, es_gateway=es_gateway)
        except (ConfigError, ValueError) as exc:
            typer.echo(f"error: {exc}", err=True)
            return 2
        senders.append(lane.transport)
        deadline = datetime.now(UTC) + CHECK_DEADLINE
        try:
            checked = await lane.check(credential, deadline=deadline)
        except IdentityError as exc:
            typer.echo(_explain(exc), err=True)
            return 3 if isinstance(exc, IdentityUnavailableError) else 1
        except DB_ERRORS as exc:  # the lane's state and ledger are ARGUS's database
            typer.echo(f"error: {short_db_error(exc)}", err=True)
            return 2
        identity, access = checked.identity, checked.access
        typer.echo(f"{identity.username}: a native ELK account, ARGUS id {identity.argus_uid}")
        if access.admin_account:
            typer.echo("  an admin account, let in without custody (DQ15 (b))")
        typer.echo(f"  capability map v{access.map_version}; in ARGUS this account may:")
        for capability in ordered(access.capabilities):
            typer.echo(f"  - {LABELS[capability]}")
        return 0
    finally:
        for sender in senders:
            close = getattr(sender, "aclose", None)
            if close is not None:
                await close()
        await engine.dispose()


def _explain(exc: IdentityError) -> str:
    if isinstance(exc, IdentityDeniedError):
        return f"denied by Elasticsearch ({exc.reason}): wrong name or password, or disabled"
    if isinstance(exc, IdentityRefusedError):
        return f"refused by ARGUS ({exc.reason})"
    return f"could not tell ({exc.reason}): nothing counted against the account; try later"


@identity_app.command("map")
def identity_map() -> None:
    """The capability map: what each ARGUS capability checks in ELK (no request)."""
    typer.echo(
        f"capability map v{capmap.MAP_VERSION} (Kibana {capmap.KIBANA_VERSION},"
        f" {capmap.SECURITY_FEATURE}, {capmap.CASES_FEATURE}):"
    )
    for name, needs in capmap.describe():
        typer.echo(f"  {name}: {needs}")
    typer.echo(
        "  refused: superusers (cluster all); admin accounts ("
        + ", ".join(capmap.ADMIN_CANARIES)
        + ") unless identity.admin_accounts is without_custody"
    )


@identity_app.command("state")
def identity_state(config: ConfigOption = None) -> None:
    """The identity gate (its own reachability and overload signals) and its switch."""
    settings = load(config)

    async def use(store: PgStore) -> list[str]:
        reach = await store.identity_reach()
        switches = await store.switches()
        now = datetime.now(UTC)
        gate = "closed (checks go)"
        if reach.is_open(now):
            assert reach.open_until is not None
            gate = f"open until {reach.open_until:%H:%M:%S} UTC ({reach.reason})"
        elif reach.open_until is not None:
            gate = f"half-open: the next check is a trial ({reach.reason})"
        stopped = switches.blocks("identity")
        return [f"identity gate: {gate}", "identity switch: " + ("STOPPED" if stopped else "on")]

    for line in _run(_with_store(settings, use)):
        typer.echo(line)


# --------------------------------------------------------------------------- the cutover (Q-E3)


def _in_db[T](settings: Settings, work: Callable[[AsyncConnection], Coroutine[Any, Any, T]]) -> T:
    """``work`` in one transaction of ARGUS's own database; a refusal or a database problem ends
    the command with its words (exit 1)."""
    from argus.web.cutover import CutoverError

    async def go() -> T:
        engine = engine_for(settings)
        try:
            async with engine.begin() as conn:
                return await work(conn)
        finally:
            await engine.dispose()

    try:
        return _run(go())
    except CutoverError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None


@identity_app.command("link")
def identity_link(
    username: Annotated[str, typer.Argument(help="the local ARGUS account")],
    elk: Annotated[str, typer.Option("--elk", help="its ELK username, exactly as ELK has it")],
    yes_different_person: Annotated[
        bool,
        typer.Option(
            "--yes-different-person",
            help="link although the ELK name is another local account's name (the pair is right)",
        ),
    ] = False,
    config: ConfigOption = None,
) -> None:
    """Link a local account to the person's ELK account. The account keeps its ``users.id``, so
    reviews, notes, approvals and the audit trail stay with the same person; the local password
    stays until their first ELK sign-in has worked (then `disable-local`). The person's own
    sign-in finds the account: nothing is asked of the SIEM here."""
    from argus.web.cli import link_account

    link_account(load(config), username, elk, different_person=yes_different_person)


@cutover_app.command("status")
def cutover_status(config: ConfigOption = None) -> None:
    """Every account: linked or not, ELK sign-in seen or not, local password on or off, and why
    it stays local. Break-glass is listed apart."""
    from argus.web import cutover

    settings = load(config)

    async def read(conn: AsyncConnection) -> list[str]:
        return cutover.render(
            await cutover.accounts(conn),
            await cutover.glass(conn),
            elk_mode=settings.web.elk_signin,
        )

    for line in _in_db(settings, read):
        typer.echo(line)


@identity_app.command("disable-local")
def identity_disable_local(
    username: Annotated[str, typer.Argument(help="a linked account whose ELK sign-in worked")],
    config: ConfigOption = None,
) -> None:
    """Switch a person's local password off. Refused unless their ELK sign-in has worked at
    least once since the link (read from the audit trail), and while `web.elk_signin` is off.
    The break-glass account is never touched. The way back (a rollback to local mode) is
    `enable-local`."""
    from argus.web import cutover

    settings = load(config)
    operator = operator_of(settings)

    async def work(conn: AsyncConnection) -> bool:
        return await cutover.disable_local(
            conn, username, elk_mode=settings.web.elk_signin, operator=operator
        )

    if _in_db(settings, work):
        typer.echo(
            f"{username}: the local password is off; they sign in through ELK only."
            f" (A rollback to local mode needs: argus identity enable-local {username})"
        )
    else:
        typer.echo(f"{username}: the local password was already off")


@identity_app.command("enable-local")
def identity_enable_local(
    username: Annotated[str, typer.Argument(help="a person whose local password was switched off")],
    config: ConfigOption = None,
) -> None:
    """The way back for a rollback to local mode: give a person a new local password (typed here,
    10 or more characters). It never replaces a password that is on."""
    from argus.web import cutover

    settings = load(config)
    if not _at_a_terminal():
        typer.echo("error: run this at a terminal (the password is typed, not passed)", err=True)
        raise typer.Exit(2)
    password = typer.prompt("New local password (10 or more characters)", hide_input=True,
                            confirmation_prompt=True)  # fmt: skip
    register_secret(password)
    operator = operator_of(settings)

    async def work(conn: AsyncConnection) -> None:
        await cutover.enable_local(conn, username, password, operator=operator)

    _in_db(settings, work)
    typer.echo(f"{username}: a local password is on again (it counts only in local mode)")
