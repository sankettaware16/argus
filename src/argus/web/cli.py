"""``argus web`` (the Inbox: the loopback, or TLS on the network, D-104), ``argus user ...``
(reviewer accounts, and ``user link`` for ELK sign-in), ``argus sessions ...`` (end every session;
make the web's secret) and ``argus break-glass ...`` (the emergency account, Q-E2)."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Annotated, Any

import typer
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.caseteam.service import post_config
from argus.config.settings import Settings, operator_of
from argus.db.errors import DB_ERRORS, short_db_error
from argus.gateway.cli import ConfigOption, engine_for, load
from argus.web import auth
from argus.web.capabilities import LOCAL_DEFAULT, NEEDS, Capability, effective, ordered, parse

CAPABILITY_HELP = (
    "one or more of: " + ", ".join(c.value for c in Capability)
    + " (each needs its prerequisites to count: approve needs manage_cases, answer_gold needs"
    " review, everything needs view)"
)  # fmt: skip

user_app = typer.Typer(no_args_is_help=True, help="Reviewer accounts for the Inbox (R7).")
sessions_app = typer.Typer(
    no_args_is_help=True, help="Sessions of the Inbox: end them all, make the web's secret (Q-E2)."
)
break_glass_app = typer.Typer(
    no_args_is_help=True,
    help="The emergency account for when ELK cannot be asked: view and review only (Q-E2).",
)


def web_engine(settings: Settings) -> AsyncEngine:
    """The engine the web runs on: its own login (``database.api_user``, only the grants the
    web needs, Q-A2) when ``web.database_role`` is ``api``, else the runtime login. Exit code 2
    while that login's password is missing."""
    from argus.cli import _engine  # argus.cli imports this module: import at call time

    return _engine(settings, settings.web.database_role)


def web(config: ConfigOption = None) -> None:
    """Serve the Inbox: on the loopback address (reviewers use an SSH forward, e.g.
    ``ssh -L 8765:127.0.0.1:8765 <this machine>``), or with TLS on the network (D-104). With
    ``web.elk_signin`` people sign in with their own ELK accounts (Q-E2)."""
    import uvicorn

    from argus.web.app import create_app

    settings = load(config)
    engine = web_engine(settings)
    lane = None
    if settings.web.elk_signin:
        lane = _identity_lane(settings, engine)
    privacy = None
    try:  # on-demand assessments need the privacy layer, as the assess service does
        from argus.assets.store import load_asset_map
        from argus.llm.privacy import Privacy, load_policy

        assets = load_asset_map(settings.assets.map_path)
        if assets is not None:
            privacy = Privacy.build(load_policy(), assets, settings.site.own_networks)
    except Exception as exc:  # the Inbox works without it
        why = str(exc) if type(exc).__name__ == "PrivacyConfigError" else type(exc).__name__
        typer.echo(f"note: no on-demand assessments ({why})", err=True)
    from argus.cases.signing import KeyFileError

    watch = None
    try:  # what proves a case quiet (Q-C2); without it no case can be called quiet
        from argus.cases import watchrun

        watch = watchrun.context_for(settings)
    except Exception as exc:  # the case pages work without it
        typer.echo(f"note: no quiet-window check for cases ({type(exc).__name__})", err=True)
    try:
        from argus.cases.membership import load_shared
        from argus.outside.eligible import Eligibility
        from argus.outside.service import view_of

        shared = load_shared()
        eligible = (
            Eligibility(privacy.classifier, privacy.campus, privacy.campus_for)
            if privacy is not None
            else None
        )
        app = create_app(engine, settings.web, privacy=privacy, lane=lane, watch=watch,
                         watch_mode=settings.cases.watch,
                         outside_view=view_of(settings.outside, lambda parent: (
                             shared.reason("domain", parent) is None
                             and (eligible is None or eligible.check("domain", parent) is None)
                         )), team=post_config(settings),
                         signins=signins_reading(settings, privacy, watch))  # fmt: skip
    except KeyFileError as exc:  # the approval key named in web.approval_key_file
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from None
    web = settings.web
    tls: dict[str, Any] = {}
    if web.tls_cert is not None and web.tls_key is not None:
        tls = {"ssl_certfile": str(web.tls_cert), "ssl_keyfile": str(web.tls_key)}
    shown = web.allowed_hosts[0] if web.allowed_hosts else web.host
    typer.echo(f"ARGUS Inbox on {web.scheme}://{shown}:{web.port}/")
    uvicorn.run(app, host=web.host, port=web.port, proxy_headers=False, server_header=False,
                log_level="warning", **tls)  # fmt: skip


def signins_reading(settings: Settings, privacy: Any, watch: Any) -> Any:
    """What the pages need to show who used a device (AR6): the rules, the classifier that says
    which addresses are internal (the privacy layer's, else the watch's), the campus resolvers.
    None when there is no classifier: the card is then off."""
    from argus.signins import view

    classifier = getattr(privacy, "classifier", None) or getattr(watch, "classifier", None)
    return None if classifier is None else view.reading_of(settings, classifier)


def _at_a_terminal() -> bool:
    return sys.stdin.isatty()


def _identity_lane(settings: Settings, engine: AsyncEngine) -> Any:
    """The identity lane the web checks people with (Q-E1): on the web's own database login,
    with ARGUS's reader key for the security-index check after a 401 (without it a 401 is never
    a denial, only "unavailable")."""
    from argus.config.errors import ConfigError
    from argus.gateway.pgstore import PgStore
    from argus.gateway.service import build_gateway, collector_config, lane_plan
    from argus.identity.service import build_identity_lane

    try:
        es_gateway = None
        try:
            es_gateway, store = build_gateway(settings.siem, engine)
        except ConfigError:
            typer.echo("note: no siem.api_key here: a 401 cannot be confirmed, so ELK's refusal"
                       " of a wrong password counts for nothing (sign-in is safe but blind)",
                       err=True)  # fmt: skip
            store = PgStore(engine, collector_config(settings.siem), lane_plan(settings.siem))
        return build_identity_lane(settings, store, es_gateway=es_gateway)
    except (ConfigError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from None


def _capabilities(names: list[str]) -> list[Capability]:
    """The capabilities named, or an error naming the unknown ones."""
    unknown = sorted({n for n in names if n not in {c.value for c in Capability}})
    if unknown:
        typer.echo(f"error: unknown capability {', '.join(unknown)}; {CAPABILITY_HELP}", err=True)
        raise typer.Exit(2)
    return ordered(parse(names))


@user_app.command("add")
def user_add(
    username: Annotated[str, typer.Argument(help="login name: lowercase, 2-32 characters")],
    display_name: Annotated[str, typer.Option("--name", help="shown in the Inbox")] = "",
    capability: Annotated[
        list[str] | None,
        typer.Option(
            "--capability",
            "-c",
            help="what it may do (repeat it); without it: view,"
            " see_logs, review and answer_gold, as every account had before",
        ),
    ] = None,
    config: ConfigOption = None,
) -> None:
    """Create a reviewer; the password is asked twice (never on the command line)."""
    if username == "break-glass":
        typer.echo("error: break-glass is the emergency account: `argus break-glass on`", err=True)
        raise typer.Exit(2)
    kind = "service" if username == "argus-assistant" else "person"  # it never signs in
    granted = LOCAL_DEFAULT if capability is None else frozenset(_capabilities(capability))
    if not sys.stdin.isatty():
        typer.echo("error: run this at a terminal (the password is typed, not passed)", err=True)
        raise typer.Exit(2)
    password = typer.prompt("Password (10 or more characters)", hide_input=True,
                            confirmation_prompt=True)  # fmt: skip
    settings = load(config)

    async def go() -> int:
        engine = engine_for(settings)
        try:
            async with engine.begin() as conn:
                user_id = await auth.add_user(conn, username, display_name or username, password,
                                              granted, kind)  # fmt: skip
                await auth.audit(
                    conn,
                    actor="cli",
                    action="user.add",
                    target_type="user",
                    target_id=username,
                    details={"capabilities": sorted(c.value for c in granted)},
                )
                return user_id
        finally:
            await engine.dispose()

    try:
        asyncio.run(go())
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from None
    except IntegrityError:
        typer.echo("error: that name is taken or not valid (a-z, 0-9, _ . -; 2-32)", err=True)
        raise typer.Exit(1) from None
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None
    typer.echo(f"{username}: created")


@user_app.command("disable")
def user_disable(username: str, config: ConfigOption = None) -> None:
    """Disable a reviewer (their sessions stop working at once)."""
    settings = load(config)

    async def go() -> bool:
        engine = engine_for(settings)
        try:
            async with engine.begin() as conn:
                row = await conn.execute(
                    text("UPDATE users SET disabled = true WHERE username = :u RETURNING id"),
                    {"u": username},
                )
                found = row.first() is not None
                await auth.audit(conn, actor="cli", action="user.disable", target_type="user",
                                 target_id=username, details={"found": found})  # fmt: skip
                return found
        finally:
            await engine.dispose()

    if not asyncio.run(go()):
        typer.echo(f"error: no user {username}", err=True)
        raise typer.Exit(1)
    typer.echo(f"{username}: disabled")


@user_app.command("list")
def user_list(config: ConfigOption = None) -> None:
    """Reviewers, what they may do, and when they were last seen."""
    settings = load(config)

    async def go() -> list[str]:
        engine = engine_for(settings)
        try:
            async with engine.connect() as conn:
                rows = await conn.execute(
                    text(
                        "SELECT u.username, u.display_name, u.disabled, max(s.last_seen_at),"
                        " u.capabilities, u.elk_username, u.kind FROM users u"
                        " LEFT JOIN user_sessions s"
                        " ON s.user_id = u.id GROUP BY u.id ORDER BY u.username"
                    )
                )
                out = []
                for name, shown, off, seen, granted, elk, kind in rows:
                    may = ", ".join(c.value for c in ordered(effective(granted or ()))) or "nothing"
                    when = f"last seen {seen:%Y-%m-%d %H:%M} UTC" if seen else "never seen"
                    extra = (f", {kind}" if kind != "person" else "") + (
                        f", ELK account {elk!r}" if elk else ""
                    )
                    out.append(
                        f"{name} ({shown}){' disabled' if off else ''}{extra}, {when}; may: {may}"
                    )
                return out
        finally:
            await engine.dispose()

    for line in asyncio.run(go()):
        typer.echo(line)


def _change_capabilities(username: str, names: list[str], grant: bool, config: ConfigOption
                         ) -> None:  # fmt: skip
    wanted = _capabilities(names)
    settings = load(config)

    async def go() -> list[str] | None:
        engine = engine_for(settings)
        try:
            async with engine.begin() as conn:
                now = await conn.scalar(
                    text("SELECT capabilities FROM users WHERE username = :u FOR UPDATE"),
                    {"u": username},
                )
                if now is None:
                    return None
                have = set(now) | {c.value for c in wanted} if grant else (
                    set(now) - {c.value for c in wanted})  # fmt: skip
                stored = [c.value for c in ordered(parse(have))]
                await conn.execute(
                    text("UPDATE users SET capabilities = CAST(:c AS text[]) WHERE username = :u"),
                    {"c": stored, "u": username},
                )
                await auth.audit(conn, actor="cli", action="user.grant" if grant else "user.revoke",
                                 target_type="user", target_id=username,
                                 details={"capabilities": [c.value for c in wanted],
                                          "now": stored})  # fmt: skip
                return stored
        finally:
            await engine.dispose()

    try:
        stored = asyncio.run(go())
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None
    if stored is None:
        typer.echo(f"error: no user {username}", err=True)
        raise typer.Exit(1)
    counts = effective(stored)
    shown = ", ".join(c.value for c in ordered(counts)) or "nothing"
    typer.echo(f"{username} may: {shown}")
    for c in ordered(parse(stored)):
        if c not in counts:
            missing = ", ".join(n.value for n in ordered(NEEDS[c] - counts))
            typer.echo(f"note: {c.value} counts only with {missing}", err=True)


@user_app.command("grant")
def user_grant(
    username: str,
    capabilities: Annotated[list[str], typer.Argument(help=CAPABILITY_HELP)],
    config: ConfigOption = None,
) -> None:
    """Let a local account do more (Q-A1); its sessions see the change at their next request."""
    _change_capabilities(username, capabilities, True, config)


@user_app.command("revoke")
def user_revoke(
    username: str,
    capabilities: Annotated[list[str], typer.Argument(help=CAPABILITY_HELP)],
    config: ConfigOption = None,
) -> None:
    """Take capabilities away from a local account; its sessions lose them at once."""
    _change_capabilities(username, capabilities, False, config)


def grade(
    count: Annotated[int, typer.Option("--count", "-n", min=1, max=500)] = 30,
    config: ConfigOption = None,
) -> None:
    """R7 gate: grade random investigations (is each one correctly grouped?). Answers are
    saved to data/gate/grading-<UTC time>.csv; the share of yes is printed at the end."""
    import csv
    import json
    from datetime import UTC, datetime
    from pathlib import Path

    from argus.web import render

    if not sys.stdin.isatty():
        typer.echo("error: run this at a terminal", err=True)
        raise typer.Exit(2)
    settings = load(config)

    async def sample() -> list[dict[str, Any]]:
        engine = engine_for(settings)
        try:
            async with engine.connect() as conn:
                rows = await conn.execute(
                    text(
                        "SELECT i.id, coalesce(i.rule_name, i.rule_id) AS rule, i.group_key,"
                        " i.alert_count, i.duplicate_count, i.first_event_at, i.last_event_at,"
                        " (SELECT json_agg(x) FROM (SELECT a.normalized->'entities' AS x"
                        "  FROM investigation_alerts ia JOIN alert_records a"
                        "  ON a.alert_id = ia.alert_id WHERE ia.investigation_id = i.id"
                        "  LIMIT 3) s) AS examples"
                        " FROM investigations i ORDER BY random() LIMIT :n"
                    ),
                    {"n": count},
                )
                return [dict(row._mapping) for row in rows]
        finally:
            await engine.dispose()

    items = asyncio.run(sample())
    if not items:
        typer.echo("no investigations yet: run the collector first", err=True)
        raise typer.Exit(1)
    answers: list[tuple[str, str]] = []
    for number, item in enumerate(items, start=1):
        typer.echo(f"\n[{number}/{len(items)}] {render.untrusted(item['rule'], 120)}")
        typer.echo(f"  key: {render.untrusted(item['group_key'], 200)}")
        typer.echo(
            f"  {item['alert_count']} alerts (+{item['duplicate_count']} repeats),"
            f" {render.ist(item['first_event_at'])} to {render.ist(item['last_event_at'])}"
        )
        for example in item["examples"] or []:
            typer.echo(f"  e.g. {render.untrusted(json.dumps(example), 160)}")
        typer.echo(
            f"  Inbox: {settings.web.scheme}://{settings.web.host}:{settings.web.port}"
            f"/investigations/{item['id']}"
        )
        answer = ""
        while answer not in ("y", "n", "s"):
            answer = typer.prompt("Correctly grouped? [y]es / [n]o / [s]kip").strip().lower()[:1]
        if answer != "s":
            answers.append((str(item["id"]), answer))
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    out = Path("data/gate") / f"grading-{stamp}.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="") as handle:
        csv.writer(handle).writerows([("investigation", "correctly_grouped"), *answers])
    yes = sum(answer == "y" for _, answer in answers)
    share = 100 * yes / len(answers) if answers else 0.0
    typer.echo(f"\n{yes} of {len(answers)} correctly grouped ({share:.0f}%); saved to {out}")


# --------------------------------------------------------------------------- ELK sign-in


DifferentPersonOption = Annotated[
    bool,
    typer.Option(
        "--yes-different-person",
        help="link although the ELK name is another local account's name (the pair is right)",
    ),
]


@user_app.command("link")
def user_link(
    username: Annotated[str, typer.Argument(help="the local ARGUS account")],
    elk_username: Annotated[str, typer.Argument(help="its ELK username, exactly as ELK has it")],
    yes_different_person: DifferentPersonOption = False,
    config: ConfigOption = None,
) -> None:
    """Link a local account to the person's ELK account (Q-E2; the same as `argus identity link
    USER --elk NAME`). Their next ELK sign-in finds this account (its ``users.id`` and all its
    history); the local password stays until that sign-in has worked. A local account could
    always answer gold items; in ELK mode only a named owner may (DQ15), so linking takes
    ``answer_gold`` away: give it back with ``argus user grant <account> answer_gold`` to those
    who should keep it."""
    link_account(load(config), username, elk_username, different_person=yes_different_person)


def link_account(
    settings: Settings, username: str, elk_username: str, *, different_person: bool = False
) -> None:
    """The terminal side of linking (shared by ``argus user link`` and ``argus identity link``)."""
    from argus.web import cutover

    early = cutover.name_problem(settings, elk_username)
    if early is not None:
        typer.echo(f"error: {elk_username!r} cannot be linked ({early})", err=True)
        raise typer.Exit(2)

    async def go() -> bool:
        engine = engine_for(settings)
        try:
            async with engine.begin() as conn:
                return await cutover.link(
                    conn, username, elk_username,
                    operator=operator_of(settings), different_person=different_person,
                )  # fmt: skip
        finally:
            await engine.dispose()

    try:
        stripped = asyncio.run(go())
    except cutover.CutoverError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None
    except IntegrityError:
        typer.echo("error: that ELK name is linked to another account", err=True)
        raise typer.Exit(1) from None
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None
    typer.echo(f"{username} is linked to the ELK account {elk_username!r}; the local password"
               " stays until their first ELK sign-in has worked")  # fmt: skip
    if stripped:
        gold = cutover.GOLD
        typer.echo(f"{gold} was removed from {username}: only named owners answer gold items in"
                   f" ELK mode. To keep it: argus user grant {username} {gold}")  # fmt: skip


@sessions_app.command("end-all")
def sessions_end_all(config: ConfigOption = None) -> None:
    """End every open session at once (the sealed ELK credentials are wiped with them)."""
    settings = load(config)

    async def go() -> int:
        engine = engine_for(settings)
        try:
            async with engine.begin() as conn:
                done = await conn.execute(
                    text("UPDATE user_sessions SET ended_at = now(), credential = NULL,"
                         " ended_why = 'end_all' WHERE ended_at IS NULL"))  # fmt: skip
                count = int(done.rowcount or 0)
                await auth.audit(conn, actor="cli", action="sessions.end_all",
                                 details={"sessions": count})  # fmt: skip
                return count
        finally:
            await engine.dispose()

    try:
        count = asyncio.run(go())
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None
    typer.echo(f"{count} session(s) ended")


@sessions_app.command("keygen")
def sessions_keygen(
    out: Annotated[Path, typer.Argument(help="a new file for the web's secret (mode 0600)")],
    config: ConfigOption = None,
) -> None:
    """Make the web's secret: 32 random bytes as 64 hex digits, in a file only this user can
    read (``web.secret_file`` names it). It keys the sealed ELK credentials and the names of
    failed sign-ins; lose it and every session must sign in again. Give it to ``argus-web``
    alone (plan §7.9)."""
    from argus.cases import signing

    try:
        signing.write_key(out, signing.new_key())
    except FileExistsError:
        typer.echo(f"error: {out} exists; it is never overwritten", err=True)
        raise typer.Exit(1) from None
    typer.echo(f"wrote {out} (mode 0600). Set web.secret_file to it; never commit or paste it")


def _outage_confirmed(settings: Settings) -> bool:
    """Whether ARGUS itself sees the SIEM as down for people: its identity gate is open, or an open
    session could not be verified because of an outage."""
    from datetime import UTC, datetime

    from argus.gateway.pgstore import PgStore

    async def go() -> bool:
        engine = engine_for(settings)
        try:
            reach = await PgStore(engine).identity_reach()
            if reach.is_open(datetime.now(UTC)):
                return True
            async with engine.connect() as conn:
                stuck = await conn.scalar(
                    text("SELECT count(*) FROM user_sessions WHERE ended_at IS NULL"
                         " AND unverified_why = 'outage' AND expires_at > now()"))  # fmt: skip
            return bool(stuck)
        finally:
            await engine.dispose()

    return asyncio.run(go())


@break_glass_app.command("on")
def break_glass_on(
    minutes: Annotated[
        int,
        typer.Option("--minutes", min=1, max=240, help="how long it stays on (at most 4 hours)"),
    ] = 120,
    override: Annotated[
        bool,
        typer.Option(
            "--override",
            help="switch it on although ARGUS does not see an outage (typed confirmation)",
        ),
    ] = False,
    config: ConfigOption = None,
) -> None:
    """Switch the emergency account on: asks why (typed), checks that the SIEM is down, makes a
    one-time password and prints it once. View and review only; nothing it does reaches Kibana."""
    from argus.web import breakglass

    if not _at_a_terminal():
        typer.echo("error: run this at a terminal on the ARGUS host (the reason is typed)",
                   err=True)  # fmt: skip
        raise typer.Exit(2)
    settings = load(config)
    if not settings.web.elk_signin:
        typer.echo("error: web.elk_signin is off: local accounts sign in as they always did",
                   err=True)  # fmt: skip
        raise typer.Exit(2)
    reason = typer.prompt("Why is break-glass needed? (typed, 10 to 500 characters)")
    try:
        down = _outage_confirmed(settings)
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None
    if not down:
        if not override:
            typer.echo("error: ARGUS does not see an SIEM outage (no open session cannot be"
                       " verified and the identity gate is closed). If the SIEM is down for"
                       " people anyway, run again with --override", err=True)  # fmt: skip
            raise typer.Exit(1)
        if typer.prompt("Type OVERRIDE to switch it on without a confirmed outage") != "OVERRIDE":
            typer.echo("not switched on", err=True)
            raise typer.Exit(1)

    async def go() -> tuple[str, Any]:
        engine = engine_for(settings)
        try:
            async with engine.begin() as conn:
                return await breakglass.open_window(
                    conn,
                    reason=reason,
                    enabled_by=operator_of(settings),
                    minutes=minutes,
                    override=not down,
                )
        finally:
            await engine.dispose()

    try:
        password, ends = asyncio.run(go())
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from None
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None
    typer.echo(f"break-glass is ON until {ends:%Y-%m-%d %H:%M} UTC")
    typer.echo(f"  sign in at /signin as {breakglass.NAME} with this one-time password:")
    typer.echo(f"  {password}")
    typer.echo("  it is shown once and works for one sign-in; the session ends with the window."
               " Switch it off with `argus break-glass off` as soon as ELK is back")  # fmt: skip


@break_glass_app.command("off")
def break_glass_off(config: ConfigOption = None) -> None:
    """Switch the emergency account off: the window ends, the account is disabled, its sessions
    end."""
    from argus.web import breakglass

    settings = load(config)

    async def go() -> bool:
        engine = engine_for(settings)
        try:
            async with engine.begin() as conn:
                return await breakglass.close_window(conn, by=operator_of(settings))
        finally:
            await engine.dispose()

    try:
        was_open = asyncio.run(go())
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None
    typer.echo("break-glass is OFF" + ("" if was_open else " (it was not on)"))


@break_glass_app.command("status")
def break_glass_status(config: ConfigOption = None) -> None:
    """Whether the emergency account is on, until when, and whether its password was used."""
    from argus.web import breakglass

    settings = load(config)

    async def go() -> breakglass.Window | None:
        engine = engine_for(settings)
        try:
            async with engine.connect() as conn:
                return await breakglass.active(conn)
        finally:
            await engine.dispose()

    try:
        window = asyncio.run(go())
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None
    if window is None:
        typer.echo("break-glass is OFF")
        return
    used = "its password was used" if window.consumed_at else "its password was not used yet"
    typer.echo(f"break-glass is ON until {window.expires_at:%Y-%m-%d %H:%M} UTC; {used}")
