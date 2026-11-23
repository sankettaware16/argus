"""``argus case ...`` and ``argus audit ...``: the case record at the terminal.

Changes are made as a named person (``--as <username>``, audited as ``user:<id>`` with
``via: cli``) holding a local account's capabilities: everything but approving, which only the web's
login records. Nothing here sends anything to Kibana. ``argus case backfill`` is a dry run unless
``--apply``; ``argus case sync`` applies the same rules to new verdicts and proposals.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable, Coroutine
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import typer
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from argus import raising, site
from argus.assets import load_asset_map
from argus.assets.classify import IpClassifier
from argus.assets.store import NoAssetMapError
from argus.campaigns import lookups as campaign_lookups
from argus.campaigns.analysis import Campaign
from argus.cases import (
    autonomy,
    blocklist,
    chain,
    known,
    knownrun,
    knownview,
    membership,
    opener,
    proposer,
    sendcheck,
    signing,
    splitting,
    suggest,
    titling,
    watchrun,
)
from argus.cases.approvals import ApprovalError
from argus.cases.machine import (
    Assign,
    CaseRefused,
    Command,
    Confirm,
    Contain,
    Dismiss,
    Link,
    Notify,
    Open,
    RecordBlock,
    Release,
    Reopen,
    ReplayError,
    Retitle,
    Take,
    WithdrawNotice,
    replay,
    same_case,
)
from argus.cases.model import LOCAL_CAPABILITIES, REASONS, Actor, Member, QuietWindow, Severity
from argus.cases.service import CaseService, no_quiet_window
from argus.config.durations import format_duration, parse_duration
from argus.config.errors import ConfigError
from argus.config.settings import Settings
from argus.db.audit import record_audit
from argus.db.errors import DB_ERRORS, short_db_error
from argus.gateway.cli import ConfigOption, engine_for, load
from argus.gateway.service import health_config
from argus.llm.privacy import Privacy, PrivacyConfigError, load_policy, privacy_map
from argus.outside.eligible import Eligibility
from argus.outside.service import view_of
from argus.responder.machine import ist_day

case_app = typer.Typer(no_args_is_help=True, help="Cases: ARGUS's record of real problems.")
audit_app = typer.Typer(no_args_is_help=True, help="The audit trail's hash chain.")

As = Annotated[str, typer.Option("--as", help="the person acting: an ARGUS username")]
Version = Annotated[
    int | None, typer.Option("--version", help="the version you saw (refused if it moved)")
]
CaseArg = Annotated[str, typer.Argument(help="the case's number or id")]
Note = Annotated[str | None, typer.Option("--note", help="a note for the case's history")]


def _shown(value: object) -> str:
    """``value`` on one line with control and other unprintable characters escaped, as
    ``argus.cli._printable``: indicator values and reasons come from the logs, and a terminal
    escape in a user name must not retitle, clear or write to the operator's terminal."""
    return "".join(
        char if char.isprintable() else char.encode("unicode_escape").decode("ascii")
        for char in str(value)
    )


def _go[T](config: ConfigOption, use: Callable[[AsyncConnection, Settings], Coroutine[Any, Any, T]],
           *, write: bool = True) -> T:  # fmt: skip
    settings = load(config)

    async def wrapped() -> T:
        engine = engine_for(settings)
        try:
            if write:
                async with engine.begin() as conn:
                    return await use(conn, settings)
            async with engine.connect() as conn:
                return await use(conn, settings)
        except CaseRefused as exc:
            typer.echo(f"refused ({exc.code}): {_shown(exc.message)}", err=True)
            raise typer.Exit(1 if exc.code != "invalid" else 2) from None
        except ApprovalError as exc:
            typer.echo(f"refused ({exc.status}): {_shown(exc.message)}", err=True)
            raise typer.Exit(1) from None
        except ConfigError as exc:  # e.g. the shared-infrastructure list: one line, not a traceback
            typer.echo(f"error: {_shown(exc)}", err=True)
            raise typer.Exit(1) from None
        except DB_ERRORS as exc:
            typer.echo(f"error: {short_db_error(exc)}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()

    return asyncio.run(wrapped())


async def _person(conn: AsyncConnection, username: str) -> Actor:
    row = (
        await conn.execute(
            text("SELECT id, disabled FROM users WHERE username = :u"), {"u": username}
        )
    ).first()
    if row is None or row.disabled or username == opener.ASSISTANT:
        raise CaseRefused("forbidden", f"{username!r} is not an active person's account")
    return Actor.person(int(row.id), LOCAL_CAPABILITIES, via="cli")


async def _case_id(service: CaseService, ref: str) -> uuid.UUID:
    found: uuid.UUID | None
    if ref.isdigit():
        found = await service.by_number(int(ref))
    else:
        try:
            found = uuid.UUID(ref)
        except ValueError:
            raise CaseRefused("invalid", f"{ref!r} is neither a case number nor an id") from None
    if found is None or await service.get(found) is None:
        raise CaseRefused("not_found", f"no case {ref}")
    return found


Build = Callable[[CaseService, Actor], Coroutine[Any, Any, Command]]


def _command(config: ConfigOption, ref: str, username: str, version: int | None,
             build: Build, *, watched: bool = False) -> None:  # fmt: skip
    async def use(conn: AsyncConnection, settings: Settings) -> str:
        quiet = watchrun.Finder(conn, watchrun.context_for(settings)) if watched else None
        service = await CaseService.start(conn, quiet or no_quiet_window)
        actor = await _person(conn, username)
        case_id = await _case_id(service, ref)
        applied = await service.apply(actor, case_id, await build(service, actor),
                                      expected_version=version)  # fmt: skip
        case = applied.case
        planned = f"; {len(applied.outbox_ids)} Kibana writes planned" if applied.outbox_ids else ""
        now = f"now {case.state} (version {case.version})"
        return f"case {case.number}: {applied.step.kind}, {now}{planned}"

    typer.echo(_go(config, use))


@case_app.command("list")
def case_list(
    state: Annotated[str | None, typer.Option(help="only cases in this state")] = None,
    limit: Annotated[int, typer.Option(min=1, max=1000)] = 50,
    config: ConfigOption = None,
) -> None:
    """The newest cases."""

    async def use(conn: AsyncConnection, _: Settings) -> list[str]:
        rows = await conn.execute(
            text(
                "SELECT number, state, severity, version, title, owner_user_id, kibana_wait,"
                " (SELECT count(*) FROM case_members m WHERE m.case_id = c.id"
                " AND m.removed_at IS NULL) AS members FROM cases c"
                " WHERE (CAST(:s AS text) IS NULL OR state = :s) ORDER BY number DESC LIMIT :n"
            ),
            {"s": state, "n": limit},
        )
        return [
            f"{r.number:>5}  {r.state:<9}  {r.severity:<8}  v{r.version:<3}  {r.members:>3} inv."
            f"  {_shown(r.title)}"
            + ("" if r.kibana_wait is None else f"  [{_shown(r.kibana_wait)}]")
            for r in rows
        ]

    lines = _go(config, use, write=False)
    typer.echo("\n".join(lines) if lines else "no cases")


@case_app.command("show")
def case_show(ref: CaseArg, config: ConfigOption = None) -> None:
    """A case, its members, indicators, history and planned Kibana writes."""

    async def use(conn: AsyncConnection, _: Settings) -> list[str]:
        service = await CaseService.start(conn)
        case_id = await _case_id(service, ref)
        case = await service.get(case_id)
        assert case is not None
        lines = [
            f"case {case.number} ({case.id}): {_shown(case.title)}",
            f"  state {case.state}, severity {case.severity}, version {case.version},"
            f" owner {'ARGUS' if case.owner_user_id is None else f'user:{case.owner_user_id}'}",
        ]
        if case.closure_reason:
            lines.append(f"  closed as {case.closure_reason} (approval {case.closure_request_id})")
        if case.kibana_wait or case.attention:
            lines.append(_shown(f"  {case.kibana_wait or ''} {case.attention or ''}".rstrip()))
        lines.append(f"  members: {', '.join(str(m) for m in sorted(case.members)) or 'none'}")
        lines += [f"  {i.role}: {i.kind} {_shown(i.value)}" for i in sorted(case.indicators)]
        events = await conn.execute(
            text(
                "SELECT case_version, kind, actor, from_state, to_state, occurred_at,"
                " kibana_rows FROM case_events WHERE case_id = :c ORDER BY case_version"
            ),
            {"c": case_id},
        )
        lines += [
            f"  v{e.case_version} {e.occurred_at:%Y-%m-%d %H:%M} UTC {e.kind} by {_shown(e.actor)}"
            f" ({e.from_state or 'new'} -> {e.to_state})"
            + (f", {e.kibana_rows} Kibana writes" if e.kibana_rows else "")
            for e in events
        ]
        outbox = await conn.execute(
            text(
                "SELECT id, write_class, op, state FROM kibana_outbox WHERE case_id = :c"
                " ORDER BY id"
            ),
            {"c": case_id},
        )
        lines += [f"  outbox {o.id}: {o.write_class} {o.op} {o.state}" for o in outbox]
        return lines

    typer.echo("\n".join(_go(config, use, write=False)))


@case_app.command("open")
def case_open(
    investigations: Annotated[
        list[str], typer.Option("--investigation", help="an investigation id")
    ],
    title: Annotated[str, typer.Option(help="what the problem is, in plain words")],
    username: As,
    severity: Annotated[str, typer.Option(help="low, medium, high or critical")] = "medium",
    config: ConfigOption = None,
) -> None:
    """Open a case by hand (a person who may manage cases)."""
    if severity not in ("low", "medium", "high", "critical"):
        typer.echo("error: severity is low, medium, high or critical", err=True)
        raise typer.Exit(2)
    try:
        members = tuple(Member(uuid.UUID(i), "person") for i in investigations)
    except ValueError:
        typer.echo("error: an investigation is given by its id", err=True)
        raise typer.Exit(2) from None

    async def use(conn: AsyncConnection, _: Settings) -> str:
        service = await CaseService.start(conn)
        actor = await _person(conn, username)
        sev: Severity = severity  # type: ignore[assignment]
        applied = await service.open(actor, Open(title, sev, "person", members))
        case = applied.case
        return (
            f"case {case.number} opened ({case.id}): {case.kibana_wait or 'Kibana create planned'}"
        )

    typer.echo(_go(config, use))


@case_app.command("confirm")
def case_confirm(ref: CaseArg, username: As, version: Version = None, note: Note = None,
                 config: ConfigOption = None) -> None:  # fmt: skip
    """Confirm a suspected case: it becomes open (a person who may manage cases)."""

    async def build(_: CaseService, __: Actor) -> Command:
        return Confirm(note)

    _command(config, ref, username, version, build)


@case_app.command("dismiss")
def case_dismiss(
    ref: CaseArg,
    username: As,
    reason: Annotated[str, typer.Option(help="rule_false_positive, benign_expected, benign_policy,"
                                             " attempt_no_impact, created_in_error or"
                                             " duplicate")],
    version: Version = None,
    note: Note = None,
    config: ConfigOption = None,
) -> None:  # fmt: skip
    """Dismiss a suspected case (a reviewer)."""
    if reason not in REASONS:
        typer.echo(f"error: a reason is one of {', '.join(REASONS)}", err=True)
        raise typer.Exit(2)

    async def build(_: CaseService, __: Actor) -> Command:
        return Dismiss(reason, note)

    _command(config, ref, username, version, build)


@case_app.command("take")
def case_take(ref: CaseArg, username: As, version: Version = None,
              config: ConfigOption = None) -> None:  # fmt: skip
    """Take a case: you own it (Kibana shows your user id)."""

    async def build(_: CaseService, __: Actor) -> Command:
        return Take()

    _command(config, ref, username, version, build)


@case_app.command("contain")
def case_contain(
    ref: CaseArg,
    username: As,
    attest: Annotated[
        str, typer.Option("--attest", help="what you know: for example that the hosts were cleaned")
    ],
    version: Version = None,
    config: ConfigOption = None,
) -> None:
    """Contain a case (a person who may manage cases). Needs your attestation and a verified
    quiet window from the still-active watch. "72 hours" means the three whole UTC days
    before today. What was read: ARGUS's own alerts on each of them and, for each address of the
    case that can be checked in the proxy logs, the logs 01:40-22:59 UTC on each of the three
    days (with verified zeros); the nightly seam and today are covered by the alerts
    only, and a case with no such address rests on the alerts alone (the verdict says so).
    Without that evidence the case stays where it is, and the reason is shown."""

    async def build(_: CaseService, __: Actor) -> Command:
        return Contain(attest, QuietWindow(False, "the service decides"))

    _command(config, ref, username, version, build, watched=True)


@case_app.command("assign")
def case_assign(
    ref: CaseArg,
    to: Annotated[str, typer.Option("--to", help="the username who will own it")],
    username: As,
    version: Version = None,
    config: ConfigOption = None,
) -> None:
    """Give a case to another person."""

    async def build(service: CaseService, _: Actor) -> Command:
        target = (
            await service.conn.execute(text("SELECT id FROM users WHERE username = :u"), {"u": to})
        ).scalar_one_or_none()
        return Assign(int(target or 0), target is not None and await service.assignable(target))

    _command(config, ref, username, version, build)


@case_app.command("release")
def case_release(ref: CaseArg, username: As, version: Version = None,
                 config: ConfigOption = None) -> None:  # fmt: skip
    """Give a case back to ARGUS (open, owned by ARGUS)."""

    async def build(_: CaseService, __: Actor) -> Command:
        return Release()

    _command(config, ref, username, version, build)


@case_app.command("reopen")
def case_reopen(
    ref: CaseArg,
    username: As,
    reason: Annotated[str, typer.Option(help="why it is reopened")],
    version: Version = None,
    config: ConfigOption = None,
) -> None:
    """Reopen a closed case (never silently: a reason is required)."""

    async def build(_: CaseService, __: Actor) -> Command:
        return Reopen(reason)

    _command(config, ref, username, version, build)


@case_app.command("link")
def case_link(
    ref: CaseArg,
    investigations: Annotated[
        list[str], typer.Option("--investigation", help="an investigation id")
    ],
    username: As,
    version: Version = None,
    config: ConfigOption = None,
) -> None:
    """Add investigations to a case."""
    try:
        members = tuple(Member(uuid.UUID(i), "person") for i in investigations)
    except ValueError:
        typer.echo("error: an investigation is given by its id", err=True)
        raise typer.Exit(2) from None

    async def build(_: CaseService, __: Actor) -> Command:
        return Link(members)

    _command(config, ref, username, version, build)


@case_app.command("split")
def case_split(
    ref: CaseArg,
    investigations: Annotated[
        list[str], typer.Option("--investigation", help="an investigation id to move out")
    ],
    username: As,
    reason: Annotated[str, typer.Option("--reason", help="why they are not one problem")],
    title: Annotated[
        str | None, typer.Option("--title", help="open a new case with this title for them")
    ] = None,
    severity: Annotated[
        str | None,
        typer.Option(help="the new case's severity: low, medium (default), high or critical"),
    ] = None,
    into: Annotated[
        str | None, typer.Option("--into", help="or move them into this case (number or id)")
    ] = None,
    version: Version = None,
    config: ConfigOption = None,
) -> None:
    """Move investigations out of a case, into a new case or an existing one, in one step.
    For a suggested case that holds two devices that are separate problems: record the owner's
    notice on the case that holds only the notified one. The actor indicators only the moved
    investigations carried go with them; C2 and other indicators stay on this case and are copied
    to the other. A case keeps at least one investigation (moving all is a merge). The history of
    both cases says what moved and why; nothing is deleted."""
    if (title is None) == (into is None):
        typer.echo("error: give --title (a new case) or --into (an existing case)", err=True)
        raise typer.Exit(2)
    if severity is not None and into is not None:
        typer.echo("error: --severity is for the new case; --into keeps the case's own", err=True)
        raise typer.Exit(2)
    if severity not in (None, "low", "medium", "high", "critical"):
        typer.echo("error: severity is low, medium, high or critical", err=True)
        raise typer.Exit(2)
    try:
        moving = tuple(uuid.UUID(i) for i in investigations)
    except ValueError:
        typer.echo("error: an investigation is given by its id", err=True)
        raise typer.Exit(2) from None

    async def use(conn: AsyncConnection, settings: Settings) -> list[str]:
        service = await CaseService.start(conn)
        actor = await _person(conn, username)
        case_id = await _case_id(service, ref)
        into_id = None if into is None else await _case_id(service, into)
        classifier = IpClassifier(
            load_asset_map(settings.assets.map_path), settings.site.own_networks
        )
        carry = splitting.carrier(conn, classifier, tuple(settings.campaigns.resolvers))
        sev: Severity = severity or "medium"  # type: ignore[assignment]
        done = await service.split(
            actor, case_id, moving, reason=reason, carry=carry, expected_version=version,
            title=title, severity=sev, into_id=into_id,
        )  # fmt: skip
        left, joined = done.source.case, done.target.case
        lines = [
            f"case {left.number}: {len(moving)} investigation(s) moved to case {joined.number}"
            f" ({'opened' if done.new else 'linked'}); case {left.number} is {left.state}"
            f" (version {left.version}), case {joined.number} is {joined.state}"
            f" (version {joined.version})"
        ]
        if done.carried.leaving:
            gone = ", ".join(f"{i.kind} {_shown(i.value)}" for i in done.carried.leaving)
            lines.append(f"  left case {left.number} with them: {gone}")
        if done.carried.staying:
            kept = ", ".join(f"{i.kind} {_shown(i.value)}" for i in done.carried.staying)
            lines.append(
                f"  still on case {left.number}: {kept} (an investigation that stays involves"
                " it too)"
            )
        if left.notified:
            lines.append(f"  note: case {left.number} is notified; the notice stays with it")
            decided = (
                await conn.execute(
                    text(
                        "SELECT outcome, count(*) AS n FROM case_known_matches WHERE case_id = :c"
                        " AND investigation_id = ANY(:ids) GROUP BY outcome ORDER BY outcome"
                    ),
                    {"c": case_id, "ids": list(moving)},
                )
            ).all()
            if decided:
                said = ", ".join(f"{r.n} {r.outcome}" for r in decided)
                lines.append(
                    f"  note: the known pass had already decided {said} of the moved"
                    " investigations under the notice; those decisions stay as they are, so look"
                    " at them again"
                )
        if done.target.step.writes:
            lines.append(f"  {len(done.target.outbox_ids)} Kibana writes planned")
        elif joined.kibana_wait:
            lines.append(f"  case {joined.number}: {_shown(joined.kibana_wait)}")
        return lines

    typer.echo("\n".join(_go(config, use)))


@case_app.command("retitle")
def case_retitle(
    ref: Annotated[str | None, typer.Argument(help="the case's number or id")] = None,
    title: Annotated[str | None, typer.Option("--title", help="the new title")] = None,
    username: Annotated[str | None, typer.Option("--as", help="the person: a username")] = None,
    reason: Annotated[str | None, typer.Option("--reason", help="why it is renamed")] = None,
    all_: Annotated[
        bool, typer.Option("--all", help="ARGUS's own titles of every case, made again from facts")
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="with --all: print old -> new, change nothing")
    ] = False,
    explain: Annotated[
        bool, typer.Option("--explain", help="with --all: each new title's claims and facts")
    ] = False,
    version: Version = None,
    config: ConfigOption = None,
) -> None:
    """Rename a case, or make ARGUS's titles current.

    `argus case retitle 7 --title "..." --as asha --reason "..."` is a person's title: ARGUS never
    changes it afterwards. `argus case retitle --all [--dry-run] [--explain]` makes the title of
    every case that ARGUS wrote (a closed one too) again from the case's facts, and changes the
    ones that differ (a count too, at once); a title a person wrote is left alone; `--explain`
    prints each claim of a new title with the fact it rests on. The assessment service does the
    same for the cases that are not closed every 15 minutes (`cases.retitle`), on a material
    change only."""
    if all_:
        if ref or title or username or reason or version is not None:
            typer.echo("error: --all takes no case, title, person or reason", err=True)
            raise typer.Exit(2)
        _retitle_all(config, dry_run=dry_run, explain=explain)
        return
    if dry_run or explain:
        typer.echo("error: --dry-run and --explain go with --all", err=True)
        raise typer.Exit(2)
    if not (ref and title and username and reason):
        typer.echo("error: give the case, --title, --as and --reason (or use --all)", err=True)
        raise typer.Exit(2)
    new_title, why = title, reason

    async def build(_: CaseService, __: Actor) -> Command:
        return Retitle(new_title, why)

    _command(config, ref, username, version, build)


def _retitle_all(config: ConfigOption, *, dry_run: bool, explain: bool = False) -> None:
    settings = load(config)
    assets = load_asset_map(settings.assets.map_path)
    classifier = IpClassifier(assets, settings.site.own_networks)

    async def go() -> titling.Report:
        engine = engine_for(settings)
        try:
            ctx = titling.Context(classifier)
            return await titling.refresh(
                engine, ctx, dry_run=dry_run, everything=True, limit=10**6, wait=timedelta(0)
            )
        except DB_ERRORS as exc:
            typer.echo(f"error: {short_db_error(exc)}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()

    report = asyncio.run(go())
    if assets is None:
        typer.echo(
            "note: no asset map is imported (argus assets import), so only private addresses"
            f" count as {site.own('devices')} and no place is named"
        )
    typer.echo(f"{'dry run: ' if dry_run else ''}{report.looked} cases looked at")
    for change in report.changes:
        typer.echo(f"  case {change.number}: {_shown(change.old)} -> {_shown(change.new)}")
        for claim in change.claims if explain else ():
            words, fact = _shown(claim["words"]), _shown(claim["fact"])
            typer.echo(f"      {claim['slot']}: {words}  [{fact}]")
    typer.echo(f"a person's title, left alone: {report.kept}")
    typer.echo(
        f"{'would change' if dry_run else 'changed'}: "
        f"{len(report.changes) if dry_run else report.applied} of {len(report.changes)}"
    )
    for skipped in report.skipped:
        typer.echo(f"  skipped {_shown(skipped)}")


@case_app.command("notify")
def case_notify(
    ref: CaseArg,
    username: As,
    told: Annotated[
        str, typer.Option("--told", help="who was told: the owner, or the unit they belong to")
    ],
    how: Annotated[str, typer.Option("--how", help="email, phone, in_person, through_it or other")],
    at: Annotated[
        str | None, typer.Option("--at", help="when they were told, ISO time (default: now)")
    ] = None,
    note: Note = None,
    version: Version = None,
    config: ConfigOption = None,
) -> None:
    """Record that the device's owner (or the team that looks after it) was told.
    The case stays open and watched, leaves the work queues, and ARGUS counts its alerts instead of
    raising them; it speaks again only when something changes, suggests telling the owner again
    after 7 days and network-side action after 21 (`argus case blocklist`). Recordable more than
    once on an open or assigned case."""
    when = _moment(at)

    async def use(conn: AsyncConnection, settings: Settings) -> str:
        service = await CaseService.start(conn)
        actor = await _person(conn, username)
        case_id = await _case_id(service, ref)
        context = watchrun.context_for(settings)
        managed = await knownrun.managed(conn, case_id, context.classifier, context.rules)
        applied = await service.apply(
            actor, case_id, Notify(told, how, when, note, managed),  # type: ignore[arg-type]
            expected_version=version,
        )  # fmt: skip
        kind = site.say("{kind}-managed") if managed else "personal or unmanaged"
        return (
            f"case {applied.case.number}: owner notified ({kind}); version {applied.case.version}"
        )

    typer.echo(_go(config, use))


@case_app.command("withdraw-notice")
def case_withdraw_notice(
    ref: CaseArg,
    username: As,
    reason: Annotated[str, typer.Option("--reason", help="why the notice is withdrawn")],
    who: Annotated[
        str | None, typer.Option("--who", help="who withdraws it (default: --as)")
    ] = None,
    version: Version = None,
    config: ConfigOption = None,
) -> None:
    """Withdraw a notice that was recorded by mistake. The case is not notified any more
    and ARGUS stops absorbing its device's alerts; what it already decided known stays decided,
    and the notice rows stay as the record of what was said. Record the notice again if it was
    true."""

    async def build(_: CaseService, actor: Actor) -> Command:
        return WithdrawNotice(who or actor.name, reason)

    _command(config, ref, username, version, build)


@case_app.command("block")
def case_block(
    ref: CaseArg,
    username: As,
    by: Annotated[str, typer.Option("--by", help="who put the block in place")],
    where: Annotated[str, typer.Option("--where", help="where: DNS, the firewall, the web proxy")],
    at: Annotated[
        str | None, typer.Option("--at", help="when it was blocked, ISO time (default: now)")
    ] = None,
    note: Note = None,
    version: Version = None,
    config: ConfigOption = None,
) -> None:
    """Record that the case's servers or domains were blocked at the network. The
    status line then reads "blocked at the network; the device is still infected"."""
    when = _moment(at)

    async def build(_: CaseService, __: Actor) -> Command:
        return RecordBlock(by, where, when, note)

    _command(config, ref, username, version, build)


def _moment(value: str | None) -> datetime | None:
    """An ISO time with a time zone (or UTC when it has none), for --at."""
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise typer.BadParameter(
            f"{value!r} is not an ISO time (2026-10-26T09:00:00+05:30)"
        ) from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


@case_app.command("blocklist")
def case_blocklist(
    ref: CaseArg,
    fmt: Annotated[str, typer.Option("--format", help="text (an e-mail) or csv")] = "text",
    config: ConfigOption = None,
) -> None:
    """The case's ready block list: its domains, registered domains and addresses
    with the outside evidence ARGUS holds, for the head of cybersecurity. Shared infrastructure is
    left out. Nothing is asked of an outside source."""
    if fmt not in ("text", "csv"):
        raise typer.BadParameter("the format is text or csv")

    async def use(conn: AsyncConnection, settings: Settings) -> str:
        service = await CaseService.start(conn)
        case_id = await _case_id(service, ref)
        classifier = IpClassifier(
            load_asset_map(settings.assets.map_path), settings.site.own_networks
        )
        found = await blocklist.build(conn, case_id, membership.load_shared(), classifier)
        assert found is not None
        return blocklist.to_csv(found) if fmt == "csv" else blocklist.to_text(found, ist_day)

    typer.echo(_go(config, use, write=False), nl=False)


@case_app.command("report")
def case_report(
    ref: CaseArg,
    pdf: Annotated[
        Path | None, typer.Option("--pdf", help="write the report as a PDF to this file")
    ] = None,
    csv_dir: Annotated[
        Path | None,
        typer.Option("--csv", help="write the indicators and affected-devices CSVs to this folder"),
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="show the report without storing it as a version")
    ] = False,
    versions: Annotated[
        bool, typer.Option("--versions", help="list the stored versions and stop")
    ] = False,
    config: ConfigOption = None,
) -> None:
    """The case's incident report: summary, verdict, timeline, actors, assets, evidence
    with the query behind each line, hypotheses, indicators and actions. Written from ARGUS's own
    database only (no request to the SIEM or Kibana, no model); stored as the next version when the
    evidence changed (``--dry-run`` only shows it). ``--pdf`` and ``--csv`` write the files the
    hand-made case had."""
    from argus.incident import files, gather, plain, run, store

    settings = load(config)

    async def go() -> list[str]:
        engine = engine_for(settings)
        try:
            async with engine.connect() as conn:
                case_id = await _case_id(await CaseService.start(conn), ref)
                if versions:
                    return [
                        f"version {v.version}: {v.generated_at:%Y-%m-%d %H:%M} UTC"
                        + (f", {v.decision}" if v.decision else "")
                        for v in await store.versions(conn, case_id)
                    ] or ["no report yet"]
            now = datetime.now(UTC)
            classifier = IpClassifier(
                load_asset_map(settings.assets.map_path), settings.site.own_networks
            )
            ctx = run.context_for(settings, now, classifier)
            async with engine.connect() as conn:
                signal = (await gather.signals(conn, [case_id])).get(case_id)
            briefer = None
            if settings.incident.brief != "off":  # the same brief the assessment pass writes
                try:
                    privacy = Privacy.build(
                        load_policy(), privacy_map(settings), settings.site.own_networks
                    )
                except (NoAssetMapError, PrivacyConfigError, ValueError):
                    privacy = None
                if privacy is not None:
                    briefer, said = run.briefer_for(settings, privacy, engine)
                    if said:
                        typer.echo(said, err=True)
            try:
                made = await run.make(engine, case_id, ctx, briefer=briefer)
            finally:
                if briefer is not None and briefer.close is not None:
                    await briefer.close()
            if made is None or signal is None:
                raise CaseRefused("not_found", f"no case {ref}")
            report, note = made.report, ""
            if not dry_run:
                stored, new = await run.write(engine, made, run.key_of(signal, ctx), now)
                assert stored is not None
                report = stored.report
                note = (f"stored as version {stored.version}" if new
                        else f"unchanged: version {stored.version} stands")  # fmt: skip
            out = plain.lines(report)
            if pdf is not None:
                pdf.write_bytes(files.pdf(report))
                out.append(f"wrote {pdf}")
            if csv_dir is not None:
                csv_dir.mkdir(parents=True, exist_ok=True)
                named = (
                    (files.indicators_name(report), files.indicators_csv(report)),
                    (files.affected_name(report), files.affected_csv(report)),
                    *(
                        [(files.accounts_name(report), files.accounts_csv(report))]
                        if files.has_accounts(report)
                        else []
                    ),
                )
                for name, data in named:
                    (csv_dir / name).write_bytes(data.encode("utf-8"))
                    out.append(f"wrote {csv_dir / name}")
            return [*out, note] if note else out
        except CaseRefused as exc:
            typer.echo(f"refused ({exc.code}): {_shown(exc.message)}", err=True)
            raise typer.Exit(1 if exc.code != "invalid" else 2) from None
        except ConfigError as exc:
            typer.echo(f"error: {_shown(exc)}", err=True)
            raise typer.Exit(1) from None
        except DB_ERRORS as exc:
            typer.echo(f"error: {_shown(short_db_error(exc))}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()

    for line in asyncio.run(go()):
        typer.echo(line)


known_app = typer.Typer(
    no_args_is_help=True, help="Cases whose owner was told: the known infection."
)
case_app.add_typer(known_app, name="known")


@known_app.command("status")
def known_status(config: ConfigOption = None) -> None:
    """Every notified case: how long, how many alerts ARGUS counted instead of raising, the
    changes it raised, and the suggestions waiting for a person."""

    async def use(conn: AsyncConnection, _: Settings) -> list[str]:
        out = []
        for c in await knownview.notified(conn, datetime.now(UTC)):
            kind = (
                ""
                if c.managed is None
                else (site.say(" [{kind}-managed]") if c.managed else " [personal]")
            )
            out.append(f"case {c.number}{kind}: {c.line(ist_day)}")
            out.append(
                f"  {c.devices} device(s), {c.owner_notices} notice(s), {c.blocks} block(s),"
                f" alerts a day: {c.trend}"
            )
            out += [f"  suggestion: {r.why}" for r in c.reminders]
            out += [f"  changed: {x.why} (investigation {x.investigation_id})" for x in c.changes]
            if c.new_total:
                listed = ", ".join(d.value for d in c.new_destinations[:5])
                more = c.new_total - min(len(c.new_destinations), 5)
                out.append(
                    f"  {c.new_total} new destination(s) since notice: {listed}"
                    + (f" and {more} more" if more > 0 else "")
                )
        return out

    for line in _go(config, use, write=False) or ["no notified cases"]:
        typer.echo(_shown(line))


@known_app.command("run")
def known_run(config: ConfigOption = None) -> None:
    """One pass of the known infections now, as the assessment service makes it after every
    read of the evidence: new investigations of notified devices are decided (known or changed),
    a moved address is noted, reminders are suggested, a quiet case is proposed for closing."""
    settings = load(config)
    try:
        assets = privacy_map(settings)
    except NoAssetMapError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None
    shared = membership.load_shared()
    try:
        privacy = Privacy.build(load_policy(), assets, settings.site.own_networks)
    except PrivacyConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None

    async def go() -> knownrun.Report:
        engine = engine_for(settings)
        try:
            view = view_of(settings.outside, lambda parent: shared.reason("domain", parent) is None)
            ctx = raising.known_for(settings, privacy, shared, view)  # as the service builds it
            assert ctx is not None
            return await knownrun.run(engine, ctx, datetime.now(UTC))
        except ConfigError as exc:
            typer.echo(f"error: {_shown(exc)}", err=True)
            raise typer.Exit(1) from None
        except DB_ERRORS as exc:
            typer.echo(f"error: {short_db_error(exc)}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()

    report = asyncio.run(go())
    typer.echo(report.line())
    for problem in report.problems:
        typer.echo(f"  problem: {_shown(problem)}", err=True)


@known_app.command("dismiss")
def known_dismiss(
    ref: CaseArg,
    kind: Annotated[str, typer.Argument(help="notify_again or network_action")],
    username: As,
    config: ConfigOption = None,
) -> None:
    """Say a suggestion (notify again, ask for network-side action) is not needed."""
    if kind not in known.REMINDER_KINDS:
        raise typer.BadParameter("the kind is notify_again or network_action")

    async def use(conn: AsyncConnection, _: Settings) -> str:
        service = await CaseService.start(conn)
        actor = await _person(conn, username)
        case_id = await _case_id(service, ref)
        if not await service.dismiss_reminder(actor, case_id, kind):
            raise CaseRefused("not_found", f"no open {kind} suggestion for case {ref}")
        return f"case {ref}: {kind} suggestion dismissed"

    typer.echo(_go(config, use))


@case_app.command("note")
def case_note(
    ref: CaseArg,
    username: As,
    body: Annotated[str, typer.Option("--text", help="the note (for people only)")],
    config: ConfigOption = None,
) -> None:
    """A note on a case, for people only: never sent to a model."""

    async def use(conn: AsyncConnection, _: Settings) -> str:
        service = await CaseService.start(conn)
        actor = await _person(conn, username)
        note_id = await service.add_note(actor, await _case_id(service, ref), body)
        return f"note {note_id} added"

    typer.echo(_go(config, use))


@case_app.command("replay")
def case_replay(ref: CaseArg, config: ConfigOption = None) -> None:
    """Rebuild the case from its events and compare it with the stored row (exit 1 if they
    differ)."""

    async def use(conn: AsyncConnection, _: Settings) -> tuple[bool, str]:
        service = await CaseService.start(conn)
        case_id = await _case_id(service, ref)
        stored = await service.get(case_id)
        try:
            rebuilt = replay(await service.events(case_id))
        except ReplayError as exc:
            return False, f"the history is broken: {exc}"
        if stored is None or not same_case(rebuilt, stored):
            return False, "the stored case differs from its history"
        return True, f"case {rebuilt.number}: its {rebuilt.version} events rebuild it exactly"

    ok, message = _go(config, use, write=False)
    typer.echo(message, err=not ok)
    if not ok:
        raise typer.Exit(1)


def _opener(config: ConfigOption, *, apply: bool, window: str | None, part: str,
            since: datetime | None = None) -> None:  # fmt: skip
    settings = load(config)
    span = settings.history.window if window is None else parse_duration(window)
    if not timedelta(hours=1) <= span <= timedelta(days=365):
        typer.echo("error: the window is 1h to 365d", err=True)
        raise typer.Exit(2)
    classifier = IpClassifier(load_asset_map(settings.assets.map_path),
                              settings.site.own_networks)  # fmt: skip

    async def go() -> opener.Report:
        engine = engine_for(settings)
        try:
            return await opener.run(engine, window=span, classifier=classifier,
                                    dry_run=not apply, part=part, since=since)  # fmt: skip
        except ConfigError as exc:
            typer.echo(f"error: {_shown(exc)}", err=True)
            raise typer.Exit(1) from None
        except DB_ERRORS as exc:
            typer.echo(f"error: {short_db_error(exc)}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()

    report = asyncio.run(go())
    reach = f"the last {format_duration(span)}"
    if since is not None:
        reach += f" and since {since:%Y-%m-%d}"
    typer.echo(f"{'' if apply else 'dry run: '}verdicts and proposals of {reach}")
    for opening in report.planned:
        typer.echo(f"  {_shown(opener.describe(opening))}")
    counts = report.counts()
    typer.echo(
        "planned: " + (", ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "nothing")
    )
    if apply:
        done = report.applied
        typer.echo(
            "applied: " + (", ".join(f"{k} {v}" for k, v in sorted(done.items())) or "nothing")
        )
        for replanned in report.replanned:
            typer.echo(f"  {_shown(replanned)}")
        for skipped in report.skipped:
            typer.echo(f"  skipped {_shown(skipped)}")


@case_app.command("backfill")
def case_backfill(
    apply: Annotated[
        bool, typer.Option("--apply", help="make the changes (default: a dry run)")
    ] = False,
    window: Annotated[
        str | None, typer.Option(help="how far back (default: history.window)")
    ] = None,
    since: Annotated[
        str, typer.Option(help="and back to this day, UTC")
    ] = opener.BACKFILL_FROM.strftime("%Y-%m-%d"),
    config: ConfigOption = None,
) -> None:
    """Cases for past verdicts and proposals, back to a fixed start date and over history.window,
    at most 20 new cases an hour. A dry run unless --apply."""
    try:
        start = datetime.strptime(since, "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError:
        typer.echo("error: --since is a day: YYYY-MM-DD", err=True)
        raise typer.Exit(2) from None
    _opener(config, apply=apply, window=window, part="backfill", since=start)


@case_app.command("sync")
def case_sync(
    dry_run: Annotated[bool, typer.Option("--dry-run", help="only say what it would do")] = False,
    config: ConfigOption = None,
) -> None:
    """Open, link or record cases for new true-positive verdicts and proposals."""
    _opener(config, apply=not dry_run, window=None, part="opener")


NO_ASSET_MAP_NOTE = (
    "note: no asset map is imported (argus assets import), so campaigns were skipped: the"
    " {own:devices} behind a domain family cannot be told apart without it; the other suggestions"
    " (a host seen by several rules, actors at the same rare targets) are made as usual"
)


@case_app.command("suggest")
def case_suggest(
    dry_run: Annotated[bool, typer.Option("--dry-run", help="only say what it would do")] = False,
    config: ConfigOption = None,
) -> None:
    """Suggest cases from evidence across the last 72 hours of unreviewed investigations:
    campaigns (several internal devices reaching one flagged destination or one operator's
    domains, from the stored names and the outside answers already cached; nothing is asked), a
    host in Needs attention seen by several rules or on several days, actors that hit the same
    rare targets. A suggested case is suspected: a person confirms or dismisses it. The
    assessment service does this every 15 minutes; this runs it once now."""
    settings = load(config)
    assets = load_asset_map(settings.assets.map_path)
    classifier = IpClassifier(assets, settings.site.own_networks)

    async def go() -> suggest.Report:
        engine = engine_for(settings)
        try:
            found: tuple[Campaign, ...] = ()
            if assets is not None:  # the internal view needs the asset map
                try:
                    privacy = Privacy.build(load_policy(), assets, settings.site.own_networks)
                except PrivacyConfigError as exc:
                    typer.echo(f"error: {exc}", err=True)
                    raise typer.Exit(1) from None
                shared = membership.load_shared()
                _, result = await campaign_lookups.evaluate(
                    engine, datetime.now(UTC), window=settings.history.window,
                    classifier=classifier,
                    view=view_of(settings.outside,
                                 lambda parent: shared.reason("domain", parent) is None),
                    eligibility=Eligibility(privacy.classifier, privacy.ours, privacy.ours_for),
                    shared=shared, resolvers=settings.campaigns.resolvers,
                )  # fmt: skip
                found = result.campaigns
            return await suggest.run(engine, classifier=classifier, dry_run=dry_run,
                                     campaigns=found,
                                     offers_per_hour=settings.cases.offers_per_hour)  # fmt: skip
        except ConfigError as exc:
            typer.echo(f"error: {_shown(exc)}", err=True)
            raise typer.Exit(1) from None
        except DB_ERRORS as exc:
            typer.echo(f"error: {short_db_error(exc)}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()

    report = asyncio.run(go())
    typer.echo(f"{'dry run: ' if dry_run else ''}unreviewed investigations of the last 72 hours")
    if assets is None:
        typer.echo(site.say(NO_ASSET_MAP_NOTE))
    for action in report.planned:
        typer.echo(f"  {_shown(suggest.describe(action))}")
    typer.echo("planned: " + suggest.words(report.counts()))
    if not dry_run:
        typer.echo("applied: " + suggest.words(report.applied))
        for skipped in report.skipped:
            typer.echo(f"  skipped {_shown(skipped)}")


@audit_app.command("verify")
def audit_verify(config: ConfigOption = None) -> None:
    """Check both hash chains, every row (exit 1 on any sign of tampering)."""

    settings = load(config)

    async def go() -> list[chain.ChainReport]:
        engine = engine_for(settings)
        try:
            return await chain.verify_snapshot(engine)
        except DB_ERRORS as exc:
            typer.echo(f"error: {short_db_error(exc)}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()

    reports = asyncio.run(go())
    for report in reports:
        typer.echo(f"{'PASS' if report.ok else 'FAIL'}  {report.chain}  {report.summary()}")
    if not all(r.ok for r in reports):
        raise typer.Exit(1)


@audit_app.command("head")
def audit_head(config: ConfigOption = None) -> None:
    """The chains' heads: write them down (or let the daily report keep them) to anchor the
    chain outside the database."""

    async def use(conn: AsyncConnection, _: Settings) -> dict[str, tuple[int, str]]:
        return await chain.heads(conn)

    for name, (seq, head) in sorted(_go(config, use, write=False).items()):
        typer.echo(f"{name}  {seq}  {head}")


approvals_app = typer.Typer(
    no_args_is_help=True,
    help="Closure approvals: signing keys, ARGUS's proposals, send-time checks.",
)
KeyOption = Annotated[
    list[Path],
    typer.Option("--key", help="a key file the writer accepts (repeat for a rotation)"),
]
Apply = Annotated[bool, typer.Option("--apply", help="do it (without: a dry run)")]


@approvals_app.command("keygen")
def approvals_keygen(
    path: Annotated[Path, typer.Argument(help="the new key file (refused if it exists)")],
) -> None:
    """A new approval signing key (mode 0600). The web signs with it; the writer is given the
    same file to verify (root-owned credentials under custody)."""
    key = signing.new_key()
    try:
        signing.write_key(path, key)
    except OSError as exc:
        typer.echo(f"error: {path}: {exc.strerror}", err=True)
        raise typer.Exit(1) from None
    typer.echo(f"wrote approval key {key.key_id} to {path}")


def _verifier(keys: list[Path]) -> signing.Verifier:
    if not keys:
        typer.echo("error: give the writer's key file(s) with --key", err=True)
        raise typer.Exit(2)
    try:
        return signing.Verifier([signing.load_key(path) for path in keys])
    except signing.KeyFileError as exc:
        typer.echo(f"error: {_shown(exc)}", err=True)
        raise typer.Exit(1) from None


@approvals_app.command("check-send")
def approvals_check_send(
    key: KeyOption,
    outbox: Annotated[int | None, typer.Option(help="only this outbox row")] = None,
    apply: Apply = False,
    config: ConfigOption = None,
) -> None:
    """The send-time checks of every closure write waiting in the outbox (nothing is sent to
    Kibana: the writer does that). With ``--apply`` each verdict is applied to the row: let go,
    held back for a re-confirmation, refused or skipped."""
    verifier = _verifier(key)

    async def use(conn: AsyncConnection, _: Settings) -> list[sendcheck.SendCheck]:
        ids = [outbox] if outbox is not None else await sendcheck.held(conn)
        if apply:
            return [await sendcheck.release(conn, i, verifier) for i in ids]
        return [await sendcheck.check(conn, i, verifier) for i in ids]

    found = _go(config, use, write=apply)
    for result in found:
        expired = " (approval expired unsent)" if result.expired_unsent else ""
        typer.echo(f"outbox {result.outbox_id}: {_shown(result.summary)}{expired}")
    if not found:
        typer.echo("no closure write is waiting")


@approvals_app.command("propose")
def approvals_propose(apply: Apply = False, config: ConfigOption = None) -> None:
    """ARGUS's closure proposals (benign or false-positive cases every member of which people
    reviewed so; contained cases with a verified quiet window). A person approves each one."""

    async def use(conn: AsyncConnection, settings: Settings) -> list[str]:
        finder = watchrun.Finder(conn, watchrun.context_for(settings))
        found = await proposer.candidates(conn, windows=finder)
        if not apply:
            return [f"would propose case {c.number} as {c.reason}: {c.evidence}" for c in found]
        service = await CaseService.start(conn, finder)
        lines = []
        for candidate in found:
            done = await proposer.propose(service, candidate)
            lines.append(
                f"case {candidate.number}: proposed as {candidate.reason}"
                f" (request {done.request_id})"
                if done.request_id is not None
                else f"case {candidate.number}: not proposed ({done.refused})"
            )
        return lines

    lines = _go(config, use, write=apply)
    for line in lines or ["nothing to propose"]:
        typer.echo(_shown(line))


@approvals_app.command("apply")
def approvals_apply(config: ConfigOption = None) -> None:
    """Close or merge the cases whose approval is complete but was recorded by the web's own
    login (which cannot change cases), as the person whose approval completed it. One that
    cannot be applied (a merge whose target closed meanwhile) is reported and the rest go on."""

    async def use(conn: AsyncConnection, _: Settings) -> list[str]:
        ids = (
            await conn.execute(
                text(
                    "SELECT r.id FROM approval_requests r JOIN cases c ON c.id = r.case_id"
                    " WHERE r.kind IN ('closure', 'merge') AND c.version = r.case_version"
                    " AND c.state <> 'closed' ORDER BY r.id"
                )
            )
        ).scalars()
        service = await CaseService.start(conn)
        lines = []
        for request_id in list(ids):
            try:
                async with conn.begin_nested():
                    done = await service.apply_approved(int(request_id))
            except CaseRefused as exc:
                lines.append(f"request {request_id}: not applied ({exc.message})")
                continue
            except ApprovalError as exc:
                lines.append(f"request {request_id}: not applied ({exc.message})")
                continue
            for applied in done:
                lines.append(f"case {applied.case.number}: {applied.step.kind} (request"
                             f" {request_id})")  # fmt: skip
        return lines

    for line in _go(config, use) or ["nothing to apply"]:
        typer.echo(_shown(line))


@approvals_app.command("ledger")
def approvals_ledger(config: ConfigOption = None) -> None:
    """The autonomy ledger: what people did with ARGUS's proposals, class by class, and
    the approvals that expired unsent. Nothing closes on its own."""

    async def use(conn: AsyncConnection, _: Settings) -> autonomy.Ledger:
        return await autonomy.ledger(conn)

    found = _go(config, use, write=False)
    typer.echo(f"approvals expired unsent: {found.expired_unsent_rate.text()}")
    typer.echo(f"requests expired before anyone decided: {found.expired_undecided}")
    typer.echo(f"approved writes rightly skipped (reopened or rejected): {found.skipped_writes}")
    if not found.classes:
        typer.echo("ARGUS has proposed no closure yet")
    for line in found.classes:
        typer.echo(
            f"{line.reason}: {line.proposed} proposed, {line.approved} approved,"
            f" {line.rejected} rejected, {line.reopened} reopened, {line.pending} waiting,"
            f" {line.expired_undecided} expired, {line.revoked} approved by someone revoked"
            f" since; right {line.right.text()}"
        )
        typer.echo("  still needs: " + "; ".join(line.missing()))


watch_app = typer.Typer(no_args_is_help=True, help="The daily still-active watch of open cases.")
case_app.add_typer(watch_app, name="watch")


def _gateway(settings: Settings, engine: Any) -> tuple[Any, Any]:
    """The Elastic Gateway for the watch's proxy-log questions (a seam for the tests)."""
    from argus.gateway.service import build_gateway

    return build_gateway(settings.siem, engine)


def _lines(report: watchrun.Report) -> list[str]:
    lines = [f"mode: {report.mode}; {len(report.cases)} case(s) watched; {report.asked} request(s)"]
    for case in report.cases:
        done = ", ".join(f"{n} {k}" for k, n in sorted(case.rows.items())) or "no new answers"
        lines.append(f"case {case.number} ({case.state}): {done}")
        if case.joined or case.followed or case.suggested or case.cut_off:
            lines.append(
                f"  joined {case.joined}, following {case.followed}, suggested {case.suggested},"
                f" cut off {case.cut_off}"
            )
        lines += [f"  {event}" for event in case.events]
        lines += [f"  {note}" for note in case.notes]
    lines += [f"problem: {problem}" for problem in report.problems]
    return lines


@watch_app.command("run")
def watch_run(
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="read and plan only: change and ask nothing")
    ] = False,
    local_only: Annotated[
        bool, typer.Option("--local-only", help="ARGUS's own alerts only: ask the SIEM nothing")
    ] = False,
    config: ConfigOption = None,
) -> None:
    """Run the still-active watch once (every open true-positive case: new activity, the day's
    answers from ARGUS's own alerts and, in mode "on", the proxy logs). Once a day, after
    01:30 UTC. Does nothing while cases.watch is off."""
    settings = load(config)
    mode = "local" if local_only else settings.cases.watch
    if settings.cases.watch == "off":
        typer.echo("the still-active watch is off (cases.watch): nothing was done")
        return

    async def go() -> watchrun.Report:
        engine = engine_for(settings)
        gateway: Any = None
        try:
            ctx = watchrun.context_for(settings)
            if mode == "on" and not dry_run:
                gateway, _state = _gateway(settings, engine)
                asker = watchrun.GatewayAsker(
                    gateway, engine, enabled=settings.enrichment.templates,
                    history=settings.history.window, is_own=ctx.is_own,
                    health_config=health_config(settings.siem),
                )  # fmt: skip
                ctx = replace(ctx, asker=asker)
            return await watchrun.run(
                engine, ctx, now=datetime.now(UTC), apply=not dry_run, mode=mode
            )
        except DB_ERRORS as exc:
            typer.echo(f"error: {_shown(short_db_error(exc))}", err=True)
            raise typer.Exit(1) from None
        except ConfigError as exc:
            typer.echo(f"error: {_shown(exc)}", err=True)
            raise typer.Exit(1) from None
        finally:
            if gateway is not None:
                await gateway.transport.aclose()
            await engine.dispose()

    report = asyncio.run(go())
    for line in _lines(report):
        typer.echo(("dry run: " if dry_run and line.startswith("mode") else "") + _shown(line))
    if report.problems:
        raise typer.Exit(1)


@watch_app.command("status")
def watch_status(ref: CaseArg, config: ConfigOption = None) -> None:
    """What the watch can say about a case: the last days' answers (a question left open says
    "not checked: <reason>"), the suspected cases that follow it, and whether it is verifiably
    quiet for 72 hours."""

    async def use(conn: AsyncConnection, settings: Settings) -> list[str]:
        ctx = watchrun.context_for(settings)  # a configuration error first, before any lookup
        service = await CaseService.start(conn)
        case_id = await _case_id(service, ref)
        return await watchrun.status(conn, ctx, case_id, datetime.now(UTC))

    typer.echo(f"watch mode: {load(config).cases.watch}")
    for line in _go(config, use, write=False):
        typer.echo(_shown(line))


@case_app.command("suggestions")
def case_suggestions(
    dismiss: Annotated[
        int | None, typer.Option("--dismiss", help="dismiss this suggestion (needs --as)")
    ] = None,
    username: Annotated[str | None, typer.Option("--as", help="the person dismissing")] = None,
    config: ConfigOption = None,
) -> None:
    """Investigations that may belong to a case but were not joined: their only match is a shared
    address or name, or they match several cases equally. Join one with `argus case link`."""

    async def use(conn: AsyncConnection, _: Settings) -> list[str]:
        if dismiss is not None:
            if username is None:
                raise CaseRefused("invalid", "dismissing a suggestion needs --as <username>")
            actor = await _person(conn, username)
            done = await conn.execute(
                text(
                    "UPDATE case_suggestions SET dismissed_at = now(), dismissed_by = :u"
                    " WHERE id = :i AND dismissed_at IS NULL RETURNING investigation_id, case_id"
                ),
                {"u": actor.user_id, "i": dismiss},
            )
            row = done.first()
            if row is None:
                raise CaseRefused("not_found", f"no open suggestion {dismiss}")
            session = AsyncSession(bind=conn)
            try:  # a person's action: audited as user:<id> like the others
                await record_audit(
                    session, actor=actor.name, action="case.suggestion_dismissed",
                    target_type="case", target_id=str(row.case_id),
                    details={"suggestion": dismiss, "investigation": str(row.investigation_id),
                             "via": actor.via},
                )  # fmt: skip
            finally:
                await session.close()
            return [f"suggestion {dismiss} dismissed"]
        rows = await conn.execute(
            text(
                "SELECT s.id, c.number, c.state, s.investigation_id, s.kind, s.why FROM"
                " case_suggestions s JOIN cases c ON c.id = s.case_id WHERE s.dismissed_at IS NULL"
                " AND NOT EXISTS (SELECT 1 FROM case_members m WHERE m.investigation_id ="
                " s.investigation_id AND m.removed_at IS NULL) ORDER BY s.id"
            )
        )
        return [
            f"{r.id:>5}  investigation {r.investigation_id} -> case {r.number} ({r.state})"
            f" [{r.kind}] {r.why}"
            for r in rows
        ]

    lines = _go(config, use, write=dismiss is not None)
    for line in lines or ["no suggestions"]:
        typer.echo(_shown(line))


def _action_lines(number: int, state: str, views: list[Any]) -> list[str]:
    from argus.responder import machine

    lines = [f"case {number} ({state}): {len(views)} advised action(s); advice only, nothing runs"]
    for n, v in enumerate(views, 1):
        lines.append(f"{n:>2}. {v.action}  [{v.state}]  {v.title}  (owner: {v.owner_name})")
        lines.append(f"      {v.say}")
        lines.append(f"      {v.detail}")
        if v.attestation:
            lines.append(f"      their words: {v.attestation}")
        if v.state == "not_verified" and v.last_beat is not None:
            lines.append(f"      last sign of activity: {machine.ist12(v.last_beat)}")
    return lines


@case_app.command("actions")
def case_actions(
    ref: CaseArg,
    recommend: Annotated[
        bool, typer.Option("--recommend", help="record the advice and ARGUS's verdicts")
    ] = False,
    request: Annotated[
        str | None, typer.Option("--request", help="an action id: its owner was asked (needs --as)")
    ] = None,
    done: Annotated[
        str | None, typer.Option("--done", help="an action id: it was done (needs --as, --attest)")
    ] = None,
    attest: Annotated[
        str | None, typer.Option("--attest", help="in your words, what was done and by whom")
    ] = None,
    username: Annotated[str | None, typer.Option("--as", help="the person reporting")] = None,
    config: ConfigOption = None,
) -> None:
    """What ARGUS advises for a case, who was asked, what was reported done, and whether the case
    then went quiet. Advice only: nothing is executed, and
    no model is asked. A person's "done" is an attestation."""
    from argus.responder import store
    from argus.responder.machine import ActionRefused

    writes = recommend or request is not None or done is not None
    if (request is not None or done is not None) and username is None:
        raise typer.BadParameter("recording a request or a report needs --as <username>")
    if (request is not None) + (done is not None) + recommend > 1:
        raise typer.BadParameter("give one of --recommend, --request and --done")
    if done is not None and attest is None:
        raise typer.BadParameter("--done needs --attest, in your own words")

    async def use(conn: AsyncConnection, settings: Settings) -> list[str]:
        try:
            ctx: watchrun.Context | None = watchrun.context_for(settings)
        except (ConfigError, OSError):
            ctx = None  # without the watch's settings an action can be found not verified only
        service = await CaseService.start(conn)
        case_id = await _case_id(service, ref)
        case = await service.get(case_id)
        assert case is not None
        now = datetime.now(UTC)
        notes = [] if ctx is not None else ["watch settings unavailable: nothing can be verified"]
        try:
            if recommend:
                new = await store.recommend(conn, case_id, now)
                notes.append(f"recorded {len(new)} new recommendation(s)")
                moved = await store.refresh(conn, case_id, now, ctx=ctx)
                notes += [f"{action} is now {state}" for action, state in moved]
            elif request is not None:
                assert username is not None
                await store.request(conn, case_id, request, await _person(conn, username), now)
                notes.append(f"{request}: request recorded")
            elif done is not None:
                assert username is not None
                assert attest is not None
                person = await _person(conn, username)
                await store.report_done(conn, case_id, done, person, attest, now)
                notes.append(f"{done}: reported done (an attestation)")
            views = await store.actions_for(conn, case_id, ctx=ctx, now=now)
        except ActionRefused as exc:
            raise CaseRefused(exc.code, exc.message) from None
        return [*notes, *_action_lines(case.number, case.state, views)]

    for line in _go(config, use, write=writes):
        typer.echo(_shown(line))


@case_app.command("actions-sync")
def case_actions_sync(config: ConfigOption = None) -> None:
    """Record the advice for every confirmed case and ARGUS's verdict on every reported "done"
    (a timer runs this after the daily watch). Advice only: nothing is executed, no model is
    asked, the SIEM is not contacted."""
    from argus.cases.model import CONFIRMED
    from argus.responder import store
    from argus.responder.machine import ActionRefused

    async def use(conn: AsyncConnection, settings: Settings) -> list[str]:
        try:
            ctx: watchrun.Context | None = watchrun.context_for(settings)
        except (ConfigError, OSError):
            ctx = None
        now = datetime.now(UTC)
        lines = []
        if ctx is None:
            lines.append("watch settings unavailable: nothing can be verified")
        for watched in await watchrun.watched(conn, now):
            try:
                # one savepoint for each case: a case that cannot be recorded (odd stored data, a
                # refusal of the database) is a problem line and rolls back only itself
                async with conn.begin_nested():
                    new: list[str] = []
                    if watched.state in CONFIRMED:  # a closed case keeps its actions
                        try:
                            new = await store.recommend(conn, watched.id, now)
                        except ActionRefused as exc:
                            lines.append(f"case {watched.number}: {exc.message}")
                    moved = await store.refresh(conn, watched.id, now, ctx=ctx)
            except Exception as exc:
                lines.append(f"case {watched.number}: could not be recorded ({type(exc).__name__})")
                continue
            if new or moved:
                said = [f"{len(new)} recommended"] if new else []
                said += [f"{action} is now {state}" for action, state in moved]
                lines.append(f"case {watched.number}: " + ", ".join(said))
        return lines or ["nothing to record"]

    for line in _go(config, use):
        typer.echo(_shown(line))


#  the case team (docs/runbooks/kibana-case-team.md)
from argus.caseteam.cli import team_app  # noqa: E402

case_app.add_typer(team_app, name="team")
