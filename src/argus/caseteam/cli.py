"""``argus case team ...``: the case team at the terminal.

* ``preview <n>``: exactly what would be sent for case ``n``, as a dry run (nothing is written, no
  Kibana key is read); works while ``case_team.post`` is off.
* ``status [<n>]``: the posts and their steps, and what the read-back last saw of each Kibana case.
* ``run [<n>]``: post now. A person at a terminal types ``WC``; ``--unattended`` is for a timer and
  needs ``case_team.post`` and the class ``WC`` on. One lock: a second run does nothing meanwhile.
  Run it in the writer's account (``sudo argus-owner --as writer case team run``).
* ``sync``: read the posted cases' comments for a person's ``Verdict:`` now.
* ``refresh <n> [--apply]``: correct a posted case in place (title, description, comments); a dry
  run by default. What a person changed in Kibana is never overwritten.
* ``resend <step>`` and ``skip <step> --reason``: decide a step the four looks did not find in
  Kibana (or one that failed or was held).
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import date
from pathlib import Path
from typing import Annotated, Any

import typer
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.caseteam import service, store, verdicts
from argus.caseteam.model import EDIT_KINDS
from argus.caseteam.sender import Poster, Prepared
from argus.config.errors import ConfigError
from argus.config.settings import Settings
from argus.db.engine import create_engine
from argus.gateway.cli import ConfigOption, _human_at_a_terminal, engine_for, load
from argus.incident.plain import printable

team_app = typer.Typer(no_args_is_help=True, help="The case team's posts in Kibana.")
CaseArg = Annotated[int, typer.Argument(help="the case's number")]


async def _case_id(engine: AsyncEngine, number: int) -> uuid.UUID:
    async with engine.connect() as conn:
        found = (
            await conn.execute(text("SELECT id FROM cases WHERE number = :n"), {"n": number})
        ).scalar_one_or_none()
    if found is None:
        typer.echo(f"error: no case {number}", err=True)
        raise typer.Exit(1)
    return uuid.UUID(str(found))


def _writer_engine(settings: Settings) -> AsyncEngine:
    try:
        return create_engine(settings.database, role="writer")
    except ConfigError:
        typer.echo(
            "error: the writer's database login is not set up here: run this in the writer's"
            " account (sudo argus-owner --as writer case team ...)",
            err=True,
        )
        raise typer.Exit(2) from None


def _lines(prep: Prepared, poster: Poster, *, text_: bool, requests: bool) -> list[str]:
    out: list[str] = []
    d = prep.decision
    out.append(f"case {prep.number} ({prep.state})")
    if prep.stored is None:
        return [*out, f"decision: {d.action} ({d.why})"]
    report = prep.stored.report
    out.append(f"incident {report.header.incident_id}, report version {prep.stored.version}")
    verdict = report.verdict
    sure = "" if verdict.confidence is None else f" ({verdict.confidence:.2f})"
    out.append(f"ARGUS's {verdict.kind}: {verdict.outcome or 'none'}{sure}")
    say = d.action if not d.dry_run else f"{d.would} (dry run: posting is off)"
    out.append(f"decision: {say}: {d.why}")
    if d.route:
        out.append(f"route: {d.route}")
    if d.needs_approval:
        out.append(
            "canary: needs a person's approval of this case"
            + (" (given)" if prep.approval is None else f" ({prep.approval})")
        )
    for problem in prep.problems:
        out.append(f"stops sending: {problem}")
    for note in prep.notes:
        out.append(f"note: {note}")
    if prep.plan is None:
        return out
    out.append(f"plan {prep.plan.plan_hash[:16]}: {len(prep.plan.steps)} steps")
    texts = {s.key: s.text for s in prep.plan.steps}
    sent = poster.requests(prep) if requests else []
    for n, step in enumerate(prep.plan.steps, 1):
        out.append(f"  {n:>2}. {step.describe()}  [{step.key}]")
        if requests:
            r = sent[n - 1]
            out.append(f"      {r['method']} {r['path']} ({r['content_type']})")
            if step.kind != "comment" and step.kind != "open":
                out.append(f"      {r['body'][:400]}")
        if text_ and texts.get(step.key):
            out += ["      | " + line for line in str(texts[step.key]).split("\n")]
    return [printable(x) for x in out]


@team_app.command("preview")
def preview(
    number: CaseArg,
    text_: Annotated[bool, typer.Option("--text", help="print every comment in full")] = False,
    requests: Annotated[
        bool, typer.Option("--requests", help="print each step's request (method, path, body)")
    ] = False,
    config: ConfigOption = None,
) -> None:
    """What would be sent for the case, as a dry run: nothing is written to the SIEM or Kibana, and
    no Kibana key is needed."""
    settings = load(config)

    async def go() -> list[str]:
        engine = engine_for(settings)
        try:
            case_id = await _case_id(engine, number)
            poster = service.preview_poster(settings, engine)
            async with engine.connect() as conn:
                prep = await poster.prepare(conn, case_id)
            return _lines(prep, poster, text_=text_, requests=requests)
        finally:
            await engine.dispose()

    for line in asyncio.run(go()):
        typer.echo(line)


def _read_back(r: Any) -> str:
    """What the read-back (``argus-kibana-sync``) last saw of the post's Kibana case."""
    if r.kibana_case_id is None:
        return "read back: not in Kibana yet"
    if r.deleted_at is not None:
        return (
            f"read back: DELETED in Kibana (found {r.deleted_at:%Y-%m-%d %H:%M} UTC);"
            " nothing more is posted to it, ARGUS keeps its own record"
        )
    if r.read_at is None:
        return "read back: not read yet"
    said = f"read back: Kibana status {r.kibana_status}, read {r.read_at:%Y-%m-%d %H:%M} UTC"
    if r.unmanaged:
        said += f"; a person changed {', '.join(sorted(r.unmanaged))}"
    if r.paused_reason:
        said += f"; paused: {r.paused_reason}"
    return said


@team_app.command("status")
def status(
    number: Annotated[int | None, typer.Argument(help="a case's number")] = None,
    config: ConfigOption = None,
) -> None:
    """The posts and the state of their steps."""
    settings = load(config)

    async def go() -> list[str]:
        engine = engine_for(settings)
        try:
            async with engine.connect() as conn:
                rows = (
                    await conn.execute(
                        text(
                            "SELECT c.number, p.incident_id, p.kibana_case_id, p.state,"
                            " p.held_reason, p.opened_at, p.last_version, c.id AS cid,"
                            " m.status AS kibana_status, m.read_at, m.deleted_at,"
                            " m.paused_reason, m.unmanaged"
                            " FROM case_team_posts p JOIN cases c ON c.id = p.case_id"
                            " LEFT JOIN kibana_mirror m ON m.case_id = p.case_id"
                            " WHERE (CAST(:n AS integer) IS NULL OR c.number = CAST(:n AS integer))"
                            " ORDER BY c.number"
                        ),
                        {"n": number},
                    )
                ).all()
                out: list[str] = []
                for r in rows:
                    out.append(
                        f"case {r.number}: {r.incident_id} kibana={r.kibana_case_id or '-'}"
                        f" {r.state}"
                        + (f" ({r.held_reason})" if r.held_reason else "")
                        + f", report version {r.last_version or '-'}"
                    )
                    out.append("    " + _read_back(r))
                    counts: dict[str, int] = {}
                    for s in await store.steps_of(conn, r.cid):
                        counts[s.state] = counts.get(s.state, 0) + 1
                        left = s.state == "skipped" and s.kind in EDIT_KINDS  # a person's edit
                        if left or s.state in ("ambiguous", "resend", "failed", "held"):
                            out.append(f"    step {s.id} {s.key}: {s.state} {s.state_reason or ''}")
                    out.append(
                        "    steps: " + ", ".join(f"{n} {k}" for k, n in sorted(counts.items()))
                    )
                return [printable(x) for x in out] or ["no case has been posted"]
        finally:
            await engine.dispose()

    for line in asyncio.run(go()):
        typer.echo(line)


@team_app.command("run")
def run(
    number: Annotated[int | None, typer.Argument(help="a case's number; omit for a pass")] = None,
    unattended: Annotated[
        bool, typer.Option("--unattended", help="no prompt (a timer); needs the switches on")
    ] = False,
    config: ConfigOption = None,
) -> None:
    """Post now: one case, or a pass over the cases that qualify (the unfinished first)."""
    settings = load(config)
    problems = service.gate_problems(settings)
    if problems:
        for problem in problems:
            typer.echo(f"cannot post: {problem}", err=True)
        raise typer.Exit(2)
    if not unattended:
        if not _human_at_a_terminal():
            typer.echo("error: this is done by a person at a terminal (or --unattended)", err=True)
            raise typer.Exit(2)
        typer.echo("This writes to Kibana on the SIEM as the six case team users (class WC).")
        if typer.prompt("Type WC to confirm") != "WC":
            typer.echo("not confirmed", err=True)
            raise typer.Exit(1)

    async def go() -> list[str]:
        engine = _writer_engine(settings)
        try:
            poster = service.build_poster(settings, engine, wait_for_gaps=True)
            await poster.housekeeping()
            if number is not None:
                reports = [await poster.run_case(await _case_id(engine, number))]
            else:
                reports = await poster.run_pass()
            return [printable(line) for r in reports for line in r.lines()] or ["nothing to do"]
        finally:
            await engine.dispose()

    for line in asyncio.run(go()):
        typer.echo(line)


@team_app.command("sync")
def sync(config: ConfigOption = None) -> None:
    """Read the posted cases' comments for a person's ``Verdict:`` and record each as a label."""
    settings = load(config)
    if not settings.kibana.enabled:
        typer.echo("error: kibana.enabled is false: the Kibana lane is off", err=True)
        raise typer.Exit(2)

    async def go() -> list[str]:
        from argus.gateway.kibana.service import build_kibana_gateway
        from argus.gateway.service import build_gateway

        engine = engine_for(settings)
        try:
            es, lane = build_gateway(settings.siem, engine)
            gateway = build_kibana_gateway(settings, lane, es_gateway=es)
            report = await verdicts.read_all(
                engine,
                gateway,
                service_user=settings.kibana.service_user,
                elk=settings.web.elk_signin,
            )
            return report.lines()
        finally:
            await engine.dispose()

    for line in asyncio.run(go()):
        typer.echo(line)


@team_app.command("refresh")
def refresh(
    number: CaseArg,
    apply: Annotated[
        bool, typer.Option("--apply", help="plan the edits (the next run sends them)")
    ] = False,
    config: ConfigOption = None,
) -> None:
    """Correct a posted case in place: title, description and comments as the newest report
    renders them. A dry run unless ``--apply``; applying only plans, it writes nothing to Kibana."""
    settings = load(config)
    if apply:
        _decide(
            "REFRESH",
            f"Case {number}'s title, description and comments in Kibana will be rewritten from"
            " the newest report by the case team's next run (what a person changed there is left).",
        )

    async def go() -> list[str]:
        engine = _writer_engine(settings) if apply else engine_for(settings)
        try:
            poster = service.refresh_poster(settings, engine, writer=apply)
            found = await poster.refresh(await _case_id(engine, number), apply=apply)
            return [printable(line) for line in found.lines()]
        finally:
            await engine.dispose()

    for line in asyncio.run(go()):
        typer.echo(line)


def _decide(word: str, what: str) -> None:
    if not _human_at_a_terminal():
        typer.echo("error: this is done by a person at a terminal", err=True)
        raise typer.Exit(2)
    typer.echo(what)
    if typer.prompt(f"Type {word} to confirm") != word:
        typer.echo("not confirmed", err=True)
        raise typer.Exit(1)


@team_app.command("resend")
def resend(
    step: Annotated[int, typer.Argument(help="the step's id (argus case team status)")],
    config: ConfigOption = None,
) -> None:
    """Send a step once more that four looks did not find in Kibana (a person's decision)."""
    settings = load(config)
    _decide("RESEND", f"Step {step} was not found in Kibana: it will be sent once more.")

    async def go() -> bool:
        engine = _writer_engine(settings)
        try:
            return await service.preview_poster(settings, engine).resend(step, by=_operator())
        finally:
            await engine.dispose()

    typer.echo(
        "planned to be sent again"
        if asyncio.run(go())
        else "that step is not waiting for a decision"
    )


@team_app.command("skip")
def skip(
    step: Annotated[int, typer.Argument(help="the step's id")],
    reason: Annotated[str, typer.Option(help="why (kept with the step)")],
    config: ConfigOption = None,
) -> None:
    """A step that cannot or should not go on (or was done by hand in Kibana) is never sent."""
    settings = load(config)
    _decide("SKIP", f"Step {step} will never be sent; the steps after it go on.")

    async def go() -> bool:
        engine = _writer_engine(settings)
        try:
            return await service.preview_poster(settings, engine).skip(
                step, by=_operator(), reason=reason[:300]
            )
        finally:
            await engine.dispose()

    try:
        done = asyncio.run(go())
    except ValueError as refused:
        typer.echo(f"refused: {refused}", err=True)
        raise typer.Exit(1) from None
    typer.echo("skipped" if done else "that step cannot be skipped")


def _operator() -> str:
    import os

    return os.environ.get("SUDO_USER") or os.environ.get("USER") or "operator"


@team_app.command("provision")
def provision_cmd(
    apply_: Annotated[
        bool, typer.Option("--apply", help="Make it on the SIEM (default: print the plan only).")
    ] = False,
    admin_user: Annotated[
        str | None,
        typer.Option("--admin-user", help="The administrator's user name (else it is asked)."),
    ] = None,
    credentials: Annotated[
        Path | None,
        typer.Option(help="Where the keys go (default: local/creds-writer in the checkout)."),
    ] = None,
    without_visualiser: Annotated[
        bool, typer.Option("--without-visualiser", help="Leave out the optional seventh user.")
    ] = False,
    expiration: Annotated[int, typer.Option(help="Days the API keys last.")] = 365,
    config: ConfigOption = None,
) -> None:
    """Make the case team's Kibana users from one administrator login: two roles in the
    site's space, seven users with passwords nobody sees, one API key each, written to the writer's
    credential folder (mode 600). The login is asked once and never stored, printed or logged.
    Without --apply it prints the plan and sends nothing. Posting stays off afterwards."""
    import getpass
    import os
    from datetime import UTC, datetime

    from argus import site
    from argus.caseteam import provision
    from argus.config.settings import DEFAULT_CONFIG_PATH
    from argus.config.sources import CONFIG_ENV_VAR
    from argus.install import files
    from argus.ops.units import REPO

    settings = load(config)
    folder = credentials or REPO / "local" / "creds-writer"
    try:
        plan = provision.plan_for(
            settings.site, folder, visualiser=not without_visualiser, expiration_days=expiration
        )
    except provision.ProvisionError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from None
    if not apply_:
        for line in provision.describe(plan):
            typer.echo(line)
        return
    if settings.siem.url is None or settings.siem.ca_file is None:
        typer.echo("error: siem.url and siem.ca_file are not set: run argus init first", err=True)
        raise typer.Exit(2)
    if site.in_quiet_hours(datetime.now(UTC)):
        hours = site.quiet_hours()
        typer.echo(
            f"error: the SIEM's quiet hours ({hours.start}-{hours.end} UTC): try later", err=True
        )
        raise typer.Exit(1)
    user = admin_user or typer.prompt("Elasticsearch administrator user name")
    secret = getpass.getpass("Password (not shown): ")
    siem = provision.HttpSiem(
        str(settings.siem.url), Path(settings.siem.ca_file), user, secret, say=typer.echo
    )
    del secret
    try:
        out = provision.apply(plan, siem, say=typer.echo)
    except provision.ProvisionError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None
    finally:
        siem.close()
    if out.expires is not None:
        config_path = config or Path(os.environ.get(CONFIG_ENV_VAR) or DEFAULT_CONFIG_PATH)
        local = config_path.parent / "local.yaml"
        recorded = files.get(files.read_yaml(local), "case_team.keys_expire")
        expires = min(out.expires, recorded) if isinstance(recorded, date) else out.expires
        files.update_yaml(local, {"case_team.keys_expire": expires})
        typer.echo(f"case_team.keys_expire: {expires} (config/local.yaml)")
    typer.echo(
        f"case team: {len(out.made)} made, {len(out.rekeyed)} new keys, {len(out.kept)} kept."
        " Posting stays off: docs/case-team.md says how to switch it on."
    )
