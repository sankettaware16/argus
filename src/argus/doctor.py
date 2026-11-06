"""``argus doctor``: quick, read-only health checks. Later components register their own checks.

The database checks log in as the runtime role, so they see what ARGUS itself can see.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from alembic.script.revision import RevisionError
from alembic.util import CommandError
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import site
from argus.assets import AssetMapError, load_asset_map
from argus.cases import chain
from argus.config.durations import format_duration
from argus.config.settings import ConfigError, Settings
from argus.db import migrate, roles
from argus.db.engine import create_engine
from argus.db.errors import DB_ERRORS, is_connection_failure, short_db_error
from argus.gateway.transport import ca_summary
from argus.observability.redaction import redact_text, register_secret
from argus.ops import case_team_login
from argus.ops.case_team_login import TeamLogin
from argus.site import Role


@dataclass(frozen=True)
class CheckResult:
    name: str
    ok: bool
    detail: str
    warn: bool = False
    """Passes, but something needs a person soon (an expiry within 30 days, a stale source):
    shown as WARN; only failures make ``argus doctor`` exit 1."""

    @property
    def label(self) -> str:
        if not self.ok:
            return "FAIL"
        return "WARN" if self.warn else "PASS"


CheckFn = Callable[[Settings], Awaitable[list[CheckResult]]]
_CHECKS: list[CheckFn] = []


def register_check(fn: CheckFn) -> CheckFn:
    _CHECKS.append(fn)
    return fn


async def run_checks(settings: Settings) -> list[CheckResult]:
    window = format_duration(settings.history.window)
    results = [
        CheckResult("config", True, f"environment={settings.environment} history.window={window}")
    ]
    for check in _CHECKS:
        try:
            results.extend(await check(settings))
        except Exception as exc:  # a broken check must not hide the others
            results.append(CheckResult(check.__name__, False, redact_text(f"check crashed: {exc}")))
    return results


@register_check
async def database_checks(settings: Settings) -> list[CheckResult]:
    try:
        engine = create_engine(settings.database)
    except ConfigError as exc:
        return [CheckResult("database", False, str(exc))]
    try:
        try:
            async with engine.connect() as conn:
                version = (await conn.execute(text("SHOW server_version"))).scalar_one()
                tz = (await conn.execute(text("SHOW TimeZone"))).scalar_one()
        except (SQLAlchemyError, OSError) as exc:
            hint = " — run `argus db bootstrap` to create or repair it" if _refused(exc) else ""
            return [CheckResult("database", False, short_db_error(exc) + hint)]

        results = [
            CheckResult(
                "database",
                True,
                f"PostgreSQL {version} at {settings.database.host}:{settings.database.port}",
            ),
            CheckResult("database timezone", tz == "UTC", f"session TimeZone={tz}"),
        ]
        head = migrate.head_revision()
        try:
            current = await migrate.current_revision(engine)
        except (CommandError, RevisionError) as exc:  # e.g. several rows in alembic_version
            results.append(CheckResult("migrations", False, short_db_error(exc)))
            return results
        except DB_ERRORS as exc:  # before 0003 the runtime role may not read alembic_version
            hint = (
                " — run `argus db upgrade` (and `argus db bootstrap` if it is at head already)"
                if _sqlstate(exc) == _INSUFFICIENT_PRIVILEGE
                else ""
            )
            results.append(CheckResult("migrations", False, short_db_error(exc) + hint))
            return results
        results.append(
            CheckResult(
                "migrations",
                current == head,
                f"current={current or 'none'} head={head}"
                + ("" if current == head else " — run `argus db upgrade`"),
            )
        )
        if current == head:
            drift = await migrate.schema_drift(engine)
            results.append(
                CheckResult(
                    "schema matches models",
                    not drift,
                    "in sync" if not drift else f"{len(drift)} difference(s): {drift[:3]}",
                )
            )
            missing = await migrate.missing_guard_triggers(engine)
            results.append(
                CheckResult(
                    "audit trail append-only",
                    not missing,
                    "triggers present and always enabled"
                    if not missing
                    else f"triggers missing, disabled or not ENABLE ALWAYS: {', '.join(missing)}",
                )
            )
            unguarded = await migrate.missing_resume_triggers(engine)
            results.append(
                CheckResult(
                    "switches resumed by the owner only",
                    not unguarded,
                    "triggers present and always enabled (Q-A5)"
                    if not unguarded
                    else f"triggers missing, disabled or not ENABLE ALWAYS: {', '.join(unguarded)}",
                )
            )
            reports = await chain.verify_snapshot(engine)  # every row, one snapshot
            results += [CheckResult(f"audit chain ({r.chain})", r.ok, r.summary()) for r in reports]
            problems = await roles.runtime_role_problems(engine)
            detail = "; ".join(problems) if problems else "least privilege, owns nothing"
            if any(roles.repaired_by_bootstrap(problem) for problem in problems):
                detail += " — run `argus db bootstrap` to repair the role"
            results.append(
                CheckResult("runtime role", not problems, f"{settings.database.user}: {detail}")
            )
            results.append(await web_login_check(as_the_web_runs(settings)))
            results.append(await writer_login_check(settings, as_the_case_team_runs(settings)))
            results.append(await shadow_check(engine, settings))
            results.append(await signin_check(engine, settings))
        return results
    finally:
        await engine.dispose()


async def signin_check(engine: AsyncEngine, settings: Settings) -> CheckResult:
    """How people sign in (ELK or local accounts), the login-failure alarm (60 refused checks in
    an hour across all names: ELK's refusals, or wrong local passwords), and an emergency
    (break-glass) window that is open."""
    name = "sign-in"
    mode = "ELK accounts" if settings.web.elk_signin else "local accounts (ELK sign-in is off)"
    try:
        async with engine.connect() as conn:
            alarm = (
                await conn.execute(
                    text(
                        "SELECT occurred_at, details->>'refused_checks_in_an_hour' FROM"
                        " audit_events WHERE action = 'signin.alarm'"
                        " AND occurred_at > now() - interval '6 hours'"
                        " ORDER BY id DESC LIMIT 1"
                    )
                )
            ).first()
            window = (
                await conn.execute(
                    text(
                        "SELECT expires_at FROM break_glass WHERE ended_at IS NULL"
                        " AND expires_at > now()"
                    )
                )
            ).first()
    except DB_ERRORS as exc:
        return CheckResult(name, False, short_db_error(exc))
    if settings.web.elk_signin and settings.web.secret_file is not None:
        from argus.cases.signing import KeyFileError, load_key

        try:
            load_key(settings.web.secret_file)
        except KeyFileError as exc:
            return CheckResult(name, False, f"web.secret_file: {exc}")
    if alarm is not None:
        return CheckResult(
            name, False,
            f"ALARM: {alarm[1]} refused sign-in checks within an hour (at"
            f" {alarm[0]:%Y-%m-%d %H:%M} UTC): someone is guessing passwords; see the audit"
            " trail (action login)",
        )  # fmt: skip
    keyless = settings.web.elk_signin and not (
        settings.siem.api_key and settings.siem.api_key.get_secret_value()
    )
    if keyless:
        return CheckResult(
            name, True,
            f"{mode}; but the web has no siem.api_key: a 401 cannot be told from a security-index"
            " outage, so no wrong password is ever counted or locked (give argus-web the reader"
            " key)",
            warn=True,
        )  # fmt: skip
    if window is not None:
        return CheckResult(
            name, True,
            f"{mode}; break-glass is ON until {window[0]:%Y-%m-%d %H:%M} UTC: switch it off with"
            " `argus break-glass off` when ELK is back",
            warn=True,
        )  # fmt: skip
    return CheckResult(name, True, f"{mode}; no alarm in the last 6 hours, break-glass off")


async def shadow_check(engine: AsyncEngine, settings: Settings) -> CheckResult:
    """The local model's shadow answers (``llm_shadow``) are never shown. The web's own login has
    no grant on them; the runtime login, which the web uses until ``web.database_role: api``,
    may read them, so they must not exist then."""
    name = "shadow store"
    if settings.web.database_role == "api":
        return CheckResult(name, True, "the web's own login has no grant on llm_shadow")
    try:
        async with engine.connect() as conn:
            stored = bool(await conn.scalar(text("SELECT EXISTS (SELECT 1 FROM llm_shadow)")))
    except DB_ERRORS as exc:
        return CheckResult(name, False, f"llm_shadow: {short_db_error(exc)}")
    if stored:
        return CheckResult(
            name,
            False,
            f"llm_shadow holds shadow answers and the web logs in as {settings.database.user},"
            " which may read them: set web.database_role: api (Q-A2) and restart argus-web",
        )
    return CheckResult(
        name,
        True,
        "empty; `argus llm shadow` waits for the web's own login (web.database_role: api)",
    )


def as_the_web_runs(settings: Settings) -> Settings:
    """The settings as ``argus-web`` runs with them: its unit's database role, approval key and
    credentials folder (``units.web``) over the shared ``web`` section, which doctor reads
    outside the unit."""
    unit, web, database = settings.units.web, settings.web, settings.database
    changes: dict[str, object] = {}
    if unit.database_role is not None:
        changes["database_role"] = unit.database_role
    if unit.approval_key_file is not None and web.approval_key_file is None:
        changes["approval_key_file"] = Path(unit.approval_key_file)
    if unit.credentials is not None and not roles.api_login_configured(database):
        try:
            password = (Path(unit.credentials) / "database.api_password").read_text().strip()
        except OSError:
            password = ""
        if password:
            register_secret(password)
            database = database.model_copy(update={"api_password": SecretStr(password)})
    return settings.model_copy(update={"web": web.model_copy(update=changes), "database": database})


async def web_login_check(settings: Settings) -> CheckResult:
    """The web's own login, from its own point of view: exactly ``argus_web``'s grants
    and nothing else, and whether the web uses it (``web.database_role``)."""
    database, name = settings.database, "web login"
    uses_it = settings.web.database_role == "api"
    if not roles.api_login_configured(database):
        if uses_it:
            return CheckResult(
                name,
                False,
                "web.database_role is api, but ARGUS_DATABASE__API_PASSWORD is not set: the web"
                " cannot start",
            )
        return CheckResult(
            name,
            True,
            f"the web logs in as {database.user}, with more grants than it needs; its own login"
            f" {database.api_user} is not set up (Q-A2: set ARGUS_DATABASE__API_PASSWORD, run"
            " `argus db bootstrap`, then web.database_role: api)",
            warn=True,
        )
    try:
        engine = create_engine(database, role="api")
    except ConfigError as exc:
        return CheckResult(name, False, str(exc))
    try:
        try:
            problems = await roles.api_role_problems(engine)
        except (SQLAlchemyError, OSError) as exc:
            hint = " — run `argus db bootstrap` to create or repair it" if _refused(exc) else ""
            return CheckResult(name, False, f"{database.api_user}: {short_db_error(exc)}{hint}")
    finally:
        await engine.dispose()
    if problems:
        detail = "; ".join(problems)
        if any(roles.repaired_by_bootstrap(problem) for problem in problems):
            detail += " — run `argus db bootstrap` to repair the role"
        return CheckResult(name, False, f"{database.api_user}: {detail}")
    if not uses_it:
        return CheckResult(
            name,
            True,
            f"{database.api_user} has exactly the web's grants, but the web still logs in as"
            f" {database.user}: set web.database_role: api and restart argus-web (Q-A2)",
            warn=True,
        )
    return CheckResult(name, True, f"{database.api_user}: exactly the web's grants, in use")


def as_the_case_team_runs(settings: Settings) -> TeamLogin | None:
    """The case team's login as ``argus-case-team.service`` uses it in this installation's
    checkout (``units.root``): its credential, the login its switches name, and whether the
    installation runs it (an enabled timer counts only when the installed units are this
    checkout's). None under custody, whose system unit gets root's credential."""
    from argus.ops import custody, units

    if case_team_login.SERVICE in custody.moved_units():
        return None
    root = settings.units.root or units.REPO
    folder = units.user_unit_dir()
    try:
        installed = units.installed_root(folder)
        mine = installed is not None and installed.resolve() == root.resolve()
        enabled = units.enabled_units(folder) if mine else set()
    except OSError:  # the units check says why the folder cannot be read
        enabled = set()
    return case_team_login.team_login(
        root, run=settings.units.run, enabled=enabled, post=settings.case_team.post
    )


async def writer_login_check(settings: Settings, team: TeamLogin | None = None) -> CheckResult:
    """The case writer's own login, from its own point of view: exactly the grants of
    migrations 0037 and 0038 (the outbox moves, its tables, the lane's state, the audit trail and
    what it reads), a member of ``argus_writer`` alone, nothing else. With ``team`` (the case
    team's login as its unit uses it) the password is its credential's, and a login that does
    not work fails only while the installation runs the case team: off is a choice, and then it
    is a warning (``argus init`` repairs the login). Not set up is fine while it is off."""
    database, name, shown = settings.database, "writer login", case_team_login.SHOWN
    if team is not None:
        if team.password is not None:
            register_secret(team.password)
        database = database.model_copy(update=team.database_update())
    user = database.writer_user
    own = team is not None and team.password is not None  # the unit's own credential
    runs = "; ".join(team.runs) if team is not None else ""
    if team is not None and team.problem is not None and runs:
        return CheckResult(
            name,
            False,
            f"{user}: {shown} {team.problem}, and the case team is set to run"
            f" ({runs}): it cannot start until that file holds the login's password",
        )
    if not roles.writer_login_configured(database):
        if runs:
            return CheckResult(
                name,
                False,
                f"{user}: the case team is set to run ({runs}), but its login has no password:"
                f" put one in {shown} (mode 600) and run `argus init`, which makes the"
                f" login (docs/case-team.md), or stop the case team: {case_team_login.STOPS}",
            )
        if team is None:
            hint = (
                "set ARGUS_DATABASE__WRITER_PASSWORD in its credentials and run"
                " `argus db bootstrap`"
            )
        else:
            hint = f"put its password in {shown} and run `argus init`"
        detail = f"{user} is not set up (the writer is off until its canary: {hint})"
        if team is not None and team.problem is not None:
            detail += f"; {shown} {team.problem}"
        return CheckResult(name, True, detail)
    judged = not own or bool(runs)
    fix = f"run `argus init` (it sets the login's password from {shown})"
    if own:
        try:
            roles.check_writer_settings(database)
        except ConfigError as exc:  # a login name in its switches that cannot be its own
            return CheckResult(name, not judged, f"{user}: {exc}", warn=not judged)
    try:
        engine = create_engine(database, role="writer")
    except ConfigError as exc:
        return CheckResult(name, False, str(exc))
    try:
        try:
            problems = await roles.writer_role_problems(engine)
        except (SQLAlchemyError, OSError) as exc:
            if _refused(exc) and not judged:
                return CheckResult(
                    name,
                    True,
                    f"{user}: the case team is off, and its login does not log in with"
                    f" {shown} ({short_db_error(exc)}): `argus init` repairs it",
                    warn=True,
                )
            if not _refused(exc):
                hint = ""
            elif own:
                hint = f" — {fix}"
            else:
                hint = " — run `argus db bootstrap` to create or repair it"
            return CheckResult(name, False, f"{user}: {short_db_error(exc)}{hint}")
    finally:
        await engine.dispose()
    if problems:
        detail = "; ".join(problems)
        if any(roles.repaired_by_bootstrap(problem) for problem in problems):
            detail += " — run `argus init` to repair the role" if own else (
                " — run `argus db bootstrap` to repair the role")  # fmt: skip
        if not judged:
            return CheckResult(name, True, f"{user}: the case team is off; {detail}", warn=True)
        return CheckResult(name, False, f"{user}: {detail}")
    if not own:
        return CheckResult(name, True, f"{user}: exactly the writer's grants")
    off = "" if runs else " (the case team is off)"
    return CheckResult(
        name, True, f"{user}: exactly the writer's grants, logs in with {shown}{off}"
    )


@register_check
async def approval_key_check(settings: Settings) -> list[CheckResult]:
    """The key ``argus-web`` signs approvals with: without it the approvals queue can be
    read and nothing can be decided. Its id must be one the writer accepts
    (``kibana.writer.approval_keys``)."""
    from argus.cases.signing import KeyFileError, load_key

    name, path = "approval signing key (web)", as_the_web_runs(settings).web.approval_key_file
    if path is None:
        return [
            CheckResult(
                name,
                True,
                "web.approval_key_file is not set: the approvals queue can be read, but no"
                " decision is recorded (`argus approvals keygen`, then set it for argus-web)",
                warn=True,
            )
        ]
    try:
        key = load_key(path)
    except KeyFileError as exc:
        return [CheckResult(name, False, str(exc))]
    return [CheckResult(name, True, f"key {key.key_id} (the writer must accept this id)")]


_INSUFFICIENT_PRIVILEGE = "42501"


def _sqlstate(exc: BaseException) -> str | None:
    return getattr(getattr(exc, "orig", None), "sqlstate", None)


# How the server refuses a runtime login that `argus db bootstrap` creates or repairs: a wrong
# password, an expired one or a role that does not exist (PostgreSQL gives all three the same
# answer), a login without LOGIN, one with a connection limit, and a database the runtime role
# may not connect to.
_REFUSALS = (
    "password authentication failed",
    "is not permitted to log in",
    "too many connections for role",
    "permission denied for database",
)


def _refused(exc: BaseException) -> bool:
    """Connection failures carry no SQLSTATE, hence the text."""
    return is_connection_failure(exc) and any(refusal in str(exc) for refusal in _REFUSALS)


@register_check
async def asset_map_check(settings: Settings) -> list[CheckResult]:
    path = settings.assets.map_path
    try:
        asset_map = load_asset_map(path)
    except AssetMapError as exc:
        return [CheckResult("assets", False, f"the imported asset map is invalid: {exc}")]
    if asset_map is None:
        return [CheckResult("assets", True, "no asset map imported (asset context is unknown)")]
    if path.stat().st_mode & 0o077:
        return [
            CheckResult("assets", False, "the asset map is readable by other users (chmod 600)")
        ]
    return [
        CheckResult(
            "assets",
            True,
            f"{asset_map.network_count} networks, sha256 {asset_map.sha256[:12]}",
        )
    ]


CA_WARN_DAYS = 30


@register_check
async def site_check(settings: Settings) -> list[CheckResult]:
    """The site profile: the log families it names, the space, and the words and
    zone the pages and the incident IDs use."""
    profile = settings.site
    names = ", ".join(profile.all_sources) or "none yet: `argus discover` proposes them"
    detail = f"{len(profile.families)} log families ({names}); space {profile.space}"
    detail += (
        f"; zone {profile.timezone}; incident IDs {profile.incident_id_prefix}-YYYY-MMDD-NN"
        f"; {len(profile.own_networks)} own networks, {len(profile.own_domains)} own domains"
    )
    results = [CheckResult("site", True, detail)]
    # a role with two families: the sign-ins and the case watch read the first of their role only
    for role, used_by, on in (
        (Role.AUTH, "the sign-ins", settings.signins.enabled),
        (Role.PROXY, "the case watch", settings.cases.watch == "on"),
    ):
        families = profile.of_role(role)
        family_names = [f.name for f in families]
        if on and len(families) > 1:
            results.append(
                CheckResult(
                    f"site {role.value} families",
                    True,
                    f"{len(families)} {role.value} families ({', '.join(family_names)}):"
                    f" {used_by} read {families[0].name} only (D-284); a case whose devices"
                    " use another is told quiet",
                    warn=True,
                )
            )
    return results


@register_check
async def timezone_check(settings: Settings) -> list[CheckResult]:
    """The database reads the site's zone as Python does (the SQL report days and the
    investigation days must count the same days), asked at nine instants of 2026."""
    try:
        engine = create_engine(settings.database)
    except ConfigError:
        return []  # the database checks say why
    name = settings.site.timezone
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SET TRANSACTION READ ONLY"))
            rows = (
                await conn.execute(
                    text(
                        "SELECT t, t AT TIME ZONE :zone FROM unnest(CAST(:at AS timestamptz[]))"
                        " AS probe(t)"
                    ),
                    {"zone": name, "at": list(site.ZONE_PROBES)},
                )
            ).all()
    except DB_ERRORS as exc:
        if is_connection_failure(exc):
            return []  # the database checks say why
        return [CheckResult("site time zone", False, f"the database rejects {name}: "
                            + redact_text(short_db_error(exc))[:200])]  # fmt: skip
    finally:
        await engine.dispose()
    odd = site.zone_disagreements(name, [(r[0], r[1]) for r in rows])
    if odd:
        return [CheckResult("site time zone", False,
                            f"{name}: the database and Python read it differently at {odd[0]}"
                            f" (and {len(odd) - 1} more): choose a region zone")]  # fmt: skip
    return [CheckResult("site time zone", True, f"{name}: the database reads it as Python does")]


@register_check
async def siem_check(settings: Settings) -> list[CheckResult]:
    """The address, the pinned CA and the API key's presence; no request to the SIEM
    (that is ``argus siem selftest``)."""
    siem = settings.siem
    configured = siem.api_key is not None and bool(siem.api_key.get_secret_value())
    try:
        ca = ca_summary(siem.ca_file)
    except ValueError as exc:
        if not configured and not siem.ca_file.exists():  # the SIEM not set up yet: like the key
            results = [CheckResult("the SIEM CA", True, "not pinned yet (D-033)")]
        else:
            results = [CheckResult("the SIEM CA", False, f"{exc} (pin the SIEM's CA, D-033)")]
    else:
        now = datetime.now(UTC)
        days = (ca.not_after - now).days
        detail = f"{ca.subject}, valid until {ca.not_after:%Y-%m-%d} ({days} days)"
        if ca.not_after <= now:
            results = [
                CheckResult(
                    "the SIEM CA",
                    False,
                    f"{ca.subject} expired on {ca.not_after:%Y-%m-%d}: renew the pin",
                )
            ]
        elif days < CA_WARN_DAYS:  # warned 30 days ahead, a failure once expired
            detail = (
                f"{ca.subject} expires {ca.not_after:%Y-%m-%d}: renew the pin within {days} days"
            )
            results = [CheckResult("the SIEM CA", True, detail, warn=True)]
        else:
            results = [CheckResult("the SIEM CA", True, detail)]
    if siem.url is None:  # no default address: a key without one cannot be used
        results.append(
            CheckResult(
                "the SIEM address",
                not configured,
                "not configured: ARGUS cannot read the SIEM yet (siem.url)"
                if not configured
                else "siem.url is not set, but a key is: set the address (siem: url:)",
            )
        )
    else:
        results.append(CheckResult("the SIEM address", True, siem.url))
    if not configured:
        results.append(
            CheckResult(
                "the SIEM key", True, "not configured: ARGUS cannot read the SIEM yet (D-048)"
            )
        )
    else:
        results.append(
            CheckResult("the SIEM key", True, "configured (`argus siem selftest` checks it)")
        )
    return results


@register_check
async def agents_check(settings: Settings) -> list[CheckResult]:
    """The investigation agent's files: loaded, pinned and enabled as code says, with
    the gold run ids code ties them to; every other bound agent's own state (off is a state;
    a refused file fails, or warns while the agent is off); then whether the files or their
    pins changed since their approval tag (a warning: a new version and its pin agree with
    each other, and only an approval says they are wanted)."""
    from argus.agent import drift, loader
    from argus.agent.registry import BINDINGS, COORDINATOR, ENABLED, GOLD_RUNS
    from argus.evaluation.agent_eval import signature_of

    try:
        agents = loader.load()
    except (loader.AgentError, OSError) as exc:
        results = [CheckResult("agents", False, f"refused: {loader.shown(str(exc))}")]
    else:
        lead = agents.coordinator
        assert lead.budget is not None  # the loader refuses a coordinator without one
        runs = {"no_tools": signature_of(agents, lead.budget, False),
                "tools": signature_of(agents, lead.budget, True)}  # fmt: skip
        detail = (f"{agents.summary()}; gold run ids {runs['no_tools']} (no tools),"
                  f" {runs['tools']} (tools)")  # fmt: skip
        if runs == dict(GOLD_RUNS):
            results = [CheckResult("agents", True, detail)]
        else:
            tied = f"{GOLD_RUNS['no_tools']}, {GOLD_RUNS['tools']}"
            results = [CheckResult("agents", False, f"{detail}, but code ties them to {tied}")]
    try:
        surveyed = {n: got for n, got in loader.survey().items() if n in BINDINGS}
    except (loader.AgentError, OSError):
        surveyed = {}  # the directory itself: the line above says why
    # The line above speaks for the coordinator and the specialists its file names; when its
    # own file is refused, whom it names is not known, so each other agent gets its own line.
    own = surveyed.get(COORDINATOR)
    family = {COORDINATOR, *(own.specialists if isinstance(own, loader.Definition) else ())}
    others = {n: got for n, got in surveyed.items() if n not in family}
    for name, got in sorted(others.items()):
        on = ENABLED.get(name) is not None
        if isinstance(got, loader.AgentError):
            results.append(CheckResult(f"agent {name}", not on, f"{'on' if on else 'off'},"
                                       f" and refused: {got}", warn=not on))  # fmt: skip
        else:
            results.append(CheckResult(f"agent {name}", True,
                                       f"{got.version}, {'on' if on else 'off'}"))  # fmt: skip
    found = await asyncio.to_thread(drift.since_approved)
    waiting = f"; pins waiting for their approval: {', '.join(found.waiting)}"
    waiting = waiting if found.waiting else ""
    if found.why is not None:
        detail = f"cannot tell: {found.why}{waiting}"
    elif found.changed:
        detail = f"changed since {found.tag}, not approved yet: {', '.join(found.changed)}{waiting}"
    else:
        detail = f"as at {found.tag}{waiting}"
    warn = found.why is not None or bool(found.changed) or bool(found.waiting)
    results.append(CheckResult("agents since approval", True, loader.shown(detail), warn=warn))
    return results


@register_check
async def privacy_domains_check(settings: Settings) -> list[CheckResult]:
    """The privacy layer's own domains: ``site.own_domains`` and the policy's
    ``campus_domains`` must name at least one, or no text for a model can be built. FAIL while a
    provider is enabled and none is listed; WARN while none is enabled (nothing is sent, but the
    first one switched on would be refused)."""
    from pydantic import ValidationError

    from argus import site
    from argus.llm.privacy import load_policy
    from argus.llm.providers import load_config

    try:
        policy = load_policy(require_domains=False)
    except (OSError, ValueError, ValidationError) as exc:
        return [CheckResult("privacy domains", False, redact_text(f"data policy: {exc}")[:300])]
    with site.using(settings.site):
        domains = site.own_domains(policy.campus_domains)
    if domains:
        return [CheckResult("privacy domains", True, f"{len(domains)} own domains are replaced")]
    try:
        enabled = [p.name for p in load_config().providers if p.enabled]
    except (OSError, ValueError, ValidationError):
        enabled = []  # the llm check says why
    detail = (
        "no domain of the organisation is listed (site.own_domains, or campus_domains in"
        " config/llm_data_policy.yaml): the privacy layer refuses to build a request until one is"
    )
    if enabled:
        return [CheckResult("privacy domains", False, f"{detail}; enabled: {', '.join(enabled)}")]
    return [CheckResult("privacy domains", True, f"{detail}; no model is enabled", warn=True)]


@register_check
async def llm_check(settings: Settings) -> list[CheckResult]:
    """The LLM gateway: its configuration, the keys file, each provider's key and pinned
    certificate, and the gateway's alarms. Offline: ``argus llm probe`` asks the providers."""
    from pydantic import ValidationError

    from argus.llm import doctor as llm_doctor
    from argus.llm.providers import load_config, load_keys
    from argus.llm.store import PgLlmStore

    try:
        config = load_config()
    except (OSError, ValueError, ValidationError) as exc:
        return [CheckResult("llm config", False, redact_text(f"config/llm.yaml: {exc}")[:300])]
    present = set(load_keys(config.keys_file, {k for p in config.providers for k in p.keys}))
    found = llm_doctor.offline_checks(config, present, datetime.now(UTC))
    try:
        engine = create_engine(settings.database)
    except ConfigError:
        engine = None
    if engine is not None:
        try:
            state = await PgLlmStore(engine).state()
            found.append(llm_doctor.alarms_check(state, {p.name for p in config.providers}))
        except DB_ERRORS:
            pass  # the database checks say why
        finally:
            await engine.dispose()
    return [CheckResult(f.name, f.ok, f.detail) for f in found]


# The platform checks register themselves; imported last, as they import this module.
from argus.ops import checks as _platform_checks  # noqa: E402

__all__ = ["CheckResult", "_platform_checks", "register_check", "run_checks"]
