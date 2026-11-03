"""Adversarial re-attack of ``argus db bootstrap`` after its round-3 rewrite (D-029).

Attacks the new repair code in ``argus.db.roles`` (``ensure_roles`` with ``_state``, ``_restore``,
``_clear_settings``, ``_revoke_memberships``, ``_retrying`` and ``_execute``; ``grant_connect``),
what the CLI prints and audits for it, and where the login's password verifier can still turn
up. Cases that need no database are in tests/unit/adversarial/test_adv_roles_config_reattack.py.

Conventions, as in the sibling adversarial files: a docstring starting with **DEFECT** marks a test
that fails on the current code on purpose and passes once the hole is closed; **LOCK-IN** tests
pass today and pin behaviour that held up under attack.

Safety:
* Databases are throwaway ``argus_test_*`` ones from tests/integration/conftest.py. A setting
  stored for every role is stored only for such a database.
* ``argus``, ``argus_app`` and ``argus_runtime`` are never changed. Roles a test creates are named
  ``argus_test_role_<unix>_<8 hex>`` (``throwaway_roles``) and dropped together afterwards, so
  grants among them never block the cleanup. A test that damages the group role points
  ``roles.RUNTIME_ROLE`` at a throwaway name while it runs.
* Passwords are synthetic, except the local owner password, which reaches the CLI only through
  the environment. Passwords and SCRAM verifiers are only ever checked as booleans, and failures
  report the server's message, never the SQL (which may hold a verifier).
"""

from __future__ import annotations

import asyncio
import io
import itertools
import json
import logging
import os
import re
import secrets
import time
from collections.abc import Awaitable, Callable, Iterator, Sequence
from datetime import timedelta
from pathlib import Path
from typing import Any

import psycopg
import pytest
from psycopg import sql
from pydantic import SecretStr
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import CliRunner, Result

import argus.cli as cli
from argus.cli import app
from argus.config import DatabaseSettings
from argus.db import roles
from argus.db.engine import create_engine
from argus.observability.logs import configure_logging
from argus.observability.redaction import clear_registered_secrets
from tests.conftest import THROWAWAY_SITE, hide_in_reports
from tests.integration.conftest import (
    TEST_DB_PREFIX,
    TEST_ROLE_PATTERN,
    TEST_ROLE_PREFIX,
    admin_connect,
    owner_password,
)

runner = CliRunner()
RoleNames = Callable[[], str]
MakeLogin = Callable[[], Awaitable[DatabaseSettings]]
AdminConnection = psycopg.Connection[tuple[Any, ...]]

# An unmasked SCRAM-SHA-256 verifier (iterations:salt$StoredKey:ServerKey). Redaction leaves
# "SCRAM-SHA-256$***", which this does not match.
VERIFIER = re.compile(r"SCRAM-SHA-256\$[0-9]+:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+")
MASKED_VERIFIER = "SCRAM-SHA-256$***"
# lock_timeout and statement_timeout are equal below 10 s (argus.db.engine): either may fire first.
BLOCKED_TOO_LONG = ("55P03", "57014")
INSUFFICIENT_PRIVILEGE = "42501"
# The attributes bootstrap controls, in pg_roles order, and the state each role must end in.
FLAGS = ("LOGIN", "SUPERUSER", "CREATEDB", "CREATEROLE", "REPLICATION", "BYPASSRLS", "INHERIT")
SAFE_LOGIN = (True, False, False, False, False, False, True)
SAFE_GROUP = (False, False, False, False, False, False, True)
# Since PostgreSQL 16 only a role holding these (or a superuser) may take them off another role:
# the CREATEROLE owner below holds none of them.
NEEDS_MORE_THAN_CREATEROLE = frozenset({"SUPERUSER", "CREATEDB", "REPLICATION", "BYPASSRLS"})
# Edge values for the login's connection limit and password expiry; the first of each is safe.
LIMITS = (-1, 0, 1, 100)
EXPIRIES = ("infinity", "2000-01-01 00:00:00+00", "2999-12-31 00:00:00+00", "-infinity")


@pytest.fixture(autouse=True)
def _forget_cli_state() -> Iterator[None]:
    """The CLI registers passwords for redaction and points logging at its captured stream;
    neither may outlive the test."""
    yield
    clear_registered_secrets()
    configure_logging("WARNING", "console", stream=io.StringIO())


@pytest.fixture
def throwaway_roles(db_settings: DatabaseSettings, test_database: str) -> Iterator[RoleNames]:
    """Names for roles a test creates itself, ``argus_test_role_<unix>_<8 hex>`` as make_login
    names its logins. Afterwards the ones that exist are dropped in one statement (with what they
    own or were granted), so memberships they granted one another do not block it."""
    names: list[str] = []

    def _name() -> str:
        name = f"{TEST_ROLE_PREFIX}{int(time.time())}_{secrets.token_hex(4)}"
        assert TEST_ROLE_PATTERN.fullmatch(name), name  # the stale cleanup must recognise it
        names.append(name)
        return name

    yield _name
    with admin_connect(db_settings, test_database) as conn:
        rows = conn.execute("SELECT rolname FROM pg_roles WHERE rolname = ANY(%s)", (names,))
        existing = [str(name) for (name,) in rows.fetchall()]
        if existing:
            listed = sql.SQL(", ").join(sql.Identifier(name) for name in existing)
            conn.execute(sql.SQL("DROP OWNED BY {}").format(listed))
            conn.execute(sql.SQL("DROP ROLE {}").format(listed))


@pytest.fixture
def computed_verifiers(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every SCRAM verifier bootstrap computes while the test runs, in this process (the CLI
    included): kept in memory to look for, never shown."""
    seen: list[str] = []
    original = roles._password_verifier

    async def recording(conn: Any, user: str, password: str) -> sql.Literal:
        literal = await original(conn, user, password)
        seen.append(literal.as_string().strip("'"))
        return literal

    monkeypatch.setattr(roles, "_password_verifier", recording)
    return seen


# --------------------------------------------------------------------------- helpers


def _shows_a_verifier(text: str, verifiers: Sequence[str] = ()) -> bool:
    """Whether ``text`` holds an unmasked verifier, or the salt, StoredKey or ServerKey of one of
    ``verifiers`` on its own (pytest shortens a long value by cutting out its middle)."""
    if VERIFIER.search(text):
        return True
    for verifier in verifiers:
        salted, keys = verifier.removeprefix("SCRAM-SHA-256$").split("$", 1)
        if any(part in text for part in (salted.split(":", 1)[1], *keys.split(":", 1))):
            return True
    return False


def _driver_message(exc: BaseException) -> str:
    """The server's message for ``exc`` with its DETAIL, never the SQL (which may hold a
    verifier)."""
    original = getattr(exc, "orig", None) or exc
    lines = str(original).strip().splitlines()
    shown = lines[:1] + [line.strip() for line in lines[1:] if line.startswith("DETAIL:")]
    return f"{type(original).__name__}: {' '.join(shown)}"


def _sqlstate(exc: BaseException) -> str | None:
    return getattr(getattr(exc, "orig", None), "sqlstate", None)


def _as_superuser(
    settings: DatabaseSettings, database: str, *statements: sql.Composable | str
) -> None:
    with admin_connect(settings, database) as conn:
        for statement in statements:
            conn.execute(statement)


def _query(
    settings: DatabaseSettings, database: str, query: str, params: Any = ()
) -> list[tuple[Any, ...]]:
    with admin_connect(settings, database) as conn:
        return conn.execute(query, params).fetchall()


def _grants(
    settings: DatabaseSettings, database: str, member: str
) -> list[tuple[str, str, bool, bool, bool]]:
    """Every grant making ``member`` a member of a role: (role, grantor, admin, inherit, set)."""
    rows = _query(
        settings,
        database,
        "SELECT r.rolname, g.rolname, am.admin_option, am.inherit_option, am.set_option"
        " FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.roleid"
        " JOIN pg_roles g ON g.oid = am.grantor JOIN pg_roles m ON m.oid = am.member"
        " WHERE m.rolname = %s ORDER BY 1, 2",
        (member,),
    )
    return [(str(r), str(g), bool(a), bool(i), bool(s)) for r, g, a, i, s in rows]


def _member_of(
    settings: DatabaseSettings, database: str, member: str
) -> dict[str, tuple[bool, bool]]:
    """The roles ``member`` belongs to directly: name -> (ADMIN OPTION through any grant,
    INHERIT through any grant)."""
    found: dict[str, tuple[bool, bool]] = {}
    for role, _, admin, inherit, _ in _grants(settings, database, member):
        had = found.get(role, (False, False))
        found[role] = (had[0] or admin, had[1] or inherit)
    return found


def _stored(settings: DatabaseSettings, database: str, role: str) -> dict[str, list[str]]:
    """Names of the settings stored on ``role``: database name ('*' for everywhere) -> names."""
    rows = _query(
        settings,
        database,
        "SELECT coalesce(d.datname, '*'), s.setconfig FROM pg_db_role_setting s"
        " LEFT JOIN pg_database d ON d.oid = s.setdatabase"
        " WHERE s.setrole = (SELECT oid FROM pg_roles WHERE rolname = %s)",
        (role,),
    )
    return {str(where): sorted(item.split("=", 1)[0] for item in config) for where, config in rows}


def _attributes(conn: AdminConnection, role: str) -> tuple[Any, ...]:
    """The role's attributes in FLAGS order, its connection limit and its password expiry."""
    row = conn.execute(
        "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls,"
        " rolinherit, rolconnlimit, coalesce(rolvaliduntil::text, 'infinity')"
        " FROM pg_roles WHERE rolname = %s",
        (role,),
    ).fetchone()
    assert row is not None, role
    return tuple(row)


def _stored_verifier(conn: AdminConnection, role: str) -> str | None:
    """The role's stored password verifier: only ever compared, never shown."""
    row = conn.execute("SELECT rolpassword FROM pg_authid WHERE rolname = %s", (role,)).fetchone()
    return None if row is None else row[0]


def _stage(
    conn: AdminConnection, role: str, flags: Sequence[bool], limit: int, expiry: str
) -> None:
    """Give ``role`` exactly these attributes, connection limit and password expiry."""
    clauses = [sql.SQL(name if on else f"NO{name}") for name, on in zip(FLAGS, flags, strict=True)]
    conn.execute(
        sql.SQL("ALTER ROLE {} WITH {} CONNECTION LIMIT {} VALID UNTIL {}").format(
            sql.Identifier(role),
            sql.SQL(" ").join(clauses),
            sql.SQL(str(int(limit))),
            sql.Literal(expiry),
        )
    )


def _with_login(
    settings: DatabaseSettings, database: str, user: str, password: str
) -> DatabaseSettings:
    return settings.model_copy(
        update={"user": user, "password": SecretStr(password), "name": database}
    )


async def _bootstrap(
    owner: DatabaseSettings, login: DatabaseSettings, database: str, *, connect: bool = True
) -> list[str]:
    """What ``argus db bootstrap`` does for ``login`` (roles, then CONNECT) in one transaction;
    the repairs it reported."""
    engine = create_engine(owner, database=database, role="owner")
    changes: list[str] = []
    try:
        async with engine.begin() as conn:
            await roles.ensure_roles(conn, login, changes=changes)
            if connect:
                await roles.grant_connect(conn, database)
    finally:
        await engine.dispose()
    return changes


def _login_problem(login: DatabaseSettings, database: str) -> str | None:
    """None if ``login`` logs in to ``database`` with its configured password, else the server's
    reason (it never holds the password)."""
    assert database.startswith(TEST_DB_PREFIX), database
    assert login.password is not None
    try:
        with psycopg.connect(
            host=login.host,
            port=login.port,
            user=login.user,
            password=login.password.get_secret_value(),
            dbname=database,
            connect_timeout=5,
        ) as conn:
            conn.execute("SELECT 1")
    except psycopg.Error as exc:
        lines = str(exc).strip().splitlines()
        return lines[-1] if lines else type(exc).__name__
    return None


def _createrole_owner(
    settings: DatabaseSettings,
    database: str,
    names: RoleNames,
    monkeypatch: pytest.MonkeyPatch,
) -> DatabaseSettings:
    """Settings whose owner is a new login with CREATEROLE and nothing else (D-029's owner on a
    shared or production host), whose login is a new name, and whose group role is a new name
    (``roles.RUNTIME_ROLE`` points at it while the test runs)."""
    owner, group, login = names(), names(), names()
    password = f"fake-owner-pw-{secrets.token_hex(8)}"
    hide_in_reports(password)
    _as_superuser(
        settings,
        database,
        sql.SQL("CREATE ROLE {} LOGIN CREATEROLE PASSWORD {}").format(
            sql.Identifier(owner), sql.Literal(password)
        ),
    )
    monkeypatch.setattr(roles, "RUNTIME_ROLE", group)
    runtime = _with_login(settings, database, login, f"fake-runtime-pw-{secrets.token_hex(8)}")
    return runtime.model_copy(update={"owner_user": owner, "owner_password": SecretStr(password)})


def _reported(changes: Sequence[str], role: str) -> set[str]:
    """The attributes a ``<role> had ...: reset`` repair names."""
    prefix, suffix = f"{role} had ", ": reset"
    found: set[str] = set()
    for change in changes:
        if change.startswith(prefix) and change.endswith(suffix):
            found |= set(change[len(prefix) : -len(suffix)].split(", "))
    return found


# --------------------------------------------------------------------------- CLI helpers


def _cli_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    settings: DatabaseSettings,
    database: str,
    *,
    user: str,
    runtime_password: str,
    owner: str | None = None,
    owner_secret: str | None = None,
    extra: str = "",
    logging_section: str = "logging:\n  level: WARNING\n",
) -> Path:
    """A config for the CLI that reaches only ``database``: no .env in reach, no other ARGUS_
    variable, both passwords in the environment, ``extra`` lines in the database section."""
    for key in list(os.environ):
        if key.upper().startswith("ARGUS_"):
            monkeypatch.delenv(key)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(
        "ARGUS_DATABASE__OWNER_PASSWORD",
        owner_secret if owner_secret is not None else owner_password(settings),
    )
    monkeypatch.setenv("ARGUS_DATABASE__PASSWORD", runtime_password)
    assert database.startswith(TEST_DB_PREFIX), database
    config = tmp_path / "argus.yaml"
    config.write_text(
        "database:\n"
        f"  host: '{settings.host}'\n"
        f"  port: {settings.port}\n"
        f"  name: '{database}'\n"
        f"  user: '{user}'\n"
        f"  owner_user: '{owner or settings.owner_user}'\n"
        "  connect_timeout: 3s\n" + extra + logging_section + THROWAWAY_SITE,
        encoding="utf-8",
    )
    return config


def _log_every_statement(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the CLI log SQLAlchemy's statements and rows too (its own setup caps them at
    WARNING), so whatever reaches the server is in its output, through its redaction."""
    configure = cli.configure_logging

    def with_statements(level: str, fmt: str, *, stream: Any = None) -> None:
        configure(level, fmt, stream=stream)
        logging.getLogger("sqlalchemy.engine").setLevel(logging.DEBUG)

    monkeypatch.setattr(cli, "configure_logging", with_statements)


def _scrub(output: str, hidden: Sequence[str]) -> str:
    for secret in hidden:
        output = output.replace(secret, "***")
    return VERIFIER.sub("SCRAM-SHA-256$<unmasked>", output)


def _invoke(
    settings: DatabaseSettings,
    *args: str,
    hidden: Sequence[str] = (),
    verifiers: Sequence[str] = (),
) -> Result:
    """Run the CLI; fail (without printing them) if it printed a password, a verifier, or a
    part of one of ``verifiers``."""
    result = runner.invoke(app, list(args))
    shown = result.output + result.stderr
    printed = any(secret in shown for secret in (owner_password(settings), *hidden))
    assert not printed, "a database password appeared in CLI output"
    unmasked = _shows_a_verifier(shown, verifiers)
    assert not unmasked, "an unmasked SCRAM verifier appeared in CLI output"
    return result


def _uncaught(result: Result, hidden: Sequence[str]) -> str | None:
    exc = result.exception
    if exc is None or isinstance(exc, SystemExit):
        return None
    first = str(exc).splitlines()[0][:200] if str(exc) else ""
    return _scrub(f"{type(exc).__module__}.{type(exc).__name__}: {first}", hidden)


def _error_lines(result: Result) -> list[str]:
    return [line for line in result.stderr.splitlines() if line.startswith("error:")]


# =========================================================================== 1. memberships


@pytest.mark.parametrize("granted_by", ["the-login-itself", "a-role-the-login-made-admin"])
async def test_a_group_membership_that_the_cascade_takes_is_granted_again(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
    granted_by: str,
) -> None:
    """DEFECT: a login holding ADMIN OPTION on argus_runtime (one of the states bootstrap
    repairs) can grant the group to itself a second time, directly or through a role it makes an
    admin. That second grant depends on the first. _revoke_memberships reads every grant up
    front, keeps the inheriting non-admin one, and revokes the ADMIN one "GRANTED BY ... CASCADE",
    which deletes the grant it meant to keep as well. It then decides from what it read before
    that the login is still a member, and grants nothing. Bootstrap reports "...'s membership in
    argus_runtime had ADMIN OPTION: granted again" and the roles ready, while the login is no
    longer a member of argus_runtime at all: every ARGUS statement is refused until bootstrap
    runs again. The memberships should be read again after revoking, before deciding whether to
    grant the group."""
    group, user, helper = throwaway_roles(), throwaway_roles(), throwaway_roles()
    monkeypatch.setattr(roles, "RUNTIME_ROLE", group)
    login = _with_login(db_settings, test_database, user, f"fake-pw-{secrets.token_hex(8)}")
    await _bootstrap(db_settings, login, test_database)
    g, u, h = sql.Identifier(group), sql.Identifier(user), sql.Identifier(helper)
    _as_superuser(
        db_settings,
        test_database,
        sql.SQL("CREATE ROLE {} NOLOGIN").format(h),
        sql.SQL("GRANT {} TO {} WITH ADMIN OPTION").format(g, u),
    )
    with admin_connect(db_settings, test_database) as conn:  # what the login itself may now do
        conn.execute(sql.SQL("SET ROLE {}").format(u))
        if granted_by == "the-login-itself":
            conn.execute(sql.SQL("GRANT {} TO {} GRANTED BY {}").format(g, u, u))
        else:
            conn.execute(sql.SQL("GRANT {} TO {} WITH ADMIN OPTION").format(g, h))
            conn.execute(sql.SQL("SET ROLE {}").format(h))
            conn.execute(sql.SQL("GRANT {} TO {} WITH INHERIT TRUE").format(g, u))
        conn.execute("RESET ROLE")
    staged = sorted(grant[2:4] for grant in _grants(db_settings, test_database, user))
    assert staged == [(False, True), (True, True)]  # a plain grant, and one with ADMIN OPTION
    changes = await _bootstrap(db_settings, login, test_database)
    member = _member_of(db_settings, test_database, user)
    assert member == {group: (False, True)}, f"bootstrap reported {changes}; the login has {member}"


async def test_memberships_the_cascade_takes_from_other_roles_are_reported(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DEFECT (low): D-029 says bootstrap prints each repair and records it in the audit row. A
    login with ADMIN OPTION on some role can grant that role to others; revoking the login's
    membership "CASCADE" then also revokes every membership granted that way, held by roles that
    are not ARGUS's. Those revocations are neither printed nor audited: the repaired list names
    only the login's own membership, so nothing records that another role lost one. Bootstrap
    should name what the cascade revoked (or refuse to cascade)."""
    group, user, team, bystander = (throwaway_roles() for _ in range(4))
    monkeypatch.setattr(roles, "RUNTIME_ROLE", group)
    login = _with_login(db_settings, test_database, user, f"fake-pw-{secrets.token_hex(8)}")
    await _bootstrap(db_settings, login, test_database)
    u, t, b = sql.Identifier(user), sql.Identifier(team), sql.Identifier(bystander)
    _as_superuser(
        db_settings,
        test_database,
        sql.SQL("CREATE ROLE {} NOLOGIN").format(t),
        sql.SQL("CREATE ROLE {} NOLOGIN").format(b),
        sql.SQL("GRANT {} TO {} WITH ADMIN OPTION").format(t, u),
    )
    with admin_connect(db_settings, test_database) as conn:
        conn.execute(sql.SQL("SET ROLE {}").format(u))
        conn.execute(sql.SQL("GRANT {} TO {}").format(t, b))
        conn.execute("RESET ROLE")
    refused: str | None = None
    changes: list[str] = []
    try:
        changes = await _bootstrap(db_settings, login, test_database)
    except (DBAPIError, roles.BootstrapError) as exc:  # refusing to cascade is a fix too
        refused = _driver_message(exc)
    if refused is None:
        assert _member_of(db_settings, test_database, user) == {group: (False, True)}
    kept = team in _member_of(db_settings, test_database, bystander)
    told = any(bystander in change for change in changes)
    assert kept or told, f"{bystander} lost its membership in {team} unreported: {changes}"


async def test_duplicate_and_optionless_grants_are_handled_grant_by_grant(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LOCK-IN: grants are handled one by one, as each grantor made them. Two grants of another
    role (one by the superuser without INHERIT or SET, one by a deputy with INHERIT) are both
    revoked and each reported; a second, harmless grant of the group by a deputy (INHERIT, SET
    FALSE, no ADMIN OPTION) is kept beside bootstrap's own; a second bootstrap has nothing left
    to repair."""
    group, user, extra, deputy = (throwaway_roles() for _ in range(4))
    monkeypatch.setattr(roles, "RUNTIME_ROLE", group)
    login = _with_login(db_settings, test_database, user, f"fake-pw-{secrets.token_hex(8)}")
    await _bootstrap(db_settings, login, test_database)
    g, u, x, d = (sql.Identifier(name) for name in (group, user, extra, deputy))
    _as_superuser(
        db_settings,
        test_database,
        sql.SQL("CREATE ROLE {} NOLOGIN").format(x),
        sql.SQL("CREATE ROLE {} NOLOGIN").format(d),
        sql.SQL("GRANT {} TO {} WITH ADMIN OPTION").format(x, d),
        sql.SQL("GRANT {} TO {} WITH ADMIN OPTION").format(g, d),
        sql.SQL("GRANT {} TO {} WITH INHERIT FALSE, SET FALSE").format(x, u),
    )
    with admin_connect(db_settings, test_database) as conn:
        conn.execute(sql.SQL("SET ROLE {}").format(d))
        conn.execute(sql.SQL("GRANT {} TO {} WITH INHERIT TRUE").format(x, u))
        conn.execute(sql.SQL("GRANT {} TO {} WITH INHERIT TRUE, SET FALSE").format(g, u))
        conn.execute("RESET ROLE")
    changes = await _bootstrap(db_settings, login, test_database)
    assert changes == [f"{user} was a member of {extra}: revoked"] * 2
    assert _member_of(db_settings, test_database, user) == {group: (False, True)}
    group_grants = [
        grant for grant in _grants(db_settings, test_database, user) if grant[0] == group
    ]
    assert len(group_grants) == 2
    assert await _bootstrap(db_settings, login, test_database) == []


async def test_memberships_other_roles_hold_in_the_login_or_the_group_are_left_alone(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LOCK-IN: bootstrap repairs what the login and the group are members of, never who is a
    member of them: a role the login itself is granted to, and another member of the group (with
    ADMIN OPTION even), keep their memberships, and nothing is reported."""
    group, user, holder, other = (throwaway_roles() for _ in range(4))
    monkeypatch.setattr(roles, "RUNTIME_ROLE", group)
    login = _with_login(db_settings, test_database, user, f"fake-pw-{secrets.token_hex(8)}")
    await _bootstrap(db_settings, login, test_database)
    g, u, h, o = (sql.Identifier(name) for name in (group, user, holder, other))
    _as_superuser(
        db_settings,
        test_database,
        sql.SQL("CREATE ROLE {} NOLOGIN").format(h),
        sql.SQL("CREATE ROLE {} NOLOGIN").format(o),
        sql.SQL("GRANT {} TO {}").format(u, h),
        sql.SQL("GRANT {} TO {} WITH ADMIN OPTION").format(g, o),
    )
    assert await _bootstrap(db_settings, login, test_database) == []
    assert _member_of(db_settings, test_database, holder) == {user: (False, True)}
    assert _member_of(db_settings, test_database, other) == {group: (True, True)}
    assert _member_of(db_settings, test_database, user) == {group: (False, True)}


async def test_a_group_made_a_member_of_its_login_is_put_back_the_right_way_round(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LOCK-IN: if the login lost the group and the group was made a member of the login instead
    (PostgreSQL then refuses the grant bootstrap needs, as a membership loop), bootstrap revokes
    the group's membership first, so granting the group to the login works, and says both."""
    group, user = throwaway_roles(), throwaway_roles()
    monkeypatch.setattr(roles, "RUNTIME_ROLE", group)
    login = _with_login(db_settings, test_database, user, f"fake-pw-{secrets.token_hex(8)}")
    await _bootstrap(db_settings, login, test_database)
    g, u = sql.Identifier(group), sql.Identifier(user)
    _as_superuser(
        db_settings,
        test_database,
        sql.SQL("REVOKE {} FROM {}").format(g, u),
        sql.SQL("GRANT {} TO {}").format(u, g),
    )
    changes = await _bootstrap(db_settings, login, test_database)
    assert changes == [
        f"{group} was a member of {user}: revoked",
        f"{user} was not a member of {group}: granted",
    ]
    assert _member_of(db_settings, test_database, group) == {}
    assert _member_of(db_settings, test_database, user) == {group: (False, True)}


async def test_a_createrole_owners_own_admin_grants_survive_its_repairs(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LOCK-IN: PostgreSQL 16+ grants a CREATEROLE owner ADMIN OPTION on each role it creates,
    which is what lets it manage them later. Bootstrap by such an owner repairs what the owner
    itself granted (another membership, ADMIN OPTION on the group) and a stored setting, rotates
    the password, keeps the owner's own ADMIN grants, and can run again."""
    settings = _createrole_owner(db_settings, test_database, throwaway_roles, monkeypatch)
    owner, group, user = settings.owner_user, roles.RUNTIME_ROLE, settings.user
    extra = throwaway_roles()
    await _bootstrap(settings, settings, test_database)
    with admin_connect(db_settings, test_database) as conn:  # damage this owner may undo
        conn.execute(sql.SQL("SET ROLE {}").format(sql.Identifier(owner)))
        conn.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(extra)))
        for role in (extra, group):
            conn.execute(
                sql.SQL("GRANT {} TO {} WITH ADMIN OPTION").format(
                    sql.Identifier(role), sql.Identifier(user)
                )
            )
        conn.execute(sql.SQL("ALTER ROLE {} SET work_mem = '1MB'").format(sql.Identifier(user)))
        conn.execute("RESET ROLE")
    rotated = settings.model_copy(update={"password": SecretStr(f"fake-pw-{secrets.token_hex(8)}")})
    changes = await _bootstrap(settings, rotated, test_database)
    assert sorted(changes) == sorted(
        [
            f"{user} had stored settings (work_mem): cleared",
            f"{user} was a member of {extra}: revoked",
            f"{user}'s membership in {group} had ADMIN OPTION: granted again",
        ]
    )
    assert _member_of(db_settings, test_database, user) == {group: (False, True)}
    owned = _member_of(db_settings, test_database, owner)
    assert {role: admin for role, (admin, _) in owned.items()} == {
        group: True,
        user: True,
        extra: True,
    }
    assert _login_problem(rotated, test_database) is None
    assert await _bootstrap(settings, rotated, test_database) == []


def _createrole_cli(
    names: RoleNames,
    settings: DatabaseSettings,
    database: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, DatabaseSettings, str]:
    """A CLI config whose owner is a new CREATEROLE login, with both roles created by a first
    ``argus db bootstrap``: the config, the settings and the owner's password."""
    login = _createrole_owner(settings, database, names, monkeypatch)
    assert login.password is not None
    assert login.owner_password is not None
    first, owner_secret = login.password.get_secret_value(), login.owner_password.get_secret_value()
    config = _cli_config(
        tmp_path,
        monkeypatch,
        settings,
        database,
        user=login.user,
        runtime_password=first,
        owner=login.owner_user,
        owner_secret=owner_secret,
    )
    created = _invoke(settings, "db", "bootstrap", "-c", str(config), hidden=(first, owner_secret))
    assert created.exit_code == 0, _scrub(created.output, [first, owner_secret])
    return config, login, owner_secret


@pytest.mark.parametrize("granted", ["a-predefined-role", "admin-option-on-the-group"])
def test_a_createrole_owner_stops_cleanly_at_a_grant_only_a_superuser_can_revoke(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    granted: str,
) -> None:
    """LOCK-IN: a CREATEROLE owner may revoke only grants made by roles whose privileges it has.
    When the superuser granted the login pg_read_server_files, or ADMIN OPTION on the group,
    bootstrap stops with exit code 1 and one line, no traceback and no secret, and everything it
    had done is rolled back: the password rotation, the stored setting it cleared, the
    memberships."""
    config, login, owner_secret = _createrole_cli(
        throwaway_roles, db_settings, test_database, tmp_path, monkeypatch
    )
    user, group = login.user, roles.RUNTIME_ROLE
    role = "pg_read_server_files" if granted == "a-predefined-role" else group
    _as_superuser(
        db_settings,
        test_database,
        sql.SQL("GRANT {} TO {} WITH ADMIN OPTION").format(
            sql.Identifier(role), sql.Identifier(user)
        ),
        sql.SQL("ALTER ROLE {} SET work_mem = '1MB'").format(sql.Identifier(user)),
    )
    before = _grants(db_settings, test_database, user)
    assert login.password is not None
    first, second = login.password.get_secret_value(), f"fake-second-pw-{secrets.token_hex(8)}"
    monkeypatch.setenv("ARGUS_DATABASE__PASSWORD", second)
    hidden = (first, second, owner_secret)
    result = _invoke(db_settings, "db", "bootstrap", "-c", str(config), hidden=hidden)
    assert _uncaught(result, hidden) is None
    assert result.exit_code == 1, _scrub(result.output, hidden)
    lines = _error_lines(result)
    assert len(lines) == 1, [_scrub(line, hidden) for line in lines]
    assert _grants(db_settings, test_database, user) == before
    assert _stored(db_settings, test_database, user) == {"*": ["work_mem"]}
    assert _login_problem(login, test_database) is None
    renewed = _with_login(login, test_database, user, second)
    assert _login_problem(renewed, test_database) is not None


# =========================================================================== 2. attributes


async def test_every_combination_of_drifted_attributes_is_repaired_by_a_superuser_owner(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LOCK-IN: all 128 combinations of the seven attributes, on the login (with a connection
    limit of 0, 1 or 100 and a password expiry in the past, the future or at -infinity, in turn)
    and on the group: a superuser owner puts each back in one bootstrap and names exactly the
    attributes that had drifted. The group's limit and expiry are left alone (it cannot log in).
    Afterwards the login logs in."""
    group, user = throwaway_roles(), throwaway_roles()
    monkeypatch.setattr(roles, "RUNTIME_ROLE", group)
    login = _with_login(db_settings, test_database, user, f"fake-pw-{secrets.token_hex(8)}")
    await _bootstrap(db_settings, login, test_database)
    engine = create_engine(db_settings, database=test_database, role="owner")
    wrong: list[str] = []
    try:
        with admin_connect(db_settings, test_database) as admin:
            for role, safe in ((user, SAFE_LOGIN), (group, SAFE_GROUP)):
                combinations = itertools.product((False, True), repeat=len(FLAGS))
                for index, flags in enumerate(combinations):
                    limit = LIMITS[index % len(LIMITS)] if role == user else -1
                    expiry = EXPIRIES[index % len(EXPIRIES)] if role == user else "infinity"
                    _stage(admin, role, flags, limit, expiry)
                    changes: list[str] = []
                    async with engine.begin() as conn:
                        await roles.ensure_roles(conn, login, changes=changes)
                    expected = {
                        name if on else f"NO{name}"
                        for name, on, want in zip(FLAGS, flags, safe, strict=True)
                        if on != want
                    }
                    expected |= {"a connection limit"} if limit != -1 else set()
                    expected |= {"a password expiry"} if expiry != "infinity" else set()
                    state = _attributes(admin, role)
                    fixed = state == (*safe, -1, "infinity")
                    if not fixed or _reported(changes, role) != expected:
                        wrong.append(f"{flags} {limit} {expiry}: {state} {changes}")
    finally:
        await engine.dispose()
    assert wrong == []
    assert _login_problem(login, test_database) is None


async def test_a_createrole_owner_repairs_what_it_may_and_changes_nothing_otherwise(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LOCK-IN: the same 128 combinations on each role, bootstrapped by a CREATEROLE owner that
    holds no other attribute. Since PostgreSQL 16 it may not take SUPERUSER, CREATEDB, REPLICATION
    or BYPASSRLS off a role: bootstrap fails (SQLSTATE 42501, or a BootstrapError) exactly when one
    of them drifted, and then nothing changed (attributes, limit, expiry and stored verifier as
    staged). Every other combination is put back, limit and expiry included."""
    settings = _createrole_owner(db_settings, test_database, throwaway_roles, monkeypatch)
    user, group = settings.user, roles.RUNTIME_ROLE
    await _bootstrap(settings, settings, test_database)
    engine = create_engine(settings, database=test_database, role="owner")
    wrong: list[str] = []
    try:
        with admin_connect(db_settings, test_database) as admin:
            for role, safe in ((user, SAFE_LOGIN), (group, SAFE_GROUP)):
                combinations = itertools.product((False, True), repeat=len(FLAGS))
                for index, flags in enumerate(combinations):
                    limit = LIMITS[index % len(LIMITS)] if role == user else -1
                    expiry = EXPIRIES[index % len(EXPIRIES)] if role == user else "infinity"
                    _stage(admin, role, flags, limit, expiry)
                    before = _attributes(admin, role)
                    verifier = _stored_verifier(admin, user)
                    drifted = {
                        name
                        for name, on, want in zip(FLAGS, flags, safe, strict=True)
                        if on != want
                    }
                    refused: str | None = None
                    try:
                        async with engine.begin() as conn:
                            await roles.ensure_roles(conn, settings)
                    except DBAPIError as exc:
                        refused = _sqlstate(exc)
                    except roles.BootstrapError:  # a clearer refusal is as good
                        refused = INSUFFICIENT_PRIVILEGE
                    after = _attributes(admin, role)
                    same_password = _stored_verifier(admin, user) == verifier
                    if drifted & NEEDS_MORE_THAN_CREATEROLE:
                        ok = refused == INSUFFICIENT_PRIVILEGE and after == before and same_password
                    else:
                        ok = refused is None and after == (*safe, -1, "infinity")
                    if not ok:
                        wrong.append(f"{role == user} {flags} {limit} {expiry}: {refused} {after}")
                _stage(admin, role, safe, -1, "infinity")
    finally:
        await engine.dispose()
    assert wrong == []


@pytest.mark.parametrize("attribute", sorted(NEEDS_MORE_THAN_CREATEROLE))
def test_a_createrole_owner_says_which_attribute_of_which_role_it_cannot_take_off(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attribute: str,
) -> None:
    """DEFECT (low): a runtime login that is a superuser is the state D-029 exists to prevent.
    With a CREATEROLE owner, bootstrap fails and changes nothing, as it should, but all it says
    is "error: bootstrap failed: permission denied to alter role": not which role, not that it is
    a superuser (or has REPLICATION, BYPASSRLS or CREATEDB), not that only a superuser can repair
    it. PostgreSQL's DETAIL says so, but the CLI prints only the first line, so the operator is
    left to guess, and may give the owner more power instead. The error should name the login
    and the attribute."""
    config, login, owner_secret = _createrole_cli(
        throwaway_roles, db_settings, test_database, tmp_path, monkeypatch
    )
    user = login.user
    _as_superuser(
        db_settings,
        test_database,
        sql.SQL("ALTER ROLE {} {}").format(sql.Identifier(user), sql.SQL(attribute)),
    )
    assert login.password is not None
    first, second = login.password.get_secret_value(), f"fake-second-pw-{secrets.token_hex(8)}"
    monkeypatch.setenv("ARGUS_DATABASE__PASSWORD", second)
    hidden = (first, second, owner_secret)
    result = _invoke(db_settings, "db", "bootstrap", "-c", str(config), hidden=hidden)
    assert _uncaught(result, hidden) is None
    assert result.exit_code == 1, _scrub(result.output, hidden)
    with admin_connect(db_settings, test_database) as admin:
        assert _attributes(admin, user)[FLAGS.index(attribute)] is True  # nothing changed
    assert _login_problem(login, test_database) is None
    [line] = _error_lines(result)
    assert user in line, line
    assert attribute in line.upper(), line


# =========================================================================== 3. stored settings


def test_bootstrap_clears_settings_for_its_database_names_them_only_and_leaves_others(
    throwaway_roles: RoleNames,
    make_database: Callable[[], str],
    db_settings: DatabaseSettings,
    test_database: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LOCK-IN: settings stored on the login everywhere and in ARGUS's database are cleared, one
    stored for another database is left alone, and the console and the audit row name the
    cleared settings without any value (here a custom setting holding a fake secret), with DEBUG
    logs and SQLAlchemy's statement log on."""
    user, other = throwaway_roles(), make_database()
    password = f"fake-runtime-pw-{secrets.token_hex(8)}"
    value = f"fake-secret-setting-{secrets.token_hex(8)}"
    config = _cli_config(
        tmp_path,
        monkeypatch,
        db_settings,
        test_database,
        user=user,
        runtime_password=password,
        logging_section="logging:\n  level: DEBUG\n  format: json\n",
    )
    _log_every_statement(monkeypatch)
    for command in (["db", "upgrade"], ["db", "bootstrap"]):
        result = _invoke(db_settings, *command, "-c", str(config), hidden=(password,))
        assert result.exit_code == 0, _scrub(result.output, [password])
    u = sql.Identifier(user)
    _as_superuser(
        db_settings,
        test_database,
        sql.SQL("ALTER ROLE {} SET work_mem = '1MB'").format(u),
        sql.SQL("ALTER ROLE {} SET argus_reattack.token = {}").format(u, sql.Literal(value)),
        sql.SQL("ALTER ROLE {} IN DATABASE {} SET session_replication_role = replica").format(
            u, sql.Identifier(test_database)
        ),
        sql.SQL("ALTER ROLE {} IN DATABASE {} SET default_transaction_read_only = on").format(
            u, sql.Identifier(other)
        ),
    )
    result = _invoke(db_settings, "db", "bootstrap", "-c", str(config), hidden=(password,))
    assert result.exit_code == 0, _scrub(result.output, [password])
    names = "argus_reattack.token, session_replication_role, work_mem"
    repair = f"{user} had stored settings ({names}): cleared"
    told = [line for line in result.stdout.splitlines() if line.startswith("repaired:")]
    assert told == [f"repaired: {repair}"]
    assert _stored(db_settings, test_database, user) == {other: ["default_transaction_read_only"]}
    [(details, row)] = _query(
        db_settings,
        test_database,
        "SELECT details, audit_events::text FROM audit_events WHERE action = 'db.bootstrap'"
        " ORDER BY id DESC LIMIT 1",
    )
    assert details["repaired"] == [repair]
    value_shown = value in row or value in result.stdout
    assert not value_shown


async def test_a_createrole_owner_never_reports_a_setting_it_could_not_clear_as_cleared(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DEFECT: for a role that is not a superuser, ALTER ROLE ... RESET ALL silently keeps every
    setting it may not set itself (PostgreSQL's GUCArrayReset): superuser-only settings such as
    session_replication_role and log_statement, and custom placeholders. So bootstrap by a
    CREATEROLE owner reports "<login> had stored settings (argus_reattack.flag, log_statement,
    session_replication_role, work_mem): cleared" while only work_mem is gone: the login keeps
    session_replication_role = replica, the very setting D-029 clears stored settings for, and the
    audit row says it was removed. Bootstrap should read the settings again after RESET ALL and
    fail (or at least not claim them) while any remain."""
    settings = _createrole_owner(db_settings, test_database, throwaway_roles, monkeypatch)
    user = sql.Identifier(settings.user)
    await _bootstrap(settings, settings, test_database)
    _as_superuser(
        db_settings,
        test_database,
        sql.SQL("ALTER ROLE {} SET session_replication_role = replica").format(user),
        sql.SQL("ALTER ROLE {} SET argus_reattack.flag = 'on'").format(user),
        sql.SQL("ALTER ROLE {} SET work_mem = '1MB'").format(user),
        sql.SQL("ALTER ROLE {} IN DATABASE {} SET log_statement = 'none'").format(
            user, sql.Identifier(test_database)
        ),
    )
    refused: str | None = None
    changes: list[str] = []
    try:
        changes = await _bootstrap(settings, settings, test_database)
    except (DBAPIError, roles.BootstrapError) as exc:
        refused = _driver_message(exc)
    left = _stored(db_settings, test_database, settings.user)
    assert refused is not None or left == {}, f"bootstrap reported {changes}; still stored: {left}"


@pytest.mark.parametrize(
    "statement",
    [
        "ALTER DATABASE {database} SET session_replication_role = replica",
        "ALTER ROLE ALL IN DATABASE {database} SET session_replication_role = replica",
    ],
    ids=["for-the-database", "for-every-role-in-the-database"],
)
async def test_doctor_sees_a_setting_stored_for_every_role_in_argus_database(
    make_login: MakeLogin,
    migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
    statement: str,
) -> None:
    """DEFECT: round 3 made doctor fail a runtime login with settings stored on it, because
    session_replication_role = replica stored by a superuser makes every ARGUS session skip
    ordinary triggers and foreign-key checks. The same setting stored for the whole database (or
    for every role in it) reaches every ARGUS session just the same, but doctor only looks at the
    rows stored for the login itself (pg_db_role_setting.setrole = the login), and bootstrap
    leaves them too: doctor passes while the runtime session runs with session_replication_role =
    replica. Doctor should check where the session's settings come from (pg_settings.source
    'database', 'user', 'database user' or 'global'). Only this throwaway database gets it."""
    login = await make_login()
    _as_superuser(
        db_settings,
        test_database,
        sql.SQL(statement).format(database=sql.Identifier(test_database)),
    )
    engine = create_engine(login, database=test_database)
    try:
        async with engine.connect() as conn:
            shown = (await conn.exec_driver_sql("SHOW session_replication_role")).scalar_one()
        problems = await roles.runtime_role_problems(engine)
    finally:
        await engine.dispose()
    assert shown == "replica"  # every ARGUS session runs with it
    assert any("session_replication_role" in problem for problem in problems), problems


@pytest.mark.parametrize("damage", ["member-of-another-role", "settings-stored-on-it", "superuser"])
def test_doctor_points_to_bootstrap_for_the_login_states_bootstrap_now_repairs(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    damage: str,
) -> None:
    """DEFECT (low): D-029's amendment says "Doctor points to argus db bootstrap for every login
    state that bootstrap repairs". It does so when the login cannot connect, but not in its
    "runtime role" check, which is where the states bootstrap gained in round 3 show up: another
    membership, settings stored on the login, a dangerous attribute. Doctor names the problem
    ("is a member of ...", "has settings stored on it (...)", "is a superuser") and stops there,
    so the operator is not told that one bootstrap repairs it."""
    login = throwaway_roles()
    password = f"fake-runtime-pw-{secrets.token_hex(8)}"
    config = _cli_config(
        tmp_path, monkeypatch, db_settings, test_database, user=login, runtime_password=password
    )
    for command in (["db", "bootstrap"], ["db", "upgrade"], ["doctor"]):
        result = _invoke(db_settings, *command, "-c", str(config), hidden=(password,))
        assert result.exit_code == 0, _scrub(result.output, [password])
    user = sql.Identifier(login)
    statement = {
        "member-of-another-role": sql.SQL("GRANT pg_read_server_files TO {}").format(user),
        "settings-stored-on-it": sql.SQL("ALTER ROLE {} SET work_mem = '1MB'").format(user),
        "superuser": sql.SQL("ALTER ROLE {} SUPERUSER").format(user),
    }[damage]
    _as_superuser(db_settings, test_database, statement)
    result = _invoke(db_settings, "doctor", "-c", str(config), hidden=(password,))
    assert result.exit_code == 1, _scrub(result.output, [password])
    failed = [line for line in result.output.splitlines() if line.startswith("FAIL")]
    assert [line.split()[1:3] for line in failed] == [["runtime", "role"]], failed
    assert "argus db bootstrap" in failed[0], failed[0]


# =========================================================================== 4. secrets


def _blocker_statements(case: str, user: str, group: str, extra: str) -> list[sql.Composable]:
    """What an uncommitted transaction holds so that bootstrap waits at the statement ``case``."""
    u, g = sql.Identifier(user), sql.Identifier(group)
    return {
        "create-login": [sql.SQL("CREATE ROLE {} NOLOGIN").format(u)],
        "alter-attributes": [sql.SQL("ALTER ROLE {} CONNECTION LIMIT 5").format(u)],
        "alter-password": [sql.SQL("ALTER ROLE {} CONNECTION LIMIT 5").format(u)],
        "reset-settings": [sql.SQL("ALTER ROLE {} SET work_mem = '2MB'").format(u)],
        "revoke-membership": [
            sql.SQL("GRANT {} TO {} WITH INHERIT FALSE").format(sql.Identifier(extra), u)
        ],
        "grant-membership": [sql.SQL("GRANT {} TO {}").format(g, u)],
    }[case]


def _staged_damage(case: str, user: str, group: str, extra: str) -> list[sql.Composable]:
    """What must already be wrong (committed) for bootstrap to reach the statement ``case``."""
    u, g = sql.Identifier(user), sql.Identifier(group)
    return {
        "alter-attributes": [sql.SQL("ALTER ROLE {} CREATEDB").format(u)],
        "reset-settings": [sql.SQL("ALTER ROLE {} SET work_mem = '1MB'").format(u)],
        "revoke-membership": [
            sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(extra)),
            sql.SQL("GRANT {} TO {}").format(sql.Identifier(extra), u),
        ],
        "grant-membership": [sql.SQL("REVOKE {} FROM {}").format(g, u)],
    }.get(case, [])


# Each case and a piece of the statement bootstrap must be waiting at when it gives up.
_WAITS_AT = {
    "advisory-lock": "pg_advisory_xact_lock",
    "create-login": "CREATE ROLE",
    "alter-attributes": "WITH NOCREATEDB",
    "alter-password": "WITH PASSWORD",
    "reset-settings": "RESET ALL",
    "revoke-membership": "REVOKE ",
    "grant-membership": "GRANT ",
}
_BLOCKED = list(_WAITS_AT)
# Statements SQLAlchemy runs around bootstrap's own.
_BOOKKEEPING = ("BEGIN", "SAVEPOINT", "RELEASE SAVEPOINT", "ROLLBACK", "COMMIT")


def _logged_statements(result: Result) -> list[str]:
    """The statements SQLAlchemy logged during a CLI run with JSON logs, in order."""
    statements: list[str] = []
    for line in result.stderr.splitlines():
        if line.startswith("{"):
            record = json.loads(line)
            event = record.get("event")
            engine = record.get("logger") == "sqlalchemy.engine.Engine"
            # "[generated in ...]" and the like are the parameters of the statement before.
            if engine and isinstance(event, str) and not event.startswith("["):
                statements.append(event)
    return statements


@pytest.mark.parametrize("blocked", _BLOCKED)
def test_a_bootstrap_stopped_at_any_statement_fails_in_one_line_without_secrets(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    computed_verifiers: list[str],
    blocked: str,
) -> None:
    """LOCK-IN: bootstrap made to wait past its 1 s lock timeout at each of its statements (the
    advisory lock, CREATE ROLE with the verifier, ALTER of the attributes, ALTER ... PASSWORD,
    RESET ALL, REVOKE, GRANT), with DEBUG JSON logs and SQLAlchemy's statement log on, ends with
    exit code 1 and one error line about the timeout. Neither password nor any part of the
    verifier it computed reaches stdout or stderr (the logged role DDL shows "SCRAM-SHA-256$***"),
    and nothing it did is kept: the old password still works, the new one does not, the damage
    is still there."""
    group, user, extra = throwaway_roles(), throwaway_roles(), throwaway_roles()
    monkeypatch.setattr(roles, "RUNTIME_ROLE", group)
    first = f"fake-first-pw-{secrets.token_hex(8)}"
    second = f"fake-second-pw-{secrets.token_hex(8)}"
    hidden = (first, second)
    config = _cli_config(
        tmp_path,
        monkeypatch,
        db_settings,
        test_database,
        user=user,
        runtime_password=first,
        extra="  statement_timeout: 1s\n",
        logging_section="logging:\n  level: DEBUG\n  format: json\n",
    )
    _log_every_statement(monkeypatch)
    if blocked == "create-login":  # only the group exists: CREATE ROLE is the login's
        _as_superuser(
            db_settings,
            test_database,
            sql.SQL("CREATE ROLE {} NOLOGIN INHERIT").format(sql.Identifier(group)),
        )
    else:
        created = _invoke(
            db_settings,
            "db",
            "bootstrap",
            "-c",
            str(config),
            hidden=hidden,
            verifiers=computed_verifiers,
        )
        assert created.exit_code == 0, _scrub(created.output, hidden)
    damage = _staged_damage(blocked, user, group, extra)
    if damage:
        _as_superuser(db_settings, test_database, *damage)
    before = _grants(db_settings, test_database, user)
    monkeypatch.setenv("ARGUS_DATABASE__PASSWORD", second)
    with admin_connect(db_settings, test_database) as blocker:
        if blocked == "advisory-lock":
            blocker.execute("SELECT pg_advisory_lock(%s)", (roles.BOOTSTRAP_LOCK_KEY,))
            result = _invoke(
                db_settings,
                "db",
                "bootstrap",
                "-c",
                str(config),
                hidden=hidden,
                verifiers=computed_verifiers,
            )
        else:
            with blocker.transaction(force_rollback=True):
                for statement in _blocker_statements(blocked, user, group, extra):
                    blocker.execute(statement)
                result = _invoke(
                    db_settings,
                    "db",
                    "bootstrap",
                    "-c",
                    str(config),
                    hidden=hidden,
                    verifiers=computed_verifiers,
                )
    assert _uncaught(result, hidden) is None
    assert result.exit_code == 1, _scrub(result.output, hidden)
    [line] = _error_lines(result)
    assert line.startswith("error: bootstrap failed: canceling statement due to"), line
    waited_at = [stmt for stmt in _logged_statements(result) if not stmt.startswith(_BOOKKEEPING)]
    assert waited_at, "no statement was logged"
    assert _WAITS_AT[blocked] in waited_at[-1], waited_at[-1][:60]  # the intended statement
    if blocked in ("create-login", "alter-password"):  # the statement with the verifier was logged
        assert MASKED_VERIFIER in result.output + result.stderr
    if blocked == "create-login":
        exists = _query(
            db_settings, test_database, "SELECT 1 FROM pg_roles WHERE rolname = %s", (user,)
        )
        assert exists == []
        return
    old = _with_login(db_settings, test_database, user, first)
    new = _with_login(db_settings, test_database, user, second)
    assert _login_problem(old, test_database) is None
    assert _login_problem(new, test_database) is not None
    assert _grants(db_settings, test_database, user) == before
    if blocked == "alter-attributes":
        with admin_connect(db_settings, test_database) as admin:
            assert _attributes(admin, user)[FLAGS.index("CREATEDB")] is True
    if blocked == "reset-settings":
        assert _stored(db_settings, test_database, user) == {"*": ["work_mem"]}


async def _failed_role_statement(
    settings: DatabaseSettings,
    login: DatabaseSettings,
    database: str,
    held: sql.Composable,
) -> DBAPIError:
    """The DBAPIError of an ensure_roles that waits past a 1 s lock timeout while another
    transaction holds ``held``."""
    quick = settings.model_copy(update={"statement_timeout": timedelta(seconds=1)})
    engine = create_engine(quick, database=database, role="owner")
    caught: DBAPIError | None = None
    try:
        with admin_connect(settings, database) as blocker, blocker.transaction(force_rollback=True):
            blocker.execute(held)
            try:
                async with engine.begin() as conn:
                    await roles.ensure_roles(conn, login)
            except DBAPIError as exc:
                caught = exc
    finally:
        await engine.dispose()
    assert caught is not None, "bootstrap did not fail"
    assert _sqlstate(caught) in BLOCKED_TOO_LONG, _driver_message(caught)
    return caught


@pytest.mark.parametrize("held", ["the-bootstrap-lock", "its-own-catalog-row"])
async def test_the_runtime_login_can_only_delay_its_repair_by_the_lock_timeout(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
    held: str,
) -> None:
    """LOCK-IN (a residual risk, as for the migration lock in test_adv_roles.py): the login that
    bootstrap repairs needs no privilege to stand in its way. It can hold the bootstrap advisory
    lock in ARGUS's database, or lock its own catalog row by changing its own password in a
    transaction it keeps open. Bootstrap then fails within its lock timeout instead of hanging,
    and nothing it did is kept; ending the login's sessions (or revoking its CONNECT) first is
    the operator's way through."""
    group, user = throwaway_roles(), throwaway_roles()
    monkeypatch.setattr(roles, "RUNTIME_ROLE", group)
    login = _with_login(db_settings, test_database, user, f"fake-pw-{secrets.token_hex(8)}")
    await _bootstrap(db_settings, login, test_database)
    assert login.password is not None
    renewed = login.model_copy(update={"password": SecretStr(f"fake-pw-{secrets.token_hex(8)}")})
    quick = db_settings.model_copy(update={"statement_timeout": timedelta(seconds=1)})
    refused: str | None = None
    started = time.monotonic()
    with psycopg.connect(
        host=login.host,
        port=login.port,
        user=user,
        password=login.password.get_secret_value(),
        dbname=test_database,
        connect_timeout=5,
    ) as runtime:
        if held == "the-bootstrap-lock":
            runtime.execute("SELECT pg_advisory_lock(%s)", (roles.BOOTSTRAP_LOCK_KEY,))
        else:  # psycopg leaves this transaction open until the connection closes
            own = f"fake-own-pw-{secrets.token_hex(8)}"
            runtime.execute(sql.SQL("ALTER ROLE CURRENT_USER PASSWORD {}").format(sql.Literal(own)))
        try:
            await _bootstrap(quick, renewed, test_database)
        except DBAPIError as exc:
            refused = _sqlstate(exc)
        runtime.rollback()
    assert refused in BLOCKED_TOO_LONG, refused
    assert time.monotonic() - started < 20
    assert _login_problem(login, test_database) is None  # the repair was rolled back
    assert _login_problem(renewed, test_database) is not None


@pytest.mark.parametrize("blocked", ["create-login", "alter-password"])
async def test_pytest_reports_a_failed_role_statement_without_its_verifier(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
    computed_verifiers: list[str],
    blocked: str,
) -> None:
    """DEFECT: round 3 redacted the verifier from the exception's text, but pytest reports a
    failing test with the arguments of the first and the last frame of the traceback (the
    default --tb=auto), and for a failed role statement the last frame is psycopg's
    cursor.execute(query), with the whole statement as ``query``: ``ALTER ROLE ... WITH PASSWORD
    'SCRAM-SHA-256$4096:...'`` in full, and for the longer CREATE ROLE, whose middle saferepr
    cuts out, still the salt, StoredKey and ServerKey. The session fixture _runtime_roles
    bootstraps the real argus_app at the start of every integration run, so a lock timeout there
    (several sessions bootstrapping at once) prints the real login's verifier in every report,
    and hide_in_reports masks only the passwords. Here pytest's own hooks build the report the
    failure would get, the harness's masking included. Reports should mask SCRAM verifiers
    too."""
    group, user = throwaway_roles(), throwaway_roles()
    monkeypatch.setattr(roles, "RUNTIME_ROLE", group)
    login = _with_login(db_settings, test_database, user, f"fake-pw-{secrets.token_hex(8)}")
    u = sql.Identifier(user)
    if blocked == "create-login":
        _as_superuser(
            db_settings,
            test_database,
            sql.SQL("CREATE ROLE {} NOLOGIN INHERIT").format(sql.Identifier(group)),
        )
        held = sql.SQL("CREATE ROLE {} NOLOGIN").format(u)
    else:
        await _bootstrap(db_settings, login, test_database)
        held = sql.SQL("ALTER ROLE {} CONNECTION LIMIT 5").format(u)
    caught = await _failed_role_statement(db_settings, login, test_database, held)
    assert computed_verifiers  # the verifier the failed statement held
    in_text = _shows_a_verifier(f"{caught} {caught!r}", computed_verifiers)
    assert not in_text  # round 3's fix: the exception's own text is redacted

    def fail() -> None:
        raise caught

    monkeypatch.setattr(request.config.option, "tbstyle", "auto")  # pytest's default
    monkeypatch.setattr(request.config.option, "showlocals", False)
    call = pytest.CallInfo.from_call(fail, when="call")
    report = request.node.ihook.pytest_runtest_makereport(item=request.node, call=call)
    in_report = _shows_a_verifier(str(report.longrepr), computed_verifiers)
    assert not in_report, "pytest's report of the failed bootstrap shows the SCRAM verifier"


async def test_a_debug_log_capture_never_records_the_password_verifier(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    computed_verifiers: list[str],
) -> None:
    """DEFECT: scripts/gate.sh runs the whole suite with ``-o log_cli=true --log-cli-level=DEBUG``
    and ``-rA`` and keeps the output as data/gate/<time>/session.log. pytest then sets the root
    logger to DEBUG for the whole run, and SQLAlchemy's engine logger, which ARGUS's own logging
    setup caps at WARNING but nothing has capped before the first integration test, logs every
    statement at INFO to pytest's handlers, where ARGUS's redaction never sees it. The session
    fixture _runtime_roles runs ``ALTER ROLE "argus_app" WITH PASSWORD '<verifier>'`` first thing,
    so every gate log holds the real runtime login's SCRAM verifier, and the gate's secret scan
    (scripts/secret_scan.py) only looks for the passwords themselves. Here a throwaway login is
    created and bootstrapped again with SQLAlchemy's statement log captured. A statement holding
    a verifier should never reach that logger unredacted (run it past SQLAlchemy's logging, or
    redact on that logger itself), whoever turns the log on."""
    group, user = throwaway_roles(), throwaway_roles()
    monkeypatch.setattr(roles, "RUNTIME_ROLE", group)
    login = _with_login(db_settings, test_database, user, f"fake-pw-{secrets.token_hex(8)}")
    caplog.set_level(logging.DEBUG, logger="sqlalchemy.engine")  # as under --log-cli-level=DEBUG
    for _ in range(2):  # CREATE ROLE ... PASSWORD, then ALTER ROLE ... PASSWORD
        await _bootstrap(db_settings, login, test_database)
    captured = caplog.text
    assert "CREATE ROLE" in captured  # the role DDL was captured
    assert "WITH PASSWORD" in captured
    leaked = _shows_a_verifier(captured, computed_verifiers)
    assert not leaked, "the captured DEBUG log holds the login's SCRAM verifier"


# =========================================================================== 5. concurrency


async def _overlapping(
    owner: DatabaseSettings,
    databases: Sequence[str],
    logins: Sequence[DatabaseSettings],
    *,
    hold: float,
) -> list[tuple[str | None, list[str]]]:
    """Bootstrap ``logins[i]`` on ``databases[i]``, all at once, the way the CLI does (roles,
    then CONNECT), each holding its transaction open for ``hold`` seconds so that they overlap.
    Connections are made first, so the runs start together. Per run: the server's message if it
    failed, and the repairs it reported."""
    engines = [create_engine(owner, database=database, role="owner") for database in databases]

    async def run(index: int) -> tuple[str | None, list[str]]:
        database, changes = databases[index], []
        target = logins[index].model_copy(update={"name": database})
        try:
            async with engines[index].begin() as conn:
                await roles.ensure_roles(conn, target, changes=changes)
                await roles.grant_connect(conn, database)
                await asyncio.sleep(hold)
        except DBAPIError as exc:
            return _driver_message(exc), changes
        return None, changes

    try:
        for engine in engines:
            async with engine.connect() as conn:
                await conn.exec_driver_sql("SELECT 1")
        return await asyncio.wait_for(
            asyncio.gather(*(run(index) for index in range(len(databases)))), timeout=120
        )
    finally:
        for engine in engines:
            await engine.dispose()


async def test_eight_bootstraps_of_a_damaged_login_on_one_database_repair_it_once(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LOCK-IN: eight bootstraps at once on one database, of a login with drifted attributes, a
    stored setting, another membership and ADMIN OPTION on the group: the advisory lock runs them
    one after the other, all succeed, the first repairs everything (and alone reports it), and
    the login ends as D-029 wants it."""
    group, user, extra = throwaway_roles(), throwaway_roles(), throwaway_roles()
    monkeypatch.setattr(roles, "RUNTIME_ROLE", group)
    login = _with_login(db_settings, test_database, user, f"fake-pw-{secrets.token_hex(8)}")
    await _bootstrap(db_settings, login, test_database)
    g, u, x = sql.Identifier(group), sql.Identifier(user), sql.Identifier(extra)
    _as_superuser(
        db_settings,
        test_database,
        sql.SQL("CREATE ROLE {} NOLOGIN").format(x),
        sql.SQL("GRANT {} TO {}").format(x, u),
        sql.SQL("GRANT {} TO {} WITH ADMIN OPTION").format(g, u),
        sql.SQL("ALTER ROLE {} CREATEDB CONNECTION LIMIT 3").format(u),
        sql.SQL("ALTER ROLE {} SET work_mem = '1MB'").format(u),
    )
    outcomes = await _overlapping(db_settings, [test_database] * 8, [login] * 8, hold=0.2)
    assert [error for error, _ in outcomes if error] == []
    reports = [changes for _, changes in outcomes if changes]
    assert len(reports) == 1, reports
    assert len(reports[0]) == 4, reports[0]
    assert _member_of(db_settings, test_database, user) == {group: (False, True)}
    assert _stored(db_settings, test_database, user) == {}
    with admin_connect(db_settings, test_database) as admin:
        assert _attributes(admin, user) == (*SAFE_LOGIN, -1, "infinity")
    assert _login_problem(login, test_database) is None


async def test_six_bootstraps_on_six_databases_at_once_all_succeed(
    throwaway_roles: RoleNames,
    make_database: Callable[[], str],
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DEFECT (low): the advisory lock belongs to one database, so bootstraps of one login on
    different databases still collide on its catalog row, and _retrying gives each statement 5
    attempts: of N overlapping runs the last needs N, so the sixth fails with "tuple concurrently
    updated" (in a probe without any delay, 3 of 8 runs failed in every round). The CLI and the
    test harness bootstrap the same login from many databases (argus_app from every throwaway
    database of every concurrent pytest session). A conflict should be retried until the lock
    timeout instead of a fixed number of times, or bootstraps serialised across databases."""
    group, user = throwaway_roles(), throwaway_roles()
    monkeypatch.setattr(roles, "RUNTIME_ROLE", group)
    login = _with_login(db_settings, test_database, user, f"fake-pw-{secrets.token_hex(8)}")
    await _bootstrap(db_settings, login, test_database)
    databases = [test_database, *(make_database() for _ in range(5))]
    outcomes = await _overlapping(db_settings, databases, [login] * len(databases), hold=0.5)
    assert [error for error, _ in outcomes if error] == []
    assert _login_problem(login, test_database) is None


async def test_a_membership_repair_racing_a_password_change_on_another_database(
    throwaway_roles: RoleNames,
    make_database: Callable[[], str],
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LOCK-IN: two bootstraps at once on two databases, each with its own new password, while
    the login has another membership and ADMIN OPTION on the group and the group is a member of
    another role: in three rounds both succeed every time, the memberships end right, and exactly
    one of the two passwords works (the one committed last)."""
    group, user, extra, outer = (throwaway_roles() for _ in range(4))
    monkeypatch.setattr(roles, "RUNTIME_ROLE", group)
    login = _with_login(db_settings, test_database, user, f"fake-pw-{secrets.token_hex(8)}")
    await _bootstrap(db_settings, login, test_database)
    other = make_database()
    g, u, x, o = (sql.Identifier(name) for name in (group, user, extra, outer))
    _as_superuser(
        db_settings,
        test_database,
        sql.SQL("CREATE ROLE {} NOLOGIN").format(x),
        sql.SQL("CREATE ROLE {} NOLOGIN").format(o),
    )
    for _ in range(3):
        _as_superuser(
            db_settings,
            test_database,
            sql.SQL("GRANT {} TO {}").format(x, u),
            sql.SQL("GRANT {} TO {} WITH ADMIN OPTION").format(g, u),
            sql.SQL("GRANT {} TO {}").format(o, g),
        )
        databases = [test_database, other]
        logins = [
            _with_login(db_settings, database, user, f"fake-pw-{secrets.token_hex(8)}")
            for database in databases
        ]
        outcomes = await _overlapping(db_settings, databases, logins, hold=0.2)
        assert [error for error, _ in outcomes if error] == []
        assert _member_of(db_settings, test_database, user) == {group: (False, True)}
        assert _member_of(db_settings, test_database, group) == {}
        works = [_login_problem(each, test_database) is None for each in logins]
        assert sorted(works) == [False, True]


# =========================================================================== 6. CONNECT


async def test_the_connect_remedy_a_failed_first_bootstrap_prints_can_be_followed(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DEFECT: on D-029's shared host the owner has CREATEROLE, a DBA owns the database and
    PUBLIC may not connect. The first bootstrap there fails (grant_connect's new check, rightly)
    and says "Ask the database's owner to run GRANT CONNECT ON DATABASE <db> TO <group>". But the
    whole bootstrap was one transaction, so the group role it had just created was rolled back
    with it: the DBA's GRANT fails with 'role "<group>" does not exist', and bootstrap keeps
    failing the same way. The advice cannot be followed (unless the DBA thinks of creating the
    role, or of giving the owner CONNECT WITH GRANT OPTION). Bootstrap should keep the roles, or
    name a remedy that works before they exist."""
    settings = _createrole_owner(db_settings, test_database, throwaway_roles, monkeypatch)
    database = sql.Identifier(test_database)
    _as_superuser(
        db_settings,
        test_database,
        sql.SQL("REVOKE CONNECT ON DATABASE {} FROM PUBLIC").format(database),
        sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
            database, sql.Identifier(settings.owner_user)
        ),
    )
    with pytest.raises(roles.BootstrapError) as info:
        await _bootstrap(settings, settings, test_database)
    message = str(info.value)
    assert "run " in message, message
    remedy = message.split("run ", 1)[1]
    assert remedy.startswith("GRANT CONNECT ON DATABASE"), message
    problem: str | None = None
    try:  # what the database's owner (here the superuser) is asked to run
        _as_superuser(db_settings, test_database, remedy)
    except psycopg.Error as exc:
        problem = _driver_message(exc)
    assert problem is None, f"the GRANT bootstrap asks for fails: {problem}"
    await _bootstrap(settings, settings, test_database)
    assert _login_problem(settings, test_database) is None


async def test_grant_connect_is_satisfied_by_public_when_the_owner_cannot_grant(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LOCK-IN: grant_connect's new check asks whether the group may connect, not whether the
    GRANT did anything: a CREATEROLE owner that cannot grant CONNECT (PostgreSQL only warns) on a
    database where PUBLIC may connect bootstraps without an error, and the login logs in."""
    settings = _createrole_owner(db_settings, test_database, throwaway_roles, monkeypatch)
    await _bootstrap(settings, settings, test_database)
    [(explicit,)] = _query(
        db_settings,
        test_database,
        "SELECT count(*) FROM pg_database d, aclexplode(d.datacl) a"
        " WHERE d.datname = %s AND a.grantee = to_regrole(%s)",
        (test_database, roles.RUNTIME_ROLE),
    )
    assert explicit == 0  # the GRANT granted nothing
    assert _login_problem(settings, test_database) is None


# =========================================================================== 7. the audit row


def test_a_bootstrap_with_more_to_repair_than_an_audit_row_holds_still_repairs(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DEFECT (low): the CLI records every repair in the audit row, whose details record_audit
    caps at 64 KiB, and it catches only database errors and BootstrapError. With enough to repair
    (here 1,100 settings stored on the login; a few hundred memberships would do) record_audit
    raises AuditError: it escapes the CLI as a traceback, and because the audit insert shares
    bootstrap's transaction every repair is rolled back, on every run, so bootstrap can never
    repair that login. The repaired list should be capped in the audit row (with a count), and
    an audit failure reported in one line."""
    user = throwaway_roles()
    password = f"fake-runtime-pw-{secrets.token_hex(8)}"
    config = _cli_config(
        tmp_path, monkeypatch, db_settings, test_database, user=user, runtime_password=password
    )
    for command in (["db", "upgrade"], ["db", "bootstrap"]):
        result = _invoke(db_settings, *command, "-c", str(config), hidden=(password,))
        assert result.exit_code == 0, _scrub(result.output, [password])
    _as_superuser(
        db_settings,
        test_database,
        sql.SQL(
            "DO $$ BEGIN FOR i IN 1..1100 LOOP EXECUTE format('ALTER ROLE %I SET %I = ''x''', {},"
            " 'argus_reattack.s' || lpad(i::text, 4, '0') || repeat('x', 42)); END LOOP; END $$"
        ).format(sql.Literal(user)),
    )
    result = _invoke(db_settings, "db", "bootstrap", "-c", str(config), hidden=(password,))
    uncaught = _uncaught(result, [password])
    assert uncaught is None, f"exception escaped the CLI (a traceback): {uncaught}"
    assert result.exit_code == 0, _scrub(result.output, [password])
    assert _stored(db_settings, test_database, user) == {}
