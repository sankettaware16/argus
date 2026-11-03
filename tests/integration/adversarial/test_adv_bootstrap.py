"""Adversarial: ``argus db bootstrap`` (D-029), the setup path and its secret handling.

Attacks how ARGUS creates and repairs its roles (``argus.db.roles.ensure_roles`` and
``grant_connect``, the CLI's ``db bootstrap``), the passwords and SCRAM verifiers that pass through
it, doctor's hints for a broken runtime login, migration 0003 and the harness's stale-role cleanup.
Cases that need no database are in tests/unit/adversarial/test_adv_roles_config.py.

Conventions, as in the sibling adversarial files: a docstring starting with **DEFECT** marks a test
that fails on the current code on purpose and passes once the hole is closed; **LOCK-IN** tests
pass today and pin behaviour that held up under attack.

Safety:
* Databases are throwaway ``argus_test_*`` ones from tests/integration/conftest.py.
* Roles are cluster-wide. ``argus``, ``argus_app`` and ``argus_runtime`` are never changed: tests
  change only logins from ``make_login`` and roles of their own from ``throwaway_roles``, named
  ``argus_test_role_<unix>_<8 hex>`` like make_login's (so the stale cleanup recognises a
  leftover) and dropped afterwards. A test that must create or damage the group role points
  ``roles.RUNTIME_ROLE`` at a throwaway name while it runs.
* Passwords are synthetic, except the local owner password, which reaches the CLI only through
  the environment. Output is checked for passwords and SCRAM verifiers as booleans, and failures
  are reported with the server's message only, never the SQL (which holds the verifier), so a
  failing test prints neither.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import io
import logging
import os
import re
import secrets
import time
import traceback
from collections.abc import Awaitable, Callable, Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import psycopg
import pytest
from alembic.operations import Operations
from psycopg import sql
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import CliRunner, Result

import argus.cli as cli
import tests.integration.conftest as harness
from argus.cli import app
from argus.config import ConfigError, DatabaseSettings
from argus.db import migrate, roles
from argus.db.audit import record_audit
from argus.db.engine import create_engine, session_factory
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
MakeLogin = Callable[[], Awaitable[DatabaseSettings]]
RoleNames = Callable[..., str]

# An unmasked SCRAM-SHA-256 verifier, iterations:salt$StoredKey:ServerKey. Redaction leaves
# "SCRAM-SHA-256$***", which this does not match.
VERIFIER = re.compile(r"SCRAM-SHA-256\$[0-9]+:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+")
# lock_timeout and statement_timeout are equal below 10 s (argus.db.engine): either may fire first.
BLOCKED_TOO_LONG = ("55P03", "57014")
# (rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, rolinherit)
SAFE_LOGIN = (True, False, False, False, False, False, True)
SAFE_GROUP = (False, False, False, False, False, False, True)


@pytest.fixture(autouse=True)
def _forget_cli_state() -> Iterator[None]:
    """The CLI registers the owner password for redaction and points logging at its captured
    stream; neither may outlive the test."""
    yield
    clear_registered_secrets()
    configure_logging("WARNING", "console", stream=io.StringIO())


@pytest.fixture
def throwaway_roles(db_settings: DatabaseSettings, test_database: str) -> Iterator[RoleNames]:
    """Names for roles a test creates itself, ``argus_test_role_<unix>_<8 hex>`` as make_login
    names its logins (``width`` pads the timestamp with zeros up to that many bytes). Afterwards
    each one that exists is dropped, newest first, with what it owns or was granted."""
    names: list[str] = []

    def _name(width: int | None = None) -> str:
        stamp, tag = str(int(time.time())), secrets.token_hex(4)
        if width is not None:
            stamp = stamp.zfill(width - len(TEST_ROLE_PREFIX) - 1 - len(tag))
        name = f"{TEST_ROLE_PREFIX}{stamp}_{tag}"
        assert TEST_ROLE_PATTERN.fullmatch(name), name  # the stale cleanup must recognise it
        names.append(name)
        return name

    yield _name
    failed: list[str] = []
    with admin_connect(db_settings, test_database) as conn:
        for name in reversed(names):
            if conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (name,)).fetchone():
                try:
                    conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(name)))
                    conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(name)))
                except psycopg.Error as exc:
                    failed.append(f"{name}: {_driver_message(exc)}")
    assert not failed, failed


# --------------------------------------------------------------------------- helpers


def _driver_message(exc: BaseException) -> str:
    """The server's message for ``exc`` with its DETAIL, never the SQL (which may hold a
    verifier)."""
    original = getattr(exc, "orig", None) or exc
    lines = str(original).strip().splitlines()
    shown = lines[:1] + [line.strip() for line in lines[1:] if line.startswith("DETAIL:")]
    return f"{type(original).__name__}: {' '.join(shown)}"


def _sqlstate(exc: BaseException) -> str | None:
    return getattr(getattr(exc, "orig", None), "sqlstate", None)


def _as_superuser(settings: DatabaseSettings, database: str, *statements: sql.Composable) -> None:
    with admin_connect(settings, database) as conn:
        for statement in statements:
            conn.execute(statement)


def _query(
    settings: DatabaseSettings, database: str, query: str, params: Any = ()
) -> list[tuple[Any, ...]]:
    with admin_connect(settings, database) as conn:
        return conn.execute(query, params).fetchall()


def _attributes(settings: DatabaseSettings, database: str, role: str) -> tuple[Any, ...]:
    rows = _query(
        settings,
        database,
        "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls,"
        " rolinherit FROM pg_roles WHERE rolname = %s",
        (role,),
    )
    assert len(rows) == 1, role
    return rows[0]


def _memberships(
    settings: DatabaseSettings, database: str, member: str
) -> dict[str, tuple[bool, bool, bool]]:
    """The roles ``member`` is a direct member of: name -> (admin, inherit, set) option."""
    rows = _query(
        settings,
        database,
        "SELECT r.rolname, am.admin_option, am.inherit_option, am.set_option"
        " FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.roleid"
        " JOIN pg_roles m ON m.oid = am.member WHERE m.rolname = %s",
        (member,),
    )
    return {str(name): (bool(adm), bool(inh), bool(st)) for name, adm, inh, st in rows}


def _admin_and_inherit(
    settings: DatabaseSettings, database: str, member: str
) -> dict[str, tuple[bool, bool]]:
    """Like _memberships, without the SET option (whether the login may SET ROLE to the group
    is harmless either way)."""
    return {role: options[:2] for role, options in _memberships(settings, database, member).items()}


def _with_login(
    settings: DatabaseSettings, database: str, user: str, password: str
) -> DatabaseSettings:
    return settings.model_copy(
        update={"user": user, "password": SecretStr(password), "name": database}
    )


async def _bootstrap(owner: DatabaseSettings, login: DatabaseSettings, database: str) -> list[str]:
    """What ``argus db bootstrap`` does for ``login``: roles and CONNECT, in one transaction."""
    engine = create_engine(owner, database=database, role="owner")
    try:
        async with engine.begin() as conn:
            created = await roles.ensure_roles(conn, login)
            await roles.grant_connect(conn, database)
            return created
    finally:
        await engine.dispose()


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


def _verifier_is_for(settings: DatabaseSettings, database: str, role: str, secret: bytes) -> bool:
    """Whether the role's stored SCRAM-SHA-256 verifier was made from ``secret`` (compared here,
    never shown)."""
    rows = _query(
        settings, database, "SELECT rolpassword FROM pg_authid WHERE rolname = %s", (role,)
    )
    stored = rows[0][0] if rows else None
    if not isinstance(stored, str) or not stored.startswith("SCRAM-SHA-256$"):
        return False
    iterations_salt, keys = stored.removeprefix("SCRAM-SHA-256$").split("$", 1)
    iterations, salt = iterations_salt.split(":", 1)
    stored_key = keys.split(":", 1)[0]
    salted = hashlib.pbkdf2_hmac("sha256", secret, base64.b64decode(salt), int(iterations))
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    return hmac.compare_digest(hashlib.sha256(client_key).digest(), base64.b64decode(stored_key))


# --------------------------------------------------------------------------- CLI helpers


def _cli_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    settings: DatabaseSettings,
    database: str,
    *,
    user: str,
    runtime_password: str | None = None,
    extra: str = "",
    logging_section: str = "logging:\n  level: WARNING\n",
) -> Path:
    """A config for the CLI that reaches only ``database``: no .env in reach, no other ARGUS_
    variable, the owner password in the environment, ``extra`` lines in the database section."""
    for key in list(os.environ):
        if key.upper().startswith("ARGUS_"):
            monkeypatch.delenv(key)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ARGUS_DATABASE__OWNER_PASSWORD", owner_password(settings))
    if runtime_password is not None:
        monkeypatch.setenv("ARGUS_DATABASE__PASSWORD", runtime_password)
    assert database.startswith(TEST_DB_PREFIX), database
    config = tmp_path / "argus.yaml"
    config.write_text(
        "database:\n"
        f"  host: '{settings.host}'\n"
        f"  port: {settings.port}\n"
        f"  name: '{database}'\n"
        f"  user: '{user}'\n"
        f"  owner_user: '{settings.owner_user}'\n"
        "  connect_timeout: 3s\n" + extra + logging_section + THROWAWAY_SITE,
        encoding="utf-8",
    )
    return config


def _scrub(output: str, hidden: list[str]) -> str:
    for secret in hidden:
        output = output.replace(secret, "***")
    return VERIFIER.sub("SCRAM-SHA-256$<unmasked>", output)


def _invoke(settings: DatabaseSettings, *args: str, hidden: tuple[str, ...] = ()) -> Result:
    """Run the CLI; fail (without printing them) if it printed a password or a verifier."""
    result = runner.invoke(app, list(args))
    shown = result.output + result.stderr
    passwords = [owner_password(settings), *hidden]
    printed = any(secret in shown for secret in passwords)
    assert not printed, "a database password appeared in CLI output"
    assert not VERIFIER.search(shown), "an unmasked SCRAM verifier appeared in CLI output"
    return result


def _uncaught(result: Result, hidden: list[str]) -> str | None:
    exc = result.exception
    if exc is None or isinstance(exc, SystemExit):
        return None
    first = str(exc).splitlines()[0][:200] if str(exc) else ""
    return _scrub(f"{type(exc).__module__}.{type(exc).__name__}: {first}", hidden)


def _error_lines(result: Result) -> list[str]:
    return [line for line in result.stderr.splitlines() if line.strip()]


# --------------------------------------------------------------------------- CREATEROLE owner


def _createrole_owner(
    settings: DatabaseSettings,
    database: str,
    names: RoleNames,
    monkeypatch: pytest.MonkeyPatch,
) -> DatabaseSettings:
    """Settings whose owner is a new non-superuser login with CREATEROLE (D-029's owner for a
    shared or production host), whose login is a new name, and whose group role is a new name
    (``roles.RUNTIME_ROLE`` points at it while the test runs)."""
    owner, group, login = names(), names(), names()
    password = secrets.token_urlsafe(24)
    hide_in_reports(password)
    _as_superuser(
        settings,
        database,
        sql.SQL("CREATE ROLE {} LOGIN CREATEROLE PASSWORD {}").format(
            sql.Identifier(owner), sql.Literal(password)
        ),
    )
    monkeypatch.setattr(roles, "RUNTIME_ROLE", group)
    return _with_login(settings, database, login, secrets.token_urlsafe(24)).model_copy(
        update={"owner_user": owner, "owner_password": SecretStr(password)}
    )


async def test_bootstrap_again_as_a_createrole_owner_rotates_the_password(
    db_settings: DatabaseSettings,
    test_database: str,
    throwaway_roles: RoleNames,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DEFECT: D-029 says a shared or production host uses a non-superuser owner with CREATEROLE
    "with no code change". The first bootstrap by such an owner works (LOCK-IN below), but every
    later one fails, so it can never rotate the runtime password or repair the login: for an
    existing login ensure_roles always runs ``ALTER ROLE <login> WITH LOGIN NOSUPERUSER ...
    NOREPLICATION NOBYPASSRLS INHERIT PASSWORD ...``, and since PostgreSQL 16 only a superuser
    may name the SUPERUSER attribute in ALTER ROLE at all, even to switch it off ("Only roles
    with the SUPERUSER attribute may change the SUPERUSER attribute"; REPLICATION and BYPASSRLS
    likewise). Bootstrap should name only the attributes that differ from the safe state and set
    the password on its own."""
    login = _createrole_owner(db_settings, test_database, throwaway_roles, monkeypatch)
    engine = create_engine(login, database=test_database, role="owner")
    rotated = login.model_copy(update={"password": SecretStr(secrets.token_urlsafe(24))})
    problem: str | None = None
    try:
        async with engine.begin() as conn:
            assert sorted(await roles.ensure_roles(conn, login)) == sorted(
                [roles.RUNTIME_ROLE, login.user]
            )
        try:
            async with engine.begin() as conn:
                await roles.ensure_roles(conn, rotated)
        except DBAPIError as exc:
            problem = _driver_message(exc)
    finally:
        await engine.dispose()
    if problem is not None:  # outside the except clause: the SQL (and verifier) is not chained
        pytest.fail(f"bootstrap again as a CREATEROLE owner failed: {problem}", pytrace=False)
    assert _login_problem(rotated, test_database) is None


async def test_first_bootstrap_by_a_createrole_owner_is_least_privileged(
    db_settings: DatabaseSettings,
    test_database: str,
    throwaway_roles: RoleNames,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LOCK-IN: under PostgreSQL 16+ CREATEROLE semantics a non-superuser owner can create both
    roles, and the result is what D-029 wants. The login has no dangerous attribute, is an
    inheriting, non-admin member of the group and of nothing else, and is not a member of the
    owner; the owner holds ADMIN OPTION on both roles it created (which is what lets it manage
    them later) and has gained no attribute."""
    login = _createrole_owner(db_settings, test_database, throwaway_roles, monkeypatch)
    group = roles.RUNTIME_ROLE
    engine = create_engine(login, database=test_database, role="owner")
    try:
        async with engine.begin() as conn:
            created = await roles.ensure_roles(conn, login)
    finally:
        await engine.dispose()
    assert sorted(created) == sorted([group, login.user])
    assert _attributes(db_settings, test_database, login.user) == SAFE_LOGIN
    assert _attributes(db_settings, test_database, group) == SAFE_GROUP
    assert _admin_and_inherit(db_settings, test_database, login.user) == {group: (False, True)}
    owner_admin = {
        role: options[0]
        for role, options in _memberships(db_settings, test_database, login.owner_user).items()
    }
    assert owner_admin == {group: True, login.user: True}
    owner = _attributes(db_settings, test_database, login.owner_user)
    assert owner == (True, False, False, True, False, False, True)  # LOGIN CREATEROLE only
    [(member_of_owner,)] = _query(
        db_settings,
        test_database,
        "SELECT pg_has_role(%s, %s, 'MEMBER')",
        (login.user, login.owner_user),
    )
    assert member_of_owner is False
    assert _login_problem(login, test_database) is None


# --------------------------------------------------------------------------- an existing login


@pytest.mark.parametrize(
    "damage",
    [
        pytest.param("VALID UNTIL '2000-01-01'", id="password-expired"),
        pytest.param("CONNECTION LIMIT 0", id="no-connection-allowed"),
    ],
)
async def test_bootstrap_makes_an_expired_or_capped_login_usable_again(
    make_login: MakeLogin, db_settings: DatabaseSettings, test_database: str, damage: str
) -> None:
    """DEFECT: bootstrap puts the login's attributes back, but not VALID UNTIL or CONNECTION
    LIMIT. A login whose password has expired, or that may hold no connection, stays unusable
    while bootstrap reports the roles ready. For an expired password PostgreSQL answers only
    "password authentication failed", and doctor's hint for that answer is to run `argus db
    bootstrap`, which changes nothing: a loop. Bootstrap should also set VALID UNTIL 'infinity'
    and CONNECTION LIMIT -1."""
    login = await make_login()
    _as_superuser(
        db_settings,
        test_database,
        sql.SQL("ALTER ROLE {} " + damage).format(sql.Identifier(login.user)),
    )
    assert await _bootstrap(db_settings, login, test_database) == []
    problem = _login_problem(login, test_database)
    assert problem is None, f"bootstrap reported the roles ready, but the login fails: {problem}"


async def test_bootstrap_restores_the_inherit_option_of_the_group_membership(
    make_login: MakeLogin,
    migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
) -> None:
    """DEFECT: since PostgreSQL 16 inheriting a role's privileges is an option of each membership,
    which defaults to the member's INHERIT attribute when it is granted. A DBA who creates the
    login NOINHERIT (hardening guides suggest it) and grants it argus_runtime makes a membership
    without INHERIT. Bootstrap then sets INHERIT on the login and grants the group again, but
    granting an existing membership changes none of its options: the login holds none of
    argus_runtime's privileges while bootstrap says the roles are ready (doctor then fails with
    "permission denied for table alembic_version" and suggests `argus db upgrade`). Bootstrap
    should grant the group WITH INHERIT TRUE."""
    login = await make_login()
    user, group = sql.Identifier(login.user), sql.Identifier(roles.RUNTIME_ROLE)
    _as_superuser(
        db_settings,
        test_database,
        sql.SQL("REVOKE {} FROM {}").format(group, user),
        sql.SQL("ALTER ROLE {} NOINHERIT").format(user),
        sql.SQL("GRANT {} TO {}").format(group, user),
    )
    staged = _memberships(db_settings, test_database, login.user)[roles.RUNTIME_ROLE]
    assert staged[1] is False  # the membership does not inherit, as staged
    await _bootstrap(db_settings, login, test_database)
    engine = create_engine(login, database=test_database)
    try:
        problems = await roles.runtime_role_problems(engine)
    finally:
        await engine.dispose()
    assert problems == []


@pytest.mark.parametrize(
    "granted",
    [
        "pg_execute_server_program",
        "pg_write_server_files",
        "pg_read_server_files",
        "pg_maintain",
        "a-role-of-its-own",
        "admin-option-on-the-group",
    ],
)
async def test_bootstrap_leaves_the_login_a_member_of_argus_runtime_and_nothing_more(
    make_login: MakeLogin,
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    granted: str,
) -> None:
    """DEFECT: the runtime login is meant to be "a member of argus_runtime and nothing more"
    (argus.db.roles) and bootstrap "creates or repairs" it, but it never looks at the login's
    other memberships, so one that someone added survives every bootstrap. With
    pg_execute_server_program the runtime role runs programs on the database server as its OS
    account, and in the Docker image that account may connect over the local socket as any role,
    the superuser included, without a password (pg_hba: local trust); pg_write_server_files and
    pg_read_server_files write and read files as the server; pg_maintain lets it LOCK the audit
    table; ADMIN OPTION on argus_runtime lets it hand the runtime privileges to other roles or take
    them from other logins. doctor does not see such memberships either (test_adv_roles.py).
    Bootstrap should revoke every membership of the login except a plain one in argus_runtime,
    and say so."""
    login = await make_login()
    user = sql.Identifier(login.user)
    if granted == "admin-option-on-the-group":
        grant = sql.SQL("GRANT {} TO {} WITH ADMIN OPTION").format(
            sql.Identifier(roles.RUNTIME_ROLE), user
        )
    elif granted == "a-role-of-its-own":
        role = throwaway_roles()
        _as_superuser(
            db_settings,
            test_database,
            sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)),
        )
        grant = sql.SQL("GRANT {} TO {}").format(sql.Identifier(role), user)
    else:
        grant = sql.SQL("GRANT {} TO {}").format(sql.Identifier(granted), user)
    _as_superuser(db_settings, test_database, grant)
    await _bootstrap(db_settings, login, test_database)
    memberships = _admin_and_inherit(db_settings, test_database, login.user)
    assert memberships == {roles.RUNTIME_ROLE: (False, True)}


async def test_bootstrap_leaves_the_group_a_member_of_nothing(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DEFECT: the same for the group role. Bootstrap puts argus_runtime's attributes back but
    keeps any membership it was given, and every runtime login inherits it: here
    pg_execute_server_program."""
    group, user = throwaway_roles(), throwaway_roles()
    monkeypatch.setattr(roles, "RUNTIME_ROLE", group)
    login = _with_login(db_settings, test_database, user, secrets.token_urlsafe(24))
    assert sorted(await _bootstrap(db_settings, login, test_database)) == sorted([group, user])
    _as_superuser(
        db_settings,
        test_database,
        sql.SQL("GRANT pg_execute_server_program TO {}").format(sql.Identifier(group)),
    )
    await _bootstrap(db_settings, login, test_database)
    assert _memberships(db_settings, test_database, group) == {}


@pytest.mark.parametrize(
    ("statement", "setting", "default"),
    [
        pytest.param(
            "ALTER ROLE {login} SET session_replication_role = replica",
            "session_replication_role",
            "origin",
            id="replica-everywhere",
        ),
        pytest.param(
            "ALTER ROLE {login} IN DATABASE {database} SET session_replication_role = replica",
            "session_replication_role",
            "origin",
            id="replica-in-its-database",
        ),
        pytest.param(
            "ALTER ROLE {login} SET default_transaction_read_only = on",
            "default_transaction_read_only",
            "off",
            id="read-only",
        ),
    ],
)
async def test_bootstrap_clears_settings_stored_on_the_login(
    make_login: MakeLogin,
    db_settings: DatabaseSettings,
    test_database: str,
    statement: str,
    setting: str,
    default: str,
) -> None:
    """DEFECT: settings stored on the login with ALTER ROLE ... SET survive bootstrap and apply
    to every ARGUS session, and one a superuser stored applies even where the login could not set
    it itself. With session_replication_role = replica, which D-029 says the runtime role cannot
    set, every runtime session skips ordinary triggers and foreign-key checks (the audit guards
    still fire only because they are ENABLE ALWAYS); with default_transaction_read_only = on ARGUS
    can write nothing. Bootstrap should reset the login's stored settings (ALTER ROLE ... RESET
    ALL, and IN DATABASE for ARGUS's database)."""
    login = await make_login()
    _as_superuser(
        db_settings,
        test_database,
        sql.SQL(statement).format(
            login=sql.Identifier(login.user), database=sql.Identifier(test_database)
        ),
    )
    await _bootstrap(db_settings, login, test_database)
    engine = create_engine(login, database=test_database)
    try:
        async with engine.connect() as conn:
            shown = (await conn.exec_driver_sql(f"SHOW {setting}")).scalar_one()
    finally:
        await engine.dispose()
    assert shown == default


async def test_bootstrap_takes_every_dangerous_attribute_off_the_login(
    make_login: MakeLogin, db_settings: DatabaseSettings, test_database: str
) -> None:
    """LOCK-IN: SUPERUSER, CREATEDB, CREATEROLE, REPLICATION, BYPASSRLS, NOINHERIT and NOLOGIN set
    on the login are all put back (test_roles.py covers CREATEDB, CREATEROLE and NOINHERIT), and
    the login works again."""
    login = await make_login()
    _as_superuser(
        db_settings,
        test_database,
        sql.SQL(
            "ALTER ROLE {} NOLOGIN SUPERUSER CREATEDB CREATEROLE REPLICATION BYPASSRLS NOINHERIT"
        ).format(sql.Identifier(login.user)),
    )
    assert await _bootstrap(db_settings, login, test_database) == []
    assert _attributes(db_settings, test_database, login.user) == SAFE_LOGIN
    assert _login_problem(login, test_database) is None


def test_cli_bootstrap_says_which_dangerous_attributes_it_removed(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DEFECT: bootstrap repairs a runtime login that someone made a superuser without saying so.
    The CLI prints the same "already present, attributes reset" as for a login that was right
    all along, and the audit row holds only the login and the roles created. A superuser
    runtime login is what D-029 exists to prevent, so finding one is a sign of tampering; the
    repair wipes that evidence and nobody learns it was needed. Bootstrap should name what it
    changed, on the console and in the audit row."""
    login = throwaway_roles()
    password = f"fake-runtime-pw-{secrets.token_hex(8)}"
    config = _cli_config(
        tmp_path, monkeypatch, db_settings, test_database, user=login, runtime_password=password
    )
    for command in (["db", "upgrade"], ["db", "bootstrap"]):
        result = _invoke(db_settings, *command, "-c", str(config), hidden=(password,))
        assert result.exit_code == 0, _scrub(result.output, [password])
    _as_superuser(
        db_settings,
        test_database,
        sql.SQL("ALTER ROLE {} NOLOGIN SUPERUSER CREATEROLE").format(sql.Identifier(login)),
    )
    result = _invoke(db_settings, "db", "bootstrap", "-c", str(config), hidden=(password,))
    assert result.exit_code == 0, _scrub(result.output, [password])
    assert _attributes(db_settings, test_database, login) == SAFE_LOGIN  # repaired, as above
    rows = _query(
        db_settings,
        test_database,
        "SELECT details::text FROM audit_events WHERE action = 'db.bootstrap' ORDER BY id DESC",
    )
    told = "superuser" in result.output.lower() or "superuser" in rows[0][0].lower()
    assert told, "neither the CLI nor the audit row says that the login was a superuser"


async def test_bootstrap_takes_every_dangerous_attribute_off_the_group(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LOCK-IN: a group role that exists already with LOGIN, SUPERUSER and the other dangerous
    attributes is put back to a plain NOLOGIN role before the login is made a member of it."""
    group, user = throwaway_roles(), throwaway_roles()
    _as_superuser(
        db_settings,
        test_database,
        sql.SQL(
            "CREATE ROLE {} LOGIN SUPERUSER CREATEDB CREATEROLE REPLICATION BYPASSRLS NOINHERIT"
        ).format(sql.Identifier(group)),
    )
    monkeypatch.setattr(roles, "RUNTIME_ROLE", group)
    login = _with_login(db_settings, test_database, user, secrets.token_urlsafe(24))
    assert await _bootstrap(db_settings, login, test_database) == [user]
    assert _attributes(db_settings, test_database, group) == SAFE_GROUP
    assert _admin_and_inherit(db_settings, test_database, user) == {group: (False, True)}


async def test_a_login_named_like_the_group_never_turns_the_group_into_a_login(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LOCK-IN: with database.user equal to the group's name (the settings accept it), bootstrap
    would give the group LOGIN and a password. It fails when it grants the group to itself, and
    because every step runs in one transaction the group stays a NOLOGIN role without a password.
    (Refusing that name before connecting is a DEFECT in test_adv_roles_config.py.)"""
    group, user = throwaway_roles(), throwaway_roles()
    monkeypatch.setattr(roles, "RUNTIME_ROLE", group)
    await _bootstrap(
        db_settings,
        _with_login(db_settings, test_database, user, "fake-pw-a1b2c3d4"),
        test_database,
    )
    as_group = _with_login(db_settings, test_database, group, "fake-pw-e5f6a7b8")
    with pytest.raises((DBAPIError, ConfigError)):
        await _bootstrap(db_settings, as_group, test_database)
    assert _attributes(db_settings, test_database, group) == SAFE_GROUP
    assert _query(
        db_settings,
        test_database,
        "SELECT rolpassword IS NULL FROM pg_authid WHERE rolname = %s",
        (group,),
    ) == [(True,)]


async def test_a_failed_bootstrap_keeps_the_old_password(
    make_login: MakeLogin, db_settings: DatabaseSettings, test_database: str
) -> None:
    """LOCK-IN: bootstrap changes the roles and grants CONNECT in one transaction, so when a
    later step fails (here: GRANT CONNECT on a database that does not exist) the password change
    is rolled back too. The login keeps its old password and the new one is refused."""
    login = await make_login()
    new = login.model_copy(update={"password": SecretStr(f"fake-new-pw-{secrets.token_hex(8)}")})
    missing = f"{TEST_DB_PREFIX}{int(time.time())}_{secrets.token_hex(4)}"  # never created
    engine = create_engine(db_settings, database=test_database, role="owner")
    failed = False
    try:
        async with engine.begin() as conn:
            await roles.ensure_roles(conn, new)
            await roles.grant_connect(conn, missing)
    except DBAPIError:
        failed = True
    finally:
        await engine.dispose()
    assert failed
    assert _login_problem(login, test_database) is None
    assert _login_problem(new, test_database) is not None


# --------------------------------------------------------------------------- passwords


async def test_a_failed_role_statement_carries_no_password_verifier(
    make_login: MakeLogin, db_settings: DatabaseSettings, test_database: str
) -> None:
    """DEFECT: role DDL cannot take bind parameters, so ensure_roles writes the login's SCRAM
    verifier into the statement text, and when that statement fails SQLAlchemy's exception text
    repeats it (``[SQL: ALTER ROLE ... PASSWORD 'SCRAM-SHA-256$<iterations>:<salt>$<keys>']``):
    hide_parameters cannot hide a literal. The CLI prints only the server's first line, but every
    other reader of the exception sees the verifier: a pytest report (the session fixture
    _runtime_roles bootstraps the real argus_app, and a failure there is reported for every
    integration test; hide_in_reports masks only the passwords and the gate's secret scan looks
    only for them), a traceback, a log handler without ARGUS's redaction. With the verifier, an
    attacker can guess the password offline, or log in with it after sniffing one SCRAM
    exchange. The statement should be redacted in the exception (it is in ARGUS's logs). Here the
    ALTER fails on a lock timeout while another transaction holds the login's catalog row."""
    login = await make_login()
    quick = db_settings.model_copy(update={"statement_timeout": timedelta(seconds=1)})
    engine = create_engine(quick, database=test_database, role="owner")  # lock_timeout = 1 s
    renderings: list[str] = []
    state: str | None = None
    try:
        with (
            admin_connect(db_settings, test_database) as blocker,
            blocker.transaction(force_rollback=True),
        ):
            blocker.execute(
                sql.SQL("ALTER ROLE {} CONNECTION LIMIT 5").format(sql.Identifier(login.user))
            )
            try:
                async with engine.begin() as conn:
                    await roles.ensure_roles(conn, login)
            except DBAPIError as exc:
                state = _sqlstate(exc)
                renderings = [str(exc), repr(exc), "".join(traceback.format_exception(exc))]
    finally:
        await engine.dispose()
    assert state in BLOCKED_TOO_LONG, state
    leaked = any(VERIFIER.search(rendering) for rendering in renderings)
    assert not leaked, "the failed role statement's exception text holds the SCRAM verifier"


_PASSWORD_SHAPES = {
    "quotes": "fake'pw\"with`quotes",
    "backslashes": "fake\\pw\\\\0\\n",
    "percent-and-braces": "fake%41%%pw%s%(x)s{0}",
    "spaces-at-both-ends": "  fake pw with spaces  ",
    "dollar-references": "fake${HOME}$pw$$",
    "conninfo-syntax": "fake pw' host=192.0.2.1 port=1 dbname=postgres x='",
    "url-delimiters": "fake:@/?#[]&=+;,pw",
    "decomposed-unicode": "fa\U00000308ke-pa\U00000308ss",
    "saslprep-mapped": "\U0000fb01x\xa0fake\xadpw",  # a ligature, a no-break space, a soft hyphen
    "emoji-and-rtl": "fake-\U0001f511-\U000005d0\U000005d1",
    "control-characters": "fake\x07pw\t\x1b",
    "unassigned-code-point": "fake-\U000e0fff-pw",
    "100k-ascii": "f" * 100_000,
    "1025-non-ascii": "\xe4" * 1025,
}


@pytest.mark.parametrize("password", list(_PASSWORD_SHAPES.values()), ids=list(_PASSWORD_SHAPES))
async def test_passwords_of_every_shape_log_in_after_bootstrap(
    make_login: MakeLogin, db_settings: DatabaseSettings, test_database: str, password: str
) -> None:
    """LOCK-IN: the verifier libpq computes for bootstrap matches what libpq sends when logging
    in, for quotes, backslashes, %, conninfo and URL syntax, Unicode that SASLprep normalises or
    maps, control characters, 100,000 ASCII characters and 1,025 non-ASCII ones. ARGUS's engine
    logs in, so does plain psycopg, and the old password stops working."""
    login = await make_login()
    shaped = login.model_copy(update={"password": SecretStr(password)})
    assert await _bootstrap(db_settings, shaped, test_database) == []
    engine = create_engine(shaped, database=test_database)
    try:
        async with engine.connect() as conn:
            current = (await conn.execute(text("SELECT current_user"))).scalar_one()
    finally:
        await engine.dispose()
    assert current == login.user
    assert _login_problem(shaped, test_database) is None
    assert _login_problem(login, test_database) is not None


def test_cli_bootstrap_refuses_a_password_with_a_nul_character(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DEFECT: the settings accept a password with a NUL (a YAML "\\0" escape here; a raw NUL byte
    in .env loads the same way), and libpq takes passwords as C strings. Bootstrap hashes only the
    part before the NUL and reports success: the runtime login's real password is now that short
    prefix (from a leading NUL there is none at all: PostgreSQL clears it). It should refuse the
    password as bad configuration, exit code 2, before changing anything."""
    login = throwaway_roles()
    first = f"fake-first-pw-{secrets.token_hex(8)}"
    config = _cli_config(
        tmp_path, monkeypatch, db_settings, test_database, user=login, runtime_password=first
    )
    created = _invoke(db_settings, "db", "bootstrap", "-c", str(config), hidden=(first,))
    assert created.exit_code == 0, _scrub(created.output, [first])
    prefix, rest = "short", f"fake-rest-{secrets.token_hex(8)}"
    monkeypatch.delenv("ARGUS_DATABASE__PASSWORD")
    config = _cli_config(
        tmp_path,
        monkeypatch,
        db_settings,
        test_database,
        user=login,
        extra=f'  password: "{prefix}\\0{rest}"\n',
    )
    result = _invoke(db_settings, "db", "bootstrap", "-c", str(config), hidden=(first, rest))
    weakened = _verifier_is_for(db_settings, test_database, login, prefix.encode())
    assert not weakened, "bootstrap set the login's password to the 5 characters before the NUL"
    assert result.exit_code == 2, _scrub(result.output, [first, rest])
    assert (
        _login_problem(_with_login(db_settings, test_database, login, first), test_database) is None
    )


def test_cli_bootstrap_with_an_undecodable_runtime_password_is_a_config_error(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DEFECT: on POSIX an environment variable may hold bytes that are not UTF-8; Python turns
    them into lone surrogates and the settings accept them. Bootstrap logs in as the owner and
    then crashes in _password_verifier (``password.encode()``) with a UnicodeEncodeError: a
    traceback and exit code 1 instead of exit code 2 and one line. Every runtime connection with
    that password fails the same way (doctor: "check crashed: 'utf-8' codec can't encode ...").
    The settings should refuse a password that is not valid UTF-8."""
    login = throwaway_roles()
    first = f"fake-first-pw-{secrets.token_hex(8)}"
    config = _cli_config(
        tmp_path, monkeypatch, db_settings, test_database, user=login, runtime_password=first
    )
    assert (
        _invoke(db_settings, "db", "bootstrap", "-c", str(config), hidden=(first,)).exit_code == 0
    )
    undecodable = "fake-pw-" + b"\xff".decode("utf-8", "surrogateescape") + secrets.token_hex(4)
    monkeypatch.setenv("ARGUS_DATABASE__PASSWORD", undecodable)
    result = _invoke(db_settings, "db", "bootstrap", "-c", str(config), hidden=(first, undecodable))
    uncaught = _uncaught(result, [first])
    assert uncaught is None, f"exception escaped the CLI (a traceback): {uncaught}"
    assert result.exit_code == 2, _scrub(result.output, [first])
    assert result.stderr.startswith("error:")
    assert (
        _login_problem(_with_login(db_settings, test_database, login, first), test_database) is None
    )


def test_cli_bootstrap_debug_output_and_audit_hold_no_password_or_verifier(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LOCK-IN: with DEBUG JSON logs and SQLAlchemy's statement log forced on (so the role DDL is
    logged, verifier included), neither password nor an unmasked verifier reaches stdout or
    stderr, for a bootstrap that creates the login and one that repairs it: redaction leaves
    ``PASSWORD 'SCRAM-SHA-256$***'``. Their audit rows name the login and what was created, and
    hold no password or verifier."""
    login = throwaway_roles()
    password = f"fake-runtime-pw-{secrets.token_hex(8)}"
    config = _cli_config(
        tmp_path,
        monkeypatch,
        db_settings,
        test_database,
        user=login,
        runtime_password=password,
        logging_section="logging:\n  level: DEBUG\n  format: json\n",
    )
    upgrade = _invoke(db_settings, "db", "upgrade", "-c", str(config), hidden=(password,))
    assert upgrade.exit_code == 0, _scrub(upgrade.output, [password])  # bootstrap is audited
    configure = cli.configure_logging

    def with_statements(level: str, fmt: str, *, stream: Any = None) -> None:
        configure(level, fmt, stream=stream)
        logging.getLogger("sqlalchemy.engine").setLevel(logging.INFO)

    monkeypatch.setattr(cli, "configure_logging", with_statements)
    shown = []
    for _ in range(2):  # creates the login, then repairs it
        result = _invoke(db_settings, "db", "bootstrap", "-c", str(config), hidden=(password,))
        assert result.exit_code == 0, _scrub(result.output, [password])
        shown.append(result.output + result.stderr)
    assert "PASSWORD 'SCRAM-SHA-256$***'" in shown[0]  # the statements were logged, masked
    assert "PASSWORD 'SCRAM-SHA-256$***'" in shown[1]
    rows = _query(
        db_settings,
        test_database,
        "SELECT details FROM audit_events WHERE action = 'db.bootstrap' ORDER BY id",
    )
    assert [(row[0]["login"], row[0]["created"]) for row in rows] == [(login, [login]), (login, [])]
    stored = _query(db_settings, test_database, "SELECT audit_events::text FROM audit_events")
    secrets_stored = any(
        password in row[0] or owner_password(db_settings) in row[0] or VERIFIER.search(row[0])
        for row in stored
    )
    assert not secrets_stored


@pytest.mark.parametrize("case", ["wrong-owner-password", "reserved-login-name", "no-database"])
def test_cli_bootstrap_failures_are_one_line_without_secrets(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    """LOCK-IN: a bootstrap the server refuses ends with exit code 1 and one line on stderr, no
    traceback, and neither password nor verifier, though the refused CREATE ROLE statement held
    one. (A reserved name may instead become a configuration error, exit code 2, once bootstrap
    refuses it before connecting.)"""
    password = f"fake-runtime-pw-{secrets.token_hex(8)}"
    user, database = throwaway_roles(), test_database
    if case == "reserved-login-name":
        user = f"pg_argus_{secrets.token_hex(4)}"
    if case == "no-database":
        database = f"{TEST_DB_PREFIX}{int(time.time())}_{secrets.token_hex(4)}"  # never created
    config = _cli_config(
        tmp_path, monkeypatch, db_settings, database, user=user, runtime_password=password
    )
    wrong = f"fake-wrong-owner-pw-{secrets.token_hex(6)}"
    if case == "wrong-owner-password":
        monkeypatch.setenv("ARGUS_DATABASE__OWNER_PASSWORD", wrong)
    result = _invoke(db_settings, "db", "bootstrap", "-c", str(config), hidden=(password, wrong))
    assert _uncaught(result, [password]) is None
    assert result.exit_code in ((1, 2) if case == "reserved-login-name" else (1,))
    lines = _error_lines(result)
    assert lines
    assert lines[0].startswith("error: ")
    if result.exit_code == 1:
        assert len(lines) == 1, [_scrub(line, [password]) for line in lines]
    if case == "wrong-owner-password":
        assert "password authentication failed" in lines[0]
    if case == "no-database":
        assert "does not exist" in lines[0]


# --------------------------------------------------------------------------- concurrency


async def _bootstraps_at_once(
    owner: DatabaseSettings, login: DatabaseSettings, database: str, runs: int, *, connect: bool
) -> list[str]:
    """Start ``runs`` bootstraps of ``login`` together; each holds its transaction open for a
    moment, so they overlap. The server's message for each run that failed."""
    engines = [create_engine(owner, database=database, role="owner") for _ in range(runs)]

    async def bootstrap(engine: AsyncEngine) -> str | None:
        try:
            async with engine.begin() as conn:
                await roles.ensure_roles(conn, login)
                if connect:
                    await roles.grant_connect(conn, database)
                await asyncio.sleep(0.3)
        except DBAPIError as exc:
            return _driver_message(exc)
        return None

    try:
        outcomes = await asyncio.wait_for(
            asyncio.gather(*(bootstrap(engine) for engine in engines)), timeout=60
        )
    finally:
        for engine in engines:
            await engine.dispose()
    return [outcome for outcome in outcomes if outcome is not None]


async def test_four_concurrent_bootstraps_all_succeed(
    make_login: MakeLogin, db_settings: DatabaseSettings, test_database: str
) -> None:
    """DEFECT: role catalog rows are not locked, so a bootstrap that changes the login fails with
    "tuple concurrently updated" once for every overlapping run that commits before it, and
    ensure_roles tries only 3 times: of N overlapping runs, the last needs N attempts. Two and
    three succeed (test_roles.py and the LOCK-IN below); of four, one fails. The session fixture
    _runtime_roles runs the same code at the start of every pytest session, so four sessions
    starting together (several agents here) can fail the same way. A transaction-level advisory
    lock, as migrations take, would serialise bootstraps instead."""
    login = await make_login()
    failures = await _bootstraps_at_once(db_settings, login, test_database, 4, connect=False)
    assert failures == []
    assert _login_problem(login, test_database) is None


async def test_three_concurrent_cli_style_bootstraps_succeed(
    make_login: MakeLogin, db_settings: DatabaseSettings, test_database: str
) -> None:
    """LOCK-IN: three overlapping bootstraps, each also granting CONNECT as the CLI does, all
    succeed: the retries absorb the conflicts, and changing the login's row serialises the
    CONNECT grants that follow it."""
    login = await make_login()
    failures = await _bootstraps_at_once(db_settings, login, test_database, 3, connect=True)
    assert failures == []
    assert _login_problem(login, test_database) is None


# --------------------------------------------------------------------------- names, grants


async def test_a_63_byte_login_name_works_end_to_end(
    throwaway_roles: RoleNames,
    migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
) -> None:
    """LOCK-IN: the longest name bootstrap accepts, 63 bytes, is kept whole by PostgreSQL: the
    login is created, logs in under exactly that name and passes doctor's runtime-role check."""
    name = throwaway_roles(width=63)
    assert len(name.encode()) == 63
    login = _with_login(db_settings, test_database, name, secrets.token_urlsafe(24))
    roles.check_bootstrap_settings(login)
    assert await _bootstrap(db_settings, login, test_database) == [name]
    engine = create_engine(login, database=test_database)
    try:
        async with engine.connect() as conn:
            assert (await conn.execute(text("SELECT current_user"))).scalar_one() == name
        assert await roles.runtime_role_problems(engine) == []
    finally:
        await engine.dispose()


async def test_grant_connect_that_grants_nothing_is_not_reported_as_done(
    throwaway_roles: RoleNames, db_settings: DatabaseSettings, test_database: str
) -> None:
    """DEFECT: GRANT CONNECT ON DATABASE by a role that neither owns the database nor holds the
    privilege with grant option is no error in PostgreSQL; it only warns "no privileges were
    granted". grant_connect ignores the warning, so a bootstrap by such an owner (D-029's
    CREATEROLE owner on a shared host, where a DBA owns the database and PUBLIC may not connect)
    prints "... may connect to <database>" while the runtime role still cannot connect. It should
    fail instead, or check has_database_privilege afterwards."""
    owner = throwaway_roles()
    password = secrets.token_urlsafe(24)
    hide_in_reports(password)
    database = sql.Identifier(test_database)
    _as_superuser(
        db_settings,
        test_database,
        sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
            sql.Identifier(owner), sql.Literal(password)
        ),
        sql.SQL("REVOKE CONNECT ON DATABASE {} FROM PUBLIC").format(database),
        sql.SQL("REVOKE CONNECT ON DATABASE {} FROM {}").format(
            database, sql.Identifier(roles.RUNTIME_ROLE)
        ),
        sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(database, sql.Identifier(owner)),
    )
    settings = db_settings.model_copy(
        update={"owner_user": owner, "owner_password": SecretStr(password)}
    )
    engine = create_engine(settings, database=test_database, role="owner")
    refused: str | None = None
    try:
        async with engine.connect() as conn:  # this owner can connect: a refusal is grant_connect's
            await conn.execute(text("SELECT 1"))
        try:
            async with engine.begin() as conn:
                await roles.grant_connect(conn, test_database)
        except Exception as exc:
            refused = _driver_message(exc)
    finally:
        await engine.dispose()
    if refused is None:
        [(granted,)] = _query(
            db_settings,
            test_database,
            "SELECT has_database_privilege(%s, %s, 'CONNECT')",
            (roles.RUNTIME_ROLE, test_database),
        )
        assert granted, "grant_connect returned normally, but argus_runtime still may not connect"


# --------------------------------------------------------------------------- doctor's hints


@pytest.mark.parametrize("damage", ["lost-membership", "nologin", "no-connect"])
def test_doctor_points_to_bootstrap_for_a_login_that_bootstrap_repairs(
    throwaway_roles: RoleNames,
    db_settings: DatabaseSettings,
    test_database: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    damage: str,
) -> None:
    """DEFECT: doctor hints at `argus db bootstrap` only for "password authentication failed".
    Three other states of the runtime login, each repaired by bootstrap, get no hint or a wrong
    one: a login that lost argus_runtime cannot read alembic_version and doctor says "run `argus
    db upgrade`" (the database is at head, so that changes nothing); a NOLOGIN login ("not
    permitted to log in") and a database the runtime role may not connect to ("permission denied
    for database") get no hint at all."""
    login = throwaway_roles()
    password = f"fake-runtime-pw-{secrets.token_hex(8)}"
    config = _cli_config(
        tmp_path, monkeypatch, db_settings, test_database, user=login, runtime_password=password
    )
    for command in (["db", "bootstrap"], ["db", "upgrade"], ["doctor"]):
        result = _invoke(db_settings, *command, "-c", str(config), hidden=(password,))
        assert result.exit_code == 0, _scrub(result.output, [password])
    database, user = sql.Identifier(test_database), sql.Identifier(login)
    statements = {
        "lost-membership": [
            sql.SQL("REVOKE {} FROM {}").format(sql.Identifier(roles.RUNTIME_ROLE), user)
        ],
        "nologin": [sql.SQL("ALTER ROLE {} NOLOGIN").format(user)],
        "no-connect": [
            sql.SQL("REVOKE CONNECT ON DATABASE {} FROM PUBLIC").format(database),
            sql.SQL("REVOKE CONNECT ON DATABASE {} FROM {}").format(
                database, sql.Identifier(roles.RUNTIME_ROLE)
            ),
        ],
    }[damage]
    _as_superuser(db_settings, test_database, *statements)
    result = _invoke(db_settings, "doctor", "-c", str(config), hidden=(password,))
    assert result.exit_code == 1
    failed = [line for line in result.output.splitlines() if line.startswith("FAIL")]
    assert failed
    assert any("argus db bootstrap" in line for line in failed), failed


def test_argus_db_upgrade_before_bootstrap_shows_the_migration_hint(
    db_settings: DatabaseSettings,
    test_database: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """DEFECT: migration 0003 refuses to run before bootstrap, with the HINT 'run "argus db
    bootstrap" first', written for exactly this user. But the CLI prints only the first line of
    the server's message, so `argus db upgrade` says "error: upgrade failed: role "argus_runtime"
    does not exist" and the hint is lost. Here 0003's own check looks for a role name that does
    not exist (Alembic's execute is wrapped to swap the name), so the real group is not touched."""
    missing = f"{TEST_ROLE_PREFIX}{int(time.time())}_{secrets.token_hex(4)}"  # never created
    original = Operations.execute
    swapped: list[str] = []

    def execute(self: Operations, sqltext: Any, **options: Any) -> Any:
        if isinstance(sqltext, str) and "rolname = 'argus_runtime'" in sqltext:
            sqltext = sqltext.replace("rolname = 'argus_runtime'", f"rolname = '{missing}'")
            swapped.append(sqltext)
        return original(self, sqltext, **options)

    monkeypatch.setattr(Operations, "execute", execute)
    config = _cli_config(tmp_path, monkeypatch, db_settings, test_database, user=missing)
    result = _invoke(db_settings, "db", "upgrade", "-c", str(config))
    assert swapped, "0003 no longer checks for the group role first"
    assert result.exit_code == 1, result.output
    assert 'role "argus_runtime" does not exist' in result.stderr
    [(left,)] = _query(db_settings, test_database, "SELECT to_regclass('audit_events')")
    assert left is None  # 0001 and 0002 were rolled back with it
    assert "argus db bootstrap" in result.stderr, result.stderr


# --------------------------------------------------------------------------- migration 0003


def _runtime_privileges(settings: DatabaseSettings, database: str) -> dict[str, bool]:
    [row] = _query(
        settings,
        database,
        "SELECT has_table_privilege(%(r)s, 'audit_events', 'SELECT'),"
        " has_any_column_privilege(%(r)s, 'audit_events', 'INSERT'),"
        " has_table_privilege(%(r)s, 'alembic_version', 'SELECT'),"
        " EXISTS (SELECT FROM pg_namespace n, aclexplode(n.nspacl) a WHERE n.nspname = 'public'"
        "  AND a.grantee = to_regrole(%(r)s) AND a.privilege_type = 'USAGE')",
        {"r": roles.RUNTIME_ROLE},
    )
    names = ("read audit_events", "insert audit_events", "read alembic_version", "use public")
    return dict(zip(names, (bool(value) for value in row), strict=True))


async def _write_event(engine: AsyncEngine, action: str) -> None:
    async with session_factory(engine)() as session, session.begin():
        await record_audit(session, actor="test", action=action, details={"n": action})


async def test_downgrading_and_upgrading_0003_keeps_the_trail_and_toggles_every_privilege(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
) -> None:
    """LOCK-IN: with events in the trail, downgrading 0003 revokes every privilege of the runtime
    role (also the per-column INSERT, and its own USAGE entry on schema public) and keeps every
    row; upgrading again grants them back, the runtime role reads the old rows and appends."""
    for action in ("adv.one", "adv.two"):
        await _write_event(app_engine, action)
    query = "SELECT id, actor, action, details FROM audit_events ORDER BY id"
    before = _query(db_settings, test_database, query)
    assert len(before) == 2
    assert all(_runtime_privileges(db_settings, test_database).values())

    await migrate.downgrade(migrated_engine, "0002")
    assert _runtime_privileges(db_settings, test_database) == dict.fromkeys(
        ("read audit_events", "insert audit_events", "read alembic_version", "use public"), False
    )
    assert _query(db_settings, test_database, query) == before
    await app_engine.dispose()
    with pytest.raises(DBAPIError, match="permission denied for table audit_events"):
        await _write_event(app_engine, "adv.refused")

    await migrate.upgrade(migrated_engine)
    assert all(_runtime_privileges(db_settings, test_database).values())
    await _write_event(app_engine, "adv.three")
    async with app_engine.connect() as conn:
        actions = (await conn.execute(text("SELECT action FROM audit_events ORDER BY id"))).all()
    assert [row[0] for row in actions] == ["adv.one", "adv.two", "adv.three"]
    assert await roles.runtime_role_problems(app_engine) == []


# --------------------------------------------------------------------------- stale-role cleanup


class _Rows:
    def __init__(self, names: list[str]) -> None:
        self._rows = [(name,) for name in names]

    def fetchall(self) -> list[tuple[str]]:
        return self._rows


class _FakeAdmin:
    """Stands in for the stale cleanup's owner connection: its catalog queries return the given
    names and its DROP statements are only recorded, so nothing real is read or dropped."""

    def __init__(self, databases: list[str], role_names: list[str], dropped: list[str]) -> None:
        self._answers = {"SELECT datname": databases, "SELECT rolname": role_names}
        self._dropped = dropped

    def __enter__(self) -> _FakeAdmin:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def execute(self, query: Any, params: Any = None) -> _Rows | None:
        statement = query.as_string() if isinstance(query, sql.Composable) else str(query)
        if statement.startswith("DROP "):
            self._dropped.append(statement)
            return None
        for prefix, names in self._answers.items():
            if statement.startswith(prefix):
                return _Rows(names)
        raise AssertionError(f"the stale cleanup ran an unexpected statement: {statement}")


def test_stale_cleanup_drops_only_old_names_of_the_throwaway_schemes(
    db_settings: DatabaseSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """LOCK-IN: of databases and roles that only look like the throwaway ones (other digits or
    hex, case, separators, prefixes, suffixes, whitespace, Unicode digits, a quote), real roles,
    and throwaway names younger than 2 hours, the session's stale cleanup drops none. It drops an
    old database and old roles named exactly by the schemes (a zero-padded timestamp included),
    quoted as identifiers. The fixture's own code runs; its connection is a stand-in."""
    get_body: Callable[[], Callable[..., Any]] | None = getattr(
        harness._drop_stale_test_databases, "_get_wrapped_function", None
    )
    if get_body is None:
        pytest.skip("this pytest version does not expose fixture bodies")
    old, recent, tag = int(time.time()) - 3 * 3600, int(time.time()) - 3600, "0a1b2c3d"
    padded = f"{TEST_ROLE_PREFIX}{str(old).zfill(38)}_{tag}"
    old_role, old_database = f"{TEST_ROLE_PREFIX}{old}_{tag}", f"{TEST_DB_PREFIX}{old}_{tag}"
    role_names = [
        old_role,
        padded,
        f"{TEST_ROLE_PREFIX}{recent}_{tag}",
        f"{TEST_ROLE_PREFIX}{str(recent).zfill(38)}_{tag}",
        f"{TEST_ROLE_PREFIX}{old}_{tag[:7]}",
        f"{TEST_ROLE_PREFIX}{old}_{tag}0",
        f"{TEST_ROLE_PREFIX}{old}_{tag.upper()}",
        f"{TEST_ROLE_PREFIX}{old}_{tag}_x",
        f"{TEST_ROLE_PREFIX}{old}-{tag}",
        f"argus_test_rolex_{old}_{tag}",
        f"Argus_test_role_{old}_{tag}",
        f"x{TEST_ROLE_PREFIX}{old}_{tag}",
        f"{TEST_ROLE_PREFIX}{old}_{tag}\n",
        f"{TEST_ROLE_PREFIX}{old}_{tag} ",
        f" {TEST_ROLE_PREFIX}{old}_{tag}",
        f"{TEST_ROLE_PREFIX}-{old}_{tag}",
        f"{TEST_ROLE_PREFIX}+{old}_{tag}",
        f"{TEST_ROLE_PREFIX}{old}.5_{tag}",
        f"{TEST_ROLE_PREFIX}\U00000661\U00000662\U00000663_{tag}",  # Arabic-Indic digits
        f'{TEST_ROLE_PREFIX}{old}_{tag}"; DROP ROLE argus; --',
        old_database,  # a database name is not a role name
        "argus",
        "argus_app",
        "argus_runtime",
        "postgres",
        "pg_monitor",
    ]
    databases = [
        old_database,
        f"{TEST_DB_PREFIX}{recent}_{tag}",
        old_role,  # a role name is not a database name
        f"{TEST_DB_PREFIX}{old}_{tag}x",
        f"argus_testing_{old}_{tag}",
        "argus",
        "postgres",
        "template0",
        "template1",
    ]
    dropped: list[str] = []
    monkeypatch.setattr(
        harness, "admin_connect", lambda *_args: _FakeAdmin(databases, role_names, dropped)
    )
    get_body()(db_settings)
    assert sorted(dropped) == sorted(
        [
            f'DROP DATABASE IF EXISTS "{old_database}" WITH (FORCE)',
            f'DROP ROLE IF EXISTS "{old_role}"',
            f'DROP ROLE IF EXISTS "{padded}"',
        ]
    )
