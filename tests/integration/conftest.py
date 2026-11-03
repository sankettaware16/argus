"""Integration fixtures: a throwaway PostgreSQL database per test on the local Docker server.

Requires ``docker compose up -d db`` and the repo's ``.env``. If the server is unreachable the
tests FAIL (they are never silently skipped).

Safety:
* The server must be on this machine (loopback or a Unix socket); any other host fails the
  session before a connection is made. libpq opens its own sockets, so the harness checks this
  itself as well as relying on the network guard in tests/conftest.py.
* ``db_settings.name`` and ``ARGUS_DATABASE__NAME`` name a database that never exists
  (``UNSET_DATABASE``) for the whole session, from the moment pytest loads this file: a test,
  fixture of any scope, or module-level code that forgets to name its throwaway database fails
  instead of reaching the developer's ``argus`` database. As a backstop, the network guard
  refuses any psycopg connection to the developer's database (tests/conftest.py,
  ``PROTECTED_DATABASES``), in this process and in its children (the ``argus`` CLI, say).
* Neither database password ever appears in a report: a failed ``admin_connect`` chains nothing
  and masks it, and tests/conftest.py masks both in every report, collection reports included
  (they are registered when pytest loads this file).
* Stale cleanup only drops databases and roles named exactly as ``make_database`` and
  ``make_login`` name them.

Roles (D-029): ``admin_connect``, ``empty_engine`` and ``migrated_engine`` log in as the schema
owner (``database.owner_user``), like ``argus db``; ``app_engine`` logs in as the runtime role,
like ARGUS itself; ``web_engine`` as a throwaway web login (``argus_web``, Q-A2), like the web.
The session starts by doing what ``argus db bootstrap`` does for the roles (idempotent, with the
passwords from .env).
"""

from __future__ import annotations

import contextlib
import re
import secrets
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator

import psycopg
import pytest
import pytest_asyncio
from psycopg import sql
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncEngine

import argus.db.migrate as migrate
from argus.config import DatabaseSettings, load_settings
from argus.db import roles
from argus.db.engine import create_engine
from tests.conftest import (
    REPO_ROOT,
    NetworkAccessBlockedError,
    check_database_host,
    database_passwords,
    hide_in_reports,
)

TEST_DB_PREFIX = "argus_test_"
# make_database() names: argus_test_<unix seconds>_<8 hex>. Cleanup drops nothing else.
TEST_DB_PATTERN = re.compile(rf"{re.escape(TEST_DB_PREFIX)}(?P<created>[0-9]+)_[0-9a-f]{{8}}")
# make_login() names (roles are cluster-wide): argus_test_role_<unix seconds>_<8 hex>.
TEST_ROLE_PREFIX = "argus_test_role_"
TEST_ROLE_PATTERN = re.compile(rf"{re.escape(TEST_ROLE_PREFIX)}(?P<created>[0-9]+)_[0-9a-f]{{8}}")
# Never created: what a test gets when it forgets to name its throwaway database.
UNSET_DATABASE = f"{TEST_DB_PREFIX}unset_{secrets.token_hex(4)}"
DATABASE_NAME_VARIABLE = "ARGUS_DATABASE__NAME"
# `argus db upgrade` and `downgrade` dump the database first where a checkout's .env switches it
# on (Q-A2, production's only); tests migrate throwaway databases, so the dump is off for the
# session unless a test switches it on (with backup.tools: image, never compose: QA2-R1).
BACKUP_FIRST_VARIABLE = "ARGUS_BACKUP__BEFORE_MIGRATION"
STALE_AFTER_SECONDS = 2 * 3600

# What each configuration of this file set for the session, undone by its own unconfigure: a run
# nested in this process (pytest.main() in a test) configures the file again, and ending it must
# leave the enclosing session's value in place.
_SESSION_ENVIRONMENT = pytest.StashKey[list[pytest.MonkeyPatch]]()


def pytest_configure(config: pytest.Config) -> None:
    """Called as soon as pytest loads this file, before it imports any integration test module."""
    session_environment = pytest.MonkeyPatch()
    session_environment.setenv(DATABASE_NAME_VARIABLE, UNSET_DATABASE)
    session_environment.setenv(BACKUP_FIRST_VARIABLE, "false")
    config.stash.setdefault(_SESSION_ENVIRONMENT, []).append(session_environment)
    for password in database_passwords(REPO_ROOT / ".env"):  # before collection reports
        hide_in_reports(password)


def pytest_unconfigure(config: pytest.Config) -> None:
    configured = config.stash.get(_SESSION_ENVIRONMENT, [])
    if configured:
        configured.pop().undo()


def _created_at(name: str, pattern: re.Pattern[str] = TEST_DB_PATTERN) -> int | None:
    """Creation time encoded in a make_database() (or ``pattern``) name; None for any other."""
    match = pattern.fullmatch(name)
    return int(match["created"]) if match else None


@pytest.fixture(scope="session")
def db_settings() -> DatabaseSettings:
    """Settings for the local server. ``name`` is UNSET_DATABASE: pass ``database=`` explicitly."""
    from argus import site

    with site.using(site.active()):  # loading activates the checkout's site: not for the tests
        settings = load_settings(REPO_ROOT / "config" / "argus.yaml", env_file=REPO_ROOT / ".env")
    database = settings.database
    for variable, password in (
        ("ARGUS_DATABASE__PASSWORD", database.password),
        ("ARGUS_DATABASE__OWNER_PASSWORD", database.owner_password),
    ):
        if password is None:
            pytest.fail(f"integration tests need {variable} in .env")
        hide_in_reports(password.get_secret_value())
    try:
        check_database_host(database.host)
    except NetworkAccessBlockedError as exc:
        pytest.fail(f"integration tests only use a Postgres on this machine (database.host): {exc}")
    return database.model_copy(update={"name": UNSET_DATABASE})


@pytest.fixture(autouse=True)
def _unset_database_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Environment beats .env: a plain load_settings() or CLI call gets UNSET_DATABASE.

    pytest_configure sets it for the whole session; this restores it for every test, in case an
    earlier test or fixture changed the variable without undoing it.
    """
    monkeypatch.setenv(DATABASE_NAME_VARIABLE, UNSET_DATABASE)
    monkeypatch.setenv(BACKUP_FIRST_VARIABLE, "false")


def _without_password(exc: BaseException, password: SecretStr) -> str:
    """``exc`` as one line of text, with the password masked."""
    text = " ".join(f"{type(exc).__name__}: {exc}".split())
    secret = password.get_secret_value()
    return text.replace(secret, "***") if secret else text


def owner_password(settings: DatabaseSettings) -> str:
    assert settings.owner_password is not None
    return settings.owner_password.get_secret_value()


def admin_connect(
    settings: DatabaseSettings, dbname: str = "postgres"
) -> psycopg.Connection[tuple[object, ...]]:
    """An owner connection, by default to the server's maintenance database (CREATE and DROP
    DATABASE, roles). Any other ``dbname`` must be a throwaway database.

    pytest prints the arguments of traceback frames, and psycopg's hold the password. So a failed
    attempt is not chained to the failure reported here, the report has no traceback, and the
    password is never kept in this frame.
    """
    assert dbname == "postgres" or TEST_DB_PATTERN.fullmatch(dbname), dbname
    assert settings.owner_password is not None
    try:
        return psycopg.connect(
            host=settings.host,
            port=settings.port,
            user=settings.owner_user,
            password=settings.owner_password.get_secret_value(),
            dbname=dbname,
            autocommit=True,
            connect_timeout=5,
        )
    except psycopg.OperationalError as exc:
        cause = _without_password(exc, settings.owner_password)
        problem = f"local Postgres unreachable — run `docker compose up -d db` ({cause})"
    except Exception as exc:  # the network guard refused it, say
        cause = _without_password(exc, settings.owner_password)
        problem = f"cannot connect to the local Postgres ({cause})"
    pytest.fail(problem, pytrace=False)  # outside the except clauses: nothing is chained


# Its own loop scope, so it also works in a pytest run without this project's ini settings.
@pytest_asyncio.fixture(scope="session", loop_scope="session", autouse=True)
async def _runtime_roles(db_settings: DatabaseSettings) -> None:
    """The runtime group role and login exist, as ``argus db bootstrap`` leaves them, and so do
    the web's group role (Q-A2; migrations grant it), the approvals group role (Q-C1), the purge
    group role (Q-A4) and the case writer's group role (Q-D4). The
    web's configured login is never made or changed here: roles are cluster-wide, and that
    login may be the production web's. Tests use throwaway web logins instead
    (``make_api_login``)."""
    engine = create_engine(db_settings, database="postgres", role="owner")
    try:
        async with engine.begin() as conn:
            await roles.ensure_roles(conn, db_settings)
            await roles.ensure_api_roles(
                conn, db_settings.model_copy(update={"api_password": None})
            )
            await roles.ensure_approvals_role(conn)
            await roles.ensure_purge_role(conn)
            await roles.ensure_writer_roles(
                conn, db_settings.model_copy(update={"writer_password": None})
            )
    finally:
        await engine.dispose()


@pytest.fixture(scope="session", autouse=True)
def _drop_stale_test_databases(db_settings: DatabaseSettings) -> None:
    """Remove leftovers from interrupted runs.

    Only make_database() names (TEST_DB_PATTERN) older than STALE_AFTER_SECONDS are dropped, so a
    concurrent pytest run never loses the databases it is using and no other database is touched.
    """
    cutoff = time.time() - STALE_AFTER_SECONDS
    with admin_connect(db_settings) as conn:
        names = [
            str(name) for (name,) in conn.execute("SELECT datname FROM pg_database").fetchall()
        ]
        for name in names:
            created = _created_at(name)
            if created is not None and created < cutoff:
                conn.execute(
                    sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
                )
        logins = [str(name) for (name,) in conn.execute("SELECT rolname FROM pg_roles").fetchall()]
        for name in logins:
            created = _created_at(name, TEST_ROLE_PATTERN)
            if created is not None and created < cutoff:
                # Fails while the role still holds privileges in a database that is not stale.
                with contextlib.suppress(psycopg.Error):
                    conn.execute(sql.SQL("DROP ROLE IF EXISTS {}").format(sql.Identifier(name)))


@pytest.fixture
def make_database(db_settings: DatabaseSettings) -> Iterator[Callable[[], str]]:
    created: list[str] = []

    def _make() -> str:
        name = f"{TEST_DB_PREFIX}{int(time.time())}_{secrets.token_hex(4)}"
        assert TEST_DB_PATTERN.fullmatch(name), name  # stale cleanup must recognise it
        with admin_connect(db_settings) as conn:
            conn.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
            created.append(name)
            for group in (roles.RUNTIME_ROLE, roles.API_ROLE):
                conn.execute(
                    sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                        sql.Identifier(name), sql.Identifier(group)
                    )
                )
        return name

    yield _make
    with admin_connect(db_settings) as conn:
        for name in created:
            conn.execute(
                sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
            )


@pytest.fixture
def test_database(make_database: Callable[[], str]) -> str:
    return make_database()


@pytest.fixture
async def empty_engine(
    db_settings: DatabaseSettings, test_database: str
) -> AsyncIterator[AsyncEngine]:
    """The schema owner's engine on an empty throwaway database (migrations, DDL)."""
    engine = create_engine(db_settings, database=test_database, role="owner")
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.fixture
async def migrated_engine(empty_engine: AsyncEngine) -> AsyncEngine:
    """The owner's engine on a database at head."""
    await migrate.upgrade(empty_engine)
    return empty_engine


@pytest.fixture
async def app_engine(
    db_settings: DatabaseSettings, test_database: str, migrated_engine: AsyncEngine
) -> AsyncIterator[AsyncEngine]:
    """The runtime role's engine (what ARGUS itself uses) on the same database at head."""
    engine = create_engine(db_settings, database=test_database)
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.fixture
async def make_api_login(
    db_settings: DatabaseSettings, test_database: str
) -> AsyncIterator[Callable[[], Awaitable[DatabaseSettings]]]:
    """Throwaway web logins (Q-A2), made the way ``argus db bootstrap`` makes the web's login: a
    member of ``argus_web`` and ``argus_approvals`` (Q-C3), with a random password. Returns
    settings whose ``api_user`` is it (to ``test_database``); afterwards the role and its
    privileges there are dropped."""
    created: list[str] = []
    engine = create_engine(db_settings, database=test_database, role="owner")

    async def _make() -> DatabaseSettings:
        name = f"{TEST_ROLE_PREFIX}{int(time.time())}_{secrets.token_hex(4)}"
        assert TEST_ROLE_PATTERN.fullmatch(name), name  # stale cleanup must recognise it
        password = secrets.token_urlsafe(24)
        hide_in_reports(password)
        login = db_settings.model_copy(
            update={"api_user": name, "api_password": SecretStr(password), "name": test_database}
        )
        created.append(name)
        async with engine.begin() as conn:
            await roles.ensure_api_roles(conn, login)
            await roles.ensure_web_approvals(conn, login)
        return login

    try:
        yield _make
    finally:
        await engine.dispose()
        with admin_connect(db_settings, test_database) as conn:
            existing = {
                str(name)
                for (name,) in conn.execute(
                    "SELECT rolname FROM pg_roles WHERE rolname = ANY(%s)", (created,)
                ).fetchall()
            }
            for name in existing:
                conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(name)))
                conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(name)))


@pytest.fixture
async def web_engine(
    make_api_login: Callable[[], Awaitable[DatabaseSettings]],
    test_database: str,
    migrated_engine: AsyncEngine,
) -> AsyncIterator[AsyncEngine]:
    """The engine the web app gets in tests: a throwaway web login (``argus_web``'s grants
    only, Q-A2), on the same database at head, so the web suite runs as production's web does
    once ``web.database_role`` is ``api``."""
    login = await make_api_login()
    engine = create_engine(login, database=test_database, role="api")
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.fixture
async def make_writer_login(
    db_settings: DatabaseSettings, test_database: str
) -> AsyncIterator[Callable[[], Awaitable[DatabaseSettings]]]:
    """Throwaway case-writer logins (Q-D4), made the way ``argus db bootstrap`` makes the
    writer's: a member of ``argus_writer`` alone, with a random password.
    Returns settings whose ``writer_user`` is it (to ``test_database``); afterwards the role and
    its privileges there are dropped."""
    created: list[str] = []
    engine = create_engine(db_settings, database=test_database, role="owner")

    async def _make() -> DatabaseSettings:
        name = f"{TEST_ROLE_PREFIX}{int(time.time())}_{secrets.token_hex(4)}"
        assert TEST_ROLE_PATTERN.fullmatch(name), name  # stale cleanup must recognise it
        password = secrets.token_urlsafe(24)
        hide_in_reports(password)
        login = db_settings.model_copy(
            update={
                "writer_user": name,
                "writer_password": SecretStr(password),
                "name": test_database,
            }
        )
        created.append(name)
        async with engine.begin() as conn:
            await roles.ensure_writer_roles(conn, login)
        return login

    try:
        yield _make
    finally:
        await engine.dispose()
        with admin_connect(db_settings, test_database) as conn:
            existing = {
                str(name)
                for (name,) in conn.execute(
                    "SELECT rolname FROM pg_roles WHERE rolname = ANY(%s)", (created,)
                ).fetchall()
            }
            for name in existing:
                conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(name)))
                conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(name)))


@pytest.fixture
async def writer_engine(
    make_writer_login: Callable[[], Awaitable[DatabaseSettings]],
    test_database: str,
    migrated_engine: AsyncEngine,
) -> AsyncIterator[AsyncEngine]:
    """The case writer's engine in tests: a throwaway writer login (the writer's own grants,
    Q-D4 and its review R8) on the same database at head."""
    login = await make_writer_login()
    engine = create_engine(login, database=test_database, role="writer")
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.fixture
async def make_login(
    db_settings: DatabaseSettings, test_database: str
) -> AsyncIterator[Callable[[], Awaitable[DatabaseSettings]]]:
    """Throwaway runtime logins, made the way ``argus db bootstrap`` makes one, each with a random
    password. Roles are cluster-wide, so tests that change a login's attributes or memberships use
    one of these, never the configured login. Returns settings that log in as it (to
    ``test_database``); afterwards the role and whatever that database granted it are dropped."""
    created: list[str] = []
    engine = create_engine(db_settings, database=test_database, role="owner")

    async def _make() -> DatabaseSettings:
        name = f"{TEST_ROLE_PREFIX}{int(time.time())}_{secrets.token_hex(4)}"
        assert TEST_ROLE_PATTERN.fullmatch(name), name  # stale cleanup must recognise it
        password = secrets.token_urlsafe(24)
        hide_in_reports(password)
        login = db_settings.model_copy(
            update={"user": name, "password": SecretStr(password), "name": test_database}
        )
        created.append(name)
        async with engine.begin() as conn:
            await roles.ensure_roles(conn, login)
        return login

    try:
        yield _make
    finally:
        await engine.dispose()
        with admin_connect(db_settings, test_database) as conn:
            existing = {
                str(name)
                for (name,) in conn.execute(
                    "SELECT rolname FROM pg_roles WHERE rolname = ANY(%s)", (created,)
                ).fetchall()
            }
            for name in existing:
                conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(name)))
                conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(name)))
