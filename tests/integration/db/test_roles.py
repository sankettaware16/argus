"""Role separation (D-029): what the runtime role may and may not do, and how it is set up.

ARGUS runs as a login in the group role ``argus_runtime``; the schema owner runs ``argus db``.
Refusals are checked by SQLSTATE 42501 *and* message, so a test cannot pass because an
append-only trigger (which raises the same SQLSTATE) happened to stop the statement instead of
the privilege system. Privileges are per database, so tests change grants only inside their
throwaway database; role attributes and memberships are cluster-wide, so tests change those only
on throwaway logins from ``make_login``.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import io
import os
import secrets
import time
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from typing import Any, Literal

import psycopg
import pytest
from psycopg import sql
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import CliRunner

from argus.cli import app
from argus.config import ConfigError, DatabaseSettings, load_settings
from argus.db import migrate, roles
from argus.db.audit import record_audit
from argus.db.engine import create_engine, session_factory
from argus.observability.logs import configure_logging
from argus.observability.redaction import clear_registered_secrets
from tests.conftest import REPO_ROOT
from tests.integration.conftest import (
    TEST_DB_PREFIX,
    TEST_ROLE_PREFIX,
    admin_connect,
    owner_password,
)

INSUFFICIENT_PRIVILEGE = "42501"
runner = CliRunner()


async def _audit_rows(engine: AsyncEngine) -> list[tuple[Any, ...]]:
    async with engine.connect() as conn:
        result = await conn.execute(text("SELECT * FROM audit_events ORDER BY id"))
        return [tuple(row) for row in result]


async def _write(engine: AsyncEngine, action: str = "roles.test") -> None:
    async with session_factory(engine)() as session, session.begin():
        await record_audit(session, actor="test", action=action, details={"k": "v"})


def _as_owner(settings: DatabaseSettings, database: str, *statements: sql.Composable | str) -> None:
    with admin_connect(settings, database) as conn:
        for statement in statements:
            conn.execute(statement)


def _app_connect(settings: DatabaseSettings, database: str) -> psycopg.Connection[tuple[Any, ...]]:
    assert database.startswith(TEST_DB_PREFIX), database
    assert settings.password is not None
    return psycopg.connect(
        host=settings.host,
        port=settings.port,
        user=settings.user,
        password=settings.password.get_secret_value(),
        dbname=database,
        connect_timeout=5,
    )


# =========================================================================== what it may not do

_REFUSED: dict[str, tuple[str, str]] = {
    "update": ("UPDATE audit_events SET actor = 'mallory'", "permission denied for table"),
    "delete": ("DELETE FROM audit_events", "permission denied for table audit_events"),
    "truncate": ("TRUNCATE audit_events", "permission denied for table audit_events"),
    "backdate-an-event": (
        "INSERT INTO audit_events (actor, action, occurred_at) VALUES ('a', 'b', '2020-01-01')",
        "permission denied for table audit_events",
    ),
    "choose-an-id": (
        "INSERT INTO audit_events (id, actor, action) OVERRIDING SYSTEM VALUE"
        " VALUES (-1, 'a', 'b')",
        "permission denied for table audit_events",
    ),
    "disable-a-guard-trigger": (
        "ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only_rows",
        "must be owner of table audit_events",
    ),
    "make-a-guard-replica-only": (
        "ALTER TABLE audit_events ENABLE REPLICA TRIGGER audit_events_append_only_rows",
        "must be owner of table audit_events",
    ),
    "drop-the-table": ("DROP TABLE audit_events", "must be owner of table audit_events"),
    "take-ownership": (
        "ALTER TABLE audit_events OWNER TO CURRENT_USER",
        "must be owner of table audit_events",
    ),
    "drop-the-guard-function": (
        "DROP FUNCTION argus_reject_mutation()",
        "must be owner of function argus_reject_mutation",
    ),
    "replace-the-guard-function": (
        "CREATE OR REPLACE FUNCTION public.argus_reject_mutation() RETURNS trigger"
        " LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$",
        "permission denied for schema public",
    ),
    "add-a-trigger": (
        "CREATE TRIGGER sneaky BEFORE INSERT ON audit_events FOR EACH ROW"
        " EXECUTE FUNCTION argus_reject_mutation()",
        "permission denied for table audit_events",
    ),
    "create-a-table": ("CREATE TABLE public.notes (id int)", "permission denied for schema public"),
    "create-a-schema": ("CREATE SCHEMA sneaky", "permission denied for database"),
    "skip-triggers-as-replica": (
        "SET session_replication_role = replica",
        'permission denied to set parameter "session_replication_role"',
    ),
    "lock-out-everyone": (
        "LOCK TABLE audit_events IN ACCESS EXCLUSIVE MODE",
        "permission denied for table audit_events",
    ),
    "rewrite-the-migration-state": (
        "UPDATE alembic_version SET version_num = '0001'",
        "permission denied for table alembic_version",
    ),
    "add-a-migration-state": (
        "INSERT INTO alembic_version VALUES ('ffffffffffff')",
        "permission denied for table alembic_version",
    ),
    "become-a-superuser": ("ALTER ROLE CURRENT_USER SUPERUSER", "permission denied to alter role"),
    "allow-itself-createdb": (
        "ALTER ROLE CURRENT_USER CREATEDB",
        "permission denied to alter role",
    ),
    "create-a-role": ("CREATE ROLE sneaky", "permission denied to create role"),
    "read-password-hashes": (
        "SELECT rolpassword FROM pg_authid",
        "permission denied for table pg_authid",
    ),
}


@pytest.mark.parametrize(("statement", "message"), list(_REFUSED.values()), ids=list(_REFUSED))
async def test_the_runtime_role_is_refused_by_the_privilege_system(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, statement: str, message: str
) -> None:
    await _write(app_engine)
    before = await _audit_rows(migrated_engine)
    with pytest.raises(DBAPIError) as info:
        async with app_engine.begin() as conn:
            await conn.exec_driver_sql(statement)
    error = info.value.orig
    assert getattr(error, "sqlstate", None) == INSUFFICIENT_PRIVILEGE, str(error)
    assert message in str(error)
    assert "append-only" not in str(error)  # refused by privileges, not by a guard trigger
    assert await _audit_rows(migrated_engine) == before
    assert await migrate.missing_guard_triggers(migrated_engine) == []
    assert await roles.runtime_role_problems(app_engine) == []


async def test_the_runtime_role_cannot_switch_to_the_owner(
    app_engine: AsyncEngine, db_settings: DatabaseSettings
) -> None:
    for statement in (
        f'SET ROLE "{db_settings.owner_user}"',
        f'SET SESSION AUTHORIZATION "{db_settings.owner_user}"',
    ):
        with pytest.raises(DBAPIError) as info:
            async with app_engine.connect() as conn:
                await conn.exec_driver_sql(statement)
        assert getattr(info.value.orig, "sqlstate", None) == INSUFFICIENT_PRIVILEGE, statement
        assert "permission denied to set" in str(info.value.orig)


@pytest.mark.parametrize(
    "statement",
    [
        "GRANT UPDATE, DELETE ON audit_events TO PUBLIC",
        "GRANT ALL ON audit_events TO argus_runtime",
        "GRANT INSERT (occurred_at) ON audit_events TO CURRENT_USER",
        "GRANT CREATE ON SCHEMA public TO argus_runtime",
    ],
)
async def test_a_grant_by_the_runtime_role_gives_it_nothing(
    app_engine: AsyncEngine, statement: str
) -> None:
    """It holds privileges without grant option: PostgreSQL then only warns ("no privileges were
    granted") or refuses; either way nothing changes."""
    with contextlib.suppress(DBAPIError):
        async with app_engine.begin() as conn:
            await conn.exec_driver_sql(statement)
    assert await roles.runtime_role_problems(app_engine) == []


def test_bulk_copy_cannot_set_ids_or_timestamps(
    app_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str
) -> None:
    with _app_connect(db_settings, test_database) as conn:
        with conn.cursor() as cur, cur.copy("COPY audit_events (actor, action) FROM STDIN") as copy:
            copy.write_row(("bulk", "bulk.load"))  # the columns it may insert: allowed
        conn.commit()
        for columns in ("id, actor, action", "actor, action, occurred_at"):
            with (
                pytest.raises(psycopg.errors.InsufficientPrivilege),
                conn.cursor() as cur,
                cur.copy(f"COPY audit_events ({columns}) FROM STDIN"),
            ):
                pass
            conn.rollback()


# =========================================================================== what it may do


async def test_the_runtime_role_can_do_its_job_and_see_what_doctor_needs(
    app_engine: AsyncEngine,
) -> None:
    await _write(app_engine, "roles.allowed")
    rows = await _audit_rows(app_engine)
    assert [row[3] for row in rows] == ["roles.allowed"]
    assert rows[0][0] > 0  # numbered by the database
    assert await migrate.current_revision(app_engine) == migrate.head_revision()
    assert await migrate.schema_drift(app_engine) == []
    assert await migrate.missing_guard_triggers(app_engine) == []
    assert await roles.runtime_role_problems(app_engine) == []
    async with app_engine.begin() as conn:  # temporary tables are its own business
        await conn.exec_driver_sql("CREATE TEMP TABLE scratch (id int)")
        await conn.exec_driver_sql("SET ROLE argus_runtime")


async def test_the_owner_is_still_stopped_by_the_guard_triggers(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    """Two layers: the owner holds every privilege, yet the triggers stop it (D-016)."""
    await _write(app_engine)
    with pytest.raises(DBAPIError, match="append-only"):
        async with migrated_engine.begin() as conn:
            await conn.exec_driver_sql("DELETE FROM audit_events")


# =========================================================================== doctor's check

# 0026 (Q-C1): the hash chain's columns, set only by the owner's trigger.
_CHAIN_COLUMNS = (
    "can insert audit_events.chain_seq",
    "can insert audit_events.prev_hash",
    "can insert audit_events.row_hash",
)
_MISGRANTS: dict[str, tuple[str, list[str]]] = {
    "update": ("GRANT UPDATE ON audit_events TO argus_runtime", ["can UPDATE audit_events"]),
    "update-one-column": (
        "GRANT UPDATE (details) ON audit_events TO argus_runtime",
        ["can UPDATE audit_events"],
    ),
    "update-through-public": (
        "GRANT UPDATE ON audit_events TO PUBLIC",
        ["can UPDATE audit_events"],
    ),
    "delete": ("GRANT DELETE ON audit_events TO argus_runtime", ["can DELETE audit_events"]),
    "truncate": ("GRANT TRUNCATE ON audit_events TO argus_runtime", ["can TRUNCATE audit_events"]),
    "trigger": ("GRANT TRIGGER ON audit_events TO argus_runtime", ["can TRIGGER audit_events"]),
    "references": (
        "GRANT REFERENCES (actor) ON audit_events TO argus_runtime",
        ["can REFERENCES audit_events"],
    ),
    "insert-timestamps": (
        "GRANT INSERT (occurred_at) ON audit_events TO argus_runtime",
        ["can insert audit_events.occurred_at"],
    ),
    "insert-every-column": (
        "GRANT INSERT ON audit_events TO argus_runtime",
        ["can insert audit_events.id", "can insert audit_events.occurred_at", *_CHAIN_COLUMNS],
    ),
    "lost-insert": (
        "REVOKE INSERT (details) ON audit_events FROM argus_runtime",
        ["cannot insert audit_events.details"],
    ),
    "lost-read": ("REVOKE SELECT ON audit_events FROM argus_runtime", ["cannot read audit_events"]),
    "writable-migration-state": (
        "GRANT UPDATE ON alembic_version TO argus_runtime",
        ["can UPDATE alembic_version"],
    ),
    "insertable-migration-state": (
        "GRANT INSERT ON alembic_version TO argus_runtime",
        ["can insert alembic_version.version_num"],
    ),
    "create-in-public": (
        "GRANT CREATE ON SCHEMA public TO argus_runtime",
        ["can create tables in schema public"],
    ),
    "owns-the-trail": (
        "ALTER TABLE audit_events OWNER TO argus_runtime",
        [
            "owns audit_events (or is a member of its owner)",
            "can DELETE audit_events",
            "can TRUNCATE audit_events",
            "can TRIGGER audit_events",
            "can UPDATE audit_events",
            "can REFERENCES audit_events",
            "can insert audit_events.id",
            "can insert audit_events.occurred_at",
            *_CHAIN_COLUMNS,
            "can USAGE sequence audit_events_id_seq",  # its identity sequence moved with it
            "can SELECT sequence audit_events_id_seq",
            "can UPDATE sequence audit_events_id_seq",
        ],
    ),
    # QA2-R5's neighbours (QA2-R4): identity columns need no sequence privilege, so any is extra
    "sequence-update": (
        "GRANT UPDATE ON SEQUENCE audit_events_id_seq TO argus_runtime",
        ["can UPDATE sequence audit_events_id_seq"],
    ),
    "sequence-usage-through-public": (
        "GRANT USAGE, SELECT ON SEQUENCE audit_events_id_seq TO PUBLIC",
        ["can USAGE sequence audit_events_id_seq", "can SELECT sequence audit_events_id_seq"],
    ),
}


@pytest.mark.parametrize(("statement", "expected"), list(_MISGRANTS.values()), ids=list(_MISGRANTS))
async def test_doctor_reports_each_privilege_beyond_or_short_of_the_plan(
    app_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
    statement: str,
    expected: list[str],
) -> None:
    assert await roles.runtime_role_problems(app_engine) == []
    _as_owner(db_settings, test_database, statement)
    assert await roles.runtime_role_problems(app_engine) == expected


async def test_doctor_reports_a_database_where_the_runtime_role_can_create_schemas(
    app_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str
) -> None:
    grant = sql.SQL("GRANT CREATE ON DATABASE {} TO argus_runtime").format(
        sql.Identifier(test_database)
    )
    _as_owner(db_settings, test_database, grant)
    assert await roles.runtime_role_problems(app_engine) == ["can create schemas"]


@pytest.mark.parametrize(
    ("attribute", "problem"),
    [
        ("CREATEDB", "can create databases"),
        ("CREATEROLE", "can create roles"),
        ("REPLICATION", "can replicate"),
        ("BYPASSRLS", "bypasses row-level security"),
    ],
)
async def test_doctor_reports_role_attributes(
    make_login: Callable[[], Awaitable[DatabaseSettings]],
    migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
    attribute: str,
    problem: str,
) -> None:
    login = await make_login()
    engine = create_engine(login, database=test_database)
    try:
        assert await roles.runtime_role_problems(engine) == []
        _as_owner(
            db_settings,
            test_database,
            sql.SQL("ALTER ROLE {} {}").format(sql.Identifier(login.user), sql.SQL(attribute)),
        )
        assert await roles.runtime_role_problems(engine) == [problem]
    finally:
        await engine.dispose()


async def test_doctor_reports_a_superuser_or_a_member_of_the_owner(
    make_login: Callable[[], Awaitable[DatabaseSettings]],
    migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
) -> None:
    superuser, member = await make_login(), await make_login()
    _as_owner(
        db_settings,
        test_database,
        sql.SQL("ALTER ROLE {} SUPERUSER").format(sql.Identifier(superuser.user)),
        sql.SQL("GRANT {} TO {}").format(
            sql.Identifier(db_settings.owner_user), sql.Identifier(member.user)
        ),
    )
    for login in (superuser, member):
        engine = create_engine(login, database=test_database)
        try:
            problems = await roles.runtime_role_problems(engine)
        finally:
            await engine.dispose()
        assert "owns audit_events (or is a member of its owner)" in problems, login.user
        assert "can UPDATE audit_events" in problems
    engine = create_engine(superuser, database=test_database)
    try:
        assert (await roles.runtime_role_problems(engine))[0] == "is a superuser"
    finally:
        await engine.dispose()


@pytest.fixture
def cli_env(
    test_database: str, db_settings: DatabaseSettings, monkeypatch: pytest.MonkeyPatch
) -> Path:
    monkeypatch.chdir(REPO_ROOT)  # the repo .env: both passwords
    monkeypatch.setenv("ARGUS_DATABASE__NAME", test_database)
    monkeypatch.setenv("ARGUS_LOGGING__LEVEL", "WARNING")
    config = REPO_ROOT / "config" / "argus.yaml"
    effective = load_settings(config).database.name
    assert effective == test_database
    assert effective.startswith(TEST_DB_PREFIX)
    return config


def test_argus_doctor_fails_on_an_overprivileged_runtime_role(
    cli_env: Path, db_settings: DatabaseSettings, test_database: str
) -> None:
    assert runner.invoke(app, ["db", "upgrade", "-c", str(cli_env)]).exit_code == 0
    _as_owner(db_settings, test_database, "GRANT DELETE ON audit_events TO argus_runtime")
    result = runner.invoke(app, ["doctor", "-c", str(cli_env)])
    passwords = [owner_password(db_settings)]
    if db_settings.password is not None:
        passwords.append(db_settings.password.get_secret_value())
    printed = any(p in result.output for p in passwords)
    assert not printed, "a real database password appeared in doctor's output"
    assert result.exit_code == 1, result.output
    assert "FAIL  runtime role" in result.output
    assert f"{db_settings.user}: can DELETE audit_events" in result.output


# =========================================================================== bootstrap


async def test_bootstrap_creates_a_least_privileged_login_with_a_hashed_password(
    make_login: Callable[[], Awaitable[DatabaseSettings]],
    migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
) -> None:
    login = await make_login()
    with admin_connect(db_settings, test_database) as conn:
        row = conn.execute(
            "SELECT rolcanlogin, rolsuper, rolinherit, rolcreaterole, rolcreatedb,"
            " rolreplication, rolbypassrls, pg_has_role(rolname, %s, 'MEMBER'),"
            " rolpassword LIKE 'SCRAM-SHA-256$4096:%%'"
            " FROM pg_authid WHERE rolname = %s",
            (roles.RUNTIME_ROLE, login.user),
        ).fetchone()
        group = conn.execute(
            "SELECT rolcanlogin, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls"
            " FROM pg_roles WHERE rolname = %s",
            (roles.RUNTIME_ROLE,),
        ).fetchone()
    assert row == (True, False, True, False, False, False, False, True, True)
    assert group == (False, False, False, False, False)
    engine = create_engine(login, database=test_database)
    try:
        await _write(engine)  # logs in with its password and has the runtime privileges
        assert await roles.runtime_role_problems(engine) == []
    finally:
        await engine.dispose()


async def test_bootstrap_again_restores_attributes_and_the_configured_password(
    make_login: Callable[[], Awaitable[DatabaseSettings]],
    migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
) -> None:
    login = await make_login()
    other = f"Other-{secrets.token_hex(8)}"
    _as_owner(
        db_settings,
        test_database,
        sql.SQL("ALTER ROLE {} CREATEDB CREATEROLE NOINHERIT PASSWORD {}").format(
            sql.Identifier(login.user), sql.Literal(other)
        ),
        sql.SQL("REVOKE {} FROM {}").format(
            sql.Identifier(roles.RUNTIME_ROLE), sql.Identifier(login.user)
        ),
    )
    async with migrated_engine.begin() as conn:
        assert await roles.ensure_roles(conn, login) == []  # nothing new to create
    engine = create_engine(login, database=test_database)
    try:
        assert await roles.runtime_role_problems(engine) == []
    finally:
        await engine.dispose()
    with pytest.raises(psycopg.OperationalError, match="password authentication failed"):
        psycopg.connect(
            host=login.host,
            port=login.port,
            user=login.user,
            password=other,
            dbname=test_database,
            connect_timeout=5,
        ).close()


@pytest.mark.parametrize("login_exists", [False, True], ids=["new-login", "existing-login"])
async def test_concurrent_bootstraps_both_succeed(
    db_settings: DatabaseSettings,
    test_database: str,
    migrated_engine: AsyncEngine,
    make_login: Callable[[], Awaitable[DatabaseSettings]],
    login_exists: bool,
) -> None:
    """Two runs change the same role at once. Role catalog rows are not locked, so the later
    statement fails once the earlier transaction commits (a duplicate CREATE, or "tuple
    concurrently updated" for ALTER); bootstrap must absorb that and both runs succeed."""
    login = await make_login()  # its name is cleaned up afterwards
    if not login_exists:
        _as_owner(
            db_settings, test_database, sql.SQL("DROP ROLE {}").format(sql.Identifier(login.user))
        )
    engines = [create_engine(db_settings, database=test_database, role="owner") for _ in "ab"]

    async def bootstrap(engine: AsyncEngine) -> list[str]:
        async with engine.begin() as conn:
            created = await roles.ensure_roles(conn, login)
            await asyncio.sleep(0.3)  # keep the change uncommitted while the other run waits
            return created

    try:
        results = await asyncio.wait_for(
            asyncio.gather(*(bootstrap(engine) for engine in engines)), timeout=30
        )
    finally:
        for engine in engines:
            await engine.dispose()
    assert sorted(results) == ([[], []] if login_exists else [[], [login.user]])
    login_engine = create_engine(login, database=test_database)
    try:
        assert await roles.runtime_role_problems(login_engine) == []
    finally:
        await login_engine.dispose()


async def test_grant_connect_lets_the_runtime_role_in_when_public_may_not(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
) -> None:
    database = sql.Identifier(test_database)
    _as_owner(
        db_settings,
        test_database,
        sql.SQL("REVOKE CONNECT ON DATABASE {} FROM PUBLIC").format(database),
        sql.SQL("REVOKE CONNECT ON DATABASE {} FROM argus_runtime").format(database),
    )
    await app_engine.dispose()  # no pooled connection left from before
    with pytest.raises(DBAPIError, match="permission denied for database"):
        async with app_engine.connect():
            pass
    async with migrated_engine.begin() as conn:
        await roles.grant_connect(conn, test_database)
    async with app_engine.connect() as conn:
        assert (await conn.execute(text("SELECT 1"))).scalar_one() == 1


@pytest.mark.parametrize(
    "user", ["Argus_App", "argus-app", "1argus", "argus app", "", "a" * 64, "argüs"]
)
def test_bootstrap_only_creates_plain_lowercase_role_names(
    db_settings: DatabaseSettings, user: str
) -> None:
    with pytest.raises(ConfigError, match="lowercase letters, digits and _"):
        roles.check_bootstrap_settings(db_settings.model_copy(update={"user": user}))


def test_bootstrap_needs_the_runtime_password(db_settings: DatabaseSettings) -> None:
    with pytest.raises(ConfigError, match="ARGUS_DATABASE__PASSWORD"):
        roles.check_bootstrap_settings(db_settings.model_copy(update={"password": None}))


# =========================================================================== migration 0003


class _DeliberateRollbackError(Exception):
    """Ends a migration transaction without committing it."""


async def _migrate_with_the_runtime_role_hidden(
    engine: AsyncEngine,
    direction: Literal["upgrade", "downgrade"],
    revision: str,
    *,
    then_roll_back: bool = False,
) -> None:
    """Migrate in a transaction that first renames ``argus_runtime``: other sessions keep seeing
    the role, and the rename is undone with the transaction (which ``then_roll_back`` forces)."""
    hidden = f"argus_runtime_hidden_{secrets.token_hex(4)}"
    async with migrate.migration_transaction(engine) as conn:
        await conn.exec_driver_sql(f'ALTER ROLE argus_runtime RENAME TO "{hidden}"')
        await migrate.run(conn, direction, revision)
        if then_roll_back:
            assert await migrate.current_revision(conn) == revision
            raise _DeliberateRollbackError


async def test_upgrade_without_the_runtime_role_says_to_bootstrap_first(
    empty_engine: AsyncEngine,
) -> None:
    await migrate.upgrade(empty_engine, "0002")
    with pytest.raises(DBAPIError) as info:
        await _migrate_with_the_runtime_role_hidden(empty_engine, "upgrade", "head")
    error = info.value.orig
    assert isinstance(error, psycopg.errors.UndefinedObject)
    assert 'role "argus_runtime" does not exist' in str(error)
    assert error.diag.message_hint == 'run "argus db bootstrap" first'
    assert await migrate.current_revision(empty_engine) == "0002"
    async with empty_engine.connect() as conn:  # the rename was rolled back with the migration
        found = await conn.execute(text("SELECT 1 FROM pg_roles WHERE rolname = 'argus_runtime'"))
        assert found.first() is not None


async def test_downgrading_0003_revokes_the_runtime_privileges(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await migrate.downgrade(migrated_engine, "0002")
    for statement in ("SELECT version_num FROM alembic_version", "SELECT id FROM audit_events"):
        with pytest.raises(DBAPIError, match="permission denied for table"):
            async with app_engine.connect() as conn:
                await conn.exec_driver_sql(statement)
    await migrate.upgrade(migrated_engine)
    assert await roles.runtime_role_problems(app_engine) == []


async def test_downgrading_0003_without_the_runtime_role_is_a_no_op(
    migrated_engine: AsyncEngine,
) -> None:
    with pytest.raises(_DeliberateRollbackError):
        await _migrate_with_the_runtime_role_hidden(
            migrated_engine, "downgrade", "0002", then_roll_back=True
        )
    assert await migrate.current_revision(migrated_engine) == migrate.head_revision()


def test_the_runtime_grants_match_migration_0003(monkeypatch: pytest.MonkeyPatch) -> None:
    """The privileges doctor expects are the ones the migration grants."""
    path = Path(migrate.MIGRATIONS_DIR) / "versions" / "0003_runtime_role_grants.py"
    spec = importlib.util.spec_from_file_location("argus_migration_0003", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    executed: list[str] = []
    monkeypatch.setattr(module.op, "execute", lambda sql: executed.append(" ".join(sql.split())))
    module.upgrade()
    columns = ", ".join(roles.RUNTIME_GRANTS["audit_events"].insert)
    assert executed[1:] == [
        "GRANT USAGE ON SCHEMA public TO argus_runtime",
        "GRANT SELECT ON alembic_version TO argus_runtime",
        f"GRANT SELECT, INSERT ({columns}) ON audit_events TO argus_runtime",
    ]
    assert set(roles.RUNTIME_GRANTS) == {
        "alembic_version", "audit_events", "admin_changes", "admin_sealed", "admin_state",
        "user_links", "admin_jobs", "admin_job_secrets",
        "siem_switches", "siem_state", "siem_requests", "siem_live_sessions",
        "alert_records", "collector_cursors", "reconciliation_runs", "coverage_gaps",
        "investigations", "investigation_alerts", "investigation_entities", "entities", "jobs",
        "users", "user_sessions", "review_events", "review_state",
        "evidence", "dossiers", "signals", "langgraph.checkpoint_migrations",
        "langgraph.checkpoints", "langgraph.checkpoint_blobs", "langgraph.checkpoint_writes",
        "rules", "rule_revisions", "ti_sources", "ti_indicators", "ti_lookups", "knowledge_items",
        "soak_samples", "writeback_outbox", "gold_items", "gold_labels", "assessments",
        "llm_state", "llm_calls", "tuning_reports", "siem_probes", "evidence_requests",
        "chain_heads", "cases", "case_members", "case_indicators", "case_events", "case_notes",
        "entity_notes", "case_openings", "approval_requests", "approval_decisions",
        "kibana_outbox", "kibana_mirror", "action_ledger", "llm_shadow", "identity_checks",
        "freshness_readings", "freshness_watermarks", "freshness_shadow", "freshness_proposals",
        "kibana_sync_state", "kibana_sync_cycles", "kibana_findings", "kibana_people_cases",
        "kibana_alert_states", "user_devices", "break_glass", "investigation_checks",
        "kibana_steps", "kibana_lookups", "kibana_writer_runs", "kibana_writer_ramp",
        "case_watch_checks", "case_suggestions", "notices", "case_actions", "reports",
        "assessment_shares", "investigation_raises", "outside_lookups", "outside_requests",
        "case_notices", "case_known_matches", "case_known_keys", "case_reminders",
        "incident_reports", "incident_report_decisions", "incident_report_checks",
        "case_team_posts", "case_team_steps", "case_team_approvals", "case_team_seen",
        "case_team_reads", "case_team_looks", "signin_sightings", "signin_lookups",
        "risk_objects", "risk_groups", "risk_entities", "risk_observations", "risk_sources",
        "risk_object_scores", "risk_crossings", "risk_incidents", "risk_incident_objects",
        "risk_incident_groups", "risk_links", "risk_threats", "risk_aliases", "exposure_checks",
        "case_holds", "case_seen", "spot_checks", "user_rounds", "report_sends",
        "risk_gray_items", "risk_mode", "risk_evidence", "risk_readings",
    }  # fmt: skip
    assert roles.RUNTIME_GRANTS["alembic_version"] == roles.TableGrant(select=True)
    assert roles.RUNTIME_GRANTS["audit_events"].update == ()


MIRROR_0034 = ("case_id", "kibana_case_id", "kibana_version", "status", "title", "severity",
               "tags", "created_by", "sync_alerts", "unmanaged", "kibana_created_at",
               "kibana_updated_at", "read_at", "deleted_at", "actions_seen", "argus_actions",
               "paused_reason")  # fmt: skip


@pytest.mark.parametrize(
    ("migration", "tables"),
    [
        ("0004_elastic_gateway_state",
         ("siem_switches", "siem_state", "siem_requests", "siem_live_sessions")),
        ("0005_collector_alert_store",
         ("alert_records", "collector_cursors", "reconciliation_runs", "coverage_gaps")),
        ("0006_investigations_and_jobs",
         ("investigations", "investigation_alerts", "investigation_entities", "entities",
          "jobs")),
        ("0007_inbox_users_and_reviews", ("users", "user_sessions", "review_events")),
        ("0008_context_graph",
         ("evidence", "dossiers", "signals",
          "GRANT UPDATE (deferred_since, deferrals) ON jobs TO argus_runtime",
          "GRANT USAGE ON SCHEMA langgraph TO argus_runtime",
          "langgraph.checkpoint_migrations", "langgraph.checkpoints",
          "langgraph.checkpoint_blobs", "langgraph.checkpoint_writes")),
        ("0009_reference_data",
         ("rules", "rule_revisions", "ti_sources", "ti_indicators", "ti_lookups",
          "knowledge_items")),
        ("0011_rules_and_dossiers_per_pack",
         ("GRANT INSERT (definition_at), UPDATE (definition_at) ON rules TO argus_runtime",
          "GRANT INSERT (pack) ON signals TO argus_runtime")),
        ("0012_soak_samples", ("soak_samples",)),
        ("0013_writeback_outbox", ("writeback_outbox",)),
        ("0014_writeback_sent_count",
         ("GRANT UPDATE (sent_count) ON writeback_outbox TO argus_runtime",)),
        ("0016_gold_set_items_and_labels_p2", ("gold_items", "gold_labels")),
        ("0017_assessments_p3",
         ("assessments", "GRANT INSERT (assessment_id) ON review_events TO argus_runtime")),
        ("0018_llm_gateway_state_and_ledger_p5", ("llm_state", "llm_calls")),
        ("0019_tuning_reports_p7", ("tuning_reports",)),
        ("0020_assessment_priority",
         ("GRANT INSERT (priority) ON assessments TO argus_runtime",)),
        ("0022_siem_probe_history", ("siem_probes",)),
        ("0023_evidence_requests_and_ledger_task_key",
         ("evidence_requests", "GRANT INSERT (task_key) ON siem_requests TO argus_runtime")),
        ("0024_sessions_and_capabilities",
         ("GRANT INSERT (capabilities), UPDATE (capabilities) ON users TO argus_runtime",
          "GRANT INSERT (expires_at), UPDATE (stepped_up_at, stepup_failures) ON user_sessions"
          " TO argus_runtime")),
        ("0025_review_state", ("review_state",)),
        ("0026_cases_outbox_approvals_chain",  # argus_approvals' EXECUTE: doctor's function check
         ("chain_heads", "cases", "case_members", "case_indicators", "case_events", "case_notes",
          "entity_notes", "case_openings", "approval_requests", "approval_decisions",
          "kibana_outbox", "kibana_mirror", "action_ledger")),
        ("0028_llm_shadow_store_q_g2", ("llm_shadow",)),
        ("0029_kibana_lane_and_lanes",
         ("GRANT INSERT (lane, target, outbox_id, payload_hash, write_class, approval_id, health,"
          " switches) ON siem_requests TO argus_runtime",)),
        ("0030_closure_approval_send_checks",
         ("GRANT EXECUTE ON FUNCTION argus_approval_propose(text, uuid, integer, text, text,"
          " bigint, jsonb, text, text, timestamptz, text) TO argus_runtime",
          "GRANT EXECUTE ON FUNCTION argus_closure_write_move(bigint, text, text)"
          " TO argus_runtime",
          "GRANT EXECUTE ON FUNCTION argus_closure_write_lock(bigint) TO argus_runtime",
          "identity_checks")),
        ("0033_freshness_watermarks",
         ("GRANT INSERT (asked_at), UPDATE (asked_at) ON evidence TO argus_runtime",
          "freshness_readings", "freshness_watermarks", "freshness_shadow",
          "freshness_proposals")),
        ("0034_kibana_read_back",
         ("GRANT INSERT (" + ", ".join(MIRROR_0034) + "), UPDATE ("
          + ", ".join(MIRROR_0034[2:]) + ") ON kibana_mirror TO argus_runtime",
          "kibana_sync_state", "kibana_sync_cycles", "kibana_findings", "kibana_people_cases",
          "kibana_alert_states")),
        ("0035_kibana_read_back_review",
         ("GRANT INSERT (unexplained), UPDATE (kibana_case_id, unexplained) ON kibana_mirror"
          " TO argus_runtime",
          "GRANT UPDATE (diff_cursor) ON kibana_sync_state TO argus_runtime")),
        ("0036_elk_sign_in",
         ("GRANT INSERT (kind, realm), UPDATE (elk_username, realm) ON users TO argus_runtime",
          "GRANT UPDATE (credential, ended_why) ON user_sessions TO argus_runtime",
          "user_devices", "break_glass",
          "GRANT INSERT (kibana_ok) ON review_events TO argus_runtime")),
        ("0037_kibana_case_writer",
         ("kibana_steps", "kibana_lookups", "kibana_writer_runs", "kibana_writer_ramp")),
        ("0039_investigation_checks", ("investigation_checks",)),
        ("0044_case_actions", ("case_actions",)),
        ("0046_reports", ("reports",)),
        ("0048_outside_intel", ("outside_lookups", "outside_requests")),
        ("0050_owner_notified",
         ("GRANT UPDATE (notified_at, blocked_at) ON cases TO argus_runtime", "case_notices",
          "case_known_matches", "case_known_keys", "case_reminders")),
        ("0051_owner_notified_review", ("case_known_matches",)),
        ("0052_incident_reports",
         ("incident_reports", "incident_report_decisions", "incident_report_checks")),
        ("0053_case_team",
         ("case_team_posts", "case_team_steps", "case_team_approvals", "case_team_seen")),
        ("0054_case_team_review",
         ("case_team_reads", "case_team_looks",
          "GRANT INSERT (counts) ON case_team_seen TO argus_runtime")),
        ("0055_case_split",
         ("GRANT UPDATE (link, link_value, added_version, added_by, added_at)"
          " ON case_members TO argus_runtime",
          "GRANT UPDATE (role, source, added_version, added_by, added_at, removed_version,"
          " removed_at) ON case_indicators TO argus_runtime")),
        ("0056_signins", ("signin_sightings", "signin_lookups")),
        ("0057_signins_review",
         ("GRANT INSERT (unnamed, store_failures), UPDATE (unnamed, store_failures)"
          " ON signin_lookups TO argus_runtime",
          "GRANT INSERT (core_hash) ON incident_reports TO argus_runtime")),
        ("0070_risk_engine",
         ("GRANT UPDATE (lineage, tactics, stage_mask, indices, family, meta_at) ON rules"
          " TO argus_runtime",
          "risk_objects", "risk_groups", "risk_entities", "risk_observations", "risk_sources",
          "risk_object_scores", "risk_crossings")),
        ("0071_risk_incidents",
         ("risk_incidents", "risk_incident_objects", "risk_incident_groups", "risk_links",
          "risk_threats", "risk_aliases")),
        ("0075_exposure_checks", ("exposure_checks",)),
        ("0100_queue_marks",
         ("case_holds", "case_seen", "spot_checks", "user_rounds", "report_sends")),
        ("0095_risk_present",
         ("GRANT UPDATE (title, certainty, shown, shown_day, queued_at, raised_by_ai, presented,"
          " presented_at) ON risk_incidents TO argus_runtime",
          "risk_gray_items", "risk_mode")),
        ("0101_risk_evidence", ("risk_evidence",)),
        ("0104_risk_readings", ("risk_readings",)),
    ],
)  # fmt: skip
def test_the_runtime_grants_match_each_migration(
    migration: str, tables: tuple[str, ...], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each GRANT a migration runs is exactly what doctor expects (RUNTIME_GRANTS); a later
    migration's columns (LATER_COLUMNS) are granted by that migration, written out above."""
    path = Path(migrate.MIGRATIONS_DIR) / "versions" / f"{migration}.py"
    spec = importlib.util.spec_from_file_location(f"argus_migration_{migration}", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    executed: list[str] = []
    monkeypatch.setattr(module.op, "execute", lambda sql: executed.append(" ".join(sql.split())))
    monkeypatch.setattr(module.op, "create_table", lambda *a, **k: None)
    for name in ("create_index", "add_column", "drop_constraint", "create_check_constraint",
                 "alter_column", "create_primary_key", "create_foreign_key"):  # fmt: skip
        monkeypatch.setattr(module.op, name, lambda *a, **k: None)
    monkeypatch.setattr(module.op, "f", lambda name: name)
    module.upgrade()
    grants = [sql for sql in executed if sql.startswith("GRANT") and "TO argus_runtime" in sql]

    def later(table: str) -> set[str]:
        return {
            column
            for after, by_table in LATER_COLUMNS.items()
            if after > migration
            for column in by_table.get(table, ())
        }

    expected = [
        table if table.startswith("GRANT") else grant_sql(table, without=later(table))
        for table in tables
    ]
    assert grants == expected


LEDGER_0029 = ("lane", "target", "outbox_id", "payload_hash", "write_class", "approval_id",
               "health", "switches")  # fmt: skip
# Columns of an earlier migration's tables that a later migration added (and granted).
LATER_COLUMNS = {
    "0095": {
        "risk_incidents": (
            "title",
            "certainty",
            "shown",
            "shown_day",
            "queued_at",
            "raised_by_ai",
            "presented",
            "presented_at",
        )
    },
    "0008": {"jobs": ("deferred_since", "deferrals")},
    "0011": {"rules": ("definition_at",), "signals": ("pack",)},
    "0014": {"writeback_outbox": ("sent_count",)},
    "0045": {"writeback_outbox": ("case_id", "closure_request_id")},
    "0017": {"review_events": ("assessment_id",)},
    "0020": {"assessments": ("priority",)},
    "0023": {"siem_requests": ("task_key",)},
    "0024": {
        "users": ("capabilities",),
        "user_sessions": ("expires_at", "stepped_up_at", "stepup_failures"),
    },
    "0029": {"siem_requests": LEDGER_0029},
    "0033": {"evidence": ("asked_at",)},
    "0034": {"kibana_mirror": MIRROR_0034},  # 0026 gave SELECT only (Q-D3 writes the mirror)
    "0035": {"kibana_mirror": ("unexplained",), "kibana_sync_state": ("diff_cursor",)},
    "0036": {
        "users": ("kind", "realm", "elk_username"),
        "user_sessions": ("credential", "ended_why"),
        "review_events": ("kibana_ok",),
    },
    "0050": {"cases": ("notified_at", "blocked_at")},
    "0051": {"case_known_matches": ("changed_version",)},
    "0054": {"case_team_seen": ("counts",)},
    # "update:" names a column only the UPDATE grant gained (it was inserted already)
    "0055": {
        "case_members": tuple(
            f"update:{c}" for c in ("link", "link_value", "added_version", "added_by", "added_at")
        ),
        "case_indicators": tuple(
            f"update:{c}"
            for c in (
                "role",
                "source",
                "added_version",
                "added_by",
                "added_at",
                "removed_version",
                "removed_at",
            )
        ),
    },
    "0057": {"signin_lookups": ("unnamed", "store_failures"), "incident_reports": ("core_hash",)},
    "0070": {"rules": ("lineage", "tactics", "stage_mask", "indices", "family", "meta_at")},
}


def grant_sql(table: str, role: str = "argus_runtime", without: set[str] | None = None) -> str:
    grant = roles.RUNTIME_GRANTS[table]
    skip = without or set()
    parts = ["SELECT"] if grant.select else []
    if grant.delete:
        parts.append("DELETE")
    inserted = [c for c in grant.insert if c not in skip]
    updated = [c for c in grant.update if c not in skip and f"update:{c}" not in skip]
    if inserted:
        parts.append(f"INSERT ({', '.join(inserted)})")
    if updated:
        parts.append(f"UPDATE ({', '.join(updated)})")
    return f"GRANT {', '.join(parts)} ON {table} TO {role}"


# =========================================================================== temporary objects


async def test_unqualified_names_resolve_in_public_before_pg_temp(app_engine: AsyncEngine) -> None:
    """The search_path every connection starts with (engine.py): pg_temp is searched last, so a
    temporary audit_events never takes the name over, not even in the unit of work that made it.
    Without it pg_temp would be searched first."""
    async with app_engine.connect() as conn:
        assert (await conn.exec_driver_sql("SHOW search_path")).scalar_one() == "public,pg_temp"
        await conn.exec_driver_sql("CREATE TEMP TABLE audit_events (id int)")
        schema = await conn.execute(
            text(
                "SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
                " WHERE c.oid = to_regclass('audit_events')"
            )
        )
        assert schema.scalar_one() == "public"


async def test_a_temporary_table_is_gone_at_the_next_checkout(
    db_settings: DatabaseSettings, app_engine: AsyncEngine
) -> None:
    """The pool reset's DISCARD TEMP: a temporary object never outlives its unit of work on a
    pooled connection (here the same backend serves both units of work)."""
    engine = create_engine(
        db_settings.model_copy(update={"pool_size": 1, "max_overflow": 0}),
        database=app_engine.url.database,
    )
    try:
        async with engine.connect() as conn:
            first = (await conn.exec_driver_sql("SELECT pg_backend_pid()")).scalar_one()
            await conn.exec_driver_sql("CREATE TEMP TABLE scratch (id int)")
            await conn.commit()
        async with engine.connect() as conn:
            second = (await conn.exec_driver_sql("SELECT pg_backend_pid()")).scalar_one()
            left = await conn.exec_driver_sql("SELECT to_regclass('pg_temp.scratch')")
            assert left.scalar_one() is None
        assert second == first  # precondition: the same pooled connection came back
    finally:
        await engine.dispose()


async def test_an_audit_write_names_its_schema_whatever_the_unit_of_work_set(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """ARGUS's statements name the public schema (schema_translate_map), so a unit of work that
    puts pg_temp first on its own search_path cannot turn its audit write into a write to a
    temporary table."""
    async with session_factory(app_engine)() as session, session.begin():
        await session.execute(text("CREATE TEMP TABLE audit_events (LIKE public.audit_events)"))
        await session.execute(text("SET LOCAL search_path = pg_temp, public"))
        await record_audit(session, actor="test", action="roles.qualified")
    async with migrated_engine.connect() as conn:
        actions = await conn.execute(text("SELECT action FROM public.audit_events"))
        assert [row[0] for row in actions] == ["roles.qualified"]


# =========================================================================== the CLI's report


@pytest.fixture
def throwaway_login(db_settings: DatabaseSettings, test_database: str) -> Iterator[str]:
    """A login name of the stale-cleanup scheme for the CLI to create; dropped afterwards."""
    name = f"{TEST_ROLE_PREFIX}{int(time.time())}_{secrets.token_hex(4)}"
    yield name
    with admin_connect(db_settings, test_database) as conn:
        if conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (name,)).fetchone():
            conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(name)))
            conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(name)))


def test_cli_bootstrap_prints_and_audits_exactly_what_it_repaired(
    throwaway_login: str,
    db_settings: DatabaseSettings,
    test_database: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    password = f"fake-runtime-pw-{secrets.token_hex(8)}"
    for key in list(os.environ):
        if key.upper().startswith("ARGUS_"):
            monkeypatch.delenv(key)
    monkeypatch.chdir(tmp_path)  # no .env in reach
    monkeypatch.setenv("ARGUS_DATABASE__OWNER_PASSWORD", owner_password(db_settings))
    monkeypatch.setenv("ARGUS_DATABASE__PASSWORD", password)
    config = tmp_path / "argus.yaml"
    config.write_text(
        f"database:\n  host: '{db_settings.host}'\n  port: {db_settings.port}\n"
        f"  name: '{test_database}'\n  user: '{throwaway_login}'\n"
        f"  owner_user: '{db_settings.owner_user}'\nlogging:\n  level: WARNING\n",
        encoding="utf-8",
    )
    hidden = (password, owner_password(db_settings))
    try:
        for command in (["db", "upgrade"], ["db", "bootstrap"]):
            result = runner.invoke(app, [*command, "-c", str(config)])
            printed = any(secret in result.output for secret in hidden)
            assert not printed, "a password appeared in CLI output"
            assert result.exit_code == 0, result.output
        login = sql.Identifier(throwaway_login)
        _as_owner(
            db_settings,
            test_database,
            sql.SQL("ALTER ROLE {} SUPERUSER").format(login),
            sql.SQL("ALTER ROLE {} SET work_mem = '1MB'").format(login),
            sql.SQL("GRANT pg_read_server_files TO {}").format(login),
        )
        result = runner.invoke(app, ["db", "bootstrap", "-c", str(config)])
    finally:
        clear_registered_secrets()
        configure_logging("WARNING", "console", stream=io.StringIO())
    printed = any(secret in result.output for secret in hidden)
    assert not printed, "a password appeared in CLI output"
    assert result.exit_code == 0, result.output
    repaired = [
        f"{throwaway_login} had SUPERUSER: reset",
        f"{throwaway_login} had stored settings (work_mem): cleared",
        f"{throwaway_login} was a member of pg_read_server_files: revoked",
    ]
    assert result.stdout.splitlines() == [
        f"roles ready: {throwaway_login} (member of argus_runtime) may connect to"
        f" {test_database}; already present",
        *(f"repaired: {repair}" for repair in repaired),
    ]
    with admin_connect(db_settings, test_database) as conn:
        rows = conn.execute(
            "SELECT details FROM audit_events WHERE action = 'db.bootstrap' ORDER BY id"
        ).fetchall()
    assert [row[0]["repaired"] for row in rows] == [[], repaired]
