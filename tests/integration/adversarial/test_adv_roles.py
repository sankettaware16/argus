"""Adversarial review of D-029's role separation: attacks on the privilege boundary that
``tests/integration/db/test_roles.py`` does not already cover.

Goal 1 attacks the runtime role itself (``app_engine`` or a throwaway login): can it change,
hide or lose audit events, neuter the guard triggers, or escalate? Goal 2 attacks
``roles.runtime_role_problems`` -- the check behind ``argus doctor`` -- for false negatives (a
dangerous capability it misses) and false positives (a safe setup it flags).

Conventions (see the sibling adversarial files): a docstring starting with **DEFECT** marks a
test that fails on the current code on purpose -- it proves the hole and passes once it is
closed; **LOCK-IN** tests pass today and pin behaviour that held up under attack.

Safety: every database here is a throwaway one from ``tests/integration/conftest.py`` (names
start with ``argus_test_``); role attributes and memberships are cluster-wide, so they are only
ever changed on throwaway logins from ``make_login`` (never on ``argus_app``/``argus_runtime``),
and every grant is reverted and every engine disposed in a ``finally``.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from datetime import timedelta

import pytest
from psycopg import sql
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config import DatabaseSettings
from argus.db import migrate, roles
from argus.db.audit import record_audit
from argus.db.engine import create_engine, session_factory
from tests.integration.conftest import admin_connect

INSUFFICIENT_PRIVILEGE = "42501"


def _as_owner(settings: DatabaseSettings, database: str, *statements: sql.Composable | str) -> None:
    """Run owner-only statements (grants, role DDL) against a throwaway database."""
    with admin_connect(settings, database) as conn:
        for statement in statements:
            conn.execute(statement)


# =========================================================================== Goal 1: the trail


async def test_defect_a_temp_table_named_audit_events_shadows_the_trail_across_pool_reuse(
    migrated_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str
) -> None:
    """DEFECT: the pool reset runs ``RESET SESSION AUTHORIZATION; RESET ROLE; RESET ALL`` -- not
    ``DISCARD TEMP`` -- so temporary objects outlive a connection's return to the pool. A runtime
    session that creates a ``TEMP TABLE audit_events`` therefore leaves a shadow that, via
    search_path (pg_temp is resolved first), captures the next unqualified audit statement on the
    same pooled connection. The ORM's ``INSERT INTO audit_events`` is unqualified, so a later
    ``record_audit`` writes into the private temp table: the event never reaches the durable
    trail, is invisible to every other session, and vanishes when the connection closes. This
    contradicts D-029's "Temporary objects cannot touch ARGUS's tables"; the pool reset must drop
    temporary objects. The runtime role is ARGUS itself, so a compromised component, a SQL
    injection or a Phase-2 LLM-built query reaches this."""
    app = create_engine(
        db_settings.model_copy(update={"pool_size": 1, "max_overflow": 0}),
        database=test_database,
    )
    try:
        # One unit of work creates the shadow and hands the connection back to the pool.
        async with app.connect() as conn:
            await conn.exec_driver_sql(
                "CREATE TEMP TABLE audit_events ("
                " id bigint GENERATED ALWAYS AS IDENTITY,"
                " occurred_at timestamptz DEFAULT now(),"
                " actor text, action text, outcome text,"
                " target_type text, target_id text, correlation_id text, details jsonb)"
            )
            await conn.commit()
        # The next unit of work makes an ordinary audit write on the reused connection.
        async with session_factory(app)() as session, session.begin():
            await record_audit(session, actor="argus", action="trail.write", details={"k": "v"})
        # On the reused connection the name must resolve to the real table, not the temp shadow.
        async with app.connect() as conn:
            schema = (
                await conn.execute(
                    text(
                        "SELECT n.nspname FROM pg_class c"
                        " JOIN pg_namespace n ON n.oid = c.relnamespace"
                        " WHERE c.oid = to_regclass('audit_events')"
                    )
                )
            ).scalar_one()
        assert schema == "public", f"audit_events resolves to {schema!r}, a temporary shadow"
    finally:
        await app.dispose()
    # The event must be in the real, durable trail (read as the owner).
    async with migrated_engine.connect() as conn:
        result = await conn.execute(text("SELECT action FROM public.audit_events ORDER BY id"))
        actions = [row[0] for row in result]
    assert actions == ["trail.write"]


async def test_lockin_a_schema_qualified_write_still_reaches_the_real_trail(
    migrated_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str
) -> None:
    """LOCK-IN: the temp-table shadow only diverts *unqualified* names. A ``public.``-qualified
    insert reaches the real table even while a ``TEMP TABLE audit_events`` is present, which is
    why qualifying the ORM's statements (or, better, dropping temp objects on reset) closes the
    hole above."""
    app = create_engine(
        db_settings.model_copy(update={"pool_size": 1, "max_overflow": 0}),
        database=test_database,
    )
    try:
        async with app.connect() as conn:
            await conn.exec_driver_sql("CREATE TEMP TABLE audit_events (id bigint)")
            await conn.exec_driver_sql(
                "INSERT INTO public.audit_events (actor, action) VALUES ('argus', 'qualified')"
            )
            await conn.commit()
    finally:
        await app.dispose()
    async with migrated_engine.connect() as conn:
        result = await conn.execute(text("SELECT action FROM public.audit_events ORDER BY id"))
        actions = [row[0] for row in result]
    assert actions == ["qualified"]


async def test_lockin_guard_trigger_binds_by_oid_not_by_a_shadowable_name(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """LOCK-IN: the append-only trigger calls ``argus_reject_mutation`` by OID (D-029), so placing
    a same-named no-op function in pg_temp ahead of public on the search_path does not turn the
    guard off -- the owner's DELETE is still rejected."""
    async with session_factory(app_engine)() as session, session.begin():
        await record_audit(session, actor="argus", action="guard.seed", details={})
    async with migrated_engine.connect() as conn:
        await conn.exec_driver_sql(
            "CREATE FUNCTION pg_temp.argus_reject_mutation() RETURNS trigger"
            " LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$"
        )
        await conn.exec_driver_sql("SET search_path = pg_temp, public")
        await conn.commit()
        with pytest.raises(DBAPIError, match="append-only"):
            await conn.exec_driver_sql("DELETE FROM audit_events")


async def test_lockin_runtime_role_cannot_renumber_via_the_identity_sequence(
    app_engine: AsyncEngine,
) -> None:
    """LOCK-IN: the runtime role holds no privilege on the audit id sequence, so it cannot
    ``nextval``/``setval`` it or ``ALTER`` it to renumber future events or force id collisions."""
    sequence = "public.audit_events_id_seq"
    async with app_engine.connect() as conn:
        for privilege in ("USAGE", "SELECT", "UPDATE"):
            held = (
                await conn.execute(
                    text("SELECT has_sequence_privilege(:s, :p)"),
                    {"s": sequence, "p": privilege},
                )
            ).scalar_one()
            assert held is False, privilege
    for statement in (
        "SELECT nextval('public.audit_events_id_seq')",
        "SELECT setval('public.audit_events_id_seq', 1, false)",
        "ALTER SEQUENCE public.audit_events_id_seq RESTART WITH 1",
    ):
        with pytest.raises(DBAPIError) as info:
            async with app_engine.begin() as conn:
                await conn.exec_driver_sql(statement)
        assert getattr(info.value.orig, "sqlstate", None) == INSUFFICIENT_PRIVILEGE, statement


async def test_lockin_runtime_can_stall_migrations_but_they_fail_within_the_timeout(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
) -> None:
    """LOCK-IN: advisory locks need no privilege, so the runtime role can take ARGUS's migration
    lock and block the owner's migrations -- a denial of service. The exposure is bounded: the
    contended migration fails within the lock/statement timeout rather than hanging, and leaves
    the schema untouched."""
    owner = create_engine(
        db_settings.model_copy(update={"statement_timeout": timedelta(seconds=2)}),
        database=test_database,
        role="owner",
    )
    async with app_engine.connect() as holder:
        await holder.execute(text("SELECT pg_advisory_lock(:k)"), {"k": migrate.MIGRATION_LOCK_KEY})
        try:
            started = time.monotonic()
            with pytest.raises(DBAPIError):
                await migrate.upgrade(owner)
            assert time.monotonic() - started < 20
        finally:
            await owner.dispose()
            await holder.execute(text("SELECT pg_advisory_unlock_all()"))
    assert await migrate.current_revision(migrated_engine) == migrate.head_revision()


# =========================================================================== Goal 2: doctor

# Predefined roles that grant server-level capabilities without any role attribute or table
# grant that runtime_role_problems inspects, so doctor is blind to membership in them.
_DANGEROUS_PREDEFINED_ROLES = [
    "pg_read_server_files",
    "pg_write_server_files",
    "pg_execute_server_program",
    "pg_read_all_data",
    "pg_signal_backend",
    "pg_maintain",
]


@pytest.mark.parametrize("predefined", _DANGEROUS_PREDEFINED_ROLES)
async def test_defect_doctor_is_blind_to_dangerous_predefined_role_membership(
    make_login: Callable[[], Awaitable[DatabaseSettings]],
    migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
    predefined: str,
) -> None:
    """DEFECT: runtime_role_problems inspects role attributes and per-table grants but never a
    role's memberships, so membership in a PostgreSQL predefined role is invisible to it. Any of
    these gives the runtime login a dangerous server-level capability -- read/write arbitrary
    files on the database host, run programs as the server account, read every table (including
    pg_authid), signal other backends, or lock any table -- while doctor still reports it as
    least-privileged. doctor must flag membership in such roles."""
    login = await make_login()
    engine = create_engine(login, database=test_database)
    grant = sql.SQL("GRANT {} TO {}").format(sql.Identifier(predefined), sql.Identifier(login.user))
    revoke = sql.SQL("REVOKE {} FROM {}").format(
        sql.Identifier(predefined), sql.Identifier(login.user)
    )
    try:
        assert await roles.runtime_role_problems(engine) == []
        _as_owner(db_settings, test_database, grant)
        problems = await roles.runtime_role_problems(engine)
        assert problems != [], f"doctor is blind to membership in {predefined}"
    finally:
        _as_owner(db_settings, test_database, revoke)
        await engine.dispose()


async def test_defect_doctor_passes_a_runtime_role_that_can_read_password_hashes(
    make_login: Callable[[], Awaitable[DatabaseSettings]],
    migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
) -> None:
    """DEFECT: with ``pg_read_all_data`` the runtime login can read ``pg_authid`` (every role's
    password hash) -- which test_roles.py pins as forbidden for the plain runtime role -- yet
    runtime_role_problems reports nothing, because it ignores predefined-role membership. The
    ``pg_authid`` read succeeds before and after any doctor fix; what must change is that doctor
    flags the membership."""
    login = await make_login()
    engine = create_engine(login, database=test_database)
    grant = sql.SQL("GRANT pg_read_all_data TO {}").format(sql.Identifier(login.user))
    revoke = sql.SQL("REVOKE pg_read_all_data FROM {}").format(sql.Identifier(login.user))
    try:
        _as_owner(db_settings, test_database, grant)
        async with engine.connect() as conn:
            hashes = (await conn.execute(text("SELECT count(*) FROM pg_authid"))).scalar_one()
        assert hashes > 0  # the membership really does expose the password hashes
        assert await roles.runtime_role_problems(engine) != []
    finally:
        _as_owner(db_settings, test_database, revoke)
        await engine.dispose()


async def test_lockin_doctor_catches_pg_write_all_data_via_the_column_checks(
    make_login: Callable[[], Awaitable[DatabaseSettings]],
    migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
) -> None:
    """LOCK-IN: ``pg_write_all_data`` is the predefined role that grants writes on the audit
    table, and doctor already catches it -- ``has_table_privilege``/``has_column_privilege``
    honour predefined-role membership, so the role is reported able to DELETE and UPDATE
    audit_events and to insert its id and occurred_at (the columns the database must own)."""
    login = await make_login()
    engine = create_engine(login, database=test_database)
    grant = sql.SQL("GRANT pg_write_all_data TO {}").format(sql.Identifier(login.user))
    revoke = sql.SQL("REVOKE pg_write_all_data FROM {}").format(sql.Identifier(login.user))
    try:
        _as_owner(db_settings, test_database, grant)
        problems = await roles.runtime_role_problems(engine)
    finally:
        _as_owner(db_settings, test_database, revoke)
        await engine.dispose()
    for expected in (
        "can DELETE audit_events",
        "can UPDATE audit_events",
        "can insert audit_events.id",
        "can insert audit_events.occurred_at",
    ):
        assert expected in problems, problems
