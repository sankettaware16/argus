"""Re-attack of D-029's privilege boundary after the round-3 fixes (the temp-object/search_path
fix in ``argus.db.engine``, and doctor's membership and settings checks in ``argus.db.roles``).

This file is the independent check on those fixes and on what they might have broken. It is a
sibling of ``test_adv_roles.py`` and ``test_adv_bootstrap.py`` and does not repeat their cases.

Three fronts:

* **Goal 1 — temp objects and the search path.** The fix makes every connection start with
  ``search_path = public, pg_temp`` and runs ``DISCARD TEMP`` when a pooled connection is
  returned, so a temporary ``audit_events`` can no longer shadow the real table across pool
  reuse (the round-2/3 defect). The LOCK-INs here pin that the guarantee holds for *every* kind
  of temporary object, for a committed ``SET search_path``, across prepared statements, and for a
  schema named like the login. The DEFECT shows the one place the guarantee does **not** reach:
  a single unit of work that re-points its own search path still diverts its unqualified audit
  write into a temporary shadow, so the event is lost from the durable trail.

* **Goal 2 — doctor's new checks** (``roles._membership_problems`` / ``_settings_problems``):
  no false negative for a membership reached through a chain, a SET-option-only link, or the
  group; no false positive for a CREATEROLE owner (which PostgreSQL 16 makes a member of the
  roles it creates) or for a setting stored for another database.

* **Goal 3 — other escalation** the runtime role must still be refused: COPY to/from an external
  program or a server file, and the server-file reading functions.

Conventions (see the sibling adversarial files): a docstring starting with **DEFECT** marks a
test that fails on the current code on purpose and passes once the hole is closed; **LOCK-IN**
tests pass today and pin behaviour that held up under attack.

Safety: every database here is a throwaway one from ``tests/integration/conftest.py`` (names
start with ``argus_test_``). ``argus``, ``argus_app`` and ``argus_runtime`` are never altered:
role attributes and memberships are changed only on ``make_login`` logins and on roles this file
creates itself, named ``argus_test_role_<unix>_<8 hex>`` (the ``throwaway_roles`` fixture drops
them). A test that needs its own group role points ``roles.RUNTIME_ROLE`` at a throwaway name
with monkeypatch. Every engine is disposed in a ``finally`` and secret values are never printed.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Awaitable, Callable, Iterator

import pytest
from psycopg import sql
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config import DatabaseSettings
from argus.db import roles
from argus.db.audit import record_audit
from argus.db.engine import create_engine, session_factory
from tests.conftest import hide_in_reports
from tests.integration.conftest import TEST_ROLE_PATTERN, TEST_ROLE_PREFIX, admin_connect

INSUFFICIENT_PRIVILEGE = "42501"

# A temporary table shaped exactly like the real audit_events, so the ORM's
# ``INSERT ... RETURNING id, occurred_at`` succeeds against it if a name ever resolves here.
_TEMP_AUDIT = (
    "CREATE TEMP TABLE audit_events ("
    " id bigint GENERATED ALWAYS AS IDENTITY,"
    " occurred_at timestamptz DEFAULT now(),"
    " actor text, action text, outcome text,"
    " target_type text, target_id text, correlation_id text, details jsonb)"
)
# What migration 0003 grants the group role; replayed onto a throwaway group so a login in it is
# as privileged as the real runtime role (and doctor reports no grant difference).
_MIGRATION_0003_GRANTS = (
    "GRANT USAGE ON SCHEMA public TO {group}",
    "GRANT SELECT ON alembic_version TO {group}",
    "GRANT SELECT, INSERT (actor, action, outcome, target_type, target_id, correlation_id,"
    " details) ON audit_events TO {group}",
)
# The later migrations grant exactly what RUNTIME_GRANTS says (checked per migration in
# tests/integration/db/test_roles.py), so their statements are built from it.
_LATER_GRANTS = (
    "GRANT USAGE ON SCHEMA langgraph TO {group}",  # 0008 (D-054)
    *(
        "GRANT "
        + ", ".join(
            (["SELECT"] if g.select else [])
            + (["DELETE"] if g.delete else [])
            + ([f"INSERT ({', '.join(g.insert)})"] if g.insert else [])
            + ([f"UPDATE ({', '.join(g.update)})"] if g.update else [])
        )
        + f" ON {table} TO {{group}}"
        for table, g in roles.RUNTIME_GRANTS.items()
        if table not in ("alembic_version", "audit_events")
    ),
    # 0030 (Q-C3): the functions the runtime may execute, ARGUS's proposals and the
    # send-time check's moves
    *(f"GRANT EXECUTE ON FUNCTION {f} TO {{group}}" for f in roles.RUNTIME_FUNCTIONS),
)

MakeLogin = Callable[[], Awaitable[DatabaseSettings]]


def _as_owner(settings: DatabaseSettings, database: str, *statements: sql.Composable | str) -> None:
    """Run owner-only statements (role DDL, grants) against a throwaway database."""
    with admin_connect(settings, database) as conn:
        for statement in statements:
            conn.execute(statement)


@pytest.fixture
def throwaway_roles(
    db_settings: DatabaseSettings, test_database: str
) -> Iterator[Callable[[], str]]:
    """Names for roles a test creates itself, ``argus_test_role_<unix>_<8 hex>`` as make_login
    names its logins (so the session's stale cleanup recognises a leftover). Afterwards each one
    that still exists is dropped, newest first, with what it owns or was granted."""
    names: list[str] = []

    def _name() -> str:
        name = f"{TEST_ROLE_PREFIX}{int(time.time())}_{secrets.token_hex(4)}"
        assert TEST_ROLE_PATTERN.fullmatch(name), name
        names.append(name)
        return name

    yield _name
    with admin_connect(db_settings, test_database) as conn:
        for name in reversed(names):
            if conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (name,)).fetchone():
                conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(name)))
                conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(name)))


async def _resolved_schema(engine: AsyncEngine) -> str:
    """The schema an unqualified ``audit_events`` resolves to on ``engine``'s connection."""
    async with engine.connect() as conn:
        return str(
            (
                await conn.execute(
                    text(
                        "SELECT n.nspname FROM pg_class c JOIN pg_namespace n"
                        " ON n.oid = c.relnamespace WHERE c.oid = to_regclass('audit_events')"
                    )
                )
            ).scalar_one()
        )


async def _durable_actions(owner_engine: AsyncEngine) -> list[str]:
    async with owner_engine.connect() as conn:
        result = await conn.execute(text("SELECT action FROM public.audit_events ORDER BY id"))
        return [row[0] for row in result]


# =========================================================================== Goal 1: temp / path


async def test_defect_search_path_repointed_in_one_unit_of_work_diverts_the_audit_write(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """DEFECT: the fix stops a temporary ``audit_events`` from shadowing the real table *across*
    pool reuse (DISCARD TEMP on reset) and makes ``public`` come before ``pg_temp`` at connect.
    But within a single unit of work the session may still re-point its own search path: a
    ``SET LOCAL search_path = pg_temp, public`` (or a plain ``SET``/``set_config`` in the same
    transaction) puts pg_temp first again, and the ORM's audit statement is unqualified
    (``INSERT INTO audit_events``, the model names no schema). So a session that creates a
    ``TEMP TABLE audit_events`` and re-points its path -- which ARGUS reaches through SQL
    injection or a Phase-2 LLM-built query running in the same session that then records what it
    did -- writes the audit event into the private temporary shadow. The event never reaches the
    durable, shared trail and vanishes when the connection is reset: the very record of the
    tampering is lost, contradicting D-029's "no unqualified name resolves there". Qualifying the
    ORM's audit table to ``public`` (schema on the model) closes this; the reset cannot, because
    it runs only between units of work."""
    async with session_factory(app_engine)() as session, session.begin():
        await session.execute(text(_TEMP_AUDIT))
        await session.execute(text("SET LOCAL search_path = pg_temp, public"))
        await record_audit(session, actor="argus", action="tamper.hidden", details={"k": "v"})
    assert "tamper.hidden" in await _durable_actions(migrated_engine), (
        "the audit write was diverted into a temporary shadow and lost from the durable trail"
    )


async def test_lockin_a_committed_set_search_path_and_temp_shadow_are_both_undone_on_reset(
    app_engine: AsyncEngine, db_settings: DatabaseSettings, migrated_engine: AsyncEngine
) -> None:
    """LOCK-IN: a hostile unit of work both commits ``SET search_path = pg_temp, public`` (session
    level, which RESET ALL must undo) and creates a ``TEMP TABLE audit_events`` (which DISCARD
    TEMP must drop). After the connection returns to the pool, the next unit of work on the same
    connection starts with ``public, pg_temp`` again and its unqualified ORM write lands in the
    real table -- the round-2/3 defect stays closed even when the attacker also re-points the
    path, not just creates a temp table."""
    engine = create_engine(
        db_settings.model_copy(update={"pool_size": 1, "max_overflow": 0}),
        database=app_engine.url.database,
    )
    try:
        async with engine.connect() as conn:
            await conn.exec_driver_sql(_TEMP_AUDIT)
            await conn.exec_driver_sql("SET search_path = pg_temp, public")
            await conn.commit()
        async with session_factory(engine)() as session, session.begin():
            await record_audit(session, actor="argus", action="after.reset", details={})
        async with engine.connect() as conn:
            search_path = (await conn.execute(text("SHOW search_path"))).scalar_one()
        assert search_path == "public,pg_temp"
        assert await _resolved_schema(engine) == "public"
    finally:
        await engine.dispose()
    assert await _durable_actions(migrated_engine) == ["after.reset"]


async def test_lockin_discard_temp_clears_every_kind_of_temporary_object(
    app_engine: AsyncEngine, db_settings: DatabaseSettings
) -> None:
    """LOCK-IN: the reset's ``DISCARD TEMP`` drops not only temp tables but temp views, sequences
    and functions too, and ``RESET ALL`` restores the startup search path -- all on the same
    reused backend (the pid is unchanged, so the reset never errored and forced a new connection).
    Nothing an attacker leaves in pg_temp survives to the next unit of work."""
    engine = create_engine(
        db_settings.model_copy(update={"pool_size": 1, "max_overflow": 0}),
        database=app_engine.url.database,
    )
    try:
        async with engine.connect() as conn:
            pid = (await conn.execute(text("SELECT pg_backend_pid()"))).scalar_one()
            await conn.exec_driver_sql(_TEMP_AUDIT)
            await conn.exec_driver_sql("CREATE TEMP VIEW shadow_view AS SELECT 1 AS x")
            await conn.exec_driver_sql("CREATE TEMP SEQUENCE shadow_seq")
            await conn.exec_driver_sql(
                "CREATE FUNCTION pg_temp.shadow_fn() RETURNS int LANGUAGE sql AS 'SELECT 1'"
            )
            await conn.exec_driver_sql("SET search_path = pg_temp, public")
            await conn.commit()
        async with engine.connect() as conn:
            reused_pid = (await conn.execute(text("SELECT pg_backend_pid()"))).scalar_one()
            left_relations = (
                await conn.execute(
                    text(
                        "SELECT count(*) FROM pg_class c JOIN pg_namespace n"
                        " ON n.oid = c.relnamespace WHERE n.nspname LIKE 'pg_temp%'"
                    )
                )
            ).scalar_one()
            left_functions = (
                await conn.execute(
                    text(
                        "SELECT count(*) FROM pg_proc p JOIN pg_namespace n"
                        " ON n.oid = p.pronamespace WHERE n.nspname LIKE 'pg_temp%'"
                    )
                )
            ).scalar_one()
            search_path = (await conn.execute(text("SHOW search_path"))).scalar_one()
        assert reused_pid == pid, "the reset invalidated the connection instead of cleaning it"
        assert left_relations == 0
        assert left_functions == 0
        assert search_path == "public,pg_temp"
    finally:
        await engine.dispose()


async def test_lockin_a_prepared_audit_insert_keeps_writing_to_the_real_table(
    app_engine: AsyncEngine, db_settings: DatabaseSettings, migrated_engine: AsyncEngine
) -> None:
    """LOCK-IN: psycopg prepares a statement after it has run a few times on a connection, and the
    fix keeps ``DISCARD TEMP`` rather than ``DISCARD ALL`` precisely so those prepared plans
    survive. Recording many events on one pooled connection -- interleaving a ``TEMP TABLE
    audit_events`` that is dropped on each reset -- the prepared INSERT plan stays bound to
    ``public.audit_events`` (it was resolved with public first), never follows a dropped temp
    object, and never invalidates the connection: one backend, every event durable."""
    engine = create_engine(
        db_settings.model_copy(update={"pool_size": 1, "max_overflow": 0}),
        database=app_engine.url.database,
    )
    pids: set[int] = set()
    try:
        for i in range(10):
            async with session_factory(engine)() as session, session.begin():
                await record_audit(session, actor="argus", action=f"prep.{i}", details={"i": i})
            if i % 3 == 0:  # leave a temp shadow behind on some checkouts
                async with engine.connect() as conn:
                    await conn.exec_driver_sql(_TEMP_AUDIT)
                    await conn.commit()
            async with engine.connect() as conn:
                pids.add(int((await conn.execute(text("SELECT pg_backend_pid()"))).scalar_one()))
    finally:
        await engine.dispose()
    assert len(pids) == 1, "the connection was replaced; the reset or a stale plan broke it"
    assert await _durable_actions(migrated_engine) == [f"prep.{i}" for i in range(10)]


async def test_lockin_a_schema_named_like_the_login_does_not_capture_audit_writes(
    app_engine: AsyncEngine, db_settings: DatabaseSettings, migrated_engine: AsyncEngine
) -> None:
    """LOCK-IN: the startup search path is a literal ``public, pg_temp`` -- it has no ``$user``
    entry -- so a schema named exactly like the runtime login, holding its own ``audit_events``,
    is never searched, even when the runtime role is granted use of it. The unqualified ORM write
    still resolves to ``public`` and reaches the durable trail. (The owner sets this up; the
    runtime role cannot create a schema.)"""
    user = db_settings.user
    schema = sql.Identifier(user)
    async with migrated_engine.begin() as conn:
        await conn.exec_driver_sql(sql.SQL("CREATE SCHEMA {}").format(schema).as_string())
        await conn.exec_driver_sql(
            sql.SQL("CREATE TABLE {}.audit_events (id bigint, actor text, action text)")
            .format(schema)
            .as_string()
        )
        await conn.exec_driver_sql(
            sql.SQL("GRANT USAGE ON SCHEMA {} TO {}")
            .format(schema, sql.Identifier(roles.RUNTIME_ROLE))
            .as_string()
        )
        await conn.exec_driver_sql(
            sql.SQL("GRANT INSERT, SELECT ON {}.audit_events TO {}")
            .format(schema, sql.Identifier(roles.RUNTIME_ROLE))
            .as_string()
        )
    try:
        async with session_factory(app_engine)() as session, session.begin():
            await record_audit(session, actor="argus", action="userschema.test", details={})
        assert await _resolved_schema(app_engine) == "public"
    finally:
        async with migrated_engine.begin() as conn:
            await conn.exec_driver_sql(sql.SQL("DROP SCHEMA {} CASCADE").format(schema).as_string())
    assert "userschema.test" in await _durable_actions(migrated_engine)


# =========================================================================== Goal 2: doctor


async def test_lockin_doctor_reports_a_dangerous_role_reached_through_a_chain(
    make_login: MakeLogin,
    throwaway_roles: Callable[[], str],
    migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
) -> None:
    """LOCK-IN: ``_membership_problems`` uses ``pg_has_role(..., 'MEMBER')``, which follows the
    whole membership graph, so a dangerous capability reached through an intermediate role is not
    hidden. A login made a member of an ordinary role that is itself a member of
    ``pg_read_all_data`` is reported for every link, not just the direct one, while its correct
    membership in argus_runtime raises nothing."""
    login = await make_login()
    middle = throwaway_roles()
    engine = create_engine(login, database=test_database)
    try:
        _as_owner(
            db_settings,
            test_database,
            sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(middle)),
            sql.SQL("GRANT pg_read_all_data TO {}").format(sql.Identifier(middle)),
            sql.SQL("GRANT {} TO {}").format(sql.Identifier(middle), sql.Identifier(login.user)),
        )
        problems = await roles.runtime_role_problems(engine)
    finally:
        await engine.dispose()
    # pg_read_all_data reads every sequence too, which doctor names since QA2-R4
    sequences = [p for p in problems if " sequence " in p]
    assert sequences, problems
    assert all(p.startswith("can SELECT sequence ") for p in sequences), sequences
    assert sorted(p for p in problems if p not in sequences) == sorted(
        [f"is a member of {middle}", "is a member of pg_read_all_data"]
    ), problems


async def test_lockin_doctor_reports_a_set_option_only_membership(
    make_login: MakeLogin,
    migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
) -> None:
    """LOCK-IN: a membership granted ``WITH INHERIT FALSE, SET TRUE`` gives the login no privilege
    until it runs ``SET ROLE``, so the table and attribute checks see nothing -- but the login can
    still assume the role on demand. doctor reports it, because ``pg_has_role(..., 'MEMBER')`` is
    true for a SET-only membership just as for an inheriting one."""
    login = await make_login()
    engine = create_engine(login, database=test_database)
    try:
        _as_owner(
            db_settings,
            test_database,
            sql.SQL("GRANT pg_read_all_data TO {} WITH INHERIT FALSE, SET TRUE").format(
                sql.Identifier(login.user)
            ),
        )
        problems = await roles.runtime_role_problems(engine)
    finally:
        await engine.dispose()
    assert problems == ["is a member of pg_read_all_data"], problems


async def test_lockin_doctor_has_no_false_positive_under_a_createrole_owner(
    throwaway_roles: Callable[[], str],
    migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LOCK-IN: D-029 allows a non-superuser owner with CREATEROLE on a shared host. Since
    PostgreSQL 16 such an owner is automatically made an ADMIN member of every role it creates,
    so the owner becomes a member of both the group and the login. doctor checks the login's own
    view, where the direction is the other way round (the owner is a member of the login, not the
    login of the owner), so it must not misread this as the login owning the trail or belonging to
    an extra role. With the group given the migrations' grants, ``runtime_role_problems`` is
    empty."""
    owner_name, group, login_name = throwaway_roles(), throwaway_roles(), throwaway_roles()
    owner_password = secrets.token_urlsafe(24)
    hide_in_reports(owner_password)
    _as_owner(
        db_settings,
        test_database,
        sql.SQL("CREATE ROLE {} LOGIN CREATEROLE PASSWORD {}").format(
            sql.Identifier(owner_name), sql.Literal(owner_password)
        ),
    )
    monkeypatch.setattr(roles, "RUNTIME_ROLE", group)
    owner = db_settings.model_copy(
        update={"owner_user": owner_name, "owner_password": SecretStr(owner_password)}
    )
    login = owner.model_copy(
        update={"user": login_name, "password": SecretStr(secrets.token_urlsafe(24))}
    )
    owner_engine = create_engine(owner, database=test_database, role="owner")
    try:
        async with owner_engine.begin() as conn:
            created = await roles.ensure_roles(conn, login)
        assert sorted(created) == sorted([group, login_name])
        _as_owner(
            db_settings,
            test_database,
            *(
                sql.SQL(g).format(group=sql.Identifier(group))
                for g in (*_MIGRATION_0003_GRANTS, *_LATER_GRANTS)
            ),
        )
        login_engine = create_engine(login, database=test_database)
        try:
            problems = await roles.runtime_role_problems(login_engine)
        finally:
            await login_engine.dispose()
    finally:
        await owner_engine.dispose()
    assert problems == [], problems


async def test_lockin_doctor_ignores_a_setting_stored_for_another_database(
    make_login: MakeLogin,
    make_database: Callable[[], str],
    migrated_engine: AsyncEngine,
    db_settings: DatabaseSettings,
    test_database: str,
) -> None:
    """LOCK-IN: ``_settings_problems`` looks only at settings that apply to ARGUS's sessions --
    stored role-wide (``setdatabase = 0``) or for the current database. A dangerous setting stored
    for a *different* database (``ALTER ROLE ... IN DATABASE other SET session_replication_role =
    replica``) never reaches ARGUS, so flagging it would be a false positive; doctor stays silent.
    The same setting in ARGUS's own database is reported."""
    login = await make_login()
    other_database = make_database()
    engine = create_engine(login, database=test_database)
    user = sql.Identifier(login.user)
    try:
        _as_owner(
            db_settings,
            test_database,
            sql.SQL("ALTER ROLE {} IN DATABASE {} SET session_replication_role = replica").format(
                user, sql.Identifier(other_database)
            ),
        )
        assert await roles.runtime_role_problems(engine) == []

        _as_owner(
            db_settings,
            test_database,
            sql.SQL("ALTER ROLE {} IN DATABASE {} SET session_replication_role = replica").format(
                user, sql.Identifier(test_database)
            ),
        )
        assert await roles.runtime_role_problems(engine) == [
            "has settings stored on it (session_replication_role)"
        ]
    finally:
        await engine.dispose()


# =========================================================================== Goal 3: escalation


@pytest.mark.parametrize(
    "statement",
    [
        pytest.param("COPY audit_events TO PROGRAM 'cat'", id="copy-table-to-program"),
        pytest.param("COPY (SELECT 1) TO PROGRAM 'cat'", id="copy-query-to-program"),
        pytest.param("COPY audit_events FROM PROGRAM 'echo a,b'", id="copy-from-program"),
        pytest.param("COPY audit_events FROM '/etc/hostname'", id="copy-from-server-file"),
    ],
)
async def test_lockin_runtime_role_gets_no_program_or_server_file_access_via_copy(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, statement: str
) -> None:
    """LOCK-IN: COPY to or from an external program, and COPY from a file the server reads, are
    refused for the runtime role (they need superuser or ``pg_execute_server_program`` /
    ``pg_read_server_files``). Each is stopped by the privilege system (SQLSTATE 42501), before
    any program runs or file is read -- so a compromised runtime session cannot read host files or
    run commands as the database's OS account."""
    with pytest.raises(DBAPIError) as info:
        async with app_engine.begin() as conn:
            await conn.exec_driver_sql(statement)
    assert getattr(info.value.orig, "sqlstate", None) == INSUFFICIENT_PRIVILEGE, str(info.value)
    assert "append-only" not in str(info.value.orig)  # refused by privileges, not a guard trigger


@pytest.mark.parametrize(
    "statement",
    [
        pytest.param("SELECT pg_read_file('/etc/hostname')", id="pg_read_file"),
        pytest.param("SELECT pg_ls_dir('.')", id="pg_ls_dir"),
    ],
)
async def test_lockin_runtime_role_cannot_read_server_files_through_functions(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, statement: str
) -> None:
    """LOCK-IN: the server-side file functions are restricted to superusers and members of
    ``pg_read_server_files``; the runtime role is neither, so ``pg_read_file`` and ``pg_ls_dir``
    are refused (42501). Reading the data directory or host files is not reachable from a runtime
    session."""
    with pytest.raises(DBAPIError) as info:
        async with app_engine.begin() as conn:
            await conn.exec_driver_sql(statement)
    assert getattr(info.value.orig, "sqlstate", None) == INSUFFICIENT_PRIVILEGE, str(info.value)
