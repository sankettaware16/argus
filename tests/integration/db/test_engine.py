from __future__ import annotations

import time
from collections.abc import Awaitable, Callable

import pytest
from psycopg import sql
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config import DatabaseSettings
from argus.db.engine import APPLICATION_NAME, create_engine
from argus.db.errors import short_db_error
from tests.integration.conftest import admin_connect


async def test_session_settings(db_settings: DatabaseSettings, test_database: str) -> None:
    engine = create_engine(db_settings, database=test_database)
    try:
        async with engine.connect() as conn:
            assert (await conn.execute(text("SHOW TimeZone"))).scalar_one() == "UTC"
            assert (await conn.execute(text("SHOW statement_timeout"))).scalar_one() == "30s"
            assert (await conn.execute(text("SHOW lock_timeout"))).scalar_one() == "10s"
            assert (
                await conn.execute(text("SHOW application_name"))
            ).scalar_one() == APPLICATION_NAME
            now = (await conn.execute(text("SELECT now()"))).scalar_one()
            assert now.utcoffset().total_seconds() == 0
    finally:
        await engine.dispose()


async def test_statement_timeout_is_enforced(
    db_settings: DatabaseSettings, test_database: str
) -> None:
    fast = db_settings.model_copy(
        update={"statement_timeout": db_settings.statement_timeout.__class__(seconds=1)}
    )
    engine = create_engine(fast, database=test_database)
    started = time.monotonic()
    try:
        with pytest.raises(DBAPIError, match="statement timeout"):
            async with engine.connect() as conn:
                await conn.execute(text("SELECT pg_sleep(5)"))
    finally:
        await engine.dispose()
    assert time.monotonic() - started < 4


async def test_wrong_password_fails_without_leaking(
    db_settings: DatabaseSettings, test_database: str
) -> None:
    wrong = "Wrong-Pass-For-Test-42"
    engine = create_engine(
        db_settings.model_copy(update={"password": SecretStr(wrong)}), database=test_database
    )
    try:
        with pytest.raises(OperationalError) as info:
            async with engine.connect():
                pass
    finally:
        await engine.dispose()
    message = short_db_error(info.value)
    assert "cannot connect" in message
    assert wrong not in message


async def test_unreachable_server_fails_fast(db_settings: DatabaseSettings) -> None:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        closed_port = sock.getsockname()[1]
    engine = create_engine(db_settings.model_copy(update={"port": closed_port}))
    started = time.monotonic()
    try:
        with pytest.raises(OperationalError):
            async with engine.connect():
                pass
    finally:
        await engine.dispose()
    assert time.monotonic() - started < 6


async def _identity(engine: AsyncEngine) -> tuple[int, str, str]:
    async with engine.connect() as conn:
        row = (
            await conn.execute(text("SELECT pg_backend_pid(), current_user, session_user"))
        ).one()
    return int(row[0]), str(row[1]), str(row[2])


@pytest.mark.parametrize(
    "statements",
    [
        ["SET ROLE pg_monitor"],
        ["SET SESSION AUTHORIZATION pg_monitor"],
        ["SET SESSION AUTHORIZATION pg_read_all_data", "SET ROLE pg_read_all_data"],
    ],
    ids=["set-role", "set-session-authorization", "both"],
)
async def test_committed_role_change_does_not_leak_into_the_next_checkout(
    db_settings: DatabaseSettings, test_database: str, statements: list[str]
) -> None:
    """RESET ALL leaves the role and the session authorization alone. Unless the pool's reset
    undoes them too, one unit of work's role (D-029: owner/app/api roles) and its privileges carry
    over into the next unit of work that gets the same pooled connection. (As the owner: only a
    superuser may switch to these roles.)"""
    engine = create_engine(
        db_settings.model_copy(update={"pool_size": 1, "max_overflow": 0}),
        database=test_database,
        role="owner",
    )
    try:
        pid, login_user, _ = await _identity(engine)
        async with engine.begin() as conn:
            superuser = (
                await conn.execute(
                    text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
                )
            ).scalar_one()
            assert superuser, "precondition: the local Docker Postgres user is a superuser"
            for statement in statements:
                await conn.execute(text(statement))
            changed_to = (await conn.execute(text("SELECT current_user"))).scalar_one()
        assert changed_to != login_user  # precondition: the change took effect and was committed

        assert await _identity(engine) == (pid, login_user, login_user)
        async with engine.begin() as conn:  # the login user's privileges are back
            await conn.execute(text("CREATE TABLE created_after_reset (id int)"))
    finally:
        await engine.dispose()


async def test_the_runtime_role_is_back_after_a_committed_set_role(
    db_settings: DatabaseSettings, app_engine: AsyncEngine
) -> None:
    """The pool's reset works for a login that is no superuser: ``RESET SESSION AUTHORIZATION``
    and ``RESET ROLE`` are allowed to any role, so the runtime login gets its connection back
    as itself after switching to its group role."""
    engine = create_engine(
        db_settings.model_copy(update={"pool_size": 1, "max_overflow": 0}),
        database=app_engine.url.database,
    )
    try:
        pid, login_user, _ = await _identity(engine)
        assert login_user == db_settings.user
        async with engine.begin() as conn:
            await conn.execute(text("SET ROLE argus_runtime"))
            assert (await conn.execute(text("SELECT current_user"))).scalar_one() == "argus_runtime"
        assert await _identity(engine) == (pid, login_user, login_user)
    finally:
        await engine.dispose()


async def test_a_role_the_login_starts_in_is_back_after_a_committed_set_role_none(
    db_settings: DatabaseSettings,
    test_database: str,
    make_login: Callable[[], Awaitable[DatabaseSettings]],
) -> None:
    """A login may start its sessions in a role (``ALTER ROLE ... SET role``). The reset returns a
    connection to where it started, not merely to the login: a unit of work that leaves the role
    must not hand the next one a connection without it. RESET ROLE does this, and so does
    PostgreSQL 17's RESET SESSION AUTHORIZATION."""
    login = await make_login()
    with admin_connect(db_settings, test_database) as conn:
        conn.execute(
            sql.SQL("ALTER ROLE {} IN DATABASE {} SET role = {}").format(
                sql.Identifier(login.user),
                sql.Identifier(test_database),
                sql.Literal("argus_runtime"),
            )
        )
    engine = create_engine(
        login.model_copy(update={"pool_size": 1, "max_overflow": 0}), database=test_database
    )
    try:
        started = await _identity(engine)
        assert started[1:] == ("argus_runtime", login.user)  # precondition: it starts in the role
        async with engine.begin() as conn:
            await conn.execute(text("SET ROLE NONE"))
            assert (await conn.execute(text("SELECT current_user"))).scalar_one() == login.user
        assert await _identity(engine) == started
    finally:
        await engine.dispose()


_AFTER_RESET = text(
    "SELECT pg_backend_pid(), current_user, current_setting('role'), "
    "current_setting('statement_timeout')"
)


async def test_the_reset_keeps_working_for_the_whole_life_of_a_pooled_connection(
    db_settings: DatabaseSettings, app_engine: AsyncEngine
) -> None:
    """The reset is several statements in one execute(), which psycopg may send only as a simple
    query, never as a prepared statement. psycopg prepares a query from its sixth run on a
    connection; this one must stay unprepared and keep resetting, through SQLAlchemy's async
    adapter, long after that (a failed reset would replace the connection: a new backend pid)."""
    engine = create_engine(
        db_settings.model_copy(update={"pool_size": 1, "max_overflow": 0}),
        database=app_engine.url.database,
    )
    try:
        pid, login_user, _ = await _identity(engine)
        for _ in range(12):
            async with engine.begin() as conn:
                await conn.execute(text("SET ROLE argus_runtime"))
                await conn.execute(text("SET statement_timeout = 0"))
            async with engine.connect() as conn:
                row = (await conn.execute(_AFTER_RESET)).one()
            assert tuple(row) == (pid, login_user, "none", "30s")
    finally:
        await engine.dispose()
