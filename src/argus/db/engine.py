"""Async database engine and sessions (SQLAlchemy 2 + psycopg 3)."""

from __future__ import annotations

import logging

from sqlalchemy import event
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import ConnectionPoolEntry, PoolResetState

from argus.config.settings import DatabaseRole, DatabaseSettings
from argus.observability.redaction import redact_text

APPLICATION_NAME = "argus"
# ARGUS's tables live in public. Every statement SQLAlchemy builds from them names the schema
# (INSERT INTO public.audit_events ...), so no search_path can send it elsewhere: not the one a
# connection starts with, and not one a unit of work sets for itself (SET LOCAL search_path =
# pg_temp, public would otherwise turn ARGUS's own audit write into a write to a temporary table).
ARGUS_SCHEMA = "public"
# Run when a connection goes back to the pool, as one query: psycopg sends a query without
# parameters as a simple query, which may hold several statements. The login user first, so
# RESET ALL runs as it. RESET ROLE is belt and braces: on PostgreSQL 17, RESET SESSION
# AUTHORIZATION already resets the role too, to the one the connection started with. DISCARD TEMP
# drops temporary objects, so none outlives the unit of work that made it.
_RESET_SESSION = "RESET SESSION AUTHORIZATION; RESET ROLE; RESET ALL; DISCARD TEMP"
# Unqualified names resolve in public first; pg_temp is searched last instead of first, so a
# temporary table never shadows an ARGUS table (an "audit_events" in pg_temp would otherwise
# capture the audit writes made on that connection).
_SEARCH_PATH = "public,pg_temp"


def create_engine(
    settings: DatabaseSettings, *, database: str | None = None, role: DatabaseRole = "app"
) -> AsyncEngine:
    """Engine with conservative timeouts: a stuck query or lock fails instead of hanging ARGUS.

    ``role`` picks the login (D-029): the runtime role ``app`` for everything ARGUS does, the
    schema ``owner`` only for ``argus db`` (bootstrap, migrations). ``database`` overrides
    ``settings.name`` (tests use throwaway databases); an override that is blank, too long or not
    UTF-8 raises ConfigError rather than falling back to the configured database. Bound parameter
    values never appear in exception text (they may hold credentials or raw SIEM data), and every
    connection is reset to these session settings, and to the user it logged in as, before it is
    reused.
    """
    url = settings.url(database=database, role=role)
    statement_ms = int(settings.statement_timeout.total_seconds() * 1000)
    options = " ".join(
        (
            f"-c statement_timeout={statement_ms}",
            f"-c lock_timeout={min(statement_ms, 10_000)}",
            "-c idle_in_transaction_session_timeout=60000",
            "-c TimeZone=UTC",
            f"-c search_path={_SEARCH_PATH}",
        )
    )
    engine = create_async_engine(
        url,
        pool_size=settings.pool_size,
        max_overflow=settings.max_overflow,
        pool_pre_ping=True,
        pool_recycle=1800,
        hide_parameters=True,
        execution_options={"schema_translate_map": {None: ARGUS_SCHEMA}},
        connect_args={
            "connect_timeout": int(settings.connect_timeout.total_seconds()),
            "application_name": APPLICATION_NAME,
            "options": options,
        },
    )
    event.listen(engine.sync_engine, "reset", _reset_session_state)
    return engine


def _reset_session_state(
    dbapi_connection: DBAPIConnection, _record: ConnectionPoolEntry, state: PoolResetState
) -> None:
    """Undo session-level changes before a pooled connection is reused.

    The pool's own reset is a ROLLBACK, which keeps anything a committed ``SET`` changed
    (timeouts, TimeZone, search_path, session_replication_role, the role) and every temporary
    table for the connection's whole life. ``RESET ALL`` restores the startup options above but
    leaves the role and the session authorization alone, so a ``SET ROLE`` or ``SET SESSION
    AUTHORIZATION`` in one unit of work would carry its privileges into the next; resetting both
    returns to the user the connection logged in as. ``DISCARD TEMP`` drops temporary objects.
    All four are transactional, so they run after the rollback and are committed.
    """
    if state.terminate_only or not state.asyncio_safe:
        return  # the connection is being discarded, or no event loop is available to talk to it
    dbapi_connection.rollback()
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute(_RESET_SESSION)
    finally:
        cursor.close()
    dbapi_connection.commit()


def session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


class _RedactStatements(logging.Filter):
    """SQLAlchemy logs each statement at INFO whenever its logger is enabled for that level, also
    where ARGUS's logging (which redacts, and keeps SQLAlchemy at WARNING) is not configured: a
    test run with --log-cli-level=DEBUG, say. Role DDL holds a password verifier, so statements
    are redacted where they are logged, whatever handler receives them."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_text(record.getMessage())
        record.args = None
        return True


# Engine is SQLAlchemy's statement logger (one per engine class unless logging_name is set).
logging.getLogger("sqlalchemy.engine.Engine").addFilter(_RedactStatements())
