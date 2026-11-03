"""Engine construction and the pool's reset, without a database (nothing here connects)."""

from __future__ import annotations

from typing import Any, cast

import pytest
from pydantic import SecretStr
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.pool import ConnectionPoolEntry, PoolResetState

from argus.config import ConfigError, DatabaseSettings
from argus.config.settings import DatabaseRole
from argus.db import engine as engine_module
from argus.db.engine import create_engine

SETTINGS = DatabaseSettings(
    password=SecretStr("fake-secret-engine-unit"), owner_password=SecretStr("fake-secret-owner")
)


class _Recorder:
    """A DBAPI connection (and its cursors) that records what it is asked to do."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def rollback(self) -> None:
        self.calls.append(("rollback",))

    def commit(self) -> None:
        self.calls.append(("commit",))

    def cursor(self) -> _Recorder:
        return self

    def execute(self, statement: str) -> None:
        self.calls.append(("execute", statement))

    def close(self) -> None:
        self.calls.append(("close",))


def _reset(state: PoolResetState) -> list[tuple[str, ...]]:
    recorder = _Recorder()
    engine_module._reset_session_state(
        cast(DBAPIConnection, recorder), cast(ConnectionPoolEntry, None), state
    )
    return recorder.calls


def test_the_pool_reset_is_one_query_between_the_rollback_and_the_commit() -> None:
    """One execute() for the four statements, the login user first (so RESET ALL runs as it).
    RESET ROLE stays, belt and braces, although PostgreSQL 17's RESET SESSION AUTHORIZATION resets
    the role too; DISCARD TEMP drops temporary objects (round 3: a temporary audit_events table
    outlived the unit of work and captured later audit writes)."""
    calls = _reset(
        PoolResetState(transaction_was_reset=False, terminate_only=False, asyncio_safe=True)
    )
    assert [call[0] for call in calls] == ["rollback", "execute", "close", "commit"]
    statements = [part.strip() for part in calls[1][1].split(";")]
    assert statements == ["RESET SESSION AUTHORIZATION", "RESET ROLE", "RESET ALL", "DISCARD TEMP"]


def test_every_connection_searches_public_before_pg_temp(monkeypatch: pytest.MonkeyPatch) -> None:
    """pg_temp is searched first unless the search_path names it, so it is named last: a
    temporary table never shadows an ARGUS table, not even in the unit of work that made it."""
    seen: dict[str, Any] = {}
    real = engine_module.create_async_engine

    def spy(url: Any, **kwargs: Any) -> Any:
        seen.update(kwargs["connect_args"])
        return real(url, **kwargs)

    monkeypatch.setattr(engine_module, "create_async_engine", spy)
    logins: tuple[DatabaseRole, ...] = ("app", "owner")
    for role in logins:
        engine = create_engine(SETTINGS, database="argus_unit_never_connected", role=role)
        engine.sync_engine.dispose()  # never connected
        assert "search_path=public,pg_temp" in seen["options"].split()


@pytest.mark.parametrize(
    "state",
    [
        PoolResetState(transaction_was_reset=False, terminate_only=True, asyncio_safe=True),
        PoolResetState(transaction_was_reset=False, terminate_only=False, asyncio_safe=False),
    ],
    ids=["connection-being-discarded", "no-event-loop"],
)
def test_nothing_is_sent_when_the_connection_cannot_be_reused_or_reached(
    state: PoolResetState,
) -> None:
    assert _reset(state) == []


def test_a_database_name_that_is_not_utf8_is_a_config_error() -> None:
    """A lone surrogate (an undecodable byte in an environment variable, say) is reported by the
    settings' own name check, never as a raw UnicodeEncodeError; nothing connects."""
    with pytest.raises(ConfigError, match="database name must be valid UTF-8 text"):
        create_engine(SETTINGS, database="argus\udcff")
    with pytest.raises(ConfigError, match="database name must be valid UTF-8 text"):
        create_engine(SETTINGS, database="argus\udcff", role="owner")
