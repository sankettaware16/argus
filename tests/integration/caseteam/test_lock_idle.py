"""The run's lock is the session's: its connection never idles inside a transaction while a run
waits on the Kibana lane (the server ended one such run after 60 s on 2026-10-30)."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.caseteam import store
from tests.integration.caseteam.kit import rig

pytestmark = pytest.mark.integration


async def test_the_lock_is_held_outside_any_transaction(
    migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    r = rig(migrated_engine, writer_engine)
    async with r.poster._exclusive() as got:
        assert got
        async with migrated_engine.connect() as conn:
            states = (
                (
                    await conn.execute(
                        text(
                            "SELECT a.state FROM pg_locks l JOIN pg_stat_activity a USING (pid)"
                            " WHERE l.locktype = 'advisory' AND l.objid = :k"
                            # this database's only: production's case team may hold its own
                            " AND l.database = (SELECT oid FROM pg_database"
                            " WHERE datname = current_database())"
                        ),
                        {"k": store.LOCK_KEY & 0xFFFFFFFF},
                    )
                )
                .scalars()
                .all()
            )
    assert states == ["idle"]
