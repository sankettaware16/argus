"""Fixtures for the context graph (R8): a checkpoint saver on the throwaway database, and
investigations made by the real collector store and grouper."""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import DatabaseSettings
from argus.context.checkpoints import open_saver
from tests.integration.grouping.test_grouping import doc, ingest

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)


@pytest.fixture
async def saver(
    db_settings: DatabaseSettings, test_database: str, app_engine: AsyncEngine
) -> AsyncIterator[AsyncPostgresSaver]:
    async with open_saver(db_settings, database=test_database) as checkpointer:
        yield checkpointer


async def seed(engine: AsyncEngine, specs: Sequence[tuple[int, str, str]]) -> list[Any]:
    """Alerts (n, rule, source ip) one hour before NOW; returns the investigation ids."""
    await ingest(engine, [doc(n, rule, ip, NOW - timedelta(hours=1)) for n, rule, ip in specs])
    async with engine.connect() as conn:
        rows = await conn.execute(text("SELECT id FROM investigations ORDER BY id"))
        return list(rows.scalars())
