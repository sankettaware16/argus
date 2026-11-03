"""0058: the request ledger accepts the case team's class WC; a downgrade that would leave a WC row
invalid is refused, and a clean one round-trips."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.db import migrate

pytestmark = pytest.mark.integration

ROW = (
    "INSERT INTO siem_requests (at, component, purpose, template, version, indices, outcome,"
    " took_ms, elapsed_ms, response_bytes, attempts, write_class)"
    " VALUES (now(), 'caseteam', 'kibana_write', 't', 1, '{}', 'ok', 0, 0, 0, 1, :w)"
)


async def test_a_wc_row_is_accepted_and_a_downgrade_would_not_lose_it(
    migrated_engine: AsyncEngine,
) -> None:
    await migrate.downgrade(migrated_engine, "0057")  # clean: no WC row yet
    await migrate.upgrade(migrated_engine)
    async with migrated_engine.begin() as conn:
        await conn.execute(text(ROW), {"w": "WC"})
    await migrate.downgrade(migrated_engine, "0058")  # 0059 (titles) has nothing to keep here
    with pytest.raises(Exception, match="refused"):
        await migrate.downgrade(migrated_engine, "0057")
    assert await migrate.current_revision(migrated_engine) == "0058"


async def test_an_unknown_class_is_still_refused(migrated_engine: AsyncEngine) -> None:
    with pytest.raises(Exception, match="write_class_valid"):
        async with migrated_engine.begin() as conn:
            await conn.execute(text(ROW), {"w": "WX"})
