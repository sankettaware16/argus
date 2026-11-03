"""Migration 0049 (AR2c, D-170): the ledger of outside requests accepts the purpose ``families``;
going back to 0048 counts those requests as prefetch requests and refuses the new purpose; going
forward again restores it. No grants change (no table is added)."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.db import migrate
from argus.outside import store
from tests.integration.cases.conftest import rows

pytestmark = pytest.mark.integration

INSERT = (
    "INSERT INTO outside_requests (at, source, kind, purpose, outcome)"
    " VALUES (now(), 'virustotal', 'domain', :p, 'ok')"
)


async def purposes(engine: AsyncEngine) -> list[str]:
    return [
        r.purpose for r in await rows(engine, "SELECT purpose FROM outside_requests ORDER BY id")
    ]


async def test_the_ledger_takes_the_families_purpose_and_no_other_new_one(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    assert "families" in store.PURPOSES
    for purpose in store.PURPOSES:
        async with app_engine.begin() as conn:  # as the runtime login
            await conn.execute(text(INSERT), {"p": purpose})
    assert await purposes(app_engine) == list(store.PURPOSES)
    with pytest.raises(IntegrityError):
        async with app_engine.begin() as conn:
            await conn.execute(text(INSERT), {"p": "browsing"})


async def test_going_back_counts_family_requests_as_prefetch_and_forward_restores_the_purpose(
    migrated_engine: AsyncEngine,
) -> None:
    async with migrated_engine.begin() as conn:
        for purpose in ("agent", "families", "prefetch", "families"):
            await conn.execute(text(INSERT), {"p": purpose})
    await migrate.downgrade(migrated_engine, "0048")
    assert await migrate.current_revision(migrated_engine) == "0048"
    assert await purposes(migrated_engine) == ["agent", "prefetch", "prefetch", "prefetch"]
    with pytest.raises(IntegrityError):
        async with migrated_engine.begin() as conn:
            await conn.execute(text(INSERT), {"p": "families"})
    await migrate.upgrade(migrated_engine)
    assert await migrate.current_revision(migrated_engine) == migrate.head_revision()
    async with migrated_engine.begin() as conn:
        await conn.execute(text(INSERT), {"p": "families"})
    assert await migrate.schema_drift(migrated_engine) == []
