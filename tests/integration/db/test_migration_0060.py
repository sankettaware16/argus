"""0060 (D-234): every CHECK reads back the same once reparsed, as a restore reparses it; 0056's
nested BETWEEN did not, and the backup drill failed every restore on it."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.db import migrate

pytestmark = pytest.mark.integration

CHECKS = """
    SELECT c.relname AS tbl, k.conname AS name, pg_get_constraintdef(k.oid) AS def
    FROM pg_constraint k JOIN pg_class c ON c.oid = k.conrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND k.contype = 'c' ORDER BY 1, 2
"""


async def _unstable(engine: AsyncEngine) -> list[str]:
    out: list[str] = []
    async with engine.begin() as conn:
        for tbl, name, definition in (await conn.execute(text(CHECKS))).all():
            trans = await conn.begin_nested()
            await conn.execute(text(f'CREATE TEMP TABLE reparse (LIKE public."{tbl}")'))
            await conn.execute(text(f"ALTER TABLE reparse ADD CONSTRAINT again {definition}"))
            again = (
                await conn.execute(
                    text(
                        "SELECT pg_get_constraintdef(oid) FROM pg_constraint"
                        " WHERE conname = 'again' AND conrelid = 'reparse'::regclass"
                    )
                )
            ).scalar_one()
            await trans.rollback()
            if again != definition:
                out.append(f"{tbl}.{name}")
    return out


async def test_every_check_reads_back_the_same_once_reparsed(migrated_engine: AsyncEngine) -> None:
    assert await _unstable(migrated_engine) == []


async def test_0059_had_the_nested_check_and_the_round_trip_holds(
    migrated_engine: AsyncEngine,
) -> None:
    await migrate.downgrade(migrated_engine, "0059")
    assert await _unstable(migrated_engine) == ["signin_sightings.ck_signin_sightings_hours_valid"]
    await migrate.upgrade(migrated_engine)
    assert await _unstable(migrated_engine) == []
    assert await migrate.current_revision(migrated_engine) == migrate.head_revision()
