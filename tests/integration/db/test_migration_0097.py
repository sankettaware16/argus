"""0097 (D-322): a one-row table owns no sequence. 0095 gave ``risk_mode``'s pinned id a sequence it
never draws from, and the weekly restore drill failed on it ("behind its column: next 1, highest
1"). The guards: no table whose key a CHECK pins to one value owns a sequence, and with every
one-row table's row written the backup's sequence check finds nothing."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.db import migrate
from argus.ops import backup

pytestmark = pytest.mark.integration

# tables whose one-column key a CHECK pins to a constant (``CHECK (id = 1)``): one-row tables
PINNED = """
    SELECT format('%I.%I', n.nspname, c.relname) AS tbl, a.attname AS col
    FROM pg_constraint pk
    JOIN pg_class c ON c.oid = pk.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = pk.conkey[1]
    WHERE pk.contype = 'p' AND cardinality(pk.conkey) = 1
      AND n.nspname NOT IN ('pg_catalog', 'information_schema')
      AND EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conrelid = c.oid AND k.contype = 'c'
                  AND k.conkey = pk.conkey
                  AND pg_get_constraintdef(k.oid)
                      ~ ('^CHECK \\(\\(?' || a.attname || ' = (\\d+|''[^'']*''(::\\w+)?)\\)?\\)$'))
    ORDER BY 1
"""
OWNED = """
    SELECT format('%I.%I', tn.nspname, t.relname), s.relname
    FROM pg_depend d JOIN pg_class s ON s.oid = d.objid AND s.relkind = 'S'
    JOIN pg_class t ON t.oid = d.refobjid JOIN pg_namespace tn ON tn.oid = t.relnamespace
    WHERE d.classid = 'pg_class'::regclass AND d.refclassid = 'pg_class'::regclass
      AND d.deptype IN ('a', 'i')
"""
# how each one-row table's row is written (the code writes it with its pinned key; a migration
# may have written it already)
ROWS = {
    "public.kibana_sync_state": "INSERT INTO kibana_sync_state (id) VALUES (1)",
    "public.llm_state": "INSERT INTO llm_state (name) VALUES ('gateway')",
    "public.risk_mode": "INSERT INTO risk_mode (id, present, at) VALUES (1, true, now())",
}


async def _pinned(engine: AsyncEngine) -> set[str]:
    async with engine.connect() as conn:
        return {r.tbl for r in await conn.execute(text(PINNED))}


async def _owning(engine: AsyncEngine) -> dict[str, str]:
    async with engine.connect() as conn:
        return {str(t): str(s) for t, s in await conn.execute(text(OWNED))}


async def test_no_one_row_table_owns_a_sequence(migrated_engine: AsyncEngine) -> None:
    pinned = await _pinned(migrated_engine)
    assert pinned == set(ROWS), "a new one-row table: add how its row is written to ROWS"
    owning = await _owning(migrated_engine)
    assert {t: owning[t] for t in pinned if t in owning} == {}


async def test_with_every_one_row_table_written_the_sequence_check_is_clean(
    migrated_engine: AsyncEngine,
) -> None:
    async with migrated_engine.begin() as conn:
        for insert in ROWS.values():
            await conn.execute(text(f"{insert} ON CONFLICT DO NOTHING"))
        assert await backup.sequence_problems(conn) == []


async def test_0096_had_the_sequence_and_the_round_trip_holds(
    migrated_engine: AsyncEngine,
) -> None:
    await migrate.downgrade(migrated_engine, "0096")
    owning = await _owning(migrated_engine)
    pinned = await _pinned(migrated_engine)
    assert {t: owning[t] for t in pinned if t in owning} == {"public.risk_mode": "risk_mode_id_seq"}
    async with migrated_engine.begin() as conn:
        await conn.execute(text(ROWS["public.risk_mode"]))
        assert await backup.sequence_problems(conn) == [
            "sequence public.risk_mode_id_seq: behind its column (next 1, highest 1)"
        ]
    await migrate.upgrade(migrated_engine)
    assert "public.risk_mode" not in await _owning(migrated_engine)
    async with migrated_engine.connect() as conn:
        assert await backup.sequence_problems(conn) == []
        default = await conn.scalar(
            text(
                "SELECT column_default FROM information_schema.columns"
                " WHERE table_name = 'risk_mode' AND column_name = 'id'"
            )
        )
    assert default is None
    assert await migrate.current_revision(migrated_engine) == migrate.head_revision()
