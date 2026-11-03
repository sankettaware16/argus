"""0064 (D-291): a database made before the rename (the gateway's five tables under another
prefix) ends with exactly the schema, data and grants of a fresh one; a fresh one is left alone."""

from __future__ import annotations

import importlib
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.db import migrate

pytestmark = pytest.mark.integration

RENAME: str = importlib.import_module("argus.db.migrations.versions.0064_siem_names").RENAME

SCHEMA = """
    SELECT 'rel' AS k, c.relkind::text AS t, c.relname::text AS name, '' AS extra
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'i', 'S')
    UNION ALL
    SELECT 'con', k.contype::text, k.conname::text, pg_get_constraintdef(k.oid)
    FROM pg_constraint k JOIN pg_namespace n ON n.oid = k.connamespace
    WHERE n.nspname = current_schema()
    UNION ALL
    SELECT 'trg', t.relname::text, g.tgname::text, pg_get_triggerdef(g.oid)
    FROM pg_trigger g JOIN pg_class t ON t.oid = g.tgrelid
    WHERE NOT g.tgisinternal
    UNION ALL
    SELECT 'def', c.table_name::text, c.column_name::text, coalesce(c.column_default, '')
    FROM information_schema.columns c WHERE c.table_schema = current_schema()
    UNION ALL
    SELECT 'grant', g.table_name::text, g.grantee::text, g.privilege_type::text
    FROM information_schema.role_table_grants g WHERE g.table_schema = current_schema()
    ORDER BY 1, 2, 3, 4
"""

# the reverse of 0064 for the test only: every object named siem_ gets another prefix
BACK = """
DO $$
DECLARE r record;
BEGIN
    FOR r IN SELECT k.conname, t.relname FROM pg_constraint k
        JOIN pg_class t ON t.oid = k.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = current_schema() AND k.conname LIKE '%siem\\_%'
    LOOP
        EXECUTE format('ALTER TABLE %I RENAME CONSTRAINT %I TO %I',
                       r.relname, r.conname, replace(r.conname, 'siem_', ':p_'));
    END LOOP;
    FOR r IN SELECT g.tgname, t.relname FROM pg_trigger g JOIN pg_class t ON t.oid = g.tgrelid
        WHERE NOT g.tgisinternal AND g.tgname LIKE '%siem\\_%'
    LOOP
        EXECUTE format('ALTER TRIGGER %I ON %I RENAME TO %I',
                       r.tgname, r.relname, replace(r.tgname, 'siem_', ':p_'));
    END LOOP;
    FOR r IN SELECT c.relname, c.relkind FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = current_schema() AND c.relkind IN ('i', 'S', 'r')
          AND c.relname LIKE '%siem\\_%'
        ORDER BY c.relkind DESC
    LOOP
        EXECUTE format('ALTER %s %I RENAME TO %I',
                       CASE r.relkind WHEN 'i' THEN 'INDEX' WHEN 'S' THEN 'SEQUENCE'
                       ELSE 'TABLE' END,
                       r.relname, replace(r.relname, 'siem_', ':p_'));
    END LOOP;
END
$$;
"""


async def _schema(conn: AsyncConnection) -> list[tuple[Any, ...]]:
    return [tuple(r) for r in (await conn.execute(text(SCHEMA))).all()]


async def _back(conn: AsyncConnection, prefix: str) -> None:
    await conn.execute(text(BACK.replace(":p_", f"{prefix}_")))


@pytest.mark.parametrize("prefix", ["legacy", "acme_soc"])
async def test_an_old_database_ends_like_a_fresh_one(
    migrated_engine: AsyncEngine, prefix: str
) -> None:
    async with migrated_engine.begin() as conn:
        fresh = await _schema(conn)
        assert any(r[2] == "siem_requests" for r in fresh)
        await _back(conn, prefix)
        old = await _schema(conn)
        assert not any("siem_" in str(r[2]) for r in old if r[0] in ("rel", "con", "trg"))
        assert any(r[2] == f"{prefix}_requests" for r in old)
        count = f"SELECT count(*) FROM {prefix}_switches"  # noqa: S608 - the test's own prefix
        n = (await conn.execute(text(count))).scalar_one()
        await conn.execute(text(RENAME))
        assert await _schema(conn) == fresh
        assert (await conn.execute(text("SELECT count(*) FROM siem_switches"))).scalar_one() == n


async def test_a_fresh_database_is_left_alone(migrated_engine: AsyncEngine) -> None:
    async with migrated_engine.begin() as conn:
        fresh = await _schema(conn)
        await conn.execute(text(RENAME))
        assert await _schema(conn) == fresh


async def test_a_lone_switches_table_is_not_a_prefix(migrated_engine: AsyncEngine) -> None:
    """Only a prefix under which the ledger and the live sessions exist too is renamed."""
    async with migrated_engine.begin() as conn:
        await conn.execute(text("CREATE TABLE other_switches (x int)"))
        fresh = await _schema(conn)
        await conn.execute(text(RENAME))
        assert await _schema(conn) == fresh


@pytest.mark.parametrize("revision", ["0020", "0049"])
async def test_an_old_database_upgrades_from_an_old_revision(
    migrated_engine: AsyncEngine, revision: str
) -> None:
    """A dump restored from before D-291 (or the replay's copy, at 0049) passes the migrations that
    name a siem_ table (0021-0058): each renames the old tables first (argus.db.siem_names)."""
    async with migrated_engine.begin() as conn:
        fresh = await _schema(conn)
    await migrate.downgrade(migrated_engine, revision)
    async with migrated_engine.begin() as conn:
        await _back(conn, "legacy")
        assert (await conn.execute(text("SELECT to_regclass('legacy_requests')"))).scalar_one()
    await migrate.upgrade(migrated_engine)
    async with migrated_engine.begin() as conn:
        assert await _schema(conn) == fresh
