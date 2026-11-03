"""Migrations must carry existing data forward unchanged, step by step (R1 gate).

Each step from base to head runs with real rows in the database: rows written before the step
must read back identically afterwards, and every step must survive downgrade → upgrade.
"""

from __future__ import annotations

from typing import Any

from alembic.script import ScriptDirectory
from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.db import migrate


def _revisions_base_to_head() -> list[str]:
    script = ScriptDirectory.from_config(migrate.alembic_config())
    return [rev.revision for rev in reversed(list(script.walk_revisions("base", "heads")))]


async def _has_table(engine: AsyncEngine, table: str) -> bool:
    async with engine.connect() as conn:
        return bool(await conn.run_sync(lambda c: inspect(c).has_table(table)))


async def _audit_rows(engine: AsyncEngine) -> list[tuple[Any, ...]]:
    async with engine.connect() as conn:
        result = await conn.execute(
            text(
                "SELECT id, occurred_at, actor, action, outcome, target_type, target_id, "
                "correlation_id, details FROM audit_events ORDER BY id"
            )
        )
        return [tuple(row) for row in result]


async def _seed(engine: AsyncEngine, tag: str) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO audit_events "
                "(actor, action, outcome, target_type, target_id, details) "
                "VALUES (:actor, :action, 'success', 'test', :tid, CAST(:details AS jsonb))"
            ),
            {
                "actor": "migration-test",
                "action": f"seed.{tag}",
                "tid": f"row-{tag}",
                "details": '{"note": "ünïcode ✓", "n": 1, "nested": {"list": [1, 2, 3]}}',
            },
        )


def test_revision_chain_is_linear() -> None:
    revisions = _revisions_base_to_head()
    assert revisions[0] == "0001"
    assert revisions[-1] == migrate.head_revision()
    assert len(revisions) == len(set(revisions))


async def test_every_step_carries_data_forward(empty_engine: AsyncEngine) -> None:
    revisions = _revisions_base_to_head()
    previous: str | None = None
    for revision in revisions:
        before = (
            await _audit_rows(empty_engine)
            if await _has_table(empty_engine, "audit_events")
            else []
        )

        await migrate.upgrade(empty_engine, revision)
        assert await migrate.current_revision(empty_engine) == revision
        after = before
        if await _has_table(empty_engine, "audit_events"):
            after = await _audit_rows(empty_engine)
            assert after[: len(before)] == before, f"step to {revision} changed existing rows"

        # A step must be reversible and re-appliable with data present.
        if previous is not None:
            await migrate.downgrade(empty_engine, previous)
            assert await migrate.current_revision(empty_engine) == previous
            await migrate.upgrade(empty_engine, revision)
            assert await migrate.current_revision(empty_engine) == revision
            assert await _audit_rows(empty_engine) == after, f"down/up of {revision} lost data"

        if await _has_table(empty_engine, "audit_events"):
            await _seed(empty_engine, revision)
        previous = revision

    assert await migrate.current_revision(empty_engine) == migrate.head_revision()
    rows = await _audit_rows(empty_engine)
    assert [row[3] for row in rows] == [f"seed.{rev}" for rev in revisions]
    assert await migrate.missing_guard_triggers(empty_engine) == []
