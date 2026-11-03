"""After the retention purge (Q-A4, review A4-R1 and R11): the worker never derives a dossier from
emptied raw alerts or snapshots, and a key whose answer was purged is never asked of the SIEM
again."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import Settings
from argus.context import graph
from argus.context.cli import queue_rederive
from argus.context.packs import default_registry
from argus.context.worker import Worker
from argus.ops import purge
from argus.reference import store as reference
from tests.integration.context.conftest import NOW, seed
from tests.integration.context.kit import FakeGateway
from tests.integration.context.test_graph_exact import ctx, task
from tests.integration.grouping.test_grouping import doc, ingest

pytestmark = pytest.mark.integration


def alert(n: int) -> dict[str, Any]:
    d = doc(n, "r1", "10.0.0.1", NOW - timedelta(minutes=50 - n))
    d["_source"].update({
        "kibana.alert.rule.note": "### Investigation Steps\n1. Check `destination.ip`.\n",
        "kibana.alert.rule.revision": 1,
        "kibana.alert.rule.name": "Rule r1",
        "destination": {"ip": f"8.8.8.{n % 2}"},
    })  # fmt: skip
    return d


async def drain(engine: AsyncEngine, saver: AsyncPostgresSaver) -> list[Any]:
    async with engine.begin() as conn:
        await reference.refresh_rules(conn, NOW, hold=timedelta(0))
    worker = Worker(engine, saver, packs=default_registry(), clock=lambda: NOW)
    results: list[Any] = []
    while batch := await worker.run_once(limit=10):
        results += batch
    return results


async def dossiers(engine: AsyncEngine) -> list[tuple[int, str]]:
    async with engine.connect() as conn:
        found = await conn.execute(text("SELECT version, pack FROM dossiers ORDER BY created_at"))
        return [(v, p) for v, p in found.all()]


async def test_a_job_queued_before_the_raw_purge_keeps_the_stored_dossier(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver, migrated_engine: AsyncEngine
) -> None:
    """A re-derivation queued after a pack change waits while the nightly purge empties the raw
    alerts: the worker must not write a dossier saying 'no alert has destination.ip' when all
    three had it. It finishes the job as skipped and keeps what is stored."""
    await ingest(app_engine, [alert(n) for n in range(3)])
    await drain(app_engine, saver)
    async with migrated_engine.begin() as conn:  # as if an older pack had written it
        await conn.execute(text("DELETE FROM signals"))
        await conn.execute(text("UPDATE dossiers SET pack = 'stub@1'"))
    before = await dossiers(app_engine)
    assert await queue_rederive(app_engine, "generic@12") == 1  # raw intact: queued
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE jobs SET run_after = :t WHERE status = 'queued'"), {"t": NOW}
        )
    cut = purge.cutoffs(Settings(), NOW + timedelta(days=31))  # the purge, 31 days on
    outcome = await purge.run(migrated_engine, cut)
    assert outcome.done.changed["raw_source"]["alert_records.raw"] == 3
    results = await drain(app_engine, saver)
    assert [r.outcome for r in results] == ["skipped"]
    assert str(results[0].detail).startswith("skipped: the retention purge removed")
    assert await dossiers(app_engine) == before  # nothing new derived from {}
    async with app_engine.connect() as conn:
        status, error = (
            await conn.execute(text("SELECT status, error FROM jobs WHERE trigger = 'rederive'"))
        ).one()
    assert (status, error) == ("done", results[0].detail)


async def test_a_purged_answer_is_not_asked_of_the_siem_again(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """Version 1's snapshot was purged; a later version must not send the same task to the SIEM
    for logs long expired (its 'empty' would read as a negative): recorded as not checked."""
    (inv,) = await seed(app_engine, [(1, "r1", "10.0.0.1")])
    gateway = FakeGateway()
    c = ctx(app_engine, inv, gateway=gateway)
    await graph.evidence_step(c, inv, 1, task(inv, 1, "collect"))
    assert gateway.calls == [1]
    async with migrated_engine.begin() as conn:
        await conn.execute(text("SET LOCAL ROLE argus_purge"))
        await conn.execute(text("UPDATE evidence SET snapshot = NULL, snapshot_purged_at = now()"))
        await conn.execute(text("RESET ROLE"))
        await conn.execute(text("UPDATE investigations SET version = 2"))
    again = await graph.evidence_step(c, inv, 2, task(inv, 1, "collect"))
    assert gateway.calls == [1], "version 2 re-sent the task to the SIEM"
    assert again["status"] == "skipped_budget"
    async with app_engine.connect() as conn:
        coverage = (
            await conn.execute(text("SELECT coverage FROM evidence WHERE version = 2"))
        ).scalar_one()
    assert coverage == {"reason": "purged"}
