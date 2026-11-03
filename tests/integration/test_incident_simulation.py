"""The incident simulation (plan §10, R16): a scripted timeline like 2026-10-09's.

Alerts flow; the SIEM stops answering for 3 hours while the rule keeps alerting; at recovery a
burst arrives with old timestamps, one execution at its alert limit and one manual run.
Afterwards: every alert stored exactly once, the outage a closed gap, the truncated run a
gap of its rule, every investigation with a dossier, and the investigation pages say alerts
may be missing for that time. Local only (a fake the SIEM): < 5 minutes."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.collector.runner import Runner
from argus.context.packs import default_registry
from argus.context.worker import Worker
from argus.gateway.errors import TransportFailedError
from argus.reference import store as reference
from argus.web import queries
from tests.integration.collector.fake_es import FakeAlertsES
from tests.integration.collector.test_collector import MIN, aid, build, stored

pytestmark = pytest.mark.integration


@pytest.fixture
async def saver(db_settings: Any, test_database: str, app_engine: AsyncEngine) -> Any:
    from argus.context.checkpoints import open_saver

    async with open_saver(db_settings, database=test_database) as checkpointer:
        yield checkpointer


def shape(es: FakeAlertsES, alert_id: str, execution: str, *, manual: bool = False) -> None:
    source = es.docs[alert_id].source
    source.update(
        {
            "kibana.alert.rule.execution.uuid": execution,
            "kibana.alert.rule.execution.timestamp": source["@timestamp"],
            "kibana.alert.rule.max_signals": 5,
            "kibana.alert.rule.revision": 1,
            "kibana.alert.rule.execution.type": "manual" if manual else "scheduled",
        }
    )


async def test_the_2026_10_09_incident(app_engine: AsyncEngine, saver: AsyncPostgresSaver) -> None:
    es = FakeAlertsES()
    collector, clock = build(es, app_engine)

    async def probe() -> None:
        return None

    runner = Runner(collector, probe, backfill_done=True)
    for n in range(3):  # normal flow (below the limit of 5)
        es.add(aid(n), clock.now - timedelta(seconds=30 + n))
        shape(es, aid(n), "normal")
    await runner.step()

    def down(request: Any) -> None:
        raise TransportFailedError("reset", retriable=False)

    outage_start = clock.now
    es.before = down
    for _ in range(180):  # 3 h: the SIEM does not answer; the rule goes on alerting
        clock.advance(MIN)
        await runner.step()
    burst = []
    for n in range(40):  # recovery: a burst written with old timestamps
        alert_id = aid(100 + n)
        es.add(alert_id, outage_start + timedelta(minutes=2 * n + 1))
        shape(es, alert_id, "full" if n < 5 else f"run-{n}", manual=(n == 39))
        burst.append(alert_id)
    es.before = None
    clock.advance(MIN)
    await runner.step()  # the poll catches up and closes the gap
    clock.advance(MIN)
    await runner.step()  # the reconciliation the recovery scheduled

    stored_now = await stored(app_engine)
    assert set(stored_now) == es.ids()  # every alert, the late ones too
    async with app_engine.connect() as conn:
        dupes = (
            await conn.execute(
                text("SELECT alert_id, count(*) FROM alert_records GROUP BY 1 HAVING count(*) > 1")
            )
        ).all()
        gaps = (
            await conn.execute(
                text("SELECT kind, start_at, end_at FROM coverage_gaps ORDER BY start_at")
            )
        ).all()
    assert dupes == []
    lag = [g for g in gaps if g.kind == "argus_collector_lag"]
    assert len(lag) == 1
    assert lag[0].end_at is not None

    async with app_engine.begin() as conn:
        await reference.refresh_rules(conn, clock.now, hold=timedelta(0))
    async with app_engine.connect() as conn:
        truncated = (
            (
                await conn.execute(
                    text("SELECT subject FROM coverage_gaps WHERE kind = 'truncated_execution'")
                )
            )
            .scalars()
            .all()
        )
    assert truncated == ["rule:rule-a:execution:full"]

    worker = Worker(app_engine, saver, packs=default_registry(), clock=lambda: clock.now)
    while await worker.run_once(limit=20):
        pass
    async with app_engine.connect() as conn:
        missing = (
            await conn.execute(
                text(
                    "SELECT count(*) FROM investigations i WHERE NOT EXISTS (SELECT 1"
                    " FROM dossiers d WHERE d.investigation_id = i.id AND d.version = i.version)"
                )
            )
        ).scalar_one()
        summary = await queries.investigation(
            conn,
            (
                await conn.execute(
                    text("SELECT investigation_id FROM investigation_alerts WHERE alert_id = :a"),
                    {"a": burst[0]},
                )
            ).scalar_one(),
        )
        assert summary is not None
        shown = await queries.coverage(conn, summary)
    assert missing == 0  # every investigation has a dossier
    kinds = {g["kind"] for g in shown}
    assert {"argus_collector_lag", "truncated_execution"} <= kinds  # the page warns of both
