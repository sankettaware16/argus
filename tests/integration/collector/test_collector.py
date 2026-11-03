"""The collector against a scripted the SIEM and a real Postgres (as the runtime role), through the
real gateway: live poll, overlap, equal timestamps, reconciliation, backfill, states, gaps."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.collector import collector as co
from argus.collector import store
from argus.collector.collector import Collector
from argus.gateway.errors import TransportFailedError
from argus.gateway.gateway import Gateway
from argus.gateway.health import HealthConfig, HealthMemory
from argus.gateway.state import MemoryStore
from tests.integration.collector.fake_es import FakeAlertsES
from tests.unit.gateway.fakes import FakeClock

pytestmark = pytest.mark.integration

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
MIN = timedelta(minutes=1)
HOUR = timedelta(hours=1)
FOREVER = timedelta(days=3650)


def aid(n: int) -> str:
    return f"{n:040x}"


def build(es: FakeAlertsES, engine: AsyncEngine, **kw: Any) -> tuple[Collector, FakeClock]:
    clock = FakeClock(now=NOW)
    gateway = Gateway(
        es,
        MemoryStore(memory=HealthMemory(probed_at=NOW)),
        clock=clock,
        sleep=clock.sleep,
        health_config=HealthConfig(stale_degraded=FOREVER, stale_stop=FOREVER),
    )
    return Collector(gateway, engine, window=timedelta(days=5), clock=clock, **kw), clock


async def stored(engine: AsyncEngine) -> dict[str, dict[str, Any]]:
    async with engine.connect() as conn:
        rows = await conn.execute(
            text(
                "SELECT alert_id, status, recovered_by, workflow_status, source_missing_at,"
                " rule_id FROM alert_records"
            )
        )
        return {row.alert_id: dict(row._mapping) for row in rows}


async def cursor(engine: AsyncEngine, name: str = "live") -> datetime | None:
    async with engine.connect() as conn:
        return await store.cursor(conn, name)


# --------------------------------------------------------------------------- live poll


async def test_a_poll_stores_new_alerts_once(app_engine: AsyncEngine) -> None:
    es = FakeAlertsES()
    for n in range(5):
        es.add(aid(n), NOW - MIN * (n + 1))
    collector, clock = build(es, app_engine)
    result = await collector.poll()
    assert (result.new, result.cursor) == (5, NOW)
    rows = await stored(app_engine)
    assert set(rows) == es.ids()
    assert {r["status"] for r in rows.values()} == {"normalized"}
    assert {r["recovered_by"] for r in rows.values()} == {"live"}
    mgets = [c for c in es.calls if c.path.endswith("/_mget")]
    clock.advance(MIN)
    again = await collector.poll()
    assert again.new == 0
    assert [c for c in es.calls if c.path.endswith("/_mget")] == mgets  # nothing fetched twice


async def test_the_first_poll_reads_only_the_overlap(app_engine: AsyncEngine) -> None:
    es = FakeAlertsES()
    es.add(aid(1), NOW - 4 * MIN)
    es.add(aid(2), NOW - 6 * MIN)  # older: the backfill's job
    collector, _ = build(es, app_engine)
    await collector.poll()
    assert set(await stored(app_engine)) == {aid(1)}


async def test_late_writes_within_the_overlap_are_caught(app_engine: AsyncEngine) -> None:
    es = FakeAlertsES()
    collector, clock = build(es, app_engine)
    await collector.poll()
    es.add(aid(1), NOW - 3 * MIN)  # became visible after the poll that covered its time
    clock.advance(MIN)
    await collector.poll()
    assert aid(1) in await stored(app_engine)


async def test_equal_timestamps_across_pages(
    app_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(co, "PAGE", 3)
    es = FakeAlertsES()
    for n in range(10):
        es.add(aid(n), NOW - 2 * MIN)
    collector, _ = build(es, app_engine)
    result = await collector.poll()
    assert (result.pages, result.new) == (4, 10)
    assert set(await stored(app_engine)) == es.ids()


async def test_a_failed_poll_leaves_the_cursor(app_engine: AsyncEngine) -> None:
    es = FakeAlertsES()
    collector, clock = build(es, app_engine)
    await collector.poll()
    es.add(aid(1), NOW + 30 * 60 * timedelta(seconds=1))

    def down(request: Any) -> None:
        raise TransportFailedError("reset", retriable=False)

    es.before = down
    for _ in range(180):  # three hours, one poll a minute
        clock.advance(MIN)
        with pytest.raises(TransportFailedError):
            await collector.poll()
    assert await cursor(app_engine) == NOW
    es.before = None
    clock.advance(MIN)
    await collector.poll()
    assert aid(1) in await stored(app_engine)


# --------------------------------------------------------------------------- hours


async def test_reconciliation_recovers_and_marks_missing(app_engine: AsyncEngine) -> None:
    es = FakeAlertsES()
    base = NOW - 5 * HOUR
    for n in range(6):
        es.add(aid(n), base + n * 10 * MIN, rule="rule-a" if n % 2 else "rule-b")
    collector, _ = build(es, app_engine)
    first = await collector.reconcile(base, NOW)
    assert (first.recovered, first.missing_in_es, len(first.mismatched)) == (6, 0, 1)
    assert {r["recovered_by"] for r in (await stored(app_engine)).values()} == {"reconciliation"}
    del es.docs[aid(0)]  # rule-b
    es.add(aid(9), base + 30 * MIN, rule="rule-a")  # same hour and total, another rule
    second = await collector.reconcile(base, NOW)
    assert (second.recovered, second.missing_in_es) == (1, 1)
    rows = await stored(app_engine)
    assert rows[aid(0)]["source_missing_at"] is not None  # kept, never deleted
    third = await collector.reconcile(base, NOW)
    assert third.mismatched == ()
    async with app_engine.connect() as conn:
        runs = (await conn.execute(text("SELECT hours, recovered, outcome FROM reconciliation_runs"
                                         " ORDER BY id"))).all()  # fmt: skip
    assert runs == [(5, 6, "ok"), (5, 1, "ok"), (5, 0, "ok")]


async def test_a_rule_swap_with_equal_totals_is_found(app_engine: AsyncEngine) -> None:
    es = FakeAlertsES()
    hour = NOW - 3 * HOUR
    es.add(aid(1), hour + MIN, rule="rule-a")
    collector, _ = build(es, app_engine)
    await collector.reconcile(hour, NOW)
    del es.docs[aid(1)]
    es.add(aid(2), hour + MIN, rule="rule-b")  # same count, other rule
    result = await collector.reconcile(hour, NOW)
    assert (result.recovered, result.missing_in_es) == (1, 1)


async def test_backfill_runs_newest_first_and_resumes(app_engine: AsyncEngine) -> None:
    es = FakeAlertsES()
    for n in range(40):
        es.add(aid(n), NOW - n * 3 * HOUR - MIN)
    collector, _ = build(es, app_engine)
    first = await collector.backfill_step()
    assert first is not None
    assert await cursor(app_engine, "backfill") == NOW - 5 * HOUR  # 6 hours down from 13:00
    assert set(await stored(app_engine)) == {aid(0), aid(1)}
    steps = 1
    while await collector.backfill_step() is not None:
        steps += 1
    assert steps == 21  # 5 days + the current hour, 6 hours at a time
    window_start = NOW - timedelta(days=5)
    expected = {i for i, d in es.docs.items() if d.at >= window_start}
    assert set(await stored(app_engine)) == expected
    assert await collector.backfill_step() is None


async def test_states_follow_triage(app_engine: AsyncEngine) -> None:
    es = FakeAlertsES()
    es.add(aid(1), NOW - HOUR)
    es.add(aid(2), NOW - HOUR, status="closed")
    collector, _ = build(es, app_engine)
    await collector.reconcile(NOW - 2 * HOUR, NOW)
    es.docs[aid(1)].source["kibana.alert.workflow_status"] = "acknowledged"
    es.docs[aid(2)].source["kibana.alert.workflow_status"] = "open"
    assert await collector.sync_states() == 2
    rows = await stored(app_engine)
    assert (rows[aid(1)]["workflow_status"], rows[aid(2)]["workflow_status"]) == (
        "acknowledged", "open",
    )  # fmt: skip
    assert await collector.sync_states() == 0


async def test_a_quarantined_alert_is_stored_with_its_reason(app_engine: AsyncEngine) -> None:
    es = FakeAlertsES()
    es.add(aid(1), NOW - MIN)
    es.docs[aid(1)].source["kibana.alert.rule"] = {"rule_id": "rule-z"}  # conflicts
    collector, _ = build(es, app_engine)
    await collector.poll()
    row = (await stored(app_engine))[aid(1)]
    assert (row["status"], row["rule_id"]) == ("quarantined", "rule-a")
