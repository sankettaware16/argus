"""Regression tests for R5 review round 1 (docs/reviews/r5-review-1.md), one per finding."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.collector import store
from argus.collector.runner import Runner
from tests.integration.collector.fake_es import FakeAlertsES
from tests.integration.collector.test_collector import HOUR, MIN, NOW, aid, build, stored

pytestmark = pytest.mark.integration


async def test_1_an_alert_with_a_naive_time_and_a_numeric_rule_is_placed(
    app_engine: AsyncEngine,
) -> None:
    es = FakeAlertsES()
    es.add(aid(1), NOW - 2 * HOUR)
    source = es.docs[aid(1)].source
    source["@timestamp"] = source["@timestamp"].removesuffix("Z")  # no offset: UTC to ES
    source["kibana.alert.rule.rule_id"] = 5
    source["kibana.alert.rule"] = {"rule_id": 6}  # conflicting: quarantined
    collector, _ = build(es, app_engine)
    first = await collector.reconcile(NOW - 3 * HOUR, NOW)
    assert first.recovered == 1
    row = (await stored(app_engine))[aid(1)]
    assert (row["status"], row["rule_id"]) == ("quarantined", "5")
    again = await collector.reconcile(NOW - 3 * HOUR, NOW)
    assert again.mismatched == ()  # counted in its hour: not fetched again and again


async def test_2_the_state_sweep_takes_any_number_of_alerts(app_engine: AsyncEngine) -> None:
    statuses = {aid(n): "closed" for n in range(40_000)}
    async with app_engine.begin() as conn:
        assert await store.set_statuses(conn, statuses, NOW - HOUR, NOW) == []


async def test_3_a_triage_change_refreshes_the_raw_document(app_engine: AsyncEngine) -> None:
    es = FakeAlertsES()
    es.add(aid(1), NOW - HOUR)
    collector, _ = build(es, app_engine)
    await collector.reconcile(NOW - 2 * HOUR, NOW)
    async with app_engine.connect() as conn:
        before = (
            await conn.execute(text("SELECT state_hash, content_hash FROM alert_records"))
        ).one()
    es.docs[aid(1)].source["kibana.alert.workflow_status"] = "closed"
    es.docs[aid(1)].source["kibana.alert.workflow_tags"] = ["false positive"]
    assert await collector.sync_states() == 1
    async with app_engine.connect() as conn:
        after = (
            await conn.execute(
                text(
                    "SELECT state_hash, content_hash, raw->>'kibana.alert.workflow_status',"
                    " workflow_status FROM alert_records"
                )
            )
        ).one()
    assert after[0] != before[0]
    assert after[1] == before[1]  # triage is state, not content
    assert (after[2], after[3]) == ("closed", "closed")


async def test_4_any_poll_failure_opens_a_gap(app_engine: AsyncEngine) -> None:
    es = FakeAlertsES()
    collector, clock = build(es, app_engine)

    async def probe() -> None:
        return None

    runner = Runner(collector, probe, backfill_done=True)
    await runner.step()

    def broken(request: Any) -> None:
        raise RuntimeError("not a gateway error")

    es.before = broken
    clock.advance(MIN)
    await runner.step()
    async with app_engine.connect() as conn:
        gaps = (await conn.execute(text("SELECT kind, detail FROM coverage_gaps"))).all()
    assert gaps == [("argus_collector_lag", "RuntimeError")]


async def test_5_a_failed_backfill_waits_a_minute(app_engine: AsyncEngine) -> None:
    es = FakeAlertsES()
    collector, clock = build(es, app_engine)
    counts = 0

    def refuse_counts(request: Any) -> None:
        nonlocal counts
        if b'"aggs"' in (request.body or b""):
            counts += 1
            raise RuntimeError("down")

    es.before = refuse_counts

    async def probe() -> None:
        return None

    runner = Runner(collector, probe)
    for _ in range(12):  # one minute of 5-second ticks
        await runner.step()
        clock.advance(timedelta(seconds=5))
    assert counts == 1
    await runner.step()
    assert counts == 2


async def test_6_a_cursor_ahead_of_the_clock_skips_nothing(app_engine: AsyncEngine) -> None:
    es = FakeAlertsES()
    collector, clock = build(es, app_engine)
    clock.advance(2 * HOUR)  # the clock jumps ahead
    await collector.poll()
    clock.now = NOW  # and is corrected
    es.add(aid(1), NOW - 2 * MIN)
    await collector.poll()
    assert aid(1) in await stored(app_engine)
