"""Collector tests written for mutation survivors (D-040) that need Postgres: ingest counts,
hour boundaries, per-page cursor commits, failed and empty reconciliations, chunks, pages,
overflowing rules and alerts without a rule id."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.collector import collector as co
from argus.collector import store
from argus.collector.templates import AlertCounts
from argus.gateway.errors import TransportFailedError
from tests.integration.collector.fake_es import INDEX, FakeAlertsES, alert
from tests.integration.collector.test_collector import HOUR, MIN, NOW, aid, build, cursor, stored

pytestmark = pytest.mark.integration


def hit(n: int, at: Any, **changes: Any) -> dict[str, Any]:
    source = alert(aid(n), at)
    source.update(changes)
    return {"_index": INDEX, "_id": aid(n), "found": True, "_source": source}


async def test_ingest_counts(app_engine: AsyncEngine) -> None:
    async with app_engine.begin() as conn:
        assert await store.ingest(conn, [], "live", NOW) == store.Ingested(0, 0, 0)
        conflicting = hit(2, NOW, **{"kibana.alert.rule": {"rule_id": "z"}})
        batch = [hit(1, NOW), conflicting, {"_id": "x", "found": False}]
        first = await store.ingest(conn, batch, "live", NOW)
        assert first == store.Ingested(2, 0, 1)
        same = await store.ingest(conn, [hit(1, NOW)], "live", NOW)
        assert same == store.Ingested(0, 0, 0)
        closed = hit(1, NOW, **{"kibana.alert.workflow_status": "closed"})
        assert await store.ingest(conn, [closed], "live", NOW) == store.Ingested(0, 1, 0)


async def test_detected_at_sources(app_engine: AsyncEngine) -> None:
    odd = hit(3, NOW, **{"kibana.alert.rule": {"rule_id": "z"}})
    odd["_source"]["@timestamp"] = "not a time"
    async with app_engine.begin() as conn:
        await store.ingest(conn, [hit(1, NOW - MIN)], "live", NOW)  # from R3
        await store.ingest(conn, [odd], "live", NOW, {aid(3): NOW - HOUR})  # from the listing
        await store.ingest(conn, [odd], "live", NOW)  # again, without: kept
        quarantined = hit(4, NOW - 2 * MIN, **{"kibana.alert.rule": {"rule_id": "z"}})
        await store.ingest(conn, [quarantined], "live", NOW)  # parsed like R3
        rows = dict(
            (await conn.execute(text("SELECT alert_id, detected_at FROM alert_records"))).all()
        )
    assert rows == {aid(1): NOW - MIN, aid(3): NOW - HOUR, aid(4): NOW - 2 * MIN}


async def test_hour_boundaries_and_small_returns(app_engine: AsyncEngine) -> None:
    hour = NOW - HOUR
    async with app_engine.begin() as conn:
        await store.ingest(conn, [hit(1, hour), hit(2, NOW)], "live", NOW,
                           {aid(1): hour, aid(2): NOW})  # fmt: skip
        assert await store.ids_between(conn, hour, NOW) == {aid(1)}
        per_rule, totals = await store.counts_between(conn, hour, NOW)
        assert (per_rule, totals) == ({(hour, "rule-a"): 1}, {hour: 1})
        assert await store.mark_missing(conn, {aid(1)}, NOW) == 1
        assert await store.mark_missing(conn, {aid(1)}, NOW) == 0
        assert await store.mark_missing(conn, set(), NOW) == 0
        assert await store.known_ids(conn, []) == set()
        assert await store.close_gaps(conn, ["breaker_open"], "alerts", NOW) == 0


async def test_each_page_moves_the_cursor_in_its_transaction(
    app_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(co, "PAGE", 2)
    es = FakeAlertsES()
    for n in range(5):
        es.add(aid(n), NOW - 4 * MIN + n * timedelta(seconds=30))
    commits = 0

    async def crash_on_second_commit(name: str) -> None:
        nonlocal commits
        if name == "commit":
            commits += 1
            if commits == 2:
                raise RuntimeError("killed")

    collector, _ = build(es, app_engine, checkpoint=crash_on_second_commit)
    with pytest.raises(RuntimeError):
        await collector.poll()
    assert await cursor(app_engine) == NOW - 4 * MIN + timedelta(seconds=30)
    assert set(await stored(app_engine)) == {aid(0), aid(1)}


async def test_a_failed_reconciliation_is_recorded_and_raised(app_engine: AsyncEngine) -> None:
    es = FakeAlertsES()
    collector, _ = build(es, app_engine)
    await collector.reconcile(NOW, NOW + 30 * MIN)  # no whole hour: nothing recorded

    def down(request: Any) -> None:
        raise TransportFailedError("reset", retriable=False)

    es.before = down
    with pytest.raises(TransportFailedError):
        await collector.reconcile(NOW - 2 * HOUR, NOW)
    async with app_engine.connect() as conn:
        runs = (await conn.execute(text("SELECT hours, outcome FROM reconciliation_runs"))).all()
    assert runs == [(0, "transport_failure")]


async def test_reconciliation_walks_every_chunk(app_engine: AsyncEngine) -> None:
    es = FakeAlertsES()
    for n in range(13):
        es.add(aid(n), NOW - (n + 1) * HOUR + MIN)
    collector, _ = build(es, app_engine)
    result = await collector.reconcile(NOW - 13 * HOUR, NOW)
    assert (result.hours, result.recovered) == (13, 13)


async def test_overflowing_rules_and_alerts_without_a_rule(
    app_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    es = FakeAlertsES()
    hour = NOW - 2 * HOUR
    es.add(aid(1), hour + MIN, rule="rule-a")
    es.add(aid(2), hour + 2 * MIN, rule="rule-b")
    del es.docs[aid(2)].source["kibana.alert.rule.rule_id"]
    collector, _ = build(es, app_engine)
    await collector.reconcile(hour, NOW)
    settled = await collector.reconcile(hour, NOW)
    assert settled.mismatched == ()  # the rule-less alert counts on both sides
    es.add(aid(3), hour + 3 * MIN, rule="rule-c")
    await collector.reconcile(hour, NOW)
    monkeypatch.setattr(AlertCounts, "RULES", 1)  # more rules than the terms size
    overflowing = await collector.reconcile(hour, NOW)
    assert overflowing.mismatched == (hour,)


async def test_states_page_through_and_reread(
    app_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(co, "PAGE", 2)
    es = FakeAlertsES()
    for n in range(5):
        es.add(aid(n), NOW - HOUR + n * MIN)
    collector, _ = build(es, app_engine)
    await collector.reconcile(NOW - 2 * HOUR, NOW)
    for n in range(5):
        es.docs[aid(n)].source["kibana.alert.workflow_status"] = "closed"
    assert await collector.sync_states() == 5
    rows = await stored(app_engine)
    assert {r["workflow_status"] for r in rows.values()} == {"closed"}
    async with app_engine.connect() as conn:
        query = "SELECT DISTINCT raw->>'kibana.alert.workflow_status' FROM alert_records"
        raw = (await conn.execute(text(query))).all()
    assert raw == [("closed",)]


async def test_long_runs_refresh_before_every_chunk(app_engine: AsyncEngine) -> None:
    """Found by the first real backfill: one probe at the start went stale after 3 minutes
    and the health state (D-049) then refused the rest."""
    calls = 0

    async def fresh() -> None:
        nonlocal calls
        calls += 1

    collector, _ = build(FakeAlertsES(), app_engine, before_chunk=fresh)
    await collector.reconcile(NOW - 13 * HOUR, NOW)
    assert calls == 3  # 6 + 6 + 1 hours


async def grouped(engine: AsyncEngine) -> tuple[int, int]:
    async with engine.connect() as conn:
        query = (
            "SELECT (SELECT count(*) FROM alert_records WHERE status = 'normalized'),"
            " (SELECT count(*) FROM investigation_alerts)"
        )
        normalized, linked = (await conn.execute(text(query))).one()
    return normalized, linked


async def test_every_way_in_groups_what_it_stores(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    es = FakeAlertsES()
    es.add(aid(1), NOW - MIN)
    names: list[str] = []

    async def note(name: str) -> None:
        names.append(name)

    collector, _ = build(es, app_engine, checkpoint=note)
    await collector.poll()  # the live poll
    assert names == ["ids", "mget", "commit"]
    assert await grouped(app_engine) == (1, 1)
    es.add(aid(2), NOW - 3 * HOUR)
    await collector.reconcile(NOW - 4 * HOUR, NOW)  # a recovered alert
    assert await grouped(app_engine) == (2, 2)
    async with migrated_engine.begin() as conn:  # a link lost (as the owner: ARGUS cannot)
        await conn.execute(text("DELETE FROM investigation_alerts WHERE alert_id = :a"),
                           {"a": aid(1)})  # fmt: skip
    es.docs[aid(1)].source["kibana.alert.workflow_status"] = "closed"
    await collector.sync_states()
    assert await grouped(app_engine) == (2, 2)
    ledger = collector.gateway.state.ledger  # type: ignore[attr-defined]
    assert {entry.component for entry in ledger} == {"collector"}


async def test_closing_gaps_counts_them(app_engine: AsyncEngine) -> None:
    async with app_engine.begin() as conn:
        await store.open_gap(conn, "breaker_open", "alerts", NOW - HOUR, "x")
        await store.open_gap(conn, "breaker_open", "alerts", NOW - MIN, "again")  # one open
        assert await store.close_gaps(conn, ["breaker_open"], "alerts", NOW) == 1
        assert await store.close_gaps(conn, ["breaker_open"], "alerts", NOW) == 0
