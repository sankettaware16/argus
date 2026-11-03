"""The lane budgets and the Kibana lane's state in Postgres, as the runtime role (Q-D2,
migration 0029): lanes and Kibana state shared across processes, the cross-lane heavy rule,
ledger rows with the new columns, the audited resume, the new switches."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import DatabaseSettings
from argus.db.engine import create_engine
from argus.gateway import budget as bu
from argus.gateway.budget import Verdict
from argus.gateway.kibana import writes
from argus.gateway.kibana.writes import WriteClass, WriteUnits
from argus.gateway.lanes import Lane, LaneStates
from argus.gateway.pgstore import SWITCHES, PgStore, lanes_from_json, lanes_to_json
from argus.gateway.state import LedgerEntry
from argus.gateway.templates import CostClass
from tests.integration.gateway.test_pgstore import TIMES

pytestmark = pytest.mark.integration
T0 = datetime(2026, 10, 23, 10, 0, tzinfo=UTC)


@settings(max_examples=30)
@given(
    used=st.dictionaries(st.sampled_from([lane for lane in Lane if lane is not Lane.COLLECTOR]),
                         st.integers(0, 10**7)),
    starts=st.lists(TIMES, max_size=6),
)  # fmt: skip
def test_lane_states_round_trip(used: dict[Lane, int], starts: list[datetime]) -> None:
    states = LaneStates(
        {lane: bu.BudgetState(day=T0.date(), day_used_ms=n, tokens_ms=1.5, refilled_at=T0)
         for lane, n in used.items()},
        {Lane.IDENTITY: tuple(starts)} if starts else {},
    )  # fmt: skip
    assert lanes_from_json(lanes_to_json(states)) == states


async def test_the_new_switches_exist_and_run(app_engine: AsyncEngine) -> None:
    store = PgStore(app_engine)
    assert {"investigation", "freshness", "cases", "identity"} <= set(SWITCHES)
    assert await store.set_switch("cases", stopped=True, actor="t", reason="test")
    assert "cases" in (await store.switches()).stopped
    with pytest.raises(DBAPIError):
        async with app_engine.begin() as conn:
            await conn.execute(text("INSERT INTO siem_switches (component) VALUES ('kibana2')"))


async def test_lanes_are_shared_and_kept_apart(
    app_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str
) -> None:
    other = create_engine(db_settings, database=test_database)
    try:
        a, b = PgStore(app_engine), PgStore(other)
        admitted = await a.lane_admit(Lane.KIBANA_READ, CostClass.LIGHT, T0, 1.0, "l1")
        assert admitted.verdict is Verdict.ADMITTED
        assert admitted.lease is not None
        busy = await b.lane_admit(Lane.KIBANA_READ, CostClass.LIGHT, T0, 1.0, "l2")
        assert (busy.verdict, busy.reason) == (Verdict.WAIT, "concurrency")  # one at a time
        await b.lane_settle(Lane.KIBANA_READ, admitted.lease, 15_000, T0, 1.0)  # a timeout
        assert (await a.lanes()).bucket(Lane.KIBANA_READ).day_used_ms == 15_000
        collector = await a.budget_admit(CostClass.LIGHT, T0, 1.0, "c1")
        assert collector.verdict is Verdict.ADMITTED  # the collector does not feel it
        assert (await a.budget()).day_used_ms == 0
    finally:
        await other.dispose()


async def test_d022s_concurrency_is_one_pool_across_lanes_and_processes(
    app_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str
) -> None:
    """Review F2: two ARGUS processes, every lane: at most D-022's 2 requests at once, and the
    lanes other than the collector's never take its last slot."""
    other = create_engine(db_settings, database=test_database)
    try:
        a, b = PgStore(app_engine), PgStore(other)
        kibana = await a.lane_admit(Lane.KIBANA_READ, CostClass.LIGHT, T0, 1.0, "k1")
        assert kibana.verdict is Verdict.ADMITTED
        assert kibana.lease is not None
        identity = await b.lane_admit(Lane.IDENTITY, CostClass.LIGHT, T0, 1.0, "i1")
        assert (identity.verdict, identity.reason) == (Verdict.WAIT, "concurrency")
        first = await b.budget_admit(CostClass.LIGHT, T0, 1.0, "c1")
        assert first.verdict is Verdict.ADMITTED  # the collector's own slot
        second = await a.budget_admit(CostClass.LIGHT, T0, 1.0, "c2")
        assert (second.verdict, second.reason) == (Verdict.WAIT, "concurrency")
        probe = await a.budget_admit(CostClass.PROBE, T0, 1.0, "p1")
        assert (probe.verdict, probe.reason) == (Verdict.WAIT, "concurrency")  # probes count
        await b.lane_settle(Lane.KIBANA_READ, kibana.lease, 50, T0, 1.0)
        again = await a.budget_admit(CostClass.LIGHT, T0, 1.0, "c2")
        assert again.verdict is Verdict.ADMITTED
    finally:
        await other.dispose()


async def test_heavy_queries_one_at_a_time_across_lanes(app_engine: AsyncEngine) -> None:
    store = PgStore(app_engine)
    heavy = await store.lane_admit(Lane.INVESTIGATION, CostClass.HEAVY, T0, 1.0, "h1")
    assert heavy.verdict is Verdict.ADMITTED
    waiting = await store.budget_admit(CostClass.HEAVY, T0, 1.0, "h2")
    assert (waiting.verdict, waiting.reason) == (Verdict.WAIT, "heavy_concurrency")
    assert heavy.lease is not None
    await store.lane_settle(Lane.INVESTIGATION, heavy.lease, 800, T0, 1.0)
    later = T0 + timedelta(seconds=1)
    assert (await store.budget_admit(CostClass.HEAVY, later, 1.0, "h3")).verdict is Verdict.ADMITTED


async def test_concurrent_writers_never_both_take_the_last_place(app_engine: AsyncEngine) -> None:
    store = PgStore(app_engine)
    caps = writes.WriteCaps(case_per_day=1)

    async def take(n: int) -> str | None:
        return await store.kibana_change(
            lambda s: writes.admit_write(s, WriteClass.W1, WriteUnits(True), T0, f"r{n}", caps)
        )

    results = await asyncio.gather(*(take(n) for n in range(6)))
    assert sorted(results, key=str) == [None, *["case_daily_cap"] * 5] or results.count(None) == 1
    assert (await store.kibana_lane()).counters.case_writes == 1


async def test_kibana_stop_pause_and_the_audited_resume(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    store = PgStore(app_engine)
    await store.kibana_change(lambda s: (None, writes.stop(s, "401", T0)))
    await store.kibana_change(lambda s: (None, writes.pause(s, WriteClass.W2, "403")))
    lane = await store.kibana_lane()
    assert (lane.stopped, dict(lane.paused)) == ("401", {"W2": "403"})
    # the runtime may stop and pause, only the owner resumes (Q-A5's rule, migration 0029)
    for cls in (None, WriteClass.W2):
        with pytest.raises(DBAPIError) as refused:
            await store.kibana_resume(actor="op", reason="no", write_class=cls)
        assert getattr(refused.value.orig, "sqlstate", None) == "42501"
    assert (await store.kibana_lane()).stopped == "401"
    store = PgStore(migrated_engine)  # the owner
    assert await store.kibana_resume(actor="op", reason="key re-minted", write_class=None)
    assert await store.kibana_resume(actor="op", reason="checked", write_class=WriteClass.W2)
    assert not await store.kibana_resume(actor="op", reason="again", write_class=None)
    lane = await store.kibana_lane()
    assert (lane.stopped, dict(lane.paused)) == (None, {})
    async with app_engine.connect() as conn:
        rows = (await conn.execute(text(
            "SELECT target_id, details ->> 'was', details ->> 'reason' FROM audit_events"
            " WHERE action = 'kibana.resume' ORDER BY id"))).all()  # fmt: skip
    assert [tuple(r) for r in rows] == [
        ("kibana", "401", "key re-minted"), ("W2", "403", "checked"), ("kibana", None, "again"),
    ]  # fmt: skip


async def _execute(engine: AsyncEngine, statement: str) -> None:
    async with engine.begin() as conn:
        await conn.execute(text(statement))


async def test_the_runtime_keeps_writing_the_kibana_row_but_never_lifts_a_stop(
    app_engine: AsyncEngine,
) -> None:
    """Migration 0029's guard: counters, stops and pauses stay the runtime's; lifting a stop or
    a pause by any path (here a raw UPDATE, as anything holding the runtime password could) is
    refused."""
    store = PgStore(app_engine)
    caps = writes.WriteCaps()
    assert await store.kibana_change(
        lambda s: writes.admit_write(s, WriteClass.W1, WriteUnits(True), T0, "r1", caps)
    ) is None  # fmt: skip
    await store.kibana_change(lambda s: (None, writes.pause(s, WriteClass.W1, "403")))
    await store.kibana_change(lambda s: (None, writes.pause(s, WriteClass.WA, "403")))
    later = T0 + timedelta(seconds=5)
    assert await store.kibana_change(
        lambda s: writes.admit_write(s, WriteClass.W2, WriteUnits(True), later, "r1", caps)
    ) is None  # another class still writes; the pauses stay  # fmt: skip
    for update in (
        """UPDATE siem_state SET state = jsonb_set(state, '{paused}', '{}'::jsonb)
           WHERE name = 'kibana'""",
        """UPDATE siem_state SET state = jsonb_set(state, '{paused}', '{"W1": "403"}'::jsonb)
           WHERE name = 'kibana'""",
        """UPDATE siem_state SET state = jsonb_set(state, '{paused}', 'null'::jsonb)
           WHERE name = 'kibana'""",
        """UPDATE siem_state SET state = '{}'::jsonb WHERE name = 'kibana'""",
    ):
        with pytest.raises(DBAPIError):
            await _execute(app_engine, update)
    await store.kibana_change(lambda s: (None, writes.stop(s, "401", T0)))
    with pytest.raises(DBAPIError):
        await _execute(app_engine, "UPDATE siem_state SET state = jsonb_set(state,"
                       " '{stopped}', 'null'::jsonb) WHERE name = 'kibana'")  # fmt: skip
    lane = await store.kibana_lane()
    assert (lane.stopped, sorted(lane.paused), lane.counters.case_writes) == (
        "401", ["W1", "WA"], 2,
    )  # fmt: skip
    async with app_engine.begin() as conn:  # other rows of siem_state are not guarded
        await conn.execute(text(
            "UPDATE siem_state SET state = state WHERE name IN ('budget', 'lanes')"))  # fmt: skip


async def test_doctor_names_a_missing_kibana_resume_guard(migrated_engine: AsyncEngine) -> None:
    from argus.db import migrate

    assert await migrate.missing_resume_triggers(migrated_engine) == []
    await _execute(
        migrated_engine,
        "ALTER TABLE siem_state ENABLE TRIGGER siem_state_kibana_resume_needs_owner",
    )  # origin only: a replica session would skip it
    assert await migrate.missing_resume_triggers(migrated_engine) == [
        "siem_state.siem_state_kibana_resume_needs_owner"
    ]


async def test_kibanas_breaker_is_its_own(app_engine: AsyncEngine) -> None:
    store = PgStore(app_engine)
    await store.kibana_breaker_overload(T0)
    assert (await store.kibana_breaker_peek(T0))[0] is False
    assert (await store.breaker_peek(T0))[0] is True


async def test_ledger_rows_carry_the_lane_and_the_write(app_engine: AsyncEngine) -> None:
    store = PgStore(app_engine)
    entry = LedgerEntry(
        at=T0, component="writer", purpose="kibana_write", template="cases.close", version=1,
        indices=(), outcome="ok", http_status=200, took_ms=120, elapsed_ms=130,
        response_bytes=900, attempts=1, lane="kibana_write", target="kibana",
        outbox_id="o-7", payload_hash="a" * 64, write_class="W3", approval_id="ap-1",
        health="normal", switches=("collector",),
    )  # fmt: skip
    await store.record(entry)
    async with app_engine.connect() as conn:
        row = (await conn.execute(text(
            "SELECT lane, target, outbox_id, payload_hash, write_class, approval_id, health,"
            " switches FROM siem_requests WHERE outbox_id = 'o-7'"))).one()  # fmt: skip
    assert tuple(row) == ("kibana_write", "kibana", "o-7", "a" * 64, "W3", "ap-1", "normal",
                          ["collector"])  # fmt: skip
    bad = LedgerEntry(**{**entry.__dict__, "write_class": "W9"})
    with pytest.raises(DBAPIError):
        await store.record(bad)
    with pytest.raises(DBAPIError):
        await store.record(LedgerEntry(**{**entry.__dict__, "target": "elsewhere"}))
    with pytest.raises(DBAPIError):  # still append-only for the runtime role
        async with app_engine.begin() as conn:
            await conn.execute(text("UPDATE siem_requests SET outcome = 'x'"))
