"""The gateway's shared state in Postgres, as the runtime role (migration 0004, D-048)."""

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
from argus.db import roles
from argus.db.engine import create_engine
from argus.gateway import breaker as br
from argus.gateway import budget as bu
from argus.gateway.builtin import AlertIds, AlertIdsParams
from argus.gateway.gateway import Gateway
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.pgstore import (
    PgStore,
    breaker_from_json,
    breaker_to_json,
    budget_from_json,
    budget_to_json,
    health_from_json,
    health_to_json,
)
from argus.gateway.state import LedgerEntry
from argus.gateway.templates import CostClass, Purpose
from tests.unit.gateway.fakes import FakeClock, FakeTransport

pytestmark = pytest.mark.integration

T0 = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
TIMES = st.datetimes(
    min_value=datetime(2020, 1, 1),  # noqa: DTZ001 - Hypothesis bounds are naive
    max_value=datetime(2100, 1, 1),  # noqa: DTZ001
    timezones=st.just(UTC),
)


# --------------------------------------------------------------------------- JSON forms


@settings(max_examples=50)
@given(
    st.builds(
        bu.BudgetState,
        tokens_ms=st.none() | st.floats(-1e7, 1e7),
        refilled_at=st.none() | TIMES,
        day=st.none() | st.dates(),
        day_used_ms=st.integers(0, 10**8),
        heavy_day=st.integers(0, 5000),
        heavy_starts=st.tuples(TIMES, TIMES),
        probe_starts=st.tuples(TIMES),
        leases=st.lists(
            st.builds(
                bu.Lease,
                st.text(min_size=1, max_size=8),
                st.sampled_from(list(CostClass)),
                st.integers(0, 5000),
                TIMES,
            ),
            max_size=3,
        ).map(tuple),
        expired=st.lists(st.text(min_size=1, max_size=8), max_size=3).map(tuple),
    )
)
def test_budget_json_round_trip(state: bu.BudgetState) -> None:
    assert budget_from_json(budget_to_json(state)) == state


@settings(max_examples=50)
@given(
    st.builds(
        br.BreakerState, st.integers(0, 3), st.none() | TIMES, st.none() | TIMES, st.none() | TIMES
    )
)
def test_breaker_json_round_trip(state: br.BreakerState) -> None:
    assert breaker_from_json(breaker_to_json(state)) == state


@settings(max_examples=50)
@given(
    st.builds(
        HealthMemory,
        state=st.sampled_from(list(HealthState)),
        since=st.none() | TIMES,
        probed_at=st.none() | TIMES,
        recovered_at=st.none() | TIMES,
        reasons=st.lists(st.text(max_size=10), max_size=3).map(tuple),
        search_rejected=st.none() | st.integers(0, 10**9),
        breakers_tripped=st.none() | st.integers(0, 10**9),
        recent=st.lists(st.lists(st.text(max_size=5), max_size=2).map(tuple), max_size=3).map(
            tuple
        ),
    )
)
def test_health_json_round_trip(memory: HealthMemory) -> None:
    assert health_from_json(health_to_json(memory)) == memory


def test_empty_rows_are_fresh_states() -> None:
    assert budget_from_json({}) == bu.BudgetState()
    assert breaker_from_json({}) == br.BreakerState()
    assert health_from_json({}) == HealthMemory()


def test_rows_written_before_review_1_still_load() -> None:
    """Rows from before ``expired`` and ``probed_at`` existed load as "none yet"."""
    budget = budget_to_json(bu.BudgetState(day=T0.date()))
    del budget["expired"]
    assert budget_from_json(budget).expired == ()
    health = health_to_json(HealthMemory(state=HealthState.CAUTION))
    del health["probed_at"]
    assert health_from_json(health).probed_at is None


async def test_breaker_peek_reads_without_taking_the_trial(app_engine: AsyncEngine) -> None:
    store = PgStore(app_engine)
    await store.breaker_overload(T0)
    assert await store.breaker_peek(T0) == (False, T0 + timedelta(minutes=5))
    after = T0 + timedelta(minutes=5)
    assert (await store.breaker_peek(after))[0]
    assert (await store.breaker()).trial_until is None
    assert (await store.breaker_admit(after))[0]
    assert not (await store.breaker_peek(after))[0]


# --------------------------------------------------------------------------- as the runtime role


async def test_the_runtime_role_holds_exactly_the_gateway_grants(app_engine: AsyncEngine) -> None:
    assert await roles.runtime_role_problems(app_engine) == []


async def test_switches_are_audited(app_engine: AsyncEngine, migrated_engine: AsyncEngine) -> None:
    store = PgStore(app_engine)
    assert (await store.switches()).stopped == frozenset()
    assert await store.set_switch("collector", stopped=True, actor="tester", reason="drill")
    assert not await store.set_switch("collector", stopped=True, actor="tester", reason="again")
    assert (await store.switches()).stopped == {"collector"}
    # the runtime may stop, only the owner resumes (migration 0027, Q-A5); the refusal
    # rolls back its audit event with it
    with pytest.raises(DBAPIError) as refused:
        await store.set_switch("collector", stopped=False, actor="tester", reason=None)
    assert getattr(refused.value.orig, "sqlstate", None) == "42501"
    assert (await store.switches()).stopped == {"collector"}
    owner = PgStore(migrated_engine)
    assert await owner.set_switch("collector", stopped=False, actor="tester", reason=None)
    with pytest.raises(ValueError, match="unknown component"):
        await store.set_switch("everything", stopped=True, actor="tester", reason=None)
    async with app_engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT action, target_id, details->>'changed' FROM audit_events"
                    " WHERE target_type = 'siem_switch' ORDER BY id"
                )
            )
        ).all()
    assert rows == [
        ("siem.stop", "collector", "true"),
        ("siem.stop", "collector", "false"),
        ("siem.resume", "collector", "true"),
    ]


async def test_state_machines_persist(app_engine: AsyncEngine) -> None:
    store = PgStore(app_engine)
    await store.save_health(HealthMemory(state=HealthState.CAUTION, since=T0, reasons=("heap",)))
    assert (await PgStore(app_engine).health()).reasons == ("heap",)
    await store.breaker_overload(T0)
    assert await store.breaker_admit(T0) == (False, T0 + timedelta(minutes=5))
    assert (await store.breaker_admit(T0 + timedelta(minutes=5)))[0]
    await store.breaker_success(T0 + timedelta(minutes=6))
    assert (await store.breaker()).open_until is None
    admission = await store.budget_admit(CostClass.MEDIUM, T0, 1.0, "a")
    assert admission.lease is not None
    await store.budget_settle(admission.lease, 120, T0, 1.0)
    assert (await store.budget()).day_used_ms == 120


async def test_two_processes_share_one_budget(
    app_engine: AsyncEngine, db_settings: DatabaseSettings, test_database: str
) -> None:
    """Two engines (separate connection pools, as two processes have) race for slots: the
    row lock serialises them, so at most two leases are ever out."""
    other = create_engine(db_settings, database=test_database)
    try:
        stores = [PgStore(app_engine), PgStore(other)]
        results = await asyncio.gather(
            *(stores[n % 2].budget_admit(CostClass.LIGHT, T0, 1.0, f"l{n}") for n in range(12))
        )
        admitted = [r for r in results if r.verdict is bu.Verdict.ADMITTED]
        assert len(admitted) == 2
        assert {r.reason for r in results if r.verdict is bu.Verdict.WAIT} == {"concurrency"}
        assert len((await stores[1].budget()).leases) == 2
    finally:
        await other.dispose()


async def test_live_sessions(app_engine: AsyncEngine) -> None:
    store = PgStore(app_engine)
    await store.start_live_session("s1", actor="devuser", now=T0, minutes=20, max_requests=2)
    assert await store.live_use("s1", T0)
    assert await store.live_use("s1", T0)
    assert not await store.live_use("s1", T0)  # used up
    await store.start_live_session("s2", actor="devuser", now=T0, minutes=20, max_requests=50)
    assert not await store.live_use("s2", T0 + timedelta(minutes=20))  # over
    assert await store.end_live_session("s2", actor="devuser", now=T0)
    assert not await store.live_use("s2", T0)
    assert not await store.end_live_session("s2", actor="devuser", now=T0)
    assert not await store.live_use("nope", T0)
    for minutes, requests in ((0, 10), (61, 10), (20, 0), (20, 51)):
        with pytest.raises(ValueError, match="live session"):
            await store.start_live_session(
                "x", actor="a", now=T0, minutes=minutes, max_requests=requests
            )


async def test_the_ledger_is_append_only_for_the_runtime_role(app_engine: AsyncEngine) -> None:
    store = PgStore(app_engine)
    entry = LedgerEntry(
        T0, "collector", "collect", "alerts.ids", 1, (".alerts-x",), "ok", 200, 5, 7, 100, 1
    )
    await store.record(entry)
    for statement in (
        "UPDATE siem_requests SET took_ms = 0",
        "DELETE FROM siem_requests",
        "UPDATE siem_state SET name = 'budget' WHERE false",
        "DELETE FROM siem_switches",
        "INSERT INTO siem_state (name) VALUES ('x')",
    ):
        async with app_engine.connect() as conn:
            with pytest.raises(DBAPIError, match="permission denied"):
                await conn.execute(text(statement))


async def test_the_gateway_on_postgres(app_engine: AsyncEngine) -> None:
    clock = FakeClock()
    transport = FakeTransport(clock=clock)
    store = PgStore(app_engine)
    gateway = Gateway(transport, store, clock=clock, sleep=clock.sleep)
    params = AlertIdsParams(start=T0 - timedelta(minutes=5), end=T0)
    await gateway.run(AlertIds(), params, purpose=Purpose.COLLECT, component="collector",
                      deadline=T0 + timedelta(seconds=30))  # fmt: skip
    async with app_engine.connect() as conn:
        row = (
            await conn.execute(
                text("SELECT template, outcome, took_ms, indices FROM siem_requests")
            )
        ).one()
    assert tuple(row) == ("alerts.ids", "ok", 5, [".alerts-security.alerts-acme-soc"])
    assert (await store.budget()).leases == ()
    await store.set_switch("global", stopped=True, actor="tester", reason=None)
    with pytest.raises(Exception, match="kill switch"):
        await gateway.run(AlertIds(), params, purpose=Purpose.COLLECT, component="collector",
                          deadline=T0 + timedelta(seconds=30))  # fmt: skip
    assert len(transport.calls) == 1
