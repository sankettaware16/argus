"""Lane budgets (plan §7.8, Q-D2): the plan adds up to the ceiling, each lane spends only its own
share, a debt slows only its own lane, heavy queries run one at a time across lanes, and the
gate's properties: Kibana lanes timing out never delay the collector; no log request in STOP
or under the global switch."""

from __future__ import annotations

import contextlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.gateway.budget import BudgetConfig, BudgetState, Lease, Verdict
from argus.gateway.builtin import AlertIds, AlertIdsParams, Freshness, FreshnessParams
from argus.gateway.errors import (
    BudgetExhaustedError,
    DeadlinePassedError,
    DeferredError,
    RefusedError,
    StoppedError,
)
from argus.gateway.gateway import LaneGate, in_quiet_hours
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.lanes import (
    DEFAULT_LANES,
    LANE_OF,
    Lane,
    LanePlan,
    LaneSpec,
    LaneStates,
    admit,
    lane_of,
    proportional,
    settle,
)
from argus.gateway.templates import CostClass, Purpose
from tests.unit.gateway.fakes import SQUID_TODAY, FakeTransport, listing, make, ok, search_answer

pytestmark = pytest.mark.unit
T0 = datetime(2026, 10, 23, 10, 0, tzinfo=UTC)
PLAN = LanePlan()


class FreshnessRead(Freshness):
    """A light log read (Q-F1 builds its own); ``health.freshness`` is probe-cost."""

    name = "test.freshness_read"
    cost = CostClass.LIGHT


def test_the_default_lanes_are_plan_7_8s_table() -> None:
    table = {
        Lane.COLLECTOR: (600, 720_000, 100, 2),
        Lane.ENRICHMENT: (800, 1_080_000, 1_400, 1),
        Lane.INVESTIGATION: (400, 360_000, 300, 1),
        Lane.FRESHNESS: (100, 180_000, 0, 1),
        Lane.KIBANA_READ: (200, 240_000, 0, 1),
        Lane.KIBANA_WRITE: (200, 180_000, 0, 1),
        Lane.IDENTITY: (300, 120_000, 0, 1),
        Lane.MEASUREMENT: (0, 120_000, 100, 1),
        Lane.CHECKING: (400, 600_000, 100, 1),
    }
    got = {
        lane: (s.per_minute_ms, s.per_day_ms, s.heavy_per_day, s.concurrency)
        for lane, s in DEFAULT_LANES.items()
    }
    assert got == table
    assert DEFAULT_LANES[Lane.IDENTITY].per_minute_requests == 6
    ceiling = BudgetConfig()
    assert sum(s.per_minute_ms for s in DEFAULT_LANES.values()) == ceiling.took_per_minute_ms
    assert sum(s.per_day_ms for s in DEFAULT_LANES.values()) == ceiling.took_per_day_ms
    assert sum(s.heavy_per_day for s in DEFAULT_LANES.values()) == ceiling.heavy_per_day


def test_every_purpose_has_its_lane() -> None:
    assert set(LANE_OF) == set(Purpose)
    assert lane_of(Purpose.PROBE) is None
    assert lane_of(Purpose.SELFTEST) is None
    assert {lane_of(p) for p in (Purpose.COLLECT, Purpose.BACKFILL,
                                 Purpose.RECONCILE)} == {Lane.COLLECTOR}  # fmt: skip
    # D-321: whatever is not the collector's own work leaves the poll's lane
    assert {lane_of(p) for p in (Purpose.ENRICH, Purpose.MEASURE,
                                 Purpose.DISCOVER)} == {Lane.ENRICHMENT}  # fmt: skip
    assert lane_of(Purpose.KIBANA_WRITE) is lane_of(Purpose.WRITEBACK) is Lane.KIBANA_WRITE
    assert lane_of(Purpose.FRESHNESS) is Lane.FRESHNESS
    assert lane_of(Purpose.IDENTITY) is Lane.IDENTITY
    assert Lane.MEASUREMENT not in set(LANE_OF.values())  # closed: no purpose spends it yet


async def test_the_measuring_session_is_sent_on_the_enrichment_lane() -> None:
    """Q-A3's session's ``measure`` requests go out in NORMAL on the enrichment lane (D-321:
    never on the poll's; the measurement lane has no minute share), and wait in CAUTION."""
    gateway, transport, store, clock = make()
    transport.default = search_answer()
    params = AlertIdsParams(start=clock.now - timedelta(minutes=5), end=clock.now)
    await gateway.run(AlertIds(), params, purpose=Purpose.MEASURE, component="measure",
                      deadline=clock.now + timedelta(seconds=30))  # fmt: skip
    assert (store.ledger[-1].lane, store.ledger[-1].outcome) == ("enrichment", "ok")
    assert store.lanes.bucket(Lane.ENRICHMENT).day_used_ms > 0
    assert store.budget.day_used_ms == 0  # the collector's bucket is untouched
    store.memory = HealthMemory(state=HealthState.CAUTION, probed_at=clock.now)
    with pytest.raises(DeferredError):
        await gateway.run(AlertIds(), params, purpose=Purpose.MEASURE, component="measure",
                          deadline=clock.now + timedelta(seconds=30))  # fmt: skip


@given(
    per_minute=st.integers(100, 60_000),
    burst=st.integers(100, 60_000),
    per_day=st.integers(60_000, 86_400_000),
    heavy=st.integers(1, 20_000),
    concurrency=st.integers(1, 4),
)
def test_proportional_lanes_never_exceed_any_ceiling(
    per_minute: int, burst: int, per_day: int, heavy: int, concurrency: int
) -> None:
    ceiling = BudgetConfig(took_per_minute_ms=per_minute, burst_ms=burst, took_per_day_ms=per_day,
                           heavy_per_day=heavy, concurrency=concurrency)  # fmt: skip
    plan = LanePlan(ceiling)  # raises if they did
    lanes = proportional(ceiling)
    assert sum(s.per_minute_ms for s in lanes.values()) <= min(per_minute, burst)
    assert sum(s.per_day_ms for s in lanes.values()) <= per_day
    assert sum(s.heavy_per_day for s in lanes.values()) <= heavy
    assert all(s.concurrency <= concurrency for s in lanes.values())
    assert plan.config(Lane.COLLECTOR).took_per_minute_ms == lanes[Lane.COLLECTOR].per_minute_ms


def test_a_plan_over_the_ceiling_is_refused() -> None:
    lanes = dict(DEFAULT_LANES)
    lanes[Lane.FRESHNESS] = LaneSpec(101, 180_000)
    with pytest.raises(ValueError, match="a minute"):
        LanePlan(BudgetConfig(), lanes)
    lanes[Lane.FRESHNESS] = LaneSpec(100, 180_001)
    with pytest.raises(ValueError, match="a day"):
        LanePlan(BudgetConfig(), lanes)
    lanes[Lane.FRESHNESS] = LaneSpec(100, 180_000, heavy_per_day=1)
    with pytest.raises(ValueError, match="heavy"):
        LanePlan(BudgetConfig(), lanes)
    del lanes[Lane.FRESHNESS]
    with pytest.raises(ValueError, match="no allowance"):
        LanePlan(BudgetConfig(), lanes)
    with pytest.raises(ValueError, match="negative"):
        LaneSpec(-1, 0)
    with pytest.raises(ValueError, match="at least one"):
        LaneSpec(1, 1, concurrency=0)
    with pytest.raises(ValueError, match="at least 1"):
        LaneSpec(1, 1, per_minute_requests=0)


def _admit(
    states: LaneStates,
    lane: Lane,
    cost: CostClass = CostClass.LIGHT,
    now: datetime = T0,
    lease: str = "l",
    collector: BudgetState | None = None,
) -> tuple[Any, LaneStates]:
    return admit(states, PLAN, lane, cost, now, scale=1.0, lease_id=lease, collector=collector)


def test_the_collectors_lane_and_probes_are_not_lanes_here() -> None:
    with pytest.raises(ValueError, match="original budget"):
        _admit(LaneStates(), Lane.COLLECTOR)
    with pytest.raises(ValueError, match="probes"):
        _admit(LaneStates(), Lane.FRESHNESS, CostClass.PROBE)
    lease = Lease("l", CostClass.LIGHT, 50, T0 + timedelta(minutes=2))
    with pytest.raises(ValueError, match="original budget"):
        settle(LaneStates(), PLAN, Lane.COLLECTOR, lease, 1, T0, scale=1.0)


def test_measurement_is_closed_until_a_decision_gives_it_a_minute_share() -> None:
    admission, _ = _admit(LaneStates(), Lane.MEASUREMENT)
    assert (admission.verdict, admission.reason) == (Verdict.EXHAUSTED, "lane_closed")


def test_lanes_without_heavy_queries_refuse_them() -> None:
    for lane in (Lane.FRESHNESS, Lane.KIBANA_READ, Lane.KIBANA_WRITE, Lane.IDENTITY):
        admission, _ = _admit(LaneStates(), lane, CostClass.HEAVY)
        assert (admission.verdict, admission.reason) == (Verdict.EXHAUSTED, "heavy_daily")


def test_heavy_queries_run_one_at_a_time_across_lanes() -> None:
    collector = BudgetState(
        tokens_ms=1_800.0, refilled_at=T0, day=T0.date(),
        leases=(Lease("c", CostClass.HEAVY, 1_000, T0 + timedelta(minutes=2)),),
        heavy_starts=(T0,), heavy_day=1,
    )  # fmt: skip
    admission, _ = _admit(LaneStates(), Lane.INVESTIGATION, CostClass.HEAVY, collector=collector)
    assert (admission.verdict, admission.reason) == (Verdict.WAIT, "heavy_concurrency")
    assert admission.retry_at == T0 + timedelta(minutes=2)
    admission, _ = _admit(LaneStates(), Lane.INVESTIGATION, CostClass.HEAVY)
    assert admission.verdict is Verdict.ADMITTED
    starts = tuple(T0 - timedelta(seconds=s) for s in range(6))
    busy = BudgetState(tokens_ms=1_800.0, refilled_at=T0, day=T0.date(), heavy_starts=starts)
    admission, _ = _admit(LaneStates(), Lane.INVESTIGATION, CostClass.HEAVY, collector=busy)
    assert (admission.verdict, admission.reason) == (Verdict.WAIT, "heavy_rate")


def test_identity_checks_are_six_a_minute() -> None:
    states = LaneStates()
    for n in range(6):
        admission, states = _admit(states, Lane.IDENTITY, lease=f"i{n}", now=T0)
        assert admission.verdict is Verdict.ADMITTED, n
        assert admission.lease is not None
        states = settle(states, PLAN, Lane.IDENTITY, admission.lease, 1, T0, scale=1.0)
    admission, states = _admit(states, Lane.IDENTITY, lease="i6")
    assert (admission.verdict, admission.reason) == (Verdict.WAIT, "request_rate")
    admission, _ = _admit(states, Lane.IDENTITY, lease="i7", now=T0 + timedelta(seconds=61))
    assert admission.verdict is Verdict.ADMITTED


@settings(max_examples=200)
@given(
    charges=st.lists(st.tuples(st.sampled_from([Lane.KIBANA_READ, Lane.KIBANA_WRITE,
                                                 Lane.FRESHNESS, Lane.IDENTITY]),
                               st.integers(0, 60_000)), max_size=30),
)  # fmt: skip
def test_a_debt_slows_only_its_own_lane(charges: list[tuple[Lane, int]]) -> None:
    """Whatever the other lanes spent (timeouts included), the investigation lane admits at
    once, exactly as if they had spent nothing."""
    states = LaneStates()
    for n, (lane, took) in enumerate(charges):
        admission, states = _admit(states, lane, lease=f"x{n}")
        if admission.lease is not None:
            states = settle(states, PLAN, lane, admission.lease, took, T0, scale=1.0)
    alone, _ = _admit(LaneStates(), Lane.INVESTIGATION, lease="mine")
    after, _ = _admit(states, Lane.INVESTIGATION, lease="mine")
    assert after == alone
    assert after.verdict is Verdict.ADMITTED


@settings(max_examples=100)
@given(tooks=st.lists(st.integers(0, 600_000), min_size=1, max_size=60))
def test_a_lane_never_spends_more_than_its_day(tooks: list[int]) -> None:
    states = LaneStates()
    spent = 0
    now = T0
    for n, took in enumerate(tooks):
        now += timedelta(minutes=10)
        admission, states = _admit(states, Lane.KIBANA_READ, lease=f"r{n}", now=now)
        if admission.verdict is Verdict.ADMITTED:
            assert admission.lease is not None
            assert spent < DEFAULT_LANES[Lane.KIBANA_READ].per_day_ms
            states = settle(states, PLAN, Lane.KIBANA_READ, admission.lease, took, now, scale=1.0)
            spent = states.bucket(Lane.KIBANA_READ).day_used_ms
    if now.date() == T0.date():
        assert spent <= DEFAULT_LANES[Lane.KIBANA_READ].per_day_ms + max(tooks)


# --------------------------------------------------------------------------- through the gateway


def test_quiet_hours() -> None:
    assert in_quiet_hours(T0.replace(hour=0, minute=0))
    assert in_quiet_hours(T0.replace(hour=1, minute=29, second=59))
    assert not in_quiet_hours(T0.replace(hour=1, minute=30))
    assert not in_quiet_hours(T0.replace(hour=23, minute=59))


async def _collect(gateway: Any, clock: Any) -> Any:
    return await gateway.run(
        AlertIds(), AlertIdsParams(start=clock.now - timedelta(minutes=5), end=clock.now),
        purpose=Purpose.COLLECT, component="collector", deadline=clock.now + timedelta(seconds=5),
    )  # fmt: skip


@settings(max_examples=50, deadline=None)
@given(timeouts=st.integers(1, 40), hanging=st.integers(0, 1))
async def test_kibana_lanes_timing_out_never_delay_the_collector(
    timeouts: int, hanging: int
) -> None:
    """The gate's property: any number of Kibana calls charged their whole timeout, and one
    still in flight, leave the collector's admission as it was: no wait, nothing refused."""
    from argus.gateway.kibana.errors import UnknownOutcomeError
    from argus.gateway.kibana.templates import CaseGet, CaseParams
    from tests.unit.gateway.kibana.fakes import FakeKibana
    from tests.unit.gateway.kibana.fakes import make as make_kibana

    kibana = FakeKibana().on("GET", "/api/cases/c1", UnknownOutcomeError("slow", timed_out=True))
    gateway, _, store, clock, es_gateway = make_kibana(kibana)
    es_gateway.transport.default = search_answer()  # type: ignore[attr-defined]
    for _ in range(timeouts):
        with contextlib.suppress(UnknownOutcomeError, BudgetExhaustedError, DeadlinePassedError):
            await gateway.read(CaseGet(), CaseParams(case_id="c1"), component="sync",
                               deadline=clock.now + timedelta(seconds=30))  # fmt: skip
        store.memory = HealthMemory(probed_at=clock.now)
    if hanging:  # a Kibana request holding its lease right now
        bucket = store.lanes.bucket(Lane.KIBANA_READ)
        held = Lease("hang", CostClass.LIGHT, 50, clock.now + timedelta(minutes=2))
        store.lanes = LaneStates(
            {**store.lanes.buckets, Lane.KIBANA_READ: replace(bucket, leases=(held,))},
            store.lanes.starts,
        )
    slept = list(clock.slept)
    before = clock.now
    for _ in range(2):  # two concurrent collector slots' worth, one after the other
        await _collect(es_gateway, clock)
    assert clock.slept == slept  # the collector did not wait
    assert clock.now - before < timedelta(seconds=1)
    assert store.budget.day_used_ms > 0
    assert all(entry.lane == "kibana_read" for entry in store.ledger if entry.target == "kibana")


@given(
    purpose=st.sampled_from(list(Purpose)),
    state=st.sampled_from([HealthState.STOP, HealthState.NORMAL]),
    global_switch=st.booleans(),
)
async def test_no_log_request_in_stop_or_under_the_global_switch(
    purpose: Purpose, state: HealthState, global_switch: bool
) -> None:
    gateway, transport, store, clock = make(
        FakeTransport().on("_resolve", ok(listing(SQUID_TODAY)))
    )
    store.memory = HealthMemory(state=state, probed_at=clock.now)
    if global_switch:
        store.stopped.add("global")
    template = Freshness() if purpose in (Purpose.PROBE, Purpose.SELFTEST) else FreshnessRead()
    with contextlib.suppress(RefusedError):  # refused one way or another: what matters is below
        await gateway.run(
            template, FreshnessParams(source="squid", now=clock.now), purpose=purpose,
            component="t", deadline=clock.now + timedelta(seconds=30),
        )  # fmt: skip
    log_calls = [c for c in transport.calls if "acme-logs-" in c.path and "_search" in c.path]
    if state is HealthState.STOP or global_switch:
        assert log_calls == []
        assert transport.calls == []


async def test_freshness_waits_out_the_quiet_hours_and_spends_its_own_lane() -> None:
    gateway, transport, store, clock = make(
        FakeTransport().on("_resolve", ok(listing(SQUID_TODAY)))
    )
    clock.now = clock.now.replace(hour=0, minute=45)
    store.memory = HealthMemory(probed_at=clock.now)
    with pytest.raises(DeferredError, match="quiet hours"):
        await gateway.run(FreshnessRead(), FreshnessParams(source="squid", now=clock.now),
                          purpose=Purpose.FRESHNESS, component="freshness",
                          deadline=clock.now + timedelta(seconds=30))  # fmt: skip
    assert transport.calls == []
    clock.now = clock.now.replace(hour=1, minute=30)
    store.memory = HealthMemory(probed_at=clock.now)
    await gateway.run(FreshnessRead(), FreshnessParams(source="squid", now=clock.now),
                      purpose=Purpose.FRESHNESS, component="freshness",
                      deadline=clock.now + timedelta(seconds=30))  # fmt: skip
    assert store.lanes.bucket(Lane.FRESHNESS).day_used_ms == 5  # the search's took
    assert store.budget.day_used_ms == 5  # only the listing probe, on the probes' allowance
    assert store.ledger[-1].lane == "freshness"


async def test_identity_checks_run_in_stop_on_their_own_lane() -> None:
    _, _, store, clock = make()
    store.memory = HealthMemory(state=HealthState.STOP, probed_at=clock.now)
    gate = LaneGate(store, clock=clock, sleep=clock.sleep)
    async with gate.hold(Purpose.IDENTITY, deadline=clock.now + timedelta(seconds=10)) as spend:
        spend.charge(120)
    assert store.lanes.bucket(Lane.IDENTITY).day_used_ms == 120
    store.stopped.add("identity")
    with pytest.raises(StoppedError):
        async with gate.hold(Purpose.IDENTITY, deadline=clock.now + timedelta(seconds=10)):
            pass
    with pytest.raises(ValueError, match="its own"):
        async with gate.hold(Purpose.COLLECT, deadline=clock.now + timedelta(seconds=10)):
            pass
