"""The enrichment lane and the poll's reserve (D-321): enrichment, however slow and however much
of it, never refuses the collector's poll; backfill and reconciliation leave the poll
``POLL_RESERVE_MS`` of the collector's bucket; the split adds no load (the lanes still add up
to the ceiling); a lanes row stored before the lane existed starts it full."""

from __future__ import annotations

import contextlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.gateway import budget
from argus.gateway.budget import BudgetConfig, BudgetState, Verdict
from argus.gateway.builtin import AlertIds, AlertIdsParams
from argus.gateway.errors import BudgetExhaustedError, DeadlinePassedError, LaneBusyError
from argus.gateway.health import HealthMemory
from argus.gateway.lanes import (
    DEFAULT_LANES,
    KEEPS_FOR_POLL,
    POLL_RESERVE_MS,
    SHARE_TOTALS,
    SHARES,
    Lane,
    LanePlan,
    kept_for_poll,
    lane_of,
)
from argus.gateway.pgstore import lanes_from_json, lanes_to_json
from argus.gateway.state import MemoryStore
from argus.gateway.templates import CostClass, Purpose
from tests.unit.gateway.fakes import T0 as START
from tests.unit.gateway.fakes import make, search_answer

pytestmark = pytest.mark.unit
T0 = datetime(2026, 11, 13, 18, 19, tzinfo=UTC)


def test_the_split_takes_only_the_collectors_former_share() -> None:
    """1,400 ms a minute, 30 minutes a day and 1,500 heavy queries were the collector's; the
    collector and enrichment share exactly that now, and the lanes add up to the ceiling."""
    together = [SHARES[Lane.COLLECTOR], SHARES[Lane.ENRICHMENT]]
    assert tuple(sum(x[i] for x in together) for i in range(3)) == (1_400, 30, 1_500)
    for i, total in enumerate(SHARE_TOTALS):
        assert sum(share[i] for share in SHARES.values()) == total
    LanePlan()  # within the ceiling
    assert DEFAULT_LANES[Lane.ENRICHMENT].concurrency == 1  # never both slots: one is the poll's


def test_only_backfill_and_reconciliation_keep_a_reserve_for_the_poll() -> None:
    assert frozenset({Purpose.BACKFILL, Purpose.RECONCILE}) == KEEPS_FOR_POLL
    for purpose in Purpose:
        expected = POLL_RESERVE_MS if purpose in KEEPS_FOR_POLL else 0
        assert kept_for_poll(purpose) == expected
        assert kept_for_poll(purpose, "collector") == expected
        assert kept_for_poll(purpose, "writeback") == 0
        if purpose in KEEPS_FOR_POLL:
            assert lane_of(purpose) is Lane.COLLECTOR


def _collector() -> BudgetConfig:
    return LanePlan().config(Lane.COLLECTOR)


def test_a_reserve_waits_until_the_bucket_holds_the_estimate_and_the_reserve() -> None:
    config = _collector()
    state = BudgetState(tokens_ms=3_100.0, refilled_at=T0, day=T0.date())
    waiting, _ = budget.admit(state, config, CostClass.MEDIUM, T0, scale=1.0, lease_id="r",
                              kept_ms=POLL_RESERVE_MS)  # fmt: skip
    assert (waiting.verdict, waiting.reason) == (Verdict.WAIT, "server_time")
    # 150 ms short at 600 ms a minute: 15 s
    assert waiting.retry_at == T0 + timedelta(seconds=15)
    polled, after = budget.admit(state, config, CostClass.LIGHT, T0, scale=1.0, lease_id="p")
    assert polled.verdict is Verdict.ADMITTED  # the poll takes what the reserve kept
    assert after.tokens_ms == 3_050.0
    with pytest.raises(ValueError, match="keeps no less"):
        budget.admit(state, config, CostClass.LIGHT, T0, scale=1.0, lease_id="x", kept_ms=-1)


def test_a_full_bucket_at_full_scale_always_admits_whatever_the_reserve() -> None:
    """Never a request that can never start: at full scale a full bucket admits, even when the
    reserve is larger than the bucket; below it, a request without a reserve still does."""
    config = _collector()
    full = BudgetState(tokens_ms=budget.capacity(config, 1.0), refilled_at=T0, day=T0.date())
    admission, _ = budget.admit(full, config, CostClass.MEDIUM, T0, scale=1.0, lease_id="r",
                                kept_ms=50_000)  # fmt: skip
    assert admission.verdict is Verdict.ADMITTED
    for scale in (0.5, 0.25, 0.1):
        small = BudgetState(tokens_ms=budget.capacity(config, scale), refilled_at=T0,
                            day=T0.date())  # fmt: skip
        plain, _ = budget.admit(small, config, CostClass.MEDIUM, T0, scale=scale, lease_id="p")
        assert plain.verdict is Verdict.ADMITTED


@settings(max_examples=300)
@given(
    tokens=st.floats(-20_000, 10_000),
    kept=st.integers(0, 20_000),
    cost=st.sampled_from([CostClass.LIGHT, CostClass.MEDIUM, CostClass.HEAVY]),
    scale=st.sampled_from([1.0, 0.5, 0.25, 0.1]),
)
def test_an_admission_with_a_reserve_leaves_it(
    tokens: float, kept: int, cost: CostClass, scale: float
) -> None:
    config = _collector()
    state = BudgetState(tokens_ms=tokens, refilled_at=T0, day=T0.date())
    admission, after = budget.admit(state, config, cost, T0, scale=scale, lease_id="x",
                                    kept_ms=kept)  # fmt: skip
    plain, _ = budget.admit(state, config, cost, T0, scale=scale, lease_id="x")
    estimate = config.estimate_ms[cost]
    # a reserve counts against the full-scale bucket; nothing kept, against today's
    full = budget.capacity(config, 1.0 if kept else scale)
    if admission.verdict is Verdict.ADMITTED:
        assert plain.verdict is Verdict.ADMITTED  # a reserve only ever asks for more
        assert after.tokens_ms is not None
        assert after.tokens_ms >= min(kept, full - estimate) - 1e-6
    else:  # what the bucket held (never above today's capacity) was short of the need
        assert min(tokens, budget.capacity(config, scale)) < min(estimate + kept, full)


def _store() -> MemoryStore:
    """The gateway's state as production builds it: the collector's bucket is its lane's."""
    plan = LanePlan()
    return MemoryStore(memory=HealthMemory(probed_at=START), budget_config=plan.config(
        Lane.COLLECTOR), lane_plan=plan)  # fmt: skip


async def _poll(gateway: object, clock: object) -> None:
    now = clock.now  # type: ignore[attr-defined]
    await gateway.run(  # type: ignore[attr-defined]
        AlertIds(), AlertIdsParams(start=now - timedelta(minutes=5), end=now),
        purpose=Purpose.COLLECT, component="collector", deadline=now + timedelta(seconds=30),
    )  # fmt: skip


@settings(max_examples=60, deadline=None)
@given(tooks=st.lists(st.integers(0, 6_500), min_size=1, max_size=60))
async def test_a_burst_of_slow_evidence_never_refuses_the_poll(tooks: list[int]) -> None:
    """Production's evening (13 Nov, D-321): enrichment spent the shared bucket into debt and
    the next poll was refused before it was sent (``lane_busy``), opening a gap. Now any run
    of evidence requests, each up to 6.5 s of server time, leaves the poll admitted at once."""
    gateway, transport, store, clock = make(store=_store())

    async def sleep(seconds: float) -> None:  # the probe keeps running meanwhile
        await clock.sleep(seconds)
        store.memory = HealthMemory(probed_at=clock.now)

    gateway.sleep = sleep
    for n, took in enumerate(tooks):
        transport.default = search_answer(took=took)
        with contextlib.suppress(BudgetExhaustedError, DeadlinePassedError):
            await gateway.run(
                AlertIds(), AlertIdsParams(start=clock.now - timedelta(minutes=5), end=clock.now),
                purpose=Purpose.ENRICH, component="enrichment",
                deadline=clock.now + timedelta(minutes=4),
            )  # fmt: skip
        assert store.ledger[-1].lane in ("enrichment", None), n
    transport.default = search_answer(took=40)
    slept = list(clock.slept)
    await _poll(gateway, clock)
    assert clock.slept == slept  # the poll did not wait
    assert store.ledger[-1].lane == "collector"
    assert store.ledger[-1].outcome == "ok"
    assert store.budget.day_used_ms == 40  # the collector's bucket paid only for the poll


async def test_reconciliation_cannot_take_the_polls_reserve() -> None:
    gateway, transport, store, clock = make(store=_store())
    store.budget = BudgetState(tokens_ms=2_900.0, refilled_at=clock.now, day=clock.now.date())
    with pytest.raises(LaneBusyError):  # a light count needs 3,050: 15 s of refill, too late
        await gateway.run(
            AlertIds(), AlertIdsParams(start=clock.now - timedelta(minutes=5), end=clock.now),
            purpose=Purpose.RECONCILE, component="collector",
            deadline=clock.now + timedelta(seconds=5),
        )  # fmt: skip
    assert transport.calls == []
    await _poll(gateway, clock)  # the reserve is the poll's
    assert store.ledger[-1].outcome == "ok"


def test_a_lanes_row_from_before_the_lane_starts_it_full() -> None:
    """Production's ``siem_state`` 'lanes' row holds the other lanes' buckets: read now, the
    enrichment lane is missing from it and starts full; a lane no longer known is dropped."""
    used = BudgetState(tokens_ms=-500.0, refilled_at=T0, day=T0.date(), day_used_ms=9_000)
    stored = lanes_to_json(replace(
        lanes_from_json({}), buckets={Lane.INVESTIGATION: used, Lane.CHECKING: used},
    ))  # fmt: skip
    assert set(stored["buckets"]) == {"investigation", "checking"}
    stored["buckets"]["retired"] = stored["buckets"]["checking"]
    stored["starts"] = {"identity": [T0.isoformat()], "retired": [T0.isoformat()]}
    states = lanes_from_json(stored)
    assert set(states.buckets) == {Lane.INVESTIGATION, Lane.CHECKING}
    assert set(states.starts) == {Lane.IDENTITY}
    fresh = states.bucket(Lane.ENRICHMENT)
    assert fresh == BudgetState()
    plan = LanePlan()
    rolled = budget.roll(fresh, plan.config(Lane.ENRICHMENT), T0, 1.0)
    assert rolled.tokens_ms == plan.config(Lane.ENRICHMENT).burst_ms == 10_000


# --------------------------------------------------------------------------- review (D-321)


async def test_a_reconciliation_count_as_slow_as_production_s_never_refuses_the_next_poll() -> None:
    """A count of reconciliation costs ~1.8 s of server time on production (~170 s a day over
    at least 96 counts), far above its light estimate. Admitted on a bucket holding just its
    estimate and the reserve, it must still leave a debt the poll can wait out within its 30 s
    (300 ms of refill at 600 ms a minute): else the poll after it is refused, a gap."""
    gateway, transport, store, clock = make(store=_store())
    store.budget = BudgetState(tokens_ms=1_100.0, refilled_at=clock.now, day=clock.now.date())
    transport.default = search_answer(took=1_800)
    with contextlib.suppress(LaneBusyError):
        await gateway.run(
            AlertIds(), AlertIdsParams(start=clock.now - timedelta(minutes=5), end=clock.now),
            purpose=Purpose.RECONCILE, component="collector",
            deadline=clock.now + timedelta(seconds=30),
        )  # fmt: skip
    transport.default = search_answer(took=40)
    await _poll(gateway, clock)
    assert store.ledger[-1].lane == "collector"
    assert store.ledger[-1].outcome == "ok"


def test_in_a_slow_start_backfill_and_reconciliation_wait_for_the_full_bucket() -> None:
    """After a CAUTION spell the bucket holds a quarter or half of a minute's share (150-300 ms)
    and refills as slowly: a count admitted on that full little bucket costs ~1.8 s, a debt
    the poll cannot wait out for many minutes. The reserve is kept from the full-scale bucket,
    so backfill and reconciliation wait for full health; the poll goes on."""
    config = _collector()
    for scale in (0.5, 0.25, 0.1):
        full = BudgetState(tokens_ms=budget.capacity(config, scale), refilled_at=T0,
                           day=T0.date())  # fmt: skip
        held, _ = budget.admit(full, config, CostClass.LIGHT, T0, scale=scale, lease_id="r",
                               kept_ms=POLL_RESERVE_MS)  # fmt: skip
        assert held.verdict is Verdict.WAIT, scale
        polled, _ = budget.admit(full, config, CostClass.LIGHT, T0, scale=scale, lease_id="p")
        assert polled.verdict is Verdict.ADMITTED, scale


async def test_the_writebacks_last_look_keeps_no_reserve() -> None:
    """The write-back sender reads the alerts once more on the collector's lane (purpose
    reconcile) while it holds the one slot the other lanes share: a reserve would keep it, and
    every lane waiting behind it, for minutes. Only the collector's own work keeps one."""
    assert kept_for_poll(Purpose.RECONCILE, "writeback") == 0
    assert kept_for_poll(Purpose.RECONCILE, "collector") == POLL_RESERVE_MS
    gateway, _transport, store, clock = make(store=_store())
    store.budget = BudgetState(tokens_ms=900.0, refilled_at=clock.now, day=clock.now.date())
    await gateway.run(
        AlertIds(), AlertIdsParams(start=clock.now - timedelta(minutes=5), end=clock.now),
        purpose=Purpose.RECONCILE, component="writeback",
        deadline=clock.now + timedelta(seconds=5),
    )  # fmt: skip
    assert store.ledger[-1].outcome == "ok"
