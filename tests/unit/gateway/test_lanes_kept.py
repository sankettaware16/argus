"""Q-E1's share kept for re-checks (plan §7.8: "2 checks a minute kept for re-checks"): a
request with ``kept`` leaves that many of a rate-limited lane's requests a minute to others,
and their server time (D-130: ``kept`` light calls' worth stays in the bucket), and may always
take the minute's first start. The identity lane is 300 ms a minute (D-130, D-131); a sign-in
keeps 2 (its whoami 3)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.gateway.budget import BudgetConfig, Verdict
from argus.gateway.gateway import LaneGate
from argus.gateway.health import HealthMemory
from argus.gateway.lanes import Lane, LanePlan, LaneSpec, LaneStates, admit, proportional, settle
from argus.gateway.state import MemoryStore
from argus.gateway.templates import CostClass, Purpose
from tests.unit.gateway.fakes import FakeClock

T0 = datetime(2026, 10, 23, 10, 0, tzinfo=UTC)
ROOMY = LaneSpec(per_minute_ms=300, per_day_ms=120_000, per_minute_requests=6)


def plan(per_minute: int = 6) -> LanePlan:
    lanes = proportional(BudgetConfig())
    lanes[Lane.IDENTITY] = LaneSpec(
        per_minute_ms=300, per_day_ms=120_000, per_minute_requests=per_minute
    )
    return LanePlan(BudgetConfig(), lanes)


def run(p: LanePlan, kinds: list[int], spacing: timedelta = timedelta(seconds=1)) -> list[bool]:
    """Admit one request per entry (its ``kept``), settling each at 0 ms; True if admitted."""
    states = LaneStates()
    now = T0
    out = []
    for n, kept in enumerate(kinds):
        admission, states = admit(states, p, Lane.IDENTITY, CostClass.LIGHT, now, scale=1.0,
                                  lease_id=f"l{n}", kept=kept)  # fmt: skip
        out.append(admission.verdict is Verdict.ADMITTED)
        if admission.lease is not None:
            states = settle(states, p, Lane.IDENTITY, admission.lease, 0, now, scale=1.0)
        now += spacing
    return out


def test_signins_leave_two_of_six_to_rechecks() -> None:
    assert run(plan(), [2] * 6) == [True] * 4 + [False] * 2
    assert run(plan(), [2] * 4 + [0] * 3) == [True] * 6 + [False]
    assert run(plan(), [0] * 7) == [True] * 6 + [False]


def test_the_wait_ends_when_one_of_the_limit_frees() -> None:
    p = plan()
    states = LaneStates()
    for n in range(5):  # four sign-ins and a re-check, a second apart
        admission, states = admit(states, p, Lane.IDENTITY, CostClass.LIGHT,
                                  T0 + timedelta(seconds=n), scale=1.0, lease_id=f"l{n}",
                                  kept=2 if n < 4 else 0)  # fmt: skip
        assert admission.lease is not None
        states = settle(states, p, Lane.IDENTITY, admission.lease, 0, T0, scale=1.0)
    now = T0 + timedelta(seconds=5)
    signin, _ = admit(states, p, Lane.IDENTITY, CostClass.LIGHT, now, scale=1.0, lease_id="s",
                      kept=2)  # fmt: skip
    assert signin.verdict is Verdict.WAIT
    assert signin.reason == "request_rate"
    # 5 started, a sign-in may have 4: two must leave the minute, the second at T0 + 1 s
    assert signin.retry_at == T0 + timedelta(seconds=61)
    recheck, _ = admit(states, p, Lane.IDENTITY, CostClass.LIGHT, now, scale=1.0,
                       lease_id="r", kept=0)  # fmt: skip
    assert recheck.verdict is Verdict.ADMITTED


@pytest.mark.parametrize(("per_minute", "signins"), [(1, 1), (2, 1), (3, 1), (4, 2), (6, 4)])
def test_a_signin_may_always_take_one(per_minute: int, signins: int) -> None:
    got = run(plan(per_minute), [2] * 8)
    assert got == [True] * signins + [False] * (8 - signins)


def test_kept_is_never_negative() -> None:
    with pytest.raises(ValueError, match="no fewer than zero"):
        admit(LaneStates(), plan(), Lane.IDENTITY, CostClass.LIGHT, T0, scale=1.0,
              lease_id="x", kept=-1)  # fmt: skip


def test_lanes_without_a_rate_ignore_kept() -> None:
    p = LanePlan()
    states = LaneStates()
    for n in range(8):
        admission, states = admit(states, p, Lane.KIBANA_READ, CostClass.LIGHT,
                                  T0 + timedelta(seconds=n), scale=1.0, lease_id=f"k{n}",
                                  kept=5)  # fmt: skip
        assert admission.verdict is Verdict.ADMITTED
        assert admission.lease is not None
        states = settle(states, p, Lane.KIBANA_READ, admission.lease, 0, T0, scale=1.0)


@given(st.integers(1, 6), st.integers(0, 3), st.integers(0, 10))
def test_admitted_in_a_minute(per_minute: int, kept: int, extra: int) -> None:
    """``kept`` is 0, 2 or 3 in ARGUS (a re-check, a sign-in's verify, its whoami); with the
    lane's 300 ms every such request leaves the kept calls' server time, so only the starts
    rule decides."""
    got = run(plan(per_minute), [kept] * (per_minute + extra))
    assert sum(got) == min(max(per_minute - kept, 1), per_minute + extra)


def test_a_sign_in_that_would_starve_the_rechecks_server_time_waits() -> None:
    """D-130: with the bucket nearly spent, a sign-in's request waits for the refill; a
    re-check (``kept`` 0) and the minute's first request do not."""
    p = plan()
    states = LaneStates()
    admission, states = admit(states, p, Lane.IDENTITY, CostClass.LIGHT, T0, scale=1.0,
                              lease_id="a", kept=2)  # fmt: skip
    assert admission.lease is not None
    states = settle(states, p, Lane.IDENTITY, admission.lease, 240, T0, scale=1.0)  # 60 left
    waiting, _ = admit(states, p, Lane.IDENTITY, CostClass.LIGHT, T0 + timedelta(seconds=1),
                       scale=1.0, lease_id="b", kept=2)  # fmt: skip
    assert waiting.verdict is Verdict.WAIT
    assert waiting.reason == "kept_for_rechecks"
    assert waiting.retry_at is not None
    assert T0 < waiting.retry_at <= T0 + timedelta(seconds=61)
    recheck, _ = admit(states, p, Lane.IDENTITY, CostClass.LIGHT, T0 + timedelta(seconds=1),
                       scale=1.0, lease_id="c", kept=0)  # fmt: skip
    assert recheck.verdict is Verdict.ADMITTED


async def test_lane_gate_passes_kept_and_reports_what_it_saw() -> None:
    clock = FakeClock(T0)
    store = MemoryStore(memory=HealthMemory(probed_at=T0))
    store.stopped.add("collector")
    gate = LaneGate(store, clock=clock, sleep=clock.sleep)
    for _ in range(4):
        async with gate.hold(Purpose.IDENTITY, deadline=T0 + timedelta(seconds=5), kept=2) as s:
            assert (s.health, s.switches) == ("normal", ("collector",))
            s.charge(0)
    from argus.gateway.errors import DeadlinePassedError

    with pytest.raises(DeadlinePassedError, match="request_rate"):
        async with gate.hold(Purpose.IDENTITY, deadline=T0 + timedelta(seconds=5), kept=2):
            pass
    async with gate.hold(Purpose.IDENTITY, deadline=T0 + timedelta(seconds=5)) as s:
        s.charge(0)
