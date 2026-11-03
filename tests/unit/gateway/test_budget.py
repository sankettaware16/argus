"""The server-time budget (plan §5.2, D-022): unit cases, a state machine, and the gate's
1,000-request burst on a fake clock."""

from __future__ import annotations

import random
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, precondition, rule

from argus.gateway.budget import (
    Admission,
    BudgetConfig,
    BudgetState,
    Lease,
    Verdict,
    admit,
    capacity,
    roll,
    settle,
)
from argus.gateway.templates import CostClass

pytestmark = pytest.mark.unit

T0 = datetime(2026, 10, 12, 6, 0, tzinfo=UTC)
CONFIG = BudgetConfig()
P, L, M, H = CostClass.PROBE, CostClass.LIGHT, CostClass.MEDIUM, CostClass.HEAVY


def go(
    state: BudgetState,
    cost: CostClass,
    now: datetime = T0,
    scale: float = 1.0,
    config: BudgetConfig = CONFIG,
    lease_id: str = "x",
) -> tuple[Admission, BudgetState]:
    return admit(state, config, cost, now, scale=scale, lease_id=lease_id)


def s(seconds: float) -> timedelta:
    return timedelta(seconds=seconds)


def test_defaults_are_d022() -> None:
    assert (CONFIG.took_per_minute_ms, CONFIG.burst_ms, CONFIG.took_per_day_ms) == (
        3_000, 3_000, 3_600_000,
    )  # fmt: skip
    assert (CONFIG.concurrency, CONFIG.heavy_concurrency) == (2, 1)
    assert (CONFIG.heavy_per_minute, CONFIG.heavy_per_day) == (6, 2_000)
    assert CONFIG.estimate_ms == {P: 20, L: 50, M: 250, H: 1_000}
    assert CONFIG.lease == timedelta(minutes=2)


def test_a_fresh_budget_starts_full_and_reserves_the_estimate() -> None:
    admission, state = go(BudgetState(), M)
    assert admission.verdict is Verdict.ADMITTED
    assert admission.lease == Lease("x", M, 250, T0 + timedelta(minutes=2))
    assert state.tokens_ms == 3_000 - 250
    assert state.leases == (admission.lease,)


def test_settle_returns_the_estimate_and_charges_took() -> None:
    admission, state = go(BudgetState(), M)
    assert admission.lease is not None
    state = settle(state, CONFIG, admission.lease, 400, T0, scale=1.0)
    assert state.tokens_ms == 3_000 - 400
    assert state.day_used_ms == 400
    assert state.leases == ()
    with pytest.raises(ValueError, match="never negative"):
        settle(state, CONFIG, admission.lease, -1, T0, scale=1.0)


def test_tokens_refill_at_3_seconds_per_minute_up_to_the_burst() -> None:
    state = replace(BudgetState(), tokens_ms=0.0, refilled_at=T0, day=T0.date())
    assert roll(state, CONFIG, T0 + s(30), 1.0).tokens_ms == pytest.approx(1_500)
    assert roll(state, CONFIG, T0 + s(600), 1.0).tokens_ms == 3_000
    assert roll(state, CONFIG, T0 + s(30), 0.5).tokens_ms == pytest.approx(750)
    full = replace(state, tokens_ms=3_000.0)
    assert roll(full, CONFIG, T0, 0.5).tokens_ms == 1_500  # a smaller scale caps at once
    assert roll(state, CONFIG, T0 - s(5), 1.0).tokens_ms == 0  # a clock step back adds nothing


def test_waiting_for_server_time() -> None:
    state = replace(BudgetState(), tokens_ms=100.0, refilled_at=T0, day=T0.date())
    admission, after = go(state, M)
    assert (admission.verdict, admission.reason) == (Verdict.WAIT, "server_time")
    assert admission.retry_at == T0 + s(3)  # 150 ms of tokens at 50 ms/s
    assert after.leases == ()
    admission, _ = go(state, M, scale=0.5)
    assert admission.retry_at == T0 + s(6)
    admission, _ = go(replace(state, tokens_ms=-900.0), L)
    assert admission.retry_at == T0 + s(19)


def test_an_estimate_above_the_scaled_burst_needs_only_a_full_bucket() -> None:
    config = replace(CONFIG, burst_ms=800)
    admission, state = go(BudgetState(), H, config=config)
    assert admission.verdict is Verdict.ADMITTED
    assert state.tokens_ms == -200


def test_concurrency_is_2() -> None:
    state = BudgetState()
    for n in range(2):
        admission, state = go(state, L, lease_id=str(n))
        assert admission.verdict is Verdict.ADMITTED
    admission, _ = go(state, L, lease_id="3")
    assert (admission.verdict, admission.reason) == (Verdict.WAIT, "concurrency")
    assert admission.retry_at == T0 + timedelta(minutes=2)
    admission, _ = go(state, P, lease_id="p")
    assert admission.reason == "concurrency"  # probes share the two slots


def test_an_expired_lease_frees_its_slot_and_its_estimate_stays_charged() -> None:
    state = BudgetState()
    for n in range(2):
        _, state = go(state, M, lease_id=str(n))
    later = T0 + timedelta(minutes=2)
    rolled = roll(state, CONFIG, later, 1.0)
    assert rolled.leases == ()
    assert rolled.day_used_ms == 500
    admission, _ = go(state, M, now=later, lease_id="2")
    assert admission.verdict is Verdict.ADMITTED
    lease = state.leases[0]
    after = settle(rolled, CONFIG, lease, 300, later, scale=1.0)
    assert after.day_used_ms == 500 - 250 + 300  # the estimate is replaced by the real took


def test_heavy_limits() -> None:
    admission, state = go(BudgetState(), H, lease_id="h1")
    assert admission.verdict is Verdict.ADMITTED
    assert (state.heavy_day, state.heavy_starts) == (1, (T0,))
    admission, _ = go(state, H, lease_id="h2")
    assert (admission.verdict, admission.reason) == (Verdict.WAIT, "heavy_concurrency")
    admission, _ = go(state, L, lease_id="l")
    assert admission.verdict is Verdict.ADMITTED  # the second slot takes other work
    starts = tuple(T0 + s(i) for i in range(6))
    busy = replace(BudgetState(), heavy_starts=starts, heavy_day=6)
    admission, _ = go(busy, H, now=T0 + s(10))
    assert (admission.verdict, admission.reason) == (Verdict.WAIT, "heavy_rate")
    assert admission.retry_at == T0 + s(60)
    admission, _ = go(busy, H, now=T0 + s(60))
    assert admission.verdict is Verdict.ADMITTED  # the first start left the minute
    spent = replace(BudgetState(), heavy_day=2_000, day=T0.date())
    admission, _ = go(spent, H)
    assert (admission.verdict, admission.reason) == (Verdict.EXHAUSTED, "heavy_daily")
    admission, _ = go(replace(spent, heavy_day=1_999), H)
    assert admission.verdict is Verdict.ADMITTED


def test_the_daily_cap() -> None:
    near = replace(BudgetState(), day=T0.date(), day_used_ms=3_600_000 - 250)
    admission, _ = go(near, M)
    assert admission.verdict is Verdict.ADMITTED
    admission, _ = go(replace(near, day_used_ms=3_600_000 - 249), M)
    assert (admission.verdict, admission.reason) == (Verdict.EXHAUSTED, "daily")
    _, held = go(replace(near, day_used_ms=3_600_000 - 299), L, lease_id="a")
    admission, _ = go(held, M, lease_id="b")
    assert admission.reason == "daily"  # leases in flight count
    tomorrow = T0 + timedelta(days=1)
    admission, state = go(replace(near, day_used_ms=3_600_000, heavy_day=2_000), H, now=tomorrow)
    assert admission.verdict is Verdict.ADMITTED
    assert (state.day, state.heavy_day) == (tomorrow.date(), 1)


def test_probes_have_their_own_allowance() -> None:
    state = replace(BudgetState(), tokens_ms=-10_000.0, refilled_at=T0, day=T0.date(),
                    day_used_ms=3_600_000)  # fmt: skip
    for n in range(12):
        admission, state = go(state, P, now=T0 + s(n), lease_id=str(n))
        assert admission.verdict is Verdict.ADMITTED, n
        assert admission.lease is not None
        state = settle(state, CONFIG, admission.lease, 5, T0 + s(n), scale=1.0)
    admission, _ = go(state, P, now=T0 + s(30))
    assert (admission.verdict, admission.reason) == (Verdict.WAIT, "probe_rate")
    assert admission.retry_at == T0 + s(60)
    assert state.tokens_ms == pytest.approx(-10_000 + 11 * 50 - 12 * 5)  # refill 11 s, 12 probes


def test_probe_took_is_charged_to_the_bucket_and_the_day() -> None:
    admission, state = go(BudgetState(), P)
    assert admission.lease is not None
    assert state.tokens_ms == 3_000  # nothing reserved
    state = settle(state, CONFIG, admission.lease, 40, T0, scale=1.0)
    assert (state.tokens_ms, state.day_used_ms) == (2_960, 40)


def test_work_needs_a_scale() -> None:
    for scale in (0.0, -1.0, 1.5):
        with pytest.raises(ValueError, match="scale"):
            go(BudgetState(), L, scale=scale)
    admission, _ = go(BudgetState(), P, scale=0.0)
    assert admission.verdict is Verdict.ADMITTED


# --------------------------------------------------------------------------- state machine


class Budget(RuleBasedStateMachine):
    """Random admissions, settlements and clock steps: the server time ARGUS can have charged
    never exceeds what the bucket allowed, and every count limit holds."""

    def __init__(self) -> None:
        super().__init__()
        self.now = T0
        self.state = BudgetState()
        self.open: dict[str, Lease] = {}
        self.charged = 0.0  # took of settled work; estimates of work never settled
        self.n = 0
        self.heavy_starts: list[datetime] = []
        self.probe_starts: list[datetime] = []

    @rule(cost=st.sampled_from([P, L, M, H]))
    def try_admit(self, cost: CostClass) -> None:
        self.n += 1
        lease_id = str(self.n)
        admission, self.state = go(self.state, cost, now=self.now, lease_id=lease_id)
        if admission.verdict is not Verdict.ADMITTED:
            assert admission.retry_at is None or admission.retry_at >= self.now
            return
        assert admission.lease is not None
        self.open[lease_id] = admission.lease
        if cost is H:
            self.heavy_starts.append(self.now)
        if cost is P:
            self.probe_starts.append(self.now)
            return
        in_flight = sum(x.estimate_ms for x in self.open.values() if x.cost is not P)
        allowed = CONFIG.burst_ms + CONFIG.took_per_minute_ms * self.elapsed_ms() / 60_000
        assert self.charged + in_flight <= allowed + 1e-6

    def elapsed_ms(self) -> float:
        return (self.now - T0).total_seconds() * 1000

    @precondition(lambda self: self.open)
    @rule(data=st.data(), took=st.integers(0, 3_000))
    def finish(self, data: st.DataObject, took: int) -> None:
        lease_id = data.draw(st.sampled_from(sorted(self.open)))
        lease = self.open.pop(lease_id)
        self.state = settle(self.state, CONFIG, lease, took, self.now, scale=1.0)
        self.charged += took

    @rule(seconds=st.integers(0, 150))
    def wait(self, seconds: int) -> None:
        self.now += s(seconds)
        for lease_id, lease in list(self.open.items()):
            if lease.expires <= self.now:  # its process died: never settled
                del self.open[lease_id]
                self.charged += lease.estimate_ms if lease.cost is not P else 0

    @invariant()
    def limits(self) -> None:
        live = [x for x in self.state.leases if x.expires > self.now]
        assert len(live) <= CONFIG.concurrency
        assert sum(1 for x in live if x.cost is H) <= CONFIG.heavy_concurrency
        minute = [t for t in self.heavy_starts if self.now - t < timedelta(minutes=1)]
        assert len(minute) <= CONFIG.heavy_per_minute
        probes = [t for t in self.probe_starts if self.now - t < timedelta(minutes=1)]
        assert len(probes) <= CONFIG.probes_per_minute


TestBudget = Budget.TestCase
TestBudget.settings = settings(max_examples=max(50, settings().max_examples), deadline=None)


# --------------------------------------------------------------------------- a burst and a scale

BURST = BudgetConfig(
    took_per_minute_ms=200,
    burst_ms=60_000,
    strained_burst_ms=200,
    took_per_day_ms=10**9,  # the day's share is not what these test
)
SCALES = (1.0, 0.5, 0.25, 0.1)
SLACK = max(CONFIG.estimate_ms.values())  # a call admitted on a bucket smaller than its estimate


class BurstBudget(RuleBasedStateMachine):
    """The write lane's shape (D-235, D-242): a 60 s capacity at full scale and a minute's share
    scaled below it, with the scale changing at random (CAUTION, DEGRADED, a slow start after a
    recovery, and back). Whatever the scale does, the bucket never holds more than its capacity at
    the scale it was last rolled at, and the server time spent never exceeds the initial capacity
    plus the refill at the scales each stretch was rolled at (clipping a full bucket only takes
    tokens away; the refill of a stretch is paid at the scale of the roll that ends it)."""

    def __init__(self) -> None:
        super().__init__()
        self.now = T0
        self.scale = 1.0
        self.state = BudgetState()
        self.open: dict[str, Lease] = {}
        self.charged = 0.0
        self.allowed = float(BURST.burst_ms)  # at most: a new bucket starts full at full scale
        self.unrolled = 0  # minutes waited since the bucket was last rolled
        self.n = 0

    def rolled_now(self) -> None:
        """A roll is about to happen at the current scale: the stretch since the last one is
        refilled at that scale."""
        self.allowed += self.unrolled * BURST.took_per_minute_ms * self.scale
        self.unrolled = 0

    @rule(cost=st.sampled_from([L, M, H]))
    def try_admit(self, cost: CostClass) -> None:
        self.n += 1
        name = str(self.n)
        self.rolled_now()
        admission, self.state = admit(
            self.state, BURST, cost, self.now, scale=self.scale, lease_id=name
        )
        assert self.state.tokens_ms is not None
        assert self.state.tokens_ms <= capacity(BURST, self.scale) + 1e-6
        if admission.verdict is Verdict.ADMITTED:
            assert admission.lease is not None
            self.open[name] = admission.lease
        in_flight = sum(x.estimate_ms for x in self.open.values())
        assert self.charged + in_flight <= self.allowed + SLACK + 1e-6

    @precondition(lambda self: self.open)
    @rule(data=st.data(), took=st.integers(0, 3_000))
    def finish(self, data: st.DataObject, took: int) -> None:
        name = data.draw(st.sampled_from(sorted(self.open)))
        lease = self.open.pop(name)
        self.rolled_now()
        self.state = settle(self.state, BURST, lease, took, self.now, scale=self.scale)
        self.charged += took

    @rule(scale=st.sampled_from(SCALES))
    def the_health_changes(self, scale: float) -> None:
        self.scale = scale

    @rule(minutes=st.integers(0, 600))
    def wait(self, minutes: int) -> None:
        self.now += timedelta(minutes=minutes)
        self.unrolled += minutes
        for name, lease in list(self.open.items()):
            if lease.expires <= self.now:  # its process died: never settled
                del self.open[name]
                self.charged += lease.estimate_ms

    @invariant()
    def no_burst_below_full_scale(self) -> None:
        if self.scale < 1.0 and self.state.tokens_ms is not None:
            rolled = roll(self.state, BURST, self.now, self.scale)
            assert rolled.tokens_ms is not None
            assert rolled.tokens_ms <= BURST.strained_burst_ms * self.scale + 1e-6


TestBurstBudget = BurstBudget.TestCase
TestBurstBudget.settings = settings(max_examples=max(50, settings().max_examples), deadline=None)


@pytest.mark.parametrize(("scale", "want"), [(1.0, 60_000), (0.5, 100), (0.25, 50), (0.1, 20)])
def test_the_capacity_is_the_burst_at_full_scale_and_a_scaled_minute_below_it(
    scale: float, want: float
) -> None:
    assert capacity(BURST, scale) == want
    full = roll(BudgetState(), BURST, T0, scale)
    assert full.tokens_ms == want  # a new bucket starts full, at this scale


def test_a_full_burst_is_cut_to_the_strained_capacity_at_the_next_roll_below_full_scale() -> None:
    state = roll(BudgetState(), BURST, T0, 1.0)
    assert state.tokens_ms == 60_000
    caution = roll(state, BURST, T0 + timedelta(seconds=1), 0.5)  # a CAUTION blip
    assert caution.tokens_ms == pytest.approx(100)
    back = roll(caution, BURST, T0 + timedelta(minutes=10), 1.0)  # and the burst is gone
    assert back.tokens_ms == pytest.approx(100 + 599 / 60 * 200)  # 599 s of refill at 200 ms/min


def test_the_burst_comes_back_only_by_the_refill_after_a_blip() -> None:
    state = roll(roll(BudgetState(), BURST, T0, 1.0), BURST, T0, 0.5)
    five_hours = roll(state, BURST, T0 + timedelta(hours=5), 1.0)
    assert five_hours.tokens_ms == pytest.approx(60_000)
    one_hour = roll(state, BURST, T0 + timedelta(hours=1), 1.0)
    assert one_hour.tokens_ms == pytest.approx(100 + 12_000)


# --------------------------------------------------------------------------- 1,000-request burst


def test_a_1000_request_burst_on_a_fake_clock_holds_the_budget() -> None:
    """1,000 requests all want to go at once. Event-driven fake clock: it jumps to the next
    retry time or completion. Each request runs its took plus 50 ms; took is up to twice the
    estimate. At every admission the server time charged so far stays within what the bucket
    allowed; concurrency and heavy limits hold throughout."""
    rnd = random.Random(20261012)
    costs = [rnd.choice([L, L, L, M, M, H]) for _ in range(1_000)]
    pending = list(range(1_000))
    running: dict[int, tuple[Lease, datetime, int]] = {}
    state = BudgetState()
    now = T0
    took_total = 0
    heavy_starts: list[datetime] = []
    admitted = 0
    while pending or running:
        for index, (lease, ends, took) in list(running.items()):
            if ends <= now:
                state = settle(state, CONFIG, lease, took, now, scale=1.0)
                took_total += took
                del running[index]
        retry: list[datetime] = []
        for index in list(pending):
            admission, state = go(state, costs[index], now=now, lease_id=str(index))
            assert admission.verdict is not Verdict.EXHAUSTED
            if admission.verdict is Verdict.WAIT:
                assert admission.retry_at is not None
                retry.append(admission.retry_at)
                if admission.reason in {"server_time", "concurrency"}:
                    break  # nobody else can go now either
                continue
            assert admission.lease is not None
            admitted += 1
            took = rnd.randint(0, 2 * admission.lease.estimate_ms)
            running[index] = (admission.lease, now + timedelta(milliseconds=took + 50), took)
            pending.remove(index)
            if costs[index] is H:
                heavy_starts.append(now)
            allowed = CONFIG.burst_ms + CONFIG.took_per_minute_ms * (now - T0).total_seconds() / 60
            in_flight = sum(lease.estimate_ms for lease, _, _ in running.values())
            assert took_total + in_flight <= allowed + 1e-6
            assert len(running) <= 2
            assert sum(1 for lease, _, _ in running.values() if lease.cost is H) <= 1
        events = [ends for _, ends, _ in running.values()] + retry
        if events:
            now = max(min(events), now + timedelta(milliseconds=1))
    elapsed_min = (now - T0).total_seconds() / 60
    assert admitted == 1_000
    assert took_total <= CONFIG.burst_ms + CONFIG.took_per_minute_ms * elapsed_min + 2 * 2_000
    for start in heavy_starts:
        assert sum(1 for t in heavy_starts if start <= t < start + timedelta(minutes=1)) <= 6


def test_below_full_scale_a_stored_full_burst_admits_only_a_scaled_minutes_share() -> None:
    """A bucket stored full (60 s) and then asked at CAUTION: the first roll cuts it to 100 ms, so
    two light calls (50 ms each) go and the third waits for the refill, as before AR9's burst."""
    config = replace(BURST, concurrency=10)  # (the leases stay open: concurrency is not the point)
    state = roll(BudgetState(), config, T0, 1.0)
    admitted = 0
    for n in range(5):
        admission, state = admit(state, config, L, T0, scale=0.5, lease_id=f"c{n}")
        admitted += admission.verdict is Verdict.ADMITTED
    assert admitted == 2
    assert admission.verdict is Verdict.WAIT
    assert admission.reason == "server_time"
