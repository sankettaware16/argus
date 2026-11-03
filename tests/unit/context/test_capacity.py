"""The capacity model (plan §11, D-054): R6's queue rules and the real budget code."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from argus.context.capacity import (
    LATENCY,
    PROFILES,
    Latency,
    Profile,
    Report,
    Scenario,
    busiest_start,
    full_days,
    rate_at,
    simulate,
)
from argus.gateway.budget import BudgetConfig
from argus.gateway.templates import CostClass

pytestmark = pytest.mark.unit

T0 = datetime(2026, 10, 9, 6, tzinfo=UTC)
M, L, H = CostClass.MEDIUM, CostClass.LIGHT, CostClass.HEAVY
FIXED = Latency({L: 20, M: 100, H: 500}, {L: 20.001, M: 100.001, H: 500.001})


def stream(investigations: int, every: timedelta, changes: int) -> list[tuple[datetime, int]]:
    return [(T0 + every * k, inv) for inv in range(investigations) for k in range(changes)]


def test_the_same_inputs_give_the_same_report() -> None:
    changes = stream(30, timedelta(minutes=7), 12)
    a = simulate(changes, Scenario(PROFILES["medium"], LATENCY, seed=3))
    b = simulate(changes, Scenario(PROFILES["medium"], LATENCY, seed=3))
    assert a == b
    assert simulate([], Scenario(PROFILES["small"], LATENCY)).runs == {}


def test_changes_are_coalesced_like_the_queue() -> None:
    """A new investigation runs at once; changes within 30 minutes of the last run wait for
    one run 30 minutes later; a change during a run queues one more."""
    burst = [(T0 + timedelta(seconds=s), 1) for s in range(0, 600, 10)]  # 60 changes, 10 min
    report = simulate(burst, Scenario(Profile("p", (M,), (M,)), FIXED))
    assert report.runs == {"created": 1, "new_alerts": 1}
    assert report.requests == 2
    assert report.unfinished == 0


def test_a_local_only_profile_costs_nothing_and_waits_for_nothing() -> None:
    changes = stream(50, timedelta(minutes=3), 40)
    report = simulate(changes, Scenario(PROFILES["stub"], LATENCY))
    assert report.enrich_ms_by_day == {}
    assert report.requests == 0
    assert report.max_wait_s == 0
    collector = sum(report.collector_ms_by_day.values())
    minutes = (max(changes)[0] - T0).total_seconds() / 60 + 12 * 60
    assert collector == pytest.approx(120 * minutes, rel=0.02)  # ids + mget every minute


def test_an_outage_defers_then_the_backlog_drains_after_a_slow_start() -> None:
    changes = stream(80, timedelta(minutes=5), 60)
    outage = (T0 + timedelta(hours=1), T0 + timedelta(hours=4))
    profile = Profile("p", (M, M, L), (M,))
    hit = simulate(changes, Scenario(profile, FIXED, outage=outage))
    calm = simulate(changes, Scenario(profile, FIXED))
    assert hit.drained_after is not None
    assert timedelta(0) < hit.drained_after < timedelta(hours=6)
    assert hit.max_wait_s >= 3 * 3600  # jobs due at the outage's start waited it out
    assert calm.max_wait_s < 600
    assert hit.unfinished == calm.unfinished == 0
    assert calm.drained_after is None


def test_the_daily_cap_turns_into_skipped_budget_never_into_missing_work() -> None:
    changes = stream(400, timedelta(minutes=2), 30)
    tight = BudgetConfig(took_per_day_ms=120_000)  # 2 minutes of server time a day
    report = simulate(changes, Scenario(Profile("p", (H, H), (H,)), FIXED, budget=tight))
    assert report.skipped > 0
    for day, used in report.enrich_ms_by_day.items():
        assert used + report.collector_ms_by_day.get(day, 0) <= tight.took_per_day_ms + 2 * 500
    assert report.requests == sum(
        len(Profile("p", (H, H), (H,)).first if t == "created" else (H,)) * n
        for t, n in report.runs.items()
    )


def test_more_server_time_per_run_uses_more_of_the_cap() -> None:
    changes = stream(60, timedelta(minutes=4), 30)
    days = ["2026-10-09"]
    shares = [
        simulate(changes, Scenario(PROFILES[name], LATENCY)).share(BudgetConfig(), days)
        for name in ("stub", "small", "medium", "rich")
    ]
    assert shares == sorted(shares)
    assert shares[0] == 0 < shares[1]


def test_helpers() -> None:
    changes = [(T0 + timedelta(minutes=m), 1) for m in (0, 10, 70, 75, 80)]
    assert rate_at(changes, T0 + timedelta(minutes=81)) == 3
    assert rate_at(changes, T0 + timedelta(minutes=30), timedelta(minutes=30)) == 2
    assert busiest_start(changes, timedelta(minutes=15)) == T0
    assert full_days([(T0, 1), (T0 + timedelta(days=3), 1)]) == ["2026-10-10", "2026-10-11"]
    assert full_days([]) == []
    assert Scenario(PROFILES["stub"], LATENCY).budget == BudgetConfig()


def test_a_simulation_that_does_not_settle_stops_instead_of_filling_memory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import argus.context.capacity as capacity

    changes = stream(5, timedelta(minutes=3), 4)
    monkeypatch.setattr(capacity, "EVENTS_PER_INPUT", 1)
    with pytest.raises(RuntimeError, match="did not settle"):
        simulate(changes, Scenario(PROFILES["small"], LATENCY))
    monkeypatch.setattr(capacity, "EVENTS_PER_INPUT", 200)
    assert simulate(changes, Scenario(PROFILES["small"], LATENCY)).unfinished == 0


# ----------------------------------------------------------------------------- exact scenarios
# Fixed server times (median = p95: no spread) make every number below computable by hand.
EXACT = Latency({L: 20, M: 100, H: 500}, {L: 20, M: 100, H: 500})


def test_an_exact_steady_scenario() -> None:
    """inv 1 at 0, 10 and 50 min, inv 2 at 5 min; first run M+L (100 + 20 ms), re-run M."""
    minute = timedelta(minutes=1)
    changes = [(T0, 1), (T0 + 5 * minute, 2), (T0 + 10 * minute, 1), (T0 + 50 * minute, 1)]
    r = simulate(changes, Scenario(Profile("p", (M, L), (M,)), EXACT))
    # the re-runs wait for the coalescing: 30 min after the previous run finished
    assert r.runs == {"created": 2, "new_alerts": 2}
    assert (r.requests, r.skipped, r.unfinished) == (6, 0, 0)
    assert r.enrich_ms_by_day == {"2026-10-09": 2 * (100 + 20) + 2 * 100}
    # a poll a minute until 12 h after the last change; the last poll's mget falls after the end
    assert r.collector_ms_by_day == {"2026-10-09": 771 * (10 + 110) - 110}
    assert r.busiest_minute_ms == 120 + 100 + 20
    # due to dossier: M, L and two round trips of 15 ms; re-runs M only
    assert sorted(r.waits) == pytest.approx([0.115, 0.115, 0.15, 0.15])
    assert (r.max_wait_s, r.p95_wait_s) == pytest.approx((0.15, 0.15))
    assert (r.backlog_peak, r.drained_after) == (0, None)
    assert r.share(BudgetConfig()) == pytest.approx(440 / 3_600_000)
    assert r.share(BudgetConfig(), ["2026-10-09", "2026-10-10"]) == pytest.approx(220 / 3_600_000)
    assert Report().share(BudgetConfig()) == 0.0


def test_an_exact_outage_scenario() -> None:
    """A job due 1 min into a 30 min outage is deferred 1, 2, 4, 8, 10, 10 min (at 1, 2, 4,
    8, 16, 26) and runs at 36 min, in the slow start; the backlog is gone at the next poll."""
    minute = timedelta(minutes=1)
    outage = (T0, T0 + 30 * minute)
    r = simulate([(T0 + minute, 1)], Scenario(Profile("p", (M,), ()), EXACT, outage=outage))
    assert r.runs == {"created": 1}
    assert r.requests == 1
    assert r.max_wait_s == pytest.approx(35 * 60 + 0.115)
    assert r.drained_after == 7 * minute
    # no polls in the outage; the last poll's mget falls after the end
    assert r.collector_ms_by_day == {"2026-10-09": (721 - 29) * 120 - 110}
    assert r.enrich_ms_by_day == {"2026-10-09": 100}


def test_the_slow_start_after_an_outage() -> None:
    from argus.context.capacity import _Sim

    minute = timedelta(minutes=1)
    sim = _Sim([(T0, 1)], Scenario(PROFILES["stub"], LATENCY, outage=(T0, T0 + 60 * minute)))
    end = T0 + 60 * minute
    assert [sim.scale(t) for t in (T0 - minute, T0, end - timedelta(seconds=1))] == [1.0, 0, 0]
    assert sim.scale(end) == 0.25
    assert sim.scale(end + 20 * minute - timedelta(seconds=1)) == 0.25
    assert sim.scale(end + 20 * minute) == 0.5
    assert sim.scale(end + 40 * minute - timedelta(seconds=1)) == 0.5
    assert sim.scale(end + 40 * minute) == 1.0
    assert _Sim([(T0, 1)], Scenario(PROFILES["stub"], LATENCY)).scale(T0) == 1.0


def test_server_times_follow_the_median_and_95th_percentile() -> None:
    import random

    rng = random.Random(1)
    samples = sorted(LATENCY.sample(M, rng) for _ in range(20_000))
    assert samples[10_000] == pytest.approx(150, rel=0.05)
    assert samples[19_000] == pytest.approx(600, rel=0.07)
    assert EXACT.sample(L, rng) == 20
    assert Latency({L: 0.2}, {L: 0.2}).sample(L, rng) == 1  # never below 1 ms


def test_a_full_gateway_is_asked_again_every_half_second_like_the_real_one() -> None:
    """Both slots busy with heavy queries when the collector polls: like the gateway (POLL),
    the model asks again 0.5 s later, not when the leases would expire (2 min)."""
    from argus.context.capacity import _Sim

    start = T0 + timedelta(seconds=59.8)  # two 300 ms runs hold both slots over the minute
    slow = Latency({L: 20, M: 300}, {L: 20, M: 300})
    sim = _Sim([(start, 1), (start, 2)], Scenario(Profile("p", (M,), ()), slow))
    sim.run()
    minute = T0.replace(second=0) + timedelta(minutes=1)
    assert sim.by_minute[minute] == 120  # this minute's poll ran in this minute


def test_the_documented_assumptions() -> None:
    """Changing these changes every capacity result: on purpose only (D-054, gate report)."""
    from argus.context import capacity

    median = {CostClass.PROBE: 10, L: 30, M: 150, H: 800}
    p95 = {CostClass.PROBE: 30, L: 200, M: 600, H: 3000}
    assert Latency(median, p95) == capacity.LATENCY
    assert {n: (p.first, p.rerun) for n, p in PROFILES.items()} == {
        "stub": ((), ()),
        "small": ((M, M, L), (M,)),
        "rich-rederive": ((M, M, M, M, H, L, L), ()),
        "medium": ((M, M, M, H, L), (M, H)),
        "rich": ((M, M, M, M, H, L, L), (M, M, H)),
    }
    assert ((timedelta(minutes=20), 0.25), (timedelta(minutes=40), 0.5)) == capacity.SLOW_START
    assert (capacity.NETWORK_MS, capacity.EVENTS_PER_INPUT) == (15, 200)
    scenario = Scenario(PROFILES["stub"], LATENCY)
    assert (scenario.runs_at_once, scenario.collector_ms, scenario.outage, scenario.seed) == (
        2, (10, 110), None, 0)  # fmt: skip


def test_a_change_while_running_runs_again_after_the_coalescing() -> None:
    """The change at 50 ms lands while the first run (H: 500 + 15 ms) is in flight."""
    ms = timedelta(milliseconds=1)
    r = simulate([(T0, 1), (T0 + 50 * ms, 1)], Scenario(Profile("p", (H,), (M,)), EXACT))
    assert r.runs == {"created": 1, "changed_while_running": 1}
    assert (r.requests, r.unfinished) == (2, 0)
    assert sorted(r.waits) == pytest.approx([0.115, 0.515])


def test_a_burst_waits_in_the_queue_two_at_a_time() -> None:
    """Twelve new investigations at once, two runs in flight: ten wait at the next poll."""
    r = simulate([(T0, i) for i in range(12)], Scenario(Profile("p", (H, H), ()), EXACT))
    assert r.runs == {"created": 12}
    assert (r.backlog_peak, len(r.waits), r.unfinished) == (10, 12, 0)
    assert sorted(r.waits)[:2] == pytest.approx([1.03, 2.06])
    assert (r.max_wait_s, r.p95_wait_s) == pytest.approx((200.115, 200.115))
    wide = simulate([(T0, i) for i in range(40)], Scenario(Profile("p", (H,), ()), EXACT))
    assert wide.backlog_peak == 38
    assert (wide.max_wait_s, wide.p95_wait_s) == pytest.approx((367.315, 361.545))
