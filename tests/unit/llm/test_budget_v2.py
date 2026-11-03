"""The budget's v2 parts (Q-G1): breakers per model and per provider, ARGUS's own exact caps,
leases, latencies and slowness, alarms, probes, and the JSON round trip of all of it."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.gateway import breaker as breaker_core
from argus.llm import budget
from argus.llm.budget import Alarm, Ask, Bucket, Config, Limits, Priority, State

pytestmark = pytest.mark.unit
NOW = datetime(2026, 10, 16, 12, 0, 30, tzinfo=UTC)
CONFIG = Config(monthly_cap_usd=1.0, margin=0.8)


def ask(*buckets: Bucket, priority: Priority = Priority.NORMAL) -> Ask:
    return Ask("p", "m", buckets, 100, 0.0, priority)


def test_a_models_breaker_closes_only_that_model() -> None:
    state = budget.overload(State(), "p/m", NOW)
    refused, same = budget.admit(state, ask(), NOW, CONFIG)
    assert (refused.ok, refused.why) == (False, "p/m: breaker open")
    assert refused.until == NOW + breaker_core.COOLDOWNS[0]
    assert same is state
    other = Ask("p", "n", (), 100, 0.0, Priority.NORMAL)
    assert budget.admit(state, other, NOW, CONFIG)[0].ok


def test_a_providers_breaker_closes_every_model_and_both_are_named() -> None:
    state = budget.overload(budget.overload(State(), "p", NOW), "p/m", NOW)
    refused, _ = budget.admit(state, ask(), NOW, CONFIG)
    assert refused.why == "p: breaker open; p/m: breaker open"


def test_after_the_cool_down_each_breaker_takes_one_trial() -> None:
    state = budget.overload(State(), "p/m", NOW)
    later = NOW + breaker_core.COOLDOWNS[0]
    admitted, state = budget.admit(state, ask(), later, CONFIG)
    assert admitted.ok
    assert state.breakers["p/m"].trial_until == later + breaker_core.TRIAL_LEASE
    assert state.breakers["p"] == breaker_core.BreakerState()
    second, _ = budget.admit(state, ask(), later, CONFIG)
    assert second.why == "p/m: breaker open"
    closed = budget.success(state, "p/m", later)
    assert budget.admit(closed, ask(), later, CONFIG)[0].ok


def test_an_exact_bucket_takes_no_margin_and_no_share() -> None:
    own = Bucket("evaluate:p", Limits(rpd=3), exact=True)
    state, oks = State(), 0
    for _ in range(5):
        admitted, state = budget.admit(state, ask(own, priority=Priority.LOW), NOW, CONFIG)
        oks += admitted.ok
    assert oks == 3
    shared = Bucket("p", Limits(rpd=10))  # 10 x 0.8 x 0.5 = 4 for LOW
    state, oks = State(), 0
    for _ in range(6):
        admitted, state = budget.admit(state, ask(shared, priority=Priority.LOW), NOW, CONFIG)
        oks += admitted.ok
    assert oks == 4
    minute = Bucket("x", Limits(rpm=2), exact=True)
    state, oks = State(), 0
    for _ in range(3):
        admitted, state = budget.admit(state, ask(minute), NOW, CONFIG)
        oks += admitted.ok
    assert oks == 2


def test_a_lease_holds_its_slots_and_frees_them() -> None:
    until = NOW + timedelta(minutes=11)
    got, state = budget.lease(State(), "p", "a", 2, NOW, until)
    assert got.ok
    got, state = budget.lease(state, "p", "b", 2, NOW, until + timedelta(minutes=1))
    assert got.ok
    busy, same = budget.lease(state, "p", "c", 2, NOW, until)
    assert (busy.ok, busy.why) == (False, "p: busy (2 of 2 calls)")
    assert busy.until == NOW + budget.LEASE_RETRY
    assert same is state
    soon = NOW + timedelta(seconds=20)
    state_soon = State(leases={"p": {"a": soon}})
    busy, _ = budget.lease(state_soon, "p", "c", 1, NOW, until)
    assert busy.until == soon  # the holder's end, when it is sooner than a minute
    state = budget.release(state, "p", "a")
    assert state.leases == {"p": {"b": until + timedelta(minutes=1)}}
    assert budget.release(state, "p", "nobody") is state
    assert budget.release(state, "q", "b") is state
    assert budget.release(state, "p", "b").leases == {}
    other = budget.lease(state, "q", "x", 1, NOW, until)[1]
    assert set(other.leases) == {"p", "q"}


def test_an_expired_lease_is_dropped_when_another_is_taken() -> None:
    crashed = State(leases={"p": {"dead": NOW}})  # its end has come
    got, state = budget.lease(crashed, "p", "new", 1, NOW, NOW + timedelta(minutes=1))
    assert got.ok
    assert state.leases == {"p": {"new": NOW + timedelta(minutes=1)}}


def test_latencies_judge_a_slow_model_on_the_median() -> None:
    state = State()
    for ms in (200_000, 10_000):
        state = budget.observe(state, "p/m", ms, 120_000, NOW)
    assert state.latency["p/m"] == (200_000, 10_000)
    assert state.cooldowns == {}
    state = budget.observe(state, "p/m", 130_000, 120_000, NOW)  # median 130 s
    assert state.cooldowns == {"p/m": NOW + budget.SLOW_WAIT}
    assert "p/m" not in state.latency
    exact = State(latency={"p/m": (120_000, 120_000)})
    assert budget.observe(exact, "p/m", 120_000, 120_000, NOW).cooldowns == {}
    many = State(latency={"p/m": (1, 2, 3, 4, 5)})
    assert budget.observe(many, "p/m", 6, 120_000, NOW).latency["p/m"] == (2, 3, 4, 5, 6)
    assert budget.observe(State(), "p/m", -5, 1, NOW).latency["p/m"] == (0,)


def test_alarms_are_raised_kept_short_and_cleared() -> None:
    state = budget.raise_alarm(State(), "p", "tls_failed", "x" * 500, NOW)
    assert state.alarms["p"] == Alarm("tls_failed", NOW, "x" * 300)
    assert budget.clear_alarm(state, "p").alarms == {}
    assert budget.clear_alarm(state, "q") is state
    again = budget.raise_alarm(state, "p", "unauthorized", "key", NOW + timedelta(minutes=1))
    assert again.alarms["p"].kind == "unauthorized"


times = st.datetimes(
    min_value=datetime(2026, 1, 1),  # noqa: DTZ001 - Hypothesis bounds are naive
    max_value=datetime(2027, 1, 1),  # noqa: DTZ001
    timezones=st.just(UTC),
)
names = st.sampled_from(["local", "p", "q/m"])


@given(
    st.dictionaries(names, st.dictionaries(st.text(min_size=1, max_size=8), times, max_size=3)),
    st.dictionaries(names, times),
    st.dictionaries(names, st.lists(st.integers(0, 10**7), max_size=5).map(tuple)),
    st.dictionaries(names, st.builds(Alarm, st.sampled_from(["tls_failed", "unauthorized"]),
                                     times, st.text(max_size=40))),
)  # fmt: skip
def test_the_v2_state_round_trips_through_json(
    leases: dict[str, dict[str, datetime]],
    probed: dict[str, datetime],
    latency: dict[str, tuple[int, ...]],
    alarms: dict[str, Alarm],
) -> None:
    state = State(leases=leases, probed=probed, latency=latency, alarms=alarms)
    assert budget.from_json(budget.to_json(state)) == state


def test_a_state_stored_before_v2_still_reads() -> None:
    old = budget.to_json(State(spent_usd=1.5))
    for key in ("leases", "probed", "latency", "alarms"):
        del old[key]
    assert budget.from_json(old) == State(spent_usd=1.5)
