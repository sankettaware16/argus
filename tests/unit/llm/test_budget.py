"""The LLM gateway's budgets (P5): limits with margin, shares by priority, cost cap, cool-downs,
breakers, settling, and the JSON round trip."""

from __future__ import annotations

import dataclasses
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.llm import budget
from argus.llm.budget import Ask, Bucket, Config, Limits, Priority, State, Window

NOW = datetime(2026, 10, 16, 12, 0, 30, tzinfo=UTC)
CONFIG = Config(monthly_cap_usd=1.0, margin=0.8)


def ask(
    tokens: int = 100,
    cost: float = 0.0,
    priority: Priority = Priority.NORMAL,
    limits: Limits | None = None,
    model_limits: Limits | None = None,
) -> Ask:
    buckets = []
    if limits is not None:
        buckets.append(Bucket("p", limits))
    if model_limits is not None:
        buckets.append(Bucket("p/m", model_limits))
    return Ask("p", "m", tuple(buckets), tokens, cost, priority)


def run(state: State, a: Ask, n: int, now: datetime = NOW) -> tuple[int, State, budget.Admission]:
    ok = 0
    last = budget.Admission(True)
    for _ in range(n):
        last, state = budget.admit(state, a, now, CONFIG)
        ok += last.ok
    return ok, state, last


def test_requests_per_minute_use_the_margin_and_reopen_next_minute() -> None:
    ok, state, last = run(State(), ask(limits=Limits(rpm=10)), 20)
    assert ok == 8
    assert not last.ok
    assert last.until == datetime(2026, 10, 16, 12, 1, tzinfo=UTC)
    assert last.why == "p: minute limit"
    ok, _, _ = run(state, ask(limits=Limits(rpm=10)), 20, NOW + timedelta(minutes=1))
    assert ok == 8


def test_tokens_per_minute() -> None:
    ok, state, last = run(State(), ask(tokens=300, limits=Limits(tpm=1000)), 5)
    assert ok == 2  # 800 usable: 300 + 300, a third would be 900
    assert state.windows["p"].minute_tokens == 600
    assert not last.ok
    assert last.why == "p: minute limit"


def test_a_call_larger_than_a_limit_is_never_admitted() -> None:
    for limits in (Limits(tpm=1000), Limits(tpd=1000)):
        admission, state = budget.admit(State(), ask(tokens=801, limits=limits), NOW, CONFIG)
        assert admission == budget.Admission(False, None, "p: too large")
        assert state == State()
    assert budget.admit(State(), ask(tokens=800, limits=Limits(tpm=1000)), NOW, CONFIG)[0].ok


def test_day_limits_follow_the_priority_share() -> None:
    lim = Limits(rpd=100)
    got = {}
    for p in Priority:
        got[p], _, last = run(State(), ask(priority=p, model_limits=lim), 200)
        assert last.until == datetime(2026, 10, 17, tzinfo=UTC)
        assert last.why == "p/m: day limit"
    assert got == {Priority.HIGH: 80, Priority.NORMAL: 64, Priority.LOW: 40}


def test_a_low_priority_run_leaves_the_rest_of_the_day() -> None:
    lim = Limits(tpd=10_000)
    ok, state, _ = run(State(), ask(tokens=1000, priority=Priority.LOW, limits=lim), 10)
    assert ok == 4
    ok, state, _ = run(state, ask(tokens=1000, priority=Priority.HIGH, limits=lim), 10)
    assert ok == 4
    assert state.windows["p"].day_tokens == 8000


def test_day_tokens_reset_on_the_next_day() -> None:
    lim = Limits(tpd=1000)
    _, state, last = run(State(), ask(tokens=500, priority=Priority.HIGH, limits=lim), 2)
    assert not last.ok
    admission, state = budget.admit(state, ask(500, limits=lim), NOW + timedelta(days=1), CONFIG)
    assert admission.ok
    assert state.windows["p"].day_tokens == 500


def test_every_bucket_must_have_room() -> None:
    a = ask(limits=Limits(rpm=100), model_limits=Limits(rpm=5))
    ok, state, last = run(State(), a, 10)
    assert ok == 4
    assert last.why == "p/m: minute limit"
    assert state.windows["p"].minute_requests == 4 == state.windows["p/m"].minute_requests


def test_the_monthly_cost_cap_by_share_and_the_next_month() -> None:
    a = ask(cost=0.3)
    ok, state, last = run(State(), a, 5)
    assert ok == 2
    assert round(state.spent_usd, 6) == 0.6
    assert last.why == "monthly cost cap"
    assert last.until == datetime(2026, 11, 1, tzinfo=UTC)
    ok, _, _ = run(state, replace(a, priority=Priority.HIGH), 5)
    assert ok == 1
    december = datetime(2026, 12, 31, 23, 0, tzinfo=UTC)
    _, _, last = run(replace(state, spent_usd=1.0, month="2026-12"), a, 1, december)
    assert last.until == datetime(2027, 1, 1, tzinfo=UTC)
    ok, state, _ = run(state, a, 5, NOW + timedelta(days=31))
    assert ok == 2
    assert state.month == "2026-11"


def test_a_call_costing_more_than_the_cap_never_goes() -> None:
    admission, _ = budget.admit(State(), ask(cost=0.81), NOW, CONFIG)
    assert admission == budget.Admission(False, None, "costs more than the monthly cap")
    assert budget.admit(State(), ask(cost=0.8), NOW, CONFIG)[0].ok


def test_free_calls_ignore_the_cost_cap() -> None:
    ok, _, _ = run(State(spent_usd=99.0, month="2026-10"), ask(cost=0.0), 3)
    assert ok == 3


def test_cool_downs_for_the_provider_and_for_the_model() -> None:
    for name in ("p", "p/m"):
        state = budget.cool_down(State(), name, NOW + timedelta(seconds=30), NOW)
        admission, _ = budget.admit(state, ask(), NOW, CONFIG)
        assert admission == budget.Admission(False, NOW + timedelta(seconds=30),
                                             f"{name}: cooling down")  # fmt: skip
        assert budget.admit(state, ask(), NOW + timedelta(seconds=30), CONFIG)[0].ok
    other = budget.cool_down(State(), "p/other", NOW + timedelta(hours=1), NOW)
    assert budget.admit(other, ask(), NOW, CONFIG)[0].ok


def test_cool_downs_last_at_most_a_day_never_shorten_and_drop_old_ones() -> None:
    state = budget.cool_down(State(), "p", NOW + timedelta(days=9), NOW)
    assert state.cooldowns["p"] == NOW + budget.MAX_COOLDOWN
    assert budget.cool_down(state, "p", NOW + timedelta(hours=1), NOW) == state
    later = NOW + timedelta(days=2)
    state = budget.cool_down(state, "q", later + timedelta(minutes=1), later)
    assert state.cooldowns == {"q": later + timedelta(minutes=1)}


def test_the_breaker_waits_then_allows_one_trial() -> None:
    state = budget.overload(State(), "p", NOW)
    admission, _ = budget.admit(state, ask(), NOW, CONFIG)
    assert admission == budget.Admission(False, NOW + timedelta(minutes=5), "p: breaker open")
    after = NOW + timedelta(minutes=5)
    first, state = budget.admit(state, ask(), after, CONFIG)
    second, _ = budget.admit(state, ask(), after, CONFIG)
    assert first.ok
    assert not second.ok
    assert second.until == after + timedelta(minutes=2)
    state = budget.success(state, "p", after)
    assert budget.admit(state, ask(), after, CONFIG)[0].ok
    assert budget.success(State(), "p", NOW).breakers["p"] == budget.breaker_core.BreakerState()


def test_a_refused_admission_changes_nothing() -> None:
    state = budget.overload(State(), "p", NOW)
    _, after = budget.admit(state, ask(limits=Limits(rpm=5)), NOW, CONFIG)
    assert after == state


def test_the_kill_switch_refuses_everything() -> None:
    admission, state = budget.admit(State(stopped=True), ask(), NOW, CONFIG)
    assert admission == budget.Admission(False, None, "stopped")
    assert state.stopped


def test_waits_report_the_latest_time_everything_clears() -> None:
    state = budget.cool_down(State(), "p", NOW + timedelta(hours=2), NOW)
    _, state, _ = run(state, ask(limits=Limits(rpm=1)), 0)
    state = replace(state, windows={"p": Window().at(NOW)})
    state = replace(state, windows={"p": replace(state.windows["p"], minute_requests=5)})
    admission, _ = budget.admit(state, ask(limits=Limits(rpm=1)), NOW, CONFIG)
    assert admission.until == NOW + timedelta(hours=2)
    assert admission.why == "p: minute limit; p: cooling down"


def test_settling_replaces_the_estimate() -> None:
    a = ask(tokens=1000, cost=0.5, priority=Priority.HIGH, limits=Limits(tpm=10_000))
    _, state = budget.admit(State(), a, NOW, CONFIG)
    state = budget.settle(state, a, NOW, 300, 0.1)
    w = state.windows["p"]
    assert (w.minute_tokens, w.day_tokens, w.minute_requests) == (300, 300, 1)
    assert round(state.spent_usd, 6) == 0.1


def test_settling_after_the_minute_keeps_the_minute_but_fixes_the_day() -> None:
    a = ask(tokens=1000, limits=Limits(tpm=10_000))
    _, state = budget.admit(State(), a, NOW, CONFIG)
    later = NOW + timedelta(minutes=2)
    _, state = budget.admit(state, replace(a, tokens=10), later, CONFIG)
    state = budget.settle(state, a, NOW, 300, 0.0)
    assert state.windows["p"].minute_tokens == 10
    assert state.windows["p"].day_tokens == 310


def test_settling_after_the_day_or_month_moves_nothing() -> None:
    a = ask(tokens=1000, cost=0.5, priority=Priority.HIGH, limits=Limits(tpd=100_000))
    _, state = budget.admit(State(), a, NOW, CONFIG)
    next_month = NOW + timedelta(days=20)
    _, state = budget.admit(state, replace(a, tokens=10, cost_usd=0.01), next_month, CONFIG)
    state = budget.settle(state, a, NOW, 0, 0.0)
    assert state.windows["p"].day_tokens == 10
    assert state.spent_usd == 0.01


def test_settling_never_goes_negative_and_skips_unknown_buckets() -> None:
    a = ask(tokens=10, cost=0.01, limits=Limits(tpm=1000))
    state = State(windows={"p": Window().at(NOW)}, month="2026-10")
    state = budget.settle(state, replace(a, buckets=(*a.buckets, Bucket("x", Limits()))),
                          NOW, 0, 0.0)  # fmt: skip
    assert state.windows["p"].minute_tokens == 0
    assert state.spent_usd == 0.0
    assert "x" not in state.windows


def test_the_window_rolls() -> None:
    w = Window(NOW.replace(second=0), 3, 30, NOW.date(), 5, 50)
    assert w.at(NOW) == w
    assert w.at(NOW + timedelta(minutes=1)) == Window(
        NOW.replace(second=0) + timedelta(minutes=1), 0, 0, NOW.date(), 5, 50
    )
    assert w.at(NOW + timedelta(days=1)).day_requests == 0


def test_the_next_month_from_any_day() -> None:
    for day in (1, 15, 28, 31):
        now = datetime(2026, 1, day, 23, 59, tzinfo=UTC)
        assert budget._next_month(now) == datetime(2026, 2, 1, tzinfo=UTC)


times = st.datetimes(
    min_value=datetime(2026, 1, 1),  # noqa: DTZ001 - Hypothesis bounds are naive
    max_value=datetime(2027, 1, 1),  # noqa: DTZ001
    timezones=st.just(UTC),
)


@given(
    st.dictionaries(
        st.sampled_from(["p", "p/m", "q"]),
        st.builds(
            Window,
            times,
            st.integers(0, 99),
            st.integers(0, 9999),
            st.dates(),
            st.integers(0, 99),
            st.integers(0, 9999),
        ),
    ),
    st.dictionaries(st.sampled_from(["p", "q/m"]), times),
    st.booleans(),
    st.floats(0, 100, allow_nan=False),
    st.booleans(),
)
def test_the_state_round_trips_through_json(
    windows: dict[str, Window],
    cooldowns: dict[str, datetime],
    tripped: bool,
    spent: float,
    stopped: bool,
) -> None:
    breakers = {"p": budget.breaker_core.on_overload(budget.breaker_core.BreakerState(), NOW)}
    state = State(windows, cooldowns, breakers if tripped else {}, "2026-10", spent, stopped)
    assert budget.from_json(budget.to_json(state)) == state
    assert budget.from_json({}) == State()
    assert budget.from_json(budget.to_json(State(windows={"p": Window()}))) == State(
        windows={"p": Window()}
    )


# -- the exact values and edges (mutation testing, P5) --------------------------------------


def test_the_records_are_immutable() -> None:
    records = [Limits(), Window(), State(), Bucket("p", Limits()), ask(),
               budget.Admission(True), Config()]  # fmt: skip
    for record in records:
        field_name = dataclasses.fields(record)[0].name
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(record, field_name, None)


def test_the_defaults() -> None:
    assert [p.value for p in Priority] == ["high", "normal", "low"]
    assert Priority("high") is Priority.HIGH
    assert Window() == Window(None, 0, 0, None, 0, 0)
    assert budget.Admission(True).why == ""
    assert budget.Admission(True).until is None
    assert Config() == Config(10.0, 0.8, {Priority.HIGH: 1.0, Priority.NORMAL: 0.8,
                                          Priority.LOW: 0.5})  # fmt: skip


def test_a_cool_down_is_cut_to_one_day() -> None:
    state = budget.cool_down(State(), "p", NOW + timedelta(days=9), NOW)
    assert state.cooldowns["p"] == NOW + timedelta(hours=24)


def test_a_call_exactly_the_size_of_the_day_limit_goes() -> None:
    # tpd 1000 at margin 0.8 and the NORMAL share 0.8: 640
    lim = Limits(tpd=1000)
    assert budget.admit(State(), ask(tokens=640, limits=lim), NOW, CONFIG)[0].ok
    assert budget.admit(State(), ask(tokens=641, limits=lim), NOW, CONFIG)[0].why == (
        "p: too large"
    )


def test_each_bucket_counts_from_its_own_window() -> None:
    a = ask(limits=Limits(rpm=100), model_limits=Limits(rpm=100))
    windows = {"p": replace(Window().at(NOW), minute_requests=7, minute_tokens=70),
               "p/m": replace(Window().at(NOW), minute_requests=2, minute_tokens=20)}  # fmt: skip
    admission, state = budget.admit(State(windows=windows), a, NOW, CONFIG)
    assert admission.ok
    assert (state.windows["p"].minute_requests, state.windows["p"].minute_tokens) == (8, 170)
    assert (state.windows["p/m"].minute_requests, state.windows["p/m"].minute_tokens) == (3, 120)


def test_the_same_cool_down_again_changes_nothing() -> None:
    old = NOW - timedelta(minutes=5)
    state = State(cooldowns={"p": NOW + timedelta(minutes=1), "q": old})
    assert budget.cool_down(state, "p", NOW + timedelta(minutes=1), NOW) is state


def test_a_cool_down_ending_now_is_dropped() -> None:
    state = State(cooldowns={"q": NOW})
    after = budget.cool_down(state, "p", NOW + timedelta(minutes=1), NOW)
    assert after.cooldowns == {"p": NOW + timedelta(minutes=1)}


def test_the_daily_cost_cap() -> None:
    """A backlog cannot spend the month in a day (D-098)."""
    config = Config(monthly_cap_usd=10.0, margin=0.8, daily_cap_usd=1.0)
    a = ask(cost=0.3)  # NORMAL: 0.8 of $1 a day
    ok, state, last = (0, State(), None)
    for _ in range(4):
        last, state = budget.admit(state, a, NOW, config)
        ok += last.ok
    assert ok == 2
    assert last is not None
    assert last.why == "daily cost cap"
    assert last.until == datetime(2026, 10, 17, tzinfo=UTC)
    assert round(state.day_spent_usd, 6) == 0.6
    assert state.day == "2026-10-16"
    tomorrow, _ = budget.admit(state, a, NOW + timedelta(days=1), config)
    assert tomorrow.ok
    settled = budget.settle(state, a, NOW, 10, 0.05)
    assert round(settled.day_spent_usd, 6) == 0.35
    late = budget.settle(state, a, NOW - timedelta(days=1), 10, 0.05)  # another day's call
    assert late.day_spent_usd == state.day_spent_usd
    big, _ = budget.admit(State(), ask(cost=0.9), NOW, config)
    assert big == budget.Admission(False, None, "costs more than the daily cap")
    free, _ = budget.admit(State(day="2026-10-16", day_spent_usd=99.0), ask(cost=0.0), NOW,
                           config)  # fmt: skip
    assert free.ok
    no_cap, _ = budget.admit(State(day="2026-10-16", day_spent_usd=99.0), a, NOW, CONFIG)
    assert no_cap.ok is True  # without a daily cap the day's spend does not count
    round_trip = budget.from_json(budget.to_json(state))
    assert (round_trip.day, round_trip.day_spent_usd) == (state.day, state.day_spent_usd)
    exactly, _ = budget.admit(State(), ask(cost=0.8), NOW, config)
    assert exactly.ok  # a call that costs the whole daily share is admitted
    filled, _ = budget.admit(State(day="2026-10-16", day_spent_usd=0.5), ask(cost=0.3), NOW,
                             config)  # fmt: skip
    assert filled.ok  # reaching the daily share exactly is still inside it
