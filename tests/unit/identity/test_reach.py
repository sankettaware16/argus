"""The identity gate (Q-E1): its own reachability and overload signals, cool-downs, one trial
at a time, the reset after an hour."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from hypothesis import given
from hypothesis import strategies as st

from argus.identity.reach import (
    COOLDOWNS,
    FAILURE_WINDOW,
    RESET_AFTER,
    TRIAL_LEASE,
    ReachState,
    Signal,
    admit,
    report,
)

T0 = datetime(2026, 10, 23, 10, 0, tzinfo=UTC)
S = timedelta(seconds=1)


def test_closed_admits() -> None:
    ok, state = admit(ReachState(), T0)
    assert ok
    assert state == ReachState()


def test_one_connection_failure_does_not_open() -> None:
    state = report(ReachState(), T0, Signal.UNREACHABLE)
    assert state.failures == (T0,)
    assert admit(state, T0)[0]


def test_two_failures_within_the_window_open_it() -> None:
    state = report(ReachState(), T0, Signal.UNREACHABLE)
    state = report(state, T0 + FAILURE_WINDOW - S, Signal.UNREACHABLE)
    assert state.is_open(T0 + FAILURE_WINDOW - S)
    assert state.reason == "unreachable"
    assert state.level == 1
    assert state.open_until == T0 + FAILURE_WINDOW - S + COOLDOWNS[0]
    assert not admit(state, T0 + FAILURE_WINDOW)[0]


def test_two_failures_further_apart_do_not() -> None:
    state = report(ReachState(), T0, Signal.UNREACHABLE)
    state = report(state, T0 + FAILURE_WINDOW, Signal.UNREACHABLE)
    assert state.open_until is None
    assert state.failures == (T0 + FAILURE_WINDOW,)


def test_an_answer_between_failures_resets_them() -> None:
    state = report(ReachState(), T0, Signal.UNREACHABLE)
    state = report(state, T0 + S, Signal.ANSWERED)
    state = report(state, T0 + 2 * S, Signal.UNREACHABLE)
    assert state.open_until is None
    assert state.failures == (T0 + 2 * S,)


def test_an_overload_opens_it_at_once() -> None:
    state = report(ReachState(), T0, Signal.OVERLOADED)
    assert state.is_open(T0)
    assert state.reason == "overloaded"
    assert state.open_until == T0 + COOLDOWNS[0]


def test_after_the_cooldown_one_trial_at_a_time() -> None:
    state = report(ReachState(), T0, Signal.OVERLOADED)
    end = T0 + COOLDOWNS[0]
    assert not admit(state, end - S)[0]
    ok, state = admit(state, end)
    assert ok
    assert state.trial_until == end + TRIAL_LEASE
    assert not admit(state, end + S)[0]  # the trial is out
    ok, _again = admit(state, end + TRIAL_LEASE)  # it never reported: given up
    assert ok


def test_a_passed_trial_closes_it_and_the_level_stays() -> None:
    state = report(ReachState(), T0, Signal.OVERLOADED)
    end = T0 + COOLDOWNS[0]
    _ok, state = admit(state, end)
    state = report(state, end + S, Signal.ANSWERED)
    assert state.open_until is None
    assert state.trial_until is None
    assert state.level == 1
    state = report(state, end + 2 * S, Signal.OVERLOADED)
    assert state.open_until == end + 2 * S + COOLDOWNS[1]  # one step longer


def test_a_failed_trial_reopens_at_once_one_step_longer() -> None:
    state = report(ReachState(), T0, Signal.OVERLOADED)
    end = T0 + COOLDOWNS[0]
    _ok, state = admit(state, end)
    state = report(state, end + S, Signal.UNREACHABLE)  # one failure is enough in a trial
    assert state.is_open(end + S)
    assert state.level == 2
    assert state.open_until == end + S + COOLDOWNS[1]


def test_reports_while_open_change_nothing() -> None:
    state = report(ReachState(), T0, Signal.OVERLOADED)
    for signal in Signal:
        assert report(state, T0 + S, signal) == state


def test_the_level_tops_out_and_resets_after_an_hour() -> None:
    state = ReachState()
    now = T0
    for _ in range(len(COOLDOWNS) + 2):
        state = report(state, now, Signal.OVERLOADED)
        assert state.open_until is not None
        now = state.open_until
    assert state.level == len(COOLDOWNS)
    assert state.open_until is not None
    assert state.last_trip is not None
    assert state.open_until - state.last_trip == COOLDOWNS[-1]
    later = state.last_trip + RESET_AFTER
    ok, fresh = admit(state, later)
    assert ok
    assert fresh.level == 0
    assert report(state, later, Signal.OVERLOADED).level == 1


@given(st.lists(st.tuples(st.sampled_from(list(Signal)), st.integers(0, 400)), max_size=30))
def test_never_admits_while_open(steps: list[tuple[Signal, int]]) -> None:
    state = ReachState()
    now = T0
    for signal, seconds in steps:
        now += timedelta(seconds=seconds)
        before = state
        ok, state = admit(state, now)
        if before.is_open(now):
            assert not ok
        if ok:
            state = report(state, now, signal)
        assert state.level <= len(COOLDOWNS)
        if state.open_until is not None and state.last_trip is not None:
            assert state.open_until - state.last_trip in COOLDOWNS
