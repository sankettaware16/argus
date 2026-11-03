"""The identity lane's own reachability and overload gate (Q-E1, plan §5 and §7.2).

The identity lane is never gated on the SIEM's health state, on a STOP that ARGUS's own key
caused, or on a stale probe: a person's sign-in has nothing to do with the reader key. It is
gated on what its own requests see instead:

- **unreachable:** two requests in a row that could not connect within ``FAILURE_WINDOW``;
- **overloaded:** an answer that says the SIEM is overloaded (429, 503, a rejected execution or
  a tripped circuit breaker), at once.

Either opens the gate for a cool-down (30 s, 2 min, 5 min, then 15 min while it keeps
happening); meanwhile every check answers "unavailable" without a request. After the
cool-down one trial request at a time may go; any answer from the SIEM that is not an overload
closes the gate (a 401 is an answer: the SIEM is reachable). The escalation falls back to the
first step after ``RESET_AFTER`` without a trip.

Pure: (state, now) in, (decision, state) out. The store keeps the state (``siem_state`` row
``identity``), so every ARGUS process shares it.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum

COOLDOWNS = (
    timedelta(seconds=30),
    timedelta(minutes=2),
    timedelta(minutes=5),
    timedelta(minutes=15),
)
FAILURE_WINDOW = timedelta(seconds=60)
FAILURES_TO_TRIP = 2
TRIAL_LEASE = timedelta(seconds=15)  # longer than one call (5 s) and its admission
RESET_AFTER = timedelta(hours=1)


class Signal(StrEnum):
    ANSWERED = "answered"  # the SIEM answered, and not with an overload
    UNREACHABLE = "unreachable"  # no connection
    OVERLOADED = "overloaded"


@dataclass(frozen=True)
class ReachState:
    level: int = 0  # 0: closed; n: the n-th cool-down in a row
    open_until: datetime | None = None
    trial_until: datetime | None = None
    last_trip: datetime | None = None
    reason: str | None = None  # why it last opened: "unreachable" or "overloaded"
    failures: tuple[datetime, ...] = ()  # connection failures in a row, within the window

    def is_open(self, now: datetime) -> bool:
        return self.open_until is not None and now < self.open_until


def _fresh(state: ReachState, now: datetime) -> ReachState:
    if state.level and state.last_trip is not None and now - state.last_trip >= RESET_AFTER:
        return replace(state, level=0)
    return state


def admit(state: ReachState, now: datetime) -> tuple[bool, ReachState]:
    """May a check go now? Closed: yes. Open: no until the cool-down ends, then one trial at a
    time."""
    state = _fresh(state, now)
    if state.open_until is None:
        return True, state
    if now < state.open_until:
        return False, state
    if state.trial_until is not None and now < state.trial_until:
        return False, state
    return True, replace(state, trial_until=now + TRIAL_LEASE)


def _trip(state: ReachState, now: datetime, reason: Signal) -> ReachState:
    level = min(state.level + 1, len(COOLDOWNS))
    return ReachState(
        level=level,
        open_until=now + COOLDOWNS[level - 1],
        trial_until=None,
        last_trip=now,
        reason=reason.value,
        failures=(),
    )


def report(state: ReachState, now: datetime, signal: Signal) -> ReachState:
    """What one request saw. While the gate is open (requests already out when it opened)
    nothing changes but a passed trial closing it."""
    state = _fresh(state, now)
    if state.is_open(now):
        return state
    if signal is Signal.ANSWERED:
        return replace(state, open_until=None, trial_until=None, failures=())
    if signal is Signal.OVERLOADED:
        return _trip(state, now, signal)
    failures = (*(t for t in state.failures if now - t < FAILURE_WINDOW), now)
    if state.open_until is not None or len(failures) >= FAILURES_TO_TRIP:
        return _trip(state, now, signal)  # a failed trial re-opens at once, one step longer
    return replace(state, failures=failures)
