"""The overload breaker (plan §5.2): a 429, a rejected execution or a tripped circuit breaker
on the SIEM pauses every request except health probes, with escalating cool-downs. After a
cool-down exactly one trial request may go; its success closes the breaker, another overload
re-opens it one step longer. A trial that never reports (its process died) is given up after
TRIAL_LEASE. The escalation level drops back to zero after RESET_AFTER without an overload.

Pure: (state, now) in, (decision, state) out. The gateway keeps the state in Postgres.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta

COOLDOWNS = (timedelta(minutes=5), timedelta(minutes=15), timedelta(minutes=60))
TRIAL_LEASE = timedelta(minutes=2)
RESET_AFTER = timedelta(hours=6)


@dataclass(frozen=True)
class BreakerState:
    level: int = 0  # 0 closed; n > 0: the n-th consecutive cool-down
    open_until: datetime | None = None
    trial_until: datetime | None = None  # a trial request is out until then
    last_trip: datetime | None = None

    def is_open(self, now: datetime) -> bool:
        return self.open_until is not None and now < self.open_until


def admit(state: BreakerState, now: datetime) -> tuple[bool, BreakerState]:
    """May a request go now? A closed breaker says yes; an open one no; after the cool-down,
    yes for one trial at a time."""
    if state.level and state.last_trip is not None and now - state.last_trip >= RESET_AFTER:
        state = BreakerState()
    if state.open_until is None:
        return True, state
    if now < state.open_until:
        return False, state
    if state.trial_until is not None and now < state.trial_until:
        return False, state
    return True, replace(state, trial_until=now + TRIAL_LEASE)


def peek(state: BreakerState, now: datetime) -> bool:
    """Would ``admit`` say yes now? Read-only: takes no trial."""
    return admit(state, now)[0]


def on_overload(state: BreakerState, now: datetime) -> BreakerState:
    """An overload answer. While the breaker is open it changes nothing: the requests that
    were already out when it tripped report the same overload."""
    if state.is_open(now):
        return state
    level = min(state.level + 1, len(COOLDOWNS))
    return BreakerState(
        level=level, open_until=now + COOLDOWNS[level - 1], trial_until=None, last_trip=now
    )


def on_success(state: BreakerState, now: datetime) -> BreakerState:
    """A request came back without overload: a passed trial closes the breaker (the level stays
    until RESET_AFTER, so the next trip waits longer)."""
    if state.open_until is None or now < state.open_until:
        return state
    return replace(state, open_until=None, trial_until=None)
