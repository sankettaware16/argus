"""The SIEM load budget, counted in Elasticsearch server time (``took``).

A token bucket refilled per minute up to ``burst_ms`` (both scaled by the health state); admission
reserves the cost class's estimate and settling charges the real ``took`` (a timeout is charged its
whole deadline). Also a daily cap, concurrency leases, heavy-query limits and a separate probe
allowance. Pure: (state, request, now) in, (admission, state) out; the gateway keeps the state in
Postgres so every ARGUS process shares one budget.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import date, datetime, timedelta
from enum import StrEnum

from argus.gateway.templates import CostClass

MINUTE = timedelta(minutes=1)
MAX_EXPIRED = 256


@dataclass(frozen=True)
class BudgetConfig:
    took_per_minute_ms: int = 3_000
    burst_ms: int = 3_000
    strained_burst_ms: int | None = None  # the capacity when the scale is below 1; None: burst_ms
    took_per_day_ms: int = 3_600_000
    concurrency: int = 2
    heavy_concurrency: int = 1
    heavy_per_minute: int = 6
    heavy_per_day: int = 2_000
    probes_per_minute: int = 12
    estimate_ms: dict[CostClass, int] = field(
        default_factory=lambda: {
            CostClass.PROBE: 20,
            CostClass.LIGHT: 50,
            CostClass.MEDIUM: 250,
            CostClass.HEAVY: 1_000,
        }
    )
    lease: timedelta = timedelta(minutes=2)


@dataclass(frozen=True)
class Lease:
    id: str
    cost: CostClass
    estimate_ms: int
    expires: datetime


@dataclass(frozen=True)
class BudgetState:
    tokens_ms: float | None = None  # None: never used, starts full
    refilled_at: datetime | None = None
    day: date | None = None
    day_used_ms: int = 0
    heavy_day: int = 0
    heavy_starts: tuple[datetime, ...] = ()
    probe_starts: tuple[datetime, ...] = ()
    leases: tuple[Lease, ...] = ()
    expired: tuple[str, ...] = ()  # ids of leases whose estimate roll charged to ``day``


class Verdict(StrEnum):
    ADMITTED = "admitted"
    WAIT = "wait"  # try again at retry_at
    EXHAUSTED = "exhausted"  # not today: skipped_budget


@dataclass(frozen=True)
class Admission:
    verdict: Verdict
    reason: str
    lease: Lease | None = None
    retry_at: datetime | None = None


def capacity(config: BudgetConfig, scale: float) -> float:
    """What the bucket holds when full: ``burst_ms`` at full scale; below it ``strained_burst_ms``
    (when the bucket has one: the burst is for a healthy cluster only), both scaled."""
    if scale < 1.0 and config.strained_burst_ms is not None:
        return config.strained_burst_ms * scale
    return config.burst_ms * scale


def roll(state: BudgetState, config: BudgetConfig, now: datetime, scale: float) -> BudgetState:
    """Bring the state to ``now``: start a new UTC day, then expire leases (charging their
    estimates to the current day) and refill tokens."""
    day, used, heavy_day, charged = state.day, state.day_used_ms, state.heavy_day, state.expired
    if day != now.date():
        day, used, heavy_day, charged = now.date(), 0, 0, ()
    expired = [lease for lease in state.leases if lease.expires <= now]
    used += sum(lease.estimate_ms for lease in expired)
    charged = (*charged, *(lease.id for lease in expired))
    full = capacity(config, scale)
    if state.tokens_ms is None or state.refilled_at is None:
        tokens = full
    else:
        elapsed = max((now - state.refilled_at).total_seconds() * 1000, 0.0)
        tokens = state.tokens_ms + elapsed * config.took_per_minute_ms * scale / 60_000
        tokens = min(tokens, full)
    return BudgetState(
        tokens_ms=tokens,
        refilled_at=now,
        day=day,
        day_used_ms=used,
        heavy_day=heavy_day,
        heavy_starts=tuple(t for t in state.heavy_starts if now - t < MINUTE),
        probe_starts=tuple(t for t in state.probe_starts if now - t < MINUTE),
        leases=tuple(lease for lease in state.leases if lease.expires > now),
        expired=charged[-MAX_EXPIRED:],
    )


def admit(
    state: BudgetState,
    config: BudgetConfig,
    cost: CostClass,
    now: datetime,
    *,
    scale: float,
    lease_id: str,
    kept_ms: int = 0,
) -> tuple[Admission, BudgetState]:
    """Admit one request. ``kept_ms``: server time the request must leave in the bucket for
    others (the collector's poll, ``lanes.kept_for_poll``), counted against the bucket at full
    scale: a request keeping a reserve is admitted once the full-scale bucket is full, and
    while the scale is below 1 (a slow start, CAUTION) it waits whenever that bucket is too
    small to hold its estimate and the reserve. A request keeping nothing is always admitted
    once the bucket is full."""
    if kept_ms < 0:
        raise ValueError("a request keeps no less than nothing for others")
    if cost is not CostClass.PROBE and not 0 < scale <= 1:
        raise ValueError("work other than probes needs a budget scale in (0, 1]")
    state = roll(state, config, now, max(scale, 0.0))
    estimate = config.estimate_ms[cost]
    lease = Lease(lease_id, cost, estimate, now + config.lease)

    def wait(reason: str, at: datetime) -> tuple[Admission, BudgetState]:
        return Admission(Verdict.WAIT, reason, retry_at=max(at, now)), state

    if len(state.leases) >= config.concurrency:
        return wait("concurrency", min(lease.expires for lease in state.leases))
    if cost is CostClass.PROBE:
        if len(state.probe_starts) >= config.probes_per_minute:
            return wait("probe_rate", state.probe_starts[0] + MINUTE)
        state = replace(
            state, probe_starts=(*state.probe_starts, now), leases=(*state.leases, lease)
        )
        return Admission(Verdict.ADMITTED, "ok", lease), state
    if cost is CostClass.HEAVY:
        if state.heavy_day >= config.heavy_per_day:
            return Admission(Verdict.EXHAUSTED, "heavy_daily"), state
        heavy = [lease for lease in state.leases if lease.cost is CostClass.HEAVY]
        if len(heavy) >= config.heavy_concurrency:
            return wait("heavy_concurrency", min(lease.expires for lease in heavy))
        if len(state.heavy_starts) >= config.heavy_per_minute:
            return wait("heavy_rate", state.heavy_starts[0] + MINUTE)
    reserved = sum(lease.estimate_ms for lease in state.leases if lease.cost is not CostClass.PROBE)
    if state.day_used_ms + reserved + estimate > config.took_per_day_ms:
        return Admission(Verdict.EXHAUSTED, "daily"), state
    tokens = state.tokens_ms or 0.0
    if kept_ms:
        needed = min(estimate + kept_ms, capacity(config, 1.0))
    else:
        needed = min(estimate, capacity(config, scale))
    if tokens < needed:
        rate = config.took_per_minute_ms * scale / 60_000  # per millisecond
        return wait("server_time", now + timedelta(milliseconds=(needed - tokens) / rate))
    state = replace(state, tokens_ms=tokens - estimate, leases=(*state.leases, lease))
    if cost is CostClass.HEAVY:
        state = replace(
            state, heavy_day=state.heavy_day + 1, heavy_starts=(*state.heavy_starts, now)
        )
    return Admission(Verdict.ADMITTED, "ok", lease), state


def settle(
    state: BudgetState,
    config: BudgetConfig,
    lease: Lease,
    took_ms: int,
    now: datetime,
    *,
    scale: float,
) -> BudgetState:
    """The request of ``lease`` is over and cost ``took_ms`` of server time."""
    if took_ms < 0:
        raise ValueError("took is never negative")
    state = roll(state, config, now, max(scale, 0.0))
    returned = lease.estimate_ms if lease.cost is not CostClass.PROBE else 0
    used = state.day_used_ms + took_ms
    if lease.id in state.expired:  # roll charged its estimate to today already
        used -= lease.estimate_ms
    return replace(
        state,
        tokens_ms=(state.tokens_ms or 0.0) + returned - took_ms,
        day_used_ms=max(used, 0),
        leases=tuple(item for item in state.leases if item.id != lease.id),
        expired=tuple(item for item in state.expired if item != lease.id),
    )
