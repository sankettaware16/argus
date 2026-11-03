"""The SIEM's health state machine.

Probe readings in, NORMAL / CAUTION / DEGRADED / STOP out. Each condition has an entry test and a
looser stay test (hysteresis); after DEGRADED or STOP the budget comes back slowly (a quarter,
then half, then all). A memory no probe has refreshed for a while is not trusted (unknown is not
healthy): ``effective`` makes it DEGRADED, then STOP. Pure: (memory, readings, now) in, memory out.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from argus.gateway.templates import Purpose


class HealthState(StrEnum):
    NORMAL = "normal"
    CAUTION = "caution"
    DEGRADED = "degraded"
    STOP = "stop"


LEVEL = {
    HealthState.NORMAL: 0,
    HealthState.CAUTION: 1,
    HealthState.DEGRADED: 2,
    HealthState.STOP: 3,
}
BY_LEVEL = {level: state for state, level in LEVEL.items()}
SCALE = {HealthState.NORMAL: 1.0, HealthState.CAUTION: 0.5, HealthState.DEGRADED: 0.1}

# Which work each state allows: investigation, measurement and every write only in NORMAL;
# freshness and Kibana reads also in CAUTION (half the share) and DEGRADED (a tenth);
# identity checks in every state (STOP does not block sign-in), on their own lane.
_NORMAL_ONLY = frozenset(
    {
        Purpose.BACKFILL,
        Purpose.RECONCILE,
        Purpose.WRITEBACK,
        Purpose.INVESTIGATE,
        Purpose.MEASURE,
        Purpose.KIBANA_WRITE,
        Purpose.DISCOVER,
    }
)
ALLOWED: dict[HealthState, frozenset[Purpose]] = {
    HealthState.NORMAL: frozenset(Purpose),
    HealthState.CAUTION: frozenset(Purpose) - _NORMAL_ONLY,
    HealthState.DEGRADED: frozenset(
        {
            Purpose.PROBE,
            Purpose.SELFTEST,
            Purpose.COLLECT,
            Purpose.FRESHNESS,
            Purpose.KIBANA_READ,
            Purpose.IDENTITY,
        }
    ),
    HealthState.STOP: frozenset({Purpose.PROBE, Purpose.IDENTITY}),
}


@dataclass(frozen=True)
class HealthConfig:
    disk_caution: float = 85.0
    disk_degraded: float = 90.0
    disk_stop: float = 95.0
    heap_caution: float = 85.0  # used until a measured p90 baseline exists
    load_caution: float = 16.0  # 1-minute load (about the SIEM's core count)
    ingest_lag_degraded: timedelta = timedelta(minutes=15)
    margin: float = 5.0  # percentage points below a threshold to leave it
    load_margin: float = 0.9  # leave a load condition below 90% of its threshold
    lag_margin: timedelta = timedelta(minutes=5)
    clean_probes: int = 3
    slow_start: tuple[timedelta, timedelta] = (timedelta(minutes=20), timedelta(minutes=40))
    stale_degraded: timedelta = timedelta(minutes=3)
    stale_stop: timedelta = timedelta(minutes=15)


@dataclass(frozen=True)
class Readings:
    """One probe's view of the SIEM. None means unknown (that part of the probe failed)."""

    at: datetime
    probe_ok: bool = True  # False: the node-stats probe got no usable answer
    auth_failed: bool = False  # the probe got 401/403
    disk_percent: float | None = None
    heap_percent: float | None = None
    load_1m: float | None = None
    search_queue: int | None = None
    search_rejected: int | None = None  # cumulative counter
    breakers_tripped: int | None = None  # cumulative, all breakers
    write_rejected: int | None = None  # cumulative; chronic on the SIEM, recorded only
    blocked_indices: tuple[str, ...] = ()  # read_only_allow_delete on a target index
    ingest_lag: Mapping[str, timedelta] = field(default_factory=dict)
    stale_rules: int | None = None  # rules not run for > 3x their interval


@dataclass(frozen=True)
class Baselines:
    heap_p90: float | None = None
    load_p90: float | None = None


@dataclass(frozen=True)
class HealthMemory:
    state: HealthState = HealthState.NORMAL
    since: datetime | None = None
    probed_at: datetime | None = None  # the last probe; None: never probed
    recovered_at: datetime | None = None
    reasons: tuple[str, ...] = ()
    search_rejected: int | None = None
    breakers_tripped: int | None = None
    # per counter condition: whether it fired at each of the last probes (newest last)
    recent: tuple[tuple[str, ...], ...] = ()


def _rose(previous: int | None, current: int | None) -> bool:
    return previous is not None and current is not None and current > previous


def evaluate(
    memory: HealthMemory,
    readings: Readings,
    config: HealthConfig,
    *,
    kill_switch: bool = False,
    baselines: Baselines = Baselines(),  # noqa: B008 - frozen
) -> HealthMemory:
    enter: dict[str, int] = {}
    stay: dict[str, int] = {}

    def condition(name: str, level: int, entered: bool, stays: bool) -> None:
        if entered:
            enter[name] = level
        if entered or stays:
            stay[name] = level

    if kill_switch:
        condition("kill_switch", 3, True, False)
    condition("auth_failed", 3, readings.auth_failed, False)
    condition("index_blocked", 3, bool(readings.blocked_indices), False)
    disk = readings.disk_percent
    if disk is not None:
        for name, level, limit in (
            ("disk_stop", 3, config.disk_stop),
            ("disk_degraded", 2, config.disk_degraded),
            ("disk_caution", 1, config.disk_caution),
        ):
            condition(name, level, disk >= limit, disk >= limit - config.margin)
    condition("probe_failed", 2, not readings.probe_ok and not readings.auth_failed, False)

    fired: list[str] = []
    if _rose(memory.search_rejected, readings.search_rejected):
        fired.append("search_rejections")
    if _rose(memory.breakers_tripped, readings.breakers_tripped):
        fired.append("breaker_trips")
    if readings.search_queue:
        fired.append("search_queue")
    recent = (*memory.recent, tuple(fired))[-config.clean_probes :]
    for name, level in (("search_rejections", 2), ("breaker_trips", 2), ("search_queue", 1)):
        condition(name, level, name in fired, any(name in probe for probe in recent))

    heap_limit = baselines.heap_p90 if baselines.heap_p90 is not None else config.heap_caution
    # Late sources (per source with the trip wire): one late source affects only its own
    # "nothing found" results; two or more, or one with rising search rejections, a search
    # queue or heap over its limit, still mean DEGRADED.
    heap_now = readings.heap_percent
    pressed = bool({"search_rejections", "search_queue"} & set(fired)) or (
        heap_now is not None and heap_now > heap_limit
    )
    pressed_stays = any({"search_rejections", "search_queue"} & set(probe) for probe in recent) or (
        heap_now is not None and heap_now > heap_limit - config.margin
    )
    lags = sorted(readings.ingest_lag.items())
    late = [s for s, lag in lags if lag > config.ingest_lag_degraded]
    still = [s for s, lag in lags if lag > config.ingest_lag_degraded - config.lag_margin]
    trips = len(late) >= 2 or (len(late) == 1 and pressed)
    holds = len(still) >= 2 or (len(still) == 1 and pressed_stays)
    for source in still:
        condition(f"ingest_lag:{source}", 2, trips and source in late, holds)
    condition("stale_rules", 2, bool(readings.stale_rules), False)
    if readings.heap_percent is not None:
        heap = readings.heap_percent
        condition("heap", 1, heap > heap_limit, heap > heap_limit - config.margin)
    load_limit = baselines.load_p90 if baselines.load_p90 is not None else config.load_caution
    if readings.load_1m is not None:
        load = readings.load_1m
        condition("load", 1, load > load_limit, load > load_limit * config.load_margin)

    current = LEVEL[memory.state]
    entered = max(enter.values(), default=0)
    held = max(stay.values(), default=0)
    level = entered if entered >= current else max(entered, min(current, held))
    state = BY_LEVEL[level]
    recovered_at = memory.recovered_at
    if level < current and current >= LEVEL[HealthState.DEGRADED]:
        recovered_at = readings.at
    reasons = tuple(sorted(name for name, lvl in stay.items() if lvl == level and level))
    return replace(
        memory,
        state=state,
        since=memory.since if state is memory.state and memory.since else readings.at,
        probed_at=readings.at,
        recovered_at=recovered_at,
        reasons=reasons,
        search_rejected=readings.search_rejected
        if readings.search_rejected is not None
        else memory.search_rejected,
        breakers_tripped=readings.breakers_tripped
        if readings.breakers_tripped is not None
        else memory.breakers_tripped,
        recent=recent,
    )


def effective(memory: HealthMemory, now: datetime, config: HealthConfig) -> HealthMemory:
    """The memory as the gateway may trust it at ``now``: never probed or not probed for
    ``stale_degraded`` is at least DEGRADED, not probed for ``stale_stop`` is STOP."""
    if memory.probed_at is None:
        floor, reason = HealthState.DEGRADED, "never_probed"
    elif now - memory.probed_at >= config.stale_stop:
        floor, reason = HealthState.STOP, "probe_stale"
    elif now - memory.probed_at >= config.stale_degraded:
        floor, reason = HealthState.DEGRADED, "probe_stale"
    else:
        return memory
    if LEVEL[memory.state] >= LEVEL[floor]:
        return memory
    return replace(memory, state=floor, reasons=(reason,))


def on_auth_failed(memory: HealthMemory, at: datetime) -> HealthMemory:
    """The SIEM answered 401/403: STOP at once, without waiting for the next probe."""
    since = memory.since if memory.state is HealthState.STOP and memory.since else at
    return replace(memory, state=HealthState.STOP, since=since, reasons=("auth_failed",))


def scale(memory: HealthMemory, now: datetime, config: HealthConfig) -> float:
    """The share of the budget ARGUS may use now: a tenth in DEGRADED (the collector only),
    0 in STOP. ``memory`` is the effective one."""
    base = SCALE.get(memory.state, 0.0)
    if memory.recovered_at is not None:
        since = now - memory.recovered_at
        first, second = config.slow_start
        if since < first:
            return min(base, 0.25)
        if since < second:
            return min(base, 0.5)
    return base


def allowed(state: HealthState, purpose: Purpose) -> bool:
    return purpose in ALLOWED[state]


def readings_from_node_stats(payload: Any, at: datetime) -> Readings:
    """Readings from ``GET _nodes/_local/stats/fs,jvm,os,thread_pool,breaker``; missing parts
    are None. An answer without exactly one node, with a failed node, or without disk, heap,
    load and the search counters is a failed probe (unknown is not healthy)."""
    summary = payload.get("_nodes") if isinstance(payload, Mapping) else None
    failed = summary.get("failed") if isinstance(summary, Mapping) else None
    if failed != 0 or isinstance(failed, bool):
        return Readings(at=at, probe_ok=False)
    nodes = payload.get("nodes")
    if not isinstance(nodes, Mapping) or len(nodes) != 1:
        return Readings(at=at, probe_ok=False)
    node = next(iter(nodes.values()))
    if not isinstance(node, Mapping):
        return Readings(at=at, probe_ok=False)

    def number(*path: str) -> float | None:
        value: Any = node
        for key in path:
            value = value.get(key) if isinstance(value, Mapping) else None
        return (
            float(value) if isinstance(value, int | float) and not isinstance(value, bool) else None
        )

    total = number("fs", "total", "total_in_bytes")
    available = number("fs", "total", "available_in_bytes")
    disk = None
    if total and available is not None and 0 <= available <= total:
        disk = round((total - available) / total * 100, 2)
    breakers = node.get("breakers")
    tripped = None
    if isinstance(breakers, Mapping):
        counts = [b.get("tripped") for b in breakers.values() if isinstance(b, Mapping)]
        valid = [c for c in counts if isinstance(c, int) and not isinstance(c, bool)]
        if counts and len(valid) == len(counts):
            tripped = sum(valid)

    def count(*path: str) -> int | None:
        value = number(*path)
        return int(value) if value is not None else None

    readings = Readings(
        at=at,
        disk_percent=disk,
        heap_percent=number("jvm", "mem", "heap_used_percent"),
        load_1m=number("os", "cpu", "load_average", "1m"),
        search_queue=count("thread_pool", "search", "queue"),
        search_rejected=count("thread_pool", "search", "rejected"),
        breakers_tripped=tripped,
        write_rejected=count("thread_pool", "write", "rejected"),
    )
    required = (
        readings.disk_percent,
        readings.heap_percent,
        readings.load_1m,
        readings.search_queue,
        readings.search_rejected,
    )
    if any(value is None for value in required):
        return replace(readings, probe_ok=False)
    return readings
