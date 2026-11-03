"""Lane budgets: the load ceiling divided into lanes, each a sub-allowance.

Every request to the SIEM spends one lane's share: its own server-time bucket, daily cap, heavy
queries a day and concurrency, so a debt (a slow search, a timeout charged whole) slows only that
lane. Lanes: collector (collect, backfill, reconcile, enrich, measure), investigation, freshness,
kibana_read, kibana_write, identity and measurement (closed until adopted). ``LanePlan`` refuses
lanes that add up to more than the ceiling. Across lanes the concurrency is one pool
(``shared_wait``), heavy queries run one at a time, and health probes spend their own allowance.
``lane_of`` maps a purpose to its lane; ``admit`` / ``settle`` are pure, like the one-bucket ones.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from enum import StrEnum
from types import MappingProxyType

from argus.gateway import budget as budget_core
from argus.gateway.budget import Admission, BudgetConfig, BudgetState, Lease, Verdict
from argus.gateway.templates import CostClass, Purpose

MINUTE = timedelta(minutes=1)


class Lane(StrEnum):
    COLLECTOR = "collector"  # the collector and enrichment (the original budget)
    INVESTIGATION = "investigation"
    FRESHNESS = "freshness"
    KIBANA_READ = "kibana_read"
    KIBANA_WRITE = "kibana_write"  # Kibana case writes and alert writes
    IDENTITY = "identity"
    MEASUREMENT = "measurement"


LANE_OF: Mapping[Purpose, Lane | None] = MappingProxyType(
    {
        Purpose.PROBE: None,  # outside every lane: the probe allowance
        Purpose.SELFTEST: None,  # probe-cost; Kibana keys' self-test spends kibana_read
        Purpose.COLLECT: Lane.COLLECTOR,
        Purpose.BACKFILL: Lane.COLLECTOR,
        Purpose.RECONCILE: Lane.COLLECTOR,
        Purpose.ENRICH: Lane.COLLECTOR,
        Purpose.WRITEBACK: Lane.KIBANA_WRITE,
        Purpose.INVESTIGATE: Lane.INVESTIGATION,
        Purpose.FRESHNESS: Lane.FRESHNESS,
        Purpose.MEASURE: Lane.COLLECTOR,  # the measuring session, until the lanes are adopted
        Purpose.IDENTITY: Lane.IDENTITY,
        Purpose.KIBANA_READ: Lane.KIBANA_READ,
        Purpose.KIBANA_WRITE: Lane.KIBANA_WRITE,
        Purpose.DISCOVER: Lane.COLLECTOR,  # a person's few metadata reads, in NORMAL only
    }
)


def lane_of(purpose: Purpose) -> Lane | None:
    """The lane ``purpose`` spends; None for health probes (their own allowance)."""
    return LANE_OF[purpose]


@dataclass(frozen=True)
class LaneSpec:
    """One lane's share of the ceiling."""

    per_minute_ms: int  # server time a minute (also the burst, unless ``burst_ms``); 0 closes it
    per_day_ms: int
    heavy_per_day: int = 0
    concurrency: int = 1
    per_minute_requests: int | None = None  # identity: checks a minute (6)
    # the bucket's capacity at full scale (NORMAL health): server time that may be spent at once.
    # None: a minute's share. It is not a share: the refill and the day's cap are unchanged and it
    # does not count toward the lanes' per-minute sum
    burst_ms: int | None = None

    def __post_init__(self) -> None:
        if self.per_minute_ms < 0 or self.per_day_ms < 0 or self.heavy_per_day < 0:
            raise ValueError("a lane's allowance is never negative")
        if self.burst_ms is not None and not self.per_minute_ms <= self.burst_ms <= self.per_day_ms:
            raise ValueError("a burst is at least a minute's share and at most the day's")
        if self.concurrency < 1:
            raise ValueError("a lane runs at least one request at a time")
        if self.per_minute_requests is not None and self.per_minute_requests < 1:
            raise ValueError("a lane's request rate is at least 1 a minute")


# The lanes' table as parts of the ceiling: (a minute, a day, heavy a day, concurrency). At
# the default ceiling (3,000 ms, 60 min, 2,000 heavy) they are the table's numbers exactly; under
# another ceiling (a test's, or a measured one) every lane keeps its proportion.
SHARES: Mapping[Lane, tuple[int, int, int, int]] = MappingProxyType(
    {
        Lane.COLLECTOR: (1_800, 40, 1_600, 2),
        Lane.INVESTIGATION: (400, 6, 300, 1),
        Lane.FRESHNESS: (100, 3, 0, 1),
        Lane.KIBANA_READ: (200, 4, 0, 1),
        Lane.KIBANA_WRITE: (200, 3, 0, 1),
        Lane.IDENTITY: (300, 2, 0, 1),
        Lane.MEASUREMENT: (0, 2, 100, 1),
    }
)
SHARE_TOTALS = (3_000, 60, 2_000)
# Lanes whose bucket may hold more than a minute's share at NORMAL: the Kibana
# write lane may spend 60 s of server time at once, so a case of ~45 s posts in one or two runs.
BURSTS: Mapping[Lane, int] = MappingProxyType({Lane.KIBANA_WRITE: 60_000})
IDENTITY_CHECKS_PER_MINUTE = 6


def proportional(ceiling: BudgetConfig) -> dict[Lane, LaneSpec]:
    """The lanes for ``ceiling``: each lane's part of it, rounded down (so the lanes never
    add up to more than the ceiling)."""
    minute, day, heavy = SHARE_TOTALS
    out: dict[Lane, LaneSpec] = {}
    for lane, (m, d, h, concurrency) in SHARES.items():
        per_minute = min(ceiling.took_per_minute_ms, ceiling.burst_ms) * m // minute
        per_day = ceiling.took_per_day_ms * d // day
        burst = min(BURSTS.get(lane, 0), per_day)  # never more than the lane's day
        out[lane] = LaneSpec(
            per_minute_ms=per_minute,
            per_day_ms=per_day,
            burst_ms=burst if burst > per_minute else None,
            heavy_per_day=ceiling.heavy_per_day * h // heavy,
            concurrency=min(concurrency, ceiling.concurrency),
            per_minute_requests=IDENTITY_CHECKS_PER_MINUTE if lane is Lane.IDENTITY else None,
        )
    return out


DEFAULT_LANES: Mapping[Lane, LaneSpec] = MappingProxyType(proportional(BudgetConfig()))


@dataclass(frozen=True)
class LanePlan:
    """The ceiling (``BudgetConfig``) and every lane's share of it."""

    ceiling: BudgetConfig = field(default_factory=BudgetConfig)
    lanes: Mapping[Lane, LaneSpec] | None = None  # None: the proportions of the ceiling

    def __post_init__(self) -> None:
        if self.lanes is None:
            object.__setattr__(self, "lanes", MappingProxyType(proportional(self.ceiling)))
        assert self.lanes is not None
        missing = set(Lane) - set(self.lanes)
        if missing:
            raise ValueError(f"no allowance for lanes {', '.join(sorted(missing))}")
        for lane, spec in self.lanes.items():
            if spec.concurrency > self.ceiling.concurrency:
                raise ValueError(
                    f"the {lane} lane's concurrency ({spec.concurrency}) exceeds the ceiling's"
                    f" ({self.ceiling.concurrency}, D-022)"
                )
        identity = self.lanes[Lane.IDENTITY].per_minute_requests
        if identity is None or identity > IDENTITY_CHECKS_PER_MINUTE:
            raise ValueError(
                f"the identity lane checks at most {IDENTITY_CHECKS_PER_MINUTE} a minute (§7.8)"
            )
        specs = list(self.lanes.values())
        for what, total, limit in (
            ("server time a minute", sum(s.per_minute_ms for s in specs), self.ceiling.burst_ms),
            ("server time a minute", sum(s.per_minute_ms for s in specs),
             self.ceiling.took_per_minute_ms),
            ("server time a day", sum(s.per_day_ms for s in specs), self.ceiling.took_per_day_ms),
            ("heavy queries a day", sum(s.heavy_per_day for s in specs),
             self.ceiling.heavy_per_day),
        ):  # fmt: skip
            if total > limit:
                raise ValueError(f"the lanes' {what} ({total}) exceeds the ceiling's ({limit})")

    def spec(self, lane: Lane) -> LaneSpec:
        assert self.lanes is not None
        return self.lanes[lane]

    def config(self, lane: Lane) -> BudgetConfig:
        """The lane's bucket as ``budget.py`` takes it."""
        spec = self.spec(lane)
        return replace(
            self.ceiling,
            took_per_minute_ms=spec.per_minute_ms,
            burst_ms=spec.per_minute_ms if spec.burst_ms is None else spec.burst_ms,
            strained_burst_ms=None if spec.burst_ms is None else spec.per_minute_ms,
            took_per_day_ms=spec.per_day_ms,
            heavy_per_day=spec.heavy_per_day,
            concurrency=spec.concurrency,
        )


def plan_from(ceiling: BudgetConfig, given: Mapping[str, LaneSpec | None]) -> LanePlan:
    """The plan for ``ceiling`` with the lanes ``given`` (by name; None or absent: the lane's
    share of the ceiling). ValueError if they exceed it. Used by the settings' own check, so
    it imports nothing beyond the budget."""
    lanes = proportional(ceiling)
    for name, spec in given.items():
        if spec is not None:
            lane = Lane(name)
            if lane is Lane.IDENTITY and spec.per_minute_requests is None:
                spec = replace(spec, per_minute_requests=IDENTITY_CHECKS_PER_MINUTE)
            lanes[lane] = spec
    return LanePlan(ceiling, lanes)


@dataclass(frozen=True)
class LaneStates:
    """Every lane's bucket (``BudgetState``), and the request starts of the rate-limited
    lanes. The collector's bucket is kept apart (the original ``budget`` state) and passed in
    where a rule spans every lane."""

    buckets: Mapping[Lane, BudgetState] = field(default_factory=dict)
    starts: Mapping[Lane, tuple[datetime, ...]] = field(default_factory=dict)

    def bucket(self, lane: Lane) -> BudgetState:
        return self.buckets.get(lane, BudgetState())


def _live_heavy(state: BudgetState, now: datetime) -> tuple[int, tuple[datetime, ...]]:
    """(heavy leases still held, heavy starts within the last minute) of one bucket."""
    held = sum(1 for lease in state.leases if lease.cost is CostClass.HEAVY and lease.expires > now)
    return held, tuple(t for t in state.heavy_starts if now - t < MINUTE)


def shared_wait(
    buckets: Mapping[Lane, BudgetState], lane: Lane, now: datetime, ceiling: BudgetConfig
) -> Admission | None:
    """The concurrency limit across every lane (``buckets`` holds each lane's bucket, the
    collector's included): a WAIT if ``ceiling.concurrency`` requests run now, or if ``lane`` is
    not the collector's and the other lanes already hold all but one slot (the collector's own,
    kept for it whatever they do); else None. Health probes hold leases in the collector's
    bucket, so they count too."""
    live = [(other, x) for other, state in buckets.items() for x in state.leases if x.expires > now]
    limit = ceiling.concurrency
    if len(live) >= limit:
        return Admission(Verdict.WAIT, "concurrency", retry_at=min(x.expires for _, x in live))
    others = [x for other, x in live if other is not Lane.COLLECTOR]
    if lane is not Lane.COLLECTOR and limit >= 2 and len(others) >= limit - 1:
        return Admission(Verdict.WAIT, "concurrency", retry_at=min(x.expires for x in others))
    return None


def heavy_elsewhere(
    buckets: Mapping[Lane, BudgetState], lane: Lane, now: datetime, config: BudgetConfig
) -> Admission | None:
    """The cross-lane heavy rule: a WAIT if a heavy query of another lane runs now, or if the
    lanes together started ``heavy_per_minute`` heavy queries in the last minute; else None."""
    held = 0
    starts: list[datetime] = []
    leases: list[Lease] = []
    for other, state in buckets.items():
        h, s = _live_heavy(state, now)
        starts += s
        if other is not lane:
            held += h
            leases += [x for x in state.leases if x.cost is CostClass.HEAVY and x.expires > now]
    if held >= config.heavy_concurrency:
        return Admission(Verdict.WAIT, "heavy_concurrency", retry_at=min(x.expires for x in leases))
    if len(starts) >= config.heavy_per_minute:
        return Admission(Verdict.WAIT, "heavy_rate", retry_at=min(starts) + MINUTE)
    return None


def admit(
    states: LaneStates,
    plan: LanePlan,
    lane: Lane,
    cost: CostClass,
    now: datetime,
    *,
    scale: float,
    lease_id: str,
    collector: BudgetState | None = None,
    kept: int = 0,
) -> tuple[Admission, LaneStates]:
    """Admit one request of ``lane`` (not the collector's: its bucket is ``budget_admit``).
    ``collector`` is the collector's bucket, for the rules across lanes. ``kept`` is how many
    of a rate-limited lane's requests a minute this request must leave to others (a
    sign-in leaves two to the re-checks of open sessions); a request may always take at
    least one a minute."""
    if kept < 0:
        raise ValueError("a request keeps no fewer than zero checks for others")
    if lane is Lane.COLLECTOR:
        raise ValueError("the collector's lane is the original budget (budget_admit)")
    if cost is CostClass.PROBE:
        raise ValueError("health probes spend their own allowance, not a lane")
    spec = plan.spec(lane)
    if spec.per_minute_ms == 0:
        return Admission(Verdict.EXHAUSTED, "lane_closed"), states
    config = plan.config(lane)
    if cost is CostClass.HEAVY and spec.heavy_per_day > 0:
        everyone = {**states.buckets, Lane.COLLECTOR: collector or BudgetState()}
        waiting = heavy_elsewhere(everyone, lane, now, config)
        if waiting is not None:
            return waiting, states
    everyone = {**states.buckets, Lane.COLLECTOR: collector or BudgetState()}
    waiting = shared_wait(everyone, lane, now, plan.ceiling)
    if waiting is not None:
        return waiting, states
    starts = tuple(t for t in states.starts.get(lane, ()) if now - t < MINUTE)
    if spec.per_minute_requests is not None:
        limit = max(spec.per_minute_requests - kept, 1)
        if len(starts) >= limit:
            retry_at = sorted(starts)[len(starts) - limit] + MINUTE  # one of the limit frees
            return Admission(Verdict.WAIT, "request_rate", retry_at=retry_at), states
    if kept > 0 and spec.per_minute_requests is not None and starts:
        # the kept requests need server time too: this request may not
        # leave the lane's bucket with less than ``kept`` light calls' worth, else the kept
        # starts are unusable; it waits for the refill, never past the minute it would take.
        # Only rate-limited lanes keep anything, and a request may always take the minute's
        # first start (the rule above)
        rolled = budget_core.roll(states.bucket(lane), config, now, scale)
        tokens = rolled.tokens_ms if rolled.tokens_ms is not None else config.burst_ms * scale
        short = kept * config.estimate_ms[CostClass.LIGHT] + config.estimate_ms[cost] - tokens
        if short > 0:
            per_minute = config.took_per_minute_ms * scale
            wait = MINUTE * min(short / per_minute, 1.0) if per_minute > 0 else MINUTE
            return Admission(Verdict.WAIT, "kept_for_rechecks", retry_at=now + wait), states
    admission, bucket = budget_core.admit(
        states.bucket(lane), config, cost, now, scale=scale, lease_id=lease_id
    )
    buckets = {**states.buckets, lane: bucket}
    started = dict(states.starts)
    if spec.per_minute_requests is not None:
        started[lane] = (*starts, now) if admission.verdict is Verdict.ADMITTED else starts
    return admission, LaneStates(buckets, started)


def settle(
    states: LaneStates,
    plan: LanePlan,
    lane: Lane,
    lease: Lease,
    took_ms: int,
    now: datetime,
    *,
    scale: float,
) -> LaneStates:
    """The request of ``lease`` on ``lane`` is over and cost ``took_ms``."""
    if lane is Lane.COLLECTOR:
        raise ValueError("the collector's lane is the original budget (budget_settle)")
    bucket = budget_core.settle(
        states.bucket(lane), plan.config(lane), lease, took_ms, now, scale=scale
    )
    return replace(states, buckets={**states.buckets, lane: bucket})


def fill(
    states: LaneStates, plan: LanePlan, lane: Lane, now: datetime, *, scale: float
) -> tuple[float, float, LaneStates]:
    """A person's top-up of one lane's bucket to its capacity: returns the server time the
    bucket held (after bringing it to ``now``), what it holds now, and the new states. Only at
    full scale (the SIEM NORMAL, no slow start: the burst exists only then), never for the
    collector's lane (the original budget) or a closed one, never over a debt (a slow call's
    cost is real: the refill pays it), and it never lowers a bucket. The day's cap, the
    concurrency and the other lanes are untouched."""
    if lane is Lane.COLLECTOR:
        raise ValueError("the collector's lane is the original budget, not a lane bucket")
    if scale < 1.0:
        raise ValueError("a bucket is topped up only while the SIEM is NORMAL (full scale)")
    spec = plan.spec(lane)
    if spec.per_minute_ms == 0:
        raise ValueError(f"the {lane} lane is closed")
    config = plan.config(lane)
    rolled = budget_core.roll(states.bucket(lane), config, now, scale)
    before = rolled.tokens_ms if rolled.tokens_ms is not None else 0.0
    if before < 0:
        raise ValueError(f"the {lane} lane is in debt ({-before:.0f} ms): the refill pays it first")
    after = max(before, budget_core.capacity(config, scale))
    filled = replace(rolled, tokens_ms=after)
    return before, after, replace(states, buckets={**states.buckets, lane: filled})


def collector_wait(
    states: LaneStates,
    collector: BudgetState,
    cost: CostClass,
    now: datetime,
    config: BudgetConfig,
    ceiling: BudgetConfig,
) -> Admission | None:
    """The rules across lanes seen from the collector's lane (``budget_admit``, probes
    included): heavy queries one at a time, then the shared concurrency limit."""
    everyone = {**states.buckets, Lane.COLLECTOR: collector}
    if cost is CostClass.HEAVY:
        waiting = heavy_elsewhere(everyone, Lane.COLLECTOR, now, config)
        if waiting is not None:
            return waiting
    return shared_wait(everyone, Lane.COLLECTOR, now, ceiling)
