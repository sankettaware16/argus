"""The capacity model (plan §11, D-054): does enrichment fit the SIEM's load budget?

A discrete-event simulation that drives the **real budget code** (``argus.gateway.budget``:
token bucket, daily cap, concurrency, heavy limits) with:

* a job stream replayed from stored alerts (when each investigation got a new alert) under
  R6's rules: a new investigation runs at once, a changed one at most every 30 minutes, a
  change during a run queues it again;
* a per-run request profile (cost classes of the first run and of a re-run) with log-normal
  server times per cost class, and the collector's own polling sharing the budget;
* an optional outage (the SIEM unavailable: runs deferred with the worker's backoff), then the
  health state's slow start (a quarter, then half, then all of the budget).

Pure and seeded: the same inputs give the same report.
"""

from __future__ import annotations

import bisect
import heapq
import math
import random
import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from argus.gateway import budget
from argus.gateway.budget import BudgetConfig, BudgetState, Verdict
from argus.gateway.gateway import POLL, POLL_REASONS
from argus.gateway.templates import CostClass
from argus.jobs.queue import COALESCE, DEFER_MAX, DEFER_STEP

MINUTE = timedelta(minutes=1)
SLOW_START = ((timedelta(minutes=20), 0.25), (timedelta(minutes=40), 0.5))
NETWORK_MS = 15  # round trip on top of server time
EVENTS_PER_INPUT = 200


@dataclass(frozen=True)
class Profile:
    """What one run asks of the SIEM, in order (one request at a time within a run)."""

    name: str
    first: tuple[CostClass, ...]
    rerun: tuple[CostClass, ...]


@dataclass(frozen=True)
class Latency:
    """Server time per cost class: log-normal from a median and a 95th percentile (ms)."""

    median_ms: dict[CostClass, float]
    p95_ms: dict[CostClass, float]

    def sample(self, cost: CostClass, rng: random.Random) -> int:
        median, p95 = self.median_ms[cost], self.p95_ms[cost]
        sigma = math.log(p95 / median) / 1.6449
        return max(1, round(rng.lognormvariate(math.log(median), sigma)))


@dataclass(frozen=True)
class Scenario:
    profile: Profile
    latency: Latency
    budget: BudgetConfig = field(default_factory=BudgetConfig)
    runs_at_once: int = 2  # runs in flight (the worker's concurrency, bounded by the gateway)
    collector_ms: tuple[int, int] = (10, 110)  # its poll each minute: ids, then mget
    outage: tuple[datetime, datetime] | None = None
    seed: int = 0


@dataclass
class Report:
    runs: dict[str, int] = field(default_factory=dict)  # by trigger
    requests: int = 0
    skipped: int = 0  # refused by the daily caps: skipped_budget
    enrich_ms_by_day: dict[str, int] = field(default_factory=dict)
    collector_ms_by_day: dict[str, int] = field(default_factory=dict)
    busiest_minute_ms: int = 0
    max_wait_s: float = 0.0  # from due to finished (the dossier written), the longest
    p95_wait_s: float = 0.0
    backlog_peak: int = 0
    drained_after: timedelta | None = None  # from the outage's end
    unfinished: int = 0
    waits: list[float] = field(default_factory=list, repr=False)

    def share(self, config: BudgetConfig, days: Sequence[str] | None = None) -> float:
        """Enrichment's server time over full days, as a share of the daily cap."""
        chosen = list(days) if days else sorted(self.enrich_ms_by_day)
        if not chosen:
            return 0.0
        used = sum(self.enrich_ms_by_day.get(d, 0) for d in chosen)
        return used / (config.took_per_day_ms * len(chosen))


@dataclass
class _Job:
    inv: int
    trigger: str
    due: datetime
    first: bool
    deferrals: int = 0
    remaining: list[CostClass] = field(default_factory=list)
    started: bool = False

    serial: int = 0

    def __post_init__(self) -> None:
        self.origin = self.due  # when it first became due, whatever deferrals followed


class _Sim:
    """Events in time order: changes, due jobs, request steps and settles, collector polls."""

    def __init__(self, changes: Sequence[tuple[datetime, int]], scenario: Scenario) -> None:
        self.sc = scenario
        self.cfg = scenario.budget
        self.rng = random.Random(scenario.seed)  # noqa: S311 - a seeded model, not a secret
        self.report = Report()
        self.state = BudgetState()
        self.heap: list[tuple[datetime, int, str, int, object]] = []
        self.order = 0
        self.version: dict[int, int] = {}
        self.seen: set[int] = set()
        self.last_done: dict[int, datetime] = {}
        self.active: dict[int, _Job] = {}
        self.queued: list[tuple[datetime, int, int]] = []
        self.running: dict[int, int] = {}
        self.free = scenario.runs_at_once
        self.by_minute: dict[datetime, int] = {}
        self.backlog: set[int] | None = None  # serials of the jobs waiting when it ended
        self.serial = 0
        events = sorted(changes)
        self.start, self.end = events[0][0], events[-1][0] + timedelta(hours=12)
        for at, inv in events:
            self.push(at, "change", inv)
        first = self.start.replace(second=0, microsecond=0)
        minutes = int((self.end - first) / MINUTE) + 1
        for n in range(minutes):
            self.push(first + n * MINUTE, "poll", -1)
        # A run that has not settled after this many events is broken (never a real stream:
        # each change or poll causes a handful): stop instead of filling memory.
        self.budget = EVENTS_PER_INPUT * (len(events) + minutes)

    def push(self, at: datetime, kind: str, inv: int, data: object = None) -> None:
        heapq.heappush(self.heap, (at, self.order, kind, inv, data))
        self.order += 1

    def scale(self, now: datetime) -> float:
        outage = self.sc.outage
        if outage is None:
            return 1.0
        if outage[0] <= now < outage[1]:
            return 0.0
        if now >= outage[1]:
            for span, share in SLOW_START:
                if now - outage[1] < span:
                    return share
        return 1.0

    def enqueue(self, job: _Job) -> None:
        self.serial += 1
        job.serial = self.serial
        self.active[job.inv] = job
        heapq.heappush(self.queued, (job.due, self.order, job.inv))
        self.push(job.due, "due", job.inv)

    def charge(self, now: datetime, took: int, *, enrich: bool) -> None:
        day = now.date().isoformat()
        target = self.report.enrich_ms_by_day if enrich else self.report.collector_ms_by_day
        target[day] = target.get(day, 0) + took
        key = now.replace(second=0, microsecond=0)
        self.by_minute[key] = self.by_minute.get(key, 0) + took

    def admit(self, now: datetime, cost: CostClass, s: float) -> budget.Admission:
        lease_id = uuid.UUID(int=self.rng.getrandbits(128)).hex
        admission, self.state = budget.admit(
            self.state, self.cfg, cost, now, scale=s, lease_id=lease_id
        )
        return admission

    @staticmethod
    def retry(now: datetime, admission: budget.Admission) -> datetime:
        """When to ask again, as the gateway does: a lease's expiry is only an upper bound
        for a free slot, so slots are asked for again every POLL."""
        at = admission.retry_at or now + timedelta(seconds=1)
        if admission.reason in POLL_REASONS:
            at = min(at, now + POLL)
        return max(at, now + timedelta(milliseconds=50))

    # ------------------------------------------------------------------ handlers

    def on_change(self, now: datetime, inv: int) -> None:
        self.version[inv] = self.version.get(inv, 0) + 1
        if inv in self.active:
            return  # the active job takes the newest version when it starts
        first = inv not in self.seen
        self.seen.add(inv)
        due = now if first else max(now, self.last_done.get(inv, now) + COALESCE)
        self.enqueue(_Job(inv, "created" if first else "new_alerts", due, first))

    def on_poll(self, now: datetime) -> None:
        s = self.scale(now)
        if s > 0:
            self.push(now, "collect", -1, list(self.sc.collector_ms))
        report, outage = self.report, self.sc.outage
        due = [i for d, _, i in self.queued if d <= now and i in self.active]
        report.backlog_peak = max(report.backlog_peak, len(due))
        if outage and now >= outage[1] and report.drained_after is None:
            if self.backlog is None:  # every job that was due before the outage ended
                self.backlog = {j.serial for j in self.active.values() if j.origin < outage[1]}
            waiting = {j.serial for j in self.active.values()} & self.backlog
            if not waiting:
                report.drained_after = now - outage[1]

    def on_collect(self, now: datetime, tooks: list[int]) -> None:
        if not tooks:
            return
        admission = self.admit(now, CostClass.LIGHT, max(self.scale(now), 0.1))
        if admission.verdict is Verdict.ADMITTED:
            assert admission.lease is not None
            took = tooks[0]
            done = now + timedelta(milliseconds=took + NETWORK_MS)
            self.charge(now, took, enrich=False)
            self.push(done, "settle", -1, (admission.lease, took, tooks[1:]))
        elif admission.verdict is Verdict.WAIT:
            self.push(self.retry(now, admission), "collect", -1, tooks)

    def start_due(self, now: datetime) -> None:
        while self.free > 0 and self.queued and self.queued[0][0] <= now:
            due, _, inv = heapq.heappop(self.queued)
            job = self.active.get(inv)
            if job is None or job.due != due or inv in self.running:
                continue
            self.free -= 1
            self.running[inv] = self.version[inv]
            if not job.started:
                job.started = True
                job.remaining = list(self.sc.profile.first if job.first else self.sc.profile.rerun)
                self.report.runs[job.trigger] = self.report.runs.get(job.trigger, 0) + 1
            self.push(now, "step", inv)

    def on_step(self, now: datetime, inv: int) -> None:
        job = self.active[inv]
        if not job.remaining:  # nothing (more) to ask the SIEM: local work only
            self.finish(now, inv)
            return
        s = self.scale(now)
        if s <= 0:  # SourceUnavailable: deferred, resumes with what is left
            self.free += 1
            self.running.pop(inv)
            job.due = now + min(DEFER_STEP * (2**job.deferrals), DEFER_MAX)
            job.deferrals += 1
            heapq.heappush(self.queued, (job.due, self.order, inv))
            self.push(job.due, "due", inv)
            return
        cost = job.remaining[0]
        admission = self.admit(now, cost, s)
        if admission.verdict is Verdict.EXHAUSTED:
            self.report.requests += 1
            self.report.skipped += 1
            job.remaining.pop(0)
            self.push(now, "step", inv)
        elif admission.verdict is Verdict.ADMITTED:
            assert admission.lease is not None
            self.report.requests += 1
            job.remaining.pop(0)
            took = self.sc.latency.sample(cost, self.rng)
            self.charge(now, took, enrich=True)
            done = now + timedelta(milliseconds=took + NETWORK_MS)
            self.push(done, "settle", inv, (admission.lease, took, None))
        else:
            self.push(self.retry(now, admission), "step", inv)

    def on_settle(self, now: datetime, inv: int, data: object) -> None:
        assert isinstance(data, tuple)
        lease: budget.Lease = data[0]
        took: int = data[1]
        rest: list[int] | None = data[2]
        s = max(self.scale(now), 0.1)
        self.state = budget.settle(self.state, self.cfg, lease, took, now, scale=s)
        if inv < 0:
            self.push(now, "collect", -1, rest)
        else:
            self.push(now, "step", inv)

    def finish(self, now: datetime, inv: int) -> None:
        self.free += 1
        job = self.active.pop(inv)
        self.report.waits.append((now - job.origin).total_seconds())
        claimed = self.running.pop(inv)
        self.last_done[inv] = now
        if self.version[inv] > claimed:
            self.enqueue(_Job(inv, "changed_while_running", now + COALESCE, False))

    def run(self) -> Report:
        handled = 0
        while self.heap:
            handled += 1
            if handled > self.budget or len(self.heap) > self.budget:
                raise RuntimeError(f"the simulation did not settle after {handled} events")
            now, _, kind, inv, data = heapq.heappop(self.heap)
            if now > self.end:
                break
            if kind == "change":
                self.on_change(now, inv)
            elif kind == "poll":
                self.on_poll(now)
            elif kind == "collect":
                self.on_collect(now, data)  # type: ignore[arg-type]
            elif kind == "step":
                self.on_step(now, inv)
            elif kind == "settle":
                self.on_settle(now, inv, data)
            self.start_due(now)
        report = self.report
        report.unfinished = len(self.active)
        report.busiest_minute_ms = max(self.by_minute.values(), default=0)
        if report.waits:
            ordered = sorted(report.waits)
            report.max_wait_s = ordered[-1]
            report.p95_wait_s = ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))]
        return report


def simulate(changes: Sequence[tuple[datetime, int]], scenario: Scenario) -> Report:
    """Run the stream through the queue rules and the budget; returns what it cost."""
    if not changes:
        return Report()
    return _Sim(changes, scenario).run()


def full_days(changes: Sequence[tuple[datetime, int]]) -> list[str]:
    """The UTC days the stream covers from start to end (not its first and last day)."""
    if not changes:
        return []
    first, last = min(changes)[0].date(), max(changes)[0].date()
    days = []
    day = first + timedelta(days=1)
    while day < last:
        days.append(day.isoformat())
        day += timedelta(days=1)
    return days


# Assumptions until R10-R14 measure their templates on es-local and live (D-054): server time
# per cost class (light from the request ledger: alert mget/ids; medium and heavy guessed for
# filtered log searches and aggregations on one daily index) and per-run profiles to compare.
_M, _H, _L, _P = CostClass.MEDIUM, CostClass.HEAVY, CostClass.LIGHT, CostClass.PROBE
LATENCY = Latency(
    median_ms={_P: 10, _L: 30, _M: 150, _H: 800}, p95_ms={_P: 30, _L: 200, _M: 600, _H: 3000}
)
PROFILES = {
    p.name: p
    for p in (
        Profile("stub", (), ()),
        Profile("small", (_M, _M, _L), (_M,)),
        Profile("rich-rederive", (_M, _M, _M, _M, _H, _L, _L), ()),
        Profile("medium", (_M, _M, _M, _H, _L), (_M, _H)),
        Profile("rich", (_M, _M, _M, _M, _H, _L, _L), (_M, _M, _H)),
    )
}


def busiest_start(changes: Sequence[tuple[datetime, int]], span: timedelta) -> datetime:
    """The start of the ``span`` with the most changes (sampled every 200 changes)."""
    times = sorted(t for t, _ in changes)
    candidates = times[::200] or times
    return max(candidates, key=lambda t: rate_at(changes, t + span, span))


def rate_at(
    changes: Sequence[tuple[datetime, int]], at: datetime, span: timedelta = timedelta(hours=1)
) -> int:
    """How many changes in the ``span`` before ``at``."""
    times = [t for t, _ in sorted(changes)]
    return bisect.bisect_left(times, at) - bisect.bisect_left(times, at - span)
