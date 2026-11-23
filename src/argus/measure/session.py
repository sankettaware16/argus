"""One measuring session through the gateway.

A person runs it at a terminal, in NORMAL health, never in the quiet hours. It sends ARGUS's own
production templates (only ones already sent in production), each a few times with different
windows or subjects, through ``Gateway.run`` with the ``measure`` purpose, so the shared budget,
heavy cap, breaker, kill switch and ledger apply. On top, its own stricter rules: at most 50
requests and 10 heavy ones (counted where requests leave, ``CappedTransport``), heavy requests at
least 10 s apart, at most 3 s of server time in any 60 s (all of ARGUS counted from the ledger),
and before every request the kill switches, breaker, quiet hours, health and a fresh probe. Any
CAUTION signal or failed request **ends the session**, and the gateway is never let retry.
``verify`` then reads the ledger and probe readings back and checks the session's limits.
"""

from __future__ import annotations

import asyncio
import itertools
import math
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

# Every module that registers a template ARGUS sends: ``cost_of`` reads the registry, and an
# unknown name counts as heavy, so each must be imported in this process (a test
# compares this process's registry with every ``@register`` in the package).
from argus import site
from argus.collector.templates import AlertCounts, AlertStates, CountsParams, StatesParams
from argus.context import beacon, dns, live_check, paths, source_events  # noqa: F401
from argus.context.bounds import quiet
from argus.context.proxy import ProxyDestination, ProxyHost, WindowParams, _days
from argus.context.web import FollowParams, WebFollowups
from argus.freshness import template as _freshness_template  # noqa: F401  (its cost)
from argus.gateway.builtin import AlertIds, AlertIdsParams, AlertsMget, MgetParams
from argus.gateway.errors import (
    DeadlinePassedError,
    DeferredError,
    GatewayError,
    RefusedError,
    StoppedError,
)
from argus.gateway.gateway import Gateway
from argus.gateway.health import HealthConfig, HealthMemory, HealthState, effective, scale
from argus.gateway.state import GatewayState, ProbeRow, RecentRequest
from argus.gateway.templates import REGISTRY, CostClass, Params, Purpose, Template
from argus.gateway.transport import Transport, WireRequest, WireResponse
from argus.reference.templates import NewestParams, TiLookup, TiNewest, lookup_params
from argus.reference.ti import variants
from argus.risk import webchecks as _exposure_templates  # noqa: F401  (their cost)
from argus.signins import template as _signins_template  # noqa: F401  (its cost)

COMPONENT = "measure"  # the session's ledger rows: its requests and its own probes
MINUTE = timedelta(minutes=1)
IDS_PAGE = 1_000  # the collector's page (collector.PAGE)
MGET_BATCH = 200  # the collector's mget (collector.MGET)
IDS_WINDOW = timedelta(minutes=10)
LOG_WINDOW = timedelta(hours=1)


@dataclass(frozen=True)
class Limits:
    """The session's own rules; the budget's still apply underneath."""

    max_requests: int = 50  # every request, its probes and index listings included
    max_heavy: int = 10
    heavy_gap: timedelta = timedelta(seconds=10)
    pace_slack: timedelta = timedelta(seconds=1)  # the pacer waits this much longer
    minute_ms: int = 3_000  # server time in any 60 s, all of ARGUS
    heavy_per_minute: int = 6  # all of ARGUS
    samples: int = 3  # per template: the derivation needs at least 3
    cap_s: tuple[tuple[CostClass, int], ...] = (
        (CostClass.LIGHT, 1),
        (CostClass.MEDIUM, 1),
        (CostClass.HEAVY, 2),
    )  # Elasticsearch's own timeout per request: the most server time it may take
    wire_slack: timedelta = timedelta(milliseconds=300)  # the wire waits this much longer
    margin_ms: int = 200  # room kept on top of the most a request can be charged
    probe_fresh: timedelta = timedelta(seconds=60)
    reserve: int = 4  # requests kept back: an index listing and the closing probe
    budget_wait: timedelta = timedelta(seconds=30)  # the longest wait for the shared budget
    busy_retries: int = 3  # tries when the shared budget is busy (nothing was sent)
    busy_pause: timedelta = timedelta(seconds=5)
    max_wait: timedelta = timedelta(seconds=120)  # the longest wait for room
    max_duration: timedelta = timedelta(minutes=20)
    # a move to CAUTION within 5 minutes after ARGUS used more than 1,500 ms in a minute
    # counts against ARGUS, so verify watches the readings that long after such a session
    attribution: timedelta = timedelta(minutes=5)
    attribution_ms: int = 1_500

    def cap(self, cost: CostClass) -> int:
        """Seconds of server time a request of this class may take (its search timeout)."""
        return dict(self.cap_s).get(cost, max(s for _, s in self.cap_s))

    def timeout(self, cost: CostClass) -> timedelta:
        """The request's own timeout: Elasticsearch stops at ``cap`` seconds (the gateway sends
        whole seconds), the wire waits ``wire_slack`` longer for the answer."""
        return timedelta(seconds=self.cap(cost)) + self.wire_slack

    def need_ms(self, cost: CostClass) -> int:
        """Room a request needs in the last minute: the most the gateway can charge it (a
        timed-out request is charged its whole wire timeout), plus a margin."""
        return int(self.timeout(cost).total_seconds() * 1_000) + self.margin_ms


LIMITS = Limits()


def cost_of(template: str) -> CostClass:
    """A ledger row's cost class from its template's name; an unknown name counts as heavy."""
    found = REGISTRY.get(template)
    return found.cost if found is not None else CostClass.HEAVY


def _template_of(request: WireRequest) -> str:
    """The template's name from the opaque id ``argus-<component>/<name>@<version>``."""
    return request.opaque_id.split("/", 1)[-1].rsplit("@", 1)[0]


# --------------------------------------------------------------------------- the plan


@dataclass(frozen=True)
class Planned:
    label: str  # "proxy.host #2"
    template: Template
    params: Params

    @property
    def name(self) -> str:
        return type(self.template).name

    @property
    def cost(self) -> CostClass:
        return type(self.template).cost


@dataclass(frozen=True)
class Subjects:
    """What the session asks about, from the newest stored alerts (no request to the SIEM)."""

    host: str | None = None  # a proxy host (squid)
    destination: str | None = None  # a public destination (squid)
    client: str | None = None  # a web client (nginx)
    mget: tuple[tuple[str, tuple[str, ...]], ...] = ()  # (backing index, ids) batches


@dataclass(frozen=True)
class Plan:
    items: tuple[Planned, ...]
    skipped: tuple[str, ...] = ()  # what is not measured, and why

    @property
    def heavy(self) -> int:
        return sum(1 for item in self.items if item.cost is CostClass.HEAVY)


async def gather_subjects(conn: AsyncConnection, batches: int = LIMITS.samples) -> Subjects:
    who = await live_check.subjects(conn)
    rows = await conn.execute(
        text(
            "SELECT index, alert_id FROM alert_records WHERE index = (SELECT index FROM"
            " alert_records ORDER BY detected_at DESC NULLS LAST, alert_id LIMIT 1)"
            " ORDER BY detected_at DESC NULLS LAST, alert_id LIMIT :n"
        ),
        {"n": batches * MGET_BATCH},
    )
    found = rows.all()
    chunks = tuple(
        (found[at][0], tuple(row[1] for row in found[at : at + MGET_BATCH]))
        for at in range(0, len(found), MGET_BATCH)
    )
    return Subjects(who["host"], who["destination"], who["client"], chunks)


def log_windows(now: datetime, count: int) -> list[tuple[datetime, datetime]] | str:
    """``count`` one-hour windows, newest first, each inside one daily index and before the
    ingest margin (live_check.window), an hour apart so that none repeats; or why not now."""
    base = live_check.window(now, LOG_WINDOW)
    if isinstance(base, str):
        return base
    start, end = base
    found = []
    for back in range(24):
        shifted = (start - back * LOG_WINDOW, end - back * LOG_WINDOW)
        if _days(*shifted) == 1:
            found.append(shifted)
        if len(found) == count:
            break
    return found


def build_plan(
    subjects: Subjects,
    now: datetime,
    *,
    history: timedelta,
    log_queries: bool,
    proxy_aggregations: bool,
    samples: int = LIMITS.samples,
    limits: Limits = LIMITS,
) -> Plan:
    """The session's requests, in the order they go: light and medium ones between the heavy
    ones, so the heavy gap costs no time. Only templates ARGUS already sends in production;
    each sample differs (window or subject), so none is answered from a cache."""
    if samples < 3:
        raise ValueError("the derivation needs at least 3 samples of each template")
    hour = now.replace(minute=0, second=0, microsecond=0)
    rounds: list[list[Planned]] = [[] for _ in range(samples)]
    heavy: list[Planned] = []
    skipped: list[str] = []

    ti_sources = site.active().ti_sources

    def add(k: int, template: Template, params: Params) -> None:
        rounds[k].append(Planned(f"{type(template).name} #{k + 1}", template, params))

    for k in range(samples):
        end = now - k * IDS_WINDOW
        add(k, AlertIds(), AlertIdsParams(start=end - IDS_WINDOW, end=end, size=IDS_PAGE))
        add(k, AlertCounts(), CountsParams(start=hour - (k + 1) * timedelta(hours=1), hours=1))
        moved = now - k * MINUTE
        add(k, AlertStates(), StatesParams(start=moved - history, end=moved))
        if ti_sources:
            add(k, TiNewest(), NewestParams(index=ti_sources[k % len(ti_sources)].index))
    for k, (index, ids) in enumerate(subjects.mget[:samples]):
        add(k, AlertsMget(), MgetParams(index=index, ids=ids))
    if len(subjects.mget) < samples:
        skipped.append(f"alerts.mget: {len(subjects.mget)} of {samples} batches of stored alerts")
    values = [v for v in (subjects.host, subjects.destination, subjects.client) if v]
    lookups = site.active().ti_lookups
    for k, value in enumerate(values[:samples] if lookups else []):
        add(k, TiLookup(), lookup_params([lookups[k % len(lookups)]], tuple(variants("ip", value))))
    if not ti_sources:
        skipped.append("ti.newest, ti.lookup: the site names no threat-intel source")
    elif len(values) < samples or not lookups:
        skipped.append(f"ti.lookup: {len(values)} of {samples} addresses in the stored alerts")

    windows = log_windows(now, samples)
    logs_now = not isinstance(windows, str)
    if isinstance(windows, str):
        skipped.append(f"log templates: {windows}")
        windows = []
    elif len(windows) < samples:
        skipped.append(f"log templates: only {len(windows)} one-hour windows today")
    if not log_queries:
        skipped.append("web.followups: off in the settings (enrichment.log_queries)")
    elif subjects.client is None:
        skipped.append("web.followups: no web client in the stored alerts")
    elif logs_now:
        for k, (start, end) in enumerate(windows):
            add(k, WebFollowups(), FollowParams(ip=subjects.client, start=start, end=end))
    if not proxy_aggregations:
        skipped.append("proxy.host, proxy.destination: off in the settings")
    else:
        for template, subject in ((ProxyHost(), subjects.host),
                                  (ProxyDestination(), subjects.destination)):  # fmt: skip
            if subject is None:
                skipped.append(f"{type(template).name}: no subject in the stored alerts")
                continue
            for k, (start, end) in enumerate(windows):
                params = WindowParams(ip=subject, start=start, end=end)
                heavy.append(Planned(f"{type(template).name} #{k + 1}", template, params))
    heavy.sort(key=lambda item: item.label.split("#")[1])  # host and destination alternate
    light = [item for round_ in rounds for item in round_]
    items = _interleave(heavy, light)
    budget = limits.max_requests - limits.reserve - 4  # the opening probe and log listings
    if len(items) > budget or len(heavy) > limits.max_heavy:
        raise ValueError(f"{len(items)} requests ({len(heavy)} heavy) exceed the session's caps")
    return Plan(tuple(items), tuple(skipped))


def _interleave(heavy: Sequence[Planned], light: Sequence[Planned]) -> list[Planned]:
    if not heavy:
        return list(light)
    step = math.ceil(len(light) / len(heavy))
    items: list[Planned] = []
    for i, item in enumerate(heavy):
        items.append(item)
        items.extend(light[i * step : (i + 1) * step])
    items.extend(light[len(heavy) * step :])
    return items


# --------------------------------------------------------------------------- pacing


def room_ms(rows: Sequence[RecentRequest], at: datetime, limits: Limits = LIMITS) -> int:
    """Server time left in the 60 s up to ``at`` (all of ARGUS)."""
    used = sum(row.took_ms for row in rows if at - MINUTE < row.at <= at)
    return limits.minute_ms - used


def ready_at(
    rows: Sequence[RecentRequest], now: datetime, cost: CostClass, limits: Limits = LIMITS
) -> datetime | None:
    """The earliest moment from ``now`` at which a request of ``cost`` may start, as far as the
    ledger's rows say (they only age out): the last minute leaves room for its whole timeout,
    and for a heavy one fewer than ``heavy_per_minute`` heavy ones in the last minute and the
    last one ``heavy_gap`` (plus slack) ago. None: it never fits."""
    allowed = limits.minute_ms - limits.need_ms(cost)
    if allowed < 0:
        return None
    seen = sorted((row for row in rows if row.at <= now), key=lambda row: row.at)
    recent = [row for row in seen if row.at > now - MINUTE]
    ready = now
    used = sum(row.took_ms for row in recent)
    for row in recent:  # oldest first: wait until enough of them have left the minute
        if used <= allowed:
            break
        used -= row.took_ms
        ready = max(ready, row.at + MINUTE)
    if cost is CostClass.HEAVY:
        heavy = [row for row in recent if cost_of(row.template) is CostClass.HEAVY]
        over = len(heavy) - (limits.heavy_per_minute - 1)
        if over > 0:
            ready = max(ready, heavy[over - 1].at + MINUTE)
        last = [row for row in seen if cost_of(row.template) is CostClass.HEAVY]
        if last:
            ready = max(ready, last[-1].at + limits.heavy_gap + limits.pace_slack)
    return ready


# --------------------------------------------------------------------------- signals


def caution_signals(
    memory: HealthMemory,
    latest: ProbeRow | None,
    baseline: ProbeRow | None,
    now: datetime,
    config: HealthConfig,
    fresh: timedelta = LIMITS.probe_fresh,
) -> list[str]:
    """Every sign that the SIEM is not plainly NORMAL now; empty: go on. ``memory`` is the
    effective health memory; ``baseline`` the session's first reading (counters must not rise
    from it). Unknown is not healthy: a missing reading is a signal too."""
    found: list[str] = []
    if memory.state is not HealthState.NORMAL:
        reasons = f" ({', '.join(memory.reasons)})" if memory.reasons else ""
        found.append(f"the SIEM is {memory.state}{reasons}")
    if latest is None:
        return [*found, "no stored probe reading"]
    age = now - latest.at
    if age > fresh:
        found.append(f"the newest probe reading is {int(age.total_seconds())} s old")
    if latest.state != HealthState.NORMAL.value:
        found.append(f"the newest probe left the SIEM {latest.state}")
    if not latest.probe_ok:
        found.append("the newest probe failed")
    if latest.auth_failed:
        found.append("the SIEM refused the key")
    if latest.blocked_indices:
        found.append(f"{len(latest.blocked_indices)} index(es) blocked")
    gauges = (
        ("disk", latest.disk_percent, config.disk_caution, True),
        ("heap", latest.heap_percent, config.heap_caution, False),
        ("load", latest.load_1m, config.load_caution, False),
    )
    for name, value, limit, inclusive in gauges:
        if value is None or not math.isfinite(value):
            found.append(f"{name} unknown")
        elif value > limit or (inclusive and value >= limit):
            found.append(f"{name} {value:g} (CAUTION at {limit:g})")
    if latest.search_queue is None:
        found.append("search queue unknown")
    elif latest.search_queue > 0:
        found.append(f"search queue {latest.search_queue}")
    for name, value, first in (
        ("search rejections", latest.search_rejected, baseline and baseline.search_rejected),
        ("breaker trips", latest.breakers_tripped, baseline and baseline.breakers_tripped),
    ):
        if value is None:
            found.append(f"{name} unknown")
        elif isinstance(first, int) and value > first:
            found.append(f"{name} rose by {value - first}")
    return found


# --------------------------------------------------------------------------- the session


class AgainError(DeferredError):
    """Nothing was sent: the session takes the request from the top (pacing, probe, signals)."""

    reason = "again"


class NoRoomError(AgainError):
    """The last minute has no room for the request (asked again after every budget wait)."""

    reason = "no_room"


class StaleReadingError(AgainError):
    """The newest probe reading grew too old while the request waited: probe first."""

    reason = "stale_reading"


class NoRetryError(RefusedError):
    """The gateway would retry a request of the session: it never may. Raised
    from the session's check, which the gateway asks before a retry; the row keeps the
    first attempt's charge, and the session ends."""

    reason = "no_retry"


class SessionCapError(RefusedError):
    """The session's own cap: the request was not sent."""

    reason = "session_cap"


@dataclass
class CappedTransport:
    """Counts every request where it leaves and refuses (unsent) past the session's caps:
    50 requests, 10 heavy, heavy ones ``heavy_gap`` apart. Retries and index listings count."""

    inner: Transport
    clock: Callable[[], datetime]
    limits: Limits = LIMITS
    sent: int = 0
    heavy: int = 0
    measured: int = 0  # requests other than probes and index listings: retries show here
    last_heavy: datetime | None = None

    async def send(self, request: WireRequest) -> WireResponse:
        cost = cost_of(_template_of(request))
        heavy = cost is CostClass.HEAVY
        now = self.clock()
        if self.sent >= self.limits.max_requests:
            raise SessionCapError(f"the session's {self.limits.max_requests} requests are used")
        if heavy and self.heavy >= self.limits.max_heavy:
            raise SessionCapError(f"the session's {self.limits.max_heavy} heavy requests are used")
        if heavy and self.last_heavy is not None and now - self.last_heavy < self.limits.heavy_gap:
            raise SessionCapError("heavy requests go at least 10 s apart")
        self.sent += 1
        if cost is not CostClass.PROBE:
            self.measured += 1
        if heavy:
            self.heavy += 1
            self.last_heavy = now
        return await self.inner.send(request)

    @property
    def left(self) -> int:
        return self.limits.max_requests - self.sent

    async def aclose(self) -> None:
        close = getattr(self.inner, "aclose", None)
        if close is not None:
            await close()


class MeasureStore(GatewayState, Protocol):
    async def requests_since(
        self, since: datetime, until: datetime | None = None
    ) -> list[RecentRequest]: ...
    async def probes_since(
        self, since: datetime, until: datetime | None = None
    ) -> list[ProbeRow]: ...
    async def latest_probe(self) -> ProbeRow | None: ...


@dataclass(frozen=True)
class Sample:
    label: str
    template: str
    cost: str
    at: datetime
    outcome: str  # "ok" or the error's reason
    took_ms: int | None = None
    elapsed_ms: int | None = None


@dataclass
class SessionReport:
    started: datetime
    planned: int
    ended: datetime | None = None
    samples: list[Sample] = field(default_factory=list)
    stopped: str | None = None  # why it ended before its plan did; None: the whole plan ran
    notes: list[str] = field(default_factory=list)
    requests_sent: int = 0
    heavy_sent: int = 0

    @property
    def complete(self) -> bool:
        return self.stopped is None and len(self.samples) == self.planned

    def to_json(self) -> dict[str, Any]:
        def time(value: datetime | None) -> str | None:
            return None if value is None else value.isoformat()

        return {
            "format": 1,
            "component": COMPONENT,
            "started": time(self.started),
            "ended": time(self.ended),
            "planned": self.planned,
            "complete": self.complete,
            "stopped": self.stopped,
            "notes": list(self.notes),
            "requests_sent": self.requests_sent,
            "heavy_sent": self.heavy_sent,
            "samples": [
                {
                    "label": s.label,
                    "template": s.template,
                    "cost": s.cost,
                    "at": s.at.isoformat(),
                    "outcome": s.outcome,
                    "took_ms": s.took_ms,
                    "elapsed_ms": s.elapsed_ms,
                }
                for s in self.samples
            ],
        }


class AbortError(Exception):
    """The session ends now; the message says why, in plain words."""


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Session:
    def __init__(
        self,
        gateway: Gateway,
        store: MeasureStore,
        plan: Plan,
        *,
        counter: CappedTransport,
        probe: Callable[[], Awaitable[HealthMemory]],
        health_config: HealthConfig | None = None,
        limits: Limits = LIMITS,
        clock: Callable[[], datetime] = _utcnow,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if gateway.transport is not counter:
            raise ValueError("the session's gateway must send through its CappedTransport")
        if gateway.listing_component != COMPONENT:  # its index listings are the session's
            raise ValueError(f"the session's gateway must name its listings {COMPONENT!r}")
        self.gateway = gateway
        self.store = store
        self.plan = plan
        self.counter = counter
        self.probe = probe
        self.config = health_config or HealthConfig()
        self.limits = limits
        self.clock = clock
        self.sleep = sleep
        self.baseline: ProbeRow | None = None
        self.opened = False  # the opening probe went: from then on, a closing one may
        self.started = clock()
        self.report = SessionReport(started=self.started, planned=len(plan.items))

    async def run(self) -> SessionReport:
        """The session; ``self.report`` holds what was done so far, also when it is
        interrupted (Ctrl-C: no closing probe then, the request in flight is settled by the
        gateway)."""
        report = self.report
        try:
            await self._rules(self.clock(), starting=True)
            self.opened = True
            await self._probe()
            self.baseline = await self.store.latest_probe()
            await self._signals(self.clock())
            for item in self.plan.items:
                if self.counter.left < 1 + self.limits.reserve:
                    report.stopped = "the session's requests are used up"
                    break
                report.samples.append(await self._one(item, report))
        except AbortError as exc:
            report.stopped = str(exc)
        except BaseException:
            report.stopped = "interrupted"
            report.notes.append("no closing probe: interrupted")
            self._count(report)
            raise
        await self._close(report)
        return report

    def _count(self, report: SessionReport) -> None:
        report.ended = self.clock()
        report.requests_sent = self.counter.sent
        report.heavy_sent = self.counter.heavy

    async def _close(self, report: SessionReport) -> None:
        """A closing probe for the after-state, unless the session never opened, the quiet
        hours began or a kill switch is stopped: then nothing more is sent."""
        now = self.clock()
        if not self.opened:
            report.notes.append("nothing was sent")
        elif quiet(now):
            report.notes.append(f"no closing probe: {site.quiet_hours().words()}")
        elif (await self.store.switches()).stopped:
            report.notes.append("no closing probe: a kill switch is stopped")
        elif self.counter.left >= 2:
            try:
                await self._probe()
                latest = await self.store.latest_probe()
                memory = effective(await self.store.health(), self.clock(), self.config)
                for signal in caution_signals(memory, latest, self.baseline, self.clock(),
                                              self.config, self.limits.probe_fresh):  # fmt: skip
                    report.notes.append(f"after the session: {signal}")
            except (AbortError, GatewayError) as exc:
                report.notes.append(f"no closing probe: {exc}")
        else:
            report.notes.append("no closing probe: no request left")
        self._count(report)

    async def _probe(self) -> None:
        if self.counter.left < 2:
            raise AbortError("no request left for a health probe")
        await self.probe()

    async def _rules(self, now: datetime, *, starting: bool = False) -> None:
        """The rules that need no reading: the time of day, the kill switches, the breaker."""
        if quiet(now):
            raise AbortError(f"{site.quiet_hours().words()} is the SIEM's busy time: no measuring")
        if starting and quiet(now + self.limits.max_duration):
            raise AbortError(
                f"the session could run into {site.quiet_hours().start} UTC: start it after"
                f" {site.quiet_hours().end}"
            )
        if now - self.started > self.limits.max_duration:
            raise AbortError(f"the session ran {self.limits.max_duration} without finishing")
        stopped = (await self.store.switches()).stopped
        if stopped:
            raise AbortError(f"a kill switch is stopped ({', '.join(sorted(stopped))})")
        ok, until = await self.store.breaker_peek(now)
        if not ok:
            when = f" until {until:%H:%M} UTC" if until else ""
            raise AbortError(f"the overload breaker is open{when}")

    async def _found(self, now: datetime) -> list[str]:
        """Every CAUTION signal now: the readings against the session's first one, the health
        state, and a budget still coming back after DEGRADED or STOP (slow start)."""
        latest = await self.store.latest_probe()
        memory = effective(await self.store.health(), now, self.config)
        found = caution_signals(memory, latest, self.baseline, now, self.config,
                                self.limits.probe_fresh)  # fmt: skip
        if memory.state is HealthState.NORMAL and scale(memory, now, self.config) < 1:
            found.append("the budget is still coming back after DEGRADED or STOP")
        return found

    async def _signals(self, now: datetime) -> None:
        found = await self._found(now)
        if found:
            raise AbortError("CAUTION signal: " + "; ".join(found))

    async def _check(self, now: datetime) -> None:
        """The gateway asks this again after any wait and once the lease is held: the quiet
        hours, the kill switches and every CAUTION signal, as before the request,
        so a wait never carries a request past them. A reading that went stale meanwhile
        sends the request back to be probed first."""
        if quiet(now):
            raise DeferredError(f"{site.quiet_hours().words()}: no measuring")
        if (await self.store.switches()).stopped:
            raise StoppedError("a kill switch is stopped")
        latest = await self.store.latest_probe()
        if latest is None or now - latest.at > self.limits.probe_fresh:
            raise StaleReadingError("the newest probe reading is older than a minute")
        found = await self._found(now)
        if found:
            raise DeferredError("CAUTION signal: " + "; ".join(found))

    def _check_for(self, item: Planned) -> Callable[[datetime], Awaitable[None]]:
        """The gateway's check for this request: never a retry, then the session's rules and
        the room it needs in the last minute, asked again after any budget wait and once the
        lease is held. The gateway asks it before a retry too: by then the request has left
        (the transport counted it), and the check refuses."""
        measured = self.counter.measured

        async def check(now: datetime) -> None:
            if self.counter.measured != measured:
                raise NoRetryError("the session never retries a request")
            await self._check(now)
            rows = await self.store.requests_since(now - MINUTE)
            ready = ready_at(rows, now, item.cost, self.limits)
            if ready is None or ready > now:
                raise NoRoomError("the last minute has no room for this request now")

        return check

    async def _one(self, item: Planned, report: SessionReport) -> Sample:
        busy = 0
        waited = timedelta(0)
        while True:
            now = self.clock()
            await self._rules(now)
            latest = await self.store.latest_probe()
            if latest is None or now - latest.at > self.limits.probe_fresh:
                await self._probe()
                now = self.clock()
            await self._signals(now)
            rows = await self.store.requests_since(now - MINUTE)
            ready = ready_at(rows, now, item.cost, self.limits)
            if ready is None:
                raise AbortError(f"{item.label}: its timeout does not fit 3 s a minute")
            if ready > now:
                waited += ready - now
                if waited > self.limits.max_wait:
                    raise AbortError(f"{item.label}: no room in the SIEM's budget within 2 minutes")
                await self.sleep((ready - now).total_seconds())
                continue
            sent, measured = self.counter.sent, self.counter.measured
            try:
                result = await self.gateway.run(
                    item.template, item.params, purpose=Purpose.MEASURE, component=COMPONENT,
                    deadline=now + self.limits.budget_wait, check=self._check_for(item),
                    request_timeout=self.limits.timeout(item.cost),
                )  # fmt: skip
            except AgainError:
                continue  # nothing sent: the minute filled up or the reading went stale
            except NoRetryError as exc:  # the first attempt failed; the gateway would retry
                first = exc.__context__
                reason = first.reason if isinstance(first, GatewayError) else exc.reason
                report.samples.append(self._failed(item, now, reason))
                raise AbortError(f"{item.label}: the SIEM did not answer cleanly ({reason}); the"
                                 " session never retries a request") from None  # fmt: skip
            except DeadlinePassedError:
                if self.counter.sent == sent and busy < self.limits.busy_retries:
                    busy += 1  # the shared budget was busy: nothing was sent
                    await self.sleep(self.limits.busy_pause.total_seconds())
                    continue
                report.samples.append(self._failed(item, now, "deadline_passed"))
                raise AbortError(f"{item.label}: the budget stayed busy") from None
            except GatewayError as exc:
                report.samples.append(self._failed(item, now, exc.reason))
                raise AbortError(f"{item.label}: {exc.reason}: {exc}") from None
            elapsed = int((self.clock() - now).total_seconds() * 1000)
            sample = Sample(item.label, item.name, item.cost.value, now, "ok", result.took_ms,
                            elapsed)  # fmt: skip
            if self.counter.measured - measured > 1:  # a retry the check never saw
                report.samples.append(sample)
                raise AbortError(
                    f"{item.label}: it needed a retry: the SIEM did not answer cleanly"
                )
            if result.took_ms > self.limits.cap(item.cost) * 1_000:
                report.samples.append(sample)
                cap = self.limits.cap(item.cost)
                raise AbortError(f"{item.label}: {result.took_ms} ms is past its {cap} s")
            after = self.clock()
            left = room_ms(await self.store.requests_since(after - MINUTE), after, self.limits)
            if left < 0:
                report.samples.append(sample)
                used = self.limits.minute_ms - left
                raise AbortError(f"ARGUS used {used} ms of server time in a minute")
            return sample

    @staticmethod
    def _failed(item: Planned, at: datetime, reason: str) -> Sample:
        return Sample(item.label, item.name, item.cost.value, at, reason)


# --------------------------------------------------------------------------- verification


@dataclass(frozen=True)
class Verdict:
    problems: tuple[str, ...]
    facts: tuple[str, ...]
    # the attribution window had not passed when this was judged: verify again after it
    pending_until: datetime | None = None

    @property
    def passed(self) -> bool:
        return not self.problems


def sends(row: RecentRequest) -> int:
    """Requests a ledger row sent to the SIEM: its attempts, less one the session's cap refused
    (the cap refuses before sending). A row the cap refused on its first attempt sent none;
    one whose retry it refused sent its first attempt."""
    return max(row.attempts - (row.outcome == SessionCapError.reason), 0)


def busiest_minute(
    rows: Sequence[RecentRequest],
    first: datetime,
    last: datetime,
    within: Sequence[RecentRequest] | None = None,
) -> tuple[int, int, datetime | None, datetime | None]:
    """(most server time, most heavy requests) in any 60 s that starts at a row from ``first``
    to ``last`` (and holds one of ``within``, when given), and where each starts. The busiest
    60 s always start at a row, so no other start needs checking."""
    ordered = sorted(rows, key=lambda row: row.at)
    marked = None if within is None else {id(row) for row in within}
    most_ms, most_heavy, at_ms, at_heavy = 0, 0, None, None
    for i, start in enumerate(ordered):
        if not first <= start.at <= last:
            continue
        window = [row for row in ordered[i:] if row.at < start.at + MINUTE]
        if marked is not None and not any(id(row) in marked for row in window):
            continue
        took = sum(row.took_ms for row in window)
        heavy = sum(1 for row in window if cost_of(row.template) is CostClass.HEAVY)
        if took > most_ms:
            most_ms, at_ms = took, start.at
        if heavy > most_heavy:
            most_heavy, at_heavy = heavy, start.at
    return most_ms, most_heavy, at_ms, at_heavy


def _state(value: str) -> HealthState:
    try:
        return HealthState(value)
    except ValueError:  # a state this code does not know is not healthy
        return HealthState.STOP


def verify(
    rows: Sequence[RecentRequest],
    probes: Sequence[ProbeRow],
    start: datetime,
    end: datetime,
    *,
    limits: Limits = LIMITS,
    config: HealthConfig | None = None,
    requests_sent: int | None = None,
    now: datetime | None = None,
) -> Verdict:
    """The check of a session from what was stored: ``rows`` are the ledger's rows (all of ARGUS)
    around the session, ``probes`` the readings from ``start`` to ``watch_until`` (``end`` plus a
    minute, or 5 minutes when ARGUS used more than 1,500 ms in a minute). Every 60 s that holds a
    request of the session is checked, for all of ARGUS and for the session alone; every reading
    must be NORMAL with no CAUTION signal; the ledger must hold at least ``requests_sent``
    requests. Judged before the readings' window ends, the verdict is only provisional
    (``pending_until``)."""
    config = config or HealthConfig()
    problems: list[str] = []
    around = [row for row in rows if start - MINUTE <= row.at <= end + MINUTE]
    ours = [row for row in around if row.component == COMPONENT and start <= row.at <= end]
    sent = [row for row in ours if sends(row)]
    heavy = [row for row in sent if cost_of(row.template) is CostClass.HEAVY]
    count = sum(sends(row) for row in sent)
    heavy_count = sum(sends(row) for row in heavy)
    if not ours:
        problems.append("the ledger holds no request of the session")
    if count > limits.max_requests:
        problems.append(f"{count} requests sent, more than {limits.max_requests}")
    if requests_sent is not None and count < requests_sent:
        problems.append(f"the ledger holds {count} of the {requests_sent} requests the session"
                        " sent")  # fmt: skip
    if heavy_count > limits.max_heavy:
        problems.append(f"{heavy_count} heavy requests, more than {limits.max_heavy}")
    for before, after in itertools.pairwise(heavy):
        if after.at - before.at < limits.heavy_gap:
            gap = (after.at - before.at).total_seconds()
            problems.append(f"heavy requests {gap:.1f} s apart at {after.at:%H:%M:%S}")
    problems.extend(f"a heavy request sent twice at {row.at:%H:%M:%S} (a retry, under 10 s apart)"
                    for row in heavy if sends(row) > 1)  # fmt: skip
    facts: list[str] = [
        f"session {start:%Y-%m-%d %H:%M:%S} to {end:%H:%M:%S} UTC: {count} requests,"
        f" {heavy_count} heavy, {sum(row.took_ms for row in sent)} ms of server time",
    ]
    busiest = 0
    for scope, scoped in (("all of ARGUS", around), ("the session", sent)):
        most_ms, most_heavy, at_ms, at_heavy = busiest_minute(scoped, start - MINUTE, end, sent)
        busiest = max(busiest, most_ms)
        facts.append(f"busiest minute, {scope}: {most_ms} ms, {most_heavy} heavy")
        if most_ms > limits.minute_ms and at_ms is not None:
            problems.append(f"{scope} used {most_ms} ms in the minute from {at_ms:%H:%M:%S}")
        if most_heavy > limits.heavy_per_minute and at_heavy is not None:
            problems.append(
                f"{scope} sent {most_heavy} heavy requests in the minute from {at_heavy:%H:%M:%S}"
            )
    failed = sorted({row.outcome for row in sent if row.outcome != "ok"})
    if failed:
        problems.append(f"requests that did not answer ok: {', '.join(failed)}")
    until = watch_until(end, busiest, limits)
    attributed = until > end + MINUTE
    if attributed:
        facts.append(f"ARGUS used more than {limits.attribution_ms} ms in a minute: readings up"
                     f" to {until:%H:%M:%S} UTC count against the session")  # fmt: skip
    readings = sorted((p for p in probes if start <= p.at <= until), key=lambda p: p.at)
    if not readings:
        problems.append("no probe reading during the session")
    flagged = 0
    for reading in readings:
        memory = HealthMemory(state=_state(reading.state), reasons=reading.reasons)
        signals = caution_signals(memory, reading, readings[0], reading.at, config)
        flagged += bool(signals)
        problems.extend(f"probe at {reading.at:%H:%M:%S}: {signal}" for signal in signals)
    facts.append(f"{len(readings)} probe readings, {flagged} with a CAUTION signal")
    # judged early, an attributed verdict is provisional; the minute after a quiet session is
    # its closing probe's, already read
    pending = until if attributed and now is not None and now < until else None
    return Verdict(tuple(problems), tuple(facts), pending)


def watch_until(end: datetime, busiest_ms: int, limits: Limits = LIMITS) -> datetime:
    """The end of the readings that count against a session: a minute after it, or
    5 minutes when ARGUS used more than ``attribution_ms`` in one of its minutes."""
    return end + (limits.attribution if busiest_ms > limits.attribution_ms else MINUTE)


def refused(plan: Plan, gateway: Gateway, now: datetime, limits: Limits = LIMITS) -> list[str]:
    """The planned requests the gateway's validator would refuse (a live run never starts
    with one: it could not finish)."""
    found = []
    for item in plan.items:
        try:
            gateway.preview(item.template, item.params, deadline=now + limits.timeout(item.cost),
                            now=now)  # fmt: skip
        except (GatewayError, TypeError, ValueError) as exc:
            found.append(f"{item.label}: {exc}")
    return found


def describe(plan: Plan, gateway: Gateway, now: datetime, limits: Limits = LIMITS) -> list[str]:
    """The dry run: each request as the gateway would validate it, without sending anything."""
    lines = [
        f"{len(plan.items)} requests ({plan.heavy} heavy), plus up to"
        f" {limits.max_requests - len(plan.items)} probes and index listings; at most"
        f" {limits.max_requests} in all and {limits.max_heavy} heavy",
    ]
    for item in plan.items:
        deadline = now + limits.timeout(item.cost)
        try:
            final = gateway.preview(item.template, item.params, deadline=deadline, now=now)
        except (GatewayError, TypeError, ValueError) as exc:
            lines.append(f"  {item.label} ({item.cost}): REFUSED by the gateway: {exc}")
            continue
        where = ",".join(final.indices) or (final.pattern or "")
        lines.append(f"  {item.label} ({item.cost}, at most {limits.cap(item.cost)} s):"
                     f" {final.spec.endpoint} {where}")  # fmt: skip
    lines.extend(f"  not measured: {note}" for note in plan.skipped)
    return lines
