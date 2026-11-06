"""The Elastic Gateway: the only path from ARGUS to the SIEM.

``Gateway.run`` stops at the first refusal; nothing is sent unless every step says yes: the
deadline, the kill switches and the SIEM's health, the template's request and exact indices, the
validator on the **final** request, the live-test session's limits, the overload breaker, the
index listing, and the budget of the purpose's lane (``lanes.lane_of``). The kill switches, health
and breaker are asked again after every budget wait and before a retry. It retries at most once,
checks the answer (typed errors, complete results; a 401/403 puts the SIEM in STOP), charges the
server time and writes a ledger row per request. ``LaneGate`` gives other clients (the identity
checks) the same lane admission.
"""

from __future__ import annotations

import asyncio
import contextlib
import random
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any

from argus import site
from argus.gateway import budget as budget_core
from argus.gateway import health as health_core
from argus.gateway.budget import Lease, Verdict
from argus.gateway.discovery import DISCOVERY_SCOPES
from argus.gateway.errors import (
    AuthFailedError,
    BreakerOpenError,
    BudgetExhaustedError,
    DeadlinePassedError,
    DeferredError,
    GatewayError,
    LaneBusyError,
    LiveSessionError,
    OverloadedError,
    RefusedError,
    SourceMissingError,
    StoppedError,
    TemplateRejectedError,
    TimedOutError,
    TransportFailedError,
)
from argus.gateway.health import HealthConfig, HealthState
from argus.gateway.indices import daily_indices, exact_indices, pad_only_after, resolve
from argus.gateway.lanes import Lane, lane_of
from argus.gateway.responses import check_complete, check_status, parse_json, took_ms
from argus.gateway.state import GatewayState, LedgerEntry
from argus.gateway.templates import (
    COMPONENT,
    CostClass,
    Endpoint,
    Family,
    Params,
    Purpose,
    RequestPlan,
    Template,
    plan_key,
)
from argus.gateway.transport import Transport, WireRequest, wire_path
from argus.gateway.validator import FORCED_SEARCH_PARAMS, FinalRequest, encode_body, validate
from argus.site import LogFamily

PROBE_PURPOSES = frozenset({Purpose.PROBE, Purpose.SELFTEST})
# never in the quiet hours; a discovery is a person's command, but it may wait a minute
# for the budget, so the gateway asks again at every request, not only the command at its start
QUIET_PURPOSES = frozenset({Purpose.FRESHNESS, Purpose.DISCOVER, Purpose.CHECK})
OWN_HEALTH = frozenset({Purpose.IDENTITY})  # its own reachability, not the SIEM's
# The only requests the identity purpose may carry: sign-in and capability checks and the
# security index's health. Anything else labelled identity would skip the SIEM's health.
IDENTITY_ENDPOINTS = frozenset(
    {Endpoint.AUTHENTICATE, Endpoint.HAS_PRIVILEGES, Endpoint.SECURITY_HEALTH}
)
# A caller's own rule for one request, asked at ``now``; it raises a RefusedError to stop it.
SendCheck = Callable[[datetime], Awaitable[None]]
RETRY_MIN_LEFT = timedelta(seconds=2)
POLL = timedelta(milliseconds=500)  # how often to ask again for a concurrency slot
POLL_REASONS = frozenset({"concurrency", "heavy_concurrency"})


def utcnow() -> datetime:
    return datetime.now(UTC)


def in_quiet_hours(now: datetime) -> bool:
    """The site's quiet hours (``site.quiet_hours``; default 00:00-01:30 UTC):
    the SIEM creates the day's indices and ILM deletes old ones."""
    return site.in_quiet_hours(now)


@dataclass(frozen=True)
class Seen:
    """What the gateway saw when it last asked: the budget scale, the SIEM's effective health
    and the stopped switches (recorded on the ledger row)."""

    scale: float
    health: str
    stopped: tuple[str, ...]


async def admitted_by_state(
    state: GatewayState,
    purpose: Purpose,
    cost: CostClass,
    now: datetime,
    config: HealthConfig,
) -> Seen:
    """The budget scale this work may use now, or the refusal (kill switch, health, quiet
    hours). Probes run at any scale, also 0: they roll the bucket with the real one."""
    switches = await state.switches()
    stopped = tuple(sorted(switches.stopped))
    if purpose not in PROBE_PURPOSES and switches.blocks(COMPONENT[purpose]):
        raise StoppedError("stopped by the operator's kill switch")
    if purpose in QUIET_PURPOSES and in_quiet_hours(now):
        raise DeferredError(
            f"{purpose} waits for the end of the quiet hours ({site.quiet_hours().end} UTC)"
        )
    memory = health_core.effective(await state.health(), now, config)
    if purpose in OWN_HEALTH:
        return Seen(1.0, memory.state.value, stopped)
    if not health_core.allowed(memory.state, purpose):
        if memory.state is HealthState.STOP:
            raise StoppedError("the SIEM is in STOP")
        raise DeferredError(f"the SIEM is {memory.state}: {purpose} waits")
    scale = health_core.scale(memory, now, config)
    if scale <= 0 and cost is not CostClass.PROBE:
        raise DeferredError(f"the SIEM is {memory.state}: no budget for {purpose}")
    return Seen(scale, memory.state.value, stopped)


async def lane_admit(
    state: GatewayState, lane: Lane | None, cost: CostClass, now: datetime, scale: float,
    lease_id: str,
) -> budget_core.Admission:  # fmt: skip
    """Admission on ``lane``'s bucket: the collector's lane and probes use the original budget."""
    if lane is None or lane is Lane.COLLECTOR or cost is CostClass.PROBE:
        return await state.budget_admit(cost, now, scale, lease_id)
    return await state.lane_admit(lane, cost, now, scale, lease_id)


async def lane_settle(
    state: GatewayState, lane: Lane | None, lease: Lease, took_ms: int, now: datetime,
    scale: float,
) -> None:  # fmt: skip
    if lane is None or lane is Lane.COLLECTOR or lease.cost is CostClass.PROBE:
        await state.budget_settle(lease, took_ms, now, scale)
    else:
        await state.lane_settle(lane, lease, took_ms, now, scale)


@dataclass(frozen=True)
class Targets:
    """The index families ARGUS may read. Unless given, the site profile's (``argus.site``):
    the alerts index of its space, its log families and, as ``log_sources``, the ones the
    health probe and the freshness reader watch. The gateway's own build (``service.targets``)
    allows every family."""

    alerts: str = field(default_factory=lambda: site.active().alerts_index_name)
    alerts_backing: str = field(default_factory=lambda: site.active().alerts_backing_prefix)
    families: tuple[LogFamily, ...] = field(default_factory=lambda: site.active().families)
    log_sources: frozenset[str] = field(
        default_factory=lambda: frozenset(site.active().watched_sources)
    )
    ti: frozenset[str] = field(default_factory=lambda: frozenset(site.active().ti_indices))

    def family(self, source: str) -> LogFamily:
        """The family of a source key, if this gateway may read it."""
        if source in self.log_sources:
            for family in self.families:
                if family.name == source:
                    return family
        raise TemplateRejectedError("index_not_allowed", f"{source:.40} is not a log source")

    def log_index_prefix(self, source: str) -> str:
        """A daily family's index prefix (``<prefix>YYYY.MM.DD`` are its indices)."""
        family = self.family(source)
        if not family.daily:
            raise TemplateRejectedError(
                "index_not_allowed", f"{source:.40} is a data stream: it has no daily indices"
            )
        return family.prefix

    def is_log_index(self, name: str) -> bool:
        """Whether an index name belongs to a log family this gateway may read."""
        return any(f.name in self.log_sources and f.owns_index(name) for f in self.families)


@dataclass(frozen=True)
class LiveLimits:
    """The stricter limits of a human-issued live-test session."""

    session_id: str
    max_size: int = 10
    max_window: timedelta = timedelta(minutes=15)
    per_minute: int = 10


@dataclass(frozen=True)
class Result:
    body: Any
    took_ms: int
    indices: tuple[str, ...]


class Gateway:
    def __init__(
        self,
        transport: Transport,
        state: GatewayState,
        *,
        targets: Targets | None = None,
        health_config: HealthConfig | None = None,
        clock: Callable[[], datetime] = utcnow,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        listing_ttl: timedelta = timedelta(minutes=5),
        live: LiveLimits | None = None,
        rng: random.Random | None = None,
        listing_component: str = "gateway",
    ) -> None:
        self.transport = transport
        self.state = state
        self.targets = targets or Targets()
        self.health_config = health_config or HealthConfig()
        self.clock = clock
        self.sleep = sleep
        self.listing_ttl = listing_ttl
        self.live = live
        self.rng = rng or random.Random()  # noqa: S311 - retry jitter, not a secret
        # the ledger's component for the index listings it sends itself (the measuring
        # session's gateway names its own, so they count as the session's)
        self.listing_component = listing_component
        self._listings: dict[str, tuple[datetime, frozenset[str]]] = {}
        self._live_starts: list[datetime] = []
        self._live_lock = asyncio.Lock()

    # ------------------------------------------------------------------ public

    async def run(
        self,
        template: Template,
        params: Params,
        *,
        purpose: Purpose,
        component: str,
        deadline: datetime,
        check: SendCheck | None = None,
        request_timeout: timedelta | None = None,
    ) -> Result:
        """Send one request. ``check`` is the caller's own rule (for example NORMAL only and
        no quiet hours): it is asked whenever the gateway asks its own state again (at the
        start, after every budget wait, once the lease is held, before a retry), so a wait
        never outlives it; it raises a RefusedError to stop the request. ``request_timeout``
        caps the request's own timeout (Elasticsearch's and the wire's) below the template's,
        while ``deadline`` still bounds everything, budget waits included."""
        now = self.clock()
        if now >= deadline:
            raise DeadlinePassedError("the deadline passed before the request started")
        limit = type(template).timeout
        if request_timeout is not None:
            if request_timeout <= timedelta(0):
                raise ValueError("a request's timeout is positive")
            limit = min(limit, request_timeout)
        spec = type(template).spec()
        if (spec.cost is CostClass.PROBE) != (purpose in PROBE_PURPOSES):
            raise TemplateRejectedError(
                "cost_mismatch", "probe-cost templates are for probes and self-tests only"
            )
        if purpose in OWN_HEALTH and spec.endpoint not in IDENTITY_ENDPOINTS:
            raise TemplateRejectedError(
                "purpose_mismatch", f"{spec.name} is not an identity check: pick its own purpose"
            )
        seen = await self._admitted_by_state(purpose, spec.cost, now)
        if spec.family is Family.LOG and (
            seen.health == HealthState.STOP or "global" in seen.stopped
        ):
            # no log request in STOP or under the global switch, a probe's neither
            raise StoppedError("log reads wait: the SIEM is in STOP or ARGUS is stopped")
        if check is not None:
            await check(now)
        plan = template.plan(params)
        indices, pattern, optional = self._wanted(plan)
        final = self._final(plan, indices, pattern, limit, deadline, now)
        validate(final)
        if self.live is not None:
            await self._live_check(final, plan, now)
        await self._breaker_closed(spec.cost, now)
        window = plan.window
        if window is not None and spec.family is Family.LOG and self._daily(window.source):
            resolved = await self._resolve(window.source, indices, optional, now, deadline)
            # a subset of indices the validator accepted: every index rule still holds
            final = replace(final, indices=resolved)
        lane = lane_of(purpose)
        lease, seen = await self._admit(purpose, spec.cost, seen, deadline, check)
        try:
            if check is not None:  # the resolve and the budget may have waited
                await check(self.clock())
            if spec.cost is not CostClass.PROBE:
                ok, until = await self.state.breaker_admit(self.clock())
                if not ok:  # another request took the trial meanwhile
                    raise BreakerOpenError(until)
        except BaseException:
            await asyncio.shield(lane_settle(self.state, lane, lease, 0, self.clock(), seen.scale))
            raise
        key = plan_key(plan, params)  # on the ledger row: joins the request to its evidence
        stream = window is not None and spec.family is Family.LOG and not self._daily(window.source)
        result = await self._send(
            template, final, lease, seen, purpose, component, deadline, key, check, limit,
            missing="source_missing" if stream else "source_expired",
        )  # fmt: skip
        return replace(result, body=template.answer(params, result.body))

    def preview(
        self, template: Template, params: Params, *, deadline: datetime, now: datetime | None = None
    ) -> FinalRequest:
        """The final request ``run`` would validate for these parameters (log indices from the
        window, before the listing narrows them), checked by the validator. Sends nothing and
        asks no state: for dry runs. Raises what the template or the validator raise."""
        now = self.clock() if now is None else now
        plan = template.plan(params)
        indices, pattern, _optional = self._wanted(plan)
        final = self._final(plan, indices, pattern, type(template).timeout, deadline, now)
        validate(final)
        return final

    # ------------------------------------------------------------------ steps

    async def _admitted_by_state(self, purpose: Purpose, cost: CostClass, now: datetime) -> Seen:
        return await admitted_by_state(self.state, purpose, cost, now, self.health_config)

    async def _breaker_closed(self, cost: CostClass, now: datetime) -> None:
        """Refuse while the overload breaker is open. Read-only: takes no trial."""
        if cost is not CostClass.PROBE:
            ok, until = await self.state.breaker_peek(now)
            if not ok:
                raise BreakerOpenError(until)

    def _wanted(self, plan: RequestPlan) -> tuple[tuple[str, ...], str | None, frozenset[str]]:
        """(indices, resolve pattern, optional indices) from the plan alone. Log indices are
        checked against the listing later, after every local check passed."""
        spec = plan.spec
        targets = self.targets
        if spec.endpoint is Endpoint.RESOLVE_INDEX:
            if plan.source is None:
                raise TemplateRejectedError("index_not_allowed", "resolve_index needs a source")
            return (), targets.log_index_prefix(plan.source) + "*", frozenset()
        if spec.endpoint is Endpoint.DISCOVER_INDICES:  # discovery: names no family yet
            scope = DISCOVERY_SCOPES.get(plan.source or "")
            if scope is None:
                raise TemplateRejectedError("index_not_allowed", "an unknown discovery scope")
            return (), scope, frozenset()
        if spec.endpoint is Endpoint.FIELD_MAPPING:  # one index the listing showed, the fields
            return plan.names, ",".join(plan.fields), frozenset()
        if spec.family is Family.LOG:
            if plan.window is None or plan.names:
                raise TemplateRejectedError("index_not_allowed", "log requests name a window")
            family = targets.family(plan.window.source)
            if not family.daily:  # a data stream: its name, whatever the window; the time range
                return (family.pattern,), None, frozenset()  # in the query selects the data
            prefix = family.prefix
            try:
                if not plan.window.pad:  # a whole day's index: a missing one is never skipped
                    return (
                        exact_indices(prefix, plan.window.start, plan.window.end),
                        None,
                        frozenset(),
                    )
                wanted = daily_indices(prefix, plan.window.start, plan.window.end)
            except ValueError as exc:
                raise TemplateRejectedError("too_many_indices", str(exc)) from None
            return wanted, None, pad_only_after(prefix, plan.window.end)
        if spec.family is Family.ALERTS:
            names = plan.names or (targets.alerts,)
            for name in names:
                if name != targets.alerts and not name.startswith(targets.alerts_backing):
                    raise TemplateRejectedError("index_not_allowed", "not an alerts index")
            return names, None, frozenset()
        if spec.family is Family.TI:
            if not plan.names or not set(plan.names) <= targets.ti:
                raise TemplateRejectedError("index_not_allowed", "not a threat-intel index")
            return plan.names, None, frozenset()
        for name in plan.names:  # CLUSTER: index blocks of the alerts alias and log indices
            if name != targets.alerts and not targets.is_log_index(name):
                raise TemplateRejectedError("index_not_allowed", "not an ARGUS index")
        return plan.names, None, frozenset()

    def _daily(self, source: str) -> bool:
        """Whether a source's indices are daily ones, which the listing checks; a data stream
        is named as it is and a missing one is Elasticsearch's own 404 (``source_missing``)."""
        return self.targets.family(source).daily

    async def _resolve(
        self,
        source: str,
        wanted: tuple[str, ...],
        optional: frozenset[str],
        now: datetime,
        deadline: datetime,
    ) -> tuple[str, ...]:
        listing = await self._listing(source, now, deadline, refresh=False)
        try:
            return resolve(wanted, listing, now.date(), optional)
        except SourceMissingError as exc:
            if exc.reason != "source_not_ready":
                raise
            listing = await self._listing(source, now, deadline, refresh=True)
            return resolve(wanted, listing, now.date(), optional)

    async def _listing(
        self, source: str, now: datetime, deadline: datetime, *, refresh: bool
    ) -> frozenset[str]:
        cached = self._listings.get(source)
        fresh_for = timedelta(minutes=1) if refresh else self.listing_ttl
        if cached is not None and now - cached[0] < fresh_for:
            return cached[1]
        from argus.gateway.builtin import IndexListing, IndexListingParams

        result = await self.run(
            IndexListing(),
            IndexListingParams(source=source),
            purpose=Purpose.PROBE,
            component=self.listing_component,
            deadline=deadline,
        )
        names = frozenset(IndexListing.names(result.body))
        self._listings[source] = (now, names)
        return names

    def _final(
        self,
        plan: RequestPlan,
        indices: tuple[str, ...],
        pattern: str | None,
        timeout: timedelta,
        deadline: datetime,
        now: datetime,
    ) -> FinalRequest:
        params = plan.url_params
        body = plan.body
        if plan.spec.endpoint is Endpoint.SEARCH:
            params = (*params, *FORCED_SEARCH_PARAMS.items())
            seconds = max(1, int(min(timeout, deadline - now).total_seconds()))
            if isinstance(body, dict):
                body = {**body, "timeout": f"{seconds}s"}
        return FinalRequest(plan.spec, indices, pattern, params, body)

    async def _live_check(self, final: FinalRequest, plan: RequestPlan, now: datetime) -> None:
        live = self.live
        assert live is not None
        body = final.body
        if isinstance(body, dict) and body.get("size", 10) > live.max_size:
            raise LiveSessionError(f"live tests read at most {live.max_size} documents")
        if isinstance(body, dict) and ("aggs" in body or "aggregations" in body):
            raise LiveSessionError("live tests do not aggregate")
        if plan.window is not None and plan.window.end - plan.window.start > live.max_window:
            raise LiveSessionError("live tests read at most 15 minutes of logs")
        async with self._live_lock:
            self._live_starts = [t for t in self._live_starts if now - t < timedelta(minutes=1)]
            if len(self._live_starts) >= live.per_minute:
                raise LiveSessionError(f"live tests send at most {live.per_minute} per minute")
            if not await self.state.live_use(live.session_id, now):
                raise LiveSessionError("the live-test session is over or used up")
            self._live_starts.append(now)

    async def _admit(
        self,
        purpose: Purpose,
        cost: CostClass,
        seen: Seen,
        deadline: datetime,
        check: SendCheck | None = None,
    ) -> tuple[Lease, Seen]:
        """A budget lease on the purpose's lane, waiting within the deadline. After every wait
        the kill switches, the health state and the breaker are asked again: a wait never
        outlives a refusal."""
        lease_id = uuid.uuid4().hex
        lane = lane_of(purpose)
        while True:
            now = self.clock()
            admission = await lane_admit(self.state, lane, cost, now, seen.scale, lease_id)
            if admission.verdict is Verdict.ADMITTED:
                assert admission.lease is not None
                return admission.lease, seen
            if admission.verdict is Verdict.EXHAUSTED:
                raise BudgetExhaustedError(f"the {admission.reason} budget is spent")
            retry_at = admission.retry_at or now + timedelta(seconds=1)
            if admission.reason in POLL_REASONS:  # a lease's expiry is only an upper bound
                retry_at = min(retry_at, now + POLL)
            if retry_at >= deadline:
                raise LaneBusyError(
                    f"the budget ({admission.reason}) frees up too late", admission.retry_at
                )
            await self.sleep(max((retry_at - now).total_seconds(), 0.01))
            now = self.clock()
            seen = await self._admitted_by_state(purpose, cost, now)
            if check is not None:
                await check(now)
            await self._breaker_closed(cost, now)

    async def _send(
        self,
        template: Template,
        final: FinalRequest,
        lease: Lease,
        seen: Seen,
        purpose: Purpose,
        component: str,
        deadline: datetime,
        key: str,
        check: SendCheck | None = None,
        limit: timedelta | None = None,
        missing: str = "source_expired",
    ) -> Result:
        spec = final.spec
        limit_s = (type(template).timeout if limit is None else limit).total_seconds()
        method, path = wire_path(final)
        body = None if final.body is None else encode_body(final.body)
        attempts = 0
        status: int | None = None
        size = 0
        spent = 0  # server time charged for earlier attempts
        started = sent_at = self.clock()
        finished = False

        scale = seen.scale
        lane = lane_of(purpose)

        async def finish(outcome: str, took: int) -> None:
            nonlocal finished
            finished = True
            now = self.clock()
            await lane_settle(self.state, lane, lease, took, now, scale)
            elapsed = int((now - started).total_seconds() * 1000)
            await self.state.record(
                LedgerEntry(
                    at=started,
                    component=component,
                    purpose=purpose.value,
                    template=spec.name,
                    version=spec.version,
                    indices=final.indices or ((final.pattern,) if final.pattern else ()),
                    outcome=outcome,
                    http_status=status,
                    took_ms=took,
                    elapsed_ms=max(elapsed, 0),
                    response_bytes=size,
                    attempts=attempts,
                    live_session=self.live.session_id if self.live else None,
                    task_key=key,
                    lane=None if lane is None else lane.value,
                    health=seen.health,
                    switches=seen.stopped,
                )
            )

        try:
            while True:
                attempts += 1
                now = self.clock()
                left = (deadline - now).total_seconds()
                if left <= 0:
                    await finish("deadline_passed", spent)
                    raise DeadlinePassedError("the deadline passed before the request was sent")
                timeout = min(limit_s, left)
                wire = WireRequest(
                    method, path, final.url_params, body, type(template).opaque_id(component),
                    timeout,
                )  # fmt: skip
                sent_at = self.clock()
                try:
                    response = await self.transport.send(wire)
                    status = response.status
                    size = len(response.body)
                    payload = parse_json(response.body)
                    check_status(response.status, payload, missing=missing)
                except TransportFailedError as exc:
                    timed_out = isinstance(exc, TimedOutError)
                    if not exc.reached:  # no connection: the SIEM did no work
                        charged = 0
                    else:
                        charged = int(timeout * 1000) if timed_out else self._ms(sent_at)
                    if exc.retriable and attempts == 1 and deadline - self.clock() > RETRY_MIN_LEFT:
                        spent += charged
                        await self.sleep(self.rng.uniform(0.5, 1.5))
                        try:
                            await self._admitted_by_state(purpose, spec.cost, self.clock())
                            if check is not None:
                                await check(self.clock())
                            await self._breaker_closed(spec.cost, self.clock())
                        except RefusedError as refusal:
                            await finish(refusal.reason, spent)
                            raise
                        continue
                    await finish(exc.reason, spent + charged)
                    raise
                except OverloadedError as exc:
                    await self.state.breaker_overload(self.clock())
                    await finish(exc.reason, spent + self._ms(sent_at))
                    raise
                except AuthFailedError as exc:
                    memory = await self.state.health()
                    await self.state.save_health(health_core.on_auth_failed(memory, self.clock()))
                    await finish(exc.reason, spent + self._ms(sent_at))
                    raise
                except GatewayError as exc:
                    await finish(exc.reason, spent + self._ms(sent_at))
                    raise
                took = spent + took_ms(spec.endpoint, payload, response.elapsed_ms)
                try:
                    check_complete(spec.endpoint, payload)
                except GatewayError as exc:
                    await finish(exc.reason, took)
                    raise
                if spec.cost is not CostClass.PROBE:
                    await self.state.breaker_success(self.clock())
                await finish("ok", took)
                return Result(payload, took, final.indices)
        except BaseException:
            if not finished:  # cancelled, or a bug: the lease is settled all the same
                await asyncio.shield(finish("aborted", spent + self._ms(sent_at)))
            raise

    def _ms(self, since: datetime) -> int:
        return max(int((self.clock() - since).total_seconds() * 1000), 0)


@dataclass
class Spend:
    """What a call admitted by ``LaneGate.hold`` cost; unset, it is max(elapsed, estimate).
    ``health`` and ``switches`` are what the admission saw (for the caller's ledger row)."""

    took_ms: int | None = None
    health: str | None = None
    switches: tuple[str, ...] = ()

    def charge(self, took_ms: int) -> None:
        if took_ms < 0:
            raise ValueError("a call never costs less than nothing")
        self.took_ms = took_ms


class LaneGate:
    """A lane's admission for a client that is not ``Gateway`` (identity checks with a
    person's own credential): the purpose's kill switch and health rule, the lane's budget
    (waiting within the deadline, the rules asked again after every wait), and one settle of
    what the call cost. The collector's lane and probes have their own path (``Gateway.run``).

        async with gate.hold(Purpose.IDENTITY, deadline=...) as spend:
            answer = await my_client.check(...)
            spend.charge(answer_round_trip_ms)
    """

    def __init__(
        self,
        state: GatewayState,
        *,
        health_config: HealthConfig | None = None,
        clock: Callable[[], datetime] = utcnow,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.state = state
        self.health_config = health_config or HealthConfig()
        self.clock = clock
        self.sleep = sleep

    @contextlib.asynccontextmanager
    async def hold(
        self, purpose: Purpose, *, deadline: datetime, cost: CostClass = CostClass.LIGHT,
        kept: int = 0,
    ) -> AsyncIterator[Spend]:  # fmt: skip
        """Admit one call of ``purpose``; ``kept``: the lane's requests a minute this call
        leaves to others (``lanes.admit``)."""
        lane = lane_of(purpose)
        if lane is None or lane is Lane.COLLECTOR or cost is CostClass.PROBE:
            raise ValueError(f"{purpose} has its own path: Gateway.run")
        lease_id = uuid.uuid4().hex
        while True:
            now = self.clock()
            if now >= deadline:
                raise DeadlinePassedError("the deadline passed before the call started")
            seen = await admitted_by_state(self.state, purpose, cost, now, self.health_config)
            admission = await self.state.lane_admit(
                lane, cost, now, seen.scale, lease_id, kept=kept
            )
            if admission.verdict is Verdict.ADMITTED:
                break
            if admission.verdict is Verdict.EXHAUSTED:
                raise BudgetExhaustedError(f"the {lane} lane's {admission.reason} budget is spent")
            retry_at = admission.retry_at or now + timedelta(seconds=1)
            if admission.reason in POLL_REASONS:
                retry_at = min(retry_at, now + POLL)
            if retry_at >= deadline:
                raise DeadlinePassedError(f"the {lane} lane ({admission.reason}) frees up too late")
            await self.sleep(max((retry_at - now).total_seconds(), 0.01))
        lease = admission.lease
        assert lease is not None
        spend = Spend(health=seen.health, switches=seen.stopped)
        started = self.clock()
        try:
            yield spend
        finally:
            elapsed = max(int((self.clock() - started).total_seconds() * 1000), 0)
            took = spend.took_ms if spend.took_ms is not None else max(elapsed, lease.estimate_ms)
            await asyncio.shield(
                self.state.lane_settle(lane, lease, took, self.clock(), seen.scale)
            )
