"""Where the gateway keeps its shared state: kill switches, health memory, budget, breaker,
live-test sessions, the request ledger and the probes' readings. Every read-modify-write
is atomic, so separate ARGUS processes share one budget and one breaker (``PgStore``, in
``argus.gateway.pgstore``). ``MemoryStore`` is the same behaviour inside one process, for tests
and tools.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Protocol, TypeVar

from argus.gateway import breaker as breaker_core
from argus.gateway import budget as budget_core
from argus.gateway import lanes as lanes_core
from argus.gateway.health import HealthMemory, Readings
from argus.gateway.kibana import writes as kibana_writes
from argus.gateway.lanes import Lane, LanePlan, LaneStates
from argus.gateway.templates import CostClass
from argus.identity import reach as reach_core

T = TypeVar("T")


@dataclass(frozen=True)
class Switches:
    stopped: frozenset[str] = frozenset()  # "global" and/or component names

    def blocks(self, component: str | None) -> bool:
        return "global" in self.stopped or (component is not None and component in self.stopped)


@dataclass(frozen=True)
class LiveSession:
    """A human-issued live-test session: a request cap and an end time."""

    id: str
    ends_at: datetime
    max_requests: int
    used: int = 0
    ended: bool = False


@dataclass(frozen=True)
class LedgerEntry:
    at: datetime
    component: str
    purpose: str
    template: str
    version: int
    indices: tuple[str, ...]
    outcome: str  # "ok" or an error reason
    http_status: int | None
    took_ms: int
    elapsed_ms: int
    response_bytes: int
    attempts: int
    live_session: str | None = None
    task_key: str | None = None  # the request's content address: joins its evidence
    # the lane it spent, where it went, and for a write what it was
    lane: str | None = None
    target: str = "elasticsearch"  # or "kibana"
    outbox_id: str | None = None
    payload_hash: str | None = None
    write_class: str | None = None
    approval_id: str | None = None
    health: str | None = None  # the SIEM's effective state when it was sent
    switches: tuple[str, ...] = ()  # the kill switches that were stopped then


@dataclass(frozen=True)
class RecentRequest:
    """A ledger row as the re-measurement reads it back."""

    at: datetime
    component: str
    purpose: str
    template: str
    outcome: str
    took_ms: int
    http_status: int | None = None  # None: no answer from the SIEM
    attempts: int = 1  # the attempts the row covers (a refused attempt included)


@dataclass(frozen=True)
class ProbeRow:
    """A stored probe reading (``siem_probes``) and the state it led to."""

    at: datetime
    state: str
    reasons: tuple[str, ...] = ()
    probe_ok: bool = True
    auth_failed: bool = False
    disk_percent: float | None = None
    heap_percent: float | None = None
    load_1m: float | None = None
    search_queue: int | None = None
    search_rejected: int | None = None
    breakers_tripped: int | None = None
    blocked_indices: tuple[str, ...] = ()


def probe_from(readings: Readings, memory: HealthMemory) -> ProbeRow:
    return ProbeRow(
        at=readings.at,
        state=str(memory.state),
        reasons=tuple(memory.reasons),
        probe_ok=readings.probe_ok,
        auth_failed=readings.auth_failed,
        disk_percent=readings.disk_percent,
        heap_percent=readings.heap_percent,
        load_1m=readings.load_1m,
        search_queue=readings.search_queue,
        search_rejected=readings.search_rejected,
        breakers_tripped=readings.breakers_tripped,
        blocked_indices=tuple(readings.blocked_indices),
    )


class GatewayState(Protocol):
    async def switches(self) -> Switches: ...
    async def health(self) -> HealthMemory: ...
    async def save_health(self, memory: HealthMemory) -> None: ...
    async def budget_admit(
        self, cost: CostClass, now: datetime, scale: float, lease_id: str, *, kept_ms: int = 0
    ) -> budget_core.Admission: ...
    async def budget_settle(
        self, lease: budget_core.Lease, took_ms: int, now: datetime, scale: float
    ) -> None: ...
    async def breaker_peek(self, now: datetime) -> tuple[bool, datetime | None]: ...
    async def breaker_admit(self, now: datetime) -> tuple[bool, datetime | None]: ...
    async def breaker_overload(self, now: datetime) -> None: ...
    async def breaker_success(self, now: datetime) -> None: ...
    async def live_use(self, session_id: str, now: datetime) -> bool: ...
    async def record(self, entry: LedgerEntry) -> None: ...
    async def record_probe(self, readings: Readings, memory: HealthMemory) -> None: ...
    # the lanes other than the collector's (whose bucket is budget_admit's)
    async def lane_admit(
        self, lane: Lane, cost: CostClass, now: datetime, scale: float, lease_id: str,
        *, kept: int = 0,
    ) -> budget_core.Admission: ...  # fmt: skip
    async def lane_settle(
        self, lane: Lane, lease: budget_core.Lease, took_ms: int, now: datetime, scale: float
    ) -> None: ...


class KibanaState(Protocol):
    """The Kibana lane's shared state: stopped, paused classes, the write caps' counters
    and Kibana's own overload breaker."""

    async def kibana_lane(self) -> kibana_writes.KibanaLaneState: ...
    async def kibana_change(
        self,
        change: Callable[[kibana_writes.KibanaLaneState], tuple[T, kibana_writes.KibanaLaneState]],
    ) -> T: ...
    async def kibana_breaker_peek(self, now: datetime) -> tuple[bool, datetime | None]: ...
    async def kibana_breaker_admit(self, now: datetime) -> tuple[bool, datetime | None]: ...
    async def kibana_breaker_overload(self, now: datetime) -> None: ...
    async def kibana_breaker_success(self, now: datetime) -> None: ...


class SharedState(GatewayState, KibanaState, Protocol):
    """A store that keeps both the gateway's and the Kibana lane's state."""


class DiscoveryStore:
    """The store ``argus discover`` runs on: everything it reads and spends is the real store's
    (budget, breakers, ledger, kill switches, health memory), but it remembers no failure and no
    reading: ``save_health`` and ``record_probe`` do nothing and a Kibana lane change is dropped, so
    a 401 or 403 on a discovery read never puts the SIEM in STOP or stops the Kibana lane for the
    services that share the real store. ``adopt`` sets the health this command's requests are
    admitted by (a probe's reading, never saved)."""

    def __init__(self, inner: SharedState) -> None:
        self.inner = inner
        self.adopted: HealthMemory | None = None

    def adopt(self, memory: HealthMemory) -> None:
        """Use ``memory`` as the health of this command's requests (the real memory is left)."""
        self.adopted = memory

    # ---- what is not remembered
    async def save_health(self, memory: HealthMemory) -> None:
        return None

    async def record_probe(self, readings: Readings, memory: HealthMemory) -> None:
        return None

    async def kibana_change(
        self,
        change: Callable[[kibana_writes.KibanaLaneState], tuple[T, kibana_writes.KibanaLaneState]],
    ) -> T:
        result, _dropped = change(await self.inner.kibana_lane())
        return result

    # ---- what is the real store's
    async def switches(self) -> Switches:
        return await self.inner.switches()

    async def health(self) -> HealthMemory:
        return self.adopted if self.adopted is not None else await self.inner.health()

    async def budget_admit(
        self, cost: CostClass, now: datetime, scale: float, lease_id: str, *, kept_ms: int = 0
    ) -> budget_core.Admission:
        return await self.inner.budget_admit(cost, now, scale, lease_id, kept_ms=kept_ms)

    async def budget_settle(
        self, lease: budget_core.Lease, took_ms: int, now: datetime, scale: float
    ) -> None:
        await self.inner.budget_settle(lease, took_ms, now, scale)

    async def breaker_peek(self, now: datetime) -> tuple[bool, datetime | None]:
        return await self.inner.breaker_peek(now)

    async def breaker_admit(self, now: datetime) -> tuple[bool, datetime | None]:
        return await self.inner.breaker_admit(now)

    async def breaker_overload(self, now: datetime) -> None:
        await self.inner.breaker_overload(now)

    async def breaker_success(self, now: datetime) -> None:
        await self.inner.breaker_success(now)

    async def live_use(self, session_id: str, now: datetime) -> bool:
        return await self.inner.live_use(session_id, now)

    async def record(self, entry: LedgerEntry) -> None:
        await self.inner.record(entry)

    async def lane_admit(
        self, lane: Lane, cost: CostClass, now: datetime, scale: float, lease_id: str,
        *, kept: int = 0,
    ) -> budget_core.Admission:  # fmt: skip
        return await self.inner.lane_admit(lane, cost, now, scale, lease_id, kept=kept)

    async def lane_settle(
        self, lane: Lane, lease: budget_core.Lease, took_ms: int, now: datetime, scale: float
    ) -> None:
        await self.inner.lane_settle(lane, lease, took_ms, now, scale)

    async def kibana_lane(self) -> kibana_writes.KibanaLaneState:
        return await self.inner.kibana_lane()

    async def kibana_breaker_peek(self, now: datetime) -> tuple[bool, datetime | None]:
        return await self.inner.kibana_breaker_peek(now)

    async def kibana_breaker_admit(self, now: datetime) -> tuple[bool, datetime | None]:
        return await self.inner.kibana_breaker_admit(now)

    async def kibana_breaker_overload(self, now: datetime) -> None:
        await self.inner.kibana_breaker_overload(now)

    async def kibana_breaker_success(self, now: datetime) -> None:
        await self.inner.kibana_breaker_success(now)


@dataclass
class MemoryStore:
    budget_config: budget_core.BudgetConfig = field(default_factory=budget_core.BudgetConfig)
    stopped: set[str] = field(default_factory=set)
    memory: HealthMemory = field(default_factory=HealthMemory)
    budget: budget_core.BudgetState = field(default_factory=budget_core.BudgetState)
    breaker: breaker_core.BreakerState = field(default_factory=breaker_core.BreakerState)
    sessions: dict[str, LiveSession] = field(default_factory=dict)
    ledger: list[LedgerEntry] = field(default_factory=list)
    probes: list[tuple[Readings, HealthMemory]] = field(default_factory=list)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    lane_plan: LanePlan = field(default_factory=LanePlan)
    lanes: LaneStates = field(default_factory=LaneStates)
    kibana: kibana_writes.KibanaLaneState = field(default_factory=kibana_writes.KibanaLaneState)
    kibana_breaker: breaker_core.BreakerState = field(default_factory=breaker_core.BreakerState)
    identity: reach_core.ReachState = field(default_factory=reach_core.ReachState)

    async def switches(self) -> Switches:
        return Switches(frozenset(self.stopped))

    async def health(self) -> HealthMemory:
        return self.memory

    async def save_health(self, memory: HealthMemory) -> None:
        self.memory = memory

    async def budget_admit(
        self, cost: CostClass, now: datetime, scale: float, lease_id: str, *, kept_ms: int = 0
    ) -> budget_core.Admission:
        async with self.lock:
            # heavy queries one at a time across every lane; the concurrency limit shared by all
            waiting = lanes_core.collector_wait(
                self.lanes, self.budget, cost, now, self.budget_config, self.lane_plan.ceiling
            )
            if waiting is not None:
                return waiting
            admission, self.budget = budget_core.admit(
                self.budget, self.budget_config, cost, now, scale=scale, lease_id=lease_id,
                kept_ms=kept_ms,
            )  # fmt: skip
            return admission

    async def budget_settle(
        self, lease: budget_core.Lease, took_ms: int, now: datetime, scale: float
    ) -> None:
        async with self.lock:
            self.budget = budget_core.settle(
                self.budget, self.budget_config, lease, took_ms, now, scale=scale
            )

    async def breaker_peek(self, now: datetime) -> tuple[bool, datetime | None]:
        return breaker_core.peek(self.breaker, now), self.breaker.open_until

    async def breaker_admit(self, now: datetime) -> tuple[bool, datetime | None]:
        async with self.lock:
            ok, self.breaker = breaker_core.admit(self.breaker, now)
            return ok, self.breaker.open_until

    async def breaker_overload(self, now: datetime) -> None:
        async with self.lock:
            self.breaker = breaker_core.on_overload(self.breaker, now)

    async def breaker_success(self, now: datetime) -> None:
        async with self.lock:
            self.breaker = breaker_core.on_success(self.breaker, now)

    async def live_use(self, session_id: str, now: datetime) -> bool:
        async with self.lock:
            session = self.sessions.get(session_id)
            if (
                session is None
                or session.ended
                or now >= session.ends_at
                or session.used >= session.max_requests
            ):
                return False
            self.sessions[session_id] = replace(session, used=session.used + 1)
            return True

    async def record(self, entry: LedgerEntry) -> None:
        self.ledger.append(entry)

    async def record_probe(self, readings: Readings, memory: HealthMemory) -> None:
        self.probes.append((readings, memory))

    async def lane_admit(
        self, lane: Lane, cost: CostClass, now: datetime, scale: float, lease_id: str,
        *, kept: int = 0,
    ) -> budget_core.Admission:  # fmt: skip
        async with self.lock:
            admission, self.lanes = lanes_core.admit(
                self.lanes, self.lane_plan, lane, cost, now,
                scale=scale, lease_id=lease_id, collector=self.budget, kept=kept,
            )  # fmt: skip
            return admission

    async def lane_settle(
        self, lane: Lane, lease: budget_core.Lease, took_ms: int, now: datetime, scale: float
    ) -> None:
        async with self.lock:
            self.lanes = lanes_core.settle(
                self.lanes, self.lane_plan, lane, lease, took_ms, now, scale=scale
            )

    async def kibana_lane(self) -> kibana_writes.KibanaLaneState:
        return self.kibana

    async def kibana_change(
        self,
        change: Callable[[kibana_writes.KibanaLaneState], tuple[T, kibana_writes.KibanaLaneState]],
    ) -> T:
        async with self.lock:
            result, self.kibana = change(self.kibana)
            return result

    async def kibana_breaker_peek(self, now: datetime) -> tuple[bool, datetime | None]:
        return breaker_core.peek(self.kibana_breaker, now), self.kibana_breaker.open_until

    async def kibana_breaker_admit(self, now: datetime) -> tuple[bool, datetime | None]:
        async with self.lock:
            ok, self.kibana_breaker = breaker_core.admit(self.kibana_breaker, now)
            return ok, self.kibana_breaker.open_until

    async def kibana_breaker_overload(self, now: datetime) -> None:
        async with self.lock:
            self.kibana_breaker = breaker_core.on_overload(self.kibana_breaker, now)

    async def kibana_breaker_success(self, now: datetime) -> None:
        async with self.lock:
            self.kibana_breaker = breaker_core.on_success(self.kibana_breaker, now)

    async def identity_reach_admit(self, now: datetime) -> tuple[bool, reach_core.ReachState]:
        async with self.lock:
            ok, self.identity = reach_core.admit(self.identity, now)
            return ok, self.identity

    async def identity_reach_report(
        self, now: datetime, signal: reach_core.Signal
    ) -> reach_core.ReachState:
        async with self.lock:
            self.identity = reach_core.report(self.identity, now, signal)
            return self.identity

    async def requests_since(
        self, since: datetime, until: datetime | None = None
    ) -> list[RecentRequest]:
        rows = [
            RecentRequest(
                e.at,
                e.component,
                e.purpose,
                e.template,
                e.outcome,
                e.took_ms,
                e.http_status,
                e.attempts,
            )
            for e in self.ledger
            if e.at >= since and (until is None or e.at < until)
        ]
        return sorted(rows, key=lambda row: row.at)

    async def probes_since(self, since: datetime, until: datetime | None = None) -> list[ProbeRow]:
        rows = [
            probe_from(readings, memory)
            for readings, memory in self.probes
            if readings.at >= since and (until is None or readings.at < until)
        ]
        return sorted(rows, key=lambda row: row.at)

    async def latest_probe(self) -> ProbeRow | None:
        if not self.probes:
            return None
        return max((probe_from(r, m) for r, m in self.probes), key=lambda row: row.at)
