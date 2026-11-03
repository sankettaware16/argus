"""The gateway's shared state in Postgres.

Each state machine (health memory, budget, breaker) is one JSON row of ``siem_state``; every
change is a read-modify-write under ``SELECT ... FOR UPDATE``, so all ARGUS processes share one
budget and one breaker. Operator actions (kill switches, live sessions) are audited in the same
transaction as the change.
"""

from __future__ import annotations

import json
import math
from collections.abc import Callable
from datetime import date, datetime, timedelta
from typing import Any, TypeVar

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker

from argus.db.audit import record_audit
from argus.gateway import breaker as breaker_core
from argus.gateway import budget as budget_core
from argus.gateway import lanes as lanes_core
from argus.gateway.health import HealthMemory, HealthState, Readings
from argus.gateway.kibana import writes as kibana_writes
from argus.gateway.lanes import Lane, LanePlan, LaneStates
from argus.gateway.state import LedgerEntry, ProbeRow, RecentRequest, Switches
from argus.gateway.templates import COMPONENTS, CostClass
from argus.identity import reach as reach_core

T = TypeVar("T")
SWITCHES = ("global", *COMPONENTS)
MAX_LIVE_REQUESTS = 50
MAX_LIVE_DURATION = timedelta(minutes=60)


# --------------------------------------------------------------------------- JSON forms


def _time(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _parse_time(value: Any) -> datetime | None:
    return None if value is None else datetime.fromisoformat(value)


def budget_to_json(state: budget_core.BudgetState) -> dict[str, Any]:
    return {
        "tokens_ms": state.tokens_ms,
        "refilled_at": _time(state.refilled_at),
        "day": None if state.day is None else state.day.isoformat(),
        "day_used_ms": state.day_used_ms,
        "heavy_day": state.heavy_day,
        "heavy_starts": [t.isoformat() for t in state.heavy_starts],
        "probe_starts": [t.isoformat() for t in state.probe_starts],
        "leases": [
            {
                "id": lease.id,
                "cost": lease.cost.value,
                "estimate_ms": lease.estimate_ms,
                "expires": lease.expires.isoformat(),
            }
            for lease in state.leases
        ],
        "expired": list(state.expired),
    }


def budget_from_json(data: dict[str, Any]) -> budget_core.BudgetState:
    if not data:
        return budget_core.BudgetState()
    return budget_core.BudgetState(
        tokens_ms=data["tokens_ms"],
        refilled_at=_parse_time(data["refilled_at"]),
        day=None if data["day"] is None else date.fromisoformat(data["day"]),
        day_used_ms=data["day_used_ms"],
        heavy_day=data["heavy_day"],
        heavy_starts=tuple(datetime.fromisoformat(t) for t in data["heavy_starts"]),
        probe_starts=tuple(datetime.fromisoformat(t) for t in data["probe_starts"]),
        leases=tuple(
            budget_core.Lease(
                lease["id"],
                CostClass(lease["cost"]),
                lease["estimate_ms"],
                datetime.fromisoformat(lease["expires"]),
            )
            for lease in data["leases"]
        ),
        expired=tuple(data.get("expired", ())),
    )


def lanes_to_json(states: LaneStates) -> dict[str, Any]:
    return {
        "buckets": {lane.value: budget_to_json(b) for lane, b in sorted(states.buckets.items())},
        "starts": {
            lane.value: [t.isoformat() for t in starts]
            for lane, starts in sorted(states.starts.items())
        },
    }


def lanes_from_json(data: dict[str, Any]) -> LaneStates:
    if not data:
        return LaneStates()
    return LaneStates(
        buckets={Lane(k): budget_from_json(v) for k, v in data.get("buckets", {}).items()},
        starts={
            Lane(k): tuple(datetime.fromisoformat(t) for t in v)
            for k, v in data.get("starts", {}).items()
        },
    )


def breaker_to_json(state: breaker_core.BreakerState) -> dict[str, Any]:
    return {
        "level": state.level,
        "open_until": _time(state.open_until),
        "trial_until": _time(state.trial_until),
        "last_trip": _time(state.last_trip),
    }


def breaker_from_json(data: dict[str, Any]) -> breaker_core.BreakerState:
    if not data:
        return breaker_core.BreakerState()
    return breaker_core.BreakerState(
        level=data["level"],
        open_until=_parse_time(data["open_until"]),
        trial_until=_parse_time(data["trial_until"]),
        last_trip=_parse_time(data["last_trip"]),
    )


def reach_to_json(state: reach_core.ReachState) -> dict[str, Any]:
    return {
        "level": state.level,
        "open_until": _time(state.open_until),
        "trial_until": _time(state.trial_until),
        "last_trip": _time(state.last_trip),
        "reason": state.reason,
        "failures": [_time(t) for t in state.failures],
    }


def reach_from_json(data: dict[str, Any]) -> reach_core.ReachState:
    return reach_core.ReachState(
        level=int(data.get("level", 0)),
        open_until=_parse_time(data.get("open_until")),
        trial_until=_parse_time(data.get("trial_until")),
        last_trip=_parse_time(data.get("last_trip")),
        reason=data.get("reason"),
        failures=tuple(t for t in (_parse_time(x) for x in data.get("failures", ())) if t),
    )


def health_to_json(memory: HealthMemory) -> dict[str, Any]:
    return {
        "state": memory.state.value,
        "since": _time(memory.since),
        "probed_at": _time(memory.probed_at),
        "recovered_at": _time(memory.recovered_at),
        "reasons": list(memory.reasons),
        "search_rejected": memory.search_rejected,
        "breakers_tripped": memory.breakers_tripped,
        "recent": [list(probe) for probe in memory.recent],
    }


def health_from_json(data: dict[str, Any]) -> HealthMemory:
    if not data:
        return HealthMemory()
    return HealthMemory(
        state=HealthState(data["state"]),
        since=_parse_time(data["since"]),
        probed_at=_parse_time(data.get("probed_at")),
        recovered_at=_parse_time(data["recovered_at"]),
        reasons=tuple(data["reasons"]),
        search_rejected=data["search_rejected"],
        breakers_tripped=data["breakers_tripped"],
        recent=tuple(tuple(probe) for probe in data["recent"]),
    )


# --------------------------------------------------------------------------- the store


class PgStore:
    def __init__(
        self,
        engine: AsyncEngine,
        budget_config: budget_core.BudgetConfig | None = None,
        lane_plan: LanePlan | None = None,
    ) -> None:
        self.engine = engine
        self.budget_config = budget_config or budget_core.BudgetConfig()
        self.lane_plan = lane_plan or LanePlan()
        self.sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def _budget_and_lanes(
        self,
        change: Callable[
            [budget_core.BudgetState, LaneStates],
            tuple[T, budget_core.BudgetState, LaneStates],
        ],
    ) -> T:
        """Both budget rows under one lock, always in the order budget, lanes (no deadlock)."""
        async with self.engine.begin() as conn:
            rows = await conn.execute(
                text(
                    "SELECT name, state FROM siem_state WHERE name IN ('budget', 'lanes')"
                    " ORDER BY name FOR UPDATE"
                )
            )
            found: dict[str, Any] = dict(rows.all())
            budget, lanes = budget_from_json(found["budget"]), lanes_from_json(found["lanes"])
            result, new_budget, new_lanes = change(budget, lanes)
            if new_budget != budget:
                await conn.execute(
                    text(
                        "UPDATE siem_state SET state = CAST(:s AS jsonb), updated_at = now()"
                        " WHERE name = 'budget'"
                    ),
                    {"s": _json(budget_to_json(new_budget))},
                )
            if new_lanes != lanes:
                await conn.execute(
                    text(
                        "UPDATE siem_state SET state = CAST(:s AS jsonb), updated_at = now()"
                        " WHERE name = 'lanes'"
                    ),
                    {"s": _json(lanes_to_json(new_lanes))},
                )
            return result

    async def _change(
        self,
        name: str,
        load: Callable[[dict[str, Any]], Any],
        dump: Callable[[Any], dict[str, Any]],
        change: Callable[[Any], tuple[T, Any]],
    ) -> T:
        async with self.engine.begin() as conn:
            row = await conn.execute(
                text("SELECT state FROM siem_state WHERE name = :n FOR UPDATE"), {"n": name}
            )
            result, new = change(load(row.scalar_one()))
            await conn.execute(
                text(
                    "UPDATE siem_state SET state = CAST(:s AS jsonb), updated_at = now()"
                    " WHERE name = :n"
                ),
                {"n": name, "s": _json(dump(new))},
            )
            return result

    async def _read(self, name: str) -> dict[str, Any]:
        async with self.engine.connect() as conn:
            row = await conn.execute(
                text("SELECT state FROM siem_state WHERE name = :n"), {"n": name}
            )
            value: dict[str, Any] = row.scalar_one()
            return value

    # ---------------------------------------------------------------- GatewayState

    async def switches(self) -> Switches:
        async with self.engine.connect() as conn:
            rows = await conn.execute(text("SELECT component FROM siem_switches WHERE stopped"))
            return Switches(frozenset(name for (name,) in rows))

    async def health(self) -> HealthMemory:
        return health_from_json(await self._read("health"))

    async def save_health(self, memory: HealthMemory) -> None:
        await self._change("health", health_from_json, health_to_json, lambda _old: (None, memory))

    async def budget_admit(
        self, cost: CostClass, now: datetime, scale: float, lease_id: str
    ) -> budget_core.Admission:
        """The collector's lane (and probes): both budget rows, for the rules across lanes
        (heavy queries one at a time, the concurrency limit shared by every lane)."""

        def change(
            budget: budget_core.BudgetState, lanes: LaneStates
        ) -> tuple[budget_core.Admission, budget_core.BudgetState, LaneStates]:
            waiting = lanes_core.collector_wait(
                lanes, budget, cost, now, self.budget_config, self.lane_plan.ceiling
            )
            if waiting is not None:
                return waiting, budget, lanes
            admission, budget = budget_core.admit(
                budget, self.budget_config, cost, now, scale=scale, lease_id=lease_id
            )
            return admission, budget, lanes

        return await self._budget_and_lanes(change)

    async def lane_admit(
        self, lane: Lane, cost: CostClass, now: datetime, scale: float, lease_id: str,
        *, kept: int = 0,
    ) -> budget_core.Admission:  # fmt: skip
        def change(
            budget: budget_core.BudgetState, lanes: LaneStates
        ) -> tuple[budget_core.Admission, budget_core.BudgetState, LaneStates]:
            admission, lanes = lanes_core.admit(
                lanes, self.lane_plan, lane, cost, now,
                scale=scale, lease_id=lease_id, collector=budget, kept=kept,
            )  # fmt: skip
            return admission, budget, lanes

        return await self._budget_and_lanes(change)

    async def lane_settle(
        self, lane: Lane, lease: budget_core.Lease, took_ms: int, now: datetime, scale: float
    ) -> None:
        def change(state: LaneStates) -> tuple[None, LaneStates]:
            return None, lanes_core.settle(
                state, self.lane_plan, lane, lease, took_ms, now, scale=scale
            )

        await self._change("lanes", lanes_from_json, lanes_to_json, change)

    async def lanes(self) -> LaneStates:
        return lanes_from_json(await self._read("lanes"))

    async def lane_fill(
        self, lane: Lane, *, actor: str, now: datetime, scale: float, health: str, reason: str
    ) -> tuple[float, float]:
        """A person tops one lane's bucket up to its capacity (``lanes.fill``); audited in
        the same transaction with who, when, what it held and what it holds. Writes ARGUS's own
        database only. Returns (before, after) in milliseconds of server time."""
        async with self.sessions() as session, session.begin():
            row = await session.execute(
                text("SELECT state FROM siem_state WHERE name = 'lanes' FOR UPDATE")
            )
            old = lanes_from_json(row.scalar_one())
            before, after, new = lanes_core.fill(old, self.lane_plan, lane, now, scale=scale)
            await session.execute(
                text(
                    "UPDATE siem_state SET state = CAST(:s AS jsonb), updated_at = now()"
                    " WHERE name = 'lanes'"
                ),
                {"s": _json(lanes_to_json(new))},
            )
            await record_audit(
                session,
                actor=actor,
                action="siem.lane_fill",
                target_type="siem_lane",
                target_id=lane.value,
                details={"before_ms": round(before, 1), "after_ms": round(after, 1),
                         "scale": scale, "health": health, "reason": reason,
                         "at": now.isoformat()},
            )  # fmt: skip
            return before, after

    # ---------------------------------------------------------------- KibanaState

    async def kibana_lane(self) -> kibana_writes.KibanaLaneState:
        return kibana_writes.from_json(await self._read("kibana"))

    async def kibana_change(
        self,
        change: Callable[[kibana_writes.KibanaLaneState], tuple[T, kibana_writes.KibanaLaneState]],
    ) -> T:
        return await self._change("kibana", kibana_writes.from_json, kibana_writes.to_json, change)

    async def kibana_breaker(self) -> breaker_core.BreakerState:
        return breaker_from_json(await self._read("kibana_breaker"))

    async def kibana_breaker_peek(self, now: datetime) -> tuple[bool, datetime | None]:
        state = await self.kibana_breaker()
        return breaker_core.peek(state, now), state.open_until

    async def kibana_breaker_admit(self, now: datetime) -> tuple[bool, datetime | None]:
        def change(state: breaker_core.BreakerState) -> tuple[tuple[bool, datetime | None], Any]:
            ok, new = breaker_core.admit(state, now)
            return (ok, new.open_until), new

        return await self._change("kibana_breaker", breaker_from_json, breaker_to_json, change)

    async def kibana_breaker_overload(self, now: datetime) -> None:
        await self._change(
            "kibana_breaker",
            breaker_from_json,
            breaker_to_json,
            lambda state: (None, breaker_core.on_overload(state, now)),
        )

    async def kibana_breaker_success(self, now: datetime) -> None:
        await self._change(
            "kibana_breaker",
            breaker_from_json,
            breaker_to_json,
            lambda state: (None, breaker_core.on_success(state, now)),
        )

    async def identity_reach(self) -> reach_core.ReachState:
        return reach_from_json(await self._read("identity"))

    async def identity_reach_admit(self, now: datetime) -> tuple[bool, reach_core.ReachState]:
        def change(
            state: reach_core.ReachState,
        ) -> tuple[tuple[bool, reach_core.ReachState], reach_core.ReachState]:
            ok, new = reach_core.admit(state, now)
            return (ok, new), new

        return await self._change("identity", reach_from_json, reach_to_json, change)

    async def identity_reach_report(
        self, now: datetime, signal: reach_core.Signal
    ) -> reach_core.ReachState:
        def change(
            state: reach_core.ReachState,
        ) -> tuple[reach_core.ReachState, reach_core.ReachState]:
            new = reach_core.report(state, now, signal)
            return new, new

        return await self._change("identity", reach_from_json, reach_to_json, change)

    async def kibana_resume(
        self, *, actor: str, reason: str, write_class: kibana_writes.WriteClass | None
    ) -> bool:
        """An operator resumes Kibana work (None) or one paused write class; audited with the
        change. True if something was stopped or paused."""
        async with self.sessions() as session, session.begin():
            row = await session.execute(
                text("SELECT state FROM siem_state WHERE name = 'kibana' FOR UPDATE")
            )
            old = kibana_writes.from_json(row.scalar_one())
            new = kibana_writes.resume(old, write_class)
            await session.execute(
                text(
                    "UPDATE siem_state SET state = CAST(:s AS jsonb), updated_at = now()"
                    " WHERE name = 'kibana'"
                ),
                {"s": _json(kibana_writes.to_json(new))},
            )
            changed = new != old
            await record_audit(
                session,
                actor=actor,
                action="kibana.resume",
                target_type="kibana_lane",
                target_id=write_class.value if write_class else "kibana",
                details={"changed": changed, "reason": reason,
                         "was": old.stopped if write_class is None
                         else old.paused.get(write_class.value)},
            )  # fmt: skip
            return changed

    async def budget_settle(
        self, lease: budget_core.Lease, took_ms: int, now: datetime, scale: float
    ) -> None:
        def change(state: budget_core.BudgetState) -> tuple[None, Any]:
            return None, budget_core.settle(
                state, self.budget_config, lease, took_ms, now, scale=scale
            )

        await self._change("budget", budget_from_json, budget_to_json, change)

    async def budget(self) -> budget_core.BudgetState:
        return budget_from_json(await self._read("budget"))

    async def breaker_peek(self, now: datetime) -> tuple[bool, datetime | None]:
        state = await self.breaker()
        return breaker_core.peek(state, now), state.open_until

    async def breaker_admit(self, now: datetime) -> tuple[bool, datetime | None]:
        def change(state: breaker_core.BreakerState) -> tuple[tuple[bool, datetime | None], Any]:
            ok, new = breaker_core.admit(state, now)
            return (ok, new.open_until), new

        return await self._change("breaker", breaker_from_json, breaker_to_json, change)

    async def breaker_overload(self, now: datetime) -> None:
        await self._change(
            "breaker",
            breaker_from_json,
            breaker_to_json,
            lambda state: (None, breaker_core.on_overload(state, now)),
        )

    async def breaker_success(self, now: datetime) -> None:
        await self._change(
            "breaker",
            breaker_from_json,
            breaker_to_json,
            lambda state: (None, breaker_core.on_success(state, now)),
        )

    async def breaker(self) -> breaker_core.BreakerState:
        return breaker_from_json(await self._read("breaker"))

    async def live_use(self, session_id: str, now: datetime) -> bool:
        async with self.engine.begin() as conn:
            row = await conn.execute(
                text(
                    "UPDATE siem_live_sessions SET used = used + 1 WHERE id = :id"
                    " AND ended_at IS NULL AND ends_at > :now AND used < max_requests"
                    " RETURNING used"
                ),
                {"id": session_id, "now": now},
            )
            return row.first() is not None

    async def record(self, entry: LedgerEntry) -> None:
        async with self.engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO siem_requests (at, component, purpose, template, version,"
                    " indices, outcome, http_status, took_ms, elapsed_ms, response_bytes,"
                    " attempts, live_session, task_key, lane, target, outbox_id, payload_hash,"
                    " write_class, approval_id, health, switches) VALUES (:at, :component,"
                    " :purpose, :template, :version, :indices, :outcome, :http_status,"
                    " :took_ms, :elapsed_ms, :response_bytes, :attempts, :live_session,"
                    " :task_key, :lane, :target, :outbox_id, :payload_hash, :write_class,"
                    " :approval_id, :health, :switches)"
                ),
                {
                    "at": entry.at,
                    "component": entry.component,
                    "purpose": entry.purpose,
                    "template": entry.template,
                    "version": entry.version,
                    "indices": list(entry.indices),
                    "outcome": entry.outcome,
                    "http_status": entry.http_status,
                    "took_ms": entry.took_ms,
                    "elapsed_ms": entry.elapsed_ms,
                    "response_bytes": entry.response_bytes,
                    "attempts": entry.attempts,
                    "live_session": entry.live_session,
                    "task_key": entry.task_key,
                    "lane": entry.lane,
                    "target": entry.target,
                    "outbox_id": entry.outbox_id,
                    "payload_hash": entry.payload_hash,
                    "write_class": entry.write_class,
                    "approval_id": entry.approval_id,
                    "health": entry.health,
                    "switches": list(entry.switches),
                },
            )

    async def record_probe(self, readings: Readings, memory: HealthMemory) -> None:
        """One probe's readings and the state it led to, for the
        budget's re-measurement: what the probe read anyway, so no request is added."""
        async with self.engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO siem_probes (at, state, reasons, probe_ok, auth_failed,"
                    " disk_percent, heap_percent, load_1m, search_queue, search_rejected,"
                    " breakers_tripped, write_rejected, blocked_indices, ingest_lag_s,"
                    " stale_rules) VALUES (:at, :state, :reasons, :probe_ok, :auth_failed,"
                    " :disk, :heap, :load, :queue, :rejected, :tripped, :write_rejected,"
                    " :blocked, CAST(:lag AS jsonb), :stale)"
                ),
                probe_row(readings, memory),
            )

    # ---------------------------------------------------------------- read back

    async def requests_since(
        self, since: datetime, until: datetime | None = None
    ) -> list[RecentRequest]:
        """Ledger rows from ``since`` (inclusive) to ``until`` (exclusive), oldest first."""
        async with self.engine.connect() as conn:
            rows = await conn.execute(
                text(
                    "SELECT at, component, purpose, template, outcome, took_ms, http_status,"
                    " attempts FROM siem_requests"
                    " WHERE at >= :since AND (CAST(:until AS timestamptz) IS NULL OR at < :until)"
                    " ORDER BY at, id"
                ),
                {"since": since, "until": until},
            )
            return [RecentRequest(*row) for row in rows]

    async def probes_since(self, since: datetime, until: datetime | None = None) -> list[ProbeRow]:
        """Stored probe readings from ``since`` to ``until`` (exclusive), oldest first."""
        async with self.engine.connect() as conn:
            rows = await conn.execute(
                text(_PROBES_SINCE),
                {"since": since, "until": until},
            )
            return [_probe(row) for row in rows]

    async def latest_probe(self) -> ProbeRow | None:
        async with self.engine.connect() as conn:
            row = await conn.execute(text(_LATEST_PROBE))
            found = row.first()
            return None if found is None else _probe(found)

    # ---------------------------------------------------------------- operator actions

    async def set_switch(
        self, component: str, *, stopped: bool, actor: str, reason: str | None
    ) -> bool:
        """Stop or resume; True if it changed. Audited with the change."""
        if component not in SWITCHES:
            raise ValueError(f"unknown component {component!r}; one of {', '.join(SWITCHES)}")
        async with self.sessions() as session, session.begin():
            row = await session.execute(
                text(
                    "UPDATE siem_switches SET stopped = :s, changed_at = now(),"
                    " changed_by = :a, reason = :r WHERE component = :c AND stopped <> :s"
                    " RETURNING component"
                ),
                {"s": stopped, "a": actor, "r": reason, "c": component},
            )
            changed = row.first() is not None
            await record_audit(
                session,
                actor=actor,
                action="siem.stop" if stopped else "siem.resume",
                target_type="siem_switch",
                target_id=component,
                details={"changed": changed, "reason": reason},
            )
            return changed

    async def start_live_session(
        self, session_id: str, *, actor: str, now: datetime, minutes: int, max_requests: int
    ) -> None:
        if not 1 <= max_requests <= MAX_LIVE_REQUESTS:
            raise ValueError(f"a live session sends 1-{MAX_LIVE_REQUESTS} requests")
        duration = timedelta(minutes=minutes)
        if not timedelta(0) < duration <= MAX_LIVE_DURATION:
            raise ValueError("a live session lasts 1-60 minutes")
        async with self.sessions() as session, session.begin():
            await session.execute(
                text(
                    "INSERT INTO siem_live_sessions (id, created_by, ends_at, max_requests)"
                    " VALUES (:id, :a, :e, :m)"
                ),
                {"id": session_id, "a": actor, "e": now + duration, "m": max_requests},
            )
            await record_audit(
                session,
                actor=actor,
                action="siem.live_session.start",
                target_type="live_session",
                target_id=session_id,
                details={"minutes": minutes, "max_requests": max_requests},
            )

    async def end_live_session(self, session_id: str, *, actor: str, now: datetime) -> bool:
        async with self.sessions() as session, session.begin():
            row = await session.execute(
                text(
                    "UPDATE siem_live_sessions SET ended_at = :now WHERE id = :id"
                    " AND ended_at IS NULL RETURNING used"
                ),
                {"id": session_id, "now": now},
            )
            used = row.scalar_one_or_none()
            await record_audit(
                session,
                actor=actor,
                action="siem.live_session.end",
                target_type="live_session",
                target_id=session_id,
                details={"used": used},
            )
            return used is not None


_PROBES_SINCE = (
    "SELECT at, state, reasons, probe_ok, auth_failed, disk_percent, heap_percent, load_1m,"
    " search_queue, search_rejected, breakers_tripped, blocked_indices FROM siem_probes"
    " WHERE at >= :since AND (CAST(:until AS timestamptz) IS NULL OR at < :until)"
    " ORDER BY at, id"
)
_LATEST_PROBE = (
    "SELECT at, state, reasons, probe_ok, auth_failed, disk_percent, heap_percent, load_1m,"
    " search_queue, search_rejected, breakers_tripped, blocked_indices FROM siem_probes"
    " ORDER BY at DESC, id DESC LIMIT 1"
)


def _probe(row: Any) -> ProbeRow:
    return ProbeRow(
        at=row.at,
        state=row.state,
        reasons=tuple(row.reasons or ()),
        probe_ok=row.probe_ok,
        auth_failed=row.auth_failed,
        disk_percent=row.disk_percent,
        heap_percent=row.heap_percent,
        load_1m=row.load_1m,
        search_queue=row.search_queue,
        search_rejected=row.search_rejected,
        breakers_tripped=row.breakers_tripped,
        blocked_indices=tuple(row.blocked_indices or ()),
    )


_MAX_COUNTER = (1 << 63) - 1  # every counter column of siem_probes is a bigint


def _gauge(value: float | None, high: float | None) -> float | None:
    """A reading as stored: finite, not negative, at most ``high``; else unknown (None). A
    malformed reading is never a reason for the probe to fail."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        number = float(value)
    except OverflowError:  # an int too large for a float
        return None
    if not math.isfinite(number) or number < 0 or (high is not None and number > high):
        return None
    return number


def _counter(value: int | None) -> int | None:
    if value is None or isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if 0 <= value <= _MAX_COUNTER else None


def probe_row(readings: Readings, memory: HealthMemory) -> dict[str, Any]:
    """The ``siem_probes`` row of one probe (its readings, its outcome)."""
    lag = {
        str(source)[:200]: round(delay.total_seconds(), 3)
        for source, delay in sorted(readings.ingest_lag.items())
        if math.isfinite(delay.total_seconds())
    }
    return {
        "at": readings.at,
        "state": str(memory.state),
        "reasons": [str(reason)[:200] for reason in memory.reasons],
        "probe_ok": readings.probe_ok,
        "auth_failed": readings.auth_failed,
        "disk": _gauge(readings.disk_percent, 100.0),
        "heap": _gauge(readings.heap_percent, 100.0),
        "load": _gauge(readings.load_1m, None),
        "queue": _counter(readings.search_queue),
        "rejected": _counter(readings.search_rejected),
        "tripped": _counter(readings.breakers_tripped),
        "write_rejected": _counter(readings.write_rejected),
        "blocked": [str(name)[:300] for name in readings.blocked_indices],
        "lag": _json(lag),
        "stale": _counter(readings.stale_rules),
    }


def _json(value: dict[str, Any]) -> str:
    return json.dumps(value, separators=(",", ":"))
