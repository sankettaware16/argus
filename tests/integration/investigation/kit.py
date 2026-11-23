"""Test kit for the wave on Postgres: investigations with a dossier as the generic pack stores
it, the decision engine's "no decision", and a fake gateway that answers the wave's templates
and records how each request was sent (purpose, component)."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.context import batch1
from argus.context.packs import default_registry
from argus.gateway.gateway import Result
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.state import MemoryStore
from argus.gateway.templates import Params, Purpose, Template
from argus.investigation import catalogue
from argus.investigation.plan import Caps
from argus.investigation.wave import Env
from tests.unit.investigation.kit import FIRST, LAST, NOW, SQUID, body, unknown

__all__ = ["NOW", "SQUID", "FakeGateway", "body", "env", "seed", "unknown"]

ON = catalogue.Switches(
    templates=frozenset(batch1.TEMPLATES), proxy_aggregations=True, log_queries=True, ti_sync=True
)


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


async def seed(
    owner: AsyncEngine,
    dossier: Mapping[str, Any],
    *,
    rule_type: str | None = "query",
    severity: str = "medium",
    decided: bool = False,
    pack: str = "generic@12",
    created: datetime | None = None,
) -> uuid.UUID:
    """An investigation with this dossier body (and the decision engine's "no decision" on it
    unless ``decided``), at version 1."""
    inv = uuid.uuid4()
    rule = f"rule-{inv.hex[:8]}"
    body_ = {**dossier, "investigation_id": str(inv), "version": 1, "facts_version": 1,
             "family": "generic", "pack": pack}  # fmt: skip
    body_["facts"] = {**body_["facts"], "investigation_id": str(inv), "rule_id": rule}
    async with owner.begin() as conn:
        if rule_type is not None:
            await conn.execute(
                text(
                    "INSERT INTO rules (rule_id, type, alerts, execution_status, refreshed_at)"
                    " VALUES (:r, :t, 1, 'ok', now())"
                ),
                {"r": rule, "t": rule_type},
            )
        await conn.execute(
            text(
                "INSERT INTO investigations (id, grouping_version, rule_id, group_key,"
                " bucket_start, bucket_end, previous_id, first_event_at, last_event_at, severity,"
                " alert_count, version) VALUES (:id, 'g1', :r, :k, :s, :e, :id, :f, :l, :sev, 4, 1)"
            ),
            {"id": inv, "r": rule, "k": str(inv), "s": FIRST - timedelta(hours=1),
             "e": LAST + timedelta(hours=20), "f": FIRST, "l": LAST, "sev": severity},
        )  # fmt: skip
        h = digest(body_)
        await conn.execute(
            text(
                "INSERT INTO dossiers (investigation_id, version, facts_version, job_id, run_kind,"
                " family, pack, status, dossier_hash, body, evidence_count, created_at)"
                " VALUES (:i, 1, 1, 1, 'collect', 'generic', :p, 'evidence_ready', :h,"
                " CAST(:b AS jsonb), 0, :c)"
            ),
            {"i": inv, "p": pack, "h": h, "b": json.dumps(body_), "c": created or NOW},
        )
        if not decided:
            await conn.execute(
                text(
                    "INSERT INTO assessments (investigation_id, version, pack, dossier_hash,"
                    " view_hash, assessor, status, run_after, finished_at)"
                    " VALUES (:i, 1, :p, :h, :v, 'engine@1', 'no_decision', :n, :n)"
                ),
                {"i": inv, "p": pack, "h": h, "v": digest(["view", h]), "n": NOW},
            )
    return inv


def beats(window_start: datetime, minutes: Sequence[int]) -> dict[str, Any]:
    base = int(window_start.timestamp() * 1000)
    return {"beats": {"buckets": [{"key": base + m * 60_000, "doc_count": 1} for m in minutes]},
            "requests": {"value": len(minutes)},
            "first": {"value": base + minutes[0] * 60_000},
            "last": {"value": base + minutes[-1] * 60_000 + 7_000}}  # fmt: skip


def answer(aggs: Mapping[str, Any] | None = None, rows: int = 0) -> dict[str, Any]:
    hits = [{"_index": "i", "_id": str(n), "_source": {}} for n in range(rows)]
    return {"took": 7, "timed_out": False,
            "hits": {"total": {"value": rows or (3 if aggs else 0), "relation": "eq"},
                     "hits": hits},
            **({} if aggs is None else {"aggregations": dict(aggs)})}  # fmt: skip


def typical(template: Template, params: Params) -> dict[str, Any]:
    name = type(template).name
    if name == "proxy.pair":
        start = getattr(params, "start")  # noqa: B009
        return answer(beats(start, [0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 65]))
    if name == "proxy.host":
        return answer({"destination_count": {"value": 3}, "bytes": {"value": 10},
                       "timeline": {"buckets": [{"doc_count": 1}, {"doc_count": 0},
                                                {"doc_count": 1}]}})  # fmt: skip
    if name == "proxy.destination":
        return answer({"host_count": {"value": 4}, "hosts": {"buckets": []},
                       "urls": {"buckets": []}})  # fmt: skip
    if name == "web.followups":
        return answer(None, rows=2)
    return answer({"requests": {"value": 3}})


@dataclass
class FakeGateway:
    """The gateway as the wave sees it: ``run`` answers by template and records the call."""

    state: MemoryStore
    answers: Callable[[Template, Params], dict[str, Any]] = typical
    fail: dict[str, Exception] = field(default_factory=dict)  # by template name
    calls: list[tuple[str, Purpose, str]] = field(default_factory=list)
    now: datetime = NOW
    took: int = 7

    def clock(self) -> datetime:
        return self.now

    async def run(
        self, template: Template, params: Params, *, purpose: Purpose, component: str,
        deadline: datetime, check: Any = None, request_timeout: Any = None,
    ) -> Result:  # fmt: skip
        name = type(template).name
        self.calls.append((name, purpose, component))
        if check is not None:
            await check(self.now)
        if name in self.fail:
            raise self.fail[name]
        return Result(self.answers(template, params), self.took, ("index",))


def healthy(state: HealthState = HealthState.NORMAL, at: datetime = NOW) -> MemoryStore:
    return MemoryStore(memory=HealthMemory(state=state, probed_at=at))


def env(
    engine: AsyncEngine,
    gateway: FakeGateway | None = None,
    *,
    switches: catalogue.Switches = ON,
    caps: Caps | None = None,
    state: MemoryStore | None = None,
    per_day: int = 120,
    now: datetime = NOW,
) -> Env:
    held = gateway.state if gateway is not None else (state or healthy())
    if gateway is not None:
        gateway.now = now
    return Env(
        engine=engine, state=held, gateway=gateway,  # type: ignore[arg-type]
        packs=default_registry(), switches=switches, is_own=batch1.private_or(None),
        caps=caps or Caps(), per_day=per_day, clock=lambda: now,
    )  # fmt: skip
