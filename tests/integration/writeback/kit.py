"""The write-back's test rig (Q-D5): Postgres as the writer's own login, a fake Kibana and
Elasticsearch for alert status behind the real Kibana lane (budgets, health, switches, breaker,
caps, the checks of the answer) and the real Elasticsearch gateway.

The fake keeps each alert's workflow status. ``POST signals/status`` answers with the
update_by_query body the recorded cassette shows (tests/kibana/cassettes/alert_writes__*);
``_mget`` answers whole alerts. Faults, per status request: ``status`` (Kibana answers an
error; ``apply`` alerts were changed first), ``lose`` (no connection: Kibana did nothing),
``timeout`` (no answer; Kibana applies it at once, after ``land_after`` seconds by its own
clock, or never), ``body`` (a 200 whose fields differ from a clean report; ``apply`` alerts were
changed), ``garbage`` (applied, answered with something that is not JSON).
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from email.utils import format_datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.gateway.budget import BudgetConfig
from argus.gateway.errors import TemplateRejectedError, TransportFailedError
from argus.gateway.gateway import Gateway, Targets
from argus.gateway.health import HealthMemory
from argus.gateway.kibana import selftest
from argus.gateway.kibana.errors import UnknownOutcomeError
from argus.gateway.kibana.gateway import KibanaGateway, KibanaTargets
from argus.gateway.kibana.transport import KResponse, KWire, wire_refusal
from argus.gateway.kibana.writes import WriteCaps, WriteClass
from argus.gateway.lanes import LanePlan
from argus.gateway.state import MemoryStore
from argus.gateway.transport import WireRequest, WireResponse
from argus.writeback_sender import AlertSender, Operator, RunResult
from tests.unit.kibana_sync.fake import INDEX, SPACE, T0, Clock

API = f"/s/{SPACE}/api"
STATUS_ROUTE = f"{API}/detection_engine/signals/status"


def report(total: int, updated: int, over: dict[str, Any] | None = None) -> dict[str, Any]:
    """The update_by_query body of the recorded cassette, with fields replaced by ``over``."""
    return {
        "took": 3, "timed_out": False, "total": total, "updated": updated, "deleted": 0,
        "batches": 1, "version_conflicts": 0, "noops": 0, "retries": {"bulk": 0, "search": 0},
        "throttled_millis": 0, "requests_per_second": -1, "throttled_until_millis": 0,
        "failures": [], **(over or {}),
    }  # fmt: skip


@dataclass
class Fault:
    kind: str  # status, lose, timeout, body, garbage
    when: Callable[[Sequence[str]], bool] = lambda ids: True
    status: int = 500
    apply: int = 0
    land_after: float | None = 0.0
    body: dict[str, Any] = field(default_factory=dict)
    times: int = 1


@dataclass
class World:
    clock: Clock
    statuses: dict[str, str] = field(default_factory=dict)
    faults: list[Fault] = field(default_factory=list)
    calls: list[tuple[tuple[str, ...], str]] = field(default_factory=list)  # reached Kibana
    applied: list[tuple[tuple[str, ...], str]] = field(default_factory=list)
    call_times: list[datetime] = field(default_factory=list)
    landing: list[tuple[datetime, tuple[str, ...], str]] = field(default_factory=list)
    mgets: list[tuple[str, tuple[str, ...]]] = field(default_factory=list)
    gone: set[str] = field(default_factory=set)
    transitions: dict[str, int] = field(default_factory=dict)  # alert -> times its status moved
    down: bool = False
    es_down: bool = False
    extra_privileges: set[str] = field(default_factory=set)

    def seed(self, ids: Sequence[str], status: str = "open") -> None:
        for alert_id in ids:
            self.statuses.setdefault(alert_id, status)

    def tick(self) -> None:
        """Requests still on their way when ARGUS gave up reach Kibana now."""
        for item in [i for i in self.landing if i[0] <= self.clock.now]:
            self.landing.remove(item)
            self.change(item[1], item[2])

    def change(self, ids: Sequence[str], status: str) -> int:
        changed = 0
        for alert_id in ids:
            if alert_id in self.statuses and alert_id not in self.gone:
                if self.statuses[alert_id] != status:
                    self.transitions[alert_id] = self.transitions.get(alert_id, 0) + 1
                self.statuses[alert_id] = status
                changed += 1
        if changed:
            self.applied.append((tuple(ids), status))
        return changed

    def take(self, ids: Sequence[str]) -> Fault | None:
        for fault in self.faults:
            if fault.when(ids):
                fault.times -= 1
                if fault.times <= 0:
                    self.faults.remove(fault)
                return fault
        return None

    def written(self) -> list[str]:
        """Every alert of every status change Kibana applied, in order."""
        return [a for ids, _ in self.applied for a in ids]


@dataclass
class Kibana:
    world: World

    def refusal(self, request: KWire) -> TemplateRejectedError | None:
        why = wire_refusal(request, SPACE)
        return None if why is None else TemplateRejectedError("route_refused", why)

    def _answer(self, status: int, body: Any, raw: bytes | None = None) -> KResponse:
        date = format_datetime(self.world.clock.now, usegmt=True)
        return KResponse(status, raw or json.dumps(body).encode(), 20.0, date)

    async def send(self, request: KWire) -> KResponse:
        w = self.world
        w.tick()
        if w.down:
            raise UnknownOutcomeError("connection refused", reached=False)
        if request.target == "es":
            return self._answer(200, self._privileges(json.loads(request.body or b"{}")))
        if request.method == "GET" and request.path == f"{API}/status":
            return self._answer(
                200,
                {
                    "name": "kibana",
                    "version": {"number": "8.19.12"},
                    "status": {"overall": {"level": "available"}},
                },
            )
        if request.method == "GET" and request.path == f"{API}/cases/configure":
            return self._answer(200, [])
        assert request.method == "POST", request.path
        assert request.path == STATUS_ROUTE, request.path
        sent = json.loads(request.body or b"{}")
        assert set(sent) == {"signal_ids", "status"}, "ids only, never a query"
        ids, status = tuple(sent["signal_ids"]), str(sent["status"])
        w.calls.append((ids, status))
        w.call_times.append(w.clock.now)
        fault = w.take(ids)
        if fault is not None:
            if fault.kind == "lose":
                raise UnknownOutcomeError("connection reset", reached=False)
            if fault.kind == "status":
                w.change(ids[: fault.apply], status)
                return self._answer(fault.status, {"statusCode": fault.status})
            if fault.kind == "timeout":
                if fault.land_after is not None and fault.land_after <= 0:
                    w.change(ids, status)
                elif fault.land_after is not None:
                    w.landing.append(
                        (w.clock.now + timedelta(seconds=fault.land_after), ids, status)
                    )
                raise UnknownOutcomeError("timed out", reached=True, timed_out=True)
            if fault.kind == "garbage":
                w.change(ids, status)
                return self._answer(200, None, raw=b"<html>")
            if fault.kind == "body":
                changed = w.change(ids[: fault.apply], status)
                return self._answer(200, report(len(ids), changed, fault.body))
        total = sum(1 for a in ids if a in w.statuses and a not in w.gone)
        return self._answer(200, report(total, w.change(ids, status)))

    def _privileges(self, body: dict[str, Any]) -> dict[str, Any]:
        """``_has_privileges`` for the alert writer: what its profile needs, plus ``extra``."""
        held = set(selftest.ALERT_WRITER_NEEDS) | self.world.extra_privileges
        answer: dict[str, Any] = {
            "has_all_requested": False,
            "cluster": dict.fromkeys(body.get("cluster", []), False),
            "application": {
                selftest.APP: {
                    body["application"][0]["resources"][0]: dict.fromkeys(
                        body["application"][0]["privileges"], False
                    )
                }
            },
        }
        if "index" in body:
            entry = body["index"][0]
            answer["index"] = {
                entry["names"][0]: {p: p in held for p in entry["privileges"]},
            }
        return answer


@dataclass
class Es:
    world: World

    async def send(self, request: WireRequest) -> WireResponse:
        w = self.world
        w.tick()
        if w.es_down:
            raise TransportFailedError("connection refused", retriable=False, reached=False)
        if request.path.endswith("/_license"):
            body = {"license": {"type": "basic", "status": "active"}}
            return WireResponse(200, json.dumps(body).encode(), 3.0)
        assert request.path.endswith("/_mget"), request.path
        index = request.path.split("/")[1]
        ids = tuple(json.loads(request.body or b"{}")["ids"])
        w.mgets.append((index, ids))
        docs = []
        for alert_id in ids:
            if alert_id in w.statuses and alert_id not in w.gone:
                source = {"kibana.alert.workflow_status": w.statuses[alert_id], "x": 1}
                docs.append(
                    {"_index": index, "_id": alert_id, "_version": 1, "found": True,
                     "_source": source}
                )  # fmt: skip
            else:
                docs.append({"_index": index, "_id": alert_id, "found": False})
        return WireResponse(200, json.dumps({"docs": docs}).encode(), 4.0)


@dataclass
class Rig:
    engine: AsyncEngine  # the writer's login
    owner: AsyncEngine
    clock: Clock
    world: World
    lane: MemoryStore
    gateway: KibanaGateway
    es: Gateway

    def healthy(self) -> None:
        self.lane.memory = HealthMemory(probed_at=self.clock.now + timedelta(hours=2))

    def sender(self, **kw: Any) -> AlertSender:
        kw.setdefault("clock", self.clock)
        kw.setdefault("sleep", self.clock.sleep)
        return AlertSender(self.engine, self.gateway, es=self.es, **kw)

    async def run(self, **kw: Any) -> RunResult:
        self.healthy()
        return await self.sender(**kw).run()

    async def seed_world(self) -> list[str]:
        """Every alert in ARGUS's records exists in the fake, open."""
        async with self.owner.connect() as conn:
            ids = list(
                (await conn.execute(text("SELECT alert_id FROM alert_records ORDER BY 1")))
                .scalars()
                .all()
            )
        self.world.seed(ids)
        return ids

    async def sql(self, query: str, **params: Any) -> list[Any]:
        async with self.owner.connect() as conn:
            return list((await conn.execute(text(query), params)).all())

    async def row(self, n: int = 0) -> Any:
        return (await self.sql("SELECT * FROM writeback_outbox ORDER BY id"))[n]


def rig(
    owner: AsyncEngine,
    engine: AsyncEngine,
    *,
    classes: frozenset[WriteClass] = frozenset({WriteClass.WA}),
    caps: WriteCaps | None = None,
) -> Rig:
    clock = Clock(T0)
    world = World(clock)
    lane = MemoryStore(
        memory=HealthMemory(probed_at=T0), budget_config=BudgetConfig(), lane_plan=LanePlan()
    )
    es = Gateway(Es(world), lane, targets=Targets(), clock=clock, sleep=clock.sleep)
    gateway = KibanaGateway(
        Kibana(world), lane, targets=KibanaTargets(space=SPACE), caps=caps, classes=classes,
        es_gateway=es, clock=clock, sleep=clock.sleep,
    )  # fmt: skip
    r = Rig(engine, owner, clock, world, lane, gateway, es)
    r.healthy()
    return r


def operator(clock: Clock, name: str = "ravi") -> Operator:
    return Operator(name, f"uid-{name}", clock.now)


__all__ = ["INDEX", "SPACE", "Fault", "Operator", "Rig", "World", "operator", "report", "rig"]
