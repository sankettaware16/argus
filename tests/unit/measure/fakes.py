"""A scripted the SIEM for the measuring session: probes, index listings, searches and mgets,
each answering with the server time it is told, on a fake clock."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from argus.config.settings import SiemSettings
from argus.gateway.gateway import Gateway, Targets
from argus.gateway.health import HealthMemory
from argus.gateway.service import probe
from argus.gateway.state import MemoryStore
from argus.gateway.transport import WireRequest, WireResponse
from argus.measure.session import (
    COMPONENT,
    LIMITS,
    CappedTransport,
    Limits,
    Plan,
    Session,
    Subjects,
    build_plan,
    cost_of,
)
from tests.unit.gateway.fakes import FakeClock

T0 = datetime(2026, 10, 23, 10, 0, tzinfo=UTC)  # 10:00 UTC: inside the hours a session may run
SETTINGS = SiemSettings()
HISTORY = timedelta(days=5)
BACKING = ".internal.alerts-security.alerts-acme-soc-000001"
SUBJECTS = Subjects(
    host="10.10.1.5",
    destination="203.0.113.9",
    client="198.51.100.7",
    mget=tuple((BACKING, tuple(f"id-{k}-{n}" for n in range(200))) for k in range(3)),
)
TOOK = {"light": 15, "medium": 60, "heavy": 650}


def node(
    *, load: float = 2.0, queue: int = 0, rejected: int = 7, tripped: int = 0, heap: int = 50
) -> dict[str, Any]:
    return {
        "_nodes": {"total": 1, "successful": 1, "failed": 0},
        "nodes": {
            "n": {
                "fs": {"total": {"total_in_bytes": 100, "available_in_bytes": 40}},
                "jvm": {"mem": {"heap_used_percent": heap}},
                "os": {"cpu": {"load_average": {"1m": load}}},
                "thread_pool": {
                    "search": {"queue": queue, "rejected": rejected},
                    "write": {"rejected": 3},
                },
                "breakers": {"parent": {"tripped": tripped}},
            }
        },
    }


def template_of(request: WireRequest) -> str:
    return request.opaque_id.split("/", 1)[-1].rsplit("@", 1)[0]


def _answer(body: Any, status: int = 200, elapsed: float = 5.0) -> WireResponse:
    return WireResponse(status, json.dumps(body).encode(), elapsed)


@dataclass
class FakeElastic:
    """Answers like the SIEM; ``nodes`` are the node-stats answers in turn (the last repeats);
    ``replies`` overrides a template's answer (a WireResponse, an exception or a function)."""

    clock: FakeClock
    nodes: list[dict[str, Any]] = field(default_factory=lambda: [node()])
    took: dict[str, int] = field(default_factory=dict)
    replies: dict[str, Any] = field(default_factory=dict)
    calls: list[WireRequest] = field(default_factory=list)
    at: list[datetime] = field(default_factory=list)

    async def send(self, request: WireRequest) -> WireResponse:
        self.calls.append(request)
        self.at.append(self.clock())
        name = template_of(request)
        if name in self.replies:
            reply = self.replies[name]
            if isinstance(reply, BaseException):
                raise reply
            if callable(reply):
                result: WireResponse = reply(request)
                return result
            assert isinstance(reply, WireResponse)
            return reply
        if name == "health.node_stats":
            body = self.nodes.pop(0) if len(self.nodes) > 1 else self.nodes[0]
            return _answer(body)
        if name == "health.index_blocks":
            return _answer({BACKING: {"settings": {"index.uuid": "u"}}})
        if name == "indices.listing":
            source = request.path.split("acme-logs-", 1)[1].split("-", 1)[0]
            prefix = f"acme-logs-{source}-"
            days = [(T0 - timedelta(days=n)).strftime("%Y.%m.%d") for n in range(5)]
            return _answer({"indices": [{"name": prefix + day} for day in days]})
        took = self.took.get(name, TOOK[cost_of(name).value])
        self.clock.advance(timedelta(milliseconds=took + 5))
        if request.path.endswith("/_mget"):
            ids = json.loads(request.body or b"{}").get("ids", [])
            return _answer({"docs": [{"_id": i, "found": True} for i in ids]}, elapsed=took)
        body = {
            "took": took,
            "timed_out": False,
            "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
            "hits": {"hits": []},
        }
        return _answer(body)


def plan_at(now: datetime = T0, subjects: Subjects = SUBJECTS, **kw: Any) -> Plan:
    options: dict[str, Any] = {"log_queries": True, "proxy_aggregations": True, **kw}
    return build_plan(subjects, now, history=HISTORY, **options)


@dataclass
class Rig:
    session: Session
    elastic: FakeElastic
    store: MemoryStore
    clock: FakeClock
    counter: CappedTransport
    gateway: Gateway


def rig(
    *,
    plan: Plan | None = None,
    store: MemoryStore | None = None,
    elastic: FakeElastic | None = None,
    limits: Limits = LIMITS,
    clock: FakeClock | None = None,
    inner: Callable[[FakeElastic], Any] | None = None,
) -> Rig:
    clock = clock or FakeClock(T0)
    elastic = elastic or FakeElastic(clock)
    store = store or MemoryStore(memory=HealthMemory(probed_at=clock()))
    counter = CappedTransport(inner(elastic) if inner else elastic, clock, limits)
    gateway = Gateway(counter, store, targets=Targets(), clock=clock, sleep=clock.sleep,
                      listing_component=COMPONENT)  # fmt: skip

    async def probe_once() -> HealthMemory:
        return await probe(gateway, store, SETTINGS, clock(), component=COMPONENT)

    session = Session(gateway, store, plan or plan_at(clock()), counter=counter,
                      probe=probe_once, limits=limits, clock=clock, sleep=clock.sleep)  # fmt: skip
    return Rig(session, elastic, store, clock, counter, gateway)
