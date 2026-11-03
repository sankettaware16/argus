"""A scripted Kibana transport, real answers from Q-D1's cassettes, and a Kibana lane on a fake
clock (Q-D2 tests)."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from argus.gateway.budget import BudgetConfig
from argus.gateway.errors import TemplateRejectedError
from argus.gateway.gateway import Gateway, Targets
from argus.gateway.health import HealthMemory
from argus.gateway.kibana import models
from argus.gateway.kibana.gateway import KibanaGateway, KibanaTargets, WriteContext, WriteRun
from argus.gateway.kibana.templates import (
    AttachAlerts,
    AttachParams,
    CloseCase,
    CommentOnCase,
    CommentParams,
    CreateCase,
    KibanaTemplate,
    SetAlertStatus,
    UpdateCase,
)
from argus.gateway.kibana.transport import KResponse, KWire, wire_refusal
from argus.gateway.kibana.writes import WriteClass
from argus.gateway.state import MemoryStore
from tests.unit.gateway.fakes import FakeClock, FakeTransport, ok

T0 = datetime(2026, 10, 23, 10, 0, tzinfo=UTC)  # inside the write window (02:30-17:30 UTC)
CASSETTES = Path(__file__).resolve().parents[3] / "kibana" / "cassettes"
CASE_ID = "11111111-1111-4111-8111-111111111111"
ARGUS_CASE = "argus:case:00000000-0000-4000-8000-000000000001"  # the cassette's, stood in
ALERT_INDEX = ".internal.alerts-security.alerts-acme-soc-000001"
ALERT_ID = "a" * 64
PLACEHOLDER = re.compile(r"<(uuid|hex|version|time|run|took):?(\d*)>")


def _stand_in(match: re.Match[str]) -> str:
    kind, n = match[1], int(match[2] or 0)
    if kind == "uuid":
        return CASE_ID if n == 2 else f"00000000-0000-4000-8000-{n:012d}"
    if kind == "hex":
        return ALERT_ID if n == 1 else f"{n:064x}"
    if kind == "version":
        return f"WzEsMV0{n}"
    if kind == "time":
        return "2026-10-23T10:00:00.000Z"
    if kind == "run":
        return "run1"
    return "1"


def cassette(name: str) -> list[dict[str, Any]]:
    """A Q-D1 cassette's exchanges, placeholders replaced by stand-ins (the case of the write
    cassette is CASE_ID, its alert ALERT_ID)."""
    raw = (CASSETTES / f"{name}.json").read_text()
    exchanges: list[dict[str, Any]] = json.loads(PLACEHOLDER.sub(_stand_in, raw))["exchanges"]
    return exchanges


def answer(name: str, method: str, path_end: str, nth: int = 0) -> Any:
    """The ``nth`` recorded answer of ``method`` to a path ending in ``path_end``."""
    found = [
        e["answer"]
        for e in cassette(name)
        if e["method"] == method and e["path"].endswith(path_end)
    ]
    return found[nth]


WRITES = "write_templates__test_the_write_classes_whole"
READS = "read_templates__test_kibana_reads_whole"


def status_answer(version: str = "8.19.12", level: str = "available") -> dict[str, Any]:
    """``GET api/status`` as Kibana answers it (Q-D1's cassette keeps a reduced form)."""
    return {
        "name": "argus-kibana",
        "version": {"number": version, "build_flavor": "traditional"},
        "status": {"overall": {"level": level, "summary": "All services are available"}},
    }


KReply = KResponse | Exception | Callable[[KWire], KResponse]


def reply(body: Any, status: int = 200, elapsed_ms: float = 20.0) -> KResponse:
    return KResponse(status, json.dumps(body).encode(), elapsed_ms, "Fri, 23 Oct 2026 10:00:00 GMT")


@dataclass
class FakeKibana:
    """Answers by (method, path suffix), first match; else 404. Records every request."""

    routes: list[tuple[str, str, list[KReply]]] = field(default_factory=list)
    calls: list[KWire] = field(default_factory=list)
    clock: FakeClock | None = None
    latency: timedelta = timedelta(milliseconds=20)

    def on(self, method: str, path_end: str, *replies: KReply) -> FakeKibana:
        self.routes.append((method, path_end, list(replies)))
        return self

    def refusal(self, request: KWire) -> TemplateRejectedError | None:
        """The real transport's route allowlist (every key is installed here)."""
        why = wire_refusal(request, "acme-soc")
        return None if why is None else TemplateRejectedError("route_refused", why)

    async def send(self, request: KWire) -> KResponse:
        self.calls.append(request)
        if self.clock is not None:
            self.clock.advance(self.latency)
        for method, end, replies in self.routes:
            if request.method == method and request.path.endswith(end) and replies:
                item = replies.pop(0) if len(replies) > 1 else replies[0]
                if isinstance(item, Exception):
                    raise item
                if callable(item):
                    return item(request)
                return item
        return reply({"statusCode": 404, "error": "Not Found"}, 404)


def echo_create(request: KWire) -> KResponse:
    """The recorded create's answer with the title and tags of the request."""
    sent = json.loads(request.body or b"{}")
    case = answer(WRITES, "POST", "/api/cases")
    return reply({**case, "title": sent["title"], "tags": sent["tags"]})


def ready_kibana() -> FakeKibana:
    """Status, configuration and the real write answers of Q-D1's write cassette."""
    return (
        FakeKibana()
        .on("GET", "/api/status", reply(status_answer()))
        .on("GET", "/api/cases/configure", reply([]))
        .on("POST", "/api/cases", echo_create)
        .on("PATCH", "/api/cases", reply(answer(WRITES, "PATCH", "/api/cases", 0)))
    )


def licence_es() -> FakeTransport:
    return FakeTransport().on("/_license", ok({"license": {"type": "basic", "status": "active"}}))


def make(
    kibana: FakeKibana | None = None,
    *,
    classes: frozenset[WriteClass] = frozenset(),
    store: MemoryStore | None = None,
    es: FakeTransport | None = None,
) -> tuple[KibanaGateway, FakeKibana, MemoryStore, FakeClock, Gateway]:
    clock = FakeClock(T0)
    kibana = kibana or ready_kibana()
    kibana.clock = clock
    store = store or MemoryStore(memory=HealthMemory(probed_at=T0), budget_config=BudgetConfig())
    es = es or licence_es()
    es.clock = clock
    es_gateway = Gateway(es, store, targets=Targets(), clock=clock, sleep=clock.sleep)
    gateway = KibanaGateway(
        kibana,
        store,
        targets=KibanaTargets(),
        classes=classes,
        es_gateway=es_gateway,
        clock=clock,
        sleep=clock.sleep,
    )
    return gateway, kibana, store, clock, es_gateway


def create_params(title: str = "[ARGUS 7] C2 beacon from 1 campus host") -> models.CaseCreate:
    return models.CaseCreate(
        title=title,
        description="Contract test case ([ARGUS 7] C2 beacon from 1 campus host).",
        tags=("argus", ARGUS_CASE, "argus:owner:argus", "argus:state:open"),
        severity="low",
    )


def context(
    gateway: KibanaGateway,
    template: KibanaTemplate,
    params: Any,
    cls: WriteClass = WriteClass.W1,
    *,
    approval: str | None = None,
    outbox: str = "outbox-1",
) -> WriteContext:
    return WriteContext(cls, outbox, gateway.payload_hash(template, params), approval)


async def start(gateway: KibanaGateway, clock: FakeClock) -> WriteRun:
    return await gateway.start_run(component="test", deadline=clock.now + timedelta(seconds=60))


async def create(
    gateway: KibanaGateway, run: WriteRun, clock: FakeClock, params: models.CaseCreate | None = None
) -> Any:
    params = params or create_params()
    return await gateway.write(
        CreateCase(), params, run=run, context=context(gateway, CreateCase(), params),
        component="test", deadline=clock.now + timedelta(seconds=60),
    )  # fmt: skip


__all__ = [
    "AttachAlerts",
    "AttachParams",
    "CloseCase",
    "CommentOnCase",
    "CommentParams",
    "SetAlertStatus",
    "UpdateCase",
]
