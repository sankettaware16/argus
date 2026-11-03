"""Recorded shapes of three Elastics for the tests of `argus discover` (P4-D1): one with daily
indices (ACME's kind), one with data streams (a fresh Elastic Agent kind), an empty one. The
answers have the shape of Elasticsearch 8.19's `_resolve/index`, `_mapping/field`, `_license`,
`_ilm/policy` and `_has_privileges`, and of Kibana's status, spaces and features."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from argus.gateway.gateway import Gateway, Targets
from argus.gateway.health import HealthMemory
from argus.gateway.kibana.gateway import KibanaGateway, KibanaTargets
from argus.gateway.kibana.transport import KWire, wire_refusal
from argus.gateway.state import DiscoveryStore, MemoryStore
from argus.gateway.templates import REGISTRY  # noqa: F401  (the discovery templates register)
from tests.unit.gateway.fakes import T0, FakeClock, FakeTransport, ok
from tests.unit.gateway.kibana.fakes import FakeKibana, reply, status_answer

DAYS = ("2026.10.28", "2026.10.29", "2026.10.30")


def mapped(fields: dict[str, tuple[str, bool]], index: str) -> dict[str, Any]:
    """``GET <index>/_mapping/field/...`` as Elasticsearch answers (after the gateway's
    filter_path): a ``text`` field has a ``keyword`` sub-field when the flag is set."""
    out: dict[str, Any] = {}
    for full_name, (kind, keyword) in fields.items():
        leaf: dict[str, Any] = {"type": kind}
        if keyword:
            leaf["fields"] = {"keyword": {"type": "keyword", "ignore_above": 256}}
        out[full_name] = {"mapping": {full_name.rsplit(".", 1)[-1]: leaf}}
    return {index: {"mappings": out}}


SQUID = {
    "@timestamp": ("date", False), "source.ip": ("ip", False), "destination.ip": ("ip", False),
    "destination.bytes": ("long", False), "url.original": ("text", True),
    "http.request.method": ("text", True), "http.response.status_code": ("integer", False),
    "event.action": ("text", True), "event.ingested": ("date", False),
}  # fmt: skip
NGINX = {
    "@timestamp": ("date", False), "source.ip": ("ip", False), "url.domain": ("text", True),
    "url.path": ("keyword", False), "http.request.method": ("text", True),
    "http.response.status_code": ("integer", False), "http.response.body.bytes": ("long", False),
    "user_agent.original": ("text", True),
}  # fmt: skip
DNS = {
    "@timestamp": ("date", False), "source.ip": ("ip", False), "client.ip": ("ip", False),
    "dns.question.name": ("text", True), "dns.question.type": ("text", True),
    "dns.response_code": ("text", True),
}  # fmt: skip
SSO = {
    "@timestamp": ("date", False), "source.ip": ("ip", False), "user.name": ("text", True),
    "event.outcome": ("text", True), "event.action": ("text", True),
    "user_agent.original": ("text", True),
}  # fmt: skip
ECS_NGINX = {k: ("keyword", False) if v[0] == "text" else v for k, v in NGINX.items()}
ECS_AUTH = {k: ("keyword", False) if v[0] == "text" else v for k, v in SSO.items()}
EMPTY_LISTING: dict[str, Any] = {"indices": [], "aliases": [], "data_streams": []}


def daily(prefix: str, days: tuple[str, ...] = DAYS) -> list[dict[str, str]]:
    return [{"name": f"{prefix}{day}"} for day in days]


def daily_listing() -> dict[str, Any]:
    """ACME's kind: daily indices by product, and some that are no log family."""
    return {
        "indices": [
            *daily("acme-logs-squid-"),
            *daily("acme-logs-nginx-"),
            *daily("acme-logs-dns-"),
            *daily("acme-logs-postfix-"),
            *daily("acme-logs-sso-"),
            *daily("acme-metrics-"),
            {"name": "acme-threat-intel"},
        ],
        "aliases": [],
        "data_streams": [],
    }


def stream_listing() -> dict[str, Any]:
    """A fresh Elastic Agent install: data streams, backing indices named by day and number."""

    def stream(name: str) -> dict[str, Any]:
        return {
            "name": name,
            "timestamp_field": "@timestamp",
            "backing_indices": [f".ds-{name}-{DAYS[0]}-000001", f".ds-{name}-{DAYS[-1]}-000002"],
        }

    return {
        "indices": [],
        "aliases": [],
        "data_streams": [
            stream("logs-nginx.access-default"),
            stream("logs-system.auth-default"),
            stream("metrics-system.cpu-default"),
            stream("logs-elastic_agent.filebeat-default"),
        ],
    }


def alerts_listing(*spaces: str) -> dict[str, Any]:
    return {"aliases": [{"name": f".alerts-security.alerts-{s}", "indices": []} for s in spaces]}


def elastic(
    listing: dict[str, Any],
    mappings: dict[str, dict[str, tuple[str, bool]]],
    *,
    spaces: tuple[str, ...] = ("default",),
    version: str = "8.19.12",
    licence: str = "basic",
    read_ilm: bool = False,
    ilm: dict[str, Any] | None = None,
) -> FakeTransport:
    """Answers by path (first match): ``mappings`` by a part of the index name."""
    transport = FakeTransport()
    for part, fields in mappings.items():
        transport.on(f"{part}", ok(mapped(fields, part)))
    # the mapping routes name indices; the order of the others matters (the root last)
    transport.on("/_resolve/index/.alerts-security", ok(alerts_listing(*spaces)))
    transport.on("/_resolve/index/*", ok(listing))
    transport.on("/_license", ok({"license": {"type": licence, "status": "active"}}))
    transport.on(
        "/_security/user/_has_privileges", ok({"cluster": {"monitor": True, "read_ilm": read_ilm}})
    )
    transport.on("/_ilm/policy", ok(ilm or {}))
    transport.on("/", ok({"version": {"number": version}}))  # GET /
    return transport


class KibanaOf(FakeKibana):
    """The fake Kibana for the sites of these tests: its route allowlist is for ``space``."""

    space = "default"

    def refusal(self, request: KWire) -> Any:
        from argus.gateway.errors import TemplateRejectedError

        why = wire_refusal(request, self.space)
        return None if why is None else TemplateRejectedError("route_refused", why)


def kibana(
    spaces: tuple[str, ...] = ("default",), version: str = "8.19.12", space: str = "default"
) -> KibanaOf:
    server = KibanaOf()
    server.space = space
    server.on("GET", "/api/status", reply(status_answer(version)))
    server.on(
        "GET",
        "/api/spaces/space",
        reply([{"id": s, "name": s.title(), "disabledFeatures": []} for s in spaces]),
    )
    server.on(
        "GET",
        "/api/features",
        reply(
            [
                {"id": "discover", "name": "Discover", "app": ["discover"]},
                {"id": "siemV2", "name": "Security", "app": ["siem"]},
                {"id": "securitySolutionCasesV3", "name": "Cases", "app": ["securitySolution"]},
            ]
        ),
    )
    return server


def gateways(
    transport: FakeTransport, server: FakeKibana | None, store: MemoryStore | None = None
) -> tuple[Gateway, KibanaGateway | None, MemoryStore, FakeClock]:
    clock = FakeClock(T0)
    transport.clock = clock
    store = store or MemoryStore(memory=HealthMemory(probed_at=T0))
    es = Gateway(transport, store, targets=Targets(), clock=clock, sleep=clock.sleep)
    if server is None:
        return es, None, store, clock
    server.clock = clock
    server.latency = timedelta(milliseconds=20)
    lane = KibanaGateway(
        server, store, targets=KibanaTargets(space=getattr(server, "space", "default")),
        es_gateway=es, clock=clock, sleep=clock.sleep,
    )  # fmt: skip
    return es, lane, store, clock


def discovery_gateways(
    transport: FakeTransport, server: FakeKibana | None, store: MemoryStore | None = None
) -> tuple[Gateway, KibanaGateway | None, DiscoveryStore, MemoryStore, FakeClock]:
    """The gateways as ``argus discover`` builds them: on a ``DiscoveryStore`` over the real
    (here in-memory) store, which is also returned to see what was and was not remembered."""
    real = store or MemoryStore(memory=HealthMemory(probed_at=T0))
    shadow = DiscoveryStore(real)
    es, lane, _, clock = gateways(transport, server, shadow)  # type: ignore[arg-type]
    return es, lane, shadow, real, clock


NODE_STATS: dict[str, Any] = {
    "_nodes": {"failed": 0},
    "nodes": {
        "n": {
            "fs": {"total": {"total_in_bytes": 100, "available_in_bytes": 90}},
            "jvm": {"mem": {"heap_used_percent": 10}},
            "os": {"cpu": {"load_average": {"1m": 0.1}}},
            "thread_pool": {"search": {"queue": 0, "rejected": 0}, "write": {"rejected": 0}},
            "breakers": {"request": {"tripped": 0}},
        }
    },
}
