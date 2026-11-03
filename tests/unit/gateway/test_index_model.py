"""The index model of the gateway over the site profile (P4-D1): daily indices unchanged, data
streams named as they are, the field names of the templates from the family, the health probe
and the self-test from the site (D-238)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest

from argus import site
from argus.config.settings import SiemSettings
from argus.context import proxy
from argus.context.dns import DnsHostDomains, DomainsParams
from argus.context.paths import PathParams, WebPathOutcomes
from argus.context.proxy import ProxyDestination, ProxyHost, WindowParams
from argus.gateway.errors import DeferredError, TemplateRejectedError
from argus.gateway.gateway import Gateway, Targets
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.service import probe, selftest, targets
from argus.gateway.state import MemoryStore
from argus.gateway.templates import Purpose
from argus.gateway.validator import validate
from argus.site import LogFamily, Role, SiteSettings
from tests.unit.gateway.fakes import (
    T0,
    FakeClock,
    FakeTransport,
    listing,
    make,
    ok,
    search_answer,
)

pytestmark = pytest.mark.unit

START, END = T0.replace(hour=9), T0.replace(hour=10)
DEADLINE = T0 + timedelta(minutes=5)

STREAMS = SiteSettings(
    families=(
        LogFamily(role=Role.PROXY, pattern="logs-zscaler.nss-default"),
        LogFamily(role=Role.WEB, pattern="logs-nginx.access-default", watch=False),
        LogFamily(role=Role.DNS, pattern="dns-logs-*"),
    )
)


def search_calls(transport: FakeTransport) -> list[Any]:
    return [c for c in transport.calls if c.path.endswith("/_search")]


async def run_proxy(site_profile: SiteSettings, **kw: Any) -> FakeTransport:
    with site.using(site_profile):
        gateway, transport, _, _ = make(**kw)
        await gateway.run(
            ProxyHost(),
            WindowParams(ip="10.1.2.3", start=START, end=END),
            purpose=Purpose.INVESTIGATE,
            component="t",
            deadline=DEADLINE,
        )
    return transport


# --------------------------------------------------------------------------- data streams


async def test_a_data_stream_family_is_named_as_it_is_and_never_listed() -> None:
    transport = await run_proxy(STREAMS)
    assert [c.path for c in transport.calls] == ["/logs-zscaler.nss-default/_search"]


async def test_a_daily_family_is_listed_and_its_day_named() -> None:
    transport = FakeTransport().on("_resolve", ok(listing("dns-logs-2026.10.09")))
    with site.using(STREAMS):
        gateway, transport, _, _ = make(transport)
        await gateway.run(
            DnsHostDomains(),
            DomainsParams(ip="10.1.2.3", start=START, end=END),
            purpose=Purpose.INVESTIGATE,
            component="t",
            deadline=DEADLINE,
        )
    assert next(c.path for c in transport.calls).startswith("/_resolve/index/dns-logs-")
    assert [c.path for c in search_calls(transport)] == ["/dns-logs-2026.10.09/_search"]


async def test_a_missing_stream_is_elasticsearchs_404_not_a_silent_skip() -> None:
    from argus.gateway.errors import SourceMissingError
    from argus.gateway.transport import WireResponse

    missing = WireResponse(
        404, b'{"error": {"type": "index_not_found_exception", "root_cause": []}}', 3.0
    )
    transport = FakeTransport().on("_search", missing)
    with site.using(STREAMS):
        gateway, *_ = make(transport)
        with pytest.raises(SourceMissingError):
            await gateway.run(
                ProxyHost(),
                WindowParams(ip="10.1.2.3", start=START, end=END),
                purpose=Purpose.INVESTIGATE,
                component="t",
                deadline=DEADLINE,
            )


def test_targets_know_the_site_and_refuse_what_it_does_not_have() -> None:
    with site.using(STREAMS):
        t = Targets()
        assert t.alerts == ".alerts-security.alerts-default"
        assert t.log_sources == {"proxy", "dns"}  # the web family is read, not watched
        assert t.family("proxy").pattern == "logs-zscaler.nss-default"
        for source in ("web", "squid"):
            with pytest.raises(TemplateRejectedError, match="not a log source"):
                t.family(source)
        with pytest.raises(TemplateRejectedError, match="data stream"):
            t.log_index_prefix("proxy")
        assert t.log_index_prefix("dns") == "dns-logs-"
        assert t.is_log_index("dns-logs-2026.10.09")
        assert t.is_log_index("logs-zscaler.nss-default")
        assert t.is_log_index(".ds-logs-zscaler.nss-default-2026.10.09-000001")
        assert not t.is_log_index("logs-nginx.access-default")  # not allowed on this Targets
        assert not t.is_log_index("something-else")
        service = targets(SiemSettings())  # the gateway's own build allows every family
        assert service.log_sources == {"proxy", "web", "dns"}
        assert service.is_log_index("logs-nginx.access-default")


def test_acmes_targets_are_what_they_were() -> None:
    t = Targets()
    assert t.alerts == ".alerts-security.alerts-acme-soc"
    assert t.alerts_backing == ".internal.alerts-security.alerts-acme-soc-"
    assert t.log_sources == {"squid", "dns", "nginx", "postfix"}
    assert targets(SiemSettings()).log_sources == {"squid", "dns", "nginx", "postfix", "sso"}
    assert t.log_index_prefix("squid") == "acme-logs-squid-"
    assert Targets(log_sources=frozenset({"sso"})).family("sso").pattern == "acme-logs-sso-*"
    assert t.ti == {"abuse-ioc", "acme-threat-intel"}


# --------------------------------------------------------------------------- field names


async def test_the_body_uses_the_familys_field_names() -> None:
    fields = {"action": "event.action.keyword", "url": "url.original.keyword"}
    custom = SiteSettings(
        families=(
            LogFamily(
                role=Role.PROXY,
                pattern="px-*",
                time_field="event.created",
                fields={**fields, "client_ip": "client.ip", "server_ip": "server.ip"},
            ),
        )
    )
    transport = FakeTransport().on("_resolve", ok(listing("px-2026.10.09")))
    transport.on("_search", ok(search_answer()))
    with site.using(custom):
        gateway, transport, _, _ = make(transport)
        await gateway.run(
            ProxyHost(), WindowParams(ip="10.1.2.3", start=START, end=END),
            purpose=Purpose.INVESTIGATE, component="t", deadline=DEADLINE,
        )  # fmt: skip
        (call,) = search_calls(transport)
        body = call.body.decode()
        assert '"client.ip":"10.1.2.3"' in body
        assert '"event.created"' in body
        assert '"@timestamp"' not in body
        assert '"server.ip"' in body
        assert '"destination.ip"' not in body
        assert '"event.action.keyword"' in body
        spec = ProxyHost.spec()
        assert spec.filter_fields == {"client.ip", "event.created"}
        assert "event.action.keyword" in spec.aggregate_fields
        assert "destination.bytes" in spec.aggregate_fields  # the default ECS name stays


def test_the_same_template_has_acmes_names_on_acmes_site_and_ecs_names_on_neutral_ones() -> None:
    acme = ProxyHost().plan(WindowParams(ip="10.0.0.1", start=START, end=END))
    assert "event.action.keyword" in repr(acme.body)
    assert acme.window is not None
    assert acme.window.source == "squid"
    plain = SiteSettings(families=(LogFamily(role=Role.PROXY, pattern="p-*"),))
    with site.using(plain):
        neutral = ProxyHost().plan(WindowParams(ip="10.0.0.1", start=START, end=END))
        assert "event.action.keyword" not in repr(neutral.body)
        assert "'event.action'" in repr(neutral.body)
        assert neutral.window is not None
        assert neutral.window.source == "proxy"
        assert "event.action" in ProxyHost.spec().aggregate_fields
    assert "event.action.keyword" in ProxyHost.spec().aggregate_fields


def test_every_field_a_template_builds_into_its_body_is_in_its_allowlist() -> None:
    """The validator accepts the body of each field-mapped template on a neutral site and on
    one with .keyword names: no field in a body is missing from the template's allowlists."""
    fields = {
        Role.WEB: {"domain": "url.domain.keyword"},
        Role.PROXY: {"action": "event.action.keyword", "url": "url.original.keyword"},
    }
    for names in ({}, fields):
        profile = SiteSettings(
            families=(
                LogFamily(role=Role.PROXY, pattern="px-*", fields=names.get(Role.PROXY, {})),
                LogFamily(role=Role.WEB, pattern="web-*", fields=names.get(Role.WEB, {})),
                LogFamily(role=Role.DNS, pattern="dns-*"),
            )
        )
        with site.using(profile):
            gateway, *_ = make()
            for template, params in (
                (ProxyHost(), WindowParams(ip="10.0.0.1", start=START, end=END)),
                (ProxyDestination(), WindowParams(ip="1.2.3.4", start=START, end=END)),
                (DnsHostDomains(), DomainsParams(ip="10.0.0.1", start=START, end=END)),
                (
                    WebPathOutcomes(),
                    PathParams(
                        ip="1.2.3.4", site="a.example", paths=("/.env",), start=START, end=END
                    ),
                ),
            ):
                final = gateway.preview(template, params, deadline=DEADLINE)
                validate(final)  # raises when a field in the body is not allowlisted


def test_the_family_a_module_applies_to_is_chosen_by_role() -> None:
    with site.using(STREAMS):
        assert proxy.applies(["logs-zscaler.nss-default"])
        assert not proxy.applies(["acme-logs-squid-*"])
    assert proxy.applies(["acme-logs-squid-*"])
    assert not proxy.applies(["x-nginx-*"])


# ------------------------------------------------------------------ health probe, self-test


async def test_the_probe_asks_for_todays_daily_index_and_the_stream_by_name() -> None:
    store = MemoryStore(memory=HealthMemory(probed_at=T0))
    transport = FakeTransport()
    node = {
        "_nodes": {"failed": 0},
        "nodes": {
            "n": {
                "fs": {"total": {"total_in_bytes": 100, "available_in_bytes": 90}},
                "jvm": {"mem": {"heap_used_percent": 10}},
                "os": {"cpu": {"load_average": {"1m": 0.1}}},
                "thread_pool": {
                    "search": {"queue": 0, "rejected": 0},
                    "write": {"rejected": 0},
                },
                "breakers": {"request": {"tripped": 0}},
            }
        },
    }
    transport.on("_nodes", ok(node))
    transport.on(
        "_settings", ok({".internal.alerts-security.alerts-default-000001": {"settings": {}}})
    )
    clock = FakeClock()
    with site.using(STREAMS):
        gateway = Gateway(transport, store, clock=clock, sleep=clock.sleep)
        memory = await probe(gateway, store, SiemSettings(), T0)
        assert memory.state is HealthState.NORMAL
        blocks = next(c for c in transport.calls if "_settings" in c.path)
        assert blocks.path.split("/_settings")[0] == (
            "/.alerts-security.alerts-default,logs-zscaler.nss-default,dns-logs-2026.10.09"
        )  # the web family is not watched
        transport.calls.clear()
        await probe(gateway, store, SiemSettings(), T0, indices=False)
        assert not [c for c in transport.calls if "_settings" in c.path]


async def test_the_self_test_follows_the_sites_version_range() -> None:
    cluster = dict.fromkeys(
        ("manage", "manage_security", "manage_api_key", "manage_ilm", "all"), False
    )

    def fake(version: str) -> FakeTransport:
        t = FakeTransport()
        t.on("_security/_authenticate", ok({"authentication_type": "api_key"}))
        t.on("_has_privileges", ok({"cluster": {"monitor": True, **cluster}, "index": {}}))
        t.on("/", ok({"version": {"number": version}}))
        return t

    async def version_problems(version: str) -> list[str]:
        gateway, *_ = make(fake(version))
        problems = await selftest(gateway, SiemSettings(), T0)
        return [p for p in problems if p.startswith("server version")]

    assert await version_problems("8.19.3") == []  # ACME's range is >=8.19,<8.20
    assert await version_problems("8.20.0") == [
        "server version 8.20.0 is not in the range >=8.19,<8.20"
    ]
    with site.using(SiteSettings()):  # the neutral range is >=8.0,<10
        assert await version_problems("9.1.0") == []
        assert await version_problems("7.17.0") == [
            "server version 7.17.0 is not in the range >=8.0,<10"
        ]
        assert len(await version_problems("10.0.0")) == 1


async def test_discovery_is_for_normal_health_only() -> None:
    from argus.gateway.discovery import DiscoverIndices, IndicesParams

    store = MemoryStore(memory=HealthMemory(state=HealthState.CAUTION, probed_at=T0))
    gateway, transport, _, _ = make(store=store)
    with pytest.raises(DeferredError):
        await gateway.run(
            DiscoverIndices(), IndicesParams(scope="data"), purpose=Purpose.DISCOVER,
            component="discover", deadline=DEADLINE,
        )  # fmt: skip
    assert transport.calls == []
