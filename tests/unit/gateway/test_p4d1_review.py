"""The gateway-side review fixes of P4-D1 (F5, F8, F9, F16, F17, F19): what the self-test and
`see_logs` ask of the site's own families, a missing data stream's own reason, a stream search
that must say which time, system indices a mapping read refuses, a name that merely contains a
prefix owning nothing, and the site models hashing."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest

from argus import site
from argus.config.settings import SiemSettings
from argus.context.proxy import ProxyHost, WindowParams
from argus.gateway.builtin import BlocksParams, IndexBlocks
from argus.gateway.discovery import MappingParams
from argus.gateway.errors import SourceMissingError, TemplateRejectedError
from argus.gateway.gateway import Gateway, Targets
from argus.gateway.service import selftest, targets
from argus.gateway.templates import Purpose
from argus.gateway.transport import WireResponse
from argus.gateway.validator import FinalRequest, validate
from argus.identity import capmap
from argus.site import LogFamily, Role, SiteSettings, TiSource
from tests.unit.gateway.fakes import SQUID_TODAY, T0, FakeTransport, listing, make, ok

pytestmark = pytest.mark.unit

START, END = T0.replace(hour=9), T0.replace(hour=10)
DEADLINE = T0 + timedelta(minutes=5)
MISSING = WireResponse(
    404, b'{"error": {"type": "index_not_found_exception", "root_cause": []}}', 3.0
)
STREAMS = SiteSettings(
    families=(
        LogFamily(role=Role.PROXY, pattern="logs-zscaler.nss-default"),
        LogFamily(role=Role.WEB, pattern="logs-nginx.access-default", time_field="event.created"),
        LogFamily(role=Role.DNS, pattern="logs-bind.log-default", watch=False),
    )
)


# ------------------------------------------------------------- F8: a missing stream's own reason


async def test_a_missing_data_stream_is_source_missing_not_source_expired() -> None:
    with site.using(STREAMS):
        gateway, _, store, _ = make(FakeTransport().on("_search", MISSING))
        with pytest.raises(SourceMissingError) as caught:
            await gateway.run(
                ProxyHost(),
                WindowParams(ip="10.1.2.3", start=START, end=END),
                purpose=Purpose.INVESTIGATE,
                component="t",
                deadline=DEADLINE,
            )
    assert caught.value.reason == "source_missing"  # nothing is known about retention
    assert store.ledger[-1].outcome == "source_missing"


async def test_a_daily_index_the_search_cannot_find_is_still_source_expired() -> None:
    transport = FakeTransport().on("_resolve", ok(listing(SQUID_TODAY))).on("_search", MISSING)
    gateway, _, store, _ = make(transport)
    with pytest.raises(SourceMissingError) as caught:
        await gateway.run(
            ProxyHost(),
            WindowParams(ip="10.1.2.3", start=START, end=END),
            purpose=Purpose.INVESTIGATE,
            component="t",
            deadline=DEADLINE,
        )
    assert caught.value.reason == "source_expired"
    assert store.ledger[-1].outcome == "source_expired"


# ------------------------------------------------------------- F9: a stream search has a range


def stream_request(body: dict[str, Any]) -> FinalRequest:
    with site.using(STREAMS):
        gateway = Gateway(None, None)  # type: ignore[arg-type]  # sends nothing
        final = gateway.preview(
            ProxyHost(),
            WindowParams(ip="10.1.2.3", start=START, end=END),
            deadline=DEADLINE,
            now=T0,
        )
    assert final.indices == ("logs-zscaler.nss-default",)
    return replace(final, body={**(final.body or {}), **body})


def test_a_stream_search_with_a_range_on_its_time_field_is_valid() -> None:
    with site.using(STREAMS):
        validate(stream_request({}))


@pytest.mark.parametrize(
    "query",
    [
        {"bool": {"filter": [{"term": {"source.ip": "10.1.2.3"}}]}},  # no range at all
        {"bool": {"filter": [{"range": {"source.ip": {"gte": "10.0.0.0"}}}]}},  # not the time
        {"bool": {"should": [{"range": {"@timestamp": {"gte": "2026-10-09T09:00:00Z"}}}]}},
        {"bool": {"must_not": [{"range": {"@timestamp": {"gte": "2026-10-09T09:00:00Z"}}}]}},
        {"term": {"source.ip": "10.1.2.3"}},
        {"match_all": {}},
    ],
)
def test_a_stream_search_without_a_range_on_its_time_field_is_refused(
    query: dict[str, Any],
) -> None:
    with site.using(STREAMS), pytest.raises(TemplateRejectedError) as caught:
        validate(stream_request({"query": query}))
    assert caught.value.code == "range_required"


def test_the_range_is_on_the_time_field_of_the_family_that_is_read() -> None:
    with site.using(STREAMS):
        gateway = Gateway(None, None)  # type: ignore[arg-type]
        final = gateway.preview(
            ProxyHost(),
            WindowParams(ip="10.1.2.3", start=START, end=END),
            deadline=DEADLINE,
            now=T0,
        )
        assert final.body["query"]["bool"]["filter"][1]["range"].keys() == {"@timestamp"}
        other = LogFamily(
            role=Role.PROXY, pattern="logs-zscaler.nss-default", time_field="event.created"
        )
    with site.using(SiteSettings(families=(other,))):
        gateway = Gateway(None, None)  # type: ignore[arg-type]
        final = gateway.preview(
            ProxyHost(),
            WindowParams(ip="10.1.2.3", start=START, end=END),
            deadline=DEADLINE,
            now=T0,
        )
        assert final.body["query"]["bool"]["filter"][1]["range"].keys() == {"event.created"}
        validate(final)
        wrong = replace(
            final,
            body={
                **final.body,
                "query": {"bool": {"filter": [{"range": {"source.ip": {"gte": "10.0.0.0"}}}]}},
            },
        )
        with pytest.raises(TemplateRejectedError, match="range_required"):
            validate(wrong)


def test_daily_families_need_no_such_rule() -> None:
    gateway = Gateway(None, None)  # type: ignore[arg-type]
    final = gateway.preview(
        ProxyHost(), WindowParams(ip="10.1.2.3", start=START, end=END), deadline=DEADLINE, now=T0
    )
    body = dict(final.body or {})
    body["query"] = {"bool": {"filter": [{"term": {"source.ip": "10.1.2.3"}}]}}
    validate(replace(final, body=body))  # the day is in the index name


# ------------------------------------------------------------- F16: system indices


@pytest.mark.parametrize("name", [".security-7", ".kibana_8.19.12_001", ".alerts-x", "..", "."])
def test_a_mapping_is_not_read_of_a_system_index(name: str) -> None:
    with pytest.raises(ValueError, match="pattern"):
        MappingParams(index=name, fields=("@timestamp",))


@pytest.mark.parametrize(
    "name", ["acme-logs-squid-2026.10.30", ".ds-logs-nginx.access-default-2026.10.30-000001"]
)
def test_a_mapping_is_read_of_a_day_or_a_backing_index(name: str) -> None:
    assert MappingParams(index=name, fields=("@timestamp",)).index == name


def test_the_validator_refuses_a_system_index_mapping_whatever_the_params_say() -> None:
    gateway = Gateway(None, None)  # type: ignore[arg-type]
    from argus.gateway.discovery import DiscoverFieldMapping

    final = gateway.preview(
        DiscoverFieldMapping(),
        MappingParams(index="acme-logs-squid-2026.10.30", fields=("@timestamp",)),
        deadline=DEADLINE,
        now=T0,
    )
    validate(final)
    for system in (".security-7", ".kibana_8.19.12_001"):
        with pytest.raises(TemplateRejectedError, match="system one"):
            validate(replace(final, indices=(system,)))


@pytest.mark.parametrize(
    "pattern", ["..", ".ds-*", ".security-*", ".kibana-*", ".hidden", "._x-*", "-lead-*"]
)
def test_a_log_family_is_never_a_hidden_or_system_index(pattern: str) -> None:
    with pytest.raises(ValueError, match="pattern"):
        LogFamily(role=Role.OTHER, pattern=pattern)


def test_the_alerts_alias_may_still_start_with_a_dot() -> None:
    assert SiteSettings().alerts_index_name.startswith(".alerts-security")
    assert SiteSettings(alerts_index=".alerts-custom-{space}", space="x").alerts_index_name == (
        ".alerts-custom-x"
    )


# ------------------------------------------------------------- F17: the prefix is not "contains"


@pytest.mark.parametrize(
    "name",
    [
        "evil-acme-logs-squid-2026.10.09",
        "xacme-logs-squid-2026.10.09",
        "acme-logs-squi-2026.10.09",
        ".ds-evil-acme-logs-squid-2026.10.09",
        "evil.ds-acme-logs-squid-2026.10.09",
        "acme-logs-squid",
        "",
    ],
)
def test_an_index_that_merely_contains_a_prefix_is_not_a_log_index(name: str) -> None:
    family = site.active().family("squid")
    assert family is not None
    assert not family.owns_index(name)
    assert not Targets().is_log_index(name)
    assert site.source_of_index(name) is None


def test_the_family_prefix_and_the_stream_name_own_exactly_their_indices() -> None:
    squid = site.active().family("squid")
    assert squid is not None
    assert squid.owns_index("acme-logs-squid-2026.10.09")
    assert Targets().is_log_index("acme-logs-squid-2026.10.09")
    assert site.source_of_index(".ds-acme-logs-squid-2026.10.09") == "squid"
    with site.using(STREAMS):
        stream = site.active().family("proxy")
        assert stream is not None
        assert stream.owns_index("logs-zscaler.nss-default")
        assert stream.owns_index(".ds-logs-zscaler.nss-default-2026.10.09-000001")
        assert not stream.owns_index("xlogs-zscaler.nss-default")
        assert not stream.owns_index("logs-zscaler.nss-default-extra")
        assert not stream.owns_index(".ds-logs-zscaler.nss-default")


async def test_the_cluster_allowlist_refuses_an_index_that_only_contains_a_prefix() -> None:
    gateway, *_ = make(FakeTransport())
    with pytest.raises(TemplateRejectedError, match="not an ARGUS index"):
        await gateway.run(
            IndexBlocks(),
            BlocksParams(indices=("evil-acme-logs-squid-2026.10.09",)),
            purpose=Purpose.PROBE,
            component="probe",
            deadline=DEADLINE,
        )


# ------------------------------------------------------------- F5 and F17: the self-test's names

ELASTIC_CLUSTER = dict.fromkeys(
    ("manage", "manage_security", "manage_api_key", "manage_ilm", "all"), False
)


def selftest_transport() -> FakeTransport:
    transport = FakeTransport()
    transport.on("_security/_authenticate", ok({"authentication_type": "api_key"}))
    transport.on(
        "_has_privileges", ok({"cluster": {"monitor": True, **ELASTIC_CLUSTER}, "index": {}})
    )
    transport.on("/", ok({"version": {"number": "8.19.12"}}))
    return transport


async def asked_names(site_profile: SiteSettings | None = None) -> list[str]:
    transport = selftest_transport()
    gateway, *_ = make(transport)
    if site_profile is None:
        await selftest(gateway, SiemSettings(), T0)
    else:
        with site.using(site_profile):
            await selftest(gateway, SiemSettings(), T0)
    call = next(c for c in transport.calls if "_has_privileges" in c.path)
    (entry,) = json.loads(call.body or b"{}")["index"]
    names: list[str] = entry["names"]
    return names


async def test_acmes_selftest_asks_these_four_names_in_this_order() -> None:
    assert await asked_names() == [
        ".alerts-security.alerts-acme-soc",
        "acme-logs-*",
        "abuse-ioc",
        "acme-threat-intel",
    ]


async def test_another_sites_selftest_asks_its_own_families_and_threat_intel_if_it_has_any() -> (
    None
):
    mixed = SiteSettings(
        families=(
            LogFamily(role=Role.WEB, pattern="logs-nginx.access-default"),
            LogFamily(role=Role.PROXY, pattern="acme-logs-squid-*"),
        )
    )
    assert await asked_names(mixed) == [
        ".alerts-security.alerts-default",
        "logs-nginx.access-default",  # not one guessed pattern: squid is checked too
        "acme-logs-squid-*",
    ]
    with_ti = SiteSettings(
        families=mixed.families,
        ti_sources=(TiSource(index="my-ti", schema="ioc", mode="lookup"),),
    )
    assert (await asked_names(with_ti))[-1] == "my-ti"
    assert await asked_names(SiteSettings()) == [".alerts-security.alerts-default"]  # nothing else


def test_the_gateways_targets_are_the_sites_threat_intel() -> None:
    assert targets(SiemSettings()).ti == {"abuse-ioc", "acme-threat-intel"}
    with site.using(SiteSettings()):
        assert targets(SiemSettings()).ti == frozenset()
        assert Targets().ti == frozenset()
    one = SiteSettings(ti_sources=(TiSource(index="x-ti", schema="ecs", mode="lookup"),))
    with site.using(one):
        assert targets(SiemSettings()).ti == {"x-ti"}


def test_see_logs_asks_each_family_and_fails_closed_without_any() -> None:
    families = SiteSettings(
        families=(
            LogFamily(role=Role.WEB, pattern="logs-nginx.access-default"),
            LogFamily(role=Role.DNS, pattern="logs-bind.log-default"),
        )
    )
    with site.using(families):
        t = capmap.Targets()
        assert t.log_patterns == ("logs-nginx.access-default", "logs-bind.log-default")
        body = capmap.request_body(t)
        (logs,) = [e for e in body["index"] if e["names"] == list(t.log_patterns)]
        assert logs["privileges"]
        held = {
            "cluster": dict.fromkeys(body["cluster"], False),
            "index": {
                name: dict.fromkeys(entry["privileges"], True)
                for entry in body["index"]
                for name in entry["names"]
            },
            "application": {
                capmap.KIBANA_APP: {
                    t.resource: dict.fromkeys(body["application"][0]["privileges"], True)
                },
                capmap.ARGUS_APP: {"*": dict.fromkeys(body["application"][1]["privileges"], False)},
            },
        }
        assert any(c.value == "see_logs" for c in capmap.read(held, t).capabilities)
        held["index"]["logs-bind.log-default"] = dict.fromkeys(logs["privileges"], False)
        assert not any(c.value == "see_logs" for c in capmap.read(held, t).capabilities)
    with site.using(SiteSettings()):
        t = capmap.Targets()
        body = capmap.request_body(t)
        assert [e["names"] for e in body["index"]] == [
            [".alerts-security.alerts-default"],
            [".internal.alerts-security.alerts-default-*"],
        ]  # no logs entry: Elasticsearch is never asked about an empty list of names
        held = {
            "cluster": dict.fromkeys(body["cluster"], False),
            "index": {
                name: dict.fromkeys(entry["privileges"], True)
                for entry in body["index"]
                for name in entry["names"]
            },
            "application": {
                capmap.KIBANA_APP: {
                    t.resource: dict.fromkeys(body["application"][0]["privileges"], True)
                },
                capmap.ARGUS_APP: {"*": dict.fromkeys(body["application"][1]["privileges"], False)},
            },
        }
        assert not any(c.value == "see_logs" for c in capmap.read(held, t).capabilities)


# ------------------------------------------------------------- F19: the models hash


def test_the_site_models_are_hashable() -> None:
    squid = LogFamily(role=Role.PROXY, pattern="x-*", fields={"client_ip": "source.address"})
    same = LogFamily(role=Role.PROXY, pattern="x-*", fields={"client_ip": "source.address"})
    other = LogFamily(role=Role.PROXY, pattern="x-*", fields={"client_ip": "client.ip"})
    assert hash(squid) == hash(same)
    assert {squid, same, other} == {squid, other}
    profile = site.active()
    assert hash(profile) == hash(profile.model_copy())
    assert isinstance(hash(SiteSettings()), int)
    assert isinstance(hash(Targets()), int)
    assert hash(Targets()) == hash(Targets())
