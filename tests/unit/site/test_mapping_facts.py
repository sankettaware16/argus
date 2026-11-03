"""P4-D1 part 2, step 5 (D-284): the mapping facts the batch-1 templates were checked against (the
captured-mapping table) are the families' ``fields``, ``types`` and ``ignore_above``; the value
cap of a request is the families' smallest ``ignore_above``; the incident report's queries name
the family a query ran on and its fields. ACME's section gives the table it always was."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from argus import site
from argus.context import batch1, bounds, paths
from argus.incident import discover
from argus.site import LogFamily, Role, SiteSettings

pytestmark = pytest.mark.unit

# The table batch1.FIELDS was (captured mappings of 2026-10-08), written out as it was.
OLD_FIELDS: dict[str, dict[str, str]] = {
    "squid": {
        "@timestamp": "date", "source.ip": "ip", "destination.ip": "ip",
        "destination.port": "long", "destination.bytes": "long", "url.original": "text+keyword",
        "http.request.method": "text+keyword", "http.response.status_code": "integer",
        "event.action": "text+keyword",
    },
    "dns": {
        "@timestamp": "date", "source.ip": "ip", "client.ip": "ip",
        "dns.question.name": "text+keyword", "dns.question.type": "text+keyword",
        "dns.response_code": "text+keyword",
    },
    "nginx": {
        "@timestamp": "date", "source.ip": "ip", "url.domain": "text+keyword",
        "url.path": "keyword", "http.request.method": "text+keyword",
        "http.response.status_code": "integer", "http.response.body.bytes": "long",
        "user_agent.original": "text+keyword",
    },
}  # fmt: skip
OLD_SOURCES = {
    "proxy.pair": ("squid",),
    "proxy.contact": ("squid",),
    "dns.host_domains": ("dns",),
    "web.path_outcomes": ("nginx",),
    "logs.source_events": ("squid", "nginx", "dns"),
}
AGENT = SiteSettings(
    families=(
        LogFamily(
            name="proxy", role=Role.PROXY, pattern="logs-squid.access-default",
            time_field="event.created", types={"url.original": "keyword"}, ignore_above=1024,
        ),
        LogFamily(role=Role.WEB, pattern="logs-nginx.access-default",
                  types={"url.domain": "keyword", "url.path": "keyword"}),
        LogFamily(role=Role.DNS, pattern="logs-dns.log-default",
                  fields={"client_ip": "client.ip", "client_ip_alt": "source.ip"}),
    )
)  # fmt: skip


def test_acmes_table_is_the_captured_one() -> None:
    assert {k: dict(batch1.FIELDS[k]) for k in batch1.FIELDS} == OLD_FIELDS
    assert list(batch1.FIELDS) == ["squid", "dns", "nginx"]
    assert {k: batch1.SOURCES[k] for k in batch1.SOURCES} == OLD_SOURCES
    with pytest.raises(KeyError):
        batch1.FIELDS["postfix"]  # a mail family is no batch-1 source
    with pytest.raises(KeyError):
        batch1.FIELDS["nope"]


def test_acmes_index_mapping_is_what_it_was() -> None:
    built = batch1.mapping("squid")
    assert built["date_detection"] is False
    props = built["properties"]
    assert props["@timestamp"] == {"type": "date"}
    assert props["source"]["properties"]["ip"] == {"type": "ip"}
    assert props["url"]["properties"]["original"] == {
        "type": "text",
        "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
    }
    assert props["http"]["properties"]["response"]["properties"]["status_code"] == {
        "type": "integer"
    }


def test_acmes_value_cap_is_256() -> None:
    assert bounds.keyword_chars() == 256
    assert site.keyword_chars("squid") == 256
    assert site.keyword_chars("nobody") == 256  # the smallest of the site's families


def test_a_neutral_site_has_no_table() -> None:
    with site.using(SiteSettings()):
        assert list(batch1.FIELDS) == []
        assert dict(batch1.SOURCES.items()) == dict.fromkeys(OLD_SOURCES, ())
        assert bounds.keyword_chars() == 256


def test_a_site_states_its_own_types_and_cap() -> None:
    with site.using(AGENT):
        assert list(batch1.FIELDS) == ["proxy", "web", "dns"]
        proxy = batch1.FIELDS["proxy"]
        assert proxy["event.created"] == "date"  # the family's time field
        assert "@timestamp" not in proxy
        assert proxy["url.original"] == "keyword"  # said by the site
        assert proxy["event.action"] == "text+keyword"  # the role's default
        assert batch1.FIELDS["web"]["url.domain"] == "keyword"
        assert batch1.FIELDS["dns"]["client.ip"] == "ip"
        assert batch1.SOURCES["logs.source_events"] == ("proxy", "web", "dns")
        assert batch1.SOURCES["proxy.pair"] == ("proxy",)
        assert batch1.mapping("proxy")["properties"]["event"]["properties"]["action"] == {
            "type": "text",
            "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}},
        }
        assert site.keyword_chars("proxy") == 1024
        assert site.keyword_chars() == 256  # the smallest family


def test_the_value_cap_follows_the_sites_families() -> None:
    long_site = "a" * 300 + ".example"
    with site.using(AGENT), pytest.raises(ValueError, match="256 characters"):  # web has 256
        paths.PathParams(ip="1.2.3.4", site=long_site, paths=("/x",), start=_t(1), end=_t(2))
    only_proxy = SiteSettings(families=(AGENT.families[0],))
    with site.using(only_proxy):
        assert bounds.keyword_chars() == 1024
        paths.PathParams(ip="1.2.3.4", site=long_site, paths=("/x",), start=_t(1), end=_t(2))


def _t(hour: int) -> datetime:
    return datetime(2026, 10, 9, 10 + hour, tzinfo=UTC)


@pytest.mark.parametrize(
    "bad",
    [{"url.original": "string"}, {"url.original": ""}, {"": "keyword"}, {"a b": "keyword"}],
)
def test_a_type_must_be_one_the_mapping_knows(bad: dict[str, str]) -> None:
    with pytest.raises(ValidationError, match="types maps a field path"):
        LogFamily(role=Role.PROXY, pattern="x-*", types=bad)


@pytest.mark.parametrize("bad", [0, -1, 32767])
def test_ignore_above_is_what_elasticsearch_allows(bad: int) -> None:
    with pytest.raises(ValidationError):
        LogFamily(role=Role.PROXY, pattern="x-*", ignore_above=bad)


def test_families_differing_in_types_are_not_equal_or_one_hash() -> None:
    a = LogFamily(role=Role.PROXY, pattern="x-*")
    b = LogFamily(role=Role.PROXY, pattern="x-*", types={"url.original": "keyword"})
    c = LogFamily(role=Role.PROXY, pattern="x-*", ignore_above=512)
    assert len({hash(a), hash(b), hash(c)}) == 3
    assert a == LogFamily(role=Role.PROXY, pattern="x-*")


# --------------------------------------------------------------------------- the report's queries

T0, T1 = "2026-10-29T10:00:00+00:00", "2026-10-29T11:00:00+00:00"
CFG = discover.Config(kibana_url="https://kibana.example", space="acme-soc")
AT = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)


def query(template: str, **params: Any) -> Any:
    found = discover.for_template(CFG, template, 1, {"start": T0, "end": T1, **params}, AT)
    assert found is not None
    return found


def test_acmes_queries_name_squid_nginx_and_dns() -> None:
    q = query("proxy.pair", host="10.1.2.3", destination="1.2.3.4")
    assert q.index == "acme-logs-squid-*"
    assert "source.ip : '10.1.2.3' and destination.ip : '1.2.3.4'" in q.other or q.text
    host = query("proxy.host", ip="10.1.2.3")
    assert "FROM acme-logs-squid-* | WHERE @timestamp >=" in host.text + host.other
    web = query("web.path_outcomes", ip="1.2.3.4", site="www.example.org", paths=["/.env"])
    assert "url.domain.keyword" in web.text + web.other
    assert "FROM acme-logs-nginx-*" in web.text + web.other
    dns = query("dns.host_domains", ip="10.1.2.3")
    assert "client.ip" in dns.text + dns.other


def test_a_sites_queries_name_its_family_fields_and_time_field() -> None:
    with site.using(AGENT):
        q = query("proxy.host", ip="10.1.2.3", source="proxy")
        both = q.text + " " + q.other
        assert "FROM logs-squid.access-default | WHERE event.created >=" in both
        assert "@timestamp" not in both
        sourced = query("logs.source_events", source="proxy", ip="10.1.2.3")
        assert "| SORT event.created ASC | LIMIT 100" in sourced.text + sourced.other
        dns = query("dns.host_domains", ip="10.1.2.3", source="dns")
        assert 'client.ip : "10.1.2.3" or source.ip : "10.1.2.3"' in dns.text + dns.other
        web = query("web.followups", ip="1.2.3.4")
        assert "FROM logs-nginx.access-default" in web.text + web.other


def test_a_query_without_a_family_of_the_role_names_the_role() -> None:
    with site.using(SiteSettings()):
        q = query("proxy.host", ip="10.1.2.3")
        assert q.index == "proxy-*"  # no family: the role's own name, as before
