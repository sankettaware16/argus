"""On the suite's site (the shapes of a real one) the templates are what they were before P4-D1
(D-238): the allowlists the validator holds each log template to, copied from the class data the
templates had, and the source key of each window. If one changes, stored evidence and the
validator's rules changed. (A real site's pack pins the same on its own site.)"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from argus.context.beacon import ContactParams, PairParams, ProxyContact, ProxyPair
from argus.context.dns import DnsHostDomains, DomainsParams
from argus.context.paths import PathParams, WebPathOutcomes
from argus.context.proxy import ProxyDestination, ProxyHost, WindowParams
from argus.context.source_events import LogsSourceEvents, SourceParams
from argus.context.web import FollowParams, WebFollowups
from argus.signins.template import DayParams, SigninsDay

pytestmark = pytest.mark.unit

T = datetime(2026, 10, 9, 9, 0, tzinfo=UTC)
E = T + timedelta(hours=1)

SPECS: dict[str, dict[str, set[str]]] = {
    "proxy.host": {
        "filter": {"source.ip", "@timestamp"},
        "aggregate": {
            "destination.ip",
            "destination.bytes",
            "http.response.status_code",
            "event.action.keyword",
            "@timestamp",
        },
    },
    "proxy.destination": {
        "filter": {"destination.ip", "@timestamp"},
        "aggregate": {"source.ip", "url.original.keyword"},
    },
    "proxy.pair": {
        "filter": {"source.ip", "destination.ip", "@timestamp"},
        "aggregate": {"@timestamp", "destination.bytes"},
    },
    "proxy.contact": {
        "filter": {"source.ip", "destination.ip", "@timestamp"},
        "aggregate": {"source.ip", "@timestamp"},
    },
    "dns.host_domains": {
        "filter": {"source.ip", "client.ip", "@timestamp"},
        "aggregate": {
            "dns.question.name.keyword",
            "dns.question.type.keyword",
            "dns.response_code.keyword",
            "@timestamp",
        },
    },
    "web.path_outcomes": {
        "filter": {
            "source.ip",
            "url.domain.keyword",
            "url.path",
            "http.response.status_code",
            "@timestamp",
        },
        "aggregate": {
            "url.path",
            "http.response.status_code",
            "http.response.body.bytes",
            "@timestamp",
        },
    },
    "web.followups": {
        "filter": {"source.ip", "@timestamp", "http.response.status_code"},
        "return": {
            "@timestamp",
            "url.domain",
            "url.path",
            "http.response.status_code",
            "http.request.method",
        },
        "sort": {"@timestamp"},
    },
    "logs.source_events": {
        "filter": {
            "source.ip",
            "client.ip",
            "@timestamp",
            "destination.ip",
            "destination.port",
            "url.domain.keyword",
        },
        "return": {
            "@timestamp",
            "source.ip",
            "destination.ip",
            "destination.port",
            "url.original",
            "http.request.method",
            "http.response.status_code",
            "event.action",
            "destination.bytes",
            "url.domain",
            "url.path",
            "http.response.body.bytes",
            "user_agent.original",
            "client.ip",
            "dns.question.name",
            "dns.question.type",
            "dns.response_code",
        },
        "sort": {"@timestamp"},
    },
    "signins.day": {
        "filter": {"source.ip", "event.action.keyword", "@timestamp"},
        "aggregate": {
            "source.ip",
            "user.name.keyword",
            "user_agent.original.keyword",
            "event.outcome.keyword",
            "@timestamp",
        },
    },
}
TEMPLATES = {
    t.name: t
    for t in (
        ProxyHost,
        ProxyDestination,
        ProxyPair,
        ProxyContact,
        DnsHostDomains,
        WebPathOutcomes,
        WebFollowups,
        LogsSourceEvents,
        SigninsDay,
    )
}


@pytest.mark.parametrize("name", sorted(SPECS))
def test_the_allowlists_are_what_they_were(name: str) -> None:
    spec = TEMPLATES[name].spec()
    got = {
        "filter": set(spec.filter_fields),
        "aggregate": set(spec.aggregate_fields),
        "return": set(spec.return_fields),
        "sort": set(spec.sort_fields),
    }
    for kind, expected in SPECS[name].items():
        assert got[kind] == expected, (name, kind)
    for kind in {"filter", "aggregate", "return", "sort"} - set(SPECS[name]):
        assert got[kind] == set(), (name, kind)  # nothing more than it had


def window_source(template: Any, params: Any) -> str:
    plan = template().plan(params)
    assert plan.window is not None
    return plan.window.source


def test_each_template_reads_the_source_it_read() -> None:
    day = DayParams(day=T.date(), addresses=("10.0.0.1",), actions=("user_login_success",), end=E)
    assert window_source(ProxyHost, WindowParams(ip="10.0.0.1", start=T, end=E)) == "squid"
    assert window_source(ProxyDestination, WindowParams(ip="1.2.3.4", start=T, end=E)) == "squid"
    assert (
        window_source(ProxyPair, PairParams(host="10.0.0.1", destination="1.2.3.4", start=T, end=E))
        == "squid"
    )
    assert (
        window_source(ProxyContact, ContactParams(destination="1.2.3.4", start=T, end=E)) == "squid"
    )
    assert window_source(DnsHostDomains, DomainsParams(ip="10.0.0.1", start=T, end=E)) == "dns"
    paths = PathParams(ip="1.2.3.4", site="a.example", paths=("/.env",), start=T, end=E)
    assert window_source(WebPathOutcomes, paths) == "nginx"
    assert window_source(WebFollowups, FollowParams(ip="1.2.3.4", start=T, end=E)) == "nginx"
    assert window_source(SigninsDay, day) == "sso"
    for source in ("squid", "nginx", "dns"):
        params = SourceParams(source=source, ip="10.0.0.1", start=T, end=E)
        assert window_source(LogsSourceEvents, params) == source


def test_acmes_section_holds_the_words_the_code_had_before_part_two() -> None:
    """Part 2 (D-284) made the zone, the prefix, the own network, the noun, the names and the quiet
    hours the site's: ACME's section gives each the value that was a literal."""
    from ipaddress import ip_network

    from argus import site

    profile = site.active()
    assert (profile.timezone, profile.timezone_label) == ("Asia/Kolkata", "IST")
    assert profile.incident_id_prefix == "ACME-IR"
    assert profile.own_network_noun == "campus"
    assert (profile.organisation.name, profile.organisation.short_name) == (
        "Example University",
        "ACME",
    )
    assert (profile.quiet_hours.start, profile.quiet_hours.end) == ("00:00", "01:30")
    assert profile.own_networks == (ip_network("131.21.124.0/22"),)
    assert profile.own_domains == ("example.edu", "example-univ.org")
    assert all(f.ignore_above == 256 and f.types == {} for f in profile.families)
