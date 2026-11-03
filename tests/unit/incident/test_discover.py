"""The exact query behind a line of evidence (AR7, D-190): each template that ran has a query in
both languages and a read-only Discover link built from configuration alone; values enter only as
quoted literals; the rison and URL encoding hold the whole query; no registered investigation
template is left without one."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, unquote

import pytest
from hypothesis import given
from hypothesis import strategies as st

import argus.context.beacon
import argus.context.dns
import argus.context.paths
import argus.context.proxy
import argus.context.source_events
import argus.context.web
import argus.reference.templates  # noqa: F401
from argus.incident import discover as d
from argus.investigation.catalogue import CHECKS

pytestmark = pytest.mark.unit

CFG = d.Config(kibana_url="https://kibana.example", base_path="/kb", space="s1")
START = datetime(2026, 10, 15, 12, 0, tzinfo=UTC)
END = START + timedelta(hours=2)
WINDOW = {"start": START.isoformat(), "end": END.isoformat()}
PARAMS = {
    "proxy.host": {"ip": "10.1.2.3", **WINDOW},
    "proxy.destination": {"ip": "77.1.2.3", **WINDOW},
    "proxy.pair": {"host": "10.1.2.3", "destination": "77.1.2.3", **WINDOW},
    "proxy.contact": {"destination": "77.1.2.3", "hosts": ["10.1.2.3", "10.1.2.4"], **WINDOW},
    "dns.host_domains": {"ip": "10.1.2.3", **WINDOW},
    "web.followups": {"ip": "203.0.113.9", **WINDOW},
    "web.path_outcomes": {
        "ip": "203.0.113.9",
        "site": "a.example.edu",
        "paths": ["/.git/config"],
        **WINDOW,
    },
    "logs.source_events": {"source": "dns", "ip": "10.1.2.3", "narrow": [], **WINDOW},
    "ti.lookup": {"values": ["77.1.2.3", "bad.example"]},
}


def test_every_template_the_investigation_can_run_has_a_query() -> None:
    assert set(CHECKS) <= set(d.TEMPLATES)
    assert set(PARAMS) == set(d.TEMPLATES)


@pytest.mark.parametrize("template", sorted(PARAMS))
def test_each_template_gives_both_languages_and_a_link(template: str) -> None:
    q = d.for_template(CFG, template, 1, PARAMS[template], END)
    assert q is not None
    assert q.template == f"{template}@1"
    assert q.language == "esql"
    assert q.text.startswith("FROM ")
    assert q.other
    assert " | " in q.text
    assert "LIMIT" in q.text
    assert q.url.startswith("https://kibana.example/kb/s/s1/app/discover#/?_g=(")
    parts = unquote(q.url.split("#/?", 1)[1])
    assert "dataSource:(type:'esql')" in parts
    assert q.index in parts
    assert q.time_to > q.time_from
    views = d.Config(
        kibana_url="https://kibana.example",
        space="s1",
        views={"squid": "v1", "dns": "v2", "nginx": "v3", "ti": "v4"},
    )
    k = d.for_template(views, template, 1, PARAMS[template], END)
    assert k is not None
    assert k.language == "kql"
    assert k.other
    assert k.other.startswith("FROM ")
    assert "dataViewId" in unquote(k.url)
    assert "language:'kuery'" in unquote(k.url)


def test_the_proxy_pair_query_text() -> None:
    q = d.for_template(CFG, "proxy.pair", 1, PARAMS["proxy.pair"], END)
    assert q is not None
    assert q.text == (
        'FROM acme-logs-squid-* | WHERE @timestamp >= "2026-10-15T12:00:00.000Z" AND '
        '@timestamp < "2026-10-15T14:00:00.000Z" | WHERE source.ip == "10.1.2.3" AND '
        'destination.ip == "77.1.2.3" | LIMIT 100'
    )
    assert q.other == 'source.ip : "10.1.2.3" and destination.ip : "77.1.2.3"'


def test_a_template_without_a_query_or_with_unreadable_parameters_gives_none() -> None:
    assert d.for_template(CFG, "alerts.count", 1, {}, END) is None
    assert d.for_template(CFG, "proxy.pair", 1, {"host": "10.1.2.3"}, END) is None
    assert (
        d.for_template(
            CFG, "proxy.host", 1, {"ip": "1.2.3.4", "start": "not a time", "end": "x"}, END
        )
        is None
    )


@given(st.text(max_size=60))
def test_a_value_can_only_be_a_quoted_literal(value: str) -> None:
    kql, esql = d.kql_str(value), d.esql_str(value)
    for lit in (kql, esql):
        assert lit.startswith('"')
        assert lit.endswith('"')
        assert len(lit) >= 2
        inner = lit[1:-1]
        # every quote or backslash inside is escaped: removing the escapes leaves no bare quote
        assert '"' not in inner.replace('\\"', "").replace("\\\\", "")
        assert not any(ord(c) < 32 or 127 <= ord(c) < 160 for c in inner)


def test_a_hostile_value_cannot_add_a_clause() -> None:
    evil = '1.2.3.4" or source.ip : "*'
    q = d.for_template(CFG, "proxy.host", 1, {"ip": evil, **WINDOW}, END)
    assert q is not None
    assert q.other == 'source.ip : "1.2.3.4\\" or source.ip : \\"*"'
    assert 'source.ip == "1.2.3.4\\" or source.ip : \\"*"' in q.text
    nul = d.for_template(CFG, "proxy.host", 1, {"ip": "1.2.3.4\n| DROP", **WINDOW}, END)
    assert nul is not None
    assert "\n" not in nul.text
    assert "DROP" in nul.text


def test_rison_writes_kibana_state_and_escapes_what_it_must() -> None:
    assert d.rison({"a": 1, "b": [True, None, "x"], "c": {"d": "it's!"}}) == (
        "(a:1,b:!(!t,!n,'x'),c:(d:'it!'s!!'))"
    )
    assert d.rison({"@timestamp": 0}) == "('@timestamp':0)"
    with pytest.raises(TypeError):
        d.rison({"a": object()})


@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=40))
def test_a_link_holds_the_whole_query_whatever_it_says(text: str) -> None:
    url = d.discover_url(
        CFG,
        language="esql",
        index="i-*",
        text="",
        esql="FROM i-* | WHERE x == " + d.esql_str(text),
        start=START,
        end=END,
        source="squid",
    )
    fragment = url.split("#/?", 1)[1]
    state = parse_qs(fragment)
    assert set(state) == {"_g", "_a"}  # no stray & or # from the value escaped the parameter
    assert d.esql_str(text) in unquote(state["_a"][0]).replace("!!", "!").replace("!'", "'")


def test_the_alert_and_tag_queries() -> None:
    q = d.alerts_query(CFG, ["Rule b", "Rule a", ""], START, END)
    assert q.index == ".alerts-security.alerts-s1"
    assert q.other == 'kibana.alert.rule.name : ("Rule a" or "Rule b")'
    tag = d.tag_query(CFG, "ACME-IR-2026-1027-01", START, END)
    assert "MV_EXPAND kibana.alert.workflow_tags" in tag.text
    assert tag.other == 'kibana.alert.workflow_tags : "ACME-IR-2026-1027-01"'


def test_the_log_index_is_the_sites_family_pattern_and_a_source_the_site_lacks_falls_back() -> None:
    """The family's pattern for a source the site has (ACME: the daily squid indices); for one it
    does not, ``<source>-*`` (P4-D1 review F17: no source outside the site is a hardcoded
    ACME index). The callers only pass squid, dns and nginx today."""
    assert CFG.log_index("squid") == "acme-logs-squid-*"
    assert CFG.log_index("nginx") == "acme-logs-nginx-*"
    assert CFG.log_index("unknown") == "unknown-*"
    from argus import site
    from argus.site import LogFamily, Role, SiteSettings

    stream = LogFamily(role=Role.PROXY, pattern="logs-zscaler.nss-default")
    with site.using(SiteSettings(families=(stream,))):
        assert CFG.log_index("proxy") == "logs-zscaler.nss-default"
        assert CFG.log_index("squid") == "squid-*"
