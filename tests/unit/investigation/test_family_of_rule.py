"""A site with two families of one role (P4-D1 review F3): the evidence reads the family the rule
reads, `catalogue.sources_of` and the modules agree on it, a rule that names none reads the first
and says so, and a one-family site's requests are exactly what they were."""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from itertools import product
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus import site
from argus.context import batch1, beacon, dns, paths, proxy, web
from argus.context.packs import TaskSpec
from argus.gateway.gateway import Gateway
from argus.gateway.templates import REGISTRY, plan_key
from argus.investigation import catalogue
from argus.site import LogFamily, Role, SiteSettings
from tests.unit.gateway.fakes import T0
from tests.unit.investigation import kit

pytestmark = pytest.mark.unit

TWO = SiteSettings(
    families=(
        LogFamily(name="squid_a", role=Role.PROXY, pattern="corp-a-squid-*"),
        LogFamily(
            name="squid_b",
            role=Role.PROXY,
            pattern="corp-b-squid-*",
            time_field="event.created",
            fields={"client_ip": "source.address", "server_ip": "destination.address"},
        ),
        LogFamily(name="nginx_a", role=Role.WEB, pattern="corp-a-nginx-*"),
        LogFamily(
            name="nginx_b",
            role=Role.WEB,
            pattern="corp-b-nginx-*",
            fields={"domain": "url.domain.keyword", "client_ip": "client.ip"},
        ),
        LogFamily(name="dns_a", role=Role.DNS, pattern="corp-a-dns-*"),
        LogFamily(name="dns_b", role=Role.DNS, pattern="corp-b-dns-*"),
    )
)


@pytest.fixture
def two() -> Any:
    with site.using(TWO):
        yield TWO


def built(template: str, indices: list[str]) -> TaskSpec:
    task = catalogue.build(template, kit.material(indices))
    assert isinstance(task, TaskSpec), task
    return task


def preview(task: TaskSpec) -> Any:
    return Gateway(None, None).preview(  # type: ignore[arg-type]  # sends nothing
        task.template, task.params, deadline=kit.NOW + timedelta(minutes=5), now=kit.NOW
    )


# ------------------------------------------------------------------ the two-family site


@pytest.mark.usefixtures("two")
@pytest.mark.parametrize(
    ("template", "indices", "source"),
    [
        ("proxy.host", ["corp-a-squid-*"], "squid_a"),
        ("proxy.host", ["corp-b-squid-*"], "squid_b"),
        ("proxy.destination", ["corp-b-squid-*"], "squid_b"),
        ("proxy.pair", ["corp-b-squid-*"], "squid_b"),
        ("proxy.contact", ["corp-b-squid-*"], "squid_b"),
        ("proxy.contact", ["corp-a-squid-*", "corp-b-squid-*"], "squid_a"),  # the first named
        ("web.followups", ["corp-b-nginx-*"], "nginx_b"),
        ("web.path_outcomes", ["corp-b-nginx-*"], "nginx_b"),
        ("web.path_outcomes", ["corp-a-nginx-*"], "nginx_a"),
        ("dns.host_domains", ["corp-b-dns-*"], "dns_b"),
        ("dns.host_domains", ["corp-b-dns-2026.10.09"], "dns_b"),  # one day's index
        ("proxy.host", ["corp-b-*"], "squid_b"),  # a pattern that covers only B's logs
    ],
)
def test_the_evidence_reads_the_family_the_rule_reads(
    template: str, indices: list[str], source: str
) -> None:
    task = built(template, indices)
    assert getattr(task.params, "source") == source  # noqa: B009 - written into the request
    final = preview(task)  # the gateway's validator accepts it, whichever family
    assert task.template.plan(task.params).window.source == source  # type: ignore[union-attr]
    prefix = TWO.family(source).prefix  # type: ignore[union-attr]
    assert all(name.startswith(prefix) for name in final.indices)


@pytest.mark.usefixtures("two")
def test_family_b_is_queried_with_its_own_field_names() -> None:
    task = built("proxy.host", ["corp-b-squid-*"])
    body = task.template.plan(task.params).body
    filters = body["query"]["bool"]["filter"]
    assert filters[0] == {"term": {"source.address": kit.HOST}}
    assert filters[1]["range"].keys() == {"event.created"}
    assert body["aggs"]["destinations"]["terms"]["field"] == "destination.address"
    other = built("proxy.host", ["corp-a-squid-*"])
    assert other.template.plan(other.params).body["query"]["bool"]["filter"][0] == {
        "term": {"source.ip": kit.HOST}
    }
    web_task = built("web.followups", ["corp-b-nginx-*"])
    assert web_task.template.plan(web_task.params).body["query"]["bool"]["filter"][0] == {
        "term": {"client.ip": kit.HOST}
    }


@pytest.mark.usefixtures("two")
def test_the_allowlists_hold_every_familys_fields() -> None:
    """One template class reads any family of its role, so its validator allowlist is the union
    (a request for B must not be refused because A's names were the only ones listed)."""
    spec = REGISTRY["proxy.host"].spec()
    assert {"source.ip", "source.address", "@timestamp", "event.created"} <= spec.filter_fields
    web_spec = REGISTRY["web.followups"].spec()
    assert {"source.ip", "client.ip"} <= web_spec.filter_fields
    assert {"url.domain"} <= web_spec.return_fields


@pytest.mark.usefixtures("two")
def test_the_two_families_are_two_requests_with_two_keys() -> None:
    a, b = built("proxy.host", ["corp-a-squid-*"]), built("proxy.host", ["corp-b-squid-*"])
    key = {n: plan_key(t.template.plan(t.params), t.params) for n, t in (("a", a), ("b", b))}
    assert key["a"] != key["b"]
    assert json.loads(a.params.model_dump_json())["source"] == "squid_a"  # the stored params say


@pytest.mark.usefixtures("two")
def test_a_rule_that_names_no_family_of_the_role_reads_the_first_and_says_so(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="argus.site"):
        task = built("proxy.host", ["acme-logs-*"])
    assert getattr(task.params, "source") == "squid_a"  # noqa: B009 - the first
    assert "name none of this site's proxy families: reading squid_a, the first" in caplog.text
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="argus.site"):
        built("proxy.host", ["corp-b-squid-*"])
    assert caplog.text == ""  # a rule that does name one is not a guess


@pytest.mark.usefixtures("two")
def test_a_source_must_be_a_family_of_the_role() -> None:
    ok = proxy.WindowParams(ip="10.0.0.1", start=T0, end=T0 + timedelta(hours=1), source="squid_b")
    assert ok.source == "squid_b"
    for wrong in ("nginx_a", "nope", "dns_b"):
        with pytest.raises(ValueError, match="is not a proxy family"):
            proxy.WindowParams(ip="10.0.0.1", start=T0, end=T0 + timedelta(hours=1), source=wrong)
    with pytest.raises(ValueError, match="is not a web family"):
        web.FollowParams(ip="10.0.0.1", start=T0, end=T0 + timedelta(hours=1), source="squid_a")
    back = proxy.WindowParams.model_validate_json(ok.model_dump_json())
    assert back == ok


# ------------------------------------------------------------------ the one-family site (ACME)


def test_a_one_family_sites_requests_are_what_they_always_were() -> None:
    for role in (Role.PROXY, Role.WEB, Role.DNS):
        assert site.source_param(role, ["anything-*"]) is None
        assert site.source_param(role, None) is None
    params = proxy.WindowParams(ip="10.0.0.1", start=T0, end=T0 + timedelta(hours=1))
    assert params.source is None
    dumped = json.loads(params.model_dump_json())
    assert "source" not in dumped  # so the content address and the stored params are unchanged
    assert set(dumped) == {"ip", "start", "end"}
    for model, extra in (
        (beacon.PairParams, {"host": "10.0.0.1", "destination": "8.8.8.8"}),
        (beacon.ContactParams, {"destination": "8.8.8.8"}),
        (web.FollowParams, {"ip": "10.0.0.1"}),
        (dns.DomainsParams, {"ip": "10.0.0.1"}),
        (paths.PathParams, {"ip": "10.0.0.1", "site": "x.example", "paths": ("/a",)}),
    ):
        start = T0.replace(hour=9)
        made = model(**extra, start=start, end=start + timedelta(hours=1))
        assert "source" not in json.loads(made.model_dump_json()), model


def test_the_dossiers_requests_on_acme_carry_no_source() -> None:
    for template, indices in (
        ("proxy.host", kit.SQUID),
        ("proxy.destination", kit.SQUID),
        ("web.followups", kit.NGINX),
        ("proxy.pair", kit.SQUID),
        ("dns.host_domains", kit.DNS),
    ):
        task = built(template, list(indices))
        assert getattr(task.params, "source") is None  # noqa: B009
        assert "source" not in json.loads(task.params.model_dump_json())
        assert task.template.plan(task.params).window.source in {  # type: ignore[union-attr]
            "squid",
            "nginx",
            "dns",
        }


def test_sources_of_is_the_sites_rule_families() -> None:
    for indices in (
        ["acme-logs-*"],
        ["acme-logs-squid-*", "-acme-logs-squid-2026.10.09"],
        ["logs-squid.access-default"],
        ["acme-logs-nginx*,acme-logs-dns-*"],
        [],
    ):
        assert catalogue.sources_of(indices) == frozenset(
            f.name for f in site.rule_families(indices)
        )
    assert batch1  # the builders are the same ones the packs use


# ------------------------------------------------------------------ the property

PREFIXES = ["corp-a", "corp-b", "corp-c"]
ENTRIES = [
    "corp-a-squid-*",
    "corp-b-squid-*",
    "corp-c-squid-2026.10.09",
    "corp-*",
    "corp-b-*",
    "*",
    "other-*",
    "corp-a-nginx-*,corp-b-squid-*",
    "-corp-a-squid-*",
    "squid_b",
    "",
    "corp-b-squid-2026.1*",
]


def site_of(per_role: dict[Role, int]) -> SiteSettings:
    families = []
    for role, word in ((Role.PROXY, "squid"), (Role.WEB, "nginx"), (Role.DNS, "dns")):
        for i in range(per_role[role]):
            families.append(
                LogFamily(
                    name=f"{word}_{PREFIXES[i][-1]}", role=role, pattern=f"{PREFIXES[i]}-{word}-*"
                )
            )
    return SiteSettings(families=tuple(families))


@settings(max_examples=150, deadline=None)
@given(
    st.tuples(st.integers(0, 3), st.integers(0, 3), st.integers(0, 3)),
    st.lists(st.sampled_from(ENTRIES), max_size=4),
)
def test_the_family_read_is_one_the_rule_reads_whenever_the_rule_reads_one(
    counts: tuple[int, int, int], indices: list[str]
) -> None:
    per_role = dict(zip((Role.PROXY, Role.WEB, Role.DNS), counts, strict=True))
    with site.using(site_of(per_role)):
        for role in per_role:
            of_role = site.active().of_role(role)
            chosen = site.source_for(role, indices)
            param = site.source_param(role, indices)
            if not of_role:
                assert chosen == role.value
                assert param is None
                continue
            names = [f.name for f in of_role]
            assert chosen in names  # always a family of the role
            named = [f.name for f in of_role if any(site.names_family(i, f) for i in indices)]
            covered = {f.name for f in site.rule_families(indices, known=names)}
            if named:
                assert chosen == named[0]  # the modules' reading (`reads`)
            elif covered:
                assert chosen in covered  # the catalogue's reading
                assert chosen == next(n for n in names if n in covered)
            else:
                assert chosen == names[0]  # a guess, the first
            assert (param is None) == (len(of_role) < 2)
            if param is not None:
                assert param == chosen
            # they agree: whatever the catalogue says the rule reads of this role, the family
            # read is one of it, unless the rule names a family the catalogue does not list
            if covered and named:
                assert chosen in covered or chosen in named
            assert site.fields_for(role, chosen).role is role


def test_every_entry_pair_picks_a_family_of_the_role() -> None:
    with site.using(site_of({Role.PROXY: 3, Role.WEB: 2, Role.DNS: 2})):
        for first, second in product(ENTRIES, repeat=2):
            for role in (Role.PROXY, Role.WEB, Role.DNS):
                names = {f.name for f in site.active().of_role(role)}
                assert site.source_for(role, [first, second]) in names
