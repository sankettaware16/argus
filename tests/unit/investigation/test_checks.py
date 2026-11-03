"""Q-F3: "Check more", one approved template on one entity: what is refused at once, what each
template takes, and that a request is built or refused, never wrong."""

from __future__ import annotations

import ipaddress
from datetime import timedelta

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.context import batch1, proxy, web
from argus.context.packs import TaskSpec
from argus.gateway.gateway import Gateway, Targets
from argus.gateway.state import MemoryStore
from argus.investigation import catalogue, checks
from argus.reference.templates import TiLookup
from tests.unit.investigation.kit import ALL_ON, C2, DNS, HOST, NGINX, NOW, SQUID, material

pytestmark = pytest.mark.unit
CAMPUS = batch1.private_or(None)
TARGETS = Targets(log_sources=frozenset({"squid", "dns", "nginx", "postfix"}))
GATEWAY = Gateway(object(), MemoryStore(), targets=TARGETS)  # type: ignore[arg-type]
EVERY_SOURCE = SQUID + NGINX + DNS


def build(template: str, entity: str, indices: tuple[str, ...] = EVERY_SOURCE,
          switches: catalogue.Switches = ALL_ON) -> TaskSpec | batch1.Refusal:  # fmt: skip
    return checks.build(template, entity, material(indices), switches, CAMPUS)


@pytest.mark.parametrize(
    ("entity", "clean"),
    [
        ("10.20.3.4", "10.20.3.4"),
        (" 185.220.101.5 ", "185.220.101.5"),
        ("2001:0DB8:0:0:0:0:0:1", "2001:db8::1"),
        ("Evil.Example.COM.", "evil.example.com"),
        ("a.b", None),  # no top-level name of two letters
        ("localhost", None),
        ("10.0.0", None),
        ("", None),
        ("a b.example.com", None),
        ("https://x.example.com/", None),
        ("x" * 300 + ".example.com", None),
    ],
)
def test_what_an_entity_is(entity: str, clean: str | None) -> None:
    assert checks.clean(entity) == clean


@pytest.mark.parametrize(
    ("template", "entity", "problem"),
    [
        ("proxy.host", "10.20.3.4", None),
        ("ti.lookup", "evil.example.com", None),
        ("ti.lookup", "185.220.101.5", None),
        ("logs.source_events", "10.20.3.4", "that is not a check a person may ask for"),
        ("proxy.nothing", "10.20.3.4", "that is not a check a person may ask for"),
        ("proxy.host", "not an address", "that is neither an address nor a domain"),
        ("proxy.host", "evil.example.com", "this check takes an address"),
        ("dns.host_domains", "evil.example.com", "this check takes an address"),
    ],
)
def test_what_is_refused_at_once(template: str, entity: str, problem: str | None) -> None:
    assert checks.validate(template, entity) == problem


def test_the_approved_checks_are_catalogue_templates_with_a_subject() -> None:
    assert set(checks.APPROVED) <= set(catalogue.CHECKS)
    assert "logs.source_events" not in checks.APPROVED  # asked about an alert, not an entity


@pytest.mark.parametrize(
    ("template", "entity", "cls"),
    [
        ("proxy.host", HOST, proxy.ProxyHost),
        ("proxy.destination", C2, proxy.ProxyDestination),
        ("web.followups", C2, web.WebFollowups),
        ("web.followups", HOST, web.WebFollowups),
        ("proxy.pair", HOST, None),
        ("proxy.pair", C2, None),
        ("proxy.contact", C2, None),
        ("dns.host_domains", HOST, None),
        ("web.path_outcomes", C2, None),
        ("ti.lookup", C2, TiLookup),
        ("ti.lookup", "evil.example.com", TiLookup),
    ],
)
def test_each_template_is_built_from_its_entity(template: str, entity: str,
                                                cls: type | None) -> None:  # fmt: skip
    task = build(template, entity)
    assert isinstance(task, TaskSpec), task
    assert type(task.template).name == template
    if cls is not None:
        assert isinstance(task.template, cls)
    if template in batch1.TEMPLATES:
        batch1.final_request(task, TARGETS, NOW)


def test_a_pair_is_made_from_the_entity_and_the_dossiers_other_end() -> None:
    from argus.context.beacon import PairParams

    host, dest = build("proxy.pair", HOST), build("proxy.pair", C2)
    assert isinstance(host, TaskSpec)
    assert isinstance(dest, TaskSpec)
    assert isinstance(host.params, PairParams)
    assert isinstance(dest.params, PairParams)
    assert (host.params.host, host.params.destination) == (HOST, C2)
    assert (dest.params.host, dest.params.destination) == (HOST, C2)
    other = build("proxy.pair", "10.99.0.7")
    assert isinstance(other, TaskSpec)
    assert isinstance(other.params, PairParams)
    assert (other.params.host, other.params.destination) == ("10.99.0.7", C2)


@pytest.mark.parametrize(
    ("template", "entity", "why"),
    [
        ("proxy.host", C2, "takes an internal address, not a public one"),
        ("proxy.destination", HOST, "takes a public address, not an internal one"),
        ("proxy.contact", HOST, "takes a public address"),
        ("dns.host_domains", C2, "takes an internal address"),
        ("proxy.host", "127.0.0.1", "takes an internal address, not a special one"),
        ("web.followups", "169.254.1.1", "not one ARGUS asks about"),
        ("web.followups", "224.0.0.1", "not one ARGUS asks about"),
    ],
)
def test_an_address_of_the_wrong_kind_is_refused(template: str, entity: str, why: str) -> None:
    got = build(template, entity)
    assert isinstance(got, batch1.Refusal)
    assert why in got.detail


def test_the_rules_own_indices_decide() -> None:
    for template, entity, indices in (
        ("proxy.host", HOST, NGINX + DNS),
        ("web.followups", C2, SQUID + DNS),
        ("dns.host_domains", HOST, SQUID + NGINX),
    ):
        got = build(template, entity, indices)
        assert isinstance(got, batch1.Refusal)
        assert got.detail == "the rule does not read the log this check needs"
    assert isinstance(build("ti.lookup", C2, ()), TaskSpec)  # no log needed


def test_a_switched_off_check_is_refused() -> None:
    off = catalogue.Switches(templates=frozenset({"proxy.contact"}), proxy_aggregations=False)
    assert build("proxy.host", HOST, switches=off) == batch1.Refusal("off")
    assert build("proxy.pair", HOST, switches=off) == batch1.Refusal("off")
    assert isinstance(build("proxy.contact", C2, switches=off), TaskSpec)
    assert build("ti.lookup", C2, switches=off) == batch1.Refusal("off")


def test_nothing_comes_from_the_rule_or_the_person_but_the_entity() -> None:
    a = build("proxy.host", HOST)
    b = checks.build("proxy.host", HOST, material(EVERY_SOURCE, rule_type="threshold"),
                     ALL_ON, CAMPUS)  # fmt: skip
    assert isinstance(a, TaskSpec)
    assert isinstance(b, TaskSpec)
    assert a.ref()["task_key"] == b.ref()["task_key"]


addresses = st.one_of(
    st.ip_addresses(v=4), st.ip_addresses(v=6),
    st.sampled_from([ipaddress.ip_address(x) for x in (HOST, C2, "8.8.8.8", "100.64.0.1")]),
)  # fmt: skip
domains = st.from_regex(r"[a-z][a-z0-9-]{0,20}(\.[a-z][a-z0-9-]{0,20}){0,2}\.[a-z]{2,6}",
                        fullmatch=True)  # fmt: skip


@settings(max_examples=150, deadline=None)
@given(
    template=st.sampled_from(checks.APPROVED),
    entity=st.one_of(addresses.map(str), domains),
    indices=st.sampled_from([SQUID, NGINX, DNS, EVERY_SOURCE, ()]),
)
def test_a_request_is_built_or_refused_never_wrong(template: str, entity: str,
                                                   indices: tuple[str, ...]) -> None:  # fmt: skip
    got = build(template, entity, indices)
    if isinstance(got, batch1.Refusal):
        assert got.sentence
        return
    assert type(got.template).name == template
    spec = catalogue.CHECKS[template]
    assert catalogue.reads_needed(spec, catalogue.sources_of(indices))
    if template in batch1.TEMPLATES:
        batch1.final_request(got, TARGETS, NOW)  # the validator accepts it
    GATEWAY.preview(got.template, got.params, deadline=NOW + timedelta(hours=1), now=NOW)
