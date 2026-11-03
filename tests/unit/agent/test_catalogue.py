"""The agent's tool catalogue (P6): allowlisted templates, parameters built by ARGUS from
revealed entities, refusals with reasons."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta

import pytest

from argus.agent import catalogue
from argus.agent.catalogue import Refusal
from argus.assets.classify import IpClassifier
from argus.context import proxy, web
from argus.context.packs import TaskSpec
from argus.reference.templates import LOOKUP_SIZE, TiLookup
from tests.unit.llm.conftest import ASSETS, CAMPUS_PREFIX

FIRST = datetime(2026, 10, 14, 20, 40, tzinfo=UTC)
FACTS = {"first_event_at": FIRST.isoformat(),
         "last_event_at": (FIRST + timedelta(minutes=35)).isoformat()}  # fmt: skip
NOW = datetime(2026, 10, 16, 12, tzinfo=UTC)
VALUES = {"I1.IP_1": "10.20.3.4", "I1.IP_2": "8.8.8.8", "I1.SITE_1": "Evil.Example.",
          "I1.HOST_1": "tp8", "I1.IP_3": "not-an-ip", "I1.IP_4": "198.51.100.7"}  # fmt: skip
CLASSIFIER = IpClassifier(ASSETS, (CAMPUS_PREFIX,))


def reveal(token: str) -> str:
    if token not in VALUES:
        raise ValueError("unknown")
    return VALUES[token]


def build(tool: str, token: str, facts: dict[str, str] = FACTS, now: datetime = NOW) -> object:
    return catalogue.build(tool, token, reveal, facts, now, CLASSIFIER)


def test_the_catalogue_is_the_allowlist() -> None:
    assert sorted(catalogue.TOOLS) == ["outside.reputation", "outside.server",
                                       "proxy.destination", "proxy.host", "ti.lookup",
                                       "web.followups"]  # fmt: skip
    assert {t.domain for t in catalogue.TOOLS.values()} == {"proxy", "web", "intel"}
    assert build("alerts.mget", "I1.IP_1") == Refusal(
        "no tool 'alerts.mget'; tools: outside.reputation, outside.server, proxy.destination,"
        " proxy.host, ti.lookup, web.followups"
    )


def test_proxy_host_on_a_campus_address_with_the_packs_window() -> None:
    task = build("proxy.host", "I1.IP_1")
    assert isinstance(task, TaskSpec)
    assert task.template.name == "proxy.host"
    assert task.params == proxy.WindowParams(
        ip="10.20.3.4", start=FIRST.replace(minute=0) - timedelta(hours=1),
        end=FIRST.replace(minute=0) + timedelta(hours=2),
    )  # fmt: skip
    for campus in ("I1.IP_4",):
        assert isinstance(build("proxy.host", campus), TaskSpec)
    assert build("proxy.host", "I1.IP_2") == Refusal("proxy.host takes a campus address")


def test_proxy_destination_on_a_public_address() -> None:
    task = build("proxy.destination", "I1.IP_2")
    assert isinstance(task, TaskSpec)
    assert task.template.name == "proxy.destination"
    assert task.params.ip == "8.8.8.8"  # type: ignore[attr-defined]
    assert build("proxy.destination", "I1.IP_1") == Refusal(
        "proxy.destination takes a public address"
    )


def test_a_window_not_ready_is_refused() -> None:
    soon = FIRST + timedelta(minutes=10)
    assert build("proxy.host", "I1.IP_1", now=FIRST - timedelta(hours=1)) == Refusal(
        "the proxy logs for this time are not ready or out of range"
    )
    assert build("web.followups", "I1.IP_1", now=soon) == Refusal(
        "the web logs after the alert are not ready yet"
    )
    assert build("web.followups", "I1.IP_1", facts={}) == Refusal(
        "the web logs after the alert are not ready yet"
    )


def test_web_followups_from_the_first_alert() -> None:
    task = build("web.followups", "I1.IP_2")
    assert isinstance(task, TaskSpec)
    assert task.params == web.FollowParams(ip="8.8.8.8", start=FIRST, end=FIRST + web.FOLLOW)


def test_threat_lookups_for_addresses_and_domains() -> None:
    task = build("ti.lookup", "I1.IP_2")
    assert isinstance(task, TaskSpec)
    assert isinstance(task.template, TiLookup)
    assert task.params.values == ("8.8.8.8", "::ffff:8.8.8.8")  # type: ignore[attr-defined]
    assert task.params.size == LOOKUP_SIZE  # type: ignore[attr-defined]
    site = build("ti.lookup", "I1.SITE_1")
    assert isinstance(site, TaskSpec)
    assert site.params.values == ("EVIL.EXAMPLE", "evil.example")  # type: ignore[attr-defined]


@pytest.mark.parametrize(
    ("tool", "token", "reason"),
    [
        ("proxy.host", "I1.HOST_1", "proxy.host takes IP, not HOST"),
        ("ti.lookup", "I1.USER_1", "ti.lookup takes IP or SITE, not USER"),
        ("proxy.host", "I1.IP_9", "I1.IP_9 is not an entity of this item"),
        ("proxy.host", "I1.IP_3", "not an address"),
        ("web.followups", "I1.IP_3", "not an address"),
        ("ti.lookup", "I1.IP_3", "not an address"),
        ("proxy.destination", "I1.IP_3", "not an address"),
    ],
)
def test_refusals(tool: str, token: str, reason: str) -> None:
    assert build(tool, token) == Refusal(reason)


def test_a_reveal_that_returns_the_token_is_refused() -> None:
    got = catalogue.build("ti.lookup", "I1.IP_1", lambda t: t, FACTS, NOW, CLASSIFIER)
    assert got == Refusal("I1.IP_1 is not an entity of this item")


def test_a_public_value_shown_in_the_item_may_be_named_as_it_is() -> None:
    text = "Entities: ip 8.8.8.8, evil.example; I1.IP_1"
    for entity in ("8.8.8.8", "evil.example"):
        got = catalogue.build("ti.lookup", entity, reveal, FACTS, NOW, CLASSIFIER, text)
        assert isinstance(got, TaskSpec)
    dest = catalogue.build("proxy.destination", "8.8.8.8", reveal, FACTS, NOW, CLASSIFIER, text)
    assert isinstance(dest, TaskSpec)
    assert catalogue.build("proxy.host", "evil.example", reveal, FACTS, NOW, CLASSIFIER, text) == (
        Refusal("proxy.host takes IP, not SITE")
    )


@pytest.mark.parametrize(
    "entity",
    ["9.9.9.9", "other.example", "8.8.8.8 OR 1", "8.8.8", "example", "I1.IP_1 ", "8.8.8.89",
     "vil.example", "", "a" * 300 + ".example"],
)  # fmt: skip
def test_anything_else_is_refused_before_a_query_is_built(entity: str) -> None:
    text = "Entities: ip 8.8.8.88, 8.8.8.8, evil.example"
    got = catalogue.build("ti.lookup", entity, reveal, FACTS, NOW, CLASSIFIER, text)
    assert isinstance(got, Refusal)
    assert got.reason == "name one entity of the item: its pseudonym, or a public address or domain"


def test_shown_is_whole_tokens() -> None:
    assert catalogue.shown("8.8.8.8", "to 8.8.8.8.")
    assert catalogue.shown("8.8.8.8", "(8.8.8.8)")
    assert not catalogue.shown("8.8.8.8", "8.8.8.80")
    assert not catalogue.shown("8.8.8.8", "18.8.8.8")
    assert not catalogue.shown("8.8.8.8", "8.8.8.8.1")
    assert not catalogue.shown("evil.example", "devil.example")


def test_refusals_and_tools_are_values() -> None:
    for value, attribute in ((Refusal("r"), "reason"), (catalogue.TOOLS["ti.lookup"], "name")):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(value, attribute, "x")
