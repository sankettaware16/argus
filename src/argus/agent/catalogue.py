"""The investigation agent's tools: an allowlist over the Elastic gateway's registered templates,
never a free-form query. A model asks for a tool and one entity *pseudonym*; ARGUS reveals the
value in memory and builds every parameter itself, with the packs' windows and bounds, and refuses
a request it cannot honour with a reason the model sees. The two ``outside.*`` tools are not
Elastic templates: they ask VirusTotal, or Shodan then Censys, through
``argus.outside.service.Outside``, which refuses internal indicators again."""

from __future__ import annotations

import re
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from argus import site
from argus.assets.classify import IpClass, IpClassifier
from argus.context import proxy, web
from argus.context.packs import TaskSpec
from argus.outside import facts as outside
from argus.reference.templates import LOOKUP_SIZE, TiLookup, lookup_params
from argus.reference.ti import variants

INTERNAL = frozenset({IpClass.ASSET, IpClass.CAMPUS, IpClass.INTERNAL})
# exactly one item's pseudonym (``I1.IP_2``), nothing around it
ENTITY = re.compile(r"I\d+\.(?:IP|MAC|SITE|HOST|USER|EMAIL|ID|HASH|CRED)_\d+")
# a public address or domain as the item shows it (the validator let it through: not internal)
LITERAL = re.compile(r"[0-9A-Fa-f:.]{3,45}|(?=.{4,253}$)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}")


@dataclass(frozen=True)
class Refusal:
    reason: str


@dataclass(frozen=True)
class OutsideAsk:
    """A lookup at outside threat intel: ``sources`` in the order to try them, for one external
    indicator (``kind``: ip or domain). Not an Elastic template."""

    sources: tuple[str, ...]
    kind: str
    value: str


Built = TaskSpec | Refusal | OutsideAsk


@dataclass(frozen=True)
class Tool:
    name: str
    domain: str  # the specialist that may use it: web, proxy, intel
    labels: frozenset[str]  # the pseudonym labels it takes (IP, SITE)
    describe: str  # what the model is told it does (``site.say`` tokens)
    build: Callable[[str, str, Mapping[str, Any], datetime, IpClassifier], Built]


def _ip_of(value: str, classifier: IpClassifier) -> tuple[str, IpClass] | Refusal:
    got = classifier.classify(value)
    if got.address is None:
        return Refusal("not an address")
    return got.address, got.ip_class


def _proxy(internal: bool) -> Callable[..., TaskSpec | Refusal]:
    def build(
        label: str, value: str, facts: Mapping[str, Any], now: datetime, c: IpClassifier
    ) -> TaskSpec | Refusal:
        found = _ip_of(value, c)
        if isinstance(found, Refusal):
            return found
        address, kind = found
        if internal and kind not in INTERNAL:
            return Refusal(f"proxy.host takes {site.a_own('address')}")
        if not internal and kind is not IpClass.PUBLIC:
            return Refusal("proxy.destination takes a public address")
        span = proxy.window(facts, now)
        if span is None:
            return Refusal("the proxy logs for this time are not ready or out of range")
        template = proxy.ProxyHost() if internal else proxy.ProxyDestination()
        return TaskSpec(template, proxy.WindowParams(ip=address, start=span[0], end=span[1]))

    return build


def _followups(
    label: str, value: str, facts: Mapping[str, Any], now: datetime, c: IpClassifier
) -> TaskSpec | Refusal:
    found = _ip_of(value, c)
    if isinstance(found, Refusal):
        return found
    span = web.follow_window(facts, now)
    if span is None:
        return Refusal("the web logs after the alert are not ready yet")
    return TaskSpec(web.WebFollowups(), web.FollowParams(ip=found[0], start=span[0], end=span[1]))


def _lookup(
    label: str, value: str, facts: Mapping[str, Any], now: datetime, c: IpClassifier
) -> TaskSpec | Refusal:
    lookups = site.active().ti_lookups
    if not lookups:
        return Refusal("the site names no threat-intel source to look in")
    if label == "IP":
        found = _ip_of(value, c)
        if isinstance(found, Refusal):
            return found
        terms = variants("ip", found[0])
    else:
        terms = variants("domain", value.lower().rstrip("."))
    return TaskSpec(TiLookup(), lookup_params(lookups, tuple(sorted(terms)), LOOKUP_SIZE))


def _outside(sources: tuple[str, ...]) -> Callable[..., Built]:
    def build(
        label: str, value: str, facts: Mapping[str, Any], now: datetime, c: IpClassifier
    ) -> Built:
        if label == "IP":
            found = _ip_of(value, c)
            if isinstance(found, Refusal):
                return found
            address, kind = found
            if kind is not IpClass.PUBLIC:
                return Refusal(
                    "outside lookups take a public address, never "
                    + site.a_own_or("one", "private")
                )
            return OutsideAsk(sources, "ip", address)
        name = outside.canonical("domain", value)
        if name is None:
            return Refusal("not a domain name")
        return OutsideAsk(sources, "domain", name)

    return build


def settled(body: Mapping[str, Any], value: str) -> bool:
    """The local threat lists already list ``value`` (an answer of the item's threat-intel check
    with a match), so an outside source adds nothing to whether it is bad."""
    node: Any = body
    for step in ("context", "pack", "ti", "answers"):
        node = node.get(step) if isinstance(node, Mapping) else None
    answers = node
    for answer in answers if isinstance(answers, list) else []:
        if not isinstance(answer, Mapping) or str(answer.get("value", "")).lower() != value.lower():
            continue
        sources = answer.get("sources")
        if isinstance(sources, Mapping) and any(
            isinstance(o, Mapping) and o.get("match") for o in sources.values()
        ):
            return True
    return False


TOOLS: dict[str, Tool] = {
    t.name: t
    for t in (
        Tool("proxy.host", "proxy", frozenset({"IP"}),
             "{a_own:host}'s proxy traffic in the alert's hours: top destinations, bytes,"
             " answers, and a 10-minute timeline", _proxy(internal=True)),
        Tool("proxy.destination", "proxy", frozenset({"IP"}),
             "a public destination's proxy traffic in the alert's hours: how many"
             " {own:hosts} reached it, which, and the top URLs", _proxy(internal=False)),
        Tool("web.followups", "web", frozenset({"IP"}),
             "a client's successful (2xx) web answers in the six hours after the first"
             " alert", _followups),
        Tool("ti.lookup", "intel", frozenset({"IP", "SITE"}),
             "the threat-intel lists for an address or a domain", _lookup),
        Tool("outside.reputation", "intel", frozenset({"IP", "SITE"}),
             "VirusTotal's reputation of an outside address or domain: how many of its engines"
             " flag it (a small daily allowance: only for an outside destination the threat lists"
             " do not already settle)", _outside((outside.VIRUSTOTAL,))),
        Tool("outside.server", "intel", frozenset({"IP"}),
             "what an outside address is, from Shodan and then Censys: open ports, software,"
             " names, who runs it, known CVEs (a small allowance: only for an outside address"
             " the threat lists do not already settle)",
             _outside((outside.SHODAN, outside.CENSYS))),
    )
}  # fmt: skip


def lines(names: Collection[str]) -> str:
    """What a model is told about the tools ``names`` names, one line each, in the
    catalogue's order whatever the order given."""
    return "\n".join(
        f"- {t.name} ({'/'.join(sorted(t.labels))}): {site.say(t.describe)}"
        for t in TOOLS.values()
        if t.name in names
    )


def shown(value: str, text: str) -> bool:
    """``value`` appears in ``text`` as a whole token."""
    return re.search(rf"(?<![\w.:-]){re.escape(value)}(?![\w:-]|\.\w)", text) is not None


def build(
    tool: str,
    entity: str,
    reveal: Callable[[str], str],
    facts: Mapping[str, Any],
    now: datetime,
    classifier: IpClassifier,
    text: str = "",
) -> Built:
    """The task for ``tool`` on ``entity``: a pseudonym of the item (revealed in memory
    only), or a public address or domain shown in ``text``, the rendering the model read."""
    spec = TOOLS.get(tool)
    if spec is None:
        return Refusal(f"no tool {tool!r}; tools: {', '.join(sorted(TOOLS))}")
    if ENTITY.fullmatch(entity):
        label = entity.split(".", 1)[-1].rsplit("_", 1)[0]
        if label not in spec.labels:  # checked before anything is revealed
            return Refusal(f"{tool} takes {' or '.join(sorted(spec.labels))}, not {label}")
        try:
            value = reveal(entity)
        except ValueError:
            return Refusal(f"{entity} is not an entity of this item")
        if value == entity:
            return Refusal(f"{entity} is not an entity of this item")
    elif LITERAL.fullmatch(entity) and shown(entity, text):
        label = "SITE" if classifier.classify(entity).address is None else "IP"
        value = entity
    else:
        return Refusal("name one entity of the item: its pseudonym, or a public address or domain")
    if label not in spec.labels:
        return Refusal(f"{tool} takes {' or '.join(sorted(spec.labels))}, not {label}")
    return spec.build(label, value, facts, now, classifier)
