"""Proxy heuristics of the generic pack, from the stored alerts only: what kind
of port a host used, how its requests were denied, and whether one address looks like many
users behind a NAT. Hints for a person, stated as such; never a verdict."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from argus.context.evidence import SignalValue, local, unknown

# Port classes (IANA and common use); a port in none of them is "other".
PORTS: tuple[tuple[str, frozenset[int] | range], ...] = (
    ("remote admin", frozenset({22, 23, 3389, 5900, 5901, 5938, 6568})),
    ("web", frozenset({80, 443, 8080, 8443, 8000, 8888})),
    ("mail", frozenset({25, 110, 143, 465, 587, 993, 995})),
    ("peer-to-peer", range(6881, 6890)),
    ("peer-to-peer", frozenset({1337, 6969, 51413, 4662, 4672})),
    ("gaming", frozenset({3074, 3478, 3479, 27015, 27016, 25565, 7777, 9987})),
    ("anonymizer or proxy", frozenset({9001, 9030, 9050, 9150, 1080, 3128})),
)
NAT_AGENTS = 8  # distinct user agents from one source in one investigation


def port_class(port: Any) -> str:
    try:
        number = float(str(port))
    except ValueError:
        return "other"
    if not number.is_integer():
        return "other"
    return next((name for name, ports in PORTS if int(number) in ports), "other")


def _shown(fact: Mapping[str, Any], complete: bool) -> str:
    """exact: every value of the field over every alert is in the facts; lower_bound: not."""
    whole = complete and fact.get("distinct", 0) <= len(fact.get("top", []))
    return "exact" if whole else "lower_bound"


def context(fields: Mapping[str, Any], complete: bool = True) -> dict[str, Any]:
    """Only the fields the alerts have: an absent field is not a zero."""
    out: dict[str, Any] = {}
    if "destination.port" in fields:
        fact = fields["destination.port"]
        classes: dict[str, int] = {}
        for port, n in fact.get("top", []):
            name = port_class(port)
            classes[name] = classes.get(name, 0) + int(n)
        out["port_classes"] = dict(sorted(classes.items()))
        out["ports_shown"] = _shown(fact, complete)
    if "event.action" in fields:
        fact = fields["event.action"]
        out["denied"] = {
            str(a): int(n) for a, n in fact.get("top", []) if "DENIED" in str(a).upper()
        }
        out["actions_shown"] = _shown(fact, complete)
    agents = fields.get("user_agent.original")
    sources = fields.get("source.ip", {})
    if agents:
        many = agents.get("distinct", 0) >= NAT_AGENTS and sources.get("distinct") == 1
        if many or complete:  # fewer agents over some of the alerts says nothing
            out["nat_hint"] = bool(many)
        out["agents"] = agents.get("distinct", 0)
    return out


def _count(name: str, version: int, value: int, shown: str | None) -> SignalValue:
    if shown is None:
        return unknown(name, version, "no_fields")
    if shown == "exact":
        return local(name, version, value)
    if value > 0:
        return SignalValue(name, version, value, "known", None, "lower_bound", ())
    return unknown(name, version, "partial_coverage")


RISKY = ("remote admin", "peer-to-peer", "anonymizer or proxy")


def signals(version: int, h: Mapping[str, Any]) -> list[SignalValue]:
    classes = h.get("port_classes", {})
    return [
        _count(
            "ports.risky", version, sum(n for name, n in classes.items() if name in RISKY),
            h.get("ports_shown"),
        ),
        _count("proxy.denied", version, sum(h.get("denied", {}).values()), h.get("actions_shown")),
        local("nat.hint", version, h["nat_hint"])
        if "nat_hint" in h
        else unknown("nat.hint", version, "no_fields"),
    ]  # fmt: skip


def summary(h: Mapping[str, Any]) -> list[str]:
    lines = []
    classes = h.get("port_classes", {})
    if classes:
        lines.append("Ports used: " + ", ".join(f"{name} ({n})" for name, n in classes.items()))
    if h.get("denied"):
        lines.append(
            "Denied by the proxy: " + ", ".join(f"{a} ({n})" for a, n in h["denied"].items())
        )
    if h.get("nat_hint"):
        lines.append(
            f"{h['agents']} different browsers or apps from one address: possibly"
            " several users behind a NAT"
        )
    return lines
