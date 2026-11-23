"""What the writer works out once from a case's facts, and the context it is given.

:class:`Scene` holds the case's shape in plain collections (internal devices, outside actors,
servers, rules, the span of its alerts, what is flagged and listed), so the parts of the report read
the same answers. Pure: no database, no clock."""

from __future__ import annotations

import ipaddress
import uuid
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from argus.assets.classify import IpClass, IpClassifier
from argus.incident import discover
from argus.incident import model as m
from argus.incident.gather import CaseFacts, MemberRow, OutsideRow
from argus.outside import facts as outside_facts
from argus.responder.catalogue import Catalogue
from argus.signins.view import Reading

FLAG_THRESHOLD = outside_facts.DEFAULT_THRESHOLD  # engines that make a detection
_INTERNAL = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)


@dataclass(frozen=True)
class Context:
    """What the writer needs besides the facts."""

    cfg: discover.Config
    as_at: datetime
    classifier: IpClassifier | None = None
    catalogue: Catalogue | None = None
    active_days: int = 3  # activity within this many days is "still going on"
    quiet_days: int = 14  # no activity this long: ARGUS proposes "stopped after notice"
    signins: Reading | None = None  # how the SSO sign-ins of the case's devices are read
    own_domains: tuple[str, ...] = ()  # a site under one of these is an internal web site


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def private(value: str) -> bool:
    """Private space (RFC 1918, IPv6 ULA): what an internal address is without an asset map."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(address.version == n.version and address in n for n in _INTERNAL)


def ours(value: str, classifier: IpClassifier | None) -> bool:
    """Whether ``value`` is an internal address (the asset map's, an internal prefix or private
    space)."""
    if classifier is not None:
        kind = classifier.classify(value).ip_class
        return kind in (IpClass.ASSET, IpClass.OWN, IpClass.INTERNAL)
    return private(value)


def first_of(values: Iterable[str]) -> str | None:
    for value in values:
        return value
    return None


def top(values: Iterable[str], n: int) -> list[str]:
    """The ``n`` commonest non-empty values (ties by name)."""
    counts = Counter(v for v in values if v)
    return [v for v, _ in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:n]]


@dataclass
class Scene:
    f: CaseFacts
    ctx: Context
    rules: dict[str, tuple[int, datetime, datetime]]  # rule -> (alerts, first, last)
    first: datetime | None
    last: datetime | None
    alerts: int
    standing: m.Standing
    devices: list[str]  # internal addresses the case names as actors
    outsiders: list[str]  # outside addresses the case names as actors
    servers: list[str]  # the case's command-and-control indicators
    members: dict[uuid.UUID, MemberRow]
    entity_of: dict[uuid.UUID, set[tuple[str, str]]]
    days_of: dict[uuid.UUID, set[str]]
    vt: dict[tuple[str, str], OutsideRow]
    flagged: list[str]  # indicators VirusTotal flags
    listed: list[str]  # indicators the local threat lists hold
    flag_counts: Counter[str]  # ARGUS's evidence flags, by investigations
    limits: list[str] = field(default_factory=list)

    @classmethod
    def of(cls, f: CaseFacts, ctx: Context) -> Scene:
        rules: dict[str, tuple[int, datetime, datetime]] = {}
        for d in f.days:
            n, lo, hi = rules.get(d.rule, (0, d.first, d.last))
            rules[d.rule] = (n + d.alerts, min(lo, d.first), max(hi, d.last))
        firsts = [d.first for d in f.days] or [x.first for x in f.members if x.first]
        lasts = [d.last for d in f.days] or [x.last for x in f.members if x.last]
        first = min(firsts) if firsts else None
        last = max(lasts) if lasts else None
        entity_of: dict[uuid.UUID, set[tuple[str, str]]] = defaultdict(set)
        for e in f.entities:
            entity_of[e.investigation_id].add((e.kind, e.value))
        days_of: dict[uuid.UUID, set[str]] = defaultdict(set)
        for inv_day in f.inv_days:
            days_of[inv_day.investigation_id].add(inv_day.day)
        actors = [i for i in f.indicators if i.role == "actor" and i.kind == "ip"]
        vt = {
            (o.kind, o.value): o
            for o in sorted(f.outside, key=lambda o: o.fetched_at)
            if o.source == outside_facts.VIRUSTOTAL and o.status == outside_facts.FOUND
        }  # the newest answer wins
        flagged = sorted(
            value
            for (_, value), o in vt.items()
            if outside_facts.flagged(o.source, o.status, o.answer, FLAG_THRESHOLD)
        )
        return cls(
            f=f,
            ctx=ctx,
            rules=rules,
            first=first,
            last=last,
            alerts=f.alerts_total or sum(x.alerts for x in f.members),
            standing=standing(last, ctx),
            devices=sorted({i.value for i in actors if ours(i.value, ctx.classifier)}),
            outsiders=sorted({i.value for i in actors if not ours(i.value, ctx.classifier)}),
            servers=sorted({i.value for i in f.indicators if i.role == "c2"}),
            members={x.id: x for x in f.members},
            entity_of=entity_of,
            days_of=days_of,
            vt=vt,
            flagged=flagged,
            listed=sorted({v for x in f.members for v in x.listed}),
            flag_counts=Counter(flag for x in f.members for flag in x.flags),
            limits=list(f.limits),
        )

    def vt_answer(self, value: str) -> Mapping[str, Any]:
        for kind in ("ip", "domain"):
            found = self.vt.get((kind, value))
            if found is not None:
                return found.answer
        return {}

    def members_naming(self, value: str) -> list[MemberRow]:
        """The member investigations that list ``value`` among their entities."""
        return [x for x in self.f.members if any(v == value for _, v in self.entity_of[x.id])]


def standing(last: datetime | None, ctx: Context) -> m.Standing:
    """Whether the activity is still going on: the last alert is within ``active_days``."""
    if last is None:
        return "unknown"
    return "ongoing" if ctx.as_at - last <= timedelta(days=ctx.active_days) else "quiet"
