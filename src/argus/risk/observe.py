"""Step 1 of the engine (E1): an alert group, with its newest dossier's signals, becomes scored
**observations** inside **objects** (devices, accounts, own sites). A pure function: the
replay runs it unchanged.

- One **rule observation** per (object, alert group): the rule's lineage is the source, its
  severity (scaled by its risk score) the base, its tactics the stages, its index the family (for
  a rule that reads several families, the family of the group's own alerts' index).
- One **evidence observation** per (object, evidence kind) the dossier or the stored flags show
  (``config/risk.yaml``'s ``evidence``): a threat-list hit, an outside detection, a beacon...
- Objects come from the group's actor key: an internal address is a device, a host name a
  device, an account an account. An inbound group (an outside actor) puts its observations on
  the organisation's own **target** instead (a site); with no target named, on the sites the
  exposure step found for it (E3), and with none found it has no object and only the digest
  counts it. Outside things are threat values on the observation (linking is E2).
- A group a notified case holds as a known infection gives no observation (its case has it).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any, Literal

from argus.assets.classify import IpClass, IpClassifier
from argus.cases.membership import NO_SHARED, Shared
from argus.outside.psl import registered_parent
from argus.risk.config import RiskConfig, passes, stage_bit
from argus.risk.roles import (
    ACTOR_NAMESPACES,
    MAX_VALUE,
    OWN_CLASSES,
    Direction,
    RoleEntity,
    account,
    roles,
)
from argus.risk.rulemeta import RuleMeta, index_family, new_lineage
from argus.site import LogFamily

ObjectKind = Literal["device", "account", "site"]
ObsRole = Literal["actor", "target"]
OBJECT_KINDS: tuple[ObjectKind, ...] = ("device", "account", "site")
MAX_TARGETS = 16
# The host's own addresses (ECS): the only field a host alias is read from. ``source.ip`` and
# ``client.ip`` of a host's log are often the other party (a client that logged in to it).
HOST_ADDRESS = "host.ip"
IDENTITY_FIELDS = (HOST_ADDRESS,)  # read with the group's alerts, never an entity


@dataclass(frozen=True)
class Group:
    """An alert group as the engine reads it."""

    id: uuid.UUID
    version: int
    rule_id: str
    severity: str | None
    risk_score: float | None
    key: str  # the group key (canonical JSON of [field, value] pairs)
    first_at: datetime
    last_at: datetime
    alerts: int
    day: date  # the site's day of its bucket
    fields: Mapping[str, Sequence[object]] = field(default_factory=dict)  # ECS field -> values
    outcomes: Sequence[str] = ()  # "success" | "failure" per alert whose outcome is known
    signals: Mapping[str, Any] = field(default_factory=dict)  # known values, newest dossier
    flags: Sequence[str] = ()  # the stored raise flags
    known: bool = False  # held as a known infection by a notified case
    indices: Sequence[str] = ()  # the concrete indices its alerts were made from
    # the own sites an inbound group reached when its alerts name none (E3: its stored web
    # evidence, else the checking lane's lookup)
    sites: Sequence[str] = ()


@dataclass(frozen=True, order=True, slots=True)
class ObjectRef:
    kind: ObjectKind
    key: str


@dataclass(frozen=True, slots=True)
class Observation:
    object: ObjectRef
    role: ObsRole
    source_kind: Literal["rule", "evidence"]
    source_key: str
    group: uuid.UUID
    version: int
    at: datetime
    day: date
    base: float
    outcome: float
    stages: int
    family: str | None
    strong: bool
    threats: tuple[str, ...] = ()
    evidence: tuple[str, ...] = ()
    seen_at: datetime | None = None  # when the fact became known, if later (the replay's)


@dataclass(frozen=True)
class Observed:
    group: uuid.UUID
    direction: Direction
    outcome: float
    objects: tuple[ObjectRef, ...]
    observations: tuple[Observation, ...]
    entities: tuple[RoleEntity, ...]
    hubs: tuple[str, ...] = ()  # why internal actors were left out as hubs (identity, E4)
    aliases: tuple[tuple[ObjectRef, ObjectRef], ...] = ()  # (address, host) the group shows


@dataclass(frozen=True)
class Context:
    config: RiskConfig
    classifier: IpClassifier
    own_domains: Sequence[str] = ()
    fresh_feeds: frozenset[str] = frozenset({"mirror", "lookup"})  # modes with a fresh feed
    shared: Shared = NO_SHARED
    families: Sequence[LogFamily] = ()  # the site's log families
    # identity (E4): an address on a day -> its device and why it is a hub (None: plain address)
    devices: Callable[[str, date], tuple[ObjectRef, str | None]] | None = None


def key_pairs(key: str) -> list[tuple[str, list[str]]]:
    """The group key's (field, values) pairs; an unreadable key (a singleton) has none."""
    try:
        pairs = json.loads(key)
    except (ValueError, TypeError):
        return []
    out: list[tuple[str, list[str]]] = []
    if not isinstance(pairs, list):
        return out
    for pair in pairs:
        if isinstance(pair, list) and len(pair) == 2 and isinstance(pair[0], str):
            raw = pair[1] if isinstance(pair[1], list) else [pair[1]]
            out.append((pair[0], [str(v) for v in raw if isinstance(v, str | int | float)
                                  and not isinstance(v, bool)]))  # fmt: skip
    return out


def rule_base(config: RiskConfig, severity: str | None, risk_score: float | None) -> float:
    """The severity's base, scaled by the risk score over the severity's default (bounded)."""
    sev = (severity or "").lower()
    if sev not in config.severity_base:
        return config.unknown_severity_base
    base = config.severity_base[sev]
    if risk_score is None or risk_score <= 0:
        return base
    scale = risk_score / config.default_risk_score[sev]
    return base * min(config.risk_scale.max, max(config.risk_scale.min, scale))


def outcome_factor(outcomes: Sequence[str]) -> float:
    """Blocked or failed (every alert whose outcome is known says so): times 0.5; else times 1."""
    known = [o for o in outcomes if o in ("success", "failure")]
    return 0.5 if known and all(o == "failure" for o in known) else 1.0


def evidence_of(group: Group, ctx: Context) -> list[tuple[str, float, int, bool, tuple[str, ...]]]:
    """(kind, base, stages, strong, what showed it) for each evidence kind the group shows."""
    out = []
    flags = set(group.flags)
    for kind in ctx.config.evidence:
        held = tuple(
            sorted(
                [n for n, test in kind.signals.items()
                 if n in group.signals and passes(test, group.signals[n])]
                + [f for f in kind.flags if f in flags]
            )
        )  # fmt: skip
        if not held:
            continue
        base, strong = kind.base, kind.strong
        if kind.feeds:
            feeds = {kind.feeds[n] for n in held if n in kind.feeds}
            if feeds and not feeds & ctx.fresh_feeds:  # only a stale feed holds it
                base, strong = kind.stale_base or kind.base, False
        out.append((kind.kind, base, stage_bit(kind.stage), strong, held))
    return out


def _threats(entities: Sequence[RoleEntity], ctx: Context) -> tuple[str, ...]:
    """The outside things of the group as ``kind:value`` (a domain as its registered parent),
    shared infrastructure left out."""
    out: list[str] = []
    for e in entities:
        if e.role != "threat":
            continue
        kind, value = e.kind, e.value
        if kind == "domain":
            value = registered_parent(value) or value
        if kind in ("ip", "domain") and ctx.shared.reason(kind, value) is not None:
            continue
        item = f"{kind}:{value}"
        if item not in out:
            out.append(item)
    return tuple(sorted(out)[: ctx.config.max_threats])


def objects_of(
    group: Group, direction: Direction, entities: Sequence[RoleEntity], ctx: Context,
    hubs: list[str] | None = None,
) -> list[tuple[ObjectRef, ObsRole]]:  # fmt: skip
    """The group's internal objects and their role: its internal actors (addresses, hosts and
    accounts of the key, and the accounts that acted), or, for an inbound group, the own
    targets it names. A hub address (identity) is left out, its reason added to ``hubs``."""
    found: dict[ObjectRef, ObsRole] = {}
    limit = ctx.config.max_actors
    for name, raw in key_pairs(group.key):
        namespace = name.split(".", 1)[0]
        if namespace not in ACTOR_NAMESPACES | {"host"}:
            continue
        for value in raw:
            ref: ObjectRef | None = None
            if name.endswith(".ip"):
                c = ctx.classifier.classify(value)
                if c.address is not None and c.ip_class in OWN_CLASSES:
                    ref = ObjectRef("device", f"ip:{c.address}")
                    if ctx.devices is not None:
                        ref, hub = ctx.devices(c.address, group.day)
                        if hub is not None:
                            if hubs is not None and hub not in hubs:
                                hubs.append(hub)
                            continue
            elif namespace == "host":
                host = value.strip().lower()
                ref = ObjectRef("device", f"host:{host}") if 0 < len(host) <= MAX_VALUE else None
            elif namespace == "user" or name.endswith(".user.name") or name.endswith(".email"):
                acct = account(value)
                ref = ObjectRef("account", acct) if acct and direction != "inbound" else None
            if ref is not None and len(found) < limit:
                found.setdefault(ref, "actor")
    if direction != "inbound":
        for e in entities:
            if e.role == "actor" and e.kind in ("user", "email") and len(found) < limit:
                found.setdefault(ObjectRef("account", e.value), "actor")
        return list(found.items())
    targets = 0
    for e in entities:
        if e.role != "target" or e.kind not in ("ip", "domain", "host"):
            continue
        if targets >= MAX_TARGETS or len(found) >= limit:
            break
        prefix = {"ip": "ip", "domain": "domain", "host": "host"}[e.kind]
        ref = ObjectRef("site", f"{prefix}:{e.value}")
        if ref not in found:
            found[ref] = "target"
            targets += 1
    if not targets:  # no target named: the sites the exposure step found for it (E3)
        for site in group.sites[:MAX_TARGETS]:
            name = site.strip().rstrip(".").lower()
            if 0 < len(name) <= MAX_VALUE and len(found) < limit:
                found.setdefault(ObjectRef("site", f"domain:{name}"), "target")
    return list(found.items())


def observe(group: Group, rule: RuleMeta | None, ctx: Context) -> Observed:
    """The group's objects and observations (see the module's docstring)."""
    fields: dict[str, list[object]] = {k: list(v) for k, v in group.fields.items()}
    for name, raw in key_pairs(group.key):  # the key's values are the group's too
        fields.setdefault(name, [])
        fields[name] = list(dict.fromkeys([*raw, *fields[name]]))
    direction, entities = roles(fields, ctx.classifier, ctx.own_domains)
    outcome = outcome_factor(group.outcomes)
    if group.known:
        return Observed(group.id, direction, outcome, (), (), entities)
    hubs: list[str] = []
    objects = objects_of(group, direction, entities, ctx, hubs)
    lineage = rule.lineage if rule is not None else new_lineage(group.rule_id)
    stages = rule.stage_mask if rule is not None else 0
    family = rule.family if rule is not None else None
    if family is None:  # a rule over several families: the group's own alerts tell
        family = index_family(group.indices, ctx.families)
    base = rule_base(ctx.config, group.severity, group.risk_score)
    threats = _threats(entities, ctx)
    evidence = evidence_of(group, ctx)
    out: list[Observation] = []
    for ref, role in objects:
        out.append(Observation(
            ref, role, "rule", f"rule:{lineage}", group.id, group.version, group.last_at,
            group.day, base, outcome, stages, family, False, threats,
        ))  # fmt: skip
        for kind, ev_base, ev_stages, strong, held in evidence:
            out.append(Observation(
                ref, role, "evidence", f"ev:{kind}", group.id, group.version, group.last_at,
                group.day, ev_base, 1.0, ev_stages, None, strong, (), held,
            ))  # fmt: skip
    return Observed(
        group.id,
        direction,
        outcome,
        tuple(r for r, _ in objects),
        tuple(out),
        entities,
        tuple(hubs),
        host_aliases(objects, fields, group, ctx),
    )


def host_aliases(
    objects: Sequence[tuple[ObjectRef, ObsRole]], fields: Mapping[str, Sequence[object]],
    group: Group, ctx: Context,
) -> tuple[tuple[ObjectRef, ObjectRef], ...]:  # fmt: skip
    """(address, host) when the group's key names one host and its alerts give that host exactly
    one internal address of its own (``host.ip``): the host had that address that day (identity,
    E4). Never a peer's address: a login to a server names its client in ``source.ip``."""
    hosts = [r for r, role in objects if r.kind == "device" and r.key.startswith("host:")]
    if len(hosts) != 1:
        return ()
    addresses = {
        c.address for v in fields.get(HOST_ADDRESS, ())
        if (c := ctx.classifier.classify(v)).address is not None and c.ip_class in OWN_CLASSES
    }  # fmt: skip
    if len(addresses) != 1:
        return ()
    address = addresses.pop()
    ref = ObjectRef("device", f"ip:{address}")
    if ctx.devices is not None:
        ref, hub = ctx.devices(address, group.day)
        if hub is not None:
            return ()
    return ((ref, hosts[0]),)


def is_own(classifier: IpClassifier, value: str) -> bool:
    return classifier.classify(value).ip_class in OWN_CLASSES


def public(classifier: IpClassifier, value: str) -> bool:
    return classifier.classify(value).ip_class is IpClass.PUBLIC
