"""An incident at a glance: the few numbers and the four small series that the Visualiser draws,
from the stored report and nothing else.

Both pictures (:mod:`argus.caseteam.visual` and :mod:`argus.incident.dashboard`) are made from the
same :class:`Glance`. Pure. Nothing here names a site, an index or a rule: which field a chart
splits on is decided by the *shape* of the case (outside addresses against internal servers, or
internal devices reaching outside servers). Names of people never appear."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime

from argus import site
from argus.incident import model as m

TOP = 10  # bars in an actors or targets chart
RULE_ROWS = 20  # rows of the rules table
LISTED = "on the local threat lists"  # what a report indicator's evidence says of a listed one
ACTORS_AT = 25  # the report lists at most this many actors (parts.MAX_ACTORS)
RULES_AT = 12  # and at most this many rules in its timeline (parts.PHASES)

ACTOR_IP = "source.ip"
ACTOR_HOST = "host.name"
SITE = "url.domain"
SERVER_IP = "destination.ip"
SERVER_DNS = "dns.question.name"
RULE = "kibana.alert.rule.name"


@dataclass(frozen=True)
class Slice:
    """One bar: a label the report shows and the alerts it stands for."""

    label: str
    value: int


@dataclass(frozen=True)
class Layer:
    """One stacked series of the alerts-over-time chart: a rule (or all the rest)."""

    name: str
    values: tuple[int, ...]  # one for each day of :attr:`Glance.days`


@dataclass(frozen=True)
class Shape:
    """What a case's charts split on. ``None`` for a field: the case has no such thing to draw."""

    actors_field: str | None
    actors_title: str
    targets_field: str | None
    targets_title: str


@dataclass(frozen=True)
class Glance:
    alerts: int
    actors: int
    actors_more: bool  # the report lists only its first 25
    targets: int
    targets_word: str  # what a target is, singular: "site", "server", "device"
    listed: int  # indicators the local threat lists hold
    first: datetime | None
    last: datetime | None
    rules: int
    rules_more: bool
    shape: Shape
    days: tuple[str, ...]  # local days (``2026-10-15``) of the alerts-over-time chart
    layers: tuple[Layer, ...]
    top_actors: tuple[Slice, ...]
    top_targets: tuple[Slice, ...]
    rule_rows: tuple[Slice, ...]


def _people(actor: m.ReportActor) -> bool:
    return actor.kind == "user"


def shape_of(report: m.IncidentReport) -> Shape:
    """The case's shape, from the report's own fields. Actors are split on the address (an
    outside attacker or an internal device: both are ``source.ip`` in the alerts) or, when every
    actor is a host, on the host name. Targets are the internal sites the alerts name
    (``url.domain``) when the report names sites, else the servers the devices reached
    (``destination.ip``, or the DNS name when the report's own queries read DNS)."""
    actors = [a for a in report.actors if not _people(a)]
    outside = any(not a.inside for a in actors)
    if not actors:
        actors_field, actors_title = None, "Top actors"
    elif all(a.kind == "host" for a in actors):
        actors_field, actors_title = ACTOR_HOST, "Top hosts"
    else:
        actors_field = ACTOR_IP
        actors_title = "Top outside addresses" if outside else f"Top {site.own('devices')}"
    if any(a.kind == "directory" and a.label for a in report.assets):
        targets_field, targets_title = SITE, site.say("{Own:sites} reached")
    else:
        servers = [i for i in report.indicators if i.role == "c2"]
        if not servers:
            targets_field, targets_title = None, "Targets"
        elif any(i.kind == "domain" for i in servers):
            dns = any(SERVER_DNS in q.text for q in report.queries)
            targets_field, targets_title = (SERVER_DNS if dns else SITE), "Servers reached"
        else:
            targets_field, targets_title = SERVER_IP, "Servers reached"
    return Shape(actors_field, actors_title, targets_field, targets_title)


def _top(counts: dict[str, int], n: int) -> tuple[Slice, ...]:
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return tuple(Slice(label, value) for label, value in ranked[:n] if value > 0)


def _targets(report: m.IncidentReport, shape: Shape) -> dict[str, int]:
    """Alerts by target, from the report's assets: the internal sites (the alerts' directories,
    summed by site) or the servers its devices reached (the devices' alerts, summed by the name
    each reached)."""
    counts: dict[str, int] = defaultdict(int)
    if shape.targets_field == SITE and any(a.kind == "directory" for a in report.assets):
        for a in report.assets:
            if a.kind == "directory" and a.label:
                counts[a.label] += max(a.alerts, 1)
    elif shape.targets_field is not None:
        for a in report.assets:
            if a.kind == "device" and a.label:
                counts[a.label] += max(a.alerts, 1)
    return dict(counts)


def _target_count(report: m.IncidentReport, shape: Shape, drawn: dict[str, int]) -> tuple[int, str]:
    if shape.targets_field == SITE and drawn:
        return len(drawn), "site"
    servers = {i.value for i in report.indicators if i.role == "c2"}
    if servers:
        return len(servers), "server"
    devices = sum(1 for a in report.assets if a.kind == "device")
    return devices, "device"


def glance_of(report: m.IncidentReport) -> Glance:
    shape = shape_of(report)
    t = report.timeline
    actors = [a for a in report.actors if not _people(a)]
    drawn = _targets(report, shape)
    targets, word = _target_count(report, shape, drawn)
    phases = sorted(t.phases, key=lambda p: (-p.alerts, p.name))
    return Glance(
        alerts=report.meta.alerts_total,
        actors=len(actors),
        actors_more=len(report.actors) >= ACTORS_AT,
        targets=targets,
        targets_word=word,
        listed=sum(1 for i in report.indicators if LISTED in i.evidence),
        first=report.header.first_alert_at,
        last=report.header.last_alert_at,
        rules=len(phases),
        rules_more=len(phases) >= RULES_AT,
        shape=shape,
        days=tuple(d.day for d in t.days),
        layers=tuple(
            Layer(name, tuple(d.counts[i] if i < len(d.counts) else 0 for d in t.days))
            for i, name in enumerate(t.columns)
        ),
        top_actors=_top({a.value: a.alerts for a in actors if a.alerts > 0}, TOP)
        if shape.actors_field
        else (),
        top_targets=_top(drawn, TOP) if shape.targets_field else (),
        rule_rows=tuple(Slice(p.name, p.alerts) for p in phases[:RULE_ROWS]),
    )


def more(n: int, capped: bool) -> str:
    """A count the report may have cut: ``25+``."""
    return f"{n}+" if capped else str(n)
