"""An incident at a glance: the few numbers and the four small series that the Visualiser draws,
from the stored report and nothing else.

Both pictures (:mod:`argus.caseteam.visual` and :mod:`argus.incident.dashboard`) are made from the
same :class:`Glance`. Pure. Nothing here names a site, an index or a rule: which field a chart
splits on is decided by the *shape* of the case (outside addresses against internal sites or
servers, or internal devices reaching outside servers). A count and the panel under it come from
the same list, so they cannot disagree; every day from the first alert to the last has its bar
(a quiet day is a gap, never left out); fewer than two items are a list, not a chart. Names of
people never appear."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from math import ceil
from typing import Final

from argus import site
from argus.incident import model as m
from argus.incident.words import count

TOP = 10  # bars in an actors or targets chart
BARS_FROM = 2  # fewer items than this are drawn as a short list, not as a chart
RULE_ROWS = 20  # rows of the rules table
LISTED = "on the local threat lists"  # what a report indicator's evidence says of a listed one
ACTORS_AT = 25  # the report lists at most this many actors (parts.MAX_ACTORS)
RULES_AT = 12  # and at most this many rules in its timeline (parts.PHASES)
DAILY_UP_TO = 62  # a case this many days long or shorter is drawn day by day, a longer by weeks
MAX_BARS = 104  # never more bars than this: a longer case puts several weeks in a bar

ACTOR_IP = "source.ip"
ACTOR_HOST = "host.name"
SITE = "url.domain"
SERVER_IP = "destination.ip"
SERVER_DNS = "dns.question.name"
RULE = "kibana.alert.rule.name"
# the fields an actors or targets chart may split on: the report says which of them most of the
# case's alerts hold (``meta.carried``), so a live chart is never drawn over a field they lack
CHART_FIELDS: Final = (ACTOR_IP, ACTOR_HOST, SITE, SERVER_IP, SERVER_DNS)
ACTIVITY: Final = {"ongoing": "Still active", "quiet": "Quiet", "unknown": "Not known"}


@dataclass(frozen=True)
class Slice:
    """One bar or list item: a label the report shows, the alerts it stands for (None: the report
    names it but does not count its alerts) and what the report says of it."""

    label: str
    value: int | None
    note: str = ""


@dataclass(frozen=True)
class Layer:
    """One stacked series of the alerts-over-time chart: a rule (or all the rest)."""

    name: str
    values: tuple[int, ...]  # one for each bar of :attr:`Glance.days`


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
    targets: int  # the items :attr:`top_targets` is the top of
    targets_more: bool  # the report's list they come from was cut
    targets_word: str  # what a target is, singular: "site", "server", "target"
    targets_charted: bool  # a live chart over the targets field would draw every target
    listed: int  # indicators the local threat lists hold
    first: datetime | None
    last: datetime | None
    rules: int
    rules_more: bool
    shape: Shape
    step: int  # days in one bar of the alerts-over-time chart (1, 7, ...)
    days: tuple[str, ...]  # the local day each bar starts on, every one from the first to the last
    layers: tuple[Layer, ...]
    top_actors: tuple[Slice, ...]
    top_targets: tuple[Slice, ...]
    rule_rows: tuple[Slice, ...]
    severity: str  # the case's, capitalised
    call: str  # the verdict and whose it is, in words
    standing: m.Standing
    activity: str  # "Still active", "Quiet", "Not known"
    dwell: str  # first to last alert, in words
    carried: frozenset[str] | None  # of CHART_FIELDS, what most alerts hold (None: not known)

    @property
    def bucket(self) -> str:
        """What one bar of the alerts-over-time chart counts: ``day``, ``week``, ``14 days``."""
        return "day" if self.step == 1 else "week" if self.step == 7 else f"{self.step} days"

    def drawable(self, field: str | None) -> bool:
        """Whether a live chart split on ``field`` would draw the case's alerts (most of them hold
        it, or the report does not know)."""
        return field is not None and (self.carried is None or field in self.carried)


def bars(items: Sequence[Slice]) -> bool:
    """Whether a panel of these items is a bar chart: two or more, each with a count."""
    return len(items) >= BARS_FROM and all(s.value is not None for s in items)


def _people(actor: m.ReportActor) -> bool:
    return actor.kind == "user"


@dataclass(frozen=True)
class _Targets:
    """What a case's targets are, from one list of the report: what the count says and what the
    panel draws."""

    field: str | None
    title: str
    word: str
    items: tuple[Slice, ...]
    more: bool
    charted: bool = True  # a live chart over ``field`` would draw every item


def counted(
    items: Sequence[Slice], total: int, word: str, *, shared: bool = False
) -> tuple[Slice, ...]:
    """The items as the report counts them, or, when the counts overlap (one investigation names
    several of the items, so its alerts are counted under each: ``shared``, or the counts add up
    to more than the case's ``total`` alerts), named without a count and with what their
    investigations hold: bars or a ranking on such counts would draw alerts that are not there."""
    if not shared and (not total or sum(s.value or 0 for s in items) <= total):
        return tuple(items)
    out: list[Slice] = []
    for s in items:
        if s.value is None:
            out.append(s)
            continue
        held = f"in investigations of {_alerts(s.value)}, with other {word}s"
        out.append(Slice(s.label, None, "; ".join(x for x in (s.note, held) if x)))
    return tuple(out)


def _alerts(n: int) -> str:
    return f"{count(n)} {'alert' if n == 1 else 'alerts'}"


def _targets(report: m.IncidentReport) -> _Targets:
    """The case's targets, from the first of: the internal sites, else the internal servers, its
    outside actors went against (``report.targets``, counted by the alerts of the investigations
    that name each, and named without a count where those overlap: :func:`counted`); the
    internal sites its alerts' paths name (the directories, summed by site); the outside servers
    its devices reached (every command-and-control indicator, named, not counted: the domains
    first, on the field the queries of the report read them by; a list, not a live chart, when
    some are addresses and some names, as one chart splits on one field)."""
    hit = report.targets
    total = report.meta.alerts_total
    for kind, field, title, word in (
        ("site", SITE, "{Own:sites} reached", "site"),
        ("host", SERVER_IP, "{Own:servers} reached", "server"),
    ):
        chosen = [t for t in hit if t.kind == kind]
        if chosen:
            items = counted(
                [Slice(t.value, t.alerts, t.label or "") for t in chosen],
                total,
                word,
                shared=any(t.shared for t in chosen),
            )
            return _Targets(field, site.say(title), word, items, report.targets_total > len(hit))
    sites: dict[str, int] = defaultdict(int)
    for a in report.assets:
        if a.kind == "directory" and a.label:
            sites[a.label] += a.alerts
    if sites:
        items = counted([Slice(label, n) for label, n in sites.items()], total, "site")
        cut = report.assets_total > len(report.assets)
        return _Targets(SITE, site.say("{Own:sites} reached"), "site", items, cut)
    servers = list({i.value: i for i in report.indicators if i.role == "c2"}.values())
    servers.sort(key=lambda i: (i.kind != "domain", i.kind != "ip"))  # names, then addresses
    kinds = {i.kind for i in servers}
    if kinds <= {"ip"}:
        field = SERVER_IP
    else:
        field = SERVER_DNS if any(SERVER_DNS in q.text for q in report.queries) else SITE
    if servers:
        items = tuple(Slice(i.value, None, i.evidence) for i in servers)
        cut = report.indicators_total > len(report.indicators)
        one = len(kinds) == 1 and kinds <= {"domain", "ip"}
        return _Targets(field, "Servers reached", "server", items, cut, one)
    return _Targets(None, "Targets", "target", (), False)


def shape_of(report: m.IncidentReport) -> Shape:
    """The case's shape, from the report's own fields. Actors are split on the address (an
    outside attacker or an internal device: both are ``source.ip`` in the alerts) or, when every
    actor is a host, on the host name. Targets follow :func:`_targets`: ``url.domain`` for sites,
    ``destination.ip`` for servers by address, the DNS name when the report's own queries read
    DNS."""
    actors = [a for a in report.actors if not _people(a)]
    outside = any(not a.inside for a in actors)
    if not actors:
        actors_field, actors_title = None, "Top actors"
    elif all(a.kind == "host" for a in actors):
        actors_field, actors_title = ACTOR_HOST, "Top hosts"
    else:
        actors_field = ACTOR_IP
        actors_title = "Top outside addresses" if outside else f"Top {site.own('devices')}"
    found = _targets(report)
    return Shape(actors_field, actors_title, found.field, found.title)


def _ranked(items: Iterable[Slice], n: int) -> tuple[Slice, ...]:
    """The first ``n``: the biggest first (ties by name) when every item is counted, else in the
    report's own order."""
    listed = list(items)
    if all(s.value is not None for s in listed):
        listed.sort(key=lambda s: (-(s.value or 0), s.label))
    return tuple(listed[:n])


def _series(t: m.ReportTimeline) -> tuple[int, tuple[str, ...], tuple[Layer, ...]]:
    """(days a bar, the day each bar starts, the layers): every local day from the first alert's
    to the last's, a day with no alert a bar of zero; a case longer than :data:`DAILY_UP_TO` days
    by weeks (several weeks a bar past :data:`MAX_BARS` of them)."""
    width = len(t.columns)
    by_day: dict[date, list[int]] = {}
    try:
        for d in t.days:
            row = by_day.setdefault(date.fromisoformat(d.day), [0] * width)
            for i in range(width):
                row[i] += d.counts[i] if i < len(d.counts) else 0
    except ValueError:  # a day the calendar does not have: drawn as the report lists them
        layers = tuple(
            Layer(name, tuple(d.counts[i] if i < len(d.counts) else 0 for d in t.days))
            for i, name in enumerate(t.columns)
        )
        return 1, tuple(d.day for d in t.days), layers
    if not by_day:
        return 1, (), tuple(Layer(name, ()) for name in t.columns)
    start = min(by_day)
    span = (max(by_day) - start).days + 1
    step = 1 if span <= DAILY_UP_TO else 7 * max(1, ceil(span / (7 * MAX_BARS)))
    sums = [[0] * width for _ in range(0, span, step)]
    for day, counts in by_day.items():
        bar = sums[(day - start).days // step]
        for i, n in enumerate(counts):
            bar[i] += n
    days = tuple((start + timedelta(days=k * step)).isoformat() for k in range(len(sums)))
    return (
        step,
        days,
        tuple(Layer(name, tuple(b[i] for b in sums)) for i, name in enumerate(t.columns)),
    )


def call_of(verdict: m.ReportVerdict) -> str:
    """The verdict in words and whose it is: a person's (only when people reviewed every one of
    the case's investigations, else how many they reviewed), or ARGUS's own (with how sure it
    is), never a bare "true positive" on a case no person has decided."""
    if verdict.outcome is None:
        return "No call yet"
    words = verdict.words.removeprefix("a ")
    words = words[:1].upper() + words[1:]
    if verdict.kind == "person":
        every, done = verdict.investigations, verdict.reviewed
        if not every:  # a report written before it was counted: how many is not known
            return f"{words} (from people's reviews)"
        if done < every:
            return f"{words} (people reviewed {count(done)} of {count(every)} investigations)"
        return f"{words} (a person's verdict)"
    if verdict.kind == "case":
        return f"{words} (a person confirmed the case)"
    sure = "" if verdict.confidence is None else f", {round(verdict.confidence * 100)}% sure"
    who = "ARGUS's reading" if verdict.kind == "reading" else "ARGUS's call"
    return f"{words}{sure} ({who}, not confirmed by a person)"


def carried_of(docs: Iterable[Mapping[str, Sequence[str]]]) -> tuple[str, ...] | None:
    """Of :data:`CHART_FIELDS`, the ones at least half of the alert documents hold a value of
    (None when there is no document to tell)."""
    rows = list(docs)
    if not rows:
        return None
    return tuple(
        f
        for f in CHART_FIELDS
        if 2 * sum(1 for d in rows if any(str(v).strip() for v in d.get(f, ()))) >= len(rows)
    )


def glance_of(report: m.IncidentReport) -> Glance:
    shape = shape_of(report)
    t = report.timeline
    actors = [a for a in report.actors if not _people(a)]
    found = _targets(report)
    phases = sorted(t.phases, key=lambda p: (-p.alerts, p.name))
    step, days, layers = _series(t)
    carried = report.meta.carried
    return Glance(
        alerts=report.meta.alerts_total,
        actors=len(actors),
        actors_more=len(report.actors) >= ACTORS_AT,
        targets=len(found.items),
        targets_more=found.more,
        targets_word=found.word,
        targets_charted=found.charted,
        listed=sum(1 for i in report.indicators if LISTED in i.evidence),
        first=report.header.first_alert_at,
        last=report.header.last_alert_at,
        rules=len(phases),
        rules_more=len(phases) >= RULES_AT,
        shape=shape,
        step=step,
        days=days,
        layers=layers,
        top_actors=_ranked(
            counted(
                [Slice(a.value, a.alerts) for a in actors if a.alerts > 0],
                report.meta.alerts_total,
                "actor",
            ),
            TOP,
        )
        if shape.actors_field
        else (),
        top_targets=_ranked(found.items, TOP) if shape.targets_field else (),
        rule_rows=tuple(Slice(p.name, p.alerts) for p in phases[:RULE_ROWS]),
        severity=report.header.severity.capitalize(),
        call=call_of(report.verdict),
        standing=report.summary.standing,
        activity=ACTIVITY.get(report.summary.standing, "Not known"),
        dwell=t.dwell_words or "Not known",
        carried=None if carried is None else frozenset(carried),
    )


def more(n: int, capped: bool) -> str:
    """A count the report may have cut: ``25+``."""
    return f"{n}+" if capped else str(n)
