"""The incident replay of the engine v2 (``scripts/replay_incidents.py --engine v2``, P4-F E0):
step a clock through a window of a copy's stored alert groups and measure, per day of the site's
zone, what the shadow engine would put in front of a person, beside today's pipeline.

It reads the copy and writes nothing (one read-only transaction). Every alert group of the window
is read through the engine's own path (:func:`argus.risk.store.groups`) and observed once
(:func:`argus.risk.observe.observe`), so **the flags of every group are derived again** from its
newest dossier, whatever today's raise step read. At each step the groups ARGUS held by then are
visible: a group from its first stored alert (``first_seen_at``, never before its first event),
an open group's observations at the clock, not its future. Every active object is scored with
the pass's own code (:func:`argus.risk.run.evaluate_all`).

Three modes bound what the copy cannot know:

- ``db`` (lower bound): only what the copy holds, each fact from when the copy knew it: an
  outside detection from the time the cache fetched it, and an operator or campaign tie (set by
  the campaign analysis, after the dossier) from the stored flags' last evaluation, a late bound;
- ``oracle`` (upper bound): the VirusTotal answers of ``--outside-answers`` and the cache, known
  from the first step (marked invented where hand-made), and the operator and campaign ties
  with them;
- ``no-vt``: no outside detection and no operator tie, to show what the engine finds without
  VirusTotal.

Baseline columns from the same groups: today's pipeline (Needs attention by rule severity or a
raise, judged by the stored flags as measured, and again with the flags derived here; plus the
suggested cases the copy made), severity only, and plain 1-day throttling (every alert group).

Approximations (said in the report): a group is seen, from its first stored alert, with its
newest dossier and its final alerts; the stored operator and campaign flags are their final state
(in ``db`` mode from their last evaluation); a feed counts as fresh at a group's time unless its
newest indicator was already older then; rules' metadata is read from their newest stored
alert."""

from __future__ import annotations

import json
import statistics
import time
import uuid
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus import site
from argus.assess import raised
from argus.assets.classify import IpClassifier
from argus.cases.membership import Shared
from argus.context.paths import same_file
from argus.evaluation import gold
from argus.grouping import assign
from argus.outside import facts as outside_facts
from argus.outside.psl import registered_parent
from argus.risk import checking, exposure, exposure_db, rulemeta, run, score, store, webchecks
from argus.risk.config import RiskConfig
from argus.risk.observe import Context, Group, ObjectRef, Observation, observe
from argus.site import LogFamily

MODES = ("db", "oracle", "no-vt")
BATCH = 1000
STABLE = (date(2026, 10, 26), date(2026, 11, 3))  # measure.md's window with today's pipeline live
OUTSIDE = raised.OUTSIDE
OPERATOR = raised.OPERATOR
CAMPAIGN = raised.CAMPAIGN
# The flags the campaign analysis adds after a dossier: in db mode a fact they alone hold counts
# from the stored flags' last evaluation (adding one moves it), not from the group's first alert.
LATE_FLAGS = frozenset({OPERATOR, CAMPAIGN})
# When the copy knew a group: its stored flags' last evaluation (current version) and the first
# of its alerts ARGUS stored.
_KNOWN_AT = text(
    "SELECT u.id, (SELECT r.evaluated_at FROM investigation_raises r JOIN investigations i"
    "  ON i.id = r.investigation_id AND i.version = r.version"
    "  WHERE r.investigation_id = u.id) AS raised_at,"
    " (SELECT min(a.first_seen_at) FROM investigation_alerts l JOIN alert_records a"
    "  ON a.alert_id = l.alert_id WHERE l.investigation_id = u.id) AS stored_at"
    " FROM unnest(CAST(:ids AS uuid[])) AS u(id)"
)


@dataclass(frozen=True)
class GroupMeta:
    id: uuid.UUID
    first_at: datetime
    last_at: datetime
    end: datetime  # the end of its bucket (the day it is counted on is over), or its arrival
    day: date
    alerts: int
    severity: str | None
    direction: str
    outcome: float
    known_at: datetime | None  # when a notified case's known-infection step took it, if ever
    kinds: tuple[str, ...]
    stored_flags: tuple[str, ...]
    derived_flags: tuple[str, ...]
    objects: tuple[ObjectRef, ...]
    arrived: datetime  # when ARGUS first held one of its alerts (never before its first event)
    sources: tuple[str, ...] = ()  # E3: an inbound group's outside addresses
    answers: tuple[tuple[str, str, int | None], ...] = ()  # E3: its stored 2xx answers
    rule: str = ""


@dataclass
class Loaded:
    groups: dict[uuid.UUID, GroupMeta] = field(default_factory=dict)
    observations: list[Observation] = field(default_factory=list)
    first_alert: dict[str, datetime | None] = field(default_factory=dict)
    verdicts: list[tuple[datetime, uuid.UUID]] = field(default_factory=list)
    cases: list[datetime] = field(default_factory=list)
    domains: dict[uuid.UUID, set[str]] = field(default_factory=dict)
    seconds: float = 0.0
    detections: Found = field(default_factory=dict)  # the mode's outside detections (E2)


Found = dict[tuple[str, str], tuple[datetime | None, bool]]


def _detections(rows: Sequence[Any], threshold: int) -> Found:
    """(kind, indicator) -> (when it was known, whether it is a parent the names under it
    inherit) for VirusTotal answers of at least ``threshold`` engines."""
    out: Found = {}
    for kind, indicator, answer, fetched in rows:
        if not isinstance(answer, Mapping):
            continue
        try:
            malicious = int(answer.get("malicious") or 0)
        except (TypeError, ValueError):
            continue
        if malicious < threshold:
            continue
        inherit = kind == "domain" and answer.get("ranked") is False
        held = out.get((kind, indicator))
        if held is None or (fetched is not None and (held[0] is None or fetched < held[0])):
            out[(kind, indicator)] = (fetched, inherit)
    return out


def timed(
    o: Observation, mode: str, first_at: datetime, outside_at: datetime | None,
    raised_at: datetime | None,
) -> Observation:  # fmt: skip
    """An observation with the time its fact became known, when later than the group's first
    alert: an outside detection from ``outside_at`` (the cache's fetch); in db mode a fact only
    late flags hold (an operator or campaign tie) from ``raised_at`` (the stored flags' last
    evaluation). Oracle mode knows both from the start; no-vt has neither."""
    if outside_at is not None and outside_at > first_at and o.source_key == "ev:outside":
        o = replace(o, seen_at=outside_at)
    if (mode == "db" and raised_at is not None and raised_at > first_at
            and o.source_kind == "evidence" and o.evidence
            and set(o.evidence) <= LATE_FLAGS):  # fmt: skip
        o = replace(o, seen_at=max(raised_at, o.seen_at or raised_at))
    return o


EXPOSURE_KEYS = frozenset(f"ev:{k}" for k in exposure.SIGNALS)
OracleFacts = dict[tuple[str, date], list[tuple[exposure.PairFacts, datetime | None]]]


def oracle_facts(answers: Sequence[Mapping[str, Any]], config: RiskConfig) -> OracleFacts:
    """The oracle's answers of the checking lane, by (source, UTC day): each ``{source, site,
    day, at?, served?: [paths], bulk?: n, prefix?, shared?: [paths]}`` (``at``: when the lane
    would have answered; none: from the start)."""
    out: OracleFacts = defaultdict(list)
    for item in answers:
        source, where = str(item.get("source") or ""), str(item.get("site") or "").lower()
        day = item.get("day")
        if not source or not where or day is None:
            continue
        day = day if isinstance(day, date) else date.fromisoformat(str(day))
        at = item.get("at")
        when = (at if isinstance(at, datetime) else datetime.fromisoformat(str(at))) if at else None
        facts = exposure.PairFacts(
            source, where, served=tuple(str(p) for p in item.get("served") or ()),
            bulk=int(item.get("bulk") or 0), bulk_prefix=item.get("prefix"),
            shared=tuple(str(p) for p in item.get("shared") or ()),
        )  # fmt: skip
        out[(source, day)].append((facts, when.astimezone(UTC) if when else None))
    return out


def _oracle(g: Group, sources: Sequence[str], oracle: OracleFacts,
            config: RiskConfig) -> tuple[Group, datetime | None]:  # fmt: skip
    """``g`` with the oracle's facts of its sources on its day (and the time they were known)."""
    day = g.last_at.astimezone(UTC).date()
    facts: dict[tuple[str, str], exposure.PairFacts] = {}
    times: list[datetime] = []
    for src in sources:
        for item, at in oracle.get((src, day), ()):
            facts[(item.source, item.site)] = item
            if at is not None:
                times.append(at)
    if not facts:
        return g, None
    named = [str(v) for v in g.fields.get("url.domain", ()) if isinstance(v, str)]
    evidence = [(s, "", None) for s in g.sites]
    sites_of = exposure.group_sites(sources, day, named, evidence, {}, facts,
                                    timedelta(days=config.exposure.window_days))  # fmt: skip
    if not sites_of.signals:
        return g, None
    sites = sites_of.sites or tuple(dict.fromkeys(site for (_, site) in facts))
    return replace(g, sites=sites, signals={**g.signals, **sites_of.signals}), max(
        times, default=None
    )


def _checked(o: Observation, answer_at: datetime | None) -> Observation:
    """An exposure fact known from when the checking lane would have answered."""
    if answer_at is None or o.source_key not in EXPOSURE_KEYS or answer_at <= o.at:
        return o
    return replace(o, seen_at=max(answer_at, o.seen_at or answer_at))


def detected_at(
    values: Sequence[tuple[str, str]], found: Mapping[tuple[str, str], tuple[datetime | None, bool]]
) -> tuple[bool, datetime | None]:  # fmt: skip
    """Whether one of a group's indicators (or a domain's registered parent, when its answer may
    be inherited) is a detection, and the earliest time it was known (None: from the start)."""
    times: list[datetime | None] = []
    for kind, value in values:
        hit = found.get((kind, value))
        if hit is not None:
            times.append(hit[0])
        if kind == "domain":
            parent = registered_parent(value)
            if parent and parent != value:
                hit = found.get(("domain", parent))
                if hit is not None and hit[1]:
                    times.append(hit[0])
    if not times:
        return False, None
    if any(t is None for t in times):
        return True, None
    return True, min(t for t in times if t is not None)


async def _rules(
    conn: AsyncConnection, families: Sequence[LogFamily], now: datetime
) -> dict[str, rulemeta.RuleMeta]:
    """Every rule's metadata, derived in memory (the copy need not hold the engine's columns)."""
    rows = (await conn.execute(text("SELECT rule_id, name, first_alert_at FROM rules"))).all()
    lineages = rulemeta.assign_lineages(
        [rulemeta._Row(r.rule_id, r.name, None, r.first_alert_at) for r in rows]
    )
    first: dict[str, datetime | None] = {}
    for r in rows:
        lineage = lineages[r.rule_id]
        held = first.get(lineage)
        if r.first_alert_at is not None and (held is None or r.first_alert_at < held):
            first[lineage] = r.first_alert_at
    out = {}
    for r in rows:
        found = (await conn.execute(rulemeta._META, {"rule": r.rule_id, "now": now})).first()
        stages, family = 0, None
        if found is not None:
            tactics, indices, _ = rulemeta.meta_from(found.fields, found.ancestors)
            stages = rulemeta.stage_mask(tactics)
            family = rulemeta.family_of(indices, families)
        lineage = lineages[r.rule_id]
        out[r.rule_id] = rulemeta.RuleMeta(r.rule_id, lineage, stages, family, first.get(lineage))
    return out


async def load(
    conn: AsyncConnection, *, start: datetime, end: datetime, mode: str, config: RiskConfig,
    classifier: IpClassifier, families: Sequence[LogFamily], campus_domains: Sequence[str],
    feed_modes: dict[str, str], shared: Shared, answers: Mapping[str, Any] | None,
    threshold: int = 3, exposure_answers: Sequence[Mapping[str, Any]] | None = None,
    devices: Callable[[str, date], tuple[ObjectRef, str | None]] | None = None,
) -> Loaded:  # fmt: skip
    """Every alert group the window needs (and the 14 days before it), observed once. In oracle
    mode ``exposure_answers`` are what the checking lane would have found (E3: no log of the
    window is left to check), known from each answer's ``at``."""
    started = time.perf_counter()
    out = Loaded()
    oracle = oracle_facts(exposure_answers or (), config)
    lo = start - config.windows["14d"].span
    rules = await _rules(conn, families, end)
    out.first_alert = {f"rule:{m.lineage}": m.first_alert_at for m in rules.values()}
    feeds = [tuple(r) for r in (await conn.execute(text("SELECT source, newest FROM ti_sources")))]
    cache = (
        await conn.execute(
            text(
                "SELECT kind, indicator, answer, fetched_at FROM outside_lookups"
                " WHERE source = 'virustotal' AND status = 'found'"
            )
        )
    ).all()
    found = _detections([tuple(r) for r in cache], threshold) if mode != "no-vt" else {}
    if mode == "oracle":
        found = {k: (None, v[1]) for k, v in found.items()}
        for value, answer in (answers or {}).items():
            kind = "ip" if outside_facts.canonical("ip", value) else "domain"
            indicator = outside_facts.canonical(kind, value)
            if indicator is not None:
                found.update(_detections([(kind, indicator, answer, None)], threshold))
    out.detections = found
    ids = [
        r.id
        for r in await conn.execute(
            text(
                "SELECT id FROM investigations WHERE last_event_at >= :lo"
                " AND first_event_at <= :hi ORDER BY id"
            ),
            {"lo": lo, "hi": end},
        )
    ]
    names = sorted({n for kind in config.evidence for n in kind.signals})
    known = {
        r.investigation_id: r.decided_at
        for r in await conn.execute(
            text(
                "SELECT investigation_id, min(decided_at) AS decided_at FROM case_known_matches"
                " WHERE outcome = 'known' GROUP BY 1"
            )
        )
    }
    for n in range(0, len(ids), BATCH):
        batch = ids[n : n + BATCH]
        values: dict[uuid.UUID, list[tuple[str, str]]] = defaultdict(list)
        for row in await conn.execute(
            text(
                "SELECT investigation_id, kind, value FROM investigation_entities"
                " WHERE investigation_id = ANY(CAST(:ids AS uuid[])) AND kind IN ('ip', 'domain')"
            ),
            {"ids": batch},
        ):
            values[row.investigation_id].append((row.kind, row.value))
        known_at = {r.id: (r.raised_at, r.stored_at)
                    for r in await conn.execute(_KNOWN_AT, {"ids": batch})}  # fmt: skip
        stored_answers = await exposure_db.followups(conn, batch)
        # without the incident evidence (D-323): it was asked after the fact, for presented
        # incidents only, and carries no time a step could honour
        for g in await store.groups(conn, batch, names, exposure=config.exposure, measured=False):
            sources = tuple(exposure_db.outside_sources(g))
            answer_at: datetime | None = None
            if mode == "oracle" and oracle and sources:
                g, answer_at = _oracle(g, sources, oracle, config)
            out.domains[g.id] = {v for k, v in values[g.id] if k == "domain"}
            hit, flagged_at = detected_at(values[g.id], found)
            flags = [f for f in g.flags if f != OUTSIDE]
            if mode == "no-vt":
                flags = [f for f in flags if f not in (OPERATOR, CAMPAIGN)]
            elif hit:
                flags.append(OUTSIDE)
            g2 = replace(g, flags=tuple(flags), known=False)  # known from its decision on
            fresh = run.fresh_feeds(feeds, g.last_at, config.feed_fresh_days, feed_modes)
            fresh = fresh or frozenset(  # a feed updated since may well have been fresh then
                feed_modes[s]
                for s, newest in feeds
                if s in feed_modes and newest and newest > g.last_at
            )  # fmt: skip
            ctx = Context(config, classifier, campus_domains, fresh, shared, families, devices)
            seen = observe(g2, rules.get(g.rule_id), ctx)
            raised_at, stored_at = known_at.get(g.id, (None, None))
            outside_at = flagged_at if hit else None
            out.observations.extend(
                _checked(timed(o, mode, g.first_at, outside_at, raised_at), answer_at)
                for o in seen.observations
            )
            arrived = max(g.first_at, stored_at) if stored_at is not None else g.first_at
            body = {"signals": [{"name": k, "status": "known", "value": v}
                                for k, v in g.signals.items()]}  # fmt: skip
            derived = list(gold.flags(body))
            derived += [f for f in flags if f in (OUTSIDE, OPERATOR, CAMPAIGN) and f not in derived]
            out.groups[g.id] = GroupMeta(
                g.id, g.first_at, g.last_at, max(_bucket_end(g), arrived), g.day, g.alerts,
                g.severity, seen.direction, seen.outcome, known.get(g.id),
                tuple(sorted({o.source_key[3:] for o in seen.observations
                              if o.source_kind == "evidence"})),
                tuple(f for f in g.flags), tuple(derived), seen.objects, arrived,
                sources if seen.direction == "inbound" else (),
                tuple(stored_answers.get(g.id, ())), g.rule_id,
            )  # fmt: skip
    for r in await conn.execute(
        text(
            "SELECT investigation_id, decided_at FROM review_state"
            " WHERE outcome = 'true_positive' AND decided_at IS NOT NULL"
        )
    ):
        if r.investigation_id in out.groups:
            out.verdicts.append((r.decided_at, r.investigation_id))
    out.cases = [
        r.created_at
        for r in await conn.execute(text("SELECT created_at FROM cases WHERE cause = 'raised'"))
    ]
    out.seconds = time.perf_counter() - started
    return out


def _bucket_end(g: Group) -> datetime:
    """The end of the group's 24-hour bucket (its first alert is in it)."""
    return assign.bucket_start(g.first_at) + assign.WINDOW


def _day(at: datetime) -> date:
    return at.astimezone(site.zone()).date()


@dataclass
class Incident:
    name: str
    refs: set[ObjectRef]
    found_by_people: datetime | None
    first_item: str | None = None
    first_lane: list[str] = field(default_factory=list)
    first_crossing: str | None = None  # warm-up included (an item that began before the window)
    first_gray: str | None = None
    pieces: set[ObjectRef] = field(default_factory=set)
    items: int = 0
    groups: int = 0
    presented_groups: int = 0


def incidents_of(
    spec: Mapping[str, Any], loaded: Loaded
) -> dict[str, Incident]:  # fmt: skip
    """Each library incident's campus objects: its addresses as devices, and for its domain
    suffixes the objects of every group that named such a domain."""
    out = {}
    by_source: dict[str, set[ObjectRef]] = defaultdict(set)  # E3: an outside address's sites
    for g in loaded.groups.values():
        for src in g.sources:
            by_source[src].update(r for r in g.objects if r.kind == "site")
    for name, item in spec.items():
        refs = {ObjectRef("device", f"ip:{ip}") for ip in item.get("ips") or []}
        for ip in item.get("ips") or []:
            refs.update(by_source.get(str(ip), ()))
        suffixes = [s.lower() for s in item.get("domain_suffixes") or []]
        if suffixes:
            for gid, domains in loaded.domains.items():
                if any(d.endswith(s) for d in domains for s in suffixes):
                    refs.update(loaded.groups[gid].objects)
        found = item.get("found_by_people")
        when: datetime | None = None
        if isinstance(found, datetime):
            when = found.astimezone(UTC)
        elif isinstance(found, date):
            when = datetime(
                found.year, found.month, found.day, 23, 59, tzinfo=site.zone()
            ).astimezone(UTC)
        out[name] = Incident(name, refs, when)
    return out


def replay(
    loaded: Loaded, *, start: datetime, end: datetime, step: timedelta, config: RiskConfig,
    incidents: dict[str, Incident], warmup: timedelta | None = None,
    on_step: Callable[[datetime, run.Scored, list[Observation], bool], None] | None = None,
) -> dict[str, Any]:  # fmt: skip
    """Step the clock and count, per day, what the engine would present (see the module). The
    clock starts ``warmup`` (the quiet period of an item) before ``start`` and counts nothing
    then: an object already in a lane before the window is no new item on its first day."""
    started = time.perf_counter()
    cpu = 0.0
    by_group: dict[uuid.UUID, list[Observation]] = defaultdict(list)
    for o in loaded.observations:
        by_group[o.group].append(o)
    arrivals = sorted(loaded.groups.values(), key=lambda g: (g.arrived, str(g.id)))
    pointer = 0
    live: dict[uuid.UUID, GroupMeta] = {}
    keep = config.windows["14d"].span
    quiet = timedelta(days=config.item_quiet_days)
    last_lane: dict[ObjectRef, datetime] = {}
    lanes_now: dict[ObjectRef, tuple[str, ...]] = {}
    gray_now: set[ObjectRef] = set()
    in_lane_at: dict[ObjectRef, list[datetime]] = defaultdict(list)
    items: dict[date, Counter[str]] = defaultdict(Counter)
    item_rows: list[dict[str, Any]] = []
    crossings: dict[date, int] = Counter()
    gray_new: dict[date, set[ObjectRef]] = defaultdict(set)
    gray_lanes: dict[date, Counter[str]] = defaultdict(Counter)
    digest: dict[date, Counter[str]] = defaultdict(Counter)
    presented_inbound: dict[date, int] = Counter()
    verdict_groups = sorted(loaded.verdicts)
    obj_of_group = {g.id: g.objects for g in loaded.groups.values()}
    pending_end = sorted(loaded.groups.values(), key=lambda g: (g.end, str(g.id)))
    end_pointer = 0
    clock = start - (timedelta(days=config.item_quiet_days) if warmup is None else warmup)
    steps = 0
    sources_of = {gid: meta.sources for gid, meta in loaded.groups.items()}  # E3's fold
    inbound_rules: dict[str, Counter[str]] = defaultdict(Counter)  # E3: high inbound rules
    folds: dict[date, int] = Counter()
    who: dict[ObjectRef, list[str]] = defaultdict(list)
    for name, inc in incidents.items():
        for ref in inc.refs:
            who[ref].append(name)
    while clock <= end:
        while pointer < len(arrivals) and arrivals[pointer].arrived <= clock:
            live[arrivals[pointer].id] = arrivals[pointer]
            pointer += 1
        for gid in [g for g, meta in live.items() if meta.last_at < clock - keep]:
            del live[gid]
        visible: list[Observation] = []
        for gid in live:
            taken = live[gid].known_at
            if taken is not None and taken <= clock:  # its notified case holds it now
                continue
            for o in by_group.get(gid, ()):
                if o.seen_at is not None and o.seen_at > clock:
                    continue
                visible.append(o if o.at <= clock else replace(o, at=clock))
        refs = {obj for at, gid in verdict_groups if at <= clock and gid in live
                for obj in obj_of_group.get(gid, ())}  # fmt: skip
        scored = run.evaluate_all(visible, clock, config, loaded.first_alert, refs,
                                  active_within=timedelta(days=7))  # fmt: skip
        cpu += scored.seconds
        day = _day(clock)
        counting = clock >= start
        lately = {r for r, at in last_lane.items() if clock - at <= quiet}  # in a lane lately
        entering = [r for r, v in scored.verdicts.items() if v.lanes and r not in lately]
        entered = set(entering)
        held_now = [r for r, v in scored.verdicts.items() if v.lanes and r not in entered]
        fold = exposure.folded(entering, held_now, scored.verdicts, sources_of, config.exposure)
        if on_step is not None:  # the linker and the lifecycle (E2) at this step
            on_step(clock, scored, visible, counting)
        for ref, v in scored.verdicts.items():
            if v.lanes:
                for name in who.get(ref, ()):
                    if incidents[name].first_crossing is None:
                        incidents[name].first_crossing = clock.isoformat()
                last = last_lane.get(ref)
                before = lanes_now.get(ref, ())
                fresh = last is None or clock - last > quiet
                folded = fresh and ref in fold
                if counting and folded:
                    folds[day] += 1
                    for name in who.get(ref, ()):
                        incidents[name].pieces.add(ref)
                if counting and fresh and not folded:
                    items[day][v.lanes[0]] += 1
                    top = v.window("7d" if v.lanes[0] in ("slow", "exposure") else "24h")
                    item_rows.append({
                        "at": clock.isoformat(), "object": ref.kind, "lanes": list(v.lanes),
                        "score": round(top.score, 1),
                        "why": [c.source.split(":", 1)[0] + ":" + (c.source.split(":", 1)[1]
                                if c.source.startswith("ev:") else "rule")
                                for c in top.contributions[:6]],
                        "incident": who.get(ref, []),
                    })  # fmt: skip
                    for name in who.get(ref, ()):
                        inc = incidents[name]
                        inc.items += 1
                        inc.pieces.add(ref)
                        if inc.first_item is None:
                            inc.first_item, inc.first_lane = clock.isoformat(), list(v.lanes)
                if counting:
                    crossings[day] += len(set(v.lanes) - set(before))
                last_lane[ref] = clock
                in_lane_at[ref].append(clock)
            if counting and v.gray and ref not in gray_now:
                gray_new[day].add(ref)
                gray_lanes[day].update(v.gray)
                for name in who.get(ref, ()):
                    if incidents[name].first_gray is None:
                        incidents[name].first_gray = clock.isoformat()
        lanes_now = {r: v.lanes for r, v in scored.verdicts.items() if v.lanes}
        gray_now = {r for r, v in scored.verdicts.items() if v.gray}
        while end_pointer < len(pending_end) and pending_end[end_pointer].end <= clock:
            g = pending_end[end_pointer]
            end_pointer += 1
            if g.end <= start or g.first_at > end:
                continue
            presented = any(
                g.first_at - timedelta(hours=1) <= t <= g.end
                for ref in g.objects for t in in_lane_at.get(ref, ())
            )  # fmt: skip
            verdicts = [scored.verdicts[r] for r in g.objects if r in scored.verdicts]
            known = g.known_at is not None and g.known_at <= g.end
            cat = "presented" if presented and not known else score.category(
                known=known, direction=g.direction, outcome=g.outcome, kinds=g.kinds,
                verdicts=verdicts,
            )  # fmt: skip
            digest[g.day][cat] += 1
            if g.direction == "inbound" and (g.severity or "").lower() in ("high", "critical"):
                inbound_rules[g.rule][cat] += 1
            if cat == "presented" and g.direction == "inbound":
                presented_inbound[g.day] += 1
            for inc in incidents.values():
                if set(g.objects) & inc.refs:
                    inc.groups += 1
                    inc.presented_groups += cat == "presented"
        clock += step
        steps += 1
    days = sorted({_day(start) + timedelta(days=n) for n in range((end - start).days + 1)})
    return {
        "items": items, "item_rows": item_rows, "crossings": crossings, "gray_new": gray_new,
        "gray_lanes": gray_lanes,
        "digest": digest, "presented_inbound": presented_inbound, "days": days,
        "exposure_folds": folds,
        "inbound_rules": inbound_rules,
        "steps": steps, "seconds": time.perf_counter() - started,
        "score_cpu_per_step": cpu / max(steps, 1),
    }  # fmt: skip


def _noisiest(rules: Mapping[str, Counter[str]]) -> dict[str, Any]:
    """E3: where the alert groups of the high-severity inbound rule with the most groups ended
    (counts only; no rule is named)."""
    if not rules:
        return {}
    top = max(sorted(rules), key=lambda r: sum(rules[r].values()))
    found = rules[top]
    total = sum(found.values())
    presented = found.get("presented", 0)
    return {"groups": total, "presented": presented,
            "digest_share": _share(total - presented, total),
            "by_category": dict(found.most_common())}  # fmt: skip


def _lookups(waiting: Mapping[str, datetime], day: date) -> tuple[int, int]:
    """(requests, sources still waiting at the day's end): one lookup an hour, outside the
    quiet hours, of at most 50 of the sources that arrived by then."""
    queue = sorted(waiting.items(), key=lambda kv: (kv[1], kv[0]))
    start = datetime(day.year, day.month, day.day, tzinfo=UTC)
    requests = 0
    for hour in range(24):
        at = start + timedelta(hours=hour, minutes=59)
        if site.in_quiet_hours(at):
            continue
        ready = [src for src, arrived in queue if arrived <= at][: webchecks.MAX_SOURCES]
        if ready:
            requests += 1
            queue = [(s, a) for s, a in queue if s not in set(ready)]
    return requests, len(queue)


def checking_budget(loaded: Loaded, days: Sequence[date], config: RiskConfig) -> dict[str, Any]:
    """E3: what the checking lane would have asked each day of the window (every check
    switched on), from the stored web evidence: the hourly site lookups (one request an hour,
    at most 50 addresses) and the candidates' checks, with their worst-case server time (each
    request at its first-run limit) against the lane's day cap. A bound, not a measurement: the
    window's logs are gone."""
    ex = config.exposure
    per_day: dict[date, dict[str, Any]] = {}
    by_day: dict[date, list[GroupMeta]] = defaultdict(list)
    for g in loaded.groups.values():
        if g.sources:
            by_day[g.last_at.astimezone(UTC).date()].append(g)
    for day in days:
        groups = by_day.get(day, [])
        inputs = checking.Inputs()
        pairs: dict[tuple[str, str], checking.Pair] = {}
        waiting: dict[str, datetime] = {}  # a source whose site is unknown -> its arrival
        seen: dict[str, set[str]] = defaultdict(set)
        for g in groups:
            for src in g.sources:
                if g.answers:
                    for where, path, _ in g.answers:
                        p = pairs.setdefault((src, where), checking.Pair(
                            src, where, day, g.first_at, g.last_at))  # fmt: skip
                        p.first_at = min(p.first_at, g.first_at)
                        p.last_at = max(p.last_at, g.last_at)
                        p.paths[path] = p.paths.get(path, 0) + 1
                        p.rows += 1
                        seen[same_file(path)].add(src)
                elif not g.objects:
                    waiting[src] = min(waiting.get(src, g.arrived), g.arrived)
        inputs.pairs = list(pairs.values())
        inputs.rare = exposure.rare_paths(seen, ex)
        for p in inputs.pairs:
            inputs.sources_of.setdefault((p.site, p.day), set()).add(p.source)
        now = datetime(day.year, day.month, day.day, 23, 0, tzinfo=UTC)
        asks = checking.plan(inputs, now, ex, checking.TEMPLATES - {"web.source_sites"})
        kinds = Counter(a.kind for a in asks)
        lookups, over = _lookups(waiting, day)
        worst = (sum(checking.FIRST_RUN_MS[a.name] for a in asks)
                 + lookups * checking.FIRST_RUN_MS["web.source_sites"])  # fmt: skip
        found = len(checking.candidates(inputs, now, ex))
        per_day[day] = {"lookups": lookups, "lookup_sources_left": over,
                        "checks": dict(kinds), "candidates": found, "worst_ms": worst,
                        "within_cap": worst <= ex.day_ms}  # fmt: skip
    worst_days = [v["worst_ms"] for v in per_day.values()]
    return {
        "per_day": {d.isoformat(): v for d, v in sorted(per_day.items())},
        "worst_ms_mean": round(statistics.mean(worst_days)) if worst_days else 0,
        "worst_ms_max": max(worst_days, default=0),
        "day_cap_ms": ex.day_ms,
        "days_within_cap": sum(1 for v in per_day.values() if v["within_cap"]),
    }


def baseline(loaded: Loaded, days: Sequence[date]) -> dict[date, dict[str, int]]:
    """Per day of its bucket: alerts, alert groups (plain 1-day throttling), severity only, and
    today's Needs attention (by severity or a raise) on the stored flags as measured and on the
    flags derived here, the flagged and raised groups, and the suggested cases made that day."""
    out: dict[date, Counter[str]] = {d: Counter() for d in days}
    for g in loaded.groups.values():
        if g.day not in out:
            continue
        row = out[g.day]
        sev = (g.severity or "").lower() in ("high", "critical")
        row["alerts"] += g.alerts
        row["groups"] += 1
        row["severity_only"] += sev
        row["flagged_stored"] += bool(g.stored_flags)
        row["raised_stored"] += raised.raises(g.stored_flags)
        row["today_stored"] += sev or raised.raises(g.stored_flags)
        row["raised_derived"] += raised.raises(g.derived_flags)
        row["today_derived"] += sev or raised.raises(g.derived_flags)
    for at in loaded.cases:
        d = _day(at)
        if d in out:
            out[d]["suggested_cases"] += 1
    return {d: dict(v) for d, v in out.items()}


def _share(part: float, whole: float) -> float:
    return round(part / whole, 3) if whole else 0.0


def _mean(rows: Sequence[Mapping[str, Any]], key: str) -> float:
    return round(sum(float(r.get(key, 0)) for r in rows) / len(rows), 1) if rows else 0.0


def summary(
    result: Mapping[str, Any], base: Mapping[date, Mapping[str, int]],
    incidents: Mapping[str, Incident], loaded: Loaded,
) -> dict[str, Any]:  # fmt: skip
    """The report: per day, then the window and the stable window's averages, then the
    incidents."""
    per_day = []
    for d in result["days"]:
        items = result["items"].get(d, Counter())
        digest = result["digest"].get(d, Counter())
        b = base.get(d, {})
        presented = digest.get("presented", 0)
        per_day.append({
            "day": d.isoformat(),
            "v2_items": sum(items.values()), "v2_items_by_lane": dict(items),
            "v2_crossings": result["crossings"].get(d, 0),
            "v2_exposure_folded": result.get("exposure_folds", {}).get(d, 0),
            "v2_gray_new": len(result["gray_new"].get(d, ())),
            "v2_gray_by_lane": dict(result["gray_lanes"].get(d, Counter())),
            "v2_presented_groups": presented,
            "v2_presented_inbound": result["presented_inbound"].get(d, 0),
            "v2_digest": dict(sorted(digest.items())),
            **{f"base_{k}": v for k, v in sorted(b.items())},
            "base_today_items": b.get("today_stored", 0) + b.get("suggested_cases", 0),
        })  # fmt: skip
    stable = [r for r in per_day if STABLE[0].isoformat() <= r["day"] <= STABLE[1].isoformat()]
    v2 = [r["v2_items"] for r in per_day]
    three = [sum(v2[i : i + 3]) for i in range(max(len(v2) - 2, 1))]
    digest_total: Counter[str] = Counter()
    for r in per_day:
        digest_total.update(r["v2_digest"])
    groups_total = sum(digest_total.values())
    inbound_items = sum(1 for r in result["item_rows"] if r["object"] == "site")
    total_items = len(result["item_rows"])
    presented = sum(r["v2_presented_groups"] for r in per_day)
    report = {
        "per_day": per_day,
        "window": {
            "days": len(per_day),
            "v2_items_mean": _mean(per_day, "v2_items"),
            "v2_items_median": statistics.median(v2) if v2 else 0,
            "v2_items_p95": sorted(v2)[max(0, round(0.95 * len(v2)) - 1)] if v2 else 0,
            "v2_items_max": max(v2) if v2 else 0,
            "v2_max_3_days": max(three) if v2 else 0,
            "v2_gray_new_mean": _mean(per_day, "v2_gray_new"),
            "base_today_items_mean": _mean(per_day, "base_today_items"),
            "base_today_stored_mean": _mean(per_day, "base_today_stored"),
            "base_today_derived_mean": _mean(per_day, "base_today_derived"),
            "base_severity_only_mean": _mean(per_day, "base_severity_only"),
            "base_groups_mean": _mean(per_day, "base_groups"),
            "base_alerts_mean": _mean(per_day, "base_alerts"),
        },
        "stable_window": {
            "from": STABLE[0].isoformat(),
            "to": STABLE[1].isoformat(),
            "days": len(stable),
            **{
                k: _mean(stable, k)
                for k in (
                    "v2_items",
                    "v2_gray_new",
                    "v2_presented_groups",
                    "base_alerts",
                    "base_groups",
                    "base_severity_only",
                    "base_flagged_stored",
                    "base_raised_stored",
                    "base_today_stored",
                    "base_raised_derived",
                    "base_today_derived",
                    "base_suggested_cases",
                    "base_today_items",
                )
            },
        },
        "digest": {
            "groups": groups_total,
            "by_category": dict(digest_total.most_common()),
            "inbound_share_of_groups": _share(
                sum(v for k, v in digest_total.items() if k.startswith("inbound_")), groups_total
            ),
        },
        "t6": {
            "items_on_sites": inbound_items,
            "items": total_items,
            "inbound_share_of_items": round(inbound_items / total_items, 3) if total_items else 0,
            "inbound_share_of_presented_groups": _share(
                sum(r["v2_presented_inbound"] for r in per_day), presented
            ),
        },
        "incidents": {},
        "noisiest_inbound_rule": _noisiest(result.get("inbound_rules", {})),
        "items": result["item_rows"],
        "timing": {
            "load_seconds": round(loaded.seconds, 1),
            "replay_seconds": round(result["seconds"], 1),
            "steps": result["steps"],
            "score_cpu_per_step": round(result["score_cpu_per_step"], 4),
            "observations": len(loaded.observations),
            "groups": len(loaded.groups),
        },
    }
    for name, inc in incidents.items():
        lead = None
        if inc.first_item and inc.found_by_people:
            first = datetime.fromisoformat(inc.first_item)
            lead = round((inc.found_by_people - first).total_seconds() / 3600, 1)
        report["incidents"][name] = {
            "objects": len(inc.refs), "first_item": inc.first_item, "first_lane": inc.first_lane,
            "first_crossing": inc.first_crossing,
            "first_gray": inc.first_gray, "items": inc.items,
            "objects_presented": len(inc.pieces), "groups": inc.groups,
            "groups_presented": inc.presented_groups,
            "found_by_people": inc.found_by_people.isoformat() if inc.found_by_people else None,
            "lead_hours": lead,
        }  # fmt: skip
    return report


def dumps(report: Mapping[str, Any]) -> str:
    return json.dumps(report, indent=1, default=str)
