"""The presenter (P4-F E5) on the linker's incidents: each live incident gets a priority, a why
line, its checks, its benign alternatives and a certainty word, and, with ``risk.present`` on,
each one shown is a **suspected case** whose members are its alert groups.

One incident model: the linker's (``argus.risk.incidents``, ``argus.risk.lifecycle``). The
priority step feeds the lifecycle (:func:`ranker`, its ``band_of``), so a band that rises is a
material change the lifecycle says; the lifecycle's material changes are the only re-queue.
Every pass, after the linker:

1. Each root incident (an overflow has no card of its own) is **valued** from its objects'
   scores (:mod:`argus.risk.priority`, :mod:`argus.risk.alternatives`) and gets its title.
2. **The capacity governor**: at most ``shown_per_day`` new incidents a day become cards on
   Today (``shown``, per mode); P1 and P2 are never held back; P3, then P4, take the room left;
   the rest wait, counted as "more waiting" and listed in Incidents' Needs you (Today and the
   queue are one set: ``casepages.WORK``).
3. **Presenting** (``risk.present`` on): every incident a person could decide becomes a
   suspected case through :class:`argus.cases.service.CaseService` (cause ``raised``, as
   ``argus:engine``), shown or waiting; later alert groups the linker folds in join its case
   silently (a ``linked`` event). A case a person closed keeps the incident quiet for
   :data:`MEMORY` unless a strong material change breaks it (a new flagged thing, stage, log
   family or a higher band); then a new case follows the old one with the alert groups no case
   holds, or, when the change is on the groups the closed case holds (an investigation is in
   one case at a time), the closed case is told (``activity_after_closure``: Today's New
   activity shows it). A case a person reopens is presented again. A sealed incident's
   follow-on inherits the predecessor's case: an open one it takes over, a closed one is its
   memory. Alert groups another case holds are never taken: an incident with no case of its own
   whose alert groups all sit in cases people have or decided is not presented (``elsewhere``);
   with free groups it is presented with those; an undecided case today's suggester made is
   taken over as the incident's own. When the linker merges two incidents, the merged one's
   undecided case is merged into the survivor's (or becomes the survivor's own when it has
   none); a person's decision on either incident blocks the merge in the lifecycle instead.
4. **The gray band**: campus objects just under a lane, valued the same way (Today shows five).

Off (the default) is the shadow: only the engine's own tables are written. Postgres only: no
SIEM request and no model."""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from collections import Counter, defaultdict
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus import site
from argus.assets.classify import IpClassifier
from argus.cases import naming, opener, titling
from argus.cases.machine import RAISED_REASON, AfterClosure, CaseRefused, Link, Open
from argus.cases.model import CONFIRMED, Actor, Indicator, Member, Severity
from argus.cases.service import CaseService
from argus.risk import alternatives as alt
from argus.risk import lifecycle, outbound_db, score, titles
from argus.risk import priority as prio
from argus.risk.config import RiskConfig
from argus.risk.identity import read_same
from argus.risk.lifecycle import Incident, Material
from argus.risk.observe import ObjectRef, Observation

log = logging.getLogger("argus.risk")
PART = "engine"  # ARGUS acts as ``argus:engine``
MEMORY = timedelta(days=30)  # a closed case keeps its incident quiet (D-309 (4))
# A presenting pass this recent: the old feeds may stop. The pass runs every 10 minutes (a oneshot
# timer, up to a minute late) and records the time it started only when it commits, so a window
# of 10 minutes lapsed for a minute or two each cycle and the old feeds (the per-pattern AI runs
# among them) came back each time (D-324). Two missed passes still bring them back.
ALIVE = timedelta(minutes=25)
GRAY_KEPT = 20  # gray-band items kept (Today shows five)
MEMBERS_MAX = 200  # alert groups one case takes
THREATS_KEPT = 20  # rare outside values a new case holds as indicators
WHY_LIMIT = 5
SEVERITY: dict[str, Severity] = {"P1": "critical", "P2": "high", "P3": "medium", "P4": "low"}
EVIDENCE_WORDS = {
    "outside": "outside detection (VirusTotal)",
    "ti": "on a threat list",
    "operator": "same operator as a flagged server",
    "success": "the attack got an answer",
    "tunnel": "DNS tunnelling suspected",
    "beacon": "regular timing, like a beacon",
    "ports": "risky ports",
    "rare_dest": "a destination almost no one else reaches",
    "persistence": "the same rare destination on several days",
    "bulk_success": "many files taken by one outside source",
}
CHECK_SIGNALS = ("ti.listed", "ti.listed_remote", "proxy.regularity")


@dataclass(frozen=True)
class Options:
    """``risk.*`` of the settings: whether the engine presents its incidents as cases, and the
    governor's daily room."""

    present: bool = False
    shown_per_day: int = 10


@dataclass(frozen=True)
class Context:
    config: RiskConfig
    options: Options = Options()
    classifier: IpClassifier | None = None
    campus_domains: Sequence[str] = ()
    weights: prio.Weights = prio.WEIGHTS


@dataclass(frozen=True)
class Obj:
    """A campus object as the presenter reads it: its 7-day verdict."""

    ref: ObjectRef
    id: int = 0
    lanes: tuple[str, ...] = ()
    hub: bool = False
    criticality: float = 1.0
    score: float = 0.0  # 7 days
    families: int = 0
    stages: int = 0
    strong: bool = False
    parts: tuple[prio.Part, ...] = ()
    last_at: datetime | None = None
    kinds: frozenset[str] = frozenset()  # evidence kinds (ev:<kind>) of its 7 days
    gray: tuple[str, ...] = ()
    # the device it is with other addresses (identity.same_devices, D-334); None: its own
    same: str | None = None

    @property
    def kind(self) -> str:
        return self.ref.kind

    @property
    def key(self) -> str:
        return self.ref.key

    @property
    def label(self) -> str:
        return lifecycle.label(self.ref)


def obj_of(ref: ObjectRef, v: score.Verdict, *, oid: int = 0, hub: bool = False,
           criticality: float = 1.0, same: str | None = None) -> Obj:  # fmt: skip
    """One object's facts from its verdict's 7-day window."""
    w7 = v.window("7d")
    parts = tuple(sorted((prio.Part(c.source, c.score, c.base) for c in w7.contributions),
                         key=lambda p: (-p.points, p.source)))  # fmt: skip
    return Obj(
        ref, oid, tuple(v.lanes), hub, criticality, w7.score, len(w7.families), w7.stages,
        w7.strong, parts, max((c.at for c in w7.contributions), default=None),
        frozenset(c.source[3:] for c in w7.contributions if c.source.startswith("ev:")),
        tuple(v.gray), same,
    )  # fmt: skip


# --------------------------------------------------------------------------- valuing (pure)


def words_for(config: RiskConfig, rule_names: Mapping[str, str]) -> Callable[[prio.Part], str]:
    """A source's words in the why line: an evidence kind's plain words (with "out-of-date list"
    when a stale feed gave it), or the rule's name (words only: nothing decides on it)."""

    def words(part: prio.Part) -> str:
        kind, _, key = part.source.partition(":")
        if kind == "ev":
            said = EVIDENCE_WORDS.get(key, key.replace("_", " "))
            return said + (" (out-of-date list)" if stale(config, part) else "")
        name = rule_names.get(key)
        return f"rule: {name}" if name else "a rule"

    return words


def stale(config: RiskConfig, part: prio.Part) -> bool:
    """Whether an evidence part was weighed as coming from an out-of-date threat-intel feed."""
    if not part.source.startswith("ev:"):
        return False
    kind = config.kind(part.source[3:])
    return (kind is not None and kind.stale_base is not None and kind.stale_base < kind.base
            and abs(part.base - kind.stale_base) < 1e-9)  # fmt: skip


def as_devices(objects: Sequence[Obj]) -> list[Obj]:
    """``objects`` with the addresses that are one device (``same``) as one object: the one
    with the highest score stands for it, with the most stages, families and the latest activity
    of them all. One laptop seen under eleven addresses is one device to the priority, not a
    spread over eleven."""
    held: dict[str, Obj] = {}
    out: list[Obj] = []
    for o in sorted(objects, key=lambda o: (-o.score, o.key)):
        if o.same is None:
            out.append(o)
            continue
        top = held.get(o.same)
        if top is None:
            held[o.same] = o
            continue
        times = [t for t in (top.last_at, o.last_at) if t is not None]
        held[o.same] = replace(
            top, families=max(top.families, o.families), stages=max(top.stages, o.stages),
            strong=top.strong or o.strong, last_at=max(times, default=None),
            kinds=top.kinds | o.kinds,
        )  # fmt: skip
    return sorted([*out, *held.values()], key=lambda o: (-o.score, o.key))


def joined(objects: Sequence[Obj]) -> int:
    """How many addresses of ``objects`` are counted with another as one device."""
    groups = Counter(o.same for o in objects if o.same is not None)
    return sum(n for n in groups.values() if n > 1)


def facts_of(objects: Sequence[Obj], last_seen: datetime | None) -> list[prio.Facts]:
    return [
        prio.Facts(o.kind, o.label, o.score, o.families, o.stages, o.parts,
                   max((t for t in (o.last_at, last_seen) if t is not None), default=None),
                   o.criticality)
        for o in as_devices(objects)
    ]  # fmt: skip


def stale_points(objects: Sequence[Obj], config: RiskConfig) -> float:
    """The top object's points of out-of-date intel, when no fresh strong fact stands by it."""
    top = max(objects, key=lambda o: (o.score, o.key)) if objects else None
    if top is None or top.strong:
        return 0.0
    return sum(p.points for p in top.parts if stale(config, p))


def rank(objects: Sequence[Obj], now: datetime, config: RiskConfig, last_seen: datetime | None,
         w: prio.Weights = prio.WEIGHTS, confirmed: bool = False) -> prio.Scored:  # fmt: skip
    """An incident's priority from its objects (the evidence's; a confirm's trust on request)."""
    trust = prio.Trust(confirmed, stale_points(objects, config))
    return prio.score(facts_of(objects, last_seen), now, trust, w)


def ranker(
    verdicts: Mapping[ObjectRef, score.Verdict], now: datetime, config: RiskConfig,
    w: prio.Weights = prio.WEIGHTS, same: Mapping[ObjectRef, str] | None = None,
) -> Callable[[Incident], str]:  # fmt: skip
    """The lifecycle's ``band_of``: the priority step on the pass's verdicts. It sets the
    incident's priority (the evidence's: a person's confirm is no new fact) and returns its
    band, so a band that rises is a material change the lifecycle says."""

    def band_of(inc: Incident) -> str:
        one = same or {}  # read at the call: the linking pass fills it before it ranks
        objs = [obj_of(r, verdicts[r], same=one.get(r)) for r in inc.objects if r in verdicts]
        scored = rank(objs, now, config, inc.last_seen, w)
        inc.priority = scored.priority
        return scored.band

    return band_of


def lane_of(objects: Sequence[Obj], config: RiskConfig) -> str | None:
    """A gray-band item's lane: the one it just misses."""
    held = {lane for o in objects for lane in o.lanes}
    for lane in lifecycle.LANE_ORDER:
        if lane in held:
            return lane
    missed = {lane for o in objects for lane in o.gray}
    for lane in lifecycle.LANE_ORDER:
        if lane in missed:
            return lane
    return None


@dataclass(frozen=True)
class Value:
    """What the presenter makes of an incident's objects (pure)."""

    priority: int  # with a person's confirm counted (the card's)
    band: str
    evidence: prio.Scored  # the evidence's alone (the lifecycle's band, the case's severity)
    certainty: str  # the engine's word ("Confirmed" once a person confirmed)
    why: tuple[prio.WhyItem, ...]
    checks: tuple[alt.Check, ...]
    alternatives: tuple[alt.Alternative, ...]
    active: bool
    strong: bool
    evidence_certainty: str = "Unclear"  # the evidence's word alone (the API sends this one)

    @property
    def evidence_band(self) -> str:
        return self.evidence.band

    def view(self) -> dict[str, Any]:
        return {
            "priority": self.priority, "band": self.band, "certainty": self.evidence_certainty,
            "why": [{"op": i.op, "points": i.points, "text": i.text} for i in self.why],
            "why_line": prio.line(self.why),
            "checks": [{"state": c.state, "text": c.text} for c in self.checks],
            "alternatives": [{"name": a.name, "state": a.state, "test": a.test}
                             for a in self.alternatives],
        }  # fmt: skip


def value(
    objects: Sequence[Obj], now: datetime, ctx: Context, *, confirmed: bool,
    reach: Mapping[str, int], signals: Iterable[str], rule_names: Mapping[str, str],
    lanes: Collection[str], last_seen: datetime | None,
    measured: Sequence[alt.Measured] = (),
) -> Value:  # fmt: skip
    """An incident's priority, band, certainty, why line, checks and alternatives from its
    objects (pure). ``measured``: what the checking lane found for it (D-323); it changes the
    checks, the alternatives and so the certainty word, never the priority (its facts reach the
    score only as the engine's observations)."""
    config, w = ctx.config, ctx.weights
    words = words_for(config, rule_names)
    facts = facts_of(objects, last_seen)
    strong = any(o.strong for o in objects)
    trust = prio.Trust(confirmed, stale_points(objects, config))
    evidence = prio.score(facts, now, prio.Trust(False, trust.stale_points), w)
    scored = prio.score(facts, now, trust, w) if confirmed else evidence
    why = prio.why(scored, facts, words, now, trust, w, WHY_LIMIT)
    kinds = frozenset(k for o in objects for k in o.kinds)
    ti_parts = [p for o in objects for p in o.parts if p.source == "ev:ti"]
    stale_intel = bool(ti_parts) and all(stale(config, p) for p in ti_parts)
    tests = alt.Evidence(
        kinds=kinds, strong=strong, stale_intel=stale_intel,
        object_kinds=frozenset(o.kind for o in objects), hubs=sum(o.hub for o in objects),
        named_hosts=sum(o.key.startswith("host:") for o in objects), objects=len(objects),
        reach=dict(reach), signals=frozenset(signals),
        acting=any(o.kind != "site" for o in objects), measured=tuple(measured),
    )  # fmt: skip
    found = alt.alternatives(tests)
    word = alt.certainty(confirmed=confirmed, lanes=lanes, strong=strong, found=found)
    alone = alt.certainty(confirmed=False, lanes=lanes, strong=strong, found=found)
    checks = list(alt.checks(tests))
    moved = joined(objects)
    if moved:  # said where a reader looks for what ARGUS checked: the count is not the devices
        checks.append(alt.Check("checked", site.say(
            f"{moved} of its addresses are most likely one {{own:device}} that moved: the same"
            " account signed in from each, never from two at the same time"
        )))  # fmt: skip
    return Value(scored.priority, scored.band, evidence, word, tuple(why), tuple(checks),
                 tuple(found), scored.active, strong, alone)  # fmt: skip


def breaks(shown: Mapping[str, Any], now_: Mapping[str, Any]) -> bool:
    """Whether a material change ends a closed case's memory: a newly flagged outside thing, a
    new stage, a new log family or a higher band (new rules or more devices alone do not).
    ``shown``: the lifecycle's material when the person was shown it; empty: no memory."""
    if not shown:
        return True
    old, new = Material.of_json(shown), Material.of_json(now_)
    return bool(
        new.flagged - old.flagged
        or new.stages & ~old.stages
        or new.families - old.families
        or lifecycle.BANDS.index(new.band) > lifecycle.BANDS.index(old.band)
    )


def govern(waiting: Sequence[tuple[int, str, int]], shown_today: int, room: int) -> set[int]:
    """Which of the incidents not shown yet ((id, band, priority)) the governor shows now: every
    P1 and P2; then P3, then P4, by priority, while today's shown count is under ``room`` (the
    rest wait for the next day's room)."""
    out: set[int] = set()
    count = shown_today
    for iid, band, _ in sorted(waiting, key=lambda w: (w[1], -w[2], w[0])):
        if band in ("P1", "P2") or count < room:
            out.add(iid)
            count += 1
    return out


def site_day(moment: datetime) -> date:
    return moment.astimezone(site.zone()).date()


def mode_of(ctx: Context) -> str:
    """The mode a card is shown in (the governor's room is per mode: shadow's choices do not
    carry into presenting, so switching on goes through the daily room)."""
    return "present" if ctx.options.present else "shadow"


def threats_of(obs: Iterable[Observation], now: datetime, window: timedelta
               ) -> tuple[dict[ObjectRef, set[str]], dict[str, int]]:  # fmt: skip
    """The outside things each acting object named in its rule observations of the window, and
    how many objects reach each (the alternatives' reach)."""
    since = now - window
    threats: dict[ObjectRef, set[str]] = defaultdict(set)
    for o in obs:
        if o.source_kind == "rule" and o.role == "actor" and since <= o.at <= now and o.threats:
            threats[o.object].update(o.threats)
    reach: dict[str, int] = defaultdict(int)
    for held in threats.values():
        for t in held:
            reach[t] += 1
    return threats, dict(reach)


# --------------------------------------------------------------------------- reads


@dataclass(frozen=True)
class Group:
    """An alert group of an incident."""

    id: uuid.UUID
    alerts: int
    at: datetime
    case_id: uuid.UUID | None  # the case that holds it (any state)
    case_open: bool  # that case is not closed
    adoptable: bool = False  # that case is ARGUS's own suggestion nobody decided, no incident's
    engine: bool = False  # that case presents an engine incident


@dataclass
class Stored:
    """A root incident as the linker stored it, with its case: its own, or, for a sealed
    incident's follow-on without one, the predecessor's (``inherited``: the follow-on's memory,
    or the open case it takes over)."""

    id: int
    state: str
    version: int
    changed: tuple[str, ...]
    material: dict[str, Any]
    material_at: datetime | None
    priority: int
    band: str
    lanes: tuple[str, ...]
    view: dict[str, Any]
    case_id: uuid.UUID | None
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    title: str | None
    certainty: str
    shown: bool
    shown_day: date | None
    queued_at: datetime | None
    presented: dict[str, Any]
    presented_at: datetime | None
    case_state: str | None = None
    case_title: str | None = None
    case_closed_at: datetime | None = None
    person_event: int | None = None  # the newest case event a person made, if any
    follows_id: int | None = None  # the sealed incident this one continues
    inherited: bool = False  # the case is the predecessor's, not stored on this row
    objects: dict[int, tuple[ObjectRef, str]] = field(default_factory=dict)  # id -> ref, role
    groups: list[Group] = field(default_factory=list)

    @property
    def live(self) -> bool:
        return self.state in lifecycle.LIVE

    @property
    def own_case_id(self) -> uuid.UUID | None:
        """The case this row holds (what another pass may have changed meanwhile)."""
        return None if self.inherited else self.case_id


_INCIDENTS = text(
    "SELECT r.id, r.state, r.version, r.changed, r.material, r.material_at, r.priority, r.band,"
    " r.lanes, r.view, r.case_id, r.first_seen, r.last_seen, r.created_at, r.title,"
    " r.certainty, r.shown, r.shown_day, r.queued_at, r.presented, r.presented_at,"
    " r.follows_id, c.state AS case_state, c.title AS case_title, c.closed_at AS case_closed_at,"
    " (SELECT max(e.id) FROM case_events e WHERE e.case_id = r.case_id"
    "  AND e.actor_user_id IS NOT NULL) AS person_event"
    " FROM risk_incidents r LEFT JOIN cases c ON c.id = r.case_id"
    " WHERE r.state <> 'merged' AND r.parent_id IS NULL"
    " AND (r.state IN ('active', 'quiet') OR (r.case_id IS NOT NULL AND c.state <> 'closed'))"
    " ORDER BY r.id"
)
# a follow-on's predecessor with a case: the nearest one up the chain of sealed incidents
_PREDECESSORS = text(
    "WITH RECURSIVE chain AS ("
    " SELECT r.id AS start, r.follows_id AS pred, 1 AS depth FROM risk_incidents r"
    " WHERE r.id = ANY(CAST(:ids AS bigint[])) AND r.follows_id IS NOT NULL"
    " UNION ALL"
    " SELECT ch.start, p.follows_id, ch.depth + 1 FROM chain ch"
    " JOIN risk_incidents p ON p.id = ch.pred"
    " WHERE p.case_id IS NULL AND p.follows_id IS NOT NULL AND ch.depth < 10)"
    " SELECT DISTINCT ON (ch.start) ch.start, p.id AS pred, p.case_id, p.presented,"
    " p.presented_at, c.state AS case_state, c.title AS case_title,"
    " c.closed_at AS case_closed_at, (SELECT max(e.id) FROM case_events e"
    "  WHERE e.case_id = p.case_id AND e.actor_user_id IS NOT NULL) AS person_event"
    " FROM chain ch JOIN risk_incidents p ON p.id = ch.pred AND p.case_id IS NOT NULL"
    " JOIN cases c ON c.id = p.case_id ORDER BY ch.start, ch.depth"
)
_OBJECTS = text(
    "SELECT m.incident_id, m.object_id, m.role, b.kind, b.key, b.hub, b.criticality"
    " FROM risk_incident_objects m JOIN risk_objects b ON b.id = m.object_id"
    " WHERE m.incident_id = ANY(CAST(:ids AS bigint[]))"
)
_GROUPS = text(
    "SELECT DISTINCT ig.incident_id, ig.investigation_id, g.alerts, g.at, m.case_id,"
    " (c.state IS NOT NULL AND c.state <> 'closed') AS case_open,"
    " coalesce(c.state = 'suspected' AND c.cause = 'raised' AND NOT EXISTS (SELECT 1"
    "  FROM risk_incidents ri WHERE ri.case_id = c.id), false) AS adoptable,"
    " EXISTS (SELECT 1 FROM risk_incidents re WHERE re.case_id = m.case_id) AS engine"
    " FROM risk_incident_groups ig JOIN risk_groups g ON g.investigation_id = ig.investigation_id"
    " LEFT JOIN case_members m ON m.investigation_id = ig.investigation_id"
    "  AND m.removed_at IS NULL"
    " LEFT JOIN cases c ON c.id = m.case_id"
    " WHERE ig.incident_id = ANY(CAST(:ids AS bigint[]))"
)
_SIGNALS = text(
    "SELECT DISTINCT s.investigation_id, s.name FROM signals s"
    " JOIN investigations i ON i.id = s.investigation_id AND i.version = s.version"
    " WHERE s.investigation_id = ANY(CAST(:ids AS uuid[])) AND s.status = 'known'"
    " AND s.name = ANY(CAST(:names AS text[]))"
)
_RULE_NAMES = text(
    "SELECT DISTINCT ON (lineage) lineage, name FROM rules"
    " WHERE lineage = ANY(CAST(:l AS text[])) AND name IS NOT NULL"
    " ORDER BY lineage, last_alert_at DESC NULLS LAST"
)
_GRAY_HELD = text("SELECT object_id FROM risk_gray_items")


@dataclass
class World:
    """Everything one pass reads."""

    stored: list[Stored]
    verdicts: Mapping[ObjectRef, score.Verdict]
    ids: Mapping[ObjectRef, int]
    hubs: frozenset[int]  # object ids the engine marks hubs
    criticality: Mapping[int, float]
    threats: dict[ObjectRef, set[str]]
    reach: dict[str, int]
    signals: dict[uuid.UUID, set[str]]
    rule_names: dict[str, str]
    shown_today: int
    gray_stored: set[int]
    measured: dict[int, list[alt.Measured]] = field(default_factory=dict)  # incident -> (D-323)
    # device -> the device it is with other addresses (identity.same_devices, D-334)
    same: dict[ObjectRef, str] = field(default_factory=dict)


async def read(
    conn: AsyncConnection, now: datetime, ctx: Context,
    verdicts: Mapping[ObjectRef, score.Verdict], ids: Mapping[ObjectRef, int],
    obs: Sequence[Observation],
) -> World:  # fmt: skip
    stored = [
        Stored(
            int(r.id), r.state, int(r.version), tuple(r.changed or ()), dict(r.material or {}),
            r.material_at, int(r.priority), r.band, tuple(r.lanes or ()), dict(r.view or {}),
            r.case_id, r.first_seen, r.last_seen, r.created_at, r.title, r.certainty,
            bool(r.shown), r.shown_day, r.queued_at, dict(r.presented or {}), r.presented_at,
            r.case_state, r.case_title, r.case_closed_at, r.person_event, r.follows_id,
        )
        for r in await conn.execute(_INCIDENTS)
    ]  # fmt: skip
    by_id = {s.id: s for s in stored}
    hubs: set[int] = set()
    criticality: dict[int, float] = {}
    following = sorted(s.id for s in stored if s.case_id is None and s.follows_id is not None)
    if following:
        for r in await conn.execute(_PREDECESSORS, {"ids": following}):
            s = by_id[int(r.start)]
            s.case_id, s.case_state, s.case_title = r.case_id, r.case_state, r.case_title
            s.case_closed_at, s.person_event, s.inherited = r.case_closed_at, r.person_event, True
            s.presented, s.presented_at = dict(r.presented or {}), r.presented_at
    if by_id:
        bound = {"ids": sorted(by_id)}
        for r in await conn.execute(_OBJECTS, bound):
            ref = ObjectRef(r.kind, r.key)
            by_id[int(r.incident_id)].objects[int(r.object_id)] = (ref, r.role)
            if r.hub:
                hubs.add(int(r.object_id))
            criticality[int(r.object_id)] = float(r.criticality)
        seen: dict[tuple[int, uuid.UUID], None] = {}
        for r in await conn.execute(_GROUPS, bound):
            key = (int(r.incident_id), r.investigation_id)
            if key in seen:
                continue
            seen[key] = None
            by_id[int(r.incident_id)].groups.append(Group(
                r.investigation_id, int(r.alerts), r.at, r.case_id, bool(r.case_open),
                bool(r.adoptable), bool(r.engine),
            ))  # fmt: skip
        for s in stored:
            s.groups.sort(key=lambda g: (g.at, str(g.id)))
    threats, reach = threats_of(obs, now, ctx.config.windows["7d"].span)
    signals: dict[uuid.UUID, set[str]] = defaultdict(set)
    group_ids = sorted({g.id for s in stored for g in s.groups}, key=str)
    if group_ids:
        for r in await conn.execute(_SIGNALS, {"ids": group_ids, "names": list(CHECK_SIGNALS)}):
            signals[r.investigation_id].add(str(r.name))
    lineages = sorted({
        c.source[5:] for v in verdicts.values() for c in v.window("7d").contributions
        if c.source.startswith("rule:")
    })  # fmt: skip
    rule_names: dict[str, str] = {}
    if lineages:
        rule_names = {str(r.lineage): str(r.name)
                      for r in await conn.execute(_RULE_NAMES, {"l": lineages})}  # fmt: skip
    shown_today = int((await conn.execute(
        text("SELECT count(*) FROM risk_incidents WHERE shown_day = :d"
             " AND view ->> 'shown_in' = :mode"),
        {"d": site_day(now), "mode": mode_of(ctx)},
    )).scalar_one())  # fmt: skip
    gray_stored = {int(i) for i in (await conn.execute(_GRAY_HELD)).scalars()}
    measured = await outbound_db.measured_for(conn, sorted(by_id))
    devices = sorted({ref.key for s in stored for ref, _ in s.objects.values()
                      if ref.kind == "device"})  # fmt: skip
    same = await read_same(conn, devices)
    return World(stored, verdicts, ids, frozenset(hubs), criticality, threats, reach, signals,
                 rule_names, shown_today, gray_stored, dict(measured), same)  # fmt: skip


# --------------------------------------------------------------------------- planning (pure)


@dataclass
class Planned:
    """One root incident after the pass: what to write and what the case step must do."""

    stored: Stored
    objects: list[Obj]
    value: Value
    title: str
    view: dict[str, Any]
    shown: bool
    shown_day: date | None
    queued_at: datetime | None
    presented: dict[str, Any]
    presented_at: datetime | None
    elsewhere: uuid.UUID | None = None  # a person's case that has it instead
    adopt: uuid.UUID | None = None  # the undecided suggested case it takes as its own
    retitle: bool = False
    requeued: bool = False  # the lifecycle's material change at this pass
    new: bool = False

    @property
    def id(self) -> int:
        return self.stored.id

    @property
    def case_id(self) -> uuid.UUID | None:
        return self.adopt or self.stored.case_id

    @property
    def confirmed(self) -> bool:
        return self.stored.case_state in CONFIRMED

    @property
    def closed(self) -> bool:
        return self.stored.case_state == "closed"


@dataclass(frozen=True)
class GrayItem:
    obj: Obj
    value: Value
    title: str
    view: dict[str, Any]
    lane: str | None
    first_seen: datetime
    last_seen: datetime


@dataclass
class Plan:
    incidents: list[Planned]
    gray: list[GrayItem]


def _elsewhere(groups: Sequence[Group], case_id: uuid.UUID | None) -> uuid.UUID | None:
    """The case that has this incident instead of it (then it is not presented, not counted and
    nothing is folded): only when the incident has no case of its own and none of its alert
    groups is free for one (every one sits in a case people have or decided, not ARGUS's own
    undecided suggestion), the case holding its newest alert group; it waits for a new group.
    An incident with a case, or with a free alert group, is presented: a person's case keeps
    the groups it holds, the free ones fold into the incident's own."""
    if case_id is not None or not groups:
        return None
    if all(g.case_id is not None and not g.adoptable for g in groups):
        return groups[-1].case_id
    return None


def _adoptable(groups: Sequence[Group], taken: set[uuid.UUID]) -> uuid.UUID | None:
    """The undecided suggested case (of today's suggester) holding most of its alert groups."""
    held: dict[uuid.UUID, int] = defaultdict(int)
    for g in groups:
        if g.adoptable and g.case_id is not None and g.case_id not in taken:
            held[g.case_id] += 1
    return min(held, key=lambda c: (-held[c], str(c))) if held else None


def fallback_title(objs: Sequence[Obj], lane: str | None) -> str:
    top = max(objs, key=lambda o: (o.score, o.key)) if objs else None
    what = prio.object_words(top.kind if top else "object")[0]
    who = f" {top.label}" if top else ""
    more = f" and {len(objs) - 1} more" if len(objs) > 1 else ""
    lead = "Possible incident" if lane is not None else "Watched"
    return f"{lead}: {what}{who}{more}"[:200]


def objects_of(s: Stored, world: World) -> list[Obj]:
    out = []
    for oid, (ref, _) in s.objects.items():
        v = world.verdicts.get(ref)
        if v is not None:
            out.append(obj_of(ref, v, oid=oid, hub=oid in world.hubs,
                              criticality=world.criticality.get(oid, 1.0),
                              same=world.same.get(ref)))  # fmt: skip
    return sorted(out, key=lambda o: (-o.score, o.key))


def plan(world: World, now: datetime, ctx: Context) -> Plan:
    """The pass's incidents, pure: each root incident valued, the governor's choice and what the
    case step must do; and the gray band."""
    out: list[Planned] = []
    adopted: set[uuid.UUID] = set()
    mode = mode_of(ctx)
    for s in world.stored:
        objs = objects_of(s, world)
        reach = {t: world.reach.get(t, 1) for o in objs for t in world.threats.get(o.ref, ())}
        signals = {n for g in s.groups for n in world.signals.get(g.id, ())}
        v = value(objs, now, ctx, confirmed=s.case_state in CONFIRMED, reach=reach,
                  signals=signals, rule_names=world.rule_names, lanes=s.lanes,
                  last_seen=s.last_seen, measured=world.measured.get(s.id, ()))  # fmt: skip
        requeued = s.material_at == now and s.version > 1
        new = s.created_at == now
        view = {**s.view, **v.view(), "groups": len(s.groups),
                "alerts": sum(g.alerts for g in s.groups)}  # fmt: skip
        elsewhere = _elsewhere(s.groups, s.case_id)
        view["elsewhere"] = str(elsewhere) if elsewhere else None
        if s.case_state != "closed":  # a note on a closed case ends with the case's reopening
            view.pop("after_closure", None)
        # what a person last saw: the version held when they last acted on its case (before
        # this pass's change, which the linker already counted)
        seen = int(s.view.get("seen_version", 0))
        if s.person_event is not None and s.person_event != s.view.get("person_event"):
            seen = s.version - 1 if requeued else s.version
        view["person_event"], view["seen_version"] = s.person_event, seen
        adopt = None
        if ctx.options.present and s.case_id is None and elsewhere is None and s.live:
            adopt = _adoptable(s.groups, adopted)
            if adopt is not None:
                adopted.add(adopt)
        # a card shown in the other mode is not shown in this one (it goes through the room)
        shown = s.shown and s.view.get("shown_in", mode) == mode
        queued = s.queued_at
        if requeued or (shown and queued is None):
            queued = s.material_at or now
        presented, presented_at = s.presented, s.presented_at
        seen_by_people = shown or (s.case_id is not None and not s.inherited)
        if seen_by_people and s.case_state != "closed" and (requeued or not presented):
            presented, presented_at = dict(s.material), now
        out.append(Planned(
            s, objs, v, s.title or fallback_title(objs, s.view.get("lane")), view,
            shown or adopt is not None, s.shown_day or (site_day(now) if adopt else None),
            queued, presented, presented_at, elsewhere, adopt,
            retitle=s.title is None or requeued, requeued=requeued, new=new,
        ))  # fmt: skip
    waiting = [(i, p.stored.band, p.stored.priority) for i, p in enumerate(out)
               if p.stored.live and not p.shown and p.elsewhere is None
               and not (p.closed and _memory_holds(p, now))]  # fmt: skip
    today = site_day(now)
    for i in govern(waiting, world.shown_today, ctx.options.shown_per_day):
        p = out[i]
        p.shown, p.shown_day, p.queued_at = True, today, now
        if not p.presented:
            p.presented, p.presented_at = dict(p.stored.material), now
    for p in out:
        p.view["shown_in"] = mode if p.shown else None
    held = {oid for s in world.stored if s.live for oid in s.objects}
    gray: list[GrayItem] = []
    for ref, verdict in world.verdicts.items():
        oid = world.ids.get(ref)
        if oid is None or oid in held or oid in world.hubs or verdict.lanes or not verdict.gray:
            continue
        o = obj_of(ref, verdict, oid=oid, criticality=world.criticality.get(oid, 1.0))
        gray.append(_gray_item(o, now, ctx, world))
    gray.sort(key=lambda g: (-g.value.priority, g.obj.key))
    return Plan(out, gray[:GRAY_KEPT])


def _gray_item(o: Obj, now: datetime, ctx: Context, world: World) -> GrayItem:
    reach = {t: world.reach.get(t, 1) for t in world.threats.get(o.ref, ())}
    v = value([o], now, ctx, confirmed=False, reach=reach, signals=(), rule_names=world.rule_names,
              lanes=(), last_seen=o.last_at)  # fmt: skip
    lane = lane_of([o], ctx.config)
    last = o.last_at or now
    view = {**v.view(), "lane": lane,
            "objects": [{"kind": o.kind, "label": o.label, "role": "actor"}],
            "active": v.active, "groups": 0, "alerts": 0}  # fmt: skip
    return GrayItem(o, v, fallback_title([o], None), view, lane, last, last)


# --------------------------------------------------------------------------- writes


def _hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def indicators(objs: Sequence[Obj], threats: Iterable[str], reach: Mapping[str, int]
               ) -> tuple[Indicator, ...]:  # fmt: skip
    """A new case's indicators: its campus objects as actors (a site as an indicator), and its
    rare outside values (reached by few campus objects)."""
    out: list[Indicator] = []
    for o in objs:
        prefix, _, rest = o.key.partition(":")
        if o.kind == "account":
            out.append(Indicator("user", o.key[:512], "actor"))
        elif o.kind == "device" and prefix in ("ip", "host"):
            out.append(Indicator(prefix, rest.split("@", 1)[0], "actor"))  # type: ignore[arg-type]
        elif o.kind == "site" and prefix in ("ip", "domain", "host"):
            out.append(Indicator(prefix, rest, "indicator"))  # type: ignore[arg-type]
    rare = sorted((t for t in set(threats) if reach.get(t, 1) <= alt.RARE),
                  key=lambda t: (reach.get(t, 1), t))[:THREATS_KEPT]  # fmt: skip
    for t in rare:
        kind, _, rest = t.partition(":")
        if kind in ("ip", "domain") and rest:
            out.append(Indicator(kind, rest, "indicator"))  # type: ignore[arg-type]
    return tuple(dict.fromkeys(out))


def _marks(p: Planned, world: World) -> tuple[Indicator, ...]:
    threats = {t for o in p.objects for t in world.threats.get(o.ref, ())}
    return indicators(p.objects, threats, world.reach)


async def _title(conn: AsyncConnection, p: Planned, world: World, ctx: Context) -> str:
    ids = [g.id for g in p.stored.groups][-MEMBERS_MAX:]
    fallback = fallback_title(p.objects, p.stored.view.get("lane"))
    if not ids:
        return fallback
    try:  # naming v2 phase 2: the incident's own facts, led by the engine's certainty word
        async with conn.begin_nested():
            facts = await titles.read_facts(conn, p.id, titles.Context(ctx.classifier))
        if facts is not None and p.value.certainty in naming.CERTAINTIES:
            return titles.title_for_incident(facts, p.value.certainty).text[:200]
    except (DBAPIError, ValueError):
        pass
    tctx = titling.Context(ctx.classifier, tuple(ctx.campus_domains))
    try:
        async with conn.begin_nested():
            made = await titling.for_members(conn, ids, _marks(p, world), tctx, fallback)
    except DBAPIError:
        return fallback
    return (made or fallback)[:200]


async def _certainty_title(conn: AsyncConnection, p: Planned, ctx: Context) -> str:
    """The stored title with its certainty word following the engine's, once the incident has
    the checking lane's evidence (D-323), which can move it; the other words stay until a
    material change retitles them (``titles.retitle``)."""
    current = p.title
    word, _ = titles.split_certainty(current)
    if word is None or word == p.value.certainty or p.value.certainty not in naming.CERTAINTIES:
        return current
    try:
        async with conn.begin_nested():
            facts = await titles.read_facts(conn, p.id, titles.Context(ctx.classifier))
    except (DBAPIError, ValueError):
        return current
    if facts is None:
        return current
    made = titles.retitle(current, facts, p.value.certainty, material=False,
                          confirmed=p.confirmed)  # fmt: skip
    return current if made is None else made.text[:200]


_UPDATE = text(
    "UPDATE risk_incidents SET title = :title, certainty = :certainty,"
    " view = CAST(:view AS jsonb), shown = :shown, shown_day = :shown_day,"
    " queued_at = :queued_at, presented = CAST(:presented AS jsonb),"
    " presented_at = :presented_at WHERE id = :id"
)
_GRAY_UPSERT = text(
    "INSERT INTO risk_gray_items (object_id, priority, band, lane, certainty, title, view,"
    " first_seen, last_seen, updated_at) VALUES (:o, :priority, :band, :lane, :certainty,"
    " :title, CAST(:view AS jsonb), :first, :last, :now) ON CONFLICT (object_id) DO UPDATE SET"
    " priority = EXCLUDED.priority, band = EXCLUDED.band, lane = EXCLUDED.lane,"
    " certainty = EXCLUDED.certainty, title = EXCLUDED.title, view = EXCLUDED.view,"
    " first_seen = least(risk_gray_items.first_seen, EXCLUDED.first_seen),"
    " last_seen = EXCLUDED.last_seen, updated_at = EXCLUDED.updated_at"
)


def _row(p: Planned) -> dict[str, Any]:
    return {
        "id": p.id, "title": p.title[:200] or "Possible incident", "certainty": p.value.certainty,
        "view": json.dumps(p.view, sort_keys=True, default=str), "shown": p.shown,
        "shown_day": p.shown_day, "queued_at": p.queued_at,
        "presented": json.dumps(p.presented, sort_keys=True), "presented_at": p.presented_at,
    }  # fmt: skip


def _same(s: Stored, row: Mapping[str, Any]) -> bool:
    return (
        s.title == row["title"] and s.certainty == row["certainty"] and s.shown == row["shown"]
        and s.shown_day == row["shown_day"] and s.queued_at == row["queued_at"]
        and s.presented_at == row["presented_at"]
        and _hash(s.view) == _hash(json.loads(row["view"]))
        and _hash(s.presented) == _hash(json.loads(row["presented"]))
    )  # fmt: skip


async def _write(conn: AsyncConnection, planned: Plan, world: World, now: datetime) -> None:
    for p in planned.incidents:
        row = _row(p)
        if not _same(p.stored, row):
            await conn.execute(_UPDATE, row)
        if p.adopt is not None:
            await conn.execute(
                text("UPDATE risk_incidents SET case_id = :c WHERE id = :i AND case_id IS NULL"),
                {"c": p.adopt, "i": p.id},
            )
    kept = {g.obj.id for g in planned.gray}
    gone = sorted(world.gray_stored - kept)
    if gone:
        await conn.execute(
            text("DELETE FROM risk_gray_items WHERE object_id = ANY(CAST(:ids AS bigint[]))"),
            {"ids": gone},
        )
    if planned.gray:
        await conn.execute(_GRAY_UPSERT, [
            {"o": g.obj.id, "priority": g.value.priority, "band": g.value.band, "lane": g.lane,
             "certainty": g.value.certainty, "title": g.title,
             "view": json.dumps(g.view, sort_keys=True, default=str), "first": g.first_seen,
             "last": g.last_seen, "now": now}
            for g in planned.gray
        ])  # fmt: skip


@dataclass
class Report:
    incidents: int = 0
    new: int = 0
    requeued: int = 0
    shown: int = 0
    waiting: int = 0
    gray: int = 0
    opened: int = 0
    folded: int = 0
    adopted: int = 0  # undecided suggested cases an incident took as its own
    merged: int = 0  # cases of merged incidents joined to the survivor's (or taken as its own)
    told: int = 0  # closed cases told of new evidence on the alert groups they hold
    elsewhere: int = 0  # incidents another case has (not presented, not counted)
    skipped: list[str] = field(default_factory=list)  # incidents a case step left out, and why

    def line(self) -> str:
        cases = ""
        if self.opened or self.folded or self.adopted or self.merged or self.told:
            cases = (f"; cases opened {self.opened}, adopted {self.adopted}, folded into"
                     f" {self.folded}, merged {self.merged}, told after closure"
                     f" {self.told}")  # fmt: skip
        held = f", {self.elsewhere} held by another case" if self.elsewhere else ""
        skipped = ""
        if self.skipped:
            more = f" and {len(self.skipped) - 1} more" if len(self.skipped) > 1 else ""
            skipped = f"; {len(self.skipped)} not presented ({self.skipped[0]}{more})"
        return (f"presenter: {self.incidents} possible incidents ({self.new} new,"
                f" {self.requeued} changed), {self.shown} shown, {self.waiting} waiting{held},"
                f" {self.gray} in the gray band{cases}{skipped}")  # fmt: skip


async def record_mode(conn: AsyncConnection, present: bool, now: datetime) -> None:
    """The switch as this pass saw it, and when (the queue's pages read it; the assessment
    service stops the old feeds only while a presenting pass is recent: :func:`presenting`)."""
    await conn.execute(
        text(
            "INSERT INTO risk_mode (id, present, at) VALUES (1, :p, :now) ON CONFLICT (id)"
            " DO UPDATE SET present = EXCLUDED.present, at = EXCLUDED.at"
        ),
        {"p": present, "now": now},
    )


async def presenting(conn: AsyncConnection, now: datetime) -> bool:
    """Whether a presenter pass with ``risk.present`` on ran within :data:`ALIVE` of ``now``."""
    row = (await conn.execute(text("SELECT present, at FROM risk_mode WHERE id = 1"))).first()
    return row is not None and bool(row.present) and abs(now - row.at) <= ALIVE


async def run(
    engine: AsyncEngine, ctx: Context, now: datetime,
    verdicts: Mapping[ObjectRef, score.Verdict], ids: Mapping[ObjectRef, int],
    obs: Sequence[Observation],
) -> Report:  # fmt: skip
    """One presenter pass over the linker's incidents (see the module's docstring)."""
    report = Report()
    async with engine.begin() as conn:
        await record_mode(conn, ctx.options.present, now)
        world = await read(conn, now, ctx, verdicts, ids, obs)
        if ctx.options.present:
            await _take_over(conn, world, now, ctx)
        planned = plan(world, now, ctx)
        for p in planned.incidents:
            if p.retitle:
                p.title = await _title(conn, p, world, ctx)
            elif world.measured.get(p.id) and p.stored.title:
                p.title = await _certainty_title(conn, p, ctx)
        await _write(conn, planned, world, now)
    report.gray = len(planned.gray)
    for p in planned.incidents:
        if not p.stored.live:
            continue
        report.incidents += 1
        report.new += p.new
        report.requeued += p.requeued
        report.adopted += p.adopt is not None
        if p.elsewhere is not None:
            report.elsewhere += 1
        elif p.shown:
            report.shown += 1
        else:
            report.waiting += 1
    if ctx.options.present:
        await _present(engine, planned, world, now, report, ctx)
    return report


# --------------------------------------------------------------------------- presenting


_TAKEN = text(
    "SELECT DISTINCT investigation_id FROM case_members"
    " WHERE investigation_id = ANY(CAST(:ids AS uuid[])) AND removed_at IS NULL"
)
_TAKE_OVER = text(
    "UPDATE risk_incidents SET case_id = :c, shown = true, shown_day = coalesce(shown_day, :day),"
    " queued_at = coalesce(queued_at, :now), presented = CAST(:m AS jsonb), presented_at = :now,"
    " view = view || jsonb_build_object('shown_in', CAST(:mode AS text))"
    " WHERE id = :i AND case_id IS NULL"
)
# the undecided case of an incident the linker merged, and the incident that took its place
_ORPHANS = text(
    "WITH RECURSIVE chain AS ("
    " SELECT r.id AS orphan, r.case_id AS orphan_case, r.merged_into AS next, 1 AS depth"
    " FROM risk_incidents r JOIN cases c ON c.id = r.case_id"
    " WHERE r.state = 'merged' AND c.state = 'suspected' AND c.cause = 'raised'"
    " UNION ALL"
    " SELECT ch.orphan, ch.orphan_case, r.merged_into, ch.depth + 1 FROM chain ch"
    " JOIN risk_incidents r ON r.id = ch.next WHERE r.state = 'merged' AND ch.depth < 20)"
    " SELECT ch.orphan, ch.orphan_case, s.id AS survivor, s.case_id AS survivor_case,"
    " sc.state AS survivor_state, s.material FROM chain ch"
    " JOIN risk_incidents s ON s.id = ch.next AND s.state <> 'merged'"
    " LEFT JOIN cases sc ON sc.id = s.case_id"
    " WHERE s.case_id IS DISTINCT FROM ch.orphan_case ORDER BY ch.orphan"
)


async def _take_over(conn: AsyncConnection, world: World, now: datetime, ctx: Context) -> None:
    """A sealed incident's follow-on takes over the predecessor's open case (one case, one live
    incident: its new alert groups fold into it); a closed one stays the predecessor's, as the
    follow-on's memory."""
    claimed: set[uuid.UUID] = set()
    for s in world.stored:
        if not s.inherited or s.case_state == "closed" or s.case_id is None:
            continue
        if s.case_id in claimed:  # a second follow-on of the same case: it folds into it
            continue
        async with conn.begin_nested():
            await conn.execute(
                text("UPDATE risk_incidents SET case_id = NULL WHERE case_id = :c"
                     " AND state = 'sealed'"),
                {"c": s.case_id},
            )  # fmt: skip
            took = await conn.execute(_TAKE_OVER, {
                "c": s.case_id, "i": s.id, "day": site_day(now), "now": now,
                "m": json.dumps(s.material, sort_keys=True), "mode": mode_of(ctx),
            })  # fmt: skip
        if not took.rowcount:
            continue
        claimed.add(s.case_id)
        s.inherited, s.shown, s.shown_day = False, True, s.shown_day or site_day(now)
        s.queued_at, s.presented, s.presented_at = s.queued_at or now, dict(s.material), now
        s.view = {**s.view, "shown_in": mode_of(ctx)}
        for other in world.stored:  # the sealed predecessor, read this pass as its case was open
            if other.id != s.id and other.case_id == s.case_id and other.state == "sealed":
                other.case_id, other.case_state, other.case_closed_at = None, None, None


async def _merge_orphans(engine: AsyncEngine, planned: Plan, now: datetime, report: Report,
                         ctx: Context) -> None:  # fmt: skip
    """The undecided case of an incident the linker merged joins the survivor's case (a merge,
    as ``argus:engine``), or becomes the survivor's own when it has none; a survivor whose case
    a person closed keeps the orphan waiting (the lifecycle blocks such merges)."""
    actor = Actor.argus(PART)
    async with engine.connect() as conn:
        rows = (await conn.execute(_ORPHANS)).all()
    by_id = {p.id: p for p in planned.incidents}
    for r in rows:
        try:
            async with engine.begin() as conn:
                await conn.execute(
                    text("SELECT pg_advisory_xact_lock(:k)"), {"k": opener.OPENER_LOCK_KEY}
                )
                if r.survivor_case is None:
                    took = await conn.execute(_TAKE_OVER, {
                        "c": r.orphan_case, "i": int(r.survivor), "day": site_day(now),
                        "now": now, "m": json.dumps(r.material or {}, sort_keys=True),
                        "mode": mode_of(ctx),
                    })  # fmt: skip
                    if not took.rowcount:
                        continue
                    p = by_id.get(int(r.survivor))
                    if p is not None:
                        p.stored.case_id, p.stored.case_state = r.orphan_case, "suspected"
                        p.stored.inherited, p.shown = False, True
                    report.merged += 1
                    continue
                if r.survivor_state == "closed":
                    report.skipped.append(f"incident {r.orphan}: the incident it joined has a"
                                          " closed case")  # fmt: skip
                    continue
                service = await CaseService.start(conn)
                await service.merge(actor, r.orphan_case, r.survivor_case)
                report.merged += 1
        except CaseRefused as exc:
            report.skipped.append(f"incident {r.orphan}: {exc.message}")
            log.warning("risk: merging incident %s's case was refused (%s)", r.orphan,
                        exc.message)  # fmt: skip
        except DBAPIError as exc:
            code = getattr(exc.orig, "sqlstate", None)
            report.skipped.append(f"incident {r.orphan}: refused by the database ({code})")
            log.warning("risk: merging incident %s's case was refused (%s)", r.orphan, code)


def _attention(p: Planned) -> str:
    return f"{RAISED_REASON}{p.value.evidence_band} · {prio.line(p.value.why)}"[:500]


def _members(p: Planned, taken: Collection[uuid.UUID] = ()) -> tuple[Member, ...]:
    """The incident's alert groups no case holds yet (the newest :data:`MEMBERS_MAX`): none when
    the pass read them, and none in ``taken`` (the ones a case took since)."""
    free = [g for g in p.stored.groups if g.case_id is None and g.id not in taken]
    top = p.objects[0].label[:200] if p.objects else None
    return tuple(Member(g.id, "actor", top) for g in free[-MEMBERS_MAX:])


def _memory_holds(p: Planned, now: datetime) -> bool:
    """A closed case's "not an incident" memory: :data:`MEMORY` from its closing, unless a strong
    material change broke it."""
    closed = p.stored.case_closed_at
    if closed is None or now - closed > MEMORY:
        return False
    return not breaks(p.presented, p.stored.material)


def _told(p: Planned) -> str:
    """What the closed case is told when a strong change breaks its memory on the alert groups
    it holds (an investigation is in one case at a time: no new case can take them)."""
    said = ", ".join(p.stored.changed) or "a material change"
    line = prio.line(p.value.why)
    return f"New evidence since it was closed: {said} · {p.value.evidence_band} · {line}"[:500]


async def _present(
    engine: AsyncEngine, planned: Plan, world: World, now: datetime, report: Report,
    ctx: Context,
) -> None:  # fmt: skip
    """Join the cases of merged incidents to their survivors', then, for each incident a person
    could decide (shown or waiting for Today's room), open its suspected case when it has none
    (or its closed case's memory ended), and fold its new alert groups into its case, each in
    its own transaction. A strong change on the alert groups a closed case holds is told to
    that case instead."""
    actor = Actor.argus(PART)
    await _merge_orphans(engine, planned, now, report, ctx)
    for p in planned.incidents:
        if p.elsewhere is not None or (p.case_id is None and not p.stored.live):
            continue
        if p.closed and (not p.stored.live or _memory_holds(p, now)):
            continue
        tell = p.closed and p.stored.live and breaks(p.presented, p.stored.material)
        if not _members(p) and not tell:
            continue
        marks = _marks(p, world)
        severity = SEVERITY[p.value.evidence_band]  # a person's confirm raises no severity
        try:
            async with engine.begin() as conn:
                await conn.execute(
                    text("SELECT pg_advisory_xact_lock(:k)"), {"k": opener.OPENER_LOCK_KEY}
                )
                # a case may have taken some since the pass read them
                taken = set((await conn.execute(_TAKEN, {"ids": [g.id for g in p.stored.groups]}))
                            .scalars())  # fmt: skip
                members = _members(p, taken)
                service = await CaseService.start(conn)
                if not members:
                    if tell and p.case_id is not None:
                        await _tell(conn, service, actor, p, now)
                        report.told += 1
                    elif p.case_id is None:
                        report.skipped.append(f"incident {p.id}: other cases hold its alert"
                                              " groups")  # fmt: skip
                    continue
                if p.case_id is None or p.closed:
                    held = (await conn.execute(  # another pass may have presented it meanwhile
                        text("SELECT case_id FROM risk_incidents WHERE id = :i FOR UPDATE"),
                        {"i": p.id},
                    )).first()  # fmt: skip
                    if held is None or held.case_id != p.stored.own_case_id:
                        continue
                    applied = await service.open(actor, Open(
                        p.title, severity, "raised", members, marks, suspected=True,
                        attention=_attention(p),
                    ))  # fmt: skip
                    view = dict(p.view)
                    if p.stored.case_id is not None:
                        view["previous_cases"] = [*view.get("previous_cases", []),
                                                  str(p.stored.case_id)]  # fmt: skip
                    await conn.execute(
                        text(
                            "UPDATE risk_incidents SET case_id = :c, view = CAST(:view AS jsonb),"
                            " presented = CAST(:m AS jsonb), presented_at = :now,"
                            " queued_at = :now WHERE id = :i"
                        ),
                        {"c": applied.case.id, "i": p.id,
                         "view": json.dumps(view, sort_keys=True, default=str),
                         "m": json.dumps(p.stored.material, sort_keys=True), "now": now},
                    )  # fmt: skip
                    report.opened += 1
                else:
                    case = await service.get(p.case_id, lock=True)
                    if case is None or case.state == "closed":
                        continue
                    await service.apply(actor, p.case_id, Link(members, (), severity),
                                        expected_version=None)  # fmt: skip
                    report.folded += 1
        except CaseRefused as exc:
            report.skipped.append(f"incident {p.id}: {exc.message}")
            log.warning("risk: presenting incident %s was refused (%s)", p.id, exc.message)
        except DBAPIError as exc:
            code = getattr(exc.orig, "sqlstate", None)
            report.skipped.append(f"incident {p.id}: refused by the database ({code})")
            log.warning("risk: presenting incident %s was refused (%s)", p.id, code)


async def _tell(conn: AsyncConnection, service: CaseService, actor: Actor, p: Planned,
                now: datetime) -> None:  # fmt: skip
    """The closed case's ``activity_after_closure`` note: Today's New activity lists the case
    until a person acts on it. What was told is what the person was last shown (``presented``),
    so only a further strong change tells again; the memory is not renewed."""
    assert p.case_id is not None
    await service.apply(actor, p.case_id, AfterClosure(summary=_told(p)), expected_version=None)
    view = {**p.view, "after_closure": p.stored.version}
    await conn.execute(
        text(
            "UPDATE risk_incidents SET view = CAST(:view AS jsonb),"
            " presented = CAST(:m AS jsonb), presented_at = :now WHERE id = :i"
        ),
        {"view": json.dumps(view, sort_keys=True, default=str), "i": p.id,
         "m": json.dumps(p.stored.material, sort_keys=True), "now": now},
    )  # fmt: skip
