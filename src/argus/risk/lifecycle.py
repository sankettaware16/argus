"""Step 7 of the engine (E2): the incident's lifecycle. Pure: the pass and the replay run it.

An **incident** is a set of linked campus objects and the alert groups on them. Each pass:

1. **Match.** A component (``link.components``) holding an object of a live incident joins it;
   two live incidents a component touches merge, the older one keeps the id, unless a **merge
   blocker** holds (a sealed or merged incident, a person's decision on either one — a confirmed
   or a closed case is theirs, and people merge cases themselves — different owners, or the cap
   of risk objects): then the link is kept as a recommendation. A component
   that touches none opens a new incident when one of its objects is in a lane; one holding a
   sealed incident's objects opens a linked new incident only with an alert group no incident
   holds yet (new activity).
2. **Fold.** Every alert group with an observation on an incident's objects joins it silently,
   for any rule and any day; past the group cap a linked overflow incident takes the rest (a
   merge too: the kept incident takes the other's groups within its cap, and its overflows).
3. **Material change**, the only re-queue: a new source, stage, log family or flagged outside
   thing, more devices (1, 2-3, 4-10, 11+) or a higher priority band. The version rises and the
   change is said in words; anything else updates counts only.
4. **Ageing.** Quiet after ``quiet_hours`` without an observation (shown, ranked lower); a
   "stopped" proposal after ``stop_days`` quiet; sealed ``seal_days`` after it began: it stops
   growing, and later activity of its objects opens a linked new incident. The pass seals
   (:func:`seal`) before it builds the linker's candidates, so a sealed incident's objects are
   no members any more.
"""

from __future__ import annotations

import hashlib
import json
import math
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

from argus.risk.config import STAGES
from argus.risk.identity import DAY_MARK, device_of
from argus.risk.incident_config import IncidentConfig
from argus.risk.link import Component, Link
from argus.risk.observe import ObjectRef, Observation

State = Literal["active", "quiet", "sealed", "merged"]
LIVE: tuple[State, ...] = ("active", "quiet")
BANDS = ("P4", "P3", "P2", "P1")
LANE_ORDER = ("decisive", "campaign", "exposure", "burst", "slow")


def bucket(devices: int) -> int:
    """Device counts that matter: 1, 2-3, 4-10, 11 and more."""
    return 0 if devices <= 1 else 1 if devices <= 3 else 2 if devices <= 10 else 3


BUCKET_WORDS = ("1 device", "2-3 devices", "4-10 devices", "11 or more devices")


@dataclass(frozen=True)
class Material:
    """What a re-queue is judged on (all only ever grow, except the band)."""

    sources: frozenset[str] = frozenset()
    stages: int = 0
    families: frozenset[str] = frozenset()
    flagged: frozenset[str] = frozenset()
    devices: int = 0  # the bucket
    band: str = "P4"

    def as_json(self) -> dict[str, Any]:
        return {"sources": sorted(self.sources), "stages": self.stages,
                "families": sorted(self.families), "flagged": sorted(self.flagged),
                "devices": self.devices, "band": self.band}  # fmt: skip

    @staticmethod
    def of_json(data: Mapping[str, Any] | None) -> Material:
        if not data:
            return Material()
        return Material(
            frozenset(data.get("sources", ())), int(data.get("stages", 0)),
            frozenset(data.get("families", ())), frozenset(data.get("flagged", ())),
            int(data.get("devices", 0)), str(data.get("band", "P4")),
        )  # fmt: skip

    def digest(self) -> str:
        raw = json.dumps(self.as_json(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode()).hexdigest()[:32]


def grow(old: Material, new: Material) -> Material:
    """What the incident has seen so far: the union, the larger bucket, the highest band (a band
    that falls and rises again is no new change)."""
    top = max(old.band, new.band, key=BANDS.index)
    return Material(
        old.sources | new.sources, old.stages | new.stages, old.families | new.families,
        old.flagged | new.flagged, max(old.devices, new.devices), top,
    )  # fmt: skip


def _source_words(source: str) -> str:
    kind, _, name = source.partition(":")
    return f"evidence: {name.replace('_', ' ')}" if kind == "ev" else "another rule"


def changes(old: Material, new: Material) -> list[str]:
    """The material differences, in words (empty: nothing material)."""
    out: list[str] = []
    added = sorted(new.sources - old.sources)
    rules = [s for s in added if s.startswith("rule:")]
    for s in added:
        if not s.startswith("rule:"):
            out.append("new " + _source_words(s))
    if rules:
        out.append(f"{len(rules)} new rule{'s' if len(rules) > 1 else ''}")
    gained = new.stages & ~old.stages
    if gained:
        out.append("new stage: " + ", ".join(s for i, s in enumerate(STAGES) if gained >> i & 1))
    for f in sorted(new.families - old.families):
        out.append(f"new log family: {f}")
    for t in sorted(new.flagged - old.flagged)[:5]:
        out.append(f"newly flagged: {t.split(':', 1)[-1]}")
    if new.devices > old.devices:
        out.append(f"now {BUCKET_WORDS[new.devices]}")
    if BANDS.index(new.band) > BANDS.index(old.band):
        out.append(f"priority rose to {new.band}")
    return out


def priority(top: float, others: Sequence[float]) -> int:
    """A provisional priority (0-100) from the objects' 7-day scores: the top object's and a
    share of the next five. The priority step (E5) replaces it through ``band_of``."""
    x = top + 0.3 * sum(sorted(others, reverse=True)[:5])
    return round(100 * (1 - math.exp(-x / 80)))


def band(value: int) -> str:
    return "P1" if value >= 70 else "P2" if value >= 45 else "P3" if value >= 25 else "P4"


@dataclass(eq=False)  # one incident is one object: compared and hashed by identity
class Incident:
    """One incident as the lifecycle holds it."""

    id: int | None
    created_at: datetime
    first_seen: datetime
    last_seen: datetime
    objects: dict[ObjectRef, str] = field(default_factory=dict)  # ref -> actor | affected
    groups: dict[uuid.UUID, datetime] = field(default_factory=dict)  # group -> joined
    lanes: set[str] = field(default_factory=set)
    state: State = "active"
    version: int = 1
    material: Material = Material()
    changed: list[str] = field(default_factory=list)
    material_at: datetime | None = None
    stop_proposed_at: datetime | None = None
    campaign: bool = False
    parent: int | None = None  # the incident this one overflows
    root: Incident | None = None  # the same, while that one has no id yet
    follows: int | None = None  # the sealed incident this one continues
    merged_into: int | None = None
    owner: int | None = None  # the person who holds its case: different owners never merge
    decision: str | None = None  # a person's decision on its case (confirmed, closed): never merged
    links: list[Link] = field(default_factory=list)
    recommended: list[Link] = field(default_factory=list)
    priority: int = 0
    band: str = "P4"
    key: str = ""  # a stable handle for a new incident before it has an id
    new: bool = False  # opened at this pass
    requeued: bool = False  # a material change at this pass
    # device -> the device it is with others (identity.same_devices), as the pass read it
    same: Mapping[ObjectRef, str] = field(default_factory=dict)

    @property
    def devices(self) -> int:
        """Its devices: an address's days are one, and so are the addresses the pass read as
        one device that moved (``same``, D-334)."""
        return len({device_of(o, self.same) for o in self.objects if o.kind == "device"})

    @property
    def size(self) -> int:
        """Its risk objects, as the caps count them (a device's days are one)."""
        return len({device_of(o) for o in self.objects})

    @property
    def live(self) -> bool:
        return self.state in LIVE

    @property
    def overflow(self) -> bool:
        return self.parent is not None or self.root is not None

    def lane(self) -> str:
        for lane in LANE_ORDER:
            if lane in self.lanes:
                return lane
        return "slow"


@dataclass(frozen=True)
class Facts:
    """What the lifecycle reads of the window at a pass."""

    groups: Mapping[ObjectRef, Sequence[tuple[uuid.UUID, datetime]]]  # object -> its groups
    observations: Mapping[ObjectRef, Sequence[Observation]]
    flagged: Callable[[str], bool]
    score_7d: Mapping[ObjectRef, float] = field(default_factory=dict)
    roles: Mapping[ObjectRef, str] = field(default_factory=dict)
    same: Mapping[ObjectRef, str] = field(default_factory=dict)  # addresses that are one device


def facts_of(obs: Iterable[Observation], now: datetime, flagged: Callable[[str], bool],
             score_7d: Mapping[ObjectRef, float] | None = None,
             same: Mapping[ObjectRef, str] | None = None) -> Facts:  # fmt: skip
    groups: dict[ObjectRef, dict[uuid.UUID, datetime]] = {}
    per: dict[ObjectRef, list[Observation]] = {}
    roles: dict[ObjectRef, str] = {}
    for o in obs:
        if o.at > now:
            continue
        held = groups.setdefault(o.object, {})
        if o.group not in held or o.at > held[o.group]:
            held[o.group] = o.at
        per.setdefault(o.object, []).append(o)
        if roles.get(o.object) != "actor":
            roles[o.object] = o.role
    return Facts(
        {r: sorted(g.items(), key=lambda kv: (kv[1], str(kv[0]))) for r, g in groups.items()},
        per, flagged, score_7d or {}, roles, same or {},
    )  # fmt: skip


def material_of(inc: Incident, facts: Facts, band_of: Callable[[Incident], str]) -> Material:
    inc.same = facts.same  # its devices are counted as this pass read them
    sources: set[str] = set()
    stages = 0
    families: set[str] = set()
    flagged: set[str] = set()
    for ref in inc.objects:
        for o in facts.observations.get(ref, ()):
            if o.at < inc.first_seen - timedelta(days=14):
                continue
            sources.add(o.source_key)
            stages |= o.stages
            if o.family and o.source_kind == "rule":
                families.add(o.family)
            flagged.update(t for t in o.threats if facts.flagged(t))
    return Material(frozenset(sources), stages, frozenset(families), frozenset(flagged),
                    bucket(inc.devices), band_of(inc))  # fmt: skip


def provisional_band(inc: Incident, facts: Facts) -> str:
    scores = sorted((facts.score_7d.get(r, 0.0) for r in inc.objects), reverse=True)
    inc.priority = priority(scores[0], scores[1:]) if scores else 0
    return band(inc.priority)


MEMBER = "member"  # not a lane: an object a live incident already holds


def seal(incidents: Iterable[Incident], now: datetime, config: IncidentConfig) -> None:
    """Seal every live incident ``seal_days`` after it began: it takes nothing more. The pass
    calls it before :func:`candidates_of` (and :func:`advance` again)."""
    span = timedelta(days=config.lifecycle.seal_days)
    for inc in incidents:
        if inc.live and now - inc.created_at >= span:
            inc.state = "sealed"


def candidates_of(
    lanes: Mapping[ObjectRef, Sequence[str]], incidents: Iterable[Incident]
) -> dict[ObjectRef, tuple[str, ...]]:
    """What the linker starts from: the objects in a lane, and those a live incident already
    holds (a new object linked to one joins its incident). Seal first (:func:`seal`)."""
    out = {ref: tuple(v) for ref, v in lanes.items() if v}
    for inc in incidents:
        if inc.live and not inc.overflow:
            for ref in inc.objects:
                out.setdefault(ref, (MEMBER,))
    return out


def can_merge(a: Incident, b: Incident, cap: int) -> bool:
    """The merge blockers: both live, nobody's decision on either (a person's confirm or
    closure makes the incident theirs: the link is kept as a recommendation, and people merge
    cases themselves), the same owner, within the cap."""
    if not (a.live and b.live) or a.overflow or b.overflow:
        return False
    if a.decision is not None or b.decision is not None or a.owner != b.owner:
        return False
    return len({device_of(o) for o in (*a.objects, *b.objects)}) <= cap


@dataclass
class Outcome:
    incidents: list[Incident]
    opened: list[Incident] = field(default_factory=list)
    requeued: list[Incident] = field(default_factory=list)
    merged: list[tuple[Incident, Incident]] = field(default_factory=list)  # (kept, gone)


def _role(ref: ObjectRef, facts: Facts) -> str:
    return "affected" if facts.roles.get(ref) == "target" else "actor"


def advance(
    incidents: Sequence[Incident], comps: Sequence[Component], facts: Facts, now: datetime,
    config: IncidentConfig, band_of: Callable[[Incident], str] | None = None,
) -> Outcome:  # fmt: skip
    """One pass of the lifecycle (see the module's docstring). ``incidents``: those held (they
    are changed in place); new ones have no id and a ``key``."""
    band_fn = band_of or (lambda inc: provisional_band(inc, facts))

    def cap_of(inc: Incident) -> int:
        return config.caps.campaign_objects if inc.campaign else config.caps.objects

    held = list(incidents)
    for inc in held:
        inc.new = inc.requeued = False
    seal(held, now, config)  # sealed first: a sealed incident takes nothing more
    taken = {g for i in held if i.state != "merged" for g in i.groups}
    owner_of: dict[ObjectRef, Incident] = {}
    sealed_of: dict[ObjectRef, Incident] = {}
    for inc in sorted(held, key=_order):
        if inc.overflow or inc.state == "merged":
            continue
        for ref in inc.objects:
            if inc.live:
                owner_of.setdefault(ref, inc)
            elif inc.state == "sealed":
                prior = sealed_of.get(ref)
                if prior is None or inc.created_at > prior.created_at:
                    sealed_of[ref] = inc
    out = Outcome(held)
    count = 0
    for comp in comps:
        touched = sorted({owner_of[r] for r in comp.objects if r in owner_of}, key=_order)
        if touched:
            target = touched[0]
            for other in touched[1:]:
                if other.state == "merged":
                    continue
                if can_merge(target, other, max(cap_of(target), cap_of(other))):
                    _merge(target, other, now, held, config)
                    out.merged.append((target, other))
                    for ref in other.objects:
                        owner_of[ref] = target
                else:
                    target.recommended.extend(
                        lk for lk in comp.links
                        if lk.b is not None and ({lk.a, lk.b} & set(other.objects))
                    )  # fmt: skip
        else:
            if all(lane == MEMBER for lanes in comp.lanes.values() for lane in lanes):
                continue  # members of an incident sealed at this pass, and nothing in a lane
            times = [(g, t) for r in comp.objects for g, t in facts.groups.get(r, ())]
            follows = sorted({sealed_of[r] for r in comp.objects if r in sealed_of}, key=_order)
            if follows:  # a sealed incident's objects: only new activity opens its follow-on
                times = [(g, t) for g, t in times if g not in taken]
                if not times:
                    continue
            count += 1
            first = min((t for _, t in times), default=now)
            target = Incident(None, now, first, first, key=f"new-{now.isoformat()}-{count}",
                              new=True, follows=follows[-1].id if follows else None)  # fmt: skip
            held.append(target)
            out.opened.append(target)
        target.campaign = target.campaign or comp.campaign
        cap = cap_of(target)
        for ref in comp.objects:
            if ref in target.objects or (ref in owner_of and owner_of[ref] is not target):
                continue
            size = {device_of(o) for o in target.objects}
            if len(size | {device_of(ref)}) > cap:
                target.recommended.extend(lk for lk in comp.links if ref in (lk.a, lk.b))
                continue
            target.objects[ref] = _role(ref, facts)
            owner_of[ref] = target
        for ref, lanes in comp.lanes.items():
            if ref in target.objects:
                target.lanes.update(lane for lane in lanes if lane != MEMBER)
        known = {(lk.a, lk.b, lk.via, lk.value) for lk in target.links}
        target.links.extend(
            lk for lk in comp.links
            if (lk.a, lk.b, lk.via, lk.value) not in known and lk.a in target.objects
            and (lk.b is None or lk.b in target.objects)
        )  # fmt: skip
        seen_rec = {(lk.a, lk.b, lk.value) for lk in target.recommended}
        for lk in comp.recommended:
            if (lk.a, lk.b, lk.value) not in seen_rec:
                target.recommended.append(lk)
                seen_rec.add((lk.a, lk.b, lk.value))
    _fold(held, facts, now, config)
    for inc in held:
        if inc.state == "merged":
            continue
        if inc.live:
            _age(inc, now, config)
        if inc.overflow:
            continue
        new = material_of(inc, facts, band_fn)
        inc.band = new.band
        if inc.new:
            inc.material, inc.changed, inc.material_at = new, ["new incident"], now
            continue
        said = changes(inc.material, new)
        inc.material = grow(inc.material, new)
        if said and inc.live:
            inc.version += 1
            inc.changed, inc.material_at, inc.requeued = said, now, True
            out.requeued.append(inc)
    return out


def _order(inc: Incident) -> tuple[int, str]:
    return (inc.id if inc.id is not None else 1 << 62, inc.key)


def _kids(root: Incident, held: Iterable[Incident]) -> list[Incident]:
    """The overflows of ``root`` (by object, or by id once stored)."""
    return [
        i for i in held if i.overflow and i.state != "merged" and (
            i.root is root or (i.root is None and root.id is not None and i.parent == root.id)
        )
    ]  # fmt: skip


def _home(root: Incident, at: datetime, now: datetime, held: list[Incident],
          kids: list[Incident], config: IncidentConfig) -> Incident:  # fmt: skip
    """Where one more alert group of ``root`` goes: the root within the group cap, else an
    overflow with room, else a new linked overflow."""
    cap = config.caps.groups
    if len(root.groups) < cap:
        return root
    room = next((k for k in kids if len(k.groups) < cap), None)
    if room is not None:
        return room
    kid = Incident(
        None, now, at, at, dict(root.objects), state="active", parent=root.id, root=root,
        key=f"{root.key or root.id}-overflow-{len(kids) + 1}", campaign=root.campaign,
    )  # fmt: skip
    kid.lanes = set(root.lanes)
    kids.append(kid)
    held.append(kid)
    return kid


def _merge(target: Incident, other: Incident, now: datetime, held: list[Incident],
           config: IncidentConfig) -> None:  # fmt: skip
    """``other`` joins ``target``: its objects, and its alert groups within the group cap (the
    rest to ``target``'s overflows); its overflows become ``target``'s."""
    for ref, role in other.objects.items():
        target.objects.setdefault(ref, role)
    kids = _kids(target, held)
    for kid in _kids(other, held):
        kid.root, kid.parent = target, target.id
        kids.append(kid)
    holding = {g for k in (target, *kids) for g in k.groups}
    for gid, joined in sorted(other.groups.items(), key=lambda kv: (kv[1], str(kv[0]))):
        if gid not in holding:
            home = _home(target, joined, now, held, kids, config)
            home.groups[gid] = joined
            home.last_seen = max(home.last_seen, joined)
            holding.add(gid)
    target.lanes |= other.lanes
    target.links.extend(other.links)
    target.first_seen = min(target.first_seen, other.first_seen)
    target.last_seen = max(target.last_seen, other.last_seen)
    target.campaign = target.campaign or other.campaign
    target.material = grow(target.material, other.material)
    other.state, other.merged_into = "merged", target.id
    other.objects, other.groups = {}, {}
    if other.new:  # opened and merged in one pass: it never was
        other.new = False


def _fold(held: list[Incident], facts: Facts, now: datetime, config: IncidentConfig) -> None:
    """Every alert group on an incident's objects joins it (past the cap, its overflow). A new
    incident begins at its first alert group (a sealed one's follow-on: at its first new one)."""
    roots = [i for i in held if not i.overflow and i.live]
    by_id = {i.id: i for i in held if i.id is not None}
    kids_of: dict[int, list[Incident]] = {}  # the root (by object identity) -> its overflows
    for inc in held:
        if inc.overflow and inc.state != "merged":
            root = inc.root or (by_id.get(inc.parent) if inc.parent is not None else None)
            if root is not None:
                kids_of.setdefault(id(root), []).append(inc)
    taken = {g for i in held if i.state != "merged" for g in i.groups}
    for inc in sorted(roots, key=_order):
        found: dict[uuid.UUID, datetime] = {}
        for ref in inc.objects:
            for gid, at in facts.groups.get(ref, ()):
                fresh = gid not in taken
                if fresh:
                    found[gid] = min(at, found.get(gid, at))
                inc.last_seen = max(inc.last_seen, at)
                if inc.new and (fresh or inc.follows is None):
                    inc.first_seen = min(inc.first_seen, at)
        kids = kids_of.setdefault(id(inc), [])
        for gid, at in sorted(found.items(), key=lambda kv: (kv[1], str(kv[0]))):
            home = _home(inc, at, now, held, kids, config)
            home.groups[gid] = now
            home.last_seen = max(home.last_seen, at)
            taken.add(gid)


def _age(inc: Incident, now: datetime, config: IncidentConfig) -> None:
    life = config.lifecycle
    idle = now - inc.last_seen
    if idle >= timedelta(hours=life.quiet_hours):
        inc.state = "quiet"
        if idle >= timedelta(days=life.stop_days) and inc.stop_proposed_at is None:
            inc.stop_proposed_at = now
    else:
        inc.state = "active"
        inc.stop_proposed_at = None


# --------------------------------------------------------------------------- what others read


def label(ref: ObjectRef) -> str:
    """An object as a person reads it: the address (and its day, for a dynamic one), the host,
    the account or the site."""
    kind, _, value = ref.key.partition(":")
    if ref.kind == "device" and kind == "ip" and DAY_MARK in value:
        address, _, day = value.partition(DAY_MARK)
        return f"{address} (on {day})"
    return value if kind in ("ip", "host", "domain") else ref.key


def view_part(inc: Incident, now: datetime) -> dict[str, Any]:
    """The incident's part of the engine view (the priority step adds priority, certainty, the
    why line, checks and alternatives): lane, objects, active, first and last seen, version and
    what changed."""
    objects = sorted(inc.objects.items(), key=lambda kv: (kv[1] != "actor", kv[0]))
    return {
        "lane": inc.lane(),
        "objects": [{"kind": ref.kind, "label": label(ref), "role": role}
                    for ref, role in objects[:50]],
        "active": inc.state == "active",
        "first_seen": inc.first_seen.isoformat(),
        "last_seen": inc.last_seen.isoformat(),
        "version": inc.version,
        "changed": list(inc.changed),
        "provisional_priority": inc.priority,
        "provisional_band": inc.band,
    }  # fmt: skip
