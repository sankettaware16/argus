"""The incident replay (P4-F E2): at each step of ``argus.risk.replay``'s clock, the linker and
the lifecycle run on what the copy held then, in memory, exactly as the pass runs them; the
report says, per day, how many incidents a person would have been asked to look at, and per
known incident, how many pieces it came in (every incident opened on its objects, merged later
or not) and how much of it one incident held, at the end and when people found it.

Outside detections and the popularity list are the replay mode's (``db``: from when the cache
fetched them, popularity as the pass reads it, ranked within ``detection_days``; ``oracle``: from
the start; ``no-vt``: none); a group's strong evidence names its outside thing from when it
was known; ``argus.campaigns``' analysis runs every few hours of the clock on the copy's own
sightings and cached answers, timed as the mode says. It reads the copy and writes nothing."""

from __future__ import annotations

import time
import uuid
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus import site
from argus.campaigns import analysis
from argus.campaigns import load as campaign_load
from argus.campaigns.families import Sighting
from argus.cases.membership import NO_SHARED, Shared
from argus.outside.psl import registered_parent
from argus.risk import lifecycle, link
from argus.risk.identity import address_of, device_of
from argus.risk.incident_config import IncidentConfig
from argus.risk.incidents import bindings_of, group_flags, merge_flags
from argus.risk.lifecycle import Incident
from argus.risk.link import Flag, World
from argus.risk.observe import ObjectRef, Observation
from argus.risk.replay import Incident as Known
from argus.risk.replay import Loaded
from argus.risk.score import Stats, Verdict

CAMPAIGN_EVERY = timedelta(hours=6)
BANDS = ("P1", "P2", "P3", "P4")
Ranker = Callable[[Mapping[ObjectRef, Verdict], datetime], Callable[[Incident], str]]


def shown(bands: Mapping[str, int], waiting: int = 0, room: int = 10) -> tuple[int, int]:
    """What the capacity governor shows on a day, and what waits after it: every P1 and P2 of
    the day's new incidents, then P3 and P4 (the ones waiting from earlier days with the day's)
    while there is room (E5); the rest wait for the next day's room."""
    urgent = bands.get("P1", 0) + bands.get("P2", 0)
    queued = waiting + bands.get("P3", 0) + bands.get("P4", 0)
    taken = min(queued, max(0, room - urgent))
    return urgent + taken, queued - taken


@dataclass
class Answers:
    """The copy's cached VirusTotal answers the campaign analysis reads: by domain parent and by
    address, each (status, answer, fetched_at)."""

    domains: dict[str, list[tuple[str, Mapping[str, Any], datetime]]] = field(default_factory=dict)
    addresses: dict[str, list[tuple[str, Mapping[str, Any], datetime]]] = field(
        default_factory=dict
    )


async def answers(conn: AsyncConnection, loaded: Loaded) -> Answers:
    """Every cached VirusTotal answer for the window's domain parents and their addresses."""
    parents = sorted({p for names in loaded.domains.values() for n in names
                      if (p := registered_parent(n))})  # fmt: skip
    out = Answers()
    if not parents:
        return out
    rows = await conn.execute(
        text(
            "SELECT kind, indicator, status, answer, fetched_at FROM outside_lookups"
            " WHERE source = 'virustotal' AND ((kind = 'domain' AND indicator = ANY(:p))"
            " OR kind = 'ip')"
        ),
        {"p": parents},
    )
    for r in rows:
        if not isinstance(r.answer, Mapping):
            continue
        where = out.domains if r.kind == "domain" else out.addresses
        where.setdefault(r.indicator, []).append((r.status, r.answer, r.fetched_at))
    return out


def _known(
    held: Sequence[tuple[str, Mapping[str, Any], datetime]], clock: datetime, mode: str
) -> tuple[str, Mapping[str, Any]] | None:
    """The newest answer the mode knows at ``clock``."""
    if mode == "no-vt" or not held:
        return None
    seen = [h for h in held if mode == "oracle" or h[2] <= clock]
    if not seen:
        return None
    newest = max(seen, key=lambda h: h[2])
    return newest[0], newest[1]


def campaigns_at(
    loaded: Loaded, cached: Answers, clock: datetime, mode: str, window: timedelta,
    threshold: int, shared: Shared, visible: Sequence[Observation],
) -> list[analysis.Campaign]:  # fmt: skip
    """``argus.campaigns``' analysis on the groups the copy held at ``clock``."""
    objects: dict[uuid.UUID, set[ObjectRef]] = defaultdict(set)
    ips: dict[uuid.UUID, set[str]] = defaultdict(set)
    for o in visible:
        objects[o.group].add(o.object)
        if o.source_kind == "rule" and o.role == "actor":
            ips[o.group].update(t.split(":", 1)[1] for t in o.threats if t.startswith("ip:"))
    sightings = []
    hosts: dict[uuid.UUID, frozenset[tuple[str, str]]] = {}
    for gid, refs in objects.items():
        meta = loaded.groups.get(gid)
        if meta is None or meta.last_at < clock - window:
            continue
        keys = frozenset(
            ("ip", a) if (a := address_of(r)) is not None else ("host", r.key[5:])
            for r in refs if r.kind == "device"
        )  # fmt: skip
        if keys:
            hosts[gid] = keys
        names = loaded.domains.get(gid, set())
        if names:
            sightings.append(Sighting(gid, keys, frozenset(names)))
    readings: dict[str, analysis.Reading] = {}
    parents = {p for s in sightings for n in s.names if (p := registered_parent(n))}
    for p in sorted(parents):
        got = _known(cached.domains.get(p, []), clock, mode)
        if got is None or not analysis.current(*got):
            continue
        reading = analysis.reading_of(*got)
        first = campaign_load.first_address(reading.addresses,
                                            lambda a: shared.reason("ip", a) is None)  # fmt: skip
        ip = _known(cached.addresses.get(first, []), clock, mode) if first else None
        if ip is not None and ip[0] == "found":
            reading = analysis.reading_of(got[0], got[1], ip[1], first)
        readings[p] = reading
    servers: dict[str, set[uuid.UUID]] = defaultdict(set)
    for gid, values in ips.items():
        for a in values:
            got = _known(cached.addresses.get(a, []), clock, mode)
            if got is not None and got[0] == "found":
                try:
                    bad = int(got[1].get("malicious") or 0)
                except (TypeError, ValueError):
                    bad = 0
                if bad >= threshold:
                    servers[a].add(gid)
    world = analysis.World(tuple(sorted(sightings, key=lambda s: str(s.investigation_id))),
                           readings, {a: frozenset(i) for a, i in servers.items()}, hosts,
                           threshold)  # fmt: skip
    found = analysis.analyse(
        world, shared=shared, usable=lambda p: shared.reason("domain", p) is None
    )
    return list(found.campaigns)


def detection_flags(loaded: Loaded, threats: Sequence[str]) -> dict[str, Flag]:
    """The mode's outside detections of the window's outside things (a domain by its parent's own
    answer, when no popularity list ranks it)."""
    out: dict[str, Flag] = {}
    for t in threats:
        kind, _, value = t.partition(":")
        if kind not in ("ip", "domain"):
            continue
        hit = loaded.detections.get((kind, value))
        if hit is None or (kind == "domain" and not hit[1]):
            continue
        out[t] = Flag("outside", hit[0])
    return out


class IncidentReplay:
    """The linker and the lifecycle at each replay step (the callback of ``replay.replay``)."""

    def __init__(
        self, loaded: Loaded, config: IncidentConfig, *, mode: str, threshold: int = 3,
        shared: Shared = NO_SHARED, cached: Answers | None = None,
        known: Mapping[str, Known] | None = None, start: datetime | None = None,
        detection_days: int = 30, ranker: Ranker | None = None, room: int = 10,
    ) -> None:  # fmt: skip
        self.loaded = loaded
        self.config = config
        self.mode = mode
        self.ranker = ranker  # E5: the priority step; None: the provisional band
        self.room = room
        self.threshold = threshold
        self.shared = shared
        self.cached = cached or Answers()
        self.known = dict(known or {})
        self.start = start
        self.detection_days = timedelta(days=detection_days)
        threats = sorted({t for o in loaded.observations for t in o.threats})
        self.detections = detection_flags(loaded, threats)
        self.ranked: dict[str, list[datetime]] = {}  # a ranked domain -> when the cache said so
        for p, held in self.cached.domains.items():
            times = sorted(at for status, a, at in held
                           if status == "found" and a.get("ranked") is True)  # fmt: skip
            if times:
                self.ranked[f"domain:{p}"] = times
        self.incidents: list[Incident] = []
        self.next_id = 1
        self.opened_at: dict[int, datetime] = {}
        self.opened_counted: dict[int, bool] = {}
        self.ever: dict[int, set[ObjectRef]] = defaultdict(set)  # each incident's objects, ever
        self.at_people: dict[str, dict[str, Any]] = {}  # a known incident when people found it
        self.per_day: dict[date, Counter[str]] = defaultdict(Counter)
        self.largest: dict[date, int] = defaultdict(int)
        self.largest_campaign: dict[date, int] = defaultdict(int)
        self.campaigns: list[analysis.Campaign] = []
        self.campaigns_at: datetime | None = None
        self.campaign_count = 0
        self.seconds = 0.0
        self.steps = 0
        self.why_requeued: Counter[str] = Counter()
        self.flags: dict[str, Flag] = {}
        self.bands: dict[date, Counter[str]] = defaultdict(Counter)  # E5: new incidents by band
        self.rose: dict[date, Counter[str]] = defaultdict(Counter)  # re-queued into a band

    def popular(self, clock: datetime) -> frozenset[str]:
        """The domains a popularity list ranks, as the mode knows them at ``clock`` (the pass:
        a ranked answer fetched within ``detection_days``)."""
        if self.mode == "no-vt":
            return frozenset()
        if self.mode == "oracle":
            return frozenset(self.ranked)
        since = clock - self.detection_days
        return frozenset(d for d, times in self.ranked.items()
                         if any(since <= t <= clock for t in times))  # fmt: skip

    def __call__(self, clock: datetime, scored: Any, visible: list[Observation],
                 counting: bool) -> None:  # fmt: skip
        started = time.process_time()
        config = self.config
        for name, k in self.known.items():  # how it stood when people found it (the last step)
            found = k.found_by_people
            if found is not None and clock > found and name not in self.at_people:
                self.at_people[name] = self._measure(k, found)
        if self.campaigns_at is None or clock - self.campaigns_at >= CAMPAIGN_EVERY:
            self.campaigns = campaigns_at(
                self.loaded, self.cached, clock, self.mode, timedelta(hours=config.campaign.hours),
                self.threshold, self.shared, visible,
            )  # fmt: skip
            self.campaigns_at = clock
        bindings = bindings_of(self.campaigns, visible)
        flags = merge_flags(
            {t: f for t, f in self.detections.items() if f.at is None or f.at <= clock},
            group_flags(visible, config),
            {t: Flag("campaign", self.campaigns_at) for b in bindings for t in b.threats},
        )
        self.flags = flags
        world = World(flags, self.popular(clock), {}, (), (), bindings)
        lanes = {ref: tuple(v.lanes) for ref, v in scored.verdicts.items() if v.lanes}
        lifecycle.seal(self.incidents, clock, config)  # as the pass: before the candidates
        candidates = lifecycle.candidates_of(lanes, self.incidents)
        stats = Stats(scored.factors)
        comps = link.link_all(visible, clock, candidates, config, stats, world)
        score_7d = {ref: v.window("7d").score for ref, v in scored.verdicts.items()}
        facts = lifecycle.facts_of(visible, clock, lambda t: link.flagged_at(flags.get(t), clock),
                                   score_7d)  # fmt: skip
        band_of = self.ranker(scored.verdicts, clock) if self.ranker is not None else None
        out = lifecycle.advance(self.incidents, comps, facts, clock, config, band_of)
        self.incidents = out.incidents
        for inc in out.incidents:
            if inc.id is None and inc.state != "merged":
                inc.id = self.next_id
                self.next_id += 1
            if inc.root is not None and inc.root.id is not None:
                inc.parent = inc.root.id
        for kept, gone in out.merged:
            gone.merged_into = kept.id
        for inc in out.incidents:  # before a later merge empties them
            if inc.id is not None and inc.state != "merged" and not inc.overflow:
                self.ever[inc.id] |= set(inc.objects)
        day = clock.astimezone(site.zone()).date()
        for inc in out.opened:
            if inc.state == "merged" or inc.id is None:
                continue
            self.opened_at[inc.id] = clock
            self.opened_counted[inc.id] = counting
            if counting:
                self.per_day[day]["new"] += 1
                if not inc.overflow:
                    self.bands[day][inc.band] += 1
        if counting:
            self.per_day[day]["requeued"] += len(out.requeued)
            for inc in out.requeued:
                for said in inc.changed:
                    self.why_requeued[_change_kind(said)] += 1
                    if said.startswith("priority rose to "):
                        self.rose[day][said.rsplit(" ", 1)[-1]] += 1
            self.per_day[day]["merged"] += len(out.merged)
            for inc in out.incidents:
                if inc.live and not inc.overflow:
                    if inc.campaign:
                        self.largest_campaign[day] = max(self.largest_campaign[day], inc.devices)
                    else:
                        self.largest[day] = max(self.largest[day], inc.devices)
        self.campaign_count = max(self.campaign_count, len(self.campaigns))
        self.steps += 1
        self.seconds += time.process_time() - started

    # ----------------------------------------------------------------------- the report

    def _final(self, inc: Incident) -> Incident:
        by_id = {i.id: i for i in self.incidents if i.id is not None}
        seen = 0
        while inc.state == "merged" and inc.merged_into in by_id and seen < 100:
            inc = by_id[inc.merged_into]
            seen += 1
        return inc

    def _holdings(self) -> tuple[dict[int, Incident], dict[int, set[uuid.UUID]],
                                 dict[int, set[ObjectRef]]]:  # fmt: skip
        """Each final incident (by id), the alert groups and the objects it holds now (its
        overflows' with it)."""
        by_id = {i.id: i for i in self.incidents if i.id is not None}
        groups_of: dict[int, set[uuid.UUID]] = defaultdict(set)
        objects_of: dict[int, set[ObjectRef]] = defaultdict(set)
        for inc in self.incidents:
            if inc.state == "merged":
                continue
            root = inc
            if inc.overflow:
                root = inc.root or by_id.get(inc.parent or -1) or inc
            root = self._final(root)
            if root.id is None:
                continue
            groups_of[root.id] |= set(inc.groups)
            objects_of[root.id] |= set(inc.objects)
        return by_id, groups_of, objects_of

    def _measure(self, k: Known, as_of: datetime | None = None) -> dict[str, Any]:
        """How one known incident stood when people found it (``as_of``): the incidents opened
        on its objects by then, merged later or not, and the most of its alert groups the copy
        held by then (the warm-up's too: people may have found it before the window) one
        incident held."""
        _, groups_of, _ = self._holdings()
        refs = k.refs
        own = {g.id for g in self.loaded.groups.values() if set(g.objects) & refs
               and (g.arrived <= as_of if as_of is not None
                    else self.start is None or g.end > self.start)}  # fmt: skip
        pieces = sorted(i for i, objs in self.ever.items() if objs & refs
                        and i in self.opened_at
                        and (as_of is None or self.opened_at[i] <= as_of))  # fmt: skip
        inside = max((len(g & own) for g in groups_of.values()), default=0)
        return {
            "incidents": len(pieces),
            "groups": len(own),
            "groups_in_one_incident": inside,
            "share_in_one_incident": round(inside / len(own), 3) if own else None,
        }

    def report(self, known: Mapping[str, Known], days: Sequence[date],
               start: datetime) -> dict[str, Any]:  # fmt: skip
        self.start = start
        by_id, groups_of, objects_of = self._holdings()
        out: dict[str, Any] = {}
        for name, k in known.items():
            refs = k.refs
            own = {g.id for g in self.loaded.groups.values() if set(g.objects) & refs
                   and g.end > start}  # fmt: skip
            pieces = sorted(i for i, objs in self.ever.items()
                            if objs & refs and i in self.opened_at)  # fmt: skip
            counted = [i for i in pieces if self.opened_counted.get(i)]
            best: int | None = None
            inside = 0
            for rid, groups in groups_of.items():
                n = len(groups & own)
                if n > inside:
                    best, inside = rid, n
            first = min((self.opened_at[i] for i in pieces), default=None)
            lead = None
            if first is not None and k.found_by_people is not None:
                lead = round((k.found_by_people - first).total_seconds() / 3600, 1)
            dominant = by_id.get(best) if best is not None else None
            held = objects_of.get(best, set()) if best is not None else set()
            at_people = self.at_people.get(name)
            if at_people is None and k.found_by_people is not None:  # after the last step
                at_people = self._measure(k, k.found_by_people)
            out[name] = {
                "objects": len(refs),
                "incidents": len(pieces),
                "incidents_in_window": len(counted),
                "first_incident": first.isoformat() if first else None,
                "found_by_people": k.found_by_people.isoformat() if k.found_by_people else None,
                "lead_hours": lead,
                "groups": len(own),
                "groups_in_one_incident": inside,
                "share_in_one_incident": round(inside / len(own), 3) if own else None,
                # the same, as it stood when people found it (pieces opened by then)
                "at_found_by_people": at_people,
                "objects_in_one_incident": len(held & refs),
                "dominant_devices": len({device_of(o) for o in held if o.kind == "device"}),
                "dominant_lanes": sorted(dominant.lanes) if dominant else [],
                "dominant_campaign": bool(dominant and dominant.campaign),
                "dominant_links": dict(Counter(lk.via for lk in dominant.links if lk.b))
                if dominant else {},
                "dominant_bridges": len({lk.value for lk in dominant.links if lk.b})
                if dominant else 0,
                # local reports only (data/gate): the outside things that bridged it
                "dominant_bridge_detail": sorted(
                    {(lk.via, lk.value, getattr(self.flags.get(lk.value), "source", "-"))
                     for lk in dominant.links if lk.b}
                )[:20] if dominant else [],
            }  # fmt: skip
        new = [self.per_day.get(d, Counter())["new"] for d in days]
        ordered = sorted(new)
        largest = max(self.largest.values(), default=0)
        per_day: list[dict[str, Any]] = []
        waiting = 0
        for d in days:
            bands = self.bands.get(d, Counter())
            day_shown, waiting = shown(bands, waiting, self.room)
            per_day.append({
                "day": d.isoformat(), **dict(self.per_day.get(d, Counter())),
                "largest_devices": self.largest.get(d, 0),
                "largest_campaign_devices": self.largest_campaign.get(d, 0),
                "bands": {b: bands.get(b, 0) for b in BANDS},
                "rose": dict(sorted(self.rose.get(d, Counter()).items())),
                "shown": day_shown, "waiting": waiting,
            })  # fmt: skip
        count = max(len(days), 1)
        return {
            "per_day": per_day,
            # E5: new root incidents a day by band, what the governor shows and what waits
            "bands_mean": {b: round(sum(r["bands"][b] for r in per_day) / count, 2)
                           for b in BANDS},
            "bands_max": {b: max((r["bands"][b] for r in per_day), default=0) for b in BANDS},
            "rose_mean": round(sum(sum(r["rose"].values()) for r in per_day) / count, 2),
            "shown_mean": round(sum(r["shown"] for r in per_day) / count, 2),
            "shown_max": max((r["shown"] for r in per_day), default=0),
            "waiting_end": waiting,
            "new_mean": round(sum(new) / len(new), 2) if new else 0,
            "new_median": ordered[len(ordered) // 2] if ordered else 0,
            "new_p95": ordered[max(0, round(0.95 * len(ordered)) - 1)] if ordered else 0,
            "new_max_3_days": max((sum(new[i:i + 3]) for i in range(max(len(new) - 2, 1))),
                                  default=0),
            "requeued_why": dict(self.why_requeued.most_common()),
            "requeued_mean": round(sum(self.per_day.get(d, Counter())["requeued"] for d in days)
                                   / max(len(days), 1), 2),
            "largest_devices": largest,
            "largest_campaign_devices": max(self.largest_campaign.values(), default=0),
            "incidents_opened": len(self.opened_at),
            "campaigns_seen": self.campaign_count,
            "known": out,
            "cpu_seconds": round(self.seconds, 1),
            "cpu_per_step": round(self.seconds / max(self.steps, 1), 4),
        }  # fmt: skip


def _change_kind(said: str) -> str:
    """A material change's kind, for the report (``1 new rule`` -> ``new rule``)."""
    for kind in (
        "new rule",
        "new evidence",
        "new stage",
        "new log family",
        "newly flagged",
        "now",
        "priority rose",
    ):
        if kind in said:
            return kind
    return said
