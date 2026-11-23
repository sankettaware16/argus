"""The engine's pass (P4-F E1, shadow): read the alert groups whose inputs changed, write their
observations, then rescore every object of the window and record which lanes hold it. Each part
is a transaction of its own; a failure is said and the next pass tries again, and an alert group
the database refuses is held empty and said, so it never holds the others back. Postgres only:
**no SIEM request**, no LLM, and nothing of today's queue, suggester or raises is written.

The rescore is full (every object of the 14-day window, from its stored observations): scores
decay with time, so a dirty set would miss objects that fall out of a lane. It writes only what
changed materially (a lane, the held state, a score moved by more than 5 % or one point)."""

from __future__ import annotations

import contextlib
import hashlib
import logging
import time
import uuid
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.assets.classify import IpClassifier
from argus.cases.membership import NO_SHARED, Shared
from argus.outside import read as outside_read
from argus.risk import exposure, incidents, present, rulemeta, score, store
from argus.risk.config import RiskConfig
from argus.risk.observe import Context, Group, ObjectRef, Observation, Observed, observe
from argus.site import LogFamily

log = logging.getLogger("argus.risk")
BATCH = 2000  # alert groups read in one transaction
MAX_BATCHES = 10  # per pass; the rest wait for the next pass
BREAKDOWN = 12  # sources kept in a stored breakdown
# A group's digest category follows its objects while its day is recent; older days are history
# (a later lane crossing of its object folds it into the incident, E2).
CATEGORY_OPEN = timedelta(hours=48)


@dataclass
class Report:
    observed: int = 0
    observations: int = 0
    rules: int = 0
    objects: int = 0
    lanes: dict[str, int] = field(default_factory=dict)
    crossings: int = 0
    new_items: int = 0
    folded: int = 0  # E3: sites entering L5 through an outside address of another (no new item)
    written: int = 0
    pruned: int = 0
    unwritten: int = 0  # alert groups the database refused (held empty until they change)
    seconds: dict[str, float] = field(default_factory=dict)
    incidents: str = ""  # the linker's line (E2)
    presented: str = ""  # the presenter's line (E5), when it ran

    def line(self) -> str:
        lanes = ", ".join(f"{k} {v}" for k, v in sorted(self.lanes.items())) or "none"
        took = ", ".join(f"{k} {v:.2f} s" for k, v in self.seconds.items())
        folds = f", {self.folded} folded into another site's" if self.folded else ""
        refused = (
            f"; {self.unwritten} alert groups could not be written (held empty until they"
            " change)" if self.unwritten else ""
        )  # fmt: skip
        return (
            (
                f"incident engine (shadow): {self.observed} alert groups read,"
                f" {self.observations} observations; {self.objects} objects scored, in lanes:"
                f" {lanes}; {self.crossings} lane crossings ({self.new_items} new items{folds});"
                f" {self.written} rows written{refused}; {took}"
            )
            + (f"\n{self.incidents}" if self.incidents else "")
            + (f"\n{self.presented}" if self.presented else "")
        )


def salt(config: RiskConfig, identity: str = "") -> str:
    """A digest of the settings (and of identity's: ``Identity.fingerprint``): a change reads
    every group of the window again."""
    return hashlib.sha256((config.model_dump_json() + identity).encode()).hexdigest()[:16]


def fresh_feeds(
    rows: Sequence[Any], now: datetime, days: int, modes: dict[str, str]
) -> frozenset[str]:
    """The threat-intel modes (mirror, lookup) with a feed whose newest indicator is recent."""
    out = set()
    for source, newest in rows:
        mode = modes.get(source)
        if mode and newest is not None and newest >= now - timedelta(days=days):
            out.add(mode)
    return frozenset(out)


async def feeds(conn: AsyncConnection, now: datetime, config: RiskConfig,
                modes: dict[str, str]) -> frozenset[str]:  # fmt: skip
    rows = (await conn.execute(text("SELECT source, newest FROM ti_sources"))).all()
    return fresh_feeds([tuple(r) for r in rows], now, config.feed_fresh_days, modes)


@dataclass(frozen=True)
class Setup:
    config: RiskConfig
    classifier: IpClassifier
    families: Sequence[LogFamily] = ()
    own_domains: Sequence[str] = ()
    feed_modes: dict[str, str] = field(default_factory=dict)  # TI source index -> mode
    shared: Shared = NO_SHARED
    view: outside_read.View | None = None  # the outside cache's view (None: stored flags only)
    linking: incidents.LinkSetup | None = None  # the linker and lifecycle (E2); None: off
    presenter: present.Options | None = None  # E5: risk.present and the governor; None: off


async def observe_pending(engine: AsyncEngine, setup: Setup, now: datetime, report: Report) -> None:
    """Observe the groups whose inputs changed. With the linker on, identity keys the devices (a
    dynamic address per day) and leaves hubs out (an asset-map role or a resolver)."""
    config = setup.config
    since = now - config.windows["14d"].span
    who = setup.linking.identity if setup.linking is not None else None
    devices = who.devices() if who is not None else None
    settings = salt(config, who.fingerprint() if who is not None else "")
    names = sorted({n for kind in config.evidence for n in kind.signals})
    flag = next((f for kind in config.evidence if kind.kind == "outside" for f in kind.flags), "")
    for _ in range(MAX_BATCHES):
        async with engine.begin() as conn:
            found = await store.pending(conn, now, since, settings, BATCH)
            if not found:
                return
            ids = [i for i, _ in found]
            outside: dict[uuid.UUID, bool] = {}
            if setup.view is not None:
                v = setup.view
                facts = await outside_read.facts_for(
                    conn, ids, now, v.window, v.threshold, clean_window=v.clean_window,
                    parent_ok=v.parent_ok,
                )  # fmt: skip
                outside = {i: any(f.get("flagged") for f in fs) for i, fs in facts.items()}
            groups = await store.groups(conn, ids, names, outside, flag, config.exposure)
            fresh = await feeds(conn, now, config, setup.feed_modes)
            ctx = Context(config, setup.classifier, setup.own_domains, fresh, setup.shared,
                          setup.families, devices)  # fmt: skip
            rules = await rulemeta.load(conn)
            sigs = dict(found)
            observed = [(g, sigs[g.id], observe(g, rules.get(g.rule_id), ctx)) for g in groups]
            report.observations += await write(conn, now, observed, report)
            report.observed += len(observed)
            await incidents.write_aliases(conn, observed)
        if len(found) < BATCH:
            return


async def write(
    conn: AsyncConnection, now: datetime, observed: Sequence[tuple[Group, str, Observed]],
    report: Report,
) -> int:  # fmt: skip
    """Write a batch's groups; when the database refuses the batch, each group alone, so one bad
    group never holds the others back (it would be first in every batch again). A group refused
    alone is held with its signature and nothing else, said in the report and the log, and read
    again when its inputs change."""
    with contextlib.suppress(DBAPIError):
        async with conn.begin_nested():
            return await store.write(conn, now, observed)
    written = 0
    for group, sig, seen in observed:
        try:
            async with conn.begin_nested():
                written += await store.write(conn, now, [(group, sig, seen)])
        except DBAPIError as exc:
            report.unwritten += 1
            log.warning("risk: alert group %s could not be written (%s); held empty", group.id,
                        type(getattr(exc, "orig", exc)).__name__)  # fmt: skip
            empty = replace(seen, objects=(), observations=(), entities=())
            with contextlib.suppress(DBAPIError):  # not even its record: read again next pass
                async with conn.begin_nested():
                    await store.write(conn, now, [(group, sig, empty)])
    return written


@dataclass(frozen=True)
class Scored:
    """A full evaluation at one time, before anything is written."""

    verdicts: dict[ObjectRef, score.Verdict]
    factors: dict[tuple[str, str], score.Factors]
    by_group: dict[uuid.UUID, list[ObjectRef]]
    seconds: float


def evaluate_all(
    obs: Sequence[Observation], now: datetime, config: RiskConfig,
    first_alert: dict[str, datetime | None], verdict_refs: set[ObjectRef],
    criticality: Callable[[ObjectRef], float] = lambda _: 1.0,
    active_within: timedelta | None = None,
) -> Scored:  # fmt: skip
    """Every object's verdict at ``now`` from the window's observations (pure; the replay and
    the pass share it). ``active_within``: score only objects with an observation that recent
    (no lane looks further back than 7 days; the replay's shortcut)."""
    started = time.process_time()
    factors = score.factors(obs, now, config, first_alert)
    reach = score.reach(obs, now, config.persistence.window_days)
    stats = score.Stats(factors, reach, frozenset(verdict_refs))
    per: dict[ObjectRef, list[Observation]] = defaultdict(list)
    roles: dict[ObjectRef, str] = {}
    by_group: dict[uuid.UUID, dict[ObjectRef, None]] = defaultdict(dict)
    for o in obs:
        per[o.object].append(o)
        if roles.get(o.object) != "actor":
            roles[o.object] = o.role
        by_group[o.group][o.object] = None
    recent = None if active_within is None else now - active_within
    verdicts = {
        ref: score.evaluate(items, now, config, stats, role=roles[ref],
                            criticality=criticality(ref), ref=ref)
        for ref, items in per.items()
        if recent is None or any(o.at >= recent for o in items)
    }  # fmt: skip
    verdicts = exposure.lanes(verdicts, config.exposure)  # L5 on the own sites (E3)
    groups = {g: list(refs) for g, refs in by_group.items()}
    return Scored(verdicts, factors, groups, time.process_time() - started)


def _material(old: tuple[Any, ...] | None, w: score.WindowScore) -> bool:
    if old is None:
        return True
    value = float(old[0])
    if abs(w.score - value) > max(1.0, 0.05 * value):
        return True
    return tuple(old[1:]) != (w.sources, len(w.families), w.stages, w.active_days, w.strong,
                              w.anchored)  # fmt: skip


async def _folds(
    conn: AsyncConnection, scored: Scored, held: dict[int, store.Held],
    ids: dict[ObjectRef, int], now: datetime, quiet: timedelta, config: RiskConfig,
) -> set[ObjectRef]:  # fmt: skip
    """E3: the sites entering L5 now that an outside address puts there with another site (in
    L5 already, or entering before it in key order): one item (``exposure.folded``)."""
    entering: list[ObjectRef] = []
    staying: list[ObjectRef] = []
    for ref, v in scored.verdicts.items():
        if exposure.LANE not in v.lanes:
            continue
        h = held.get(ids[ref])
        last = h.last_lane_at if h else None
        (entering if last is None or now - last > quiet else staying).append(ref)
    if not entering or len(entering) + len(staying) < 2:
        return set()
    wanted = {f"ev:{k}" for k in config.exposure.lane_kinds}
    groups = sorted({c.group for r in (*entering, *staying)
                     for c in scored.verdicts[r].window("7d").contributions
                     if c.source in wanted})  # fmt: skip
    rows = await conn.execute(
        text(
            "SELECT investigation_id, value FROM risk_entities WHERE kind = 'ip'"
            " AND role = 'actor' AND investigation_id = ANY(CAST(:ids AS uuid[]))"
        ),
        {"ids": groups},
    )
    sources_of: dict[uuid.UUID, set[str]] = defaultdict(set)
    for gid, value in rows:
        if exposure.is_outside(value):
            sources_of[gid].add(value)
    order = sorted(entering, key=lambda r: (r.kind, r.key))
    return exposure.folded(order, staying, scored.verdicts, sources_of, config.exposure)


@dataclass(frozen=True)
class Rescored:
    """What a rescore read and found, for the linker (E2)."""

    scored: Scored
    observations: Sequence[Observation]
    ids: dict[ObjectRef, int]


async def rescore(
    engine: AsyncEngine, config: RiskConfig, now: datetime, report: Report
) -> Rescored:
    """Score every object of the window at ``now`` and write what changed (see the module's
    docstring)."""
    since = now - config.windows["14d"].span
    quiet = timedelta(days=config.item_quiet_days)
    async with engine.begin() as conn:
        started = time.perf_counter()
        obs, ids = await store.observations(conn, since, now)
        rules = await rulemeta.load(conn)
        first: dict[str, datetime | None] = {}
        for meta in rules.values():
            key = f"rule:{meta.lineage}"
            if meta.first_alert_at is not None and (
                first.get(key) is None or meta.first_alert_at < first[key]  # type: ignore[operator]
            ):
                first[key] = meta.first_alert_at
        held = await store.held_objects(conn, ids.values())
        by_id = {h.ref: h for h in held.values()}
        verdict_ids = await store.verdicts(conn, since, now)
        refs = {h.ref for h in held.values() if h.id in verdict_ids}
        scored = evaluate_all(obs, now, config, first, refs,
                              lambda r: by_id[r].criticality if r in by_id else 1.0)  # fmt: skip
        old_scores = await store.scores(conn)
        groups = await store.group_rows(conn, now - CATEGORY_OPEN, now)
        report.seconds["read"] = time.perf_counter() - started - scored.seconds
        report.seconds["score"] = scored.seconds
        written = time.perf_counter()
        await _write_sources(conn, scored, now)
        await conn.execute(
            text(
                "UPDATE risk_observations o SET prevalence = s.prevalence,"
                " fidelity = s.fidelity, score = o.base * o.outcome * s.prevalence * s.fidelity"
                " FROM risk_sources s WHERE s.source_key = o.source_key AND s.role = o.role"
                " AND o.at >= :since AND (o.prevalence <> s.prevalence"
                " OR o.fidelity <> s.fidelity)"
            ),
            {"since": since},
        )
        score_rows: list[dict[str, Any]] = []
        object_rows: list[dict[str, Any]] = []
        crossings: list[dict[str, Any]] = []
        gone: list[tuple[int, str]] = []
        fold = await _folds(conn, scored, held, ids, now, quiet, config)
        report.folded += len(fold)
        for ref, v in scored.verdicts.items():
            oid = ids[ref]
            for span, w in v.windows.items():
                slot = (oid, span)
                if w.sources == 0:
                    if slot in old_scores:
                        gone.append(slot)
                    continue
                if _material(old_scores.get(slot), w):
                    score_rows.append({
                        "o": oid, "span": span, "score": w.score, "sources": w.sources,
                        "families": len(w.families), "stages": w.stages,
                        "days": w.active_days, "strong": w.strong, "anchored": w.anchored,
                        "breakdown": store.dumps(w.breakdown()[:BREAKDOWN]), "now": now,
                    })  # fmt: skip
            report.objects += 1
            for lane in v.lanes:
                report.lanes[lane] = report.lanes.get(lane, 0) + 1
            h = held.get(oid)
            before = set(h.lanes) if h else set()
            item_at = h.item_at if h else None
            if v.lanes:
                last = h.last_lane_at if h else None
                fresh = (last is None or now - last > quiet) and ref not in fold
                item_at = now if fresh else item_at
                report.new_items += fresh
                for lane in v.lanes:
                    if lane in before:
                        continue
                    w = v.window("7d" if lane in ("slow", "exposure") else "24h")
                    why = store.dumps(w.breakdown()[:BREAKDOWN])
                    crossings.append({"o": oid, "lane": lane, "at": now, "new": fresh,
                                      "score": w.score, "breakdown": why})  # fmt: skip
                    report.crossings += 1
            if h is None or set(v.lanes) != before or v.held != h.held or v.lanes:
                object_rows.append({
                    "o": oid, "lanes": list(v.lanes), "held": v.held, "item_at": item_at,
                    "last": now if v.lanes else (h.last_lane_at if h else None), "now": now,
                })  # fmt: skip
        for h in held.values():  # an object in a lane last time with no observation left
            if h.ref not in scored.verdicts and h.lanes:
                object_rows.append({"o": h.id, "lanes": [], "held": "below", "item_at": h.item_at,
                                    "last": h.last_lane_at, "now": now})  # fmt: skip
        if gone:
            await conn.execute(
                text(
                    "DELETE FROM risk_object_scores s USING unnest(CAST(:o AS bigint[]),"
                    " CAST(:s AS text[])) AS g(o, s) WHERE s.object_id = g.o AND s.span = g.s"
                ),
                {"o": [k[0] for k in gone], "s": [k[1] for k in gone]},
            )
        if score_rows:
            await conn.execute(
                text(
                    "INSERT INTO risk_object_scores (object_id, span, score, sources, families,"
                    " stages, active_days, strong, anchored, breakdown, computed_at) VALUES (:o,"
                    " :span, :score, :sources, :families, :stages, :days, :strong, :anchored,"
                    " CAST(:breakdown AS jsonb), :now) ON CONFLICT (object_id, span) DO UPDATE"
                    " SET score = EXCLUDED.score, sources = EXCLUDED.sources,"
                    " families = EXCLUDED.families, stages = EXCLUDED.stages,"
                    " active_days = EXCLUDED.active_days, strong = EXCLUDED.strong,"
                    " anchored = EXCLUDED.anchored, breakdown = EXCLUDED.breakdown,"
                    " computed_at = EXCLUDED.computed_at"
                ),
                score_rows,
            )
        if object_rows:
            await conn.execute(
                text(
                    "UPDATE risk_objects SET lanes = CAST(:lanes AS text[]), held = :held,"
                    " item_at = :item_at, last_lane_at = :last, scored_at = :now WHERE id = :o"
                ),
                object_rows,
            )
        if crossings:
            await conn.execute(
                text(
                    "INSERT INTO risk_crossings (object_id, lane, at, new_item, score, breakdown)"
                    " VALUES (:o, :lane, :at, :new, :score, CAST(:breakdown AS jsonb))"
                ),
                crossings,
            )
        changed = _categories(groups, scored)
        if changed:
            await conn.execute(
                text(
                    "UPDATE risk_groups SET category = :category, scored_at = :now"
                    " WHERE investigation_id = :id"
                ),
                [{"id": i, "category": c, "now": now} for i, c in changed],
            )
        report.written += len(score_rows) + len(object_rows) + len(crossings) + len(changed)
        report.seconds["write"] = time.perf_counter() - written
    return Rescored(scored, obs, ids)


def _categories(groups: Sequence[store.GroupRow], scored: Scored) -> list[tuple[uuid.UUID, str]]:
    out = []
    for g in groups:
        verdicts = [
            scored.verdicts[r] for r in scored.by_group.get(g.id, ()) if r in scored.verdicts
        ]
        found = score.category(known=g.known, direction=g.direction, outcome=g.outcome,
                               kinds=g.kinds, verdicts=verdicts,
                               hub=g.category == "hub_activity")  # fmt: skip
        if found != g.category:
            out.append((g.id, found))
    return out


async def _write_sources(conn: AsyncConnection, scored: Scored, now: datetime) -> None:
    if not scored.factors:
        return
    await conn.execute(
        text(
            "INSERT INTO risk_sources (source_key, role, prevalence, fidelity, probation, reach,"
            " objects_median, computed_at) VALUES (:s, :r, :q, :f, :p, :reach, :m, :now)"
            " ON CONFLICT (source_key, role) DO UPDATE SET prevalence = EXCLUDED.prevalence,"
            " probation = EXCLUDED.probation, reach = EXCLUDED.reach,"
            " objects_median = EXCLUDED.objects_median, computed_at = EXCLUDED.computed_at"
        ),
        [{"s": k[0], "r": k[1], "q": f.prevalence, "f": f.fidelity, "p": f.probation,
          "reach": f.reach, "m": f.objects_median, "now": now}
         for k, f in sorted(scored.factors.items())],
    )  # fmt: skip


async def prune(engine: AsyncEngine, config: RiskConfig, now: datetime) -> int:
    """Drop what is past the engine's keep periods: alert groups and their observations after
    ``keep_days``, lane crossings and objects with nothing left after ``keep_crossings_days``."""
    keep = now - timedelta(days=config.keep_days)
    long = now - timedelta(days=config.keep_crossings_days)
    async with engine.begin() as conn:
        gone = (await conn.execute(
            text("DELETE FROM risk_groups WHERE at < :keep"), {"keep": keep}
        )).rowcount  # fmt: skip
        gone += (await conn.execute(
            text("DELETE FROM risk_crossings WHERE at < :long"), {"long": long}
        )).rowcount  # fmt: skip
        gone += (await conn.execute(
            text(
                "DELETE FROM risk_objects b WHERE b.last_seen < :long AND NOT EXISTS"
                " (SELECT 1 FROM risk_observations o WHERE o.object_id = b.id)"
            ),
            {"long": long},
        )).rowcount  # fmt: skip
    return int(gone)


async def step(engine: AsyncEngine, setup: Setup, now: datetime) -> Report:
    """One pass: rules metadata, the changed groups, the full rescore, the keep periods."""
    report = Report()
    started = time.perf_counter()
    async with engine.begin() as conn:
        report.rules = await rulemeta.sync(conn, setup.families, now)
    await observe_pending(engine, setup, now, report)
    report.seconds["observe"] = time.perf_counter() - started
    began = time.perf_counter()
    rescored = await rescore(engine, setup.config, now, report)
    report.seconds["rescore"] = time.perf_counter() - began
    verdicts = rescored.scored.verdicts
    if setup.linking is not None:  # the linker and the lifecycle (E2): a failure waits a pass
        try:
            linked = await incidents.step(
                engine, setup.linking, now, rescored.observations, rescored.ids, verdicts,
                score.Stats(rescored.scored.factors),
                present.ranker(verdicts, now, setup.config, same=setup.linking.same),
            )  # fmt: skip
            report.incidents = linked.line()
            report.seconds["link"] = linked.seconds
        except DBAPIError as exc:
            report.incidents = f"incidents: the pass failed ({type(exc).__name__}); retrying"
            log.warning("risk: the incident pass failed (%s)", type(exc).__name__)
    if setup.presenter is not None and setup.linking is not None:  # E5: priorities and cases
        began = time.perf_counter()
        ctx = present.Context(setup.config, setup.presenter, setup.classifier,
                              tuple(setup.own_domains))  # fmt: skip
        try:
            presented = await present.run(engine, ctx, now, verdicts, rescored.ids,
                                          rescored.observations)  # fmt: skip
            report.presented = presented.line()
        except DBAPIError as exc:
            report.presented = f"presenter: the pass failed ({type(exc).__name__}); retrying"
            log.warning("risk: the presenter's pass failed (%s)", type(exc).__name__)
        report.seconds["present"] = time.perf_counter() - began
    report.pruned = await prune(engine, setup.config, now)
    return report


def feed_modes(ti_sources: Sequence[Any]) -> dict[str, str]:
    return {s.index: s.mode for s in ti_sources}


def view_of(settings: Any, shared: Shared) -> outside_read.View:
    """The outside cache's view as the pass reads it (no request is made)."""
    o = settings.outside
    return outside_read.View(
        o.cache_window,
        o.flag_threshold,
        o.clean_cache_window,
        parent_ok=lambda parent: shared.reason("domain", parent) is None,
    )
