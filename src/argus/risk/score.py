"""Steps 2 to 5 of the engine (E1), pure: score observations, accumulate them per object and
window, and decide the lanes.

- ``score = base x prevalence x outcome x fidelity`` (fidelity neutral until E7), decayed by the
  window's half-life. **Each source counts once per window, at its best**: 10,000 copies of one
  observation score as one, and adding observations never lowers a score.
- **Prevalence** is label-free: a source that touches many objects a day is scaled down.
- A second **log family** multiplies the object's score; **stages** are counted by a maximum
  matching of sources to stages, so one rule tagged with two tactics is one stage, and an
  evidence fact adds a stage only outside its own alert group's rule's stages (the beacon rule's
  own beacon is no second stage).
- **Persistence**: an object reaching one rare outside destination on several days.
- **Lanes**: L1 decisive, L2 burst, L3 slow (``config/risk.yaml``), on campus objects that act.
  L2 and L3 need an anchor (an evidence fact or a person's verdict); a rule on probation may add
  weight but no lane may need it; just under a lane, anchored, is the gray band. Everything else
  is the digest's.
"""

from __future__ import annotations

import math
import uuid
from collections import defaultdict
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import date, datetime, timedelta
from typing import Any, Literal

from argus.risk.config import WINDOWS, RiskConfig, stage_bit
from argus.risk.observe import ObjectRef, Observation

Lane = Literal["decisive", "burst", "slow", "exposure"]
LANES: tuple[Lane, ...] = ("decisive", "burst", "slow", "exposure")  # exposure: E3, on sites
Held = Literal["lane", "gray_band", "probation", "rules_only", "below", "target"]
CATEGORIES = (
    "presented", "known_infection", "inbound_blocked", "inbound_attempt", "inbound_success",
    "gray_band", "probation", "rules_only", "outbound_low", "unattributed", "hub_activity",
)  # fmt: skip
PERSISTENCE = "ev:persistence"


@dataclass(frozen=True)
class Factors:
    """What a source's observations are multiplied by, from its record (label-free noise,
    probation, and later the fidelity people's decisions teach)."""

    prevalence: float = 1.0
    fidelity: float = 1.0
    probation: bool = False
    reach: int = 0  # distinct objects the source touched in the prevalence window
    objects_median: float = 0.0  # its median of distinct objects a day


NEUTRAL = Factors()


@dataclass(frozen=True)
class Contribution:
    source: str
    score: float
    base: float
    prevalence: float
    outcome: float
    fidelity: float
    decay: float
    at: datetime
    group: uuid.UUID
    stages: int
    strong: bool
    evidence: bool
    probation: bool


@dataclass(frozen=True)
class WindowScore:
    window: str
    score: float
    sources: int
    rule_sources: int
    families: tuple[str, ...]
    stages: int  # stages covered (a maximum matching)
    stage_mask: int
    strong: bool
    anchored: bool
    active_days: int
    contributions: tuple[Contribution, ...]  # one per source, largest first

    def breakdown(self) -> list[dict[str, object]]:
        """The why, largest first: each source's points and factors."""
        return [
            {"source": c.source, "points": round(c.score, 2), "base": round(c.base, 2),
             "prevalence": round(c.prevalence, 3), "outcome": c.outcome,
             "fidelity": c.fidelity, "decay": round(c.decay, 3), "group": str(c.group),
             "at": c.at.isoformat()}
            for c in self.contributions
        ]  # fmt: skip


EMPTY = WindowScore("24h", 0.0, 0, 0, (), 0, 0, False, False, 0, ())


@dataclass(frozen=True)
class Verdict:
    windows: Mapping[str, WindowScore]
    lanes: tuple[Lane, ...]
    gray: tuple[Lane, ...]
    held: Held

    def window(self, name: str) -> WindowScore:
        return self.windows.get(name, replace(EMPTY, window=name))


@dataclass(frozen=True)
class Stats:
    """What scoring an object needs beyond its own observations, computed once per evaluation:
    each source's factors, how many campus objects reached each outside value, and which objects
    a person's true-positive verdict anchors."""

    factors: Mapping[tuple[str, str], Factors] = field(default_factory=dict)
    reach: Mapping[str, int] = field(default_factory=dict)
    verdicts: Collection[ObjectRef] = frozenset()

    def of(self, source: str, role: str) -> Factors:
        return self.factors.get((source, role), NEUTRAL)


# --------------------------------------------------------------------------- source factors


def prevalence(median_objects: float, k: float) -> float:
    """``1 / (1 + log10(max(1, m / k)))``: 1 up to ``k`` objects a day, then lower."""
    return 1.0 / (1.0 + math.log10(max(1.0, median_objects / k)))


def factors(
    observations: Iterable[Observation], now: datetime, config: RiskConfig,
    first_alert: Mapping[str, datetime | None] | None = None,
) -> dict[tuple[str, str], Factors]:  # fmt: skip
    """Each (source, role)'s factors at ``now``, from the observations of the prevalence window:
    the median of its distinct objects a day (days it was seen), and probation for a rule whose
    lineage's first alert (``first_alert``: source -> time) is recent."""
    since = now - timedelta(days=config.prevalence.days)
    per_day: dict[tuple[str, str], dict[date, set[ObjectRef]]] = defaultdict(
        lambda: defaultdict(set)
    )
    for o in observations:
        if since <= o.at <= now:
            per_day[(o.source_key, o.role)][o.day].add(o.object)
    out: dict[tuple[str, str], Factors] = {}
    first_alert = first_alert or {}
    probation_since = now - timedelta(days=config.probation.days)
    for key, days in per_day.items():
        counts = sorted(len(objs) for objs in days.values())
        q = prevalence(counts[len(counts) // 2], config.prevalence.k)  # the upper median
        first = first_alert.get(key[0])
        on_probation = key[0].startswith("rule:") and first is not None and first > probation_since
        if on_probation:
            q = min(q, config.probation.factor)
        reach = len(set().union(*days.values()))
        out[key] = Factors(q, 1.0, on_probation, reach, float(counts[len(counts) // 2]))
    return out


def reach(observations: Iterable[Observation], now: datetime, days: int) -> dict[str, int]:
    """How many campus objects acting outward reached each outside value in the last ``days``."""
    since = now - timedelta(days=days)
    seen: dict[str, set[ObjectRef]] = defaultdict(set)
    for o in observations:
        if o.source_kind == "rule" and o.role == "actor" and since <= o.at <= now:
            for t in o.threats:
                seen[t].add(o.object)
    return {t: len(objs) for t, objs in seen.items()}


# --------------------------------------------------------------------------- one object


def matching(masks: Sequence[int]) -> int:
    """The size of a maximum matching of sources (each a stage mask) to stages: how many stages
    distinct sources cover, each source counting for one stage only."""
    owner: dict[int, int] = {}

    def assign(i: int, seen: set[int]) -> bool:
        for bit in range(4):
            if masks[i] >> bit & 1 and bit not in seen:
                seen.add(bit)
                if bit not in owner or assign(owner[bit], seen):
                    owner[bit] = i
                    return True
        return False

    for i in range(len(masks)):
        if len(owner) == 4:
            break
        assign(i, set())
    return len(owner)


def persistence(
    obs: Sequence[Observation], now: datetime, config: RiskConfig, reach_of: Mapping[str, int]
) -> list[Observation]:
    """The derived persistence observations of one object acting outward: one per rare outside
    value (reached by at most ``max_reach`` objects) it reached on at least ``days`` distinct
    days of the window."""
    p = config.persistence
    since = now - timedelta(days=p.window_days)
    days: dict[str, set[date]] = defaultdict(set)
    last: dict[str, Observation] = {}
    for o in obs:
        if o.source_kind != "rule" or o.role != "actor" or not since <= o.at <= now:
            continue
        for t in o.threats:
            days[t].add(o.day)
            if t not in last or (o.at, str(o.group)) > (last[t].at, str(last[t].group)):
                last[t] = o
    out = []
    for t in sorted(days):
        if len(days[t]) >= p.days and 0 < reach_of.get(t, 0) <= p.max_reach:
            o = last[t]
            out.append(Observation(
                o.object, o.role, "evidence", PERSISTENCE, o.group, o.version, o.at, o.day,
                p.base, 1.0, stage_bit(p.stage), None, False, (t,), (f"{len(days[t])} days",),
            ))  # fmt: skip
    return out


def window_score(
    obs: Sequence[Observation], now: datetime, name: str, config: RiskConfig, stats: Stats,
    criticality: float = 1.0,
) -> WindowScore:  # fmt: skip
    """One object's score in one window (see the module's docstring)."""
    return window_scores(obs, now, config, stats, criticality, (name,))[name]


def window_scores(
    obs: Sequence[Observation], now: datetime, config: RiskConfig, stats: Stats,
    criticality: float = 1.0, names: Sequence[str] = WINDOWS,
) -> dict[str, WindowScore]:  # fmt: skip
    """One object's score in each window, in one pass over its observations. Per window and
    source the best observation counts (the highest value, then a total order, so the order
    the observations come in never decides); a source's stages and strength are those of any
    of its observations in the window, so more observations never cover less. An evidence
    observation's stages exclude those of its own alert group's rule: a rule and the facts of
    its own alerts are one step, not two."""
    rule_stages: dict[uuid.UUID, int] = defaultdict(int)
    for o in obs:
        if o.source_kind == "rule" and o.at <= now:
            rule_stages[o.group] |= o.stages
    spans = [(n, config.windows[n].hours, config.windows[n].half_life_hours) for n in names]  # type: ignore[index]
    best: list[dict[str, tuple[Any, ...]]] = [{} for _ in spans]
    marks: list[dict[str, list[int]]] = [{} for _ in spans]  # [stages, strong]
    families: list[set[str]] = [set() for _ in spans]
    days: list[set[date]] = [set() for _ in spans]
    table = stats.factors
    for o in obs:
        age = (now - o.at).total_seconds() / 3600
        if age < 0:
            continue
        source = o.source_key
        f = table.get((source, o.role), NEUTRAL)
        weight = o.base * o.outcome * f.prevalence * f.fidelity
        stages = o.stages
        if o.source_kind == "evidence":
            stages &= ~rule_stages.get(o.group, 0)
        for i, (_, hours, half) in enumerate(spans):
            if age > hours:
                continue
            decay = 0.5 ** (age / half)
            rank = (weight * decay, o.at, o.group, o.stages, o.strong, o.base, o.outcome)
            held = best[i].get(source)
            if held is None or rank > held[0]:
                best[i][source] = (rank, decay, f, o.source_kind == "evidence")
            mark = marks[i].get(source)
            if mark is None:
                marks[i][source] = [stages, o.strong]
            else:
                mark[0] |= stages
                mark[1] |= o.strong
            if o.family and o.source_kind == "rule":
                families[i].add(o.family)
            days[i].add(o.day)
    out: dict[str, WindowScore] = {}
    for i, (name, _, _) in enumerate(spans):
        if not best[i]:
            out[name] = replace(EMPTY, window=name)
            continue
        contributions = []
        for source, (rank, decay, f, evidence) in best[i].items():
            stages, strong = marks[i][source]
            contributions.append(Contribution(
                source, rank[0], rank[5], f.prevalence, rank[6], f.fidelity, decay, rank[1],
                rank[2], stages, bool(strong), evidence, f.probation,
            ))  # fmt: skip
        ordered = tuple(sorted(contributions, key=lambda c: (-c.score, c.source)))
        fams = tuple(sorted(families[i]))
        factor = (1.0 + config.families.step * (min(len(fams), config.families.cap) - 1)
                  if fams else 1.0)  # fmt: skip
        out[name] = WindowScore(
            name, criticality * factor * sum(c.score for c in ordered), len(ordered),
            sum(1 for c in ordered if not c.evidence), fams,
            matching([c.stages for c in ordered if c.stages]), _union(c.stages for c in ordered),
            any(c.strong for c in ordered), any(c.evidence for c in ordered), len(days[i]),
            ordered,
        )  # fmt: skip
    return out


def _union(masks: Iterable[int]) -> int:
    out = 0
    for m in masks:
        out |= m
    return out


def _lanes(w24: WindowScore, w7: WindowScore, config: RiskConfig, anchored: bool,
           decisive_rule: bool) -> tuple[set[Lane], set[Lane]]:  # fmt: skip
    """(lanes that hold, lanes whose score holds but that lack an anchor)."""
    lanes = config.lanes
    held: set[Lane] = set()
    unanchored: set[Lane] = set()
    if decisive_rule or (w24.strong and w24.sources >= lanes.decisive.with_sources):
        held.add("decisive")
    burst = (w24.score >= lanes.burst.score and w24.sources >= lanes.burst.sources
             and w24.rule_sources >= 1)  # fmt: skip
    slow = (w7.score >= lanes.slow.score and w7.active_days >= lanes.slow.active_days
            and (len(w7.families) >= lanes.slow.families or w7.stages >= lanes.slow.stages
                 or w7.strong))  # fmt: skip
    for lane, holds, window_anchor in (("burst", burst, w24.anchored), ("slow", slow, w7.anchored)):
        if holds:
            (held if window_anchor or anchored else unanchored).add(lane)  # type: ignore[arg-type]
    return held, unanchored


def _gray(w24: WindowScore, w7: WindowScore, config: RiskConfig,
          anchored: bool) -> tuple[set[Lane], set[Lane]]:  # fmt: skip
    """(lanes just missed, lanes just missed with no anchor). The gray band holds anchored
    objects only, as the lanes do: rule hits alone are never a candidate to present."""
    lanes, band = config.lanes, config.gray_band
    out: set[Lane] = set()
    bare: set[Lane] = set()
    if w24.strong and w24.sources < lanes.decisive.with_sources:  # a strong fact anchors
        out.add("decisive")
    if (band * lanes.burst.score <= w24.score < lanes.burst.score
            and w24.sources >= lanes.burst.sources and w24.rule_sources >= 1):  # fmt: skip
        (out if w24.anchored or anchored else bare).add("burst")
    if (band * lanes.slow.score <= w7.score < lanes.slow.score
            and w7.active_days >= lanes.slow.active_days
            and (len(w7.families) >= lanes.slow.families or w7.stages >= lanes.slow.stages
                 or w7.strong)):  # fmt: skip
        (out if w7.anchored or anchored else bare).add("slow")
    return out, bare


def _decisive_rule(obs: Sequence[Observation], now: datetime, config: RiskConfig,
                   stats: Stats) -> bool:  # fmt: skip
    """A rule observation of 24 h at the decisive base (a critical rule), at full fidelity; a
    rule on probation counts only while it has touched few objects (a new advisory's match)."""
    hours = config.windows["24h"].hours
    for o in obs:
        if o.source_kind != "rule" or o.base < config.lanes.decisive.base:
            continue
        age = (now - o.at).total_seconds() / 3600
        if not 0 <= age <= hours:
            continue
        f = stats.of(o.source_key, o.role)
        if f.fidelity < 1.0:
            continue
        if f.probation and f.reach > config.probation.reach:
            continue
        return True
    return False


def evaluate(
    obs: Sequence[Observation], now: datetime, config: RiskConfig, stats: Stats, *,
    role: str = "actor", criticality: float = 1.0, ref: ObjectRef | None = None,
) -> Verdict:  # fmt: skip
    """One object's windows and lanes at ``now``. ``obs`` are its observations (any time; those
    after ``now`` are not seen yet). Lanes are for objects that act (``role`` actor); a campus
    site's lanes come with the exposure lane (E3)."""
    derived = list(obs)
    lane_span = timedelta(hours=config.windows["7d"].hours)
    if not any(now - o.at <= lane_span for o in derived):
        # nothing in the lanes' windows (7 d at most): the 14 d score only, and no lane
        windows = window_scores(derived, now, config, stats, criticality, ("14d",))
        windows.update({n: replace(EMPTY, window=n) for n in WINDOWS if n not in windows})
        return Verdict(windows, (), (), "below" if role == "actor" else "target")
    if role == "actor":
        derived.extend(persistence(obs, now, config, stats.reach))
    windows = window_scores(derived, now, config, stats, criticality)
    if role != "actor":
        return Verdict(windows, (), (), "target")
    anchored = ref is not None and ref in stats.verdicts
    decisive = _decisive_rule(derived, now, config, stats)
    plain = [o for o in derived if not stats.of(o.source_key, o.role).probation]
    if len(plain) == len(derived):
        lanes, unanchored = _lanes(windows["24h"], windows["7d"], config, anchored, decisive)
    else:  # the lanes without the sources on probation (which may only add weight)
        lanes_of = window_scores(plain, now, config, stats, criticality, ("24h", "7d"))
        w24, w7 = lanes_of["24h"], lanes_of["7d"]
        lanes, unanchored = _lanes(w24, w7, config, anchored, decisive)
    if lanes:
        return Verdict(windows, tuple(lane for lane in LANES if lane in lanes), (), "lane")
    all_lanes, all_unanchored = _lanes(windows["24h"], windows["7d"], config, anchored, decisive)
    gray, bare = _gray(windows["24h"], windows["7d"], config, anchored)
    held: Held
    if all_lanes:
        held = "probation"
    elif unanchored or all_unanchored:
        held = "rules_only"
    elif gray:
        held = "gray_band"
    elif bare:
        held = "rules_only"
    else:
        held = "below"
    return Verdict(windows, (), tuple(lane for lane in LANES if lane in gray), held)


# --------------------------------------------------------------------------- the digest


def category(
    *, known: bool, direction: str, outcome: float, kinds: Collection[str],
    verdicts: Sequence[Verdict], hub: bool = False,
) -> str:  # fmt: skip
    """Where an alert group ends a pass: ``presented`` when one of its objects is in a lane,
    else one generic digest category (``CATEGORIES``)."""
    if known:
        return "known_infection"
    if any(v.lanes for v in verdicts):
        return "presented"
    if hub:
        return "hub_activity"
    acting = [v for v in verdicts if v.held != "target"]
    if not acting:
        if direction == "inbound":
            if outcome < 1.0:
                return "inbound_blocked"
            return "inbound_success" if "success" in kinds else "inbound_attempt"
        return "unattributed"
    held = {v.held for v in acting}
    for name in ("gray_band", "probation", "rules_only"):
        if name in held:
            return name
    return "outbound_low"


def sample(ids: Iterable[uuid.UUID], day: date, n: int) -> list[uuid.UUID]:
    """``n`` alert groups picked deterministically (by a hash of id and day) for the audit."""
    import hashlib

    return sorted(ids, key=lambda i: hashlib.sha256(f"{i}:{day.isoformat()}".encode()).hexdigest())[
        :n
    ]
