"""Step 8 of the engine (E5), pure: one number for an incident, its band, and the why line.

``priority = round(100 * (1 - exp(-X / k)))`` with
``X = (R_7d(top object) + 0.3 * sum of the next five objects' R_7d) * stages * spread * activity
* trust``:

- **stages**: 1 + 0.25 per matched stage beyond the first (a maximum matching: one rule tagged
  with two tactics is one stage);
- **spread**: 1 + 0.1 per internal object beyond the first, up to ten;
- **activity**: x 1.2 with an observation in the last 24 h, x 1 within 72 h, x 0.7 when quiet;
- **trust**: x 1.3 once a person confirmed it. Intel from an out-of-date feed, when no fresh
  strong fact stands beside it, counts a fifth less again (taken off its own points, so adding
  it never lowers the total).

Bands: P1 >= 63, P2 55-62, P3 46-54, P4 below, calibrated on the replay of 15 Oct - 3 Nov (db
mode, one object an incident until the linker): P1 0.8 a day, P2 1.2, P3 3.0, P4 0.7; the plan's
first guess (70 / 45 / 25) put 91 % of the items in P2, since a lane is already crossed at
X of about 50. Every factor only grows with evidence, so adding evidence never lowers a
priority. The why line is made from the stored breakdown, largest first: ``+50 outside detection
(VirusTotal) · +25 DNS tunnelling suspected · x1.5 two log families · x1.2 still active``. No
rule is named in any decision: a rule's name appears only as words."""

from __future__ import annotations

import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final, Literal

from argus import site

Band = Literal["P1", "P2", "P3", "P4"]
BANDS: tuple[Band, ...] = ("P1", "P2", "P3", "P4")
TIMES: Final[Literal["\u00d7"]] = "\u00d7"  # the why line's multiplication sign
MINUS = "\u2212"
Op = Literal["+", "\u00d7"]
NUMBERS = ("no", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten")
STAGE_WORDS = ("reconnaissance", "access", "foothold or control", "actions on the goal")
# an object of the organisation's own network, in the site's words ("internal device")
OBJECT_THINGS = {"device": ("device", "devices"), "account": ("account", "accounts"),
                 "site": ("site", "sites")}  # fmt: skip


def object_words(kind: str) -> tuple[str, str]:
    """(one, many) for an object of ``kind`` in the site's words; an account is the person's."""
    one, many = OBJECT_THINGS.get(kind, ("object", "objects"))
    if kind == "account":
        return one, many
    return site.own(one), site.own(many)


@dataclass(frozen=True)
class Weights:
    """The priority's constants (the plan's E5; recalibrated on the replay by a person)."""

    k: float = 80.0
    others_share: float = 0.3
    others_counted: int = 5
    stage_step: float = 0.25
    spread_step: float = 0.1
    spread_cap: int = 10
    active_day: float = 1.2
    active_days: float = 1.0
    quiet: float = 0.7
    confirmed: float = 1.3
    stale_share: float = 0.2  # of the points of intel from an out-of-date feed, taken off
    p1: int = 63
    p2: int = 55
    p3: int = 46
    family_step: float = 0.5  # the engine's families.step and cap (config/risk.yaml), for the why
    family_cap: int = 3


WEIGHTS = Weights()


@dataclass(frozen=True)
class Part:
    """One source's share of an object's 7-day score, from the stored breakdown."""

    source: str  # rule:<lineage> or ev:<kind>
    points: float
    base: float = 0.0


@dataclass(frozen=True)
class Facts:
    """An internal object as the presenter reads it: its 7-day score and breakdown, and when it
    was last seen."""

    kind: str  # device, account, site
    label: str
    score: float  # R_7d
    families: int = 0
    stages: int = 0  # matched stages, 7 days
    parts: tuple[Part, ...] = ()  # largest first
    last_seen: datetime | None = None
    criticality: float = 1.0


@dataclass(frozen=True)
class Trust:
    confirmed: bool = False  # a person confirmed the incident
    stale_points: float = 0.0  # the top object's points of out-of-date intel, no fresh strong fact


NO_TRUST = Trust()


@dataclass(frozen=True)
class WhyItem:
    op: Op
    points: float
    text: str

    def words(self) -> str:
        if self.op == "+":
            sign = MINUS if self.points < 0 else "+"
            return f"{sign}{_number(abs(self.points))} {self.text}"
        return f"{TIMES}{_factor(self.points)} {self.text}"


@dataclass(frozen=True)
class Scored:
    priority: int
    band: Band
    x: float
    top: Facts | None
    others: float  # the others' share, already weighted
    stale: float  # taken off for out-of-date intel
    stage: float
    spread: float
    activity: float
    trust: float
    active: bool  # an observation in the last 72 h
    stages: int
    objects: int


def band_of(priority: int, w: Weights = WEIGHTS) -> Band:
    if priority >= w.p1:
        return "P1"
    if priority >= w.p2:
        return "P2"
    if priority >= w.p3:
        return "P3"
    return "P4"


def activity(last_seen: datetime | None, now: datetime, w: Weights = WEIGHTS) -> float:
    if last_seen is None:
        return w.quiet
    age = now - last_seen
    if age <= timedelta(hours=24):
        return w.active_day
    if age <= timedelta(hours=72):
        return w.active_days
    return w.quiet


def score(objects: Sequence[Facts], now: datetime, trust: Trust = NO_TRUST,
          w: Weights = WEIGHTS) -> Scored:  # fmt: skip
    """The incident's priority from its objects (any order; the highest score is the top)."""
    ranked = sorted(objects, key=lambda f: (-f.score, f.label))
    top = ranked[0] if ranked else None
    others = w.others_share * sum(f.score for f in ranked[1 : 1 + w.others_counted])
    stages = max((f.stages for f in ranked), default=0)
    stage = 1.0 + w.stage_step * max(0, stages - 1)
    spread = 1.0 + w.spread_step * min(max(0, len(ranked) - 1), w.spread_cap)
    last = max((f.last_seen for f in ranked if f.last_seen is not None), default=None)
    act = activity(last, now, w)
    factor = w.confirmed if trust.confirmed else 1.0
    stale = w.stale_share * max(0.0, trust.stale_points) if top else 0.0
    base = (top.score if top else 0.0) - stale + others
    x = max(0.0, base) * stage * spread * act * factor
    priority = max(0, min(100, round(100 * (1 - math.exp(-x / w.k)))))
    return Scored(priority, band_of(priority, w), x, top, others, stale, stage, spread, act,
                  factor, act >= w.active_days, stages, len(ranked))  # fmt: skip


def family_factor(families: int, w: Weights = WEIGHTS) -> float:
    return 1.0 + w.family_step * (min(families, w.family_cap) - 1) if families > 1 else 1.0


def why(
    scored: Scored, objects: Sequence[Facts], words: Callable[[Part], str],
    now: datetime, trust: Trust = NO_TRUST, w: Weights = WEIGHTS, limit: int = 5,
) -> list[WhyItem]:  # fmt: skip
    """The why line's items, from the top object's stored breakdown (largest first, at most
    ``limit`` sources), then each factor that is not one."""
    out: list[WhyItem] = []
    top = scored.top
    if top is not None:
        for part in [p for p in top.parts if round(p.points) > 0][:limit]:
            out.append(WhyItem("+", float(round(part.points)), words(part)))
        family = family_factor(top.families, w)
        if family > 1:
            out.append(WhyItem(TIMES, family, f"{_count(top.families)} log families"))
        if top.criticality != 1:
            out.append(WhyItem(TIMES, top.criticality, "the asset's criticality"))
    if round(scored.stale) > 0:
        out.append(WhyItem("+", -float(round(scored.stale)), "its threat list is out of date"))
    if scored.others >= 0.5:
        n = scored.objects - 1
        kinds = {f.kind for f in sorted(objects, key=lambda f: (-f.score, f.label))[1:]}
        noun = _noun(kinds.pop() if len(kinds) == 1 else "object", n)
        out.append(WhyItem("+", float(round(scored.others)), f"{_count(n)} other {noun}"))
    if scored.stage > 1:
        out.append(WhyItem(TIMES, scored.stage, f"{_count(scored.stages)} attack stages"))
    if scored.spread > 1:
        out.append(
            WhyItem(
                TIMES, scored.spread, f"spread over {scored.objects} {object_words('object')[1]}"
            )
        )
    if scored.activity != 1:
        last = max((f.last_seen for f in objects if f.last_seen is not None), default=None)
        out.append(WhyItem(TIMES, scored.activity, _activity_words(scored.activity, last, now, w)))
    if trust.confirmed:
        out.append(WhyItem(TIMES, w.confirmed, "confirmed by a person"))
    return out


def line(items: Sequence[WhyItem]) -> str:
    return " · ".join(i.words() for i in items)


def _activity_words(value: float, last: datetime | None, now: datetime, w: Weights) -> str:
    if value >= w.active_day:
        return "still active"
    if last is None:
        return "quiet"
    days = max(3, (now - last) // timedelta(days=1))
    return f"quiet for {days} days"


def _noun(kind: str, n: int) -> str:
    one, many = object_words(kind)
    return one if n == 1 else many


def _count(n: int) -> str:
    return NUMBERS[n] if 0 <= n < len(NUMBERS) else str(n)


def _number(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else f"{value:g}"


def _factor(value: float) -> str:
    return f"{round(value, 2):g}"
