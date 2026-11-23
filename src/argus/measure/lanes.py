"""The lanes' allowances from what was measured.

For each lane and template, the p95 of the template's server time (from at least 3 answered
requests) times its planned rate, summed over the lane, must fit the lane's share of the headroom
per minute and per day (heavy requests against its heavy share). A lane with a template of fewer
than 3 samples keeps its proposed allowance and is reported as not measured, unless its measured
templates alone put it over. The headroom is the ceiling, lowered (never raised) by the probe
readings: ARGUS may use at most ``spare_share`` of the core time the SIEM leaves unused. The rule
only proposes; raising the ceiling is the operator's decision. Pure: rows in, results out.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any, Literal

from argus.gateway.state import ProbeRow, RecentRequest
from argus.gateway.templates import REGISTRY, CostClass
from argus.measure.session import COMPONENT as MEASURE_COMPONENT
from argus.measure.session import cost_of

MIN_SAMPLES = 3
MINUTE_MS = 60_000


@dataclass(frozen=True)
class Ceiling:
    minute_ms: int = 3_000
    day_ms: int = 3_600_000
    heavy_day: int = 2_000


@dataclass(frozen=True)
class Lane:
    name: str
    label: str
    minute_ms: int
    day_ms: int
    heavy_day: int | None  # None: the lane sends no heavy request
    components: frozenset[str]  # the ledger's components whose requests are this lane's


def _lane(
    name: str, label: str, minute: int, minutes: int, heavy: int | None, *components: str
) -> Lane:
    return Lane(name, label, minute, minutes * MINUTE_MS, heavy, frozenset(components))


# The proposed allowances: they add up to the ceiling (a test keeps them so).
LANES = (
    _lane(
        "collector",
        "Collector and enrichment",
        1_800,
        40,
        1_600,
        "collector",
        "enrichment",
        "reference",
    ),
    _lane("investigation", "Investigation", 400, 6, 300, "investigation", "agent", "watch"),
    _lane("freshness", "Freshness", 150, 3, None, "freshness"),
    _lane("kibana_reads", "Kibana reads", 250, 4, None, "kibana"),
    _lane("writes", "Kibana and alert writes", 200, 3, None, "cases", "writeback"),
    _lane("identity", "Identity", 200, 2, None, "identity"),
    _lane("measurement", "Measurement and reserve", 0, 2, 100, MEASURE_COMPONENT),
)
OUTSIDE = frozenset({"probe", "selftest", "gateway"})  # probes: outside the bucket


def nearest_rank(values: Sequence[float], q: float) -> float:
    """The q-quantile by nearest rank (no interpolation): always a value that was seen."""
    if not values:
        raise ValueError("no values")
    ordered = sorted(values)
    return ordered[max(math.ceil(q * len(ordered)) - 1, 0)]


@dataclass(frozen=True)
class TemplateStats:
    template: str
    cost: CostClass
    samples: int
    p50_ms: int
    p95_ms: int
    max_ms: int


def template_stats(rows: Iterable[RecentRequest]) -> dict[str, TemplateStats]:
    """Server time per template from the answered requests (``ok``), every component's,
    probes left out (they are outside the bucket)."""
    tooks: dict[str, list[int]] = defaultdict(list)
    for row in rows:
        if row.outcome == "ok" and cost_of(row.template) is not CostClass.PROBE:
            tooks[row.template].append(row.took_ms)
    return {
        name: TemplateStats(
            name,
            cost_of(name),
            len(values),
            int(nearest_rank(values, 0.5)),
            int(nearest_rank(values, 0.95)),
            max(values),
        )
        for name, values in sorted(tooks.items())
    }


@dataclass(frozen=True)
class Rate:
    lane: str
    template: str
    per_minute: int  # the busiest minute
    per_day: int  # the busiest full UTC day (or the span's average when there is none)
    full_days: int
    planned: bool = False  # from a plan file, not observed


def lane_of(component: str, lanes: Sequence[Lane] = LANES) -> str | None:
    for lane in lanes:
        if component in lane.components:
            return lane.name
    return None


def observed_rates(
    rows: Sequence[RecentRequest], until: datetime, lanes: Sequence[Lane] = LANES
) -> tuple[list[Rate], list[str]]:
    """Each lane's templates at their busiest (every request sent, whatever it answered), the
    session's own and the probes left out; and the components no lane owns."""
    by_minute: Counter[tuple[str, str, datetime]] = Counter()
    by_day: Counter[tuple[str, str, date]] = Counter()
    first: dict[tuple[str, str], datetime] = {}
    unowned: set[str] = set()
    for row in rows:
        if row.component in OUTSIDE or row.component == MEASURE_COMPONENT:
            continue
        if cost_of(row.template) is CostClass.PROBE:
            continue
        lane = lane_of(row.component, lanes)
        if lane is None:
            unowned.add(row.component)
            continue
        key = (lane, row.template)
        by_minute[(*key, row.at.replace(second=0, microsecond=0))] += 1
        by_day[(*key, row.at.date())] += 1
        first[key] = min(first.get(key, row.at), row.at)
    rates = []
    for key, since in sorted(first.items()):
        minute = max(n for (lane, name, _), n in by_minute.items() if (lane, name) == key)
        days = {day: n for (lane, name, day), n in by_day.items() if (lane, name) == key}
        full = {day: n for day, n in days.items() if since.date() < day < until.date()}
        if full:
            per_day = max(full.values())
        else:  # no whole day seen: the span's average, scaled to a day
            span = max((until - since).total_seconds(), 3_600.0)
            per_day = math.ceil(sum(days.values()) * 86_400 / span)
        rates.append(Rate(key[0], key[1], minute, per_day, len(full)))
    return rates, sorted(unowned)


def apply_plan(rates: Sequence[Rate], plan: Mapping[str, Any]) -> list[Rate]:
    """A plan file's rates replace (or add to) the observed ones: ``{lane: {template:
    {"per_minute": n, "per_day": n}}}``; a plan never lowers an observed rate. Only templates
    ARGUS has (and no probe: probes are outside the bucket), so a typo cannot hide a lane's
    demand."""
    if not isinstance(plan, Mapping):
        raise ValueError("the plan is a mapping of lanes to templates")
    known = {lane.name for lane in LANES}
    merged = {(rate.lane, rate.template): rate for rate in rates}
    for lane, templates in plan.items():
        if lane not in known:
            raise ValueError(f"the plan names an unknown lane {lane!r}")
        if not isinstance(templates, Mapping):
            raise ValueError(f"the plan's {lane} is not a mapping of templates")
        for template, value in templates.items():
            found = REGISTRY.get(template)
            if found is None:
                raise ValueError(f"the plan names an unknown template {lane}.{template!r}")
            if found.cost is CostClass.PROBE:
                raise ValueError(f"the plan's {lane}.{template} is a probe: outside the bucket")
            if not isinstance(value, Mapping) or set(value) - {"per_minute", "per_day"}:
                raise ValueError(f"the plan's {lane}.{template} takes per_minute and per_day")
            numbers = [value.get("per_minute", 0), value.get("per_day", 0)]
            if any(isinstance(n, bool) or not isinstance(n, int) or n < 0 for n in numbers):
                raise ValueError(f"the plan's {lane}.{template} rates are whole numbers ≥ 0")
            old = merged.get((lane, template))
            merged[(lane, template)] = Rate(
                lane,
                template,
                max(numbers[0], old.per_minute if old else 0),
                max(numbers[1], old.per_day if old else 0),
                old.full_days if old else 0,
                planned=True,
            )
    return sorted(merged.values(), key=lambda rate: (rate.lane, rate.template))


@dataclass(frozen=True)
class Headroom:
    ceiling: Ceiling
    readings: int
    load_p95: float | None
    cores: int
    spare_share: float
    minute_ms: int

    @property
    def measured(self) -> bool:
        return self.load_p95 is not None

    @property
    def factor(self) -> float:
        """The share of the ceiling the headroom leaves (at most 1)."""
        return self.minute_ms / self.ceiling.minute_ms


def headroom(
    probes: Iterable[ProbeRow],
    ceiling: Ceiling = Ceiling(),  # noqa: B008 - frozen
    *,
    cores: int = 16,
    spare_share: float = 0.02,
    min_readings: int = MIN_SAMPLES,
) -> Headroom:
    """The ceiling, or less when the SIEM is busier: ``spare_share`` of the core time left
    unused at the p95 load of the good probe readings. Too few readings: the ceiling, marked
    not measured."""
    if cores < 1 or not 0 < spare_share <= 1:
        raise ValueError("cores ≥ 1 and a spare share in (0, 1]")
    loads = [
        p.load_1m
        for p in probes
        if p.probe_ok and p.load_1m is not None and math.isfinite(p.load_1m) and p.load_1m >= 0
    ]
    if len(loads) < min_readings:
        return Headroom(ceiling, len(loads), None, cores, spare_share, ceiling.minute_ms)
    p95 = nearest_rank(loads, 0.95)
    spare = max(cores - p95, 0.0) * MINUTE_MS * spare_share
    return Headroom(
        ceiling, len(loads), p95, cores, spare_share, min(ceiling.minute_ms, int(spare))
    )


Verdict = Literal["fits", "over", "not measured"]


@dataclass(frozen=True)
class LaneResult:
    lane: Lane
    minute_ms: int  # the allowance: the lane's share of the headroom
    day_ms: int
    heavy_day: int | None
    verdict: Verdict
    demand_minute_ms: int | None = None
    demand_day_ms: int | None = None
    demand_heavy_day: int | None = None
    reasons: tuple[str, ...] = ()
    rates: tuple[Rate, ...] = field(default=())


def derive(
    stats: Mapping[str, TemplateStats],
    rates: Sequence[Rate],
    room: Headroom,
    lanes: Sequence[Lane] = LANES,
) -> list[LaneResult]:
    results = []
    for lane in lanes:
        minute = int(lane.minute_ms * room.factor)
        day = int(lane.day_ms * room.factor)
        heavy_share = lane.heavy_day
        mine = tuple(rate for rate in rates if rate.lane == lane.name)
        if not mine:
            results.append(
                LaneResult(
                    lane,
                    minute,
                    day,
                    heavy_share,
                    "not measured",
                    reasons=("no planned rate: §7.8's proposal kept",),
                )
            )
            continue

        def enough(rate: Rate) -> bool:
            return rate.template in stats and stats[rate.template].samples >= MIN_SAMPLES

        short = [
            f"{rate.template}: {stats[rate.template].samples if rate.template in stats else 0}"
            f" samples (needs {MIN_SAMPLES})"
            for rate in mine
            if not enough(rate)
        ]
        # what the measured templates alone need: a lower bound when some are short, so a
        # lane they already put over stays over
        measured = [r for r in mine if enough(r)]
        demand_minute = sum(stats[r.template].p95_ms * r.per_minute for r in measured)
        demand_day = sum(stats[r.template].p95_ms * r.per_day for r in measured)
        heavy = sum(r.per_day for r in measured if stats[r.template].cost is CostClass.HEAVY)
        over = []
        if demand_minute > minute:
            over.append(f"a busy minute needs {demand_minute} ms of its {minute} ms")
        if demand_day > day:
            over.append(
                f"a busy day needs {demand_day / MINUTE_MS:.1f} of its {day / MINUTE_MS:.1f} min"
            )
        if heavy and (heavy_share is None or heavy > heavy_share):
            over.append(f"{heavy} heavy requests a day, its share {heavy_share or 0}")
        if short and not over:
            results.append(
                LaneResult(
                    lane, minute, day, heavy_share, "not measured", reasons=tuple(short), rates=mine
                )
            )
            continue
        results.append(
            LaneResult(
                lane,
                minute,
                day,
                heavy_share,
                "over" if over else "fits",
                demand_minute,
                demand_day,
                heavy,
                (*over, *(f"{reason}: not counted above" for reason in short)),
                mine,
            )
        )
    return results


def report_lines(
    results: Sequence[LaneResult],
    stats: Mapping[str, TemplateStats],
    room: Headroom,
    unowned: Sequence[str] = (),
) -> list[str]:
    lines = ["Templates (answered requests in the ledger):"]
    for s in stats.values():
        enough = "" if s.samples >= MIN_SAMPLES else " (too few)"
        lines.append(
            f"  {s.template} ({s.cost}): {s.samples} samples{enough},"
            f" p50 {s.p50_ms} ms, p95 {s.p95_ms} ms, max {s.max_ms} ms"
        )
    if room.measured:
        lines.append(
            f"Headroom: p95 load {room.load_p95:g} of {room.cores} cores over"
            f" {room.readings} readings; {room.spare_share:.0%} of the spare core time"
            f" is {room.minute_ms} ms a minute"
            f"{' (D-022 ceiling holds)' if room.factor == 1 else ' (BELOW D-022)'}"
        )
    else:
        lines.append(
            f"Headroom: not measured ({room.readings} readings): D-022's ceiling of"
            f" {room.ceiling.minute_ms} ms a minute"
        )
    lines.append("Lanes:")
    for r in results:
        heavy = "" if r.heavy_day is None else f", {r.heavy_day} heavy a day"
        lines.append(
            f"  {r.lane.label}: {r.verdict}; allowance {r.minute_ms} ms a minute,"
            f" {r.day_ms / MINUTE_MS:g} min a day{heavy}"
        )
        if r.demand_minute_ms is not None:
            lines.append(
                f"    needs {r.demand_minute_ms} ms in its busiest minute,"
                f" {(r.demand_day_ms or 0) / MINUTE_MS:.1f} min on its busiest day,"
                f" {r.demand_heavy_day} heavy"
            )
        lines.extend(f"    {reason}" for reason in r.reasons)
    if unowned:
        lines.append(f"Components no lane owns (their load is unassigned): {', '.join(unowned)}")
    return lines


def decision_draft(
    results: Sequence[LaneResult], room: Headroom, since: datetime, until: datetime
) -> str:
    """The text of a decision record for the operator to number and keep (never written here)."""
    rows = "\n".join(
        f"| {r.lane.label} | {r.minute_ms:,} ms | {r.day_ms / MINUTE_MS:g} min |"
        f" {'—' if r.heavy_day is None else f'{r.heavy_day:,}'} | {r.verdict} |"
        for r in results
    )
    measured = (
        f"p95 load {room.load_p95:g} of {room.cores} cores ({room.readings} readings)"
        if room.measured
        else f"not measured ({room.readings} readings): D-022's ceiling kept"
    )
    return f"""## D-NNN — The load budget re-measured; the lanes set
- **Date:** {until:%Y-%m-%d}. **Decided by:** the lead, from the measuring session and the ledger
  from {since:%Y-%m-%d %H:%M} to {until:%Y-%m-%d %H:%M} UTC.
- **Rule:** for each lane, Σ p95 took times planned rate ≤ the lane's share of the headroom, per
  minute and per day, each template with ≥ {MIN_SAMPLES} samples; heavy requests a day within the
  lane's heavy share. The headroom is D-022's ceiling, lowered (never raised) to
  {room.spare_share:.0%} of the SIEM's spare core time at its p95 load: {measured}.
- **Lanes** (server time a minute, a day, heavy a day; plan §7.8's shares scaled by the headroom):

| Lane | A minute | A day | Heavy a day | Verdict |
|---|---|---|---|---|
{rows}

- **Consequences:** a lane "over" keeps its proposal and its work is cut to fit, never the
  ceiling raised; "not measured" lanes keep §7.8's proposal until their templates have
  {MIN_SAMPLES} samples. Raising D-022's ceiling is the user's decision.
"""


def to_json(
    results: Sequence[LaneResult], stats: Mapping[str, TemplateStats], room: Headroom
) -> dict[str, Any]:
    return {
        "format": 1,
        "headroom": {
            "measured": room.measured,
            "readings": room.readings,
            "load_p95": room.load_p95,
            "cores": room.cores,
            "spare_share": room.spare_share,
            "minute_ms": room.minute_ms,
        },
        "templates": {
            s.template: {
                "cost": s.cost.value,
                "samples": s.samples,
                "p50_ms": s.p50_ms,
                "p95_ms": s.p95_ms,
                "max_ms": s.max_ms,
            }
            for s in stats.values()
        },
        "lanes": [
            {
                "lane": r.lane.name,
                "verdict": r.verdict,
                "minute_ms": r.minute_ms,
                "day_ms": r.day_ms,
                "heavy_day": r.heavy_day,
                "demand_minute_ms": r.demand_minute_ms,
                "demand_day_ms": r.demand_day_ms,
                "demand_heavy_day": r.demand_heavy_day,
                "reasons": list(r.reasons),
                "rates": [
                    {
                        "template": x.template,
                        "per_minute": x.per_minute,
                        "per_day": x.per_day,
                        "full_days": x.full_days,
                        "planned": x.planned,
                    }
                    for x in r.rates
                ],
            }
            for r in results
        ],
    }


HARDWARE_CHANGE = datetime.fromisoformat("2026-10-12T00:00:00+00:00")  # older rows: other hardware
DEFAULT_SPAN = timedelta(days=7)
