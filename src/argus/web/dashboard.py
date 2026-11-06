"""The SOC dashboard: alerts, cases and incidents over time, by state, severity, rule and entity,
under one set of filters. It reads ARGUS's own database only, never the SIEM.

Words: an *investigation* (an alert group on the pages) is one rule, one key and one local day
(``cases`` and ``Case`` here still mean investigations: their old name). An *incident* is a case
(one real problem across days, hosts and rules) a person confirmed, and a *possible incident* a
suspected case: ``incident_cases`` and ``possible_incidents`` count them. ``incidents`` and
``suspected`` still count investigations: those a person called a true positive, and those
ARGUS proposes as one that nobody has decided yet."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime, time, timedelta
from typing import Any, Literal
from urllib.parse import urlencode

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus import site
from argus.cases import knownview
from argus.web.queries import (
    _HUMAN,
    _SEVERITY_RANK,
    _STATE,
    CHANGED,
    KNOWN,
    RAISED,
    key_fields,
)

RangeName = Literal["24h", "7d", "30d", "90d"]
RANGES: dict[str, timedelta] = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "90d": timedelta(days=90),
}
RANGE_TITLES = {"24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days",
                "90d": "Last 90 days"}  # fmt: skip
STATE_TITLES = {"unreviewed": "Not reviewed", "follow_up": "Follow-up",
                "changed_since_review": "Changed since review", "reviewed": "Reviewed"}  # fmt: skip
AI_TITLES = {"proposed_tp": "Proposes true positive", "proposed_other": "Proposes benign",
             "no_proposal": "No proposal", "working": "Working on it",
             "none": "Not assessed"}  # fmt: skip
KINDS = ("ip", "host", "domain", "user")
TOP = 10


@dataclass(frozen=True)
class Filters:
    """What the dashboard shows. Each list is "any of these"; empty means all."""

    range: str = "7d"
    start: date | None = None  # a custom span, in local days (both or neither)
    end: date | None = None
    severity: tuple[str, ...] = ()
    state: tuple[str, ...] = ()
    verdict: tuple[str, ...] = ()
    ai: tuple[str, ...] = ()
    rule: str | None = None
    kind: str | None = None
    value: str | None = None

    def span(self, now: datetime) -> tuple[datetime, datetime]:
        if self.start is not None and self.end is not None:
            first, last = sorted((self.start, self.end))
            zone = site.zone()
            begin = datetime.combine(first, time(), zone).astimezone(UTC)
            return begin, datetime.combine(last + timedelta(days=1), time(), zone).astimezone(UTC)
        return now - RANGES[self.range], now

    def params(self) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        if self.start is not None and self.end is not None:
            out += [("start", self.start.isoformat()), ("end", self.end.isoformat())]
        elif self.range != "7d":
            out.append(("range", self.range))
        out += [("severity", s) for s in self.severity]
        out += [("state", s) for s in self.state]
        out += [("verdict", s) for s in self.verdict]
        out += [("ai", s) for s in self.ai]
        if self.rule:
            out.append(("rule", self.rule))
        if self.kind and self.value:
            out += [("kind", self.kind), ("value", self.value)]
        return out

    def url(self, **change: Any) -> str:
        """This dashboard with some filters changed (``None`` or ``()`` removes one)."""
        query = urlencode(replace(self, **change).params())
        return "/dashboard" + (f"?{query}" if query else "")

    def adding(self, name: str, value: str) -> str:
        """The URL that also filters on ``name`` = ``value`` (a click on a chart or a row)."""
        if name in ("rule", "kind"):
            return self.url(**({"rule": value} if name == "rule" else {}))
        current: tuple[str, ...] = getattr(self, name)
        return self.url(**{name: current if value in current else (*current, value)})

    def chips(self) -> list[tuple[str, str]]:
        """The active filters, each with the URL that removes it."""
        out: list[tuple[str, str]] = []
        for name, titles in (("severity", {}), ("state", STATE_TITLES), ("verdict", {}),
                             ("ai", AI_TITLES)):  # fmt: skip
            values: tuple[str, ...] = getattr(self, name)
            for v in values:
                label = titles.get(v, v.replace("_", " "))
                rest = tuple(x for x in values if x != v)
                out.append((f"{name}: {label}", self.url(**{name: rest})))
        if self.rule:
            out.append((f"rule: {self.rule}", self.url(rule=None)))
        if self.kind and self.value:
            out.append((f"{self.kind}: {self.value}", self.url(kind=None, value=None)))
        return out


_AI = """
LEFT JOIN LATERAL (
  SELECT a.status, a.outcome FROM assessments a
  WHERE a.investigation_id = i.id AND a.version = i.version
  ORDER BY (a.status = 'proposed') DESC, a.assessor LIKE 'agent%' DESC, a.id DESC LIMIT 1
) ai ON true
"""
_AI_KIND = """
CASE WHEN ai.status IS NULL THEN 'none'
     WHEN ai.status = 'proposed' AND ai.outcome = 'true_positive' THEN 'proposed_tp'
     WHEN ai.status = 'proposed' THEN 'proposed_other'
     WHEN ai.status IN ('queued', 'running') THEN 'working'
     ELSE 'no_proposal' END
"""


def _cases(
    f: Filters, start: datetime, end: datetime, *, with_ai: bool = True
) -> tuple[str, dict[str, Any]]:
    """The filtered cases as a CTE named ``f``: active in the span (a last alert after its
    start, a first alert before its end) and matching every filter. Without the assessment
    (``with_ai=False``, only when no filter asks for it) ``ai`` is "none" and each investigation
    costs one lookup less: for a read that shows the assessment of a few rows only."""
    inner = ["i.last_event_at >= :start", "i.first_event_at < :end"]
    outer = ["true"]
    params: dict[str, Any] = {"start": start, "end": end}
    if f.severity:
        inner.append("i.severity = ANY(CAST(:severity AS text[]))")
        params["severity"] = list(f.severity)
    if f.rule:
        inner.append("i.rule_id = :rule")
        params["rule"] = f.rule
    if f.kind and f.value:
        inner.append(
            "EXISTS (SELECT 1 FROM investigation_entities e WHERE e.investigation_id = i.id"
            " AND e.kind = :kind AND e.value = :value)"
        )
        params["kind"], params["value"] = f.kind, f.value
    if f.state:
        outer.append("state = ANY(CAST(:state AS text[]))")
        params["state"] = list(f.state)
    if f.verdict:
        outer.append("coalesce(verdict, 'none') = ANY(CAST(:verdict AS text[]))")
        params["verdict"] = list(f.verdict)
    if f.ai:
        outer.append("ai = ANY(CAST(:ai AS text[]))")
        params["ai"] = list(f.ai)
    assess = with_ai or bool(f.ai)
    ai_columns = (
        f"{_AI_KIND} AS ai, ai.outcome AS ai_outcome"
        if assess
        else "'none' AS ai, NULL AS ai_outcome"
    )
    cte = f"""
WITH f AS (SELECT * FROM (
  SELECT i.id, i.rule_id, coalesce(i.rule_name, i.rule_id) AS rule, i.severity,
    {_SEVERITY_RANK} AS rank, i.alert_count, i.first_event_at, i.last_event_at, i.group_key,
    {_HUMAN} AS state, last.outcome AS verdict, last.decided_at AS reviewed_at,
    {RAISED} AS raised, {KNOWN} AS known, {CHANGED} AS changed, {ai_columns}
  FROM investigations i {_STATE} {_AI if assess else ""}
  WHERE {" AND ".join(inner)}
) c WHERE {" AND ".join(outer)})
"""  # noqa: S608 - constant fragments; every value is bound
    return cte, params


_ALERTS = """
SELECT count(*) FROM alert_records ar
JOIN investigation_alerts ia ON ia.alert_id = ar.alert_id JOIN f ON f.id = ia.investigation_id
WHERE ar.event_time >= :start AND ar.event_time < :end"""


@dataclass(frozen=True)
class Case:
    id: str
    rule: str
    severity: str | None
    alert_count: int
    last_event_at: datetime | None
    state: str
    verdict: str | None
    ai: str
    key_fields: list[tuple[str, Any]] = field(default_factory=list)


@dataclass
class Dashboard:
    filters: Filters
    start: datetime
    end: datetime
    bucket: str  # "hour" or "day"
    kpis: dict[str, Any]
    series: list[tuple[datetime, dict[str, int]]]
    states: dict[str, int]
    severities: dict[str, int]
    verdicts: dict[str, int]
    ais: dict[str, int]
    rules: list[dict[str, Any]]
    entities: dict[str, list[dict[str, Any]]]
    incidents: list[Case]
    open_cases: list[Case]
    rule_choices: list[tuple[str, str]]
    notified: list[knownview.KnownCase] = field(default_factory=list)  # cases whose owner was told


def _case(row: Any) -> Case:
    return Case(str(row.id), row.rule, row.severity, row.alert_count, row.last_event_at,
                row.state, row.verdict, row.ai, key_fields(row.group_key))  # fmt: skip


_KPIS = """
SELECT count(*) AS cases,
  count(*) FILTER (WHERE state <> 'reviewed') AS open,
  count(*) FILTER (WHERE state = 'follow_up'
                   OR (NOT known AND (state = 'changed_since_review'
                       OR (state = 'unreviewed' AND (severity IN ('critical', 'high') OR raised))))
                   OR (changed AND state <> 'reviewed')) AS attention,
  count(*) FILTER (WHERE known AND (state = 'changed_since_review'
                   OR (state = 'unreviewed' AND (severity IN ('critical', 'high') OR raised))))
                   AS known,
  count(*) FILTER (WHERE state = 'follow_up') AS follow_up,
  count(*) FILTER (WHERE verdict = 'true_positive') AS incidents,
  count(*) FILTER (WHERE ai = 'proposed_tp' AND state <> 'reviewed') AS suspected,
  count(*) FILTER (WHERE state = 'reviewed') AS reviewed,
  count(*) FILTER (WHERE ai <> 'none') AS assessed,
  count(*) FILTER (WHERE severity = 'critical' AND state <> 'reviewed') AS open_critical
FROM f"""
# incidents are cases (one meaning of the word): confirmed and not closed, whoever was told (the
# case list's "incidents" view, which the number opens), and the possible ones (suspected) a
# person still decides; counted now, whatever the span and the filters
_CASES = """
SELECT count(*) FILTER (WHERE state IN ('open', 'assigned', 'contained')) AS incidents,
  count(*) FILTER (WHERE state = 'suspected') AS possible
FROM cases"""
_FIRST_REVIEW = """
SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM r.first - f.first_event_at))
FROM f JOIN (SELECT investigation_id, min(created_at) AS first FROM review_events
             WHERE action <> 'note' GROUP BY 1) r ON r.investigation_id = f.id
WHERE r.first >= f.first_event_at"""
_SERIES = """
SELECT date_trunc(:bucket, ar.event_time AT TIME ZONE @ZONE@) AS b,
       coalesce(f.severity, 'unknown') AS sev, count(*) AS n
FROM alert_records ar
JOIN investigation_alerts ia ON ia.alert_id = ar.alert_id JOIN f ON f.id = ia.investigation_id
WHERE ar.event_time >= :start AND ar.event_time < :end GROUP BY 1, 2"""
_GROUPS = """
SELECT 'state' AS g, state AS v, count(*) AS n FROM f GROUP BY state
UNION ALL SELECT 'severity', coalesce(severity, 'unknown'), count(*) FROM f GROUP BY 2
UNION ALL SELECT 'verdict', coalesce(verdict, 'none'), count(*) FROM f GROUP BY 2
UNION ALL SELECT 'ai', ai, count(*) FROM f GROUP BY ai"""
_RULES = """
SELECT rule_id, min(rule) AS rule, count(*) AS cases, sum(alert_count) AS alerts,
  count(*) FILTER (WHERE state <> 'reviewed') AS open,
  count(*) FILTER (WHERE verdict = 'true_positive') AS incidents,
  count(*) FILTER (WHERE ai = 'proposed_tp' AND state <> 'reviewed') AS suspected,
  max(rank) AS rank
FROM f GROUP BY rule_id ORDER BY sum(alert_count) DESC, rule_id LIMIT :top"""
_ENTITIES = """
SELECT kind, value, cases, alerts, open FROM (
  SELECT e.kind, e.value, count(*) AS cases, sum(f.alert_count) AS alerts,
    count(*) FILTER (WHERE f.state <> 'reviewed') AS open,
    row_number() OVER (PARTITION BY e.kind ORDER BY count(*) DESC, e.value) AS place
  FROM investigation_entities e JOIN f ON f.id = e.investigation_id GROUP BY e.kind, e.value
) x WHERE place <= :top ORDER BY kind, place"""
_INCIDENTS = """
SELECT * FROM f WHERE verdict = 'true_positive' OR (ai = 'proposed_tp' AND state <> 'reviewed')
ORDER BY coalesce(verdict = 'true_positive', false) DESC, last_event_at DESC NULLS LAST, id
LIMIT 20"""
_OPEN = """
SELECT * FROM f WHERE state <> 'reviewed'
ORDER BY (state = 'follow_up') DESC, rank DESC, last_event_at DESC NULLS LAST, id LIMIT 15"""
_CHOICES = """
SELECT rule_id, min(rule) AS rule FROM f GROUP BY rule_id ORDER BY min(rule), rule_id LIMIT 500"""
RANKS = {4: "critical", 3: "high", 2: "medium", 1: "low"}


async def build(conn: AsyncConnection, f: Filters, now: datetime) -> Dashboard:
    start, end = f.span(now)
    cte, p = _cases(f, start, end)
    hourly = end - start <= timedelta(days=2)

    async def rows(query: str, **more: Any) -> list[Any]:
        return list(await conn.execute(text(cte + query), {**p, **more}))

    kpis: dict[str, Any] = {k: int(v) for k, v in (await rows(_KPIS))[0]._mapping.items()}
    kpis["alerts"] = int((await rows(_ALERTS))[0][0])
    before_cte, before = _cases(f, start - (end - start), start)
    kpis["alerts_before"] = int(await conn.scalar(text(before_cte + _ALERTS), before))
    median = (await rows(_FIRST_REVIEW))[0][0]
    kpis["median_review_s"] = float(median) if median is not None else None
    cases = (await conn.execute(text(_CASES))).one()
    kpis["incident_cases"] = int(cases.incidents)
    kpis["possible_incidents"] = int(cases.possible)

    by_bucket: dict[datetime, dict[str, int]] = {}
    zone = site.zone()
    for r in await rows(
        _SERIES.replace("@ZONE@", site.zone_sql()), bucket="hour" if hourly else "day"
    ):
        by_bucket.setdefault(r.b.replace(tzinfo=zone), {})[r.sev] = int(r.n)

    groups: dict[str, dict[str, int]] = {"state": {}, "severity": {}, "verdict": {}, "ai": {}}
    for r in await rows(_GROUPS):
        groups[r.g][r.v] = int(r.n)

    rules = [dict(r._mapping) for r in await rows(_RULES, top=TOP)]
    for r in rules:
        r["severity"] = RANKS.get(r.pop("rank"))
    entities: dict[str, list[dict[str, Any]]] = {kind: [] for kind in KINDS}
    for r in await rows(_ENTITIES, top=TOP):
        entities.setdefault(r.kind, []).append(dict(r._mapping))

    choice_cte, choice_p = _cases(replace(f, rule=None), start, end)
    choices = await conn.execute(text(choice_cte + _CHOICES), choice_p)
    rule_choices = [(r.rule_id, r.rule) for r in choices]
    if f.rule and f.rule not in {rid for rid, _ in rule_choices}:
        rule_choices.insert(0, (f.rule, f.rule))

    return Dashboard(
        f,
        start,
        end,
        "hour" if hourly else "day",
        kpis,
        _fill(by_bucket, start, end, hourly),
        groups["state"],
        groups["severity"],
        groups["verdict"],
        groups["ai"],
        rules,
        entities,
        [_case(r) for r in await rows(_INCIDENTS)],
        [_case(r) for r in await rows(_OPEN)],
        rule_choices,
        await knownview.notified(conn, now),
    )


THREAT_EXAMINED = 60  # the open investigations whose threat-list check the tile reads
THREAT_SHOWN = 5
_URGENT = "(state = 'follow_up') DESC, rank DESC, last_event_at DESC NULLS LAST, id"
# the most urgent open ones from the filtered cases (a top-N pass: no count of all of them, which
# the dashboard's own "open" number already is, and which would make the pass spool every row to
# disk); then, for those few only, their assessment and their newest dossier's ti.listed signal
# (a known positive one wins if the dossier has several, local signals first otherwise)
_THREAT = f"""
SELECT t.id, t.rule, t.severity, t.alert_count, t.last_event_at, t.state, t.verdict, t.group_key,
  {_AI_KIND} AS ai, dd.body IS NOT NULL AS has_dossier, sig.status AS ti_status,
  sig.value AS ti_value
FROM (SELECT f.* FROM f WHERE f.state <> 'reviewed'
      ORDER BY {_URGENT} LIMIT :examined) t
JOIN investigations i ON i.id = t.id
LEFT JOIN LATERAL (
  SELECT a.status, a.outcome FROM assessments a
  WHERE a.investigation_id = i.id AND a.version = i.version
  ORDER BY (a.status = 'proposed') DESC, a.assessor LIKE 'agent%' DESC, a.id DESC LIMIT 1
) ai ON true
LEFT JOIN LATERAL (SELECT d.body FROM dossiers d WHERE d.investigation_id = i.id
                   AND d.version = i.version ORDER BY d.created_at DESC LIMIT 1) dd ON true
LEFT JOIN LATERAL (
  SELECT s ->> 'status' AS status, s -> 'value' AS value
  FROM jsonb_array_elements(
    CASE WHEN jsonb_typeof(dd.body -> 'local_signals') = 'array'
         THEN dd.body -> 'local_signals' ELSE '[]'::jsonb END ||
    CASE WHEN jsonb_typeof(dd.body -> 'signals') = 'array'
         THEN dd.body -> 'signals' ELSE '[]'::jsonb END) WITH ORDINALITY AS e(s, pos)
  WHERE s ->> 'name' = 'ti.listed'
  ORDER BY CASE WHEN s ->> 'status' = 'known' AND jsonb_typeof(s -> 'value') = 'number'
                THEN (s ->> 'value')::numeric <= 0 ELSE true END, pos LIMIT 1) sig ON true
ORDER BY {_URGENT}"""  # noqa: S608 - constant fragments; every value is bound


@dataclass(frozen=True)
class ThreatTile:
    examined: int
    on_a_list: int
    clear: int
    could_not_tell: int
    not_checked: int
    listed: list[Case]


def _ti_answer(row: Any) -> str:
    """What a dossier says about a threat list: ``on_a_list``, ``clear``, ``could_not_tell`` (an
    unknown answer, or one this code cannot read) or ``not_checked`` (no dossier, or none that
    asks)."""
    if not row.has_dossier or row.ti_status is None:
        return "not_checked"
    value = row.ti_value
    if row.ti_status != "known" or isinstance(value, bool) or not isinstance(value, int | float):
        return "could_not_tell"
    return "on_a_list" if value > 0 else "clear"


async def threat_lists(conn: AsyncConnection, f: Filters, now: datetime) -> ThreatTile:
    """Whether the most urgent open investigations of the dashboard's span are on a threat
    list, as their dossiers' ``ti.listed`` signal says (unknown is never "clear")."""
    start, end = f.span(now)
    cte, p = _cases(f, start, end, with_ai=False)
    found = list(await conn.execute(text(cte + _THREAT), {**p, "examined": THREAT_EXAMINED}))
    answers = [_ti_answer(r) for r in found]
    return ThreatTile(
        examined=len(found),
        on_a_list=answers.count("on_a_list"),
        clear=answers.count("clear"),
        could_not_tell=answers.count("could_not_tell"),
        not_checked=answers.count("not_checked"),
        listed=[_case(r) for r, a in zip(found, answers, strict=True) if a == "on_a_list"][
            :THREAT_SHOWN
        ],
    )


def _fill(by: dict[datetime, dict[str, int]], start: datetime, end: datetime,
          hourly: bool) -> list[tuple[datetime, dict[str, int]]]:  # fmt: skip
    """Every bucket of the span, empty ones included, in the site's zone. The report's buckets
    (``date_trunc`` on the local clock) are wall-clock hours and days: hours are stepped in UTC
    (an hour is an hour; a wall-clock step lands on the hour a clock change skips, which is the
    next one, and misses the one it repeats), where a clock change repeats an hour its alerts are
    counted once, in the first of the two; days are stepped as dates (a day has 23 or 25 hours
    on a clock-change day)."""
    zone = site.zone()
    wall = {k.astimezone(zone).replace(tzinfo=None): v for k, v in by.items()}
    first = start.astimezone(zone).replace(minute=0, second=0, microsecond=0)
    out: list[tuple[datetime, dict[str, int]]] = []
    if hourly:  # a span is at most 2 days of them
        seen: set[datetime] = set()
        at = first.astimezone(UTC)
        while at < end:
            local = at.astimezone(zone)
            key = local.replace(minute=0, second=0, microsecond=0, tzinfo=None)
            out.append((local, {} if key in seen else wall.get(key, {})))
            seen.add(key)
            at += timedelta(hours=1)
        return out
    day = first.date()
    while True:  # a span is at most 366 days
        midnight = datetime.combine(day, time.min, zone)
        if midnight >= end:
            return out
        out.append((midnight, wall.get(datetime.combine(day, time.min), {})))
        day += timedelta(days=1)


def duration(seconds: float | None) -> str:
    """A span of time in plain words: "45 min", "3 h 20 min", "2 days 4 h"."""
    if seconds is None:
        return "—"
    minutes = int(seconds) // 60
    if minutes < 60:
        return f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours} h {minutes} min" if minutes else f"{hours} h"
    days, hours = divmod(hours, 24)
    return f"{days} days {hours} h" if hours else f"{days} days"


def as_json(d: Dashboard) -> dict[str, Any]:
    """The dashboard's numbers for the API (``/api/dashboard``)."""
    data: dict[str, Any] = json.loads(json.dumps({
        "start": d.start.isoformat(), "end": d.end.isoformat(), "bucket": d.bucket,
        "kpis": d.kpis, "series": [[b.isoformat(), v] for b, v in d.series],
        "states": d.states, "severities": d.severities, "verdicts": d.verdicts, "ai": d.ais,
        "rules": d.rules, "entities": d.entities,
        "incidents": [c.id for c in d.incidents], "open_cases": [c.id for c in d.open_cases],
        "notified": [
            {"case": c.number, "notified_at": c.notified_at, "days": c.days, "alerts": c.alerts,
             "blocked": c.blocked_at is not None, "trend": c.trend,
             "reminders": [r.kind for r in c.reminders]}
            for c in d.notified
        ],
    }, default=str))  # fmt: skip
    return data
