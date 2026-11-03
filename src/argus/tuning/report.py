"""The weekly per-rule tuning report, every number recomputed from the store: per rule (by name),
over the week before ``now``, alerts per day, investigations, rule runs and runs at the rule's
``max_signals``; people's labels (newest outcome per investigation, plus the gold set's, over the
last ``LABEL_DAYS``); current proposals; and the dominant values with the labels of the
investigations that carry them."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

WEEK = timedelta(days=7)
LABEL_DAYS = timedelta(days=30)
TOP = 8
ASSISTANT = "argus-assistant"


@dataclass(frozen=True)
class ValueStat:
    path: str  # a grouping field, or entity.<kind>
    value: str
    investigations: int
    alerts: int
    labels: dict[str, int] = field(default_factory=dict)  # people's outcomes


@dataclass(frozen=True)
class RuleReport:
    rule: str
    start: datetime
    end: datetime
    alerts: int
    per_day: tuple[tuple[date, int], ...]
    investigations: int
    runs: int
    runs_at_limit: int
    max_signals: int | None
    labels: dict[str, int]
    proposals: dict[str, int]
    values: tuple[ValueStat, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
            "alerts": self.alerts,
            "per_day": [[d.isoformat(), n] for d, n in self.per_day],
            "investigations": self.investigations,
            "runs": self.runs,
            "runs_at_limit": self.runs_at_limit,
            "max_signals": self.max_signals,
            "labels": dict(sorted(self.labels.items())),
            "proposals": dict(sorted(self.proposals.items())),
            "values": [
                {
                    "path": v.path,
                    "value": v.value,
                    "investigations": v.investigations,
                    "alerts": v.alerts,
                    "labels": dict(sorted(v.labels.items())),
                }
                for v in self.values
            ],
        }


_RUNS = """
SELECT coalesce(normalized->>'rule_name', rule_id) AS rule, detected_at::date AS day,
       normalized->>'execution_uuid' AS run, count(*) AS alerts,
       max((normalized->>'max_signals')::int) AS max_signals
FROM alert_records
WHERE detected_at >= :start AND detected_at < :end AND normalized IS NOT NULL
GROUP BY 1, 2, 3
"""
_INVESTIGATIONS = """
SELECT i.id, coalesce(i.rule_name, i.rule_id) AS rule, i.group_key, i.alert_count,
       i.bucket_start >= :start AS this_week
FROM investigations i
WHERE i.bucket_start >= :labels_from AND i.bucket_start < :end
"""
_ENTITIES = """
SELECT e.investigation_id, e.kind, e.value FROM investigation_entities e
JOIN investigations i ON i.id = e.investigation_id
WHERE i.bucket_start >= :labels_from AND i.bucket_start < :end
"""
_LABELS = """
SELECT DISTINCT ON (x.investigation_id) x.investigation_id, x.outcome FROM (
  SELECT r.investigation_id, r.outcome, r.created_at FROM review_events r
  JOIN users u ON u.id = r.user_id
  WHERE r.action = 'reviewed' AND r.outcome IS NOT NULL AND u.username <> :assistant
    AND r.assessment_id IS NULL
  UNION ALL
  SELECT l.investigation_id, l.outcome, l.created_at FROM gold_labels l
) x ORDER BY x.investigation_id, x.created_at DESC
"""
_PROPOSALS = """
SELECT DISTINCT ON (a.investigation_id, a.assessor) a.investigation_id, a.outcome
FROM assessments a JOIN investigations i ON i.id = a.investigation_id AND i.version = a.version
WHERE a.status = 'proposed' AND i.bucket_start >= :start AND i.bucket_start < :end
ORDER BY a.investigation_id, a.assessor, a.id DESC
"""


def _pairs(group_key: str) -> list[tuple[str, str]]:
    try:
        raw = json.loads(group_key)
    except ValueError:
        return []
    return [(str(p[0]), str(p[1])) for p in raw if isinstance(p, list) and len(p) == 2]


async def build(conn: AsyncConnection, now: datetime) -> list[RuleReport]:
    end = now
    start = end - WEEK
    labels_from = end - LABEL_DAYS
    span = {"start": start, "end": end, "labels_from": labels_from}

    runs: dict[str, Counter[str]] = defaultdict(Counter)
    days: dict[str, Counter[date]] = defaultdict(Counter)
    limits: dict[str, int] = {}
    for rule, day, run, alerts, max_signals in await conn.execute(text(_RUNS), span):
        days[rule][day] += alerts
        runs[rule][str(run)] += alerts
        if max_signals is not None:
            limits[rule] = max(limits.get(rule, 0), int(max_signals))

    rows = await conn.execute(text(_LABELS), {"assistant": ASSISTANT})
    label_of: dict[Any, str] = {r[0]: r[1] for r in rows.all()}
    by_inv: dict[Any, list[str]] = defaultdict(list)
    for inv, outcome in await conn.execute(text(_PROPOSALS), span):
        by_inv[inv].append(outcome)
    entities: dict[Any, list[tuple[str, str]]] = defaultdict(list)
    for inv, kind, value in await conn.execute(text(_ENTITIES), span):
        entities[inv].append((f"entity.{kind}", str(value)))

    rules: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "inv": 0,
            "labels": Counter(),
            "proposals": Counter(),
            "values": defaultdict(lambda: [set(), 0, Counter()]),
        }
    )
    for inv, rule, group_key, alert_count, this_week in await conn.execute(
        text(_INVESTIGATIONS), span
    ):
        r = rules[rule]
        label = label_of.get(inv)
        if label is not None:
            r["labels"][label] += 1
        if not this_week:
            if label is None:
                continue  # older ones count only for the labels they carry
        else:
            r["inv"] += 1
            for outcome in by_inv.get(inv, []):
                r["proposals"][outcome] += 1
        seen = set()
        for pair in [*_pairs(group_key), *entities.get(inv, [])]:
            if pair in seen:
                continue
            seen.add(pair)
            stat = r["values"][pair]
            if this_week:
                stat[0].add(inv)
                stat[1] += int(alert_count)  # NOT NULL
            if label is not None:
                stat[2][label] += 1

    out = []
    for rule in sorted(set(rules) | set(days)):
        r = rules[rule]
        week_values = [(pair, s) for pair, s in r["values"].items() if s[0]]
        week_values.sort(key=lambda kv: (-len(kv[1][0]), -kv[1][1], kv[0]))
        limit = limits.get(rule)
        out.append(
            RuleReport(
                rule=rule,
                start=start,
                end=end,
                alerts=sum(days[rule].values()),
                per_day=tuple(sorted(days[rule].items())),
                investigations=r["inv"],
                runs=len(runs[rule]),
                runs_at_limit=sum(1 for n in runs[rule].values() if limit and n >= limit),
                max_signals=limit,
                labels=dict(r["labels"]),
                proposals=dict(r["proposals"]),
                values=tuple(
                    ValueStat(f, v, len(s[0]), s[1], dict(s[2])) for (f, v), s in week_values[:TOP]
                ),
            )
        )
    return [r for r in out if r.alerts or r.investigations]


def label_support(stat: ValueStat | Mapping[str, Any]) -> tuple[int, int]:
    """(benign-like labels, true positives) of the investigations carrying a value."""
    labels = stat.labels if isinstance(stat, ValueStat) else stat.get("labels") or {}
    positives = int(labels.get("true_positive", 0))
    benign = sum(int(n) for o, n in labels.items()
                 if o in ("benign_expected", "benign_policy", "rule_false_positive"))  # fmt: skip
    return benign, positives
