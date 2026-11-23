"""The second soak report: each exit criterion judged from the store over the soak's window.
What the store cannot show (the privacy sweep, a person's own time) is named as such, never
assumed."""

from __future__ import annotations

import itertools
import math
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.evaluation.harness import BENIGN, Rate
from argus.llm.providers import LlmConfig

GAP = timedelta(minutes=45)  # samples are 15 minutes apart: a longer silence is a gap
BACKLOG = timedelta(days=1)


@dataclass(frozen=True)
class Line:
    criterion: str
    verdict: str  # PASS, FAIL, OPEN (cannot be judged from the store), INFO
    detail: str


LABELLED_PROPOSALS = """
SELECT a.id, a.outcome, x.outcome AS label FROM assessments a
JOIN LATERAL (
  SELECT r.outcome FROM review_events r JOIN users u ON u.id = r.user_id
  WHERE r.investigation_id = a.investigation_id AND r.action = 'reviewed'
    AND r.outcome IS NOT NULL AND r.assessment_id IS NULL AND u.username <> :assistant
  UNION ALL
  SELECT l.outcome FROM gold_labels l WHERE l.investigation_id = a.investigation_id
  LIMIT 1
) x ON true
WHERE a.status = 'proposed' AND a.created_at >= :start AND a.created_at < :end
"""


async def gaps(conn: AsyncConnection, start: datetime, end: datetime) -> list[str]:
    rows = (
        (
            await conn.execute(
                text("SELECT at FROM soak_samples WHERE at >= :s AND at < :e ORDER BY at"),
                {"s": start, "e": end},
            )
        )
        .scalars()
        .all()
    )
    marks = [start, *rows, end]
    return [
        f"{a:%m-%d %H:%M} to {b:%m-%d %H:%M} UTC"
        for a, b in itertools.pairwise(marks)
        if b - a > GAP
    ]


async def budgets(
    conn: AsyncConnection, config: LlmConfig, start: datetime, end: datetime
) -> list[str]:
    """Every minute and day of the window over a configured limit (at the gateway's margin),
    recomputed from the ledger's attempts."""
    rows = (
        await conn.execute(
            text(
                "SELECT provider, model, date_trunc('minute', at) AS minute, at::date AS day,"
                " input_tokens + output_tokens AS tokens FROM llm_calls"
                " WHERE attempt > 0 AND at >= :s AND at < :e"
            ),
            {"s": start, "e": end},
        )
    ).all()
    over = []
    for p in config.providers:
        for tier, model in p.models.items():
            for bucket in p.buckets(tier):
                mine = [
                    r
                    for r in rows
                    if r.provider == p.name and (bucket.name == p.name or r.model == model.name)
                ]
                lim = bucket.limits
                for unit, key, rq, tk in (
                    ("minute", "minute", lim.rpm, lim.tpm),
                    ("day", "day", lim.rpd, lim.tpd),
                ):
                    share = 1.0 if unit == "minute" else max(config.shares.values())
                    counts: dict[Any, list[int]] = defaultdict(lambda: [0, 0])
                    for r in mine:
                        c = counts[getattr(r, key)]
                        c[0] += 1
                        c[1] += r.tokens
                    for when, (n, tokens) in counts.items():
                        if rq and n > math.floor(rq * config.margin * share):
                            over.append(f"{bucket.name}: {n} requests in a {unit} ({when})")
                        if tk and tokens > math.floor(tk * config.margin * share):
                            over.append(f"{bucket.name}: {tokens} tokens in a {unit} ({when})")
    return sorted(set(over))


_HOURS = {
    "siem": "SELECT date_trunc('hour', at), count(*) FILTER (WHERE outcome = 'ok'),"
    " count(*) FILTER (WHERE outcome IN ('transport_failure', 'timed_out'))"
    " FROM siem_requests WHERE at >= :start AND at < :end GROUP BY 1 ORDER BY 1",
    "models": "SELECT date_trunc('hour', at), count(*) FILTER (WHERE outcome = 'ok'),"
    " count(*) FILTER (WHERE outcome LIKE 'no_answer%') FROM llm_calls"
    " WHERE attempt > 0 AND at >= :start AND at < :end GROUP BY 1 ORDER BY 1",
}


async def outages(conn: AsyncConnection, start: datetime, end: datetime) -> dict[str, list[str]]:
    """Per source, the spans of hours with failed connections and no answer at all."""
    out: dict[str, list[str]] = {}
    for source, query in _HOURS.items():
        spans: list[str] = []
        first: datetime | None = None
        last: datetime | None = None
        rows = (await conn.execute(text(query), {"start": start, "end": end})).all()
        for hour, ok, down in rows:
            if down and not ok:
                first = first or hour
                last = hour
            elif ok and first is not None and last is not None:
                spans.append(f"{first:%m-%d %H}:00 to {last + timedelta(hours=1):%m-%d %H}:00")
                first = None
        if first is not None and last is not None:
            spans.append(f"{first:%m-%d %H}:00 to {last + timedelta(hours=1):%m-%d %H}:00 (open)")
        out[source] = spans
    return out


async def report(
    conn: AsyncConnection, config: LlmConfig, start: datetime, end: datetime
) -> list[Line]:
    out: list[Line] = []
    span = {"start": start, "end": end}
    for source, spans in (await outages(conn, start, end)).items():
        out.append(
            Line(
                f"{source} reachable",
                "PASS" if not spans else "INFO",
                "no outage" if not spans else "unreachable " + "; ".join(spans) + " UTC",
            )
        )
    missing = await gaps(conn, start, end)
    out.append(
        Line(
            "services ran the whole window",
            "PASS" if not missing else "INFO",
            "no gap in the samples"
            if not missing
            else f"{len(missing)} gap(s): {'; '.join(missing[:8])}",
        )
    )

    blocked = await conn.scalar(
        text(
            "SELECT count(*) FROM llm_calls WHERE outcome = 'blocked' AND at >= :start"
            " AND at < :end"
        ),
        span,
    )
    calls = await conn.scalar(
        text("SELECT count(*) FROM llm_calls WHERE attempt > 0 AND at >= :start AND at < :end"),
        span,
    )
    out.append(
        Line(
            "1. no leak",
            "OPEN",
            f"{calls} model attempts; the validator refused {blocked} (each one a leak"
            " prevented). The independent sweep over the window's dossiers decides"
            " the criterion: scripts/privacy_sweep.py",
        )
    )

    labelled = (
        await conn.execute(text(LABELLED_PROPOSALS), {**span, "assistant": "argus-assistant"})
    ).all()
    wrong_benign = [r for r in labelled if r.outcome in BENIGN and r.label == "true_positive"]
    out.append(
        Line(
            "2. no true positive proposed benign (soak)",
            "PASS" if not wrong_benign else "FAIL",
            f"{len(labelled)} proposals a person's verdict can check;"
            f" {len(wrong_benign)} benign on a true positive",
        )
    )
    benign = [r for r in labelled if r.outcome in BENIGN]
    rate = Rate(sum(r.label in BENIGN for r in benign), len(benign))
    low = rate.interval[0] if rate.interval else None
    met = rate.value is not None and rate.value >= 0.95 and low is not None and low >= 0.90
    out.append(
        Line(
            "3. benign proposals precise (>= 95%, lower bound >= 90%)",
            "PASS" if met else "OPEN",
            f"checked against verdicts: {rate.text()}",
        )
    )

    over = await budgets(conn, config, start, end)
    cost = await conn.scalar(
        text(
            "SELECT coalesce(sum(cost_usd), 0) FROM llm_calls WHERE at >="
            " date_trunc('month', CAST(:end AS timestamptz)) AND at < :end"
        ),
        span,
    )
    out.append(
        Line(
            "4a. budgets never exceeded",
            "PASS" if not over else "FAIL",
            "no minute or day over a limit" if not over else "; ".join(over[:10]),
        )
    )
    out.append(
        Line(
            "4b. monthly cost within the cap",
            "PASS" if float(cost) <= config.monthly_cap_usd else "FAIL",
            f"${float(cost):.4f} of ${config.monthly_cap_usd:.2f}",
        )
    )
    deferred, gave_up = (
        await conn.execute(
            text(
                "SELECT coalesce(sum(deferrals), 0), count(*) FILTER (WHERE status = 'failed')"
                " FROM assessments WHERE created_at >= :start AND created_at < :end"
            ),
            span,
        )
    ).one()
    oldest = await conn.scalar(
        text("SELECT min(created_at) FROM assessments WHERE status IN ('queued', 'running')")
    )
    age = end - oldest if oldest is not None else None
    fresh = age is None or age <= BACKLOG
    out.append(
        Line(
            "4c. waiting loses nothing; the backlog clears within a day",
            "PASS" if fresh and not gave_up else "FAIL",
            f"{deferred} deferrals; {gave_up} assessments failed; the oldest waiting:"
            f" {'none' if age is None else str(age).split('.')[0]}",
        )
    )

    reports = await conn.scalar(
        text("SELECT count(*) FROM tuning_reports WHERE created_at < :end"), span
    )
    out.append(
        Line(
            "5. tuning report reviewed for the 3 noisiest rules",
            "OPEN" if reports else "FAIL",
            f"{reports} reports stored; the review is recorded in the exit report",
        )
    )
    out.append(
        Line(
            "6. a reviewer task test",
            "OPEN",
            "walked through by the lead (D-092); a person's own time needs the user",
        )
    )

    for assessor, status, n in (
        await conn.execute(
            text(
                "SELECT assessor, coalesce(outcome, status), count(*) FROM assessments"
                " WHERE created_at >= :start AND created_at < :end GROUP BY 1, 2 ORDER BY 1, 2"
            ),
            span,
        )
    ).all():
        out.append(Line(f"assessments: {assessor}", "INFO", f"{status}: {n}"))
    return out


def render(lines: Sequence[Line]) -> list[str]:
    return [f"[{line.verdict}] {line.criterion}: {line.detail}" for line in lines]
