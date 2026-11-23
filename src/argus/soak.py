"""The soak: hourly samples of how ARGUS is doing, and the exit report. A sample reads only the
local store (no SIEM request): alerts and investigations, the job queue, dossier coverage, open
gaps, the server time spent on the SIEM today, overload responses and the last reconciliation. The
report judges the exit criteria ARGUS can judge from the samples over the soak (72 h) and names
the ones that need a person."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncConnection

SOAK = timedelta(hours=72)
LABELS = 30  # reviewer labels per rule, or all of its investigations if it has fewer
ASSISTANT = "argus-assistant"  # the assistant's account: its labels count, attributed
DAY_CAP_MS = 3_600_000  # 60 min of the SIEM server time a day

_SAMPLE = """
SELECT
  (SELECT count(*) FROM alert_records) AS alerts,
  (SELECT count(*) FROM alert_records WHERE first_seen_at > now() - interval '1 hour')
    AS alerts_last_hour,
  (SELECT count(*) FROM investigations) AS investigations,
  (SELECT count(*) FROM jobs WHERE status = 'queued' AND run_after <= now()) AS jobs_due,
  (SELECT count(*) FROM jobs WHERE status = 'queued') AS jobs_queued,
  (SELECT count(*) FROM jobs WHERE status = 'running') AS jobs_running,
  (SELECT count(*) FROM jobs WHERE status = 'failed') AS jobs_failed,
  (SELECT count(*) FROM jobs WHERE status = 'queued' AND deferred_since IS NOT NULL)
    AS jobs_deferred,
  (SELECT count(*) FROM investigations i WHERE EXISTS (SELECT 1 FROM dossiers d
     WHERE d.investigation_id = i.id AND d.version = i.version)) AS with_dossier,
  (SELECT count(*) FROM coverage_gaps WHERE end_at IS NULL) AS open_gaps,
  (SELECT coalesce(sum(took_ms), 0) FROM siem_requests WHERE at >= date_trunc('day', now()))
    AS took_today_ms,
  (SELECT count(*) FROM siem_requests WHERE at >= date_trunc('day', now())) AS requests_today,
  (SELECT count(*) FROM siem_requests WHERE at > now() - interval '1 hour'
     AND outcome IN ('overloaded', 'breaker_open')) AS overloads_last_hour,
  (SELECT max(at) FROM collector_cursors WHERE name = 'live') AS live_cursor,
  (SELECT hours_mismatched FROM reconciliation_runs ORDER BY id DESC LIMIT 1)
    AS last_reconcile_mismatched,
  (SELECT state ->> 'state' FROM siem_state WHERE name = 'health') AS siem,
  -- Phase 2 (D-092): the assessments' queue, the model gateway
  (SELECT count(*) FROM assessments WHERE status IN ('queued', 'running')) AS assess_waiting,
  (SELECT extract(epoch FROM now() - min(created_at))::int FROM assessments
     WHERE status IN ('queued', 'running')) AS assess_oldest_s,
  (SELECT count(*) FROM assessments WHERE status = 'proposed') AS assess_proposed,
  (SELECT count(*) FROM assessments WHERE status = 'failed') AS assess_failed,
  (SELECT count(*) FROM llm_calls WHERE at > now() - interval '1 hour' AND attempt > 0)
    AS llm_calls_last_hour,
  (SELECT count(*) FROM llm_calls WHERE at > now() - interval '1 hour' AND outcome = 'blocked')
    AS llm_blocked_last_hour,
  (SELECT coalesce(sum(cost_usd), 0) FROM llm_calls WHERE at >= date_trunc('month', now()))
    AS llm_month_usd,
  (SELECT (state ->> 'stopped')::boolean FROM llm_state WHERE name = 'gateway') AS llm_stopped
"""


async def sample(conn: AsyncConnection, now: datetime) -> dict[str, Any]:
    row = (await conn.execute(text(_SAMPLE))).one()
    metrics = {
        k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in row._mapping.items()
    }
    await conn.execute(
        text(
            "INSERT INTO soak_samples (at, metrics) VALUES (:at, :m) ON CONFLICT DO NOTHING"
        ).bindparams(bindparam("m", type_=JSONB)),
        {"at": now, "m": metrics},
    )
    return metrics


def judge(
    samples: Sequence[tuple[datetime, dict[str, Any]]], now: datetime
) -> list[dict[str, str]]:
    """The exit criteria, each PASS, FAIL or PENDING with a reason."""
    out: list[dict[str, str]] = []
    if not samples:
        return [{"criterion": "soak", "result": "PENDING", "why": "no samples yet"}]
    start, end = samples[0][0], samples[-1][0]
    span = end - start
    out.append(
        {
            "criterion": "72 h soak",
            "result": "PASS" if span >= SOAK - timedelta(hours=1) else "PENDING",
            "why": f"{span.total_seconds() / 3600:.1f} h of samples since"
            f" {start:%Y-%m-%d %H:%M} UTC",
        }
    )
    mismatched = [m.get("last_reconcile_mismatched") or 0 for _, m in samples]
    out.append(
        {
            "criterion": "0 lost / duplicated alerts (reconciliation per hour and rule)",
            "result": "PASS" if max(mismatched) == 0 else "FAIL",
            "why": f"the worst reconciliation in the soak found {max(mismatched)} hours that"
            " differed",
        }
    )
    days: dict[str, int] = {}
    for at, m in samples:
        day = at.date().isoformat()
        days[day] = max(days.get(day, 0), int(m.get("took_today_ms") or 0))
    worst = max(days.values()) if days else 0
    out.append(
        {
            "criterion": "SIEM budget held (≤ 60 min server time a day)",
            "result": "PASS" if worst <= DAY_CAP_MS else "FAIL",
            "why": f"the busiest day used {worst / 60_000:.1f} min",
        }
    )
    overloads = sum(int(m.get("overloads_last_hour") or 0) for _, m in samples)
    out.append(
        {
            "criterion": "no overload responses attributable to ARGUS",
            "result": "PASS" if overloads == 0 else "FAIL",
            "why": f"{overloads} overload or breaker responses in the soak",
        }
    )
    zero_days = {at.date() for at, m in samples if int(m.get("jobs_due") or 0) == 0}
    all_days = {at.date() for at, _ in samples}
    out.append(
        {
            "criterion": "the queue returns to 0 daily",
            "result": "PASS" if zero_days == all_days else "FAIL",
            "why": f"due jobs reached 0 on {len(zero_days)} of {len(all_days)} days",
        }
    )
    last = samples[-1][1]
    covered = int(last.get("with_dossier") or 0)
    total = int(last.get("investigations") or 0)
    out.append(
        {
            "criterion": "every investigation has a dossier",
            "result": "PASS"
            if total and covered >= total - int(last.get("jobs_queued") or 0)
            else "FAIL",
            "why": f"{covered} of {total} at their current version"
            f" ({last.get('jobs_queued')} queued)",
        }
    )
    failed = int(last.get("jobs_failed") or 0)
    out.append(
        {
            "criterion": "no job given up",
            "result": "PASS" if failed == 0 else "FAIL",
            "why": f"{failed} failed jobs",
        }
    )
    for name, why in (
        (
            "detection-rule durations within +10% of the pre-ARGUS baseline",
            "needs Kibana's rule execution data (no Kibana read yet)",
        ),
        ("review task test with a real reviewer", "needs a reviewer and 15 minutes"),
    ):
        out.append({"criterion": name, "result": "PENDING", "why": why})
    out.append(
        {
            "criterion": "write-back, not an exit criterion",
            "result": "INFO",
            "why": "built and off; switched on with the user present (D-061)",
        }
    )
    return out


TOKEN_CHARS = 4  # characters per token, for the digest's size


async def measurements(conn: AsyncConnection) -> list[dict[str, str]]:
    """Measurements for the exit criteria, from the newest dossier of every investigation: how
    often every signal is known, decision patterns per day (a model is asked once per undecided
    pattern), the digest's size."""
    rows = (
        await conn.execute(
            text(
                "SELECT DISTINCT ON (d.investigation_id) i.rule_id, i.group_key,"
                " coalesce(i.rule_name, i.rule_id) AS rule, i.bucket_start, d.body"
                " FROM dossiers d JOIN investigations i ON i.id = d.investigation_id"
                " AND d.version = i.version"
                " ORDER BY d.investigation_id, d.created_at DESC"
            )
        )
    ).all()
    return measure(rows)


def measure(rows: Sequence[Any]) -> list[dict[str, str]]:
    """``measurements`` over rows of (rule_id, group_key, rule, bucket_start, body)."""
    from argus.context.display import digest, signature
    from argus.web.queries import key_fields

    if not rows:
        return [{"criterion": "Phase 2 measurements", "result": "INFO", "why": "no dossiers yet"}]
    known: dict[str, list[int]] = {}
    days: dict[str, set[Any]] = {}
    investigations: dict[str, int] = {}
    tokens = []
    for r in rows:
        body = r.body
        signals = [*body.get("local_signals", []), *body.get("signals", [])]
        all_known = all(sig.get("status") == "known" for sig in signals)
        share = known.setdefault(r.rule, [0, 0])
        share[0] += all_known
        share[1] += 1
        keys = [f for f, _ in key_fields(r.group_key)]
        day = r.bucket_start.date().isoformat()
        days.setdefault(day, set()).add(signature(r.rule_id, keys, body)[0])  # as Patterns does
        investigations[day] = investigations.get(day, 0) + 1
        tokens.append(len(digest(body)) // TOKEN_CHARS)
    tokens.sort()
    p95 = tokens[min(len(tokens) - 1, int(len(tokens) * 0.95))]
    per_day = [len(v) for v in days.values()]
    signatures = max(per_day)
    busiest = max(investigations.values())
    lowest = sorted(known.items(), key=lambda kv: kv[1][0] / kv[1][1])[:3]
    return [
        {
            "criterion": "share of investigations with every signal known (lowest rules)",
            "result": "INFO",
            "why": ", ".join(f"{rule} {a / n:.0%}" for rule, (a, n) in lowest),
        },
        {
            "criterion": "decision patterns per day vs investigations per day",
            "result": "INFO",
            "why": f"at most {signatures} patterns on a day with up to {busiest} investigations"
            f" ({len(days)} days)",
        },
        {
            "criterion": "digest size and projected Phase 2 model use",
            "result": "INFO",
            "why": f"digest p95 {p95} tokens; at most {signatures} model requests and"
            f" {signatures * p95:,} input tokens a day (one per undecided pattern)",
        },
    ]


async def labels(conn: AsyncConnection) -> dict[str, str]:
    """Every rule has ``LABELS`` investigations decided with an outcome, or all of them if it has
    fewer; how many by people and how many by the assistant."""
    rows = (
        await conn.execute(
            text(
                "SELECT coalesce(i.rule_name, i.rule_id) AS rule, count(*) AS investigations,"
                " count(*) FILTER (WHERE EXISTS (SELECT 1 FROM review_events r"
                "  WHERE r.investigation_id = i.id"
                "  AND r.action = 'reviewed' AND r.outcome IS NOT NULL)) AS labelled,"
                " count(*) FILTER (WHERE EXISTS (SELECT 1 FROM review_events r"
                "  JOIN users u ON u.id = r.user_id WHERE r.investigation_id = i.id"
                "  AND r.action = 'reviewed' AND r.outcome IS NOT NULL"
                "  AND u.username <> :assistant)) AS by_people"
                " FROM investigations i GROUP BY coalesce(i.rule_name, i.rule_id) ORDER BY 1"
                # a rule is its name: one recreated in Kibana keeps it but gets a new id
            ),
            {"assistant": ASSISTANT},
        )
    ).all()
    return judge_labels(rows)


def judge_labels(rows: Sequence[Any]) -> dict[str, str]:
    """``labels`` over rows of (rule, investigations, labelled, by_people)."""
    short = sorted(
        ((r.labelled, min(LABELS, r.investigations), r.rule) for r in rows
         if r.labelled < min(LABELS, r.investigations)),
        key=lambda t: (t[0] - t[1], t[2]),
    )  # fmt: skip
    criterion = f"≥ {LABELS} reviewer labels per rule (or all of a rule's investigations)"
    people = sum(r.by_people for r in rows)
    split = f"{people} by people, {sum(r.labelled for r in rows) - people} by the assistant (D-071)"
    if not rows:
        return {"criterion": criterion, "result": "PENDING", "why": "no investigations yet"}
    if not short:
        return {"criterion": criterion, "result": "PASS",
                "why": f"all {len(rows)} rules have their labels; {split}"}  # fmt: skip
    worst = ", ".join(f"{rule} {have}/{need}" for have, need, rule in short[:3])
    return {
        "criterion": criterion,
        "result": "PENDING",
        "why": f"{len(rows) - len(short)} of {len(rows)} rules done; furthest behind: {worst};"
        f" {split}",
    }


async def report(conn: AsyncConnection, now: datetime | None = None) -> list[dict[str, str]]:
    now = now or datetime.now(UTC)
    rows = await conn.execute(
        text("SELECT at, metrics FROM soak_samples WHERE at > :since ORDER BY at"),
        {"since": now - SOAK - timedelta(hours=1)},
    )
    found = judge([(r.at, r.metrics) for r in rows], now)
    if found[0]["criterion"] == "soak":
        return found
    return [*found, await labels(conn), *await measurements(conn)]
