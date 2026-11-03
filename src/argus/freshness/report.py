"""The shadow's numbers: what the readings show per source, how many 72-hour
windows they would prove with and without the candidate bridge, the verdicts the log zeros
got, and the would-be proposals (``assess``). For the operator's audit only: no page
or API shows them."""

from __future__ import annotations

import uuid
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus import site
from argus.evaluation.harness import BENIGN
from argus.freshness import store
from argus.freshness.margin import Spread
from argus.freshness.model import Reading, windows
from argus.freshness.shadow import LOG_ZERO, Policy

POSITIVE = "true_positive"


def nights(
    readings: Sequence[Reading], margin: timedelta | None, gap: timedelta
) -> tuple[int, int]:
    """(nights judged, nights the ``edges`` bridge crosses): for each pause 00:00-01:30 UTC
    inside the readings, whether a reading within the margin came at most ``gap`` before it
    and another at most ``gap`` after it."""
    if margin is None or not readings or site.quiet_hours().none:
        return 0, 0
    ordered = sorted(readings, key=lambda r: r.at)
    first, last = ordered[0].at, ordered[-1].at
    day = first.astimezone(UTC).date()
    judged = crossed = 0
    while True:
        quiet = site.quiet_hours()
        begin = datetime.combine(day, quiet.start_time, UTC)
        stop = begin + quiet.length
        day += timedelta(days=1)
        if begin - gap < first:
            continue
        if stop + gap > last:
            break
        judged += 1
        before = any(r.within(margin) and begin - gap <= r.at < begin for r in ordered)
        after = any(r.within(margin) and stop <= r.at <= stop + gap for r in ordered)
        crossed += before and after
    return judged, crossed


def source_report(source: str, readings: Sequence[Reading], policy: Policy) -> dict[str, Any]:
    margin = policy.margins.get(source)
    outcomes = Counter(r.outcome for r in readings)
    lag_values = [r.lag.total_seconds() for r in readings if r.lag is not None]
    win = windows(readings, margin, gap=policy.gap)
    judged, crossed = nights(readings, margin, policy.gap)
    within = sum(r.within(margin) for r in readings) if margin is not None else None
    return {
        "source": source,
        "readings": len(readings),
        "outcomes": dict(sorted(outcomes.items())),
        "lag": None if not lag_values else Spread.of([max(v, 0.0) for v in lag_values]).as_dict(),
        "margin_s": None if margin is None else int(margin.total_seconds()),
        "within_margin": within,
        "windows_72h": {
            "judged": win.judged,
            "pass_strict": win.strict,
            "pass_bridged": win.bridged,
            "share_strict": win.share(False),
            "share_bridged": win.share(True),
        },
        "nights": {"judged": judged, "bridged": crossed},
    }


def verdict_counts(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    rows = list(rows)
    return {
        "signals": len(rows),
        "known_zero": sum(r["verdict"] == "known_zero" for r in rows),
        "known_zero_bridged": sum(r["bridged_verdict"] == "known_zero" for r in rows),
        "reasons": dict(sorted(Counter(str(r["reason"]) for r in rows).items())),
    }


async def build(
    conn: AsyncConnection, policy: Policy, since: datetime, until: datetime
) -> dict[str, Any]:
    by_source = await store.all_readings(conn, since, until)
    shadow = await store.shadow_rows(conn, since)
    proposals = await store.proposals(conn)
    return {
        "since": since.isoformat(),
        "until": until.isoformat(),
        "mode": policy.mode,
        "bridge": policy.bridge,
        "gap_s": int(policy.gap.total_seconds()),
        "sources": [source_report(s, r, policy) for s, r in sorted(by_source.items())],
        "verdicts": verdict_counts(shadow),
        "proposals": {
            "evaluated": len(proposals),
            "benign": sum(p["outcome"] in BENIGN for p in proposals if not p["bridged"]),
            "benign_bridged": sum(p["outcome"] in BENIGN for p in proposals if p["bridged"]),
            "new_benign": sum(
                p["outcome"] in BENIGN and p["actual"] not in BENIGN for p in proposals
            ),
        },
    }


# ----------------------------------------------------------------------------- assessing


def with_zeros(body: Mapping[str, Any], names: Iterable[str]) -> dict[str, Any]:
    """The dossier body as an assessor would read it with the verified zeros known: each
    named signal that a pack left "could not tell" for an unverified log zero becomes 0."""
    wanted = set(names)
    signals = []
    for s in body.get("signals") or []:
        if (
            isinstance(s, Mapping)
            and s.get("name") in wanted
            and s.get("status") == "unknown"
            and s.get("unknown_reason") == LOG_ZERO
        ):
            s = {**s, "value": 0, "status": "known", "unknown_reason": None,
                 "completeness": "exact"}  # fmt: skip
        signals.append(s)
    return {**body, "signals": signals}


_CANDIDATES = """
SELECT d.investigation_id, d.version, d.pack, d.dossier_hash, d.body,
       array_agg(f.signal ORDER BY f.signal) AS names
FROM freshness_shadow f
JOIN LATERAL (SELECT x.investigation_id, x.version, x.pack, x.dossier_hash, x.body
              FROM dossiers x WHERE x.investigation_id = f.investigation_id
              AND x.version = f.version AND x.pack = f.pack
              ORDER BY x.created_at DESC LIMIT 1) d ON true
WHERE (CASE WHEN :bridged THEN f.bridged_verdict ELSE f.verdict END) = 'known_zero'
GROUP BY d.investigation_id, d.version, d.pack, d.dossier_hash, d.body
ORDER BY d.investigation_id, d.version, d.pack
"""
_GOLD = """
SELECT DISTINCT ON (l.investigation_id) l.investigation_id, l.outcome
FROM gold_labels l ORDER BY l.investigation_id, l.id DESC
"""


async def assess(conn: AsyncConnection, now: datetime, *, bridged: bool) -> dict[str, Any]:
    """Run the deterministic engine on every dossier with a would-be verified zero, with and
    without those zeros; store each pair (``freshness_proposals``); count the would-be benign
    proposals and, on the gold set, the true positives among them (must be 0)."""
    from argus.assess.engine import NAME, Engine, learn

    assessor = Engine(await learn(conn), now)
    gold = {row.investigation_id: row.outcome for row in await conn.execute(text(_GOLD))}
    out = {"evaluated": 0, "benign": 0, "new_benign": 0, "gold_items": 0, "gold_tp_benign": 0}
    tp_benign: list[str] = []
    for row in await conn.execute(text(_CANDIDATES), {"bridged": bridged}):
        inv: uuid.UUID = row.investigation_id
        before = await assessor.assess(conn, inv, row.body)
        after = await assessor.assess(conn, inv, with_zeros(row.body, row.names))
        await store.write_proposal(
            conn,
            {
                "inv": inv, "v": row.version, "pack": row.pack, "hash": row.dossier_hash,
                "assessor": NAME, "bridged": bridged, "outcome": after.outcome,
                "actual": before.outcome, "signals": list(row.names),
                "reasons": [str(r) for r in after.reasons],
            },
        )  # fmt: skip
        out["evaluated"] += 1
        benign = after.outcome in BENIGN
        out["benign"] += benign
        out["new_benign"] += benign and before.outcome not in BENIGN
        if inv in gold:
            out["gold_items"] += 1
            if benign and gold[inv] == POSITIVE:
                out["gold_tp_benign"] += 1
                tp_benign.append(str(inv))
    return {**out, "gold_tp_benign_ids": tp_benign}


# ----------------------------------------------------------------------------- the audit

AUDIT_N = 37  # a lower bound of at least 90 % needs at least 37 items
AUDIT_BAR = 0.90
SHEET = ("investigation_id", "version", "pack", "would_propose", "proposed", "signals",
         "correct", "true_positive")  # fmt: skip
YES, NO = "yes", "no"


def sheet(proposals: Iterable[Mapping[str, Any]], *, bridged: bool) -> list[dict[str, str]]:
    """The audit sheet: every proposal the shadow's zeros would turn benign that the
    engine did not already propose benign on its own (with or without the bridge's zeros),
    with ``correct`` and ``true_positive`` left for the reviewer to answer yes or no. Rows the
    engine already proposed benign without a zero are not the shadow's work and would only
    pad the audit."""
    out = []
    for p in proposals:
        if bool(p["bridged"]) != bridged or p["outcome"] not in BENIGN or p["actual"] in BENIGN:
            continue
        out.append(
            {
                "investigation_id": str(p["investigation_id"]),
                "version": str(p["version"]),
                "pack": str(p["pack"]),
                "would_propose": str(p["outcome"]),
                "proposed": "" if p["actual"] is None else str(p["actual"]),
                "signals": " ".join(str(s) for s in p["signals"]),
                "correct": "",
                "true_positive": "",
            }
        )
    return out


def score(rows: Sequence[Mapping[str, str]]) -> dict[str, Any]:
    """The audit against the switch-on's bar: every item answered, no
    true positive among the would-be benign proposals, and a Wilson lower bound (95 %) of at
    least 90 % of them correct at n >= 37."""
    from argus.evaluation.harness import Rate

    answered = [r for r in rows if r.get("correct", "").strip().lower() in (YES, NO)]
    correct = sum(r["correct"].strip().lower() == YES for r in answered)
    positives = sum(r.get("true_positive", "").strip().lower() == YES for r in rows)
    rate = Rate(correct, len(answered))
    lower = rate.interval[0] if rate.interval else None
    unanswered = len(rows) - len(answered)
    passes = (
        unanswered == 0
        and positives == 0
        and len(answered) >= AUDIT_N
        and lower is not None
        and lower >= AUDIT_BAR
    )
    return {
        "items": len(rows),
        "answered": len(answered),
        "unanswered": unanswered,
        "correct": correct,
        "true_positives": positives,
        "lower_bound": lower,
        "bar": {"n": AUDIT_N, "lower_bound": AUDIT_BAR, "true_positives": 0},
        "passes": passes,
    }
