"""An independent recomputation of every figure of a report (Q-H3's gate): plain ``SELECT``s of
the raw rows, and the arithmetic in Python with integers, ``timedelta`` and ``Fraction``. It
shares no SQL and no helper with ``argus.reporter.sections``; the constants (which states are
"confirmed", which finding kinds are "bypass") are written out again from the definitions the
report prints."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from fractions import Fraction
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.reporter.model import Window

HOUR = timedelta(hours=1)
CONFIRMED = {"open", "assigned", "contained"}
BYPASS = [
    "closed_in_kibana",
    "reopened_in_kibana",
    "status_changed_in_kibana",
    "deleted_in_kibana",
    "person_deleted",
    "argus_tags_changed",
]
UNEXPLAINED = ["unexplained_argus_action", "unexplained_argus_case", "alert_change_unexplained"]
REASONS = [
    "remediated_verified",
    "remediated_unverified",
    "risk_accepted",
    "attempt_no_impact",
    "rule_false_positive",
    "benign_expected",
    "benign_policy",
    "duplicate",
    "created_in_error",
    "stopped_after_notice",
]
LANES = [
    "collector",
    "investigation",
    "freshness",
    "kibana_read",
    "kibana_write",
    "identity",
    "measurement",
    "unassigned",
]
GAP_KINDS = [
    "rule_not_running",
    "rule_gap_reported",
    "source_stalled",
    "late_data_beyond_lookback",
    "truncated_execution",
    "argus_collector_lag",
    "breaker_open",
]


async def rows(engine: AsyncEngine, sql: str) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(sql))).all())


def tenths(part: int, whole: int) -> float | None:
    """A percentage to one decimal, halves up, by integer arithmetic."""
    if whole == 0:
        return None
    return ((2000 * part + whole) // (2 * whole)) / 10


def percentile(values: list[int | float], p: Fraction) -> int | None:
    if not values:
        return None
    ordered = sorted(Fraction(v) for v in values)
    pos = p * (len(ordered) - 1)
    low = math.floor(pos)
    value = ordered[low]
    if low + 1 < len(ordered):
        value += (pos - low) * (ordered[low + 1] - ordered[low])
    return math.floor(value)


def hours_since(then: datetime | None, now: datetime) -> int | None:
    return None if then is None else (now - then) // HOUR


def within(moment: datetime | None, w: Window) -> bool:
    return moment is not None and w.start <= moment < w.end


async def expected(engine: AsyncEngine, w: Window) -> dict[str, Any]:
    out: dict[str, Any] = {}
    now = w.as_at
    # ---- cases
    cases = await rows(engine, "SELECT id, state, created_at FROM cases")
    state_of = {c.id: c.state for c in cases}
    unclosed = [c for c in cases if c.state != "closed"]
    for state in ("suspected", "open", "assigned", "contained"):
        out[f"cases.{state}"] = sum(1 for c in cases if c.state == state)
    ages = [now - c.created_at for c in unclosed]
    day = timedelta(days=1)
    out["cases.age.under_1_day"] = sum(1 for a in ages if a < day)
    out["cases.age.1_to_3_days"] = sum(1 for a in ages if day <= a < 3 * day)
    out["cases.age.3_to_7_days"] = sum(1 for a in ages if 3 * day <= a < 7 * day)
    out["cases.age.7_days_or_more"] = sum(1 for a in ages if a >= 7 * day)
    out["cases.oldest_unclosed_age"] = max(ages) // HOUR if ages else None
    out["cases.created"] = sum(1 for c in cases if within(c.created_at, w))
    # ---- notified, still active (AR4b): the totals; the weekly list of devices has a test
    # of its own (a seeded world has no notified case)
    notified = await rows(
        engine, "SELECT id, state, notified_at, blocked_at, closure_reason, closed_at FROM cases"
    )
    live = {c.id for c in notified if c.state in ("open", "assigned") and c.notified_at}
    notices = await rows(engine, "SELECT case_id, kind, at FROM case_notices")
    matches = await rows(
        engine,
        "SELECT k.case_id, k.outcome, i.id AS inv FROM case_known_matches k"
        " JOIN investigations i ON i.id = k.investigation_id AND i.version = k.version",
    )
    reviewed = {
        r.investigation_id
        for r in await rows(
            engine, "SELECT investigation_id FROM review_state WHERE action = 'reviewed'"
        )
    }  # the seed has no notified case, so which version was reviewed cannot matter here
    reminders = await rows(engine, "SELECT case_id, kind, dismissed_at FROM case_reminders")
    out["notified.cases"] = len(live)
    held: dict[Any, set[Any]] = defaultdict(set)
    for m in await rows(
        engine, "SELECT case_id, investigation_id FROM case_members WHERE removed_at IS NULL"
    ):
        held[m.investigation_id].add(m.case_id)
    stamps = {
        a.alert_id: a.event_time or a.detected_at
        for a in await rows(engine, "SELECT alert_id, event_time, detected_at FROM alert_records")
    }
    told = {c.id: c.notified_at for c in notified if c.id in live}
    out["notified.alerts"] = sum(
        1
        for link in await rows(engine, "SELECT alert_id, investigation_id FROM investigation_alerts")  # noqa: E501
        for case_id in held.get(link.investigation_id, ())
        if case_id in told and stamps.get(link.alert_id) is not None
        and stamps[link.alert_id] >= told[case_id] and within(stamps[link.alert_id], w)
    )  # fmt: skip
    out["notified.known"] = sum(1 for k in matches if k.outcome == "known" and k.case_id in live)
    out["notified.changes_waiting"] = sum(
        1 for k in matches if k.outcome == "changed" and k.inv not in reviewed
    )
    out["notified.reminders_waiting"] = sum(
        1
        for r in reminders
        if r.dismissed_at is None and r.case_id in live
        and (
            (r.kind == "notify_again"
             and sum(1 for n in notices if n.case_id == r.case_id and n.kind == "owner") < 2)
            or (r.kind == "network_action"
                and next(c.blocked_at for c in notified if c.id == r.case_id) is None)
        )
    )  # fmt: skip
    out["notified.notices"] = sum(1 for n in notices if n.kind == "owner" and within(n.at, w))
    out["notified.blocks"] = sum(1 for n in notices if n.kind == "block" and within(n.at, w))
    out["notified.stopped"] = sum(
        1 for c in notified if c.closure_reason == "stopped_after_notice" and within(c.closed_at, w)
    )
    # ---- still-active hosts: the campus hosts the watch named on its 'active' days
    checks = await rows(engine, "SELECT case_id, day, outcome, detail FROM case_watch_checks")
    first, last = w.start.date(), w.end.date()
    active = [
        c
        for c in checks
        if c.outcome == "active" and first <= c.day < last and state_of[c.case_id] in CONFIRMED
    ]
    hosts: dict[str, set[Any]] = defaultdict(set)
    for c in active:
        named = c.detail.get("hosts") if isinstance(c.detail, dict) else None
        for host in named if isinstance(named, list) else []:
            if isinstance(host, str) and 0 < len(host) <= 200:
                hosts[host].add(c.day)
    out["active_hosts.cases"] = len({c.case_id for c in active})
    out["active_hosts.hosts"] = len(hosts)
    for value, days in hosts.items():
        out[f"active_hosts.host.{value}"] = len(days)
    # ---- actions
    actions = await rows(
        engine, "SELECT case_id, owner, state, recommended_at, requested_at FROM case_actions"
    )
    mine = [a for a in actions if state_of[a.case_id] in CONFIRMED]
    for state in ("recommended", "requested", "reported_done", "verified", "not_verified"):
        out[f"actions.state.{state}"] = sum(1 for a in mine if a.state == state)
    waiting = [a for a in mine if a.state in ("recommended", "requested")]
    out["actions.waiting"] = len(waiting)
    since = [a.recommended_at or a.requested_at for a in waiting]
    out["actions.oldest_waiting_age"] = (now - min(since)) // HOUR if since else None
    for owner, n in sorted(Counter(a.owner for a in waiting).items()):
        out[f"actions.waiting.owner.{owner}"] = n
    out["actions.recommended_in_period"] = sum(1 for a in actions if within(a.recommended_at, w))
    # ---- closures
    closed = [
        c
        for c in await rows(engine, "SELECT state, closed_at, closure_reason FROM cases")
        if c.state == "closed" and within(c.closed_at, w)
    ]
    out["closures.total"] = len(closed)
    for reason in REASONS:
        out[f"closures.reason.{reason}"] = sum(1 for c in closed if c.closure_reason == reason)
    events = await rows(engine, "SELECT kind, occurred_at FROM case_events")
    out["closures.reopened"] = sum(
        1 for e in events if e.kind == "reopened" and within(e.occurred_at, w)
    )
    # ---- approvals
    requests = await rows(
        engine,
        "SELECT id, kind, requested_at, expires_at, required_approvals, outbox_id,"
        " outbox_sent_count FROM approval_requests",
    )
    decisions = await rows(engine, "SELECT request_id, decision FROM approval_decisions")
    outbox = await rows(engine, "SELECT id, approval_request_id, sent_count FROM kibana_outbox")
    steps = await rows(engine, "SELECT approval_request_id, sent_count FROM kibana_steps")
    closers = {
        c.closure_request_id
        for c in await rows(engine, "SELECT closure_request_id FROM cases")
        if c.closure_request_id is not None
    }

    def verdict(r: Any) -> str:
        mine_ = [d.decision for d in decisions if d.request_id == r.id]
        if "rejected" in mine_:
            return "rejected"
        return "approved" if mine_.count("approved") >= r.required_approvals else "open"

    def went_out(r: Any) -> bool:
        """Whether something was sent for the request, by the table that records its kind's send."""
        row = next((o for o in outbox if o.id == r.outbox_id), None)
        if r.kind == "compensating":
            return any(s.approval_request_id == r.id and s.sent_count > 0 for s in steps)
        if r.kind == "resend":
            return row is not None and row.sent_count > r.outbox_sent_count
        if r.kind == "reconfirm":
            return row is not None and row.sent_count > 0
        return any(o.approval_request_id == r.id and o.sent_count > 0 for o in outbox)

    asked = [r for r in requests if within(r.requested_at, w)]
    approved = [r for r in asked if verdict(r) == "approved"]
    rejected = [r for r in asked if verdict(r) == "rejected"]
    out["approvals.requested"] = len(asked)
    out["approvals.approved"] = len(approved)
    out["approvals.rejected"] = len(rejected)
    out["approvals.approval_rate"] = tenths(len(approved), len(approved) + len(rejected))
    out["approvals.waiting"] = sum(
        1 for r in requests if verdict(r) == "open" and r.expires_at > now
    )
    out["approvals.expired_unsent"] = sum(
        1
        for r in requests
        if within(r.expires_at, w)
        and r.expires_at <= now
        and verdict(r) != "rejected"
        and not went_out(r)
        and r.id not in closers
    )
    for kind in ("closure", "merge", "compensating", "resend", "reconfirm"):
        out[f"approvals.requested.{kind}"] = sum(1 for r in asked if r.kind == kind)
    # ---- the SIEM load
    reqs = [
        r
        for r in await rows(engine, "SELECT at, lane, outcome, took_ms FROM siem_requests")
        if within(r.at, w)
    ]
    out["siem.requests"] = len(reqs)
    ms = sum(r.took_ms for r in reqs)
    out["siem.server_time"] = ms
    out["siem.budget_used"] = tenths(ms, 3_600_000 * (w.end - w.start).days) if ms else tenths(0, 1)
    per_day: Counter[Any] = Counter()
    for r in reqs:
        per_day[r.at.astimezone(UTC).date()] += r.took_ms
    out["siem.busiest_day"] = max(per_day.values()) if per_day else 0
    out["siem.overloads"] = sum(1 for r in reqs if r.outcome in ("overloaded", "breaker_open"))
    for lane in LANES:
        mine_ = [r for r in reqs if (r.lane or "unassigned") == lane]
        out[f"siem.lane.{lane}.requests"] = len(mine_)
        out[f"siem.lane.{lane}.server_time"] = sum(r.took_ms for r in mine_)
    # ---- Kibana sync
    cycles = [
        c
        for c in await rows(engine, "SELECT started_at, outcome, stale FROM kibana_sync_cycles")
        if within(c.started_at, w)
    ]
    out["kibana.cycles"] = len(cycles)
    for name in ("complete", "partial", "failed"):
        out[f"kibana.cycles.{name}"] = sum(1 for c in cycles if c.outcome == name)
    out["kibana.cycles.stale"] = sum(1 for c in cycles if c.stale)
    out["kibana.success_rate"] = tenths(out["kibana.cycles.complete"], len(cycles))
    findings = await rows(
        engine, "SELECT found_at, kind, severity, lag_s, resolved_at FROM kibana_findings"
    )
    lags = [f.lag_s for f in findings if within(f.found_at, w) and f.lag_s is not None]
    out["kibana.lag.n"] = len(lags)
    out["kibana.lag.median"] = percentile(lags, Fraction(1, 2))
    out["kibana.lag.p95"] = percentile(lags, Fraction(95, 100)) if len(lags) >= 20 else None
    out["kibana.lag.max"] = max(lags) if lags else None
    box = await rows(engine, "SELECT state, created_at, sent_at FROM kibana_outbox")
    out["kibana.paused"] = sum(1 for o in box if o.state == "paused")
    out["kibana.conflicts"] = sum(1 for o in box if o.state == "conflict")
    out["kibana.ambiguous"] = sum(1 for o in box if o.state == "ambiguous")
    backlog = [o for o in box if o.state in ("planned", "approved", "sending")]
    out["kibana.backlog"] = len(backlog)
    out["kibana.backlog.oldest"] = hours_since(
        min((o.created_at for o in backlog), default=None), now
    )
    out["kibana.sent"] = sum(1 for o in box if within(o.sent_at, w))
    resends = [r for r in asked if r.kind == "resend"]
    out["kibana.resends.asked"] = len(resends)
    out["kibana.resends.approved"] = sum(1 for r in resends if verdict(r) == "approved")
    # ---- guardrails
    audit = [
        a
        for a in await rows(engine, "SELECT occurred_at, action, outcome FROM audit_events")
        if within(a.occurred_at, w)
    ]
    out["guardrails.rejected_actions"] = sum(
        1 for a in audit if (a.action, a.outcome) == ("access", "denied")
    )
    out["guardrails.sign_in_refusals"] = sum(
        1 for a in audit if a.action in ("login", "stepup") and a.outcome == "denied"
    )
    ledger = [
        x
        for x in await rows(engine, "SELECT at, write_class, outcome FROM action_ledger")
        if within(x.at, w)
    ]
    out["guardrails.refused_writes"] = sum(1 for x in ledger if x.outcome == "refused")
    mine_f = [f for f in findings if within(f.found_at, w)]
    out["guardrails.bypass_attempts"] = sum(1 for f in mine_f if f.kind in BYPASS)
    for kind in BYPASS:
        out[f"guardrails.bypass.{kind}"] = sum(1 for f in mine_f if f.kind == kind)
    out["guardrails.unexplained"] = sum(1 for f in mine_f if f.kind in UNEXPLAINED)
    out["guardrails.findings_open.alarm"] = sum(
        1 for f in findings if f.resolved_at is None and f.severity == "alarm"
    )
    out["guardrails.findings_open.attention"] = sum(
        1 for f in findings if f.resolved_at is None and f.severity == "attention"
    )
    # ---- results
    got = await rows(
        engine,
        "SELECT a.status, a.created_at, a.finished_at, i.created_at AS started"
        " FROM assessments a JOIN investigations i ON i.id = a.investigation_id",
    )
    proposed = [
        max((a.finished_at - a.started).total_seconds(), 0)
        for a in got
        if a.status == "proposed" and within(a.finished_at, w)
    ]
    out["results.n"] = len(proposed)
    out["results.median"] = percentile(proposed, Fraction(1, 2))
    out["results.p95"] = percentile(proposed, Fraction(95, 100)) if len(proposed) >= 20 else None
    out["results.max"] = math.floor(max(proposed)) if proposed else None
    out["results.no_decision"] = sum(
        1 for a in got if a.status == "no_decision" and within(a.finished_at, w)
    )
    out["results.failed"] = sum(1 for a in got if a.status == "failed" and within(a.finished_at, w))
    queued = [a for a in got if a.status in ("queued", "running")]
    out["results.waiting"] = len(queued)
    out["results.waiting.oldest"] = hours_since(
        min((a.created_at for a in queued), default=None), now
    )
    # ---- write-back
    wb = await rows(engine, "SELECT state, created_at, sent_at, error FROM writeback_outbox")
    out["writeback.planned"] = sum(1 for x in wb if within(x.created_at, w))
    out["writeback.sent"] = sum(1 for x in wb if within(x.sent_at, w))
    out["writeback.waiting"] = sum(1 for x in wb if x.state == "planned")
    out["writeback.paused"] = sum(1 for x in wb if x.state == "paused")
    out["writeback.errors"] = sum(1 for x in wb if within(x.created_at, w) and x.error is not None)
    for outcome in ("sent", "ambiguous", "conflict", "refused", "failed"):
        out[f"writes.ledger.{outcome}"] = sum(1 for x in ledger if x.outcome == outcome)
    for cls in ("W1", "W2", "W3"):
        out[f"writes.sent.{cls}"] = sum(
            1 for x in ledger if x.outcome == "sent" and x.write_class == cls
        )
    wr = [
        r
        for r in await rows(
            engine,
            "SELECT started_at, sent, verified, mismatches, ambiguous FROM kibana_writer_runs",
        )
        if within(r.started_at, w)
    ]
    out["writes.runs"] = len(wr)
    out["writes.runs.sent"] = sum(r.sent for r in wr)
    out["writes.runs.verified"] = sum(r.verified for r in wr)
    out["writes.runs.mismatches"] = sum(r.mismatches for r in wr)
    out["writes.runs.ambiguous"] = sum(r.ambiguous for r in wr)
    out["writes.read_back_rate"] = tenths(out["writes.runs.verified"], out["writes.runs.sent"])
    # ---- gaps and outages
    gaps = await rows(engine, "SELECT kind, start_at, end_at FROM coverage_gaps")
    touching = [g for g in gaps if g.start_at < w.end and (g.end_at or now) > w.start]
    out["gaps.overlapping"] = len(touching)
    out["gaps.opened"] = sum(1 for g in gaps if within(g.start_at, w))
    out["gaps.closed"] = sum(1 for g in gaps if within(g.end_at, w))
    out["gaps.open_now"] = sum(1 for g in gaps if g.end_at is None)
    inside = sum(
        (min(g.end_at or now, w.end) - max(g.start_at, w.start) for g in touching), timedelta(0)
    )
    out["gaps.minutes"] = inside // timedelta(minutes=1)
    for kind in GAP_KINDS:
        out[f"gaps.kind.{kind}"] = sum(1 for g in touching if g.kind == kind)
    probes = [p for p in await rows(engine, "SELECT at, state FROM siem_probes") if within(p.at, w)]
    for state in ("normal", "caution", "degraded", "stop"):
        out[f"outages.probes.{state}"] = sum(1 for p in probes if p.state == state)
    # ---- threat intelligence
    sources = await rows(
        engine, "SELECT source, newest, checked_at, indicators, error FROM ti_sources"
    )
    out["intel.sources"] = len(sources)
    for s in sources:
        key = s.source.replace(" ", "_")
        out[f"intel.{key}.newest_age"] = hours_since(min(s.newest, now) if s.newest else None, now)
        out[f"intel.{key}.checked_age"] = hours_since(
            min(s.checked_at, now) if s.checked_at else None, now
        )
        out[f"intel.{key}.indicators"] = s.indicators
        out[f"intel.{key}.failed"] = 1 if s.error is not None else 0
    # ---- the audit chain
    heads = {
        h.chain: h for h in await rows(engine, "SELECT chain, seq, head_hash FROM chain_heads")
    }
    out["audit.events"] = len(audit)
    for name in ("audit_events", "case_events"):
        out[f"audit.{name}.rows"] = heads[name].seq if name in heads else None
        out[f"audit.{name}.head"] = heads[name].head_hash if name in heads else None
    return out
