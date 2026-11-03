"""What the soak gate reads: each line's facts, from ARGUS's own database and the local files the
gate names, never from the SIEM. Every function takes a connection that ``run`` opened read-only as
the runtime login and asks for the window's rows, aggregated where it can; ``run`` reports a table
it cannot read rather than widening a grant. Account names are never selected."""

from __future__ import annotations

import itertools
import json
import re
from collections import defaultdict
from datetime import UTC, datetime, time, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.config.settings import Settings
from argus.gateway.kibana.templates import KREGISTRY
from argus.gateway.lanes import Lane, lane_of
from argus.gateway.service import lane_plan
from argus.gateway.templates import REGISTRY, CostClass, Purpose
from argus.measure.session import cost_of  # imports every template module (the registry)
from argus.ops import backup
from argus.signins import model as signin_model
from argus.soakgate.model import (
    AnalysisFacts,
    BackupFacts,
    CautionMove,
    ClosureFacts,
    Confirmed,
    DaySpend,
    HealthFacts,
    LaneLimit,
    LedgerWrite,
    LifecycleFacts,
    LoadFacts,
    Lookup,
    MinuteSpend,
    NotifiedFacts,
    OpenedCase,
    ReconcileFacts,
    SigninFacts,
    SweepFacts,
    Window,
    WriteFacts,
)

ASSISTANT = "argus-assistant"  # the assistant's account: its confirms are labels, not a person's
IN_DOUBT = ("ambiguous", "resend", "failed", "sending", "sent")
PROBE_REACH = timedelta(minutes=5)  # a probe this recent describes a write's moment
FIRST_SEQUENCE_DONE = ("verified", "skipped", "superseded")
# a person's changes to an ARGUS case in Kibana (the findings that carry a lag)
PERSON_CHANGES = (
    "person_edited",
    "person_deleted",
    "closed_in_kibana",
    "reopened_in_kibana",
    "status_changed_in_kibana",
    "deleted_in_kibana",
    "argus_tags_changed",
    "settings_changed",
)
ADDITIVE_STEP_KINDS = ("open", "attach", "tag", "comment", "file")
CLOSE_TEMPLATES = frozenset(
    name for name in KREGISTRY if name.rsplit(".", 1)[-1] in ("close", "closed")
)
NOTIFIED_PASS = timedelta(minutes=15)  # "one pass": the assessment loop's period with margin
SAMPLE_GAP = timedelta(minutes=45)  # soak samples are 15 minutes apart (argus.soak2.GAP)
SAMPLE_STALE = timedelta(minutes=45)
# about 3 requests a day for finished days and at most about 24 for the current day's refresh
# (once an hour); the backfill is about 14 requests once
SIGNIN_STEADY_PER_DAY = 27
SIGNIN_BACKFILL_EXTRA = 14
SIGNIN_TEMPLATE = "signins.day"
SIGNIN_GRACE = timedelta(hours=3)  # a pass may not have run since an incomplete lookup came due
# the nightly dump and the weekly drill timers (deploy/systemd; a test keeps these equal)
DUMP_AT = time(21, 30)
DRILL_AT = time(22, 0)
DRILL_WEEKDAY = 6  # Sunday
BACKUP_GRACE = timedelta(hours=3)
DRILL_GRACE = timedelta(hours=6)


def _span(w: Window) -> dict[str, datetime]:
    return {"s": w.since, "e": w.until}


async def _scalar(conn: AsyncConnection, query: str, **params: Any) -> Any:
    return (await conn.execute(text(query), params)).scalar_one()


def _label(number: Any) -> str:
    return f"case {number}"


async def lifecycle(conn: AsyncConnection, w: Window, now: datetime) -> LifecycleFacts:
    span = _span(w)
    posts = await _scalar(
        conn,
        "SELECT count(*) FROM case_team_posts WHERE created_at >= :s AND created_at < :e",
        **span,
    )
    by_state = {
        r.state: int(r.n)
        for r in await conn.execute(
            text(
                "SELECT state, count(*) AS n FROM case_team_steps"
                " WHERE created_at >= :s AND created_at < :e GROUP BY state"
            ),
            span,
        )
    }
    in_doubt = [
        f"{_label(r.number)} step {r.id} {r.key} {r.state}"
        for r in await conn.execute(
            text(
                "SELECT c.number, s.id, s.key, s.state FROM case_team_steps s"
                " JOIN cases c ON c.id = s.case_id WHERE s.state = ANY(:states)"
                " AND coalesce(s.sent_at, s.created_at) < :limit ORDER BY s.id"
            ),
            {"states": list(IN_DOUBT), "limit": now - timedelta(hours=1)},
        )
    ]
    creates = (
        await conn.execute(
            text(
                "SELECT c.number, s.sent_count FROM case_team_steps s JOIN cases c ON c.id ="
                " s.case_id WHERE s.kind = 'open' AND s.sent_count > 0"
                " AND s.created_at >= :s AND s.created_at < :e ORDER BY s.id"
            ),
            span,
        )
    ).all()
    kibana_cases = await _scalar(
        conn,
        "SELECT count(*) FROM case_team_posts WHERE kibana_case_id IS NOT NULL"
        " AND created_at >= :s AND created_at < :e",
        **span,
    )
    duplicates = [
        f"{_label(r.number)} ({r.k} Kibana cases)"
        for r in await conn.execute(
            text(
                "SELECT c.number, count(DISTINCT s.kibana_ids ->> 'case') AS k"
                " FROM case_team_steps s JOIN cases c ON c.id = s.case_id"
                " WHERE s.kind = 'open' AND s.kibana_ids ->> 'case' IS NOT NULL"
                " AND s.created_at >= :s AND s.created_at < :e GROUP BY c.number"
                " HAVING count(DISTINCT s.kibana_ids ->> 'case') > 1 ORDER BY c.number"
            ),
            span,
        )
    ]
    findings = await _scalar(
        conn,
        "SELECT count(*) FROM kibana_findings WHERE kind = 'duplicate_case'"
        " AND found_at >= :s AND found_at < :e",
        **span,
    )
    return LifecycleFacts(
        posts=int(posts),
        steps=sum(by_state.values()),
        by_state=by_state,
        in_doubt=tuple(in_doubt),
        creates_sent=len(creates),
        second_creates=tuple(_label(r.number) for r in creates if r.sent_count > 1),
        kibana_cases=int(kibana_cases),
        duplicate_cases=tuple(duplicates),
        duplicate_findings=int(findings),
    )


_OPENED = """
SELECT c.number, p.opened_at, d.decision, d.outcome, d.kind, d.username
FROM case_team_posts p JOIN cases c ON c.id = p.case_id
LEFT JOIN LATERAL (
  SELECT s.sent_at FROM case_team_steps s
  WHERE s.case_id = p.case_id AND s.kind = 'open' ORDER BY s.gen, s.seq LIMIT 1) o ON true
LEFT JOIN LATERAL (
  SELECT d.decision, coalesce(d.outcome, r.verdict_outcome) AS outcome, u.kind, u.username
  FROM incident_report_decisions d
  JOIN incident_reports r ON r.id = d.report_id
  JOIN users u ON u.id = d.by_user_id
  WHERE r.case_id = p.case_id AND d.decided_at <= coalesce(o.sent_at, p.opened_at)
  ORDER BY d.id DESC LIMIT 1) d ON true
WHERE p.kibana_case_id IS NOT NULL AND p.opened_at >= :s AND p.opened_at < :e
ORDER BY c.number
"""


async def opened_cases(conn: AsyncConnection, w: Window) -> list[OpenedCase]:
    out = []
    for r in await conn.execute(text(_OPENED), _span(w)):
        confirmed = r.decision == "confirmed" and r.outcome == "true_positive"
        by_person = confirmed and r.kind == "person" and r.username != ASSISTANT
        out.append(
            OpenedCase(
                int(r.number),
                r.opened_at,
                bool(by_person),
                bool(confirmed and not by_person and r.username == ASSISTANT),
            )
        )
    return out


def _step_of(outbox_id: str | None) -> int | None:
    found = re.fullmatch(r"team:(\d{1,18})", outbox_id or "")
    return int(found.group(1)) if found else None


def known_template(name: str) -> bool:
    return name in REGISTRY or name in KREGISTRY


def is_heavy(name: str) -> bool:
    """Whether a ledger row's template counts against a lane's heavy requests. Every Kibana
    template is light (``kregister`` refuses any other); an Elasticsearch template is what its
    registry entry says; a name in neither counts as heavy (as ``cost_of`` does)."""
    if name in KREGISTRY:
        return False
    return cost_of(name) is CostClass.HEAVY


async def writes(conn: AsyncConnection, w: Window, settings: Settings) -> WriteFacts:
    span = _span(w)
    rows = (
        await conn.execute(
            text(
                "SELECT r.at, r.template, r.write_class, r.outcome, r.health, r.outbox_id,"
                " p.state AS probe_state FROM siem_requests r"
                " LEFT JOIN LATERAL (SELECT state FROM siem_probes WHERE at <= r.at"
                " AND at > r.at - CAST(:reach AS interval) ORDER BY at DESC LIMIT 1) p ON true"
                " WHERE r.write_class = 'WC' AND r.at >= :s AND r.at < :e ORDER BY r.at, r.id"
            ),
            {**span, "reach": PROBE_REACH},
        )
    ).all()
    ledger = tuple(
        LedgerWrite(
            r.at,
            r.template,
            r.write_class,
            r.outcome,
            r.health,
            r.probe_state,
            _step_of(r.outbox_id),
        )
        for r in rows
    )
    steps = (
        await conn.execute(
            text(
                "SELECT id, sent_count FROM case_team_steps WHERE sent_count > 0"
                " AND sent_at >= :s AND sent_at < :e ORDER BY id"
            ),
            span,
        )
    ).all()
    named = {row.step_id for row in ledger if row.step_id is not None}
    existing: set[int] = set()
    if named:
        existing = {
            int(i)
            for i in (
                await conn.execute(
                    text("SELECT id FROM case_team_steps WHERE id = ANY(:ids)"),
                    {"ids": sorted(named)},
                )
            ).scalars()
        }
    without_row = tuple(int(s.id) for s in steps if s.id not in named)
    without_step = sum(1 for row in ledger if row.step_id is None or row.step_id not in existing)
    other = tuple(
        (r.write_class, int(r.n))
        for r in await conn.execute(
            text(
                "SELECT write_class, count(*) AS n FROM siem_requests WHERE write_class IS NOT"
                " NULL AND write_class <> 'WC' AND at >= :s AND at < :e GROUP BY write_class"
                " ORDER BY write_class"
            ),
            span,
        )
    )
    # a write template sent with no class at all is a write outside the classes too
    unclassified = tuple(
        (f"{r.template} (no class)", int(r.n))
        for r in await conn.execute(
            text(
                "SELECT template, count(*) AS n FROM siem_requests WHERE target = 'kibana'"
                " AND write_class IS NULL AND at >= :s AND at < :e GROUP BY template"
                " ORDER BY template"
            ),
            span,
        )
        if getattr(KREGISTRY.get(r.template), "classes", None)
    )
    templates = (
        await conn.execute(
            text(
                "SELECT template, count(*) AS n FROM siem_requests WHERE at >= :s AND at < :e"
                " GROUP BY template ORDER BY template"
            ),
            span,
        )
    ).all()
    start, end = settings.kibana.write_window
    return WriteFacts(
        steps_sent=len(steps),
        sends=sum(int(s.sent_count) for s in steps),
        rows=ledger,
        steps_without_row=without_row,
        rows_without_step=without_step,
        other_class_rows=(*other, *unclassified),
        requests_checked=sum(int(t.n) for t in templates),
        unknown_templates=tuple(
            (t.template, int(t.n)) for t in templates if not known_template(t.template)
        ),
        window_start=start,
        window_end=end,
        cases_posted=int(
            await _scalar(
                conn,
                "SELECT count(*) FROM case_team_posts WHERE kibana_case_id IS NOT NULL"
                " AND opened_at >= :s AND opened_at < :e",
                **span,
            )
        ),
        verdicts_recorded=int(
            await _scalar(
                conn,
                "SELECT count(*) FROM case_team_seen WHERE status = 'recorded'"
                " AND read_at >= :s AND read_at < :e",
                **span,
            )
        ),
        cycles_complete=int(
            await _scalar(
                conn,
                "SELECT count(*) FROM kibana_sync_cycles WHERE outcome = 'complete'"
                " AND started_at >= :s AND started_at < :e",
                **span,
            )
        ),
    )


_DECISIONS = """
SELECT c.id AS case_id, c.number, c.state, d.decision, d.decided_at,
  coalesce(d.outcome, r.verdict_outcome) AS outcome, u.kind, u.username,
  (SELECT n.verdict_outcome FROM incident_reports n WHERE n.case_id = c.id
   ORDER BY n.version DESC LIMIT 1) AS newest
FROM incident_report_decisions d
JOIN incident_reports r ON r.id = d.report_id
JOIN cases c ON c.id = r.case_id
JOIN users u ON u.id = d.by_user_id
WHERE r.case_id IN (
  SELECT r2.case_id FROM incident_report_decisions d2
  JOIN incident_reports r2 ON r2.id = d2.report_id
  WHERE d2.decided_at >= :s AND d2.decided_at < :e)
  AND d.decided_at < :e
ORDER BY c.number, d.id
"""


def next_window_start(at: datetime, start: time, end: time) -> datetime:
    """``at`` if the write window is open then, else the window's next start."""
    moment = at.timetz().replace(tzinfo=None)
    day = at.replace(hour=start.hour, minute=start.minute, second=0, microsecond=0)
    if moment < start:
        return day
    if moment >= end:
        return day + timedelta(days=1)
    return at


async def confirmed(conn: AsyncConnection, w: Window, settings: Settings) -> list[Confirmed]:
    """Person-confirmed true positives whose confirm fell in the window: a case whose newest
    decision is a person's confirm of a true positive and whose newest report still says so (the
    case team's own rule); the confirm counted is the first of the uninterrupted run at the end."""
    start, end = (time.fromisoformat(t) for t in settings.kibana.write_window)
    by_case: dict[Any, list[Any]] = defaultdict(list)
    for r in await conn.execute(text(_DECISIONS), _span(w)):
        by_case[r.case_id].append(r)
    out = []
    for case_id, decisions in by_case.items():
        run: list[Any] = []
        for d in reversed(decisions):
            is_confirm = (
                d.decision == "confirmed"
                and d.outcome == "true_positive"
                and d.kind == "person"
                and d.username != ASSISTANT
            )
            if not is_confirm:
                break
            run.append(d)
        last = decisions[-1]
        if not run or run[0] is not last or last.newest != "true_positive":
            continue
        first = run[-1]
        if not w.since <= first.decided_at < w.until:
            continue
        approved = await conn.execute(
            text(
                "SELECT min(approved_at) FROM case_team_approvals WHERE case_id = :c"
                " AND approved_at >= :t"
            ),
            {"c": case_id, "t": first.decided_at},
        )
        ready = max(first.decided_at, approved.scalar_one() or first.decided_at)
        ready = next_window_start(ready, start, end)
        post = (
            await conn.execute(
                text(
                    "SELECT p.opened_at, (SELECT bool_and(s.state = ANY(:done))"
                    " FROM case_team_steps s WHERE s.case_id = p.case_id AND s.gen = 1) AS done,"
                    " (SELECT max(coalesce(s.verified_at, s.sent_at)) FROM case_team_steps s"
                    " WHERE s.case_id = p.case_id AND s.gen = 1) AS last_at"
                    " FROM case_team_posts p WHERE p.case_id = :c AND p.kibana_case_id IS NOT NULL"
                ),
                {"c": case_id, "done": list(FIRST_SEQUENCE_DONE)},
            )
        ).first()
        out.append(
            Confirmed(
                int(last.number),
                ready,
                None if post is None else post.opened_at,
                post.last_at if post is not None and post.done else None,
                str(last.state),
            )
        )
    return sorted(out, key=lambda c: c.number)


async def closures(conn: AsyncConnection, w: Window) -> ClosureFacts:
    span = _span(w)
    events = await _scalar(
        conn,
        "SELECT count(*) FROM case_events WHERE occurred_at >= :s AND occurred_at < :e",
        **span,
    )
    closed = (
        await conn.execute(
            text(
                "SELECT c.number, e.kind, e.actor, e.actor_user_id FROM case_events e"
                " JOIN cases c ON c.id = e.case_id WHERE e.kind IN ('closed', 'dismissed',"
                " 'merged_into') AND e.occurred_at >= :s AND e.occurred_at < :e ORDER BY e.id"
            ),
            span,
        )
    ).all()
    kibana = (
        await conn.execute(
            text(
                "SELECT template, count(*) AS n FROM siem_requests WHERE target = 'kibana'"
                " AND at >= :s AND at < :e GROUP BY template ORDER BY template"
            ),
            span,
        )
    ).all()
    return ClosureFacts(
        events=int(events),
        closures=len(closed),
        automatic=tuple(
            f"{_label(r.number)} {r.kind} by {r.actor}" for r in closed if r.actor_user_id is None
        ),
        kibana_requests=sum(int(r.n) for r in kibana),
        kibana_closes=tuple(
            f"{r.template} x{r.n}" for r in kibana if r.template in CLOSE_TEMPLATES
        ),
    )


async def reconcile(conn: AsyncConnection, w: Window) -> ReconcileFacts:
    span = _span(w)
    cycles = {
        r.outcome: int(r.n)
        for r in await conn.execute(
            text(
                "SELECT outcome, count(*) AS n FROM kibana_sync_cycles"
                " WHERE started_at >= :s AND started_at < :e GROUP BY outcome"
            ),
            span,
        )
    }
    lags = tuple(
        float(r.lag_s)
        for r in await conn.execute(
            text(
                "SELECT f.lag_s FROM kibana_findings f LEFT JOIN LATERAL ("
                " SELECT health FROM kibana_sync_cycles c WHERE c.started_at <= f.found_at"
                " ORDER BY c.started_at DESC LIMIT 1) c ON true"
                " WHERE f.found_at >= :s AND f.found_at < :e AND f.lag_s IS NOT NULL"
                " AND f.kind = ANY(:kinds) AND coalesce(c.health, 'normal') = 'normal'"
            ),
            {**span, "kinds": list(PERSON_CHANGES)},
        )
    )
    open_, resolved = (
        await conn.execute(
            text(
                "SELECT count(*) FILTER (WHERE resolved_at IS NULL),"
                " count(*) FILTER (WHERE resolved_at IS NOT NULL) FROM kibana_findings"
                " WHERE kind IN ('unexplained_argus_action', 'unexplained_argus_case')"
                " AND found_at >= :s AND found_at < :e"
            ),
            span,
        )
    ).one()
    reverts = [
        f"{_label(r.number)} {r.what}"
        for r in await conn.execute(
            text(
                "SELECT c.number, s.kind AS what FROM case_team_steps s"
                " JOIN cases c ON c.id = s.case_id"
                " WHERE s.sent_at >= :s AND s.sent_at < :e AND s.kind <> ALL(:additive)"
                " AND EXISTS (SELECT 1 FROM kibana_findings f WHERE f.case_id = s.case_id"
                " AND f.kind = ANY(:kinds) AND f.found_at < s.sent_at)"
                " UNION ALL"
                " SELECT c.number, o.op AS what FROM kibana_outbox o"
                " JOIN cases c ON c.id = o.case_id"
                " WHERE o.sent_at >= :s AND o.sent_at < :e AND o.op IN ('update', 'close')"
                " AND EXISTS (SELECT 1 FROM kibana_findings f WHERE f.case_id = o.case_id"
                " AND f.kind = ANY(:kinds) AND f.found_at < o.sent_at)"
            ),
            {**span, "kinds": list(PERSON_CHANGES), "additive": list(ADDITIVE_STEP_KINDS)},
        )
    ]
    team, mirrored = (
        await conn.execute(
            text(
                "SELECT count(*), count(m.case_id) FROM case_team_posts p"
                " LEFT JOIN kibana_mirror m ON m.kibana_case_id = p.kibana_case_id"
                " WHERE p.kibana_case_id IS NOT NULL AND p.created_at >= :s AND p.created_at < :e"
            ),
            span,
        )
    ).one()
    return ReconcileFacts(
        cycles=sum(cycles.values()),
        complete=cycles.get("complete", 0),
        partial=cycles.get("partial", 0),
        failed=cycles.get("failed", 0),
        lags_s=lags,
        unexplained=int(open_),
        unexplained_resolved=int(resolved),
        reverts=tuple(reverts),
        team_cases=int(team),
        team_cases_in_mirror=int(mirrored),
    )


_NOTIFIED_CASES = """
SELECT id, notified_at FROM cases WHERE notified_at IS NOT NULL
UNION
SELECT c.id, c.notified_at FROM cases c WHERE c.id IN (
  SELECT case_id FROM case_events WHERE kind = 'notified'
  AND occurred_at >= :s AND occurred_at < :e)
"""


async def notified(conn: AsyncConnection, w: Window, now: datetime) -> NotifiedFacts:
    span = _span(w)
    cases = (await conn.execute(text(_NOTIFIED_CASES), span)).all()
    ids = [r.id for r in cases]
    if not ids:
        return NotifiedFacts(0, 0, (), 0, (), NOTIFIED_PASS.total_seconds())
    decided = await _scalar(
        conn,
        "SELECT count(*) FROM case_known_matches WHERE case_id = ANY(:ids)",
        ids=ids,
    )
    undecided = [
        f"{_label(r.number)} investigation {str(r.id)[:8]}"
        for r in await conn.execute(
            text(
                "SELECT c.number, i.id FROM cases c"
                " JOIN case_members m ON m.case_id = c.id AND m.removed_at IS NULL"
                " JOIN investigations i ON i.id = m.investigation_id"
                " LEFT JOIN case_known_matches k ON k.investigation_id = i.id"
                " WHERE c.id = ANY(:ids) AND c.notified_at IS NOT NULL"
                " AND i.last_event_at > c.notified_at AND i.updated_at < :limit"
                " AND (k.investigation_id IS NULL OR k.version < i.version) ORDER BY c.number, i.id"
            ),
            {"ids": ids, "limit": now - NOTIFIED_PASS},
        )
    ]
    lags = tuple(
        max((r.decided_at - r.updated_at).total_seconds(), 0.0)
        for r in await conn.execute(
            text(
                "SELECT k.decided_at, i.updated_at FROM case_known_matches k"
                " JOIN investigations i ON i.id = k.investigation_id"
                " WHERE k.case_id = ANY(:ids) AND k.outcome = 'changed' AND k.version = i.version"
                " AND k.decided_at >= :s AND k.decided_at < :e"
            ),
            {"ids": ids, **span},
        )
    )
    changed = await _scalar(
        conn,
        "SELECT count(*) FROM case_known_matches WHERE case_id = ANY(:ids)"
        " AND outcome = 'changed' AND decided_at >= :s AND decided_at < :e",
        ids=ids,
        **span,
    )
    return NotifiedFacts(
        cases=len(ids),
        investigations=int(decided),
        undecided=tuple(undecided),
        changed=int(changed),
        change_lags_s=lags,
        pass_s=NOTIFIED_PASS.total_seconds(),
    )


def _lane_of(lane: str | None, purpose: str) -> str | None:
    """The ledger's lane, or the purpose's for a row from before the column existed. A probe or
    self-test has none (it spends its own allowance, outside every lane)."""
    if lane is not None:
        return lane
    try:
        found = lane_of(Purpose(purpose))
    except ValueError:
        return "unknown"
    return None if found is None else found.value


async def load(conn: AsyncConnection, w: Window, settings: Settings) -> LoadFacts:
    span = _span(w)
    plan = lane_plan(settings.siem)
    limits = []
    for lane in Lane:
        spec = plan.spec(lane)
        limits.append(
            LaneLimit(
                lane.value,
                spec.per_minute_ms,
                plan.config(lane).burst_ms,
                spec.per_day_ms,
                spec.heavy_per_day,
            )
        )
    c = plan.ceiling
    ceiling = LaneLimit(
        "total", c.took_per_minute_ms, c.burst_ms, c.took_per_day_ms, c.heavy_per_day
    )

    minutes: dict[tuple[str, datetime], list[int]] = defaultdict(lambda: [0, 0, 0])
    for r in await conn.execute(
        text(
            "SELECT lane, purpose, date_trunc('minute', at) AS minute, sum(took_ms) AS took,"
            " count(*) AS n, max(took_ms) AS largest FROM siem_requests"
            " WHERE at >= :s AND at < :e GROUP BY lane, purpose, minute"
        ),
        span,
    ):
        lane_name = _lane_of(r.lane, r.purpose)
        if lane_name is not None:
            cell = minutes[(lane_name, r.minute)]
            cell[0] += int(r.took)
            cell[1] += int(r.n)
            cell[2] = max(cell[2], int(r.largest))
    days: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0, 0])
    for r in await conn.execute(
        text(
            "SELECT lane, purpose, template, (at AT TIME ZONE 'UTC')::date AS day,"
            " sum(took_ms) AS took, count(*) AS n FROM siem_requests"
            " WHERE at >= :s AND at < :e GROUP BY lane, purpose, template, day"
        ),
        span,
    ):
        lane_name = _lane_of(r.lane, r.purpose)
        if lane_name is None:
            continue
        cell = days[(lane_name, r.day.isoformat())]
        cell[0] += int(r.took)
        cell[1] += int(r.n)
        if is_heavy(r.template):
            cell[2] += int(r.n)

    probes = (
        await conn.execute(
            text(
                "SELECT at, state FROM siem_probes WHERE at >= :s - interval '10 minutes'"
                " AND at < :e ORDER BY at"
            ),
            span,
        )
    ).all()
    moves = []
    for before, now in itertools.pairwise(probes):
        if before.state == "normal" and now.state != "normal" and now.at >= w.since:
            n, took = (
                await conn.execute(
                    text(
                        "SELECT count(*), coalesce(sum(took_ms), 0) FROM siem_requests"
                        " WHERE at >= :a AND at < :b AND lane IS NOT NULL"
                    ),
                    {"a": now.at - timedelta(minutes=1), "b": now.at},
                )
            ).one()
            moves.append(CautionMove(now.at, now.state, int(n), int(took)))

    signins = settings.signins
    per_day = {
        r.day.isoformat(): int(r.n)
        for r in await conn.execute(
            text(
                "SELECT (at AT TIME ZONE 'UTC')::date AS day, count(*) AS n FROM siem_requests"
                " WHERE template = :t AND at >= :s AND at < :e GROUP BY day ORDER BY day"
            ),
            {"t": SIGNIN_TEMPLATE, **span},
        )
    }
    took = await _scalar(
        conn,
        "SELECT coalesce(sum(took_ms), 0) FROM siem_requests WHERE template = :t"
        " AND at >= :s AND at < :e",
        t=SIGNIN_TEMPLATE,
        **span,
    )
    breaches = await _scalar(
        conn,
        "SELECT count(*) FROM (SELECT at - lag(at) OVER (ORDER BY at, id) AS gap"
        " FROM siem_requests WHERE template = :t AND at >= :s AND at < :e) x"
        " WHERE gap < make_interval(secs => :gap)",
        t=SIGNIN_TEMPLATE,
        gap=signins.gap.total_seconds(),
        **span,
    )
    return LoadFacts(
        limits=tuple(limits),
        ceiling=ceiling,
        minutes=tuple(
            MinuteSpend(lane, minute, v[0], v[1], v[2])
            for (lane, minute), v in sorted(minutes.items(), key=lambda kv: (kv[0][1], kv[0][0]))
        ),
        days=tuple(
            DaySpend(lane, day, v[0], v[1], v[2])
            for (lane, day), v in sorted(days.items(), key=lambda kv: (kv[0][1], kv[0][0]))
        ),
        probes=len(probes),
        moves=tuple(moves),
        signin_per_day=per_day,
        signin_server_ms=int(took),
        signin_gap_breaches=int(breaches),
        signin_gap_s=signins.gap.total_seconds(),
        signin_steady_per_day=SIGNIN_STEADY_PER_DAY,
        signin_backfill_extra=SIGNIN_BACKFILL_EXTRA,
    )


async def signins(conn: AsyncConnection, w: Window, settings: Settings) -> SigninFacts:
    rows = (
        await conn.execute(
            text(
                "SELECT day, looked_at, complete, reason, store_failures FROM signin_lookups"
                " WHERE looked_at >= :s AND looked_at < :e ORDER BY looked_at"
            ),
            _span(w),
        )
    ).all()
    return SigninFacts(
        lookups=tuple(
            Lookup(
                r.day.isoformat(), r.looked_at, bool(r.complete), r.reason, int(r.store_failures)
            )
            for r in rows
        ),
        now=w.until,
        retention_days=settings.signins.retention_days,
        retry_after_s=signin_model.RETRY_AFTER.total_seconds(),
        backoff_s={k: v.total_seconds() for k, v in signin_model.BACKOFF.items()},
        # an answer with sightings but no usable names (UNNAMED) is settled, not retried
        terminal_reasons=frozenset({signin_model.GONE, signin_model.UNNAMED}),
        max_store_failures=signin_model.MAX_STORE_FAILURES,
        grace_s=SIGNIN_GRACE.total_seconds(),
    )


def sweep(settings: Settings) -> SweepFacts:
    """The newest stored result of ``scripts/privacy_sweep.py``, found beside the soak folder
    (``soak.dir``)."""
    base = Path(settings.soak.dir).parent / "p1"
    found = sorted(base.glob("*/sweep.json")) if base.is_dir() else []
    if not found:
        return SweepFacts(None, None, None, None, None, None)
    path = found[-1]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        at = datetime.fromisoformat(data["at"])
        at = at if at.tzinfo else at.replace(tzinfo=UTC)
        return SweepFacts(
            str(path),
            at,
            int(data["leaks"]),
            int(data["signin_name_leaks"]),
            int(data["signin_names_checked"]),
            int(data["dossiers"]),
        )
    except (OSError, ValueError, KeyError, TypeError):
        return SweepFacts(str(path), None, None, None, None, None)


async def analysis(conn: AsyncConnection, w: Window) -> AnalysisFacts:
    from argus.evaluation.harness import BENIGN
    from argus.llm.providers import load_config
    from argus.soak2 import LABELLED_PROPOSALS

    span = _span(w)
    labelled = (
        await conn.execute(
            text(LABELLED_PROPOSALS), {"start": w.since, "end": w.until, "assistant": ASSISTANT}
        )
    ).all()
    wrong = sum(1 for r in labelled if r.outcome in BENIGN and r.label == "true_positive")
    gold = await _scalar(
        conn,
        "SELECT count(DISTINCT investigation_id) FROM gold_labels",
    )
    days = {
        r.day.isoformat(): float(r.usd)
        for r in await conn.execute(
            text(
                "SELECT (at AT TIME ZONE 'UTC')::date AS day, sum(cost_usd) AS usd FROM llm_calls"
                " WHERE at >= :s AND at < :e GROUP BY day ORDER BY day"
            ),
            span,
        )
    }
    month = await _scalar(
        conn,
        "SELECT coalesce(sum(cost_usd), 0) FROM llm_calls"
        " WHERE at >= date_trunc('month', CAST(:e AS timestamptz)) AND at < :e",
        e=w.until,
    )
    finished, inconclusive = (
        await conn.execute(
            text(
                "SELECT count(*) FILTER (WHERE status IN ('proposed', 'no_decision')),"
                " count(*) FILTER (WHERE status = 'no_decision' OR (status = 'proposed'"
                " AND outcome = 'inconclusive')) FROM assessments"
                " WHERE created_at >= :s AND created_at < :e"
            ),
            span,
        )
    ).one()
    try:
        config = load_config()
        caps: tuple[float | None, float | None] = (config.daily_cap_usd, config.monthly_cap_usd)
    except (OSError, ValueError):
        caps = (None, None)
    return AnalysisFacts(
        labelled=len(labelled),
        wrong_benign=wrong,
        gold_answered=int(gold),
        cost_days=days,
        cost_month_usd=float(month),
        daily_cap_usd=caps[0],
        monthly_cap_usd=caps[1],
        finished=int(finished),
        inconclusive=int(inconclusive),
    )


async def health(conn: AsyncConnection, w: Window) -> HealthFacts:
    stamps = list(
        (
            await conn.execute(
                text("SELECT at FROM soak_samples WHERE at >= :s AND at < :e ORDER BY at"),
                _span(w),
            )
        ).scalars()
    )
    marks = [w.since, *stamps, w.until]
    gaps = tuple(
        f"{a:%m-%d %H:%M} to {b:%m-%d %H:%M} UTC"
        for a, b in itertools.pairwise(marks)
        if b - a > SAMPLE_GAP
    )
    return HealthFacts(
        samples=len(stamps),
        newest_sample=stamps[-1] if stamps else None,
        gaps=gaps,
        now=w.until,
        stale_s=SAMPLE_STALE.total_seconds(),
    )


def _due(w: Window, at: time, weekday: int | None = None) -> tuple[datetime, ...]:
    """The times in the window when a daily (or weekly) timer fires."""
    out = []
    day = w.since.date()
    while day <= w.until.date():
        moment = datetime.combine(day, at, tzinfo=UTC)
        if w.since <= moment < w.until and (weekday is None or day.weekday() == weekday):
            out.append(moment)
        day += timedelta(days=1)
    return tuple(out)


def backups(settings: Settings, w: Window) -> BackupFacts:
    base = settings.backup.dir
    try:
        found = backup.manifests(base) if base.is_dir() else []
        recorded = backup.drills(base)
        readable = base.is_dir()
    except OSError:
        found, recorded, readable = [], [], False
    nightly = [m.created_at for m in found if m.kind == "nightly"]
    drills = []
    for record in recorded:
        try:
            at = datetime.fromisoformat(str(record["at"]))
            at = at if at.tzinfo else at.replace(tzinfo=UTC)
            drills.append((at, bool(record.get("passed"))))
        except (KeyError, ValueError):
            continue
    return BackupFacts(
        dumps=tuple(sorted(t for t in nightly if w.since - timedelta(hours=1) <= t < w.until)),
        dump_due=_due(w, DUMP_AT),
        drills=tuple(sorted(d for d in drills if w.since <= d[0] < w.until)),
        drill_due=_due(w, DRILL_AT, DRILL_WEEKDAY),
        newest_dump=max(nightly, default=None),
        grace_s=BACKUP_GRACE.total_seconds(),
        readable=readable,
    )
