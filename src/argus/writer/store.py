# ruff: noqa: S608 - the f-strings put fixed table and column names in the SQL; values are bound
"""The writer's database access (Q-D4): rows to send, their moves, lookups, runs and the ramp.

Every function takes the connection of the transaction it belongs to. The outbox moves are the
ones the guard trigger allows (``argus.cases.outbox``); the writer's login holds UPDATE on
exactly the columns moved here (migration 0037). Time comes from the caller (a fake clock in
the tests), never from the database, except for the approvals' expiry, which is the database's.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession

from argus.cases import kibana as intent
from argus.db.audit import record_audit
from argus.writer import plan, render

ACTOR = "argus:writer"
OUTBOX, STEPS = "kibana_outbox", "kibana_steps"
LOOKUP_AFTER = (
    timedelta(minutes=2),
    timedelta(minutes=5),
    timedelta(minutes=15),
    timedelta(minutes=30),
)
LOCK_KEY = int.from_bytes(b"ARGUSWRT", "big") >> 1  # one writer run at a time (advisory lock)
ROW_COLUMNS = (
    "o.id, o.case_id, o.case_event_id, o.position, o.write_class, o.op, o.payload,"
    " o.payload_hash, o.idempotency_key, o.approval_request_id, o.state, o.sent_count,"
    " e.from_state, e.to_state"
)


async def audit(
    conn: AsyncConnection,
    action: str,
    case_id: uuid.UUID | str,
    details: Mapping[str, Any],
    *,
    outcome: str = "success",
    target_type: str = "case",
) -> None:
    """An audit row, in the transaction of the move it records."""
    session = AsyncSession(bind=conn)
    try:
        await record_audit(
            session,
            actor=ACTOR,
            action=action,
            outcome=outcome,
            target_type=target_type,
            target_id=str(case_id),
            details=dict(details),
        )
    finally:
        await session.close()


# --------------------------------------------------------------------------- outbox rows


def _row(r: Any) -> plan.Row:
    return plan.Row(
        id=int(r.id),
        case_id=r.case_id,
        case_event_id=int(r.case_event_id),
        position=int(r.position),
        write_class=r.write_class,
        op=r.op,
        payload=dict(r.payload),
        payload_hash=r.payload_hash,
        idempotency_key=r.idempotency_key,
        approval_request_id=r.approval_request_id,
        state=r.state,
        sent_count=int(r.sent_count),
        from_state=r.from_state,
        to_state=r.to_state,
    )


async def get_row(conn: AsyncConnection, row_id: int) -> plan.Row | None:
    found = (
        await conn.execute(
            text(
                f"SELECT {ROW_COLUMNS} FROM kibana_outbox o JOIN case_events e"
                " ON e.id = o.case_event_id WHERE o.id = :id"
            ),
            {"id": row_id},
        )
    ).first()
    return None if found is None else _row(found)


async def eligible_rows(
    conn: AsyncConnection, write_class: str, limit: int, *, case_id: uuid.UUID | None = None
) -> list[plan.Row]:
    """Rows of ``write_class`` ready to send, oldest first: planned or approved (a closure
    write only once the send-time check let it go), with every earlier row of their case
    verified or skipped (the writes of a case go in order, and one in doubt holds the rest)."""
    states = "('approved')" if write_class == "W3" else "('planned', 'approved')"
    rows = await conn.execute(
        text(
            f"SELECT {ROW_COLUMNS} FROM kibana_outbox o JOIN case_events e"
            " ON e.id = o.case_event_id"
            f" WHERE o.write_class = :c AND o.state IN {states}"
            " AND (CAST(:case AS uuid) IS NULL OR o.case_id = CAST(:case AS uuid))"
            " AND NOT EXISTS (SELECT 1 FROM kibana_outbox p WHERE p.case_id = o.case_id"
            " AND p.id < o.id AND p.state NOT IN ('verified', 'skipped'))"
            " ORDER BY o.id LIMIT :n"
        ),
        {"c": write_class, "n": limit, "case": case_id},
    )
    return [_row(r) for r in rows]


async def rows_in(conn: AsyncConnection, state: str) -> list[plan.Row]:
    rows = await conn.execute(
        text(
            f"SELECT {ROW_COLUMNS} FROM kibana_outbox o JOIN case_events e"
            " ON e.id = o.case_event_id WHERE o.state = :s ORDER BY o.id"
        ),
        {"s": state},
    )
    return [_row(r) for r in rows]


async def kibana_case_of(conn: AsyncConnection, case_id: uuid.UUID) -> str | None:
    """The Kibana id of a case's verified create (the latest, if it was made again)."""
    found: str | None = (
        await conn.execute(
            text(
                "SELECT kibana_case_id FROM kibana_outbox WHERE case_id = :c AND op = 'create'"
                " AND state = 'verified' AND kibana_case_id IS NOT NULL ORDER BY id DESC LIMIT 1"
            ),
            {"c": case_id},
        )
    ).scalar_one_or_none()
    return found


async def mirror_facts(conn: AsyncConnection, case_id: uuid.UUID) -> plan.MirrorFacts:
    row = (
        await conn.execute(
            text(
                "SELECT paused_reason, unmanaged, deleted_at, severity, tags FROM kibana_mirror"
                " WHERE case_id = :c"
            ),
            {"c": case_id},
        )
    ).first()
    if row is None:
        return plan.MirrorFacts()
    return plan.MirrorFacts(
        row.paused_reason,
        frozenset(row.unmanaged or ()),
        row.deleted_at is not None,
        row.severity,
        tuple(row.tags or ()),
    )


async def seen_of(
    conn: AsyncConnection, case_id: uuid.UUID, mirror: plan.MirrorFacts, before_image_of: int | None
) -> plan.Seen:
    """What ARGUS has seen or set on the case (plan.Seen): the row's before-image
    (``before_image_of``: its outbox id), the mirror's last poll, and the latest write ARGUS
    made to the severity and to its tags and read back (a verified row or compensating step)."""
    before: Mapping[str, Any] = {}
    if before_image_of is not None:
        found = (
            await conn.execute(
                text("SELECT before_image FROM kibana_outbox WHERE id = :i"), {"i": before_image_of}
            )
        ).scalar_one_or_none()
        before = found if isinstance(found, dict) else {}
    written = await conn.execute(
        text(
            "SELECT payload FROM ("
            " SELECT payload, verified_at, id, 0 AS src FROM kibana_outbox"
            "  WHERE case_id = :c AND state = 'verified' AND op IN ('create', 'update', 'close')"
            " UNION ALL"
            " SELECT payload, verified_at, id, 1 FROM kibana_steps"
            "  WHERE case_id = :c AND state = 'verified' AND kind = 'compensate_update'"
            ") w ORDER BY verified_at DESC NULLS LAST, src DESC, id DESC"
        ),
        {"c": case_id},
    )
    severity_set: str | None = None
    tags_set: list[str] | None = None
    for payload in written.scalars():
        if severity_set is None and isinstance(payload.get("severity"), str):
            severity_set = payload["severity"]
        if tags_set is None and isinstance(payload.get("argus_tags"), list):
            tags_set = payload["argus_tags"]
    return plan.Seen.of(
        [before.get("severity"), mirror.severity, severity_set],
        [before.get("tags") or None, mirror.tags or None, tags_set],
    )


async def names(conn: AsyncConnection, actors: Sequence[str]) -> dict[str, str]:
    """``user:<id>`` -> the person's display name (an actor that is not a person has none)."""
    ids = {
        int(a.removeprefix("user:")) for a in actors if a.startswith("user:") and a[5:].isdigit()
    }
    if not ids:
        return {}
    rows = await conn.execute(
        text("SELECT id, display_name FROM users WHERE id = ANY(:ids)"), {"ids": sorted(ids)}
    )
    return {f"user:{r.id}": r.display_name for r in rows}


async def approvers(
    conn: AsyncConnection, request_id: int
) -> tuple[list[render.Approver], datetime | None]:
    """Who approved a request (name and the name ELK knows them by) and when the last did."""
    rows = (
        await conn.execute(
            text(
                "SELECT u.display_name, coalesce(u.elk_username, u.username) AS username,"
                " d.decided_at FROM approval_decisions d JOIN users u ON u.id = d.approver_user_id"
                " WHERE d.request_id = :r AND d.decision = 'approved' ORDER BY d.decided_at, d.id"
            ),
            {"r": request_id},
        )
    ).all()
    return [render.Approver(r.display_name, r.username) for r in rows], (
        max((r.decided_at for r in rows), default=None)
    )


async def context(
    conn: AsyncConnection,
    link_base: str,
    approval_request_id: int | None,
    reference: str,
    params: Mapping[str, Any],
) -> render.Context:
    """The renderer's context for a payload: names of the people it mentions, and for a
    closing or correcting comment the approvers and the time."""
    people = await names(conn, [v for v in params.values() if isinstance(v, str)])
    approved: list[render.Approver] = []
    when: datetime | None = None
    if approval_request_id is not None:
        approved, when = await approvers(conn, approval_request_id)
    return render.Context(link_base, people, approved, when, reference)


async def alert_groups(
    conn: AsyncConnection, case_id: uuid.UUID
) -> dict[uuid.UUID, list[plan.AlertRef]]:
    """The alerts of the case's investigations, by investigation (duplicates, quarantined and
    missing alerts left out), with their concrete indices."""
    rows = await conn.execute(
        text(
            "SELECT ia.investigation_id, a.alert_id, a.index AS alert_index,"
            " coalesce(a.event_time, a.detected_at, a.first_seen_at) AS at"
            " FROM case_members m JOIN investigation_alerts ia"
            " ON ia.investigation_id = m.investigation_id"
            " JOIN alert_records a ON a.alert_id = ia.alert_id"
            " WHERE m.case_id = :c AND m.removed_at IS NULL AND ia.duplicate_of IS NULL"
            " AND a.status = 'normalized' AND a.source_missing_at IS NULL"
        ),
        {"c": case_id},
    )
    groups: dict[uuid.UUID, list[plan.AlertRef]] = {}
    for r in rows:
        groups.setdefault(r.investigation_id, []).append(
            plan.AlertRef(r.at, r.alert_id, r.alert_index)
        )
    return groups


# --------------------------------------------------------------------------- moves


async def begin_sending(conn: AsyncConnection, table: str, row_id: int, now: datetime) -> None:
    """``approved`` -> ``sending``, counted and committed before the request leaves."""
    moved = await conn.execute(
        text(
            f"UPDATE {table} SET state = 'sending', sent_count = sent_count + 1,"
            " sent_at = :now, state_reason = NULL WHERE id = :id AND state = 'approved'"
        ),
        {"id": row_id, "now": now},
    )
    if moved.rowcount != 1:
        raise StateMovedError(f"{table} {row_id} is no longer approved")


class StateMovedError(RuntimeError):
    """The row is not in the state the writer read it in (another run, a person): not sent."""


async def move(
    conn: AsyncConnection,
    table: str,
    row_id: int,
    to: str,
    reason: str | None = None,
    *,
    kibana_case_id: str | None = None,
    verified_at: datetime | None = None,
    only_from: Sequence[str] | None = None,
) -> bool:
    """Move a row to ``to`` (the trigger refuses a move the outbox does not allow); False when
    ``only_from`` is given and the row is in another state."""
    sets = ["state = :to", "state_reason = :reason"]
    params: dict[str, Any] = {
        "id": row_id,
        "to": to,
        "reason": None if reason is None else reason[:1000],
    }
    if kibana_case_id is not None:
        sets.append("kibana_case_id = :kid")
        params["kid"] = kibana_case_id
    if verified_at is not None:
        sets.append("verified_at = :vat")
        params["vat"] = verified_at
    where = "id = :id"
    if only_from is not None:
        where += " AND state = ANY(:from)"
        params["from"] = list(only_from)
    done = await conn.execute(
        text(f"UPDATE {table} SET {', '.join(sets)} WHERE {where}"),
        params,
    )
    return bool(done.rowcount == 1)


async def note(conn: AsyncConnection, table: str, row_id: int, reason: str) -> None:
    """Change a row's reason without moving it."""
    await conn.execute(
        text(f"UPDATE {table} SET state_reason = :r WHERE id = :id"),
        {"id": row_id, "r": reason[:1000]},
    )


async def stale_sending(conn: AsyncConnection, table: str, before: datetime) -> list[int]:
    """Rows left in ``sending`` since before ``before``: the writer stopped between committing
    the send and hearing the answer."""
    rows = await conn.execute(
        text(f"SELECT id FROM {table} WHERE state = 'sending' AND sent_at < :t ORDER BY id"),
        {"t": before},
    )
    return [int(i) for i in rows.scalars()]


async def ids_in(conn: AsyncConnection, table: str, state: str) -> list[int]:
    rows = await conn.execute(
        text(f"SELECT id FROM {table} WHERE state = :s ORDER BY id"),
        {"s": state},
    )
    return [int(i) for i in rows.scalars()]


# --------------------------------------------------------------------------- steps


@dataclass(frozen=True)
class Step:
    id: int
    case_id: uuid.UUID
    outbox_id: int | None
    approval_request_id: int | None
    kind: str
    seq: int
    key: str
    write_class: str
    payload: Mapping[str, Any]
    payload_hash: str
    state: str
    sent_count: int
    kibana_case_id: str | None


STEP_COLUMNS = (
    "id, case_id, outbox_id, approval_request_id, kind, seq, key, write_class, payload,"
    " payload_hash, state, sent_count, kibana_case_id"
)


def _step(r: Any) -> Step:
    return Step(
        int(r.id),
        r.case_id,
        r.outbox_id,
        r.approval_request_id,
        r.kind,
        int(r.seq),
        r.key,
        r.write_class,
        dict(r.payload),
        r.payload_hash,
        r.state,
        int(r.sent_count),
        r.kibana_case_id,
    )


async def get_step(conn: AsyncConnection, step_id: int) -> Step | None:
    found = (
        await conn.execute(
            text(f"SELECT {STEP_COLUMNS} FROM kibana_steps WHERE id = :id"),
            {"id": step_id},
        )
    ).first()
    return None if found is None else _step(found)


async def steps_in(conn: AsyncConnection, state: str) -> list[Step]:
    rows = await conn.execute(
        text(f"SELECT {STEP_COLUMNS} FROM kibana_steps WHERE state = :s ORDER BY id"),
        {"s": state},
    )
    return [_step(r) for r in rows]


async def eligible_steps(conn: AsyncConnection, write_class: str, limit: int) -> list[Step]:
    """Steps of ``write_class`` ready to send: a created case's opening comment and attachments
    once its create is verified, and an approved compensating write once its case has nothing
    else in doubt. One in doubt (ambiguous, paused, in conflict) holds the later steps of its
    kind for that case; the opening comment goes before the attachments."""
    rows = await conn.execute(
        text(
            f"SELECT s.{STEP_COLUMNS.replace(', ', ', s.')} FROM kibana_steps s"
            " WHERE s.write_class = :c AND s.state IN ('planned', 'approved')"
            " AND ((s.kind IN ('comment', 'attach') AND EXISTS (SELECT 1 FROM kibana_outbox o"
            "        WHERE o.id = s.outbox_id AND o.state = 'verified'))"
            "   OR (s.kind LIKE 'compensate%' AND NOT EXISTS (SELECT 1 FROM kibana_outbox o"
            "        WHERE o.case_id = s.case_id AND o.state NOT IN ('verified', 'skipped'))))"
            " AND NOT EXISTS (SELECT 1 FROM kibana_steps p WHERE p.case_id = s.case_id"
            "   AND p.id < s.id AND p.state NOT IN ('verified', 'skipped')"
            "   AND (p.kind = s.kind OR p.kind = 'comment' OR p.kind LIKE 'compensate%'))"
            " ORDER BY s.id LIMIT :n"
        ),
        {"c": write_class, "n": limit},
    )
    return [_step(r) for r in rows]


async def insert_step(
    conn: AsyncConnection,
    *,
    case_id: uuid.UUID,
    outbox_id: int | None,
    approval_request_id: int | None,
    kind: str,
    seq: int,
    key: str,
    write_class: str,
    payload: Mapping[str, Any],
) -> int | None:
    """Plan a step; None if it already exists (its key is unique)."""
    found = await conn.execute(
        text(
            "INSERT INTO kibana_steps (case_id, outbox_id, approval_request_id, kind, seq, key,"
            " write_class, payload, payload_hash) VALUES (:c, :o, :a, :k, :s, :key, :w,"
            " CAST(:p AS jsonb), :h) ON CONFLICT (key) DO NOTHING RETURNING id"
        ),
        {
            "c": case_id,
            "o": outbox_id,
            "a": approval_request_id,
            "k": kind,
            "s": seq,
            "key": key,
            "w": write_class,
            "p": json.dumps(payload),
            "h": intent.payload_hash(dict(payload)),
        },
    )
    new = found.scalar_one_or_none()
    return None if new is None else int(new)


CANARY_ALERTS = 5  # alerts a case holds while its class is at the canary step (plan §7.1)


async def attach_limit(conn: AsyncConnection) -> int:
    """How many alerts a case may have attached now: five while W1 is at its canary step, up
    to 200 once a person has raised the step."""
    return CANARY_ALERTS if await ramp_step(conn, "W1") == 1 else plan.MAX_ATTACHED


async def plan_attachments(conn: AsyncConnection, row: plan.Row) -> int:
    """After a create is verified: its opening comment (once) and an attach step for every
    batch of up to five representative alerts not yet in a step (at most :func:`attach_limit`
    in all: 5 at the canary, 200 after). Steps that already exist are never planned again.
    Returns how many steps were planned."""
    limit = await attach_limit(conn)
    groups = await alert_groups(conn, row.case_id)
    reps = plan.representatives(groups, limit)
    have = await conn.execute(
        text(
            "SELECT payload, seq FROM kibana_steps WHERE case_id = :c AND kind = 'attach'"
            " ORDER BY seq"
        ),
        {"c": row.case_id},
    )
    taken: set[str] = set()
    last = 0
    for r in have:
        taken |= {a for a, _ in r.payload.get("alerts", [])}
        last = max(last, int(r.seq))
    planned = 0
    opening = await insert_step(
        conn,
        case_id=row.case_id,
        outbox_id=row.id,
        approval_request_id=None,
        kind="comment",
        seq=0,
        key=f"{row.id}:comment:0",
        write_class="W1",
        payload={
            "template": "opened",
            "params": {
                "case": str(row.case_id),
                "link": intent.CASE_LINK.format(id=row.case_id),
                "alerts": len(reps),
                "investigations": len(groups),
            },
        },
    )
    planned += opening is not None
    fresh = [a for a in reps if a.alert_id not in taken][: max(limit - len(taken), 0)]
    for n, batch in enumerate(plan.batches(fresh), start=last + 1):
        added = await insert_step(
            conn,
            case_id=row.case_id,
            outbox_id=row.id,
            approval_request_id=None,
            kind="attach",
            seq=n,
            key=f"{row.id}:attach:{n}",
            write_class="W1",
            payload={"alerts": [[a.alert_id, a.index] for a in batch]},
        )
        planned += added is not None
    return planned


# --------------------------------------------------------------------------- lookups


async def schedule_lookups(
    conn: AsyncConnection, subject: str, subject_id: int, sent_count: int, now: datetime
) -> None:
    """The four looks for a write in doubt: 2, 5, 15 and 30 minutes after ``now``."""
    for attempt, wait in enumerate(LOOKUP_AFTER, start=1):
        await conn.execute(
            text(
                "INSERT INTO kibana_lookups (subject, subject_id, sent_count, attempt, due_at)"
                " VALUES (:s, :i, :n, :a, :due) ON CONFLICT DO NOTHING"
            ),
            {"s": subject, "i": subject_id, "n": sent_count, "a": attempt, "due": now + wait},
        )


@dataclass(frozen=True)
class Lookup:
    id: int
    subject: str
    subject_id: int
    sent_count: int
    attempt: int


async def due_lookups(conn: AsyncConnection, now: datetime) -> list[Lookup]:
    rows = await conn.execute(
        text(
            "SELECT id, subject, subject_id, sent_count, attempt FROM kibana_lookups"
            " WHERE done_at IS NULL AND due_at <= :now ORDER BY due_at, id"
        ),
        {"now": now},
    )
    return [
        Lookup(int(r.id), r.subject, int(r.subject_id), int(r.sent_count), int(r.attempt))
        for r in rows
    ]


async def finish_lookup(
    conn: AsyncConnection, lookup_id: int, outcome: str, details: Mapping[str, Any], now: datetime
) -> None:
    await conn.execute(
        text(
            "UPDATE kibana_lookups SET done_at = :now, outcome = :o, details = CAST(:d AS jsonb)"
            " WHERE id = :id AND done_at IS NULL"
        ),
        {"id": lookup_id, "now": now, "o": outcome, "d": json.dumps(details)},
    )


async def postpone_lookup(conn: AsyncConnection, lookup_id: int, until: datetime) -> None:
    await conn.execute(
        text("UPDATE kibana_lookups SET due_at = :t WHERE id = :id AND done_at IS NULL"),
        {"id": lookup_id, "t": until},
    )


async def close_lookups(
    conn: AsyncConnection, subject: str, subject_id: int, now: datetime, outcome: str = "not_needed"
) -> None:
    """The write is settled: the looks still waiting are not needed."""
    await conn.execute(
        text(
            "UPDATE kibana_lookups SET done_at = :now, outcome = :o WHERE subject = :s"
            " AND subject_id = :i AND done_at IS NULL"
        ),
        {"now": now, "o": outcome, "s": subject, "i": subject_id},
    )


async def outcomes(
    conn: AsyncConnection, subject: str, subject_id: int, sent_count: int
) -> list[str]:
    rows = await conn.execute(
        text(
            "SELECT outcome FROM kibana_lookups WHERE subject = :s AND subject_id = :i"
            " AND sent_count = :n AND done_at IS NOT NULL ORDER BY attempt"
        ),
        {"s": subject, "i": subject_id, "n": sent_count},
    )
    return [str(o) for o in rows.scalars()]


# --------------------------------------------------------------------------- resends


async def complete_requests(
    conn: AsyncConnection, kind: str, *, outbox_id: int | None = None
) -> list[int]:
    """Requests of ``kind`` (for the outbox row) that are complete and unexpired on the
    database's clock: no rejection and enough approvals. (Signatures and the approvers still
    standing are the writer's own check.)"""
    rows = await conn.execute(
        text(
            "SELECT r.id FROM approval_requests r WHERE r.kind = :k"
            " AND (CAST(:o AS bigint) IS NULL OR r.outbox_id = CAST(:o AS bigint))"
            " AND clock_timestamp() <= r.expires_at"
            " AND NOT EXISTS (SELECT 1 FROM approval_decisions d WHERE d.request_id = r.id"
            "                 AND d.decision = 'rejected')"
            " AND (SELECT count(*) FROM approval_decisions d WHERE d.request_id = r.id"
            "      AND d.decision = 'approved') >= r.required_approvals ORDER BY r.id"
        ),
        {"k": kind, "o": outbox_id},
    )
    return [int(i) for i in rows.scalars()]


# --------------------------------------------------------------------------- runs and the ramp


async def record_run(
    conn: AsyncConnection,
    write_class: str,
    kind: str,
    step: int,
    by: str,
    started: datetime,
    finished: datetime,
    *,
    units: int,
    sent: int,
    verified: int,
    mismatches: int,
    ambiguous: int,
    stopped: str | None,
) -> None:
    """One run, written once when it ends (the writer may insert a run, never change one)."""
    await conn.execute(
        text(
            "INSERT INTO kibana_writer_runs (write_class, kind, step, started_at, finished_at,"
            " units, sent, verified, mismatches, ambiguous, stopped, \"by\") VALUES (:c, :k, :s,"
            " :t0, :t1, :u, :n, :v, :m, :a, :st, :by)"
        ),
        {"c": write_class, "k": kind, "s": step, "t0": started, "t1": finished, "u": units,
         "n": sent, "v": verified, "m": mismatches, "a": ambiguous,
         "st": None if stopped is None else stopped[:300], "by": by},
    )  # fmt: skip


async def ramp_step(conn: AsyncConnection, write_class: str) -> int:
    step = (
        await conn.execute(
            text("SELECT step FROM kibana_writer_ramp WHERE write_class = :c"), {"c": write_class}
        )
    ).scalar_one_or_none()
    return 1 if step is None else int(step)


async def prior_state(conn: AsyncConnection, row: plan.Row) -> tuple[str, str | None] | None:
    """The state and reason of the row just before this one in its case event (a comment
    explains the change before it)."""
    found = (
        await conn.execute(
            text(
                "SELECT state, state_reason FROM kibana_outbox WHERE case_event_id = :e"
                " AND position < :p ORDER BY position DESC LIMIT 1"
            ),
            {"e": row.case_event_id, "p": row.position},
        )
    ).first()
    return None if found is None else (found.state, found.state_reason)


async def finding_sync_on(
    conn: AsyncConnection, case_id: uuid.UUID, kibana_case_id: str, version: str, now: datetime
) -> None:
    """Needs attention: Sync alerts is on in Kibana (the same finding the read-back raises)."""
    await conn.execute(
        text(
            "INSERT INTO kibana_findings (found_at, kind, severity, kibana_case_id, case_id,"
            " dedupe_key, details) VALUES (:now, 'settings_changed', 'attention', :k, :c, :key,"
            " CAST(:d AS jsonb)) ON CONFLICT (dedupe_key) DO NOTHING"
        ),
        {
            "now": now,
            "k": kibana_case_id,
            "c": case_id,
            "key": f"sync-on:{kibana_case_id}:{version}",
            "d": json.dumps({"sync_alerts": True, "found_by": "the writer"}),
        },
    )


async def finding_attention(
    conn: AsyncConnection,
    kind: str,
    case_id: uuid.UUID,
    kibana_case_id: str | None,
    key: str,
    details: Mapping[str, Any],
    now: datetime,
) -> None:
    """A finding of the writer's (``answer_unexpected`` or ``duplicate_case``), once per key."""
    severity = "attention"
    await conn.execute(
        text(
            "INSERT INTO kibana_findings (found_at, kind, severity, kibana_case_id, case_id,"
            " dedupe_key, details) VALUES (:now, :kind, :sev, :k, :c, :key, CAST(:d AS jsonb))"
            " ON CONFLICT (dedupe_key) DO NOTHING"
        ),
        {
            "now": now,
            "kind": kind,
            "sev": severity,
            "k": kibana_case_id,
            "c": case_id,
            "key": key[:400],
            "d": json.dumps(dict(details), default=str),
        },
    )
