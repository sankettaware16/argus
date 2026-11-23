# ruff: noqa: S608 - the f-strings put a fixed condition (_OWN) in the SQL
"""Write-back: people's decisions as alert status changes in Kibana. This module plans and shows;
``argus.writeback_sender`` sends. ``plan`` turns each investigation's newest decision and each
approved case closure into one outbox row for the alerts the reviewer saw whose state differs
(benign, policy or false positive closes; true positive or follow-up acknowledges); an older
unsent row is superseded. Only reviews made under an ELK check that showed the alert-status
privileges may reach Kibana; ``plan(older=True)`` adds earlier ones (an operator sends those).
With ``own`` (``writeback.own_accounts``, D-336) a person's decision made in one of ARGUS's own
accounts counts as well, and a person's dismissal of a possible incident closes its alerts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.asyncio import AsyncConnection
from sqlalchemy.types import Text

TARGET = {
    "benign_expected": "closed",
    "benign_policy": "closed",
    "rule_false_positive": "closed",
    "true_positive": "acknowledged",
}
# An approved closure closes its alerts unless it says nothing about them: a duplicate (the
# alerts are in the other case) or a case made in error.
CLOSURE_CLOSES = frozenset(
    {
        "remediated_verified",
        "remediated_unverified",
        "risk_accepted",
        "attempt_no_impact",
        "rule_false_positive",
        "benign_expected",
        "benign_policy",
        "stopped_after_notice",
    }
)
# A dismissed possible incident closes its alerts for the same reasons (D-336).
DISMISSAL_CLOSES = frozenset(
    {"rule_false_positive", "benign_expected", "benign_policy", "attempt_no_impact"}
)
BENIGN = frozenset(
    {"benign_expected", "benign_policy"}
)  # the verdicts a freshness zero could carry
# A person may undo their own dismissal for 15 minutes (``argus.web.decisions.UNDO_WINDOW``): a
# dismissal is planned, and sent, only once that has passed (an alert closed in Kibana is not
# reopened by an undo).
DISMISSAL_SETTLES = timedelta(minutes=15)
# ARGUS's own account, in use: not an ELK person's, not disabled, not replaced (frozen).
_OWN = "(u.realm = 'local' AND u.elk_username IS NULL AND NOT u.disabled AND u.frozen_at IS NULL)"
F1_HOLD = "f1_zeros"
FIRST_RUN = 5  # alerts written while nothing was ever written, with a person present


class WritebackRefused(Exception):  # noqa: N818
    pass


def _target(action: str, outcome: str | None) -> str | None:
    return "acknowledged" if action == "follow_up" else TARGET.get(outcome or "")


# a freshness "nothing found" in force (mode on, a verified zero) behind a verdict
_F1_REVIEW = (
    "SELECT EXISTS (SELECT 1 FROM freshness_shadow f WHERE f.investigation_id = :i"
    " AND f.mode = 'on' AND f.verdict = 'known_zero')"
)
_F1_CASE = (
    "SELECT EXISTS (SELECT 1 FROM case_members m JOIN freshness_shadow f"
    " ON f.investigation_id = m.investigation_id WHERE m.case_id = :c AND m.removed_at IS NULL"
    " AND f.mode = 'on' AND f.verdict = 'known_zero')"
)


async def plan(
    conn: AsyncConnection, *, older: bool = False, own: bool = False, at: datetime | None = None
) -> int:
    """Outbox rows for the decisions not planned yet. Returns how many were added. ``older``:
    also plan a person's reviews that were not made under an alert-write check, as rows that need
    an operator. ``own``: plan those made in ARGUS's own accounts, and people's dismissals, as
    rows that need none. ``at``: the time a dismissal's undo window is measured at (the
    database's clock unless given)."""
    latest = await conn.execute(
        text(
            "SELECT DISTINCT ON (e.investigation_id) e.id, e.investigation_id, e.action,"
            f" e.outcome, e.created_at, e.kibana_ok, u.kind, {_OWN} AS own FROM review_events e"
            " JOIN users u ON u.id = e.user_id"
            " WHERE e.action = 'follow_up' OR (e.action = 'reviewed' AND e.outcome IS NOT NULL)"
            " ORDER BY e.investigation_id, e.id DESC"
        )
    )
    added = 0
    for review in latest.all():
        await conn.execute(  # an older decision not sent yet is superseded
            text(
                "UPDATE writeback_outbox SET state = 'skipped', error = 'superseded by review '"
                " || :r WHERE investigation_id = :i AND review_id < :r"
                " AND state IN ('planned', 'paused')"
            ),
            {"r": review.id, "i": review.investigation_id},
        )
        # a review made under an ELK check that showed the alert-status privileges (and in a
        # verified session) may reach Kibana; an earlier person's review only through an
        # operator; a newer one that may not still supersedes, so Kibana is never told an older
        # verdict is the last word
        status = _target(review.action, review.outcome)
        if review.kind != "person" or not (review.kibana_ok or older or (own and review.own)):
            status = None
        planned = (
            await conn.execute(
                text("SELECT 1 FROM writeback_outbox WHERE review_id = :r"), {"r": review.id}
            )
        ).first()
        if status is None or planned is not None:
            continue
        ids = await _alerts(conn, review.investigation_id, status, review.created_at)
        if not ids:
            continue
        await conn.execute(
            text(
                "INSERT INTO writeback_outbox (review_id, investigation_id, status, alert_ids)"
                " VALUES (:r, :i, :s, :a) ON CONFLICT (review_id) DO NOTHING"
            ).bindparams(bindparam("a", type_=ARRAY(Text))),
            {"r": review.id, "i": review.investigation_id, "s": status, "a": list(ids)},
        )
        added += 1
    added += await _plan_closures(conn)
    return added + (await _plan_dismissals(conn, at) if older or own else 0)


async def _alerts(
    conn: AsyncConnection, investigation_id: Any, status: str, seen: Any
) -> list[str]:
    """The investigation's alerts the reviewer saw whose state differs and still exist."""
    return list(
        (
            await conn.execute(
                text(
                    "SELECT a.alert_id FROM investigation_alerts l JOIN alert_records a"
                    " ON a.alert_id = l.alert_id WHERE l.investigation_id = :i"
                    " AND l.linked_at <= :seen"  # the alerts the reviewer saw
                    " AND coalesce(a.workflow_status, 'open') <> :s"
                    " AND a.source_missing_at IS NULL"
                    " ORDER BY a.alert_id"
                ),
                {"i": investigation_id, "s": status, "seen": seen},
            )
        )
        .scalars()
        .all()
    )


async def _plan_closures(conn: AsyncConnection) -> int:
    """A row for each approved closure that closes its alerts; a row not sent yet whose case was
    reopened (or closed again by another approval) is superseded."""
    await conn.execute(
        text(
            "UPDATE writeback_outbox w SET state = 'skipped', error = 'the case was reopened'"
            " WHERE w.closure_request_id IS NOT NULL AND w.state IN ('planned', 'paused')"
            " AND NOT EXISTS (SELECT 1 FROM cases c WHERE c.id = w.case_id"
            " AND c.state = 'closed' AND c.closure_request_id = w.closure_request_id)"
        )
    )
    closed = await conn.execute(
        text(
            "SELECT c.id, c.closure_request_id, c.closure_reason, c.closed_at FROM cases c"
            " JOIN approval_requests r ON r.id = c.closure_request_id AND r.kind = 'closure'"
            " WHERE c.state = 'closed' AND c.closure_reason = ANY(:reasons)"
            " AND NOT EXISTS (SELECT 1 FROM writeback_outbox w"
            " WHERE w.closure_request_id = c.closure_request_id) ORDER BY c.closure_request_id"
        ),
        {"reasons": sorted(CLOSURE_CLOSES)},
    )
    added = 0
    for case in closed.all():
        ids = await _case_alerts(conn, case.id, case.closed_at)
        if not ids:
            continue
        await conn.execute(
            text(
                "INSERT INTO writeback_outbox (case_id, closure_request_id, status, alert_ids)"
                " VALUES (:c, :r, 'closed', :a) ON CONFLICT (closure_request_id) DO NOTHING"
            ).bindparams(bindparam("a", type_=ARRAY(Text))),
            {"c": case.id, "r": case.closure_request_id, "a": ids},
        )
        added += 1
    return added


async def _plan_dismissals(conn: AsyncConnection, at: datetime | None) -> int:
    """A row for each possible incident a person dismissed for a reason that closes its alerts,
    once the dismissal can no longer be undone; a row not sent yet whose case was reopened is
    superseded, and a case dismissed again gets a new row unless one still waits (two planners
    at once may add two: the sender finds the second's alerts closed and sends nothing)."""
    reasons = {"reasons": sorted(DISMISSAL_CLOSES)}
    await conn.execute(
        text(
            "UPDATE writeback_outbox w SET state = 'skipped', error = 'the case was reopened'"
            " WHERE w.case_id IS NOT NULL AND w.closure_request_id IS NULL"
            " AND w.state IN ('planned', 'paused')"
            " AND NOT EXISTS (SELECT 1 FROM cases c WHERE c.id = w.case_id"
            " AND c.state = 'closed' AND c.closure_request_id IS NULL"
            " AND c.closure_reason = ANY(:reasons))"
        ),
        reasons,
    )
    dismissed = await conn.execute(
        text(
            # still closed by the dismissal: a reopened case is closed again by an approval
            "SELECT c.id, c.closed_at FROM cases c WHERE c.state = 'closed'"
            " AND c.closure_request_id IS NULL AND c.closure_reason = ANY(:reasons)"
            " AND c.closed_at <= coalesce(CAST(:at AS timestamptz), now()) - :settles"
            " AND EXISTS (SELECT 1 FROM case_events e WHERE e.case_id = c.id"
            " AND e.kind = 'dismissed')"
            " AND NOT EXISTS (SELECT 1 FROM writeback_outbox w WHERE w.case_id = c.id"
            " AND w.closure_request_id IS NULL AND (w.state IN ('planned', 'paused')"
            " OR w.created_at >= c.closed_at))"
            " ORDER BY c.closed_at, c.id"
        ),
        {**reasons, "settles": DISMISSAL_SETTLES, "at": at},
    )
    added = 0
    for case in dismissed.all():
        ids = await _case_alerts(conn, case.id, case.closed_at)
        if not ids:
            continue
        await conn.execute(
            text(
                "INSERT INTO writeback_outbox (case_id, status, alert_ids)"
                " VALUES (:c, 'closed', :a)"
            ).bindparams(bindparam("a", type_=ARRAY(Text))),
            {"c": case.id, "a": ids},
        )
        added += 1
    return added


async def _case_alerts(conn: AsyncConnection, case_id: Any, at: Any) -> list[str]:
    """The alerts of the case's members linked by ``at`` that are not closed and still exist."""
    return list(
        (
            await conn.execute(
                text(
                    "SELECT DISTINCT a.alert_id FROM case_members m"
                    " JOIN investigation_alerts l ON l.investigation_id = m.investigation_id"
                    " JOIN alert_records a ON a.alert_id = l.alert_id"
                    " WHERE m.case_id = :c AND m.removed_at IS NULL AND l.linked_at <= :at"
                    " AND coalesce(a.workflow_status, 'open') <> 'closed'"
                    " AND a.source_missing_at IS NULL ORDER BY a.alert_id"
                ),
                {"c": case_id, "at": at},
            )
        )
        .scalars()
        .all()
    )


@dataclass(frozen=True)
class Standing:
    """What the sources say of an outbox row now (not what its own columns say)."""

    person: bool  # its author is a person (a break-glass or service account never reaches Kibana)
    needs_operator: bool  # made without an alert-write check: only an operator may send it
    held: str | None  # waits for the audit of the freshness answers
    settles_at: datetime | None = None  # a dismissal: when its undo window ends


async def standing(
    conn: AsyncConnection, *, review_id: int | None, investigation_id: Any, case_id: Any,
    dismissed: bool = False, own: bool = False,
) -> Standing | None:  # fmt: skip
    """The row's flags from ``review_events.kibana_ok``, ``users.kind`` and the freshness verdict
    (or the closed case's reason and its investigations' verdicts); None when the decision it was
    made from cannot be found. ``dismissed``: the row is a dismissal's (its author is read from
    the case's event). ``own``: a decision made in one of ARGUS's own accounts needs no operator."""
    if review_id is not None:
        found = (
            await conn.execute(
                text(
                    f"SELECT u.kind, e.kibana_ok, e.outcome, {_OWN} AS own FROM review_events e"
                    " JOIN users u ON u.id = e.user_id WHERE e.id = :r"
                ),
                {"r": review_id},
            )
        ).first()
        if found is None:
            return None
        held = (
            F1_HOLD
            if found.outcome in BENIGN
            and (await conn.execute(text(_F1_REVIEW), {"i": investigation_id})).scalar_one()
            else None
        )
        return Standing(found.kind == "person", not (found.kibana_ok or (own and found.own)), held)
    reason = (
        await conn.execute(
            text("SELECT closure_reason, closed_at FROM cases WHERE id = :c"), {"c": case_id}
        )
    ).first()
    if reason is None:
        return None
    held = (
        F1_HOLD
        if reason.closure_reason in BENIGN
        and (await conn.execute(text(_F1_CASE), {"c": case_id})).scalar_one()
        else None
    )
    if not dismissed:
        return Standing(True, False, held)
    author = (
        await conn.execute(
            text(
                f"SELECT u.kind, {_OWN} AS own FROM case_events e LEFT JOIN users u"
                " ON e.actor = 'user:' || u.id WHERE e.case_id = :c AND e.kind = 'dismissed'"
                " ORDER BY e.case_version DESC LIMIT 1"
            ),
            {"c": case_id},
        )
    ).first()
    if author is None:
        return None
    settles = None if reason.closed_at is None else reason.closed_at + DISMISSAL_SETTLES
    return Standing(author.kind == "person", not (own and bool(author.own)), held, settles)


async def diff(conn: AsyncConnection, *, own: bool = False) -> dict[str, Any]:
    """What a run would change: items and alerts left per target status. Rows that wait for an
    operator or for the freshness audit are counted apart, under ``needs_operator`` and ``held``,
    and a row whose decision or author no longer allows a send under ``unsendable``; the flags
    come from their sources (:func:`standing`)."""
    rows = (
        await conn.execute(
            text(
                "SELECT status, review_id, investigation_id, case_id, closure_request_id,"
                " cardinality(alert_ids) - sent_count AS left_over FROM writeback_outbox"
                " WHERE state IN ('planned', 'paused') ORDER BY id"
            )
        )
    ).all()
    out: dict[str, Any] = {}
    for row in rows:
        now = await standing(
            conn, review_id=row.review_id, investigation_id=row.investigation_id,
            case_id=row.case_id, own=own,
            dismissed=row.review_id is None and row.closure_request_id is None,
        )  # fmt: skip
        if now is None or not now.person:
            key = "unsendable"
        else:
            key = "held" if now.held else "needs_operator" if now.needs_operator else row.status
        slot = out.setdefault(key, {"reviews": 0, "alerts": 0})
        slot["reviews"] += 1
        slot["alerts"] += int(row.left_over)
    return out


def refuse_unless_ready(
    enabled: bool, writer_key: object | None, confirmed: bool, *, terminal: bool = True
) -> None:
    """The conditions of a real run, each with its own reason."""
    if not enabled:
        raise WritebackRefused("writeback.enabled is false (D-061: the user switches it on)")
    secret = getattr(writer_key, "get_secret_value", None)
    if writer_key is None or (secret is not None and not secret()) or writer_key == "":
        raise WritebackRefused("no writer key: kibana.alert_writer_api_key is not configured")
    if not terminal:
        raise WritebackRefused("a real run needs a person at a terminal (stdin is not one)")
    if not confirmed:
        raise WritebackRefused("a person must confirm a real run at the terminal")
