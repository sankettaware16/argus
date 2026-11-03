"""Whether an approval still stands when the writer is about to act on it.

The send-time check of a closure write is :mod:`argus.cases.sendcheck`. A resend of a write in
doubt and a compensating write have approvals of their own, checked the same way: every approving
decision carries the web's valid signature, the approver is not revoked since and had a good live
check within 12 hours that still shows ``approve`` and the Kibana privilege the write needs, is not
the person who asked, and two approvals are two different people."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.cases import approvals, identity
from argus.cases.approvals import DecisionRecord, RequestRecord
from argus.cases.sendcheck import LIVE_CHECK_BOUND, _requester_marks
from argus.cases.signing import Verifier

CREATE_CASE, CREATE_COMMENT = "createCase", "createComment"


def privilege_for(op: str, write_class: str) -> str:
    """The Kibana privilege an approver must hold for a write: ``createCase`` for a
    create, ``createComment`` for another W1 write, ``updateCase`` for W2 and W3."""
    if write_class == "W1":
        return CREATE_CASE if op == "create" else CREATE_COMMENT
    return identity.UPDATE_CASE


async def problem(
    conn: AsyncConnection,
    request: RequestRecord,
    verifier: Verifier | None,
    privilege: str,
    *,
    now: datetime | None = None,
) -> str | None:
    """Why the request cannot be acted on now, or None."""
    now = now or await identity.database_clock(conn)
    if verifier is None:
        return "no approval key is configured: signatures cannot be checked"
    if now > request.expires_at:
        return "it expired"
    found = await approvals.decisions(conn, request.id)
    if any(d.decision == "rejected" for d in found):
        return "it was rejected"
    counted: list[DecisionRecord] = []
    requester = await _requester_marks(conn, request)
    asked = False
    for decision in (d for d in found if d.decision == "approved"):
        statement = approvals.stored_statement(request, decision)
        if statement is None or not verifier.verify(statement, decision.signature):
            return f"tampered: decision {decision.id} has no valid signature"
        snapshot = decision.identity_check or {}
        if "approve" not in decision.capabilities or privilege not in snapshot.get("kibana", []):
            return f"tampered: decision {decision.id} was made without the needed privileges"
        if any(identity.same_person(snapshot, mark) for mark in requester):
            asked = True  # whoever asked cannot approve: not under another account either
            continue
        if await _doubt(conn, decision, now, privilege) is not None:
            continue
        if any(identity.same_person(snapshot, c.identity_check or {}) for c in counted):
            continue  # one person behind two accounts counts once
        counted.append(decision)
    if len(counted) < request.required:
        who = " (the person who asked is one of them)" if asked else ""
        return f"{len(counted)} of {request.required} approvals still hold{who}"
    return None


async def _doubt(
    conn: AsyncConnection, decision: DecisionRecord, now: datetime, privilege: str
) -> str | None:
    """Why this approver no longer counts, or None (as in the send-time check, for the privilege
    this write needs)."""
    provider = (decision.identity_check or {}).get("provider")
    row = (
        await conn.execute(
            text(
                "SELECT u.disabled,"
                " EXISTS (SELECT 1 FROM identity_checks c WHERE c.user_id = u.id"
                "   AND c.outcome = 'denied' AND c.recorded_at >= :since) AS denied,"
                " (SELECT max(c.recorded_at) FROM identity_checks c WHERE c.user_id = u.id"
                "   AND c.outcome = 'ok' AND c.provider = :p) AS good_at,"
                " (SELECT c.snapshot FROM identity_checks c WHERE c.user_id = u.id"
                "   AND c.provider = :p ORDER BY c.recorded_at DESC, c.id DESC LIMIT 1) AS newest"
                " FROM users u WHERE u.id = :u"
            ),
            {"u": decision.approver_user_id, "since": decision.decided_at, "p": provider},
        )
    ).one()
    who = f"user:{decision.approver_user_id}"
    if row.disabled or row.denied:
        return f"{who} was revoked after approving"
    if row.good_at is None or now - row.good_at > LIVE_CHECK_BOUND:
        return f"{who} has had no good live check within 12 hours"
    newest = row.newest or {}
    if "approve" not in newest.get("capabilities", []) or privilege not in newest.get("kibana", []):
        return f"{who} no longer holds the approver capability or {privilege}"
    return None
