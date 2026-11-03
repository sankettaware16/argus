"""Approval requests and decisions (plan §7.1, §7.9): only through migration 0026's functions,
which ``argus_approvals`` may call and ARGUS's runtime role may not.

The approver is the user of a live web session, never a parameter: the caller hands in the
session's raw token and the database hashes it (the stored hashes are readable, so they prove
nothing), and a session idle for more than 12 hours is refused. A person cannot approve their
own request; two different people for ``remediated_unverified`` and ``risk_accepted``; nobody
approves twice; racing approvers get one success and a conflict. Every request and decision is
in the audit trail's hash chain, written by the same functions. The alert set an approval
covers is the database's own count and digest of the case's alerts (:func:`alert_digest`), so
a case of any size can be closed.

Q-C3 (migration 0030): a decision needs the session's step-up within 5 minutes, a live check of
the approver at most 30 seconds old and the web's signature over its statement
(:func:`statement`), all stored with it; only approvals of people not revoked since count.
ARGUS proposes closures and asks for re-confirmations (:func:`propose`), never approves.
"""

from __future__ import annotations

import hashlib
import json
import math
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta
from typing import Any, Literal

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.cases.model import TWO_PERSON_REASONS, ApprovalFacts, Reason
from argus.cases.signing import STATEMENT_VERSION, iso

Decision = Literal["approved", "rejected"]
Status = Literal["approved", "rejected", "pending"]
STEP_UP_VALID = timedelta(minutes=5)  # plan §7.1: a step-up of the same session within 5 minutes
CHECK_FRESH = timedelta(seconds=30)  # plan §7.2: a change waits for a check at most 30 s old
GROUP_LIMIT = 20  # plan §7.1: benign, false-positive and no-impact closures, ≤ 20 a group
GROUP_REASONS: frozenset[str] = frozenset(
    {"attempt_no_impact", "rule_false_positive", "benign_expected", "benign_policy"}
)
# What ARGUS itself may propose (each with positive evidence; plan §7.1's closure table). A case
# whose owner was told and that went quiet is proposed as "stopped after notice" (D-169).
PROPOSE_REASONS: frozenset[str] = frozenset(
    {"remediated_verified", "stopped_after_notice", *GROUP_REASONS}
)
# An approval counts only while its approver is not revoked since they gave it (0030): the
# account enabled and no identity check denied them afterwards. ``d`` is approval_decisions.
NOT_REVOKED = (
    "NOT EXISTS (SELECT 1 FROM users u WHERE u.id = d.approver_user_id AND u.disabled)"
    " AND NOT EXISTS (SELECT 1 FROM identity_checks c WHERE c.user_id = d.approver_user_id"
    " AND c.outcome = 'denied' AND c.recorded_at >= d.decided_at)"
)
# DQ8 (a), D-110: Kibana writes happen daily 02:30-17:30 UTC (08:00-23:00 IST).
WRITE_WINDOW = (time(2, 30, tzinfo=UTC), time(17, 30, tzinfo=UTC))
MAX_VALIDITY = timedelta(hours=72)
_CODES = {
    "QC401": 401,
    "QC403": 403,
    "QC404": 404,
    "QC409": 409,
    "QC410": 410,
    "QC412": 403,  # a step-up within 5 minutes first
    "QC422": 422,
    "42501": 403,  # permission denied: this login may not record approvals
}
_KINDS = {"QC412": "step_up_required"}


class ApprovalError(Exception):
    """The database refused the request or decision; ``status`` is the HTTP answer and
    ``code`` says why when it is more than the status (``step_up_required``)."""

    def __init__(self, status: int, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.code = code

    @classmethod
    def from_db(cls, exc: DBAPIError) -> ApprovalError | None:
        code = getattr(exc.orig, "sqlstate", None)
        if code not in _CODES:
            return None
        primary = getattr(getattr(exc.orig, "diag", None), "message_primary", None)
        message = primary or "refused"
        if code == "42501":
            message = "this database login may not record approvals"
        return cls(_CODES[code], message, _KINDS.get(code))


def alert_digest(alert_ids: Iterable[str]) -> str:
    """The alert set as the database binds it to an approval: sha256 of the distinct ids,
    sorted by code point, one per line (Q-C3 compares it again at send time)."""
    return hashlib.sha256("\n".join(sorted(set(alert_ids))).encode()).hexdigest()


def required_approvals(reason: Reason | None) -> int:
    return 2 if reason in TWO_PERSON_REASONS else 1


def expires_at(now: datetime) -> datetime:
    """The end of the first write window that starts after ``now`` (DQ12 (a)): an evening
    approval goes out the next day; never more than 72 hours."""
    start, end = WRITE_WINDOW
    day = now.astimezone(UTC).date()
    for offset in range(4):
        candidate = datetime.combine(day + timedelta(days=offset), start)
        if candidate > now:
            return min(datetime.combine(candidate.date(), end), now + MAX_VALIDITY)
    raise AssertionError("a write window starts every day")  # pragma: no cover


async def _call(conn: AsyncConnection, sql: str, params: dict[str, Any]) -> Any:
    try:
        return (await conn.execute(text(sql), params)).scalar_one()
    except DBAPIError as exc:
        mapped = ApprovalError.from_db(exc)
        if mapped is None:
            raise
        raise mapped from None


async def request(
    conn: AsyncConnection,
    *,
    session_token: str,
    case_id: uuid.UUID,
    case_version: int,
    kind: str,
    reason: Reason | None,
    payload: dict[str, Any],
    payload_hash: str,
    expires: datetime,
    check: dict[str, Any],
    target_case_id: uuid.UUID | None = None,
    outbox_id: int | None = None,
    kibana_version: str | None = None,
    note: str | None = None,
) -> int:
    """A request (closure, merge, compensating write, or a resend of an outbox row in doubt),
    in the name of the session's person, with the web's live check of them (``check``, a
    :meth:`argus.cases.identity.LiveCheck.snapshot` at most 30 seconds old: the database stores
    it with the request, so their second account cannot approve it); the database binds it to
    the case's alerts now."""
    request_id: int = await _call(
        conn,
        "SELECT argus_approval_request(:s, :c, :v, :k, :r, :t, :o, CAST(:p AS jsonb), :h, :kv,"
        " :e, :n, CAST(:q AS jsonb))",
        {"s": session_token, "c": case_id, "v": case_version, "k": kind, "r": reason,
         "t": target_case_id, "o": outbox_id, "p": json.dumps(payload), "h": payload_hash,
         "kv": kibana_version, "e": expires, "n": note, "q": json.dumps(check)},
    )  # fmt: skip
    return request_id


@dataclass(frozen=True)
class Signed:
    """What the web adds to a decision (Q-C3): the session's step-up it relied on, its live
    check of the approver (:meth:`argus.cases.identity.LiveCheck.snapshot`), its signature over
    the decision's :func:`statement`, and the group with its sample, if any."""

    stepped_up_at: datetime
    check: dict[str, Any]
    signature: str
    batch: dict[str, Any] | None = None


async def decide(
    conn: AsyncConnection,
    *,
    session_token: str,
    request_id: int,
    decision: Decision,
    signed: Signed,
    note: str | None = None,
) -> Status:
    status: Status = await _call(
        conn,
        "SELECT argus_approval_decide(:s, :r, :d, :n, :t, CAST(:c AS jsonb), :g,"
        " CAST(:b AS jsonb))",
        {"s": session_token, "r": request_id, "d": decision, "n": note,
         "t": signed.stepped_up_at, "c": json.dumps(signed.check), "g": signed.signature,
         "b": None if signed.batch is None else json.dumps(signed.batch)},
    )  # fmt: skip
    return status


async def propose(
    conn: AsyncConnection,
    *,
    proposer: str,
    case_id: uuid.UUID,
    case_version: int,
    kind: Literal["closure", "reconfirm"],
    payload: dict[str, Any],
    payload_hash: str,
    expires: datetime,
    reason: Reason | None = None,
    outbox_id: int | None = None,
    kibana_version: str | None = None,
    note: str | None = None,
) -> int:
    """ARGUS's own request (the runtime role may call it): a closure it proposes after its
    request event, or a re-confirmation of a held-back closure write. A person approves it."""
    request_id: int = await _call(
        conn,
        "SELECT argus_approval_propose(:w, :c, :v, :k, :r, :o, CAST(:p AS jsonb), :h, :kv, :e,"
        " :n)",
        {"w": proposer, "c": case_id, "v": case_version, "k": kind, "r": reason, "o": outbox_id,
         "p": json.dumps(payload), "h": payload_hash, "kv": kibana_version, "e": expires,
         "n": note},
    )  # fmt: skip
    return request_id


@dataclass(frozen=True)
class RequestRecord:
    """An approval request as the database holds it (everything a statement binds)."""

    id: int
    case_id: uuid.UUID
    case_version: int
    kind: str
    reason: str | None
    target_case_id: uuid.UUID | None
    outbox_id: int | None
    outbox_sent_count: int | None
    payload: dict[str, Any]
    payload_hash: str
    alert_count: int
    alert_digest: str
    kibana_version: str | None
    required: int
    requested_by_user_id: int | None
    proposed_by: str | None
    requested_at: datetime
    expires_at: datetime
    requester_check: dict[str, Any] | None = None  # the requester's live check (0030)


@dataclass(frozen=True)
class DecisionRecord:
    id: int
    request_id: int
    approver_user_id: int
    decision: str
    capabilities: list[Any]
    stepped_up_at: datetime | None
    identity_check: dict[str, Any] | None
    signature: str | None
    batch: dict[str, Any] | None
    decided_at: datetime


_REQUEST_COLUMNS = (
    "id, case_id, case_version, kind, reason, target_case_id, outbox_id, outbox_sent_count,"
    " payload, payload_hash, alert_count, alert_digest, kibana_version, required_approvals,"
    " requested_by_user_id, proposed_by, requested_at, expires_at, requester_check"
)


def _request(row: Any) -> RequestRecord:
    return RequestRecord(
        int(row.id), row.case_id, int(row.case_version), str(row.kind), row.reason,
        row.target_case_id, row.outbox_id, row.outbox_sent_count, dict(row.payload),
        str(row.payload_hash), int(row.alert_count), str(row.alert_digest), row.kibana_version,
        int(row.required_approvals), row.requested_by_user_id, row.proposed_by,
        row.requested_at, row.expires_at, row.requester_check,
    )  # fmt: skip


async def record(conn: AsyncConnection, request_id: int) -> RequestRecord | None:
    row = (
        await conn.execute(
            text(f"SELECT {_REQUEST_COLUMNS} FROM approval_requests WHERE id = :id"),  # noqa: S608 - constant columns
            {"id": request_id},
        )
    ).first()
    return None if row is None else _request(row)


async def reconfirmations(conn: AsyncConnection, case_event_id: int) -> list[RequestRecord]:
    """The re-confirmation requests of one closure's writes (the closing change and its comment
    are re-confirmed together), newest first."""
    rows = await conn.execute(
        text(
            f"SELECT {_REQUEST_COLUMNS} FROM approval_requests"  # noqa: S608 - constant columns
            " WHERE kind = 'reconfirm' AND outbox_id IN (SELECT o.id FROM kibana_outbox o"
            " WHERE o.case_event_id = :e AND o.write_class = 'W3') ORDER BY id DESC"
        ),
        {"e": case_event_id},
    )
    return [_request(row) for row in rows.all()]


async def decisions(conn: AsyncConnection, request_id: int) -> list[DecisionRecord]:
    rows = await conn.execute(
        text(
            "SELECT id, request_id, approver_user_id, decision, capabilities, stepped_up_at,"
            " identity_check, signature, batch, decided_at FROM approval_decisions"
            " WHERE request_id = :r ORDER BY id"
        ),
        {"r": request_id},
    )
    return [
        DecisionRecord(
            int(r.id),
            int(r.request_id),
            int(r.approver_user_id),
            str(r.decision),
            list(r.capabilities),
            r.stepped_up_at,
            r.identity_check,
            r.signature,
            r.batch,
            r.decided_at,
        )
        for r in rows.all()
    ]


def statement(
    request: RequestRecord,
    *,
    approver_user_id: int,
    decision: str,
    stepped_up_at: datetime,
    check: dict[str, Any],
    batch: dict[str, Any] | None,
    capabilities: list[Any] | None = None,
) -> dict[str, Any]:
    """What a decision's signature covers: the request it decides (everything it binds) and the
    decision with its step-up, live check (whose capabilities the database stores as the
    decision's) and group. The web builds it before recording the decision; the writer
    rebuilds it from the stored rows."""
    return {
        "v": STATEMENT_VERSION,
        "act": "decision",
        "request": {
            "id": request.id,
            "case": str(request.case_id),
            "case_version": request.case_version,
            "kind": request.kind,
            "reason": request.reason,
            "target": None if request.target_case_id is None else str(request.target_case_id),
            "outbox": request.outbox_id,
            "outbox_sent_count": request.outbox_sent_count,
            "payload_hash": request.payload_hash,
            "alert_count": request.alert_count,
            "alert_digest": request.alert_digest,
            "kibana_version": request.kibana_version,
            "required": request.required,
            "requested_by": request.requested_by_user_id,
            "requester_check": request.requester_check,
            "proposed_by": request.proposed_by,
            "expires_at": iso(request.expires_at),
        },
        "approver": approver_user_id,
        "decision": decision,
        "capabilities": check.get("capabilities") if capabilities is None else capabilities,
        "stepped_up_at": iso(stepped_up_at),
        "check": check,
        "batch": batch,
    }


def stored_statement(request: RequestRecord, row: DecisionRecord) -> dict[str, Any] | None:
    """A stored decision's statement, rebuilt from its rows (None: it has nothing to sign)."""
    if row.stepped_up_at is None or row.identity_check is None:
        return None
    return statement(
        request,
        approver_user_id=row.approver_user_id,
        decision=row.decision,
        stepped_up_at=row.stepped_up_at,
        check=row.identity_check,
        batch=row.batch,
        capabilities=row.capabilities,
    )


def sample_size(n: int) -> int:
    """A group's sample, approved one by one first: max(3, 10 %), never more than the group."""
    return min(n, max(3, math.ceil(n / 10)))


def sample(request_ids: Iterable[int], seed: str) -> list[int]:
    """Which of a group's requests make its sample: a fixed choice for the group (the order of
    sha256(seed, id)), so reloading the page shows the same items."""
    ids = sorted(set(request_ids))
    ranked = sorted(ids, key=lambda i: hashlib.sha256(f"{seed}:{i}".encode()).hexdigest())
    return sorted(ranked[: sample_size(len(ids))])


def group(request_ids: Iterable[int], seed: str) -> dict[str, Any]:
    """The batch a group approval carries (stored and signed with each of its decisions)."""
    ids = sorted(set(request_ids))
    if not 2 <= len(ids) <= GROUP_LIMIT:
        raise ApprovalError(422, f"a group holds 2 to {GROUP_LIMIT} requests")
    return {"requests": ids, "sample": sample(ids, seed)}


async def facts(conn: AsyncConnection, request_id: int) -> ApprovalFacts | None:
    row = (
        await conn.execute(
            text(
                "SELECT r.id, r.case_id, r.case_version, r.kind, r.reason, r.target_case_id,"  # noqa: S608 - constant fragments; values are bound
                " r.required_approvals, r.expires_at, r.requested_by_user_id, r.proposed_by,"
                f" count(d.id) FILTER (WHERE d.decision = 'approved' AND {NOT_REVOKED})"
                " AS approved,"
                " count(d.id) FILTER (WHERE d.decision = 'rejected') AS rejected,"
                " coalesce(array_agg(d.approver_user_id ORDER BY d.id)"
                f"   FILTER (WHERE d.decision = 'approved' AND {NOT_REVOKED}), '{{}}')"
                " AS approvers"
                " FROM approval_requests r LEFT JOIN approval_decisions d ON d.request_id = r.id"
                " WHERE r.id = :id GROUP BY r.id"
            ),
            {"id": request_id},
        )
    ).first()
    if row is None:
        return None
    return ApprovalFacts(
        request_id=int(row.id),
        case_id=row.case_id,
        case_version=int(row.case_version),
        kind=str(row.kind),
        reason=row.reason,
        target_case_id=row.target_case_id,
        required=int(row.required_approvals),
        approved=int(row.approved),
        rejected=int(row.rejected),
        expires_at=row.expires_at,
        requested_by_user_id=None
        if row.requested_by_user_id is None
        else int(row.requested_by_user_id),
        approvers=tuple(int(a) for a in row.approvers),
        proposed_by=row.proposed_by,
    )


async def payload_of(conn: AsyncConnection, request_id: int) -> tuple[dict[str, Any], str]:
    row = (
        await conn.execute(
            text("SELECT payload, payload_hash FROM approval_requests WHERE id = :id"),
            {"id": request_id},
        )
    ).one()
    return dict(row.payload), str(row.payload_hash)
