"""Send-time checks (plan §7.1, §3 rules 4, 6 and 7): before a closure write (W3) leaves ARGUS,
``argus-writer`` checks again everything its approval was bound to, and sends nothing on a
doubt.

:func:`check` decides one outbox row, reading only the database:

* **versions**: the case is still closed by this approval at the closure's version (a reopen
  in between skips the write); the Kibana case's version is the one the approval saw (else
  "re-confirm"); the closing comment waits for the closing change to be verified;
* **payload**: the row's payload has its hash, the approval's payload has its hash, and the
  row is exactly the write the approval named at its position;
* **alert set**: the case's alerts (as of its closure) are the ones the approval covered;
* **expiry**: the approval has not expired (else "re-confirm", counted as expired unsent);
* **signatures**: every approving decision carries the web's valid signature over its stored
  statement (anything else is tampering: refused, paused, never sent);
* **approvers**: each counts only while not revoked since they approved (account enabled, no
  denied check), with a good live check within :data:`LIVE_CHECK_BOUND` (DQ12) from the
  provider that checked them for the approval, whose newest check still shows ``approve`` and
  Kibana's ``updateCase``; two people are two different persons (accounts, ``argus_uid``s and
  e-mail addresses), and none is the person who asked for the closure (their bound check or
  any good check of theirs naming the same ``argus_uid`` or e-mail address);
* Kibana's "Sync alerts" is off on the case (plan §7.1).

A person who rejects the re-confirmation of a write decides that it is not sent: it is
skipped (the case stays closed in ARGUS; reopening it is a person's action).

When the closure's own approval no longer holds, a person's **re-confirmation** of this write
(an approval request ARGUS asks for, bound to the case's alerts and Kibana version then) does.

:func:`release` applies a verdict to the row, through ``argus_closure_write_move()`` (the
runtime holds no UPDATE on the outbox; each move is audited): ``send`` moves it to
``approved``; ``reconfirm`` pauses it (``re-confirm: ...``) and asks for a re-confirmation;
``refuse`` pauses it (``refused: ...``) for a person: it is never let go again, and only a
change of its case skips it; ``skip`` skips it; ``wait`` leaves it. A closure write paused by
anything else waits for a person the same way. The writer (Q-D4) calls :func:`admit` in the
transaction that moves an approved row to ``sending`` and sends only on ``send``, so a
revocation between the release and the request still stops it. The database's outbox guard
refuses a closure write leaving for ``approved`` or ``sending`` without a complete, unexpired,
signed approval whatever code runs (migration 0030).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.cases import approvals, closure, identity, kibana
from argus.cases.approvals import DecisionRecord, RequestRecord
from argus.cases.signing import Verifier

LIVE_CHECK_BOUND = timedelta(hours=12)  # DQ12 as D-110 answered it
PROPOSER = "argus:sendcheck"
Verdict = Literal["send", "wait", "reconfirm", "refuse", "skip"]
_HELD = ("planned", "approved", "paused")  # rows a check may still let go or hold back
RECONFIRM = "re-confirm: "  # a hold this check made, which it may lift
REFUSED = "refused: "  # a refusal, which waits for a person


@dataclass(frozen=True)
class SendCheck:
    outbox_id: int
    verdict: Verdict
    reasons: tuple[str, ...] = ()
    basis: int | None = None  # the approval request that allows sending
    expired_unsent: bool = False  # the closure's approval expired before the write was sent

    @property
    def summary(self) -> str:
        said = "; ".join(self.reasons) if self.reasons else "all checks hold"
        return f"{self.verdict}: {said}"


@dataclass
class _Basis:
    request: RequestRecord
    tamper: list[str] = field(default_factory=list)
    doubts: list[str] = field(default_factory=list)


async def check(
    conn: AsyncConnection, outbox_id: int, verifier: Verifier, *, now: datetime | None = None
) -> SendCheck:
    """Whether closure write ``outbox_id`` may be sent now (see the module's list)."""
    now = now or await identity.database_clock(conn)
    row = (
        await conn.execute(
            text(
                "SELECT o.id, o.case_id, o.case_event_id, o.position, o.write_class, o.op,"
                " o.payload, o.payload_hash, o.approval_request_id, o.state, o.state_reason,"
                " o.sent_count,"
                " e.case_version AS event_version, k.state AS case_state,"
                " k.version AS case_version, k.closure_request_id"
                " FROM kibana_outbox o JOIN case_events e ON e.id = o.case_event_id"
                " JOIN cases k ON k.id = o.case_id WHERE o.id = :id"
            ),
            {"id": outbox_id},
        )
    ).first()
    if row is None:
        return SendCheck(outbox_id, "refuse", ("no such outbox row",))
    if row.write_class != "W3" or row.approval_request_id is None:
        return SendCheck(outbox_id, "refuse", ("not a closure write",))
    if row.state not in _HELD:
        return SendCheck(outbox_id, "wait", (f"the row is {row.state}",))
    if (
        row.case_state != "closed"
        or row.case_version != row.event_version
        or row.closure_request_id != row.approval_request_id
    ):
        return SendCheck(
            outbox_id, "skip", ("the case changed after this closure (reopened?): nothing to send",)
        )
    original = await approvals.record(conn, int(row.approval_request_id))
    assert original is not None  # a foreign key
    expired = now > original.expires_at and int(row.sent_count) == 0
    if row.state == "paused" and not (row.state_reason or "").startswith(RECONFIRM):
        return SendCheck(
            outbox_id, "refuse", (f"it waits for a person ({row.state_reason})",),
            expired_unsent=expired,
        )  # fmt: skip
    tamper = _payload_problems(row, original)
    if tamper:
        return SendCheck(outbox_id, "refuse", tuple(tamper), expired_unsent=expired)
    order = await _order_problem(conn, row)
    if order is not None:
        verdict: Verdict = "skip" if order.endswith("skipped") else "wait"
        return SendCheck(outbox_id, verdict, (order,), expired_unsent=expired)
    mirror = await _mirror(conn, row.case_id)
    if row.op == "close":
        if mirror is None:
            return SendCheck(outbox_id, "wait", ("the case is not mirrored in Kibana yet",))
        if mirror.deleted_at is not None:
            return SendCheck(outbox_id, "skip", ("the Kibana case was deleted",))
        if mirror.sync_alerts:
            return SendCheck(
                outbox_id, "refuse", ("Sync alerts is on in Kibana: nothing is sent while it is",)
            )
    alerts = await _alert_set(conn, row.case_id, int(row.event_version))
    asked = await approvals.reconfirmations(conn, int(row.case_event_id))
    if asked and any(
        d.decision == "rejected" for d in await approvals.decisions(conn, asked[0].id)
    ):
        return SendCheck(
            outbox_id, "skip", (f"a person rejected its re-confirmation ({asked[0].id})",),
            expired_unsent=expired,
        )  # fmt: skip
    bases = [*asked, original]
    requester = await _requester_marks(conn, original)
    tried: list[_Basis] = []
    for request in bases:
        basis = await _judge(conn, request, verifier, now, alerts, mirror, row.op, requester)
        if basis.tamper:
            reasons = tuple(f"approval {request.id}: {t}" for t in basis.tamper)
            return SendCheck(outbox_id, "refuse", reasons, request.id, expired)
        if not basis.doubts:
            return SendCheck(outbox_id, "send", (), request.id, expired)
        tried.append(basis)
    reasons = tuple(f"approval {b.request.id}: {d}" for b in tried for d in b.doubts)
    return SendCheck(outbox_id, "reconfirm", reasons, None, expired)


def _payload_problems(row: Any, original: RequestRecord) -> list[str]:
    problems = []
    if kibana.payload_hash(dict(row.payload)) != row.payload_hash:
        problems.append("the write's payload does not match its hash")
    if kibana.payload_hash(original.payload) != original.payload_hash:
        problems.append("the approved payload does not match its hash")
    expected = {"class": row.write_class, "op": row.op, "payload": dict(row.payload)}
    if closure.write_at(original.payload, int(row.position)) != expected:
        problems.append("the write is not the one the approval named")
    if original.kind not in ("closure", "merge"):
        problems.append(f"a {original.kind} approval does not close a case")
    return problems


async def _order_problem(conn: AsyncConnection, row: Any) -> str | None:
    """The closing comment goes after the closing change is verified."""
    if row.op != "comment":
        return None
    state = (
        await conn.execute(
            text(
                "SELECT state FROM kibana_outbox WHERE case_event_id = :e AND op = 'close'"
                " AND position < :p ORDER BY position LIMIT 1"
            ),
            {"e": row.case_event_id, "p": row.position},
        )
    ).scalar_one_or_none()
    if state is None or state == "verified":
        return None
    if state == "skipped":
        return "the closing change was skipped"
    return f"the closing change is {state}, not yet verified"


async def _mirror(conn: AsyncConnection, case_id: Any) -> Any:
    return (
        await conn.execute(
            text(
                "SELECT kibana_version, sync_alerts, deleted_at FROM kibana_mirror"
                " WHERE case_id = :c"
            ),
            {"c": case_id},
        )
    ).first()


async def _alert_set(conn: AsyncConnection, case_id: Any, version: int) -> tuple[int, str]:
    """The case's alerts as of the closure at ``version`` (a merge moved its members at that
    version): their count and digest, as the database binds them to an approval."""
    ids = (
        await conn.execute(
            text(
                "SELECT DISTINCT ia.alert_id::text FROM case_members m"
                " JOIN investigation_alerts ia ON ia.investigation_id = m.investigation_id"
                " WHERE m.case_id = :c AND (m.removed_at IS NULL OR m.removed_version >= :v)"
            ),
            {"c": case_id, "v": version},
        )
    ).scalars()
    found = list(ids)
    return len(found), approvals.alert_digest(found)


async def _requester_marks(conn: AsyncConnection, original: RequestRecord) -> list[dict[str, Any]]:
    """Who asked for the closure (a re-confirmation's requester is its closure's), as checks
    :func:`identity.same_person` compares: the check bound to the request and each good check
    of theirs (an alias may show only in a later one). Nobody for ARGUS's own proposals."""
    user = original.requested_by_user_id
    if user is None:
        return []
    marks: list[dict[str, Any]] = [{"user_id": str(user)}]
    if original.requester_check is not None:
        marks.append(dict(original.requester_check))
    seen = await conn.execute(
        text(
            "SELECT DISTINCT snapshot ->> 'argus_uid' AS argus_uid, snapshot ->> 'email' AS email"
            " FROM identity_checks WHERE user_id = :u AND outcome = 'ok'"
        ),
        {"u": user},
    )
    marks += [{"user_id": str(user), "argus_uid": r.argus_uid, "email": r.email} for r in seen]
    return marks


async def _judge(
    conn: AsyncConnection,
    request: RequestRecord,
    verifier: Verifier,
    now: datetime,
    alerts: tuple[int, str],
    mirror: Any,
    op: str,
    requester: list[dict[str, Any]],
) -> _Basis:
    basis = _Basis(request)
    if now > request.expires_at:
        basis.doubts.append("expired before the write was sent")
    if (request.alert_count, request.alert_digest) != alerts:
        basis.doubts.append(
            f"the case's alerts changed since the approval ({request.alert_count} then,"
            f" {alerts[0]} now)"
        )
    if op == "close" and mirror is not None and mirror.kibana_version != request.kibana_version:
        basis.doubts.append("the Kibana case changed since the approval (its version moved)")
    decisions = await approvals.decisions(conn, request.id)
    if any(d.decision == "rejected" for d in decisions):
        basis.doubts.append("it was rejected")
    approving = [d for d in decisions if d.decision == "approved"]
    counted: list[DecisionRecord] = []
    for decision in approving:
        statement = approvals.stored_statement(request, decision)
        if statement is None or not verifier.verify(statement, decision.signature):
            basis.tamper.append(f"decision {decision.id} has no valid signature")
            continue
        snapshot = decision.identity_check or {}
        if "approve" not in decision.capabilities or (
            op in ("close", "comment") and identity.UPDATE_CASE not in snapshot.get("kibana", [])
        ):
            basis.tamper.append(f"decision {decision.id} was made without the needed privileges")
            continue
        if any(identity.same_person(snapshot, mark) for mark in requester):
            basis.doubts.append(f"user:{decision.approver_user_id} asked for this closure")
            continue
        doubt = await _approver_doubt(conn, decision, now)
        if doubt is not None:
            basis.doubts.append(doubt)
            continue
        if any(identity.same_person(snapshot, c.identity_check or {}) for c in counted):
            basis.doubts.append(f"user:{decision.approver_user_id} is the same person twice")
            continue
        counted.append(decision)
    if len(counted) < request.required:
        basis.doubts.append(f"{len(counted)} of {request.required} approvals still hold")
    return basis


async def _approver_doubt(
    conn: AsyncConnection, decision: DecisionRecord, now: datetime
) -> str | None:
    """Why this approver no longer counts, or None: revoked since they approved (a denial from
    any provider), no good live check within the bound, or their newest check no longer shows
    what approving needs. The last two read the checks of the provider that checked them for
    the approval: a local step-up, which shows no Kibana privileges, says nothing about their
    ELK account (review F5)."""
    who = f"user:{decision.approver_user_id}"
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
    if row.disabled or row.denied:
        return f"{who} was revoked after approving"
    if row.good_at is None or now - row.good_at > LIVE_CHECK_BOUND:
        return f"{who} has had no good live check within 12 hours"
    newest = row.newest or {}
    if "approve" not in newest.get("capabilities", []) or identity.UPDATE_CASE not in newest.get(
        "kibana", []
    ):
        return f"{who} no longer holds the approver capability or Kibana's updateCase"
    return None


async def admit(
    conn: AsyncConnection, outbox_id: int, verifier: Verifier, *, now: datetime | None = None
) -> SendCheck:
    """The writer's last check, under the row's lock, in the transaction that moves the row to
    ``sending``: send only on ``send``."""
    await conn.execute(text("SELECT argus_closure_write_lock(:id)"), {"id": outbox_id})
    return await check(conn, outbox_id, verifier, now=now)


async def release(
    conn: AsyncConnection, outbox_id: int, verifier: Verifier, *, now: datetime | None = None
) -> SendCheck:
    """Check closure write ``outbox_id`` under its row lock and apply the verdict (see the
    module)."""
    found = await admit(conn, outbox_id, verifier, now=now)
    row = (
        await conn.execute(
            text("SELECT write_class, state, state_reason FROM kibana_outbox WHERE id = :id"),
            {"id": outbox_id},
        )
    ).first()
    if row is None or row.write_class != "W3" or row.state not in _HELD:
        return found
    for_person = row.state == "paused" and not (row.state_reason or "").startswith(RECONFIRM)
    if found.verdict == "skip":
        await _move(conn, outbox_id, "skipped", "; ".join(found.reasons))
    elif for_person:
        pass  # a refused write waits for a person; only a change of its case skips it
    elif found.verdict == "send":
        await _move(conn, outbox_id, "approved", None)
    elif found.verdict == "reconfirm":
        await _move(conn, outbox_id, "paused", RECONFIRM + "; ".join(found.reasons))
        await _ask_reconfirmation(conn, outbox_id)
    elif found.verdict == "refuse":
        await _move(conn, outbox_id, "paused", REFUSED + "; ".join(found.reasons))
    return found


async def _move(conn: AsyncConnection, outbox_id: int, state: str, reason: str | None) -> None:
    """The runtime's only outbox move (``argus_closure_write_move()``, which audits it)."""
    await conn.execute(
        text("SELECT argus_closure_write_move(:id, :s, :r)"),
        {"s": state, "r": None if reason is None else reason[:1000], "id": outbox_id},
    )


async def _ask_reconfirmation(conn: AsyncConnection, outbox_id: int) -> int | None:
    """A re-confirmation request for a held-back closure write (one waiting at a time): the
    same writes, bound to the case's alerts and Kibana version now."""
    row = (
        await conn.execute(
            text(
                "SELECT o.case_id, o.case_event_id, o.approval_request_id, k.version,"
                " m.kibana_version FROM kibana_outbox o JOIN cases k ON k.id = o.case_id"
                " LEFT JOIN kibana_mirror m ON m.case_id = o.case_id WHERE o.id = :id"
            ),
            {"id": outbox_id},
        )
    ).one()
    waiting = (  # one re-confirmation covers the closure's writes
        await conn.execute(
            text(
                "SELECT 1 FROM approval_requests q WHERE q.kind = 'reconfirm'"
                " AND q.outbox_id IN (SELECT o.id FROM kibana_outbox o"
                " WHERE o.case_event_id = :e AND o.write_class = 'W3')"
                " AND clock_timestamp() <= q.expires_at"
                " AND NOT EXISTS (SELECT 1 FROM approval_decisions d WHERE d.request_id = q.id"
                " AND d.decision = 'rejected')"
                " AND (SELECT count(*) FROM approval_decisions d WHERE d.request_id = q.id"
                " AND d.decision = 'approved') < q.required_approvals"
            ),
            {"e": row.case_event_id},
        )
    ).first()
    if waiting is not None:
        return None
    original = await approvals.record(conn, int(row.approval_request_id))
    assert original is not None
    now = await identity.database_clock(conn)
    return await approvals.propose(
        conn,
        proposer=PROPOSER,
        case_id=row.case_id,
        case_version=int(row.version),
        kind="reconfirm",
        payload=original.payload,
        payload_hash=original.payload_hash,
        expires=approvals.expires_at(now),
        outbox_id=outbox_id,
        kibana_version=row.kibana_version,
        note="the closure write's send-time check held it back",
    )


async def held(conn: AsyncConnection) -> list[int]:
    """Closure writes a check may still let go or hold back, oldest first."""
    rows = await conn.execute(
        text(
            "SELECT id FROM kibana_outbox WHERE write_class = 'W3'"
            " AND state IN ('planned', 'approved', 'paused') ORDER BY id"
        )
    )
    return [int(r) for r in rows.scalars()]
