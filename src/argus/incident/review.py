"""A person's Confirm or Reject of an incident report (AR7, D-190).

The decision is recorded beside the version the person read (``incident_report_decisions``) and
becomes a **label through the existing review path**: a review
(:func:`argus.web.reviews.add_review`, the same function the Inbox's Confirm and a pattern
review use) of each investigation of the case, so the decision engine learns from it and the
gold set's own answer is saved where the member is a gold item and the person may answer
gold. Nothing else is invented: no parallel label store, no new way to review.

* **Confirm** says the report's verdict is right. It labels the members with that outcome, but
  never overrides a person's own earlier review of a member (a different outcome stays).
* **Reject** says it is wrong, names the outcome the person holds instead and why. The reason is
  the review's note; it replaces the member's earlier review (the history keeps both).
* Neither closes anything or asks anyone for an approval: closing a case stays a person's approval
  (the case machine, W3).
* A decision names the version of the report the person read: when ARGUS wrote a newer one
  meanwhile the answer is a conflict and nothing is saved.

The members labelled are the case's active investigations, the newest first, at most
:data:`LABEL_CAP`; what is left is said. All of it is one transaction (the caller's): a failure
anywhere leaves no label and no decision.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, cast

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.evaluation import store as gold_store
from argus.incident import store
from argus.incident.model import OUTCOMES, Outcome
from argus.web import auth
from argus.web.capabilities import Capability
from argus.web.reviews import NOTE_LIMIT, NotFoundError, ReviewConflictError, add_review

LABEL_CAP = 200
REASON_MIN = 3
REASON_MAX = 4000
Code = str


class ReportRefused(Exception):  # noqa: N818 - a refusal, not an error
    """A decision that cannot be recorded; ``code``: ``not_found``, ``conflict`` or ``invalid``."""

    def __init__(self, code: Code, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Decided:
    record: store.Decision  # the decision as stored
    report_version: int
    decision: str
    outcome: str | None
    labelled: int  # reviews written
    already: int  # members already reviewed with the same outcome (left as they are)
    kept: int  # members a person reviewed otherwise (a confirm never overrides them)
    conflicts: int  # members that moved while the decision was recorded
    gold_saved: int
    left: int  # members beyond the cap, not labelled
    review_ids: tuple[int, ...]
    kept_by: tuple[str, ...] = ()  # who reviewed the members a confirm left as they were


_MEMBERS = text(
    "SELECT i.id, i.version,"
    " (SELECT max(r.id) FROM review_events r WHERE r.investigation_id = i.id)"
    " AS latest, s.outcome AS reviewed_outcome, s.version AS reviewed_version,"
    " s.action AS reviewed_action, s.user_id AS reviewed_by, count(*) OVER () AS total"
    " FROM case_members m JOIN investigations i ON i.id = m.investigation_id"
    " LEFT JOIN review_state s ON s.investigation_id = i.id"
    " WHERE m.case_id = :c AND m.removed_at IS NULL"
    " ORDER BY i.last_event_at DESC NULLS LAST, i.id LIMIT :n"
)


def clean_reason(reason: str | None) -> str:
    """The reason as stored: whitespace folded, 3 to 4,000 printable characters."""
    said = " ".join((reason or "").split())
    if len(said) < REASON_MIN:
        raise ReportRefused("invalid", "say why the report is wrong (at least a few words)")
    if len(said) > REASON_MAX:
        raise ReportRefused("invalid", f"the reason is at most {REASON_MAX} characters")
    if any(not c.isprintable() for c in said):
        raise ReportRefused("invalid", "the reason holds a character that cannot be shown")
    return said


async def decide(
    conn: AsyncConnection,
    me: auth.Reviewer,
    case_id: uuid.UUID,
    *,
    expected_version: int,
    decision: str,
    outcome: str | None = None,
    reason: str | None = None,
) -> Decided:
    """Record ``decision`` (``confirmed`` or ``rejected``) of the case's current report as ``me``,
    and the labels that follow."""
    state = await conn.scalar(text("SELECT state FROM cases WHERE id = :c"), {"c": case_id})
    if state is None:
        raise ReportRefused("not_found", "no such case")
    current = await store.latest(conn, case_id)
    if current is None:
        raise ReportRefused("not_found", "this case has no incident report yet")
    if current.version != expected_version:
        raise ReportRefused(
            "conflict",
            f"The report changed while you read it (it is now version {current.version}):"
            " nothing was saved. Read it again.",
        )
    if state == "closed":
        raise ReportRefused("conflict", "The case is closed: its report is no longer decided.")
    verdict = current.report.verdict
    if decision == "confirmed":
        if verdict.outcome is None or verdict.kind not in ("person", "proposal", "case"):
            raise ReportRefused(
                "invalid",
                "ARGUS has no verdict on this case to confirm (only a reading, or nothing):"
                " reject the report with the outcome you hold instead.",
            )
        label: Outcome = verdict.outcome
        note_text: str | None = None
        reason_text: str | None = None
    elif decision == "rejected":
        if outcome not in OUTCOMES:
            raise ReportRefused("invalid", "choose the outcome you hold instead")
        reason_text = clean_reason(reason)
        if outcome == verdict.outcome and verdict.kind in ("person", "proposal", "case"):
            raise ReportRefused(
                "invalid", "That is the outcome the report already holds: confirm it instead."
            )
        label, note_text = cast(Outcome, outcome), reason_text
    else:
        raise ReportRefused("invalid", "a decision is confirmed or rejected")
    rows = (await conn.execute(_MEMBERS, {"c": case_id, "n": LABEL_CAP})).all()
    total = int(rows[0].total) if rows else 0
    number = await conn.scalar(text("SELECT number FROM cases WHERE id = :c"), {"c": case_id})
    head = (
        f"Confirmed with the incident report (version {current.version}) of case {number}."
        if decision == "confirmed"
        else f"Rejected the incident report (version {current.version}) of case {number}: "
        f"{note_text}"
    )
    review_ids: list[int] = []
    kept_ids: set[int] = set()
    already = kept = conflicts = gold = 0
    may_gold = me.can(Capability.ANSWER_GOLD)
    for row in rows:
        reviewed_now = row.reviewed_action == "reviewed" and row.reviewed_version == row.version
        if reviewed_now and row.reviewed_outcome == label:
            already += 1
            continue
        if reviewed_now and decision == "confirmed":
            kept += 1  # a confirm never overrides a person's own, different review
            if row.reviewed_by is not None:
                kept_ids.add(int(row.reviewed_by))
            continue
        try:
            async with conn.begin_nested():
                done = await add_review(
                    conn, me, row.id, action="reviewed", outcome=label,
                    note=head[:NOTE_LIMIT], seen_review=row.latest, seen_version=int(row.version),
                )  # fmt: skip
        except (ReviewConflictError, NotFoundError):
            conflicts += 1
            continue
        review_ids.append(done.review_id)
        if may_gold and await _gold(conn, row.id, me.user_id, label, head):
            gold += 1
    saved = await _record(conn, current.id, decision, outcome if decision == "rejected" else label,
                          reason_text, me.user_id, review_ids)  # fmt: skip
    await auth.audit(
        conn, actor=f"user:{me.username}", action=f"incident.report.{decision}",
        target_type="case", target_id=str(case_id),
        details={"report_version": current.version, "decision_id": saved, "outcome": label,
                 "labelled": len(review_ids), "kept": kept, "already": already,
                 "conflicts": conflicts, "gold": gold},
    )  # fmt: skip
    made = await store.decision_of(conn, current.id)
    assert made is not None
    assert made.id == saved
    names: tuple[str, ...] = ()
    if kept_ids:
        found = await conn.execute(
            text("SELECT display_name FROM users WHERE id = ANY(:ids) ORDER BY display_name"),
            {"ids": sorted(kept_ids)},
        )
        names = tuple(str(r.display_name) for r in found)[:5]
    return Decided(
        made, current.version, decision, label, len(review_ids), already, kept, conflicts, gold,
        max(total - len(rows), 0), tuple(review_ids), names,
    )  # fmt: skip


async def _gold(
    conn: AsyncConnection, investigation: uuid.UUID, user_id: int, outcome: str, note: str
) -> bool:
    """The person's answer for a gold-set item, in the gold set it is in; False when it is none
    (or in more than one set, or the answer is refused): the review above stands."""
    try:
        async with conn.begin_nested():
            await gold_store.answer(conn, investigation, user_id, outcome, note[:NOTE_LIMIT],
                                    set_name=gold_store.ANY)  # fmt: skip
    except gold_store.GoldError:
        return False
    return True


async def _record(
    conn: AsyncConnection, report_id: int, decision: str, outcome: str | None,
    reason: str | None, user_id: int, review_ids: list[int],
) -> int:  # fmt: skip
    params: dict[str, Any] = {"r": report_id, "d": decision, "o": outcome, "why": reason,
                              "u": user_id, "ids": review_ids}  # fmt: skip
    made = await conn.scalar(
        text(
            "INSERT INTO incident_report_decisions (report_id, decision, outcome, reason,"
            " by_user_id, review_ids) VALUES (:r, :d, :o, :why, :u, CAST(:ids AS bigint[]))"
            " RETURNING id"
        ),
        params,
    )
    assert made is not None
    return int(made)
