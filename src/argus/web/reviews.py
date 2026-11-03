"""Recording a review (plan §9.3, D-052). A review names the latest review its author saw and
the investigation version they looked at; if either moved meanwhile, it is a conflict (409)
and nothing is written. The investigation row lock serializes reviewers."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.web.auth import Reviewer, audit

Action = Literal["reviewed", "follow_up", "note"]
Outcome = Literal[
    "benign_expected", "benign_policy", "rule_false_positive", "true_positive", "inconclusive"
]
OUTCOME_LABELS: dict[str, str] = {
    "benign_expected": "Benign: expected activity",
    "benign_policy": "Benign: allowed by policy",
    "rule_false_positive": "Rule false positive",
    "true_positive": "True positive",
    "inconclusive": "Inconclusive",
}
NOTE_LIMIT = 4000


class ReviewConflictError(Exception):
    def __init__(self, latest: int | None, version: int) -> None:
        super().__init__("someone else reviewed or the investigation changed meanwhile")
        self.latest = latest
        self.version = version


class NotFoundError(Exception):
    pass


@dataclass(frozen=True)
class Recorded:
    review_id: int
    version: int


async def add_review(
    conn: AsyncConnection,
    reviewer: Reviewer,
    investigation_id: uuid.UUID,
    *,
    action: Action,
    outcome: Outcome | None,
    note: str | None,
    seen_review: int | None,
    seen_version: int,
) -> Recorded:
    if note is not None and len(note) > NOTE_LIMIT:
        raise ValueError(f"a note has at most {NOTE_LIMIT} characters")
    if action == "note" and not note:
        raise ValueError("a note needs text")
    if action == "reviewed" and outcome is None:  # a decision is a label (D-067)
        raise ValueError("choose an outcome to mark it reviewed")
    row = (
        await conn.execute(
            text("SELECT version, alert_count FROM investigations WHERE id = :id FOR UPDATE"),
            {"id": investigation_id},
        )
    ).first()
    if row is None:
        raise NotFoundError(str(investigation_id))
    latest = (
        await conn.execute(
            text("SELECT max(id) FROM review_events WHERE investigation_id = :id"),
            {"id": investigation_id},
        )
    ).scalar_one()
    if latest != seen_review or row.version != seen_version:
        raise ReviewConflictError(latest, row.version)
    review_id = (
        await conn.execute(
            text(
                "INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                " action, outcome, note, kibana_ok)"
                " VALUES (:inv, :v, :n, :u, :a, :o, :note, :ok) RETURNING id"
            ),
            {
                "inv": investigation_id,
                "v": row.version,
                "n": row.alert_count,
                "u": reviewer.user_id,
                "a": action,
                "o": outcome,
                "note": note or None,
                "ok": reviewer.kibana_ok,
            },
        )
    ).scalar_one()
    await audit(
        conn,
        actor=f"user:{reviewer.username}",
        action=f"review.{action}",
        target_type="investigation",
        target_id=str(investigation_id),
        details={"review_id": review_id, "version": row.version, "outcome": outcome},
    )
    return Recorded(review_id, row.version)
