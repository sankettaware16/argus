"""The autonomy ledger: for each class of closure ARGUS proposes, what people did with its
proposals. Nothing closes automatically; a class that meets every measured bar (125 audited
proposals, none wrong, a Wilson lower bound of at least 97 %, four stable weeks, then a 10 % audit)
is only *ready for a person's decision*, which the ledger cannot record. It also counts approvals
that expired unsent (at most 5 %) and proposals whose approver was revoked later. Everything is
read from the approval and case tables."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.cases.approvals import NOT_REVOKED
from argus.evaluation.harness import Rate

MIN_AUDITED = 125
MIN_LOWER_BOUND = 0.97
STABLE_WEEKS = 4
STILL_TO_DO = ("a 10 % audit of the class by people", "the user's decision (DQ14)")


@dataclass(frozen=True)
class Week:
    start: datetime
    decided: int
    wrong: int


@dataclass(frozen=True)
class ClassLine:
    reason: str
    proposed: int
    approved: int
    rejected: int
    reopened: int  # closed on the proposal, reopened since
    pending: int
    expired_undecided: int
    weeks: tuple[Week, ...]  # the last four complete weeks, oldest first
    revoked: int = 0  # approved, and an approver revoked since

    @property
    def decided(self) -> int:
        return self.approved + self.rejected

    @property
    def wrong(self) -> int:
        return self.rejected + self.reopened

    @property
    def right(self) -> Rate:
        return Rate(max(0, self.approved - self.reopened), self.decided)

    def missing(self) -> list[str]:
        """What this class still lacks before the user could decide (never empty)."""
        lacking = []
        if self.decided < MIN_AUDITED:
            lacking.append(f"{MIN_AUDITED} audited proposals ({self.decided} so far)")
        if self.wrong:
            lacking.append(f"no wrong proposal ({self.wrong} wrong)")
        bound = self.right.interval
        if bound is None or bound[0] < MIN_LOWER_BOUND:
            shown = "none" if bound is None else f"{bound[0]:.1%}"
            lacking.append(f"a lower bound of {MIN_LOWER_BOUND:.1%} ({shown})")
        stable = self.weeks[-STABLE_WEEKS:]
        if len(stable) < STABLE_WEEKS or any(w.decided == 0 or w.wrong for w in stable):
            lacking.append(f"{STABLE_WEEKS} stable weeks")
        return [*lacking, *STILL_TO_DO]


@dataclass(frozen=True)
class Ledger:
    at: datetime
    classes: tuple[ClassLine, ...]
    with_writes: int  # complete closure or merge approvals with Kibana writes, now past or sent
    expired_unsent: int
    expired_undecided: int  # every request kind, people's included
    skipped_writes: int = 0  # complete approvals whose writes were rightly skipped, unsent

    @property
    def expired_unsent_rate(self) -> Rate:
        return Rate(self.expired_unsent, self.with_writes)


_PROPOSALS = f"""
SELECT r.id, r.reason, r.expires_at,
       (SELECT count(*) FROM approval_decisions d WHERE d.request_id = r.id
          AND d.decision = 'approved') AS approved,
       (SELECT count(*) FROM approval_decisions d WHERE d.request_id = r.id
          AND d.decision = 'approved' AND {NOT_REVOKED}) AS still_approved,
       (SELECT count(*) FROM approval_decisions d WHERE d.request_id = r.id
          AND d.decision = 'rejected') AS rejected,
       r.required_approvals AS required,
       (SELECT max(d.decided_at) FROM approval_decisions d WHERE d.request_id = r.id)
          AS decided_at,
       EXISTS (SELECT 1 FROM case_events e WHERE e.case_id = r.case_id AND e.kind = 'closed'
               AND e.case_version = r.case_version + 1)
       AND EXISTS (SELECT 1 FROM case_events e WHERE e.case_id = r.case_id
                   AND e.kind = 'reopened' AND e.case_version > r.case_version + 1)
          AS reopened
FROM approval_requests r
WHERE r.kind = 'closure' AND r.proposed_by IS NOT NULL
ORDER BY r.id
"""  # noqa: S608 - constant SQL

_EXPIRED = """
SELECT
  count(*) FILTER (WHERE writes AND complete AND NOT skipped
                   AND (sent_by_expiry OR expires_at < :now)) AS with_writes,
  count(*) FILTER (WHERE writes AND complete AND NOT skipped AND expires_at < :now
                   AND NOT sent_by_expiry) AS expired_unsent,
  count(*) FILTER (WHERE writes AND complete AND skipped) AS skipped_writes,
  count(*) FILTER (WHERE NOT complete AND NOT rejected AND expires_at < :now)
      AS expired_undecided
FROM (
  SELECT r.expires_at,
         jsonb_array_length(coalesce(r.payload -> 'writes', '[]'::jsonb)) > 0
           AND r.kind IN ('closure', 'merge') AS writes,
         (SELECT count(*) FROM approval_decisions d WHERE d.request_id = r.id
            AND d.decision = 'approved') >= r.required_approvals AS complete,
         EXISTS (SELECT 1 FROM kibana_outbox o WHERE o.approval_request_id = r.id
                 AND o.write_class = 'W3' AND o.state = 'skipped' AND o.sent_count = 0)
           AND NOT EXISTS (SELECT 1 FROM kibana_outbox o WHERE o.approval_request_id = r.id
                           AND o.write_class = 'W3' AND o.sent_count > 0) AS skipped,
         EXISTS (SELECT 1 FROM approval_decisions d WHERE d.request_id = r.id
                 AND d.decision = 'rejected') AS rejected,
         EXISTS (SELECT 1 FROM kibana_outbox o WHERE o.approval_request_id = r.id
                 AND o.write_class = 'W3' AND o.sent_at IS NOT NULL
                 AND o.sent_at <= r.expires_at) AS sent_by_expiry
  FROM approval_requests r
) q
"""


def _week(at: datetime) -> datetime:
    day = at.astimezone(UTC).date()
    monday = day - timedelta(days=day.weekday())
    return datetime(monday.year, monday.month, monday.day, tzinfo=UTC)


async def ledger(conn: AsyncConnection, now: datetime | None = None) -> Ledger:
    if now is None:
        now = (await conn.execute(text("SELECT clock_timestamp()"))).scalar_one()
    assert now is not None
    rows = (await conn.execute(text(_PROPOSALS))).all()
    this_week = _week(now)
    recent = [this_week - timedelta(weeks=k) for k in range(STABLE_WEEKS, 0, -1)]
    by_reason: dict[str, list[Any]] = {}
    for row in rows:
        by_reason.setdefault(str(row.reason), []).append(row)
    lines = []
    for reason, items in sorted(by_reason.items()):
        tally = {start: [0, 0] for start in recent}
        approved = rejected = reopened = pending = expired = revoked = 0
        for row in items:
            wrong = bool(row.rejected) or bool(row.reopened)
            done = bool(row.rejected) or int(row.approved) >= int(row.required)
            if row.rejected:
                rejected += 1
            elif done:
                approved += 1
                reopened += int(bool(row.reopened))
                revoked += int(int(row.still_approved) < int(row.required))
            elif row.expires_at < now:
                expired += 1
            else:
                pending += 1
            if done and row.decided_at is not None and _week(row.decided_at) in tally:
                tally[_week(row.decided_at)][0] += 1
                tally[_week(row.decided_at)][1] += int(wrong)
        weeks = tuple(Week(start, *tally[start]) for start in recent)
        lines.append(ClassLine(reason, len(items), approved, rejected, reopened, pending,
                               expired, weeks, revoked))  # fmt: skip
    totals = (await conn.execute(text(_EXPIRED), {"now": now})).one()
    return Ledger(now, tuple(lines), int(totals.with_writes), int(totals.expired_unsent),
                  int(totals.expired_undecided), int(totals.skipped_writes))  # fmt: skip
