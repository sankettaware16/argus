"""ARGUS's closure proposals (plan §7.1, §5 Q-C3): deterministic, each with positive evidence,
and only ever a proposal: a person with the approver capability approves it (DQ12 (b)), and
Phase 3 has no automatic closure (DQ14 (b): :mod:`argus.cases.autonomy` keeps the record a
class would have to earn).

A confirmed case is proposed for closure when, and only when:

* **benign or false positive**: every member investigation's newest review is a person's
  ``reviewed`` verdict made after the case was opened and at the investigation's current
  version (new alerts since make it "changed since review", as the web shows it), all with one
  outcome among
  ``benign_expected``, ``benign_policy`` and ``rule_false_positive`` (the assistant's reviews
  never count): that outcome is the reason;
* **remediated, verified**: the case is contained and the still-active watch verifies a
  72-hour quiet window (Q-C2 with Q-F1; until then never).

A case with a request at its current version (a person's or ARGUS's) is not proposed again.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.cases.approvals import ApprovalError
from argus.cases.machine import CaseRefused
from argus.cases.model import Actor, Reason
from argus.cases.service import CaseService, QuietWindows, no_quiet_window

PROPOSER = Actor.argus("proposer")
BENIGN = ("benign_expected", "benign_policy", "rule_false_positive")
LIMIT = 50  # proposals one run makes at most


@dataclass(frozen=True)
class Candidate:
    case_id: uuid.UUID
    number: int
    version: int
    reason: Reason
    evidence: str


_REVIEWED = """
SELECT c.id, c.number, c.version, min(s.outcome) AS outcome, count(*) AS members
FROM cases c
JOIN case_members m ON m.case_id = c.id AND m.removed_at IS NULL
JOIN investigations i ON i.id = m.investigation_id
LEFT JOIN review_state s ON s.investigation_id = m.investigation_id
LEFT JOIN users u ON u.id = s.user_id
WHERE c.state IN ('open', 'assigned', 'contained')
  AND NOT EXISTS (SELECT 1 FROM approval_requests r WHERE r.case_id = c.id
                  AND r.case_version = c.version)
GROUP BY c.id, c.number, c.version
HAVING bool_and(coalesce(s.action = 'reviewed'
                         AND s.outcome IN ('benign_expected', 'benign_policy',
                                           'rule_false_positive')
                         AND s.decided_at > c.opened_at AND s.version = i.version
                         AND u.username <> 'argus-assistant' AND u.kind = 'person',
                         false))
   AND count(DISTINCT s.outcome) = 1
ORDER BY c.number LIMIT :n
"""


async def candidates(
    conn: AsyncConnection, *, limit: int = LIMIT, windows: QuietWindows = no_quiet_window
) -> list[Candidate]:
    found = []
    for row in (await conn.execute(text(_REVIEWED), {"n": limit})).all():
        evidence = (
            f"every member investigation ({row.members}) was reviewed by a person as"
            f" {row.outcome} after the case was opened"
        )
        found.append(Candidate(row.id, int(row.number), int(row.version), row.outcome, evidence))
    contained = await conn.execute(
        text(
            "SELECT c.id, c.number, c.version FROM cases c WHERE c.state = 'contained'"
            " AND NOT EXISTS (SELECT 1 FROM approval_requests r WHERE r.case_id = c.id"
            " AND r.case_version = c.version) ORDER BY c.number LIMIT :n"
        ),
        {"n": limit},
    )
    service = await CaseService.start(conn, windows)
    for row in contained.all():
        case = await service.get(row.id)
        if case is None or any(c.case_id == row.id for c in found):
            continue
        window = await service.quiet_windows(case)
        if window.verified:
            found.append(Candidate(row.id, int(row.number), int(row.version),
                                   "remediated_verified", window.reason))  # fmt: skip
    return found[:limit]


@dataclass(frozen=True)
class Proposed:
    candidate: Candidate
    request_id: int | None
    refused: str | None = None


async def propose(service: CaseService, candidate: Candidate) -> Proposed:
    """One proposal, in the service's transaction (a refusal, e.g. the case moved, is said)."""
    try:
        async with service.conn.begin_nested():
            _, request_id = await service.propose_closure(
                PROPOSER,
                candidate.case_id,
                reason=candidate.reason,
                evidence=candidate.evidence,
                expected_version=candidate.version,
            )
    except CaseRefused as exc:
        return Proposed(candidate, None, str(exc))
    except ApprovalError as exc:
        return Proposed(candidate, None, exc.message)
    return Proposed(candidate, request_id)
