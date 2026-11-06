"""The typed contract of a person's work on the queue (UI v2 spec §2.3): "I'm checking" (A1),
"Mark as seen" (A2), the spot-check answer (A3), "I'm caught up" (A4), bulk "Not an incident" (A9),
the bulk review of one incident's alert groups, "sent to the CISO" (A14), a next step ticked (A16)
and the undo of one's own dismissal (A8).

Every write names what the person looked at (a case's ``expected_version``, a group's
``seen_version``) and is refused with 409 when it moved; a bulk write is all or nothing."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field

from argus.web.v1.case_models import (
    CaseRowOut,
    CaseVersion,
    DismissReason,
    SeenOut,
    Told,
)
from argus.web.v1.models import In, NoteText, Out, RequiredText, ReviewId, VersionNumber

BULK_DISMISS = 25  # the most possible incidents one "Not an incident" closes (spec §6.5)
BULK_REVIEW = 100  # the most alert groups of one incident one bulk review marks
SpotAnswer = Literal["right", "wrong", "cant_tell"]
SpotKind = Literal["incident", "alert_group"]
EngineVersion = Annotated[int, Field(ge=1, le=2**31 - 1)]


class HoldIn(In):
    """I'm checking: what you wait on (one line, your words) and when it comes back (at most
    14 days ahead)."""

    expected_version: CaseVersion
    reason: Told
    until: AwareDatetime


class CaseMarked(Out):
    """The case as it is now, with its hold, waiting time and your last look."""

    case: CaseRowOut


class SeenIn(In):
    """You looked at the case as the engine showed it at ``engine_version`` (None: a case the
    engine did not make): its changes up to then are not new to you any more."""

    engine_version: EngineVersion | None = None


class SeenDone(Out):
    case_id: uuid.UUID
    seen: SeenOut


class SpotCheckIn(In):
    """Your answer to a spot-check: ARGUS's closing looks right, it is wrong (it should have
    been raised), or you cannot tell. ``kind`` is needed only when the id could be either."""

    answer: SpotAnswer
    kind: SpotKind | None = None


class SpotScoreOut(Out):
    """Your team's spot-checks over the last ``days`` days."""

    days: int
    checked: int  # items with an answer
    wrong: int  # items someone answered "wrong"


class SpotCheckDone(Out):
    id: uuid.UUID
    kind: SpotKind
    answer: SpotAnswer
    closed_as: str | None  # how ARGUS closed it, in its words
    by: str
    at: datetime
    score: SpotScoreOut


class CaughtUpOut(Out):
    """Your "since" is now: Today counts what ARGUS handled from here."""

    since: datetime


class BulkItemIn(In):
    id: uuid.UUID
    expected_version: CaseVersion


class BulkDismissIn(In):
    """Close up to 25 possible incidents as "not an incident", for one reason, each at the
    version you looked at. All or nothing: a refusal of one closes none, and says which."""

    items: Annotated[list[BulkItemIn], Field(min_length=1, max_length=BULK_DISMISS)]
    reason: DismissReason
    note: NoteText | None = None


class BulkDismissed(Out):
    closed: list[CaseRowOut]  # in the order asked


class MemberReviewIn(In):
    investigation_id: uuid.UUID
    seen_version: VersionNumber
    seen_review: ReviewId | None


class MemberReviewsIn(In):
    """Mark several of one incident's alert groups at once: a verdict (an outcome) or "can't
    tell yet" (``follow_up``). Each names the version and the latest review you saw. "Real: act
    on it" (``true_positive``) only on a confirmed incident. All or nothing."""

    action: Literal["reviewed", "follow_up"]
    outcome: (
        Literal["benign_expected", "benign_policy", "rule_false_positive", "true_positive"] | None
    ) = None
    note: NoteText | None = None
    items: Annotated[list[MemberReviewIn], Field(min_length=1, max_length=BULK_REVIEW)]


class MemberReviewOut(Out):
    investigation_id: uuid.UUID
    review_id: int
    version: int


class MemberReviewsDone(Out):
    reviews: list[MemberReviewOut]  # in the order asked


class SentIn(In):
    """You sent the incident report (this version) to the CISO's office."""

    to: Literal["ciso"]
    report_version: Annotated[int, Field(ge=1, le=2**31 - 1)]


class SentOut(Out):
    to: Literal["ciso"]
    report_version: int
    at: datetime
    by: str


class ActionDoneIn(In):
    """A next step was done, in your words (what was done, by whom)."""

    attestation: RequiredText


class ActionDoneOut(Out):
    case_id: uuid.UUID
    action_id: str
    state: str
    by: str
    at: datetime


class UndoDismissIn(In):
    """Undo your own dismissal, right after it (within 15 minutes, nothing changed since)."""

    expected_version: CaseVersion
