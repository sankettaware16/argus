"""The case record's types: states, reasons, actors and their capabilities, and the replayable
state of a case. Capabilities are actions, not role names (ELK's Kibana privileges are mapped onto
them). The terminal's ``argus case`` commands act with :data:`LOCAL_CAPABILITIES` (everything but
approving) and no Kibana privileges, so a case opened there waits for someone who may open cases in
Kibana."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Literal, get_args

State = Literal["suspected", "open", "assigned", "contained", "closed"]
Severity = Literal["low", "medium", "high", "critical"]
Cause = Literal["verdict", "proposal", "person", "watch", "raised"]
Reason = Literal[
    "remediated_verified",
    "remediated_unverified",
    "risk_accepted",
    "attempt_no_impact",
    "rule_false_positive",
    "benign_expected",
    "benign_policy",
    "duplicate",
    "created_in_error",
    "stopped_after_notice",
]
NoticeHow = Literal["email", "phone", "in_person", "through_it", "other"]
Link = Literal["verdict", "proposal", "actor", "indicator", "c2", "person", "merge"]
IndicatorKind = Literal["ip", "domain", "host", "user", "url", "hash"]
IndicatorRole = Literal["actor", "c2", "indicator"]
IndicatorSource = Literal["investigation", "threat_intel", "person", "merge"]

STATES: tuple[State, ...] = get_args(State)
NOTICE_HOWS: tuple[NoticeHow, ...] = get_args(NoticeHow)
SEVERITIES: tuple[Severity, ...] = get_args(Severity)
REASONS: tuple[Reason, ...] = get_args(Reason)
CONFIRMED: frozenset[State] = frozenset({"open", "assigned", "contained"})
# A reviewer dismisses a suspected case (it was never confirmed, nothing is in Kibana) with one
# of these; the rest need evidence and an approver.
DISMISS_REASONS: frozenset[Reason] = frozenset(
    {"rule_false_positive", "benign_expected", "benign_policy", "created_in_error", "duplicate"}
)
# Closure reasons a person may request (``duplicate`` comes only from a merge).
REQUEST_REASONS: frozenset[Reason] = frozenset(REASONS) - {"duplicate"}
# What ARGUS itself proposes, each with positive evidence: a verified quiet window,
# people's reviews of every member, or 14 days of no matching activity after the owner was told
# ; a person still approves. Never the two-person reasons.
PROPOSE_REASONS: frozenset[Reason] = frozenset(
    {"remediated_verified", "attempt_no_impact", "rule_false_positive", "benign_expected",
     "benign_policy", "stopped_after_notice"}
)  # fmt: skip
# Two different people; every other reason needs one approver.
TWO_PERSON_REASONS: frozenset[Reason] = frozenset({"remediated_unverified", "risk_accepted"})
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}
NOTE_LIMIT = 4000
TITLE_LIMIT = 200


class Capability(StrEnum):
    """The capability names (users.capabilities); Kibana privileges are mapped onto them."""

    VIEW = "view"
    REVIEW = "review"  # dismiss a suspected case; notes (a reviewer)
    MANAGE = "manage_cases"  # open, confirm, take, assign, release, contain, link, merge,
    # publish to Kibana, request a closure
    REOPEN = "reopen"
    APPROVE = "approve"  # the approver capability


LOCAL_CAPABILITIES: frozenset[str] = frozenset(c.value for c in Capability) - {Capability.APPROVE}
# A Kibana case is created for a person only if their fresh check showed both.
KIBANA_TO_OPEN: frozenset[str] = frozenset({"createCase", "createComment"})
KIBANA_FRESH = timedelta(minutes=5)
WAITING_FOR_KIBANA = "Waiting for someone who may open cases in Kibana"


@dataclass(frozen=True)
class Actor:
    """Who acts: a person (``user:<id>``, the users.id, so a renamed login keeps its
    history) or ARGUS itself (``argus:<part>``). The name is what the audit trail records."""

    name: str
    user_id: int | None
    capabilities: frozenset[str]
    via: str
    kibana: frozenset[str] = frozenset()  # Kibana privileges from a live check
    kibana_checked_at: datetime | None = None

    @classmethod
    def person(
        cls,
        user_id: int,
        capabilities: frozenset[str] = LOCAL_CAPABILITIES,
        *,
        via: str,
        kibana: frozenset[str] = frozenset(),
        kibana_checked_at: datetime | None = None,
    ) -> Actor:
        if user_id < 1:
            raise ValueError("a person is a users.id")
        return cls(f"user:{user_id}", user_id, frozenset(capabilities), via, kibana,
                   kibana_checked_at)  # fmt: skip

    @classmethod
    def argus(cls, part: str) -> Actor:
        return cls(f"argus:{part}", None, frozenset(), part)

    @property
    def is_person(self) -> bool:
        return self.user_id is not None

    def may(self, capability: Capability) -> bool:
        return self.is_person and capability.value in self.capabilities

    def may_open_in_kibana(self, now: datetime) -> bool:
        """Their live check showed createCase and createComment within the last 5 minutes."""
        checked = self.kibana_checked_at
        return (
            self.is_person
            and self.kibana >= KIBANA_TO_OPEN
            and checked is not None
            and timedelta(0) <= now - checked <= KIBANA_FRESH
        )


@dataclass(frozen=True, order=True)
class Indicator:
    """An actor, C2 or other indicator of a case; ``source`` (where it came from) is recorded
    but is not part of its identity."""

    kind: IndicatorKind
    value: str
    role: IndicatorRole
    source: IndicatorSource = field(default="investigation", compare=False)


@dataclass(frozen=True, order=True)
class Member:
    investigation_id: uuid.UUID
    link: Link
    link_value: str | None = None


@dataclass(frozen=True)
class Case:
    """Everything that replaying a case's events rebuilds (:func:`argus.cases.machine.replay`)."""

    id: uuid.UUID
    number: int
    title: str
    state: State
    severity: Severity
    version: int
    cause: Cause
    owner_user_id: int | None = None
    cause_review_id: int | None = None
    cause_assessment_id: int | None = None
    parent_case_id: uuid.UUID | None = None
    opened_at: datetime | None = None
    closed_at: datetime | None = None
    closure_reason: Reason | None = None
    closure_request_id: int | None = None
    merged_into_id: uuid.UUID | None = None
    attention: str | None = None
    kibana_wait: str | None = None
    # The first time the device's owner was told: the case is then tracked
    # quietly while it lives as open or assigned. Cleared when it is contained or closed.
    notified_at: datetime | None = None
    blocked_at: datetime | None = None  # the first network-side block recorded for it
    mirrored: bool = False  # a Kibana create was planned: later changes are mirrored too
    members: frozenset[uuid.UUID] = field(default_factory=frozenset)
    indicators: frozenset[Indicator] = field(default_factory=frozenset)

    @property
    def confirmed(self) -> bool:
        return self.opened_at is not None

    @property
    def notified(self) -> bool:
        """Whether the owner was told and the case is tracked as a known infection."""
        return self.notified_at is not None


@dataclass(frozen=True)
class QuietWindow:
    """Whether the case's actors and indicators were verifiably quiet for 72 hours of complete
    coverage. Until log coverage is measured, nothing is verified."""

    verified: bool
    reason: str


NO_QUIET_WINDOW = QuietWindow(
    False, "a quiet window cannot be verified before known negatives are on (Q-F1)"
)


@dataclass(frozen=True)
class ApprovalFacts:
    """An approval request and its decisions, as the database holds them; ``approved`` counts
    only approvers not revoked since they approved."""

    request_id: int
    case_id: uuid.UUID
    case_version: int
    kind: str
    reason: Reason | None
    target_case_id: uuid.UUID | None
    required: int
    approved: int
    rejected: int
    expires_at: datetime
    requested_by_user_id: int | None  # None: ARGUS's own proposal (``proposed_by``)
    approvers: tuple[int, ...] = ()  # those who approved and are not revoked since
    proposed_by: str | None = None

    def complete(self, now: datetime) -> bool:
        return self.rejected == 0 and self.approved >= self.required and now <= self.expires_at


def max_severity(*values: Severity) -> Severity:
    return max(values, key=SEVERITY_RANK.__getitem__)
