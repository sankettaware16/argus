"""The typed contract of the case team's preview (AR8, D-195): what ARGUS would write to the case in
Kibana, step by step, as a dry run; where the post stands; and the canary's approval.

Nothing here writes to Kibana. The texts are exactly the comments that would be sent (values
fenced and defanged, already checked by the guardian); an account that may not read the logs sees
that they are hidden (they say what the logs said). Every error is ``ErrorOut``; an approval names
the plan's hash the person read (409 when the plan changed) and is signed with the approval key."""

from __future__ import annotations

import uuid
from typing import Annotated, Literal

from pydantic import AwareDatetime, Field

from argus.web.v1.case_models import CaseState
from argus.web.v1.models import SAFE_MAX, In, Out

Author = Literal[
    "argus-lead",
    "argus-evidence",
    "argus-intel",
    "argus-responder",
    "argus-hunter",
    "argus-reporter",
    "argus-visualiser",
]
StepKind = Literal[
    "open", "attach", "tag", "comment", "file", "retitle", "redescribe", "edit_comment"
]
Action = Literal["none", "open", "update", "resume"]
PlanHash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class TeamRequestOut(Out):
    """The request a step makes (a file's body is its name, size and hash, never its bytes)."""

    method: str
    path: str
    content_type: str
    body: str


class TeamStepOut(Out):
    n: int
    key: str
    kind: StepKind
    author: Author
    part: str
    what: str  # "argus-evidence comments (evidence)"
    text: str | None  # the exact comment or description; None when the logs are hidden
    request: TeamRequestOut | None
    state: str | None  # where the step stands when the plan is in the database


class TeamDecisionOut(Out):
    action: Action
    would: Action  # a dry run: what it would do were posting on
    why: str
    route: str | None
    dry_run: bool
    needs_approval: bool


class TeamPostOut(Out):
    """Where the post of this case stands in Kibana."""

    incident_id: str
    kibana_case_id: str | None
    state: Literal["active", "held", "done"]
    held_reason: str | None
    opened_at: AwareDatetime | None
    last_version: int | None
    steps: dict[str, int]  # state -> how many


class TeamApprovalOut(Out):
    """The canary: the first cases need a person's approval of that case before anything is
    sent."""

    required: bool
    given: bool
    why_not: str | None  # why no approval stands now
    can_approve: bool  # this person, now
    approve_why_not: str | None
    needs_step_up: bool  # they may approve but must type their password again first
    step_up_url: str | None  # where they do (it returns to this case)


class CaseTeamOut(Out):
    case_id: uuid.UUID
    case_number: int
    case_state: CaseState
    post_enabled: bool  # case_team.post
    incident_id: str | None
    report_version: int | None
    decision: TeamDecisionOut
    plan_hash: str | None
    steps: list[TeamStepOut]
    problems: list[str]  # what stops a post from being sent, in words
    approval: TeamApprovalOut
    post: TeamPostOut | None
    authors: list[Author]
    logs_hidden: bool
    note: str | None


class ApproveTeamIn(In):
    """Approve exactly the plan the person read: its hash."""

    plan_hash: PlanHash


class TeamApprovedOut(Out):
    approval_id: Annotated[int, Field(ge=1, le=SAFE_MAX)]
    plan_hash: PlanHash
    expires_at: AwareDatetime
    words: str
