"""The typed contract of the case pages (Phase 3 plan §5 Q-B3, §7.1): the case list and a case in
analyst order, the case commands a person gives, the approvals queue, notes, and "Check more".

Text a person wrote (notes, attestations, reasons, Kibana comments) or that came from alerts or
logs is returned as stored: the app shows it as untrusted text, never as markup. Words that are
ARGUS's own (why an action is unavailable, what a state means) are plain sentences made by code.
Every error is ``ErrorOut``; a change names the version it was looked at (``expected_version``)
and is refused with 409 when the case has moved on."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Annotated, Any, Literal

from pydantic import AwareDatetime, BeforeValidator, Field

from argus.web.v1.models import (
    CLEAN,
    SAFE_MAX,
    SPACE,
    In,
    NoteText,
    Out,
    RequiredText,
    SigninsOut,
    VersionNumber,
    _json_integer,
)

CaseState = Literal["suspected", "open", "assigned", "contained", "closed"]
CaseSeverity = Literal["low", "medium", "high", "critical"]
CaseView = Literal["active", "attention", "mine", "suspected", "closed", "all", "notified", "queue"]
ClosureReason = Literal[
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
# what a person may ask a closure for: every reason but "duplicate" (a merge's own, never asked for)
RequestedReason = Literal[
    "remediated_verified",
    "remediated_unverified",
    "risk_accepted",
    "attempt_no_impact",
    "rule_false_positive",
    "benign_expected",
    "benign_policy",
    "created_in_error",
    "stopped_after_notice",
]
CaseAction = Literal[
    "take",
    "assign",
    "release",
    "contain",
    "request_closure",
    "merge",
    "reopen",
    "notify",
    "block",
    "withdraw_notice",
]
ApprovalKind = Literal["closure", "merge", "compensating", "resend", "reconfirm"]
ApprovalStatus = Literal["pending", "approved", "rejected", "expired", "stale"]
EntityNoteKind = Literal["ip", "domain", "host", "user"]
NoticeHow = Literal["email", "phone", "in_person", "through_it", "other"]
NoticeKind = Literal["owner", "block"]
ReminderKind = Literal["notify_again", "network_action"]
# who was told, who blocked: words a person wrote, one line
# One line of words a person typed (the machine's ``_told``): what is left after the whitespace at
# both ends is cut holds a letter or a sign and no control character, so the schema says what the
# command accepts (Schemathesis generates control characters from a bare pattern).
_CONTROLS = r"\x00-\x1f\x7f-\x9f"
LINE = rf"^[{SPACE}]*[^{_CONTROLS}{SPACE}](?:[^{_CONTROLS}]*[^{_CONTROLS}{SPACE}])?[{SPACE}]*$"
Told = Annotated[str, Field(min_length=1, max_length=200, pattern=LINE)]
Where = Annotated[str, Field(min_length=1, max_length=100, pattern=LINE)]
Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
RequestId = Annotated[int, Field(ge=1, le=SAFE_MAX), BeforeValidator(_json_integer)]
UserId = Annotated[int, Field(ge=1, le=SAFE_MAX), BeforeValidator(_json_integer)]
CaseVersion = Annotated[int, Field(ge=1, le=2**31 - 1), BeforeValidator(_json_integer)]


class PersonRef(Out):
    id: int
    username: str
    display_name: str


class CaseRef(Out):
    id: uuid.UUID
    number: int
    title: str
    state: CaseState


class CaseRowOut(Out):
    id: uuid.UUID
    number: int
    title: str
    state: CaseState
    severity: CaseSeverity
    version: int  # send it back as expected_version
    cause: Literal["verdict", "proposal", "person", "watch", "raised"]
    owner: PersonRef | None
    opened_at: datetime | None
    closed_at: datetime | None
    closure_reason: ClosureReason | None
    attention: str | None  # ARGUS's reason this case needs a person
    kibana_wait: str | None  # why Kibana does not have it yet
    investigations: int
    alerts: int
    first_alert_at: datetime | None
    last_alert_at: datetime | None
    updated_at: datetime
    in_kibana: bool  # a Kibana create was planned: later changes are mirrored too
    waiting_for_approval: int  # requests that a person still has to decide
    needs_attention: bool
    merged_into: CaseRef | None
    notified_at: datetime | None  # the owner was told: tracked quietly, in its own list
    blocked_at: datetime | None  # a network-side block is recorded


class CaseCounts(Out):
    active: int  # open, assigned or contained, apart from the notified ones
    notified: int  # open or assigned, the owner told: tracked quietly
    attention: int
    mine: int
    suspected: int
    closed: int
    queue: int  # the cases of Home's queue: the ones that need a person, for any reason
    all: int


class CasePage(Out):
    items: list[CaseRowOut]
    view: CaseView
    offset: int
    limit: int
    has_more: bool
    counts: CaseCounts


class RuleCountOut(Out):
    rule_name: str | None
    investigations: int
    alerts: int


class CaseSummaryOut(Out):
    investigations: int
    alerts: int
    rules: list[RuleCountOut]  # the busiest first, at most 8
    rules_total: int
    first_alert_at: datetime | None
    last_alert_at: datetime | None
    reviewed: int  # investigations a person has reviewed (their newest review counts)
    unreviewed: int


WhatsNewKind = Literal["case", "investigation", "verdict", "check", "kibana", "approval", "note"]


class WhatsNewItemOut(Out):
    at: datetime
    kind: WhatsNewKind
    text: str  # ARGUS's sentence
    by: str | None
    investigation_id: uuid.UUID | None


class WhatsNewOut(Out):
    """What changed since the person's previous visit (or, on a first visit, in the last two
    days)."""

    since: datetime
    first_visit: bool
    items: list[WhatsNewItemOut]  # newest first, at most 30


TimelineKind = Literal["case", "alerts", "verdict", "check", "kibana", "signin"]


class TimelineItemOut(Out):
    at: datetime
    until: datetime | None
    kind: TimelineKind
    text: str
    by: str | None
    investigation_id: uuid.UUID | None


class CaseMemberOut(Out):
    investigation_id: uuid.UUID
    version: int  # send it back as seen_version when asking for a check
    rule_name: str | None
    severity: str | None
    alert_count: int
    first_event_at: datetime | None
    last_event_at: datetime | None
    bucket_start: datetime
    human_state: Literal["unreviewed", "reviewed", "follow_up", "changed_since_review"]
    last_outcome: str | None
    link: str  # why it is in the case: verdict, proposal, actor, indicator, c2, person, merge
    link_value: str | None
    added_at: datetime
    added_by: str


class EntityNoteOut(Out):
    id: int
    author: str
    body: str
    created_at: datetime


class CaseIndicatorOut(Out):
    kind: str
    value: str
    role: Literal["actor", "c2", "indicator"]
    source: Literal["investigation", "threat_intel", "person", "merge"]
    notes: list[EntityNoteOut]  # the newest three
    note_count: int


class CaseActionStateOut(Out):
    """One action the case page offers, and whether this person may take it now. ``why_not`` is
    the reason in plain words when not (the same refusal the command would give)."""

    action: CaseAction
    label: str
    enabled: bool
    why_not: str | None


class ClosureChoiceOut(Out):
    reason: ClosureReason
    label: str
    meaning: str
    enabled: bool
    why_not: str | None
    note: Literal["none", "optional", "required"]
    approvers: int  # people who must approve it (two for the reasons that rest on a statement)
    note_hint: str | None


class MirrorWriteOut(Out):
    id: int
    op: str
    write_class: str
    state: str
    state_reason: str | None
    case_version: int
    planned_at: datetime
    sent_at: datetime | None
    verified_at: datetime | None


class FindingOut(Out):
    """What the read-back saw in Kibana. ``details`` holds a person's words as they wrote them
    (untrusted): a comment, the name that did it."""

    id: int
    kind: str
    words: str
    severity: Literal["alarm", "attention", "info"]
    found_at: datetime
    resolved_at: datetime | None
    details: dict[str, str]


MirrorState = Literal["not_in_kibana", "waiting", "planned", "mirrored", "paused", "deleted"]


class MirrorOut(Out):
    state: MirrorState
    words: str
    kibana_case_id: str | None
    kibana_status: str | None
    kibana_severity: str | None
    kibana_version: str | None
    tags: list[str]
    created_by: str | None
    sync_alerts: bool | None
    unmanaged: list[str]
    read_at: datetime | None
    kibana_updated_at: datetime | None
    paused_reason: str | None
    deleted_at: datetime | None
    writes: list[MirrorWriteOut]  # newest first, at most 20
    writes_total: int  # all of them (more than `writes` holds when it was cut)
    findings: list[FindingOut]  # unresolved first, newest first, at most 30
    findings_total: int


class NoteOut(Out):
    id: int
    author: str
    body: str
    created_at: datetime


HistoryKind = Literal["event", "request", "decision"]


class HistoryItemOut(Out):
    at: datetime
    kind: HistoryKind
    version: int | None
    text: str  # ARGUS's sentence
    by: str | None
    detail: str | None  # what the person typed (untrusted)


class DecisionRecordOut(Out):
    approver: PersonRef | None
    decision: Literal["approved", "rejected"]
    decided_at: datetime
    note: str | None
    counts: bool  # an approval counts only while its approver is not revoked since


class OutboxHoldOut(Out):
    """The Kibana write an approval is about (a re-confirmation or a resend)."""

    op: str
    write_class: str
    state: str
    state_reason: str | None


class YouOut(Out):
    can_decide: bool
    why_not: str | None
    decided: Literal["approved", "rejected"] | None


class ApprovalOut(Out):
    id: int
    kind: ApprovalKind
    words: str  # "Close case 12 as benign: expected activity"
    reason: ClosureReason | None
    case: CaseRef
    case_version: int
    target: CaseRef | None
    status: ApprovalStatus
    status_words: str
    requested_by: PersonRef | None
    proposed_by: str | None
    requested_at: datetime
    expires_at: datetime
    required: int
    decisions: list[DecisionRecordOut]
    payload: dict[str, Any]  # the exact Kibana writes; what the approver signs for
    payload_hash: str
    alerts_then: int
    alerts_now: int | None
    alerts_same: bool | None
    note: str | None
    kibana_version: str | None
    hold: OutboxHoldOut | None
    you: YouOut
    group: str | None


SuggestionKind = Literal["shared", "tie", "also"]


class CaseSuggestionOut(Out):
    """An investigation that may belong to the case and was not joined (Q-C2). ``link_value`` and
    ``why`` name values from alerts: untrusted text."""

    id: int
    investigation_id: uuid.UUID
    rule_name: str | None
    severity: str | None
    alert_count: int
    kind: SuggestionKind
    link: Literal["actor", "c2", "indicator"]
    link_value: str | None
    why: str
    created_at: datetime


WatchOutcome = Literal["active", "quiet", "unverified", "not_checked"]


class WatchDayOut(Out):
    """One finished UTC day's answers of the still-active watch for the case: ARGUS's own alerts,
    and the proxy logs by outcome (one answer for each address). The reasons (text from the
    answers) are untrusted."""

    day: date
    alerts: WatchOutcome | None
    alerts_reason: str | None
    proxy: dict[str, int]  # outcome -> how many addresses
    proxy_reasons: list[str]  # at most three distinct ones
    seen: list[str]  # what an answer of "activity seen" recorded (untrusted text), at most four


class WatchStatusOut(Out):
    """What the watch can say about the case (``argus case watch status``'s page form)."""

    mode_words: str
    last_run_at: datetime | None  # the watch's last run (any case), None: it never ran
    late: bool  # the daily run is more than a day and a half old
    days: list[WatchDayOut]  # newest first, at most seven
    proxy_checks_due: int  # none answered yet: how many the case needs
    quiet: bool | None  # verifiably quiet for 72 hours; None: not worked out for this person
    quiet_words: str | None


class NoticeRecordOut(Out):
    """A notice or a block a person recorded. The words are theirs, shown as untrusted text."""

    kind: NoticeKind
    at: datetime  # when it happened, as they said
    told: str  # who was told (owner), or who blocked it (block)
    how: str  # how they were told, or where it was blocked
    managed: (
        bool | None
    )  # owner notices: the machines are organisation-managed (from the asset map)
    note: str | None
    by: str  # the person who recorded it
    case_version: int
    withdrawn: bool = False  # they withdrew it: it was recorded by mistake (it is kept as said)


class ReminderOut(Out):
    """A suggestion from ARGUS for a notified case that stays active: never an alarm."""

    kind: ReminderKind
    words: str
    suggested_at: datetime


class ChangeOut(Out):
    """An investigation raised because something changed since the notice."""

    investigation_id: uuid.UUID
    rule_name: str
    why: str
    last_event_at: datetime | None


class DayAlertsOut(Out):
    day: date  # a day in the site's zone (site.timezone), as the reports count them
    alerts: int


class NewDestinationOut(Out):
    """An address or a name a notified device reached after the notice that nobody flags and the
    case did not hold. ARGUS counts it and does not raise it; if a list or the outside look-ups
    flag it later, the investigation comes back as a change. The value is untrusted text."""

    kind: Literal["ip", "domain"]
    value: str
    added_at: datetime


class KnownOut(Out):
    """A confirmed case's owner-notified record (AR4b, D-169): who was told, the alerts ARGUS has
    counted since (it does not raise them), the changes it did raise, the suggestions it made,
    and the block list. ``notified_at`` is None until a person records a notice."""

    notified_at: datetime | None
    blocked_at: datetime | None
    managed: (
        bool | None
    )  # the machines are organisation-managed (the watch and containment still apply)
    line: str | None  # "still active: ..." or "blocked at the network; ..."
    alerts: int  # since the notice
    days: int
    alerts_per_day: list[DayAlertsOut]
    trend: str
    last_alert_at: datetime | None
    devices: int
    notices: list[NoticeRecordOut]
    reminders: list[ReminderOut]
    changes: list[ChangeOut]
    new_destinations: list[NewDestinationOut]  # since the notice, the first 50
    new_destinations_total: int  # all that are kept (it stops at 500)
    notify: CaseActionStateOut
    block: CaseActionStateOut
    withdraw_notice: CaseActionStateOut
    blocklist_entries: int  # what the ready block list holds (/cases/{id}/blocklist)


class CaseDetail(Out):
    case: CaseRowOut
    cause_words: str
    parent: CaseRef | None
    children: list[CaseRef]  # at most 20
    children_total: int
    summary: CaseSummaryOut
    whats_new: WhatsNewOut
    timeline: list[TimelineItemOut]  # the newest 80, oldest first
    timeline_total: int  # all it could list (more than `timeline` holds when it was cut)
    lead_investigation_id: uuid.UUID | None  # the report shown for evidence, hypotheses, unknowns
    investigations: list[CaseMemberOut]
    investigations_total: int
    indicators: list[CaseIndicatorOut]  # at most 300
    indicators_total: int
    suggestions: list[CaseSuggestionOut]  # newest first, at most 50
    suggestions_total: int
    watch: WatchStatusOut | None  # None: the watch does not look at this case
    known: KnownOut | None  # the owner-notified record; None unless open or assigned
    actions: list[CaseActionStateOut]
    closure_choices: list[ClosureChoiceOut]
    assignees: list[PersonRef]  # who the case can go to; empty for an account that cannot assign
    approvals: list[ApprovalOut]  # the newest ten
    approvals_total: int
    mirror: MirrorOut
    notes: list[NoteOut]  # the newest 200
    notes_total: int
    history: list[HistoryItemOut]  # the newest 200
    history_total: int
    logs_hidden: bool  # this account may not see what the logs said (the lead report hides it)
    signins: SigninsOut | None  # who used its devices; None: not set up on this server


class StepUpOut(Out):
    valid: bool
    valid_until: datetime | None
    url: str  # where the person confirms their password, and returns to the queue


class GroupItemOut(Out):
    request_id: int
    payload_hash: str
    case_number: int
    case_title: str


class ApprovalGroupOut(Out):
    """Up to twenty alike requests that may be approved together: the sample is approved one by
    one first, then the rest (plan §7.1)."""

    key: str
    reason: ClosureReason
    words: str
    items: list[GroupItemOut]
    sample: list[int]  # request ids


class ApprovalQueueOut(Out):
    pending: list[ApprovalOut]  # waiting for a decision, oldest first, at most 300
    pending_total: int  # how many are waiting (more than `pending` holds when it was cut)
    recent: list[ApprovalOut]  # decided or expired in the last three days, newest first
    groups: list[ApprovalGroupOut]
    step_up: StepUpOut
    can_sign: bool  # this server holds the key that signs decisions


class CaseChangeIn(In):
    """A change to a case, at the version the person looked at: 409 when it moved."""

    expected_version: CaseVersion


class AssignIn(CaseChangeIn):
    user_id: UserId


class NoticeIn(CaseChangeIn):
    """Record that the device's owner (or its department, hostel or lab) was told: who, how, and
    when (default now). ARGUS then tracks the case quietly and speaks again only on change."""

    told: Told
    how: NoticeHow
    at: AwareDatetime | None = None
    note: NoteText | None = None


class WithdrawNoticeIn(CaseChangeIn):
    """Withdraw the notice recorded by mistake: who is withdrawing it (default: you) and why. The
    case is not notified any more and ARGUS stops absorbing its device's alerts; what it already
    decided known stays decided. The notice rows stay as the record of what was said."""

    who: Told | None = None
    reason: RequiredText


class BlockIn(CaseChangeIn):
    """Record that the case's servers or domains were blocked at the network: who did it, where,
    and when (default now)."""

    by: Told
    where: Where
    at: AwareDatetime | None = None
    note: NoteText | None = None


class ContainIn(CaseChangeIn):
    attestation: RequiredText  # the person's statement that it is contained


class ReopenIn(CaseChangeIn):
    reason: RequiredText


class ClosureRequestIn(CaseChangeIn):
    """Ask for the closure whose preview the person read: ``payload_hash`` is that preview's
    hash, and the request is refused (409) if the writes would be anything else now."""

    reason: RequestedReason
    note: NoteText | None = None
    payload_hash: Sha256


class MergeIn(CaseChangeIn):
    """Merge into another case. A confirmed case asks for an approval (``payload_hash`` from
    the preview, required); a suspected case is merged at once."""

    target_case_id: uuid.UUID
    note: NoteText | None = None
    payload_hash: Sha256 | None = None


class CaseChanged(Out):
    case: CaseRowOut
    result: Literal["done", "requested", "merged"]
    request_id: int | None  # the approval request a closure or merge made


class SuggestionDismissed(Out):
    case_id: uuid.UUID
    suggestion_id: int


class ReminderDismissed(Out):
    case_id: uuid.UUID
    kind: ReminderKind


class BlockEntryOut(Out):
    """One thing to block, with the outside evidence ARGUS holds for it."""

    type: Literal["family", "domain", "address"]  # a registered domain (every name under it)
    value: str
    evidence: str  # "7 of 94 engines flag it", or that there is no outside record yet
    engines_flagging: int | None
    engines_total: int | None
    owner: str | None  # the network's owner, for an address
    registered: str | None  # the day a domain was registered
    first_seen_on_campus: datetime | None
    campus_devices: int
    evidence_checked: datetime | None


class BlocklistOut(Out):
    """The case's ready block list (AR4b, D-169): what the university can block at DNS, the
    firewall or the web proxy for everyone. Shared addresses and names are left out (counted in
    ``skipped``); the same list is a CSV (``/blocklist.csv``) and an e-mail (``/blocklist.txt``)."""

    case_number: int
    title: str
    entries: list[BlockEntryOut]
    skipped: int
    cut: bool
    notified_at: datetime | None
    blocked_at: datetime | None


class ClosurePreviewOut(Out):
    """The exact writes asking for this closure binds: the same builder as the request's, so
    what is shown is what is stored and what the approver reads."""

    case_id: uuid.UUID
    case_version: int  # the version the case is at now
    bound_version: int  # the version the request will bind (the request event is the next one)
    reason: ClosureReason
    target: CaseRef | None
    payload: dict[str, Any]
    payload_hash: str
    in_kibana: bool
    words: str
    approvers: int


class NoteCreateIn(In):
    body: RequiredText


class NoteCreated(Out):
    note: NoteOut
    duplicate: bool  # the same note by the same person a moment ago: nothing was added


class EntityNoteIn(In):
    kind: EntityNoteKind
    value: Annotated[str, Field(min_length=1, max_length=512, pattern=CLEAN)]
    body: RequiredText


class EntityNotesOut(Out):
    kind: EntityNoteKind
    value: str
    items: list[EntityNoteOut]


class DecisionIn(In):
    """Approve or reject a request: ``payload_hash`` is the one the person read. ``group`` names
    the twenty-or-fewer requests of the group this one is approved with (its sample first)."""

    decision: Literal["approved", "rejected"]
    payload_hash: Sha256
    note: NoteText | None = None
    group: Annotated[list[RequestId], Field(min_length=2, max_length=20)] | None = None


class AppliedOut(Out):
    case_id: uuid.UUID
    number: int
    state: CaseState
    version: int


class DecisionDone(Out):
    request_id: int
    status: Literal["approved", "rejected", "pending"]
    applied: list[AppliedOut]  # the closure or merge this decision completed


class GroupItemIn(In):
    request_id: RequestId
    payload_hash: Sha256


class GroupDecisionIn(In):
    """Approve the rest of a group, after its sample: each request with the hash read."""

    items: Annotated[list[GroupItemIn], Field(min_length=2, max_length=20)]
    note: NoteText | None = None


class GroupDecisionDone(Out):
    decided: list[DecisionDone]


class CheckTemplateOut(Out):
    template: str
    words: str  # what it asks
    takes: Literal["internal", "public", "address", "indicator"]
    takes_words: str
    heavy: bool
    cost_words: str


class CheckLineOut(Out):
    template: str
    eid: str | None
    status: str | None
    server_ms: int | None
    heavy: bool
    sent: bool | None
    why_not: str | None


class InvestigationCheckOut(Out):
    """A person's request for one more check and its record: its state, the E-numbers its
    answers have in the report, what it cost the SIEM, and whether an assessment has read it."""

    id: int
    version: int
    template: str
    words: str
    entity: str
    requested_by: str | None
    requested_at: datetime
    status: Literal["queued", "running", "done", "refused", "failed"]
    status_words: str
    started_at: datetime | None
    finished_at: datetime | None
    requests: int | None
    heavy_requests: int | None
    server_ms: int | None
    lines: list[CheckLineOut]
    dossier: str | None  # the dossier its answers left
    assessed: bool
    why_not: str | None  # why it was refused or failed, ARGUS's words


class CheckLimitsOut(Out):
    open_per_person: int
    open_now: int  # this person's, queued or running
    per_day: int
    today: int  # this person's, since 00:00 UTC


class InvestigationChecksOut(Out):
    investigation_id: uuid.UUID
    version: int
    items: list[InvestigationCheckOut]  # newest first, at most 30
    templates: list[CheckTemplateOut]
    limits: CheckLimitsOut


class CheckIn(In):
    """One approved template on one address or domain, about the investigation as the person
    saw it (``seen_version``: 409 when it has moved on)."""

    template: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_.]*$")]
    entity: Annotated[str, Field(min_length=1, max_length=253, pattern=CLEAN)]
    seen_version: VersionNumber


class CheckQueued(Out):
    result: Literal["queued", "open"]  # open: the same request is queued or running already
    id: int | None  # the request to follow (open: the one already waiting)
