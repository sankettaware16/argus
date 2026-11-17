"""The typed contract of ``/api/v1`` (Phase 3 plan §4, §7.5; Q-A1): what every classic page
shows and does, for the app at ``/app`` and its generated client.

Words (DQ23, D-110): an *investigation* is one rule, one actor and one IST day (what the
classic dashboard called a case); a *case* is one real problem across days, hosts and rules
(Q-C1); an *incident* is a case a person confirmed. Text from alerts, logs or models is
returned as stored: the client shows it as untrusted text. Every error is ``ErrorOut``."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

from argus.report.model import Report


class Out(BaseModel):
    """A response: exactly these fields."""

    model_config = ConfigDict(extra="forbid")


class In(BaseModel):
    """A request body: exactly these fields, never another (no mass assignment)."""

    model_config = ConfigDict(extra="forbid")


ErrorCode = Literal[
    "unauthenticated",  # 401: no session, or it ended: sign in at /signin
    "csrf",  # 403: a change without the session's X-CSRF-Token
    "forbidden",  # 403: the account lacks the capability the route needs
    "origin",  # 403: not a request from this site's own page
    "network",  # 403: the client is outside the allowed networks
    "step_up_required",  # 403: confirm your password at /stepup first
    "not_found",  # 404
    "method_not_allowed",  # 405
    "conflict",  # 409: it changed while you looked: read it again
    "not_ready",  # 409: ARGUS has not finished preparing it
    "invalid",  # 400 or 422: the request does not match this contract
    "unavailable",  # 503: ARGUS cannot reach its database, or that service is not here
    "internal",  # 500: something went wrong in ARGUS (logged; not documented per operation)
]


class ErrorOut(Out):
    """Every error: a plain sentence and a stable code."""

    detail: str
    code: ErrorCode


CapabilityName = Literal[
    "view", "see_logs", "review", "answer_gold", "manage_cases", "reopen", "approve", "admin"
]  # every Capability (a unit test keeps the two equal)
Outcome = Literal[
    "benign_expected", "benign_policy", "rule_false_positive", "true_positive", "inconclusive"
]
HumanState = Literal["unreviewed", "reviewed", "follow_up", "changed_since_review"]
AssessmentStatus = Literal["queued", "running", "proposed", "no_decision", "failed"]
View = Literal["attention", "open", "reviewed", "all", "known"]
Sort = Literal["newest", "oldest", "urgent", "reviewed", "queue"]
EntityKind = Literal["ip", "host", "domain", "user"]
StepStatus = Literal["answered", "deferred", "manual", "unknown", "other"]
ReadingKind = Literal["undecided", "citation", "benign_citation", "floor"]


class UserOut(Out):
    id: int
    username: str
    display_name: str


class CapabilityOut(Out):
    name: CapabilityName
    label: str  # what it lets the person do, in plain words


class UnverifiedOut(Out):
    """ELK sign-in only: ARGUS cannot confirm the person's access in ELK right now. In an
    ``outage`` (the SIEM was unreachable) reading and reviewing go on, but nothing reaches Kibana;
    after ARGUS's own ``refused`` (its limits) reading only."""

    since: datetime
    why: Literal["outage", "refused"]


class SiteOut(Out):
    """How the pages write times and names, from the ``site`` settings (D-284): the zone times
    are shown in, the label after them, the word for the organisation's own network and the
    organisation's names."""

    timezone: str  # an IANA zone name
    timezone_label: str | None  # the fixed label ("IST"); None: the zone's offset ("UTC-04:00")
    own_network_noun: str
    organisation_name: str
    organisation_short_name: str
    organisation_kind: str
    organisation_units: str
    organisation_reviewers: str


class SessionOut(Out):
    """Who is signed in, what they may do, and when the session ends. The CSRF token goes in
    ``X-CSRF-Token`` on every change; keep it in memory only."""

    user: UserOut
    mode: Literal["local", "elk"]  # a local password account, or an ELK sign-in
    break_glass: bool  # the emergency account (mode "local"): view and review only, never to Kibana
    unverified: UnverifiedOut | None  # set when ARGUS cannot confirm the person's access in ELK
    capabilities: list[CapabilityOut]
    csrf_token: str
    expires_at: datetime  # the absolute end, whatever happens
    idle_expires_at: datetime  # the end if no request of the person's own comes before
    idle_timeout_s: int
    stepped_up_at: datetime | None  # when the person last confirmed their password
    step_up_valid_until: datetime | None
    since: datetime | None  # when their previous session was last seen ("since your visit")
    site: SiteOut
    setup_pending: bool = False
    """The first-time setup is not finished on this host (D-328): an administrator is led to it,
    anyone else told an administrator still has to finish it."""


class KeyField(Out):
    field: str
    value: Any


class AiVerdictOut(Out):
    """The assessment a reviewer most wants to see first: a proposal first, the AI
    investigator's before the decision engine's."""

    assessor: str
    source: str  # who: "the AI investigator" or "the decision engine"
    status: AssessmentStatus
    outcome: Outcome | None
    confidence: float | None


class KnownRefOut(Out):
    """An investigation that belongs to a notified case (AR4b, D-169): ``outcome`` is ``known``
    (the owner was told; ARGUS counts its alerts and does not raise them) or ``changed``
    (something is new since the notice; ``why`` says what, and it is in Needs attention)."""

    case_id: uuid.UUID
    case_number: int
    outcome: Literal["known", "changed"]
    why: str | None
    notified_at: datetime | None


class StanceOut(Out):
    """What ARGUS thinks of an investigation, in the order a person wants it (AR4, D-182): a
    **recommendation** (``recommends``: a proposal of its own, or the one its pattern's run made),
    else a **reading** (``reading``: a run that proposed nothing, with why it did not), else
    ``none``. A reading and a pattern's run are never a proposal for this investigation:
    ``acceptable`` is true only for its own current proposal, which ``/accept`` takes."""

    kind: Literal["recommends", "reading", "none"]
    outcome: Outcome | None
    confidence: float | None
    source: str | None  # "the AI investigator" or "the decision engine"
    why: str | None  # a reading: why it is not a proposal, in plain words
    assessment_id: int | None
    from_investigation_id: uuid.UUID | None  # the pattern's run was made on this investigation
    acceptable: bool
    pattern_investigations: int | None  # how many investigations the run stands for
    pattern_alerts: int | None


class InvestigationOut(Out):
    id: uuid.UUID
    rule_id: str
    rule_name: str | None
    # the row's two lines in plain words, from the investigation's own facts (naming v2): who
    # did what by its evidence flags (never the rule's name), and its key ("from 10.0.0.7")
    title: str
    key_words: str
    key_fields: list[KeyField]
    bucket_start: datetime
    alert_count: int
    duplicate_count: int
    first_event_at: datetime | None
    last_event_at: datetime | None
    severity: str | None
    risk_score: float | None
    version: int
    created_at: datetime
    continues_id: uuid.UUID | None  # the same activity the day before
    human_state: HumanState
    latest_review: int | None  # send it back as seen_review
    new_since_review: int
    last_outcome: Outcome | None
    last_reviewed_at: datetime | None
    last_reviewer: str | None
    reasons: list[str]  # reasons to look, never verdicts
    ai: AiVerdictOut | None
    known: KnownRefOut | None  # the notified case that counts it as a known infection


class InvestigationPage(Out):
    items: list[InvestigationOut]
    view: View
    sort: Sort
    offset: int
    limit: int
    has_more: bool


class CountsOut(Out):
    """The Inbox's summary: investigations in each state; decided in the last 24 hours.
    ``attention`` is new work; ``known`` counts what the notified cases' known infections keep out
    of it (AR4b): both together are what Needs attention was."""

    attention: int
    known: int
    open: int
    follow_up: int
    changed: int
    reviewed: int
    reviewed_today: int
    all: int


class CoverageRunOut(Out):
    start_at: datetime
    detail: str | None


class CoverageOut(Out):
    """Alerts may be missing for this span (the collector's own outages, a rule at its alert
    limit)."""

    kind: str
    start_at: datetime
    end_at: datetime | None
    text: str
    runs: list[CoverageRunOut]


class ValueCount(Out):
    value: Any
    count: int


class FieldFactOut(Out):
    field: str
    stand_in: str | None  # the field the values were read from, when not this one
    top: list[ValueCount]
    distinct: int


class StepOut(Out):
    """One of the rule's own investigation steps and what ARGUS found for it."""

    number: int | None
    text: str
    status: StepStatus
    sentence: str
    shown: list[FieldFactOut]


class AddressOut(Out):
    address: str
    kind: str  # asset, internal, internal, public, special, invalid
    asset: str | None


class RelatedOut(Out):
    investigation_id: uuid.UUID
    rule_id: str | None
    rule_name: str | None
    key_fields: list[KeyField]
    bucket_start: str | None
    shared: int


class DossierOut(Out):
    """What ARGUS checked: the newest dossier, in the words the investigation page uses."""

    version: int
    pack: str
    status: str
    partial_reason: str | None
    created_at: datetime
    facts: list[str]  # key facts, in ARGUS's sentences
    decoded_paths: list[str]
    addresses: list[AddressOut]
    related: list[RelatedOut]
    steps: list[StepOut]
    has_note: bool | None  # whether the rule has investigation steps in its note
    complete: bool  # every alert read
    alerts_read: int


class HypothesisOut(Out):
    name: str
    evidence_for: list[str]
    evidence_against: list[str]


class AnswerOut(Out):
    outcome: Outcome | None
    confidence: float | None
    explanation: str | None
    hypotheses: list[HypothesisOut]
    cites: list[str]


class CheckOut(Out):
    tool: str
    value: str
    result: str


class SpecialistOut(Out):
    domain: str
    notes: str


class RunOut(Out):
    """The AI investigator's run: its answer, its SIEM checks, its specialists, its cost."""

    answer: AnswerOut | None
    checks: list[CheckOut]
    specialists: list[SpecialistOut]
    rounds: int | None
    calls: int | None
    models: list[str]
    cost_usd: float | None
    seconds: float | None


class ReadingFactOut(Out):
    text: str
    checked: bool  # the quote was found in the evidence the model was given


class ReadingOut(Out):
    """ARGUS's reading of an item the AI investigator did not propose an outcome for (AR1): what
    it made of it and why that is not a proposal. Never a proposal itself."""

    kind: ReadingKind
    outcome: Outcome
    confidence: float | None
    headline: str  # "ARGUS's reading: ... (75%) — not proposed because ..." in plain words
    why: str  # the "because" part
    reason: str | None
    facts: list[ReadingFactOut]


class AssessmentOut(Out):
    id: int
    assessor: str
    source: str
    status: AssessmentStatus
    outcome: Outcome | None
    confidence: float | None
    decided_by: str
    reasons: list[str]
    run: RunOut | None
    reading: ReadingOut | None  # a no_decision run's reading, when it left one
    created_at: datetime
    finished_at: datetime | None


class GoldSuggestionOut(Out):
    outcome: str | None
    source: str | None
    reasons: list[str]


class GoldItemOut(Out):
    """The investigation is in the gold set: the answer key's item and its newest answer."""

    split: str
    why: list[str]
    suggestion: GoldSuggestionOut
    outcome: Outcome | None
    note: str | None
    answered_by: str | None
    answered_at: datetime | None


class ReviewOut(Out):
    id: int
    action: Literal["reviewed", "follow_up", "note"]
    outcome: Outcome | None
    note: str | None
    version: int
    alert_count: int
    created_at: datetime
    reviewer: str


class FieldCount(Out):
    field: str
    count: int  # how many of the newest alerts have it


class ReportsOut(Out):
    """report@2 of the investigation (Q-F2): one report per assessor's newest assessment at the
    investigation's current version, the AI investigator's first; the newest dossier's alone when
    nothing assessed it (none when there is no dossier yet). For an account without
    ``see_logs`` every result read from the logs is replaced by "Hidden: needs log access in
    ELK." (``hidden`` counts them), as the report's own contract says."""

    items: list[Report]
    logs_hidden: bool  # this account may not see what the logs said


class SamePatternOut(Out):
    """The investigator's run on another investigation of the same pattern and IST day (AR2),
    shown as "same pattern as <id>". Display only: it is not this investigation's assessment, so
    it cannot be accepted and nothing is scored, closed or written back from it."""

    investigation_id: uuid.UUID  # the investigation the run was made on
    earlier: bool  # it is this investigation, before it changed
    assessment: AssessmentOut


#  the probable users of a device, from the SSO sign-ins ARGUS kept. Account names are
# personal data and untrusted text (they come from the logs): an account without ``see_logs`` gets
# ``hidden`` true, counts and no name in any field. ``lead`` is the one wording the app puts above
# every such card: a lead, not proof.

SigninState = Literal["likely", "possible", "shared", "none_seen", "unknown"]
SigninGapWhy = Literal["not_looked", "incomplete", "partial_day", "logs_gone"]


class SigninAccountOut(Out):
    """One account's sign-ins from the device over the days of the window."""

    user: str  # untrusted text
    first_at: datetime
    last_at: datetime
    events: int
    successes: int
    failures: int
    days: list[date]
    devices: list[str]  # browser and system in words: "Chrome on Windows"


class SigninGapOut(Out):
    day: date  # a UTC day
    why: SigninGapWhy
    words: str


class SigninHandOut(Out):
    """A day the device had exactly one account: when they differ, the address changed hands."""

    day: date
    user: str  # untrusted text


class SigninDeviceOut(Out):
    address: str
    state: SigninState
    words: str  # the state in plain words; names only when the account may see them
    accounts: list[SigninAccountOut]  # likely: one; possible: ordered; unknown: so far; else none
    account_count: int
    at_least: bool  # more accounts signed in than are listed
    shared_days: list[date]
    gaps: list[SigninGapOut]
    hands: list[SigninHandOut]
    failed_only: list[str]  # accounts with only failed sign-ins in the window (untrusted text)
    outside_window: int  # accounts that signed in on those days but not in the window's hours


class SigninStateCountOut(Out):
    state: SigninState
    devices: int


class SigninsOut(Out):
    enabled: bool  # the sign-in lookups are switched on
    hidden: bool  # this account may not see account names (needs log access)
    lead: str
    states: list[SigninStateCountOut]  # devices by state, for the whole set
    devices: list[SigninDeviceOut]  # at most 100: the ones with a probable user first
    devices_total: int


class InCaseOut(Out):
    """The incident (case) an alert group belongs to: it is decided there, not on its own."""

    id: uuid.UUID
    number: int
    title: str
    state: Literal["suspected", "open", "assigned", "contained", "closed"]


class InvestigationDetail(Out):
    investigation: InvestigationOut
    coverage: list[CoverageOut]
    dossier: DossierOut | None
    assessments: list[AssessmentOut]  # each assessor's newest, the investigator first
    same_pattern: SamePatternOut | None = None  # when it has no investigator run of its own
    acceptable_assessment_id: int | None  # the current proposal, while not reviewed
    stance: StanceOut  # what ARGUS thinks of it: a recommendation, a reading, or nothing
    ask_available: bool  # whether this server can ask the AI investigator
    gold: GoldItemOut | None
    reviews: list[ReviewOut]  # newest first
    alert_fields: list[FieldCount]  # the columns a reviewer can add to the alerts
    signins: SigninsOut | None  # who used its devices; None: not set up on this server
    case: InCaseOut | None = None  # the incident it belongs to (UI v2 A15); None: in none


class EntityOut(Out):
    kind: str
    value: Any


class AlertOut(Out):
    alert_id: str
    detected_at: datetime | None
    event_time: datetime | None
    status: str
    workflow_status: str | None
    duplicate_of: str | None
    late_arrival: bool
    severity: str | None
    entities: list[EntityOut]
    cells: dict[str, str]  # the chosen columns' values, as text


class AlertsOut(Out):
    total: int
    columns: list[str]
    items: list[AlertOut]  # the newest first, at most 200


class RawAlertOut(Out):
    alert_id: str
    investigation_id: uuid.UUID
    raw: dict[str, Any]  # as the SIEM stored it


def _json_integer(value: Any) -> Any:
    """An integer as JSON Schema means it: never true or "1" (pydantic's lax mode would take
    both as 1)."""
    if value is not None and (isinstance(value, bool) or not isinstance(value, int | float)):
        raise ValueError("a whole number")
    return value


def _json_boolean(value: Any) -> Any:
    if not isinstance(value, bool):
        raise ValueError("true or false")
    return value


SAFE_MAX = 2**53 - 1  # the largest whole number a JavaScript client holds exactly
ReviewId = Annotated[int, Field(ge=1, le=SAFE_MAX), BeforeValidator(_json_integer)]
VersionNumber = Annotated[int, Field(ge=0, le=2**31 - 1), BeforeValidator(_json_integer)]
AssessmentId = Annotated[int, Field(ge=1, le=SAFE_MAX), BeforeValidator(_json_integer)]
Flag = Annotated[bool, BeforeValidator(_json_boolean)]
CLEAN = r"^[^\x00]*$"  # Postgres stores no NUL: refused at the door (422), never a 500
NoteText = Annotated[str, Field(min_length=1, max_length=4000, pattern=CLEAN)]
# Words a person must have written (a case note, an attestation, a reason): at least one character
# that is not whitespace as ``str.strip()`` sees it, which is what the server checks (a text of
# only spaces matched the plain pattern and was refused 422). The class is the
# code points Python calls whitespace; a unit test keeps it equal. No look-ahead: pydantic's
# regex engine has none.
SPACE = r"\t-\r\x1c-\x20\x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000"
WORDS = rf"^[^\x00]*[^\x00{SPACE}][^\x00]*$"
RequiredText = Annotated[str, Field(min_length=1, max_length=4000, pattern=WORDS)]


class ReviewedIn(In):
    """Mark it reviewed: a decision is a label, so the outcome is required (D-067).
    ``also_gold`` also saves the outcome as your gold-set answer (needs answer_gold)."""

    action: Literal["reviewed"]
    outcome: Outcome
    note: NoteText | None = None
    seen_review: ReviewId | None  # the latest review you saw (None: there was none)
    seen_version: VersionNumber  # the version you looked at
    also_gold: Flag = False


class FollowUpIn(In):
    """Ask for a follow-up; an outcome and a note are optional."""

    action: Literal["follow_up"]
    outcome: Outcome | None = None
    note: NoteText | None = None
    seen_review: ReviewId | None
    seen_version: VersionNumber
    also_gold: Flag = False


class NoteIn(In):
    """A note alone: it does not change the investigation's state."""

    action: Literal["note"]
    note: NoteText
    seen_review: ReviewId | None
    seen_version: VersionNumber


ReviewIn = Annotated[ReviewedIn | FollowUpIn | NoteIn, Field(discriminator="action")]


class ReviewCreated(Out):
    review_id: int
    version: int
    gold_saved: bool


class GoldAnswerIn(In):
    outcome: Outcome
    note: NoteText | None = None


class GoldSaved(Out):
    next_investigation_id: uuid.UUID | None  # the next unanswered item, if any


class AcceptIn(In):
    assessment_id: AssessmentId


class Accepted(Out):
    assessment_id: int
    investigation_id: uuid.UUID


class AskOut(Out):
    result: Literal["queued", "exists"]  # exists: it has assessed what this shows already


class ProposalOut(Out):
    assessment_id: int
    investigation_id: uuid.UUID
    rule: str
    alerts: int
    bucket_start: datetime
    reason: str


class ProposalGroupOut(Out):
    """Proposals decided the same way; confirm them together after the audit sample."""

    group: str  # send it back to confirm
    source: str
    decided_by: str
    outcome: Outcome | None
    rule: str | None  # the investigator's groups are per rule
    models: list[str]
    size: int
    items: list[ProposalOut]  # at most 500
    sample: list[ProposalOut]  # the audit sample, chosen at random each day


class ConfirmIn(In):
    group: Annotated[str, Field(min_length=1, max_length=600, pattern=CLEAN)]
    assessment_ids: Annotated[list[AssessmentId], Field(min_length=1, max_length=500)]


class ConfirmOut(Out):
    accepted: int
    skipped: int  # changed, no longer current, or of another group


class PatternMemberOut(Out):
    investigation_id: uuid.UUID
    version: int
    latest_review: int | None


class PatternCommonOut(Out):
    field: str
    values: list[str]


class PatternRecommendationOut(Out):
    """ARGUS recommends closing these members of a pattern as ``outcome`` (AR4, D-182): every
    member with a proposal has the same closing outcome and none has a true positive it did not
    propose. ``members`` are the ones with a proposal; the others are not covered."""

    outcome: Outcome
    confidence: float | None  # the least sure of the proposals
    source: str  # "the AI investigator", "the decision engine" or "ARGUS"
    members: list[uuid.UUID]
    covered: int
    total: int


class PatternOut(Out):
    """Unreviewed investigations the same rule found the same things in: decide them
    together."""

    rule_id: str
    rule_name: str | None
    steps: list[str]
    listed: bool  # a threat-list hit
    common: list[PatternCommonOut]
    alerts: int
    members: list[PatternMemberOut]
    recommendation: PatternRecommendationOut | None = None  # when ARGUS recommends closing them


class PatternPageOut(Out):
    """The Patterns page: the groups, and what they were made from. The groups are made from a
    sample, the newest investigations not reviewed yet that have a dossier (``read`` of them, at
    most ``limit``); when ``sampled``, older ones are not in any group here."""

    groups: list[PatternOut]
    read: int
    limit: int
    sampled: bool


class PatternBriefOut(Out):
    """A pattern ARGUS recommends closing, as Home shows it (AR4 review, D-186): the investigations
    one run of the AI investigator stands for on an IST day, counted now (not reviewed, not a
    known infection's). ``covered`` of ``investigations`` have a proposal; the rest have none yet
    and are left out of a close. Real totals: no dossier is read and nothing is sampled."""

    pattern: str  # the pattern's hash; with ``day`` it names the pattern
    day: date
    rule_id: str
    rule_name: str | None
    investigations: int
    alerts: int
    covered: int
    outcome: Outcome  # the one closing outcome every proposal has
    confidence: float | None  # the least sure of the proposals
    source: str  # "the AI investigator", "the decision engine" or "ARGUS"
    examples: list[uuid.UUID]  # a few of its investigations, the biggest first


class PatternSummaryOut(Out):
    """The patterns ARGUS recommends closing: how many there are, how many investigations they
    cover, and the largest few."""

    total: int
    investigations: int  # covered across all of them
    items: list[PatternBriefOut]  # the largest, at most 8


class PatternCloseOut(Out):
    """What closing one pattern names, read when the person asks: the pattern as it is now and the
    members ARGUS has a proposal for (at most 200), each with the version and latest review it
    was read at. 404 when ARGUS no longer recommends closing it."""

    brief: PatternBriefOut
    members: list[PatternMemberOut]


class PatternItemIn(In):
    investigation_id: uuid.UUID
    version: VersionNumber
    latest_review: ReviewId | None


class PatternReviewIn(In):
    outcome: Outcome
    items: Annotated[list[PatternItemIn], Field(min_length=1, max_length=200)]


class PatternReviewOut(Out):
    reviewed: int
    changed: int  # changed since you looked: left as they are


class RuleOut(Out):
    rule_id: str
    rule_name: str | None
    investigations: int
    open: int
    alerts: int
    last_event_at: datetime | None
    type: str | None
    revision: int | None
    interval: str | None
    max_signals: int | None
    execution_status: str | None
    truncated: int  # runs that hit the rule's alert limit


class EntityRowOut(Out):
    kind: str
    value: str
    investigations: int
    supernode: bool  # in so many investigations that it links nothing


class GapOut(Out):
    kind: str
    subject: str
    start_at: datetime
    detail: str | None


class ReconciliationOut(Out):
    finished_at: datetime
    hours: int
    hours_mismatched: int
    recovered: int
    outcome: str


class KibanaSyncOut(Out):
    """The Kibana read-back (``argus-kibana-sync``), from its newest recorded cycle."""

    state: Literal["none", "ok", "partial", "failed", "late"]
    last_cycle_at: datetime | None
    last_outcome: str | None
    last_reason: str | None
    last_complete_at: datetime | None


class CaseTeamHealthOut(Out):
    """Posting confirmed incidents to Kibana: ``failing`` (a request failed and waits for a
    person), ``waiting`` (confirmed incidents are not in Kibana yet), or ``ok``."""

    state: Literal["ok", "waiting", "failing"]
    last_run_at: datetime | None  # the case team's newest round or request
    failing_since: datetime | None  # when the oldest request still failed was sent
    held: int  # confirmed incidents not in Kibana


class HealthOut(Out):
    siem_state: str
    siem_reasons: list[str]
    siem_probed_at: datetime | None
    live_cursor: datetime | None
    backfill_cursor: datetime | None
    open_gaps: list[GapOut]
    last_reconciliation: ReconciliationOut | None
    alerts: int
    quarantined: int
    investigations: int
    jobs_waiting: int
    jobs_deferred: int
    jobs_failed: int
    dossiers: int
    checkpoint_threads: int
    checkpoint_bytes: int
    kibana_sync: KibanaSyncOut
    case_team: CaseTeamHealthOut | None = None  # posting confirmed incidents to Kibana (A5)


class TermOut(Out):
    name: str
    label: str
    how: str


class ProviderCostOut(Out):
    provider: str
    today_usd: float
    calls: int


class CostOut(Out):
    """The AI spend for the cost bar: this month and today (UTC), against the caps."""

    month_usd: float
    today_usd: float
    cap_usd: float
    paid_until_usd: float  # after this, normal work moves to the free providers
    daily_cap_usd: float | None
    calls_today: int
    providers: list[ProviderCostOut]
    stopped: bool  # the AI kill switch
    at: datetime


class ProviderCallsOut(Out):
    provider: str
    attempts: int
    ok: int
    cost_usd: float


class BacklogOut(Out):
    assessor: str
    waiting: int
    oldest_wait_s: float | None


class OutcomeCountOut(Out):
    assessor: str
    label: str
    count: int


class QuotaOut(Out):
    bucket: str
    usage: str


class MetricsOut(Out):
    """How the assessments and the model gateway are doing (24 hours; 7 days for blocks,
    floor hits and outcomes)."""

    validator_blocks: int
    calls: list[ProviderCallsOut]
    fallbacks: int
    floor_hits: int
    backlog: list[BacklogOut]
    outcomes: list[OutcomeCountOut]
    month_cost_usd: float
    quota: list[QuotaOut]
    stopped: bool


class SuggestionOut(Out):
    kind: str
    path: str | None
    value: str | None
    change: str
    why: str
    risk: str
    evidence: list[str]


class TuningReportOut(Out):
    """A rule's newest weekly tuning report: apply a suggestion in Kibana yourself."""

    rule: str
    week_end: datetime
    alerts: int | None
    investigations: int | None
    runs: int | None
    runs_at_limit: int | None
    max_signals: int | None
    labels: dict[str, int]
    suggestions: list[SuggestionOut]
    dropped: list[str]
    model: str | None
    cost_usd: float | None
    created_at: datetime


class GoldRowOut(Out):
    investigation_id: uuid.UUID
    rule_name: str
    split: str
    why: list[str]
    outcome: Outcome | None
    answered_by: str | None
    answered_at: datetime | None


class GoldProgressOut(Out):
    items: int
    answered: int
    by_split: dict[str, int]


class GoldSetOut(Out):
    items: list[GoldRowOut]  # unanswered first
    progress: GoldProgressOut


class DashboardKpis(Out):
    investigations: int  # active in the span
    open: int
    attention: int  # new work
    known: int  # what notified cases' known infections keep out of it
    follow_up: int
    incidents: int  # investigations a person's verdict calls a true positive
    suspected: int  # investigations ARGUS proposes as true positive, nobody has decided yet
    incident_cases: int  # incidents: confirmed cases not closed (now, whatever the filters)
    possible_incidents: int  # possible incidents: suspected cases (now)
    reviewed: int
    assessed: int
    open_critical: int
    alerts: int
    alerts_before: int  # in the span of the same length before
    median_review_s: float | None  # first alert to first decision


class SeriesPoint(Out):
    at: datetime  # the bucket's start, in IST
    counts: dict[str, int]  # alerts by severity


class RuleShare(Out):
    rule_id: str
    rule: str
    investigations: int
    alerts: int
    open: int
    incidents: int
    suspected: int
    severity: str | None


class EntityShare(Out):
    kind: str
    value: str
    investigations: int
    alerts: int
    open: int


class InvestigationBrief(Out):
    id: uuid.UUID
    rule: str
    severity: str | None
    alert_count: int
    last_event_at: datetime | None
    state: HumanState
    verdict: str | None
    ai: Literal["proposed_tp", "proposed_other", "no_proposal", "working", "none"]
    key_fields: list[KeyField]


class RuleChoice(Out):
    rule_id: str
    rule: str


class DashboardFiltersOut(Out):
    range: Literal["24h", "7d", "30d", "90d"]
    start: date | None
    end: date | None
    severity: list[str]
    state: list[str]
    verdict: list[str]
    ai: list[str]
    rule: str | None
    kind: str | None
    value: str | None


class NotifiedBrief(Out):
    """A case whose owner was told and that stays active (AR4b, D-169): counted, not raised."""

    case_id: uuid.UUID
    case_number: int
    title: str
    notified_at: datetime
    days: int
    alerts: int  # since the notice
    trend: str
    blocked: bool  # a network-side block is recorded
    reminders: list[Literal["notify_again", "network_action"]]  # ARGUS's suggestions that are due


class DashboardOut(Out):
    """The SOC dashboard (D-103) on ARGUS's own records: never a request to the SIEM."""

    filters: DashboardFiltersOut
    start: datetime
    end: datetime
    bucket: Literal["hour", "day"]
    kpis: DashboardKpis
    series: list[SeriesPoint]
    states: dict[str, int]
    severities: dict[str, int]
    verdicts: dict[str, int]
    ai: dict[str, int]
    rules: list[RuleShare]
    entities: dict[str, list[EntityShare]]
    incidents: list[InvestigationBrief]
    open_investigations: list[InvestigationBrief]
    rule_choices: list[RuleChoice]
    notified: list[NotifiedBrief]


class SinceOut(Out):
    """What changed since the person's previous visit (``since`` in the session). Each number
    is counted up to ``CAP``; a capped number is shown as "10,000 or more". Nothing here leaves
    ARGUS's own database."""

    since: datetime | None  # None: a first visit, nothing to compare with
    cap: int
    new_investigations: int  # first grouped after ``since``
    new_severe: int  # of those, rated critical or high
    reviewed_by_others: int  # decided by someone else after ``since``
    new_proposals: int  # ARGUS proposals made after ``since``


class ThreatTileOut(Out):
    """Whether ARGUS found anything on a threat list among the most urgent open investigations of
    the dashboard's span (at most 60: ``examined`` says how many; the dashboard's own ``open``
    is how many there are). A list that was out of date or a lookup that failed is "could not
    tell", never "clear"."""

    examined: int  # open investigations looked at, most urgent first
    on_a_list: int  # an address or domain of the investigation is on a threat list
    clear: int  # checked, and nothing was found
    could_not_tell: int  # a list was out of date, or the check did not run
    not_checked: int  # no dossier yet, or it holds no threat-list check
    listed: list[InvestigationBrief]  # the most urgent that are on a list, at most 5


class ReportRowOut(Out):
    """A report in the list: its kind, the UTC days it covers and when it was made."""

    id: int
    kind: Literal["daily", "weekly"]
    period_start: datetime
    period_end: datetime
    generated_at: datetime
    has_prose: bool


class ReportMetricOut(Out):
    """One figure: ``value`` is None when there is nothing to say; ``definition`` says what is
    counted, over what time and from which table. Names (hosts, sources) come from SIEM data."""

    key: str
    label: str
    value: int | float | str | None
    unit: Literal["count", "percent", "ms", "seconds", "hours", "text"]
    definition: str


class ReportSectionOut(Out):
    id: str
    title: str
    metrics: list[ReportMetricOut]
    notes: list[str]


class ReportOut(Out):
    """One report. The figures are ``sections``; ``text`` is the same report as plain text, made
    from them by code. ``prose`` is a model's paragraph, only when the optional agent was on and
    every number in it was a number of the figures."""

    id: int
    kind: Literal["daily", "weekly"]
    period_start: datetime
    period_end: datetime
    generated_at: datetime
    as_at: datetime
    sections: list[ReportSectionOut]
    text: str
    prose: str | None
