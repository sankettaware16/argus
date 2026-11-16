"""The typed contract of the incident report (AR7, D-190): a case's report as ARGUS wrote it, the
versions kept, the files made from it, and a person's Confirm or Reject with a reason.

The report itself is :class:`argus.incident.model.IncidentReport`, served as stored (its parts
are the hand-made case's: summary, verdict, timeline, actors, assets, evidence with each line's
query and Discover link, hypotheses, indicators, actions). For a person whose ELK account cannot
read the logs, what the logs said is hidden (``logs_hidden``). Text from logs or alerts inside it
(user agents, paths, names) is untrusted: the app shows it as untrusted text, never as markup.
Every error is ``ErrorOut``; a decision names the version of the report the person read and is
refused with 409 when ARGUS wrote a newer one."""

from __future__ import annotations

import uuid
from typing import Annotated, Literal

from pydantic import AwareDatetime, BeforeValidator, Field

from argus.incident.model import IncidentReport
from argus.web.v1.case_models import CaseState
from argus.web.v1.models import SAFE_MAX, In, Out, Outcome, RequiredText, _json_integer
from argus.web.v1.work_models import SentOut

Decision = Literal["confirmed", "rejected"]
FileKind = Literal["pdf", "indicators_csv", "affected_csv", "accounts_csv"]
FileName = Literal["report.pdf", "indicators.csv", "affected-devices.csv", "affected-accounts.csv"]
ReportVersion = Annotated[int, Field(ge=1, le=2**31 - 1), BeforeValidator(_json_integer)]
ReportReason = Annotated[RequiredText, Field(min_length=3, max_length=4000)]


class ReportDecisionOut(Out):
    """What a person said about a version: confirmed, or rejected with the outcome they hold
    instead and why. The labels written from it are counted in ``labelled``. ``held_from``: the
    earlier version it was made on, when it still holds for this one (the two differ only in the
    case's title or the accounts: a retitle renames what the person decided, it does not change
    it); None when it was made on this version."""

    id: Annotated[int, Field(ge=1, le=SAFE_MAX)]
    decision: Decision
    outcome: Outcome | None
    reason: str | None
    by: str
    decided_at: AwareDatetime
    labelled: int
    held_from: int | None = None


class ReportVersionOut(Out):
    version: int
    generated_at: AwareDatetime
    prose: bool
    decision: Decision | None
    decided_at: AwareDatetime | None


class ReportFileOut(Out):
    """One of the files made from the report; ``available`` is false for an account that may not
    read the logs (the PDF says what they said)."""

    kind: FileKind
    name: str
    url: str
    available: bool


class ReportActionOut(Out):
    enabled: bool
    why_not: str | None


class GlanceItemOut(Out):
    """One bar or list item of the glance: a label from the report, its alerts (None: the
    report names it without a count), what the report says of it."""

    label: str
    value: int | None
    note: str


class GlanceLayerOut(Out):
    """One stacked series of alerts over time: a rule (or all the rest), a value per bar."""

    name: str
    values: list[int]


class GlanceOut(Out):
    """The incident at a glance, as the Visualiser draws it (UI v2 A17), from the report shown
    (what the logs said is hidden for an account without ``see_logs``). Names of people never
    appear."""

    alerts: int
    actors: int
    actors_more: bool
    actors_title: str
    targets: int
    targets_more: bool
    targets_title: str
    targets_word: str
    listed: int  # indicators the local threat lists hold
    first: AwareDatetime | None
    last: AwareDatetime | None
    rules: int
    rules_more: bool
    bucket: str  # what one bar counts: day, week, ...
    days: list[str]  # the local day each bar starts on
    layers: list[GlanceLayerOut]
    top_actors: list[GlanceItemOut]
    top_targets: list[GlanceItemOut]
    rule_rows: list[GlanceItemOut]
    severity: str
    call: str
    activity: str
    dwell: str


class CaseReportOut(Out):
    """The case's report (the newest version, or the one asked for), or why there is none."""

    case_id: uuid.UUID
    case_number: int
    case_state: CaseState
    version: int | None  # None: ARGUS has not written one yet
    newest: int | None  # the newest version, which is what a decision is about
    generated_at: AwareDatetime | None
    case_version: int | None
    prose_by: str | None
    stale: bool  # the case changed since this version: ARGUS writes a new one in its next pass
    report: IncidentReport | None
    decision: ReportDecisionOut | None
    versions: list[ReportVersionOut]
    files: list[ReportFileOut]
    logs_hidden: bool
    confirm: ReportActionOut
    reject: ReportActionOut
    note: str | None  # why there is no report, in plain words
    glance: GlanceOut | None = None  # the Visualiser's glance of the shown version (A17)
    sent: SentOut | None = None  # the newest "sent to the CISO" (A14)


class ConfirmReportIn(In):
    """Confirm the report's verdict. Names the version read: 409 when ARGUS wrote a newer one.
    Confirming labels the case's investigations with the verdict; it closes nothing."""

    expected_version: ReportVersion


class RejectReportIn(In):
    """Reject the report's verdict: the outcome you hold instead and why. The reason is stored as
    the note of the review (the label) of each investigation of the case."""

    expected_version: ReportVersion
    outcome: Outcome
    reason: ReportReason


class ReportDecided(Out):
    """What was recorded: the decision and the labels written through the review path."""

    decision: ReportDecisionOut
    labelled: int
    already: int  # members already reviewed with this outcome
    kept: int  # members a person reviewed otherwise (a confirm never overrides them)
    conflicts: int  # members that moved while the decision was recorded
    gold_saved: int
    left: int  # members beyond the cap, not labelled
    words: str
