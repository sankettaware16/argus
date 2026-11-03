"""Strict body models of every Kibana write and the checks of every Kibana answer.

Bodies are pydantic models with ``extra="forbid"``: a create always carries owner
``securitySolution``, connector ``none`` and ``settings: {syncAlerts: false}`` and never assignees,
custom fields or a category; an update names one case by id and version; attachments and status
changes are bounded per call. Answers: each read and write has a check of what Kibana must answer;
a 2xx answer that fails it (or has Sync alerts on) is an ``AnswerMismatchError``, never success.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Annotated, Any, Final, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    field_validator,
    model_serializer,
    model_validator,
)

from argus import site
from argus.gateway.kibana.errors import AnswerMismatchError

OWNER: Final = "securitySolution"
MAX_ALERTS_PER_CALL = 5  # alerts attached a call
MAX_TEAM_ALERTS_PER_CALL = 100  # the case team's attach
MAX_STATUS_ALERTS_PER_CALL = 100  # the most a status call may ever name; ``WriteCaps``
# ``status_per_call`` (``writeback.batch``) is what a call may use
MAX_TITLE = 160  # Kibana's limits (a contract test checks them)
MAX_TEXT = 30_000
MAX_TAGS = 200
MAX_TAG = 256
CLOSING_REASONS = frozenset(
    {
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
    }
)
_CASE_ID = r"^[A-Za-z0-9_-]{1,64}$"
_ALERT_ID = r"^[A-Za-z0-9_-]{1,128}$"
_ALERT_INDEX = r"^\.internal\.alerts-security\.alerts-[a-z0-9_-]{1,64}-[0-9]{6}$"
_ARGUS_CASE_TAG = re.compile(
    r"argus:case:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
_VERSION = r"^[A-Za-z0-9_=+/-]{1,200}$"

Severity = Literal["low", "medium", "high", "critical"]
Tag = Annotated[str, Field(min_length=1, max_length=MAX_TAG)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class NoConnector(_Strict):
    id: Literal["none"] = "none"
    name: Literal["none"] = "none"
    type: Literal[".none"] = ".none"
    fields: None = None


class SyncOff(_Strict):
    syncAlerts: Literal[False] = False  # noqa: N815 - Kibana's name


def _text(value: str) -> str:
    if "\x00" in value:
        raise ValueError("no NUL characters")
    if not value.strip():
        raise ValueError("not blank")
    return value


def utf16_len(value: str) -> int:
    """The length Kibana counts (JavaScript's: UTF-16 code units; an emoji is two)."""
    return len(value.encode("utf-16-le")) // 2


def _within(limit: int) -> Any:
    def check(value: str | None) -> str | None:
        if value is not None and utf16_len(value) > limit:
            raise ValueError(f"longer than Kibana's {limit} (counted in UTF-16 units)")
        return value

    return check


class CaseCreate(_Strict):
    """W1: a new case (POST /api/cases)."""

    title: Annotated[str, Field(min_length=1, max_length=MAX_TITLE)]
    description: Annotated[str, Field(min_length=1, max_length=MAX_TEXT)]
    tags: Annotated[tuple[Tag, ...], Field(min_length=2, max_length=MAX_TAGS)]
    severity: Severity
    owner: Literal["securitySolution"] = OWNER
    connector: NoConnector = NoConnector()
    settings: SyncOff = SyncOff()

    @field_validator("title", "description")
    @classmethod
    def _plain(cls, value: str) -> str:
        return _text(value)

    _title_units = field_validator("title")(_within(MAX_TITLE))
    _text_units = field_validator("description")(_within(MAX_TEXT))

    @field_validator("tags")
    @classmethod
    def _argus_tags(cls, tags: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(tags)) != len(tags):
            raise ValueError("a tag is listed twice")
        if "argus" not in tags or sum(bool(_ARGUS_CASE_TAG.fullmatch(t)) for t in tags) != 1:
            raise ValueError("a case of ARGUS carries 'argus' and exactly one argus:case:<uuid>")
        if any(not (t == "argus" or t.startswith("argus:")) for t in tags):
            raise ValueError("a new case carries ARGUS's tags only")
        return tags


class UserComment(_Strict):
    """A comment (W1, or the comment of a W2 or W3 change)."""

    type: Literal["user"] = "user"
    comment: Annotated[str, Field(min_length=1, max_length=MAX_TEXT)]
    owner: Literal["securitySolution"] = OWNER

    @field_validator("comment")
    @classmethod
    def _plain(cls, value: str) -> str:
        return _text(value)

    _units = field_validator("comment")(_within(MAX_TEXT))


class RuleRef(_Strict):
    id: None = None
    name: None = None


class AlertAttachment(_Strict):
    """W1: up to five alerts, each with its concrete index (an attach is an alert write)."""

    type: Literal["alert"] = "alert"
    alertId: Annotated[  # noqa: N815 - Kibana's name
        tuple[Annotated[str, Field(pattern=_ALERT_ID)], ...],
        Field(min_length=1, max_length=MAX_ALERTS_PER_CALL),
    ]
    index: tuple[Annotated[str, Field(pattern=_ALERT_INDEX)], ...]
    rule: RuleRef = RuleRef()
    owner: Literal["securitySolution"] = OWNER

    @model_validator(mode="after")
    def _paired(self) -> AlertAttachment:
        if len(self.index) != len(self.alertId):
            raise ValueError("each alert names its own index")
        if len(set(self.alertId)) != len(self.alertId):
            raise ValueError("an alert is listed twice")
        return self


class TeamAlertAttachment(AlertAttachment):
    """The case team's attach (WC): the same body, up to ``MAX_TEAM_ALERTS_PER_CALL`` alerts (the
    lane's cap for the team, ``team_alerts_per_call``, is what a call may use)."""

    alertId: Annotated[  # noqa: N815 - Kibana's name
        tuple[Annotated[str, Field(pattern=_ALERT_ID)], ...],
        Field(min_length=1, max_length=MAX_TEAM_ALERTS_PER_CALL),
    ]


class CaseChange(_Strict):
    """One case's change in a PATCH: no settings, assignees, custom fields, connector or
    category (they are not fields here, so ``extra="forbid"`` refuses them)."""

    id: Annotated[str, Field(pattern=_CASE_ID)]
    version: Annotated[str, Field(pattern=_VERSION)]
    title: Annotated[str, Field(min_length=1, max_length=MAX_TITLE)] | None = None
    description: Annotated[str, Field(min_length=1, max_length=MAX_TEXT)] | None = None
    tags: Annotated[tuple[Tag, ...], Field(max_length=MAX_TAGS)] | None = None
    severity: Severity | None = None
    status: Literal["open", "in-progress", "closed"] | None = None

    _title_units = field_validator("title")(_within(MAX_TITLE))
    _text_units = field_validator("description")(_within(MAX_TEXT))

    @field_validator("title", "description")
    @classmethod
    def _plain(cls, value: str | None) -> str | None:
        return None if value is None else _text(value)  # the create's rules (no NUL, not blank)

    @model_serializer(mode="wrap")
    def _only_what_changes(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        """A field ARGUS does not change is left out: Kibana refuses ``null`` for every one of
        them (400 'Invalid value "null" supplied to cases,title')."""
        data: dict[str, Any] = handler(self)
        return {key: value for key, value in data.items() if value is not None}

    @model_validator(mode="after")
    def _changes(self) -> CaseChange:
        if all(
            v is None for v in (self.title, self.description, self.tags, self.severity, self.status)
        ):
            raise ValueError("a change changes something")
        if self.tags is not None:
            if len(set(self.tags)) != len(self.tags):
                raise ValueError("a tag is listed twice")
            if "argus" not in self.tags:
                raise ValueError("a case of ARGUS keeps its 'argus' tag")
            if sum(bool(_ARGUS_CASE_TAG.fullmatch(t)) for t in self.tags) != 1:
                raise ValueError("a case of ARGUS keeps exactly one argus:case:<uuid>")
        return self


class CasesPatch(_Strict):
    """W2 or W3: PATCH /api/cases with exactly one case (one write, one outbox row)."""

    cases: Annotated[tuple[CaseChange, ...], Field(min_length=1, max_length=1)]


class UpdatePatch(CasesPatch):
    """W2: tags, severity, status (open, in-progress: a reopen is status open), title,
    description; never a closure (W3) or its tags."""

    @model_validator(mode="after")
    def _no_closure(self) -> UpdatePatch:
        change = self.cases[0]
        if change.status == "closed":
            raise ValueError("a closure is W3 (cases.close)")
        if change.tags is not None and any(
            t in ("argus:state:closed", "argus:closed") or t.startswith("argus:reason:")
            for t in change.tags
        ):
            raise ValueError("closing tags belong to a closure (W3)")
        return self


class ClosePatch(CasesPatch):
    """W3: status closed with the closing tags (one reason of the nine), nothing else."""

    @model_validator(mode="after")
    def _closure(self) -> ClosePatch:
        change = self.cases[0]
        if change.status != "closed" or change.tags is None or closing_tags(change.tags) is None:
            raise ValueError("a closure sets status closed and its reason tags (plan §7.1)")
        if any(v is not None for v in (change.title, change.description, change.severity)):
            raise ValueError("a closure changes status and tags only")
        return self


class AlertStatusChange(_Strict):
    """WA: POST /api/detection_engine/signals/status by ids, never by query."""

    signal_ids: Annotated[
        tuple[Annotated[str, Field(pattern=_ALERT_ID)], ...],
        Field(min_length=1, max_length=MAX_STATUS_ALERTS_PER_CALL),
    ]
    status: Literal["open", "acknowledged", "closed"]

    @field_validator("signal_ids")
    @classmethod
    def _unique(cls, ids: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(ids)) != len(ids):
            raise ValueError("an alert is listed twice")
        return ids


def closing_tags(tags: Sequence[str]) -> str | None:
    """The reason code of a closure's tags, or None unless they carry ``argus:state:closed``,
    ``argus:closed`` and exactly one ``argus:reason:<code>`` of the nine and no
    other ``argus:state:``."""
    reasons = [t.removeprefix("argus:reason:") for t in tags if t.startswith("argus:reason:")]
    states = [t for t in tags if t.startswith("argus:state:")]
    if states != ["argus:state:closed"] or "argus:closed" not in tags or len(reasons) != 1:
        return None
    return reasons[0] if reasons[0] in CLOSING_REASONS else None


# --------------------------------------------------------------------------- the case team
# Seven service users post one incident case; their bodies are as strict as
# ARGUS's own.

TEAM_USERS: Final = (
    "argus-lead",
    "argus-evidence",
    "argus-intel",
    "argus-responder",
    "argus-hunter",
    "argus-reporter",
    "argus-visualiser",
)
TEAM_LEAD: Final = "argus-lead"
TeamUser = Literal[
    "argus-lead",
    "argus-evidence",
    "argus-intel",
    "argus-responder",
    "argus-hunter",
    "argus-reporter",
    "argus-visualiser",
]
TEAM_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9:_./@-]{0,99}")
INCIDENT_STATE_TAG = re.compile(r"incident:[a-z]+(-[a-z]+){0,3}")
MAX_TAGS_PER_CALL = 10


class TeamCaseCreate(_Strict):
    """The lead opens the incident case: the hand-made case's ID first, then its
    ``key:value`` tags. Like an ARGUS case it is made with Sync alerts off, no connector and the
    security owner; unlike one it carries no ``argus:*`` tag (the writer's sync keeps off it)."""

    title: Annotated[str, Field(min_length=1, max_length=MAX_TITLE)]
    description: Annotated[str, Field(min_length=1, max_length=MAX_TEXT)]
    tags: Annotated[tuple[Tag, ...], Field(min_length=3, max_length=MAX_TAGS)]
    severity: Severity
    owner: Literal["securitySolution"] = OWNER
    connector: NoConnector = NoConnector()
    settings: SyncOff = SyncOff()

    @field_validator("title", "description")
    @classmethod
    def _plain(cls, value: str) -> str:
        return _text(value)

    _title_units = field_validator("title")(_within(MAX_TITLE))
    _text_units = field_validator("description")(_within(MAX_TEXT))

    @field_validator("tags")
    @classmethod
    def _incident_tags(cls, tags: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(tags)) != len(tags):
            raise ValueError("a tag is listed twice")
        if not site.incident_id_regex().fullmatch(tags[0]):
            raise ValueError("the incident ID is the first tag")
        if "incident" not in tags or "source:argus-lead" not in tags:
            raise ValueError("an incident case carries 'incident' and 'source:argus-lead'")
        if any(not TEAM_TAG.fullmatch(t) or t == "argus" or t.startswith("argus:") for t in tags):
            raise ValueError("a tag is a plain key:value and none is ARGUS's own (argus:*)")
        return tags


class TeamCasePatch(CasesPatch):
    """The lead corrects the case it opened: PATCH /api/cases with exactly one case, its
    Kibana version, and a new title and/or description; never tags, severity, status, assignees
    or settings (a closure or a reopening is a person's, and the case team never writes one)."""

    @model_validator(mode="after")
    def _text_only(self) -> TeamCasePatch:
        change = self.cases[0]
        if change.title is None and change.description is None:
            raise ValueError("an edit sets a title or a description")
        if any(v is not None for v in (change.tags, change.severity, change.status)):
            raise ValueError("the case team edits a title and a description only")
        return self


class TeamCommentPatch(_Strict):
    """A user corrects the comment they wrote: PATCH /api/cases/{case}/comments with the
    comment's id and Kibana version, its type and owner unchanged, and the new text."""

    id: Annotated[str, Field(pattern=_CASE_ID)]
    version: Annotated[str, Field(pattern=_VERSION)]
    type: Literal["user"] = "user"
    comment: Annotated[str, Field(min_length=1, max_length=MAX_TEXT)]
    owner: Literal["securitySolution"] = OWNER

    @field_validator("comment")
    @classmethod
    def _plain(cls, value: str) -> str:
        return _text(value)

    _units = field_validator("comment")(_within(MAX_TEXT))


class AlertTagSet(_Strict):
    tags_to_add: Annotated[tuple[str, ...], Field(min_length=1, max_length=MAX_TAGS_PER_CALL)]
    tags_to_remove: tuple[()] = ()

    @field_validator("tags_to_add")
    @classmethod
    def _ours(cls, tags: tuple[str, ...]) -> tuple[str, ...]:
        incident = site.incident_id_regex()
        if len(set(tags)) != len(tags) or not all(
            incident.fullmatch(t) or INCIDENT_STATE_TAG.fullmatch(t) for t in tags
        ):
            raise ValueError("the tags put on alerts are the incident ID and incident:<verdict>")
        return tags


class AlertTagChange(_Strict):
    """POST /api/detection_engine/signals/tags by ids: the incident's tags on its alerts; the case
    team never removes a tag."""

    ids: Annotated[
        tuple[Annotated[str, Field(pattern=_ALERT_ID)], ...],
        Field(min_length=1, max_length=MAX_TEAM_ALERTS_PER_CALL),
    ]
    tags: AlertTagSet

    @field_validator("ids")
    @classmethod
    def _unique(cls, ids: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(ids)) != len(ids):
            raise ValueError("an alert is listed twice")
        return ids


# --------------------------------------------------------------------------- answers


def _mismatch(what: str) -> AnswerMismatchError:
    return AnswerMismatchError(f"Kibana's answer: {what}")


def _str(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def check_case(answer: Any, *, case_id: str | None = None) -> Mapping[str, Any]:
    """A case object: an id, a version, the owner, the status, tags and ``settings``."""
    if not isinstance(answer, Mapping):
        raise _mismatch("not a case")
    if not _str(answer.get("id")) or not _str(answer.get("version")):
        raise _mismatch("a case without id or version")
    if case_id is not None and answer["id"] != case_id:
        raise _mismatch("another case")
    if answer.get("owner") != OWNER:
        raise _mismatch("a case of another owner")
    if answer.get("status") not in ("open", "in-progress", "closed"):
        raise _mismatch("a case without a known status")
    tags = answer.get("tags")
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        raise _mismatch("a case without tags")
    settings = answer.get("settings")
    if not isinstance(settings, Mapping) or not isinstance(settings.get("syncAlerts"), bool):
        raise _mismatch("a case without settings")
    created = answer.get("created_by")
    if not isinstance(created, Mapping) or not _str(created.get("username")):
        raise _mismatch("a case without its author")
    return answer


def _by(case: Mapping[str, Any], author: str | None) -> None:
    """Every case ARGUS writes to is one it made: its author is ARGUS's."""
    if author is not None and case["created_by"].get("username") != author:
        raise _mismatch("the case was made by someone else")


def check_created(answer: Any, sent: CaseCreate, author: str | None) -> Mapping[str, Any]:
    case = check_case(answer)
    if case["settings"].get("syncAlerts") is not False:
        raise _mismatch("Sync alerts is on")
    if case.get("title") != sent.title or case["status"] != "open":
        raise _mismatch("not the case ARGUS sent")
    if case.get("description") != sent.description:
        raise _mismatch("the description is not the one sent")
    if case.get("severity") != sent.severity:
        raise _mismatch("the severity is not the one sent")
    if not set(sent.tags) <= set(case["tags"]):
        raise _mismatch("the case lacks ARGUS's tags")
    _by(case, author)
    return case


def check_patched(answer: Any, sent: CasesPatch, author: str | None) -> Mapping[str, Any]:
    if not isinstance(answer, list) or len(answer) != 1:
        raise _mismatch("not exactly one case")
    change = sent.cases[0]
    case = check_case(answer[0], case_id=change.id)
    _by(case, author)
    if change.status is not None and case["settings"].get("syncAlerts") is not False:
        raise _mismatch("Sync alerts is on: the status change may have changed its alerts")
    if case["version"] == change.version:
        raise _mismatch("the version did not move")
    if change.status is not None and case["status"] != change.status:
        raise _mismatch("the status is not the one sent")
    if change.tags is not None and set(case["tags"]) != set(change.tags):
        raise _mismatch("the tags are not the ones sent")
    if change.severity is not None and case.get("severity") != change.severity:
        raise _mismatch("the severity is not the one sent")
    if change.title is not None and case.get("title") != change.title:
        raise _mismatch("the title is not the one sent")
    if change.description is not None and case.get("description") != change.description:
        raise _mismatch("the description is not the one sent")
    return case


def check_commented(answer: Any, case_id: str, author: str | None) -> Mapping[str, Any]:
    case = check_case(answer, case_id=case_id)
    _by(case, author)
    comments = case.get("totalComment")
    if not isinstance(comments, int) or isinstance(comments, bool) or comments < 1:
        raise _mismatch("the case holds no comment")
    return case


def check_attached(
    answer: Any, case_id: str, sent: AlertAttachment, author: str | None
) -> Mapping[str, Any]:
    case = check_case(answer, case_id=case_id)
    _by(case, author)
    if case["settings"].get("syncAlerts") is not False:
        raise _mismatch("Sync alerts is on: the attach may have changed its alerts' status")
    alerts = case.get("totalAlerts")
    if not isinstance(alerts, int) or isinstance(alerts, bool) or alerts < len(sent.alertId):
        raise _mismatch("the case holds fewer alerts than were attached")
    return case


def check_alert_status(answer: Any, sent: AlertStatusChange) -> Mapping[str, Any]:
    """The route answers with its update_by_query body, and a 200 alone says nothing. A clean answer
    names every alert sent and updates every one: ``total`` and ``updated`` both equal the number of
    ids (Kibana rewrites an alert that already has the status as ``updated``, and an id it does not
    find is a ``total`` of 0 with a 200). Anything else (fewer or more alerts, ``failures``,
    ``version_conflicts``, ``noops``, ``deleted``, ``timed_out``) is a mismatch that pauses the
    class."""
    if not isinstance(answer, Mapping):
        raise _mismatch("not an update report")
    updated, total = answer.get("updated"), answer.get("total")
    if not all(isinstance(n, int) and not isinstance(n, bool) for n in (updated, total)):
        raise _mismatch("an update report without counts")
    failures = answer.get("failures")
    if not isinstance(failures, list) or failures:
        raise _mismatch("the update had failures")
    if answer.get("version_conflicts") not in (0, None):
        raise _mismatch("the update had version conflicts")
    if answer.get("timed_out") not in (False, None):
        raise _mismatch("the update timed out")
    if answer.get("noops") not in (0, None) or answer.get("deleted") not in (0, None):
        raise _mismatch("the update skipped or deleted alerts")
    wanted = len(sent.signal_ids)
    if total != wanted or updated != wanted:
        raise _mismatch(f"{updated} of {total} alerts updated, {wanted} were named")
    return answer


def check_status(answer: Any) -> tuple[str, str]:
    """(version, overall level) of ``GET api/status``."""
    if not isinstance(answer, Mapping):
        raise _mismatch("not a status")
    version = answer.get("version")
    number = version.get("number") if isinstance(version, Mapping) else None
    status = answer.get("status")
    overall = status.get("overall") if isinstance(status, Mapping) else None
    level = overall.get("level") if isinstance(overall, Mapping) else None
    if not _str(number) or not _str(level):
        raise _mismatch("a status without version or level")
    assert isinstance(number, str)
    assert isinstance(level, str)
    return number, level


def check_named(answer: Any, what: str) -> list[dict[str, str]]:
    """``[{id, name}]`` of a list of spaces or features (``GET api/spaces/space``, ``GET
    api/features``): every item must be a mapping with a text ``id``; the rest is dropped."""
    found: list[dict[str, str]] = []
    for item in check_list(answer):
        if not isinstance(item, Mapping) or not isinstance(item.get("id"), str):
            raise _mismatch(f"a {what} without an id")
        name = item.get("name")
        found.append({"id": item["id"], "name": name if isinstance(name, str) else ""})
    return found


def check_page(answer: Any, items: str, *, per_page: str = "per_page") -> Mapping[str, Any]:
    """A page of a find: the list under ``items`` and the counts."""
    if not isinstance(answer, Mapping) or not isinstance(answer.get(items), list):
        raise _mismatch(f"no {items} list")
    for key in ("page", per_page, "total"):
        value = answer.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise _mismatch(f"no {key}")
    return answer


def check_list(answer: Any) -> list[Any]:
    if not isinstance(answer, list):
        raise _mismatch("not a list")
    return answer


def _team_case(answer: Any, case_id: str | None, lead: str = TEAM_LEAD) -> Mapping[str, Any]:
    case = check_case(answer, case_id=case_id)
    if case["created_by"].get("username") != lead:
        raise _mismatch("the case was not opened by the case team's lead")
    return case


def check_team_created(answer: Any, sent: TeamCaseCreate) -> Mapping[str, Any]:
    case = _team_case(answer, None)
    if case["settings"].get("syncAlerts") is not False:
        raise _mismatch("Sync alerts is on")
    if case.get("title") != sent.title or case["status"] != "open":
        raise _mismatch("not the case the lead sent")
    if case.get("description") != sent.description or case.get("severity") != sent.severity:
        raise _mismatch("the description or severity is not the one sent")
    if not set(sent.tags) <= set(case["tags"]):
        raise _mismatch("the case lacks the lead's tags")
    return case


def check_team_commented(answer: Any, case_id: str, sent: str, username: str) -> Mapping[str, Any]:
    """The answer to a comment is the case with its comments: the one just sent must be there,
    written by the user whose key sent it."""
    case = _team_case(answer, case_id)
    comments = case.get("comments")
    if not isinstance(comments, list):
        raise _mismatch("the answer holds no comments")
    for item in comments:
        by = item.get("created_by") if isinstance(item, Mapping) else None
        if (
            isinstance(item, Mapping)
            and item.get("type") == "user"
            and item.get("comment") == sent
            and isinstance(by, Mapping)
            and by.get("username") == username
        ):
            return case
    raise _mismatch("the comment is not on the case under its author's name")


def check_team_patched(answer: Any, sent: CasesPatch) -> Mapping[str, Any]:
    """The answer to the lead's edit is the updated cases: the one just sent, still the lead's,
    at a new version, with the title and description as sent. Sync alerts may be on: a person's
    setting, and a title or description changes no alert."""
    if not isinstance(answer, list) or len(answer) != 1:
        raise _mismatch("not exactly one case")
    change = sent.cases[0]
    case = _team_case(answer[0], change.id)
    if case["version"] == change.version:
        raise _mismatch("the version did not move")
    if change.title is not None and case.get("title") != change.title:
        raise _mismatch("the title is not the one sent")
    if change.description is not None and case.get("description") != change.description:
        raise _mismatch("the description is not the one sent")
    return case


def check_team_comment_edited(
    answer: Any, case_id: str, sent: TeamCommentPatch, username: str
) -> Mapping[str, Any]:
    """The answer to a comment's edit is the case with its comments: the comment just edited must
    read as sent, at a new version, and still be its author's."""
    case = _team_case(answer, case_id)
    comments = case.get("comments")
    if not isinstance(comments, list):
        raise _mismatch("the answer holds no comments")
    for item in comments:
        if not isinstance(item, Mapping) or item.get("id") != sent.id:
            continue
        by = item.get("created_by")
        if (
            item.get("type") == "user"
            and item.get("comment") == sent.comment
            and item.get("version") != sent.version
            and isinstance(by, Mapping)
            and by.get("username") == username
        ):
            return case
        break
    raise _mismatch("the comment is not as sent, at a new version, under its author's name")


def check_team_attached(
    answer: Any, case_id: str, sent: AlertAttachment, expect_total: int
) -> Mapping[str, Any]:
    """The answer to an attach is the case: it holds at least the alerts expected. Sync alerts
    may be on only for an open case: then Kibana sets the attached alerts to *open*, which
    changes only an alert a person had closed, and the poster leaves those out beforehand. On any
    other status an attach with Sync alerts on would change the alerts' status."""
    case = _team_case(answer, case_id)
    sync = case["settings"].get("syncAlerts")
    if sync is not False and not (sync is True and case.get("status") == "open"):
        raise _mismatch("Sync alerts is on: the attach may have changed its alerts' status")
    alerts = case.get("totalAlerts")
    wanted = max(expect_total, len(sent.alertId))
    if not isinstance(alerts, int) or isinstance(alerts, bool) or alerts < wanted:
        raise _mismatch("the case holds fewer alerts than were attached")
    return case


def _count(answer: Mapping[str, Any], name: str) -> int | None:
    value = answer.get(name)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise _mismatch(f"an update report with a bad {name}")
    return value


@dataclass(frozen=True)
class TagReport:
    """What Kibana's tag route says it did, read for what it is: ``gone`` named alerts matched
    nothing (the alerts index no longer holds them: index lifecycle removed them) and
    ``conflicts`` matched alerts were not updated (a rule rewrote them meanwhile). Neither is a
    wrong answer; both leave alerts untagged, which the caller deals with."""

    updated: int
    gone: int
    conflicts: int

    @property
    def complete(self) -> bool:
        return self.gone == 0 and self.conflicts == 0


def tag_report(answer: Any, sent: AlertTagChange) -> TagReport:
    """Read the answer to a tag call. Raises only for an answer that is not an update report, has
    failures or timed out, or does not add up; a smaller ``updated`` or ``version_conflicts`` is
    reported, not raised (the lane would pause the whole class for the alerts' lifecycle)."""
    if not isinstance(answer, Mapping):
        raise _mismatch("not an update report")
    updated = _count(answer, "updated")
    if updated is None:
        raise _mismatch("an update report without a count")
    failures = answer.get("failures", [])
    if not isinstance(failures, list) or failures:
        raise _mismatch("the update had failures")
    if answer.get("timed_out") not in (False, None):
        raise _mismatch("the update timed out")
    named = len(sent.ids)
    total = _count(answer, "total")
    conflicts = _count(answer, "version_conflicts") or 0
    noops = _count(answer, "noops") or 0
    deleted = _count(answer, "deleted") or 0
    matched = updated + noops + conflicts if total is None else total
    if matched > named or deleted or updated + noops + conflicts != matched:
        raise _mismatch(f"{updated} alerts updated of {matched} matched, {named} were named")
    return TagReport(updated + noops, named - matched, conflicts)


def check_alert_tags(answer: Any, sent: AlertTagChange) -> Mapping[str, Any]:
    """Tags are added to a set, so the route answers with an update report. The report must be
    well formed and add up; an alert that no longer exists (``updated`` and ``total`` under the
    number named) or that was rewritten meanwhile (``version_conflicts``) is not a wrong answer
    (:func:`tag_report` says so and the caller acts on it); failures and a timeout are."""
    tag_report(answer, sent)
    assert isinstance(answer, Mapping)
    return answer


def check_team_file(answer: Any, case_id: str, full_name: str) -> Mapping[str, Any]:
    """The answer to a file is the case; when it lists its attachments, the file's name is there."""
    case = _team_case(answer, case_id)
    comments = case.get("comments")
    if isinstance(comments, list) and comments:
        names = [
            f.get("name")
            for item in comments
            if isinstance(item, Mapping)
            and item.get("type") == "externalReference"
            and isinstance(item.get("externalReferenceMetadata"), Mapping)
            for f in item["externalReferenceMetadata"].get("files", [])
            if isinstance(f, Mapping)
        ]
        stem = full_name.rsplit(".", 1)[0]
        if names and stem not in names and full_name not in names:
            raise _mismatch("the file is not among the case's attachments")
    return case
