"""Kibana's answers as records, and what the read-back keeps. Pure.

Every case comes through the strict answer check (``models.check_case``) first; a field the
read-back needs that is missing or of the wrong type is an ``AnswerMismatchError``, never a
guess. People's text (titles, comments) is kept as untrusted text: shown escaped, never an
attestation, never model input.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from argus.gateway.kibana import models
from argus.gateway.kibana.errors import AnswerMismatchError

ARGUS_CASE_TAG = re.compile(
    r"argus:case:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
)
TEXT_KEPT = 2_000  # characters of a person's comment or title kept in a finding
# Control characters (except tab, newline and carriage return) and lone surrogates: Kibana
# accepts them in a comment, title or tag; Postgres refuses NUL, and a lone surrogate cannot be
# encoded as UTF-8 or as a jsonb escape, so one such text would fail every cycle.
_UNSAFE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\ud800-\udfff]")


def clean(text: str) -> str:
    """A person's text without the characters the database refuses (it keeps the rest)."""
    return _UNSAFE.sub("", text)


class Severity(StrEnum):
    ALARM = "alarm"  # something ARGUS cannot explain: writes pause
    ATTENTION = "attention"  # a person must act in ARGUS (Needs attention)
    INFO = "info"  # recorded and shown


class Kind(StrEnum):
    """The reconciliation's findings (the database keeps the same list)."""

    PERSON_EDITED = "person_edited"
    PERSON_DELETED = "person_deleted"
    ARGUS_TAGS_CHANGED = "argus_tags_changed"
    SETTINGS_CHANGED = "settings_changed"
    PERSON_COMMENTED = "person_commented"
    CLOSED_IN_KIBANA = "closed_in_kibana"
    REOPENED_IN_KIBANA = "reopened_in_kibana"
    STATUS_CHANGED_IN_KIBANA = "status_changed_in_kibana"
    DELETED_IN_KIBANA = "deleted_in_kibana"
    PEOPLE_CASE = "people_case"
    UNEXPLAINED_ARGUS_ACTION = "unexplained_argus_action"
    UNEXPLAINED_ARGUS_CASE = "unexplained_argus_case"
    DUPLICATE_CASE = "duplicate_case"
    NOT_ARGUS_CASE = "not_argus_case"
    ALERT_CHANGE_UNEXPLAINED = "alert_change_unexplained"
    ALERT_STATUS_BY_PERSON = "alert_status_by_person"
    CLOCK_OFFSET = "clock_offset"
    ACTIONS_REWOUND = "actions_rewound"
    ANSWER_UNEXPECTED = "answer_unexpected"


SEVERITY: Mapping[Kind, Severity] = {
    Kind.PERSON_EDITED: Severity.INFO,
    Kind.PERSON_DELETED: Severity.INFO,
    Kind.ARGUS_TAGS_CHANGED: Severity.ATTENTION,
    Kind.SETTINGS_CHANGED: Severity.ATTENTION,
    Kind.PERSON_COMMENTED: Severity.INFO,
    Kind.CLOSED_IN_KIBANA: Severity.ATTENTION,
    Kind.REOPENED_IN_KIBANA: Severity.ATTENTION,
    Kind.STATUS_CHANGED_IN_KIBANA: Severity.ATTENTION,
    Kind.DELETED_IN_KIBANA: Severity.ATTENTION,
    Kind.PEOPLE_CASE: Severity.INFO,
    Kind.UNEXPLAINED_ARGUS_ACTION: Severity.ALARM,
    Kind.UNEXPLAINED_ARGUS_CASE: Severity.ALARM,
    Kind.DUPLICATE_CASE: Severity.ATTENTION,
    Kind.NOT_ARGUS_CASE: Severity.ALARM,
    Kind.ALERT_CHANGE_UNEXPLAINED: Severity.ALARM,
    Kind.ALERT_STATUS_BY_PERSON: Severity.INFO,
    Kind.CLOCK_OFFSET: Severity.ALARM,
    Kind.ACTIONS_REWOUND: Severity.ATTENTION,
    Kind.ANSWER_UNEXPECTED: Severity.ATTENTION,
}


@dataclass(frozen=True)
class Finding:
    kind: Kind
    dedupe_key: str  # the same thing found twice is one finding
    kibana_case_id: str | None = None
    case_id: uuid.UUID | None = None
    details: Mapping[str, Any] = field(default_factory=dict)
    lag_s: int | None = None  # a person's change: how long until ARGUS saw it

    @property
    def severity(self) -> Severity:
        return SEVERITY[self.kind]


def _mismatch(what: str) -> AnswerMismatchError:
    return AnswerMismatchError(f"Kibana's answer: {what}")


def parse_time(value: Any, what: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise _mismatch(f"{what} is not a time")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise _mismatch(f"{what} is not a time") from None
    if parsed.tzinfo is None:
        raise _mismatch(f"{what} has no time zone")
    return parsed


def _optional_time(value: Any, what: str) -> datetime | None:
    return None if value is None else parse_time(value, what)


def _count(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


@dataclass(frozen=True)
class KCase:
    """A Kibana case as the read-back keeps it."""

    id: str
    version: str
    status: str
    title: str
    severity: str
    tags: tuple[str, ...]
    created_by: str
    sync_alerts: bool
    created_at: datetime
    updated_at: datetime | None
    total_comment: int = 0
    total_alerts: int = 0

    @property
    def changed_at(self) -> datetime:
        return self.updated_at or self.created_at

    def argus_case_ids(self) -> list[uuid.UUID]:
        """The ARGUS case ids its ``argus:case:<uuid>`` tags name (one, on ARGUS's cases)."""
        found = []
        for tag in self.tags:
            match = ARGUS_CASE_TAG.fullmatch(tag)
            if match:
                found.append(uuid.UUID(match.group(1)))
        return found


def parse_case(raw: Any) -> KCase:
    case = models.check_case(raw)
    severity = case.get("severity")
    if severity not in ("low", "medium", "high", "critical"):
        raise _mismatch("a case without a known severity")
    title = case.get("title")
    if not isinstance(title, str):
        raise _mismatch("a case without a title")
    return KCase(
        id=case["id"],
        version=case["version"],
        status=case["status"],
        title=title,
        severity=severity,
        tags=tuple(case["tags"]),
        created_by=case["created_by"]["username"],
        sync_alerts=case["settings"]["syncAlerts"],
        created_at=parse_time(case.get("created_at"), "created_at"),
        updated_at=_optional_time(case.get("updated_at"), "updated_at"),
        total_comment=_count(case.get("totalComment")),
        total_alerts=_count(case.get("totalAlerts")),
    )


@dataclass(frozen=True)
class KAction:
    """One user action of a case (Kibana's record of who changed what)."""

    id: str
    type: str  # create_case, comment, status, tags, severity, title, description, settings, ...
    action: str  # create, update, add, delete, push_to_service
    created_at: datetime
    by: str  # the username, "" when Kibana does not say
    payload: Mapping[str, Any]

    @property
    def comment_kind(self) -> str | None:
        """``user`` or ``alert`` for a comment action, else None."""
        comment = self.payload.get("comment")
        kind = comment.get("type") if isinstance(comment, Mapping) else None
        return kind if isinstance(kind, str) else None


def parse_action(raw: Any) -> KAction:
    if not isinstance(raw, Mapping):
        raise _mismatch("a user action that is not an object")
    action_id, kind, verb = raw.get("id"), raw.get("type"), raw.get("action")
    if not all(isinstance(v, str) and v for v in (action_id, kind, verb)):
        raise _mismatch("a user action without id, type or action")
    assert isinstance(action_id, str)
    assert isinstance(kind, str)
    assert isinstance(verb, str)
    by = raw.get("created_by")
    username = by.get("username") if isinstance(by, Mapping) else None
    payload = raw.get("payload")
    return KAction(
        id=action_id,
        type=kind,
        action=verb,
        created_at=parse_time(raw.get("created_at"), "a user action's created_at"),
        by=username if isinstance(username, str) else "",
        payload=payload if isinstance(payload, Mapping) else {},
    )


@dataclass(frozen=True)
class Mirror:
    """What ARGUS last read back of one of its cases (``kibana_mirror``)."""

    case_id: uuid.UUID
    kibana_case_id: str
    kibana_version: str
    status: str
    title: str
    severity: str
    tags: tuple[str, ...]
    created_by: str
    sync_alerts: bool
    kibana_created_at: datetime
    kibana_updated_at: datetime | None
    read_at: datetime
    unmanaged: frozenset[str] = frozenset()
    deleted_at: datetime | None = None
    actions_seen: int = 0
    argus_actions: Mapping[str, int] = field(default_factory=dict)
    paused_reason: str | None = None
    # ARGUS actions no sent write explained, by kind: already alarmed, so a later explained
    # action of the same kind is not taken for one of them
    unexplained: Mapping[str, int] = field(default_factory=dict)

    @property
    def active(self) -> bool:
        return self.deleted_at is None


@dataclass(frozen=True)
class SentWrite:
    """An outbox row of the case that was sent to Kibana at least once (``sent_count``), or one
    of the case team's steps (``by``: its Kibana user)."""

    op: str  # create, update, comment, close, attach;
    # the case team's also title, description and edit_comment
    fields: frozenset[str]  # what an update or close changes: status, severity, argus_tags
    sent_count: int
    by: str = ""  # who sent it when not the service user (a case-team user)


@dataclass(frozen=True)
class TeamPost:
    """A case team post (``case_team_posts``) as the read-back needs it to recognise the case it
    opened: the case team's cases carry no ``argus:case:<uuid>`` tag, their incident ID is the
    link until the poster has recorded the Kibana id."""

    case_id: uuid.UUID
    incident_id: str
    kibana_case_id: str | None  # recorded by the poster once the open step went through
    opens: int  # how many times the open step was sent (a request that left, whatever came back)
    opener: str  # the open step's author (the lead)


@dataclass(frozen=True)
class AlertLink:
    """An alert's case ids and status, as ``alerts.case_links`` returns them."""

    alert_id: str
    case_ids: tuple[str, ...]
    status: str | None
    user: str | None
    status_updated_at: datetime | None


@dataclass(frozen=True)
class AlertState:
    """An alert's status as the last discovery saw it (``kibana_alert_states``)."""

    alert_id: str
    status: str | None
    user: str | None
    status_updated_at: datetime | None
    seen_at: datetime


def _field(source: Mapping[str, Any], name: str) -> Any:
    """A field of an alert's ``_source``, flat (``kibana.alert.case_ids``) or nested."""
    if name in source:
        return source[name]
    value: Any = source
    for part in name.split("."):
        if not isinstance(value, Mapping):
            return None
        value = value.get(part)
    return value


def parse_links(answer: Any) -> tuple[list[AlertLink], tuple[str | int, ...] | None]:
    """The hits of an ``alerts.case_links`` answer and the ``search_after`` of the last."""
    hits = answer.get("hits", {}).get("hits") if isinstance(answer, Mapping) else None
    if not isinstance(hits, list):
        raise _mismatch("a search without hits")
    links: list[AlertLink] = []
    after: tuple[str | int, ...] | None = None
    for hit in hits:
        if not isinstance(hit, Mapping) or not isinstance(hit.get("_id"), str):
            raise _mismatch("a hit without an id")
        source = hit.get("_source") if isinstance(hit.get("_source"), Mapping) else {}
        assert isinstance(source, Mapping)
        ids = _field(source, "kibana.alert.case_ids")
        case_ids = tuple(i for i in ids if isinstance(i, str)) if isinstance(ids, list) else ()
        status = _field(source, "kibana.alert.workflow_status")
        user = _field(source, "kibana.alert.workflow_user")
        updated = _field(source, "kibana.alert.workflow_status_updated_at")
        links.append(
            AlertLink(
                alert_id=hit["_id"],
                case_ids=case_ids,
                status=status if isinstance(status, str) else None,
                user=user if isinstance(user, str) and user else None,
                status_updated_at=(
                    parse_time(updated, "workflow_status_updated_at")
                    if isinstance(updated, str)
                    else None
                ),
            )
        )
        sort = hit.get("sort")
        if isinstance(sort, list) and len(sort) == 2:
            after = tuple(v for v in sort if isinstance(v, str | int) and not isinstance(v, bool))
            after = after if len(after) == 2 else None
    return links, after


def untrusted(text: Any) -> str:
    """A person's text, cut to what a finding keeps (shown escaped, never acted on)."""
    return clean(text)[:TEXT_KEPT] if isinstance(text, str) else ""


def page_items(answer: Mapping[str, Any], key: str) -> Sequence[Any]:
    items = answer.get(key)
    return items if isinstance(items, list) else []
