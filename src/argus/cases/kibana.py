"""What a case change plans for its Kibana mirror: pure.

A planned write is ARGUS-level intent, not a Kibana request body: a fixed set of ARGUS's own
``argus:*`` tags (the writer keeps every other tag), a status, a severity, and comments as a
template name with values, never text from logs or a model. The writer renders them; an approval
binds to the payload's hash (:func:`payload_hash`). Mirrored cases carry ``argus``,
``argus:case:<uuid>`` and state and owner tags; suspected cases have no mirror."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from argus.cases import naming
from argus.cases.model import Case
from argus.normalize.canon import canonical_json

WriteClass = Literal["W1", "W2", "W3"]
Op = Literal["create", "update", "comment", "close"]
KIBANA_STATUS = {
    "open": "open",
    "assigned": "in-progress",
    "contained": "in-progress",
    "closed": "closed",
}
CASE_LINK = "/go/case/{id}"  # the permanent link to a case
# Kibana's cases API refuses a longer title (MAX_TITLE_LENGTH, counted as JavaScript does: in
# UTF-16 code units).
KIBANA_TITLE_LIMIT = 160


@dataclass(frozen=True)
class PlannedWrite:
    write_class: WriteClass
    op: Op
    payload: dict[str, Any]


def payload_hash(payload: dict[str, Any]) -> str:
    """sha256 of the payload's canonical JSON (sorted keys, no spaces, ASCII)."""
    return hashlib.sha256(canonical_json(payload).encode("ascii")).hexdigest()


def owner_tag(case: Case) -> str:
    return (
        "argus:owner:argus"
        if case.owner_user_id is None
        else f"argus:owner:user-{case.owner_user_id}"
    )


def argus_tags(case: Case) -> list[str]:
    """The full set of ARGUS's own tags the mirror should carry now (sorted)."""
    tags = {"argus", f"argus:case:{case.id}", f"argus:state:{case.state}"}
    if case.state == "closed":
        tags |= {"argus:closed", f"argus:reason:{case.closure_reason}"}
    else:
        tags.add(owner_tag(case))
    return sorted(tags)


def words(case: Case, *, by_person: bool = False) -> str:
    """The case's title as Kibana holds it: ARGUS's own without its certainty word (naming v2:
    only confirmed cases go there; "Likely beaconing ..." is "Beaconing ..."), a person's
    (``by_person``, D-230) as they wrote it."""
    if by_person:
        return case.title
    return naming.without_certainty(case.title, naming.split_certainty(case.title)[0])


def title(case: Case, *, by_person: bool = False) -> str:
    """``[ARGUS <number>] <title>`` (:func:`words`), cut to Kibana's limit with an ellipsis. The
    title is ARGUS's own words (:mod:`argus.cases.naming`: counts and values of a strict shape
    only) or a person's, without control characters (the machine and the database refuse them)."""
    prefix = f"[ARGUS {case.number}] "
    said = words(case, by_person=by_person)
    full = prefix + said
    if _utf16(full) <= KIBANA_TITLE_LIMIT:
        return full
    room = KIBANA_TITLE_LIMIT - _utf16(prefix) - 1
    cut = ""
    for char in said:
        if _utf16(cut + char) > room:
            break
        cut += char
    return prefix + cut.rstrip() + "…"


def _utf16(text: str) -> int:
    return len(text.encode("utf-16-le")) // 2


def _fields(case: Case) -> dict[str, Any]:
    return {
        "status": KIBANA_STATUS[case.state],
        "severity": case.severity,
        "argus_tags": argus_tags(case),
    }


MAX_LISTED = 20  # hosts or indicators named in a description


@dataclass(frozen=True)
class AlertSpan:
    """When the case's alerts were first and last seen (from its investigations)."""

    first: datetime | None
    latest: datetime | None


def create(case: Case, span: AlertSpan | None = None, *, by_person: bool = False) -> PlannedWrite:
    """W1: the case as it is now, with ``settings: {syncAlerts: false}`` (Kibana needs settings
    on a create; an update never sends them). The description is a short summary code writes
    from the case's alerts (what happened, its hosts and indicators, the first and latest
    alert), says decisions are made in ARGUS and links the case; findings from logs stay in
    ARGUS. No connector, assignees or custom fields (the writer's strict body model). The title
    and "what happened" leave out ARGUS's certainty word unless a person wrote the title
    (``by_person``)."""
    actors = sorted(i.value for i in case.indicators if i.role == "actor")
    marks = sorted(i.value for i in case.indicators if i.role != "actor")
    return PlannedWrite(
        "W1",
        "create",
        {
            "title": title(case, by_person=by_person),
            **_fields(case),
            "settings": {"syncAlerts": False},
            "description": {
                "template": "case_description",
                "params": {
                    "case": str(case.id),
                    "link": CASE_LINK.format(id=case.id),
                    "what": words(case, by_person=by_person),
                    "hosts": actors[:MAX_LISTED],
                    "more_hosts": max(0, len(actors) - MAX_LISTED),
                    "indicators": marks[:MAX_LISTED],
                    "more_indicators": max(0, len(marks) - MAX_LISTED),
                    "investigations": len(case.members),
                    "first_alert": _iso(span.first if span else None),
                    "latest_alert": _iso(span.latest if span else None),
                },
            },
        },
    )


def _iso(value: datetime | None) -> str | None:
    return None if value is None else value.astimezone(UTC).isoformat()


def comment(write_class: WriteClass, template: str, **params: Any) -> PlannedWrite:
    return PlannedWrite(write_class, "comment", {"template": template, "params": params})


def update(before: Case, after: Case, template: str, **params: Any) -> list[PlannedWrite]:
    """W2: whatever of status, severity and ARGUS's tags changed, then a comment saying why."""
    old, new = _fields(before), _fields(after)
    changed = {key: value for key, value in new.items() if old[key] != value}
    writes = [PlannedWrite("W2", "update", changed)] if changed else []
    return [*writes, comment("W2", template, **params)]


CLOSED_TAGS = frozenset({"argus:closed", "argus:state:closed"})


def closes_case(write: PlannedWrite) -> bool:
    """Whether the write would close the Kibana case (its status, ARGUS's closed or reason
    tags, or the closing comment): only a W3 write with a closure's approval may (the
    database's ``argus_outbox_guard`` refuses any other)."""
    payload = write.payload
    tags = payload.get("argus_tags") or []
    return (
        payload.get("status") == "closed"
        or payload.get("template") == "closed"
        or any(t in CLOSED_TAGS or str(t).startswith("argus:reason:") for t in tags)
    )


def close(after: Case) -> list[PlannedWrite]:
    """W3: one change with the closed status and the reason's tags, then the closing comment
    as its own row. Both are bound to the approval by the outbox row; the comment
    names the approver from it when the writer renders it."""
    return [
        PlannedWrite("W3", "close", _fields(after)),
        comment("W3", "closed", reason=after.closure_reason),
    ]
