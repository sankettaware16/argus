"""What to send for an outbox row, given what Kibana holds now: pure.

The planner never trusts the row alone and never overwrites a person: the payload must still have
its hash; the Kibana case is re-read first and must be one ARGUS made, not paused or deleted, and
with Sync alerts off for a status change or an attach; a PATCH sends the latest version, keeps every
tag a person added and leaves alone a field or status a person changed; what is already as planned
is skipped. The result is a request for the Kibana lane's strict templates, or a reason for not
sending."""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel

from argus.cases import kibana as intent
from argus.gateway.kibana import models
from argus.gateway.kibana.templates import (
    AttachAlerts,
    AttachParams,
    CloseCase,
    CommentOnCase,
    CommentParams,
    CreateCase,
    KibanaTemplate,
    UpdateCase,
)
from argus.writer import render

MAX_ATTACHED = 200  # representative alerts a case holds in Kibana; the rest are linked from ARGUS
MANAGED = re.compile(
    r"argus|argus:closed|argus:(case|owner|state|reason):.+", re.DOTALL
)  # the tags ARGUS writes (people's other argus:* tags are kept)
ALERT_INDEX = re.compile(r"\.internal\.alerts-security\.alerts-[a-z0-9_-]{1,64}-[0-9]{6}")
CLOSE_FIELDS = ("status", "argus_tags")


def is_managed(tag: str) -> bool:
    return MANAGED.fullmatch(tag) is not None


def merge_tags(live: Sequence[str], argus: Sequence[str]) -> tuple[str, ...]:
    """ARGUS's own tags as planned (sorted), then every tag of the live case that is not one
    ARGUS writes, in the order Kibana shows them."""
    mine = sorted(set(argus))
    kept = [t for t in dict.fromkeys(live) if not is_managed(t) and t not in mine]
    return (*mine, *kept)


@dataclass(frozen=True)
class Row:
    """An outbox row with what its case event says (``kibana_outbox`` and ``case_events``)."""

    id: int
    case_id: uuid.UUID
    case_event_id: int
    position: int
    write_class: str
    op: str
    payload: Mapping[str, Any]
    payload_hash: str
    idempotency_key: str
    approval_request_id: int | None
    state: str
    sent_count: int
    from_state: str | None
    to_state: str


@dataclass(frozen=True)
class MirrorFacts:
    """What the read-back knows of the case (``kibana_mirror``): a pause, the fields people
    edited, and a deletion."""

    paused: str | None = None
    unmanaged: frozenset[str] = frozenset()
    deleted: bool = False
    severity: str | None = None  # as the last poll read it
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class Seen:
    """What ARGUS has seen or set on a Kibana case: the severities and the sets of ARGUS-written
    tags in the row's before-image, in the mirror's last poll and in the latest write ARGUS
    made and read back. A live value outside these (and not the planned one) was changed by a
    person since, and the read-back has not polled it yet: it is not overwritten. Empty: nothing
    is known, so nothing can be told."""

    severities: frozenset[str] = frozenset()
    tags: tuple[frozenset[str], ...] = ()

    @staticmethod
    def of(severities: Iterable[object], tag_lists: Iterable[Iterable[str] | None]) -> Seen:
        return Seen(
            frozenset(s for s in severities if isinstance(s, str)),
            tuple(
                dict.fromkeys(
                    frozenset(t for t in tags if is_managed(t))
                    for tags in tag_lists
                    if tags is not None
                )
            ),
        )


@dataclass(frozen=True)
class Send:
    template: KibanaTemplate
    params: BaseModel
    expect: Mapping[str, Any] = field(default_factory=dict)  # what the read-back must show
    kept: tuple[str, ...] = ()  # fields left to a person's edit


@dataclass(frozen=True)
class Skip:
    """Nothing to send: Kibana already shows it, or a person's edit stays."""

    reason: str


HoldAction = Literal["wait", "pause", "tamper", "sync_on"]


@dataclass(frozen=True)
class Hold:
    """Nothing is sent now. ``wait``: the row stays as it is; ``pause``: a person must look
    (the row is paused); ``tamper``: the row does not match its hash (paused, and the class);
    ``sync_on``: Sync alerts is on in Kibana (the case needs attention)."""

    reason: str
    action: HoldAction = "wait"


Plan = Send | Skip | Hold


def intact(row: Row) -> bool:
    return intent.payload_hash(dict(row.payload)) == row.payload_hash


def _utf16(value: str) -> int:
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def kibana_title(raw: object) -> str:
    """The title Kibana gets: the payload's, cleaned (no control, bidirectional or invisible
    character, one line) and defanged like every value a person or a log could have written,
    cut to Kibana's limit (UTF-16 units) with an ellipsis. The lookups compare with this."""
    text = render.defang(render.clean(raw, 1000))
    if _utf16(text) <= intent.KIBANA_TITLE_LIMIT:
        return text
    cut = ""
    for char in text:
        if _utf16(cut + char) > intent.KIBANA_TITLE_LIMIT - 1:
            break
        cut += char
    return cut.rstrip() + "…"


def plan_create(row: Row, ctx: render.Context) -> Send | Hold:
    """W1: the case as ARGUS planned it, with its description written by code."""
    if not intact(row):
        return Hold("the payload does not match its hash", "tamper")
    payload = row.payload
    try:
        text = render.description(payload["description"]["params"], ctx)
        body = models.CaseCreate(
            title=kibana_title(payload["title"]),
            description=text,
            tags=tuple(payload["argus_tags"]),
            severity=payload["severity"],
        )
    except (render.RenderError, KeyError, TypeError, ValueError) as exc:
        return Hold(f"the create cannot be rendered ({type(exc).__name__}: {exc})", "pause")
    return Send(
        CreateCase(),
        body,
        {
            "title": body.title,
            "description": text,
            "severity": body.severity,
            "tags": frozenset(body.tags),
        },
    )


def _live_problem(live: Mapping[str, Any] | None, mirror: MirrorFacts, author: str) -> Hold | None:
    if mirror.deleted or live is None:
        return Hold(
            "the Kibana case is gone (deleted there): recreate or close it in ARGUS", "pause"
        )
    if live["created_by"].get("username") != author:
        return Hold("the Kibana case was not made by ARGUS: it is not written to", "pause")
    if mirror.paused:
        return Hold(f"writes to this case are paused ({mirror.paused})", "wait")
    return None


def plan_change(
    row: Row,
    live: Mapping[str, Any] | None,
    mirror: MirrorFacts,
    ctx: render.Context,
    author: str,
    *,
    explained: str | None = None,
    status_from: str | None = None,
    seen: Seen | None = None,
) -> Plan:
    """W2's update and comment and W3's close and comment, against the case as it is now.
    ``explained``: why the change this comment explains was not made (its row was skipped), so
    the comment is not written either. ``seen``: what ARGUS has seen or set on the case; a
    severity or an ARGUS tag set outside it was changed by a person after the last poll, and is
    left alone."""
    if not intact(row):
        return Hold("the payload does not match its hash", "tamper")
    problem = _live_problem(live, mirror, author)
    if problem is not None:
        return problem
    assert live is not None
    if row.op == "comment":
        if explained is not None:
            return Skip(f"the change it explains was not made ({explained})")
        return plan_comment(row.payload, live, ctx)
    if row.op == "update":
        return _plan_update(row, live, mirror, status_from, seen)
    if row.op == "close":
        return _plan_close(row, live, mirror, seen)
    return Hold(f"a {row.op} row is not a change of an existing case", "pause")


def plan_comment(
    payload: Mapping[str, Any], live: Mapping[str, Any], ctx: render.Context
) -> Send | Hold:
    try:
        text = render.comment(payload["template"], payload["params"], ctx)
        params = CommentParams(case_id=live["id"], comment=text)
    except (render.RenderError, KeyError, TypeError, ValueError) as exc:
        return Hold(f"the comment cannot be rendered ({type(exc).__name__}: {exc})", "pause")
    return Send(CommentOnCase(), params, {"comment": text})


def _sync_guard(live: Mapping[str, Any]) -> Hold | None:
    if live["settings"].get("syncAlerts") is not False:
        return Hold("Sync alerts is on in Kibana: nothing is sent while it is", "sync_on")
    return None


def _patch(live: Mapping[str, Any], **fields: Any) -> tuple[models.CaseChange, dict[str, Any]]:
    change = models.CaseChange(id=live["id"], version=live["version"], **fields)
    return change, {k: v for k, v in fields.items() if v is not None}


def _tags_edited(live: Mapping[str, Any], target: Sequence[str], seen: Seen | None) -> Hold | None:
    """ARGUS's tags on the live case are neither as ARGUS last saw or set them nor as this write
    sets them: a person changed them (a tag of ARGUS's kind added, or one removed) and the
    read-back has not polled it. Nothing is sent: the poll pauses the case for it."""
    if seen is None or not seen.tags:
        return None
    now = frozenset(t for t in live["tags"] if is_managed(t))
    if now == frozenset(t for t in target if is_managed(t)) or now in seen.tags:
        return None
    return Hold(
        "a person changed ARGUS's tags in Kibana since ARGUS last read them: nothing is sent"
        " until the read-back has seen it",
        "wait",
    )


def _plan_update(
    row: Row,
    live: Mapping[str, Any],
    mirror: MirrorFacts,
    status_from: str | None = None,
    seen: Seen | None = None,
) -> Plan:
    """``status_from``: the status Kibana should show now (a compensating write's: what the
    write it undoes set); by default the status of the case's state before this row's event."""
    payload = row.payload
    fields: dict[str, Any] = {}
    kept: list[str] = []
    if "status" in payload:
        guard = _sync_guard(live)
        if guard is not None:
            return guard
        target = payload["status"]
        before = status_from or intent.KIBANA_STATUS.get(row.from_state or "")
        if live["status"] == target:
            pass  # already so
        elif live["status"] == before:
            fields["status"] = target
        else:
            kept.append("status (a person changed it in Kibana)")
    if "argus_tags" in payload:
        edited = _tags_edited(live, payload["argus_tags"], seen)
        if edited is not None:
            return edited
    if "severity" in payload:
        if "severity" in mirror.unmanaged:
            kept.append("severity (a person edited it)")
        elif live.get("severity") == payload["severity"]:
            pass  # already so
        elif seen is not None and seen.severities and live.get("severity") not in seen.severities:
            kept.append("severity (a person changed it in Kibana since ARGUS last read it)")
        else:
            fields["severity"] = payload["severity"]
    if "argus_tags" in payload:
        merged = merge_tags(live["tags"], payload["argus_tags"])
        if set(merged) != set(live["tags"]):
            fields["tags"] = merged
    if not fields:
        why = "; ".join(kept) if kept else "Kibana already shows it"
        return Skip(why)
    change, sent = _patch(live, **fields)
    try:
        patch = models.UpdatePatch(cases=(change,))
    except ValueError as exc:
        return Hold(f"the update cannot be sent ({exc})", "pause")
    expect = {k: (frozenset(v) if k == "tags" else v) for k, v in sent.items()}
    return Send(UpdateCase(), patch, expect, tuple(kept))


def _plan_close(
    row: Row, live: Mapping[str, Any], mirror: MirrorFacts, seen: Seen | None = None
) -> Plan:
    guard = _sync_guard(live)
    if guard is not None:
        return guard
    edited = _tags_edited(live, row.payload.get("argus_tags", ()), seen)
    if edited is not None:
        return edited
    tags = merge_tags(live["tags"], row.payload.get("argus_tags", ()))
    if live["status"] == "closed" and set(tags) == set(live["tags"]):
        return Skip("Kibana already shows the case closed with its tags")
    change, _ = _patch(live, status="closed", tags=tags)
    try:
        patch = models.ClosePatch(cases=(change,))
    except ValueError as exc:
        return Hold(f"the closure cannot be sent ({exc})", "pause")
    return Send(CloseCase(), patch, {"status": "closed", "tags": frozenset(tags)})


@dataclass(frozen=True, order=True)
class AlertRef:
    """An alert with its concrete index, and when it happened (for the order)."""

    at: datetime
    alert_id: str
    index: str


def representatives(
    groups: Mapping[uuid.UUID, Sequence[AlertRef]], cap: int = MAX_ATTACHED
) -> list[AlertRef]:
    """The alerts a case attaches: the first and the latest of each investigation (one rule,
    actor and local day), each with its concrete index, in the order of their investigations'
    first alerts, at most ``cap``. An alert without a usable index is left out."""
    picked: list[tuple[AlertRef, AlertRef | None]] = []
    for group in groups.values():
        usable = sorted(a for a in group if ALERT_INDEX.fullmatch(a.index))
        if usable:
            picked.append((usable[0], usable[-1] if usable[-1] != usable[0] else None))
    out: list[AlertRef] = []
    seen: set[str] = set()
    for first, latest in sorted(picked, key=lambda pair: pair[0]):
        for alert in (first, latest):
            if alert is not None and alert.alert_id not in seen and len(out) < cap:
                seen.add(alert.alert_id)
                out.append(alert)
    return out


def batches(
    refs: Sequence[AlertRef], size: int = models.MAX_ALERTS_PER_CALL
) -> list[list[AlertRef]]:
    return [list(refs[i : i + size]) for i in range(0, len(refs), size)]


def plan_attach(
    case_id: str, alerts: Sequence[tuple[str, str]], live: Mapping[str, Any]
) -> Send | Hold:
    """An attach of up to five alerts to the Kibana case ``case_id`` (an alert write)."""
    guard = _sync_guard(live)
    if guard is not None:
        return guard
    try:
        params = AttachParams(case_id=case_id, alerts=tuple(alerts))
    except ValueError as exc:
        return Hold(f"the attachment cannot be sent ({exc})", "pause")
    return Send(AttachAlerts(), params, {"alerts": tuple(a for a, _ in alerts)})


def describe(verdict: Plan, live: Mapping[str, Any] | None = None) -> str:
    """One plain line for ``argus kibana diff``: what a run would do with this row."""
    match verdict:
        case Skip(reason):
            return f"nothing to send: {reason}"
        case Hold(reason, action):
            return f"not sent now ({action}): {reason}"
        case Send(template, params, kept=kept):
            what = _what(template.name, params, live)
            return what + (f" (left to people: {'; '.join(kept)})" if kept else "")
    raise AssertionError("a plan is a skip, a hold or a send")  # pragma: no cover


def _what(name: str, params: BaseModel, live: Mapping[str, Any] | None) -> str:
    if isinstance(params, models.CaseCreate):
        return (
            f"create the case {render.clean(params.title, 80)!r}, {params.severity},"
            f" {len(params.tags)} ARGUS tags, Sync alerts off"
        )
    if isinstance(params, models.CasesPatch):
        change = params.cases[0]
        parts = []
        if change.status is not None:
            parts.append(f"status {(live or {}).get('status', '?')} -> {change.status}")
        if change.severity is not None:
            parts.append(f"severity {(live or {}).get('severity', '?')} -> {change.severity}")
        if change.tags is not None:
            old = set((live or {}).get("tags", ()))
            new = set(change.tags)
            parts.append(f"tags +{sorted(new - old)} -{sorted(old - new)}")
        return f"{name}: " + ", ".join(parts)
    if isinstance(params, CommentParams):
        return f"comment: {render.clean(params.comment, 90)!r}"
    if isinstance(params, AttachParams):
        return f"attach {len(params.alerts)} alerts"
    return name
