"""The case lifecycle (plan §7.1): a pure transition function, and the replay that rebuilds a
case from its events.

States: suspected (ARGUS only) → open (owner ARGUS) ↔ assigned (owner a person) → contained;
any confirmed state → closed by an approved closure; suspected → closed by a reviewer's
dismissal; closed → open (or suspected, if it was never confirmed) by a person's reopen. Every
arrow is a person's action except ARGUS's own: a suspected case from its proposal, a case
opened from a person's true-positive verdict (or a suspected case confirmed by one), linking
members, and "new activity" (contained → open). Activity after closure never reopens a case:
it gets a linked new case.

Besides the states, an open or assigned case can be **notified** (AR4b, D-169, D-176): a person
records that the device's owner was told, which keeps the state and leaves the work queues (the
case is then tracked as a known infection, :mod:`argus.cases.knownrun`). Notices and network
blocks are facts on the case, not states: personal laptops cannot be forced clean, so the case
stays open and watched.

A case can also **split** (D-211): a person moves investigations out of it, into a case they open
or an existing one, with :class:`Unlink` (event ``unlinked``, the state kept). The members leave,
and so do the actor indicators only they carried, so a case that grouped two separate devices can
hold one of them (the owner's notice then covers that device alone). The other half is the
target's :class:`Open` or :class:`Link`, both naming where the investigations came from.

A case's title can change (D-230, :class:`Retitle`, event ``retitled``, any state, the state kept):
a person renames it with a reason, and ARGUS refreshes the title it wrote itself when the case's
facts change (:mod:`argus.cases.naming`). Who wrote the title is the actor of the newest
``suspected``, ``opened`` or ``retitled`` event; the service refuses ARGUS's retitle of a title a
person wrote.

:func:`decide` checks who may act and whether the move is allowed, and returns the case after
it, the event's details and the Kibana writes it plans; it never reads or writes anything.
The database checks the same edges again (migration 0026's ``argus_case_guard``).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, fields, replace
from datetime import datetime, timedelta
from typing import Any, Literal

from argus.cases import kibana
from argus.cases.kibana import PlannedWrite
from argus.cases.model import (
    CONFIRMED,
    DISMISS_REASONS,
    NOTE_LIMIT,
    NOTICE_HOWS,
    PROPOSE_REASONS,
    REQUEST_REASONS,
    TITLE_LIMIT,
    WAITING_FOR_KIBANA,
    Actor,
    ApprovalFacts,
    Capability,
    Case,
    Cause,
    Indicator,
    Member,
    NoticeHow,
    QuietWindow,
    Reason,
    Severity,
    State,
    max_severity,
)

EDGES: frozenset[tuple[State, State]] = frozenset(
    {
        ("suspected", "open"),
        ("suspected", "closed"),
        ("open", "assigned"),
        ("open", "contained"),
        ("open", "closed"),
        ("assigned", "open"),
        ("assigned", "contained"),
        ("assigned", "closed"),
        ("contained", "open"),
        ("contained", "closed"),
        ("closed", "open"),
        ("closed", "suspected"),
    }
)
MAX_MEMBERS = 500  # members or indicators one change may add (a merge moves them all)
NEW_ACTIVITY = "New activity after containment"
RAISED_REASON = "ARGUS suggests this case: "  # how the reason of a suggested case starts
ATTENTION_LIMIT = 500  # the column's limit (cases.notes_length)
TOLD_LIMIT = 200  # who was told, or who blocked
WHERE_LIMIT = 100  # where a block was put
NOTICE_PAST = timedelta(days=365)  # a notice or a block is dated within the last year...
NOTICE_FUTURE = timedelta(minutes=5)  # ...and not in the future (a clock a little ahead)
Code = Literal["forbidden", "conflict", "invalid", "unavailable", "not_found"]


class CaseRefused(Exception):  # noqa: N818 - a refusal, not an error
    """The change is not allowed; nothing was changed. ``code`` maps to HTTP: forbidden 403,
    conflict 409, invalid 422, unavailable 409 (the evidence it needs does not exist yet),
    not_found 404."""

    def __init__(self, code: Code, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


# --------------------------------------------------------------------------- commands


@dataclass(frozen=True)
class Open:
    """A new case: suspected (ARGUS's own true-positive proposal) or open (a person's verdict,
    or a person who may manage cases). ``kibana_by`` is the person whose live check decides
    whether Kibana gets the case now; otherwise it waits for someone who may open it there."""

    title: str
    severity: Severity
    cause: Cause
    members: tuple[Member, ...]
    indicators: tuple[Indicator, ...] = ()
    suspected: bool = False
    cause_review_id: int | None = None
    cause_assessment_id: int | None = None
    parent_case_id: uuid.UUID | None = None
    kibana_by: Actor | None = None
    attention: str | None = None  # ARGUS's reason a person should look (a raised case's reason)
    split_from: uuid.UUID | None = None  # the case a person moved these investigations out of


@dataclass(frozen=True)
class Confirm:
    note: str | None = None


@dataclass(frozen=True)
class ConfirmByVerdict:
    """ARGUS acts on a person's true-positive verdict with an impact or campus-host signal on
    an investigation that is, or now joins, a suspected case (plan §7.1: "new or suspected →
    open"). Kibana waits for someone who may open cases there, as for a case the verdict opens."""

    review_id: int
    by_user_id: int
    members: tuple[Member, ...] = ()
    indicators: tuple[Indicator, ...] = ()
    severity: Severity | None = None


@dataclass(frozen=True)
class Dismiss:
    reason: Reason
    note: str | None = None


@dataclass(frozen=True)
class Take:
    pass


@dataclass(frozen=True)
class Assign:
    user_id: int
    assignable: bool  # the person exists and may hold cases (the service checks)


@dataclass(frozen=True)
class Release:
    pass


@dataclass(frozen=True)
class Contain:
    attestation: str
    window: QuietWindow


@dataclass(frozen=True)
class NewActivity:
    summary: str
    members: tuple[Member, ...] = ()
    indicators: tuple[Indicator, ...] = ()
    severity: Severity | None = None


@dataclass(frozen=True)
class AfterClosure:
    """Activity followed a closed case: a suspected case that follows it (``child_case_id``), or,
    when there is nothing to open one with (the activity was seen in the logs only), a note on
    the closed case itself (``summary``, shown as its attention). Never a reopen."""

    child_case_id: uuid.UUID | None = None
    summary: str | None = None


@dataclass(frozen=True)
class Link:
    members: tuple[Member, ...] = ()
    indicators: tuple[Indicator, ...] = ()
    severity: Severity | None = None
    split_from: uuid.UUID | None = None  # the case a person moved these investigations out of


@dataclass(frozen=True)
class Unlink:
    """A person moves investigations out of a case (D-211): into a case they open for them or an
    existing one (``target_id``, which the caller has made or locked; the event names it). The
    members leave, and so do the actor indicators only they carried (``indicators``, which the
    service works out and the machine only checks are on the case); C2 and other indicators stay,
    shared infrastructure is a fact of both cases. The case keeps at least one investigation:
    moving every one is a merge."""

    investigations: tuple[uuid.UUID, ...]
    reason: str
    target_id: uuid.UUID
    indicators: tuple[Indicator, ...] = ()


@dataclass(frozen=True)
class Notify:
    """A person records that the device's owner (or its department, hostel or lab) was told
    (D-169): ``told`` says who, ``how`` the way, ``at`` when (default now). ``managed``: the case's
    devices are campus-managed machines (the caller works it out from the asset map; unknown is
    not managed). A second notice (a reminder followed) is another ``Notify``."""

    told: str
    how: NoticeHow
    at: datetime | None = None
    note: str | None = None
    managed: bool = False


@dataclass(frozen=True)
class WithdrawNotice:
    """A person withdraws a notice they recorded by mistake (D-181): ``who`` is who withdraws it,
    ``reason`` why. The case is not notified any more: the fingerprint stops absorbing, and what
    was decided known stays decided (nothing comes back as new work). The notice rows stay, as
    the record of what was said; the case event ``notice_withdrawn`` is the audit of this."""

    who: str
    reason: str


@dataclass(frozen=True)
class RecordBlock:
    """A person records that the case's servers or domains were blocked at the network (DNS,
    firewall, proxy): ``by`` is who did it (free text), ``where`` where it was put, ``at`` when."""

    by: str
    where: str
    at: datetime | None = None
    note: str | None = None


@dataclass(frozen=True)
class AddressMoved:
    """The same device came back from a new campus address (DHCP): ARGUS notes it on the case,
    adds the new address as a device and takes the investigation in (D-169 point 6)."""

    old: str
    new: str
    hours: int  # between the old address going quiet and the new one's first alert
    summary: str
    members: tuple[Member, ...] = ()
    indicators: tuple[Indicator, ...] = ()
    severity: Severity | None = None


@dataclass(frozen=True)
class Retitle:
    """A new title for the case (D-230): a person's own words (with the reason), or ARGUS's
    refreshed title when the case's facts changed (the service refuses ARGUS's when a person set
    the title). Any state; nothing is mirrored to Kibana (a title is posted once, at creation)."""

    title: str
    reason: str | None = None


@dataclass(frozen=True)
class Publish:
    pass


@dataclass(frozen=True)
class RequestClosure:
    reason: Reason
    note: str | None = None
    window: QuietWindow | None = None


@dataclass(frozen=True)
class ProposeClosure:
    """ARGUS proposes closing a case (Q-C3) for a reason with positive evidence: a verified
    quiet window (``remediated_verified``, ``attempt_no_impact``) or people's reviews (the
    benign and false-positive reasons, ``evidence`` saying which). A person approves it."""

    reason: Reason
    evidence: str | None = None
    window: QuietWindow | None = None


@dataclass(frozen=True)
class RequestMerge:
    target_id: uuid.UUID
    target_state: State
    note: str | None = None


@dataclass(frozen=True)
class Close:
    approval: ApprovalFacts


@dataclass(frozen=True)
class MergeInto:
    target_id: uuid.UUID
    target_state: State
    approval: ApprovalFacts | None  # needed for a confirmed case
    note: str | None = None


@dataclass(frozen=True)
class MergedIn:
    source_id: uuid.UUID
    members: tuple[Member, ...]
    indicators: tuple[Indicator, ...]
    severity: Severity


@dataclass(frozen=True)
class Reopen:
    reason: str


Command = (
    Confirm
    | ConfirmByVerdict
    | Dismiss
    | Take
    | Assign
    | Release
    | Contain
    | NewActivity
    | AfterClosure
    | Link
    | Unlink
    | Notify
    | WithdrawNotice
    | RecordBlock
    | AddressMoved
    | Retitle
    | Publish
    | RequestClosure
    | ProposeClosure
    | RequestMerge
    | Close
    | MergeInto
    | MergedIn
    | Reopen
)


@dataclass(frozen=True)
class Step:
    """One change: the event's kind, the case before (None when created) and after, what the
    event records, and the Kibana writes planned with it."""

    kind: str
    before: Case | None
    after: Case
    details: dict[str, Any]
    writes: tuple[PlannedWrite, ...]
    members_added: tuple[Member, ...] = ()
    members_removed: tuple[uuid.UUID, ...] = ()
    indicators_added: tuple[Indicator, ...] = ()
    indicators_removed: tuple[Indicator, ...] = ()

    @property
    def mirror_create(self) -> bool:
        return any(w.op == "create" for w in self.writes)


# --------------------------------------------------------------------------- deciding


def _refuse(code: Code, message: str) -> CaseRefused:
    return CaseRefused(code, message)


def _person(actor: Actor, capability: Capability, what: str) -> None:
    if not actor.is_person:
        raise _refuse("forbidden", f"{what} is a person's action")
    if not actor.may(capability):
        raise _refuse("forbidden", f"{what} needs the {capability.value} capability")


def _argus(actor: Actor, what: str) -> None:
    if actor.is_person:
        raise _refuse("forbidden", f"{what} is ARGUS's own move")


def _text(value: str | None, what: str, *, required: bool = False) -> str | None:
    if value is not None:
        value = value.strip()
    if not value:
        if required:
            raise _refuse("invalid", f"{what} is required")
        return None
    if len(value) > NOTE_LIMIT:
        raise _refuse("invalid", f"{what} has at most {NOTE_LIMIT} characters")
    if "\x00" in value:
        raise _refuse("invalid", f"{what} cannot hold a NUL character")
    return value


def _told(value: str, what: str, *, limit: int = TOLD_LIMIT) -> str:
    """Words a person typed that name someone or somewhere: one line, no control characters."""
    said = _text(value, what, required=True)
    assert said is not None
    if len(said) > limit:
        raise _refuse("invalid", f"{what} has at most {limit} characters")
    if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in said):
        raise _refuse("invalid", f"{what} cannot hold control characters")
    return said


def _dated(value: datetime | None, now: datetime, what: str) -> datetime:
    """When a notice or a block happened: now by default, never in the future and not more than a
    year back (a person records what they did, soon after)."""
    if value is None:
        return now
    if value.tzinfo is None:
        raise _refuse("invalid", f"{what} is dated with a time zone")
    if value > now + NOTICE_FUTURE:
        raise _refuse("invalid", f"{what} cannot be dated in the future")
    if value < now - NOTICE_PAST:
        raise _refuse("invalid", f"{what} cannot be dated more than a year back")
    return value


def _title(value: str) -> str:
    """A case title: 1 to TITLE_LIMIT characters, no control characters (it reaches terminals,
    pages and Kibana)."""
    title = _text(value, "a title", required=True)
    assert title is not None
    if len(title) > TITLE_LIMIT:
        raise _refuse("invalid", f"a title has at most {TITLE_LIMIT} characters")
    if any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in title):
        raise _refuse("invalid", "a title cannot hold control characters")
    return title


def _state(case: Case, allowed: Iterable[State], what: str) -> None:
    allowed = tuple(allowed)
    if case.state not in allowed:
        raise _refuse("conflict", f"cannot {what} a {case.state} case")


def _new_members(case: Case, members: Sequence[Member]) -> tuple[Member, ...]:
    if len(members) > MAX_MEMBERS:
        raise _refuse("invalid", f"at most {MAX_MEMBERS} members at a time")
    seen: dict[uuid.UUID, Member] = {}
    for member in members:
        if member.investigation_id in case.members or member.investigation_id in seen:
            continue
        seen[member.investigation_id] = member
    return tuple(sorted(seen.values()))


def _new_indicators(case: Case, indicators: Sequence[Indicator]) -> tuple[Indicator, ...]:
    if len(indicators) > MAX_MEMBERS:
        raise _refuse("invalid", f"at most {MAX_MEMBERS} indicators at a time")
    held = {(i.kind, i.value) for i in case.indicators}
    out: dict[tuple[str, str], Indicator] = {}
    for indicator in indicators:
        key = (indicator.kind, indicator.value)
        if key in held or key in out:
            continue
        if not 1 <= len(indicator.value) <= 512:
            raise _refuse("invalid", "an indicator has 1 to 512 characters")
        out[key] = indicator
    return tuple(sorted(out.values()))


def _unlinked(
    case: Case, moving: Sequence[uuid.UUID], target: uuid.UUID, leaving: Sequence[Indicator]
) -> frozenset[uuid.UUID]:
    """The investigations an :class:`Unlink` moves, checked: each one an active member named once,
    at least one member stays, and the indicators that go are actor rows the case holds."""
    if target == case.id:
        raise _refuse("invalid", "investigations cannot be moved to the case they are in")
    if not moving:
        raise _refuse("invalid", "name the investigations to move")
    if len(moving) > MAX_MEMBERS or len(leaving) > MAX_MEMBERS:
        raise _refuse("invalid", f"at most {MAX_MEMBERS} members or indicators at a time")
    moved = frozenset(moving)
    if len(moved) != len(moving):
        raise _refuse("invalid", "an investigation is named once")
    for investigation in moving:
        if investigation not in case.members:
            raise _refuse("conflict", f"investigation {investigation} is not in this case")
    if moved >= case.members:
        raise _refuse(
            "conflict",
            "moving every investigation out of a case is a merge: merge the case into the other"
            " (or close it), a case keeps at least one investigation",
        )
    gone = {(i.kind, i.value, i.role) for i in leaving}
    if len(gone) != len(leaving):
        raise _refuse("invalid", "an indicator is named once")
    held = {(i.kind, i.value, i.role) for i in case.indicators}
    for kind, value, role in sorted(gone):
        if role != "actor":
            raise _refuse("invalid", "only an actor indicator leaves with its investigations")
        if (kind, value, role) not in held:
            raise _refuse("conflict", f"the case does not hold the actor {kind} {value}")
    return moved


def _grow(
    case: Case, members: Sequence[Member], indicators: Sequence[Indicator]
) -> tuple[Case, tuple[Member, ...], tuple[Indicator, ...]]:
    added = _new_members(case, members)
    marks = _new_indicators(case, indicators)
    grown = replace(
        case,
        members=case.members | {m.investigation_id for m in added},
        indicators=case.indicators | frozenset(marks),
    )
    return grown, added, marks


def _mirror(before: Case, after: Case, template: str, **params: Any) -> tuple[PlannedWrite, ...]:
    """W2 for a mirrored case (nothing before a Kibana create was planned)."""
    if not before.mirrored:
        return ()
    return tuple(kibana.update(before, after, template, **params))


def _check_approval(case: Case, approval: ApprovalFacts, kind: str, now: datetime) -> None:
    if approval.case_id != case.id or approval.kind != kind:
        raise _refuse("conflict", f"the approval is not for this case's {kind}")
    if approval.case_version != case.version:
        raise _refuse("conflict", "the case changed after the approval was requested")
    if approval.rejected:
        raise _refuse("conflict", "the request was rejected")
    if approval.approved < approval.required:
        raise _refuse(
            "conflict", f"the request has {approval.approved} of {approval.required} approvals"
        )
    if now > approval.expires_at:
        raise _refuse("conflict", "the approval expired")


def create(
    case_id: uuid.UUID,
    number: int,
    command: Open,
    actor: Actor,
    now: datetime,
    span: kibana.AlertSpan | None = None,
) -> Step:
    """A new case at version 1. Pure: the service calls it once to insert the row and again
    with the number the database gave it."""
    if command.suspected:
        _argus(actor, "a suspected case")
    elif actor.is_person:
        _person(actor, Capability.MANAGE, "opening a case")
    elif command.cause != "verdict":
        raise _refuse("forbidden", "ARGUS opens a case only from a person's verdict")
    title = _title(command.title)
    if not command.members:
        raise _refuse("invalid", "a case starts with at least one investigation")
    if (command.cause == "verdict") != (command.cause_review_id is not None) or (
        command.cause == "proposal"
    ) != (command.cause_assessment_id is not None):
        raise _refuse("invalid", "the cause does not name its verdict or proposal")
    if command.suspected and command.cause not in ("proposal", "watch", "raised"):
        raise _refuse(
            "invalid", "a suspected case comes from ARGUS's own proposal, watch or evidence"
        )
    if command.cause == "watch" and not (command.suspected and command.parent_case_id):
        raise _refuse("invalid", "the watch opens a suspected case that follows a closed one")
    if command.split_from is not None and (
        command.suspected or not actor.is_person or command.split_from == case_id
    ):
        raise _refuse("invalid", "a split opens a case for a person, from another case")
    attention = _text(command.attention, "the reason")
    if attention is not None and len(attention) > ATTENTION_LIMIT:
        raise _refuse("invalid", f"the reason has at most {ATTENTION_LIMIT} characters")
    if command.cause == "raised" and not (command.suspected and attention):
        raise _refuse("invalid", "a raised case is suspected and says why ARGUS raised it")
    empty = Case(
        id=case_id,
        number=number,
        title=title,
        state="suspected" if command.suspected else "open",
        severity=command.severity,
        version=1,
        cause=command.cause,
        cause_review_id=command.cause_review_id,
        cause_assessment_id=command.cause_assessment_id,
        parent_case_id=command.parent_case_id,
        opened_at=None if command.suspected else now,
        attention=attention,
    )
    case, added, marks = _grow(empty, command.members, command.indicators)
    writes: tuple[PlannedWrite, ...] = ()
    if not command.suspected:
        opener = command.kibana_by or (actor if actor.is_person else None)
        if opener is not None and opener.may_open_in_kibana(now):
            case = replace(case, mirrored=True)
            writes = (kibana.create(case, span),)
        else:
            case = replace(case, kibana_wait=WAITING_FOR_KIBANA)
    kind = "suspected" if command.suspected else "opened"
    details = {} if command.split_from is None else {"split_from": str(command.split_from)}
    return Step(kind, None, case, details, writes, added, (), marks)


def decide(
    case: Case,
    command: Command,
    actor: Actor,
    now: datetime,
    span: kibana.AlertSpan | None = None,
) -> Step:
    """The step ``command`` makes from ``case``, or CaseRefused. Pure. ``span`` (when the
    case's alerts were first and last seen) goes into a Kibana create's description."""
    match command:
        case Confirm(note=note):
            _person(actor, Capability.MANAGE, "confirming a case")
            _state(case, ("suspected",), "confirm")
            after = replace(case, state="open", opened_at=now, version=case.version + 1)
            writes: tuple[PlannedWrite, ...] = ()
            if actor.may_open_in_kibana(now):
                after = replace(after, mirrored=True, kibana_wait=None)
                writes = (kibana.create(after, span),)
            else:
                after = replace(after, kibana_wait=WAITING_FOR_KIBANA)
            return Step("confirmed", case, after, _extra(note=_text(note, "a note")), writes)
        case ConfirmByVerdict(review_id=review, by_user_id=by, members=members,
                              indicators=indicators, severity=severity):  # fmt: skip
            _argus(actor, "confirming a case from a person's verdict")
            _state(case, ("suspected",), "confirm")
            if case.cause == "raised":
                raise _refuse("conflict", "a suggested case is confirmed by a person (Confirm)")
            if review < 1 or by < 1:
                raise _refuse("invalid", "the verdict names its review and person")
            grown, added, marks = _grow(case, members, indicators)
            after = replace(
                grown, state="open", opened_at=now, kibana_wait=WAITING_FOR_KIBANA,
                severity=max_severity(case.severity, severity or case.severity),
                version=case.version + 1,
            )  # fmt: skip
            details = {"review": review, "verdict_by": f"user:{by}"}
            return Step("confirmed", case, after, details, (), added, (), marks)
        case Dismiss(reason=reason, note=note):
            _person(actor, Capability.REVIEW, "dismissing a case")
            _state(case, ("suspected",), "dismiss")
            if reason not in DISMISS_REASONS:
                raise _refuse("invalid", f"a suspected case is not dismissed as {reason}")
            after = replace(
                case, state="closed", closed_at=now, closure_reason=reason, attention=None,
                version=case.version + 1,
            )  # fmt: skip
            return Step("dismissed", case, after, _extra(note=_text(note, "a note")), ())
        case Take():
            _person(actor, Capability.MANAGE, "taking a case")
            _state(case, ("open", "assigned"), "take")
            if case.owner_user_id == actor.user_id:
                raise _refuse("conflict", "you own this case already")
            after = replace(case, state="assigned", owner_user_id=actor.user_id,
                            version=case.version + 1)  # fmt: skip
            return Step("taken", case, after, {},
                        _mirror(case, after, "taken", by=actor.name))  # fmt: skip
        case Assign(user_id=user_id, assignable=assignable):
            _person(actor, Capability.MANAGE, "assigning a case")
            _state(case, ("open", "assigned"), "assign")
            if not assignable or user_id < 1:
                raise _refuse("invalid", "the case can only go to an active person")
            if case.owner_user_id == user_id:
                raise _refuse("conflict", "that person owns this case already")
            after = replace(case, state="assigned", owner_user_id=user_id,
                            version=case.version + 1)  # fmt: skip
            writes = _mirror(case, after, "assigned", to=f"user:{user_id}", by=actor.name)
            return Step("assigned", case, after, {"to": user_id}, writes)
        case Release():
            _person(actor, Capability.MANAGE, "releasing a case")
            _state(case, ("assigned",), "release")
            after = replace(case, state="open", owner_user_id=None, version=case.version + 1)
            return Step("released", case, after, {},
                        _mirror(case, after, "released", by=actor.name))  # fmt: skip
        case Contain(attestation=attestation, window=window):
            _person(actor, Capability.MANAGE, "confirming containment")
            _state(case, ("open", "assigned"), "contain")
            said = _text(attestation, "an attestation", required=True)
            if not window.verified:
                raise _refuse("unavailable", f"not contained: {window.reason}")
            after = replace(case, state="contained", attention=None, notified_at=None,
                            version=case.version + 1)  # fmt: skip
            writes = _mirror(case, after, "contained", by=actor.name)
            details = {"attestation": said, "window": window.reason, "at": now.isoformat()}
            return Step("contained", case, after, details, writes)
        case NewActivity(summary=summary, members=members, indicators=indicators,
                         severity=severity):  # fmt: skip
            _argus(actor, "new activity")
            _state(case, ("contained",), "reopen for new activity on")
            said = _text(summary, "a summary", required=True)
            grown, added, marks = _grow(case, members, indicators)
            after = replace(
                grown, state="open", owner_user_id=None, attention=NEW_ACTIVITY,
                severity=max_severity(case.severity, severity or case.severity),
                version=case.version + 1,
            )  # fmt: skip
            writes = _mirror(case, after, "new_activity")
            details = {"summary": said, "owner_was": case.owner_user_id}
            return Step("new_activity", case, after, details, writes, added, (), marks)
        case AfterClosure(child_case_id=child, summary=summary):
            _argus(actor, "activity after closure")
            _state(case, ("closed",), "note activity after closure on")
            if child == case.id:
                raise _refuse("invalid", "a case does not follow itself")
            if (child is None) == (summary is None):
                raise _refuse("invalid", "activity after closure names a child case or a summary")
            if child is None:
                said = _text(summary, "a summary", required=True)
                assert said is not None
                after = replace(case, attention=said[:500], version=case.version + 1)
                return Step("activity_after_closure", case, after, {"summary": said}, ())
            after = replace(case, version=case.version + 1)
            return Step("activity_after_closure", case, after, {"child": str(child)}, ())
        case Link(members=members, indicators=indicators, severity=severity, split_from=split):
            if actor.is_person:
                _person(actor, Capability.MANAGE, "linking investigations")
            if split is not None and (not actor.is_person or split == case.id):
                raise _refuse("invalid", "a split moves investigations from another case")
            _state(case, ("suspected", "open", "assigned", "contained"), "link to")
            grown, added, marks = _grow(case, members, indicators)
            if not added and not marks:
                raise _refuse("conflict", "nothing new to link")
            after = replace(
                grown, severity=max_severity(case.severity, severity or case.severity),
                version=case.version + 1,
            )  # fmt: skip
            writes = ()
            if after.severity != case.severity:
                writes = _mirror(case, after, "severity", severity=after.severity)
            details = {} if split is None else {"split_from": str(split)}
            return Step("linked", case, after, details, writes, added, (), marks)
        case Unlink(investigations=moving, reason=reason, target_id=target, indicators=leaving):
            _person(actor, Capability.MANAGE, "moving investigations out of a case")
            _state(case, ("suspected", *CONFIRMED), "move investigations out of")
            why = _text(reason, "a reason", required=True)
            moved = _unlinked(case, moving, target, leaving)
            after = replace(
                case,
                members=case.members - set(moved),
                indicators=case.indicators - set(leaving),
                version=case.version + 1,
            )
            details = _extra(target=str(target), reason=why)
            return Step("unlinked", case, after, details, (), (), tuple(sorted(moved)), (),
                        tuple(sorted(leaving)))  # fmt: skip
        case Notify(told=told, how=how, at=at, note=note, managed=managed):
            _person(actor, Capability.MANAGE, "recording a notice")
            _state(case, ("open", "assigned"), "record a notice on")
            who = _told(told, "who was told")
            if how not in NOTICE_HOWS:
                raise _refuse("invalid", f"how it was told is one of {', '.join(NOTICE_HOWS)}")
            when = _dated(at, now, "a notice")
            first = case.notified_at is None
            after = replace(case, notified_at=case.notified_at or when, attention=None,
                            version=case.version + 1)  # fmt: skip
            details = _extra(told=who, how=how, at=when.isoformat(), again=not first,
                             managed=managed, note=_text(note, "a note"))  # fmt: skip
            return Step("notified", case, after, details, ())
        case WithdrawNotice(who=who, reason=reason):
            _person(actor, Capability.MANAGE, "withdrawing a notice")
            _state(case, ("open", "assigned"), "withdraw a notice from")
            if case.notified_at is None:
                raise _refuse("conflict", "this case has no notice to withdraw")
            by = _told(who, "who is withdrawing it")
            why = _text(reason, "a reason", required=True)
            was = case.notified_at.isoformat()
            after = replace(case, notified_at=None, version=case.version + 1)
            return Step("notice_withdrawn", case, after, _extra(by=by, reason=why, was=was), ())
        case RecordBlock(by=by, where=where, at=at, note=note):
            _person(actor, Capability.MANAGE, "recording a block")
            _state(case, CONFIRMED, "record a block on")
            who = _told(by, "who blocked it")
            place = _told(where, "where it was blocked", limit=WHERE_LIMIT)
            when = _dated(at, now, "a block")
            after = replace(case, blocked_at=case.blocked_at or when, version=case.version + 1)
            details = _extra(by=who, where=place, at=when.isoformat(),
                             note=_text(note, "a note"))  # fmt: skip
            return Step("blocked", case, after, details, ())
        case AddressMoved(old=old, new=new, hours=hours, summary=summary, members=members,
                          indicators=indicators, severity=severity):  # fmt: skip
            _argus(actor, "noting a moved address")
            _state(case, ("open", "assigned"), "note a moved address on")
            if case.notified_at is None:
                raise _refuse("conflict", "only a notified case follows a device to a new address")
            said = _text(summary, "a summary", required=True)
            if old == new or not old or not new:
                raise _refuse("invalid", "a moved address names the old and the new address")
            grown, added, marks = _grow(case, members, indicators)
            if not added and not marks:
                raise _refuse("conflict", "nothing new to note: the address is held already")
            after = replace(
                grown, severity=max_severity(case.severity, severity or case.severity),
                version=case.version + 1,
            )  # fmt: skip
            details = {"old": old, "new": new, "hours": hours, "summary": said}
            return Step("address_moved", case, after, details, (), added, (), marks)
        case Retitle(title=new, reason=reason):
            if actor.is_person:
                _person(actor, Capability.MANAGE, "retitling a case")
            fixed = _title(new)
            if fixed == case.title:
                raise _refuse("conflict", "the case has that title already")
            why = _text(reason, "a reason", required=actor.is_person)
            after = replace(case, title=fixed, version=case.version + 1)
            details = _extra(old=case.title, new=fixed, by=actor.name, reason=why)
            return Step("retitled", case, after, details, ())
        case Publish():
            _person(actor, Capability.MANAGE, "opening the case in Kibana")
            _state(case, CONFIRMED, "open in Kibana")
            if case.mirrored:
                raise _refuse("conflict", "Kibana has this case already")
            if not actor.may_open_in_kibana(now):
                raise _refuse(
                    "forbidden", "your live Kibana check must show createCase and createComment"
                )
            after = replace(case, mirrored=True, kibana_wait=None, version=case.version + 1)
            return Step("published", case, after, {}, (kibana.create(after, span),))
        case RequestClosure(reason=reason, note=note, window=window):
            _person(actor, Capability.MANAGE, "requesting a closure")
            _state(case, CONFIRMED, "request closing")
            if reason not in REQUEST_REASONS:
                raise _refuse("invalid", f"{reason} is not a closure a person requests")
            said = _check_evidence(reason, note, window)
            after = replace(case, version=case.version + 1)
            return Step("closure_requested", case, after, _extra(reason=reason, note=said), ())
        case ProposeClosure(reason=reason, evidence=evidence, window=window):
            _argus(actor, "proposing a closure")
            _state(case, CONFIRMED, "propose closing")
            if reason not in PROPOSE_REASONS:
                raise _refuse("invalid", f"ARGUS does not propose a closure as {reason}")
            _needs_notice(case, reason)
            if reason in ("remediated_verified", "attempt_no_impact"):
                _check_evidence(reason, None, window)
                said = window.reason if window is not None else None
            else:
                said = _text(evidence, "the evidence", required=True)
            after = replace(case, version=case.version + 1)
            details = _extra(reason=reason, note=said, proposed=True)
            return Step("closure_requested", case, after, details, ())
        case RequestMerge(target_id=target, target_state=target_state, note=note):
            _person(actor, Capability.MANAGE, "requesting a merge")
            _state(case, CONFIRMED, "merge")
            _merge_target(case, target, target_state)
            after = replace(case, version=case.version + 1)
            details = _extra(target=str(target), note=_text(note, "a note"))
            return Step("merge_requested", case, after, details, ())
        case Close(approval=approval):
            _person(actor, Capability.APPROVE, "closing a case")
            _state(case, CONFIRMED, "close")
            _check_approval(case, approval, "closure", now)
            assert approval.reason is not None
            after = replace(
                case, state="closed", closed_at=now, closure_reason=approval.reason,
                closure_request_id=approval.request_id, attention=None, notified_at=None,
                blocked_at=None, version=case.version + 1,
            )  # fmt: skip
            writes = tuple(kibana.close(after)) if case.mirrored else ()
            return Step("closed", case, after, {"approval": approval.request_id}, writes)
        case MergeInto(target_id=target, target_state=target_state, approval=approval,
                       note=note):  # fmt: skip
            _state(case, ("suspected", *CONFIRMED), "merge")
            _merge_target(case, target, target_state)
            if case.confirmed:
                _person(actor, Capability.APPROVE, "merging a confirmed case")
                if approval is None:
                    raise _refuse("conflict", "merging a confirmed case needs an approval")
                _check_approval(case, approval, "merge", now)
                if approval.target_case_id != target:
                    raise _refuse("conflict", "the approval is for another target")
            else:
                _person(actor, Capability.MANAGE, "merging a case")
            after = replace(
                case, state="closed", closed_at=now, closure_reason="duplicate",
                closure_request_id=approval.request_id if case.confirmed and approval else None,
                merged_into_id=target, attention=None, notified_at=None, blocked_at=None,
                members=frozenset(), version=case.version + 1,
            )  # fmt: skip
            writes = tuple(kibana.close(after)) if case.mirrored else ()
            details = _extra(target=str(target), note=_text(note, "a note"))
            return Step("merged_into", case, after, details, writes, (),
                        tuple(sorted(case.members)))  # fmt: skip
        case MergedIn(source_id=source, members=members, indicators=indicators,
                      severity=severity):  # fmt: skip
            if not actor.may(Capability.APPROVE):  # an approver completing a merge may
                _person(actor, Capability.MANAGE, "merging a case")
            _state(case, ("suspected", *CONFIRMED), "merge into")
            if source == case.id:
                raise _refuse("invalid", "a case cannot be merged into itself")
            grown, added, marks = _grow(case, members, indicators)
            after = replace(
                grown, severity=max_severity(case.severity, severity), version=case.version + 1
            )
            writes = _mirror(case, after, "merged_in", source=str(source))
            return Step("merged_in", case, after, {"source": str(source)}, writes, added, (),
                        marks)  # fmt: skip
        case Reopen(reason=reason):
            _person(actor, Capability.REOPEN, "reopening a case")
            _state(case, ("closed",), "reopen")
            said = _text(reason, "a reason", required=True)
            if case.merged_into_id is not None:
                raise _refuse("conflict", "a merged case is reopened through the case it joined")
            after = replace(
                case, state="open" if case.confirmed else "suspected", owner_user_id=None,
                closed_at=None, closure_reason=None, closure_request_id=None,
                version=case.version + 1,
            )  # fmt: skip
            writes = _mirror(case, after, "reopened", by=actor.name)
            return Step("reopened", case, after, {"reason": said}, writes)
    raise _refuse("invalid", f"unknown command {type(command).__name__}")


def _extra(**values: Any) -> dict[str, Any]:
    return {key: value for key, value in values.items() if value is not None}


def _needs_notice(case: Case, reason: Reason) -> None:
    """ARGUS proposes "stopped after notice" only for a case whose owner was told (D-169); a
    person may ask for it for any case (they may have told the owner outside ARGUS)."""
    if reason == "stopped_after_notice" and case.notified_at is None:
        raise _refuse("conflict", "ARGUS proposes stopped after notice for a notified case only")


def _merge_target(case: Case, target: uuid.UUID, target_state: State) -> None:
    if target == case.id:
        raise _refuse("invalid", "a case cannot be merged into itself")
    if target_state == "closed":
        raise _refuse("conflict", "the target case is closed")
    if case.confirmed and target_state == "suspected":
        raise _refuse("conflict", "a confirmed case is merged into a confirmed one")


def _check_evidence(reason: Reason, note: str | None, window: QuietWindow | None) -> str | None:
    """Plan §7.1's closure table: the positive evidence each reason needs before it is asked."""
    if reason in ("remediated_verified", "attempt_no_impact") and (
        window is None or not window.verified
    ):
        why = window.reason if window is not None else "no verified quiet window"
        raise _refuse("unavailable", f"{reason} needs verified evidence: {why}")
    required = reason in ("remediated_unverified", "risk_accepted", "created_in_error")
    what = {
        "remediated_unverified": "the owner's attestation",
        "risk_accepted": "a written reason",
        "created_in_error": "a note",
    }.get(reason, "a note")
    return _text(note, what, required=required)


# --------------------------------------------------------------------------- replay

_SET_FIELDS = tuple(
    f.name for f in fields(Case) if f.name not in ("id", "version", "members", "indicators")
)
_UUIDS = frozenset({"parent_case_id", "merged_into_id"})
_TIMES = frozenset({"opened_at", "closed_at", "notified_at", "blocked_at"})


def _encode(name: str, value: Any) -> Any:
    if value is None:
        return None
    if name in _UUIDS:
        return str(value)
    if name in _TIMES:
        return value.isoformat()
    return value


def _decode(name: str, value: Any) -> Any:
    if value is None:
        return None
    if name in _UUIDS:
        return uuid.UUID(value)
    if name in _TIMES:
        return datetime.fromisoformat(value)
    return value


def event_details(step: Step) -> dict[str, Any]:
    """What the case event stores: the extra context plus every field the step changed (all of
    them when the case is created), the members and indicators it added or removed."""
    before = step.before
    changed = {
        name: _encode(name, getattr(step.after, name))
        for name in _SET_FIELDS
        if before is None or getattr(before, name) != getattr(step.after, name)
    }
    details: dict[str, Any] = {**step.details, "set": changed}
    if step.members_added or step.members_removed:
        details["members"] = {
            "added": [[str(m.investigation_id), m.link, m.link_value] for m in step.members_added],
            "removed": [str(i) for i in step.members_removed],
        }
    if step.indicators_added:
        details["indicators"] = [[i.kind, i.value, i.role] for i in step.indicators_added]
    if step.indicators_removed:
        details["indicators_removed"] = [[i.kind, i.value, i.role] for i in step.indicators_removed]
    return details


@dataclass(frozen=True)
class EventRecord:
    case_id: uuid.UUID
    case_version: int
    kind: str
    from_state: State | None
    to_state: State
    details: Mapping[str, Any]


class ReplayError(ValueError):
    pass


def replay(events: Sequence[EventRecord]) -> Case:
    """The case its events describe, checking that they form one unbroken history."""
    if not events:
        raise ReplayError("a case has at least one event")
    case: Case | None = None
    for event in sorted(events, key=lambda e: e.case_version):
        values = dict(event.details.get("set", {}))
        if case is None:
            if event.case_version != 1 or event.from_state is not None:
                raise ReplayError("the first event creates the case at version 1")
            unknown = set(values) - set(_SET_FIELDS)
            if unknown:
                raise ReplayError(f"unknown fields {sorted(unknown)}")
            case = Case(
                id=event.case_id,
                version=1,
                **{name: _decode(name, values.get(name)) for name in _SET_FIELDS if name in values},
            )
        else:
            if event.case_id != case.id or event.case_version != case.version + 1:
                raise ReplayError(f"version {event.case_version} does not follow {case.version}")
            if event.from_state != case.state:
                raise ReplayError(f"version {event.case_version} starts from {event.from_state}")
            changes = {name: _decode(name, value) for name, value in values.items()}
            if set(changes) - set(_SET_FIELDS):
                raise ReplayError(f"unknown fields {sorted(set(changes) - set(_SET_FIELDS))}")
            case = replace(case, version=event.case_version, **changes)
        moved = event.details.get("members") or {}
        added = {uuid.UUID(m[0]) for m in moved.get("added", [])}
        removed = {uuid.UUID(m) for m in moved.get("removed", [])}
        marks = {Indicator(k, v, r) for k, v, r in event.details.get("indicators", [])}
        gone = {Indicator(k, v, r) for k, v, r in event.details.get("indicators_removed", [])}
        case = replace(
            case,
            members=(case.members - removed) | added,
            indicators=(case.indicators - gone) | frozenset(marks),
        )
        if case.state != event.to_state:
            raise ReplayError(f"version {event.case_version} ends in {event.to_state}")
    assert case is not None
    return case


def same_case(rebuilt: Case, stored: Case) -> bool:
    """Whether a replayed case is the stored one. ``mirrored`` is left out: it is the outbox's
    fact (a Kibana create the writer skipped unsent leaves the case unmirrored, and no case
    event records that), not the case history's."""
    return replace(rebuilt, mirrored=stored.mirrored) == stored


EVENT_KINDS = (
    "suspected",
    "opened",
    "confirmed",
    "dismissed",
    "taken",
    "assigned",
    "released",
    "contained",
    "new_activity",
    "activity_after_closure",
    "linked",
    "unlinked",
    "notified",
    "notice_withdrawn",
    "blocked",
    "address_moved",
    "retitled",
    "published",
    "closure_requested",
    "merge_requested",
    "closed",
    "merged_into",
    "merged_in",
    "reopened",
)
