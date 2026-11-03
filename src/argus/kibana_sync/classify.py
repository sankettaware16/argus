"""The reconciliation: what ARGUS sees in Kibana and what it does. Pure: records in, the mirror's
new state and findings out.

ARGUS's own write must be explained by a sent outbox row or case-team step of its kind, else an
alarm and every write class pauses. A person's edit of content or their own tags is kept (ARGUS
stops managing that field); a change of ``argus:*`` tags or Sync alerts pauses ARGUS's writes to
the case; a comment is kept as untrusted text; a close or reopen is an item to confirm, never
reverted; a deletion is "Deleted in Kibana". A case of ARGUS's with no ARGUS case or sent create
is an alarm; two Kibana cases for one ARGUS case are flagged, never deleted; an alert change
ARGUS cannot explain is an alarm. People always win: nothing here plans a write to Kibana."""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime

from argus import site
from argus.gateway.health import HealthState
from argus.kibana_sync.model import (
    AlertLink,
    AlertState,
    Finding,
    KAction,
    KCase,
    Kind,
    Mirror,
    SentWrite,
    TeamPost,
    untrusted,
)

# The kinds of ARGUS's own user actions, and which sent writes explain them.
# create_case <- a sent create; a user comment <- a sent comment; an alert attachment <- a
# sent attach; a status, severity or tags change <- a sent update or close that changes
# that field. Kibana records a PATCH that adds and removes tags as up to two tags actions.
FIELD_OF_ACTION = {"status": "status", "severity": "severity", "tags": "argus_tags"}
PER_SEND = {"tags": 2}
CONTENT = frozenset(
    {
        "title",
        "description",
        "severity",
        "category",
        "customFields",
        "connector",
        "assignees",
        "observables",
        "pushed",
    }
)


# A case that the user actions do not explain (a status or tag the actions never show, or a
# change moments ago whose user action may not be searchable yet: Kibana writes the case and
# its user action separately) keeps its old version, so it is read again; one hour later the
# read gives up with a finding rather than read for ever.
GIVE_UP = timedelta(hours=1)
# A change dated further ahead of Kibana's clock than this is not "moments ago" (the clock
# alarm is 30 s): the case is not held for it.
AHEAD = timedelta(hours=1)
# Elasticsearch's daily index creation and ILM deletes (the SIEM's quiet hours): no discovery
# search and no closed listing then; the cheap change poll goes on.


def quiet_hours(at: datetime) -> bool:
    """The site's quiet hours (default 00:00 to 01:30 UTC)."""
    return site.in_quiet_hours(at)


def action_kind(action: KAction) -> str:
    """The kind of an action for counting ARGUS's own (``argus_actions``). ARGUS never deletes
    a comment: its deletion has no sent write that could explain it."""
    if action.type == "comment":
        if action.action == "delete":
            return "delete_comment"
        if action.comment_kind == "alert":
            return "attach"
        return "edit_comment" if action.action == "update" else "comment"
    if action.type == "create_case":
        return "create"
    return action.type


# The case team's edits in place: a retitle is Kibana's ``title`` action, a redescribe its
# ``description`` action, a comment edit a ``comment`` action with the verb ``update``.
TEAM_EDITS = {"title": "title", "description": "description", "edit_comment": "edit_comment"}


def count_key(kind: str, by: str, author: str) -> str:
    """What a kind of action is counted under: ``kind`` for the service user (``author``), else
    ``<user>:<kind>``, so an action is explained only by a write of its own user."""
    return kind if by == author else f"{by}:{kind}"


def capacity(sent: Iterable[SentWrite], author: str = "") -> dict[str, int]:
    """How many actions of each kind ARGUS's sent writes can explain (a case-team step, whose
    ``by`` is its user, explains only that user's)."""
    room: dict[str, int] = {}

    def add(kind: str, by: str, n: int) -> None:
        key = count_key(kind, by or author, author)
        room[key] = room.get(key, 0) + n

    for write in sent:
        n = max(write.sent_count, 0)
        if write.op in ("create", "comment", "attach"):
            add(write.op, write.by, n)
        elif write.op in TEAM_EDITS:
            add(TEAM_EDITS[write.op], write.by, n)
        elif write.op in ("update", "close"):
            for kind, name in FIELD_OF_ACTION.items():
                if name in write.fields:
                    add(kind, write.by, n * PER_SEND.get(kind, 1))
    return room


def _is_argus_tag(tag: object) -> bool:
    return isinstance(tag, str) and (tag == "argus" or tag.startswith("argus:"))


@dataclass(frozen=True)
class CaseOutcome:
    mirror: Mirror
    findings: tuple[Finding, ...]
    pause_all: bool  # an alarm: every write class pauses


def lag_seconds(action: KAction, kibana_now: datetime) -> int:
    return max(int((kibana_now - action.created_at).total_seconds()), 0)


def classify_case(
    mirror: Mirror,
    case: KCase,
    actions: Sequence[KAction],
    sent: Sequence[SentWrite],
    *,
    author: str,
    now: datetime,
    kibana_now: datetime,
    complete: bool,
    settle: timedelta = timedelta(0),
    team: frozenset[str] = frozenset(),
) -> CaseOutcome:
    """Classify the user actions read since ``mirror.actions_seen`` (in Kibana's order) and
    the case as it is now. ``author`` is the service user, ``team`` the case team's users: all
    of them are ARGUS, and any other username is a person. ``complete``: every action up to
    the case's version was read, so the mirror takes the case's version; otherwise it keeps
    its old version and the next cycle reads on from ``actions_seen``. It is not taken either
    while the actions and the case disagree, or while the case changed within ``settle`` (its
    user action may not be searchable yet)."""
    findings: list[Finding] = []
    pause_all = False
    unmanaged = set(mirror.unmanaged)
    paused = mirror.paused_reason
    counts = dict(mirror.argus_actions)
    stray = dict(mirror.unexplained)
    room = capacity(sent, author)
    argus = {author, *team}
    status = mirror.status
    cid, kid = mirror.case_id, mirror.kibana_case_id

    def add(found: Kind, key: str, by: KAction | None = None, **details: object) -> None:
        lag = None if by is None else lag_seconds(by, kibana_now)
        if by is not None:
            details = {"by": untrusted(by.by), "at": by.created_at.isoformat(), **details}
        findings.append(Finding(found, key, kid, cid, details, lag))

    for action in actions:
        key = f"{kid}:{action.id}"
        if action.by in argus:
            kind = count_key(action_kind(action), action.by, author)
            counts[kind] = counts.get(kind, 0) + 1
            if counts[kind] > room.get(kind, 0) + stray.get(kind, 0):
                stray[kind] = stray.get(kind, 0) + 1  # alarmed once: not again for a later one
                pause_all = True
                add(
                    Kind.UNEXPLAINED_ARGUS_ACTION,
                    f"unexplained:{key}",
                    action,
                    type=action.type,
                    verb=action.action,
                    counted=kind,
                )
            if action.type == "status":
                status = _status(action, status)
            continue
        # a person's action (or one Kibana does not attribute): people win
        if action.type == "comment":
            if action.action == "delete":  # the payload is the comment that was removed
                attachment = action.comment_kind == "alert"
                comment = action.payload.get("comment")
                if attachment:
                    unmanaged.add("alerts")
                    alerts = comment.get("alertId") if isinstance(comment, Mapping) else None
                    shown = alerts if isinstance(alerts, list) else []
                    gone: dict[str, object] = {"alerts": [untrusted(a) for a in shown][:20]}
                else:
                    text = comment.get("comment") if isinstance(comment, Mapping) else None
                    gone = {"comment": untrusted(text), "untrusted": True}
                add(
                    Kind.PERSON_DELETED,
                    f"removed:{key}",
                    action,
                    what="alert attachment" if attachment else "comment",
                    **gone,
                )
            elif action.comment_kind == "alert":
                unmanaged.add("alerts")
                add(Kind.PERSON_EDITED, f"edit:{key}", action, field="alerts")
            else:
                comment = action.payload.get("comment")
                text = comment.get("comment") if isinstance(comment, Mapping) else None
                add(
                    Kind.PERSON_COMMENTED,
                    f"comment:{key}",
                    action,
                    comment=untrusted(text),
                    untrusted=True,
                )
        elif action.type == "status":
            after = _status(action, status)
            if after == "closed" and status != "closed":
                add(Kind.CLOSED_IN_KIBANA, f"closed:{key}", action, before=status)
            elif status == "closed" and after != "closed":
                add(Kind.REOPENED_IN_KIBANA, f"reopened:{key}", action, after=after)
            else:
                add(
                    Kind.STATUS_CHANGED_IN_KIBANA,
                    f"status:{key}",
                    action,
                    before=status,
                    after=after,
                )
            status = after
        elif action.type == "tags":
            tags = action.payload.get("tags")
            tags = tags if isinstance(tags, list) else []
            if any(_is_argus_tag(t) for t in tags):
                paused = paused or "a person changed ARGUS's tags in Kibana"
                add(
                    Kind.ARGUS_TAGS_CHANGED,
                    f"tags:{key}",
                    action,
                    change=action.action,
                    tags=[untrusted(t) for t in tags if _is_argus_tag(t)][:20],
                )
            else:
                add(Kind.PERSON_EDITED, f"edit:{key}", action, field="tags")
        elif action.type == "settings":
            paused = paused or "a person changed the case's settings in Kibana"
            settings = action.payload.get("settings")
            sync = settings.get("syncAlerts") if isinstance(settings, Mapping) else None
            add(
                Kind.SETTINGS_CHANGED,
                f"settings:{key}",
                action,
                sync_alerts=sync if isinstance(sync, bool) else None,
            )
        elif action.type in CONTENT:
            unmanaged.add(action.type)
            add(Kind.PERSON_EDITED, f"edit:{key}", action, field=action.type)
        else:  # create_case or delete_case by a person on ARGUS's case, or a new kind
            unmanaged.add(action.type)
            add(Kind.PERSON_EDITED, f"edit:{key}", action, field=action.type)

    if case.created_by not in argus:
        pause_all = True
        paused = paused or "the case was not made by ARGUS"
        add(Kind.NOT_ARGUS_CASE, f"author:{kid}", created_by=untrusted(case.created_by))
    if case.sync_alerts and paused is None:
        paused = "Sync alerts is on for the case"
        add(Kind.SETTINGS_CHANGED, f"sync-on:{kid}:{case.version}", sync_alerts=True)

    problem = disagreement(mirror, case, actions, status)
    age = kibana_now - case.changed_at
    if complete and (problem is not None or -AHEAD <= age < settle):
        if -AHEAD <= age < GIVE_UP:
            complete = False
        elif problem is not None:
            if problem == "status":
                status = case.status
            add(
                Kind.ANSWER_UNEXPECTED,
                f"unexplained-state:{kid}:{case.version}",
                problem=f"the user actions never explained the case's {problem}",
            )

    updated = replace(
        mirror,
        kibana_version=case.version if complete else mirror.kibana_version,
        status=status,  # as the actions read so far left it (the listing may be older)
        title=case.title if complete else mirror.title,
        severity=case.severity if complete else mirror.severity,
        tags=case.tags if complete else mirror.tags,
        created_by=case.created_by,
        sync_alerts=case.sync_alerts if complete else mirror.sync_alerts,
        kibana_created_at=case.created_at,
        kibana_updated_at=case.updated_at if complete else mirror.kibana_updated_at,
        read_at=now,  # its actions were read, whatever version the mirror now holds
        unmanaged=frozenset(unmanaged),
        actions_seen=mirror.actions_seen + len(actions),
        argus_actions=counts,
        paused_reason=paused,
        unexplained=stray,
    )
    return CaseOutcome(updated, tuple(findings), pause_all)


def disagreement(
    mirror: Mirror, case: KCase, actions: Sequence[KAction], status: str
) -> str | None:
    """What of the case the user actions read so far do not explain, or None: no action at all
    (a case has at least its creation), or a status other than the one the actions left (the
    mirror carries it from read to read). Kibana writes the case first and its user action
    after, so a read between the two sees the new case with the old actions."""
    if mirror.actions_seen + len(actions) == 0:
        return "user actions"
    if status != case.status:
        return "status"
    return None


def _status(action: KAction, before: str) -> str:
    value = action.payload.get("status")
    return value if value in ("open", "in-progress", "closed") else before


def new_mirror(case_id: uuid.UUID, case: KCase, now: datetime) -> Mirror:
    """The mirror of a case ARGUS made, before any of its user actions are read."""
    return Mirror(
        case_id=case_id,
        kibana_case_id=case.id,
        kibana_version="",  # no version read yet: its actions are read from the start
        status="open",
        title=case.title,
        severity=case.severity,
        tags=(),
        created_by=case.created_by,
        sync_alerts=False,
        kibana_created_at=case.created_at,
        kibana_updated_at=None,
        read_at=now,
    )


@dataclass(frozen=True)
class Adoption:
    """What to do with a case of ``argus`` the mirror does not hold."""

    case_id: uuid.UUID | None  # adopt it as this ARGUS case's mirror
    findings: tuple[Finding, ...] = ()
    pause_all: bool = False


def adopt(
    case: KCase,
    *,
    known: Mapping[uuid.UUID, int],
    mirrored: Mapping[uuid.UUID, str],
) -> Adoption:
    """A case ``argus`` made that ARGUS has no mirror of: adopted only when its one
    ``argus:case:<uuid>`` tag names an ARGUS case with a sent create (``known``: the case's
    sent creates) that has no other live mirror. Never adopted on tags alone."""
    ids = case.argus_case_ids()
    if len(ids) != 1 or known.get(ids[0], 0) < 1:
        return Adoption(
            None,
            (
                Finding(
                    Kind.UNEXPLAINED_ARGUS_CASE,
                    f"unexplained-case:{case.id}",
                    case.id,
                    ids[0] if len(ids) == 1 and ids[0] in known else None,
                    {
                        "title": untrusted(case.title),
                        "tags": [untrusted(t) for t in case.tags][:20],
                    },
                ),
            ),
            pause_all=True,
        )
    other = mirrored.get(ids[0])
    if other is not None and other != case.id:
        return Adoption(
            None,
            (
                Finding(
                    Kind.DUPLICATE_CASE,
                    f"duplicate:{case.id}",
                    case.id,
                    ids[0],
                    {"mirror": other, "title": untrusted(case.title)},
                ),
            ),
        )
    return Adoption(ids[0])


def adopt_team(
    case: KCase, *, posts: Sequence[TeamPost], mirrored: Mapping[uuid.UUID, str]
) -> Adoption:
    """A case one of the case team's users made that ARGUS has no mirror of. The team's
    cases carry no ``argus:case:<uuid>`` tag: the post is found by the Kibana id the poster
    recorded or, before it recorded one (the create landed, the run ended), by the incident ID
    among the case's tags with an open step that was sent. A case that matches no post is an
    alarm (nothing explains it); a second Kibana case for a post that already has its case, or
    for a case already mirrored, is flagged, never adopted."""
    mine = [p for p in posts if p.kibana_case_id == case.id]
    if not mine:
        mine = [
            p
            for p in posts
            if p.kibana_case_id is None and p.opens >= 1 and p.incident_id in case.tags
        ]
    if len(mine) == 1:
        held = mirrored.get(mine[0].case_id)
        if held is None or held == case.id:
            return Adoption(mine[0].case_id)
        return _duplicate(case, mine[0].case_id, held)
    rival = [p for p in posts if p.kibana_case_id not in (None, case.id)]
    rival = [p for p in rival if p.incident_id in case.tags]
    if len(rival) == 1 and not mine:
        return _duplicate(case, rival[0].case_id, rival[0].kibana_case_id or "")
    return Adoption(
        None,
        (
            Finding(
                Kind.UNEXPLAINED_ARGUS_CASE,
                f"unexplained-case:{case.id}",
                case.id,
                None,
                {
                    "title": untrusted(case.title),
                    "tags": [untrusted(t) for t in case.tags][:20],
                    "by": untrusted(case.created_by),
                },
            ),
        ),
        pause_all=True,
    )


def _duplicate(case: KCase, case_id: uuid.UUID, other: str) -> Adoption:
    return Adoption(
        None,
        (
            Finding(
                Kind.DUPLICATE_CASE,
                f"duplicate:{case.id}",
                case.id,
                case_id,
                {"mirror": other, "title": untrusted(case.title)},
            ),
        ),
    )


def deletion_candidates(mirrors: Iterable[Mirror], listed: Iterable[str]) -> list[Mirror]:
    """Live mirrors whose case is not in a complete listing of ``argus``'s cases; each is
    confirmed by ``cases.get`` (a 404) before it counts as deleted: paging drift or Kibana's
    refresh lag can hide a case from one listing."""
    present = set(listed)
    return sorted(
        (m for m in mirrors if m.active and m.kibana_case_id not in present),
        key=lambda m: m.kibana_case_id,
    )


def deleted(mirror: Mirror, now: datetime) -> tuple[Mirror, Finding]:
    return replace(mirror, deleted_at=now), Finding(
        Kind.DELETED_IN_KIBANA,
        f"deleted:{mirror.kibana_case_id}",
        mirror.kibana_case_id,
        mirror.case_id,
        {"title": untrusted(mirror.title)},
    )


@dataclass(frozen=True)
class AlertOutcome:
    findings: tuple[Finding, ...]
    pause_all: bool
    states: tuple[AlertState, ...]  # what to keep for the next discovery


def classify_alerts(
    links: Iterable[AlertLink],
    *,
    previous: Mapping[str, AlertState],
    explained: frozenset[str],
    author: str,
    case_of: Mapping[str, tuple[str, uuid.UUID | None]],
    now: datetime,
    synced: Mapping[str, datetime] | None = None,
    slack: timedelta = timedelta(0),
) -> AlertOutcome:
    """Status changes of the alerts on ARGUS's cases, by **diffing each alert's status**
    against the one kept at the last discovery (Kibana's internal alert
    route records neither ``workflow_user`` nor ``workflow_status_updated_at``, so neither
    field can be relied on). A change with a person in ``workflow_user`` and a newer
    ``workflow_status_updated_at`` is a human signal, never a review; one ARGUS's write-back
    sent (``explained``) is quiet; any other is an alarm (possible use of the internal route):
    writers pause. An alert seen for the first time only sets its baseline.

    ``synced``: the ARGUS cases (Kibana ids) with Sync alerts on, with when they last changed:
    Kibana's own sync moves their alerts when a person closes, reopens or fills the case (and
    records no person on the alert), so a change on an alert of such a case, made after the
    alert was last seen (less ``slack``), is a person's and is quiet (it is no unexplained
    change)."""
    findings: list[Finding] = []
    states: list[AlertState] = []
    pause = False
    for link in links:
        seen = AlertState(link.alert_id, link.status, link.user, link.status_updated_at, now)
        states.append(seen)
        before = previous.get(link.alert_id)
        if before is None or before.status == link.status:
            continue
        kid, cid = next(
            (case_of[c] for c in link.case_ids if c in case_of), (None, None)
        )  # the first of ARGUS's cases it is on
        details = {"alert": link.alert_id, "before": before.status, "status": link.status}
        key = f"{link.alert_id}:{before.status}->{link.status}:{now.isoformat()}"
        moved = link.status_updated_at is not None and (
            before.status_updated_at is None or link.status_updated_at > before.status_updated_at
        )
        if link.user and link.user != author and moved:
            assert link.status_updated_at is not None
            findings.append(
                Finding(
                    Kind.ALERT_STATUS_BY_PERSON,
                    f"alert-person:{key}",
                    kid,
                    cid,
                    {
                        **details,
                        "by": untrusted(link.user),
                        "at": link.status_updated_at.isoformat(),
                    },
                )
            )
        elif link.alert_id not in explained and not _synced_change(link, before, synced, slack):
            pause = True
            findings.append(
                Finding(
                    Kind.ALERT_CHANGE_UNEXPLAINED, f"alert-unexplained:{key}", kid, cid, details
                )
            )
    return AlertOutcome(tuple(findings), pause, tuple(states))


def _synced_change(
    link: AlertLink, before: AlertState, synced: Mapping[str, datetime] | None, slack: timedelta
) -> bool:
    if not synced:
        return False
    return any(case in synced and synced[case] >= before.seen_at - slack for case in link.case_ids)


@dataclass(frozen=True)
class Intervals:
    normal: timedelta = timedelta(minutes=10)
    caution: timedelta = timedelta(minutes=20)
    degraded: timedelta = timedelta(hours=1)


def interval(state: HealthState, intervals: Intervals) -> timedelta | None:
    """How long until the next poll in the SIEM's health ``state``; None in STOP (no poll)."""
    if state is HealthState.NORMAL:
        return intervals.normal
    if state is HealthState.CAUTION:
        return intervals.caution
    if state is HealthState.DEGRADED:
        return intervals.degraded
    return None


def clock_offset_ms(date_header: str | None, sent: datetime, received: datetime) -> int | None:
    """Kibana's clock minus ARGUS's, from Kibana's Date header (whole seconds) against the
    middle of the exchange; None without a usable header."""
    if not date_header:
        return None
    try:
        theirs = parsedate_to_datetime(date_header)
    except (TypeError, ValueError, IndexError):
        return None
    if theirs.tzinfo is None:
        return None
    middle = sent + (received - sent) / 2
    return int((theirs - middle).total_seconds() * 1000)


def clock_alarm(offset_ms: int | None, limit: timedelta) -> bool:
    """Above the limit (30 s), either way. The header has whole seconds, so up to a second
    of the offset is the header's rounding."""
    return offset_ms is not None and abs(offset_ms) > limit.total_seconds() * 1000


def staleness_bound(poll: timedelta, overlap: timedelta) -> timedelta:
    """How old a live mirror's read may be at the end of a complete cycle: two polls and the
    overlap (one poll missed by a partial cycle is not yet stale)."""
    return 2 * poll + overlap


@dataclass(frozen=True)
class Staleness:
    oldest_s: int | None
    stale: bool
    stale_cases: tuple[str, ...] = field(default_factory=tuple)


def staleness(mirrors: Iterable[Mirror], now: datetime, bound: timedelta) -> Staleness:
    live = [m for m in mirrors if m.active]
    if not live:
        return Staleness(None, False)
    ages = {m.kibana_case_id: now - m.read_at for m in live}
    oldest = max(ages.values())
    old = tuple(sorted(k for k, age in ages.items() if age > bound))
    return Staleness(max(int(oldest.total_seconds()), 0), bool(old), old[:20])
