"""What the case pages show (plan §5 Q-B3, §7.1): the reads behind ``/api/v1/cases``,
``/api/v1/approvals`` and the notes, and the words ARGUS uses for them.

Reading only (the commands go through :class:`argus.cases.service.CaseService`). Two rules hold
everywhere here:

* **An action is shown as available exactly when the command would be allowed**: the case
  machine itself is asked (``machine.decide`` on the case with the person's own capabilities), so
  a button's "why not" is the refusal the command would give, in plain words, and the two cannot
  drift. The command still checks again when it is given.
* **Words of ARGUS and words of people stay apart.** A sentence made here may carry a person's
  name or a value from an alert, so the app shows every string through its untrusted-text view;
  what a person typed (a note, a reason, an attestation, a Kibana comment) is returned in its own
  field and never mixed into a sentence that could pass for ARGUS's own.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from collections.abc import Iterable, Mapping, Sequence
from datetime import date, datetime, timedelta
from typing import Any, Literal, cast

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.assets.classify import IpClassifier
from argus.cases import approvals, blocklist, knownview, watch
from argus.cases.approvals import GROUP_LIMIT, GROUP_REASONS, NOT_REVOKED
from argus.cases.machine import (
    RAISED_REASON,
    Assign,
    CaseRefused,
    Contain,
    MergeInto,
    Notify,
    RecordBlock,
    Release,
    Reopen,
    RequestClosure,
    RequestMerge,
    Take,
    WithdrawNotice,
    decide,
)
from argus.cases.membership import load_shared
from argus.cases.model import (
    NO_QUIET_WINDOW,
    REQUEST_REASONS,
    TWO_PERSON_REASONS,
    Actor,
    Case,
    QuietWindow,
)
from argus.cases.service import CaseService
from argus.responder.machine import ist_day
from argus.site import Words, say
from argus.web import auth, queries, signinpages
from argus.web.capabilities import LABELS, Capability
from argus.web.v1 import case_models as m

ROW_PAGE = 100
DETAIL_MEMBERS = 200
DETAIL_TIMELINE = 80
DETAIL_HISTORY = 200
DETAIL_NOTES = 200
DETAIL_INDICATORS = 300
DETAIL_FINDINGS = 30
DETAIL_WRITES = 20
DETAIL_APPROVALS = 10
DETAIL_CHILDREN = 20
DETAIL_SUGGESTIONS = 50
NEW_FOR_FIRST_VISIT = timedelta(days=2)
RECENT_DECISIONS = timedelta(days=3)
RECENT_LIMIT = 30
PENDING_LIMIT = 300

STATE_WORDS = {
    "suspected": "Suspected",
    "open": "Open",
    "assigned": "Assigned",
    "contained": "Contained",
    "closed": "Closed",
}
OUTCOME_WORDS = {
    "benign_expected": "benign: expected activity",
    "benign_policy": "benign: allowed by policy",
    "rule_false_positive": "a rule false positive",
    "true_positive": "a true positive",
    "inconclusive": "inconclusive",
}
REASON_WORDS: dict[str, tuple[str, str]] = {
    "remediated_verified": (
        "Fixed, and shown quiet",
        "It was a real problem, it has been fixed, and ARGUS verified 72 quiet hours afterwards.",
    ),
    "remediated_unverified": (
        "Fixed, as its owner says",
        "It was a real problem and its owner says it is fixed; ARGUS cannot verify that.",
    ),
    "risk_accepted": (
        "Left as it is, by decision",
        "It is real and nobody will fix it; the risk is accepted, in writing.",
    ),
    "attempt_no_impact": (
        "An attempt that did not work",
        "Someone tried (a scanner probing for a file, say) and ARGUS verified it did not succeed.",
    ),
    "rule_false_positive": (
        "The rule was wrong",
        "The detection rule fired on something that was not an attack.",
    ),
    "benign_expected": (
        "Benign: expected activity",
        "It happened, and it is activity {the} expects.",
    ),
    "benign_policy": (
        "Benign: allowed by policy",
        "It happened, and {the} policy allows it.",
    ),
    "duplicate": ("A duplicate", "Another case already covers it (this comes from a merge)."),
    "created_in_error": (
        "Opened by mistake",
        "The case should never have been opened, or it was only a test.",
    ),
    "stopped_after_notice": (
        "Stopped after the owner was told",
        "The device's owner was told and nothing matching has been seen for 14 days; it may not"
        " be fixed, but it is quiet.",
    ),
}
# A reason that cannot be asked for without words from the person (machine._check_evidence)
NOTE_NEEDED = {
    "remediated_unverified": "What the owner said, and who they are",
    "risk_accepted": "Who accepted the risk, and why",
    "created_in_error": "Why it was a mistake",
}
KIND_WORDS = {
    "closure": "Close",
    "merge": "Merge",
    "compensating": "Undo a Kibana change of",
    "resend": "Send again to Kibana for",
    "reconfirm": "Confirm again a held-back closure of",
}
FINDING_WORDS = {
    "person_edited": "A person edited the case in Kibana",
    "person_deleted": "A person removed something from the case in Kibana",
    "argus_tags_changed": "A person changed ARGUS's tags in Kibana",
    "settings_changed": "A person changed the case's settings in Kibana",
    "person_commented": "A person commented in Kibana",
    "closed_in_kibana": "A person closed the case in Kibana",
    "reopened_in_kibana": "A person reopened the case in Kibana",
    "status_changed_in_kibana": "A person changed the case's status in Kibana",
    "deleted_in_kibana": "The case was deleted in Kibana",
    "people_case": "A case a person made in Kibana holds this case's alerts",
    "unexplained_argus_action": "An action by ARGUS in Kibana that ARGUS did not plan",
    "unexplained_argus_case": "A case by ARGUS in Kibana that ARGUS did not plan",
    "duplicate_case": "A second Kibana case for this case",
    "not_argus_case": "A Kibana case ARGUS did not make carries this case's tag",
    "alert_change_unexplained": "An alert changed in Kibana and ARGUS cannot explain it",
    "alert_status_by_person": "A person changed an alert's status in Kibana",
    "clock_offset": "Kibana's clock and ARGUS's differ",
    "actions_rewound": "Kibana's record of actions went backwards",
    "answer_unexpected": "Kibana answered in a way ARGUS did not expect",
}
# the fields of a finding's details shown to a reader (each a person's or Kibana's words)
FINDING_FIELDS = ("by", "at", "comment", "what", "before", "after", "field", "type", "verb")
SHOWN_FIELD = 500


# --------------------------------------------------------------------------- small helpers


def _cap(value: str | None, limit: int = SHOWN_FIELD) -> str:
    return (value or "")[:limit]


def sentence(message: str) -> str:
    """A refusal as a sentence: capital first, a full stop at the end."""
    said = message.strip()
    if not said:
        return said
    said = said[0].upper() + said[1:]
    return said if said.endswith((".", "?", "!")) else said + "."


def person(row: Any, prefix: str = "") -> m.PersonRef | None:
    """A user from joined columns ``<prefix>id``, ``<prefix>username``, ``<prefix>display_name``."""
    ident = getattr(row, f"{prefix}id", None)
    if ident is None:
        return None
    return m.PersonRef(
        id=int(ident),
        username=getattr(row, f"{prefix}username"),
        display_name=getattr(row, f"{prefix}display_name") or getattr(row, f"{prefix}username"),
    )


def preview_actor(me: auth.Reviewer) -> Actor:
    """Who a preview is made for: a person who may manage cases. What asking would bind does not
    depend on who asks (the builder never reads the actor), so anyone who may view can read it;
    asking is another route, which checks the person's own capability."""
    return Actor.person(me.user_id, frozenset({"view", "review", "manage_cases"}), via="web")


def actor_of(me: auth.Reviewer) -> Actor:
    """The signed-in person as the case machine knows them: their own capabilities, no Kibana
    privileges (a command given from a page never opens a case in Kibana)."""
    names = frozenset(c.value for c in me.capabilities)
    return Actor.person(me.user_id, names, via="web")


async def names(conn: AsyncConnection, ids: Iterable[int]) -> dict[int, str]:
    wanted = sorted({i for i in ids if i is not None})
    if not wanted:
        return {}
    rows = await conn.execute(
        text("SELECT id, display_name, username FROM users WHERE id = ANY(:ids)"), {"ids": wanted}
    )
    return {int(r.id): (r.display_name or r.username) for r in rows}


def who(actor: str, by_id: Mapping[int, str]) -> str:
    """An audit actor (``user:<id>`` or ``argus:<part>``) in words."""
    kind, _, rest = actor.partition(":")
    if kind == "user" and rest.isdigit():
        return by_id.get(int(rest), f"person {rest}")
    if kind == "argus":
        return f"ARGUS ({rest})" if rest else "ARGUS"
    return actor


# --------------------------------------------------------------------------- the rows

_PENDING_TEMPLATE = (
    "(r.expires_at > now() AND (r.kind NOT IN ('closure', 'merge') OR r.case_version = c.version)"
    " AND NOT EXISTS (SELECT 1 FROM approval_decisions d WHERE d.request_id = r.id"
    " AND d.decision = 'rejected')"
    " AND (SELECT count(*) FROM approval_decisions d WHERE d.request_id = r.id"
    " AND d.decision = 'approved' AND {not_revoked}) < r.required_approvals"
    " AND NOT (r.kind IN ('closure', 'merge') AND c.state = 'closed'))"
)
_PENDING = _PENDING_TEMPLATE.replace("{not_revoked}", NOT_REVOKED)
# ARGUS's reason on a suggested case (cause raised) stays on the case when a person confirms it,
# but it asks for no one any more: the case needs attention while it is suspected.
# a notified case with a change since the notice that no person has reviewed (D-181)
CHANGED_SINCE_NOTICE = (
    "EXISTS (SELECT 1 FROM case_known_matches k WHERE k.case_id = c.id"
    " AND k.outcome = 'changed' AND c.state IN ('open', 'assigned') AND NOT EXISTS"
    " (SELECT 1 FROM review_state s WHERE s.investigation_id = k.investigation_id"
    " AND s.action = 'reviewed' AND s.version >= k.changed_version))"
)
_ATTENTION = (
    "((c.attention IS NOT NULL"  # noqa: S608 - a constant fragment
    " AND NOT (c.cause = 'raised' AND c.state <> 'suspected'"
    f" AND c.attention LIKE '{RAISED_REASON}%'))"
    f" OR {CHANGED_SINCE_NOTICE}"
    " OR EXISTS (SELECT 1 FROM kibana_findings f WHERE f.case_id = c.id AND f.resolved_at IS NULL"
    " AND f.severity IN ('attention', 'alarm'))"
    " OR EXISTS (SELECT 1 FROM kibana_outbox o WHERE o.case_id = c.id AND o.state = 'paused'"
    " AND o.state_reason LIKE 'refused: %'))"
)
_ROW = f"""
SELECT c.id, c.number, c.title, c.state, c.severity, c.version, c.cause, c.opened_at, c.closed_at,
       c.closure_reason, c.attention, c.kibana_wait, c.updated_at, c.merged_into_id,
       c.parent_case_id, c.owner_user_id, c.notified_at, c.blocked_at,
       ow.id AS owner_id, ow.username AS owner_username, ow.display_name AS owner_display_name,
       mem.n AS investigations, mem.alerts, mem.first_at, mem.last_at,
       EXISTS (SELECT 1 FROM kibana_outbox x WHERE x.case_id = c.id AND x.op = 'create'
               AND NOT (x.state = 'skipped' AND x.sent_count = 0)) AS in_kibana,
       (SELECT count(*) FROM approval_requests r WHERE r.case_id = c.id AND {_PENDING})
           AS waiting, {_ATTENTION} AS needs_attention,
       mc.number AS merged_number, mc.title AS merged_title, mc.state AS merged_state
FROM cases c
LEFT JOIN users ow ON ow.id = c.owner_user_id
LEFT JOIN cases mc ON mc.id = c.merged_into_id
LEFT JOIN LATERAL (
    SELECT count(*) AS n, coalesce(sum(i.alert_count), 0) AS alerts,
           min(i.first_event_at) AS first_at, max(i.last_event_at) AS last_at
    FROM case_members mm JOIN investigations i ON i.id = mm.investigation_id
    WHERE mm.case_id = c.id AND mm.removed_at IS NULL) mem ON true
"""  # noqa: S608 - constant fragments; values are bound


def _row(r: Any) -> m.CaseRowOut:
    merged = (
        None
        if r.merged_into_id is None
        else m.CaseRef(id=r.merged_into_id, number=int(r.merged_number), title=r.merged_title,
                       state=r.merged_state)
    )  # fmt: skip
    return m.CaseRowOut(
        id=r.id, number=int(r.number), title=r.title, state=r.state, severity=r.severity,
        version=int(r.version), cause=r.cause, owner=person(r, "owner_"),
        opened_at=r.opened_at, closed_at=r.closed_at, closure_reason=r.closure_reason,
        attention=r.attention, kibana_wait=r.kibana_wait, investigations=int(r.investigations),
        alerts=int(r.alerts), first_alert_at=r.first_at, last_alert_at=r.last_at,
        updated_at=r.updated_at, in_kibana=bool(r.in_kibana), waiting_for_approval=int(r.waiting),
        needs_attention=bool(r.needs_attention), merged_into=merged,
        notified_at=r.notified_at, blocked_at=r.blocked_at,
    )  # fmt: skip


# --- the queue's cases (AR4, D-182; the review, D-186): one definition for Home and for the list
# behind its link, so the two always hold the same cases.
# a confirmed case nobody owns (a notified one is tracked quietly: it is not asking for an owner)
UNOWNED = "(c.state = 'open' AND c.owner_user_id IS NULL AND c.notified_at IS NULL)"
# a case that holds an investigation in Needs attention (a follow-up, one changed since a review,
# one the rule rates high or ARGUS raised, a change since a notice): whoever owns the case, a
# person still has to look at it. ``ATTENTION`` leaves out what a notified case's known infection
# holds, so a quiet notified case is not here.
NEW_MEMBER = (
    "EXISTS (SELECT 1 FROM case_members mm JOIN investigations i ON i.id = mm.investigation_id"  # noqa: S608
    f" {queries._STATE} WHERE mm.case_id = c.id AND mm.removed_at IS NULL AND {queries.ATTENTION})"
)
WORK = (
    "(c.state <> 'closed' AND (c.state = 'suspected'"  # noqa: S608 - constant fragments
    f" OR {CHANGED_SINCE_NOTICE} OR {_ATTENTION}"
    f" OR EXISTS (SELECT 1 FROM approval_requests r WHERE r.case_id = c.id AND {_PENDING})"
    f" OR {UNOWNED} OR {NEW_MEMBER}))"
)

# a notified case (AR4b, D-169) is tracked quietly: it leaves "active" for its own view
_VIEWS = {
    "active": "c.state IN ('open', 'assigned', 'contained') AND c.notified_at IS NULL",
    "notified": "c.state IN ('open', 'assigned') AND c.notified_at IS NOT NULL",
    "attention": f"c.state <> 'closed' AND ({_ATTENTION} OR EXISTS (SELECT 1 FROM"  # noqa: S608
    f" approval_requests r WHERE r.case_id = c.id AND {_PENDING}))",
    "mine": "c.owner_user_id = :me AND c.state <> 'closed'",
    "suspected": "c.state = 'suspected'",
    "closed": "c.state = 'closed'",
    "queue": WORK,  # the cases of Home's queue, whatever the reason
    "all": "true",
}
_ORDER = (
    "ORDER BY (c.state = 'closed'), (c.state = 'suspected'), "
    "CASE c.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,"
    " c.updated_at DESC, c.number DESC"
)


async def counts(conn: AsyncConnection, me_id: int) -> m.CaseCounts:
    row = (
        await conn.execute(
            text(
                "SELECT"  # noqa: S608 - constant fragments; values are bound
                f" count(*) FILTER (WHERE {_VIEWS['active']}) AS active,"
                f" count(*) FILTER (WHERE {_VIEWS['notified']}) AS notified,"
                f" count(*) FILTER (WHERE {_VIEWS['attention']}) AS attention,"
                f" count(*) FILTER (WHERE {_VIEWS['mine']}) AS mine,"
                f" count(*) FILTER (WHERE {_VIEWS['suspected']}) AS suspected,"
                f" count(*) FILTER (WHERE {_VIEWS['closed']}) AS closed,"
                f" count(*) FILTER (WHERE {_VIEWS['queue']}) AS queue, count(*) AS all"
                " FROM cases c"
            ),
            {"me": me_id},
        )
    ).one()
    return m.CaseCounts(**{k: int(v) for k, v in row._mapping.items()})


async def list_cases(
    conn: AsyncConnection,
    me_id: int,
    view: m.CaseView,
    *,
    offset: int,
    limit: int,
    number: int | None = None,
    query: str | None = None,
) -> m.CasePage:
    where = _VIEWS[view]
    params: dict[str, Any] = {"me": me_id, "off": offset, "lim": limit + 1}
    if number is not None:
        where += " AND c.number = :number"
        params["number"] = number
    if query:
        where += " AND c.title ILIKE :q ESCAPE '\\'"
        params["q"] = (
            "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        )
    rows = (
        await conn.execute(text(f"{_ROW} WHERE {where} {_ORDER} OFFSET :off LIMIT :lim"), params)
    ).all()
    return m.CasePage(
        items=[_row(r) for r in rows[:limit]], view=view, offset=offset, limit=limit,
        has_more=len(rows) > limit, counts=await counts(conn, me_id),
    )  # fmt: skip


async def row_of(conn: AsyncConnection, case_id: uuid.UUID) -> m.CaseRowOut | None:
    found = (await conn.execute(text(f"{_ROW} WHERE c.id = :id"), {"id": case_id})).first()
    return None if found is None else _row(found)


# --------------------------------------------------------------------------- actions


_STATE_REFUSAL = re.compile(r"cannot [a-z ]+? a (suspected|open|assigned|contained|closed) case")
_ONLY = {
    "take": "an open or assigned case can be taken",
    "assign": "an open or assigned case can be given to someone",
    "release": "an assigned case can be released",
    "contain": "an open or assigned case can be confirmed contained",
    "reopen": "a closed case can be reopened",
    "notify": "an open or assigned case can have a notice recorded",
    "withdraw_notice": "an open or assigned case can have a notice withdrawn",
    "withdrawnotice": "an open or assigned case can have a notice withdrawn",
    "block": "a confirmed case that is not closed can have a block recorded",
    "recordblock": "a confirmed case that is not closed can have a block recorded",
    "request_closure": "an open, assigned or contained case can be closed",
    "merge": "a case that is not closed can be merged",
}


_UNVERIFIED = re.compile(r"(\w+) needs verified evidence: (.*)", re.S)
_NOT_CONTAINED = re.compile(r"not contained: (.*)", re.S)
_COMPONENT = re.compile(r"\s*\(Q-[A-Z]\d\)")
# the quiet window's reasons that name a build component or a stored word, in a person's words
_WINDOW_WORDS = {
    NO_QUIET_WINDOW.reason: "the still-active watch is not running here, so nothing can be shown"
    " quiet",
    watch.NOT_ON: "ARGUS's checks of the proxy logs that vouch for a quiet period are not switched"
    " on yet",
}


def window_words(reason: str) -> str:
    """A quiet window's reason in the words a person reads: no build component's code."""
    return _COMPONENT.sub("", _WINDOW_WORDS.get(reason, reason)).strip()


def why_not(exc: CaseRefused, action: str | None = None) -> str:
    """A refusal of the case machine in plain words: a move the case's state does not allow says
    which states do; a reason that needs a quiet window says what is missing; any other refusal
    is the machine's own sentence. No stored word (``remediated_verified``) and no build
    component's code reaches a person (Q-B3 review R3-9)."""
    found = _STATE_REFUSAL.fullmatch(exc.message)
    if found is not None and action in _ONLY:
        return f"Only {_ONLY[action]}; this one is {found.group(1)}."
    found = _UNVERIFIED.fullmatch(exc.message)
    if found is not None:
        label = REASON_WORDS.get(found.group(1), (found.group(1).replace("_", " "), ""))[0]
        return (
            f"“{label}” needs ARGUS to have shown the case quiet for 72 hours, and it has not:"
            f" {window_words(found.group(2))}."
        )
    found = _NOT_CONTAINED.fullmatch(exc.message)
    if found is not None:
        return (
            "ARGUS has not shown the case quiet for 72 hours, so it cannot be confirmed"
            f" contained yet: {window_words(found.group(1))}."
        )
    return sentence(_COMPONENT.sub("", exc.message))


def needs(capability: Capability, what: str) -> str:
    """Why an account may not: the capability it lacks, in the words of ``/access``."""
    return (
        f"Your account may not {what}: it needs the “{capability.value}” capability"
        f" ({LABELS[capability]}). Ask an ARGUS admin."
    )


_ACTION_CAPABILITY: dict[str, tuple[Capability, str]] = {
    "take": (Capability.MANAGE_CASES, "take cases"),
    "assign": (Capability.MANAGE_CASES, "assign cases"),
    "release": (Capability.MANAGE_CASES, "release cases"),
    "contain": (Capability.MANAGE_CASES, "confirm containment"),
    "request_closure": (Capability.MANAGE_CASES, "ask to close cases"),
    "merge": (Capability.MANAGE_CASES, "merge cases"),
    "reopen": (Capability.REOPEN, "reopen cases"),
}
LABEL = {
    "take": "Take",
    "assign": "Assign",
    "release": "Release",
    "contain": "Confirm contained",
    "request_closure": "Request closure",
    "merge": "Merge into another case",
    "reopen": "Reopen",
}
SUSPECTED_CLOSURE = (
    "A suspected case is confirmed by a person's true-positive verdict on one of its"
    " investigations, or merged into another case; it is not closed with an approval."
)
_NO_TARGET = uuid.UUID(int=1)  # a stand-in target: only the case's own side is asked here


def closure_choices(
    case: Case,
    me: auth.Reviewer,
    window: QuietWindow,
    now: datetime,
) -> list[m.ClosureChoiceOut]:
    """Each reason a person may ask to close for, and whether this person may now (the machine's
    own answer, with a note where one is needed)."""
    actor = actor_of(me)
    out = []
    for reason in sorted(REQUEST_REASONS, key=lambda r: list(REASON_WORDS).index(r)):
        label, meaning = REASON_WORDS[reason]
        meaning = say(meaning)
        needs_note = reason in NOTE_NEEDED
        why: str | None = None
        if not me.can(Capability.MANAGE_CASES):
            why = needs(Capability.MANAGE_CASES, "ask to close cases")
        elif case.state == "suspected":
            why = SUSPECTED_CLOSURE
        else:
            try:
                decide(
                    case, RequestClosure(reason, "x" if needs_note else None, window), actor, now
                )
            except CaseRefused as exc:
                why = why_not(exc, "request_closure")
        out.append(
            m.ClosureChoiceOut(
                reason=reason, label=label, meaning=meaning,
                enabled=why is None, why_not=why,
                note="required" if needs_note else "optional",
                approvers=2 if reason in TWO_PERSON_REASONS else 1,
                note_hint=NOTE_NEEDED.get(reason),
            )
        )  # fmt: skip
    return out


def case_actions(
    case: Case,
    me: auth.Reviewer,
    window: QuietWindow,
    choices: Sequence[m.ClosureChoiceOut],
    others: int,
    now: datetime,
) -> list[m.CaseActionStateOut]:
    """The seven actions and why each is or is not available to this person on this case."""
    actor = actor_of(me)
    out = []
    for action in ("take", "assign", "release", "contain", "request_closure", "merge", "reopen"):
        capability, what = _ACTION_CAPABILITY[action]
        why: str | None = None
        if not me.can(capability):
            why = needs(capability, what)
        elif action == "request_closure":
            if not any(c.enabled for c in choices):
                why = next((c.why_not for c in choices if c.why_not), None)
        elif action == "merge" and case.state == "closed":
            why = "A closed case is not merged into another."
        elif action == "merge" and others == 0:
            why = "There is no other case that is not closed to merge into."
        else:
            try:
                if action == "take":
                    decide(case, Take(), actor, now)
                elif action == "assign":
                    other = 1 if case.owner_user_id != 1 else 2  # anyone but the owner
                    decide(case, Assign(user_id=other, assignable=True), actor, now)
                elif action == "release":
                    decide(case, Release(), actor, now)
                elif action == "contain":
                    decide(case, Contain("x", window), actor, now)
                elif action == "merge" and case.confirmed:
                    decide(case, RequestMerge(_NO_TARGET, "open", None), actor, now)
                elif action == "merge":
                    decide(case, MergeInto(_NO_TARGET, "suspected", None), actor, now)
                else:
                    decide(case, Reopen("x"), actor, now)
            except CaseRefused as exc:
                why = why_not(exc, action)
        out.append(
            m.CaseActionStateOut(
                action=action, label=LABEL[action], enabled=why is None,
                why_not=why,
            )
        )  # fmt: skip
    return out


# --------------------------------------------------------------------------- the sentences


def _other_case(kind: str, details: Mapping[str, Any]) -> str | None:
    """The other case a split names: where an ``unlinked`` event's investigations went, and where
    an ``opened`` or ``linked`` event's came from."""
    value = details.get("target" if kind == "unlinked" else "split_from")
    return value if kind in ("unlinked", "opened", "linked") and isinstance(value, str) else None


async def case_numbers(conn: AsyncConnection, events: Sequence[Any]) -> dict[str, int]:
    """The numbers of the cases the events name as the other half of a split (one query)."""
    named: list[uuid.UUID] = []
    for e in events:
        other = _other_case(e.kind, e.details) if isinstance(e.details, dict) else None
        try:
            named += [] if other is None else [uuid.UUID(other)]
        except ValueError:
            continue
    if not named:
        return {}
    rows = await conn.execute(
        text("SELECT id, number FROM cases WHERE id = ANY(:ids)"), {"ids": named}
    )
    return {str(r.id): int(r.number) for r in rows}


def event_words(
    kind: str,
    details: Mapping[str, Any],
    by: str,
    names_by_id: Mapping[int, str],
    numbers: Mapping[str, int] | None = None,
) -> tuple[str, str | None]:
    """A case event as a sentence, and the words a person typed with it (untrusted).
    ``numbers``: the cases a split names, by id (:func:`case_numbers`)."""

    def other() -> str:
        found = _other_case(kind, details)
        number = (numbers or {}).get(found) if found is not None else None
        return f"case {number}" if number is not None else "another case"

    def reason(key: str = "reason") -> str:
        value = details.get(key)
        if isinstance(value, str) and value in REASON_WORDS:
            return REASON_WORDS[value][0].lower()
        return "a reason this page does not know"

    typed = details.get("note") or details.get("attestation") or details.get("reason")
    detail = typed if isinstance(typed, str) and typed not in REASON_WORDS else None
    if kind == "suspected":
        return "ARGUS suspected this case from its own proposal", None
    if kind == "opened":
        if details.get("split_from"):
            return f"{by} opened the case with investigations moved from {other()}", detail
        return f"{by} opened the case", detail
    if kind == "confirmed":
        verdict = details.get("verdict_by")
        if isinstance(verdict, str):
            return (
                f"A true-positive verdict by {who(verdict, names_by_id)} confirmed the case",
                detail,
            )
        return f"{by} confirmed the case", detail
    if kind == "dismissed":
        return f"{by} dismissed the suspected case as {reason()}", detail
    if kind == "taken":
        return f"{by} took the case", None
    if kind == "assigned":
        to = details.get("to")
        target = names_by_id.get(int(to)) if isinstance(to, int) else None
        return f"{by} assigned the case to {target or 'someone'}", None
    if kind == "released":
        return f"{by} released the case", None
    if kind == "contained":
        return f"{by} confirmed the case is contained", detail
    if kind == "new_activity":
        summary = details.get("summary")
        return "New activity after containment: the case is open again", (
            summary if isinstance(summary, str) else None
        )
    if kind == "activity_after_closure":
        return "New activity after the case was closed; a new case was made for it", None
    if kind == "linked":
        if details.get("split_from"):
            return f"{by} moved investigations here from {other()}", None
        return f"{by} linked more of its investigations or indicators", None
    if kind == "unlinked":
        return f"{by} moved investigations to {other()}", detail
    if kind == "notified":
        again = " again" if details.get("again") else ""
        told = details.get("told")
        how = NOTICE_HOW_WORDS.get(str(details.get("how")), "")
        said = f"Told: {told}" + (f" ({how})" if how else "") if isinstance(told, str) else None
        return f"{by} recorded that the owner was told{again}", _joined(said, detail)
    if kind == "notice_withdrawn":
        return f"{by} withdrew the owner notice (it was recorded by mistake)", detail
    if kind == "blocked":
        who_ = details.get("by")
        where = details.get("where")
        said = f"Blocked by {who_} at {where}" if isinstance(who_, str) else None
        return f"{by} recorded a block at the network", _joined(said, detail)
    if kind == "address_moved":
        summary = details.get("summary")
        return "ARGUS noted that the device came back from a new address", (
            summary if isinstance(summary, str) else None
        )
    if kind == "retitled":
        old = details.get("old")
        was = f"Was: {old}" if isinstance(old, str) else None
        return f"{by} renamed the case", _joined(detail, was)
    if kind == "published":
        return f"{by} had the case opened in Kibana", None
    if kind == "closure_requested":
        if details.get("proposed"):
            return f"ARGUS proposed closing the case as {reason()}", detail
        return f"{by} asked to close the case as {reason()}", detail
    if kind == "merge_requested":
        return f"{by} asked to merge the case into another", detail
    if kind == "closed":
        return f"The case was closed on approval {details.get('approval', '')}".strip(), None
    if kind == "merged_into":
        return f"{by} merged the case into another", detail
    if kind == "merged_in":
        return "Another case was merged into this one", None
    if kind == "reopened":
        return f"{by} reopened the case", detail
    return f"{by} changed the case", None


NOTICE_HOW_WORDS = {
    "email": "by e-mail",
    "phone": "by phone",
    "in_person": "in person",
    "through_it": "through IT",
    "other": "another way",
}


def _joined(*parts: str | None) -> str | None:
    """What a person typed, kept apart from the sentence: the lines, one under another."""
    kept = [p for p in parts if p]
    return "\n".join(kept) if kept else None


CAUSE_WORDS = {
    "verdict": "Opened from a person's true-positive verdict.",
    "proposal": "Suspected from ARGUS's own proposal.",
    "person": "Opened by a person.",
    "watch": "Suspected by ARGUS's watch: activity followed a closed case.",
    "raised": "Suggested by ARGUS from evidence across investigations. Nothing is open until a"
    " person confirms it.",
}


# --------------------------------------------------------------------------- one case


async def _investigations(conn: AsyncConnection, case_id: uuid.UUID) -> tuple[Sequence[Any], int]:
    rows = (
        await conn.execute(
            text(
                f"SELECT i.id, i.version, i.rule_name, i.severity, i.alert_count, i.first_event_at,"  # noqa: S608
                f" i.last_event_at, i.bucket_start, {queries._HUMAN} AS human_state,"
                " last.outcome AS last_outcome, mm.link, mm.link_value, mm.added_at,"
                " mm.added_by, count(*) OVER () AS total"
                " FROM case_members mm JOIN investigations i ON i.id = mm.investigation_id"
                f" {queries._STATE} WHERE mm.case_id = :c AND mm.removed_at IS NULL"
                " ORDER BY CASE i.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1"
                " WHEN 'medium' THEN 2 ELSE 3 END, i.last_event_at DESC NULLS LAST, i.id"
                " LIMIT :lim"
            ),
            {"c": case_id, "lim": DETAIL_MEMBERS},
        )
    ).all()
    return rows, int(rows[0].total) if rows else 0


async def _summary(
    conn: AsyncConnection, case_id: uuid.UUID, row: m.CaseRowOut
) -> m.CaseSummaryOut:
    rules = (
        await conn.execute(
            text(
                "SELECT i.rule_name, count(*) AS investigations,"
                " coalesce(sum(i.alert_count), 0) AS alerts, count(*) OVER () AS total"
                " FROM case_members mm JOIN investigations i ON i.id = mm.investigation_id"
                " WHERE mm.case_id = :c AND mm.removed_at IS NULL GROUP BY i.rule_name"
                " ORDER BY 3 DESC, 1 LIMIT 8"
            ),
            {"c": case_id},
        )
    ).all()
    reviewed = int(
        await conn.scalar(
            text(
                "SELECT count(*) FROM case_members mm JOIN review_state s"
                " ON s.investigation_id = mm.investigation_id"
                " JOIN investigations i ON i.id = mm.investigation_id"
                " WHERE mm.case_id = :c AND mm.removed_at IS NULL AND s.decision_id IS NOT NULL"
                " AND s.action = 'reviewed' AND s.version = i.version"
            ),
            {"c": case_id},
        )
        or 0
    )
    return m.CaseSummaryOut(
        investigations=row.investigations, alerts=row.alerts,
        rules=[m.RuleCountOut(rule_name=r.rule_name, investigations=int(r.investigations),
                              alerts=int(r.alerts)) for r in rules],
        rules_total=int(rules[0].total) if rules else 0, first_alert_at=row.first_alert_at,
        last_alert_at=row.last_alert_at, reviewed=reviewed,
        unreviewed=max(row.investigations - reviewed, 0),
    )  # fmt: skip


async def _history(
    conn: AsyncConnection, case_id: uuid.UUID, names_by_id: Mapping[int, str]
) -> tuple[list[m.HistoryItemOut], int]:
    events = (
        await conn.execute(
            text(
                "SELECT occurred_at, case_version, kind, actor, details FROM case_events"
                " WHERE case_id = :c ORDER BY case_version DESC LIMIT :lim"
            ),
            {"c": case_id, "lim": DETAIL_HISTORY},
        )
    ).all()
    out: list[m.HistoryItemOut] = []
    numbers = await case_numbers(conn, events)
    for e in events:
        by = who(e.actor, names_by_id)
        said, detail = event_words(e.kind, e.details, by, names_by_id, numbers)
        out.append(
            m.HistoryItemOut(at=e.occurred_at, kind="event", version=int(e.case_version),
                             text=said, by=by,
                             detail=_cap(detail, 4000) if isinstance(detail, str) else None)
        )  # fmt: skip
    requests = (
        await conn.execute(
            text(
                "SELECT id, requested_at, kind, reason, requested_by_user_id, proposed_by"
                " FROM approval_requests WHERE case_id = :c ORDER BY id DESC LIMIT 50"
            ),
            {"c": case_id},
        )
    ).all()
    decisions = (
        await conn.execute(
            text(
                "SELECT d.request_id, d.decided_at, d.decision, d.note, d.approver_user_id"
                " FROM approval_decisions d JOIN approval_requests r ON r.id = d.request_id"
                " WHERE r.case_id = :c ORDER BY d.id DESC LIMIT 100"
            ),
            {"c": case_id},
        )
    ).all()
    for r in requests:
        asker = (
            names_by_id.get(int(r.requested_by_user_id), "someone")
            if r.requested_by_user_id is not None
            else f"ARGUS ({r.proposed_by})"
            if r.proposed_by
            else "ARGUS"
        )
        out.append(
            m.HistoryItemOut(at=r.requested_at, kind="request", version=None, by=asker,
                             text=f"Approval request {r.id} ({r.kind}) was made",
                             detail=None)
        )  # fmt: skip
    for d in decisions:
        out.append(
            m.HistoryItemOut(
                at=d.decided_at, kind="decision", version=None,
                by=names_by_id.get(int(d.approver_user_id), "someone"),
                text=f"{d.decision.capitalize()} approval request {d.request_id}",
                detail=_cap(d.note, 4000) if d.note else None,
            )
        )  # fmt: skip
    out.sort(key=lambda h: h.at, reverse=True)
    return out[:DETAIL_HISTORY], await _history_total(conn, case_id)


async def _history_total(conn: AsyncConnection, case_id: uuid.UUID) -> int:
    """Everything the history could list: the events, the requests and the decisions."""
    return int(
        await conn.scalar(
            text(
                "SELECT (SELECT count(*) FROM case_events WHERE case_id = :c)"
                " + (SELECT count(*) FROM approval_requests WHERE case_id = :c)"
                " + (SELECT count(*) FROM approval_decisions d JOIN approval_requests r"
                " ON r.id = d.request_id WHERE r.case_id = :c)"
            ),
            {"c": case_id},
        )
        or 0
    )


async def case_user_names(conn: AsyncConnection, case_id: uuid.UUID) -> dict[int, str]:
    """The names of everyone who appears in the case's record."""
    rows = await conn.execute(
        text(
            "SELECT DISTINCT u FROM ("
            " SELECT actor_user_id AS u FROM case_events WHERE case_id = :c"
            " UNION SELECT (e.details->>'to')::bigint FROM case_events e WHERE e.case_id = :c"
            "   AND e.kind = 'assigned' AND (e.details->>'to') ~ '^[0-9]{1,15}$'"
            " UNION SELECT substring(e.details->>'verdict_by' FROM '^user:([0-9]{1,15})$')::bigint"
            "   FROM case_events e WHERE e.case_id = :c"
            " UNION SELECT requested_by_user_id FROM approval_requests WHERE case_id = :c"
            " UNION SELECT d.approver_user_id FROM approval_decisions d"
            "   JOIN approval_requests r ON r.id = d.request_id WHERE r.case_id = :c"
            " UNION SELECT author_user_id FROM case_notes WHERE case_id = :c"
            " UNION SELECT owner_user_id FROM cases WHERE id = :c) x WHERE u IS NOT NULL"
        ),
        {"c": case_id},
    )
    return await names(conn, (int(r[0]) for r in rows))


async def _notes(conn: AsyncConnection, case_id: uuid.UUID) -> tuple[list[m.NoteOut], int]:
    rows = (
        await conn.execute(
            text(
                "SELECT n.id, n.body, n.created_at, coalesce(u.display_name, u.username) AS"
                " author, count(*) OVER () AS total FROM case_notes n JOIN users u"
                " ON u.id = n.author_user_id WHERE n.case_id = :c ORDER BY n.id DESC"
                " LIMIT :lim"
            ),
            {"c": case_id, "lim": DETAIL_NOTES},
        )
    ).all()
    notes = [m.NoteOut(id=int(r.id), author=r.author, body=r.body, created_at=r.created_at)
             for r in rows]  # fmt: skip
    return notes, int(rows[0].total) if rows else 0


async def _indicators(
    conn: AsyncConnection, case_id: uuid.UUID
) -> tuple[list[m.CaseIndicatorOut], int]:
    marks = (
        await conn.execute(
            text(
                "SELECT kind, value, role, source, count(*) OVER () AS total FROM case_indicators"
                " WHERE case_id = :c AND removed_at IS NULL"
                " ORDER BY (role = 'c2') DESC, role, kind, value LIMIT :lim"
            ),
            {"c": case_id, "lim": DETAIL_INDICATORS},
        )
    ).all()
    if not marks:
        return [], 0
    notes = (
        await conn.execute(
            text(
                "SELECT n.kind, n.value, n.id, n.body, n.created_at, n.total,"
                " coalesce(u.display_name, u.username) AS author FROM ("
                " SELECT e.*, row_number() OVER (PARTITION BY e.kind, e.value ORDER BY e.id DESC)"
                " AS place, count(*) OVER (PARTITION BY e.kind, e.value) AS total"
                " FROM entity_notes e WHERE (e.kind, e.value) IN ("
                "  SELECT i.kind, i.value FROM case_indicators i WHERE i.case_id = :c"
                "  AND i.removed_at IS NULL AND i.kind IN ('ip', 'domain', 'host', 'user'))) n"
                " JOIN users u ON u.id = n.author_user_id WHERE n.place <= 3 ORDER BY n.id DESC"
            ),
            {"c": case_id},
        )
    ).all()
    by_key: dict[tuple[str, str], list[Any]] = {}
    for n in notes:
        by_key.setdefault((n.kind, n.value), []).append(n)
    out = []
    for k in marks:
        held = by_key.get((k.kind, k.value), [])
        out.append(
            m.CaseIndicatorOut(
                kind=k.kind, value=k.value, role=k.role, source=k.source,
                notes=[m.EntityNoteOut(id=int(n.id), author=n.author, body=n.body,
                                       created_at=n.created_at) for n in held],
                note_count=int(held[0].total) if held else 0,
            )
        )  # fmt: skip
    return out, int(marks[0].total)


async def entity_notes(conn: AsyncConnection, kind: str, value: str) -> list[m.EntityNoteOut]:
    rows = await conn.execute(
        text(
            "SELECT n.id, n.body, n.created_at, coalesce(u.display_name, u.username) AS author"
            " FROM entity_notes n JOIN users u ON u.id = n.author_user_id"
            " WHERE n.kind = :k AND n.value = :v ORDER BY n.id DESC LIMIT 200"
        ),
        {"k": kind, "v": value},
    )
    return [m.EntityNoteOut(id=int(r.id), author=r.author, body=r.body, created_at=r.created_at)
            for r in rows]  # fmt: skip


async def _mirror(conn: AsyncConnection, case_id: uuid.UUID, row: m.CaseRowOut) -> m.MirrorOut:
    mirror = (
        await conn.execute(
            text(
                "SELECT kibana_case_id, kibana_version, status, severity, tags, created_by,"
                " sync_alerts, unmanaged, read_at, kibana_updated_at, paused_reason, deleted_at"
                " FROM kibana_mirror WHERE case_id = :c"
            ),
            {"c": case_id},
        )
    ).first()
    writes = (
        await conn.execute(
            text(
                "SELECT o.id, o.op, o.write_class, o.state, o.state_reason, o.sent_at,"
                " o.verified_at, e.case_version, e.occurred_at, count(*) OVER () AS total"
                " FROM kibana_outbox o"
                " JOIN case_events e ON e.id = o.case_event_id WHERE o.case_id = :c"
                " ORDER BY o.id DESC LIMIT :lim"
            ),
            {"c": case_id, "lim": DETAIL_WRITES},
        )
    ).all()
    findings = (
        await conn.execute(
            text(
                "SELECT id, kind, severity, found_at, resolved_at, details, count(*) OVER ()"
                " AS total FROM kibana_findings WHERE case_id = :c"
                " ORDER BY (resolved_at IS NOT NULL), found_at DESC, id DESC"
                " LIMIT :lim"
            ),
            {"c": case_id, "lim": DETAIL_FINDINGS},
        )
    ).all()
    state: m.MirrorState
    if mirror is not None:
        if mirror.deleted_at is not None:
            state, words = "deleted", "The case was deleted in Kibana. ARGUS keeps its own record."
        elif mirror.paused_reason:
            state, words = "paused", "ARGUS has paused its writes to this Kibana case."
        else:
            state, words = "mirrored", "The case is in Kibana and ARGUS reads it back."
    elif row.in_kibana:
        state, words = "planned", "ARGUS has planned the Kibana case; it is not there yet."
    elif row.kibana_wait:
        state, words = "waiting", row.kibana_wait
    elif row.state == "suspected":
        state, words = "not_in_kibana", "Suspected cases stay in ARGUS; Kibana has nothing."
    else:
        state, words = "not_in_kibana", "This case is not in Kibana."
    return m.MirrorOut(
        state=state, words=words,
        kibana_case_id=getattr(mirror, "kibana_case_id", None),
        kibana_status=getattr(mirror, "status", None),
        kibana_severity=getattr(mirror, "severity", None),
        kibana_version=getattr(mirror, "kibana_version", None),
        tags=[_cap(t, 200) for t in (getattr(mirror, "tags", None) or [])][:60],
        created_by=getattr(mirror, "created_by", None),
        sync_alerts=getattr(mirror, "sync_alerts", None),
        unmanaged=list(getattr(mirror, "unmanaged", None) or []),
        read_at=getattr(mirror, "read_at", None),
        kibana_updated_at=getattr(mirror, "kibana_updated_at", None),
        paused_reason=getattr(mirror, "paused_reason", None),
        deleted_at=getattr(mirror, "deleted_at", None),
        writes_total=int(writes[0].total) if writes else 0,
        findings_total=int(findings[0].total) if findings else 0,
        writes=[
            m.MirrorWriteOut(id=int(w.id), op=w.op, write_class=w.write_class, state=w.state,
                             state_reason=w.state_reason, case_version=int(w.case_version),
                             planned_at=w.occurred_at, sent_at=w.sent_at,
                             verified_at=w.verified_at) for w in writes
        ],
        findings=[
            m.FindingOut(
                id=int(f.id), kind=f.kind, words=FINDING_WORDS.get(f.kind, "Something in Kibana"),
                severity=f.severity, found_at=f.found_at, resolved_at=f.resolved_at,
                details={k: _cap(str(f.details[k])) for k in FINDING_FIELDS
                         if isinstance(f.details, dict) and isinstance(f.details.get(k), str)},
            ) for f in findings
        ],
    )  # fmt: skip


# --------------------------------------------------------------------------- what's new, timeline


async def whats_new(
    conn: AsyncConnection,
    case_id: uuid.UUID,
    me: auth.Reviewer,
    now: datetime,
    names_by_id: Mapping[int, str],
) -> m.WhatsNewOut:
    first = me.previous_seen_at is None
    since = now - NEW_FOR_FIRST_VISIT if me.previous_seen_at is None else me.previous_seen_at
    items: list[m.WhatsNewItemOut] = []
    events = (
        await conn.execute(
            text(
                "SELECT occurred_at, kind, actor, details FROM case_events WHERE case_id = :c"
                " AND occurred_at > :s AND (actor_user_id IS NULL OR actor_user_id <> :me)"
                " ORDER BY occurred_at DESC LIMIT 15"
            ),
            {"c": case_id, "s": since, "me": me.user_id},
        )
    ).all()
    numbers = await case_numbers(conn, events)
    for e in events:
        by = who(e.actor, names_by_id)
        said, _ = event_words(e.kind, e.details, by, names_by_id, numbers)
        items.append(m.WhatsNewItemOut(at=e.occurred_at, kind="case", text=said, by=by,
                                       investigation_id=None))  # fmt: skip
    members = (
        await conn.execute(
            text(
                "SELECT i.id, i.rule_name, i.alert_count, mm.added_at FROM case_members mm"
                " JOIN investigations i ON i.id = mm.investigation_id WHERE mm.case_id = :c"
                " AND mm.removed_at IS NULL AND mm.added_at > :s ORDER BY mm.added_at DESC"
                " LIMIT 10"
            ),
            {"c": case_id, "s": since},
        )
    ).all()
    for i in members:
        items.append(
            m.WhatsNewItemOut(at=i.added_at, kind="investigation", by=None, investigation_id=i.id,
                              text=f"{i.rule_name or 'An investigation'} ({i.alert_count} alerts)"
                              " joined the case")
        )  # fmt: skip
    reviews = (
        await conn.execute(
            text(
                "SELECT r.created_at, r.outcome, r.action, r.investigation_id, u.id AS uid"
                " FROM review_events r JOIN case_members mm ON mm.investigation_id ="
                " r.investigation_id AND mm.case_id = :c AND mm.removed_at IS NULL"
                " JOIN users u ON u.id = r.user_id WHERE r.created_at > :s AND r.action <> 'note'"
                " AND r.user_id <> :me ORDER BY r.created_at DESC LIMIT 10"
            ),
            {"c": case_id, "s": since, "me": me.user_id},
        )
    ).all()
    review_names = await names(conn, (int(r.uid) for r in reviews))
    for r in reviews:
        said = (
            "asked for a follow-up on an investigation"
            if r.action == "follow_up"
            else f"reviewed an investigation as {OUTCOME_WORDS.get(r.outcome, 'decided')}"
        )
        items.append(
            m.WhatsNewItemOut(at=r.created_at, kind="verdict", text=said,
                              by=review_names.get(int(r.uid)), investigation_id=r.investigation_id)
        )  # fmt: skip
    checks = (
        await conn.execute(
            text(
                "SELECT c.finished_at, c.template, c.entity, c.requested_by, c.investigation_id,"
                " c.status FROM investigation_checks c JOIN case_members mm ON"
                " mm.investigation_id = c.investigation_id AND mm.case_id = :c"
                " AND mm.removed_at IS NULL WHERE c.kind = 'check' AND c.finished_at > :s"
                " ORDER BY c.finished_at DESC LIMIT 10"
            ),
            {"c": case_id, "s": since},
        )
    ).all()
    for k in checks:
        items.append(
            m.WhatsNewItemOut(
                at=k.finished_at, kind="check", by=k.requested_by,
                investigation_id=k.investigation_id,
                text=f"a check ({k.template}) on {k.entity} finished: {k.status}",
            )
        )  # fmt: skip
    findings = (
        await conn.execute(
            text(
                "SELECT found_at, kind, details FROM kibana_findings WHERE case_id = :c"
                " AND found_at > :s ORDER BY found_at DESC LIMIT 10"
            ),
            {"c": case_id, "s": since},
        )
    ).all()
    for f in findings:
        who_said = f.details.get("by") if isinstance(f.details, dict) else None
        items.append(
            m.WhatsNewItemOut(at=f.found_at, kind="kibana", investigation_id=None,
                              text=FINDING_WORDS.get(f.kind, "Something changed in Kibana"),
                              by=_cap(who_said, 200) if isinstance(who_said, str) else None)
        )  # fmt: skip
    items.sort(key=lambda i: i.at, reverse=True)
    return m.WhatsNewOut(since=since, first_visit=first, items=items[:30])


_MILESTONES = (
    "'suspected', 'opened', 'confirmed', 'contained', 'new_activity', 'closed', 'merged_into',"
    " 'merged_in', 'reopened', 'dismissed', 'notified', 'notice_withdrawn', 'blocked',"
    " 'address_moved', 'unlinked'"
)
_KIBANA_MILESTONES = (
    "'closed_in_kibana', 'reopened_in_kibana', 'person_commented', 'deleted_in_kibana'"
)


async def timeline_total(conn: AsyncConnection, case_id: uuid.UUID) -> int:
    """Everything the timeline could list (it shows the newest ``DETAIL_TIMELINE``)."""
    return int(
        await conn.scalar(
            text(
                "SELECT (SELECT count(*) FROM case_members mm JOIN investigations i"  # noqa: S608
                " ON i.id = mm.investigation_id WHERE mm.case_id = :c AND mm.removed_at IS NULL"
                " AND i.first_event_at IS NOT NULL)"
                f" + (SELECT count(*) FROM case_events WHERE case_id = :c AND kind IN"
                f" ({_MILESTONES}))"
                " + (SELECT count(*) FROM review_events r JOIN case_members mm ON"
                " mm.investigation_id = r.investigation_id AND mm.case_id = :c AND"
                " mm.removed_at IS NULL JOIN users u ON u.id = r.user_id WHERE r.action <> 'note')"
                " + (SELECT count(*) FROM investigation_checks k JOIN case_members mm ON"
                " mm.investigation_id = k.investigation_id AND mm.case_id = :c AND"
                " mm.removed_at IS NULL WHERE k.kind = 'check' AND k.finished_at IS NOT NULL)"
                f" + (SELECT count(*) FROM kibana_findings WHERE case_id = :c AND kind IN"
                f" ({_KIBANA_MILESTONES}))"
            ),
            {"c": case_id},
        )
        or 0
    )


async def timeline(
    conn: AsyncConnection,
    case_id: uuid.UUID,
    names_by_id: Mapping[int, str],
    members: Sequence[Any],
    context: Sequence[m.TimelineItemOut] = (),
) -> list[m.TimelineItemOut]:
    """The case's timeline, oldest first, the newest ``DETAIL_TIMELINE``. ``context`` are entries
    that are not events of the case (the device's sign-ins, AR6), merged in by time."""
    items: list[m.TimelineItemOut] = list(context)
    for i in members[:40]:
        if i.first_event_at is None:
            continue
        items.append(
            m.TimelineItemOut(
                at=i.first_event_at, until=i.last_event_at, kind="alerts", by=None,
                investigation_id=i.id,
                text=f"{i.rule_name or 'An investigation'}: {i.alert_count} alerts",
            )
        )  # fmt: skip
    milestones = (
        await conn.execute(
            text(
                "SELECT occurred_at, kind, actor, details FROM case_events WHERE case_id = :c"  # noqa: S608
                f" AND kind IN ({_MILESTONES}) ORDER BY case_version DESC LIMIT 30"
            ),
            {"c": case_id},
        )
    ).all()
    numbers = await case_numbers(conn, milestones)
    for e in milestones:
        by = who(e.actor, names_by_id)
        said, _ = event_words(e.kind, e.details, by, names_by_id, numbers)
        items.append(m.TimelineItemOut(at=e.occurred_at, until=None, kind="case", text=said,
                                       by=by, investigation_id=None))  # fmt: skip
    reviews = (
        await conn.execute(
            text(
                "SELECT r.created_at, r.outcome, r.action, r.investigation_id,"
                " coalesce(u.display_name, u.username) AS author FROM review_events r"
                " JOIN case_members mm ON mm.investigation_id = r.investigation_id"
                " AND mm.case_id = :c AND mm.removed_at IS NULL"
                " JOIN users u ON u.id = r.user_id WHERE r.action <> 'note'"
                " ORDER BY r.created_at DESC LIMIT 30"
            ),
            {"c": case_id},
        )
    ).all()
    for r in reviews:
        said = (
            "asked for a follow-up"
            if r.action == "follow_up"
            else f"reviewed it as {OUTCOME_WORDS.get(r.outcome, 'decided')}"
        )
        items.append(
            m.TimelineItemOut(
                at=r.created_at, until=None, kind="verdict", text=said, by=r.author,
                investigation_id=r.investigation_id,
            )
        )  # fmt: skip
    checks = (
        await conn.execute(
            text(
                "SELECT c.finished_at, c.template, c.entity, c.requested_by, c.investigation_id,"
                " c.status FROM investigation_checks c JOIN case_members mm ON"
                " mm.investigation_id = c.investigation_id AND mm.case_id = :c"
                " AND mm.removed_at IS NULL WHERE c.kind = 'check' AND c.finished_at IS NOT NULL"
                " ORDER BY c.finished_at DESC LIMIT 20"
            ),
            {"c": case_id},
        )
    ).all()
    for k in checks:
        items.append(
            m.TimelineItemOut(
                at=k.finished_at, until=None, kind="check", by=k.requested_by,
                investigation_id=k.investigation_id,
                text=f"A check ({k.template}) on {k.entity} finished: {k.status}",
            )
        )  # fmt: skip
    kibana = (
        await conn.execute(
            text(
                "SELECT found_at, kind, details FROM kibana_findings WHERE case_id = :c"  # noqa: S608
                f" AND kind IN ({_KIBANA_MILESTONES}) ORDER BY found_at DESC LIMIT 20"
            ),
            {"c": case_id},
        )
    ).all()
    for f in kibana:
        who_said = f.details.get("by") if isinstance(f.details, dict) else None
        items.append(
            m.TimelineItemOut(at=f.found_at, until=None, kind="kibana", investigation_id=None,
                              text=FINDING_WORDS.get(f.kind, "Something changed in Kibana"),
                              by=_cap(who_said, 200) if isinstance(who_said, str) else None)
        )  # fmt: skip
    items.sort(key=lambda i: i.at)
    return items[-DETAIL_TIMELINE:]


# --------------------------------------------------------------------------- approvals

_REQUEST = """
SELECT r.id, r.case_id, r.case_version, r.kind, r.reason, r.target_case_id, r.outbox_id,
       r.payload, r.payload_hash, r.alert_count, r.alert_digest, r.kibana_version,
       r.required_approvals, r.requested_by_user_id, r.proposed_by, r.requested_at, r.expires_at,
       r.note, c.number AS case_number, c.title AS case_title, c.state AS case_state,
       c.version AS case_now, t.number AS target_number, t.title AS target_title,
       t.state AS target_state, u.id AS requester_id, u.username AS requester_username,
       u.display_name AS requester_display_name
FROM approval_requests r
JOIN cases c ON c.id = r.case_id
LEFT JOIN cases t ON t.id = r.target_case_id
LEFT JOIN users u ON u.id = r.requested_by_user_id
"""


def request_status(
    *,
    kind: str,
    case_version: int,
    case_now: int,
    case_state: str,
    expires_at: datetime,
    now: datetime,
    approved: int,
    required: int,
    rejected: int,
) -> m.ApprovalStatus:
    """Where a request stands: rejected by anyone; approved when enough approvals count;
    expired past its end; stale when the case it was about has moved on (a closure or merge
    binds the case's version); else pending."""
    if rejected > 0:
        return "rejected"
    if approved >= required:
        return "approved"
    if now > expires_at:
        return "expired"
    if kind in ("closure", "merge") and (case_version != case_now or case_state == "closed"):
        return "stale"
    return "pending"


def approval_words(kind: str, reason: str | None, number: int, target: int | None) -> str:
    base = KIND_WORDS.get(kind, "Decide on")
    if kind == "closure":
        label = REASON_WORDS.get(reason or "", ("", ""))[0].lower()
        return f"Close case {number}: {label}"
    if kind == "merge":
        return f"Merge case {number} into case {target}"
    return f"{base} case {number}"


async def _alert_set(conn: AsyncConnection, case_id: uuid.UUID) -> tuple[int, str]:
    """The case's alerts now, as the database binds them to a request: count and digest."""
    ids = (
        await conn.execute(
            text(
                "SELECT DISTINCT ia.alert_id::text FROM case_members mm"
                " JOIN investigation_alerts ia ON ia.investigation_id = mm.investigation_id"
                " WHERE mm.case_id = :c AND mm.removed_at IS NULL"
            ),
            {"c": case_id},
        )
    ).scalars()
    found = list(ids)
    return len(found), approvals.alert_digest(found)


def group_key(reason: str, ids: Sequence[int]) -> str:
    return f"{reason}:" + hashlib.sha256(",".join(map(str, sorted(ids))).encode()).hexdigest()[:12]


def group_seed(ids: Sequence[int]) -> str:
    """The group's sample is a fixed choice for its set of requests: the same set, the same
    sample, however often the page is read."""
    return "group:" + ",".join(map(str, sorted(ids)))


async def approval_views(
    conn: AsyncConnection,
    where: str,
    params: Mapping[str, Any],
    me: auth.Reviewer,
    now: datetime,
    *,
    limit: int,
    order: str = "r.id DESC",
    only: Iterable[m.ApprovalStatus] | None = None,
) -> list[m.ApprovalOut]:
    """Approval requests (``where`` over ``r``, ``c``, ``t``) with their decisions, the writes
    they would make, and what this person may do about each."""
    rows = (
        await conn.execute(
            text(f"{_REQUEST} WHERE {where} ORDER BY {order} LIMIT :lim"),
            {**params, "lim": limit},
        )
    ).all()
    if not rows:
        return []
    ids = [int(r.id) for r in rows]
    decided = (
        await conn.execute(
            text(
                f"SELECT d.request_id, d.approver_user_id, d.decision, d.decided_at, d.note,"  # noqa: S608
                f" (d.decision = 'rejected' OR ({NOT_REVOKED})) AS counts, u.username,"
                " u.display_name FROM approval_decisions d JOIN users u ON u.id ="
                " d.approver_user_id WHERE d.request_id = ANY(:ids) ORDER BY d.id"
            ),
            {"ids": ids},
        )
    ).all()
    by_request: dict[int, list[Any]] = {}
    for d in decided:
        by_request.setdefault(int(d.request_id), []).append(d)
    holds = {
        int(h.id): h
        for h in (
            await conn.execute(
                text(
                    "SELECT id, op, write_class, state, state_reason FROM kibana_outbox"
                    " WHERE id = ANY(CAST(:ids AS bigint[]))"
                ),
                {"ids": [int(r.outbox_id) for r in rows if r.outbox_id is not None]},
            )
        ).all()
    }
    wanted = set(only) if only is not None else None
    out: list[m.ApprovalOut] = []
    for r in rows:
        decisions = by_request.get(int(r.id), [])
        approved = sum(1 for d in decisions if d.decision == "approved" and d.counts)
        rejected = sum(1 for d in decisions if d.decision == "rejected")
        status = request_status(
            kind=r.kind, case_version=int(r.case_version), case_now=int(r.case_now),
            case_state=r.case_state, expires_at=r.expires_at, now=now, approved=approved,
            required=int(r.required_approvals), rejected=rejected,
        )  # fmt: skip
        if wanted is not None and status not in wanted:
            continue
        now_count: int | None = None
        same: bool | None = None
        if status == "pending" and r.kind in ("closure", "merge"):
            now_count, digest = await _alert_set(conn, r.case_id)
            same = (now_count, digest) == (int(r.alert_count), r.alert_digest)
        mine = next((d for d in decisions if int(d.approver_user_id) == me.user_id), None)
        out.append(
            _approval(
                r,
                decisions,
                status,
                approved,
                now_count,
                same,
                holds.get(int(r.outbox_id)) if r.outbox_id is not None else None,
                me,
                mine,
            )
        )
    return out


def _you(r: Any, status: m.ApprovalStatus, me: auth.Reviewer, mine: Any | None) -> m.YouOut:
    decided = None if mine is None else cast("Literal['approved', 'rejected']", mine.decision)
    if not me.can(Capability.APPROVE):
        return m.YouOut(can_decide=False, why_not=needs(Capability.APPROVE, "approve or reject"),
                        decided=decided)  # fmt: skip
    if mine is not None:
        return m.YouOut(can_decide=False, decided=decided,
                        why_not=f"You already {mine.decision} this request.")  # fmt: skip
    if status != "pending":
        said = {
            "approved": "It is approved already.",
            "rejected": "It was rejected.",
            "expired": "It expired before enough people approved it.",
            "stale": "The case changed after it was asked for, so it can no longer be approved:"
            " ask again.",
        }[status]
        return m.YouOut(can_decide=False, why_not=said, decided=decided)
    if r.requested_by_user_id is not None and int(r.requested_by_user_id) == me.user_id:
        return m.YouOut(
            can_decide=False, decided=decided,
            why_not="You asked for this, so someone else has to decide it.",
        )  # fmt: skip
    return m.YouOut(can_decide=True, why_not=None, decided=decided)


def _approval(
    r: Any,
    decisions: Sequence[Any],
    status: m.ApprovalStatus,
    approved: int,
    now_count: int | None,
    same: bool | None,
    hold: Any | None,
    me: auth.Reviewer,
    mine: Any | None,
) -> m.ApprovalOut:
    required = int(r.required_approvals)
    words = {
        "pending": f"{approved} of {required} approval{'s' if required > 1 else ''} so far",
        "approved": "Approved",
        "rejected": "Rejected",
        "expired": "Expired before it was decided",
        "stale": "The case changed after it was asked for",
    }[status]
    target = (
        None
        if r.target_case_id is None
        else m.CaseRef(id=r.target_case_id, number=int(r.target_number), title=r.target_title,
                       state=r.target_state)
    )  # fmt: skip
    return m.ApprovalOut(
        id=int(r.id), kind=r.kind,
        words=approval_words(r.kind, r.reason, int(r.case_number),
                             None if r.target_number is None else int(r.target_number)),
        reason=r.reason,
        case=m.CaseRef(id=r.case_id, number=int(r.case_number), title=r.case_title,
                       state=r.case_state),
        case_version=int(r.case_version), target=target, status=status, status_words=words,
        requested_by=person(r, "requester_"), proposed_by=r.proposed_by,
        requested_at=r.requested_at, expires_at=r.expires_at, required=required,
        decisions=[
            m.DecisionRecordOut(
                approver=m.PersonRef(id=int(d.approver_user_id), username=d.username,
                                     display_name=d.display_name or d.username),
                decision=d.decision, decided_at=d.decided_at, note=_cap(d.note, 4000) or None,
                counts=bool(d.counts),
            ) for d in decisions
        ],
        payload=dict(r.payload), payload_hash=r.payload_hash, alerts_then=int(r.alert_count),
        alerts_now=now_count, alerts_same=same, note=_cap(r.note, 4000) or None,
        kibana_version=r.kibana_version,
        hold=None if hold is None else m.OutboxHoldOut(op=hold.op, write_class=hold.write_class,
                                                       state=hold.state,
                                                       state_reason=hold.state_reason),
        you=_you(r, status, me, mine), group=None,
    )  # fmt: skip


def group_kind(a: m.ApprovalOut) -> bool:
    """Whether a request is of the kind a group holds: a closure for a benign, false-positive or
    no-impact reason that one person's approval settles."""
    return a.kind == "closure" and a.reason in GROUP_REASONS and a.required == 1


def group_eligible(a: m.ApprovalOut) -> bool:
    """Whether a request may be approved in a group now: of that kind, still waiting, one this
    person may decide, and not one whose alerts changed since it was asked for (that one is read
    alone, with its warning: Q-B3 review R3-12)."""
    return (
        group_kind(a) and a.status == "pending" and a.you.can_decide and a.alerts_same is not False
    )


def groups_of(pending: Sequence[m.ApprovalOut]) -> list[m.ApprovalGroupOut]:
    """The requests that may be approved together: up to twenty to a group, of one reason, by
    case number. A lone request is no group."""
    eligible: dict[str, list[m.ApprovalOut]] = {}
    for a in pending:
        if group_eligible(a):
            eligible.setdefault(a.reason or "", []).append(a)
    out = []
    for reason, items in eligible.items():
        items.sort(key=lambda a: (a.case.number, a.id))
        for start in range(0, len(items), GROUP_LIMIT):
            chunk = items[start : start + GROUP_LIMIT]
            if len(chunk) < 2:
                continue
            ids = [a.id for a in chunk]
            key = group_key(reason, ids)
            out.append(
                m.ApprovalGroupOut(
                    key=key, reason=cast("m.ClosureReason", reason),
                    words=f"{len(chunk)} cases to close as {REASON_WORDS[reason][0].lower()}",
                    items=[m.GroupItemOut(request_id=a.id, payload_hash=a.payload_hash,
                                          case_number=a.case.number, case_title=a.case.title)
                           for a in chunk],
                    sample=approvals.sample(ids, group_seed(ids)),
                )
            )  # fmt: skip
            for a in chunk:
                a.group = key
    return out


async def pending_views(
    conn: AsyncConnection, me: auth.Reviewer, now: datetime
) -> list[m.ApprovalOut]:
    """The requests waiting for a decision, oldest first, at most ``PENDING_LIMIT``: what the
    queue lists and what its groups are formed from."""
    return await approval_views(
        conn, _PENDING, {}, me, now, limit=PENDING_LIMIT, order="r.id", only=("pending",)
    )


async def queue(
    conn: AsyncConnection, me: auth.Reviewer, now: datetime, can_sign: bool
) -> m.ApprovalQueueOut:
    pending = await pending_views(conn, me, now)
    recent = await approval_views(
        conn, "r.requested_at > :since OR EXISTS (SELECT 1 FROM approval_decisions d WHERE"
        " d.request_id = r.id AND d.decided_at > :since)", {"since": now - RECENT_DECISIONS},
        me, now, limit=RECENT_LIMIT * 4, only=("approved", "rejected", "expired", "stale"),
    )  # fmt: skip
    valid_until = None if me.stepped_up_at is None else me.stepped_up_at + approvals.STEP_UP_VALID
    total = await conn.scalar(
        text(
            "SELECT count(*) FROM approval_requests r JOIN cases c ON c.id = r.case_id"  # noqa: S608
            f" WHERE {_PENDING}"
        )
    )
    return m.ApprovalQueueOut(
        pending=pending, pending_total=int(total or 0), recent=recent[:RECENT_LIMIT],
        groups=groups_of(pending),
        step_up=m.StepUpOut(valid=valid_until is not None and now <= valid_until,
                            valid_until=valid_until, url="/stepup?next=/app/approvals"),
        can_sign=can_sign,
    )  # fmt: skip


# --------------------------------------------------------------------------- the detail


async def assignees(conn: AsyncConnection) -> list[m.PersonRef]:
    rows = await conn.execute(
        text(
            "SELECT id, username, display_name FROM users WHERE NOT disabled AND kind = 'person'"
            " AND username <> 'argus-assistant' ORDER BY lower(coalesce(display_name, username))"
            " LIMIT 200"
        )
    )
    return [
        m.PersonRef(id=int(r.id), username=r.username, display_name=r.display_name or r.username)
        for r in rows
    ]


async def ref(conn: AsyncConnection, case_id: uuid.UUID | None) -> m.CaseRef | None:
    if case_id is None:
        return None
    r = (
        await conn.execute(
            text("SELECT id, number, title, state FROM cases WHERE id = :id"), {"id": case_id}
        )
    ).first()
    return None if r is None else m.CaseRef(id=r.id, number=int(r.number), title=r.title,
                                            state=r.state)  # fmt: skip


async def others_open(conn: AsyncConnection, case_id: uuid.UUID) -> int:
    return int(
        await conn.scalar(
            text("SELECT count(*) FROM cases WHERE id <> :c AND state <> 'closed'"), {"c": case_id}
        )
        or 0
    )


ACTIVE_STATES = ("open", "assigned", "contained")
MODE_WORDS = {
    "off": "The still-active watch is switched off here, so it asks nothing.",
    "local": "The watch reads ARGUS's own alerts only; it asks the proxy logs nothing.",
    "on": "The watch reads ARGUS's own alerts and, for the case's addresses, the proxy logs.",
}
OUTCOMES = ("active", "quiet", "unverified", "not_checked")


async def suggestions(
    conn: AsyncConnection, case_id: uuid.UUID
) -> tuple[list[m.CaseSuggestionOut], int]:
    """The investigations ARGUS found that may belong to the case but did not join (their match
    is a shared address or name, or ties between cases), until one is joined or dismissed. The
    values in them come from alerts: shown as text only (Q-C2 decision 33)."""
    rows = (
        await conn.execute(
            text(
                "SELECT s.id, s.investigation_id, s.link, s.link_value, s.kind, s.why,"
                " s.created_at, i.rule_name, i.severity, i.alert_count, count(*) OVER () AS total"
                " FROM case_suggestions s JOIN investigations i ON i.id = s.investigation_id"
                " WHERE s.case_id = :c AND s.dismissed_at IS NULL AND NOT EXISTS (SELECT 1 FROM"
                " case_members mm WHERE mm.investigation_id = s.investigation_id AND"
                " mm.removed_at IS NULL) ORDER BY s.id DESC LIMIT :lim"
            ),
            {"c": case_id, "lim": DETAIL_SUGGESTIONS},
        )
    ).all()
    return [
        m.CaseSuggestionOut(
            id=int(r.id), investigation_id=r.investigation_id, rule_name=r.rule_name,
            severity=r.severity, alert_count=int(r.alert_count), kind=r.kind, link=r.link,
            link_value=_cap(r.link_value, 512) or None, why=_cap(r.why, 300),
            created_at=r.created_at,
        )
        for r in rows
    ], int(rows[0].total) if rows else 0  # fmt: skip


def watched(case: Case, now: datetime) -> bool:
    """Whether the still-active watch looks at the case: confirmed and not closed, or closed as
    remediated within the watch (Q-C2: ``watchrun.watched``)."""
    if not case.confirmed or case.merged_into_id is not None:
        return False
    if case.state in ACTIVE_STATES:
        return True
    return (
        case.state == "closed"
        and case.closure_reason in watch.WATCHED_REASONS
        and case.closed_at is not None
        and case.closed_at >= now - watch.WATCH_AFTER_CLOSURE
    )


def _count(value: Any) -> int | None:
    ok = isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 10**12
    return value if ok else None


def _seen_words(source: str, subject: str, detail: Any) -> str:
    """What an answer of "activity seen" recorded, as a short text (its values come from alerts
    and logs: shown as text only, each checked for its type and cut short)."""
    if not isinstance(detail, dict):
        return ""
    last = detail.get("last")
    when = f", the last at {_cap(last, 40)}" if isinstance(last, str) and last else ""
    if source == watch.ALERTS:
        n = _count(detail.get("alerts"))
        return "" if n is None else f"{n} alert{'s' if n != 1 else ''} of the case{when}"
    n = _count(detail.get("requests"))
    hosts = detail.get("hosts")
    named = (
        ", ".join(_cap(h, 64) for h in hosts[:5] if isinstance(h, str))
        if isinstance(hosts, list)
        else ""
    )
    if n is None:
        return ""
    who = f" from {named}" if named else ""
    return f"{_cap(subject, 64)}: {n} request{'s' if n != 1 else ''}{who}{when}"


async def watch_status(
    conn: AsyncConnection,
    case: Case,
    now: datetime,
    window: QuietWindow | None,
    *,
    context: Any | None,
    mode: str | None,
) -> m.WatchStatusOut:
    """What the watch can say about the case: when it last ran, the last days' answers (a
    question left open says why), and whether it is verifiably quiet (only when asked: the page
    works the window out for a person who can act on it). The answers' reasons may carry values
    from alerts and logs: text only."""
    today = watch.utc_day(now)
    since = today - timedelta(days=watch.BACKLOG_DAYS)
    stored = (
        await conn.execute(
            text(
                "SELECT day, source, subject, outcome, reason, detail FROM case_watch_checks"
                " WHERE case_id = :c"
                " AND day >= :since AND source <> 'proxy.pair' ORDER BY day DESC, source, subject,"
                " part"
            ),
            {"c": case.id, "since": since},
        )
    ).all()
    days: dict[Any, dict[str, Any]] = {}
    for r in stored:
        day = days.setdefault(r.day, {"alerts": None, "alerts_reason": None, "proxy": {},
                                      "reasons": [], "seen": []})  # fmt: skip
        if r.outcome == "active" and len(day["seen"]) < 4:
            found = _seen_words(r.source, r.subject, r.detail)
            if found:
                day["seen"].append(found)
        if r.source == watch.ALERTS:
            day["alerts"], day["alerts_reason"] = r.outcome, _cap(r.reason, 300) or None
        else:
            day["proxy"][r.outcome] = day["proxy"].get(r.outcome, 0) + 1
            reason = _cap(r.reason, 300)
            if reason and reason not in day["reasons"] and len(day["reasons"]) < 3:
                day["reasons"].append(reason)
    last = await conn.scalar(
        text("SELECT max(occurred_at) FROM audit_events WHERE action = 'watch.run'")
    )
    due = 0
    if context is not None and not stored:
        wanted = watch.subjects(
            ((i.kind, i.value, i.role) for i in case.indicators), context.is_campus,
            context.shared.reason,
        )  # fmt: skip
        due = len(wanted)
    return m.WatchStatusOut(
        mode_words=MODE_WORDS.get(mode or "", "This server does not know how the watch is set up."),
        last_run_at=last,
        late=last is not None and now - last > watch.RUN_LATE,
        days=[
            m.WatchDayOut(day=d, alerts=v["alerts"], alerts_reason=v["alerts_reason"],
                          proxy=v["proxy"], proxy_reasons=v["reasons"], seen=v["seen"])
            for d, v in sorted(days.items(), reverse=True)[: watch.BACKLOG_DAYS]
        ],
        proxy_checks_due=due,
        quiet=None if window is None else window.verified,
        quiet_words=None if window is None else _cap(window_words(window.reason), 600),
    )  # fmt: skip


def notice_action(
    action: Literal["notify", "block", "withdraw_notice"],
    case: Case,
    me: auth.Reviewer,
    now: datetime,
) -> m.CaseActionStateOut:
    """Whether this person may record a notice (or a block), or withdraw one, on the case now: the
    machine's own answer, so the page and the command cannot drift."""
    label, what = {
        "notify": ("Record that the owner was told", "record notices"),
        "block": ("Record a block", "record blocks"),
        "withdraw_notice": ("Withdraw the notice (recorded by mistake)", "withdraw notices"),
    }[action]
    why: str | None = None
    if not me.can(Capability.MANAGE_CASES):
        why = needs(Capability.MANAGE_CASES, what)
    else:
        try:
            if action == "notify":
                decide(case, Notify("x", "email"), actor_of(me), now)
            elif action == "withdraw_notice":
                decide(case, WithdrawNotice("x", "x"), actor_of(me), now)
            else:
                decide(case, RecordBlock("x", "x"), actor_of(me), now)
        except CaseRefused as exc:
            why = (
                "A notice is recorded on an open or assigned case; this one is "
                f"{STATE_WORDS[case.state].lower()}."
                if action == "notify" and exc.code == "conflict"
                else why_not(exc, action)
            )
    return m.CaseActionStateOut(action=action, label=label, enabled=why is None, why_not=why)


async def known_section(
    conn: AsyncConnection,
    case: Case,
    me: auth.Reviewer,
    now: datetime,
    users: Mapping[int, str],
    classifier: IpClassifier | None = None,
) -> m.KnownOut | None:
    """The owner-notified record of a confirmed case that is open or assigned (AR4b, D-169):
    what a person recorded, what ARGUS counted since (and did not raise), the changes it did
    raise, its suggestions and the size of the ready block list."""
    if case.state not in ("open", "assigned"):
        return None
    status = next(iter(await knownview.notified(conn, now, case_id=case.id)), None)
    noted = await knownview.notices(conn, case.id)
    entries = await blocklist.count(conn, case.id, load_shared(), classifier)
    return m.KnownOut(
        notified_at=case.notified_at, blocked_at=case.blocked_at,
        managed=status.managed if status is not None else None,
        line=status.line(ist_day) if status is not None else None,
        alerts=status.alerts if status is not None else 0,
        days=status.days if status is not None else 0,
        alerts_per_day=[m.DayAlertsOut(day=date.fromisoformat(d), alerts=n)
                        for d, n in (status.per_day.items() if status is not None else ())],
        trend=status.trend if status is not None else "too few days to say",
        last_alert_at=status.last_alert_at if status is not None else None,
        devices=status.devices if status is not None else 0,
        notices=[
            m.NoticeRecordOut(
                kind=n.kind, at=n.at, told=_cap(n.told, 200), how=_cap(n.how, 100),  # type: ignore[arg-type]
                managed=n.managed, note=_cap(n.note) if n.note else None,
                by=who(f"user:{n.by_user_id}", users), case_version=n.case_version,
                withdrawn=n.withdrawn,
            )
            for n in noted
        ],
        reminders=[m.ReminderOut(kind=r.kind, words=r.why, suggested_at=r.suggested_at)  # type: ignore[arg-type]
                   for r in (status.reminders if status is not None else ())],
        changes=[m.ChangeOut(investigation_id=c.investigation_id, rule_name=_cap(c.rule, 200),
                             why=_cap(c.why), last_event_at=c.last_event_at)
                 for c in (status.changes if status is not None else ())],
        new_destinations=[m.NewDestinationOut(kind=d.kind, value=_cap(d.value, 300),  # type: ignore[arg-type]
                                              added_at=d.added_at)
                          for d in (status.new_destinations if status is not None else ())],
        new_destinations_total=status.new_total if status is not None else 0,
        notify=notice_action("notify", case, me, now),
        block=notice_action("block", case, me, now),
        withdraw_notice=notice_action("withdraw_notice", case, me, now),
        blocklist_entries=entries,
    )  # fmt: skip


async def detail(
    conn: AsyncConnection,
    service: CaseService,
    case_id: uuid.UUID,
    me: auth.Reviewer,
    *,
    watch_context: Any | None = None,
    watch_mode: str | None = None,
    signins: Any | None = None,
) -> m.CaseDetail | None:
    """A case in the analyst's order: what it is, what is new, what happened, what it holds,
    what can be done, Kibana's side, the notes and the record of changes."""
    case = await service.get(case_id)
    row = await row_of(conn, case_id)
    if case is None or row is None:
        return None
    now = service.now
    users = await case_user_names(conn, case_id)
    members, total = await _investigations(conn, case_id)
    can_manage = me.can(Capability.MANAGE_CASES)
    # Q-C2's finder reads the active cases: asked only for a case a person who may act on it is
    # looking at (everyone else is told what they lack, which needs no window)
    asked = can_manage and case.state in ACTIVE_STATES
    window = await service.quiet_windows(case) if asked else NO_QUIET_WINDOW
    choices = closure_choices(case, me, window, now)
    actions = case_actions(case, me, window, choices, await others_open(conn, case_id), now)
    own = await approval_views(conn, "r.case_id = :c", {"c": case_id}, me, now,
                               limit=DETAIL_APPROVALS)  # fmt: skip
    children = (
        await conn.execute(
            text(
                "SELECT id, number, title, state, count(*) OVER () AS total FROM cases"
                " WHERE parent_case_id = :c ORDER BY number LIMIT :lim"
            ),
            {"c": case_id, "lim": DETAIL_CHILDREN},
        )
    ).all()
    approvals_total = int(
        await conn.scalar(
            text("SELECT count(*) FROM approval_requests WHERE case_id = :c"), {"c": case_id}
        )
        or 0
    )
    notes, notes_total = await _notes(conn, case_id)
    indicators, indicators_total = await _indicators(conn, case_id)
    history, history_total = await _history(conn, case_id, users)
    suggested, suggested_total = await suggestions(conn, case_id)
    hidden = not me.can(Capability.SEE_LOGS)
    sign_ins, sign_in_items = await signinpages.for_case(conn, signins, case_id, now, hidden=hidden)
    return m.CaseDetail(
        case=row,
        known=await known_section(
            conn, case, me, now, users, getattr(watch_context, "classifier", None)
        ),
        cause_words=CAUSE_WORDS[case.cause],
        parent=await ref(conn, case.parent_case_id),
        children=[m.CaseRef(id=c.id, number=int(c.number), title=c.title, state=c.state)
                  for c in children],
        children_total=int(children[0].total) if children else 0,
        summary=await _summary(conn, case_id, row),
        whats_new=await whats_new(conn, case_id, me, now, users),
        timeline=await timeline(conn, case_id, users, members, sign_in_items),
        timeline_total=await timeline_total(conn, case_id) + len(sign_in_items),
        lead_investigation_id=members[0].id if members else None,
        investigations=[
            m.CaseMemberOut(
                investigation_id=i.id, version=int(i.version), rule_name=i.rule_name,
                severity=i.severity,
                alert_count=int(i.alert_count), first_event_at=i.first_event_at,
                last_event_at=i.last_event_at, bucket_start=i.bucket_start,
                human_state=i.human_state, last_outcome=i.last_outcome, link=i.link,
                link_value=i.link_value, added_at=i.added_at, added_by=who(i.added_by, users),
            ) for i in members
        ],
        investigations_total=total, indicators=indicators, indicators_total=indicators_total,
        suggestions=suggested, suggestions_total=suggested_total,
        watch=(
            await watch_status(conn, case, now, window if asked else None,
                               context=watch_context, mode=watch_mode)
            if watched(case, now) else None
        ),
        actions=actions, closure_choices=choices,
        assignees=await assignees(conn) if can_manage else [],
        approvals=own, approvals_total=approvals_total,
        mirror=await _mirror(conn, case_id, row), notes=notes, notes_total=notes_total,
        history=history, history_total=history_total,
        logs_hidden=hidden,
        signins=sign_ins,
    )  # fmt: skip


# --------------------------------------------------------------------------- Check more

CHECK_WORDS = Words(
    {
        "proxy.host": "{A_own:host}'s proxy traffic",
        "proxy.destination": "Which {own:hosts} reached a destination",
        "proxy.pair": "How regularly a host reached a destination",
        "proxy.contact": "Which {own:hosts} reached an outside address that day",
        "dns.host_domains": "Which names a host looked up in DNS",
        "web.followups": "A client's successful web answers after the first alert",
        "web.path_outcomes": "Whether the attacked paths got a successful answer",
        "ti.lookup": "Whether an address or domain is on the threat lists",
    }
)
TAKES_WORDS = Words(
    {
        "internal": "{a_own:address}",
        "public": "an address outside {the}",
        "address": "any address",
        "indicator": "an address or a domain",
    }
)
STATUS_WORDS = {
    "queued": "Waiting for ARGUS's service to run it",
    "running": "Running now",
    "done": "Done",
    "refused": "Not asked",
    "failed": "Failed",
}


def _only(value: Any, kind: type) -> Any:
    """``value`` when it is exactly of that type (a stored record may hold anything), else None."""
    ok = isinstance(value, kind) and (kind is bool or not isinstance(value, bool))
    return value if ok else None


def _check_row(r: Any) -> m.InvestigationCheckOut:
    outcome = r.outcome if isinstance(r.outcome, dict) else {}
    lines = [
        m.CheckLineOut(
            template=str(c.get("template", "")),
            eid=_only(c.get("eid"), str),
            status=_only(c.get("status"), str),
            server_ms=_only(c.get("server_ms"), int),
            heavy=bool(c.get("heavy")),
            sent=_only(c.get("sent"), bool),
            why_not=_cap(_only(c.get("why_not"), str), 300) or None,
        )
        for c in (outcome.get("checks") or [])[:10]
        if isinstance(c, dict)
    ]
    why = outcome.get("error") or outcome.get("stopped")
    if not isinstance(why, str):
        why = next((ln.why_not for ln in lines if ln.why_not), None)
    status = r.status
    words = STATUS_WORDS[status]
    if status == "done" and lines and all(ln.sent is False for ln in lines):
        words = "Done: ARGUS already held the answer, so nothing new was asked of the SIEM"
    dossier = outcome.get("dossier")
    return m.InvestigationCheckOut(
        id=int(r.id), version=int(r.version), template=r.template,
        words=CHECK_WORDS.get(r.template, r.template), entity=r.entity,
        requested_by=r.requested_by, requested_at=r.requested_at, status=status,
        status_words=words, started_at=r.started_at, finished_at=r.finished_at,
        requests=outcome.get("requests") if isinstance(outcome.get("requests"), int) else None,
        heavy_requests=outcome.get("heavy") if isinstance(outcome.get("heavy"), int) else None,
        server_ms=outcome.get("server_ms") if isinstance(outcome.get("server_ms"), int) else None,
        lines=lines, dossier=dossier if isinstance(dossier, str) else None,
        assessed=bool(r.assessed), why_not=_cap(why, 300) or None if isinstance(why, str) else None,
    )  # fmt: skip


async def investigation_checks(
    conn: AsyncConnection, investigation_id: uuid.UUID, version: int, me: auth.Reviewer
) -> m.InvestigationChecksOut:
    """A person's "Check more" requests on one investigation with their records, the templates
    a person may ask for and what is left of this person's allowance."""
    from argus.investigation import catalogue, checks, store

    rows = (
        await conn.execute(
            text(
                "SELECT c.id, c.version, c.template, c.entity, c.requested_by, c.requested_at,"
                " c.status, c.started_at, c.finished_at, c.outcome,"
                " (c.finished_at IS NOT NULL AND EXISTS (SELECT 1 FROM assessments a"
                "  WHERE a.investigation_id = c.investigation_id AND a.created_at > c.finished_at"
                "  AND a.status IN ('proposed', 'no_decision'))) AS assessed"
                " FROM investigation_checks c WHERE c.investigation_id = :i AND c.kind = 'check'"
                " ORDER BY c.id DESC LIMIT 30"
            ),
            {"i": investigation_id},
        )
    ).all()
    open_now, _ = await store.open_requests(conn, me.username[:120])
    today = await store.checks_today(conn, me.username[:120])
    templates = [
        m.CheckTemplateOut(
            template=t, words=CHECK_WORDS[t], takes=cast("Any", checks.TAKES[t]),
            takes_words=TAKES_WORDS[checks.TAKES[t]], heavy=catalogue.is_heavy(t),
            cost_words=(
                "A heavy check: a search of the logs. It counts against ARGUS's daily SIEM"
                " allowance (300 heavy requests and 6 minutes), may wait for its turn, and is"
                " asked of one day's index only."
                if catalogue.is_heavy(t)
                else "A light check: one small lookup."
            ),
        )
        for t in checks.APPROVED
    ]  # fmt: skip
    return m.InvestigationChecksOut(
        investigation_id=investigation_id, version=version, items=[_check_row(r) for r in rows],
        templates=templates,
        limits=m.CheckLimitsOut(open_per_person=checks.OPEN_PER_PERSON, open_now=open_now,
                                per_day=checks.PER_PERSON_PER_DAY, today=today),
    )  # fmt: skip
