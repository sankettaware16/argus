"""What a notice is and when one is sent: pure rules, no database and no mail.

A **condition** is something true now that a person should hear about (a *kind*, an opaque
*subject*, a *severity*, a *count*); a **row** is what the ``notices`` table remembers about one
subject. :func:`decide` compares them: one notice per (kind, subject) until it is resolved or its
severity rises; a "still waiting" reminder at most once a day, for what waits for a person; an
outage noticed once when it has lasted :data:`OUTAGE_AFTER`, and once more when it ends; a resolved
subject that comes back is a new notice. :func:`allocate` applies the rate limit
(:data:`MAX_PER_HOUR`): the rest fold into one "N more" notice and stay due for the next pass."""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal, get_args

from argus.cases.model import SEVERITY_RANK, Severity

Kind = Literal["case_active", "after_closure", "closure_waiting", "ioc_hit", "outage"]
KINDS: tuple[Kind, ...] = get_args(Kind)
# Why a notice goes out: first time, a higher severity, a daily reminder, or the end of an outage.
Reason = Literal["new", "raised", "reminder", "ended"]
Page = Literal["case", "investigation", "health", "home"]

MAX_PER_HOUR = 10
REMIND_EVERY = timedelta(hours=24)
OUTAGE_AFTER = timedelta(hours=1)
WAITING_HOURS = 12  # a closure request waits this long before it is news (triggers, render)
END_NOTICE_WITHIN = timedelta(hours=24)  # an outage that ended longer ago is not announced
REMINDED: frozenset[Kind] = frozenset({"case_active", "after_closure", "closure_waiting"})
# Most urgent first when the hour cannot take them all.
KIND_ORDER: dict[str, int] = {
    "case_active": 0,
    "ioc_hit": 1,
    "after_closure": 2,
    "outage": 3,
    "closure_waiting": 4,
}
REASON_ORDER: dict[str, int] = {"new": 0, "raised": 0, "reminder": 1, "ended": 2}
SUBJECT_CHARS = 64  # a case's or investigation's uuid, or a fixed word


@dataclass(frozen=True)
class Target:
    """Where a notice's link leads: a page of ARGUS's web, by id where it has one."""

    page: Page
    id: uuid.UUID | None = None

    def __post_init__(self) -> None:
        if (self.id is None) != (self.page in ("health", "home")):
            raise ValueError("a case or an investigation has an id; the other pages have none")


@dataclass(frozen=True)
class Condition:
    """Something worth a notice, true now. ``since``: when it began, if the data say so (an
    outage's start); without it the first pass that sees it is the start. ``after``: how long an
    outage must have lasted to be noticed, when that is not :data:`OUTAGE_AFTER` (the watch that
    has never run: its first run is not late before 36 hours)."""

    kind: Kind
    subject: str
    severity: Severity
    count: int
    target: Target
    since: datetime | None = None
    after: timedelta | None = None

    def __post_init__(self) -> None:
        if not 1 <= len(self.subject) <= SUBJECT_CHARS:
            raise ValueError("a subject is 1 to 64 characters")
        if self.count < 0:
            raise ValueError("a count is not negative")


@dataclass(frozen=True)
class Row:
    """What the ``notices`` table holds about one subject (one occurrence of it)."""

    id: int
    kind: Kind
    subject: str
    severity: Severity
    count: int
    first_seen: datetime
    last_seen: datetime
    resolved_at: datetime | None = None
    sent_at: datetime | None = None
    sent_severity: Severity | None = None
    notified: int = 0
    ended_at: datetime | None = None


@dataclass(frozen=True)
class Intent:
    """One notice that is due: what it says (never more than kind, severity, count and where the
    link leads) and the row it is about."""

    kind: Kind
    reason: Reason
    severity: Severity
    count: int
    target: Target
    key: tuple[str, str]  # (kind, subject): the row
    first_seen: datetime
    row_id: int | None = None  # an outage's end notice names its (resolved) row


@dataclass(frozen=True)
class Decision:
    """What one subject needs: ``store`` is ``insert`` (a new row), ``update`` (the current
    severity, count and last-seen time), ``resolve`` (the condition is gone) or ``none``; and
    the notice that is due, if any."""

    store: Literal["insert", "update", "resolve", "none"]
    intent: Intent | None = None
    first_seen: datetime | None = None  # for an insert
    severity: Severity | None = None  # what to store (insert, update)
    count: int = 0


def rank(severity: Severity) -> int:
    return SEVERITY_RANK[severity]


def ready(kind: Kind, first_seen: datetime, now: datetime, after: timedelta | None = None) -> bool:
    """An outage is worth a notice once it has lasted an hour (or ``after``); everything else at
    once."""
    return kind != "outage" or now - first_seen >= (after or OUTAGE_AFTER)


def decide(row: Row | None, condition: Condition | None, now: datetime) -> Decision:
    """The store and the notice for one subject, from the row (None: never seen, or the last
    occurrence is over) and the condition (None: it no longer holds)."""
    if row is not None and row.resolved_at is not None:
        row = None  # that occurrence is over: a condition now is a new one
    if condition is None:
        return Decision("none") if row is None else Decision("resolve")
    if row is None:
        first = min(condition.since if condition.since is not None else now, now)
        count = _count(condition, first, now)
        intent = (
            _intent(condition, "new", first, count)
            if ready(condition.kind, first, now, condition.after)
            else None
        )
        return Decision("insert", intent, first, condition.severity, count)
    count = _count(condition, row.first_seen, now)
    return Decision("update", _due(row, condition, count, now), None, condition.severity, count)


def _count(condition: Condition, first_seen: datetime, now: datetime) -> int:
    """An outage's count is the hours it has lasted; the others carry their own."""
    if condition.kind == "outage":
        return hours_between(first_seen, now)
    return condition.count


def _intent(condition: Condition, reason: Reason, first_seen: datetime, count: int) -> Intent:
    return Intent(
        condition.kind,
        reason,
        condition.severity,
        count,
        condition.target,
        (condition.kind, condition.subject),
        first_seen,
    )


def _due(row: Row, condition: Condition, count: int, now: datetime) -> Intent | None:
    if not ready(row.kind, row.first_seen, now, condition.after):
        return None
    if row.sent_at is None or row.sent_severity is None:
        return _intent(condition, "new", row.first_seen, count)
    if row.kind == "outage":
        return None  # once per outage
    if rank(condition.severity) > rank(row.sent_severity):
        return _intent(condition, "raised", row.first_seen, count)
    if row.kind in REMINDED and now - row.sent_at >= REMIND_EVERY:
        return _intent(condition, "reminder", row.first_seen, count)
    return None


def ending(row: Row, target: Target, now: datetime) -> Intent | None:
    """The "it is over" notice of a resolved outage that was announced and not yet ended (and
    ended less than a day ago: after a long silence it would only confuse)."""
    if (
        row.kind == "outage"
        and row.resolved_at is not None
        and row.sent_at is not None
        and row.ended_at is None
        and now - row.resolved_at <= END_NOTICE_WITHIN
    ):
        return Intent(
            "outage",
            "ended",
            row.severity,
            hours_between(row.first_seen, row.resolved_at),
            target,
            (row.kind, row.subject),
            row.first_seen,
            row.id,
        )
    return None


def hours_between(start: datetime, end: datetime) -> int:
    """Whole hours from ``start`` to ``end``, at least 1 (a notice never says "0 hours")."""
    return max(1, int((end - start).total_seconds() // 3600))


@dataclass(frozen=True)
class Allocation:
    """``send``: the notices that go out one by one; ``folded``: those told in one "N more"
    notice (empty when everything fits); what is in neither waits for the next pass."""

    send: tuple[Intent, ...]
    folded: tuple[Intent, ...] = ()

    @property
    def emails(self) -> int:
        return len(self.send) + (1 if self.folded else 0)


def urgency(intent: Intent) -> tuple[int, int, int, datetime, tuple[str, str]]:
    """The order the hour's room is given in: severity, new before reminders before ends, then
    the kind, then the oldest subject, then the key (so the order is total and repeatable)."""
    return (
        -rank(intent.severity),
        REASON_ORDER[intent.reason],
        KIND_ORDER[intent.kind],
        intent.first_seen,
        intent.key,
    )


def allocate(intents: Iterable[Intent], room: int) -> Allocation:
    """Give ``room`` e-mails to the due notices, most urgent first. When they all fit they all go
    out; when not, the last e-mail is the "N more" notice that tells all the rest at once."""
    ordered = sorted(intents, key=urgency)
    if room <= 0 or not ordered:
        return Allocation(())
    if len(ordered) <= room:
        return Allocation(tuple(ordered))
    return Allocation(tuple(ordered[: room - 1]), tuple(ordered[room - 1 :]))


def worst(intents: Sequence[Intent]) -> Severity:
    return max((i.severity for i in intents), key=rank)


@dataclass(frozen=True)
class Step:
    """What one pass does about one (kind, subject): its row (None: there is none live), the
    condition (None: it no longer holds), and the decision."""

    key: tuple[str, str]
    row: Row | None
    condition: Condition | None
    decision: Decision


@dataclass(frozen=True)
class Reconciled:
    steps: tuple[Step, ...]
    intents: tuple[Intent, ...]


def reconcile(
    live: Iterable[Row],
    ending_rows: Iterable[Row],
    conditions: Iterable[Condition],
    now: datetime,
    *,
    failed: Iterable[str] = (),
) -> Reconciled:
    """The whole pass, pure. ``live``: the unresolved rows. ``ending_rows``: resolved outages
    announced and not yet ended. ``conditions``: what is true now. ``failed``: kinds whose
    trigger could not be read: their rows are never resolved by this pass (unknown is not
    "fine"). The result lists what to store, and the notices that are due, unordered."""
    unreadable = set(failed)
    rows: dict[tuple[str, str], Row] = {
        (r.kind, r.subject): r for r in live if r.resolved_at is None
    }
    wanted: dict[tuple[str, str], Condition] = {}
    for each in conditions:
        which = (each.kind, each.subject)
        seen = wanted.get(which)
        if seen is None or rank(each.severity) > rank(seen.severity):
            wanted[which] = each
    steps: list[Step] = []
    intents: list[Intent] = []
    for key in sorted(rows.keys() | wanted.keys()):
        row, condition = rows.get(key), wanted.get(key)
        if condition is None and key[0] in unreadable:
            continue
        decision = decide(row, condition, now)
        steps.append(Step(key, row, condition, decision))
        if decision.intent is not None:
            intents.append(decision.intent)
        if decision.store == "resolve" and row is not None:
            done = ending(_resolved(row, now), Target("health"), now)
            if done is not None:
                intents.append(done)
    for row in ending_rows:
        done = ending(row, Target("health"), now)
        if done is not None:
            intents.append(done)
    return Reconciled(tuple(steps), tuple(intents))


def _resolved(row: Row, now: datetime) -> Row:
    return Row(
        row.id, row.kind, row.subject, row.severity, row.count, row.first_seen, row.last_seen,
        now, row.sent_at, row.sent_severity, row.notified, row.ended_at,
    )  # fmt: skip
