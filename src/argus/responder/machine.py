"""The states of an action and the verdict on a person's "done": pure rules. ``recommended`` ->
``requested`` -> ``reported_done`` -> ``verified``, or ``not_verified`` with the reason and the
last sign of activity. A person's *requested* and *reported done* are attestations (ARGUS cannot
see the action); *verified* is ARGUS's own, only from evidence it holds and never while coverage
is unknown (:func:`verify_watch`; :func:`verify_paths` accepts a positive answer, never a zero).
The rules read no clock, database or network."""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Literal

from argus import site
from argus.cases import watch
from argus.cases.model import QuietWindow
from argus.context import paths as web_paths

Code = Literal["forbidden", "conflict", "invalid", "unavailable", "not_found"]
State = Literal["recommended", "requested", "reported_done", "verified", "not_verified"]
STATES: tuple[State, ...] = (
    "recommended", "requested", "reported_done", "verified", "not_verified",
)  # fmt: skip
ATTESTATION_MAX = 500

# From -> to, and who may make the move (the database's guard holds the same edges).
PERSON_EDGES: Mapping[State | None, frozenset[State]] = {
    None: frozenset({"requested", "reported_done"}),
    "recommended": frozenset({"requested", "reported_done"}),
    "requested": frozenset({"reported_done"}),
    "not_verified": frozenset({"reported_done"}),  # a person tried again
}
ARGUS_EDGES: Mapping[State | None, frozenset[State]] = {
    None: frozenset({"recommended"}),
    "reported_done": frozenset({"verified", "not_verified"}),
    "verified": frozenset({"not_verified"}),  # activity came back
    "not_verified": frozenset({"not_verified"}),  # a newer reason or beat
}

# What "still active" means for each verifier: (the words, the label of the last sign).
STILL: Mapping[str, tuple[str, str]] = {
    "proxy.contact": ("still beaconing", "last beat"),
    "alerts": ("still raising alerts", "last alert"),
    "web.path_outcomes": ("still being served", "last seen by the check of"),
}


class ActionRefused(Exception):  # noqa: N818 - a refusal, not an error
    """A move the rules do not allow, with a code the callers map (``invalid``, ``forbidden``,
    ``conflict``) and the words for a person."""

    def __init__(self, code: Code, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def move(current: State | None, to: State, *, person: bool) -> State:
    """``to`` if ``current`` may become it by a person (``person``) or by ARGUS; else refused."""
    edges = (PERSON_EDGES if person else ARGUS_EDGES).get(current, frozenset())
    if to in edges:
        return to
    who = "a person" if person else "ARGUS"
    if current is None:
        raise ActionRefused("conflict", f"{who} cannot start an action as {to}")
    raise ActionRefused("conflict", f"{who} cannot move an action from {current} to {to}")


def attest(text: str) -> str:
    """A person's words for "done": 1 to 500 printable characters (control characters are
    refused, not repaired)."""
    said = " ".join(text.split())
    if not said:
        raise ActionRefused("invalid", "say what was done (the attestation is required)")
    if len(said) > ATTESTATION_MAX:
        raise ActionRefused("invalid", f"the attestation is at most {ATTESTATION_MAX} characters")
    if any(not c.isprintable() for c in said):
        raise ActionRefused("invalid", "the attestation holds a character that cannot be shown")
    return said


UNREADABLE = "an unreadable time"


def ist12(moment: datetime) -> str:
    """``1:52 PM IST on 26 Oct 2026`` (people read the site's zone, 12-hour). Never raises: a
    time that cannot be shown (a source clock near the year 9999) reads "an unreadable time"."""
    try:
        local = moment.astimezone(site.zone())
        hour = local.hour % 12 or 12
        label = site.zone_label(local)
        return f"{hour}:{local:%M} {'AM' if local.hour < 12 else 'PM'} {label} on {local:%d %b %Y}"
    except (OverflowError, ValueError, OSError):
        return UNREADABLE


def ist_day(moment: datetime) -> str:
    """``26 Oct 2026`` in the site's zone; "an unreadable time" like :func:`ist12`."""
    try:
        return f"{moment.astimezone(site.zone()):%d %b %Y}"
    except (OverflowError, ValueError, OSError):
        return UNREADABLE


# --------------------------------------------------------------------------- the verdict


@dataclass(frozen=True)
class Verdict:
    """``verified``; ``not_verified`` (activity after the action: ``last`` is the newest sign);
    ``waiting`` (not enough evidence yet); ``not_verifiable`` (the catalogue says no check can
    tell)."""

    kind: Literal["verified", "not_verified", "waiting", "not_verifiable"]
    reason: str
    last: datetime | None = None


def not_verifiable(reason: str) -> Verdict:
    return Verdict("not_verifiable", f"not verifiable in Phase 3: {reason}")


def say(verdict: Verdict, kind: str) -> str:
    """The verdict as people read it, for the verifier ``kind``."""
    if verdict.kind != "not_verified":
        return verdict.reason
    words, label = STILL.get(kind, ("still active", "last sign"))
    if verdict.last is None:
        return f"not verified: {words}"
    return f"not verified: {words}, {label} {ist12(verdict.last)}"


def _last(detail: Mapping[str, object]) -> datetime | None:
    raw = detail.get("last")
    if not isinstance(raw, str):
        return None
    try:
        moment = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return moment if moment.tzinfo is not None else None


def activity_after(
    rows: Iterable[watch.Row],
    activity: Mapping[date, tuple[int, datetime]],
    done_at: datetime,
    *,
    sources: Collection[str],
) -> tuple[bool, datetime | None]:
    """(whether the case was active after ``done_at``, the newest sign of it we can date).
    Stored ``active`` answers of the given watch sources, and ARGUS's own alerts per UTC day
    (``activity``, as the database holds them now). The action's own day counts only for a
    sign later than the action: the same day's earlier beats were before it."""
    done_day = watch.utc_day(done_at)
    seen = False
    newest: datetime | None = None

    def note(day: date, last: datetime | None) -> None:
        nonlocal seen, newest
        if day < done_day:
            return
        if day == done_day and last is not None and last <= done_at:
            return
        seen = True
        if last is not None and (newest is None or last > newest):
            newest = last

    for row in rows:
        if row.outcome == "active" and row.source in sources:
            note(row.day, _last(row.detail))
    if watch.ALERTS in sources:
        for day, (_, last) in activity.items():
            note(day, last)
    return seen, newest


def gate_watch(
    kind: str,
    rows: Sequence[watch.Row],
    activity: Mapping[date, tuple[int, datetime]],
    listed: bool,
    done_at: datetime,
    now: datetime,
) -> Verdict | None:
    """What can be said before asking whether the case was quiet: activity after the action
    (*not verified*), the whole days that must pass first, and the proxy addresses that cannot
    be listed (``listed`` False) so the proxy logs cannot vouch. None: only the quiet window
    can still decide. ``kind``: ``proxy.contact`` (the proxy logs and ARGUS's alerts) or
    ``alerts`` (alerts only)."""
    sources = {watch.ALERTS} if kind == "alerts" else {watch.ALERTS, watch.CONTACT}
    seen, last = activity_after(rows, activity, done_at, sources=sources)
    if seen:
        words, _ = STILL[kind]
        return Verdict("not_verified", words, last)
    today = watch.utc_day(now)
    done_day = watch.utc_day(done_at)
    first_check = done_day + timedelta(days=watch.QUIET_DAYS + 1)
    if today < first_check:
        return Verdict(
            "waiting",
            f"waiting: {watch.QUIET_DAYS} whole UTC days must pass after the action"
            f" ({done_day}); the first check that can verify it is on {first_check}",
        )
    if kind != "alerts" and not listed:
        return Verdict(
            "waiting", "waiting: the case's addresses cannot be listed here, so the proxy logs "
            "cannot vouch for it",
        )  # fmt: skip
    return None


def window_verdict(window: QuietWindow) -> Verdict:
    """The verdict a quiet window (the watch's own) gives once :func:`gate_watch` let it decide."""
    if window.verified:
        return Verdict("verified", f"verified: {window.reason}"[:300])
    return Verdict("waiting", f"waiting: {window.reason}"[:300])


def verify_watch(
    kind: str,
    rows: Sequence[watch.Row],
    activity: Mapping[date, tuple[int, datetime]],
    wanted: Sequence[watch.Subject] | None,
    done_at: datetime,
    now: datetime,
    *,
    zeros_on: bool,
    blocked: str | None = None,
) -> Verdict:
    """Whether the case went quiet after ``done_at``, from the watch's answers (pure).
    ``wanted``: the case's checkable addresses (:func:`argus.cases.watch.subjects`), or None when
    the caller cannot list them, which makes "verified" impossible for the proxy logs.
    ``activity``: ARGUS's own alerts per UTC day now. The store does not call this: it asks the
    watch's finder (:class:`argus.cases.watchrun.Finder`) and turns its window into a verdict with
    :func:`gate_watch` and :func:`window_verdict`."""
    gate = gate_watch(kind, rows, activity, wanted is not None, done_at, now)
    if gate is not None:
        return gate
    window = watch.quiet_window(
        rows,
        () if kind == "alerts" else wanted or (),
        watch.utc_day(now),
        zeros_on=True if kind == "alerts" else zeros_on,
        alert_days={d for d in activity if d >= watch.utc_day(done_at)},
        blocked=blocked,
    )
    return window_verdict(window)


@dataclass(frozen=True)
class PathReading:
    """One stored ``web.path_outcomes`` answer: when it was asked, the first moment its window
    reads, and each path's outcome (:mod:`argus.context.paths`)."""

    asked_at: datetime
    start: datetime
    outcomes: Mapping[str, str]


def verify_paths(
    required: frozenset[str], readings: Sequence[PathReading], done_at: datetime
) -> Verdict:
    """Whether every path that was served is now refused. Only a reading whose window starts
    after the action counts, and only for the newest such reading of each path: a request the
    site answered but never with a 2xx (``refused``) is positive evidence; no logged request
    is not (a zero from the logs alone is never "removed")."""
    if not required:
        return Verdict("waiting", "waiting: no served path is known for this case")
    newest: dict[str, tuple[datetime, str]] = {}
    for reading in readings:
        if reading.start < done_at:
            continue
        for path in required & set(reading.outcomes):
            if path not in newest or reading.asked_at > newest[path][0]:
                newest[path] = (reading.asked_at, reading.outcomes[path])
    served = {p: at for p, (at, outcome) in newest.items() if outcome == web_paths.SUCCESS}
    if served:
        words, _ = STILL["web.path_outcomes"]
        return Verdict("not_verified", words, max(served.values()))
    unanswered = sorted(required - {p for p, (_, o) in newest.items() if o == web_paths.REFUSED})
    if not unanswered:
        return Verdict(
            "verified", "verified: the site refused every path that was served, in a check made"
            " after the action",
        )  # fmt: skip
    if not newest:
        return Verdict(
            "waiting", "waiting: no check of the web server's answers was made after the action"
        )
    return Verdict(
        "waiting",
        f"waiting: {len(unanswered)} of {len(required)} paths have no logged refusal after the"
        " action yet (no request, or an answer ARGUS cannot compare, is not proof)",
    )


def settle(stored: State, verdict: Verdict) -> State:
    """The state to show (and, when ARGUS refreshes the record, to store) for an action stored
    as ``stored`` given the newest verdict. Only a definite verdict changes it."""
    if stored == "reported_done":
        if verdict.kind == "verified":
            return "verified"
        if verdict.kind == "not_verified":
            return "not_verified"
    elif stored == "verified" and verdict.kind == "not_verified":
        return "not_verified"
    return stored
