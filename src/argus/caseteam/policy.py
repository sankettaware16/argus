"""When a case is posted to Kibana (AR8, D-195): one pure function, so the rule is the same in the
pass, the preview, the API and the tests.

1. **Posting is off by default** (``case_team.post``): then nothing is written to the SIEM, whatever
   else is true; the decision still says what it would do (a dry run).
2. **A case is opened** when (a) a person confirmed its report in ARGUS **and the outcome they
   confirmed is a true positive and the confirm is on the newest report version** (a benign or
   inconclusive confirm never opens a case, and a report that changed since needs a new
   confirm; a newer version that differs only in the accounts section, ``core`` equal, is the
   same report to the person, D-225), or (b) ARGUS's own verdict is a true positive with a
   confidence of at least ``auto_min_confidence`` and the case is suggested or open. A person's
   rejection stops both.
   At most ``per_day`` cases a day (IST).
   A case already in Kibana is never opened again: a newer report is an *update*, as new
   comments (D-195 point 4); a notified case (AR4b) that has not changed since the notice is
   never posted again, and one that did change is posted as a new comment on the existing case.
3. **The canary:** the first ``canary`` cases need a person's approval of that case before
   anything is sent.
4. **A sequence that was started is finished** (resumed) whatever the caps say: half a case is
   worse than an extra one, and the caps and the approval already let it begin.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from argus.incident import model as m

OPENABLE = ("suspected", "open", "assigned")  # suggested or open (AR2b, AR4)
UPDATABLE = ("suspected", "open", "assigned", "contained")
Action = Literal["none", "open", "update", "resume"]
Person = Literal["confirmed", "rejected"]


@dataclass(frozen=True)
class Facts:
    """What the decision reads, all of it already known to the caller."""

    post: bool
    case_state: str
    report: m.IncidentReport | None
    version: int | None
    person: Person | None  # the newest decision a person made on any version of the report
    open_done: bool  # the Kibana case exists and its opening generation is complete
    last_version: int | None  # the report version the newest finished generation posted
    last_round_at: datetime | None
    in_progress: bool  # a generation was started and is not finished
    opened_today: int  # cases opened today (IST) by the case team
    opened_total: int  # cases ever opened
    approved: bool  # a valid approval of exactly the plan generation 1 would be
    has_news: bool  # an update plan would hold at least one step
    now: datetime
    auto_min_confidence: float
    per_day: int
    canary: int
    min_update_gap: timedelta
    person_outcome: str | None = None  # the outcome that decision confirmed (or holds instead)
    person_version: int | None = None  # the report version that decision was made on
    core: str | None = None  # the newest report's hash without its accounts (D-225)
    person_core: str | None = None  # the same for the report version that decision was made on
    auto: bool = True  # ARGUS's own verdict may open a case (``case_team.auto``)
    edits_only: bool = False  # the update plan only corrects the title (D-236): no new round


@dataclass(frozen=True)
class Decision:
    action: Action
    why: str
    route: str | None = None  # how the case qualified: "a person confirmed it" / "ARGUS's verdict"
    needs_approval: bool = False
    dry_run: bool = False  # it would act, but case_team.post is off
    would: Action = "none"  # what a dry run would do

    @property
    def acts(self) -> bool:
        return self.action != "none"


def person_route(f: Facts) -> str | None:
    """A person's confirm of a true positive opens a case while the newest report still says true
    positive (D-229). A confirm puts the person's verdict into the report, and an ongoing case gets
    new alerts and evidence: both make new versions, which reach Kibana as updates, never as a
    reason to confirm again. A newer verdict that is not a true positive, or a rejection, needs a
    person again. Benign and inconclusive confirms never open one."""
    if f.person != "confirmed" or f.person_outcome != "true_positive":
        return None
    if f.report is not None and f.report.verdict.outcome == "true_positive":
        return "a person confirmed the report"
    return None


def same_core(f: Facts) -> bool:
    """Whether the confirmed version and the newest differ only in their accounts."""
    return f.core is not None and f.core == f.person_core


def route_of(f: Facts) -> str | None:
    """How a case that is not in Kibana yet qualifies to be opened, or None."""
    if f.report is None or f.person == "rejected" or f.case_state not in OPENABLE:
        return None
    via_person = person_route(f)
    if via_person is not None:
        return via_person
    v = f.report.verdict
    if (
        f.auto
        and v.outcome == "true_positive"
        and v.kind in ("person", "proposal", "case")
        and v.confidence is not None
        and v.confidence >= f.auto_min_confidence
    ):
        return f"ARGUS's verdict is a true positive ({v.confidence:.2f})"
    return None


def _waiting(f: Facts) -> str:
    """Why a case that cannot be opened yet waits, in words (never a promise it will open)."""
    assert f.report is not None
    v = f.report.verdict
    if f.person == "confirmed":
        if f.person_outcome != "true_positive":
            return (
                "a person confirmed a verdict that is not a true positive: no Kibana case is"
                " opened for it"
            )
        return (
            f"the newest report (version {f.version}) no longer says true positive: a person"
            " confirms it again"
        )
    if not f.auto:
        return "waiting for a person to confirm the report (only a person's confirm opens a case)"
    if (
        v.outcome == "true_positive"
        and v.kind in ("person", "proposal", "case")
        and v.confidence is not None
    ):
        return (
            f"waiting for a person to confirm the report (ARGUS's confidence"
            f" {v.confidence:.2f} is under {f.auto_min_confidence:.2f})"
        )
    return "waiting for a person to confirm the report"


def decide(f: Facts) -> Decision:
    """What to do with a case now (point 1 is applied last, so a dry run shows the rest)."""
    if f.report is None or f.version is None:
        return Decision("none", "ARGUS has not written this case's report yet")
    if f.in_progress:
        return _gate(f, Decision("resume", "a sequence was started and is finished first"))
    if f.open_done:
        return _gate(f, _update(f))
    if f.person == "rejected":
        return Decision("none", "a person rejected the report")
    route = route_of(f)
    if route is None:
        if f.case_state not in OPENABLE:
            return Decision("none", f"the case is {f.case_state}: only suggested or open cases")
        return Decision("none", _waiting(f))
    if f.opened_today >= f.per_day:
        return Decision("none", f"today's limit of {f.per_day} cases is reached", route)
    need = f.opened_total < f.canary
    if need and not f.approved:
        waiting = "waiting for a person's approval of this case (canary)"
        return _gate(f, Decision("none", waiting, route, True, would="open"))
    return _gate(f, Decision("open", "ready to open", route, need))


def _update(f: Facts) -> Decision:
    assert f.report is not None
    assert f.version is not None
    if f.case_state not in UPDATABLE:
        return Decision("none", f"the case is {f.case_state}: nothing more is posted")
    if f.person == "rejected":
        return Decision("none", "a person rejected the report")
    if f.last_version is not None and f.version <= f.last_version:
        return Decision("none", f"nothing new since version {f.last_version}")
    notice = f.report.summary.notice
    if notice is not None and notice.changes <= 0 and not f.edits_only:
        return Decision("none", "owner notified and unchanged since the notice: not posted again")
    if (
        f.last_round_at is not None
        and f.now - f.last_round_at < f.min_update_gap
        and not f.edits_only
    ):
        return Decision("none", "an update was posted a short while ago")
    if not f.has_news:
        return Decision("none", "the newer report holds nothing new for the case")
    why = "changed since the notice" if notice is not None else f"report version {f.version} is new"
    return Decision("update", why)


def _gate(f: Facts, d: Decision) -> Decision:
    """Point 1: with posting off, an action (or a wait for the canary's approval, which would
    lead to one) is only a dry run: it says what it would do and writes nothing."""
    would = d.action if d.acts else d.would
    if f.post or would == "none":
        return d
    why = "case_team.post is off: this is a dry run"
    if not d.acts:
        why += f" ({d.why})"
    return Decision("none", why, d.route, d.needs_approval, True, would)
