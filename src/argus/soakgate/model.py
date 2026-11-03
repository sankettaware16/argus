"""The soak gate's vocabulary: verdicts, checks, lines and the report, and the typed facts each
line is judged from.

A **line** is one numbered line of a phase's exit gate; it holds **checks**, each with a verdict,
the numbers it rests on (with their n) and what is missing when it cannot decide. A line's verdict
is its worst check: ``FAIL`` (measured, outside the limit) > ``PENDING`` (not enough data) >
``OPEN`` (only a person can say) > ``PASS``. Nothing here reads a clock, a database or a file."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

SCHEMA = "soak-gate@1"


class Verdict(StrEnum):
    PASS = "PASS"  # noqa: S105 - a verdict, not a password
    FAIL = "FAIL"
    PENDING = "PENDING"
    OPEN = "OPEN"

    @property
    def severity(self) -> int:
        return _SEVERITY[self]


_SEVERITY = {Verdict.PASS: 0, Verdict.OPEN: 1, Verdict.PENDING: 2, Verdict.FAIL: 3}


def worst(verdicts: Sequence[Verdict]) -> Verdict:
    """The most serious verdict (an empty line has nothing to show: PENDING)."""
    return max(verdicts, key=lambda v: v.severity, default=Verdict.PENDING)


@dataclass(frozen=True)
class Check:
    """One measurable claim of a line. ``n`` is the count the claim rests on (None: not a rate);
    ``measured`` holds the numbers (JSON-safe); ``needs`` says what a PENDING or OPEN check
    lacks."""

    id: str
    title: str
    verdict: Verdict
    detail: str
    n: int | None = None
    measured: Mapping[str, Any] = field(default_factory=dict)
    needs: str | None = None

    def as_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "verdict": self.verdict.value,
            "n": self.n,
            "detail": self.detail,
            "needs": self.needs,
            "measured": dict(self.measured),
        }


@dataclass(frozen=True)
class Line:
    number: int
    title: str
    checks: tuple[Check, ...]

    @property
    def verdict(self) -> Verdict:
        return worst([c.verdict for c in self.checks])

    def as_json(self) -> dict[str, Any]:
        return {
            "number": self.number,
            "title": self.title,
            "verdict": self.verdict.value,
            "checks": [c.as_json() for c in self.checks],
        }


@dataclass(frozen=True)
class Window:
    since: datetime
    until: datetime

    @property
    def span(self) -> timedelta:
        return self.until - self.since

    def days(self) -> float:
        return self.span.total_seconds() / 86_400


@dataclass(frozen=True)
class Report:
    gate: str  # "phase3"
    generated_at: datetime
    window: Window
    lines: tuple[Line, ...]
    notes: tuple[str, ...] = ()  # things the reader must know (the mirror's gap, a table unread)

    def summary(self) -> dict[str, int]:
        counts = {v.value: 0 for v in Verdict}
        for line in self.lines:
            counts[line.verdict.value] += 1
        return counts

    @property
    def failed(self) -> bool:
        return any(line.verdict is Verdict.FAIL for line in self.lines)

    def as_json(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "gate": self.gate,
            "generated_at": self.generated_at.isoformat(),
            "window": {
                "since": self.window.since.isoformat(),
                "until": self.window.until.isoformat(),
                "days": round(self.window.days(), 3),
            },
            "summary": self.summary(),
            "notes": list(self.notes),
            "lines": [line.as_json() for line in self.lines],
        }


def nearest_rank(values: Sequence[float], q: float) -> float | None:
    """The q-quantile by nearest rank (always a value that was seen); None for no values."""
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(math.ceil(q * len(ordered)) - 1, 0)]


@dataclass(frozen=True)
class Spread:
    """n, max and p95 of some durations in seconds (None where n is 0)."""

    n: int
    max_s: float | None
    p95_s: float | None

    @classmethod
    def of(cls, seconds: Sequence[float]) -> Spread:
        return cls(len(seconds), max(seconds, default=None), nearest_rank(seconds, 0.95))

    def as_json(self) -> dict[str, Any]:
        return {"n": self.n, "max_s": self.max_s, "p95_s": self.p95_s}


def seconds(delta: timedelta) -> float:
    return delta.total_seconds()


def span_text(value: float | None) -> str:
    """Seconds as a short span for a person: 45 s, 12 min, 3.4 h."""
    if value is None:
        return "n/a"
    if value < 90:
        return f"{value:.0f} s"
    if value < 5_400:
        return f"{value / 60:.0f} min"
    return f"{value / 3_600:.1f} h"


def percent(part: int, whole: int) -> str:
    return "n/a" if whole == 0 else f"{100 * part / whole:.1f} %"


@dataclass(frozen=True)
class LifecycleFacts:
    """The case team's posts and steps in the window (``case_team_posts``, ``case_team_steps``)."""

    posts: int
    steps: int
    by_state: Mapping[str, int]
    in_doubt: tuple[str, ...]  # steps in doubt or stuck for more than an hour, as short labels
    creates_sent: int  # steps of kind ``open`` that were sent at least once
    second_creates: tuple[str, ...]  # an ``open`` step sent more than once
    kibana_cases: int  # posts with a Kibana case
    duplicate_cases: tuple[str, ...]  # an ARGUS case with more than one Kibana case
    duplicate_findings: int  # the read-back's ``duplicate_case`` findings in the window


@dataclass(frozen=True)
class OpenedCase:
    """An ARGUS case that has a Kibana case, and the person's confirm that stood before it."""

    number: int
    opened_at: datetime
    confirmed_by_person: bool
    only_confirmed_by_assistant: bool = False  # the confirm is ARGUS's own assistant account's


@dataclass(frozen=True)
class LedgerWrite:
    """One ledger row of a write (a row with a class, or of a case-team template)."""

    at: datetime
    template: str
    write_class: str | None
    outcome: str
    health: str | None  # the gateway's reading when it was sent
    probe_state: str | None  # the newest probe at or before it (within a few minutes), if any
    step_id: int | None  # the case-team step its outbox id names


@dataclass(frozen=True)
class WriteFacts:
    """Every ledger row of class WC (or of the case team) against the steps that were sent."""

    steps_sent: int  # case-team steps with sent_count > 0 whose newest send is in the window
    sends: int  # their sent_count, summed
    rows: tuple[LedgerWrite, ...]
    steps_without_row: tuple[int, ...]  # sent steps with no ledger row (ids)
    rows_without_step: int
    other_class_rows: tuple[tuple[str, int], ...]  # (class, rows) for classes other than WC
    requests_checked: int  # every ledger row of the window (the base of the allowlist check)
    unknown_templates: tuple[tuple[str, int], ...]  # templates outside both allowlists
    window_start: str  # "HH:MM" UTC of the write window (kibana.write_window)
    window_end: str
    cases_posted: int
    verdicts_recorded: int
    cycles_complete: int


@dataclass(frozen=True)
class Confirmed:
    """A person-confirmed true positive: when it was ready to post, and what happened."""

    number: int
    ready_at: datetime  # the confirm, the approval (a canary) and the next write window's start
    created_at: datetime | None  # the Kibana case existed (the create verified)
    completed_at: datetime | None  # every step of the first sequence done
    case_state: str


@dataclass(frozen=True)
class ClosureFacts:
    events: int  # case events of any kind in the window (the base: ARGUS was working)
    closures: int  # closed, dismissed or merged events
    automatic: tuple[str, ...]  # closures with no person as actor, as short labels
    kibana_requests: int  # requests to Kibana in the window (the base for the second claim)
    kibana_closes: tuple[str, ...]  # ledger rows of a close template


@dataclass(frozen=True)
class ReconcileFacts:
    cycles: int
    complete: int
    partial: int
    failed: int
    lags_s: tuple[float, ...]  # people's changes found, in NORMAL cycles
    unexplained: int  # unexplained ARGUS actions or cases, not resolved
    unexplained_resolved: int
    reverts: tuple[str, ...]  # ARGUS wrote to a case after a person changed it
    team_cases: int  # case-team cases with a Kibana case
    team_cases_in_mirror: int


@dataclass(frozen=True)
class NotifiedFacts:
    cases: int  # notified cases in the window
    investigations: int  # their investigations that have a decision row
    undecided: tuple[str, ...]  # activity after the notice, no decision at the current version
    changed: int
    change_lags_s: tuple[float, ...]  # activity -> the change in Needs attention
    pass_s: float  # what "one pass" is: the longest lag that still counts


@dataclass(frozen=True)
class MinuteSpend:
    lane: str
    minute: datetime
    took_ms: int
    requests: int
    largest_ms: int = 0  # the costliest request of the minute (a bucket admits on an estimate)


@dataclass(frozen=True)
class DaySpend:
    lane: str
    day: str  # ISO date (UTC)
    took_ms: int
    requests: int
    heavy: int


@dataclass(frozen=True)
class LaneLimit:
    lane: str
    per_minute_ms: int
    burst_ms: int
    per_day_ms: int
    heavy_per_day: int


@dataclass(frozen=True)
class CautionMove:
    at: datetime
    to_state: str
    requests_before: int  # ARGUS requests in the minute before
    took_before_ms: int


@dataclass(frozen=True)
class LoadFacts:
    limits: tuple[LaneLimit, ...]
    ceiling: LaneLimit  # lane "total": the ceiling per minute, burst, day and heavy a day
    minutes: tuple[MinuteSpend, ...]
    days: tuple[DaySpend, ...]
    probes: int
    moves: tuple[CautionMove, ...]
    signin_per_day: Mapping[str, int]  # requests of the sign-ins template by UTC day
    signin_server_ms: int
    signin_gap_breaches: int  # two sign-in requests closer than signins.gap
    signin_gap_s: float
    signin_steady_per_day: int  # expected steady requests a day
    signin_backfill_extra: int


@dataclass(frozen=True)
class Lookup:
    day: str
    looked_at: datetime
    complete: bool
    reason: str | None
    store_failures: int


@dataclass(frozen=True)
class SigninFacts:
    lookups: tuple[Lookup, ...]
    now: datetime
    retention_days: int
    retry_after_s: float
    backoff_s: Mapping[str, float]
    terminal_reasons: frozenset[str]
    max_store_failures: int
    grace_s: float


@dataclass(frozen=True)
class SweepFacts:
    """The newest stored result of ``scripts/privacy_sweep.py`` (None: there is none)."""

    path: str | None
    at: datetime | None
    leaks: int | None
    signin_name_leaks: int | None
    signin_names_checked: int | None
    dossiers: int | None


@dataclass(frozen=True)
class AnalysisFacts:
    labelled: int  # proposals a person's verdict can check
    wrong_benign: int  # benign proposals on a true positive
    gold_answered: int  # the gold set's answered items (0: none yet)
    cost_days: Mapping[str, float]  # UTC day -> USD
    cost_month_usd: float
    daily_cap_usd: float | None
    monthly_cap_usd: float | None
    finished: int  # assessments finished in the window
    inconclusive: int


@dataclass(frozen=True)
class BackupFacts:
    dumps: tuple[datetime, ...]  # nightly manifests created in the window
    dump_due: tuple[datetime, ...]  # the nightly dump times that fell in the window
    drills: tuple[tuple[datetime, bool], ...]  # (at, passed) in the window
    drill_due: tuple[datetime, ...]
    newest_dump: datetime | None
    grace_s: float
    readable: bool  # the backup folder could be read


@dataclass(frozen=True)
class HealthFacts:
    samples: int
    newest_sample: datetime | None
    gaps: tuple[str, ...]  # spans without a sample (a sample every 15 minutes)
    now: datetime
    stale_s: float
