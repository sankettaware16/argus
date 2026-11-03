"""Write safety of the Kibana lane: the write classes, their caps and window, and the shared state.

A write is sent only if its class is switched on at the host and not paused, the run verified
Kibana's version and the licence, the SIEM is NORMAL, the time is inside the write window and
outside the quiet hours, the caps hold (case writes per run and day, alert mutations per call, gap
and day) and it has an outbox row, the payload's hash and, for closures, an approval. Nothing here
sends; ``admit_write`` reserves a write's place in the caps atomically.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import date, datetime, time, timedelta
from enum import StrEnum
from types import MappingProxyType

from argus import site


class WriteClass(StrEnum):
    W1 = "W1"  # create; comments; attach representative alerts
    W2 = "W2"  # tags, severity, status, reopen, each with its comment
    W3 = "W3"  # close with reason tags, then the comment
    WA = "WA"  # alert status
    WT = "WT"  # alert tags: off, a separate decision
    WC = "WC"  # the case team: the users' incident case, its files and alert tags


CASE_CLASSES = frozenset({WriteClass.W1, WriteClass.W2, WriteClass.W3})
NEEDS_APPROVAL = frozenset({WriteClass.W3})  # closures; compensating writes carry one too
RUN_FRESH = timedelta(minutes=30)  # a run's kibana.status counts this long


@dataclass(frozen=True)
class WriteCaps:
    case_gap: timedelta = timedelta(seconds=3)
    case_per_run: int = 10
    case_per_day: int = 50
    team_per_run: int = 40  # the case team's writes a run (WC): a 500-alert case is ~34 writes
    team_per_day: int = 200  # ... and a day (counted apart from W1-W3's 50): five such cases
    team_alerts_per_call: int = 100  # the case team's attach and tag calls (WC)
    team_alert_gap: timedelta = timedelta(seconds=3)  # the lane's bucket paces; this is a courtesy
    team_alerts_per_day: int = 2_000  # a 500-alert case is 500 attached + 500 tagged
    alerts_per_call: int = 5  # attachments (W1)
    status_per_call: int = 5  # alert status (WA): ``writeback.batch``, at most 100
    alert_gap: timedelta = timedelta(seconds=60)
    alerts_per_day: int = 1_000
    window: tuple[time, time] = (time(2, 30), time(17, 30))  # UTC

    def __post_init__(self) -> None:
        if not self.window[0] < self.window[1]:
            raise ValueError("the write window starts before it ends, within one UTC day")
        if site.quiet_hours().overlaps(*self.window):
            raise ValueError("the write window never reaches into the quiet hours")
        floor = (self.case_per_run, self.case_per_day, self.alerts_per_call, self.alerts_per_day)
        team = (self.team_per_run, self.team_per_day, self.team_alerts_per_call)
        if min(*floor, self.status_per_call, *team, self.team_alerts_per_day) < 1:
            raise ValueError("caps are at least 1")
        if self.team_alerts_per_call > 100:
            raise ValueError("a team attach or tag call names at most 100 alerts")
        if self.status_per_call > 100:
            raise ValueError("a status call names at most 100 alerts")


def in_window(now: datetime, caps: WriteCaps) -> bool:
    """Inside the write window and outside the quiet hours (UTC times only)."""
    if now.utcoffset() != timedelta(0):
        raise ValueError("write times are UTC")
    moment = now.time()
    start, end = caps.window
    return start <= moment < end and not site.in_quiet_hours(now)


def in_quiet_hours(now: datetime) -> bool:
    if now.utcoffset() != timedelta(0):
        raise ValueError("times are UTC")
    return site.in_quiet_hours(now)


MAX_RUNS = 16  # runs whose case writes are remembered (the per-run cap)


@dataclass(frozen=True)
class Counters:
    """Writes of one UTC day, and the case writes of the latest runs (per run, so runs that
    interleave never reset each other's count)."""

    day: date | None = None
    case_writes: int = 0
    team_writes: int = 0  # the case team's (WC), counted apart
    alert_mutations: int = 0
    last_case_write: datetime | None = None
    last_alert_call: datetime | None = None
    runs: tuple[tuple[str, int], ...] = ()  # (run id, case writes), the newest last

    def run_writes(self, run_id: str) -> int:
        return next((n for run, n in self.runs if run == run_id), 0)

    def with_run_write(self, run_id: str) -> tuple[tuple[str, int], ...]:
        others = tuple(item for item in self.runs if item[0] != run_id)
        return (*others, (run_id, self.run_writes(run_id) + 1))[-MAX_RUNS:]


@dataclass(frozen=True)
class KibanaLaneState:
    """Shared by every ARGUS process (one JSON row): Kibana stopped (401; a read's 403) until
    an operator resumes it, the paused classes (a write's 403, a wrong answer) and the
    counters of the caps."""

    stopped: str | None = None  # the reason; None: Kibana work may run
    stopped_at: datetime | None = None
    paused: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    counters: Counters = Counters()

    def is_paused(self, cls: WriteClass) -> bool:
        return cls.value in self.paused


def stop(state: KibanaLaneState, reason: str, now: datetime) -> KibanaLaneState:
    if state.stopped is not None:
        return state  # the first reason stays
    return replace(state, stopped=reason, stopped_at=now)


def pause(state: KibanaLaneState, cls: WriteClass, reason: str) -> KibanaLaneState:
    if cls.value in state.paused:
        return state
    return replace(state, paused=MappingProxyType({**state.paused, cls.value: reason}))


def resume(state: KibanaLaneState, cls: WriteClass | None) -> KibanaLaneState:
    """An operator's resume: of one class, or (None) of Kibana work as a whole."""
    if cls is None:
        return replace(state, stopped=None, stopped_at=None)
    return replace(
        state, paused=MappingProxyType({k: v for k, v in state.paused.items() if k != cls.value})
    )


@dataclass(frozen=True)
class WriteUnits:
    """What one write spends: a case write (W1-W3) and/or alert mutations (WA, attachments)."""

    case_write: bool
    alerts: int = 0


def admit_write(
    state: KibanaLaneState,
    cls: WriteClass,
    units: WriteUnits,
    now: datetime,
    run_id: str,
    caps: WriteCaps,
) -> tuple[str | None, KibanaLaneState]:
    """(None, state with the write counted) or (the refusal's reason, state unchanged). Counts
    a write when it is admitted, before sending: a write that then fails still used its place
    (no resend can hide in a cap)."""
    if state.stopped is not None:
        return "kibana_stopped", state
    if state.is_paused(cls):
        return "class_paused", state
    if not in_window(now, caps):
        return "outside_window", state
    c = state.counters
    if c.day != now.date():
        c = Counters(day=now.date(), last_case_write=c.last_case_write,
                     last_alert_call=c.last_alert_call, runs=c.runs)  # fmt: skip
    team = cls is WriteClass.WC
    if units.alerts < 0 or (not units.case_write and units.alerts == 0):
        return "nothing_to_write", state
    if units.case_write:
        if c.last_case_write is not None and now - c.last_case_write < caps.case_gap:
            return "case_gap", state
        if c.run_writes(run_id) >= (caps.team_per_run if team else caps.case_per_run):
            return "run_cap", state
        if team and c.team_writes >= caps.team_per_day:
            return "case_daily_cap", state
        if not team and c.case_writes >= caps.case_per_day:
            return "case_daily_cap", state
    if units.alerts:
        limit = (
            caps.status_per_call
            if cls is WriteClass.WA
            else caps.team_alerts_per_call
            if team
            else caps.alerts_per_call
        )
        if units.alerts > limit:
            return "alerts_per_call", state
        gap = caps.team_alert_gap if team else caps.alert_gap
        if c.last_alert_call is not None and now - c.last_alert_call < gap:
            return "alert_gap", state
        day = caps.team_alerts_per_day if team else caps.alerts_per_day
        if c.alert_mutations + units.alerts > day:
            return "alert_daily_cap", state
    if units.case_write:
        c = replace(c, case_writes=c.case_writes + (0 if team else 1),
                    team_writes=c.team_writes + (1 if team else 0),
                    runs=c.with_run_write(run_id), last_case_write=now)  # fmt: skip
    if units.alerts:
        c = replace(c, alert_mutations=c.alert_mutations + units.alerts, last_alert_call=now)
    return None, replace(state, counters=c)


# --------------------------------------------------------------------------- JSON form


def _t(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _p(value: object) -> datetime | None:
    return None if value is None else datetime.fromisoformat(str(value))


def to_json(state: KibanaLaneState) -> dict[str, object]:
    c = state.counters
    return {
        "stopped": state.stopped,
        "stopped_at": _t(state.stopped_at),
        "paused": dict(state.paused),
        "counters": {
            "day": None if c.day is None else c.day.isoformat(),
            "case_writes": c.case_writes,
            "team_writes": c.team_writes,
            "alert_mutations": c.alert_mutations,
            "last_case_write": _t(c.last_case_write),
            "last_alert_call": _t(c.last_alert_call),
            "runs": [[run, n] for run, n in c.runs],
        },
    }


def from_json(data: Mapping[str, object]) -> KibanaLaneState:
    if not data:
        return KibanaLaneState()
    c = data["counters"]
    assert isinstance(c, Mapping)
    paused = data["paused"]
    assert isinstance(paused, Mapping)
    day = c["day"]
    runs = c.get("runs", [])
    assert isinstance(runs, list)
    return KibanaLaneState(
        stopped=None if data["stopped"] is None else str(data["stopped"]),
        stopped_at=_p(data["stopped_at"]),
        paused=MappingProxyType({str(k): str(v) for k, v in paused.items()}),
        counters=Counters(
            day=None if day is None else date.fromisoformat(str(day)),
            case_writes=int(str(c["case_writes"])),
            team_writes=int(str(c.get("team_writes", 0))),
            alert_mutations=int(str(c["alert_mutations"])),
            last_case_write=_p(c["last_case_write"]),
            last_alert_call=_p(c["last_alert_call"]),
            runs=tuple((str(run), int(n)) for run, n in runs),
        ),
    )
