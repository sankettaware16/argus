"""Facts for the soak gate's judges: each builder returns facts that PASS, and a test changes the
one thing it is about."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from argus.soakgate.model import (
    AnalysisFacts,
    BackupFacts,
    CautionMove,
    ClosureFacts,
    Confirmed,
    DaySpend,
    HealthFacts,
    LaneLimit,
    LedgerWrite,
    LifecycleFacts,
    LoadFacts,
    Lookup,
    MinuteSpend,
    NotifiedFacts,
    OpenedCase,
    ReconcileFacts,
    SigninFacts,
    SweepFacts,
    WriteFacts,
)

T0 = datetime(2026, 10, 31, 8, 0, tzinfo=UTC)  # inside the write window
NOW = datetime(2026, 11, 2, 6, 30, tzinfo=UTC)  # a Monday


def lifecycle(**kw: Any) -> LifecycleFacts:
    base: dict[str, Any] = {
        "posts": 3,
        "steps": 30,
        "by_state": {"verified": 30},
        "in_doubt": (),
        "creates_sent": 3,
        "second_creates": (),
        "kibana_cases": 3,
        "duplicate_cases": (),
        "duplicate_findings": 0,
    }
    return LifecycleFacts(**{**base, **kw})


def opened(number: int = 1, *, person: bool = True, assistant: bool = False) -> OpenedCase:
    return OpenedCase(number, T0, person, assistant)


def row(minutes: int = 0, **kw: Any) -> LedgerWrite:
    base: dict[str, Any] = {
        "at": T0 + timedelta(minutes=minutes),
        "template": "team.comment",
        "write_class": "WC",
        "outcome": "ok",
        "health": "normal",
        "probe_state": "normal",
        "step_id": 1,
    }
    return LedgerWrite(**{**base, **kw})


def writes(**kw: Any) -> WriteFacts:
    base: dict[str, Any] = {
        "steps_sent": 2,
        "sends": 2,
        "rows": (row(0, step_id=1), row(1, step_id=2)),
        "steps_without_row": (),
        "rows_without_step": 0,
        "other_class_rows": (),
        "requests_checked": 50,
        "unknown_templates": (),
        "window_start": "02:30",
        "window_end": "17:30",
        "cases_posted": 3,
        "verdicts_recorded": 1,
        "cycles_complete": 20,
    }
    return WriteFacts(**{**base, **kw})


def confirmed(number: int = 1, *, created: int | None = 5, done: int | None = 40) -> Confirmed:
    return Confirmed(
        number,
        T0,
        None if created is None else T0 + timedelta(minutes=created),
        None if done is None else T0 + timedelta(minutes=done),
        "open",
    )


def closures(**kw: Any) -> ClosureFacts:
    base: dict[str, Any] = {
        "events": 40,
        "closures": 2,
        "automatic": (),
        "kibana_requests": 100,
        "kibana_closes": (),
    }
    return ClosureFacts(**{**base, **kw})


def reconcile(**kw: Any) -> ReconcileFacts:
    base: dict[str, Any] = {
        "cycles": 30,
        "complete": 30,
        "partial": 0,
        "failed": 0,
        "lags_s": (30.0, 90.0, 120.0),
        "unexplained": 0,
        "unexplained_resolved": 0,
        "reverts": (),
        "team_cases": 3,
        "team_cases_in_mirror": 3,
    }
    return ReconcileFacts(**{**base, **kw})


def notified(**kw: Any) -> NotifiedFacts:
    base: dict[str, Any] = {
        "cases": 2,
        "investigations": 10,
        "undecided": (),
        "changed": 2,
        "change_lags_s": (60.0, 120.0),
        "pass_s": 900.0,
    }
    return NotifiedFacts(**{**base, **kw})


LANES = (
    LaneLimit("collector", 1_800, 1_800, 2_400_000, 1_600),
    LaneLimit("investigation", 400, 400, 360_000, 300),
    LaneLimit("freshness", 100, 100, 180_000, 0),
    LaneLimit("kibana_read", 200, 200, 240_000, 0),
    LaneLimit("kibana_write", 200, 200, 180_000, 0),
    LaneLimit("identity", 300, 300, 120_000, 0),
    LaneLimit("measurement", 0, 0, 120_000, 100),
)
CEILING = LaneLimit("total", 3_000, 3_000, 3_600_000, 2_000)


def load(**kw: Any) -> LoadFacts:
    base: dict[str, Any] = {
        "limits": LANES,
        "ceiling": CEILING,
        "minutes": (
            MinuteSpend("collector", T0, 1_000, 10),
            MinuteSpend("investigation", T0, 300, 2),
        ),
        "days": (
            DaySpend("collector", "2026-10-31", 600_000, 3_000, 100),
            DaySpend("investigation", "2026-10-31", 60_000, 200, 50),
        ),
        "probes": 1_000,
        "moves": (),
        "signin_per_day": {"2026-10-31": 20},
        "signin_server_ms": 30_000,
        "signin_gap_breaches": 0,
        "signin_gap_s": 3.0,
        "signin_steady_per_day": 27,
        "signin_backfill_extra": 14,
    }
    return LoadFacts(**{**base, **kw})


def lookup(
    day: str = "2026-10-31",
    *,
    complete: bool = True,
    reason: str | None = None,
    ago_h: float = 1.0,
    failures: int = 0,
) -> Lookup:
    return Lookup(day, NOW - timedelta(hours=ago_h), complete, reason, failures)


def signins(*lookups: Lookup, **kw: Any) -> SigninFacts:
    base: dict[str, Any] = {
        "lookups": lookups or (lookup(),),
        "now": NOW,
        "retention_days": 5,
        "retry_after_s": 1_800.0,
        "backoff_s": {"store_failed": 21_600.0, "index_missing": 21_600.0},
        "terminal_reasons": frozenset({"logs_gone"}),
        "max_store_failures": 3,
        "grace_s": 10_800.0,
    }
    return SigninFacts(**{**base, **kw})


def sweep(**kw: Any) -> SweepFacts:
    base: dict[str, Any] = {
        "path": "data/gate/p1/x/sweep.json",
        "at": NOW - timedelta(hours=2),
        "leaks": 0,
        "signin_name_leaks": 0,
        "signin_names_checked": 40,
        "dossiers": 500,
    }
    return SweepFacts(**{**base, **kw})


def analysis(**kw: Any) -> AnalysisFacts:
    base: dict[str, Any] = {
        "labelled": 20,
        "wrong_benign": 0,
        "gold_answered": 100,
        "cost_days": {"2026-10-31": 0.2},
        "cost_month_usd": 3.0,
        "daily_cap_usd": 1.5,
        "monthly_cap_usd": 40.0,
        "finished": 50,
        "inconclusive": 5,
    }
    return AnalysisFacts(**{**base, **kw})


def health(**kw: Any) -> HealthFacts:
    base: dict[str, Any] = {
        "samples": 90,
        "newest_sample": NOW - timedelta(minutes=10),
        "gaps": (),
        "now": NOW,
        "stale_s": 2_700.0,
    }
    return HealthFacts(**{**base, **kw})


def backups(**kw: Any) -> BackupFacts:
    dump = datetime(2026, 10, 31, 21, 30, tzinfo=UTC)
    drill = datetime(2026, 11, 1, 22, 0, tzinfo=UTC)
    base: dict[str, Any] = {
        "dumps": (dump + timedelta(minutes=2),),
        "dump_due": (dump,),
        "drills": ((drill, True),),
        "drill_due": (drill,),
        "newest_dump": dump,
        "grace_s": 10_800.0,
        "readable": True,
    }
    return BackupFacts(**{**base, **kw})


def move(*, requests: int = 5, took: int = 500) -> CautionMove:
    return CautionMove(T0, "caution", requests, took)
