"""The soak gate's judges: each line of the exit gate as a pure function from typed facts to checks
(no clock, database or file, so every verdict is reproducible). **A rate has its n**: a check
whose claim rests on a count of zero cannot pass, it is PENDING with what is missing. **Only
measured limits fail**: a claim the store cannot show is OPEN, with where a person looks."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, time, timedelta
from typing import Any

from argus.gateway.kibana.writes import WriteCaps, in_window
from argus.soakgate.model import (
    AnalysisFacts,
    BackupFacts,
    Check,
    ClosureFacts,
    Confirmed,
    HealthFacts,
    LifecycleFacts,
    LoadFacts,
    NotifiedFacts,
    OpenedCase,
    ReconcileFacts,
    SigninFacts,
    Spread,
    SweepFacts,
    Verdict,
    WriteFacts,
    nearest_rank,
    percent,
    span_text,
)

# the gate's own numbers
MIN_CASES_POSTED = 3
MIN_VERDICTS = 1
MIN_CYCLES = 20
COVERAGE_LIMIT = timedelta(minutes=15)
LAG_LIMIT_S = 900.0  # a person's change appears within 15 minutes (p95, NORMAL)
IN_DOUBT_AFTER = timedelta(hours=1)
CASE_NUMBERS_SHOWN = 8

PASS, FAIL, PENDING, OPEN = Verdict.PASS, Verdict.FAIL, Verdict.PENDING, Verdict.OPEN


def _check(
    ident: str,
    title: str,
    verdict: Verdict,
    detail: str,
    *,
    n: int | None = None,
    measured: Mapping[str, Any] | None = None,
    needs: str | None = None,
) -> Check:
    return Check(ident, title, verdict, detail, n, measured or {}, needs)


def _pending(ident: str, title: str, needs: str, **measured: Any) -> Check:
    return _check(
        ident, title, PENDING, f"not measured yet: {needs}", n=0, measured=measured, needs=needs
    )


def _named(items: Sequence[str], shown: int = CASE_NUMBERS_SHOWN) -> str:
    head = ", ".join(items[:shown])
    return head if len(items) <= shown else f"{head} and {len(items) - shown} more"


def judge_lifecycle(f: LifecycleFacts) -> list[Check]:
    """1. Every step of every post verified or decided by a person; 0 steps in doubt older than an
    hour; 0 second creates sent automatically; 0 duplicate Kibana cases."""
    title = "Every step verified or decided by a person"
    by = dict(f.by_state)
    measured = {
        "posts": f.posts,
        "steps": f.steps,
        "by_state": by,
        "in_doubt_over_1h": len(f.in_doubt),
    }
    if f.steps == 0:
        steps = _pending("1a", title, "a case posted in the window (no step yet)", **measured)
    else:
        waiting = sum(by.get(s, 0) for s in ("planned", "held", "sending", "sent"))
        detail = (
            f"{by.get('verified', 0)} of {f.steps} steps verified, {by.get('skipped', 0)} skipped"
            f" and {by.get('superseded', 0)} superseded by a person or a newer round, {waiting}"
            f" still on their way, {len(f.in_doubt)} in doubt for over an hour"
        )
        if f.in_doubt:
            detail += f" ({_named(f.in_doubt)})"
        steps = _check(
            "1a", title, FAIL if f.in_doubt else PASS, detail, n=f.steps, measured=measured
        )

    title = "No second create sent"
    if f.creates_sent == 0:
        second = _pending("1b", title, "a create sent in the window", creates_sent=0)
    else:
        second = _check(
            "1b",
            title,
            FAIL if f.second_creates else PASS,
            f"{len(f.second_creates)} second creates among {f.creates_sent} creates sent"
            + (
                f" ({_named(f.second_creates)}; if a person decided it, the journal says so)"
                if f.second_creates
                else ""
            ),
            n=f.creates_sent,
            measured={"creates_sent": f.creates_sent, "second_creates": len(f.second_creates)},
        )

    title = "No duplicate Kibana case for an ARGUS case"
    if f.kibana_cases == 0:
        duplicate = _pending("1c", title, "a Kibana case opened in the window", kibana_cases=0)
    else:
        bad = bool(f.duplicate_cases) or f.duplicate_findings > 0
        duplicate = _check(
            "1c",
            title,
            FAIL if bad else PASS,
            f"{len(f.duplicate_cases)} ARGUS cases with more than one Kibana case and"
            f" {f.duplicate_findings} duplicate findings among {f.kibana_cases} Kibana cases"
            + (f" ({_named(f.duplicate_cases)})" if f.duplicate_cases else ""),
            n=f.kibana_cases,
            measured={
                "kibana_cases": f.kibana_cases,
                "duplicate_cases": len(f.duplicate_cases),
                "duplicate_findings": f.duplicate_findings,
            },
        )
    return [steps, second, duplicate]


def judge_person_only(opened: Sequence[OpenedCase]) -> list[Check]:
    """2. 0 Kibana cases opened without a person's confirm of a true positive."""
    title = "Every Kibana case follows a person's confirm of a true positive"
    if not opened:
        return [_pending("2a", title, "a Kibana case opened in the window")]
    bad = [c for c in opened if not c.confirmed_by_person]
    assistant = [c for c in bad if c.only_confirmed_by_assistant]
    detail = f"{len(opened) - len(bad)} of {len(opened)} Kibana cases had a person's confirm first"
    if bad:
        detail += f"; without one: case {_named([str(c.number) for c in bad])}"
    if assistant:
        detail += f" ({len(assistant)} confirmed only by ARGUS's own assistant account)"
    return [
        _check(
            "2a",
            title,
            FAIL if bad else PASS,
            detail,
            n=len(opened),
            measured={"cases": len(opened), "without_person_confirm": len(bad)},
        )
    ]


def _write_window(f: WriteFacts) -> WriteCaps:
    start = time.fromisoformat(f.window_start)
    end = time.fromisoformat(f.window_end)
    return WriteCaps(window=(start, end))


def judge_writes(f: WriteFacts) -> list[Check]:
    """3. Every production write has its step and ledger row; 0 requests outside the allowlist;
    0 writes outside NORMAL, the window or class WC; the minimum counts."""
    out: list[Check] = []
    title = "Every sent step has a ledger row, and every ledger row a step"
    no_health = sum(1 for r in f.rows if r.health is None)
    gap = f.sends - len(f.rows)
    measured: dict[str, Any] = {
        "steps_sent": f.steps_sent,
        "sends": f.sends,
        "ledger_rows": len(f.rows),
        "steps_without_row": len(f.steps_without_row),
        "rows_without_step": f.rows_without_step,
        "rows_without_health": no_health,
    }
    if f.steps_sent == 0 and not f.rows:
        out.append(_pending("3a", title, "a case-team write in the window", **measured))
    else:
        wrong = f.steps_without_row or f.rows_without_step or no_health
        detail = (
            f"{f.steps_sent} steps sent ({f.sends} sends) against {len(f.rows)} ledger rows of"
            f" class WC; gap {gap:+d}"
        )
        if f.steps_without_row:
            detail += f"; steps with no row: {_named([str(i) for i in f.steps_without_row])}"
        if f.rows_without_step:
            detail += f"; {f.rows_without_step} rows name no step"
        if no_health:
            detail += f"; {no_health} rows record no health"
        out.append(
            _check(
                "3a",
                title,
                FAIL if wrong else PASS,
                detail,
                n=f.steps_sent,
                measured=measured,
            )
        )

    title = "No write outside NORMAL, the write window or class WC"
    caps = _write_window(f)
    not_normal = [r for r in f.rows if (r.health or "normal") != "normal"]
    probe_not_normal = [r for r in f.rows if (r.probe_state or "normal") != "normal"]
    outside = [r for r in f.rows if not in_window(r.at, caps)]
    other = sum(n for _, n in f.other_class_rows)
    unprobed = sum(1 for r in f.rows if r.probe_state is None)
    measured = {
        "writes": len(f.rows),
        "not_normal_by_ledger": len(not_normal),
        "not_normal_by_probe": len(probe_not_normal),
        "outside_window": len(outside),
        "other_class_rows": dict(f.other_class_rows),
        "without_probe": unprobed,
    }
    if not f.rows and not other:
        out.append(_pending("3b", title, "a write in the window", **measured))
    else:
        bad = not_normal or probe_not_normal or outside or other
        detail = (
            f"of {len(f.rows)} writes: {len(not_normal)} sent when the gateway read the SIEM as"
            f" not normal, {len(probe_not_normal)} when the nearest probe did, {len(outside)}"
            f" outside {f.window_start}-{f.window_end} UTC; {other} writes of a class other than WC"
        )
        if unprobed:
            detail += f" ({unprobed} had no probe within 5 minutes before them)"
        out.append(
            _check("3b", title, FAIL if bad else PASS, detail, n=len(f.rows), measured=measured)
        )

    title = "No request outside the allowlist"
    if f.requests_checked == 0:
        out.append(_pending("3c", title, "a request in the window", requests=0))
    else:
        unknown = sum(n for _, n in f.unknown_templates)
        detail = f"{unknown} of {f.requests_checked} requests name a template ARGUS does not have"
        if unknown:
            detail += " (" + _named([f"{t} x{n}" for t, n in f.unknown_templates]) + ")"
        out.append(
            _check(
                "3c",
                title,
                FAIL if unknown else PASS,
                detail,
                n=f.requests_checked,
                measured={"requests": f.requests_checked, "unknown": unknown},
            )
        )

    out.append(_minimum_counts(f))
    return out


def _minimum_counts(f: WriteFacts) -> Check:
    got = {
        "cases_posted": f.cases_posted,
        "verdicts_recorded": f.verdicts_recorded,
        "read_back_cycles_complete": f.cycles_complete,
    }
    floor = {
        "cases_posted": MIN_CASES_POSTED,
        "verdicts_recorded": MIN_VERDICTS,
        "read_back_cycles_complete": MIN_CYCLES,
    }
    short = {k: floor[k] - v for k, v in got.items() if v < floor[k]}
    detail = (
        f"{f.cases_posted} of {MIN_CASES_POSTED} cases posted, {f.verdicts_recorded} of"
        f" {MIN_VERDICTS} `Verdict:` comments recorded, {f.cycles_complete} of {MIN_CYCLES}"
        " complete read-back cycles"
    )
    measured = {"got": got, "minimum": floor, "short_by": short}
    if not short:
        return _check("3d", "Minimum counts", PASS, detail, measured=measured)
    needs = "; ".join(f"{n} more {k.replace('_', ' ')}" for k, n in short.items())
    return _check(
        "3d",
        "Minimum counts",
        PENDING,
        detail + ". The gate allows up to 7 more days, then the shortfall run on the local tier",
        measured=measured,
        needs=needs,
    )


def judge_coverage(confirmed: Sequence[Confirmed], now: datetime) -> list[Check]:
    """4. Every person-confirmed true positive has its Kibana case within 15 minutes of the
    confirmation or of the next write window's start (n, max)."""
    title = "Kibana case within 15 minutes of the confirm or the window's start"
    if not confirmed:
        return [_pending("4a", title, "a person-confirmed true positive in the window")]
    lags: list[float] = []
    late: list[str] = []
    waiting = 0
    for c in confirmed:
        if c.created_at is not None:
            lag = max((c.created_at - c.ready_at).total_seconds(), 0.0)
            lags.append(lag)
            if lag > COVERAGE_LIMIT.total_seconds():
                late.append(f"{c.number} ({span_text(lag)})")
        elif now - c.ready_at > COVERAGE_LIMIT:
            late.append(
                f"{c.number} (not opened {span_text((now - c.ready_at).total_seconds())}"
                " after it was ready)"
            )
        else:
            waiting += 1
    spread = Spread.of(lags)
    detail = (
        f"{len(lags)} of {len(confirmed)} person-confirmed true positives have their Kibana case"
        f"; creation after ready: max {span_text(spread.max_s)}, p95 {span_text(spread.p95_s)}"
        f"; {waiting} still inside their 15 minutes"
    )
    if late:
        detail += f"; late: case {_named(late)}"
    measured = {
        "confirmed": len(confirmed),
        "created": len(lags),
        "waiting": waiting,
        "late": len(late),
        "creation_lag": spread.as_json(),
    }
    if late:
        verdict = FAIL
    elif not lags:
        verdict = PENDING
    else:
        verdict = PASS
    first = _check(
        "4a",
        title,
        verdict,
        detail,
        n=len(confirmed),
        measured=measured,
        needs="the Kibana case of each confirmed case, or 15 minutes to pass"
        if verdict is PENDING
        else None,
    )

    done = [
        max((c.completed_at - c.ready_at).total_seconds(), 0.0)
        for c in confirmed
        if c.completed_at is not None
    ]
    spread = Spread.of(done)
    title = "Post complete (reported; the gate sets no limit)"
    if not done:
        second = _pending("4b", title, "a first sequence that finished", completed=0)
    else:
        second = _check(
            "4b",
            title,
            PASS,
            f"{len(done)} of {len(confirmed)} posts complete; after ready: max"
            f" {span_text(spread.max_s)}, p95 {span_text(spread.p95_s)}",
            n=len(done),
            measured={"completed": len(done), "completion_lag": spread.as_json()},
        )
    return [first, second]


def judge_closures(f: ClosureFacts) -> list[Check]:
    """5. 0 automatic closures; 0 Kibana closes by ARGUS."""
    title = "No automatic closure"
    if f.events == 0:
        first = _pending("5a", title, "a case event in the window (ARGUS has not worked yet)")
    else:
        first = _check(
            "5a",
            title,
            FAIL if f.automatic else PASS,
            f"{len(f.automatic)} of {f.closures} closures were not made by a person"
            + (f" ({_named(f.automatic)})" if f.automatic else "")
            + f"; {f.events} case events in the window",
            n=f.closures,
            measured={"closures": f.closures, "automatic": len(f.automatic), "events": f.events},
        )
    title = "No Kibana close sent by ARGUS"
    if f.kibana_requests == 0:
        second = _pending("5b", title, "a request to Kibana in the window")
    else:
        second = _check(
            "5b",
            title,
            FAIL if f.kibana_closes else PASS,
            f"{len(f.kibana_closes)} close requests among {f.kibana_requests} requests to Kibana"
            + (f" ({_named(f.kibana_closes)})" if f.kibana_closes else ""),
            n=f.kibana_requests,
            measured={"kibana_requests": f.kibana_requests, "closes": len(f.kibana_closes)},
        )
    return [first, second]


def judge_reconciliation(f: ReconcileFacts) -> list[Check]:
    """6. A person's edit, close or delete appears within 15 minutes (p95, NORMAL); 0 reverts;
    0 unexplained ARGUS actions."""
    out: list[Check] = []
    title = "A person's change appears within 15 minutes (p95, NORMAL)"
    p95 = nearest_rank(f.lags_s, 0.95)
    if not f.lags_s:
        out.append(_pending("6a", title, "a person's edit, close or delete of an ARGUS case"))
    else:
        out.append(
            _check(
                "6a",
                title,
                PASS if p95 is not None and p95 <= LAG_LIMIT_S else FAIL,
                f"n = {len(f.lags_s)} changes; p95 {span_text(p95)},"
                f" max {span_text(max(f.lags_s))}",
                n=len(f.lags_s),
                measured={"lag": Spread.of(f.lags_s).as_json(), "limit_s": LAG_LIMIT_S},
            )
        )
    cycles = {"cycles": f.cycles, "complete": f.complete, "partial": f.partial, "failed": f.failed}
    title = "No revert of a person's change"
    if f.complete == 0:
        out.append(_pending("6b", title, "a complete read-back cycle in the window", **cycles))
    else:
        out.append(
            _check(
                "6b",
                title,
                FAIL if f.reverts else PASS,
                f"{len(f.reverts)} writes to a case after a person changed it, over"
                f" {f.complete} complete cycles ({percent(f.complete, f.cycles)} of {f.cycles})"
                + (f" ({_named(f.reverts)})" if f.reverts else ""),
                n=f.complete,
                measured={**cycles, "reverts": len(f.reverts)},
            )
        )
    title = "No unexplained action of ARGUS's own"
    if f.complete == 0:
        out.append(_pending("6c", title, "a complete read-back cycle in the window", **cycles))
    else:
        out.append(
            _check(
                "6c",
                title,
                FAIL if f.unexplained else PASS,
                f"{f.unexplained} unresolved unexplained actions or cases"
                f" ({f.unexplained_resolved} more were resolved by a person)",
                n=f.complete,
                measured={
                    **cycles,
                    "unexplained": f.unexplained,
                    "resolved": f.unexplained_resolved,
                },
            )
        )
    title = "The read-back sees the case team's cases"
    if f.team_cases == 0:
        out.append(_pending("6d", title, "a case-team case with a Kibana case"))
    elif f.team_cases_in_mirror < f.team_cases:
        missing = f.team_cases - f.team_cases_in_mirror
        out.append(
            _check(
                "6d",
                title,
                PENDING,
                f"{missing} of {f.team_cases} case-team cases are not in the read-back's mirror"
                " yet (P4-B1): a person's edit, close or delete of them is not seen",
                n=f.team_cases,
                measured={"team_cases": f.team_cases, "in_mirror": f.team_cases_in_mirror},
                needs="P4-B1: the mirror reads every ARGUS identity's cases",
            )
        )
    else:
        out.append(
            _check(
                "6d",
                title,
                PASS,
                f"all {f.team_cases} case-team cases are in the mirror",
                n=f.team_cases,
                measured={"team_cases": f.team_cases, "in_mirror": f.team_cases_in_mirror},
            )
        )
    return out


def judge_notified(f: NotifiedFacts) -> list[Check]:
    """7. Every notified case judged every day it was active; a change after the notice in Needs
    attention within one pass."""
    out: list[Check] = []
    title = "Activity on a notified case is judged"
    if f.cases == 0:
        out.append(_pending("7a", title, "a notified case with activity in the window"))
    else:
        total = f.investigations + len(f.undecided)
        out.append(
            _check(
                "7a",
                title,
                FAIL if f.undecided else PASS,
                f"{f.cases} notified cases; {f.investigations} of {total} investigations with"
                " activity after the notice are decided at their current version"
                + (
                    f"; undecided over {span_text(f.pass_s)}: {_named(f.undecided)}"
                    if f.undecided
                    else ""
                ),
                n=total,
                measured={
                    "cases": f.cases,
                    "decided": f.investigations,
                    "undecided": len(f.undecided),
                },
            )
        )
    title = "A change after the notice is in Needs attention within one pass"
    if not f.change_lags_s:
        out.append(_pending("7b", title, "a change after a notice in the window"))
    else:
        worst = max(f.change_lags_s)
        out.append(
            _check(
                "7b",
                title,
                PASS if worst <= f.pass_s else FAIL,
                f"n = {len(f.change_lags_s)} changes ({f.changed} in all); max"
                f" {span_text(worst)} after the investigation's last update, one pass is"
                f" {span_text(f.pass_s)}",
                n=len(f.change_lags_s),
                measured={"lag": Spread.of(f.change_lags_s).as_json(), "pass_s": f.pass_s},
            )
        )
    return out


def _ms(value: int) -> str:
    return f"{value:,} ms"


def judge_load(f: LoadFacts) -> list[Check]:
    """8. Every lane and the total within its limits per minute and per day; 0 moves to CAUTION
    attributable to ARGUS; the sign-ins lane within its expected request count."""
    limits = {x.lane: x for x in f.limits}
    out: list[Check] = []

    # per minute, per lane
    title = "Every lane within its minute"
    per_lane: dict[str, list[Any]] = defaultdict(list)
    for m in f.minutes:
        per_lane[m.lane].append(m)
    if not f.minutes:
        out.append(_pending("8a", title, "a request in the window"))
    else:
        rows: dict[str, Any] = {}
        failed: list[str] = []
        for lane, spent in sorted(per_lane.items()):
            lim = limits.get(lane)
            worst = max(spent, key=lambda m: m.took_ms)
            share = lim.per_minute_ms if lim else 0
            hard = (lim.burst_ms + lim.per_minute_ms) if lim else 0
            over = sum(1 for m in spent if m.took_ms > share)
            # a bucket admits on an estimate and charges the real cost after it, so a clock
            # minute may pass the bucket by the cost of its last request, never by more
            if lim is None or worst.took_ms - worst.largest_ms > hard:
                failed.append(lane)
            rows[lane] = {
                "worst_ms": worst.took_ms,
                "worst_minute": worst.minute.isoformat(),
                "share_ms": share,
                "bucket_max_ms": hard,
                "largest_request_ms": worst.largest_ms,
                "minutes_over_share": over,
                "active_minutes": len(spent),
            }
        detail = "; ".join(
            f"{lane} worst {_ms(v['worst_ms'])} of {_ms(v['share_ms'])}"
            + (f" ({v['minutes_over_share']} minutes over)" if v["minutes_over_share"] else "")
            for lane, v in rows.items()
        )
        if failed:
            detail += f"; beyond what the lane's bucket admits: {', '.join(failed)}"
        out.append(
            _check(
                "8a",
                title,
                FAIL if failed else PASS,
                detail,
                n=sum(len(v) for v in per_lane.values()),
                measured={"lanes": rows},
            )
        )

    # per day, per lane
    title = "Every lane within its day"
    if not f.days:
        out.append(_pending("8b", title, "a request in the window"))
    else:
        day_rows: dict[str, Any] = {}
        failed = []
        for d in f.days:
            lim = limits.get(d.lane)
            if lim is None or d.took_ms > lim.per_day_ms or d.heavy > lim.heavy_per_day:
                failed.append(f"{d.lane} {d.day}")
            day_rows.setdefault(d.lane, {})[d.day] = {
                "took_ms": d.took_ms,
                "requests": d.requests,
                "heavy": d.heavy,
                "per_day_ms": lim.per_day_ms if lim else 0,
                "heavy_per_day": lim.heavy_per_day if lim else 0,
            }
        busiest = max(
            f.days,
            key=lambda d: (
                d.took_ms / max(limits[d.lane].per_day_ms, 1) if d.lane in limits else 2.0
            ),
        )
        lim = limits.get(busiest.lane)
        detail = (
            f"{len(f.days)} lane-days; the fullest: {busiest.lane} on {busiest.day} used"
            f" {busiest.took_ms / 60_000:.1f} min of {(lim.per_day_ms if lim else 0) / 60_000:.1f}"
            f" min and {busiest.heavy} of {lim.heavy_per_day if lim else 0} heavy requests"
        )
        if failed:
            detail += f"; over: {_named(failed)}"
        out.append(
            _check(
                "8b",
                title,
                FAIL if failed else PASS,
                detail,
                n=len(f.days),
                measured={"lane_days": day_rows},
            )
        )

    out.append(_judge_total(f))
    out.append(_judge_caution(f))
    out.append(_judge_signin_arithmetic(f))
    return out


def _judge_total(f: LoadFacts) -> Check:
    title = "All lanes together within the ceiling"
    if not f.minutes:
        return _pending("8c", title, "a request in the window")
    ceiling = f.ceiling
    minute_total: dict[datetime, int] = defaultdict(int)
    for m in f.minutes:
        minute_total[m.minute] += m.took_ms
    worst_minute, worst_ms = max(minute_total.items(), key=lambda kv: kv[1])
    day_took: dict[str, int] = defaultdict(int)
    day_heavy: dict[str, int] = defaultdict(int)
    for d in f.days:
        day_took[d.day] += d.took_ms
        day_heavy[d.day] += d.heavy
    worst_day, day_ms = max(day_took.items(), key=lambda kv: kv[1], default=("", 0))
    heavy_day = max(day_heavy.values(), default=0)
    hard = ceiling.burst_ms + ceiling.per_minute_ms
    over = worst_ms > hard or day_ms > ceiling.per_day_ms or heavy_day > ceiling.heavy_per_day
    detail = (
        f"worst minute {_ms(worst_ms)} of {_ms(ceiling.per_minute_ms)}; busiest day {worst_day}"
        f" {day_ms / 60_000:.1f} min of {ceiling.per_day_ms / 60_000:.0f} min; most heavy requests"
        f" in a day {heavy_day} of {ceiling.heavy_per_day}"
    )
    return _check(
        "8c",
        title,
        FAIL if over else PASS,
        detail,
        n=len(minute_total),
        measured={
            "worst_minute": worst_minute.isoformat(),
            "worst_minute_ms": worst_ms,
            "minute_share_ms": ceiling.per_minute_ms,
            "minute_bucket_max_ms": hard,
            "busiest_day": worst_day,
            "busiest_day_ms": day_ms,
            "day_limit_ms": ceiling.per_day_ms,
            "most_heavy_in_a_day": heavy_day,
            "heavy_limit": ceiling.heavy_per_day,
        },
    )


def _judge_caution(f: LoadFacts) -> Check:
    title = "No move to CAUTION attributable to ARGUS"
    if f.probes == 0:
        return _pending("8d", title, "health probes in the window")
    ceiling = f.ceiling
    hard = ceiling.burst_ms + ceiling.per_minute_ms
    certain = [m for m in f.moves if m.took_before_ms > hard]
    active = [m for m in f.moves if m.requests_before > 0]
    measured = {
        "probes": f.probes,
        "moves": len(f.moves),
        "with_argus_requests_before": len(active),
        "beyond_the_ceiling_before": len(certain),
    }
    if certain:
        return _check(
            "8d",
            title,
            FAIL,
            f"{len(certain)} of {len(f.moves)} moves out of NORMAL came after ARGUS spent more"
            " than the ceiling's bucket admits in the minute before",
            n=f.probes,
            measured=measured,
        )
    if active:
        return _check(
            "8d",
            title,
            OPEN,
            f"{len(f.moves)} moves out of NORMAL in {f.probes} probes; ARGUS sent requests in the"
            f" minute before {len(active)} of them, inside its limits: a person judges whether"
            " they caused it",
            n=f.probes,
            measured=measured,
            needs="a person reads the minutes before each move (the ledger, the probe's reasons)",
        )
    return _check(
        "8d",
        title,
        PASS,
        f"{len(f.moves)} moves out of NORMAL in {f.probes} probes; none after an ARGUS request",
        n=f.probes,
        measured=measured,
    )


def _judge_signin_arithmetic(f: LoadFacts) -> Check:
    title = "The sign-ins lane within D-216's arithmetic"
    if not f.signin_per_day:
        return _pending("8e", title, "a sign-ins request in the window (the pass is off or idle)")
    days = dict(f.signin_per_day)
    busiest = max(days, key=lambda d: days[d])
    # the first day with requests may carry the one-time backfill on top of a steady day
    first = min(days)
    over = [
        d
        for d, n in days.items()
        if n > f.signin_steady_per_day + (f.signin_backfill_extra if d == first else 0)
    ]
    detail = (
        f"{sum(days.values())} requests over {len(days)} days; busiest {busiest}: {days[busiest]}"
        f" (a steady day is at most {f.signin_steady_per_day}, the backfill adds"
        f" {f.signin_backfill_extra} once); {_ms(f.signin_server_ms)} of server time;"
        f" {f.signin_gap_breaches} requests closer than {f.signin_gap_s:g} s"
    )
    if over:
        detail += f"; over: {_named(over)}"
    return _check(
        "8e",
        title,
        FAIL if over or f.signin_gap_breaches else PASS,
        detail,
        n=sum(days.values()),
        measured={
            "per_day": days,
            "steady_per_day": f.signin_steady_per_day,
            "backfill_extra": f.signin_backfill_extra,
            "server_ms": f.signin_server_ms,
            "gap_breaches": f.signin_gap_breaches,
        },
    )


def stale_lookups(f: SigninFacts) -> list[str]:
    """Incomplete lookups that should have been retried by now: not final (logs gone, a batch
    stored-failed the most times, a day past the SSO logs' retention) and older than their retry
    time plus a pass's grace. Labelled by reason and day."""
    oldest_kept = f.now.date() - timedelta(days=f.retention_days)
    out = []
    for lk in f.lookups:
        if lk.complete or lk.reason is None:
            continue
        if lk.reason in f.terminal_reasons:
            continue
        if lk.reason == "store_failed" and lk.store_failures >= f.max_store_failures:
            continue
        if datetime.fromisoformat(lk.day).date() < oldest_kept:
            continue
        due = f.backoff_s.get(lk.reason, f.retry_after_s)
        if (f.now - lk.looked_at).total_seconds() > due + f.grace_s:
            out.append(f"{lk.reason} {lk.day}")
    return out


def judge_signins(f: SigninFacts, sweep: SweepFacts, since: datetime) -> list[Check]:
    """9. Every lookup answered, incomplete with a reason, or retried; 0 account names in a model
    request, a log line, or shown without ``see_logs``."""
    out: list[Check] = []
    title = "Every lookup answered, incomplete with a reason, or retried"
    if not f.lookups:
        out.append(
            _pending("9a", title, "a sign-in lookup in the window (the pass is off or idle)")
        )
    else:
        done = sum(1 for lk in f.lookups if lk.complete)
        reasons: dict[str, int] = defaultdict(int)
        for lk in f.lookups:
            if not lk.complete:
                reasons[lk.reason or "unknown"] += 1
        retried = sum(1 for lk in f.lookups if lk.store_failures > 0)
        stale = stale_lookups(f)
        detail = (
            f"{len(f.lookups)} lookups: {done} answered, {len(f.lookups) - done} incomplete with a"
            f" reason ({', '.join(f'{k} {v}' for k, v in sorted(reasons.items())) or 'none'}),"
            f" {retried} retried after a storage failure; {len(stale)} incomplete and past their"
            " retry time"
        )
        if stale:
            detail += f" ({_named(stale)})"
        out.append(
            _check(
                "9a",
                title,
                FAIL if stale else PASS,
                detail,
                n=len(f.lookups),
                measured={
                    "lookups": len(f.lookups),
                    "answered": done,
                    "incomplete": dict(reasons),
                    "retried": retried,
                    "past_retry_time": len(stale),
                },
            )
        )
    out.append(_judge_sweep(sweep, since))
    out.append(
        _check(
            "9c",
            "No account name in a log line, or shown without `see_logs`",
            OPEN,
            "a person reads the gate's log scan (scripts/gate.sh) and the page's capability test;"
            " the store keeps neither",
            needs="the latest gate run's secret scan and the `see_logs` tests",
        )
    )
    return out


def _judge_sweep(s: SweepFacts, since: datetime) -> Check:
    title = "No account name in a model request (the privacy sweep)"
    if s.path is None:
        return _check(
            "9b",
            title,
            OPEN,
            "no stored result of scripts/privacy_sweep.py (data/gate/p1/*/sweep.json)",
            needs="run `uv run python scripts/privacy_sweep.py`",
        )
    measured = {
        "path": s.path,
        "at": s.at.isoformat() if s.at else None,
        "leaks": s.leaks,
        "signin_name_leaks": s.signin_name_leaks,
        "signin_names_checked": s.signin_names_checked,
        "dossiers": s.dossiers,
    }
    if s.leaks is None or s.signin_name_leaks is None or s.at is None:
        return _check(
            "9b",
            title,
            OPEN,
            f"the stored sweep {s.path} cannot be read",
            measured=measured,
            needs="run the sweep again",
        )
    if s.leaks or s.signin_name_leaks:
        return _check(
            "9b",
            title,
            FAIL,
            f"the sweep of {s.at:%Y-%m-%d %H:%M} UTC found {s.leaks} leaks, {s.signin_name_leaks}"
            " of them account names",
            n=s.dossiers,
            measured=measured,
        )
    if s.at < since:
        return _check(
            "9b",
            title,
            OPEN,
            f"the newest sweep ({s.at:%Y-%m-%d %H:%M} UTC) is older than the window",
            measured=measured,
            needs="run the sweep again inside the window",
        )
    if not s.signin_names_checked:
        return _check(
            "9b",
            title,
            PENDING,
            f"the sweep of {s.at:%Y-%m-%d %H:%M} UTC checked no stored account name (none was"
            " stored then)",
            n=0,
            measured=measured,
            needs="a sweep after sign-in sightings are stored",
        )
    return _check(
        "9b",
        title,
        PASS,
        f"the sweep of {s.at:%Y-%m-%d %H:%M} UTC checked {s.dossiers} dossiers against"
        f" {s.signin_names_checked} stored account names: 0 leaks",
        n=s.signin_names_checked,
        measured=measured,
    )


def judge_analysis(f: AnalysisFacts) -> list[Check]:
    """10. 0 true positives proposed benign; cost within the caps; the inconclusive rate with
    its n."""
    out: list[Check] = []
    title = "No true positive proposed benign (proposals a person's verdict checks)"
    if f.labelled == 0:
        out.append(_pending("10a", title, "a proposal in the window that a person has labelled"))
    else:
        out.append(
            _check(
                "10a",
                title,
                FAIL if f.wrong_benign else PASS,
                f"{f.wrong_benign} of {f.labelled} checkable proposals were benign on a true"
                " positive",
                n=f.labelled,
                measured={"labelled": f.labelled, "benign_on_true_positive": f.wrong_benign},
            )
        )
    out.append(
        _check(
            "10b",
            "No true positive proposed benign on the gold set",
            OPEN,
            f"the gold set has {f.gold_answered} answered items; scoring the decision engine on"
            " it is a run, not a stored result",
            measured={"gold_answered": f.gold_answered},
            needs="`uv run argus gold score --by engine --split test` (the evaluation harness)",
        )
    )
    out.append(_judge_cost(f))
    title = "The inconclusive rate (reported with its n)"
    if f.finished == 0:
        out.append(_pending("10d", title, "a finished assessment in the window"))
    else:
        out.append(
            _check(
                "10d",
                title,
                PASS,
                f"{f.inconclusive} of {f.finished} finished assessments were inconclusive"
                f" ({percent(f.inconclusive, f.finished)})",
                n=f.finished,
                measured={"finished": f.finished, "inconclusive": f.inconclusive},
            )
        )
    return out


def _judge_cost(f: AnalysisFacts) -> Check:
    title = "Cost within the caps"
    if f.daily_cap_usd is None or f.monthly_cap_usd is None:
        return _check(
            "10c",
            title,
            OPEN,
            "the model gateway's caps could not be read",
            needs="config/llm.yaml (daily_cap_usd, monthly_cap_usd)",
        )
    worst_day, worst = max(f.cost_days.items(), key=lambda kv: kv[1], default=("", 0.0))
    over = worst > f.daily_cap_usd or f.cost_month_usd > f.monthly_cap_usd
    return _check(
        "10c",
        title,
        FAIL if over else PASS,
        f"busiest day {worst_day or 'none'}: ${worst:.4f} of ${f.daily_cap_usd:.2f}; this month"
        f" ${f.cost_month_usd:.4f} of ${f.monthly_cap_usd:.2f}",
        n=len(f.cost_days),
        measured={
            "busiest_day": worst_day,
            "busiest_day_usd": worst,
            "daily_cap_usd": f.daily_cap_usd,
            "month_usd": f.cost_month_usd,
            "monthly_cap_usd": f.monthly_cap_usd,
        },
    )


def judge_health(h: HealthFacts, b: BackupFacts) -> list[Check]:
    """11. The services up (restarts counted, each explained); ``argus doctor`` 0 FAIL daily; the
    nightly backup and its drill."""
    out: list[Check] = []
    title = "Services up, restarts explained"
    measured = {
        "samples": h.samples,
        "gaps": list(h.gaps),
        "newest_sample": h.newest_sample.isoformat() if h.newest_sample else None,
    }
    if h.newest_sample is None:
        out.append(_pending("11a", title, "a soak sample in the window (argus-soak-sample.timer)"))
    elif (h.now - h.newest_sample).total_seconds() > h.stale_s:
        out.append(
            _check(
                "11a",
                title,
                FAIL,
                f"the newest sample is {span_text((h.now - h.newest_sample).total_seconds())}"
                " old: the sampler, or the machine, is not running",
                n=h.samples,
                measured=measured,
            )
        )
    else:
        gaps = (
            f"{len(h.gaps)} gaps in the samples ({_named(list(h.gaps))})"
            if h.gaps
            else ("no gap in the samples")
        )
        out.append(
            _check(
                "11a",
                title,
                OPEN,
                f"{h.samples} samples, {gaps}; unit restarts are in systemd, which the store"
                " does not keep",
                n=h.samples,
                measured=measured,
                needs="`systemctl --user show -p NRestarts <unit>` for each service, each restart"
                " explained in the journal",
            )
        )
    out.append(
        _check(
            "11b",
            "`argus doctor` 0 FAIL daily",
            OPEN,
            "doctor's results are not stored; run it (it sends no request) and journal any FAIL",
            needs="`uv run argus doctor`",
        )
    )
    out.append(_judge_dumps(b, h.now))
    out.append(_judge_drills(b, h.now))
    return out


def _judge_dumps(b: BackupFacts, now: datetime) -> Check:
    title = "The nightly dump is made"
    if not b.readable:
        return _check("11c", title, OPEN, "the backup folder cannot be read", needs="backup.dir")
    grace = timedelta(seconds=b.grace_s)
    due = [t for t in b.dump_due if now - t > grace]
    if not due:
        newest = f"; the newest dump {b.newest_dump:%Y-%m-%d %H:%M} UTC" if b.newest_dump else ""
        return _pending("11c", title, f"the first nightly dump to fall due{newest}")
    missing = [
        t for t in due if not any(t - timedelta(minutes=10) <= d <= t + grace for d in b.dumps)
    ]
    return _check(
        "11c",
        title,
        FAIL if missing else PASS,
        f"{len(due) - len(missing)} of {len(due)} due nightly dumps are in the folder"
        + (f"; missing: {_named([f'{t:%Y-%m-%d %H:%M}' for t in missing])} UTC" if missing else ""),
        n=len(due),
        measured={"due": len(due), "made": len(due) - len(missing), "missing": len(missing)},
    )


def _judge_drills(b: BackupFacts, now: datetime) -> Check:
    title = "The restore drill passes"
    if not b.readable:
        return _check("11d", title, OPEN, "the backup folder cannot be read", needs="backup.dir")
    failed = [at for at, passed in b.drills if not passed]
    grace = timedelta(seconds=b.grace_s)
    due = [t for t in b.drill_due if now - t > grace]
    missing = [
        t
        for t in due
        if not any(t - timedelta(minutes=10) <= at <= t + grace for at, _ in b.drills)
    ]
    measured = {
        "due": len(due),
        "drills": len(b.drills),
        "failed": len(failed),
        "missing": len(missing),
    }
    if not b.drills and not due:
        return _pending("11d", title, "the first weekly restore drill to fall due")
    detail = f"{len(b.drills)} drills in the window ({len(failed)} failed); {len(due)} due"
    if missing:
        detail += f", missing: {_named([f'{t:%Y-%m-%d %H:%M}' for t in missing])} UTC"
    return _check(
        "11d",
        title,
        FAIL if failed or missing else PASS,
        detail,
        n=len(b.drills),
        measured=measured,
    )
