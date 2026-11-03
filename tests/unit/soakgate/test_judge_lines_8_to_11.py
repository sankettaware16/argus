"""P4-A1: the judges of lines 8 to 11 (load, sign-ins, analysis, health) over typed facts."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.soakgate import judge
from argus.soakgate.model import Check, DaySpend, MinuteSpend, Verdict
from tests.unit.soakgate import kit

pytestmark = pytest.mark.unit

PASS, FAIL, PENDING, OPEN = Verdict.PASS, Verdict.FAIL, Verdict.PENDING, Verdict.OPEN


def verdicts(checks: list[Check]) -> dict[str, Verdict]:
    return {c.id: c.verdict for c in checks}


# --------------------------------------------------------------------------- line 8


def test_a_quiet_load_passes_every_check() -> None:
    assert verdicts(judge.judge_load(kit.load())) == {
        "8a": PASS,
        "8b": PASS,
        "8c": PASS,
        "8d": PASS,
        "8e": PASS,
    }


def test_no_request_in_the_window_is_pending() -> None:
    checks = judge.judge_load(
        kit.load(minutes=(), days=(), probes=0, signin_per_day={}, signin_server_ms=0)
    )
    assert set(verdicts(checks).values()) == {PENDING}


def _minute(lane: str, took: int) -> tuple[MinuteSpend, ...]:
    return (MinuteSpend(lane, kit.T0, took, 5),)


def test_a_minute_over_the_share_but_inside_the_bucket_is_noted_not_failed() -> None:
    check = judge.judge_load(kit.load(minutes=_minute("collector", 2_500)))[0]
    assert check.verdict is PASS
    assert "1 minutes over" in check.detail
    assert check.measured["lanes"]["collector"]["bucket_max_ms"] == 3_600


def test_a_minute_beyond_what_the_bucket_admits_fails() -> None:
    check = judge.judge_load(kit.load(minutes=_minute("collector", 3_601)))[0]
    assert check.verdict is FAIL
    assert "collector" in check.detail


def test_a_minute_may_pass_the_bucket_by_its_last_request_only() -> None:
    # a bucket admits on an estimate and charges the real cost after: the first real report
    # (2026-10-30) had kibana_read at 408 ms of a 400 ms bucket, one 100 ms request's overshoot
    over = (MinuteSpend("kibana_read", kit.T0, 408, 4, largest_ms=108),)
    assert judge.judge_load(kit.load(minutes=over))[0].verdict is PASS
    more = (MinuteSpend("kibana_read", kit.T0, 520, 4, largest_ms=108),)
    check = judge.judge_load(kit.load(minutes=more))[0]
    assert check.verdict is FAIL
    assert check.measured["lanes"]["kibana_read"]["largest_request_ms"] == 108


def test_a_closed_lane_that_spent_fails_and_an_unknown_lane_fails() -> None:
    assert judge.judge_load(kit.load(minutes=_minute("measurement", 1)))[0].verdict is FAIL
    assert judge.judge_load(kit.load(minutes=_minute("mystery", 1)))[0].verdict is FAIL


def test_the_day_limits_are_strict_for_time_and_for_heavy_requests() -> None:
    over_time = (DaySpend("investigation", "2026-10-31", 360_001, 100, 10),)
    over_heavy = (DaySpend("investigation", "2026-10-31", 1_000, 100, 301),)
    at_limit = (DaySpend("investigation", "2026-10-31", 360_000, 100, 300),)
    assert judge.judge_load(kit.load(days=over_time))[1].verdict is FAIL
    assert judge.judge_load(kit.load(days=over_heavy))[1].verdict is FAIL
    assert judge.judge_load(kit.load(days=at_limit))[1].verdict is PASS


def test_the_total_is_judged_against_the_ceiling_not_the_sum_of_shares() -> None:
    minutes = (
        MinuteSpend("collector", kit.T0, 3_000, 10),
        MinuteSpend("investigation", kit.T0, 3_000, 10),
    )
    check = judge.judge_load(kit.load(minutes=minutes))[2]
    assert check.verdict is PASS  # 6,000 ms is the ceiling's bucket: 3,000 held and 3,000 refilled
    more = (*minutes, MinuteSpend("freshness", kit.T0, 1, 1))
    assert judge.judge_load(kit.load(minutes=more))[2].verdict is FAIL
    days = (DaySpend("collector", "2026-10-31", 3_600_001, 1, 0),)
    assert judge.judge_load(kit.load(days=days))[2].verdict is FAIL


def test_a_move_out_of_normal_with_requests_before_it_is_for_a_person() -> None:
    check = judge.judge_load(kit.load(moves=(kit.move(requests=5, took=500),)))[3]
    assert check.verdict is OPEN
    assert check.needs


def test_a_move_out_of_normal_after_no_request_passes() -> None:
    check = judge.judge_load(kit.load(moves=(kit.move(requests=0, took=0),)))[3]
    assert check.verdict is PASS


def test_a_move_after_arguss_spend_beyond_the_ceiling_fails() -> None:
    check = judge.judge_load(kit.load(moves=(kit.move(requests=40, took=6_001),)))[3]
    assert check.verdict is FAIL


def test_no_probe_means_the_moves_cannot_be_counted() -> None:
    assert judge.judge_load(kit.load(probes=0))[3].verdict is PENDING


def test_the_signins_lane_may_carry_the_backfill_once_on_its_first_day() -> None:
    steady = {"2026-10-30": 27, "2026-10-31": 27}
    assert judge.judge_load(kit.load(signin_per_day=steady))[4].verdict is PASS
    first = {"2026-10-30": 41, "2026-10-31": 27}
    assert judge.judge_load(kit.load(signin_per_day=first))[4].verdict is PASS
    later = {"2026-10-30": 27, "2026-10-31": 28}
    assert judge.judge_load(kit.load(signin_per_day=later))[4].verdict is FAIL
    over_first = {"2026-10-30": 42}
    assert judge.judge_load(kit.load(signin_per_day=over_first))[4].verdict is FAIL


def test_two_signin_requests_closer_than_the_gap_fail() -> None:
    assert judge.judge_load(kit.load(signin_gap_breaches=1))[4].verdict is FAIL


@given(
    spent=st.lists(st.integers(0, 8_000), min_size=1, max_size=6),
    extra=st.integers(0, 8_000),
)
def test_more_spend_in_a_minute_never_turns_a_fail_into_a_pass(
    spent: list[int], extra: int
) -> None:
    def judged(values: list[int]) -> Verdict:
        minutes = tuple(
            MinuteSpend("collector", kit.T0 + timedelta(minutes=i), v, 1)
            for i, v in enumerate(values)
        )
        return judge.judge_load(kit.load(minutes=minutes))[0].verdict

    base = judged(spent)
    assert (base is FAIL) == any(v > 3_600 for v in spent)
    if base is FAIL:
        assert judged([*spent, extra]) is FAIL


# --------------------------------------------------------------------------- line 9


def test_answered_lookups_pass_with_their_n() -> None:
    checks = judge.judge_signins(
        kit.signins(kit.lookup(), kit.lookup(complete=False, reason="partial", ago_h=0.2)),
        kit.sweep(),
        kit.NOW - timedelta(days=2),
    )
    assert verdicts(checks) == {"9a": PASS, "9b": PASS, "9c": OPEN}
    assert checks[0].n == 2
    assert checks[0].measured["incomplete"] == {"partial": 1}


def test_an_incomplete_lookup_past_its_retry_time_fails() -> None:
    old = kit.lookup(complete=False, reason="failed", ago_h=4.0)  # retry 30 min + 3 h grace
    check = judge.judge_signins(kit.signins(old), kit.sweep(), kit.T0)[0]
    assert check.verdict is FAIL
    assert "failed 2026-10-31" in check.detail


@pytest.mark.parametrize(
    "lookup",
    [
        kit.lookup(complete=False, reason="logs_gone", ago_h=99),  # never retried
        kit.lookup(complete=False, reason="store_failed", ago_h=99, failures=3),  # left alone
        kit.lookup("2026-10-20", complete=False, reason="failed", ago_h=99),  # logs expired
        kit.lookup(complete=False, reason="store_failed", ago_h=5.0, failures=1),  # 6 h + 3 h
    ],
)
def test_a_lookup_that_is_final_or_not_yet_due_is_not_stale(lookup: object) -> None:
    facts = kit.signins(lookup)  # type: ignore[arg-type]
    assert judge.stale_lookups(facts) == []


def test_a_store_failure_is_retried_after_its_backoff() -> None:
    due = kit.lookup(complete=False, reason="store_failed", ago_h=10.0, failures=2)
    assert judge.stale_lookups(kit.signins(due)) == ["store_failed 2026-10-31"]


def test_no_lookup_in_the_window_is_pending() -> None:
    facts = kit.signins()
    facts = replace(facts, lookups=())
    assert judge.judge_signins(facts, kit.sweep(), kit.T0)[0].verdict is PENDING


@pytest.mark.parametrize(
    ("sweep", "verdict"),
    [
        (kit.sweep(), PASS),
        (kit.sweep(leaks=1), FAIL),
        (kit.sweep(signin_name_leaks=2), FAIL),
        (kit.sweep(path=None, at=None, leaks=None, signin_name_leaks=None), OPEN),
        (kit.sweep(at=None, leaks=None), OPEN),  # unreadable
        (kit.sweep(at=kit.T0 - timedelta(days=3)), OPEN),  # older than the window
        (kit.sweep(signin_names_checked=0), PENDING),  # no name was stored when it ran
    ],
)
def test_the_privacy_sweep_is_open_until_a_stored_result_inside_the_window(
    sweep: object, verdict: Verdict
) -> None:
    check = judge.judge_signins(kit.signins(), sweep, kit.T0)[1]  # type: ignore[arg-type]
    assert check.verdict is verdict


def test_a_leak_fails_even_when_the_sweep_is_old() -> None:
    old = kit.sweep(leaks=1, at=kit.T0 - timedelta(days=9))
    assert judge.judge_signins(kit.signins(), old, kit.T0)[1].verdict is FAIL


def test_log_lines_and_see_logs_are_for_a_person() -> None:
    check = judge.judge_signins(kit.signins(), kit.sweep(), kit.T0)[2]
    assert check.verdict is OPEN
    assert check.needs


# --------------------------------------------------------------------------- line 10


def test_analysis_with_nothing_wrong_passes_what_it_can_and_leaves_the_gold_set_open() -> None:
    checks = judge.judge_analysis(kit.analysis())
    assert verdicts(checks) == {"10a": PASS, "10b": OPEN, "10c": PASS, "10d": PASS}
    assert "100 answered" in checks[1].detail
    assert "gold score --by engine" in (checks[1].needs or "")


def test_a_true_positive_proposed_benign_fails() -> None:
    check = judge.judge_analysis(kit.analysis(wrong_benign=1))[0]
    assert check.verdict is FAIL
    assert check.n == 20


def test_no_labelled_proposal_or_finished_assessment_is_pending() -> None:
    checks = judge.judge_analysis(kit.analysis(labelled=0, finished=0, inconclusive=0))
    assert verdicts(checks)["10a"] is PENDING
    assert verdicts(checks)["10d"] is PENDING


@pytest.mark.parametrize(
    ("days", "month", "verdict"),
    [
        ({"2026-10-31": 1.5}, 10.0, PASS),
        ({"2026-10-31": 1.51}, 10.0, FAIL),
        ({"2026-10-31": 0.1}, 40.01, FAIL),
        ({}, 0.0, PASS),
    ],
)
def test_the_costs_caps_are_the_daily_and_the_monthly(
    days: dict[str, float], month: float, verdict: Verdict
) -> None:
    check = judge.judge_analysis(kit.analysis(cost_days=days, cost_month_usd=month))[2]
    assert check.verdict is verdict


def test_unreadable_caps_leave_the_cost_open() -> None:
    check = judge.judge_analysis(kit.analysis(daily_cap_usd=None))[2]
    assert check.verdict is OPEN


# --------------------------------------------------------------------------- line 11


def test_healthy_samples_and_backups_leave_only_what_a_person_reads_open() -> None:
    checks = judge.judge_health(kit.health(), kit.backups())
    assert verdicts(checks) == {"11a": OPEN, "11b": OPEN, "11c": PASS, "11d": PASS}
    assert "no gap in the samples" in checks[0].detail


def test_gaps_in_the_samples_are_named_for_a_person() -> None:
    check = judge.judge_health(kit.health(gaps=("11-01 02:00 to 11-01 04:00 UTC",)), kit.backups())[
        0
    ]
    assert check.verdict is OPEN
    assert "1 gaps" in check.detail


def test_a_silent_sampler_fails_and_no_sample_is_pending() -> None:
    stale = kit.health(newest_sample=kit.NOW - timedelta(minutes=46))
    assert judge.judge_health(stale, kit.backups())[0].verdict is FAIL
    fresh = kit.health(newest_sample=kit.NOW - timedelta(minutes=45))
    assert judge.judge_health(fresh, kit.backups())[0].verdict is OPEN
    none = kit.health(samples=0, newest_sample=None)
    assert judge.judge_health(none, kit.backups())[0].verdict is PENDING


def test_a_nightly_dump_that_is_due_and_missing_fails_after_its_grace() -> None:
    nothing = kit.backups(dumps=(), newest_dump=None)
    assert judge.judge_health(kit.health(), nothing)[2].verdict is FAIL
    due = kit.backups().dump_due[0]
    just_due = replace(kit.health(), now=due + timedelta(hours=2))
    assert judge.judge_health(just_due, nothing)[2].verdict is PENDING  # inside its grace


def test_a_dump_made_long_after_its_time_does_not_count_for_that_night() -> None:
    late = kit.backups().dump_due[0] + timedelta(hours=4)
    assert judge.judge_health(kit.health(), kit.backups(dumps=(late,)))[2].verdict is FAIL


def test_no_dump_due_yet_is_pending() -> None:
    check = judge.judge_health(kit.health(), kit.backups(dumps=(), dump_due=()))[2]
    assert check.verdict is PENDING


def test_a_failed_drill_or_a_missing_one_fails() -> None:
    drill_at = kit.backups().drill_due[0]
    failed = kit.backups(drills=((drill_at, False),))
    assert judge.judge_health(kit.health(), failed)[3].verdict is FAIL
    missing = kit.backups(drills=())
    assert judge.judge_health(kit.health(), missing)[3].verdict is FAIL
    none_due = kit.backups(drills=(), drill_due=())
    assert judge.judge_health(kit.health(), none_due)[3].verdict is PENDING


def test_an_unreadable_backup_folder_is_open() -> None:
    checks = judge.judge_health(kit.health(), kit.backups(readable=False))
    assert verdicts(checks)["11c"] is OPEN
    assert verdicts(checks)["11d"] is OPEN


def test_an_unnamed_events_answer_is_settled_and_never_stale() -> None:
    # the sign-ins model settles UNNAMED as an answer (sightings, no usable name): the run does
    # not retry it, so the gate must not count it as past its retry time (the first real report)
    lk = kit.lookup("2026-10-28", complete=False, reason="unnamed_events", ago_h=48)
    retrying = kit.signins(lk)
    assert judge.stale_lookups(retrying) == ["unnamed_events 2026-10-28"]
    settled = kit.signins(lk, terminal_reasons=frozenset({"logs_gone", "unnamed_events"}))
    assert judge.stale_lookups(settled) == []
