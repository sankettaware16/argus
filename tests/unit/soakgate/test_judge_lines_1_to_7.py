"""P4-A1: the judges of lines 1 to 7, each a pure function over typed facts. A baseline of facts
that PASS, and one change at a time: the boundary of each rule, and what each PENDING check says
it lacks."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.soakgate import judge
from argus.soakgate.model import Check, Verdict
from tests.unit.soakgate import kit

pytestmark = pytest.mark.unit

PASS, FAIL, PENDING, OPEN = Verdict.PASS, Verdict.FAIL, Verdict.PENDING, Verdict.OPEN


def verdicts(checks: list[Check]) -> dict[str, Verdict]:
    return {c.id: c.verdict for c in checks}


# --------------------------------------------------------------------------- line 1


def test_a_clean_lifecycle_passes_with_its_n() -> None:
    checks = judge.judge_lifecycle(kit.lifecycle())
    assert verdicts(checks) == {"1a": PASS, "1b": PASS, "1c": PASS}
    assert [c.n for c in checks] == [30, 3, 3]


def test_no_step_yet_is_pending_not_a_pass() -> None:
    checks = judge.judge_lifecycle(
        kit.lifecycle(posts=0, steps=0, by_state={}, creates_sent=0, kibana_cases=0)
    )
    assert verdicts(checks) == {"1a": PENDING, "1b": PENDING, "1c": PENDING}
    assert all(c.needs for c in checks)
    assert all(c.n == 0 for c in checks)


def test_a_step_in_doubt_for_over_an_hour_fails() -> None:
    checks = judge.judge_lifecycle(kit.lifecycle(in_doubt=("case 4 step 77 comment:x ambiguous",)))
    assert checks[0].verdict is FAIL
    assert "case 4 step 77" in checks[0].detail
    assert checks[0].measured["in_doubt_over_1h"] == 1


def test_a_second_create_fails_and_names_the_journal() -> None:
    checks = judge.judge_lifecycle(kit.lifecycle(second_creates=("case 2",)))
    assert checks[1].verdict is FAIL
    assert "journal" in checks[1].detail


def test_a_duplicate_kibana_case_or_finding_fails() -> None:
    assert (
        judge.judge_lifecycle(kit.lifecycle(duplicate_cases=("case 3 (2 Kibana cases)",)))[
            2
        ].verdict
        is FAIL
    )
    assert judge.judge_lifecycle(kit.lifecycle(duplicate_findings=1))[2].verdict is FAIL


def test_steps_on_their_way_do_not_fail() -> None:
    facts = kit.lifecycle(steps=10, by_state={"verified": 4, "planned": 3, "sent": 2, "held": 1})
    first = judge.judge_lifecycle(facts)[0]
    assert first.verdict is PASS
    assert "6 still on their way" in first.detail


# --------------------------------------------------------------------------- line 2


def test_every_case_with_a_person_confirm_passes() -> None:
    (check,) = judge.judge_person_only([kit.opened(1), kit.opened(2)])
    assert (check.verdict, check.n) == (PASS, 2)


def test_no_kibana_case_is_pending() -> None:
    (check,) = judge.judge_person_only([])
    assert check.verdict is PENDING


def test_a_case_without_a_persons_confirm_fails_and_the_assistants_is_named() -> None:
    (check,) = judge.judge_person_only(
        [kit.opened(1), kit.opened(7, person=False, assistant=True), kit.opened(9, person=False)]
    )
    assert check.verdict is FAIL
    assert "case 7, 9" in check.detail
    assert "1 confirmed only by ARGUS's own assistant account" in check.detail


# --------------------------------------------------------------------------- line 3


def test_clean_writes_pass_every_check_with_the_minimums_met() -> None:
    checks = judge.judge_writes(kit.writes())
    assert verdicts(checks) == {"3a": PASS, "3b": PASS, "3c": PASS, "3d": PASS}


def test_no_write_yet_is_pending() -> None:
    checks = judge.judge_writes(kit.writes(steps_sent=0, sends=0, rows=(), requests_checked=0))
    assert verdicts(checks)["3a"] is PENDING
    assert verdicts(checks)["3b"] is PENDING
    assert verdicts(checks)["3c"] is PENDING


def test_the_gap_between_steps_sent_and_ledger_rows_is_named() -> None:
    checks = judge.judge_writes(kit.writes(steps_sent=3, sends=4, steps_without_row=(31,)))
    assert checks[0].verdict is FAIL
    assert "gap +2" in checks[0].detail
    assert "steps with no row: 31" in checks[0].detail
    assert judge.judge_writes(kit.writes(rows_without_step=1))[0].verdict is FAIL


def test_a_row_without_a_recorded_health_fails_line_3a() -> None:
    rows = (kit.row(0, step_id=1, health=None), kit.row(1, step_id=2))
    assert judge.judge_writes(kit.writes(rows=rows))[0].verdict is FAIL


@pytest.mark.parametrize(
    "bad",
    [
        {"health": "caution"},
        {"health": "degraded"},
        {"probe_state": "caution"},
        {"at": kit.T0.replace(hour=1, minute=40)},  # before the window opens
        {"at": kit.T0.replace(hour=17, minute=30)},  # the window's end is outside it
        {"at": kit.T0.replace(hour=0, minute=10)},  # quiet hours
    ],
)
def test_a_write_outside_normal_or_the_window_fails(bad: dict[str, object]) -> None:
    rows = (kit.row(0, step_id=1, **bad),)
    checks = judge.judge_writes(kit.writes(steps_sent=1, sends=1, rows=rows))
    assert verdicts(checks)["3b"] is FAIL


def test_a_write_with_no_probe_near_it_is_noted_not_failed() -> None:
    rows = (kit.row(0, step_id=1, probe_state=None), kit.row(1, step_id=2))
    check = judge.judge_writes(kit.writes(rows=rows))[1]
    assert check.verdict is PASS
    assert "1 had no probe within 5 minutes" in check.detail


def test_a_write_class_other_than_wc_fails() -> None:
    check = judge.judge_writes(kit.writes(other_class_rows=(("W1", 2),)))[1]
    assert check.verdict is FAIL
    assert "2 writes of a class other than WC" in check.detail


def test_a_template_outside_the_allowlist_fails() -> None:
    check = judge.judge_writes(kit.writes(unknown_templates=(("cases.delete", 1),)))[2]
    assert check.verdict is FAIL
    assert "cases.delete x1" in check.detail


@pytest.mark.parametrize(
    ("cases", "verdicts_", "cycles", "short"),
    [
        (3, 1, 20, {}),
        (2, 1, 20, {"cases_posted": 1}),
        (3, 0, 20, {"verdicts_recorded": 1}),
        (3, 1, 19, {"read_back_cycles_complete": 1}),
        (0, 0, 0, {"cases_posted": 3, "verdicts_recorded": 1, "read_back_cycles_complete": 20}),
    ],
)
def test_the_minimum_counts_are_pending_below_and_pass_at_the_minimum(
    cases: int, verdicts_: int, cycles: int, short: dict[str, int]
) -> None:
    facts = kit.writes(cases_posted=cases, verdicts_recorded=verdicts_, cycles_complete=cycles)
    check = judge.judge_writes(facts)[3]
    assert check.verdict is (PASS if not short else PENDING)
    assert check.measured["short_by"] == short
    assert (check.needs is None) == (not short)


@given(
    cases=st.integers(0, 10),
    verdict=st.integers(0, 5),
    cycles=st.integers(0, 60),
    more=st.tuples(st.integers(0, 3), st.integers(0, 3), st.integers(0, 10)),
)
def test_the_minimum_counts_never_get_worse_with_more_counts(
    cases: int, verdict: int, cycles: int, more: tuple[int, int, int]
) -> None:
    def judged(c: int, v: int, y: int) -> Verdict:
        facts = kit.writes(cases_posted=c, verdicts_recorded=v, cycles_complete=y)
        return judge.judge_writes(facts)[3].verdict

    before = judged(cases, verdict, cycles)
    after = judged(cases + more[0], verdict + more[1], cycles + more[2])
    if before is PASS:
        assert after is PASS
    below = (
        cases < judge.MIN_CASES_POSTED or verdict < judge.MIN_VERDICTS or cycles < judge.MIN_CYCLES
    )
    assert (before is PENDING) == below


# --------------------------------------------------------------------------- line 4


def test_a_case_opened_inside_fifteen_minutes_passes_and_reports_its_spread() -> None:
    checks = judge.judge_coverage(
        [kit.confirmed(1, created=5), kit.confirmed(2, created=15)], kit.NOW
    )
    assert verdicts(checks) == {"4a": PASS, "4b": PASS}
    assert checks[0].measured["creation_lag"] == {"n": 2, "max_s": 900.0, "p95_s": 900.0}
    assert checks[1].measured["completion_lag"]["n"] == 2


def test_sixteen_minutes_is_late() -> None:
    checks = judge.judge_coverage([kit.confirmed(1, created=16)], kit.NOW)
    assert checks[0].verdict is FAIL
    assert "16 min" in checks[0].detail


def test_a_case_not_opened_after_fifteen_minutes_is_late_but_not_before() -> None:
    soon = kit.NOW - timedelta(minutes=10)
    waiting = replace(kit.confirmed(1, created=None, done=None), ready_at=soon)
    assert judge.judge_coverage([waiting], kit.NOW)[0].verdict is PENDING
    overdue = replace(waiting, ready_at=kit.NOW - timedelta(minutes=16))
    check = judge.judge_coverage([overdue], kit.NOW)[0]
    assert check.verdict is FAIL
    assert "not opened" in check.detail


def test_no_confirmed_true_positive_is_pending() -> None:
    checks = judge.judge_coverage([], kit.NOW)
    assert verdicts(checks) == {"4a": PENDING}


def test_a_case_opened_before_it_was_ready_has_no_lag() -> None:
    early = replace(kit.confirmed(1), created_at=kit.T0 - timedelta(minutes=3))
    assert judge.judge_coverage([early], kit.NOW)[0].measured["creation_lag"]["max_s"] == 0.0


@given(lags=st.lists(st.integers(0, 3_000), min_size=1, max_size=8), extra=st.integers(0, 3_000))
def test_one_more_late_case_never_turns_a_fail_into_a_pass(lags: list[int], extra: int) -> None:
    def judged(values: list[int]) -> Verdict:
        cases = [kit.confirmed(i, created=0) for i, _ in enumerate(values)]
        cases = [
            replace(c, created_at=c.ready_at + timedelta(seconds=s))
            for c, s in zip(cases, values, strict=True)
        ]
        return judge.judge_coverage(cases, kit.NOW)[0].verdict

    base = judged(lags)
    assert (base is FAIL) == any(s > 900 for s in lags)
    if base is FAIL:
        assert judged([*lags, extra]) is FAIL


# --------------------------------------------------------------------------- line 5


def test_no_automatic_closure_and_no_kibana_close_passes() -> None:
    assert verdicts(judge.judge_closures(kit.closures())) == {"5a": PASS, "5b": PASS}


def test_an_automatic_closure_fails() -> None:
    check = judge.judge_closures(kit.closures(automatic=("case 4 closed by argus:watch",)))[0]
    assert check.verdict is FAIL
    assert "case 4 closed by argus:watch" in check.detail


def test_a_kibana_close_request_fails_even_when_refused() -> None:
    check = judge.judge_closures(kit.closures(kibana_closes=("cases.close x1",)))[1]
    assert check.verdict is FAIL


def test_closures_with_nothing_observed_are_pending() -> None:
    checks = judge.judge_closures(kit.closures(events=0, closures=0, kibana_requests=0))
    assert verdicts(checks) == {"5a": PENDING, "5b": PENDING}


# --------------------------------------------------------------------------- line 6


def test_clean_reconciliation_passes() -> None:
    assert verdicts(judge.judge_reconciliation(kit.reconcile())) == {
        "6a": PASS,
        "6b": PASS,
        "6c": PASS,
        "6d": PASS,
    }


def test_the_lag_limit_is_fifteen_minutes_at_the_95th_percentile() -> None:
    ok = judge.judge_reconciliation(kit.reconcile(lags_s=(10.0, 900.0)))[0]
    late = judge.judge_reconciliation(kit.reconcile(lags_s=(10.0, 901.0)))[0]
    assert (ok.verdict, late.verdict) == (PASS, FAIL)
    many = tuple([30.0] * 19 + [5_000.0])  # one in twenty: the 95th percentile is the 19th
    assert judge.judge_reconciliation(kit.reconcile(lags_s=many))[0].verdict is PASS


def test_no_person_change_yet_is_pending() -> None:
    assert judge.judge_reconciliation(kit.reconcile(lags_s=()))[0].verdict is PENDING


def test_a_revert_or_an_unexplained_action_fails() -> None:
    checks = judge.judge_reconciliation(
        kit.reconcile(reverts=("case 2 close",), unexplained=1, unexplained_resolved=2)
    )
    assert verdicts(checks)["6b"] is FAIL
    assert verdicts(checks)["6c"] is FAIL
    assert "2 more were resolved" in checks[2].detail


def test_without_a_complete_cycle_nothing_is_proved() -> None:
    checks = judge.judge_reconciliation(kit.reconcile(cycles=2, complete=0, partial=2))
    assert verdicts(checks)["6b"] is PENDING
    assert verdicts(checks)["6c"] is PENDING


def test_the_mirror_missing_the_case_teams_cases_is_pending_and_says_p4_b1() -> None:
    check = judge.judge_reconciliation(kit.reconcile(team_cases=3, team_cases_in_mirror=1))[3]
    assert check.verdict is PENDING
    assert "P4-B1" in (check.needs or "")
    assert "2 of 3" in check.detail


def test_no_case_team_case_is_pending_for_the_mirror() -> None:
    check = judge.judge_reconciliation(kit.reconcile(team_cases=0, team_cases_in_mirror=0))[3]
    assert check.verdict is PENDING


# --------------------------------------------------------------------------- line 7


def test_decided_notified_cases_pass() -> None:
    assert verdicts(judge.judge_notified(kit.notified())) == {"7a": PASS, "7b": PASS}


def test_an_undecided_investigation_fails() -> None:
    check = judge.judge_notified(kit.notified(undecided=("case 5 investigation abcd1234",)))[0]
    assert check.verdict is FAIL
    assert check.n == 11


def test_a_change_slower_than_one_pass_fails() -> None:
    assert judge.judge_notified(kit.notified(change_lags_s=(60.0, 901.0)))[1].verdict is FAIL
    assert judge.judge_notified(kit.notified(change_lags_s=(60.0, 900.0)))[1].verdict is PASS


def test_no_notified_case_or_no_change_is_pending() -> None:
    checks = judge.judge_notified(
        kit.notified(cases=0, investigations=0, changed=0, change_lags_s=())
    )
    assert verdicts(checks) == {"7a": PENDING, "7b": PENDING}
