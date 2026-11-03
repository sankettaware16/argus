"""AR2 (D-150, D-160): one investigator run per pattern. The pattern key is the Patterns page's,
per rule and IST day, split by the evidence's flags; the picker takes raised patterns first, then
the most severe and newest, one member each; a covered pattern's members join its run; a shared
run is never an assessment of the others."""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from argus.assess import patterns
from argus.assess.patterns import Candidate, Key

T0 = datetime(2026, 10, 24, 6, 0, tzinfo=UTC)
D0 = date(2026, 10, 24)
P = "a" * 64
Q = "b" * 64
GROUP_KEY = '[["source.ip","10.1.1.1"]]'
BEACON = {"name": "proxy.regularity", "status": "known", "value": 0.0}
LISTED = {"name": "ti.listed", "status": "known", "value": 2}


def cand(n: int, pattern: str = P, *, day: date = D0, severity: int = 2, minutes: int = 0,
         raised: bool = False) -> Candidate:  # fmt: skip
    return Candidate(uuid.UUID(int=n), 1, "generic@1", f"{n:064x}", pattern, day, severity,
                     T0 + timedelta(minutes=minutes), raised)  # fmt: skip


def body(*signals: dict[str, Any], fields: dict[str, Any] | None = None,
         steps: list[dict[str, Any]] | None = None) -> dict[str, Any]:  # fmt: skip
    return {"local_signals": list(signals), "signals": [],
            "report": {"steps": steps or []},
            "context": {"pack": {"fields": fields or {}}}}  # fmt: skip


def make(body_: dict[str, Any], *, rule: str = "r1", bucket: datetime = T0,
         n: int = 1) -> Candidate:  # fmt: skip
    return patterns.candidate(
        investigation_id=uuid.UUID(int=n), version=1, pack="generic@1", dossier_hash=f"{n:064x}",
        rule_id=rule, group_key=GROUP_KEY, severity="high", bucket_start=bucket,
        last_event_at=bucket, body=body_,
    )  # fmt: skip


# -- the pattern's key -------------------------------------------------------------------------


def test_the_same_rule_and_checks_are_one_pattern_and_the_hash_is_stable() -> None:
    a, b = make(body(), n=1), make(body(), n=2)
    assert a.pattern == b.pattern
    assert a.key == b.key
    assert len(a.pattern) == 64
    assert set(a.pattern) <= set("0123456789abcdef")
    assert patterns.pattern_hash(("r1", (), False, ()), ()) == patterns.pattern_hash(
        ("r1", (), False, ()), ()
    )  # fmt: skip


def test_another_rule_or_another_check_outcome_is_another_pattern() -> None:
    answered = [{"number": 1, "status": "answered", "fields": []}]
    assert make(body(), rule="r1").pattern != make(body(), rule="r2").pattern
    assert make(body(), n=1).pattern != make(body(steps=answered), n=2).pattern


def test_a_flag_splits_a_pattern_and_marks_it_raised() -> None:
    plain, beacon, listed = make(body()), make(body(BEACON)), make(body(LISTED))
    assert (plain.raised, beacon.raised, listed.raised) == (False, True, True)
    assert len({plain.pattern, beacon.pattern, listed.pattern}) == 3


def test_an_unknown_signal_is_no_flag() -> None:
    unknown = {"name": "proxy.regularity", "status": "unknown", "value": 0.0}
    assert not make(body(unknown)).raised
    assert make(body(unknown)).pattern == make(body()).pattern


def test_the_values_a_rules_steps_look_at_decide_the_pattern_like_the_patterns_page() -> None:
    steps = [{"number": 1, "status": "answered", "fields": ["url.path"]}]
    few = {"url.path": {"distinct": 1, "top": [["/a", 3]]}}
    other = {"url.path": {"distinct": 1, "top": [["/b", 3]]}}
    many = {"url.path": {"distinct": 9, "top": [["/a", 1], ["/b", 1]]}}
    assert (make(body(steps=steps, fields=few)).pattern
            != make(body(steps=steps, fields=other)).pattern)  # fmt: skip
    # more than a few values are not part of the key (display.FEW)
    assert make(body(steps=steps, fields=many)).pattern == make(body(steps=steps)).pattern


def test_the_day_is_the_ist_day_of_the_bucket() -> None:
    assert patterns.day_of(datetime(2026, 10, 24, 18, 29, 59, tzinfo=UTC)) == date(2026, 10, 24)
    assert patterns.day_of(datetime(2026, 10, 24, 18, 30, tzinfo=UTC)) == date(2026, 10, 25)
    first = make(body(), bucket=datetime(2026, 10, 24, 18, 30, tzinfo=UTC))
    assert first.day == date(2026, 10, 25)
    assert first.pattern == make(body(), bucket=T0).pattern  # the key is per day, not the hash
    assert first.key != make(body(), bucket=T0).key


# -- the picker --------------------------------------------------------------------------------


def runs(todo: patterns.Plan) -> list[int]:
    return [r.investigation_id.int for r in todo.runs]


def test_one_run_per_pattern_on_its_best_member_and_the_rest_attached() -> None:
    members = [cand(1, severity=2, minutes=5), cand(2, severity=3, minutes=1),
               cand(3, severity=3, minutes=9)]  # fmt: skip
    todo = patterns.plan(members, {}, {}, budget=10)
    assert runs(todo) == [3]  # the highest severity, then the newest
    assert {c.investigation_id.int for c in todo.attach[uuid.UUID(int=3)]} == {1, 2}
    assert todo.joins == ()


def test_raised_patterns_first_then_severity_then_the_newest() -> None:
    items = [
        cand(1, "p1", severity=4, minutes=50),
        cand(2, "p2", severity=1, minutes=1, raised=True),
        cand(3, "p3", severity=3, minutes=10),
        cand(4, "p4", severity=3, minutes=20),
        cand(5, "p5", severity=1, minutes=99, raised=True),
    ]  # fmt: skip
    assert runs(patterns.plan(items, {}, {}, budget=10)) == [5, 2, 1, 4, 3]
    assert runs(patterns.plan(items, {}, {}, budget=2)) == [5, 2]  # the cap cuts the tail
    assert runs(patterns.plan(items, {}, {}, budget=0)) == []
    assert runs(patterns.plan(items, {}, {}, budget=-3)) == []


def test_a_pattern_is_per_rule_pattern_and_day() -> None:
    items = [cand(1, P, day=D0), cand(2, P, day=D0 + timedelta(days=1)), cand(3, Q, day=D0)]
    assert sorted(runs(patterns.plan(items, {}, {}, budget=10))) == [1, 2, 3]


def test_members_of_a_covered_pattern_join_its_run_and_cost_no_run() -> None:
    items = [cand(1, P), cand(2, P), cand(3, Q)]
    todo = patterns.plan(items, {(P, D0): 77}, {}, budget=10)
    assert runs(todo) == [3]
    assert sorted((c.investigation_id.int, run) for c, run in todo.joins) == [(1, 77), (2, 77)]
    full = patterns.plan(items, {(P, D0): 77}, {}, budget=0)
    assert runs(full) == []
    assert len(full.joins) == 2  # attaching is free


def test_a_pattern_with_three_failed_runs_waits_for_tomorrow() -> None:
    items = [cand(1, P), cand(2, Q)]
    todo = patterns.plan(items, {}, {(P, D0): patterns.MAX_FAILED}, budget=10)
    assert runs(todo) == [2]
    again = patterns.plan(items, {}, {(P, D0): patterns.MAX_FAILED - 1}, budget=10)
    assert sorted(runs(again)) == [1, 2]
    covered = patterns.plan(items, {(P, D0): 5}, {(P, D0): 9}, budget=10)
    assert [c.investigation_id.int for c, _ in covered.joins] == [1]  # a live run wins


def test_nothing_in_nothing_out() -> None:
    assert patterns.plan([], {}, {}, budget=5) == patterns.Plan((), {}, ())


candidates = st.builds(
    cand,
    st.integers(1, 10_000),
    st.sampled_from([P, Q, "c" * 64]),
    day=st.sampled_from([D0, D0 + timedelta(days=1)]),
    severity=st.integers(0, 4),
    minutes=st.integers(0, 300),
    raised=st.booleans(),
)
covered_maps = st.dictionaries(
    st.tuples(st.sampled_from([P, Q, "c" * 64]), st.sampled_from([D0, D0 + timedelta(days=1)])),
    st.integers(1, 99), max_size=3,
)  # fmt: skip


@given(st.lists(candidates, max_size=40, unique_by=lambda c: c.investigation_id), covered_maps,
       st.integers(-2, 12))  # fmt: skip
def test_the_plan_accounts_for_every_candidate_once_and_keeps_to_its_budget(
    items: list[Candidate], covered: dict[Key, int], budget: int
) -> None:
    todo = patterns.plan(items, covered, {}, budget)
    assert len(todo.runs) <= max(budget, 0)
    seen = [c.investigation_id for c in todo.runs]
    seen += [c.investigation_id for rest in todo.attach.values() for c in rest]
    seen += [c.investigation_id for c, _ in todo.joins]
    assert len(seen) == len(set(seen))  # no candidate twice
    by_key: dict[Key, list[Candidate]] = {}
    for c in items:
        by_key.setdefault(c.key, []).append(c)
    for run in todo.runs:
        group = by_key[run.key]
        assert run.key not in covered  # a covered pattern gets no new run
        assert run == max(group, key=Candidate.rank)  # on its best member
        rest = {c.investigation_id for c in todo.attach[run.investigation_id]}
        assert rest == {c.investigation_id for c in group} - {run.investigation_id}
        assert all(c.key == run.key for c in todo.attach[run.investigation_id])
    for member, assessment_id in todo.joins:
        assert covered[member.key] == assessment_id
    for key in covered:  # every member of a covered pattern joins
        joined = {c.investigation_id for c, _ in todo.joins if c.key == key}
        assert joined == {c.investigation_id for c in by_key.get(key, [])}
    first_plain = next((i for i, r in enumerate(todo.runs) if not r.raised), len(todo.runs))
    assert all(not r.raised for r in todo.runs[first_plain:])  # raised first


@given(st.lists(candidates, max_size=30, unique_by=lambda c: c.investigation_id),
       st.integers(0, 8), st.randoms(use_true_random=False))  # fmt: skip
def test_the_plan_does_not_depend_on_the_order_of_the_candidates(
    items: list[Candidate], budget: int, rnd: object
) -> None:
    shuffled = list(items)
    rnd.shuffle(shuffled)  # type: ignore[attr-defined]
    one = patterns.plan(items, {}, {}, budget)
    two = patterns.plan(shuffled, {}, {}, budget)
    assert one.runs == two.runs
    assert {k: set(v) for k, v in one.attach.items()} == {k: set(v) for k, v in two.attach.items()}
    assert set(one.joins) == set(two.joins)


@given(st.lists(candidates, max_size=30, unique_by=lambda c: c.investigation_id), st.integers(1, 6))
def test_raising_the_budget_only_adds_runs_at_the_end(items: list[Candidate], budget: int) -> None:
    small = patterns.plan(items, {}, {}, budget)
    large = patterns.plan(items, {}, {}, budget + 3)
    assert large.runs[: len(small.runs)] == small.runs


def test_a_member_of_a_suggested_case_is_raised_without_changing_its_pattern() -> None:
    plain = make(body(), n=1)
    kept = patterns.candidate(
        investigation_id=uuid.UUID(int=2), version=1, pack="generic@1", dossier_hash="2" * 64,
        rule_id="r1", group_key=GROUP_KEY, severity="high", bucket_start=T0, last_event_at=T0,
        body=body(), in_case=True,
    )  # fmt: skip
    assert (plain.raised, kept.raised) == (False, True)
    assert kept.pattern == plain.pattern  # the case is not part of the key


def test_a_pattern_with_a_raised_member_runs_on_it_and_goes_first() -> None:
    mixed = [cand(1, P, severity=1, raised=True), cand(2, P, severity=4, minutes=30)]
    other = cand(3, Q, severity=4, minutes=60)
    todo = patterns.plan([*mixed, other], {}, {}, budget=2)
    assert runs(todo) == [1, 3]  # the raised member is the best of its pattern; it goes first
    assert {c.investigation_id.int for c in todo.attach[uuid.UUID(int=1)]} == {2}
