"""Q-F3: the gold measurement's arithmetic. The inconclusive rate before and after, the pairs,
the exact McNemar test, and a true positive proposed benign in either arm."""

from __future__ import annotations

import math

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.investigation import measure
from argus.investigation.measure import Measured, Plan, compare, mcnemar

pytestmark = pytest.mark.unit
TP, BENIGN = "true_positive", "benign_expected"


@pytest.mark.parametrize(
    ("gained", "lost", "p"),
    [(0, 0, 1.0), (8, 0, 2 / 256), (0, 8, 2 / 256), (5, 5, 1.0), (7, 1, 2 * 9 / 256),
     (1, 0, 1.0), (10, 2, 2 * sum(math.comb(12, k) for k in range(3)) / 4096)],
)  # fmt: skip
def test_the_exact_mcnemar_test(gained: int, lost: int, p: float) -> None:
    assert mcnemar(gained, lost) == pytest.approx(p)


@given(st.integers(0, 60), st.integers(0, 60))
def test_mcnemar_is_a_symmetric_probability(a: int, b: int) -> None:
    assert mcnemar(a, b) == mcnemar(b, a)
    assert 0.0 <= mcnemar(a, b) <= 1.0


ANSWERS = {"a": BENIGN, "b": TP, "c": BENIGN, "d": TP, "e": BENIGN}


def test_a_dry_run_measures_only_the_baseline() -> None:
    before = {"a": None, "b": None, "c": BENIGN, "d": TP, "e": None}
    got = compare(ANSWERS, before, None)
    assert got.items == 5
    assert (got.inconclusive_before.hits, got.inconclusive_before.total) == (3, 5)
    assert got.inconclusive_after is None
    assert got.p is None
    assert got.holds
    assert any("not measured" in line for line in measure.lines(got))


def test_pairs_are_counted_item_by_item() -> None:
    before = {"a": None, "b": None, "c": BENIGN, "d": TP, "e": None}
    after = {"a": BENIGN, "b": None, "c": None, "d": TP, "e": TP}
    got = compare(ANSWERS, before, after)
    assert got.gained == 2  # a (right) and e (wrong)
    assert got.gained_right == 1
    assert got.lost == 1  # c
    assert got.changed == 0
    assert (got.inconclusive_after.hits if got.inconclusive_after else None) == 2  # b and c
    assert got.p == mcnemar(2, 1)
    assert got.holds


def test_a_decided_item_that_changes_is_counted() -> None:
    got = compare({"a": BENIGN}, {"a": TP}, {"a": "benign_policy"})
    assert (got.gained, got.lost, got.changed) == (0, 0, 1)


def test_a_true_positive_proposed_benign_fails_the_gate_in_either_arm() -> None:
    before = {"a": None, "b": BENIGN, "c": None, "d": None, "e": None}
    after = {"a": None, "b": None, "c": None, "d": "rule_false_positive", "e": None}
    got = compare(ANSWERS, before, after)
    assert got.tp_benign_before == ("b",)
    assert got.tp_benign_after == ("d",)
    assert not got.holds
    text = "\n".join(measure.lines(got))
    assert "benign before (must be 0): 1" in text
    assert "benign after (must be 0): 1" in text
    assert compare(ANSWERS, {"b": BENIGN}, None).holds is False
    assert compare(ANSWERS, {"b": TP}, {"b": TP}).holds


outcomes = st.sampled_from([None, BENIGN, TP, "inconclusive"])


@given(
    st.dictionaries(st.sampled_from("abcdefghij"), st.sampled_from([BENIGN, TP]), min_size=1),
    st.data(),
)
def test_the_pairs_add_up(answers: dict[str, str], data: st.DataObject) -> None:
    before = {i: data.draw(st.sampled_from([None, BENIGN, TP])) for i in answers}
    after = {i: data.draw(st.sampled_from([None, BENIGN, TP])) for i in answers}
    got = compare(answers, before, after)
    assert got.inconclusive_after is not None
    assert got.inconclusive_before.hits - got.gained + got.lost == got.inconclusive_after.hits
    assert got.gained_right <= got.gained
    assert got.holds == (
        not [i for i in answers if answers[i] == TP and (before[i] in ("benign_expected",)
                                                          or after[i] in ("benign_expected",))]
    )  # fmt: skip
    flipped = compare(answers, after, before)
    assert (flipped.gained, flipped.lost) == (got.lost, got.gained)


def test_the_report_names_the_repeats_and_what_a_wave_could_ask() -> None:
    m = Measured(
        answers={"a": BENIGN, "b": TP},
        before={"a": None, "b": None},
        after=[{"a": BENIGN, "b": None}, {"a": BENIGN, "b": None}],
        plans=[Plan("a", 2, True, 2, 1), Plan("b", 0, False, 0, 0)],
        notes=["x: its gold dossier is gone"],
    )
    text = "\n".join(measure.report(m))
    assert "repeat 1" in text
    assert "repeat 2" in text
    assert "the repeats agree item by item: yes" in text
    assert "could ask something for 1 of 2 items: 2 requests, 1 of them heavy" in text
    assert "note: x: its gold dossier is gone" in text
    m.after[1] = {"a": None, "b": None}
    assert "the repeats agree item by item: NO" in "\n".join(measure.report(m))
    dry = Measured(answers={"a": BENIGN}, before={"a": None}, after=[], plans=[], notes=[])
    assert "a dry run sends nothing" in "\n".join(measure.report(dry))
