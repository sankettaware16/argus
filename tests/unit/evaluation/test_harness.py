"""P2: scoring against the gold set, with Wilson intervals (D-082)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from argus.evaluation.harness import MIN_SAMPLE, Item, Rate, from_gold, report, score

pytestmark = pytest.mark.unit


def it(n: int, answer: str, predicted: str | None, rule: str = "r", split: str = "test") -> Item:
    return Item(f"i{n}", rule, split, answer, predicted)


@pytest.mark.parametrize(
    ("hits", "total", "low", "high"),
    [(0, 10, 0.0, 0.2775), (10, 10, 0.7225, 1.0), (5, 10, 0.2366, 0.7634), (1, 1, 0.2065, 1.0)],
)
def test_wilson_intervals(hits: int, total: int, low: float, high: float) -> None:
    interval = Rate(hits, total).interval
    assert interval is not None
    assert interval[0] == pytest.approx(low, abs=1e-4)
    assert interval[1] == pytest.approx(high, abs=1e-4)


def test_rates_say_when_they_are_too_small() -> None:
    assert Rate(0, 0).value is None
    assert Rate(0, 0).interval is None
    assert Rate(0, 0).text() == "not measured (no items)"
    assert Rate(3, 4).text() == "3/4 = 75% (95%: 30% to 95%; too few to judge (< 10))"
    assert Rate(9, 10).text() == "9/10 = 90% (95%: 60% to 98%)"
    assert Rate(9, MIN_SAMPLE).enough
    assert not Rate(1, MIN_SAMPLE - 1).enough


def test_scores() -> None:
    items = [
        it(1, "true_positive", "true_positive", "a"),
        it(2, "true_positive", "benign_expected", "a"),  # a missed attack: the worst error
        it(3, "true_positive", None, "b"),  # deferred: no proposal
        it(4, "benign_policy", "benign_expected", "b"),
        it(5, "rule_false_positive", "rule_false_positive", "b"),
        it(6, "inconclusive", "true_positive", "b"),
    ]
    s = score(items)
    assert (s.items, s.proposed) == (6, 5)
    assert (s.accuracy.hits, s.accuracy.total) == (2, 5)
    assert (s.tp_recall.hits, s.tp_recall.total) == (1, 3)
    assert s.tp_proposed_benign == ("i2",)
    assert (s.benign_precision.hits, s.benign_precision.total) == (2, 3)
    assert {k: (v.hits, v.total) for k, v in s.per_rule.items()} == {"a": (1, 2), "b": (1, 3)}
    assert s.confusion == {
        ("benign_policy", "benign_expected"): 1, ("inconclusive", "true_positive"): 1,
        ("rule_false_positive", "rule_false_positive"): 1, ("true_positive", "—"): 1,
        ("true_positive", "benign_expected"): 1, ("true_positive", "true_positive"): 1,
    }  # fmt: skip


def test_the_report_is_plain_and_complete() -> None:
    lines = report(score([it(1, "true_positive", "true_positive"), it(2, "x", None)]), "T")
    assert lines[0] == "T: 2 answered items, a proposal for 1"
    assert lines[3] == "- true positives proposed benign (must be 0): 0"
    assert lines[4] == "- benign proposals that were right: not measured (no items)"
    assert "  - r: 1/1 = 100% (95%: 21% to 100%; too few to judge (< 10))" in lines
    assert "  - x → —: 1" in lines


def test_gold_rows_become_items() -> None:
    rows = [
        SimpleNamespace(investigation_id="a", rule_name="r", split="dev", outcome="true_positive"),
        SimpleNamespace(investigation_id="b", rule_name="r", split="test", outcome=None),
        SimpleNamespace(investigation_id="c", rule_name="s", split="test", outcome="inconclusive"),
    ]
    assert from_gold(rows, {"a": "true_positive"}) == [
        Item("a", "r", "dev", "true_positive", "true_positive"),
        Item("c", "s", "test", "inconclusive", None),
    ]
    assert [i.investigation_id for i in from_gold(rows, {}, "dev")] == ["a"]


def test_records_are_frozen_and_the_report_has_its_headings() -> None:
    with pytest.raises(AttributeError):
        Rate(1, 2).hits = 3  # type: ignore[misc]
    s = score([it(1, "true_positive", "true_positive")])
    with pytest.raises(AttributeError):
        s.items = 0  # type: ignore[misc]
    with pytest.raises(AttributeError):
        it(1, "a", "b").answer = "c"  # type: ignore[misc]
    lines = report(s, "T")
    assert lines[5] == "- per rule:"
    assert lines[7] == "- answer → proposed:"


def test_the_bounds_are_clamped_exactly() -> None:
    assert Rate(20, 20).interval == (pytest.approx(0.8389, abs=1e-4), 1.0)  # 1 + 2e-16 unclamped
    assert Rate(0, 7).interval == (0.0, pytest.approx(0.3543, abs=1e-4))
