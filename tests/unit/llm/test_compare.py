"""P2's privacy comparison (D-078): scoring and the decision rule."""

from __future__ import annotations

import pytest

from argus.llm.compare import Answer, ArmScore, decide, mcnemar, score

pytestmark = pytest.mark.unit
TP, BEN = "true_positive", "benign_expected"


def answers(verdicts: str, **extra: object) -> dict[str, Answer]:
    """``"TB.."``: item i0 true_positive, i1 benign, ..."""
    return {f"i{n}": Answer(TP if v == "T" else BEN, **extra) for n, v in enumerate(verdicts)}  # type: ignore[arg-type]


GOLD = {f"i{n}": TP if v == "T" else BEN for n, v in enumerate("TTBBBBBBBB")}


@pytest.mark.parametrize(
    ("b", "c", "p"),
    [(0, 0, 1.0), (5, 0, 0.0625), (0, 5, 0.0625), (10, 0, 2 / 1024), (3, 3, 1.0), (1, 0, 1.0),
     (6, 1, 0.125)],
)  # fmt: skip
def test_mcnemar(b: int, c: int, p: float) -> None:
    assert mcnemar(b, c) == pytest.approx(p)


def test_scores() -> None:
    scores = score(
        GOLD,
        {
            "A-fake": answers("TTBBBBBBBB", facts_ok=True, tokens=100, seconds=1.0),
            "B": answers("TBBBBBBBBT", asked_withheld=True, tokens=80, seconds=2.0),
        },
    )
    a, b = scores["A-fake"], scores["B"]
    assert (a.items, a.accuracy, a.positives, a.recall, a.missed) == (10, 1.0, 2, 1.0, ())
    assert a.agreement == 1.0
    assert a.mcnemar_p == 1.0
    assert a.facts_ok == 1.0
    assert (a.tokens, a.seconds, a.asked_withheld) == (100, 1.0, 0.0)
    assert (b.accuracy, b.recall, b.missed) == (0.8, 0.5, ("i1",))
    assert b.agreement == 0.8
    assert b.mcnemar_p == 0.5
    assert b.facts_ok is None
    assert (b.tokens, b.seconds, b.asked_withheld) == (80, 2.0, 1.0)


def test_only_items_every_arm_answered_count() -> None:
    partial = answers("TTBBBBBBBB")
    del partial["i0"]
    scores = score(GOLD, {"A-fake": answers("TTBBBBBBBB"), "B": partial})
    assert scores["B"].items == 9
    assert scores["A-fake"].items == 9
    assert scores["B"].positives == 1


def test_no_positives_and_errors() -> None:
    gold = {"i0": BEN}
    assert score(gold, {"A-fake": answers("B")})["A-fake"].recall is None
    with pytest.raises(ValueError, match="reference arm 'A-fake'"):
        score(gold, {"B": answers("B")})
    with pytest.raises(ValueError, match="no item"):
        score({"x": BEN}, {"A-fake": answers("B")})


def arm_score(name: str, accuracy: float, missed: tuple[str, ...] = ()) -> ArmScore:
    return ArmScore(name, 100, accuracy, 10, 1.0, missed, 1.0, 1.0, None, 0.0, 0.0, 0.0)


def test_keep_within_the_margin() -> None:
    decision = decide({"A-fake": arm_score("A-fake", 0.90), "B": arm_score("B", 0.87)})
    assert decision.keep
    assert decision.loosen == ()
    assert not decision.report
    assert decision.reason == "within 3% of A-fake (gap +3.0%)"


def test_a_missed_true_positive_is_never_kept() -> None:
    scores = {"A-fake": arm_score("A-fake", 0.90), "B": arm_score("B", 0.90, ("i1",)),
              "C-sites": arm_score("C-sites", 0.89), "C-ips": arm_score("C-ips", 0.80)}  # fmt: skip
    decision = decide(scores)
    assert not decision.keep
    assert decision.loosen == ("C-sites",)
    assert decision.reason == "gap +0.0%; closed by C-sites"


def test_loosen_or_report() -> None:
    scores = {"A-fake": arm_score("A-fake", 0.90), "B": arm_score("B", 0.80),
              "C-ips": arm_score("C-ips", 0.88), "C-hosts": arm_score("C-hosts", 0.87),
              "A-real": arm_score("A-real", 0.95)}  # fmt: skip
    assert decide(scores).loosen == ("C-hosts", "C-ips")
    worse = {"A-fake": arm_score("A-fake", 0.90), "B": arm_score("B", 0.80, ("i2", "i3")),
             "C-ips": arm_score("C-ips", 0.85)}  # fmt: skip
    decision = decide(worse)
    assert decision.report
    assert decision.reason == "gap +10.0%, 2 true positive(s) missed; no single rule closes it"
    assert decide(worse, margin=0.06).loosen == ("C-ips",)


def test_records_are_frozen_with_defaults() -> None:
    answer = Answer(TP)
    assert (answer.facts_ok, answer.asked_withheld, answer.tokens, answer.seconds) == (
        None, False, 0, 0.0,
    )  # fmt: skip
    with pytest.raises(AttributeError):
        answer.verdict = BEN  # type: ignore[misc]
    with pytest.raises(AttributeError):
        arm_score("B", 0.5).accuracy = 1.0  # type: ignore[misc]
    decision = decide({"A-fake": arm_score("A-fake", 0.9), "B": arm_score("B", 0.9)})
    with pytest.raises(AttributeError):
        decision.keep = False  # type: ignore[misc]


def test_error_messages() -> None:
    with pytest.raises(ValueError) as caught:  # noqa: PT011 - the exact message follows
        score({"x": BEN}, {"A-fake": answers("B")})
    assert str(caught.value) == "no item has an answer from every arm"
    with pytest.raises(ValueError) as caught:  # noqa: PT011
        score({"x": BEN}, {"B": answers("B")})
    assert str(caught.value) == "the reference arm 'A-fake' has no answers"


def test_decision_texts() -> None:
    scores = {"A-fake": arm_score("A-fake", 0.90), "B": arm_score("B", 0.80),
              "C-ips": arm_score("C-ips", 0.88), "C-hosts": arm_score("C-hosts", 0.87)}  # fmt: skip
    loosen = decide(scores)
    assert (loosen.keep, loosen.report) == (False, False)
    assert loosen.reason == "gap +10.0%; closed by C-hosts, C-ips"
    alone = decide({"A-fake": arm_score("A-fake", 0.90), "B": arm_score("B", 0.80)})
    assert (alone.keep, alone.loosen, alone.report) == (False, (), True)
    assert alone.reason == "gap +10.0%; no single rule closes it"


def test_mcnemar_counts_both_directions() -> None:
    scores = score(
        GOLD,
        {"A-fake": answers("BBBBBBBBBB"), "B": answers("TTBBBBBBBB")},  # only B is right on i0, i1
    )
    assert scores["B"].mcnemar_p == 0.5
    assert scores["B"].accuracy == 1.0
    assert scores["B"].missed == ()
