"""Scoring the privacy comparison (P2, D-078): did the labels make the model's answers worse?

``score(gold, answers)`` compares every arm with a person's labels and with the reference
arm (``A-fake`` by default): accuracy, recall of true positives, the true positives an arm
misses that the reference catches, paired agreement and McNemar's exact test, cited facts
that hold, requests for withheld information, tokens and time. ``decide(scores)`` applies
the rule of D-078. Pure functions: no model, no database.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass

POSITIVE = "true_positive"
MARGIN = 0.03  # B may be at most 3 points less accurate than the reference


@dataclass(frozen=True)
class Answer:
    verdict: str  # an outcome, as a person labels: true_positive, benign_expected, ...
    facts_ok: bool | None = None  # every fact it cites matches the dossier (None: not checked)
    asked_withheld: bool = False  # it asked for information the arm withheld
    tokens: int = 0
    seconds: float = 0.0


@dataclass(frozen=True)
class ArmScore:
    arm: str
    items: int
    accuracy: float
    positives: int
    recall: float | None  # of true positives; None without any in the gold set
    missed: tuple[str, ...]  # true positives the reference catches and this arm does not
    agreement: float  # same verdict as the reference
    mcnemar_p: float  # paired test against the reference on correctness
    facts_ok: float | None
    asked_withheld: float
    tokens: float
    seconds: float


def mcnemar(b: int, c: int) -> float:
    """Exact two-sided McNemar p-value from the discordant counts ``b`` and ``c``."""
    n = b + c  # with none, the tail is 1 and so is p
    tail: float = sum(math.comb(n, k) for k in range(min(b, c) + 1)) / 2**n
    return min(1.0, 2 * tail)


def score(
    gold: Mapping[str, str],
    answers: Mapping[str, Mapping[str, Answer]],
    reference: str = "A-fake",
) -> dict[str, ArmScore]:
    """Per arm, over the items every arm answered (a missing answer is never counted as
    either right or wrong; the item is left out for every arm, so all compare like for like)."""
    if reference not in answers:
        raise ValueError(f"the reference arm {reference!r} has no answers")
    items = sorted(set(gold).intersection(*(set(a) for a in answers.values())))
    if not items:
        raise ValueError("no item has an answer from every arm")
    ref = answers[reference]
    out: dict[str, ArmScore] = {}
    for name, given in answers.items():
        right = [given[i].verdict == gold[i] for i in items]
        ref_right = [ref[i].verdict == gold[i] for i in items]
        positives = [i for i in items if gold[i] == POSITIVE]
        caught = [i for i in positives if given[i].verdict == POSITIVE]
        missed = tuple(
            i for i in positives if ref[i].verdict == POSITIVE and given[i].verdict != POSITIVE
        )
        b = sum(1 for r, s in zip(ref_right, right, strict=True) if r and not s)
        c = sum(1 for r, s in zip(ref_right, right, strict=True) if s and not r)
        checked = [ok for i in items if (ok := given[i].facts_ok) is not None]
        out[name] = ArmScore(
            arm=name,
            items=len(items),
            accuracy=sum(right) / len(items),
            positives=len(positives),
            recall=len(caught) / len(positives) if positives else None,
            missed=missed,
            agreement=sum(given[i].verdict == ref[i].verdict for i in items) / len(items),
            mcnemar_p=mcnemar(b, c),
            facts_ok=sum(checked) / len(checked) if checked else None,
            asked_withheld=sum(given[i].asked_withheld for i in items) / len(items),
            tokens=sum(given[i].tokens for i in items) / len(items),
            seconds=sum(given[i].seconds for i in items) / len(items),
        )
    return out


@dataclass(frozen=True)
class Decision:
    keep: bool  # the policy as it is
    loosen: tuple[str, ...]  # rules (C arms) whose loosening closes the gap
    report: bool  # loosening single rules does not close it: the user decides (D-078)
    reason: str


def _close(arm: ArmScore, ref: ArmScore, margin: float) -> bool:
    return arm.accuracy >= ref.accuracy - margin and not arm.missed


def decide(
    scores: Mapping[str, ArmScore],
    policy: str = "B",
    reference: str = "A-fake",
    margin: float = MARGIN,
) -> Decision:
    """Keep the policy when it is within ``margin`` of the reference and misses no true
    positive the reference catches. Else name every loosened arm (``C-…``) that is; if none
    is, the user decides."""
    b, ref = scores[policy], scores[reference]
    gap = ref.accuracy - b.accuracy
    if _close(b, ref, margin):
        return Decision(True, (), False, f"within {margin:.0%} of {reference} (gap {gap:+.1%})")
    loosen = tuple(
        sorted(n for n, s in scores.items() if n.startswith("C-") and _close(s, ref, margin))
    )
    if loosen:
        return Decision(False, loosen, False, f"gap {gap:+.1%}; closed by {', '.join(loosen)}")
    missed = f", {len(b.missed)} true positive(s) missed" if b.missed else ""
    return Decision(False, (), True, f"gap {gap:+.1%}{missed}; no single rule closes it")
