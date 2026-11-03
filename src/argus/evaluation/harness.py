"""Scoring against the gold set (P2; plan §3, §6, D-082): how often a decision-maker agrees
with the person's answers, with 95% intervals, so a small sample is never overstated.

``score(gold, predicted)`` takes the person's answers and any predictor's outcomes
(ARGUS's suggestions as a baseline today; P4's decisions and P5/P6's proposals later):
- accuracy, per rule and overall;
- the true positives proposed benign (plan §6.2: must be 0) and true-positive recall;
- the precision of benign proposals (plan §6.3: ≥ 95%, lower bound ≥ 90%);
- the confusion of outcomes.
A figure whose sample is too small says so (``MIN_SAMPLE``); intervals are Wilson score
intervals. Pure functions: deterministic for the same input (the gate's "reproduces its
numbers exactly").
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

BENIGN = frozenset({"benign_expected", "benign_policy", "rule_false_positive"})
POSITIVE = "true_positive"
MIN_SAMPLE = 10  # below this many, a rate is shown but marked "too few to judge"
Z = 1.959964  # 95%


@dataclass(frozen=True)
class Rate:
    hits: int
    total: int

    @property
    def value(self) -> float | None:
        return self.hits / self.total if self.total else None

    @property
    def interval(self) -> tuple[float, float] | None:
        """The Wilson score interval at 95%."""
        if not self.total:
            return None
        n, p = self.total, self.hits / self.total
        centre = (p + Z * Z / (2 * n)) / (1 + Z * Z / n)
        half = Z * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n)) / (1 + Z * Z / n)
        return max(0.0, centre - half), min(1.0, centre + half)

    @property
    def enough(self) -> bool:
        return self.total >= MIN_SAMPLE

    def text(self) -> str:
        if not self.total:
            return "not measured (no items)"
        low, high = self.interval or (0.0, 0.0)
        note = "" if self.enough else f"; too few to judge (< {MIN_SAMPLE})"
        return f"{self.hits}/{self.total} = {self.value:.0%} (95%: {low:.0%} to {high:.0%}{note})"


@dataclass(frozen=True)
class Item:
    investigation_id: str
    rule: str
    split: str
    answer: str  # the person's
    predicted: str | None  # the predictor's; None = no proposal (deferred)


@dataclass(frozen=True)
class Score:
    items: int
    proposed: int  # items the predictor proposed anything for
    accuracy: Rate
    tp_recall: Rate
    tp_proposed_benign: tuple[str, ...]  # must be empty (plan §6.2)
    benign_precision: Rate
    per_rule: dict[str, Rate] = field(default_factory=dict)
    confusion: dict[tuple[str, str], int] = field(default_factory=dict)  # (answer, predicted)


def score(items: list[Item]) -> Score:
    proposed = [i for i in items if i.predicted is not None]
    per: dict[str, list[bool]] = defaultdict(list)
    for i in proposed:
        per[i.rule].append(i.predicted == i.answer)
    positives = [i for i in items if i.answer == POSITIVE]
    benign_proposals = [i for i in proposed if i.predicted in BENIGN]
    return Score(
        items=len(items),
        proposed=len(proposed),
        accuracy=Rate(sum(i.predicted == i.answer for i in proposed), len(proposed)),
        tp_recall=Rate(sum(i.predicted == POSITIVE for i in positives), len(positives)),
        tp_proposed_benign=tuple(
            sorted(i.investigation_id for i in positives if i.predicted in BENIGN)
        ),
        benign_precision=Rate(
            sum(i.answer in BENIGN for i in benign_proposals), len(benign_proposals)
        ),
        per_rule={rule: Rate(sum(v), len(v)) for rule, v in sorted(per.items())},
        confusion=dict(sorted(Counter((i.answer, i.predicted or "—") for i in items).items())),
    )


def report(result: Score, title: str) -> list[str]:
    """The score as plain lines for a person."""
    lines = [
        f"{title}: {result.items} answered items, a proposal for {result.proposed}",
        f"- agreement with the person: {result.accuracy.text()}",
        f"- true positives caught: {result.tp_recall.text()}",
        f"- true positives proposed benign (must be 0): {len(result.tp_proposed_benign)}",
        f"- benign proposals that were right: {result.benign_precision.text()}",
        "- per rule:",
    ]
    lines += [f"  - {rule}: {rate.text()}" for rule, rate in result.per_rule.items()]
    lines.append("- answer → proposed:")
    lines += [f"  - {a} → {p}: {n}" for (a, p), n in result.confusion.items()]
    return lines


def from_gold(
    rows: list[Any], predicted: Mapping[str, str | None], split: str | None = None
) -> list[Item]:
    """Items from the store's gold rows (answered only), optionally one split."""
    out = []
    for r in rows:
        if r.outcome is None or (split is not None and r.split != split):
            continue
        key = str(r.investigation_id)
        out.append(Item(key, str(r.rule_name), str(r.split), r.outcome, predicted.get(key)))
    return out
