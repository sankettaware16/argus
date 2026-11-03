"""ARGUS's reading (AR1, D-150): what the investigator made of an item when it did not propose.

An answer that is inconclusive, fails the citation checks or is stopped by the decision floor
is not a proposal, but it is still the agent's best reading of the item. The agent stores it
beside the run's answer (``report["reading"]``: why it is not a proposal and which cited facts
were found in the evidence); this module says it in plain words for the pages. A reading is
display only: it has no effect on the assessment's outcome, status, score or write-back.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from argus import site
from argus.llm.prompts import OUTCOMES

UNDECIDED = "undecided"  # the answer was inconclusive
CITATION = "citation"  # a cited fact is not in the item
BENIGN_CITATION = "benign_citation"  # a benign answer that cites only quoted log or alert text
FLOOR = "floor"  # a benign answer the decision floor blocks
KINDS = (UNDECIDED, CITATION, BENIGN_CITATION, FLOOR)

OUTCOME_WORDS = {
    "true_positive": "a true positive",
    "benign_expected": "benign, expected activity",
    "benign_policy": "benign, allowed by policy",
    "rule_false_positive": "a rule false positive",
    "inconclusive": "inconclusive",
}
WHY = {
    UNDECIDED: "the evidence did not settle it",
    CITATION: "it quoted something that is not in the evidence",
    BENIGN_CITATION: (
        "its reasons for calling this harmless came only from quoted log or alert text,"
        " not from anything ARGUS itself found"
    ),
    FLOOR: "a safety check needs a person",
}
# the parts of the decision floor (assess.engine.floor) in plain words; any other is kept as is
BLOCKED_WORDS = {
    "on a threat list": "it is on a threat list",
    "ti.listed not known": "whether it is on a threat list is not known",
    "ti.listed_remote not known": "whether it is on a threat list is not known",
    "threat lists not checked": "threat lists were not checked",
    "flagged by outside threat intel": "outside threat intel flags it",
    "successful answers after the alert": "there were successful answers after the alert",
    "web.successes_after not known": "whether successful answers followed is not known",
    "remote-admin, P2P or anonymizer ports": "it uses remote-admin, P2P or anonymizer ports",
    "ports.risky not known": "the ports it used are not known",
    "regular like a beacon": "it repeats regularly, like a beacon",
    "proxy.regularity not known": "whether it repeats like a beacon is not known",
    "a destination few campus hosts reach": "few {own:hosts} reach this destination",
    "destinations not known": "how many {own:hosts} reach the destination is not known",
    "severity high": "the severity is high",
    "severity critical": "the severity is critical",
    "an entity seen for the first time": "something here is seen for the first time",
    "first-seen not known": "whether it was seen before is not known",
    "a volume spike": "there is a spike in volume",
    "volume baseline not known": "the normal volume is not known",
}


@dataclass(frozen=True)
class Fact:
    text: str
    checked: bool  # the quote was found in the evidence ARGUS gave the model


@dataclass(frozen=True)
class Reading:
    kind: str
    outcome: str  # what the model answered (an outcome, or inconclusive)
    confidence: float | None
    reason: str | None
    facts: tuple[Fact, ...]
    blocked: tuple[str, ...] = ()  # the decision floor's parts, when it is what stopped it

    def why(self, blocked: Sequence[str] | None = None) -> str:
        """Why it is not a proposal, in plain words. ``blocked`` replaces the floor's parts
        (an account without log access sees only some of them)."""
        said = WHY[self.kind]
        if self.kind != FLOOR:
            return said
        floor = self.blocked if blocked is None else blocked
        parts = [site.say(BLOCKED_WORDS.get(p, p)) for p in floor]
        return f"{said}: {'; '.join(parts)}" if parts else said

    def headline(self, blocked: Sequence[str] | None = None) -> str:
        sure = "" if self.confidence is None else f" ({round(self.confidence * 100)}%)"
        words = OUTCOME_WORDS.get(self.outcome, self.outcome)
        return f"ARGUS's reading: {words}{sure} — not proposed because {self.why(blocked)}"


def _strings(value: Any) -> list[str]:
    return [v for v in value if isinstance(v, str)] if isinstance(value, list) else []


# a run from before AR1 stored no reading, only the agent's refusal among its reasons
_REFUSALS = (
    ("the agent could not decide", UNDECIDED),
    ("a cited fact is not in the item", CITATION),
    ("a benign answer must cite ARGUS's own words", BENIGN_CITATION),
    ("floor: ", FLOOR),
)


def _legacy(answer: Mapping[str, Any], reasons: Sequence[str]) -> dict[str, Any] | None:
    """The reading of a run from before AR1, rebuilt from its refusal. Its quotes are marked
    found only where the refusal proves it: past the citation check (the benign rules)."""
    for said in reasons:
        for prefix, kind in _REFUSALS:
            if said.startswith(prefix):
                cites = answer.get("cites")
                n = len(cites) if isinstance(cites, list) else 0
                found = kind in (BENIGN_CITATION, FLOOR)
                blocked = said[len(prefix) :].split("; ") if kind == FLOOR else []
                return {"kind": kind, "checked": [found] * n, "blocked": blocked,
                        "unknown": not found}  # fmt: skip
    return None


def of(report: Mapping[str, Any] | None, reasons: Sequence[str] = ()) -> Reading | None:
    """The reading stored in an investigator run's report, or None when the run left none;
    for a run from before AR1, the one its refusal (in ``reasons``) shows."""
    if not isinstance(report, Mapping):
        return None
    stored, answer = report.get("reading"), report.get("answer")
    if not isinstance(answer, Mapping):
        return None
    if not isinstance(stored, Mapping):
        stored = _legacy(answer, [r for r in reasons if isinstance(r, str)])
        if stored is None:
            return None
    kind, outcome = stored.get("kind"), answer.get("outcome")
    if kind not in KINDS or outcome not in OUTCOMES:
        return None
    marks = stored.get("checked")
    marks = marks if isinstance(marks, list) else []
    raw_cites = answer.get("cites")
    cites = list(enumerate(raw_cites)) if isinstance(raw_cites, list) else []
    if stored.get("unknown") is True:
        cites = []  # which quotes were found is not known: none shown rather than a guess
    facts = tuple(Fact(c, i < len(marks) and marks[i] is True)
                  for i, c in cites if isinstance(c, str))  # fmt: skip
    raw = answer.get("confidence")
    confidence = None
    if isinstance(raw, int | float) and not isinstance(raw, bool) and 0 <= raw <= 1:
        confidence = float(raw)
    reason = answer.get("explanation")
    return Reading(
        kind, outcome, confidence, reason if isinstance(reason, str) and reason else None, facts,
        tuple(_strings(stored.get("blocked"))),
    )  # fmt: skip
