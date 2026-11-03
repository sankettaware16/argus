"""The gold set (Phase 2, P2; plan §3, D-080): an answer key of real investigations whose
outcome a person confirms, used to score ARGUS's and the models' answers.

``select(candidates)`` picks it deterministically:
- every investigation a person has labelled, and every one labelled a true positive;
- per rule (by name: a rule recreated in Kibana gets a new ID), up to ``PER_RULE``
  investigations of different kinds (pattern signatures, ``display.signature``), threat-list
  hits and successes after an attack first, spread over the days (all of them when a rule
  has fewer);
- each in the ``dev`` or the ``test`` split by its day (``SPLIT_DAY``), so prompts and keys
  are tuned on one part and scored on the other.
``suggest(body, label)`` pre-fills an answer for the person to confirm or correct: the
assistant's earlier label with its note where there is one (D-071), else one from generic
signals, always with its reasons. A suggestion is never an answer: only the person's is.
Pure functions: the caller reads the dossiers (read-only) and stores the result.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from argus.context import display
from argus.evaluation.harness import BENIGN
from argus.outside import facts as outside

PER_RULE = 5
SPLIT_DAY = date(2026, 10, 12)  # dev before, test from this day (Phase 1's soak began 10-13)
SEED = "gold-v1"
ASSISTANT = "argus-assistant"
POSITIVE = "true_positive"


@dataclass(frozen=True)
class Candidate:
    investigation_id: str
    version: int
    pack: str
    dossier_hash: str
    rule_id: str
    rule_name: str
    day: date
    body: Mapping[str, Any] = field(repr=False, compare=False)
    labels: tuple[tuple[str, str, str | None], ...] = ()  # (reviewer, outcome, note)

    @property
    def human(self) -> tuple[str, str | None] | None:
        """The newest outcome a person gave (not the assistant), with its note."""
        people = [(o, n) for who, o, n in self.labels if who != ASSISTANT]
        return people[-1] if people else None

    @property
    def assistant(self) -> tuple[str, str | None] | None:
        own = [(o, n) for who, o, n in self.labels if who == ASSISTANT]
        return own[-1] if own else None


@dataclass(frozen=True)
class Item:
    candidate: Candidate
    split: str  # dev | test
    why: tuple[str, ...]  # why it was chosen


def _signals(body: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    out = {}
    for s in [*(body.get("local_signals") or []), *(body.get("signals") or [])]:
        if isinstance(s, Mapping) and isinstance(s.get("name"), str):
            out[s["name"]] = s
    return out


def _known(body: Mapping[str, Any], name: str) -> Any:
    s = _signals(body).get(name)
    return s.get("value") if s and s.get("status") == "known" else None


def _positive(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0


def flags(body: Mapping[str, Any]) -> tuple[str, ...]:
    """What makes an investigation worth a person's look, from generic signals."""
    out = []
    if _positive(_known(body, "ti.listed")) or _positive(_known(body, "ti.listed_remote")):
        out.append("on a threat list")
    if _positive(_known(body, "web.successes_after")):
        out.append("successful answers after the alert")
    cv = _known(body, "proxy.regularity")
    if isinstance(cv, (int, float)) and not isinstance(cv, bool) and cv < 0.3:
        out.append("regular traffic, like a beacon")
    if _positive(_known(body, "ports.risky")):
        out.append("remote-admin, P2P or anonymizer ports")
    return outside.with_flag(out, body.get("outside"))  # AR3: an outside detection (D-165)


def _order(candidate: Candidate) -> str:
    return hashlib.sha256(f"{SEED}:{candidate.investigation_id}".encode()).hexdigest()


def _signature(c: Candidate) -> tuple[Any, ...]:
    pairs = (c.body.get("facts") or {}).get("group_key")
    keys: list[str] = []
    if isinstance(pairs, str) and pairs.startswith("["):
        with contextlib.suppress(ValueError):
            keys = [p[0] for p in json.loads(pairs) if isinstance(p, list) and p]
    return display.signature(c.rule_id, keys, c.body)[0]


def split(day: date) -> str:
    return "dev" if day < SPLIT_DAY else "test"


def select(candidates: Iterable[Candidate], per_rule: int = PER_RULE) -> list[Item]:
    """The gold set, deterministic for the same candidates (see the module's docstring)."""
    # a rule recreated in Kibana keeps its name but gets a new ID: one quota per name
    by_rule: dict[str, list[Candidate]] = defaultdict(list)
    for c in candidates:
        by_rule[c.rule_name].append(c)
    items: list[Item] = []
    for rule_id in sorted(by_rule):
        pool = sorted(by_rule[rule_id], key=_order)
        chosen: dict[str, list[str]] = {}
        for c in pool:
            why = []
            if c.human is not None:
                why.append("labelled by a person")
            if any(o == POSITIVE for _, o, _ in c.labels):
                why.append("labelled a true positive")
            if why:
                chosen[c.investigation_id] = why
        flagged = [c for c in pool if flags(c.body) and c.investigation_id not in chosen]
        for c in flagged[: max(per_rule // 2, 1)]:
            chosen[c.investigation_id] = ["signals: " + ", ".join(flags(c.body))]
        # then one per kind (signature), alternating early and late days, until the quota
        kinds: dict[tuple[Any, ...], list[Candidate]] = defaultdict(list)
        for c in pool:
            kinds[_signature(c)].append(c)
        groups = sorted(kinds.values(), key=lambda g: (-len(g), _order(g[0])))
        early = True
        while len(chosen) < per_rule and any(groups):
            for group in groups:
                if len(chosen) >= per_rule:
                    break
                group[:] = [c for c in group if c.investigation_id not in chosen]
                if not group:
                    continue
                group.sort(key=lambda c: (c.day, _order(c)))
                c = group.pop(0 if early else -1)
                early = not early
                chosen[c.investigation_id] = [f"a kind of this rule ({len(group) + 1} alike)"]
        index = {c.investigation_id: c for c in pool}
        for investigation_id, why in sorted(chosen.items(), key=lambda kv: _order(index[kv[0]])):
            c = index[investigation_id]
            items.append(Item(c, split(c.day), tuple(why)))
    return items


def extend(
    candidates: Iterable[Candidate],
    exclude: Iterable[str],
    benign: int,
    rule: str | None = None,
    rule_count: int = 0,
) -> list[Item]:
    """A further set beside a frozen one (labelling round 1, plan §13 item 6): ``benign``
    investigations whose pre-filled suggestion is benign, one rule after another so every rule
    takes its turn (Phase 2's criterion 3 needs benign answers), then up to ``rule_count`` more
    of ``rule`` whatever their suggestion (a rule short of labels, D-080). Nothing in
    ``exclude`` (the items of the sets that exist); deterministic for the same candidates."""
    skip = set(exclude)
    pool = sorted((c for c in candidates if c.investigation_id not in skip), key=_order)
    chosen: dict[str, tuple[Candidate, str]] = {}
    by_rule: dict[str, list[Candidate]] = defaultdict(list)
    for c in pool:
        if suggest(c.body, c.assistant).outcome in BENIGN:
            by_rule[c.rule_name].append(c)
    queues = [by_rule[name] for name in sorted(by_rule)]
    while len(chosen) < benign and any(queues):
        for queue in queues:
            if queue and len(chosen) < benign:
                c = queue.pop(0)
                chosen[c.investigation_id] = (c, "suggested benign (criterion 3)")
    extra = [c for c in pool if c.rule_name == rule and c.investigation_id not in chosen]
    for c in extra[:rule_count]:
        chosen[c.investigation_id] = (c, "a rule short of labels (D-080)")
    ordered = sorted(chosen.values(), key=lambda pair: (pair[0].rule_name, _order(pair[0])))
    return [Item(c, split(c.day), (why,)) for c, why in ordered]


@dataclass(frozen=True)
class Suggestion:
    outcome: str
    reasons: tuple[str, ...]
    source: str  # "assistant label" | "signals"


def suggest(body: Mapping[str, Any], assistant: tuple[str, str | None] | None) -> Suggestion:
    """A pre-filled answer for the person, with its reasons; never the answer itself."""
    seen = flags(body)
    if assistant is not None:
        outcome, note = assistant
        reasons = [note.strip()] if note and note.strip() else []
        return Suggestion(outcome, (*reasons, *seen), "assistant label")
    if "on a threat list" in seen:
        return Suggestion(POSITIVE, seen, "signals")
    if seen:
        return Suggestion("inconclusive", (*seen, "needs a person's look"), "signals")
    unknown = [n for n, s in _signals(body).items() if s.get("status") != "known"]
    if unknown:
        reason = f"could not be told: {', '.join(sorted(unknown)[:4])}"
        return Suggestion("inconclusive", (reason,), "signals")
    return Suggestion("benign_expected", ("no threat-list hit, success or beacon seen",), "signals")


def manifest(items: Sequence[Item]) -> list[dict[str, Any]]:
    """The frozen set as records (IDs, hashes and labels only, no dossier text)."""
    out = []
    for item in items:
        c = item.candidate
        s = suggest(c.body, c.assistant)
        out.append({
            "investigation_id": c.investigation_id, "version": c.version, "pack": c.pack,
            "dossier_hash": c.dossier_hash, "rule_id": c.rule_id, "rule_name": c.rule_name,
            "day": c.day.isoformat(), "split": item.split, "why": list(item.why),
            "suggestion": {"outcome": s.outcome, "reasons": list(s.reasons), "source": s.source},
            "person": c.human[0] if c.human else None,
        })  # fmt: skip
    return out
