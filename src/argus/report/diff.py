"""What's new: a pure diff of two views of a dossier.

A ``View`` holds facts (by key), checks (by E-id) and gaps (by key); the diff lists what the second
view adds to the first. Views are mappings and every list is sorted by key, so ``diff(x, x)`` is
empty and the order facts arrived in never matters."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from argus.report.model import Change, Check, Fact, Gap, WhatsNew

GONE = "no longer reported"


@dataclass(frozen=True)
class View:
    facts: Mapping[str, Fact] = field(default_factory=dict)
    checks: Mapping[str, Check] = field(default_factory=dict)
    gaps: Mapping[str, Gap] = field(default_factory=dict)


def view(facts: Iterable[Fact], checks: Iterable[Check] = (), gaps: Iterable[Gap] = ()) -> View:
    """A view from items in any order; a key given twice is a defect (two different facts
    cannot have one identity)."""
    return View(_by(facts, "key"), _by(checks, "eid"), _by(gaps, "key"))


def _by[T: (Fact, Check, Gap)](items: Iterable[T], attr: str) -> dict[str, T]:
    out: dict[str, T] = {}
    for item in items:
        key = getattr(item, attr)
        if key in out and out[key] != item:
            raise ValueError(f"two different items share the key {key!r}")
        out[key] = item
    return out


def eid_order(eid: str) -> tuple[int, str]:
    digits = eid[1:]
    return (int(digits), eid) if digits.isdigit() else (1 << 62, eid)


def _change(before: Fact | None, after: Fact) -> Change:
    eids = sorted({*after.eids, *(before.eids if before else ())}, key=eid_order)
    return Change(
        key=after.key,
        name=after.name,
        before=None if before is None else before.sentence,
        after=after.sentence,
        eids=tuple(eids),
        from_logs=after.from_logs or bool(before and before.from_logs),
    )


def diff(before: View, after: View) -> WhatsNew:
    new_facts: list[Fact] = []
    now_known: list[Change] = []
    changed: list[Change] = []
    answered: list[Change] = []
    for key in sorted(after.facts):
        a, b = after.facts[key], before.facts.get(key)
        if b == a:
            continue
        if a.kind == "signal":
            if a.status == "known" and (b is None or b.status != "known"):
                now_known.append(_change(b, a))
            elif b is not None:
                changed.append(_change(b, a))
            # an unknown signal that did not exist before is a gap opened, not a fact
        elif a.kind == "step":
            (answered if a.status == "known" else changed).append(_change(b, a))
        elif b is None:
            new_facts.append(a)
        else:
            changed.append(_change(b, a))
    for key in sorted(set(before.facts) - set(after.facts)):
        b = before.facts[key]
        changed.append(
            Change(key=key, name=b.name, before=b.sentence, after=GONE, eids=b.eids,
                   from_logs=b.from_logs)
        )  # fmt: skip
    return WhatsNew(
        new_facts=tuple(new_facts),
        now_known=tuple(now_known),
        changed=tuple(sorted(changed, key=lambda c: c.key)),
        steps_answered=tuple(answered),
        gaps_closed=tuple(before.gaps[k] for k in sorted(before.gaps) if k not in after.gaps),
        gaps_opened=tuple(after.gaps[k] for k in sorted(after.gaps) if k not in before.gaps),
        checks=tuple(
            after.checks[e]
            for e in sorted(after.checks, key=eid_order)
            if before.checks.get(e) != after.checks[e]
        ),
    )
