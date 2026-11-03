"""The gold measurement of the deterministic wave: how often the decision engine cannot decide a
gold item before the wave and after it, paired item by item, and that no true positive is
proposed benign.

``compare`` is pure: the person's answers and the engine's outcome on each item before and after,
with the inconclusive rate (n and a 95 % interval) and an exact McNemar test of gains against
losses. The engine learns the gold set's **dev** answers, so only the **test** split measures
anything (a report is per split, dev marked as a check on the code). ``measure`` runs it against
the gold set; by default (a dry run) it sends nothing, with ``live`` it runs the wave through the
investigation lane (NORMAL health, never in the quiet hours) and decides again **without storing**.
"""

from __future__ import annotations

import math
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.assess import engine as decision
from argus.evaluation import harness, store
from argus.investigation import store as istore
from argus.investigation import wave

Outcome = str | None
TEST, DEV = "test", "dev"


def mcnemar(gained: int, lost: int) -> float:
    """The exact two-sided McNemar p-value for ``gained`` and ``lost`` discordant pairs."""
    n = gained + lost
    if n == 0:
        return 1.0
    low = min(gained, lost)
    tail = sum(math.comb(n, k) for k in range(low + 1)) / (1 << n)
    return min(1.0, 2 * tail)


@dataclass(frozen=True)
class Comparison:
    items: int
    inconclusive_before: harness.Rate
    inconclusive_after: harness.Rate | None
    gained: int  # undecided before, decided after
    gained_right: int
    lost: int  # decided before, undecided after
    changed: int  # decided both times, with another outcome
    p: float | None  # McNemar, gained against lost
    tp_benign_before: tuple[str, ...]
    tp_benign_after: tuple[str, ...] | None

    @property
    def holds(self) -> bool:
        """The condition that must hold: no true positive proposed benign, in either arm."""
        return not self.tp_benign_before and not (self.tp_benign_after or ())


def compare(
    answers: Mapping[str, str],
    before: Mapping[str, Outcome],
    after: Mapping[str, Outcome] | None,
) -> Comparison:
    """``answers``: the person's outcome per item (the items measured); ``before`` and
    ``after``: the engine's outcome per item, None for no decision; ``after`` None: the wave
    was not run."""
    ids = sorted(answers)
    undecided_before = sum(before.get(i) is None for i in ids)

    def tp_benign(arm: Mapping[str, Outcome]) -> tuple[str, ...]:
        return tuple(i for i in ids if answers[i] == harness.POSITIVE
                     and arm.get(i) in harness.BENIGN)  # fmt: skip

    if after is None:
        return Comparison(len(ids), harness.Rate(undecided_before, len(ids)), None, 0, 0, 0, 0,
                          None, tp_benign(before), None)  # fmt: skip
    gained = [i for i in ids if before.get(i) is None and after.get(i) is not None]
    lost = [i for i in ids if before.get(i) is not None and after.get(i) is None]
    changed = [i for i in ids if before.get(i) is not None and after.get(i) is not None
               and before.get(i) != after.get(i)]  # fmt: skip
    return Comparison(
        items=len(ids),
        inconclusive_before=harness.Rate(undecided_before, len(ids)),
        inconclusive_after=harness.Rate(sum(after.get(i) is None for i in ids), len(ids)),
        gained=len(gained),
        gained_right=sum(after.get(i) == answers[i] for i in gained),
        lost=len(lost),
        changed=len(changed),
        p=mcnemar(len(gained), len(lost)),
        tp_benign_before=tp_benign(before),
        tp_benign_after=tp_benign(after),
    )  # fmt: skip


def lines(c: Comparison, repeat: int | None = None) -> list[str]:
    head = "Gold measurement" + ("" if repeat is None else f", repeat {repeat}")
    out = [
        f"{head}: {c.items} answered items",
        f"- the engine cannot decide, before the wave: {c.inconclusive_before.text()}",
    ]
    if c.inconclusive_after is None:
        out.append("- after the wave: not measured (a dry run sends nothing)")
    else:
        out += [
            f"- the engine cannot decide, after the wave: {c.inconclusive_after.text()}",
            f"- paired: {c.gained} decided only after (right: {c.gained_right}), {c.lost}"
            f" undecided only after, {c.changed} decided both times with another outcome;"
            f" McNemar p = {c.p:.3f}",
        ]
    out.append(f"- true positives proposed benign before (must be 0): {len(c.tp_benign_before)}")
    if c.tp_benign_after is not None:
        out.append(f"- true positives proposed benign after (must be 0): {len(c.tp_benign_after)}")
    return out


# ----------------------------------------------------------------------------- the run

_BODY = """
SELECT d.version, d.pack, d.dossier_hash, d.body, d.created_at FROM gold_items g
JOIN dossiers d ON d.investigation_id = g.investigation_id AND d.version = g.version
  AND d.pack = g.pack AND d.dossier_hash = g.dossier_hash
WHERE g.set_name = :s AND g.investigation_id = :i
"""


@dataclass(frozen=True)
class Plan:
    """What a wave would do for one gold item (dry run)."""

    investigation_id: str
    closable: int
    workable: bool
    requests: int
    heavy: int


@dataclass
class Measured:
    answers: dict[str, str]
    before: dict[str, Outcome]
    after: list[dict[str, Outcome]]  # one per repeat; empty in a dry run
    plans: list[Plan]
    notes: list[str]
    splits: dict[str, str] = field(default_factory=dict)  # item -> "dev" or "test"


async def measure(
    env: wave.Env,
    conn: AsyncConnection,
    *,
    set_name: str = store.SET,
    split: str | None = TEST,
    repeats: int = 2,
    live: bool = False,
    now: datetime | None = None,
) -> Measured:
    """Score the engine on the gold set's answered items of ``split`` (the test split by
    default; None: both) before the wave and, with ``live``, after it (``repeats`` times, the
    evidence of the first run reused by the others: the engine's second reading of the same
    evidence must agree)."""
    at = now or env.clock()
    rows = [r for r in await store.items(conn, set_name)
            if r.outcome is not None and (split is None or r.split == split)]  # fmt: skip
    learned = await decision.learn(conn)
    out = Measured({}, {}, [], [], [])
    undecided: list[tuple[str, wave.Prepared]] = []
    for r in rows:
        key = str(r.investigation_id)
        got = (await conn.execute(text(_BODY), {"s": set_name, "i": r.investigation_id})).first()
        if got is None:
            out.notes.append(f"{key}: its gold dossier is gone")
            continue
        cur = istore.Current(
            r.investigation_id, int(got.version), str(got.pack), str(got.dossier_hash),
            got.body, got.created_at, None, True,
        )  # fmt: skip
        prep = await wave.prepare_from(env, conn, cur, at, assessed=None)  # not the answer key
        first = await decision.first_seen(conn, r.investigation_id)
        spike = await decision.spike(conn, r.investigation_id)
        out.answers[key] = str(r.outcome)
        out.splits[key] = str(r.split)
        out.before[key] = decision.decide(got.body, learned, at, first, spike).outcome
        plan = await wave.plan_wave(env, conn, prep, at)
        out.plans.append(Plan(key, sum(g.closable for g in prep.gaps), wave.workable(env, prep),
                              len(plan.sends), sum(p.heavy for p in plan.sends)))  # fmt: skip
        if out.before[key] is None and plan.sends:
            undecided.append((key, prep))
    if not live:
        return out
    for _ in range(max(repeats, 1)):
        after = dict(out.before)
        for key, prep in undecided:
            plan = await wave.plan_wave(env, conn, prep, at)
            kept: dict[str, Any] = {}
            await wave.execute(env, prep, plan, "wave", keep=kept)
            body = kept.get("body")
            if body is not None:
                inv = uuid.UUID(key)
                first = await decision.first_seen(conn, inv)
                spike = await decision.spike(conn, inv)
                after[key] = decision.decide(body, learned, at, first, spike).outcome
        out.after.append(after)
    return out


def _part(m: Measured, split: str | None) -> Measured:
    keep = {k for k in m.answers if m.splits.get(k) == split}
    return Measured(
        {k: v for k, v in m.answers.items() if k in keep},
        {k: v for k, v in m.before.items() if k in keep},
        [{k: v for k, v in arm.items() if k in keep} for arm in m.after],
        [p for p in m.plans if p.investigation_id in keep],
        [],
        {k: v for k, v in m.splits.items() if k in keep},
    )


def _block(m: Measured) -> list[str]:
    """One split's lines: one block per repeat, the stability across repeats, and what a wave
    would ask."""
    if not m.after:
        out = lines(compare(m.answers, m.before, None))
    else:
        out = []
        for n, after in enumerate(m.after, start=1):
            out += lines(compare(m.answers, m.before, after), n)
        out.append(
            "- an item the engine decided before is not asked about again, so 'undecided only"
            " after' is 0 by construction and McNemar's test above is a sign test of the gains"
        )
        if len(m.after) > 1:
            same = all(a == m.after[0] for a in m.after[1:])
            out.append(f"- the repeats agree item by item: {'yes' if same else 'NO'}")
    asked = sum(p.requests for p in m.plans)
    out.append(
        f"- a wave could ask something for {sum(p.workable for p in m.plans)} of"
        f" {len(m.plans)} items: {asked} requests, {sum(p.heavy for p in m.plans)} of them heavy"
    )
    return out


def report(m: Measured) -> list[str]:
    """The measurement as plain lines, per split (an item without a split, as a direct caller
    may build one, is reported alone). The dev split is marked: the engine learned those
    answers, so it is a check on the code, not the measure."""
    found = sorted({m.splits.get(k) for k in m.answers}, key=lambda x: (x != TEST, str(x)))
    if found in ([], [None]):
        out = _block(m)
    else:
        out = []
        for split in found:
            part = _part(m, split)
            head = f"== {split} split ==" if split else "== no split =="
            if split == DEV:
                head += (" the engine learns the dev answers, so this checks the code and"
                         " measures nothing")  # fmt: skip
            out += [head, *_block(part)]
    out += [f"- note: {n}" for n in m.notes]
    return out
