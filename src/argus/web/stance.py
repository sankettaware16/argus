"""ARGUS's stance on an investigation (AR4, D-182): what its page's top card and the queue's lines
say, in the order a person wants it.

* a **recommendation**: a proposal of its own (the AI investigator's before the decision engine's),
  else the proposal the pattern's run made on another investigation of the same pattern and day
  (AR2: display only, never accepted for this one);
* else a **reading**: a run that proposed nothing but left its best reading (AR1), its own or the
  pattern's;
* else nothing.

Reading only. The bulk readers take the investigations of a list and answer in a few statements,
whatever the number. ``lean`` is the cheap one for patterns, which list thousands of members: it
keeps no reasons and no run, only what the recommendation needs.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.web.assessed import Detail, Shared, _detail, is_agent

CLOSING = frozenset({"benign_expected", "benign_policy", "rule_false_positive"})
"""The outcomes that close a pattern's investigations (not a true positive, not inconclusive)."""
MANY = 500  # the most investigations one list reads the full stance of


@dataclass(frozen=True)
class Choice:
    """The assessment a stance rests on. ``source`` is the investigation the run was made on when
    it is another investigation of the pattern, else None."""

    detail: Detail
    source: uuid.UUID | None = None
    earlier: bool = False  # the run is on this investigation, before it changed

    @property
    def proposed(self) -> bool:
        return self.detail.status == "proposed"


def choose(details: Sequence[Detail], shared: Shared | None) -> Choice | None:
    """The assessment to show for an investigation, or None when there is nothing to show.
    ``shared`` is only to be passed for an investigation the AI investigator has not read itself
    (a shared run never replaces its own)."""
    own = sorted(details, key=lambda d: (not is_agent(d.assessor), d.assessor))
    for d in own:
        if d.status == "proposed" and d.outcome is not None:
            return Choice(d)
    if shared is not None and shared.detail.status == "proposed" and shared.detail.outcome:
        return Choice(shared.detail, shared.source, shared.earlier)
    for d in own:
        if d.status == "no_decision" and d.reading is not None:
            return Choice(d)
    if shared is not None and shared.detail.status == "no_decision" and shared.detail.reading:
        return Choice(shared.detail, shared.source, shared.earlier)
    return None


_COLUMNS = (
    "a.id, a.assessor, a.status, a.outcome, a.confidence, a.decided_by, a.reasons,"
    " a.created_at, a.finished_at"
)
_HISTORY = f"""
SELECT DISTINCT ON (a.investigation_id, a.assessor) a.investigation_id AS inv, {_COLUMNS}
FROM assessments a JOIN investigations i ON i.id = a.investigation_id AND i.version = a.version
WHERE a.investigation_id = ANY(:ids)
ORDER BY a.investigation_id, a.assessor, a.id DESC
"""  # noqa: S608 - constant fragments; values are bound
_SHARED = f"""
SELECT DISTINCT ON (s.investigation_id) s.investigation_id AS inv, {_COLUMNS},
       a.investigation_id AS source
FROM assessment_shares s JOIN assessments a ON a.id = s.assessment_id
JOIN investigations i ON i.id = s.investigation_id AND i.version = s.version
WHERE s.investigation_id = ANY(:ids) AND a.status IN ('proposed', 'no_decision')
  AND NOT (a.investigation_id = s.investigation_id AND a.version = s.version)
ORDER BY s.investigation_id, (a.status = 'proposed') DESC, a.id DESC
"""  # noqa: S608 - constant fragments; values are bound


async def choices(conn: AsyncConnection, ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, Choice]:
    """``choose`` for each of ``ids`` (at most ``MANY``), in two reads; an investigation with
    nothing to show is not in the answer."""
    wanted = list(dict.fromkeys(ids))[:MANY]
    if not wanted:
        return {}
    history: dict[uuid.UUID, list[Detail]] = defaultdict(list)
    for row in await conn.execute(text(_HISTORY), {"ids": wanted}):
        history[row.inv].append(_detail(row))
    shares: dict[uuid.UUID, Shared] = {}
    unread = [i for i in wanted if not any(is_agent(d.assessor) for d in history[i])]
    if unread:
        for row in await conn.execute(text(_SHARED), {"ids": unread}):
            shares[row.inv] = Shared(row.source, row.source == row.inv, _detail(row))
    out: dict[uuid.UUID, Choice] = {}
    for i in wanted:
        found = choose(history.get(i, []), shares.get(i))
        if found is not None:
            out[i] = found
    return out


_SIZES = """
SELECT s.assessment_id, count(DISTINCT s.investigation_id) AS n,
       coalesce(sum(i.alert_count) FILTER (WHERE i.version = s.version), 0) AS alerts
FROM assessment_shares s JOIN investigations i ON i.id = s.investigation_id
WHERE s.assessment_id = ANY(:ids) GROUP BY s.assessment_id
"""


async def pattern_sizes(
    conn: AsyncConnection, assessment_ids: Sequence[int]
) -> dict[int, tuple[int, int]]:
    """For each investigator run: how many investigations it stands for (its own and the others
    of the same pattern and day) and their alerts: the size of the pattern (AR2)."""
    if not assessment_ids:
        return {}
    return {
        int(r.assessment_id): (int(r.n), int(r.alerts))
        for r in await conn.execute(text(_SIZES), {"ids": list(assessment_ids)})
    }


@dataclass(frozen=True)
class Lean:
    """What a pattern needs of an investigation's stance: its proposal (the preference of
    ``choose``) and whether the AI investigator answered true positive without proposing it."""

    assessment_id: int | None = None
    outcome: str | None = None
    confidence: float | None = None
    agent: bool = False
    true_positive_reading: bool = False


_ANSWER = (
    "(SELECT e -> 'answer' ->> 'outcome' FROM jsonb_array_elements(CASE WHEN"
    " jsonb_typeof(a.reasons) = 'array' THEN a.reasons ELSE '[]'::jsonb END) e"
    " WHERE jsonb_typeof(e) = 'object' LIMIT 1)"
)
_LEAN = f"""
SELECT inv, id, assessor, status, outcome, confidence, answer, shared FROM (
  SELECT DISTINCT ON (a.investigation_id, a.assessor) a.investigation_id AS inv, a.id, a.assessor,
         a.status, a.outcome, a.confidence, {_ANSWER} AS answer, false AS shared
  FROM assessments a JOIN investigations i ON i.id = a.investigation_id AND i.version = a.version
  WHERE a.investigation_id = ANY(:ids)
  ORDER BY a.investigation_id, a.assessor, a.id DESC
) own
UNION ALL
SELECT s.investigation_id, a.id, a.assessor, a.status, a.outcome, a.confidence, {_ANSWER}, true
FROM assessment_shares s JOIN assessments a ON a.id = s.assessment_id
JOIN investigations i ON i.id = s.investigation_id AND i.version = s.version
WHERE s.investigation_id = ANY(:ids) AND a.status IN ('proposed', 'no_decision')
  AND NOT (a.investigation_id = s.investigation_id AND a.version = s.version)
"""  # noqa: S608 - constant fragments; values are bound


def _lean_of(mine: Sequence[Any], theirs: Sequence[Any]) -> Lean | None:
    own = sorted(mine, key=lambda r: (not is_agent(r.assessor), r.assessor))
    # a shared run never replaces the investigator's own run
    other = [] if any(is_agent(r.assessor) for r in own) else theirs
    rows = [*own, *sorted(other, key=lambda r: -r.id)]
    best = next((r for r in rows if r.status == "proposed" and r.outcome is not None), None)
    blocked = any(r.status == "no_decision" and r.answer == "true_positive" for r in rows)
    if best is None and not blocked:
        return None
    return Lean(
        None if best is None else int(best.id),
        None if best is None else str(best.outcome),
        None if best is None or best.confidence is None else float(best.confidence),
        best is not None and is_agent(best.assessor),
        blocked,
    )


async def lean(conn: AsyncConnection, ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, Lean]:
    """``Lean`` for each of ``ids`` in one read, whatever the number; one with nothing to say
    is not in the answer."""
    wanted = list(dict.fromkeys(ids))
    if not wanted:
        return {}
    own: dict[uuid.UUID, list[Any]] = defaultdict(list)
    shared: dict[uuid.UUID, list[Any]] = defaultdict(list)
    for row in await conn.execute(text(_LEAN), {"ids": wanted}):
        (shared if row.shared else own)[row.inv].append(row)
    out: dict[uuid.UUID, Lean] = {}
    for i in wanted:
        found = _lean_of(own.get(i, []), shared.get(i, []))
        if found is not None:
            out[i] = found
    return out


@dataclass(frozen=True)
class Recommendation:
    """ARGUS recommends closing these members of a pattern as ``outcome``: every member with a
    proposal has the same closing outcome, and none has a true positive it did not propose.
    ``members`` are the ones with a proposal; the rest are not covered."""

    outcome: str
    confidence: float | None  # the least sure of the proposals
    source: str
    members: tuple[uuid.UUID, ...]
    total: int


def recommend(ids: Sequence[uuid.UUID], found: Mapping[uuid.UUID, Lean]) -> Recommendation | None:
    """ARGUS's recommendation for a pattern's members, or None when it recommends nothing to
    close: no proposal, proposals that differ, one that is not a closing outcome, or a member
    whose answer was a true positive."""
    members = [(i, found[i]) for i in ids if i in found]
    if any(m.true_positive_reading for _, m in members):
        return None
    proposals = [(i, m) for i, m in members if m.outcome is not None]
    outcomes = {m.outcome for _, m in proposals}
    if len(outcomes) != 1:
        return None
    outcome = str(next(iter(outcomes)))
    if outcome not in CLOSING:
        return None
    sure = [m.confidence for _, m in proposals]
    agents = [m.agent for _, m in proposals]
    known = [c for c in sure if c is not None]
    return Recommendation(
        outcome,
        None if len(known) < len(sure) else min(known),
        "the AI investigator" if all(agents) else "the decision engine" if not any(agents)
        else "ARGUS",
        tuple(i for i, _ in proposals),
        len(ids),
    )  # fmt: skip
