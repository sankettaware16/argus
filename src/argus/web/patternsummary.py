"""The patterns ARGUS recommends closing, for Home (AR4 review, D-186): a lean summary computed in
SQL from the investigator's runs and their patterns, whatever the number of investigations.

A pattern here is what AR2 grouped (``assessment_shares``: the investigations one run stands for,
its pattern's hash and IST day), counted at each member's current version, unreviewed and not
held as a notified case's known infection. The Patterns page groups by the dossiers it can read
(a sample of the newest 2,000, ``queries.patterns``); this one reads no dossier, so its numbers are
the real totals, not a sample's. The rule of the recommendation is ``stance.recommend``, in SQL:
every member that has a proposal has the same closing outcome, no member's answer was a true
positive it did not propose; the covered members are the ones with a proposal. A property test
holds the two to each other on generated data.

``summary`` is the few largest patterns (a count of all of them, and of the investigations they
cover); ``closing`` is one pattern's covered members with the version and latest review each was
read at, for the one request that closes them, asked for only when a person presses Close. Reading
only.
"""

from __future__ import annotations

import uuid
from datetime import date
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.web import stance
from argus.web.v1 import models as m

SHOWN = 8  # the patterns the summary lists
CLOSE_MAX = 200  # the most investigations one closing request names (the review route's limit)
EXAMPLES = 3

_CLOSING = ", ".join(f"'{o}'" for o in sorted(stance.CLOSING))
# A reading of a run (the investigator's "answer") is only needed for a run that proposed nothing.
_ANSWER = f"CASE WHEN a.status = 'no_decision' THEN {stance._ANSWER} END"
# The members of each pattern, the best proposal of each, and the pattern's figures; ``{only}`` is
# one pattern (a closing request) or nothing (the summary).
#
# * A member is unreviewed (no decision, ``queries._HUMAN``) and not held as known
#   (``queries.HELD``), written as two anti-joins: as ``LEFT JOIN ... IS NULL`` the planner reads
#   zero rows from the review table's never-null column, sizes everything after it at one row and
#   nests loops over the whole set (minutes on the R7 seed).
# * A member's proposal is its own (the investigator's before the engine's) else the newest of the
#   runs that stand for it; a run that stands for it never replaces the investigator's own
#   assessment, of any status (``stance._lean_of``). The reading that blocks is a run that proposed
#   nothing and answered true positive.
# * Everything is a hash join or a hash aggregate over the members once (no sort of the whole set,
#   no CTE read once for each row).
_GROUPS = f"""
m AS (
  SELECT DISTINCT s.pattern, s.day, i.id, i.version, i.alert_count
  FROM assessment_shares s
  JOIN investigations i ON i.id = s.investigation_id AND i.version = s.version
  WHERE NOT EXISTS (SELECT 1 FROM review_state last WHERE last.investigation_id = i.id
                    AND last.decision_id IS NOT NULL)
    AND NOT EXISTS (SELECT 1 FROM case_known_matches km WHERE km.investigation_id = i.id
                    AND km.outcome = 'known' AND km.version = i.version) {{only}}
), own AS (
  SELECT DISTINCT ON (a.investigation_id, a.version, a.assessor) a.investigation_id AS inv,
         a.version, a.id, a.assessor, a.status, a.outcome, a.confidence, {_ANSWER} AS answer
  FROM assessments a
  ORDER BY a.investigation_id, a.version, a.assessor, a.id DESC
), ownm AS (
  SELECT inv, version, bool_or(starts_with(assessor, 'agent')) AS agent,
         bool_or(status = 'no_decision' AND answer = 'true_positive') AS threat,
         bool_or(status = 'proposed' AND outcome IS NOT NULL) AS proposes,
         (array_agg(assessor ORDER BY (NOT starts_with(assessor, 'agent')), assessor)
          FILTER (WHERE status = 'proposed' AND outcome IS NOT NULL))[1] AS assessor,
         (array_agg(outcome ORDER BY (NOT starts_with(assessor, 'agent')), assessor)
          FILTER (WHERE status = 'proposed' AND outcome IS NOT NULL))[1] AS outcome,
         (array_agg(confidence ORDER BY (NOT starts_with(assessor, 'agent')), assessor)
          FILTER (WHERE status = 'proposed' AND outcome IS NOT NULL))[1] AS confidence
  FROM own GROUP BY inv, version
), shared AS (
  SELECT s.investigation_id AS inv, s.version, a.id, a.status, a.outcome,
         {_ANSWER} AS answer
  FROM assessment_shares s JOIN assessments a ON a.id = s.assessment_id
  WHERE a.status IN ('proposed', 'no_decision')
    AND NOT (a.investigation_id = s.investigation_id AND a.version = s.version)
), sharedm AS (
  SELECT inv, version, max(id) FILTER (WHERE status = 'proposed' AND outcome IS NOT NULL) AS best,
         bool_or(status = 'no_decision' AND answer = 'true_positive') AS threat
  FROM shared GROUP BY inv, version
), sharedp AS (
  SELECT sm.inv, sm.version, sm.threat, sm.best, a.assessor, a.outcome, a.confidence
  FROM sharedm sm LEFT JOIN assessments a ON a.id = sm.best
), pm AS (
  SELECT m.pattern, m.day, m.id, m.version, m.alert_count,
         (coalesce(om.proposes, false)
          OR (NOT coalesce(om.agent, false) AND sp.best IS NOT NULL)) AS covered,
         CASE WHEN om.proposes THEN om.assessor
              WHEN NOT coalesce(om.agent, false) THEN sp.assessor END AS assessor,
         CASE WHEN om.proposes THEN om.outcome
              WHEN NOT coalesce(om.agent, false) THEN sp.outcome END AS outcome,
         CASE WHEN om.proposes THEN om.confidence
              WHEN NOT coalesce(om.agent, false) THEN sp.confidence END AS confidence,
         (coalesce(om.threat, false)
          OR (NOT coalesce(om.agent, false) AND coalesce(sp.threat, false))) AS threat
  FROM m LEFT JOIN ownm om ON om.inv = m.id AND om.version = m.version
  LEFT JOIN sharedp sp ON sp.inv = m.id AND sp.version = m.version
), g AS (
  SELECT pattern, day, count(*) AS members, coalesce(sum(alert_count), 0) AS alerts,
         count(*) FILTER (WHERE covered) AS covered, min(outcome) = max(outcome) AS single,
         min(outcome) AS outcome, min(confidence) AS sure,
         count(*) FILTER (WHERE covered AND confidence IS NULL) AS unsure,
         coalesce(bool_and(starts_with(assessor, 'agent')) FILTER (WHERE covered), false)
             AS all_agent,
         coalesce(bool_or(starts_with(assessor, 'agent')) FILTER (WHERE covered), false)
             AS any_agent,
         bool_or(threat) AS blocked
  FROM pm GROUP BY pattern, day
), rec AS (
  SELECT g.* FROM g
  WHERE g.members >= 2 AND g.covered >= 1 AND g.single AND NOT g.blocked
    AND g.outcome IN ({_CLOSING})
)
"""  # noqa: S608 - constant fragments

# the few biggest of the recommended, with the rule and a few of their investigations each (read
# for those only)
_TOP = f"""
SELECT t.*, ex.examples, ex.rule_id, ex.rule_name FROM top t LEFT JOIN LATERAL (
  SELECT array_agg(x.id) AS examples, min(x.rule_id) AS rule_id, min(x.rule_name) AS rule_name
  FROM (SELECT pm.id, i.rule_id, i.rule_name FROM pm JOIN investigations i ON i.id = pm.id
        WHERE pm.pattern = t.pattern AND pm.day = t.day
        ORDER BY pm.alert_count DESC, pm.id LIMIT {EXAMPLES}) x) ex ON true
ORDER BY t.covered DESC, t.alerts DESC, t.pattern, t.day
"""  # noqa: S608 - constant fragments

_SUMMARY = f"""
WITH {_GROUPS.format(only="")}, top AS (
  SELECT rec.*, count(*) OVER () AS total, sum(rec.covered) OVER () AS covered_total FROM rec
  ORDER BY rec.covered DESC, rec.alerts DESC, rec.pattern, rec.day LIMIT :n)
{_TOP}"""  # noqa: S608 - constant fragments; values are bound

_ONE = f"""
WITH {_GROUPS.format(only="AND s.pattern = :pattern AND s.day = :day")}, top AS (SELECT * FROM rec)
{_TOP}"""  # noqa: S608 - constant fragments; values are bound

_MEMBERS = f"""
WITH {_GROUPS.format(only="AND s.pattern = :pattern AND s.day = :day")}
SELECT pm.id, pm.version,
       (SELECT max(e.id) FROM review_events e WHERE e.investigation_id = pm.id) AS latest
FROM pm JOIN investigations i ON i.id = pm.id WHERE pm.covered
ORDER BY i.last_event_at DESC NULLS LAST, pm.id LIMIT :cap
"""  # noqa: S608 - constant fragments; values are bound


def _source(row: Any) -> str:
    return (
        "the AI investigator" if row.all_agent else "ARGUS" if row.any_agent
        else "the decision engine"
    )  # fmt: skip


def _float(value: Any) -> float | None:
    return None if value is None else float(value)


def _brief(row: Any) -> m.PatternBriefOut:
    return m.PatternBriefOut(
        pattern=row.pattern, day=row.day, rule_id=row.rule_id, rule_name=row.rule_name,
        investigations=int(row.members), alerts=int(row.alerts), covered=int(row.covered),
        outcome=row.outcome, confidence=None if row.unsure else _float(row.sure),
        source=_source(row), examples=[uuid.UUID(str(x)) for x in row.examples or []],
    )  # fmt: skip


async def _quick(conn: AsyncConnection) -> None:
    """No JIT for this request's statements. The planner sizes the joins of CTEs (which have no
    statistics) at a million rows, above ``jit_above_cost``, and compiling the query takes longer
    than running it (60 ms of 160 on the R7 seed). The setting ends with the transaction."""
    await conn.execute(text("SELECT set_config('jit', 'off', true)"))


async def summary(conn: AsyncConnection) -> m.PatternSummaryOut:
    """The largest patterns ARGUS recommends closing, and how many there are in all."""
    await _quick(conn)
    rows = (await conn.execute(text(_SUMMARY), {"n": SHOWN})).all()
    if not rows:
        return m.PatternSummaryOut(total=0, investigations=0, items=[])
    return m.PatternSummaryOut(
        total=int(rows[0].total), investigations=int(rows[0].covered_total),
        items=[_brief(r) for r in rows],
    )  # fmt: skip


async def closing(conn: AsyncConnection, pattern: str, day: date) -> m.PatternCloseOut | None:
    """The members a recommendation to close one pattern covers (at most ``CLOSE_MAX``), read now
    with the version and latest review of each; None when ARGUS no longer recommends closing it."""
    params = {"pattern": pattern, "day": day}
    await _quick(conn)
    one = (await conn.execute(text(_ONE), params)).first()
    if one is None:
        return None
    found = (await conn.execute(text(_MEMBERS), {**params, "cap": CLOSE_MAX})).all()
    return m.PatternCloseOut(
        brief=_brief(one),
        members=[
            m.PatternMemberOut(
                investigation_id=uuid.UUID(str(r.id)),
                version=int(r.version),
                latest_review=r.latest,
            )
            for r in found
        ],
    )
