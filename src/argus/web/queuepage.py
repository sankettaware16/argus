"""The case-first queue (AR4, D-161 point 4, D-182): what needs a person, in the order to do it.

1. **ARGUS's open cases that need a person** (``casepages.WORK``, also the case list's ``queue``
   view). A suggested case (nobody has confirmed it) and a case with a change since the owner was
   told come first; then a case ARGUS or Kibana flagged or with a request waiting for an approver,
   a confirmed case nobody owns yet, and a case someone owns that holds an investigation in
   Needs attention (D-186: an owned case is not out of sight while it has new work). A notified
   case that is still active with nothing changed is not work: it is a count
   (``notified_cases``). Each case carries ARGUS's verdict or reading on its first investigation
   to look at, its devices, and a sentence for why it is here.
2. **Single investigations** in Needs attention that belong to no case that is still being worked,
   in the queue's order (``queries`` ``queue`` sort: changed since a notice, raised by ARGUS's
   evidence, follow-up, the rule's severity, the last alert). Every investigation in Needs
   attention is a single or a member of a case here, and ``cases_total``, ``singles_total`` and
   ``order_total`` count all of them, whatever the lists show.
3. **The order "Next" walks**: the unreviewed investigations of the cases above, case by case,
   then the single investigations. It is capped; ``order_total`` says how many the whole queue
   holds.

The patterns ARGUS recommends closing are ``/patterns`` and the numbers of new and known work
are ``/counts``: they are not repeated here. Reading only.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.web import casepages, queries, stance
from argus.web.v1 import case_models as cm
from argus.web.v1 import queue_models as qm
from argus.web.v1 import views

CASES_SHOWN = 30
SINGLES_SHOWN = 20
ORDER_MAX = 150
MEMBERS_PER_CASE = 10  # the most investigations of one case in the order
DEVICES_SHOWN = 4
CHANGES_SHOWN = 3

_WORK = casepages.WORK
_RANK = "CASE c.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END"
# suggested and changed cases first, then by severity and by what moved last
_ORDER = (
    f"ORDER BY (NOT (c.state = 'suspected' OR {casepages.CHANGED_SINCE_NOTICE})),"
    f" {_RANK}, c.updated_at DESC, c.number DESC"
)
_FLAGS = f"""
SELECT c.id, ({casepages.CHANGED_SINCE_NOTICE}) AS changed
FROM cases c WHERE c.id = ANY(:ids)
"""  # noqa: S608 - constant fragments; values are bound

_MEMBERS = f"""
SELECT x.case_id, x.id, x.n, x.unreviewed, x.attention, x.work FROM (
  SELECT mm.case_id, i.id,
         row_number() OVER (PARTITION BY mm.case_id ORDER BY
             {queries.MEMBER_WORK} DESC, {queries._WAITING} DESC, {queries.RAISED} DESC,
             (({queries._HUMAN}) = 'follow_up') DESC, {queries._SEVERITY_RANK} DESC,
             i.last_event_at DESC NULLS LAST, i.id) AS n,
         count(*) FILTER (WHERE {queries.MEMBER_WORK}) OVER (PARTITION BY mm.case_id) AS unreviewed,
         count(*) FILTER (WHERE {queries.ATTENTION}) OVER (PARTITION BY mm.case_id) AS attention,
         {queries.MEMBER_WORK} AS work
  FROM case_members mm JOIN investigations i ON i.id = mm.investigation_id {queries._STATE}
  WHERE mm.case_id = ANY(:ids) AND mm.removed_at IS NULL
) x WHERE x.n <= :per ORDER BY x.case_id, x.n
"""  # noqa: S608 - constant fragments; values are bound

_DEVICES = """
SELECT case_id, value, count(*) OVER (PARTITION BY case_id) AS total
FROM case_indicators WHERE case_id = ANY(:ids) AND removed_at IS NULL AND role = 'actor'
AND kind IN ('ip', 'host') ORDER BY case_id, kind, value
"""

_CHANGES = """
SELECT k.case_id, k.why FROM case_known_matches k
WHERE k.case_id = ANY(:ids) AND k.outcome = 'changed' AND k.why IS NOT NULL
AND NOT EXISTS (SELECT 1 FROM review_state s WHERE s.investigation_id = k.investigation_id
                AND s.action = 'reviewed' AND s.version >= k.changed_version)
ORDER BY k.case_id, k.investigation_id
"""

_SINGLES_TOTAL = f"""
SELECT count(*) FROM investigations i {queries._STATE}
WHERE {queries.ATTENTION} AND {queries.NO_CASE}
"""  # noqa: S608 - constant fragments; values are bound

# what the whole queue holds, the lists' caps aside: the investigations a person still has to look
# at in the cases that need one (each once; one may belong to two cases)
_CASE_WORK_TOTAL = f"""
SELECT count(DISTINCT i.id) FROM cases c
JOIN case_members mm ON mm.case_id = c.id AND mm.removed_at IS NULL
JOIN investigations i ON i.id = mm.investigation_id {queries._STATE}
WHERE {_WORK} AND {queries.MEMBER_WORK}
"""  # noqa: S608 - constant fragments; values are bound


async def _case_rows(
    conn: AsyncConnection, me_id: int
) -> tuple[list[tuple[cm.CaseRowOut, bool]], int]:
    rows = (
        await conn.execute(
            text(f"{casepages._ROW} WHERE {_WORK} {_ORDER} LIMIT :lim"),
            {"lim": CASES_SHOWN},
        )
    ).all()
    total = int(
        await conn.scalar(text(f"SELECT count(*) FROM cases c WHERE {_WORK}")) or 0  # noqa: S608
    )
    if not rows:
        return [], total
    ids = [r.id for r in rows]
    changed = {r.id: bool(r.changed) for r in await conn.execute(text(_FLAGS), {"ids": ids})}
    return [(casepages._row(r), changed.get(r.id, False)) for r in rows], total


def kind_of(row: cm.CaseRowOut, changed: bool) -> qm.QueueKind:
    """Why a case is in the queue: ARGUS suggests it, something changed since the owner was
    told, ARGUS or Kibana or an approval asks for a person, nobody owns it, or (what is left) it
    holds new work in a case that is being worked."""
    if row.state == "suspected":
        return "suggested"
    if changed:
        return "changed"
    if row.needs_attention or row.waiting_for_approval > 0:
        return "attention"
    if row.state == "open" and row.owner is None and row.notified_at is None:
        return "unowned"
    return "new"


def _new_words(row: cm.CaseRowOut, n: int) -> str:
    what = f"{n} new {'investigation' if n == 1 else 'investigations'}"
    if row.owner is not None:
        return f"{what} in a case someone owns."
    if row.state == "contained":
        return f"{what} in a case that is contained."
    return f"{what} in a case that is being worked."


def why_words(row: cm.CaseRowOut, kind: qm.QueueKind, new_members: int = 0) -> str:
    if kind == "suggested":
        return casepages.CAUSE_WORDS.get(
            row.cause, "Suggested by ARGUS. Nothing is open until a person confirms it."
        )
    if kind == "changed":
        return "Something changed since the owner was told."
    if kind == "attention":
        if row.attention:
            return row.attention
        if row.waiting_for_approval > 0:
            n = row.waiting_for_approval
            return f"{n} {'request is' if n == 1 else 'requests are'} waiting for an approver."
        return "Kibana has something for a person to look at."
    if kind == "new":
        return _new_words(row, new_members)
    return "A person confirmed it and nobody owns it yet."


async def build(conn: AsyncConnection, me_id: int, *, hide_logs: bool) -> qm.QueueOut:
    """The queue for one person."""
    found, total = await _case_rows(conn, me_id)
    ids = [row.id for row, _ in found]
    members: dict[uuid.UUID, list[Any]] = defaultdict(list)
    devices: dict[uuid.UUID, list[str]] = defaultdict(list)
    device_total: dict[uuid.UUID, int] = {}
    changes: dict[uuid.UUID, list[str]] = defaultdict(list)
    if ids:
        for r in await conn.execute(text(_MEMBERS), {"ids": ids, "per": MEMBERS_PER_CASE}):
            members[r.case_id].append(r)
        for r in await conn.execute(text(_DEVICES), {"ids": ids}):
            device_total[r.case_id] = int(r.total)
            if len(devices[r.case_id]) < DEVICES_SHOWN:
                devices[r.case_id].append(r.value)
        for r in await conn.execute(text(_CHANGES), {"ids": ids}):
            if r.why not in changes[r.case_id] and len(changes[r.case_id]) < CHANGES_SHOWN:
                changes[r.case_id].append(r.why)
    singles = await queries.inbox(
        conn, "attention", limit=SINGLES_SHOWN, sort="queue", without_case=True
    )
    singles_total = int(await conn.scalar(text(_SINGLES_TOTAL)) or 0)
    in_cases = int(await conn.scalar(text(_CASE_WORK_TOTAL)) or 0) if total else 0
    # the first investigation of each case to look at, and each single: ARGUS's stance on them
    first = {
        cid: rows[0].id for cid, rows in members.items() if rows
    }  # the best of the case: work first (the query orders it)
    stances = await stance.choices(conn, [*first.values(), *(s.id for s in singles)])
    sized = await stance.pattern_sizes(conn, [c.detail.assessment_id for c in stances.values()])

    def stance_for(inv: uuid.UUID | None) -> Any:
        found_ = stances.get(inv) if inv is not None else None
        size = sized.get(found_.detail.assessment_id) if found_ is not None else None
        return views.stance_out(found_, hide_logs=hide_logs, size=size)

    cases: list[qm.QueueCaseOut] = []
    order: list[uuid.UUID] = []
    for row, changed in found:
        rows = members.get(row.id, [])
        kind = kind_of(row, changed)
        new_members = int(rows[0].attention) if rows else 0
        work = [r.id for r in rows if r.work]
        order.extend(work)
        cases.append(
            qm.QueueCaseOut(
                id=row.id, number=row.number, title=row.title, state=row.state,
                severity=row.severity, kind=kind, why=why_words(row, kind, new_members),
                new_members=new_members,
                changes=changes.get(row.id, []), notified_at=row.notified_at,
                stance=stance_for(first.get(row.id)),
                devices=devices.get(row.id, []), devices_total=device_total.get(row.id, 0),
                investigations=row.investigations,
                unreviewed=int(rows[0].unreviewed) if rows else 0,
                alerts=row.alerts, last_alert_at=row.last_alert_at,
                waiting_for_approval=row.waiting_for_approval,
                first_investigation_id=work[0] if work else None,
            )
        )  # fmt: skip
    order.extend(s.id for s in singles)
    unique = list(dict.fromkeys(order))  # a investigation once, in its place
    notified = (await casepages.counts(conn, me_id)).notified
    return qm.QueueOut(
        cases=cases, cases_total=total,
        singles=[qm.QueueSingleOut(investigation=views.investigation(s), stance=stance_for(s.id))
                 for s in singles],
        singles_total=singles_total, notified_cases=notified, order=unique[:ORDER_MAX],
        order_total=in_cases + singles_total,
    )  # fmt: skip
