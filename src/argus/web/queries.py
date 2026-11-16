"""What the Inbox shows: read functions shared by the JSON API and the pages.
The human state of an investigation is derived from its latest review and its version."""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.assess import raised
from argus.collector.lateness import reading_sql

HumanState = Literal["unreviewed", "reviewed", "follow_up", "changed_since_review"]
View = Literal["attention", "open", "reviewed", "all", "known"]
PAGE = 100

# The latest state-changing review (notes do not change the state) and the latest review of
# any kind: one row per reviewed investigation in review_state, kept by a trigger on
# review_events, and the derived state.
_STATE = """
LEFT JOIN review_state last ON last.investigation_id = i.id
LEFT JOIN case_known_matches km ON km.investigation_id = i.id
LEFT JOIN cases kc ON kc.id = km.case_id
"""
# What ARGUS decided about an investigation of a notified case's device.
# Held: decided known for the investigation's current version; it stays known when the
# case ends (frozen: it never comes back as new work), and a later version is decided afresh.
# Waiting: decided changed, and no person has reviewed a version of the investigation at or after
# the change; a change is durable, it outlives the investigation's next versions.
_HELD = "(coalesce(km.outcome = 'known' AND km.version = i.version, false))"
_WAITING = (
    "(coalesce(km.outcome = 'changed', false) AND NOT coalesce(last.action = 'reviewed'"
    " AND last.version >= km.changed_version, false))"
)
_HUMAN = """
CASE WHEN last.decision_id IS NULL THEN 'unreviewed'
     WHEN last.action = 'follow_up' THEN 'follow_up'
     WHEN last.version < i.version THEN 'changed_since_review'
     ELSE 'reviewed' END
"""
_COLUMNS = f"""
i.id, i.rule_id, i.rule_name, i.group_key, i.bucket_start, i.alert_count, i.duplicate_count,
i.first_event_at, i.last_event_at, i.severity, i.risk_score, i.version, i.created_at,
i.continues_id, {_HUMAN} AS human_state, last.latest_id AS latest_review,
COALESCE(i.alert_count - last.alert_count, 0) AS new_since_review,
last.outcome AS last_outcome, last.decided_at AS last_reviewed_at,
(SELECT u.display_name FROM users u WHERE u.id = last.user_id) AS last_reviewer,
(SELECT rz.flags FROM investigation_raises rz WHERE rz.investigation_id = i.id
 AND rz.version = i.version) AS raised_flags,
CASE WHEN {_WAITING} OR {_HELD} THEN kc.number END AS known_case,
CASE WHEN {_WAITING} OR {_HELD} THEN kc.id END AS known_case_id,
CASE WHEN {_WAITING} THEN 'changed' WHEN {_HELD} THEN 'known' END AS known_outcome,
CASE WHEN {_WAITING} THEN km.why END AS known_why,
CASE WHEN {_WAITING} OR {_HELD} THEN kc.notified_at END AS known_since
"""  # noqa: S608 - constant fragments (the name is looked up only for the rows returned)
# ARGUS raised it: the evidence of the current version carries
# a threat-list hit, an outside detection or a tie to the operator of one, and another flag
# (``raised.raises``)
# (with ``risk.present`` on, the incident engine's cases are the queue and nothing is raised here:
# ``risk_mode``, written by every pass)
RAISED = (
    "(NOT EXISTS (SELECT 1 FROM risk_mode rm WHERE rm.present)"  # noqa: S608 - constants
    " AND EXISTS (SELECT 1 FROM investigation_raises rz WHERE rz.investigation_id = i.id"
    " AND rz.version = i.version AND ("
    + " OR ".join(f"rz.flags ? '{flag}'" for flag in raised.STRONG)
    + f") AND jsonb_array_length(rz.flags) >= {raised.MIN_FLAGS}))"
)
#  an investigation of a notified case's device that belongs to the
# known infection (the owner was told; it is counted, not raised), and one that changed since the
# notice (it is raised, with its reason, until a person reviews it). Both are decisions of
# ``argus.cases.knownrun``. ``HELD`` is what stays out of Needs attention, even once the case has
# ended (frozen); ``KNOWN`` is the part of it that belongs to a case that is still notified
# (the "notified, still active" count and list).
HELD = _HELD
KNOWN = f"({_HELD} AND coalesce(kc.notified_at IS NOT NULL, false))"
CHANGED = _WAITING
# what would put an investigation in Needs attention without the notice: changed since a review,
# or unreviewed and rated high or critical or raised from its evidence
_WOULD = (
    f"({_HUMAN} = 'changed_since_review'"
    f" OR ({_HUMAN} = 'unreviewed' AND (i.severity IN ('critical', 'high') OR {RAISED})))"
)
# Needs attention: follow-ups, and new work: changed since review, or unreviewed ones the rule
# rates high or critical or ARGUS raised from its evidence, unless they belong to a known
# infection; with what changed since a notice (not yet reviewed). ``KNOWN_ATTENTION`` is what
# the known infections keep out: new + known is what Needs attention was.
ATTENTION = f"({_HUMAN} = 'follow_up' OR (NOT {HELD} AND {_WOULD}) OR {CHANGED})"
KNOWN_ATTENTION = f"({KNOWN} AND {_WOULD})"
# What a person still has to look at among a case's investigations: not reviewed and
# not a known infection's, or in Needs attention (a person's follow-up request is work even on a
# known one). Every investigation in Needs attention that belongs to a case that is not closed is
# this, so Home's cases and singles together hold all of Needs attention.
MEMBER_WORK = f"(({_HUMAN} <> 'reviewed' AND NOT {HELD}) OR {ATTENTION})"
# the earlier definition, kept for the tests that hold new + known to it
BEFORE_NOTICES = (
    f"({_HUMAN} IN ('follow_up', 'changed_since_review')"
    f" OR ({_HUMAN} = 'unreviewed' AND (i.severity IN ('critical', 'high') OR {RAISED})))"
)
# belongs to no case that is still being worked (a closed case is no one's work: a single
# investigation of its device is judged on its own)
NO_CASE = (
    "NOT EXISTS (SELECT 1 FROM case_members cm JOIN cases cc ON cc.id = cm.case_id"
    " WHERE cm.investigation_id = i.id AND cm.removed_at IS NULL AND cc.state <> 'closed')"
)
_SEVERITY_RANK = (
    "CASE i.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2"
    " WHEN 'low' THEN 1 ELSE 0 END"
)


_ORDER = {
    "urgent": f"({_HUMAN} = 'follow_up') DESC, {_SEVERITY_RANK} DESC,"
    " i.last_event_at DESC NULLS LAST, i.id",
    "reviewed": "last.decided_at DESC, i.id",
    "newest": "i.last_event_at DESC NULLS LAST, i.id",  # by the last alert
    "oldest": "i.last_event_at ASC NULLS LAST, i.id",
    # the queue's order: what a person has to look at first. Changed since the
    # notice, then raised by ARGUS's evidence, then a follow-up, then the rule's severity, then
    # the last alert. A rule's rating alone put 20 high-rated alerts ahead of a low-rated
    # investigation ARGUS had flagged.
    "queue": f"({CHANGED}) DESC, ({RAISED}) DESC, ({_HUMAN} = 'follow_up') DESC,"
    f" {_SEVERITY_RANK} DESC, i.last_event_at DESC NULLS LAST, i.id",
}
Sort = Literal["newest", "oldest", "urgent", "reviewed", "queue"]
# How each order is read: in parts, together exactly _ORDER, each but the
# follow-ups walking an index in its order instead of sorting every
# investigation. The urgent order is the follow-ups (few: read through their own index and
# sorted), then the rest, both by rank and the last alert; the decision order is the
# never-decided (NULLS FIRST, by id), then the decided, newest first.
_FOLLOW_UP = "last.action = 'follow_up'"
_BY_RANK = f"{_SEVERITY_RANK} DESC, i.last_event_at DESC NULLS LAST, i.id"


@dataclass(frozen=True)
class _Part:
    among: str  # which investigations
    by: str  # in what order
    walk: bool = True  # read by walking its order's index


_PARTS: dict[str, tuple[_Part, ...]] = {
    "urgent": (
        _Part(_FOLLOW_UP, _BY_RANK, walk=False),
        _Part(f"NOT coalesce({_FOLLOW_UP}, false)", _BY_RANK),
    ),
    "reviewed": (
        _Part("last.decision_id IS NULL", "i.id"),
        _Part("last.decision_id IS NOT NULL", "last.decided_at DESC, i.id"),
    ),
    "newest": (_Part("true", _ORDER["newest"]),),
    "oldest": (_Part("true", _ORDER["oldest"]),),
    # sorted whole: no index serves it. The set it is asked for is the Needs attention view (the
    # queue's), or a rule's or an entity's investigations
    "queue": (_Part("true", _ORDER["queue"], walk=False),),
}
# Postgres cannot estimate how many investigations a view's state filter keeps (it is
# computed from the outer join with review_state), and would rather sort them all than walk
# an index, spilling to disk past offsets of a few thousand. A walking part is planned with
# sorting switched off for its one statement (an index for its order always exists); never
# under a rule or an entity filter, whose few investigations a sort serves best.
_SORTING = "SELECT current_setting('enable_sort'), set_config('enable_sort', :to, true)"
DEEPEST = 10_000  # the deepest offset /api/v1 pages to (criterion 14 holds that deep)


async def counts(conn: AsyncConnection, now: datetime) -> dict[str, int]:
    """The home page's summary: how many investigations are in each state, and how many
    were decided in the last 24 hours."""
    row = (
        await conn.execute(
            text(
                f"SELECT count(*) FILTER (WHERE {ATTENTION}) AS attention,"  # noqa: S608 - constant fragments; values are bound
                f" count(*) FILTER (WHERE {KNOWN_ATTENTION}) AS known,"
                f" count(*) FILTER (WHERE {_HUMAN} <> 'reviewed') AS open,"
                f" count(*) FILTER (WHERE {_HUMAN} = 'follow_up') AS follow_up,"
                f" count(*) FILTER (WHERE {_HUMAN} = 'changed_since_review') AS changed,"
                " count(*) FILTER (WHERE last.decision_id IS NOT NULL) AS reviewed,"
                " count(*) FILTER (WHERE last.decided_at > :since) AS reviewed_today,"
                " count(*) AS all"
                f" FROM investigations i {_STATE}"
            ),
            {"since": now - timedelta(hours=24)},
        )
    ).one()
    return {k: int(v) for k, v in row._mapping.items()}


SINCE_CAP = 10_000  # "since your visit" counts stop here: the page says "10,000 or more"
_SINCE = """
SELECT
 (SELECT count(*) FROM (SELECT 1 FROM investigations WHERE created_at > :since
                        LIMIT :cap) x) AS new_investigations,
 (SELECT count(*) FROM (SELECT 1 FROM investigations WHERE created_at > :since
                        AND severity IN ('critical', 'high') LIMIT :cap) x) AS new_severe,
 (SELECT count(*) FROM (SELECT 1 FROM review_state WHERE decided_at > :since
                        AND user_id IS DISTINCT FROM :me LIMIT :cap) x) AS reviewed_by_others,
 (SELECT count(*) FROM (SELECT 1 FROM assessments WHERE status = 'proposed'
                        AND finished_at > :since LIMIT :cap) x) AS new_proposals"""


async def since(conn: AsyncConnection, user_id: int, at: datetime | None) -> dict[str, int]:
    """What changed after ``at`` (the person's previous visit): new investigations, of which
    severe, decisions by others, new proposals; each counted up to ``SINCE_CAP``. A first
    visit (no ``at``) has nothing to compare with: all zero."""
    names = ("new_investigations", "new_severe", "reviewed_by_others", "new_proposals")
    if at is None:
        return dict.fromkeys(names, 0)
    row = (await conn.execute(text(_SINCE), {"since": at, "me": user_id, "cap": SINCE_CAP})).one()
    return {k: int(row._mapping[k]) for k in names}


@dataclass(frozen=True)
class Summary:
    id: uuid.UUID
    rule_id: str
    rule_name: str | None
    group_key: str
    bucket_start: datetime
    alert_count: int
    duplicate_count: int
    first_event_at: datetime | None
    last_event_at: datetime | None
    severity: str | None
    risk_score: float | None
    version: int
    created_at: datetime
    continues_id: uuid.UUID | None
    human_state: HumanState
    latest_review: int | None
    new_since_review: int
    last_outcome: str | None = None
    last_reviewed_at: datetime | None = None
    last_reviewer: str | None = None
    key_fields: list[tuple[str, Any]] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    raised_flags: list[Any] | None = None  # the evidence's flags, when it has any
    known_case: int | None = None  # the notified case that holds it as a known infection
    known_case_id: uuid.UUID | None = None
    known_outcome: str | None = None  # "known", or "changed" (something is new since the notice)
    known_why: str | None = None  # "changed since notice: ..." for a change
    known_since: datetime | None = None  # when that case's owner was told


def key_fields(group_key: str) -> list[tuple[str, Any]]:
    """The (field, value) pairs of a canonical key; an alert-only key has none."""
    if group_key.startswith("alert:"):
        return []
    try:
        pairs = json.loads(group_key)
    except ValueError:
        return []
    return [(str(p[0]), p[1]) for p in pairs if isinstance(p, list) and len(p) == 2]


def reasons(s: Summary) -> list[str]:
    """Reasons to look: never verdicts."""
    out: list[str] = []
    if s.human_state == "follow_up":
        out.append("A reviewer asked for a follow-up.")
    if s.human_state == "changed_since_review":
        out.append(f"{s.new_since_review} new alerts since it was last reviewed.")
    if s.severity in ("critical", "high"):
        out.append(f"The rule rates it {s.severity}.")
    if s.human_state != "reviewed" and (why := raised.reason(s.raised_flags)) is not None:
        out.append(why + ".")
    if s.known_outcome == "changed" and s.known_why and s.human_state != "reviewed":
        out.append(s.known_why[0].upper() + s.known_why[1:] + ".")
    return out


def _summary(row: Any) -> Summary:
    summary = Summary(**dict(row._mapping))
    summary.key_fields.extend(key_fields(summary.group_key))
    summary.reasons.extend(reasons(summary))
    return summary


async def inbox(
    conn: AsyncConnection,
    view: View = "attention",
    *,
    rule: str | None = None,
    entity: tuple[str, str] | None = None,
    offset: int = 0,
    limit: int = PAGE,
    sort: Sort | None = None,
    without_case: bool = False,
) -> list[Summary]:
    """Investigations for a view: ``attention`` (follow-ups, changed since review, unreviewed
    critical/high), ``open`` (everything not reviewed), ``all``; optionally one rule or one
    entity. ``sort``: by the last alert (newest or oldest first), most urgent first, or the
    newest decision first; without it, the view's own order (urgent; reviewed: decided).
    ``without_case``: only investigations that belong to no case that is not closed."""
    where = ["true"]
    params: dict[str, Any] = {"offset": offset, "limit": limit}
    if view == "attention":
        where.append(ATTENTION)
    elif view == "known":  # what ARGUS counts of notified cases instead of raising: the tile's set
        where.append(KNOWN_ATTENTION)
    elif view == "open":
        where.append(f"{_HUMAN} <> 'reviewed'")
    elif view == "reviewed":  # decided at least once: newest decision first
        where.append("last.decision_id IS NOT NULL")
    if without_case:
        where.append(NO_CASE)
    if rule is not None:
        where.append("i.rule_id = :rule")
        params["rule"] = rule
    if entity is not None:
        where.append(
            "EXISTS (SELECT 1 FROM investigation_entities e WHERE e.investigation_id = i.id"
            " AND e.kind = :kind AND e.value = :value)"
        )
        params["kind"], params["value"] = entity
    order = sort or ("reviewed" if view == "reviewed" else "urgent")
    parts = _PARTS[order]
    if view == "reviewed" and order == "reviewed":
        parts = parts[1:]  # nothing in this view was never decided
    found: list[Summary] = []
    for n, part in enumerate(parts):
        among = " AND ".join([*where, part.among])
        walk = part.walk and rule is None and entity is None
        if walk:
            before = (await conn.execute(text(_SORTING), {"to": "off"})).one()[0]
        rows = [
            _summary(row)
            for row in await conn.execute(
                text(
                    f"SELECT {_COLUMNS} FROM investigations i {_STATE} WHERE {among}"  # noqa: S608 - constant fragments; values are bound
                    f" ORDER BY {part.by} OFFSET :offset LIMIT :limit"
                ),
                {**params, "offset": offset, "limit": limit - len(found)},
            )
        ]
        if walk:
            await conn.execute(text(_SORTING), {"to": before})
        found.extend(rows)
        if len(found) >= limit or n == len(parts) - 1:
            break
        if rows or not offset:  # this part ended on the page: the next starts at its first
            offset = 0
            continue
        # the whole part lies before the page: the next part starts that much nearer
        size = await conn.scalar(
            text(f"SELECT count(*) FROM investigations i {_STATE} WHERE {among}"),  # noqa: S608 - constant fragments; values are bound
            params,
        )
        offset = max(0, offset - int(size or 0))
    return found


async def investigation(conn: AsyncConnection, investigation_id: uuid.UUID) -> Summary | None:
    row = (
        await conn.execute(
            text(f"SELECT {_COLUMNS} FROM investigations i {_STATE} WHERE i.id = :id"),  # noqa: S608 - constant fragments; values are bound
            {"id": investigation_id},
        )
    ).first()
    return None if row is None else _summary(row)


ALERTS_SHOWN = 200
MAX_COLUMNS = 12
CELL_CHARS = 200
FIELD_SAMPLE = 200  # alerts whose fields make the column choices


async def alerts(
    conn: AsyncConnection,
    investigation_id: uuid.UUID,
    limit: int = ALERTS_SHOWN,
    columns: Sequence[str] = (),
) -> list[dict[str, Any]]:
    """The newest alerts; with ``columns``, each alert's values of those fields as text."""
    from argus.normalize.fields import values

    raw = ", a.raw" if columns else ""
    rows = await conn.execute(
        text(
            "SELECT a.alert_id, a.detected_at, a.event_time, a.status, a.workflow_status,"  # noqa: S608 - constant fragments; values are bound
            " ia.duplicate_of, ia.late_arrival, a.normalized->'entities' AS entities,"
            f" a.normalized->>'severity' AS severity{raw}"
            " FROM investigation_alerts ia JOIN alert_records a ON a.alert_id = ia.alert_id"
            " WHERE ia.investigation_id = :id ORDER BY a.event_time DESC, a.alert_id LIMIT :n"
        ),
        {"id": investigation_id, "n": limit},
    )
    out = []
    for row in rows:
        found = dict(row._mapping)
        doc = found.pop("raw", None) or {}
        found["cols"] = {
            c: ", ".join(_cell(v) for v in values(doc, c))[:CELL_CHARS] for c in columns
        }
        out.append(found)
    return out


def _cell(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, default=str)


async def alert_fields(conn: AsyncConnection, investigation_id: uuid.UUID) -> list[list[Any]]:
    """Every field the newest ``FIELD_SAMPLE`` alerts have, with how many of them have it:
    the columns a reviewer can add to the alerts table. The rule's own bookkeeping
    (``kibana.*``) comes last."""
    from argus.normalize.fields import leaf_values

    rows = await conn.execute(
        text(
            "SELECT a.raw FROM investigation_alerts ia JOIN alert_records a"
            " ON a.alert_id = ia.alert_id WHERE ia.investigation_id = :id"
            " ORDER BY a.event_time DESC, a.alert_id LIMIT :n"
        ),
        {"id": investigation_id, "n": FIELD_SAMPLE},
    )
    counts: dict[str, int] = {}
    for row in rows:
        for path in leaf_values(row.raw or {}):
            counts[path] = counts.get(path, 0) + 1
    return [
        [path, n]
        for path, n in sorted(counts.items(), key=lambda kv: (kv[0].startswith("kibana."), kv[0]))
    ]


async def raw_alert(
    conn: AsyncConnection, investigation_id: uuid.UUID, alert_id: str
) -> dict[str, Any] | None:
    row = (
        await conn.execute(
            text(
                "SELECT a.raw FROM alert_records a JOIN investigation_alerts ia"
                " ON ia.alert_id = a.alert_id WHERE ia.investigation_id = :id"
                " AND a.alert_id = :alert"
            ),
            {"id": investigation_id, "alert": alert_id},
        )
    ).first()
    return None if row is None else dict(row.raw)


async def dossier(conn: AsyncConnection, investigation_id: uuid.UUID) -> dict[str, Any] | None:
    """The newest dossier of an investigation, with each signal's plain sentence."""
    from argus.context.display import sentence

    row = (
        await conn.execute(
            text(
                "SELECT version, pack, status, partial_reason, body, created_at FROM dossiers"
                " WHERE investigation_id = :id ORDER BY version DESC, created_at DESC LIMIT 1"
            ),
            {"id": investigation_id},
        )
    ).first()
    if row is None:
        return None
    found = dict(row._mapping)
    body = found["body"]
    found["sentences"] = [
        sentence(s, plain=True) for s in [*body.get("local_signals", []), *body.get("signals", [])]
    ]
    found["report"] = body.get("report", {})
    found["fields"] = body.get("context", {}).get("pack", {}).get("fields", {})
    found["ips"] = body.get("context", {}).get("pack", {}).get("ips", {})
    related = [r for r in body.get("context", {}).get("related", [])
               if isinstance(r, dict) and _uuid(r.get("investigation_id")) is not None]  # fmt: skip
    ids = [uuid.UUID(r["investigation_id"]) for r in related]
    named = {
        str(r.id): r
        for r in await conn.execute(
            text("SELECT id, rule_name, group_key FROM investigations WHERE id = ANY(:ids)"),
            {"ids": ids},
        )
    } if ids else {}  # fmt: skip
    found["related"] = [
        {
            **r,
            "rule_name": getattr(named.get(r["investigation_id"]), "rule_name", None),
            "key_fields": key_fields(named[r["investigation_id"]].group_key)
            if r["investigation_id"] in named
            else [],
        }
        for r in related
    ]
    return found


def _uuid(value: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value))
    except ValueError:
        return None


GAP_WORDS = {
    "truncated_execution": "the rule hit its alert limit",
    "argus_collector_lag": "ARGUS was not collecting",
    "breaker_open": "the SIEM was overloaded",
}
# A collector gap that was only lateness (argus.collector.lateness, D-321)
LATE_WORDS = {
    "late": "ARGUS collected late (caught up; nothing missed)",
    "late_unchecked": "ARGUS collected late (caught up; the check that nothing was missed has"
    " not run yet)",
}
LAG_WORDS = {  # the gateway's refusal reasons (gateway.errors), in plain words
    "lane_busy": "its own SIEM budget was busy with other work",
    "deadline_passed": "a request ran out of time",
    "deferred": "the SIEM was busy, so ARGUS waited",
    "breaker_open": "the SIEM was overloaded, so ARGUS waited",
    "overloaded": "the SIEM was overloaded, so ARGUS waited",
    "skipped_budget": "ARGUS's daily SIEM budget was used up",
    "stopped": "collection was stopped by the kill switch",
    "transport_failure": "the SIEM could not be reached",
    "timed_out": "the SIEM did not answer in time",
    "auth_failed": "the SIEM refused ARGUS's key",
    "siem_error": "the SIEM answered with an error",
    "response_error": "the SIEM's answer could not be read",
    "partial_result": "the SIEM's answer was incomplete",
}


def banners(gaps: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The coverage gaps as a few plain warnings: the runs at the alert limit together (one
    line, their times listed), each outage on its own line, the newest last. A collector gap
    that was only lateness (``reading`` late) is a note, not a warning: ``late`` is set."""
    out: list[dict[str, Any]] = []
    limited = [g for g in gaps if g["kind"] == "truncated_execution"]
    for g in gaps:
        if g["kind"] == "truncated_execution":
            continue
        reading = g.get("reading") or "outage"
        if reading in LATE_WORDS:
            out.append({
                "kind": g["kind"], "start_at": g["start_at"], "end_at": g["end_at"],
                "text": LATE_WORDS[reading], "late": reading == "late",
            })  # fmt: skip
            continue
        detail = str(g.get("detail") or "")
        out.append({
            "kind": g["kind"], "start_at": g["start_at"], "end_at": g["end_at"],
            "text": GAP_WORDS.get(g["kind"], g["kind"].replace("_", " "))
            + (f" ({LAG_WORDS.get(detail, detail.replace('_', ' '))})" if detail else ""),
            "late": False,
        })  # fmt: skip
    if limited:
        out.append({
            "kind": "truncated_execution", "start_at": limited[0]["start_at"],
            "end_at": limited[-1]["end_at"] or limited[-1]["start_at"], "runs": limited,
            "text": f"the rule hit its alert limit in {len(limited)} run"
            + ("s" if len(limited) != 1 else "")
            + (f" ({limited[0]['detail']})" if len(limited) == 1 and limited[0].get("detail")
               else "") + ": more alerts may exist for those runs",
        })  # fmt: skip
    return out


async def reviews(conn: AsyncConnection, investigation_id: uuid.UUID) -> list[dict[str, Any]]:
    rows = await conn.execute(
        text(
            "SELECT r.id, r.action, r.outcome, r.note, r.version, r.alert_count, r.created_at,"
            " u.display_name FROM review_events r JOIN users u ON u.id = r.user_id"
            " WHERE r.investigation_id = :id ORDER BY r.id DESC"
        ),
        {"id": investigation_id},
    )
    return [dict(row._mapping) for row in rows]


async def by_rule(conn: AsyncConnection) -> list[dict[str, Any]]:
    # Counted per rule first, then joined per rule: open = all - reviewed, and only the
    # reviewed investigations (review_state's rows) are joined to their state.
    rows = await conn.execute(
        text(
            "WITH per_rule AS (SELECT i.rule_id, min(i.rule_name) AS rule_name,"  # noqa: S608 - constant fragments; values are bound
            " count(*) AS investigations, sum(i.alert_count) AS alerts,"
            " max(i.last_event_at) AS last_event_at FROM investigations i GROUP BY i.rule_id),"
            " settled AS (SELECT i.rule_id, count(*) AS n FROM review_state last"
            " JOIN investigations i ON i.id = last.investigation_id"
            f" WHERE {_HUMAN} = 'reviewed' GROUP BY i.rule_id)"
            " SELECT p.rule_id, p.rule_name, p.investigations,"
            " p.investigations - coalesce(s.n, 0) AS open, p.alerts, p.last_event_at,"
            " r.type, r.revision, r.interval, r.max_signals, r.execution_status,"
            " (SELECT count(*) FROM coverage_gaps g WHERE g.kind = 'truncated_execution'"
            "  AND g.subject LIKE 'rule:' || p.rule_id || ':%') AS truncated"
            " FROM per_rule p LEFT JOIN rules r ON r.rule_id = p.rule_id"
            " LEFT JOIN settled s ON s.rule_id = p.rule_id ORDER BY open DESC, alerts DESC"
        )
    )
    return [dict(row._mapping) for row in rows]


async def coverage(conn: AsyncConnection, inv: Summary) -> list[dict[str, Any]]:
    """Coverage gaps over an investigation's time: the collector's own outages,
    and executions of its rule that hit their alert limit."""
    # Gaps are in write time (when the alerts were written, when the rule ran); events can be
    # earlier by the detection lag or a whole look-back: both ranges count.
    written = (
        await conn.execute(
            text(
                "SELECT min(a.detected_at), max(a.detected_at) FROM investigation_alerts l"
                " JOIN alert_records a ON a.alert_id = l.alert_id WHERE l.investigation_id = :i"
            ),
            {"i": inv.id},
        )
    ).one()
    times = [t for t in (inv.first_event_at, inv.last_event_at, *written) if t is not None]
    if not times:
        return []
    rows = await conn.execute(
        text(
            f"SELECT kind, start_at, end_at, detail, {reading_sql('g')} AS reading"  # noqa: S608 - a constant fragment; values are bound
            " FROM coverage_gaps g"
            " WHERE start_at <= :last AND coalesce(end_at, 'infinity') >= :first"
            " AND (subject = 'alerts' OR subject LIKE 'rule:' || :rule || ':%')"
            " ORDER BY start_at LIMIT 500"
        ),
        {"first": min(times), "last": max(times), "rule": inv.rule_id},
    )
    return [dict(row._mapping) for row in rows]


def glossary() -> list[dict[str, str]]:
    """Every signal's label and how to read it (the display registry)."""
    from argus.context.display import registry

    return sorted(
        (
            {"name": n, "label": e.title("values"), "how": e.how_to_read}
            for n, e in registry().items()
        ),
        key=lambda g: g["label"].lower(),
    )


PATTERN_SAMPLE = 2000  # the investigations the Patterns page groups (the newest ones)


@dataclass(frozen=True)
class PatternsFound:
    """The Patterns page's groups, and what they were made from: ``read`` investigations of the
    newest ``limit``. When ``read`` reaches ``limit`` the groups are a sample."""

    groups: list[dict[str, Any]]
    read: int
    limit: int

    @property
    def sampled(self) -> bool:
        return self.read >= self.limit


async def patterns_page(conn: AsyncConnection, limit: int = PATTERN_SAMPLE) -> PatternsFound:
    """Investigations not reviewed yet, grouped when the same rule found the same things (each
    step's outcome, a threat-list hit, the values its steps look at; ``display.signature``):
    look at one, decide for the group. The groups are made from the ``limit``
    newest unreviewed investigations that have a dossier (by their last alert: the ones a person
    will meet first), so older ones are in no group when there are more."""
    from argus.context.display import signature

    rows = await conn.execute(
        text(
            "WITH newest AS (SELECT i.id, i.version, i.rule_id, i.rule_name, i.alert_count,"  # noqa: S608 - constant fragments; values are bound
            " i.group_key, i.last_event_at"
            f" FROM investigations i {_STATE} WHERE {_HUMAN} = 'unreviewed' AND NOT {HELD}"
            " AND EXISTS (SELECT 1 FROM dossiers d WHERE d.investigation_id = i.id"
            " AND d.version = i.version)"
            " ORDER BY i.last_event_at DESC NULLS LAST, i.id LIMIT :n)"
            " SELECT n.id, n.version, n.rule_id, n.rule_name, n.alert_count, n.group_key, d.body,"
            " (SELECT max(e.id) FROM review_events e WHERE e.investigation_id = n.id) AS latest"
            " FROM newest n JOIN LATERAL (SELECT x.body FROM dossiers x"
            " WHERE x.investigation_id = n.id AND x.version = n.version"
            " ORDER BY x.created_at DESC LIMIT 1) d ON true"
            " ORDER BY n.last_event_at DESC NULLS LAST, n.id"
        ),
        {"n": limit},
    )
    groups: dict[tuple[Any, ...], dict[str, Any]] = {}
    read = 0
    for row in rows:
        read += 1
        keys = [f for f, _ in key_fields(row.group_key)]
        key, common = signature(row.rule_id, keys, row.body)
        group = groups.setdefault(
            key,
            {
                "rule_id": row.rule_id,
                "rule_name": row.rule_name,
                "steps": [s for _, s in key[1]],
                "listed": key[2],
                "common": common,
                "members": [],
                "alerts": 0,
            },
        )
        group["members"].append({"id": str(row.id), "version": row.version, "latest": row.latest})
        group["alerts"] += row.alert_count
    found = [g for g in groups.values() if len(g["members"]) >= 2]
    ordered = sorted(found, key=lambda g: (-len(g["members"]), str(g["rule_name"])))
    return PatternsFound(ordered, read, limit)


async def patterns(conn: AsyncConnection, limit: int = PATTERN_SAMPLE) -> list[dict[str, Any]]:
    """The Patterns page's groups (``patterns_page`` without what they were made from)."""
    return (await patterns_page(conn, limit)).groups


async def by_entity(conn: AsyncConnection, limit: int = 200) -> list[dict[str, Any]]:
    rows = await conn.execute(
        text(
            "SELECT e.kind, e.value, e.investigations, e.investigations > 200 AS supernode"
            " FROM entities e WHERE e.kind IN ('ip', 'host')"
            " ORDER BY e.investigations DESC, e.kind, e.value LIMIT :n"
        ),
        {"n": limit},
    )
    return [dict(row._mapping) for row in rows]


SYNC_LATE = timedelta(minutes=90)  # the read-back runs every 10 to 60 minutes outside STOP


def sync_state(last: Mapping[str, Any] | None, now: datetime) -> str:
    """The Kibana read-back in one word, from its newest cycle: ``none`` (no cycle recorded),
    ``ok``, ``partial``, ``failed``, or ``late`` (none finished for longer than SYNC_LATE)."""
    if last is None:
        return "none"
    if now - last["finished_at"] > SYNC_LATE:
        return "late"
    return {"complete": "ok", "partial": "partial"}.get(str(last["outcome"]), "failed")


async def kibana_sync(conn: AsyncConnection, now: datetime) -> dict[str, Any]:
    last = (
        await conn.execute(
            text(
                "SELECT finished_at, outcome, reason FROM kibana_sync_cycles"
                " ORDER BY started_at DESC LIMIT 1"
            )
        )
    ).first()
    complete = (
        await conn.execute(
            text("SELECT max(finished_at) FROM kibana_sync_cycles WHERE outcome = 'complete'")
        )
    ).scalar_one_or_none()
    row = None if last is None else dict(last._mapping)
    return {
        "state": sync_state(row, now),
        "last_cycle_at": None if row is None else row["finished_at"],
        "last_outcome": None if row is None else row["outcome"],
        "last_reason": None if row is None else row["reason"],
        "last_complete_at": complete,
    }


async def health(conn: AsyncConnection, now: datetime) -> dict[str, Any]:
    from argus.gateway.health import HealthConfig, effective
    from argus.gateway.pgstore import health_from_json

    state = (
        await conn.execute(text("SELECT state FROM siem_state WHERE name = 'health'"))
    ).scalar_one_or_none()
    rows = await conn.execute(text("SELECT name, at FROM collector_cursors"))
    cursors: dict[str, datetime] = {str(row[0]): row[1] for row in rows}
    gaps = [
        dict(row._mapping)
        for row in await conn.execute(
            text(
                "SELECT kind, subject, start_at, detail FROM coverage_gaps WHERE end_at IS NULL"
                " ORDER BY start_at"
            )
        )
    ]
    for gap in gaps:  # the reason in plain words where it is the gateway's
        gap["words"] = LAG_WORDS.get(str(gap["detail"] or ""))
    run = (
        await conn.execute(
            text(
                "SELECT finished_at, hours, hours_mismatched, recovered, outcome"
                " FROM reconciliation_runs ORDER BY id DESC LIMIT 1"
            )
        )
    ).first()
    counts = (
        await conn.execute(
            text(
                "SELECT (SELECT count(*) FROM alert_records),"
                " (SELECT count(*) FROM alert_records WHERE status = 'quarantined'),"
                " (SELECT count(*) FROM investigations),"
                " (SELECT count(*) FROM jobs WHERE status IN ('queued', 'running')),"
                " (SELECT count(*) FROM jobs WHERE status = 'queued'"
                "  AND deferred_since IS NOT NULL),"
                " (SELECT count(*) FROM jobs WHERE status = 'failed'),"
                " (SELECT count(*) FROM dossiers),"
                " (SELECT count(DISTINCT thread_id) FROM langgraph.checkpoints),"
                " pg_total_relation_size('langgraph.checkpoints')"
                "  + pg_total_relation_size('langgraph.checkpoint_blobs')"
                "  + pg_total_relation_size('langgraph.checkpoint_writes')"
            )
        )
    ).one()
    memory = effective(health_from_json(state or {}), now, HealthConfig())
    return {
        "siem_state": memory.state.value,
        "siem_reasons": list(memory.reasons),
        "siem_probed_at": memory.probed_at,
        "live_cursor": cursors.get("live"),
        "backfill_cursor": cursors.get("backfill"),
        "open_gaps": gaps,
        "last_reconciliation": None if run is None else dict(run._mapping),
        "alerts": counts[0],
        "quarantined": counts[1],
        "investigations": counts[2],
        "jobs_waiting": counts[3],
        "jobs_deferred": counts[4],
        "jobs_failed": counts[5],
        "dossiers": counts[6],
        "checkpoint_threads": counts[7],
        "checkpoint_bytes": counts[8],
        "kibana_sync": await kibana_sync(conn, now),
    }
