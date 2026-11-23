"""What is worth a notice: the five triggers, each computed from ARGUS's own database (nothing here
asks the SIEM).

1. ``case_active``: a confirmed case the watch found active in the last :data:`LOOKBACK_DAYS`, after
   its verdict or containment; not a notified case (its owner was told).
2. ``after_closure``: activity after the closure of a case still closed, in the last
   :data:`AFTER_CLOSURE_DAYS`.
3. ``closure_waiting``: a closure request nobody has decided for more than :data:`WAITING`.
4. ``ioc_hit``: an unreviewed investigation whose newest dossier lists an indicator that a source
   calls high-confidence and whose actor is an internal host.
5. ``outage``: the SIEM degraded or stopped, the Kibana lane stopped or a write class paused, the
   daily watch not run, or an ARGUS-side coverage gap; noticed once it has lasted an hour.

A trigger that fails is reported in :attr:`Found.failed` and its kind is never resolved by that
pass: a database error must not read as "everything is fine".
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.assets.classify import IpClassifier
from argus.cases import opener, watch, watchrun
from argus.cases.approvals import NOT_REVOKED
from argus.cases.model import SEVERITIES, Severity, max_severity
from argus.collector.lateness import LATE_KIND, LATE_WITHIN
from argus.gateway.health import HealthConfig, HealthMemory, HealthState, effective
from argus.gateway.kibana import writes as kibana_writes
from argus.gateway.pgstore import health_from_json
from argus.notices.model import WAITING_HOURS, Condition, Kind, Target

log = logging.getLogger("argus.notices")

LOOKBACK_DAYS = 3  # a case is "still active" for this many days after the watch last saw it
AFTER_CLOSURE_DAYS = 3
IOC_DAYS = 1
ASSISTANT = opener.ASSISTANT  # the assistant's account: its verdicts are no person's look
IOC_PAGE = 200  # investigations read at a time for kind 4, the newest first
IOC_SCAN_LIMIT = 20_000  # more than this in a day: the kind is unreadable (held), not truncated
# A request lives to the end of the next write window, 15 to 39 hours, so it is noticed while
# there are at least 3 hours left.
WAITING = timedelta(hours=WAITING_HOURS)
URGENT_LEFT = timedelta(hours=12)  # a waiting closure is high when this little time is left
# Gaps that are ARGUS's or the gateway's own (coverage_gaps.kind) and a stalled log source: an
# hour of them is an outage (a collector gap closed sooner, its hours reconciled with nothing
# differing, was lateness: argus.collector.lateness). Rules not running and truncated executions
# are the SIEM's own.
OUTAGE_GAPS: Mapping[str, Severity] = {
    "argus_collector_lag": "high",
    "breaker_open": "medium",
    "source_stalled": "medium",
}
HIGH_WORDS = frozenset({"high", "very high", "very-high", "highest", "critical"})
HIGH_PERCENT = 75.0  # a feed that scores confidence 0 to 100


@dataclass
class Found:
    """What one pass found true now, and the kinds it could not read."""

    conditions: list[Condition] = field(default_factory=list)
    failed: set[Kind] = field(default_factory=set)


def utc_day(moment: datetime) -> date:
    return moment.astimezone(UTC).date()


def _severity(value: str, floor: Severity | None = None) -> Severity:
    got: Severity = value if value in SEVERITIES else "medium"
    return got if floor is None else max_severity(got, floor)


_ACTIVE = text(
    """
WITH ref AS (
  SELECT c.id, c.severity,
         (SELECT max(coalesce(CAST(e.details ->> 'at' AS timestamptz), e.occurred_at))
            FROM case_events e WHERE e.case_id = c.id AND e.kind = 'contained') AS contained_at,
         c.opened_at
  FROM cases c
  WHERE c.state IN ('open', 'assigned', 'contained') AND c.merged_into_id IS NULL
    AND c.opened_at IS NOT NULL AND c.notified_at IS NULL
), moments AS (
  SELECT id, severity, contained_at IS NOT NULL AS was_contained,
         greatest(opened_at, coalesce(contained_at, opened_at)) AS moment FROM ref
)
SELECT a.id, a.severity, a.was_contained,
  (SELECT count(*) FROM (
     SELECT k.day AS day FROM case_watch_checks k
     WHERE k.case_id = a.id AND k.outcome = 'active' AND k.day >= :since_day
       AND (k.day > CAST(a.moment AT TIME ZONE 'UTC' AS date)
            OR (k.source = 'alerts' AND CASE WHEN k.detail ->> 'last' ~ :stamp
                 THEN CAST(k.detail ->> 'last' AS timestamptz) END > a.moment))
     UNION
     SELECT CAST(e.occurred_at AT TIME ZONE 'UTC' AS date) FROM case_events e
     WHERE e.case_id = a.id AND e.kind = 'new_activity' AND e.occurred_at > a.moment
       AND e.occurred_at >= :since
  ) days) AS days
FROM moments a ORDER BY a.id
"""
)


# The watch writes ``detail.last`` with ``datetime.isoformat()``; anything else is not read.
_STAMP = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+(Z|[+-][0-9]{2}:[0-9]{2})$"


async def case_active(conn: AsyncConnection, now: datetime) -> list[Condition]:
    since = now - timedelta(days=LOOKBACK_DAYS)
    rows = await conn.execute(
        _ACTIVE, {"since": since, "since_day": utc_day(since), "stamp": _STAMP}
    )
    out = []
    for row in rows:
        days = int(row.days)
        if days > 0:
            floor: Severity | None = "high" if row.was_contained else None
            out.append(
                Condition(
                    "case_active",
                    str(row.id),
                    _severity(row.severity, floor),
                    days,
                    Target("case", row.id),
                )
            )
    return out


_AFTER = text(
    """
SELECT c.id, c.severity, count(e.id) AS n,
       (array_agg(e.details ->> 'child' ORDER BY e.id DESC))[1] AS child
FROM cases c JOIN case_events e ON e.case_id = c.id AND e.kind = 'activity_after_closure'
WHERE c.state = 'closed' AND e.occurred_at >= :since
GROUP BY c.id, c.severity ORDER BY c.id
"""
)


async def after_closure(conn: AsyncConnection, now: datetime) -> list[Condition]:
    rows = await conn.execute(_AFTER, {"since": now - timedelta(days=AFTER_CLOSURE_DAYS)})
    out = []
    for row in rows:
        follower = await _follower(conn, row.child)
        out.append(
            Condition(
                "after_closure",
                str(row.id),
                _severity(row.severity, "high"),
                int(row.n),
                Target("case", follower or row.id),
            )
        )
    return out


async def _follower(conn: AsyncConnection, child: object) -> uuid.UUID | None:
    """The suspected case that follows a closed one, when it exists (the link leads there)."""
    try:
        wanted = uuid.UUID(str(child))
    except ValueError:
        return None
    found = (
        await conn.execute(text("SELECT id FROM cases WHERE id = :c"), {"c": wanted})
    ).scalar_one_or_none()
    return found


_WAITING = text(
    f"""
SELECT DISTINCT ON (r.case_id) r.case_id, r.requested_at AS since, r.expires_at AS expires
FROM approval_requests r JOIN cases cs ON cs.id = r.case_id
WHERE r.kind = 'closure' AND cs.state <> 'closed' AND r.expires_at > :now
  AND r.requested_at <= :cut
  AND NOT EXISTS (SELECT 1 FROM approval_decisions d
                  WHERE d.request_id = r.id AND d.decision = 'rejected')
  AND (SELECT count(*) FROM approval_decisions d
       WHERE d.request_id = r.id AND d.decision = 'approved' AND {NOT_REVOKED})
      < r.required_approvals
ORDER BY r.case_id, r.requested_at
"""  # noqa: S608 - a constant fragment; every value is bound
)


def waiting_condition(
    case_id: uuid.UUID, since: datetime, expires: datetime, now: datetime
) -> Condition | None:
    """A closure request made at ``since`` that expires at ``expires``: worth a notice once it
    has waited :data:`WAITING` and until it expires; *high* in its last 12 hours. (A request lives
    until the end of the next write window, 15 to 39 hours, so after 12 hours it always has 3 or
    more hours left: none expires unnoticed.)"""
    if now - since < WAITING or expires <= now:
        return None
    severity: Severity = "high" if expires - now <= URGENT_LEFT else "medium"
    hours = int((now - since).total_seconds() // 3600)
    return Condition("closure_waiting", str(case_id), severity, hours, Target("case", case_id))


async def closure_waiting(conn: AsyncConnection, now: datetime) -> list[Condition]:
    rows = await conn.execute(_WAITING, {"now": now, "cut": now - WAITING})
    found = (waiting_condition(r.case_id, r.since, r.expires, now) for r in rows)
    return [c for c in found if c is not None]


_LISTED = "d.body #> '{context,pack,ti,listed}'"
_IOC = text(
    f"""
SELECT i.id, i.severity, i.group_key, i.last_event_at,
       jsonb_build_object('context', jsonb_build_object('pack', jsonb_build_object(
         'ti', d.body #> '{{context,pack,ti}}'))) AS body
FROM investigations i
JOIN LATERAL (SELECT x.body FROM dossiers x WHERE x.investigation_id = i.id
              ORDER BY x.version DESC, x.created_at DESC LIMIT 1) d ON true
WHERE i.last_event_at > :since
  AND CASE WHEN jsonb_typeof({_LISTED}) = 'array' THEN jsonb_array_length({_LISTED}) END > 0
  AND jsonb_path_exists(d.body,
        '$.context.pack.ti.answers[*].sources.*.match[*].confidence', '{{}}', true)
  AND (CAST(:after_at AS timestamptz) IS NULL
       OR (i.last_event_at, i.id) < (CAST(:after_at AS timestamptz), CAST(:after_id AS uuid)))
  AND NOT EXISTS (SELECT 1 FROM review_state s JOIN users u ON u.id = s.user_id
                  WHERE s.investigation_id = i.id AND s.version = i.version
                  AND s.action = 'reviewed' AND u.kind = 'person'
                  AND u.username <> :assistant)
  AND NOT EXISTS (SELECT 1 FROM case_known_matches k
                  WHERE k.investigation_id = i.id AND k.version = i.version
                  AND k.outcome = 'known')
ORDER BY i.last_event_at DESC, i.id DESC LIMIT :page
"""  # noqa: S608 - constant fragments; every value is bound
)


def is_high_confidence(value: object) -> bool:
    """A feed's own word for its most certain indicators ("high"), or a score of 75 or more out
    of 100. Anything else, and anything missing, is not high: a notice needs positive evidence."""
    if value is None or isinstance(value, bool):
        return False
    words = str(value).strip().lower().rstrip("%").strip()
    if words in HIGH_WORDS:
        return True
    try:
        score = float(words)
    except ValueError:
        return False
    return HIGH_PERCENT <= score <= 100.0


def _list(value: object) -> list[Any]:
    """``value`` if it is a list, else nothing (a stored dossier may hold anything)."""
    return list(value) if isinstance(value, list | tuple) else []


def high_confidence(ti: Mapping[str, Any]) -> int:
    """How many listed indicators of a dossier's threat-intel answers have a source match that
    is high-confidence (the answers :mod:`argus.context.intel` already stored)."""
    listed = {v for v in _list(ti.get("listed")) if isinstance(v, str)}
    sure: set[str] = set()
    for answer in _list(ti.get("answers")):
        if not isinstance(answer, Mapping) or answer.get("value") not in listed:
            continue
        sources = answer.get("sources")
        for source in sources.values() if isinstance(sources, Mapping) else ():
            if not isinstance(source, Mapping):
                continue
            for match in _list(source.get("match")):
                if isinstance(match, Mapping) and is_high_confidence(match.get("confidence")):
                    sure.add(str(answer["value"]))
    return len(sure)


def _ti(body: object) -> Mapping[str, Any]:
    """The dossier's threat-intel pack (``context.pack.ti``), or nothing."""
    node: object = body
    for key in ("context", "pack", "ti"):
        if not isinstance(node, Mapping):
            return {}
        node = node.get(key)
    return node if isinstance(node, Mapping) else {}


async def ioc_hit(
    conn: AsyncConnection, now: datetime, classifier: IpClassifier
) -> list[Condition]:
    """Every investigation of the window that qualifies: the SQL keeps those with a listed array
    and a source match that has a confidence, and the rest of the tests (a high confidence, an
    internal actor) run here on each page, so the pages go on until the list is exhausted and no
    flood of outside scanners can push an internal host out of sight. More than
    :data:`IOC_SCAN_LIMIT` candidates raises: the kind is held, never resolved on a partial
    read."""
    out: list[Condition] = []
    after_at: datetime | None = None
    after_id: uuid.UUID | None = None
    scanned = 0
    while True:
        rows = (
            await conn.execute(
                _IOC,
                {
                    "since": now - timedelta(days=IOC_DAYS),
                    "assistant": ASSISTANT,
                    "page": IOC_PAGE,
                    "after_at": after_at,
                    "after_id": after_id,
                },
            )
        ).all()
        for row in rows:
            sure = high_confidence(_ti(row.body))
            if not sure or not opener.is_own_actor(row.group_key, classifier):
                continue
            severity: Severity = "critical" if str(row.severity).lower() == "critical" else "high"
            out.append(
                Condition("ioc_hit", str(row.id), severity, sure, Target("investigation", row.id))
            )
        scanned += len(rows)
        if len(rows) < IOC_PAGE:
            return out
        if scanned >= IOC_SCAN_LIMIT:
            raise RuntimeError("too many investigations with listed indicators to read")
        after_at, after_id = rows[-1].last_event_at, rows[-1].id


HEALTH = Target("health")


def health_outage(
    memory: HealthMemory, now: datetime, config: HealthConfig | None = None
) -> Condition | None:
    """The SIEM's health memory (the gateway's own, ``argus.gateway.health``): DEGRADED or STOP,
    also when the probe has not been heard for the time the gateway itself calls stale. A
    memory that never probed (a checkout with no collector) is no outage."""
    if memory.probed_at is None:
        return None
    config = config or HealthConfig()
    now_state = effective(memory, now, config)
    if now_state.state not in (HealthState.DEGRADED, HealthState.STOP):
        return None
    if now_state.state is memory.state:
        since = memory.since or memory.probed_at
    else:  # the probe went quiet: the state began when it was last heard, plus the grace
        grace = config.stale_stop if now_state.state is HealthState.STOP else config.stale_degraded
        since = memory.probed_at + grace
    severity: Severity = "high" if now_state.state is HealthState.STOP else "medium"
    return Condition("outage", "siem", severity, 0, HEALTH, since)


def kibana_outages(lane: kibana_writes.KibanaLaneState) -> list[Condition]:
    """Kibana work stopped (a 401 or a read's 403, until an operator resumes it), and each write
    class paused (a write's 403 or a wrong answer)."""
    out = []
    if lane.stopped is not None:
        out.append(Condition("outage", "kibana", "medium", 0, HEALTH, lane.stopped_at))
    for write_class in sorted(lane.paused):
        out.append(Condition("outage", f"kibana:{write_class}", "medium", 0, HEALTH))
    return out


def watch_outage(mode: str, last: datetime | None, now: datetime) -> Condition | None:
    """The daily still-active watch is switched on and has not run for 36 hours (the time
    ``argus doctor`` calls late). With no run at all there is no start to count from: the
    outage is noticed 36 hours after the first pass that saw the watch switched on."""
    if mode == "off":
        return None
    if last is None:  # never run: the first run is late 36 hours after the switch-on was seen
        return Condition("outage", "watch", "medium", 0, HEALTH, None, watch.RUN_LATE)
    if now - last <= watch.RUN_LATE:
        return None
    return Condition("outage", "watch", "medium", 0, HEALTH, last + watch.RUN_LATE)


async def _outages(
    conn: AsyncConnection, now: datetime, *, watch_mode: str, health: HealthConfig | None
) -> list[Condition]:
    out: list[Condition] = []
    state = (
        await conn.execute(text("SELECT state FROM siem_state WHERE name = 'health'"))
    ).scalar_one_or_none()
    if state:
        found = health_outage(health_from_json(dict(state)), now, health)
        if found is not None:
            out.append(found)
    lane = (
        await conn.execute(text("SELECT state FROM siem_state WHERE name = 'kibana'"))
    ).scalar_one_or_none()
    if lane:
        out += kibana_outages(kibana_writes.from_json(dict(lane)))
    found_watch = watch_outage(watch_mode, await watchrun.last_run(conn), now)
    if found_watch is not None:
        out.append(found_watch)
    gaps = await conn.execute(
        text(
            "SELECT kind, min(start_at) AS since FROM coverage_gaps"
            " WHERE end_at IS NULL AND kind = ANY(:kinds) GROUP BY kind ORDER BY kind"
        ),
        {"kinds": sorted(OUTAGE_GAPS)},
    )
    for gap in gaps:
        # a collector gap shorter than LATE_WITHIN may yet read as lateness, caught up with
        # nothing missed (D-321): it is noticed only once it has lasted that long
        after = LATE_WITHIN if gap.kind == LATE_KIND else None
        out.append(
            Condition("outage", f"gap:{gap.kind}", OUTAGE_GAPS[gap.kind], 0, HEALTH, gap.since,
                      after)
        )  # fmt: skip
    return out


async def compute(
    engine: AsyncEngine,
    now: datetime,
    *,
    classifier: IpClassifier,
    watch_mode: str = "off",
    health: HealthConfig | None = None,
) -> Found:
    """Every condition true at ``now``. Each trigger reads on a connection of its own, so one
    that fails (its kind goes to :attr:`Found.failed`) leaves the others intact."""
    found = Found()
    steps: list[tuple[Kind, Callable[[AsyncConnection], Any]]] = [
        ("case_active", lambda c: case_active(c, now)),
        ("after_closure", lambda c: after_closure(c, now)),
        ("closure_waiting", lambda c: closure_waiting(c, now)),
        ("ioc_hit", lambda c: ioc_hit(c, now, classifier)),
        ("outage", lambda c: _outages(c, now, watch_mode=watch_mode, health=health)),
    ]
    for kind, step in steps:
        try:
            async with engine.connect() as conn:
                found.conditions += await step(conn)
        except Exception as exc:  # a failed read is "unknown", never "resolved"
            found.failed.add(kind)
            log.warning("notice trigger %s failed: %s", kind, type(exc).__name__)
    return found
