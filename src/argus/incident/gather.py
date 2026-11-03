"""What the incident report is written from: one case's stored facts, read from ARGUS's own
database in bounded statements and held in plain, frozen records.

Nothing here asks the SIEM, Kibana or a model, and nothing is written. The counts the report states
are exact aggregates in SQL; the alert documents are a bounded sample (the first and the newest of
the case), and what was cut is recorded in :attr:`CaseFacts.limits` and said in the report.
:func:`gather` reads; :mod:`argus.incident.build` is the pure function from these records."""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import Text, TextClause, bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.ext.asyncio import AsyncConnection

from argus import site
from argus.cases import knownview
from argus.normalize.fields import values
from argus.signins.model import FINAL_AFTER
from argus.signins.view import Users

ZONE_MARK = "@ZONE@"  # in a statement: the site's time zone (``zoned``)
MEMBERS = 500
DOCS_EACH_END = 100  # alert documents read from the start and from the end of the case
INDICATORS = 1000
ENTITIES = 6000
INV_DAYS = 20000
EVIDENCE_ROWS = 200
ASSESSMENTS = 600
OUTSIDE = 400
# the alert fields the report reads: the rest of a document is dropped as soon as it is read
READ_FIELDS = (
    "source.ip", "destination.ip", "destination.port", "user_agent.original", "url.path",
    "url.domain", "http.response.status_code", "http.response.body.bytes", "source.bytes",
    "destination.bytes", "source.geo.country_name", "source.as.organization.name",
    "source.as.number", "destination.geo.country_name", "destination.as.organization.name",
    "dns.question.name", "host.name", "user.name", "rule.id",
    "kibana.alert.rule.threat.technique.id",
    "threat.technique.id", "event.category", "event.outcome",
)  # fmt: skip


@dataclass(frozen=True)
class CaseRow:
    id: uuid.UUID
    number: int
    title: str
    state: str
    severity: str
    version: int
    cause: str
    created_at: datetime
    opened_at: datetime | None
    notified_at: datetime | None
    blocked_at: datetime | None
    cause_assessment_id: int | None


@dataclass(frozen=True)
class MemberRow:
    id: uuid.UUID
    rule: str
    rule_id: str | None
    severity: str | None
    alerts: int
    first: datetime | None
    last: datetime | None
    version: int
    link: str
    reviewed_outcome: str | None  # a person's review of this version
    flags: tuple[str, ...] = ()  # what ARGUS's evidence flagged on it (investigation_raises)
    listed: tuple[str, ...] = ()  # indicators the local threat lists hold (its dossier)


@dataclass(frozen=True)
class DayRule:
    day: str  # a local day
    rule: str
    alerts: int
    first: datetime
    last: datetime


@dataclass(frozen=True)
class AlertDoc:
    """The fields of one stored alert that the report reads (dotted name -> values)."""

    alert_id: str
    investigation_id: uuid.UUID
    rule: str
    at: datetime
    fields: Mapping[str, tuple[str, ...]]


@dataclass(frozen=True)
class EntityRow:
    investigation_id: uuid.UUID
    kind: str
    value: str


@dataclass(frozen=True)
class InvDay:
    """The alerts of one member investigation on one IST day."""

    investigation_id: uuid.UUID
    day: str
    alerts: int


@dataclass(frozen=True)
class IndicatorRow:
    kind: str
    value: str
    role: str
    source: str


@dataclass(frozen=True)
class EvidenceRow:
    investigation_id: uuid.UUID
    template: str
    version: int
    params: Mapping[str, Any]
    status: str
    row_count: int | None
    snapshot: Any
    collected_at: datetime


@dataclass(frozen=True)
class AssessmentRow:
    id: int
    investigation_id: uuid.UUID  # the member it stands for
    assessor: str
    status: str
    outcome: str | None
    confidence: float | None
    reasons: Sequence[Any]
    at: datetime | None
    shared: bool = False  # a run on a pattern's other investigation


@dataclass(frozen=True)
class OutsideRow:
    source: str
    kind: str
    value: str
    status: str
    answer: Mapping[str, Any]
    fetched_at: datetime


@dataclass(frozen=True)
class ReminderRow:
    kind: str
    why: str


@dataclass(frozen=True)
class ActionRow:
    action: str
    state: str


@dataclass(frozen=True)
class CaseFacts:
    case: CaseRow
    members: tuple[MemberRow, ...]
    members_total: int
    days: tuple[DayRule, ...]
    alerts_total: int
    docs: tuple[AlertDoc, ...]
    entities: tuple[EntityRow, ...]
    inv_days: tuple[InvDay, ...]
    indicators: tuple[IndicatorRow, ...]
    indicators_total: int
    evidence: tuple[EvidenceRow, ...]
    assessments: tuple[AssessmentRow, ...]
    outside: tuple[OutsideRow, ...]
    known: knownview.KnownCase | None
    notices: tuple[knownview.NoticeRow, ...]
    reminders: tuple[ReminderRow, ...]
    actions: tuple[ActionRow, ...]
    advice: frozenset[str]  # the responder's facts of the case (c2_indicator, ...)
    served: frozenset[str] = frozenset()  # paths a web check showed served
    order: int = 1  # the case's rank among the cases created that local day (the incident id's nn)
    limits: tuple[str, ...] = field(default_factory=tuple)
    users: Users | None = None  # who signed in from the case's devices, when it is on


_CASE = text(
    "SELECT id, number, title, state, severity, version, cause, created_at, opened_at,"
    " notified_at, blocked_at, cause_assessment_id FROM cases WHERE id = :c"
)
_ORDER = (
    "SELECT count(*) FROM cases WHERE number <= :n"  # noqa: S608 - constant fragments
    f" AND (created_at AT TIME ZONE {ZONE_MARK})::date"
    f" = (CAST(:made AS timestamptz) AT TIME ZONE {ZONE_MARK})::date"
)
_MEMBERS = text(
    "SELECT i.id, coalesce(i.rule_name, i.rule_id) AS rule, i.rule_id, i.severity, i.alert_count,"
    " i.first_event_at, i.last_event_at, i.version, m.link,"
    " (SELECT s.outcome FROM review_state s WHERE s.investigation_id = i.id"
    "  AND s.action = 'reviewed' AND s.version = i.version) AS reviewed_outcome,"
    " (SELECT r.flags FROM investigation_raises r WHERE r.investigation_id = i.id"
    "  AND r.version = i.version) AS flags,"
    " (SELECT d.body #> '{context,pack,ti,listed}' FROM dossiers d"
    "  WHERE d.investigation_id = i.id ORDER BY d.version DESC LIMIT 1) AS listed,"
    " count(*) OVER () AS total"
    " FROM case_members m JOIN investigations i ON i.id = m.investigation_id"
    " WHERE m.case_id = :c AND m.removed_at IS NULL"
    " ORDER BY i.first_event_at NULLS LAST, i.id LIMIT :n"
)
_DAYS = (
    "SELECT coalesce(i.rule_name, i.rule_id) AS rule,"  # noqa: S608 - constant fragments
    f" (COALESCE(a.event_time, a.detected_at) AT TIME ZONE {ZONE_MARK})::date AS day,"
    " count(*) AS n, min(COALESCE(a.event_time, a.detected_at)) AS first,"
    " max(COALESCE(a.event_time, a.detected_at)) AS last"
    " FROM case_members m JOIN investigations i ON i.id = m.investigation_id"
    " JOIN investigation_alerts l ON l.investigation_id = m.investigation_id"
    " AND l.duplicate_of IS NULL JOIN alert_records a ON a.alert_id = l.alert_id"
    " WHERE m.case_id = :c AND m.removed_at IS NULL"
    " AND COALESCE(a.event_time, a.detected_at) IS NOT NULL GROUP BY 1, 2 ORDER BY 2, 1"
)
_DOCS = (
    "SELECT a.alert_id, i.id AS investigation_id, coalesce(i.rule_name, i.rule_id) AS rule,"
    " COALESCE(a.event_time, a.detected_at) AS at, a.raw"
    " FROM case_members m JOIN investigations i ON i.id = m.investigation_id"
    " JOIN investigation_alerts l ON l.investigation_id = m.investigation_id"
    " AND l.duplicate_of IS NULL JOIN alert_records a ON a.alert_id = l.alert_id"
    " WHERE m.case_id = :c AND m.removed_at IS NULL"
    " AND COALESCE(a.event_time, a.detected_at) IS NOT NULL"
    " ORDER BY COALESCE(a.event_time, a.detected_at) {order}, a.alert_id LIMIT :n"
)
_ENTITIES = text(
    "SELECT e.investigation_id, e.kind, e.value"
    " FROM case_members m JOIN investigation_entities e ON e.investigation_id = m.investigation_id"
    " WHERE m.case_id = :c AND m.removed_at IS NULL ORDER BY 1, 2, 3 LIMIT :n"
)
_INV_DAYS = (
    "SELECT l.investigation_id,"  # noqa: S608 - constant fragments
    f" (COALESCE(a.event_time, a.detected_at) AT TIME ZONE {ZONE_MARK})::date AS day,"
    " count(*) AS n FROM case_members m"
    " JOIN investigation_alerts l ON l.investigation_id = m.investigation_id"
    " AND l.duplicate_of IS NULL JOIN alert_records a ON a.alert_id = l.alert_id"
    " WHERE m.case_id = :c AND m.removed_at IS NULL"
    " AND COALESCE(a.event_time, a.detected_at) IS NOT NULL GROUP BY 1, 2 ORDER BY 1, 2 LIMIT :n"
)
_INDICATORS = text(
    "SELECT kind, value, role, source, count(*) OVER () AS total FROM case_indicators"
    " WHERE case_id = :c AND removed_at IS NULL ORDER BY role, kind, value LIMIT :n"
)
_EVIDENCE = text(
    "SELECT e.investigation_id, e.template, e.template_version, e.params, e.status, e.row_count,"
    " e.snapshot, e.collected_at FROM evidence e JOIN case_members m"
    " ON m.investigation_id = e.investigation_id WHERE m.case_id = :c AND m.removed_at IS NULL"
    " AND e.status IN ('ok', 'empty') AND e.reused_from_version IS NULL"
    " ORDER BY e.collected_at DESC, e.task_key LIMIT :n"
)
_ASSESSMENTS = text(
    "SELECT a.id, a.investigation_id AS member, a.assessor, a.status, a.outcome, a.confidence,"
    " a.reasons, a.finished_at, false AS shared FROM assessments a"
    " JOIN case_members m ON m.investigation_id = a.investigation_id AND m.case_id = :c"
    " AND m.removed_at IS NULL JOIN investigations i ON i.id = a.investigation_id"
    " AND i.version = a.version WHERE a.status IN ('proposed', 'no_decision')"
    " UNION ALL"
    " SELECT a.id, s.investigation_id AS member, a.assessor, a.status, a.outcome, a.confidence,"
    " a.reasons, a.finished_at, true AS shared FROM assessment_shares s"
    " JOIN assessments a ON a.id = s.assessment_id"
    " JOIN case_members m ON m.investigation_id = s.investigation_id AND m.case_id = :c"
    " AND m.removed_at IS NULL JOIN investigations i ON i.id = s.investigation_id"
    " AND i.version = s.version WHERE a.status IN ('proposed', 'no_decision')"
    " ORDER BY 8 DESC NULLS LAST, 1 DESC LIMIT :n"
)
_OUTSIDE = text(
    "SELECT source, kind, indicator, status, answer, fetched_at FROM outside_lookups"
    " WHERE status IN ('found', 'not_found') AND ((kind = 'ip' AND indicator = ANY(:ips))"
    " OR (kind = 'domain' AND indicator = ANY(:domains))) ORDER BY fetched_at DESC LIMIT :n"
).bindparams(bindparam("ips", type_=ARRAY(Text)), bindparam("domains", type_=ARRAY(Text)))
_REMINDERS = text(
    "SELECT kind, why FROM case_reminders WHERE case_id = :c AND dismissed_at IS NULL"
    " ORDER BY suggested_at"
)
_ACTIONS = text("SELECT action, state FROM case_actions WHERE case_id = :c ORDER BY id")


def _strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(v)[:300] for v in value if isinstance(v, str | int | float))


def read_fields(doc: Mapping[str, Any]) -> dict[str, tuple[str, ...]]:
    """The values of the alert fields the report reads, as short strings."""
    out: dict[str, tuple[str, ...]] = {}
    for path in READ_FIELDS:
        found = tuple(dict.fromkeys(str(v)[:300] for v in values(doc, path)))[:20]
        if found:
            out[path] = found
    return out


async def gather(conn: AsyncConnection, case_id: uuid.UUID, now: datetime) -> CaseFacts | None:
    """The facts of one case, or None when there is no such case."""
    from argus.responder import facts as responder_facts

    c = (await conn.execute(_CASE, {"c": case_id})).first()
    if c is None:
        return None
    case = CaseRow(
        c.id, int(c.number), c.title, c.state, c.severity, int(c.version), c.cause,
        c.created_at, c.opened_at, c.notified_at, c.blocked_at, c.cause_assessment_id,
    )  # fmt: skip
    limits: list[str] = []
    order = int(
        await conn.scalar(zoned(_ORDER), {"n": case.number, "made": case.created_at}) or 1
    )  # the case's rank among the day's cases
    rows = (await conn.execute(_MEMBERS, {"c": case_id, "n": MEMBERS})).all()
    members = tuple(
        MemberRow(
            r.id, r.rule or "an unnamed rule", r.rule_id, r.severity, int(r.alert_count),
            r.first_event_at, r.last_event_at, int(r.version), r.link, r.reviewed_outcome,
            _strings(r.flags), _strings(r.listed),
        )
        for r in rows
    )  # fmt: skip
    total = int(rows[0].total) if rows else 0
    if total > len(members):
        limits.append(f"only {len(members)} of the case's {total} investigations were read")
    days = tuple(
        DayRule(r.day.isoformat(), r.rule or "an unnamed rule", int(r.n), r.first, r.last)
        for r in await conn.execute(zoned(_DAYS), {"c": case_id})
    )  # fmt: skip
    alerts_total = sum(d.alerts for d in days)
    docs: dict[str, AlertDoc] = {}
    for order_by in ("ASC", "DESC"):
        for r in await conn.execute(
            text(_DOCS.format(order=order_by)), {"c": case_id, "n": DOCS_EACH_END}
        ):
            if r.alert_id not in docs and isinstance(r.raw, Mapping):
                docs[r.alert_id] = AlertDoc(r.alert_id, r.investigation_id, r.rule or "", r.at,
                                            read_fields(r.raw))  # fmt: skip
    if alerts_total > len(docs):
        limits.append(
            f"actors, networks and user agents are read from {len(docs)} of the case's"
            f" {alerts_total} alerts (the first and the newest)"
        )
    entities = tuple(
        EntityRow(r.investigation_id, r.kind, r.value)
        for r in await conn.execute(_ENTITIES, {"c": case_id, "n": ENTITIES})
    )  # fmt: skip
    inv_days = tuple(
        InvDay(r.investigation_id, r.day.isoformat(), int(r.n))
        for r in await conn.execute(zoned(_INV_DAYS), {"c": case_id, "n": INV_DAYS})
    )  # fmt: skip
    ind_rows = (await conn.execute(_INDICATORS, {"c": case_id, "n": INDICATORS})).all()
    indicators = tuple(IndicatorRow(r.kind, r.value, r.role, r.source) for r in ind_rows)
    indicators_total = int(ind_rows[0].total) if ind_rows else 0
    if indicators_total > len(indicators):
        limits.append(
            f"only {len(indicators)} of the case's {indicators_total} indicators are listed"
        )
    evidence = tuple(
        EvidenceRow(
            r.investigation_id, r.template, int(r.template_version),
            r.params if isinstance(r.params, Mapping) else {}, r.status,
            None if r.row_count is None else int(r.row_count), r.snapshot, r.collected_at,
        )
        for r in await conn.execute(_EVIDENCE, {"c": case_id, "n": EVIDENCE_ROWS})
    )  # fmt: skip
    assessments = tuple(
        AssessmentRow(
            int(r.id), r.member, r.assessor, r.status, r.outcome, r.confidence,
            r.reasons if isinstance(r.reasons, list) else [], r.finished_at, bool(r.shared),
        )
        for r in await conn.execute(_ASSESSMENTS, {"c": case_id, "n": ASSESSMENTS})
    )  # fmt: skip
    ips = sorted({i.value for i in indicators if i.kind == "ip"})
    domains = sorted({i.value for i in indicators if i.kind == "domain"})
    outside: tuple[OutsideRow, ...] = ()
    if ips or domains:
        outside = tuple(
            OutsideRow(r.source, r.kind, r.indicator, r.status,
                       r.answer if isinstance(r.answer, Mapping) else {}, r.fetched_at)
            for r in await conn.execute(_OUTSIDE, {"ips": ips, "domains": domains, "n": OUTSIDE})
        )  # fmt: skip
    known = None
    if case.notified_at is not None:
        found = await knownview.notified(conn, now, case_id=case_id)
        known = found[0] if found else None
    notices = tuple(await knownview.notices(conn, case_id)) if case.notified_at else ()
    reminders = tuple(
        ReminderRow(r.kind, r.why) for r in await conn.execute(_REMINDERS, {"c": case_id})
    )
    actions = tuple(
        ActionRow(r.action, r.state) for r in await conn.execute(_ACTIONS, {"c": case_id})
    )
    advice = await responder_facts.read_facts(conn, case_id)
    return CaseFacts(
        case, members, total, days, alerts_total, tuple(docs.values()), entities, inv_days,
        indicators,
        indicators_total, evidence, assessments, outside, known, notices, reminders, actions,
        advice.present, frozenset(p for paths in advice.paths.values() for p in paths), order,
        tuple(limits),
    )  # fmt: skip


@dataclass(frozen=True)
class Signal:
    """What a cheap look at a case gives: ``text`` changes when anything the report reads
    changes, and ``last_alert`` is its newest alert (the report's "still going on" depends on it
    and on the time, which the caller adds)."""

    text: str
    last_alert: datetime | None


async def signals(conn: AsyncConnection, case_ids: Sequence[uuid.UUID]) -> dict[uuid.UUID, Signal]:
    """A cheap signal for each case: it changes when what the report says changes **in kind**,
    and not for each alert. An ongoing case grows all day; its report must not become a
    new version every 30 minutes for that alone. So the alert count is a bucket (the log base 2 of
    it: a new version when the case doubles) and the last event is its local day (a new version each
    day the activity goes on); beyond those, the signal changes with a new or removed indicator
    (and its role), device, evidence flag or threat-list hit, a person's review or decision, a
    notice, reminder, action or outside answer, a new kind of proposal, and the case's own state.
    A case whose signal is the one stored is not read again."""
    if not case_ids:
        return {}
    statement = zoned(_SIGNALS).bindparams(bindparam("ids", type_=ARRAY(UUID)))
    found = await conn.execute(statement, {"ids": list(case_ids)})
    return {r.id: Signal(r.signal, r.last_alert) for r in found}


def _bucket(expression: str) -> str:
    """SQL: the log base 2 of a count, whole (0 for none or one)."""
    return f"coalesce(floor(log(2, greatest(({expression})::numeric, 1)))::int, 0)"


_MEMBERS_OF = (
    "FROM case_members m JOIN investigations i ON i.id = m.investigation_id"
    " WHERE m.case_id = c.id AND m.removed_at IS NULL"
)
# a case's actor addresses that are IPv4 (the SSO logs' source.ip), cast with a guard: a value that
# is not a plain address must not fail the statement
# a finished day is final this long after its end (``signins.final_after``'s default)
FINAL_SECONDS = int(FINAL_AFTER.total_seconds())
_OCTET = "(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
_ACTOR_ADDRESSES = (
    "SELECT CASE WHEN x.value ~ '^(" + _OCTET + r"\.){3}" + _OCTET + "$'"  # noqa: S608
    " THEN CAST(x.value AS inet) END AS a FROM case_indicators x"
    " WHERE x.case_id = c.id AND x.removed_at IS NULL AND x.kind = 'ip' AND x.role = 'actor'"
)
_SIGNALS = (
    # the case itself (not its version: that moves with every new activity)
    "SELECT c.id, concat_ws('|', c.state, c.severity, md5(c.title), c.opened_at, c.notified_at,"  # noqa: S608
    " c.blocked_at, c.cause_assessment_id,"
    # how big and how long: the alert count's bucket, the members, the local day of the last event
    f" (SELECT concat_ws(',', count(*), {_bucket('sum(i.alert_count)')},"
    f"   (max(i.last_event_at) AT TIME ZONE {ZONE_MARK})::date) {_MEMBERS_OF}),"
    # the indicators and their roles (a new device, server or indicator, a changed role)
    " (SELECT concat_ws(',', count(*), md5(coalesce(string_agg(x.kind || ':' || x.value || ':'"
    "   || x.role, ',' ORDER BY x.kind, x.value, x.role), '')))"
    "  FROM case_indicators x WHERE x.case_id = c.id AND x.removed_at IS NULL),"
    # ARGUS's evidence flags on the members' current versions, and the threat-list hits
    " (SELECT md5(coalesce(string_agg(DISTINCT f, ',' ORDER BY f), ''))"
    "  FROM case_members m JOIN investigations i ON i.id = m.investigation_id"
    "  JOIN investigation_raises r ON r.investigation_id = i.id AND r.version = i.version"
    "  CROSS JOIN LATERAL jsonb_array_elements_text(r.flags) AS f"
    "  WHERE m.case_id = c.id AND m.removed_at IS NULL),"
    " (SELECT md5(coalesce(string_agg(DISTINCT v, ',' ORDER BY v), ''))"
    "  FROM case_members m"
    "  JOIN LATERAL (SELECT d.body FROM dossiers d WHERE d.investigation_id = m.investigation_id"
    "   ORDER BY d.version DESC, d.pack LIMIT 1) d ON true"
    "  CROSS JOIN LATERAL jsonb_array_elements_text(CASE"
    "   WHEN jsonb_typeof(d.body #> '{context,pack,ti,listed}') = 'array'"
    "   THEN d.body #> '{context,pack,ti,listed}' ELSE '[]'::jsonb END) AS v"
    "  WHERE m.case_id = c.id AND m.removed_at IS NULL),"
    # the checks that ran (a bucket: they come with the alerts)
    f" (SELECT {_bucket('count(*)')}"
    "  FROM evidence e JOIN case_members m ON m.investigation_id = e.investigation_id"
    "  WHERE m.case_id = c.id AND m.removed_at IS NULL AND e.status IN ('ok', 'empty')),"
    # what ARGUS proposed: the outcomes held and the confidence to a tenth, not each new proposal
    " (SELECT concat_ws(',', string_agg(DISTINCT a.outcome, '/' ORDER BY a.outcome),"
    "   round(avg(a.confidence)::numeric, 1))"
    "  FROM assessments a JOIN case_members m ON m.investigation_id = a.investigation_id"
    "  WHERE m.case_id = c.id AND m.removed_at IS NULL"
    "  AND a.status IN ('proposed', 'no_decision')),"
    # people: reviews (those still current) and decisions
    " (SELECT concat_ws(',', count(*), max(s.decision_id),"
    "   count(*) FILTER (WHERE s.action = 'reviewed' AND s.version = i.version))"
    "  FROM review_state s JOIN case_members m ON m.investigation_id = s.investigation_id"
    "  JOIN investigations i ON i.id = s.investigation_id"
    "  WHERE m.case_id = c.id AND m.removed_at IS NULL),"
    " (SELECT concat_ws(',', count(*), max(n.id)) FROM case_notices n WHERE n.case_id = c.id),"
    " (SELECT concat_ws(',', count(*), max(r.id), max(r.dismissed_at))"
    "  FROM case_reminders r WHERE r.case_id = c.id),"
    " (SELECT concat_ws(',', count(*), max(q.id), max(q.verdict_at))"
    "  FROM case_actions q WHERE q.case_id = c.id),"
    " (SELECT concat_ws(',', count(*), max(o.fetched_at))"
    "  FROM outside_lookups o JOIN case_indicators x ON x.kind = o.kind AND x.value = o.indicator"
    "  WHERE x.case_id = c.id AND x.removed_at IS NULL),"
    # who signed in from the case's devices. Null (so absent from the signal) while nothing
    # was looked up; else the lookups by state (a day made final counts once) and a hash of the
    # accounts per address and day, not of their counts: a new account or a lookup that completes
    # makes a new report, more sign-ins of the same account do not.
    f" (SELECT concat_ws(',', count(*) FILTER (WHERE l.complete),"
    f"   count(*) FILTER (WHERE NOT l.complete),"
    f"   count(*) FILTER (WHERE l.complete AND l.looked_at"
    f"    >= (l.day + 1)::timestamp AT TIME ZONE 'UTC' + interval '{FINAL_SECONDS} seconds'))"
    f"  FROM ({_ACTOR_ADDRESSES}) d JOIN signin_lookups l ON l.address = d.a HAVING count(*) > 0),"
    f" (SELECT md5(string_agg(k, ',' ORDER BY k)) FROM (SELECT DISTINCT"
    f"   host(s.address) || ':' || s.day || ':' || s.user_name AS k"
    f"   FROM ({_ACTOR_ADDRESSES}) d JOIN signin_sightings s ON s.address = d.a) q"
    f"  HAVING count(*) > 0)"
    ") AS signal,"
    " (SELECT max(i.last_event_at) FROM case_members m JOIN investigations i"
    "  ON i.id = m.investigation_id WHERE m.case_id = c.id AND m.removed_at IS NULL) AS last_alert"
    " FROM cases c WHERE c.id = ANY(:ids)"
)


def zoned(sql: str) -> TextClause:
    """A statement with the site's time zone (``site.timezone``) where ``ZONE_MARK`` stands: the
    days of the report are the site's days."""
    return text(sql.replace(ZONE_MARK, site.zone_sql()))
