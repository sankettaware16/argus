"""The Reporter's section builders (Q-H3, plan §7.7): each is one function of a connection and
a :class:`~argus.reporter.model.Window`, returns a :class:`~argus.reporter.model.Section` of
figures with their definitions, and reads ARGUS's own database only (no SIEM request, no model).

Two kinds of figure, and every definition says which:

* **what happened** is counted over the period ``[start, end)``: closures, requests, findings,
  results, gaps. They do not change after the period ends (except a gap that was still open).
* **what is waiting** is counted as at ``window.as_at``, the moment the report is made: cases by
  state and age, actions, approvals, the Kibana backlog. A report made hours after its period
  ends is still about the period, but these figures are of the moment it was made.

A percentage is computed from two counts of the same report; a percentile of a short list is not
shown (below 20 results the maximum stands in for a 95th percentile, plan §8).
"""

# ruff: noqa: S608 - every statement is built from this module's constant fragments; every
# value is a bound parameter.
from __future__ import annotations

import re
from collections.abc import Awaitable, Callable
from datetime import timedelta
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus import site
from argus.cases import chain, known, knownview
from argus.db.models import CLOSURE_REASONS, OUTCOMES
from argus.reporter.model import Metric, Section, Unit, Value, Window
from argus.responder.machine import ist_day

P95_MIN_N = 20  # below this many results the maximum stands in for a 95th percentile (plan §8)
HOSTS_SHOWN = 20
NOTIFIED_SHOWN = 30  # notified cases the weekly report lists one by one
CONFIRMED = "('open', 'assigned', 'contained')"
LANES = (
    "collector", "investigation", "freshness", "kibana_read", "kibana_write", "identity",
    "measurement", "unassigned",
)  # fmt: skip
LANE_WORDS = {
    "collector": "reading alerts", "investigation": "investigating", "freshness": "log freshness",
    "kibana_read": "reading Kibana", "kibana_write": "writing to Kibana",
    "identity": "sign-in checks", "measurement": "measuring", "unassigned": "not tagged",
}  # fmt: skip
DAY_CAP_MS = 3_600_000  # D-022: 60 minutes of the SIEM server time a day (argus.soak.DAY_CAP_MS)
# What a person did in Kibana to an ARGUS case, around ARGUS's approvals (brief §10, plan §7.1).
# Not listed: "person_edited" (INFO: an edit of a field ARGUS does not own) and
# "settings_changed" (the case writer's own check raises it too, when Sync alerts is on).
BYPASS_KINDS = (
    "closed_in_kibana", "reopened_in_kibana", "status_changed_in_kibana", "deleted_in_kibana",
    "person_deleted", "argus_tags_changed",
)  # fmt: skip
UNEXPLAINED_KINDS = ("unexplained_argus_action", "unexplained_argus_case",
                     "alert_change_unexplained")  # fmt: skip
OUTBOX_BACKLOG = "('planned', 'approved', 'sending')"
LEDGER_OUTCOMES = ("sent", "ambiguous", "conflict", "refused", "failed")
ACTION_STATES = ("recommended", "requested", "reported_done", "verified", "not_verified")
PROBE_STATES = ("normal", "caution", "degraded", "stop")
GAP_KINDS = ("rule_not_running", "rule_gap_reported", "source_stalled",
             "late_data_beyond_lookback", "truncated_execution", "argus_collector_lag",
             "breaker_open")  # fmt: skip
APPROVAL_KINDS = ("closure", "merge", "compensating", "resend", "reconfirm")

Builder = Callable[[AsyncConnection, Window], Awaitable[Section]]


def metric(key: str, label: str, value: Value, unit: Unit, definition: str) -> Metric:
    return Metric(key=key, label=label, value=value, unit=unit, definition=definition)


def percent(part: int, whole: int) -> float | None:
    """``part`` of ``whole`` in percent to one decimal, halves up; None when ``whole`` is 0."""
    if whole <= 0:
        return None
    return float(
        (Decimal(part) * 100 / Decimal(whole)).quantize(Decimal("0.1"), rounding=ROUND_HALF_UP)
    )


def plain(value: object, limit: int = 80) -> str:
    """``value`` on one line with unprintable characters escaped and at most ``limit`` characters
    (names in a report come from SIEM data)."""
    shown = "".join(
        c if c.isprintable() else c.encode("unicode_escape").decode("ascii") for c in str(value)
    )
    return shown if len(shown) <= limit else shown[: limit - 1] + "…"


def slug(value: str) -> str:
    """A name inside a figure's key: no whitespace, no control characters."""
    return re.sub(r"\s+", "_", plain(value, 60))


def unique(key: str, taken: set[str]) -> str:
    """``key``, or ``key~2``, ``key~3`` ... when two names became the same key."""
    found, n = key, 1
    while found in taken:
        n += 1
        found = f"{key}~{n}"
    taken.add(found)
    return found


def _params(w: Window) -> dict[str, Any]:
    return {"s": w.start, "e": w.end, "now": w.as_at, "sd": w.start.date(), "ed": w.end.date()}


async def _one(conn: AsyncConnection, sql: str, w: Window) -> Any:
    return (await conn.execute(text(sql), _params(w))).one()


async def _all(conn: AsyncConnection, sql: str, w: Window) -> list[Any]:
    return list((await conn.execute(text(sql), _params(w))).all())


_IN = "{col} >= :s AND {col} < :e"
_AGE = "CAST(:now AS timestamptz) - {col}"


# The p-th percentile (whole number p) of the numeric column ``v`` of the CTE ``r`` (v, i = rank
# from 0, n = rows): linear interpolation between the two nearest ranks, rounded down, in exact
# numeric arithmetic (percentile_cont works in floating point and can land a hair under a whole
# second).
_PCT = (
    "(SELECT floor(lo.v + (({p} * (lo.n - 1)) % 100) / 100.0 * (coalesce(hi.v, lo.v) - lo.v))"
    "::int FROM r lo LEFT JOIN r hi ON hi.i = lo.i + 1 WHERE lo.i = ({p} * (lo.n - 1)) / 100)"
)
_RANKED = "r AS (SELECT v, row_number() OVER (ORDER BY v) - 1 AS i, count(*) OVER () AS n FROM d)"


def _hours_since(col: str, where: str = "true") -> str:
    return (
        f"floor(extract(epoch FROM CAST(:now AS timestamptz) - min({col}) FILTER (WHERE {where}))"
        " / 3600)::int"
    )


# --------------------------------------------------------------------------- cases


async def cases(conn: AsyncConnection, w: Window) -> Section:
    row = await _one(
        conn,
        f"""SELECT
          count(*) FILTER (WHERE state = 'suspected') AS suspected,
          count(*) FILTER (WHERE state = 'open') AS open,
          count(*) FILTER (WHERE state = 'assigned') AS assigned,
          count(*) FILTER (WHERE state = 'contained') AS contained,
          count(*) FILTER (WHERE state <> 'closed'
            AND {_AGE.format(col="created_at")} < interval '1 day') AS under_1d,
          count(*) FILTER (WHERE state <> 'closed'
            AND {_AGE.format(col="created_at")} >= interval '1 day'
            AND {_AGE.format(col="created_at")} < interval '3 days') AS d1_3,
          count(*) FILTER (WHERE state <> 'closed'
            AND {_AGE.format(col="created_at")} >= interval '3 days'
            AND {_AGE.format(col="created_at")} < interval '7 days') AS d3_7,
          count(*) FILTER (WHERE state <> 'closed'
            AND {_AGE.format(col="created_at")} >= interval '7 days') AS d7_up,
          {_hours_since("created_at", "state <> 'closed'")} AS oldest_hours,
          count(*) FILTER (WHERE {_IN.format(col="created_at")}) AS created
        FROM cases""",
        w,
    )
    waiting = "as at the moment the report was made"
    metrics = [
        metric(
            "cases.suspected",
            "Cases suspected, waiting for a first look",
            row.suspected,
            "count",
            f"Rows of cases in state 'suspected', {waiting}.",
        ),
        metric(
            "cases.open",
            "Cases open, no owner yet",
            row.open,
            "count",
            f"Rows of cases in state 'open', {waiting}.",
        ),
        metric(
            "cases.assigned",
            "Cases assigned to a person",
            row.assigned,
            "count",
            f"Rows of cases in state 'assigned', {waiting}.",
        ),
        metric(
            "cases.contained",
            "Cases contained",
            row.contained,
            "count",
            f"Rows of cases in state 'contained', {waiting}.",
        ),
        metric(
            "cases.age.under_1_day",
            "Unclosed cases younger than 1 day",
            row.under_1d,
            "count",
            f"Cases not closed whose age (made_at minus created_at) is under 1 day, {waiting}.",
        ),
        metric(
            "cases.age.1_to_3_days",
            "Unclosed cases 1 to 3 days old",
            row.d1_3,
            "count",
            f"Cases not closed, age from 1 day up to (not including) 3 days, {waiting}.",
        ),
        metric(
            "cases.age.3_to_7_days",
            "Unclosed cases 3 to 7 days old",
            row.d3_7,
            "count",
            f"Cases not closed, age from 3 days up to (not including) 7 days, {waiting}.",
        ),
        metric(
            "cases.age.7_days_or_more",
            "Unclosed cases 7 days old or more",
            row.d7_up,
            "count",
            f"Cases not closed, age 7 days or more, {waiting}.",
        ),
        metric(
            "cases.oldest_unclosed_age",
            "Age of the oldest unclosed case",
            row.oldest_hours,
            "hours",
            "Whole hours (rounded down) from created_at of the oldest case not "
            "closed to the moment the report was made; none when no case is unclosed.",
        ),
        metric(
            "cases.created",
            "Cases created in the period",
            row.created,
            "count",
            "Cases whose created_at is in the period.",
        ),
    ]
    return Section(id="cases", title="Cases by state and age", metrics=tuple(metrics))


# --------------------------------------------------------------------------- notified, still active

_NOTIFIED_ALERTS = """SELECT m.case_id, count(*) AS n FROM cases c
  JOIN case_members m ON m.case_id = c.id AND m.removed_at IS NULL
  JOIN investigation_alerts l ON l.investigation_id = m.investigation_id
  JOIN alert_records a ON a.alert_id = l.alert_id
  WHERE c.state IN ('open', 'assigned') AND c.notified_at IS NOT NULL
    AND COALESCE(a.event_time, a.detected_at) >= c.notified_at
    AND COALESCE(a.event_time, a.detected_at) >= :s
    AND COALESCE(a.event_time, a.detected_at) < :e
  GROUP BY m.case_id"""


def _notified_case(c: knownview.KnownCase, alerts: int, w: Window) -> list[Metric]:
    """The weekly report's lines for one notified device: since when, how long, the alerts in the
    period and their trend, the notices sent and the blocks recorded."""
    # the days are IST days (as the rest of the reports): those the period touches, its first
    # and last one in part (the period is UTC days)
    zone = site.zone()
    first = w.start.astimezone(zone).date().isoformat()
    last = (w.end - timedelta(seconds=1)).astimezone(zone).date().isoformat()
    week = {d: n for d, n in c.per_day.items() if first <= d <= last}
    key = f"notified.case.{c.number}"
    label = f"Case {c.number}"
    waiting = "as at the moment the report was made"
    return [
        metric(
            f"{key}.since",
            f"{label}: owner first told on",
            ist_day(c.notified_at),
            "text",
            f"case_notices: the time of the case's first owner notice ({site.zone_label()}).",
        ),
        metric(
            f"{key}.days",
            f"{label}: days since the owner was told",
            c.days,
            "count",
            f"Whole days from the first notice to the making, at least 1, {waiting}.",
        ),
        metric(
            f"{key}.alerts",
            f"{label}: alerts in the period",
            alerts,
            "count",
            "Alerts of the case's member investigations in the period, after the notice.",
        ),
        metric(
            f"{key}.trend",
            f"{label}: alerts a day this week",
            known.trend(week),
            "text",
            f"The second half of the period's {site.zone_label()} days against the first (more"
            " than a quarter up is rising, a fifth down falling).",
        ),
        metric(
            f"{key}.notices",
            f"{label}: notices sent",
            c.owner_notices,
            "count",
            f"Rows of case_notices of kind 'owner' for the case, {waiting}.",
        ),
        metric(
            f"{key}.blocks",
            f"{label}: network blocks recorded",
            c.blocks,
            "count",
            f"Rows of case_notices of kind 'block' for the case, {waiting}.",
        ),
    ]


async def notified(conn: AsyncConnection, w: Window) -> Section:
    """Cases whose owner was told and that stay active (AR4b, D-169 point 8): counted apart from
    new work. The totals are for every report; the weekly report also lists each such device."""
    row = await _one(
        conn,
        f"""SELECT
          (SELECT count(*) FROM cases WHERE state IN ('open', 'assigned')
             AND notified_at IS NOT NULL) AS cases,
          (SELECT count(*) FROM case_known_matches k JOIN cases c ON c.id = k.case_id
             WHERE k.outcome = 'known' AND c.notified_at IS NOT NULL
               AND c.state IN ('open', 'assigned')) AS known,
          (SELECT count(*) FROM case_known_matches k
             WHERE k.outcome = 'changed' AND NOT EXISTS (SELECT 1 FROM review_state s
               WHERE s.investigation_id = k.investigation_id
               AND s.action = 'reviewed' AND s.version >= k.changed_version)) AS changes,
          (SELECT count(*) FROM case_reminders r JOIN cases c ON c.id = r.case_id
             WHERE r.dismissed_at IS NULL AND c.state IN ('open', 'assigned')
               AND c.notified_at IS NOT NULL
               AND ((r.kind = 'notify_again' AND (SELECT count(*) FROM case_notices n
                      WHERE n.case_id = c.id AND n.kind = 'owner'
                      AND {knownview.AFTER_WITHDRAWAL}) < 2)
                    OR (r.kind = 'network_action' AND c.blocked_at IS NULL))) AS reminders,
          (SELECT count(*) FROM case_notices WHERE kind = 'owner'
             AND {_IN.format(col="at")}) AS notices,
          (SELECT count(*) FROM case_notices WHERE kind = 'block'
             AND {_IN.format(col="at")}) AS blocks,
          (SELECT count(*) FROM cases WHERE closure_reason = 'stopped_after_notice'
             AND {_IN.format(col="closed_at")}) AS stopped""",
        w,
    )
    per_case = {r.case_id: int(r.n) for r in await _all(conn, _NOTIFIED_ALERTS, w)}
    waiting = "as at the moment the report was made"
    metrics = [
        metric(
            "notified.cases",
            "Cases notified and still active",
            row.cases,
            "count",
            f"Cases in state 'open' or 'assigned' with a notice recorded (the owner was told), "
            f"{waiting}.",
        ),
        metric(
            "notified.alerts",
            "Alerts of notified cases in the period (counted, not raised)",
            sum(per_case.values()),
            "count",
            "Alerts of the member investigations of the cases above whose time is in the period "
            "and after the case's notice.",
        ),
        metric(
            "notified.known",
            "Investigations held as known infections",
            row.known,
            "count",
            f"Rows of case_known_matches decided 'known' for a case still notified, {waiting}.",
        ),
        metric(
            "notified.changes_waiting",
            "Changes since a notice waiting for a person",
            row.changes,
            "count",
            "Rows of case_known_matches decided 'changed' (a change stays until a person "
            f"reviews a version at or after it) that no person has reviewed, {waiting}.",
        ),
        metric(
            "notified.reminders_waiting",
            "Reminders waiting for a person",
            row.reminders,
            "count",
            "ARGUS's suggestions (notify again after 7 days, network-side action after 21) not "
            f"dismissed and not answered by a second notice or a block, {waiting}.",
        ),
        metric(
            "notified.notices",
            "Notices to owners recorded in the period",
            row.notices,
            "count",
            "Rows of case_notices of kind 'owner' whose time (at) is in the period.",
        ),
        metric(
            "notified.blocks",
            "Network blocks recorded in the period",
            row.blocks,
            "count",
            "Rows of case_notices of kind 'block' whose time (at) is in the period.",
        ),
        metric(
            "notified.stopped",
            "Cases closed as stopped after notice in the period",
            row.stopped,
            "count",
            "Cases whose closure_reason is 'stopped_after_notice' and whose closed_at is in the "
            "period.",
        ),
    ]
    notes: list[str] = []
    if w.kind == "weekly":
        listed = await knownview.notified(conn, w.as_at)
        listed.sort(key=lambda c: (-per_case.get(c.case_id, 0), c.number))
        for c in listed[:NOTIFIED_SHOWN]:
            metrics += _notified_case(c, per_case.get(c.case_id, 0), w)
        if len(listed) > NOTIFIED_SHOWN:
            notes.append(f"{len(listed) - NOTIFIED_SHOWN} more notified cases are not listed.")
    return Section(id="notified", title="Notified, still active", metrics=tuple(metrics),
                   notes=tuple(notes))  # fmt: skip


# --------------------------------------------------------------------------- active hosts

_ACTIVE = f"""WITH active AS (
  SELECT DISTINCT w.case_id, w.day FROM case_watch_checks w
  JOIN cases c ON c.id = w.case_id
  WHERE w.outcome = 'active' AND w.day >= CAST(:sd AS date) AND w.day < CAST(:ed AS date)
    AND c.state IN {CONFIRMED})"""
# The campus hosts the watch saw reach the destination, per case and day (detail.hosts of an
# 'active' answer: the proxy's source addresses). A case's indicators are not read: they hold
# outside addresses too, and hosts that never made contact.
_SEEN = f"""WITH seen AS (
  SELECT DISTINCT w.day, h.host FROM case_watch_checks w
  JOIN cases c ON c.id = w.case_id
  CROSS JOIN LATERAL jsonb_array_elements(
    CASE WHEN jsonb_typeof(w.detail -> 'hosts') = 'array' THEN w.detail -> 'hosts'
         ELSE '[]'::jsonb END) AS e(v)
  CROSS JOIN LATERAL (SELECT e.v #>> '{{}}' AS host) h
  WHERE w.outcome = 'active' AND w.day >= CAST(:sd AS date) AND w.day < CAST(:ed AS date)
    AND c.state IN {CONFIRMED} AND jsonb_typeof(e.v) = 'string'
    AND h.host <> '' AND length(h.host) <= 200)"""


async def active_hosts(conn: AsyncConnection, w: Window) -> Section:
    cases_n = (await _one(conn, f"{_ACTIVE} SELECT count(DISTINCT case_id) AS n FROM active", w)).n
    hosts_n = (await _one(conn, f"{_SEEN} SELECT count(DISTINCT host) AS n FROM seen", w)).n
    rows = await _all(
        conn,
        f"""{_SEEN} SELECT host, count(DISTINCT day) AS days FROM seen
        GROUP BY host ORDER BY days DESC, host LIMIT {HOSTS_SHOWN}""",
        w,
    )
    basis = (
        "a confirmed case (open, assigned or contained as at the making) with an 'active' answer"
        " of the still-active watch (case_watch_checks) on a UTC day of the period"
    )
    seen = f"the {site.own('hosts')} the watch saw reach the case's destination (detail.hosts)"
    metrics = [
        metric(
            "active_hosts.cases",
            "Confirmed cases found still active",
            cases_n,
            "count",
            f"Distinct cases: {basis}.",
        ),
        metric(
            "active_hosts.hosts",
            site.say("{Own:hosts} seen still active"),
            hosts_n,
            "count",
            f"Distinct hosts named in the 'active' answers of those cases: {seen}. Outside "
            f"addresses and the hosts a case merely lists are not counted.",
        ),
    ]
    taken: set[str] = set()
    for r in rows:
        metrics.append(
            metric(unique(f"active_hosts.host.{slug(r.host)}", taken), plain(r.host), r.days,
                   "count",
                   f"Days of the period on which the watch saw this {site.own('host')} reach the "
                   f"destination of a case ({basis}; the {HOSTS_SHOWN} with most days are "
                   f"listed)."))  # fmt: skip
    notes = (
        "A case that the watch answered 'unverified' or 'not checked' is not in this count.",
        "Only cases that are open, assigned or contained when the report is made are counted: a"
        " case closed since its active day is not, so a report made late shows fewer.",
    )
    return Section(id="active_hosts", title="Still-active hosts", metrics=tuple(metrics),
                   notes=notes)  # fmt: skip


# --------------------------------------------------------------------------- actions


async def actions(conn: AsyncConnection, w: Window) -> Section:
    rows = await _all(
        conn,
        f"""SELECT a.state, count(*) AS n FROM case_actions a JOIN cases c ON c.id = a.case_id
        WHERE c.state IN {CONFIRMED} GROUP BY a.state""",
        w,
    )
    by_state = {r.state: r.n for r in rows}
    waiting = await _one(
        conn,
        f"""SELECT count(*) AS n,
          floor(extract(epoch FROM CAST(:now AS timestamptz)
            - min(coalesce(a.recommended_at, a.requested_at))) / 3600)::int AS oldest
        FROM case_actions a JOIN cases c ON c.id = a.case_id
        WHERE c.state IN {CONFIRMED} AND a.state IN ('recommended', 'requested')""",
        w,
    )
    owners = await _all(
        conn,
        f"""SELECT a.owner, count(*) AS n FROM case_actions a JOIN cases c ON c.id = a.case_id
        WHERE c.state IN {CONFIRMED} AND a.state IN ('recommended', 'requested')
        GROUP BY a.owner ORDER BY a.owner""",
        w,
    )
    recorded = (
        await _one(
            conn,
            f"SELECT count(*) AS n FROM case_actions WHERE {_IN.format(col='recommended_at')}",
            w,
        )
    ).n
    base = "actions of cases that are open, assigned or contained (case_actions), as at the making"
    words = {
        "recommended": "Advised, nobody asked yet",
        "requested": "Asked of its owner",
        "reported_done": "Reported done, not yet judged",
        "verified": "Verified by ARGUS",
        "not_verified": "Not verified (activity continues)",
    }
    metrics = [
        metric(f"actions.state.{s}", words[s], by_state.get(s, 0), "count",
               f"Rows in state '{s}': {base}.")
        for s in ACTION_STATES
    ]  # fmt: skip
    metrics += [
        metric(
            "actions.waiting",
            "Actions waiting for somebody to act",
            waiting.n,
            "count",
            f"Rows in state 'recommended' or 'requested': {base}.",
        ),
        metric(
            "actions.oldest_waiting_age",
            "Age of the longest-waiting action",
            waiting.oldest,
            "hours",
            "Whole hours (rounded down) from the earlier of recommended_at and "
            "requested_at of the oldest waiting action to the making; none when none waits.",
        ),
    ]
    for r in owners:
        metrics.append(
            metric(
                f"actions.waiting.owner.{r.owner}",
                f"Waiting with {r.owner}",
                r.n,
                "count",
                f"Waiting actions (recommended or requested) of this owner: {base}.",
            )
        )
    metrics.append(
        metric(
            "actions.recommended_in_period",
            "Actions advised in the period",
            recorded,
            "count",
            "Rows of case_actions whose recommended_at is in the period.",
        )
    )
    return Section(id="actions", title="Actions waiting", metrics=tuple(metrics))


# --------------------------------------------------------------------------- closures


async def closures(conn: AsyncConnection, w: Window) -> Section:
    rows = await _all(
        conn,
        f"""SELECT closure_reason, count(*) AS n FROM cases
        WHERE state = 'closed' AND {_IN.format(col="closed_at")} GROUP BY closure_reason""",
        w,
    )
    by_reason = {r.closure_reason: r.n for r in rows}
    reopened = (
        await _one(
            conn,
            "SELECT count(*) AS n FROM case_events WHERE kind = 'reopened' AND "
            + _IN.format(col="occurred_at"),
            w,
        )
    ).n
    metrics = [
        metric(
            "closures.total",
            "Cases closed in the period",
            sum(by_reason.values()),
            "count",
            "Cases in state 'closed' whose closed_at is in the period (a case closed and "
            "reopened since is not counted).",
        )
    ]
    metrics += [
        metric(f"closures.reason.{reason}", reason.replace("_", " ").capitalize(),
               by_reason.get(reason, 0), "count",
               f"Cases closed in the period with closure_reason '{reason}'.")
        for reason in CLOSURE_REASONS
    ]  # fmt: skip
    metrics.append(
        metric(
            "closures.reopened",
            "Cases reopened in the period",
            reopened,
            "count",
            "Case events of kind 'reopened' whose occurred_at is in the period.",
        )
    )
    return Section(id="closures", title="Closures by reason", metrics=tuple(metrics))


# --------------------------------------------------------------------------- approvals

_REQUESTS = """WITH r AS (
  SELECT q.*,
    (SELECT count(*) FROM approval_decisions d
       WHERE d.request_id = q.id AND d.decision = 'approved') AS yes,
    EXISTS (SELECT 1 FROM approval_decisions d
       WHERE d.request_id = q.id AND d.decision = 'rejected') AS no
  FROM approval_requests q)"""
_APPROVED = "(NOT no AND yes >= required_approvals)"
# Whether something went out for a request, from the table that records that kind's send:
# closure and merge: the outbox row that names them; compensating: its Kibana steps; resend: the
# outbox row went out again after the send the request was asked at; reconfirm: the held-back
# outbox row went out.
_SENT = """(CASE r.kind
  WHEN 'compensating' THEN EXISTS (SELECT 1 FROM kibana_steps s
    WHERE s.approval_request_id = r.id AND s.sent_count > 0)
  WHEN 'resend' THEN EXISTS (SELECT 1 FROM kibana_outbox o
    WHERE o.id = r.outbox_id AND o.sent_count > r.outbox_sent_count)
  WHEN 'reconfirm' THEN EXISTS (SELECT 1 FROM kibana_outbox o
    WHERE o.id = r.outbox_id AND o.sent_count > 0)
  ELSE EXISTS (SELECT 1 FROM kibana_outbox o
    WHERE o.approval_request_id = r.id AND o.sent_count > 0)
END)"""


async def approvals(conn: AsyncConnection, w: Window) -> Section:
    row = await _one(
        conn,
        f"""{_REQUESTS} SELECT
          count(*) FILTER (WHERE {_IN.format(col="requested_at")}) AS requested,
          count(*) FILTER (WHERE {_IN.format(col="requested_at")} AND {_APPROVED}) AS approved,
          count(*) FILTER (WHERE {_IN.format(col="requested_at")} AND no) AS rejected,
          count(*) FILTER (WHERE NOT no AND yes < required_approvals
                           AND expires_at > CAST(:now AS timestamptz)) AS waiting,
          count(*) FILTER (WHERE {_IN.format(col="expires_at")}
            AND expires_at <= CAST(:now AS timestamptz) AND NOT no
            AND NOT {_SENT}
            AND NOT EXISTS (SELECT 1 FROM cases c WHERE c.closure_request_id = r.id)
          ) AS expired_unsent
        FROM r""",
        w,
    )
    kinds = await _all(
        conn,
        f"""SELECT kind, count(*) AS n FROM approval_requests
        WHERE {_IN.format(col="requested_at")} GROUP BY kind""",
        w,
    )
    by_kind = {r.kind: r.n for r in kinds}
    status = (
        "approved = no rejection and at least required_approvals approvals (signatures and "
        "revocations are the writer's own check); rejected = any rejection"
    )
    decided = row.approved + row.rejected
    metrics = [
        metric(
            "approvals.requested",
            "Approval requests made in the period",
            row.requested,
            "count",
            "Rows of approval_requests whose requested_at is in the period.",
        ),
        metric(
            "approvals.approved",
            "Of those, approved",
            row.approved,
            "count",
            f"Requests made in the period that are approved now ({status}).",
        ),
        metric(
            "approvals.rejected",
            "Of those, rejected",
            row.rejected,
            "count",
            f"Requests made in the period that are rejected now ({status}).",
        ),
        metric(
            "approvals.approval_rate",
            "Share approved of those decided",
            percent(row.approved, decided),
            "percent",
            "approved / (approved + rejected) of the requests made in the period, in percent "
            "to one decimal; none when none was decided.",
        ),
        metric(
            "approvals.waiting",
            "Requests waiting for a decision",
            row.waiting,
            "count",
            "Requests of any date, not rejected, with fewer approvals than required, not yet "
            "expired, as at the making.",
        ),
        metric(
            "approvals.expired_unsent",
            "Requests that expired with nothing sent",
            row.expired_unsent,
            "count",
            "Requests whose expires_at is in the period and before the making, not rejected, "
            "with no case closed by them and nothing sent for them: closure and merge, an "
            "outbox row naming them with sent_count above 0; compensating, a Kibana step "
            "naming them with sent_count above 0; resend, its outbox row's sent_count above "
            "the count it was asked at; reconfirm, its outbox row's sent_count above 0.",
        ),
    ]
    metrics += [
        metric(f"approvals.requested.{k}", f"Requests of kind {k}", by_kind.get(k, 0), "count",
               f"Requests of kind '{k}' made in the period.")
        for k in APPROVAL_KINDS
    ]  # fmt: skip
    return Section(id="approvals", title="Approvals", metrics=tuple(metrics))


# --------------------------------------------------------------------------- the SIEM load


async def siem_load(conn: AsyncConnection, w: Window) -> Section:
    rows = await _all(
        conn,
        f"""SELECT coalesce(lane, 'unassigned') AS lane, count(*) AS n,
          coalesce(sum(took_ms), 0)::bigint AS ms,
          count(*) FILTER (WHERE outcome IN ('overloaded', 'breaker_open')) AS overloads
        FROM siem_requests WHERE {_IN.format(col="at")} GROUP BY 1""",
        w,
    )
    lanes = {r.lane: r for r in rows}
    busiest = (
        await _one(
            conn,
            f"""SELECT coalesce(max(day_ms), 0)::bigint AS ms FROM (
              SELECT sum(took_ms) AS day_ms FROM siem_requests
              WHERE {_IN.format(col="at")} GROUP BY (at AT TIME ZONE 'UTC')::date) t""",
            w,
        )
    ).ms
    requests = sum(r.n for r in rows)
    ms = sum(r.ms for r in rows)
    over = sum(r.overloads for r in rows)
    metrics = [
        metric(
            "siem.requests",
            "Requests ARGUS sent to the SIEM, all lanes",
            requests,
            "count",
            "Rows of siem_requests (the request ledger) whose time is in the period.",
        ),
        metric(
            "siem.server_time",
            "Server time those requests took",
            ms,
            "ms",
            "Sum of took_ms over those rows (the SIEM's own time, not the network's).",
        ),
        metric(
            "siem.budget_used",
            "Share of the daily server-time budget used",
            percent(ms, DAY_CAP_MS * w.days),
            "percent",
            f"Server time / ({w.days} day(s) x 60 minutes), in percent to one decimal "
            "(D-022: 60 minutes of the SIEM server time a day).",
        ),
        metric(
            "siem.busiest_day",
            "Server time on the busiest UTC day",
            busiest,
            "ms",
            "The largest sum of took_ms over one UTC day of the period.",
        ),
        metric(
            "siem.overloads",
            "Requests answered 'overloaded' or stopped by the breaker",
            over,
            "count",
            "Rows with outcome overloaded or breaker_open.",
        ),
    ]
    for lane in LANES:
        r = lanes.get(lane)
        words = LANE_WORDS[lane]
        where = "the rows with no lane" if lane == "unassigned" else f"the rows of lane '{lane}'"
        metrics.append(
            metric(
                f"siem.lane.{lane}.requests",
                f"Requests, {words}",
                r.n if r else 0,
                "count",
                f"Count of {where} in the period.",
            )
        )
        metrics.append(
            metric(
                f"siem.lane.{lane}.server_time",
                f"Server time, {words}",
                r.ms if r else 0,
                "ms",
                f"Sum of took_ms of {where} in the period.",
            )
        )
    return Section(id="siem_load", title="the SIEM load, by lane and in total",
                   metrics=tuple(metrics))  # fmt: skip


# --------------------------------------------------------------------------- Kibana sync


async def kibana_sync(conn: AsyncConnection, w: Window) -> Section:
    cyc = await _one(
        conn,
        f"""SELECT count(*) AS total,
          count(*) FILTER (WHERE outcome = 'complete') AS complete,
          count(*) FILTER (WHERE outcome = 'partial') AS partial,
          count(*) FILTER (WHERE outcome = 'failed') AS failed,
          count(*) FILTER (WHERE stale) AS stale
        FROM kibana_sync_cycles WHERE {_IN.format(col="started_at")}""",
        w,
    )
    lag = await _one(
        conn,
        f"""WITH d AS (SELECT lag_s::numeric AS v FROM kibana_findings
          WHERE {_IN.format(col="found_at")} AND lag_s IS NOT NULL), {_RANKED}
        SELECT (SELECT count(*) FROM d) AS n, {_PCT.format(p=50)} AS median,
          {_PCT.format(p=95)} AS p95, (SELECT max(v)::int FROM d) AS worst""",
        w,
    )
    box = await _one(
        conn,
        f"""SELECT
          count(*) FILTER (WHERE state = 'paused') AS paused,
          count(*) FILTER (WHERE state = 'conflict') AS conflict,
          count(*) FILTER (WHERE state = 'ambiguous') AS ambiguous,
          count(*) FILTER (WHERE state IN {OUTBOX_BACKLOG}) AS backlog,
          {_hours_since("created_at", f"state IN {OUTBOX_BACKLOG}")} AS oldest,
          count(*) FILTER (WHERE {_IN.format(col="sent_at")}) AS sent
        FROM kibana_outbox""",
        w,
    )
    resend = await _one(
        conn,
        f"""{_REQUESTS} SELECT
          count(*) FILTER (WHERE kind = 'resend' AND {_IN.format(col="requested_at")}) AS asked,
          count(*) FILTER (WHERE kind = 'resend' AND {_IN.format(col="requested_at")}
                           AND {_APPROVED}) AS approved
        FROM r""",
        w,
    )
    p95 = lag.p95 if lag.n >= P95_MIN_N else None
    metrics = [
        metric(
            "kibana.cycles",
            "Read-back cycles in the period",
            cyc.total,
            "count",
            "Rows of kibana_sync_cycles whose started_at is in the period.",
        ),
        metric(
            "kibana.cycles.complete",
            "Cycles that read everything",
            cyc.complete,
            "count",
            "Cycles with outcome 'complete'.",
        ),
        metric(
            "kibana.cycles.partial",
            "Cycles that read part",
            cyc.partial,
            "count",
            "Cycles with outcome 'partial'.",
        ),
        metric(
            "kibana.cycles.failed",
            "Cycles that failed",
            cyc.failed,
            "count",
            "Cycles with outcome 'failed'.",
        ),
        metric(
            "kibana.cycles.stale",
            "Cycles that read stale data",
            cyc.stale,
            "count",
            "Cycles with stale = true.",
        ),
        metric(
            "kibana.success_rate",
            "Share of cycles that read everything",
            percent(cyc.complete, cyc.total),
            "percent",
            "complete / all cycles of the period, in percent to one decimal; none without cycles.",
        ),
        metric(
            "kibana.lag.n",
            "Changes with a measured lag",
            lag.n,
            "count",
            "Findings found in the period that carry lag_s (seconds from the change in "
            "Kibana to ARGUS seeing it).",
        ),
        metric(
            "kibana.lag.median",
            "Median lag",
            lag.median,
            "seconds",
            "Median (linear interpolation, rounded down to a whole second) of lag_s; none "
            "without findings.",
        ),
        metric(
            "kibana.lag.p95",
            "95th percentile lag",
            p95,
            "seconds",
            f"95th percentile of lag_s, shown from {P95_MIN_N} findings; below that the "
            "maximum is the figure to read.",
        ),
        metric("kibana.lag.max", "Longest lag", lag.worst, "seconds", "Largest lag_s."),
        metric(
            "kibana.paused",
            "Kibana rows paused",
            box.paused,
            "count",
            "Rows of kibana_outbox in state 'paused', as at the making.",
        ),
        metric(
            "kibana.conflicts",
            "Kibana rows in conflict",
            box.conflict,
            "count",
            "Rows of kibana_outbox in state 'conflict', as at the making.",
        ),
        metric(
            "kibana.ambiguous",
            "Kibana rows with an unknown outcome",
            box.ambiguous,
            "count",
            "Rows of kibana_outbox in state 'ambiguous', as at the making.",
        ),
        metric(
            "kibana.backlog",
            "Kibana rows waiting to be sent",
            box.backlog,
            "count",
            "Rows of kibana_outbox in state planned, approved or sending, as at the making.",
        ),
        metric(
            "kibana.backlog.oldest",
            "Age of the oldest waiting row",
            box.oldest,
            "hours",
            "Whole hours (rounded down) from created_at of the oldest waiting row to the "
            "making; none when nothing waits.",
        ),
        metric(
            "kibana.sent",
            "Kibana rows sent in the period",
            box.sent,
            "count",
            "Rows of kibana_outbox whose sent_at is in the period.",
        ),
        metric(
            "kibana.resends.asked",
            "Resends asked for in the period",
            resend.asked,
            "count",
            "Approval requests of kind 'resend' made in the period.",
        ),
        metric(
            "kibana.resends.approved",
            "Resends approved",
            resend.approved,
            "count",
            "Those requests that are approved now (no rejection, enough approvals).",
        ),
    ]
    return Section(id="kibana_sync", title="Kibana sync", metrics=tuple(metrics))


# --------------------------------------------------------------------------- guardrails


async def guardrails(conn: AsyncConnection, w: Window) -> Section:
    audit = await _one(
        conn,
        f"""SELECT
          count(*) FILTER (WHERE action = 'access' AND outcome = 'denied') AS refused,
          count(*) FILTER (WHERE action IN ('login', 'stepup') AND outcome = 'denied') AS signin,
          count(*) AS events
        FROM audit_events WHERE {_IN.format(col="occurred_at")}""",
        w,
    )
    found = {
        r.kind: r.n
        for r in await _all(
            conn,
            f"""SELECT kind, count(*) AS n FROM kibana_findings
            WHERE {_IN.format(col="found_at")} GROUP BY kind""",
            w,
        )
    }
    open_ = {
        r.severity: r.n
        for r in await _all(
            conn,
            "SELECT severity, count(*) AS n FROM kibana_findings WHERE resolved_at IS NULL"
            " GROUP BY severity",
            w,
        )
    }
    refused_writes = (
        await _one(
            conn,
            f"SELECT count(*) AS n FROM action_ledger WHERE outcome = 'refused' AND "
            f"{_IN.format(col='at')}",
            w,
        )
    ).n
    bypass = sum(found.get(k, 0) for k in BYPASS_KINDS)
    unexplained = sum(found.get(k, 0) for k in UNEXPLAINED_KINDS)
    metrics = [
        metric(
            "guardrails.rejected_actions",
            "Actions refused to a signed-in person",
            audit.refused,
            "count",
            "Audit events with action 'access' and outcome 'denied' in the period (a person "
            "tried something their account may not do).",
        ),
        metric(
            "guardrails.sign_in_refusals",
            "Sign-in and step-up refusals",
            audit.signin,
            "count",
            "Audit events with action 'login' or 'stepup' and outcome 'denied'.",
        ),
        metric(
            "guardrails.refused_writes",
            "Writes ARGUS refused to send",
            refused_writes,
            "count",
            "Rows of action_ledger with outcome 'refused' in the period.",
        ),
        metric(
            "guardrails.bypass_attempts",
            "Changes made in Kibana around ARGUS's approvals",
            bypass,
            "count",
            "Reconciliation findings (kibana_findings) found in the period of a person "
            "closing, reopening, re-statusing, deleting or re-tagging an ARGUS case in Kibana: "
            "the kinds listed below, added up (an edit of a field ARGUS does not own and the "
            "case writer's own settings check are not counted).",
        ),
    ]
    metrics += [
        metric(f"guardrails.bypass.{k}", k.replace("_", " ").capitalize(), found.get(k, 0),
               "count", f"Findings of kind '{k}' found in the period.")
        for k in BYPASS_KINDS
    ]  # fmt: skip
    metrics += [
        metric(
            "guardrails.unexplained",
            "Changes ARGUS cannot explain",
            unexplained,
            "count",
            "Findings found in the period of kind " + ", ".join(UNEXPLAINED_KINDS) + ".",
        ),
        metric(
            "guardrails.findings_open.alarm",
            "Findings still open, alarms",
            open_.get("alarm", 0),
            "count",
            "Findings with severity 'alarm' not yet resolved, as at the making.",
        ),
        metric(
            "guardrails.findings_open.attention",
            "Findings still open, needing a person",
            open_.get("attention", 0),
            "count",
            "Findings with severity 'attention' not yet resolved, as at the making.",
        ),
    ]
    return Section(id="guardrails", title="Bypass attempts and refused actions",
                   metrics=tuple(metrics))  # fmt: skip


# --------------------------------------------------------------------------- results


async def results(conn: AsyncConnection, w: Window) -> Section:
    row = await _one(
        conn,
        f"""WITH d AS (
          SELECT greatest(extract(epoch FROM a.finished_at - i.created_at), 0) AS v
          FROM assessments a JOIN investigations i ON i.id = a.investigation_id
          WHERE a.status = 'proposed' AND {_IN.format(col="a.finished_at")}), {_RANKED}
        SELECT (SELECT count(*) FROM d) AS n, {_PCT.format(p=50)} AS median,
          {_PCT.format(p=95)} AS p95, (SELECT floor(max(v))::int FROM d) AS worst""",
        w,
    )
    ended = {
        r.status: r.n
        for r in await _all(
            conn,
            f"""SELECT status, count(*) AS n FROM assessments
            WHERE {_IN.format(col="finished_at")} GROUP BY status""",
            w,
        )
    }
    queue = await _one(
        conn,
        f"""SELECT count(*) AS n, {_hours_since("created_at")} AS oldest FROM assessments
        WHERE status IN ('queued', 'running')""",
        w,
    )
    p95 = row.p95 if row.n >= P95_MIN_N else None
    metrics = [
        metric(
            "results.n",
            "Investigations with a proposed result",
            row.n,
            "count",
            "Assessments with status 'proposed' whose finished_at is in the period.",
        ),
        metric(
            "results.median",
            "Median time to a result",
            row.median,
            "seconds",
            "Median (linear interpolation, rounded down to a whole second) of finished_at "
            "minus the investigation's created_at; none without results.",
        ),
        metric(
            "results.p95",
            "95th percentile time to a result",
            p95,
            "seconds",
            f"95th percentile of the same, shown from {P95_MIN_N} results; below that the "
            "longest is the figure to read.",
        ),
        metric(
            "results.max",
            "Longest time to a result",
            row.worst,
            "seconds",
            "The largest of the same, rounded down to a whole second.",
        ),
        metric(
            "results.no_decision",
            "Assessments that reached no decision",
            ended.get("no_decision", 0),
            "count",
            "Assessments with status 'no_decision' whose finished_at is in the period.",
        ),
        metric(
            "results.failed",
            "Assessments that failed",
            ended.get("failed", 0),
            "count",
            "Assessments with status 'failed' whose finished_at is in the period.",
        ),
        metric(
            "results.waiting",
            "Assessments waiting or running",
            queue.n,
            "count",
            "Assessments with status 'queued' or 'running', as at the making.",
        ),
        metric(
            "results.waiting.oldest",
            "Age of the longest-waiting assessment",
            queue.oldest,
            "hours",
            "Whole hours (rounded down) from created_at of the oldest to the "
            "making; none when none waits.",
        ),
    ]
    return Section(id="results", title="Time to a result", metrics=tuple(metrics))


# --------------------------------------------------------------------------- write-back


async def writeback(conn: AsyncConnection, w: Window) -> Section:
    wb = await _one(
        conn,
        f"""SELECT
          count(*) FILTER (WHERE {_IN.format(col="created_at")}) AS planned,
          count(*) FILTER (WHERE {_IN.format(col="sent_at")}) AS sent,
          count(*) FILTER (WHERE state = 'planned') AS waiting,
          count(*) FILTER (WHERE state = 'paused') AS paused,
          count(*) FILTER (WHERE {_IN.format(col="created_at")} AND error IS NOT NULL) AS errors
        FROM writeback_outbox""",
        w,
    )
    ledger = {
        r.outcome: r.n
        for r in await _all(
            conn,
            f"""SELECT outcome, count(*) AS n FROM action_ledger
            WHERE {_IN.format(col="at")} GROUP BY outcome""",
            w,
        )
    }
    sent_by_class = {
        r.write_class: r.n
        for r in await _all(
            conn,
            f"""SELECT write_class, count(*) AS n FROM action_ledger
            WHERE outcome = 'sent' AND {_IN.format(col="at")} GROUP BY write_class""",
            w,
        )
    }
    runs = await _one(
        conn,
        f"""SELECT count(*) AS n, coalesce(sum(sent), 0)::int AS sent,
          coalesce(sum(verified), 0)::int AS verified,
          coalesce(sum(mismatches), 0)::int AS mismatches,
          coalesce(sum(ambiguous), 0)::int AS ambiguous
        FROM kibana_writer_runs WHERE {_IN.format(col="started_at")}""",
        w,
    )
    metrics = [
        metric(
            "writeback.planned",
            "Alert status changes planned in the period",
            wb.planned,
            "count",
            "Rows of writeback_outbox (alert status written back after a review) "
            "created in the period.",
        ),
        metric(
            "writeback.sent",
            "Alert status changes sent in the period",
            wb.sent,
            "count",
            "Rows of writeback_outbox whose sent_at is in the period.",
        ),
        metric(
            "writeback.waiting",
            "Alert status changes waiting",
            wb.waiting,
            "count",
            "Rows of writeback_outbox in state 'planned', as at the making.",
        ),
        metric(
            "writeback.paused",
            "Alert status changes paused",
            wb.paused,
            "count",
            "Rows of writeback_outbox in state 'paused', as at the making.",
        ),
        metric(
            "writeback.errors",
            "Alert status changes planned that carry an error",
            wb.errors,
            "count",
            "Rows of writeback_outbox created in the period with an error recorded.",
        ),
    ]
    metrics += [
        metric(f"writes.ledger.{o}", f"Kibana write requests, {o}", ledger.get(o, 0), "count",
               f"Rows of action_ledger with outcome '{o}' in the period.")
        for o in LEDGER_OUTCOMES
    ]  # fmt: skip
    metrics += [
        metric(f"writes.sent.{c}", f"Kibana writes of class {c} sent", sent_by_class.get(c, 0),
               "count", f"Rows of action_ledger with outcome 'sent' and write_class '{c}'.")
        for c in ("W1", "W2", "W3")
    ]  # fmt: skip
    metrics += [
        metric(
            "writes.runs",
            "Case-writer runs",
            runs.n,
            "count",
            "Rows of kibana_writer_runs whose started_at is in the period.",
        ),
        metric(
            "writes.runs.sent",
            "Writes those runs sent",
            runs.sent,
            "count",
            "Sum of sent over those runs.",
        ),
        metric(
            "writes.runs.verified",
            "Writes read back and confirmed",
            runs.verified,
            "count",
            "Sum of verified over those runs.",
        ),
        metric(
            "writes.runs.mismatches",
            "Read-backs that differed",
            runs.mismatches,
            "count",
            "Sum of mismatches over those runs.",
        ),
        metric(
            "writes.runs.ambiguous",
            "Writes with an unknown outcome",
            runs.ambiguous,
            "count",
            "Sum of ambiguous over those runs.",
        ),
        metric(
            "writes.read_back_rate",
            "Share of sent writes confirmed by read-back",
            percent(runs.verified, runs.sent),
            "percent",
            "verified / sent over those runs, in percent to one decimal; none when nothing "
            "was sent.",
        ),
    ]
    return Section(id="writeback", title="Write-back to Kibana", metrics=tuple(metrics))


# --------------------------------------------------------------------------- gaps and outages


async def gaps(conn: AsyncConnection, w: Window) -> Section:
    overlap = "start_at < :e AND coalesce(end_at, CAST(:now AS timestamptz)) > :s"
    row = await _one(
        conn,
        f"""SELECT
          count(*) FILTER (WHERE {overlap}) AS overlapping,
          count(*) FILTER (WHERE {_IN.format(col="start_at")}) AS opened,
          count(*) FILTER (WHERE {_IN.format(col="end_at")}) AS closed,
          count(*) FILTER (WHERE end_at IS NULL) AS open_now,
          coalesce(floor(sum(extract(epoch FROM
            least(coalesce(end_at, CAST(:now AS timestamptz)), :e) - greatest(start_at, :s))
            ) FILTER (WHERE {overlap}) / 60), 0)::int AS minutes
        FROM coverage_gaps""",
        w,
    )
    kinds = {
        r.kind: r.n
        for r in await _all(
            conn,
            f"SELECT kind, count(*) AS n FROM coverage_gaps WHERE {overlap} GROUP BY kind",
            w,
        )
    }
    probes = {
        r.state: r.n
        for r in await _all(
            conn,
            f"SELECT state, count(*) AS n FROM siem_probes WHERE {_IN.format(col='at')}"
            " GROUP BY state",
            w,
        )
    }
    metrics = [
        metric(
            "gaps.overlapping",
            "Gaps in coverage during the period",
            row.overlapping,
            "count",
            "Rows of coverage_gaps that began before the period ended and had not "
            "ended before it began (an open gap counts up to the making).",
        ),
        metric(
            "gaps.opened",
            "Gaps that began in the period",
            row.opened,
            "count",
            "Rows of coverage_gaps whose start_at is in the period.",
        ),
        metric(
            "gaps.closed",
            "Gaps that ended in the period",
            row.closed,
            "count",
            "Rows of coverage_gaps whose end_at is in the period.",
        ),
        metric(
            "gaps.open_now",
            "Gaps still open",
            row.open_now,
            "count",
            "Rows of coverage_gaps with no end, as at the making.",
        ),
        metric(
            "gaps.minutes",
            "Minutes of gaps within the period",
            row.minutes,
            "count",
            "Whole minutes (rounded down) of all gaps clipped to the period, added up; gaps "
            "that overlap each other are counted each.",
        ),
    ]
    metrics += [
        metric(f"gaps.kind.{k}", f"Gaps: {k.replace('_', ' ')}", kinds.get(k, 0), "count",
               f"Gaps of kind '{k}' that overlap the period.")
        for k in GAP_KINDS
    ]  # fmt: skip
    metrics += [
        metric(f"outages.probes.{s}", f"SIEM health checks that found it {s}",
               probes.get(s, 0), "count",
               f"Rows of siem_probes in state '{s}' in the period (about one a minute).")
        for s in PROBE_STATES
    ]  # fmt: skip
    return Section(id="gaps", title="Gaps and outages", metrics=tuple(metrics))


# --------------------------------------------------------------------------- threat intel


async def intel(conn: AsyncConnection, w: Window) -> Section:
    rows = await _all(
        conn,
        """SELECT source, indicators, error IS NOT NULL AS failed,
          CASE WHEN newest > CAST(:now AS timestamptz) THEN 0 ELSE
            floor(extract(epoch FROM CAST(:now AS timestamptz) - newest) / 3600)::int
          END AS newest_h,
          CASE WHEN checked_at > CAST(:now AS timestamptz) THEN 0 ELSE
            floor(extract(epoch FROM CAST(:now AS timestamptz) - checked_at) / 3600)::int
          END AS checked_h,
          coalesce(newest > CAST(:now AS timestamptz), false) AS newest_ahead,
          coalesce(checked_at > CAST(:now AS timestamptz), false) AS checked_ahead
        FROM ti_sources ORDER BY source""",
        w,
    )
    metrics = [
        metric(
            "intel.sources",
            "Threat-intelligence sources followed",
            len(rows),
            "count",
            "Rows of ti_sources, as at the making.",
        )
    ]
    taken: set[str] = set()
    notes: list[str] = []
    for r in rows:
        name = plain(r.source, 60)
        key = unique(f"intel.{slug(r.source)}", taken).removeprefix("intel.")
        metrics += [
            metric(
                f"intel.{key}.newest_age",
                f"{name}: age of its newest indicator",
                r.newest_h,
                "hours",
                "Whole hours (rounded down) from the source's newest indicator to "
                "the making; none when it has none; 0 when it is dated after the making.",
            ),
            metric(
                f"intel.{key}.checked_age",
                f"{name}: age of the last successful check",
                r.checked_h,
                "hours",
                "Whole hours (rounded down) from checked_at to the "
                "making; none when it was never checked; 0 when it is dated after the making.",
            ),
            metric(
                f"intel.{key}.indicators",
                f"{name}: indicators",
                r.indicators,
                "count",
                "The indicators the last check found (ti_sources.indicators).",
            ),
            metric(
                f"intel.{key}.failed",
                f"{name}: last check failed",
                int(r.failed),
                "count",
                "1 when ti_sources holds an error for the source, else 0.",
            ),
        ]
        for ahead, what in ((r.newest_ahead, "newest indicator"), (r.checked_ahead, "check")):
            if ahead:
                notes.append(
                    f"{name}: its {what} is dated after the moment the report was made, so its"
                    " age is shown as 0 hours."
                )
    return Section(
        id="intel", title="Threat-intelligence freshness", metrics=tuple(metrics),
        notes=tuple(notes),
    )  # fmt: skip


# --------------------------------------------------------------------------- audit chain


async def audit(conn: AsyncConnection, w: Window) -> Section:
    heads = await chain.heads(conn)
    events = (
        await _one(
            conn,
            f"SELECT count(*) AS n FROM audit_events WHERE {_IN.format(col='occurred_at')}",
            w,
        )
    ).n
    metrics = [
        metric(
            "audit.events",
            "Audit events in the period",
            events,
            "count",
            "Rows of audit_events whose occurred_at is in the period.",
        )
    ]
    for name in ("audit_events", "case_events"):
        seq, head = heads.get(name, (None, None))
        metrics += [
            metric(
                f"audit.{name}.rows",
                f"Hash-chained rows of {name.replace('_', ' ')}",
                seq,
                "count",
                "chain_heads.seq: the rows chained so far, as at the making.",
            ),
            metric(
                f"audit.{name}.head",
                f"Chain head of {name.replace('_', ' ')}",
                head,
                "text",
                "chain_heads.head_hash: the newest row's hash, as at the making (before the "
                "audit event that records this report).",
            ),
        ]
    return Section(id="audit", title="Audit chain", metrics=tuple(metrics))


BUILDERS: tuple[Builder, ...] = (
    cases, notified, active_hosts, actions, closures, approvals, siem_load, kibana_sync,
    guardrails, results, writeback, gaps, intel, audit,
)  # fmt: skip
_ = OUTCOMES  # the proposed outcomes are not split in this report: a person decides them
