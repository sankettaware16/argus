"""The reads behind UI v2's finding pages (spec §2.3): an entity's page (A11), the one search box
(A12), the incident reports list (A13) with "sent to the CISO" (A14), the incident an alert group
belongs to (A15) and the Kibana-posting health (A5).

Postgres only (ARGUS's own records: alert groups, cases, notes, the outside cache, the SSO
sign-ins it kept); no SIEM request, no model. Every query is cut at a fixed size, and an entity's
alert groups are found through the entity index (``investigation_entities (kind, value)``)."""

from __future__ import annotations

import ipaddress
import math
import re
import uuid
from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta
from typing import Any, Literal

from sqlalchemy import TextClause, text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus import site
from argus.assets.classify import IpClass, IpClassifier
from argus.config.settings import HistorySettings, OutsideSettings
from argus.outside import facts
from argus.web import casepages, needsyou
from argus.web.v1 import entity_models as m
from argus.web.v1 import report_models as rm
from argus.web.v1 import work_models as wm
from argus.web.v1.models import CaseTeamHealthOut, InCaseOut

PAGE_ROWS = 20  # incidents and alert groups an entity page lists
SEARCH_ROWS = 5  # of each group a search answers
TIMELINE = 50
NOTES = 5
DAYS = 14  # days of an entity a page lists
HOSTS_SHOWN = 5  # host names a day of an address lists
HOSTS_READ = 20  # host names a day of an address is compared on
REPORT_PAGE = 50
NOUNS = {"device": "Device", "account": "Account", "site": "{Own:site}",
         "outside": "Outside address"}  # fmt: skip
CAMPUS_CLASSES = (IpClass.ASSET, IpClass.CAMPUS, IpClass.INTERNAL)  # else an outside address
_NUMBER = re.compile(r"^#?(\d{1,7})$")
_IR = re.compile(r"(^IR-|-IR-\d{4}-\d{4}-\d{2}$)", re.I)
_DOMAIN = re.compile(r"^(?=.{3,253}$)[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*\.[A-Za-z]{2,63}\.?$")
_NAME = re.compile(r"^[A-Za-z0-9._@-]{2,64}$")


def _like(value: str) -> str:
    return "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def stored_kind(kind: m.PageKind, value: str) -> m.StoredKind:
    """How ARGUS's records hold a page's value: an address, a host name, a domain or a user."""
    if kind == "account":
        return "user"
    if kind == "outside":
        return "ip" if _address(value) else "domain"
    if _address(value):
        return "ip"
    if kind == "site" and _DOMAIN.match(value):
        return "domain"
    return "host"


def _address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def guess(q: str, classifier: IpClassifier | None) -> tuple[m.Guess, m.SearchEntityOut | None]:
    """What the search text looks like (spec §10.2), and the entity it names."""
    if _NUMBER.match(q):
        return "number", None
    if _IR.search(q):
        return "ir", None
    if _address(q):
        if _ip_class(q, classifier) in CAMPUS_CLASSES:
            return "device_address", m.SearchEntityOut(kind="device", value=q,
                                                       noun=site.say(NOUNS["device"]))  # fmt: skip
        return "outside_address", m.SearchEntityOut(kind="outside", value=q,
                                                    noun=site.say(NOUNS["outside"]))  # fmt: skip
    if _DOMAIN.match(q):
        return "domain", m.SearchEntityOut(
            kind="site", value=q.rstrip("."), noun=site.say(NOUNS["site"])
        )
    if _NAME.match(q):
        return "name", m.SearchEntityOut(kind="device", value=q, noun=site.say(NOUNS["device"]))
    return "words", None


def _ip_class(value: str, classifier: IpClassifier | None) -> IpClass:
    found = (classifier or IpClassifier(None)).classify(value)
    return found.ip_class


# ------------------------------------------------------------------------------ queries

_GROUPS = text(
    "SELECT i.id, i.rule_name, i.alert_count, i.first_event_at, i.last_event_at,"
    " count(*) OVER () AS total,"
    " (SELECT c.id FROM case_members mm JOIN cases c ON c.id = mm.case_id"
    "  WHERE mm.investigation_id = i.id AND mm.removed_at IS NULL ORDER BY c.number DESC"
    "  LIMIT 1) AS case_id"
    " FROM investigation_entities e JOIN investigations i ON i.id = e.investigation_id"
    " WHERE e.kind = :k AND e.value = :v"
    " ORDER BY i.last_event_at DESC NULLS LAST, i.id LIMIT :n"
)
_CASES_OF = (
    "(EXISTS (SELECT 1 FROM case_indicators ci WHERE ci.case_id = c.id AND ci.kind = :k"
    " AND ci.value = :v AND ci.removed_at IS NULL)"
    " OR EXISTS (SELECT 1 FROM case_members mm JOIN investigation_entities e"
    " ON e.investigation_id = mm.investigation_id WHERE mm.case_id = c.id"
    " AND mm.removed_at IS NULL AND e.kind = :k AND e.value = :v))"
)
_CASE_ORDER = "ORDER BY c.updated_at DESC, c.number DESC"
_IN_CASE = text(
    "SELECT c.id, c.number, c.title, c.state FROM case_members mm JOIN cases c ON c.id = mm.case_id"
    " WHERE mm.investigation_id = :i AND mm.removed_at IS NULL ORDER BY c.number DESC LIMIT 1"
)
_CASE_REFS = text("SELECT id, number, title, state FROM cases WHERE id = ANY(CAST(:ids AS uuid[]))")


async def case_of(conn: AsyncConnection, investigation_id: uuid.UUID) -> InCaseOut | None:
    """The incident an alert group belongs to (A15); None when it is in none."""
    row = (await conn.execute(_IN_CASE, {"i": investigation_id})).first()
    if row is None:
        return None
    return InCaseOut(id=row.id, number=int(row.number), title=row.title, state=row.state)


async def _refs(conn: AsyncConnection, ids: Iterable[uuid.UUID | None]) -> dict[uuid.UUID, Any]:
    wanted = sorted({i for i in ids if i is not None}, key=str)
    if not wanted:
        return {}
    return {r.id: r for r in await conn.execute(_CASE_REFS, {"ids": wanted})}


async def groups_of(
    conn: AsyncConnection, kind: str, value: str, limit: int
) -> tuple[list[m.GroupRowOut], int]:
    rows = (await conn.execute(_GROUPS, {"k": kind, "v": value, "n": limit})).all()
    refs = await _refs(conn, (r.case_id for r in rows))
    out = []
    for r in rows:
        c = refs.get(r.case_id)
        out.append(m.GroupRowOut(
            id=r.id, rule_name=r.rule_name, alerts=int(r.alert_count), first_at=r.first_event_at,
            last_at=r.last_event_at,
            case=None if c is None else InCaseOut(id=c.id, number=int(c.number), title=c.title,
                                                  state=c.state),
        ))  # fmt: skip
    return out, int(rows[0].total) if rows else 0


async def _cases(
    conn: AsyncConnection, where: str, params: dict[str, Any], me_id: int, limit: int
) -> tuple[list[Any], int]:
    rows = (
        await conn.execute(
            text(f"{casepages._ROW} WHERE {where} {_CASE_ORDER} LIMIT :lim"),
            {**params, "lim": limit},
        )
    ).all()
    total = await conn.scalar(
        text(f"SELECT count(*) FROM cases c WHERE {where}"),  # noqa: S608 - fragments
        params,
    )
    items = await needsyou.decorate(conn, [casepages._row(r) for r in rows], me_id)
    return items, int(total or 0)


async def cases_of(
    conn: AsyncConnection, kind: str, value: str, me_id: int, limit: int
) -> tuple[list[Any], int]:
    """The incidents (cases) that name the value as an indicator or hold an alert group with
    it."""
    return await _cases(conn, _CASES_OF, {"k": kind, "v": value}, me_id, limit)


async def history_days(conn: AsyncConnection, now: datetime) -> int:
    """How many days of alert detail ARGUS holds now (its oldest alert group), else the
    configured default."""
    oldest = await conn.scalar(text("SELECT min(bucket_start) FROM investigations"))
    if oldest is None:
        return int(HistorySettings().window.total_seconds() // 86400)
    held: timedelta = now - oldest
    return max(1, math.ceil(held.total_seconds() / 86400))


# an alert group's day: the site's calendar day its bucket is named for (``patterns.day_of``);
# the UTC date of a bucket's start is the day before it east of UTC
_GROUP_DAY = "(i.bucket_start AT TIME ZONE @ZONE@)::date"
_DAY_GROUPS = (
    f"SELECT {_GROUP_DAY} AS day, count(*) AS n"  # noqa: S608 - a constant
    " FROM investigation_entities e JOIN investigations i ON i.id = e.investigation_id"
    " WHERE e.kind = :k AND e.value = :v GROUP BY 1 ORDER BY 1 DESC LIMIT :n"
)
_DAY_HOSTS = (  # each day's most named hosts, from the groups that name one host only
    f"SELECT day, value FROM (SELECT {_GROUP_DAY} AS day, h.value,"  # noqa: S608 - a constant
    f"  row_number() OVER (PARTITION BY {_GROUP_DAY} ORDER BY count(*) DESC, h.value) AS place"
    "  FROM investigation_entities e JOIN investigations i ON i.id = e.investigation_id"
    "  JOIN investigation_entities h ON h.investigation_id = i.id AND h.kind = 'host'"
    "  WHERE e.kind = 'ip' AND e.value = :v"
    f"  AND {_GROUP_DAY} = ANY(CAST(:days AS date[]))"
    "  AND NOT EXISTS (SELECT 1 FROM investigation_entities x WHERE x.investigation_id = i.id"
    "   AND x.kind = 'host' AND x.value <> h.value)"
    "  GROUP BY 1, 2) s WHERE place <= :n ORDER BY day DESC, place"
)


def _zoned(sql: str) -> TextClause:
    return text(sql.replace("@ZONE@", site.zone_sql()))


def _apart(sets: Iterable[set[str]]) -> bool | None:
    """Whether two of these days share nothing (None: fewer than two days to compare)."""
    known = [s for s in sets if s]
    if len(known) < 2:
        return None
    return any(not (a & b) for n, a in enumerate(known) for b in known[n + 1 :])


async def _days(
    conn: AsyncConnection, kind: str, value: str, show_names: bool
) -> tuple[list[m.EntityDayOut], bool | None, int | None]:
    """The value's days in ARGUS's records and, for an address, the host names its alert groups
    named each day (a group naming one host only) and the accounts that signed in from it.

    ``dynamic`` (a different device on different days, spec §9.2) is decided from the host
    names: two days that name no host in common make it True, host names on two days or more
    that always meet make it False. A change of person alone never says another device (a lab
    PC is used by different students each day), so without host names the sign-ins can only
    say False (every two days share an account), else None: ARGUS cannot tell. ``shared_by``
    is the most accounts seen behind it in one day."""
    groups = {
        r.day: int(r.n)
        for r in await conn.execute(_zoned(_DAY_GROUPS), {"k": kind, "v": value, "n": DAYS})
    }
    seen: dict[Any, list[str]] = {}
    hosts: dict[Any, list[str]] = {}
    if kind == "ip":
        for r in await conn.execute(
            text(
                "SELECT day, user_name FROM signin_sightings WHERE address = CAST(:v AS inet)"
                " AND day >= (SELECT max(day) - :n FROM signin_sightings"
                "  WHERE address = CAST(:v AS inet)) ORDER BY day DESC, user_name LIMIT 2000"
            ),
            {"v": value, "n": DAYS},
        ):
            seen.setdefault(r.day, []).append(r.user_name)
        if groups:
            for r in await conn.execute(
                _zoned(_DAY_HOSTS), {"v": value, "days": sorted(groups), "n": HOSTS_READ}
            ):
                hosts.setdefault(r.day, []).append(r.value)
    days = sorted(set(groups) | set(seen), reverse=True)[:DAYS]
    out = [
        m.EntityDayOut(
            day=d, alert_groups=groups.get(d, 0), hosts=hosts.get(d, [])[:HOSTS_SHOWN],
            accounts=len(seen[d]) if d in seen else None,
            account_names=sorted(seen[d])[:20] if show_names and d in seen else None,
        )
        for d in days
    ]  # fmt: skip
    dynamic = _apart(set(hosts.get(d, ())) for d in days)
    if dynamic is None and _apart(set(seen[d]) for d in days if d in seen) is False:
        dynamic = False  # the same people every day: no sign of another device
    if not seen:
        return out, dynamic, None
    return out, dynamic, max(len(names) for names in seen.values())


async def _timeline(conn: AsyncConnection, kind: str, value: str) -> list[m.TimelineEventOut]:
    rows = await conn.execute(
        text(
            "SELECT i.id, i.rule_name, i.alert_count, i.last_event_at,"
            " (SELECT c.number FROM case_members mm JOIN cases c ON c.id = mm.case_id"
            "  WHERE mm.investigation_id = i.id AND mm.removed_at IS NULL"
            "  ORDER BY c.number DESC LIMIT 1) AS case_number"
            " FROM investigation_entities e JOIN investigations i ON i.id = e.investigation_id"
            " WHERE e.kind = :k AND e.value = :v AND i.last_event_at IS NOT NULL"
            " ORDER BY i.last_event_at DESC, i.id LIMIT :n"
        ),
        {"k": kind, "v": value, "n": TIMELINE},
    )
    return [
        m.TimelineEventOut(
            at=r.last_event_at, rule_name=r.rule_name, alerts=int(r.alert_count),
            investigation_id=r.id,
            case_number=None if r.case_number is None else int(r.case_number),
        )
        for r in rows
    ]  # fmt: skip


async def reputation(conn: AsyncConnection, kind: str, value: str) -> list[m.ReputationOut]:
    """What the outside sources said of an address or a domain, newest answer per source."""
    if kind not in ("ip", "domain"):
        return []
    threshold = OutsideSettings().flag_threshold
    rows = await conn.execute(
        text(
            "SELECT DISTINCT ON (source) source, kind, indicator, status, answer, fetched_at"
            " FROM outside_lookups WHERE kind = :k AND indicator = :v"
            " ORDER BY source, fetched_at DESC"
        ),
        {"k": kind, "v": value},
    )
    out = []
    for r in rows:
        entry = facts.fact(r.source, r.kind, r.indicator, r.status, r.answer, threshold)
        out.append(m.ReputationOut(source=facts.NAMES.get(r.source, r.source),
                                   words=facts.describe(entry), flagged=bool(entry["flagged"]),
                                   at=r.fetched_at))  # fmt: skip
    return out


async def entity_page(
    conn: AsyncConnection,
    kind: m.PageKind,
    value: str,
    me_id: int,
    *,
    now: datetime,
    classifier: IpClassifier | None,
    show_names: bool,
) -> m.EntityPageOut:
    """What ARGUS knows of one device, account, campus site or outside address."""
    stored = stored_kind(kind, value)
    address_class = asset = None
    if stored == "ip":
        found = (classifier or IpClassifier(None)).classify(value)
        address_class = found.ip_class.value
        if found.asset is not None and found.asset.entries:
            entry = found.asset.entries[0]
            asset = m.AssetOut(name=entry.name, network=str(found.asset.network),
                               fields=dict(entry.fields))  # fmt: skip
    incidents, incidents_total = await cases_of(conn, stored, value, me_id, PAGE_ROWS)
    counts = (
        await conn.execute(
            text(
                f"SELECT count(*) FILTER (WHERE c.state <> 'closed') AS open,"  # noqa: S608
                f" bool_or(c.notified_at IS NOT NULL) AS told FROM cases c WHERE {_CASES_OF}"
            ),
            {"k": stored, "v": value},
        )
    ).one()
    groups, groups_total = await groups_of(conn, stored, value, PAGE_ROWS)
    span = (
        await conn.execute(
            text(
                "SELECT min(i.first_event_at) AS first, max(i.last_event_at) AS last"
                " FROM investigation_entities e JOIN investigations i"
                " ON i.id = e.investigation_id WHERE e.kind = :k AND e.value = :v"
            ),
            {"k": stored, "v": value},
        )
    ).one()
    days, dynamic, shared = await _days(conn, stored, value, show_names)
    notes = await casepages.entity_notes(conn, stored, value)
    return m.EntityPageOut(
        kind=kind, value=value, stored_kind=stored, noun=NOUNS[kind],
        history_days=await history_days(conn, now), address_class=address_class, asset=asset,
        first_seen=span.first, last_seen=span.last, owner_told=bool(counts.told),
        incidents=incidents, incidents_total=incidents_total, open_incidents=int(counts.open),
        alert_groups=groups, alert_groups_total=groups_total,
        timeline=await _timeline(conn, stored, value), days=days, dynamic=dynamic,
        shared_by=shared, reputation=await reputation(conn, stored, value),
        notes=notes[:NOTES], notes_total=len(notes),
    )  # fmt: skip


# ------------------------------------------------------------------------- incident reports

_IR_OF = (
    "coalesce((SELECT p.incident_id FROM case_team_posts p WHERE p.case_id = c.id),"
    " r.body #>> '{header,incident_id}')"
)
_REPORTS = (
    "SELECT c.id AS case_id, c.number, c.title, c.state, r.version, r.generated_at,"  # noqa: S608
    f" {_IR_OF} AS ir,"
    " jsonb_path_exists(r.body, '$.users.devices[*].accounts[*]') AS accounts,"
    " EXISTS (SELECT 1 FROM kibana_outbox x WHERE x.case_id = c.id AND x.op = 'create'"
    "  AND NOT (x.state = 'skipped' AND x.sent_count = 0)) AS in_kibana"
    " FROM cases c JOIN LATERAL (SELECT version, generated_at, body FROM incident_reports"
    "  WHERE case_id = c.id ORDER BY version DESC LIMIT 1) r ON true"
    " WHERE c.opened_at IS NOT NULL"
)


async def sent_of(
    conn: AsyncConnection, case_ids: Sequence[uuid.UUID]
) -> dict[uuid.UUID, wm.SentOut]:
    """The newest "sent to the CISO" of each of these cases (A14)."""
    if not case_ids:
        return {}
    rows = await conn.execute(
        text(
            "SELECT DISTINCT ON (s.case_id) s.case_id, s.sent_to, s.report_version, s.sent_at,"
            " coalesce(nullif(u.display_name, ''), u.username) AS by FROM report_sends s"
            " JOIN users u ON u.id = s.by_user_id WHERE s.case_id = ANY(CAST(:ids AS uuid[]))"
            " ORDER BY s.case_id, s.id DESC"
        ),
        {"ids": sorted(set(case_ids), key=str)},
    )
    return {
        r.case_id: wm.SentOut(to=r.sent_to, report_version=int(r.report_version), at=r.sent_at,
                              by=r.by)
        for r in rows
    }  # fmt: skip


def _files(case_id: uuid.UUID, can_logs: bool, accounts: bool) -> list[rm.ReportFileOut]:
    from argus.web.v1.report_routes import report_files

    return report_files(case_id, can_logs, accounts)


async def reports(
    conn: AsyncConnection,
    *,
    q: str | None,
    offset: int,
    limit: int,
    can_logs: bool,
    case_ids: Sequence[uuid.UUID] | None = None,
) -> tuple[list[m.IncidentReportRowOut], bool, int]:
    """Confirmed incidents' reports (their newest version), newest first: by IR number, number
    or title when ``q`` is given. Returns the page, whether more follow, and the count."""
    where, params = "", dict[str, Any]()
    if q:
        number = _NUMBER.match(q)
        where = f" AND (c.title ILIKE :q ESCAPE '\\' OR {_IR_OF} ILIKE :q ESCAPE '\\'"
        params["q"] = _like(q)
        if number:
            where += " OR c.number = :n"
            params["n"] = int(number.group(1))
        where += ")"
    if case_ids is not None:
        where += " AND c.id = ANY(CAST(:ids AS uuid[]))"
        params["ids"] = list(case_ids)
    listed = text(
        f"SELECT *, count(*) OVER () AS total FROM ({_REPORTS}{where}) s"  # noqa: S608
        " ORDER BY generated_at DESC, number DESC OFFSET :off LIMIT :lim"
    )
    rows = (await conn.execute(listed, {**params, "off": offset, "lim": limit + 1})).all()
    sent = await sent_of(conn, [r.case_id for r in rows[:limit]])
    items = [
        m.IncidentReportRowOut(
            case_id=r.case_id, number=int(r.number), ir=r.ir, title=r.title, case_state=r.state,
            version=int(r.version), generated_at=r.generated_at,
            files=_files(r.case_id, can_logs, bool(r.accounts)), in_kibana=bool(r.in_kibana),
            sent=sent.get(r.case_id),
        )
        for r in rows[:limit]
    ]  # fmt: skip
    return items, len(rows) > limit, int(rows[0].total) if rows else 0


# ------------------------------------------------------------------------------ search


async def search(
    conn: AsyncConnection,
    q: str,
    me_id: int,
    *,
    classifier: IpClassifier | None,
    can_logs: bool,
) -> m.SearchOut:
    """One box (A12): an incident number, an IR number, an address, a host, an account, a
    domain, or words of a title or a rule name."""
    kind, entity = guess(q, classifier)
    incidents: list[Any] = []
    groups: list[m.GroupRowOut] = []
    found_reports: list[m.IncidentReportRowOut] = []
    n_incidents = n_groups = n_reports = 0
    if kind == "number":
        number = _NUMBER.match(q)
        assert number is not None
        incidents, n_incidents = await _cases(
            conn, "c.number = :n", {"n": int(number.group(1))}, me_id, SEARCH_ROWS
        )
    elif kind == "ir":
        found_reports, _, n_reports = await reports(conn, q=q, offset=0, limit=SEARCH_ROWS,
                                                    can_logs=can_logs)  # fmt: skip
        ids = [r.case_id for r in found_reports]
        if ids:
            incidents, n_incidents = await _cases(
                conn, "c.id = ANY(CAST(:ids AS uuid[]))", {"ids": ids}, me_id, SEARCH_ROWS
            )
    elif entity is not None:
        stored = stored_kind(entity.kind, entity.value)
        incidents, n_incidents = await cases_of(conn, stored, entity.value, me_id, SEARCH_ROWS)
        groups, n_groups = await groups_of(conn, stored, entity.value, SEARCH_ROWS)
        if kind == "name" and not groups and not incidents:  # not a host: an account?
            entity = None  # an account names a person: only with see_logs, as its page
            if can_logs:
                incidents, n_incidents = await cases_of(conn, "user", q, me_id, SEARCH_ROWS)
                groups, n_groups = await groups_of(conn, "user", q, SEARCH_ROWS)
                if groups or incidents:
                    entity = m.SearchEntityOut(kind="account", value=q, noun=NOUNS["account"])
        if entity is None:  # neither a host nor an account ARGUS knows: words, then
            return await _words(conn, q, kind, me_id, can_logs)
        if incidents:
            found_reports, _, n_reports = await reports(
                conn, q=None, offset=0, limit=SEARCH_ROWS, can_logs=can_logs,
                case_ids=[c.id for c in incidents],
            )  # fmt: skip
    else:
        return await _words(conn, q, kind, me_id, can_logs)
    return m.SearchOut(
        q=q, guess=kind, entity=entity, incidents=incidents, incidents_total=n_incidents,
        alert_groups=groups, alert_groups_total=n_groups, reports=found_reports,
        reports_total=n_reports,
    )  # fmt: skip


async def _words(
    conn: AsyncConnection, q: str, kind: m.Guess, me_id: int, can_logs: bool
) -> m.SearchOut:
    """Words of an incident title, a rule name, or an IR number or title of a report."""
    incidents, n_incidents = await _cases(conn, "c.title ILIKE :q ESCAPE '\\'",
                                          {"q": _like(q)}, me_id, SEARCH_ROWS)  # fmt: skip
    rows = (
        await conn.execute(
            text(
                "SELECT i.id, i.rule_name, i.alert_count, i.first_event_at, i.last_event_at,"
                " count(*) OVER () AS total FROM investigations i"
                " WHERE i.rule_name ILIKE :q ESCAPE '\\'"
                " ORDER BY i.last_event_at DESC NULLS LAST, i.id LIMIT :n"
            ),
            {"q": _like(q), "n": SEARCH_ROWS},
        )
    ).all()
    groups = [m.GroupRowOut(id=r.id, rule_name=r.rule_name, alerts=int(r.alert_count),
                            first_at=r.first_event_at, last_at=r.last_event_at,
                            case=await case_of(conn, r.id)) for r in rows]  # fmt: skip
    n_groups = int(rows[0].total) if rows else 0
    found_reports, _, n_reports = await reports(conn, q=q, offset=0, limit=SEARCH_ROWS,
                                                can_logs=can_logs)  # fmt: skip
    return m.SearchOut(
        q=q, guess=kind, entity=None, incidents=incidents, incidents_total=n_incidents,
        alert_groups=groups, alert_groups_total=n_groups, reports=found_reports,
        reports_total=n_reports,
    )  # fmt: skip


# ------------------------------------------------------------------- A5: posting to Kibana


async def case_team_health(conn: AsyncConnection) -> CaseTeamHealthOut:
    """Whether confirmed incidents reach Kibana: a request that failed and still waits for a
    person (a ``failed`` step is never sent again by itself) makes it ``failing``, since the
    oldest such failure was sent, whatever landed after it (the case list's ``kibana=failing``
    lists the same cases); confirmed incidents still waiting for Kibana are ``waiting``."""
    row = (
        await conn.execute(
            text(
                "SELECT (SELECT min(coalesce(s.sent_at, s.created_at)) FROM case_team_steps s"
                "   WHERE s.state = 'failed') AS failing_since,"
                " greatest((SELECT max(last_round_at) FROM case_team_posts),"
                "   (SELECT max(sent_at) FROM case_team_steps)) AS last_run_at,"
                " (SELECT count(*) FROM cases c WHERE c.state IN ('open', 'assigned', 'contained')"
                "   AND c.kibana_wait IS NOT NULL) AS held"
            )
        )
    ).one()
    held = int(row.held)
    state: Literal["ok", "waiting", "failing"] = (
        "failing" if row.failing_since is not None else "waiting" if held else "ok"
    )
    return CaseTeamHealthOut(
        state=state, last_run_at=row.last_run_at, failing_since=row.failing_since, held=held
    )
