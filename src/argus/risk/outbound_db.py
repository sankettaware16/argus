"""The incident evidence's reads and writes (D-323; Postgres only, no SIEM request here): the
presented incidents a pass may check and what is already done or reusable; the answers stored,
the incidents' alert groups marked for the engine's next pass, and the answers pruned after
``outbound.keep_days``; what the engine reads of them as signals of an alert group
(:func:`attach`), and what the presenter shows of them (:func:`measured_for`)."""

from __future__ import annotations

import ipaddress
import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.risk import alternatives as alt
from argus.risk.config import Outbound
from argus.risk.observe import Group, key_pairs
from argus.risk.outbound import Inputs, Pair, Row, Spent, Stored, Target, ranked

ACTOR_FIELDS = ("source.ip", "client.ip")
ROWS_READ = 20_000  # (device, address) sightings read for one pass
PAIRS_KEPT = 20  # sightings kept per incident (the most telling)

_TARGETS = text(
    "SELECT r.id, r.version, r.band, r.priority, r.material_at, r.last_seen"
    " FROM risk_incidents r LEFT JOIN cases c ON c.id = r.case_id"
    " WHERE r.parent_id IS NULL AND r.state IN ('active', 'quiet')"
    " AND r.band = ANY(CAST(:bands AS text[]))"
    " AND ((c.id IS NOT NULL AND c.state <> 'closed')"
    "  OR (r.case_id IS NULL AND r.shown AND r.view ->> 'shown_in' = 'present'))"
)
_PAIRS = text(
    "SELECT ig.incident_id, a.value AS device, t.value AS destination, i.last_event_at AS at,"
    " EXISTS (SELECT 1 FROM risk_observations o WHERE o.investigation_id = g.investigation_id"
    "  AND o.source_key = 'ev:beacon') AS beat,"
    " EXISTS (SELECT 1 FROM risk_threats th WHERE th.threat = 'ip:' || t.value) AS flagged"
    " FROM risk_incident_groups ig"
    " JOIN risk_groups g ON g.investigation_id = ig.investigation_id AND g.direction = 'outbound'"
    " JOIN investigations i ON i.id = g.investigation_id"
    " JOIN risk_entities a ON a.investigation_id = g.investigation_id AND a.kind = 'ip'"
    "  AND a.role = 'actor'"
    " JOIN risk_entities t ON t.investigation_id = g.investigation_id AND t.kind = 'ip'"
    "  AND t.role = 'threat'"
    " WHERE ig.incident_id = ANY(CAST(:ids AS bigint[]))"
    " ORDER BY i.last_event_at DESC LIMIT :n"
)
_ACTORS = text(
    "SELECT ig.incident_id, e.kind, e.value, i.last_event_at AS at"
    " FROM risk_incident_groups ig"
    " JOIN risk_groups g ON g.investigation_id = ig.investigation_id AND g.direction <> 'inbound'"
    " JOIN investigations i ON i.id = g.investigation_id"
    " JOIN risk_entities e ON e.investigation_id = g.investigation_id"
    "  AND ((e.kind = 'ip' AND e.role = 'actor') OR (e.kind = 'domain' AND e.role = 'threat'))"
    " WHERE ig.incident_id = ANY(CAST(:ids AS bigint[]))"
    " ORDER BY i.last_event_at DESC LIMIT :n"
)
# a contact count of a day still going on (a count so far), once that day is over: asked again
# (neither done nor reusable); a count that already says "common" stands
_SO_FAR = (
    "(kind = 'contact' AND facts ->> 'complete' = 'false' AND verdict <> 'common'"
    " AND day < CAST(:today AS date))"
)
_TUNNELS = text(
    "SELECT DISTINCT ig.incident_id FROM risk_incident_groups ig"
    " JOIN risk_observations o ON o.investigation_id = ig.investigation_id"
    " WHERE ig.incident_id = ANY(CAST(:ids AS bigint[])) AND o.source_key = 'ev:tunnel'"
)


def _is_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _stored(r: Any) -> Stored:
    facts = r.facts if isinstance(r.facts, Mapping) else {}
    return Stored(int(r.incident_id), int(r.incident_version), r.kind, r.subject, r.device,
                  r.destination, r.day, r.verdict, facts, r.checked_at)  # fmt: skip


async def inputs(conn: AsyncConnection, now: datetime, config: Outbound) -> Inputs:
    """The presented incidents of the configured bands with their outbound sightings, the checks
    done for their versions (an unknown one only while recent), and the recent answers a check
    of the same subject and day may reuse."""
    out = Inputs()
    today = now.astimezone(UTC).date()
    rows = (await conn.execute(_TARGETS, {"bands": list(config.bands)})).all()
    if not rows:
        return out
    ids = sorted(int(r.id) for r in rows)
    bound = {"ids": ids, "n": ROWS_READ}
    pairs: dict[int, list[Pair]] = defaultdict(list)
    for r in await conn.execute(_PAIRS, bound):
        if _is_address(r.device) and _is_address(r.destination) and r.device != r.destination:
            pairs[int(r.incident_id)].append(
                Pair(r.device, r.destination, r.at, bool(r.beat), bool(r.flagged))
            )
    devices: dict[int, dict[str, None]] = defaultdict(dict)
    domains: set[int] = set()
    for r in await conn.execute(_ACTORS, bound):
        if r.kind == "ip" and _is_address(r.value):
            devices[int(r.incident_id)].setdefault(r.value, None)
        elif r.kind == "domain":
            domains.add(int(r.incident_id))
    tunnels = {int(i) for i in (await conn.execute(_TUNNELS, {"ids": ids})).scalars()}
    for r in rows:
        iid = int(r.id)
        out.targets.append(Target(
            iid, int(r.version), r.band, int(r.priority), r.material_at, r.last_seen,
            tuple(ranked(pairs.get(iid, []))[:PAIRS_KEPT]), tuple(devices.get(iid, {})),
            iid in domains, iid in tunnels,
        ))  # fmt: skip
    done = await conn.execute(
        text(
            "SELECT incident_id, incident_version, kind, subject FROM risk_evidence"  # noqa: S608 - constant fragments; values are bound
            " WHERE incident_id = ANY(CAST(:ids AS bigint[]))"
            f" AND (verdict <> 'unknown' OR checked_at >= :recheck) AND NOT {_SO_FAR}"
        ),
        {"ids": ids, "recheck": now - timedelta(hours=config.recheck_hours), "today": today},
    )
    out.done = {(int(r[0]), int(r[1]), str(r[2]), str(r[3])) for r in done}
    if config.reuse_hours > 0:
        recent = await conn.execute(
            text(
                "SELECT DISTINCT ON (kind, subject, day) incident_id, incident_version, kind,"  # noqa: S608 - constant fragments; values are bound
                " subject, device, destination, day, verdict, facts, checked_at FROM risk_evidence"
                " WHERE checked_at >= :since AND verdict <> 'unknown' AND took_ms IS NOT NULL"
                f" AND NOT {_SO_FAR} ORDER BY kind, subject, day, checked_at DESC, id DESC"
            ),
            {"since": now - timedelta(hours=config.reuse_hours), "today": today},
        )
        for r in recent:
            s = _stored(r)
            out.reusable[(s.kind, s.subject, s.day)] = s
    return out


async def spent_today(conn: AsyncConnection, now: datetime, component: str) -> Spent:
    """Today's (UTC) requests and server time of ``component`` on the checking lane, and the
    whole lane's server time, from the gateway's ledger."""
    day = now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    row = (
        await conn.execute(
            text(
                "SELECT count(*) FILTER (WHERE component = :c) AS n,"
                " coalesce(sum(took_ms) FILTER (WHERE component = :c), 0) AS mine,"
                " coalesce(sum(took_ms), 0) AS lane FROM siem_requests"
                " WHERE lane = 'checking' AND at >= :day"
            ),
            {"c": component, "day": day},
        )
    ).one()
    return Spent(int(row.n), int(row.mine), int(row.lane))


async def save(conn: AsyncConnection, rows: Sequence[Row], now: datetime) -> int:
    """Store the answers; an answer replaces an earlier unknown one of the same check, or a
    contact count of a day that was still going on, never another known one."""
    if not rows:
        return 0
    result = await conn.execute(
        text(
            "INSERT INTO risk_evidence (incident_id, incident_version, kind, subject,"
            " device, destination, day, template, template_version, task_key, verdict, facts,"
            " took_ms, checked_at) VALUES (:incident, :version, :kind, :subject, :device,"
            " :destination, :day, :template, :template_version, :task_key, :verdict,"
            " CAST(:facts AS jsonb), :took, :now)"
            " ON CONFLICT (incident_id, incident_version, kind, subject) DO UPDATE SET"
            " device = EXCLUDED.device, destination = EXCLUDED.destination, day = EXCLUDED.day,"
            " template = EXCLUDED.template, template_version = EXCLUDED.template_version,"
            " task_key = EXCLUDED.task_key, verdict = EXCLUDED.verdict, facts = EXCLUDED.facts,"
            " took_ms = EXCLUDED.took_ms, checked_at = EXCLUDED.checked_at"
            " WHERE risk_evidence.verdict = 'unknown' OR (risk_evidence.kind = 'contact'"
            "  AND risk_evidence.facts ->> 'complete' = 'false')"
        ),
        [
            {"incident": r.incident, "version": r.version, "kind": r.kind, "subject": r.subject,
             "device": r.device, "destination": r.destination, "day": r.day,
             "template": r.template, "template_version": r.template_version,
             "task_key": r.task_key, "verdict": r.verdict,
             "facts": json.dumps(r.facts, sort_keys=True, default=str), "took": r.took_ms,
             "now": now}
            for r in rows
        ],
    )  # fmt: skip
    return max(int(result.rowcount or 0), 0)


async def touch(conn: AsyncConnection, incidents: Sequence[int]) -> int:
    """Mark the alert groups of ``incidents`` as changed, so the engine's next pass reads them
    again with what the checks found."""
    if not incidents:
        return 0
    result = await conn.execute(
        text(
            "UPDATE risk_groups g SET signature = md5(g.signature || '-evidence')"
            " WHERE g.investigation_id IN (SELECT investigation_id FROM risk_incident_groups"
            "  WHERE incident_id = ANY(CAST(:ids AS bigint[])))"
        ),
        {"ids": list(incidents)},
    )
    return int(result.rowcount or 0)


async def prune(conn: AsyncConnection, now: datetime, config: Outbound) -> int:
    result = await conn.execute(
        text("DELETE FROM risk_evidence WHERE checked_at < :keep"),
        {"keep": now - timedelta(days=config.keep_days)},
    )
    return int(result.rowcount or 0)


# --------------------------------------------------------------------------- what is read


def _addresses(g: Group) -> tuple[set[str], set[str]]:
    """(the group's actor addresses, every address it names)."""
    actors = {v for name, raw in key_pairs(g.key) if name in ACTOR_FIELDS for v in raw}
    named = {str(v) for name, values in g.fields.items() if name.endswith(".ip")
             for v in values if isinstance(v, str)}  # fmt: skip
    actors = {a for a in actors if _is_address(a)}
    return actors, {a for a in named | actors if _is_address(a)}


def _day(g: Group) -> date:
    return g.last_at.astimezone(UTC).date()


def signals_of(g: Group, answers: Sequence[Stored]) -> dict[str, Any]:
    """The signals the stored answers give one alert group (pure; only those it lacks): a
    regular rhythm of its actor to an address it names (``pair.period_s``), how many internal
    devices reached an address it names that day (``contact.hosts``, the fewest, of a whole day
    only: a count so far may be the device alone), a tunnel's shape in its actor's lookups
    (``dns.tunnel_suspected``). Answers within a day of the group's last alert count."""
    actors, named = _addresses(g)
    day = _day(g)
    out: dict[str, Any] = {}
    periods: list[int] = []
    hosts: list[int] = []
    for a in answers:
        if abs((a.day - day).days) > 1 or a.verdict == "unknown":
            continue
        if a.kind == "pair" and a.verdict == "regular" and a.device in actors \
                and a.destination in named:  # fmt: skip
            period = a.facts.get("period_s")
            if isinstance(period, int) and not isinstance(period, bool) and period > 0:
                periods.append(period)
        elif a.kind == "contact" and a.destination in named and a.destination not in actors \
                and a.facts.get("complete") is not False:  # fmt: skip
            n = a.facts.get("devices")
            if isinstance(n, int) and not isinstance(n, bool) and n > 0:
                hosts.append(n)
        elif a.kind == "dns" and a.verdict == "tunnel" and a.device in actors:
            out["dns.tunnel_suspected"] = True
    if periods:
        out["pair.period_s"] = min(periods)
    if hosts:
        out["contact.hosts"] = min(hosts)
    return {k: v for k, v in out.items() if k not in g.signals}


async def attach(conn: AsyncConnection, groups: Sequence[Group]) -> list[Group]:
    """``groups`` with the signals the stored answers give them (:func:`signals_of`)."""
    if not groups:
        return list(groups)
    values = sorted({a for g in groups for a in _addresses(g)[1]})
    if not values:
        return list(groups)
    days = [_day(g) for g in groups]
    rows = await conn.execute(
        text(
            "SELECT incident_id, incident_version, kind, subject, device, destination, day,"
            " verdict, facts, checked_at FROM risk_evidence WHERE verdict <> 'unknown'"
            " AND day BETWEEN :lo AND :hi AND (device = ANY(CAST(:v AS text[]))"
            "  OR destination = ANY(CAST(:v AS text[])))"
        ),
        {"lo": min(days) - timedelta(days=1), "hi": max(days) + timedelta(days=1), "v": values},
    )
    answers = [_stored(r) for r in rows]
    if not answers:
        return list(groups)
    out = []
    for g in groups:
        more = signals_of(g, answers)
        out.append(replace(g, signals={**g.signals, **more}) if more else g)
    return out


async def measured_for(conn: AsyncConnection, ids: Sequence[int]) -> dict[int, list[alt.Measured]]:
    """What the checks found for each incident: per check, the newest known answer of any of its
    versions (an unknown one only when nothing is known)."""
    out: dict[int, list[alt.Measured]] = defaultdict(list)
    if not ids:
        return out
    rows = await conn.execute(
        text(
            "SELECT DISTINCT ON (incident_id, kind, subject) incident_id, incident_version, kind,"
            " subject, device, destination, day, verdict, facts, checked_at FROM risk_evidence"
            " WHERE incident_id = ANY(CAST(:ids AS bigint[]))"
            " ORDER BY incident_id, kind, subject, verdict = 'unknown', incident_version DESC,"
            " checked_at DESC"
        ),
        {"ids": list(ids)},
    )
    for r in rows:
        s = _stored(r)
        out[s.incident].append(s.measured())
    return out
