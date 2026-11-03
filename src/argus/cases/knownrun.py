"""The known infection at work (AR4b, D-169, D-176): a pass over the cases whose owner was told.

:mod:`argus.cases.known` holds the rules. A pass (:func:`run`, called by the assessment service
after the evidence is read, and by ``argus case known run``) does this for every case that is
open or assigned and has a notice:

1. **Seed** the fingerprint the first time: the evidence flags, the university services, the
   flagged destinations and the data volume that the case's investigations showed when the
   notice was recorded (the members linked at or before it), kept as ``case_known_keys``; those
   investigations then are known.
2. **Read** the investigations that name one of the case's devices (an entity or an actor of the
   grouping key; ``per_pass`` counts only these) with activity since the notice that were not
   decided at their current version, and decide each one: known or changed
   (:func:`argus.cases.known.evaluate`). The decision is a row of ``case_known_matches``; the
   investigation joins the case (a silent link); what a change brought becomes known, and the
   destinations that are new but not flagged are noted on the case. A change is durable
   (:func:`argus.cases.known.settle`): it stays until a person reviews the investigation.
3. **Notice a moved address:** an investigation from a new campus address, soon after the
   case's only device went quiet, with the same set of indicators (a separate, small query), or
   with the case's host name, is probably the same device: ARGUS adds the address to the case
   and says so, and offers it no new case. A case with two devices never merges a third, and
   when the old address alerts again after a move the investigation is a change ("two
   devices").
4. **Suggest, never alarm:** a case still active a week after its only notice earns a "notify
   again" reminder, one still active after three weeks a "ask for network-side action"
   reminder; one with no matching activity for 14 days is proposed for closing as "stopped after
   notice" (a person approves; an unanswered proposal that expired is made again).

A case closed as "stopped after notice" keeps a short watch (``notified.reopen_days``): its
device's investigations that reach the case's indicators, or bring something new, are a change
again ("active again after it stopped"); nothing reopens by itself.

The pass reads ARGUS's own database and the outside cache only (nothing reaches the SIEM or an
outside source) and writes under the opener's lock, as the other case writers do. One case's
failure is a problem in the report and the other cases go on.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Text, bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus import site
from argus.assets.assetmap import IPNetwork
from argus.assets.classify import IpClass, IpClassifier
from argus.campaigns import load as campaign_load
from argus.cases import known, opener, proposer
from argus.cases.known import Gone, Key, Print, Rules, Subject
from argus.cases.knownview import AFTER_WITHDRAWAL
from argus.cases.machine import AddressMoved, CaseRefused, Link
from argus.cases.membership import NO_SHARED, Shared
from argus.cases.model import SEVERITIES, Actor, Indicator, Member, Severity
from argus.cases.service import CaseService
from argus.outside import facts
from argus.outside import read as outside_read
from argus.outside.eligible import Eligibility
from argus.outside.read import View

log = logging.getLogger("argus.cases.known")

ACTOR = Actor.argus("known")
CHUNK = 100  # members one change adds
MARKS_PER_CHUNK = 400  # indicators one change adds (the machine's limit is 500)
MAX_ENTITIES = 400  # entities read per investigation (a scanner has thousands)
STRONG = ("host", "user")  # device keys read from a grouping key
AGAIN = "it is active again after it stopped (case {number}, closed {day})"


@dataclass(frozen=True)
class Context:
    """What a pass needs: the asset map's classes and site types, the shared-infrastructure list
    (no outside address on it says who is behind it), the rules, the outside cache's view, and the
    eligibility check that keeps campus names out of the destinations."""

    classifier: IpClassifier
    shared: Shared = NO_SHARED
    rules: Rules = field(default_factory=Rules)
    per_pass: int = 500  # investigations of the case's devices read in a pass
    moved_per_pass: int = 50  # investigations read for a moved address, a pass (a separate query)
    resolvers: Sequence[IPNetwork] = ()
    view: View | None = None
    eligible: Eligibility | None = None
    history: timedelta = timedelta(days=5)

    def is_campus(self, value: str) -> bool:
        return self.classifier.classify(value).ip_class in opener.CAMPUS

    def site_type(self, value: str) -> str | None:
        return site_type(self.classifier, value)


def site_type(classifier: IpClassifier, value: str) -> str | None:
    """The asset map's ``site.type`` of the network an address is in (None: unknown, or the map
    lists the network twice with different types)."""
    match = classifier.classify(value).asset
    if match is None:
        return None
    kinds = {e.fields.get("site.type") for e in match.entries}
    return next(iter(kinds)) if len(kinds) == 1 else None


async def managed(
    conn: AsyncConnection, case_id: uuid.UUID, classifier: IpClassifier | None, rules: Rules
) -> bool:
    """Whether a case's devices are campus-managed (D-169): every campus address it holds as a
    device is in an asset-map network whose ``site.type`` is one of ``managed_types``. A device
    the map does not know, a case with no address, and a missing map are not managed."""
    if classifier is None:
        return False
    held = (await conn.execute(_INDICATORS, {"c": case_id})).all()
    addresses = [r.value for r in held if r.role == "actor" and r.kind == "ip"]
    return known.managed([site_type(classifier, a) for a in addresses], rules)


def rules_of(settings: Any) -> Rules:
    """The rules from the settings' ``notified`` section."""
    return Rules(
        renotify_days=settings.renotify_days,
        network_days=settings.network_days,
        quiet_days=settings.quiet_days,
        active_days=settings.active_days,
        move_window=settings.move_window,
        move_gap=settings.move_gap,
        move_similarity=settings.move_similarity,
        volume_factor=settings.volume_factor,
        managed_types=frozenset(t.lower() for t in settings.managed_types),
        reopen_days=settings.reopen_days,
    )


def context_for(
    settings: Any, classifier: IpClassifier, *, shared: Shared = NO_SHARED,
    view: View | None = None, eligible: Eligibility | None = None,
) -> Context:  # fmt: skip
    """A pass's context from the settings (``notified``, ``campaigns``, ``history``)."""
    return Context(
        classifier, shared, rules_of(settings.notified), settings.notified.per_pass,
        resolvers=tuple(settings.campaigns.resolvers), view=view, eligible=eligible,
        history=settings.history.window,
    )  # fmt: skip


# --------------------------------------------------------------------------- the cases


@dataclass(frozen=True)
class Tracked:
    """A case the pass looks after: notified (open or assigned), or closed as stopped after
    notice within ``reopen_days``."""

    id: uuid.UUID
    number: int
    state: str
    version: int
    severity: Severity
    notified_at: datetime | None
    blocked_at: datetime | None
    closed_at: datetime | None
    fingerprint: Print
    seeded: bool
    since: datetime  # activity from here on is the infection's (the notice, or the closure)

    @property
    def stopped(self) -> bool:
        return self.state == "closed"


_TRACKED = text(
    "SELECT id, number, state, version, severity, notified_at, blocked_at, closed_at FROM cases"
    " WHERE (notified_at IS NOT NULL AND state IN ('open', 'assigned'))"
    " OR (state = 'closed' AND closure_reason = 'stopped_after_notice' AND closed_at >= :since)"
    " ORDER BY number"
)
_INDICATORS = text(
    "SELECT kind, value, role FROM case_indicators WHERE case_id = :c AND removed_at IS NULL"
)
_KEYS = text("SELECT kind, value FROM case_known_keys WHERE case_id = :c")


async def tracked(conn: AsyncConnection, ctx: Context, now: datetime) -> list[Tracked]:
    """The cases to look after, with their fingerprints."""
    since = now - timedelta(days=ctx.rules.reopen_days)
    out = []
    for row in (await conn.execute(_TRACKED, {"since": since})).all():
        marks = (await conn.execute(_INDICATORS, {"c": row.id})).all()
        keys = [(str(r.kind), str(r.value)) for r in (await conn.execute(_KEYS, {"c": row.id}))]
        devices = [(r.kind, r.value) for r in marks if r.role == "actor"]
        destinations = [(r.kind, r.value) for r in marks if r.role != "actor"]
        out.append(
            Tracked(
                row.id, int(row.number), row.state, int(row.version), row.severity,
                row.notified_at, row.blocked_at, row.closed_at,
                known.print_of(devices, destinations, keys),
                any(k == known.SEED for k, _ in keys),
                row.closed_at if row.state == "closed" else row.notified_at,
            )
        )  # fmt: skip
    return out


# --------------------------------------------------------------------------- reading subjects

_BASE = text(
    "SELECT i.id, i.version, i.severity, i.group_key, i.first_event_at, i.last_event_at,"
    " rz.flags FROM investigations i LEFT JOIN investigation_raises rz"
    " ON rz.investigation_id = i.id AND rz.version = i.version"
    " WHERE i.id = ANY(:ids)"
).bindparams(bindparam("ids", type_=ARRAY(UUID)))
_ENTITIES = text(
    "SELECT investigation_id, kind, value FROM ("
    " SELECT investigation_id, kind, value, row_number() OVER (PARTITION BY investigation_id"
    " ORDER BY kind, value) AS rn FROM investigation_entities"
    " WHERE investigation_id = ANY(:ids) AND kind IN ('ip', 'domain')) x WHERE rn <= :cap"
).bindparams(bindparam("ids", type_=ARRAY(UUID)))
_DOSSIERS = text(
    "SELECT DISTINCT ON (d.investigation_id) d.investigation_id,"
    " d.body -> 'local_signals' AS local_signals, d.body -> 'signals' AS signals,"
    " d.body #> '{context,pack,ti,listed}' AS listed"
    " FROM dossiers d JOIN investigations i ON i.id = d.investigation_id AND i.version = d.version"
    " WHERE d.investigation_id = ANY(:ids)"
    " ORDER BY d.investigation_id, d.created_at DESC, d.pack DESC"
).bindparams(bindparam("ids", type_=ARRAY(UUID)))


def _signal(local: Any, signals: Any, name: str) -> Any:
    for group in (local, signals):
        for item in group if isinstance(group, list) else []:
            if isinstance(item, Mapping) and item.get("name") == name:
                return item.get("value") if item.get("status") == "known" else None
    return None


def _bytes(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return int(value) if value >= 0 else None


def listed_key(value: object) -> Key | None:
    """A threat-intel value as a destination, typed as the outside cache types it (D-181): an
    address or a name as it is written canonically, a URL as its host. A file hash names no
    destination, and neither does anything that is not a valid address, name or URL."""
    if not isinstance(value, str):
        return None
    text_ = value.strip()
    if "://" in text_:
        url = facts.canonical("url", text_)
        if url is None:
            return None
        text_ = facts.host_of(url)
    for kind in ("ip", "domain"):
        found = facts.canonical(kind, text_)
        if found is not None:
            return (kind, found)
    return None


_RANKED = text(
    "SELECT DISTINCT indicator FROM outside_lookups WHERE source = 'virustotal'"
    " AND kind = 'domain' AND status = 'found' AND answer ->> 'ranked' = 'true'"
    " AND indicator = ANY(:names)"
).bindparams(bindparam("names", type_=ARRAY(Text)))


async def popular_names(conn: AsyncConnection, names: Iterable[str]) -> frozenset[str]:
    """The names, among ``names``, that a web-popularity list ranks (D-174), or whose registered
    parent is ranked: popular infrastructure that every case holds, so reaching it says nothing
    about who is behind it."""
    wanted = set(names)
    for name in list(wanted):
        parent = known.parent_of(name)
        if parent is not None:
            wanted.add(parent)
    if not wanted:
        return frozenset()
    ranked = {str(r.indicator) for r in await conn.execute(_RANKED, {"names": sorted(wanted)})}
    return frozenset(
        n for n in names if n in ranked or ((p := known.parent_of(n)) is not None and p in ranked)
    )


async def subjects(
    conn: AsyncConnection, ctx: Context, ids: Sequence[uuid.UUID], now: datetime
) -> dict[uuid.UUID, Subject]:
    """The investigations in ``ids`` as the known infection sees them (see :class:`Subject`)."""
    if not ids:
        return {}
    base = {r.id: r for r in (await conn.execute(_BASE, {"ids": list(ids)})).all()}
    entities: dict[uuid.UUID, list[Key]] = defaultdict(list)
    for r in await conn.execute(_ENTITIES, {"ids": list(ids), "cap": MAX_ENTITIES}):
        entities[r.investigation_id].append((str(r.kind), str(r.value)))
    dossiers = {r.investigation_id: r for r in (await conn.execute(_DOSSIERS, {"ids": list(ids)}))}
    cached: Mapping[uuid.UUID, list[dict[str, Any]]] = {}
    if ctx.view is not None:
        cached = await outside_read.facts_for(
            conn, list(ids), now, ctx.view.window, ctx.view.threshold,
            clean_window=ctx.view.clean_window, parent_ok=ctx.view.parent_ok,
        )  # fmt: skip
    devices = await campaign_load.hosts_for(
        conn, {i: r.group_key for i, r in base.items()}, ctx.classifier, ctx.resolvers
    )
    outside_keys = {k for found in entities.values() for k in found if _outside(ctx, k)}
    popular = await popular_names(conn, {v for kind, v in outside_keys if kind == "domain"})
    out: dict[uuid.UUID, Subject] = {}
    for investigation_id, row in base.items():
        found = entities.get(investigation_id, [])
        actors, _ = opener.actors_of(row.group_key, ctx.classifier)
        keys = set(devices.get(investigation_id, frozenset()))
        keys |= {(a.kind, a.value) for a in actors if a.kind in STRONG}
        destinations = frozenset(
            k for k in found if k in outside_keys and not (k[0] == "domain" and k[1] in popular)
        )
        services = frozenset(
            k for k in found if k[0] == "ip" and ctx.is_campus(k[1])
            and known.managed([ctx.site_type(k[1])], ctx.rules)
        )  # fmt: skip
        flagged = {
            (str(f["kind"]), str(f["value"]))
            for f in cached.get(investigation_id, [])
            if f.get("flagged") is True and f.get("kind") in known.DESTINATION_KINDS
        }
        dossier = dossiers.get(investigation_id)
        listed = dossier.listed if dossier is not None and isinstance(dossier.listed, list) else []
        flagged |= {
            k for v in listed if (k := listed_key(v)) is not None and not _campus_key(ctx, k)
        }
        stored = row.flags if isinstance(row.flags, list) else []
        out[investigation_id] = Subject(
            investigation_id, int(row.version), frozenset(keys), destinations,
            frozenset(flagged), tuple(f for f in stored if isinstance(f, str)), services,
            _bytes(_signal(dossier.local_signals, dossier.signals, "proxy.bytes"))
            if dossier is not None else None,
            row.first_event_at, row.last_event_at, (row.severity or "medium").lower(),
        )  # fmt: skip
    return out


def _campus_key(ctx: Context, key: Key) -> bool:
    """A campus or private address: never a destination of a case, whatever a list says."""
    return key[0] == "ip" and ctx.classifier.classify(key[1]).ip_class is not IpClass.PUBLIC


def _outside(ctx: Context, key: Key) -> bool:
    """Whether an address or a name is outside the campus and says something about who is behind
    it (not a content-delivery or cloud network, not a name every investigation holds)."""
    kind, value = key
    if ctx.shared.reason(kind, value) is not None:
        return False
    if ctx.eligible is not None:
        return ctx.eligible.check(kind, value) is None
    if kind == "ip":
        return ctx.classifier.classify(value).ip_class is IpClass.PUBLIC
    return known.parent_of(value) is not None


# --------------------------------------------------------------------------- deciding

# an investigation names one of the case's devices: an entity equal to a device key, or an actor
# of its grouping key (the key is canonical JSON, each pair ``["name","value"]``)
_DEVICE_MATCH = (
    "(EXISTS (SELECT 1 FROM investigation_entities e WHERE e.investigation_id = i.id"
    "  AND (e.kind, e.value) IN (SELECT k, v FROM unnest(CAST(:kinds AS text[]),"
    "   CAST(:values AS text[])) AS u(k, v)))"
    " OR i.group_key LIKE ANY(CAST(:needles AS text[])))"
)
_UNDECIDED = (
    " AND NOT EXISTS (SELECT 1 FROM case_known_matches k WHERE k.investigation_id = i.id"
    "  AND k.version = i.version AND k.case_id = :c AND (k.outcome = 'changed'"
    "  OR rz.evaluated_at IS NULL OR k.decided_at >= rz.evaluated_at))"
    " AND NOT EXISTS (SELECT 1 FROM case_members m WHERE m.investigation_id = i.id"
    "  AND m.removed_at IS NULL AND m.case_id <> :c)"
    " AND NOT EXISTS (SELECT 1 FROM review_state s WHERE s.investigation_id = i.id"
    "  AND s.version = i.version AND s.action = 'reviewed')"
    " ORDER BY i.last_event_at DESC, i.id LIMIT :limit"
)
_FROM = (
    "SELECT i.id FROM investigations i LEFT JOIN investigation_raises rz"
    " ON rz.investigation_id = i.id AND rz.version = i.version"
    " WHERE i.last_event_at >= :since AND i.first_event_at <= :now"
)
_CANDIDATES = text(f"{_FROM} AND {_DEVICE_MATCH}{_UNDECIDED}")
# a moved address (D-169 point 6, D-181): the case's one device went quiet, and an investigation
# of an address the case does not hold began soon after, with the case's destinations
_MOVED = text(
    f"{_FROM} AND i.first_event_at >= :moved_from AND i.first_event_at <= :moved_to"  # noqa: S608
    f" AND NOT {_DEVICE_MATCH}"
    " AND (EXISTS (SELECT 1 FROM investigation_entities e WHERE e.investigation_id = i.id"
    "  AND (e.kind, e.value) IN (SELECT k, v FROM unnest(CAST(:dkinds AS text[]),"
    "   CAST(:dvalues AS text[])) AS u(k, v)))"
    "  OR (CAST(:suffixes AS text[]) <> '{}' AND EXISTS (SELECT 1 FROM investigation_entities e"
    "   WHERE e.investigation_id = i.id AND e.kind = 'domain'"
    "   AND e.value LIKE ANY(CAST(:suffixes AS text[])))))" + _UNDECIDED
)
_HELD = text("SELECT investigation_id FROM case_members WHERE case_id = :c AND removed_at IS NULL")
# the case version of the first owner notice since the last withdrawal, and the members linked
# at or before it whose activity ended by the notice's time: what the owner was told about (a
# notice recorded after the fact must not make later activity known)
_NOTICE_VERSION = text(
    "SELECT min(n.case_version) FROM case_notices n WHERE n.case_id = :c AND n.kind = 'owner'"  # noqa: S608
    f" AND {AFTER_WITHDRAWAL}"
)
_TOLD_ABOUT = text(
    "SELECT investigation_id FROM case_members WHERE case_id = :c AND removed_at IS NULL"
    " AND added_version <= :v AND investigation_id IN (SELECT id FROM investigations"
    "  WHERE last_event_at <= :at)"
)


def _like(value: str) -> str:
    return "%." + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _needle(value: str) -> str:
    """A LIKE pattern for a value inside a canonical grouping key (``,"value"]``)."""
    quoted = json.dumps(value, ensure_ascii=True)
    return "%," + quoted.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "]%"


async def candidates(
    conn: AsyncConnection, ctx: Context, case: Tracked, now: datetime,
    gone: Sequence[Gone] = (),
) -> list[uuid.UUID]:  # fmt: skip
    """The investigations to decide for a case: activity since the notice, one of the case's
    devices named (an entity or an actor of the grouping key: other devices that reach the same
    servers never use up ``per_pass``), and not decided at their current version (a "changed"
    decision stands for its version; a "known" one is looked at again when the evidence was read
    again after it), not in another case, not reviewed at their current version. Then, for a case
    that holds exactly one device that went quiet, a few investigations of other addresses that
    began soon after, with the case's destinations (a moved address: a separate small query)."""
    fp = case.fingerprint
    since = max(case.since, now - ctx.history)
    devices = sorted(fp.devices)
    rows = await conn.execute(
        _CANDIDATES,
        {
            "since": since, "now": now, "c": case.id,
            "kinds": [k for k, _ in devices], "values": [v for _, v in devices],
            "needles": [_needle(v) for _, v in devices], "limit": ctx.per_pass,
        },
    )  # fmt: skip
    ids = [r.id for r in rows]
    if case.stopped or fp.lone_address() is None or not gone:
        return ids
    wanted = sorted(fp.destinations)
    if not wanted and not fp.families:
        return ids
    last = gone[0].last_seen
    more = await conn.execute(
        _MOVED,
        {
            "since": since, "now": now, "c": case.id,
            "moved_from": last + ctx.rules.move_gap, "moved_to": last + ctx.rules.move_window,
            "kinds": [k for k, _ in devices], "values": [v for _, v in devices],
            "needles": [_needle(v) for _, v in devices],
            "dkinds": [k for k, _ in wanted], "dvalues": [v for _, v in wanted],
            "suffixes": sorted(_like(f) for f in fp.families), "limit": ctx.moved_per_pass,
        },
    )  # fmt: skip
    return ids + [r.id for r in more if r.id not in ids]


_UPSERT = text(
    "INSERT INTO case_known_matches (investigation_id, case_id, version, outcome, why,"
    " changed_version) VALUES (:i, :c, :v, :o, :w, :cv) ON CONFLICT (investigation_id)"
    " DO UPDATE SET case_id = EXCLUDED.case_id, version = EXCLUDED.version,"
    " outcome = EXCLUDED.outcome, why = EXCLUDED.why, changed_version = EXCLUDED.changed_version,"
    " decided_at = now()"
)
# what was decided before, and whether a person has reviewed a version of the investigation at or
# after the change (the same table the Inbox derives its states from)
_PRIOR = text(
    "SELECT k.investigation_id, k.outcome, k.why, k.changed_version, EXISTS (SELECT 1"
    " FROM review_state s WHERE s.investigation_id = k.investigation_id"
    " AND s.action = 'reviewed' AND s.version >= k.changed_version) AS reviewed"
    " FROM case_known_matches k WHERE k.investigation_id = ANY(:ids)"
).bindparams(bindparam("ids", type_=ARRAY(UUID)))


async def settled(
    conn: AsyncConnection, decisions: Sequence[Decision]
) -> dict[uuid.UUID, known.Settled]:
    """What to record for each decision, a change being durable (:func:`known.settle`)."""
    if not decisions:
        return {}
    ids = [d.subject.investigation_id for d in decisions]
    priors = {r.investigation_id: r for r in await conn.execute(_PRIOR, {"ids": ids})}
    out: dict[uuid.UUID, known.Settled] = {}
    for d in decisions:
        row = priors.get(d.subject.investigation_id)
        prior = (
            None if row is None
            else known.Prior(row.outcome, row.why, row.changed_version)
        )  # fmt: skip
        out[d.subject.investigation_id] = known.settle(
            prior, d.verdict, d.subject.version, reviewed=bool(row is not None and row.reviewed)
        )
    return out


_KEY = text(
    "INSERT INTO case_known_keys (case_id, kind, value, source) VALUES (:c, :k, :v, :s)"
    " ON CONFLICT DO NOTHING"
)


@dataclass
class Decision:
    subject: Subject
    verdict: known.Verdict
    new_address: Key | None = None  # a campus address the case does not hold yet (D-169 point 6)
    moved_from: str | None = None  # the old address, or the strong key it came with
    moved_hours: int = 0
    by_timing: bool = False  # the move rests on timing and indicators, not on a host name


@dataclass
class CaseResult:
    number: int
    known: int = 0
    changed: int = 0
    moved: int = 0
    kept: int = 0  # changes that stay changes (D-181): decided again, not yet reviewed
    unjudged: int = 0  # decisions made without a byte count for the data volume
    reminders: list[str] = field(default_factory=list)
    proposed: bool = False
    notes: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)  # an investigation or a link that failed

    @property
    def quiet(self) -> bool:
        return not (
            self.known or self.changed or self.moved or self.kept or self.reminders or self.proposed
        )


@dataclass
class Report:
    cases: list[CaseResult] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    def line(self) -> str:
        """One line for the log: what the pass did for each case it did something for."""
        parts = []
        for c in self.cases:
            if c.quiet:
                continue
            bits = [f"known {c.known}", f"changed {c.changed}"]
            if c.kept:
                bits.append(f"still changed {c.kept}")
            if c.moved:
                bits.append(f"moved {c.moved}")
            if c.reminders:
                bits.append("reminders " + "+".join(c.reminders))
            if c.proposed:
                bits.append("proposed closing")
            if c.unjudged:
                bits.append(f"volume not judged for {c.unjudged}")
            parts.append(f"case {c.number}: " + ", ".join(bits))
        return "known infections: " + ("; ".join(parts) if parts else "nothing new")


def _fresh_keys(fp: Print, decisions: Iterable[Decision]) -> list[tuple[str, str]]:
    """The keys a pass adds: what each change brought (it speaks once), the destinations that are
    new but not flagged (counted on the case, up to ``NEW_PER_CASE``), and the data level a
    change reached."""
    rows: dict[tuple[str, str], None] = {}
    for d in decisions:
        for row in d.verdict.adds.rows():
            rows[row] = None
    fresh = [r for r in rows if not _held(fp, r)]
    room = max(known.NEW_PER_CASE - len(fp.seen), 0)
    out = []
    for kind, value in fresh:
        if kind == known.NEW_DESTINATION:
            if room <= 0:
                continue
            room -= 1
        out.append((kind, value))
    return out


def _held(fp: Print, row: tuple[str, str]) -> bool:
    kind, value = row
    if kind == known.BYTES:
        return fp.bytes is not None and int(value) <= fp.bytes
    if kind == known.FLAG:
        return value in fp.flags
    if kind == known.FAMILY:
        return value in fp.families
    key = known.split(value)
    if kind == known.DESTINATION:
        return key in fp.destinations
    if kind == known.NEW_DESTINATION:
        return key in fp.seen or (key is not None and fp.knows(key))
    return key in fp.services if kind == known.SERVICE else False


async def seed(
    conn: AsyncConnection, ctx: Context, case: Tracked, now: datetime
) -> tuple[Print, int]:
    """Take the fingerprint's first set from what the case's investigations showed when the notice
    was recorded (the members linked at or before it and quiet since the notice's time: later
    ones, and members with activity after that time, are judged like any new investigation), and
    mark them known (they are what the owner was told about). Returns the
    fingerprint and how many were marked. Idempotent."""
    version = (await conn.execute(_NOTICE_VERSION, {"c": case.id})).scalar()
    members = list(
        (await conn.execute(_HELD, {"c": case.id})).scalars()
        if version is None
        else (
            await conn.execute(_TOLD_ABOUT, {"c": case.id, "v": version, "at": case.since})
        ).scalars()
    )
    seen = await subjects(conn, ctx, members, now)
    fp = case.fingerprint
    flags = {f for s in seen.values() for f in s.flags}
    services = {k for s in seen.values() for k in s.services if k not in fp.devices}
    flagged = {k for s in seen.values() for k in s.flagged if not fp.knows(k)}
    level = max((s.bytes for s in seen.values() if s.bytes is not None), default=None)
    reached = {
        k for s in seen.values() for k in s.destinations
        if k not in flagged and k not in s.flagged and not fp.counted(k)
    }  # fmt: skip
    rows: list[tuple[str, str]] = [(known.FLAG, f) for f in sorted(flags)]
    rows += [(known.SERVICE, known.join(k)) for k in sorted(services)]
    rows += [(known.DESTINATION, known.join(k)) for k in sorted(flagged)]
    rows += [(known.FAMILY, f) for f in sorted(known.families_of(flagged))]
    rows += [(known.NEW_DESTINATION, known.join(k)) for k in sorted(reached)[: known.NEW_PER_CASE]]
    if level:  # a level of 0 is "not judged"
        rows.append((known.BYTES, str(level)))
    rows.append((known.SEED, ""))
    for kind, value in rows:
        await conn.execute(_KEY, {"c": case.id, "k": kind, "v": value, "s": "notice"})
    decided = [
        Decision(subject, known.Verdict("known")) for subject in seen.values()
    ]  # the owner was told about them
    for decision, kept in zip(decided, (await settled(conn, decided)).values(), strict=True):
        await conn.execute(
            _UPSERT,
            {"i": decision.subject.investigation_id, "c": case.id,
             "v": decision.subject.version, "o": kept.outcome, "w": kept.why,
             "cv": kept.changed_version},
        )  # fmt: skip
    keys = [(str(r.kind), str(r.value)) for r in await conn.execute(_KEYS, {"c": case.id})]
    held = (await conn.execute(_INDICATORS, {"c": case.id})).all()
    fp = known.print_of(
        [(r.kind, r.value) for r in held if r.role == "actor"],
        [(r.kind, r.value) for r in held if r.role != "actor"],
        keys,
    )
    return fp, len(seen)


_GONE = text(
    "SELECT e.value AS device, max(i.last_event_at) AS last_seen FROM investigation_entities e"
    " JOIN investigations i ON i.id = e.investigation_id"
    " WHERE e.kind = 'ip' AND e.value = ANY(:devices) AND i.first_event_at <= :now"
    " GROUP BY e.value"
).bindparams(bindparam("devices", type_=ARRAY(Text)))
_REACHED = text(
    "SELECT d.value AS device, x.kind, x.value FROM investigation_entities d"
    " JOIN investigation_entities x ON x.investigation_id = d.investigation_id"
    " AND x.kind IN ('ip', 'domain') WHERE d.kind = 'ip' AND d.value = ANY(:devices)"
    " AND d.investigation_id IN (SELECT m.investigation_id FROM case_members m"
    "  WHERE m.case_id = :c AND m.removed_at IS NULL)"
).bindparams(bindparam("devices", type_=ARRAY(Text)))


async def gone_devices(
    conn: AsyncConnection, case: Tracked, fp: Print, now: datetime
) -> list[Gone]:
    """The case's addresses, when each was last seen and which of the case's destinations it
    reached (its indicator set)."""
    devices = sorted(v for k, v in fp.devices if k == "ip")
    if not devices:
        return []
    last = {r.device: r.last_seen for r in await conn.execute(_GONE, {"devices": devices,
                                                                      "now": now})}  # fmt: skip
    reached: dict[str, set[Key]] = defaultdict(set)
    for r in await conn.execute(_REACHED, {"devices": devices, "c": case.id}):
        key = (str(r.kind), str(r.value))
        if fp.knows(key):
            reached[r.device].add(key)
    return [Gone(("ip", d), last[d], frozenset(reached.get(d, ()))) for d in devices if d in last]


# the moves ARGUS noted on the case: the old address and when the new address first alerted
# (from the data: the earliest alert of the case's investigations that name the new address)
_MOVES = text(
    "SELECT e.details ->> 'old' AS old, min(i.first_event_at) AS since FROM case_events e"
    " JOIN case_members m ON m.case_id = e.case_id AND m.removed_at IS NULL"
    " JOIN investigation_entities x ON x.investigation_id = m.investigation_id"
    " AND x.kind = 'ip' AND x.value = e.details ->> 'new'"
    " JOIN investigations i ON i.id = m.investigation_id"
    " WHERE e.case_id = :c AND e.kind = 'address_moved' GROUP BY 1"
)


async def moved_addresses(conn: AsyncConnection, case: Tracked) -> dict[str, datetime]:
    """The addresses the case was moved from (an address, not a host name) and when the new one
    first alerted: an alert of the old one after that makes two devices (D-181)."""
    out: dict[str, datetime] = {}
    for r in await conn.execute(_MOVES, {"c": case.id}):
        if r.old is not None and r.since is not None and facts.canonical("ip", r.old) == r.old:
            out[str(r.old)] = r.since
    return out


_EARLIEST = datetime.min.replace(tzinfo=UTC)


def _severity(subject: Subject) -> Severity:
    return subject.severity if subject.severity in SEVERITIES else "medium"


def _fresh_addresses(ctx: Context, fp: Print, subject: Subject) -> list[Key]:
    """The campus addresses of an investigation that the case does not hold as devices (a
    university service is not one)."""
    extra = subject.devices - fp.devices - subject.services
    return sorted(k for k in extra if k[0] == "ip" and ctx.is_campus(k[1]))


def _again(case: Tracked, fp: Print, subject: Subject, rules: Rules) -> known.Verdict:
    """An investigation of a case closed as "stopped after notice": its device reaches the
    case's indicators, or brings something new: the infection is active again. It is a change,
    never joined to the closed case and never made known (a person decides what it is now)."""
    seen = known.evaluate(fp, subject, volume_factor=rules.volume_factor)
    if seen.outcome is None or case.closed_at is None:
        return known.Verdict(None)
    said = AGAIN.format(number=case.number, day=f"{case.closed_at:%d %b %Y}")
    return known.Verdict("changed", (said,), known.Adds(), seen.volume_judged)


def _two_devices(verdict: known.Verdict, back: Sequence[str]) -> known.Verdict:
    """A known or changed investigation in which an address that was moved from alerts again
    after the move (D-181): the case has two devices, not one that moved. It is a change."""
    said = tuple(f"two devices: {old} active again after the move" for old in back)
    return known.Verdict("changed", (*said, *verdict.changes), verdict.adds, verdict.volume_judged)


def _moved(
    ctx: Context, fp: Print, subject: Subject, gone: Sequence[Gone]
) -> Decision | None:  # fmt: skip
    """The same device from a new address (D-169 point 6, D-181), and only for a case that holds
    exactly one device (one address): the investigation lists one campus address the case does
    not hold and nothing else it does not (a host or user key of another machine, a second
    address, makes it another device: the suggester offers it). Then either it carries the host
    name the case holds (a stronger key than any timing), or it began soon after the case's
    device went quiet, with the same set of the case's destinations
    (:func:`argus.cases.known.moved`). A user shared with another machine is no key."""
    if fp.lone_address() is None:
        return None
    fresh = _fresh_addresses(ctx, fp, subject)
    extra = subject.devices - fp.devices - subject.services
    if len(fresh) != 1 or extra != {fresh[0]}:
        return None
    held = subject.devices & fp.devices
    if any(k[0] == "ip" for k in held):  # the old address is in it too: two devices, not a move
        return None
    grown = replace(fp, devices=fp.devices | {fresh[0]})
    hosts = sorted(k for k in held if k[0] == "host")
    if hosts:
        verdict = known.evaluate(grown, subject, volume_factor=ctx.rules.volume_factor)
        if verdict.outcome is None:
            return None
        return Decision(subject, verdict, fresh[0], f"host {hosts[0][1]}", 0)
    if held or subject.first_event_at is None:
        return None
    reached = frozenset(k for k in subject.destinations if fp.knows(k))
    old = known.moved(subject.first_event_at, reached, gone, ctx.rules)
    if old is None:
        return None
    hours = int((subject.first_event_at - old.last_seen).total_seconds() // 3600)
    verdict = known.evaluate(grown, subject, volume_factor=ctx.rules.volume_factor)
    if verdict.outcome is None:  # it reaches the case's destinations: it is at least known
        verdict = known.Verdict("known", (), known.Adds(), verdict.volume_judged)
    return Decision(subject, verdict, fresh[0], old.device[1], hours, by_timing=True)


def _decide_one(
    ctx: Context, case: Tracked, fp: Print, subject: Subject, gone: Sequence[Gone],
    moves: Mapping[str, datetime],
) -> Decision | None:  # fmt: skip
    if case.stopped:
        verdict = _again(case, fp, subject, ctx.rules)
        return None if verdict.outcome is None else Decision(subject, verdict)
    verdict = known.evaluate(fp, subject, volume_factor=ctx.rules.volume_factor)
    if verdict.outcome is None:
        return _moved(ctx, fp, subject, gone)
    back = known.resurfaced(subject, moves)
    return Decision(subject, _two_devices(verdict, back) if back else verdict)


def decide(
    ctx: Context, case: Tracked, fp: Print, found: Mapping[uuid.UUID, Subject],
    gone: Sequence[Gone], moves: Mapping[str, datetime] | None = None,
) -> tuple[list[Decision], list[str]]:  # fmt: skip
    """A decision for each investigation that is the case's (known or changed, or the same
    device from a new address), and the problems met: one investigation that cannot be read is a
    problem said and left, never the end of the case's pass. ``moves``: the old addresses of the
    case's moves and when the new address first alerted."""
    out: list[Decision] = []
    problems: list[str] = []
    ordered = sorted(found.values(), key=lambda s: (s.last_event_at or _EARLIEST,
                                                    str(s.investigation_id)))  # fmt: skip
    for subject in ordered:
        try:
            decision = _decide_one(ctx, case, fp, subject, gone, moves or {})
        except Exception as exc:  # one investigation never fails the others
            problems.append(f"investigation {subject.investigation_id}: {type(exc).__name__}")
            log.warning("known infection of case %s: investigation %s failed: %s",
                        case.number, subject.investigation_id, type(exc).__name__)  # fmt: skip
            continue
        if decision is not None:
            out.append(decision)
    # Two new addresses that both fit the one device that went quiet are never guessed between
    # (D-181): neither is a move, and the suggester offers them.
    guesses = {d.new_address for d in out if d.by_timing}
    if len(guesses) > 1:
        log.info("known infection of case %s: %d new addresses fit the device that went quiet;"
                 " none is taken as it", case.number, len(guesses))  # fmt: skip
        out = [d for d in out if not d.by_timing]
    return out, problems


async def _join(
    conn: AsyncConnection, service: CaseService, case: Tracked, decisions: Sequence[Decision],
    result: CaseResult,
) -> set[uuid.UUID]:  # fmt: skip
    """Put the decided investigations into the case (silent links, and a note for each moved
    address), in savepoints so that a refusal loses only its own. Returns the ones that are in
    the case now."""
    current = await service.get(case.id, lock=True)
    assert current is not None
    held = set(current.members)
    moves: dict[Key, list[Decision]] = defaultdict(list)
    rest = []
    for d in decisions:
        if d.new_address is not None:
            moves[d.new_address].append(d)
        elif d.subject.investigation_id not in held:
            rest.append(d)
    for address, group in sorted(moves.items()):
        first = group[0]
        shown = f"{first.moved_from} to {address[1]}"
        if first.moved_hours:
            gap = f"{first.moved_hours} hours after the old address went quiet"
        else:
            gap = "the same host name or user"
        said = f"probably the same device, new address ({shown}; {gap})"
        members = tuple(
            Member(d.subject.investigation_id, "actor", address[1])
            for d in group
            if d.subject.investigation_id not in held
        )
        try:
            async with conn.begin_nested():
                await service.apply(
                    ACTOR, case.id,
                    AddressMoved(str(first.moved_from), address[1], first.moved_hours, said,
                                 members, (Indicator("ip", address[1], "actor", "investigation"),),
                                 None),
                    expected_version=None,
                )  # fmt: skip
        except CaseRefused as exc:
            result.notes.append(f"moved address not noted: {exc.message}")
            continue
        except DBAPIError as exc:
            result.problems.append(f"moved address {address[1]} not noted: {type(exc).__name__}")
            continue
        held |= {m.investigation_id for m in members}
        result.moved += 1
    for start in range(0, len(rest), CHUNK):
        part = [d for d in rest[start : start + CHUNK] if d.subject.investigation_id not in held]
        if not part:
            continue
        refused = await _link(conn, service, case, part)
        if refused is None:
            held |= {d.subject.investigation_id for d in part}
            continue
        if len(part) == 1:
            result.problems.append(f"investigation {part[0].subject.investigation_id} not joined:"
                                   f" {refused}")  # fmt: skip
            continue
        # a refused chunk is tried one by one: a bad investigation loses only itself
        for d in part:
            alone = await _link(conn, service, case, [d])
            if alone is None:
                held.add(d.subject.investigation_id)
            else:
                result.problems.append(
                    f"investigation {d.subject.investigation_id} not joined: {alone}"
                )
    return held


async def _link(
    conn: AsyncConnection, service: CaseService, case: Tracked, part: Sequence[Decision]
) -> str | None:  # fmt: skip
    """A silent link of the investigations in ``part`` (with the destinations the changes among
    them brought) in a savepoint; None when it was made, else why it was refused."""
    marks: dict[tuple[str, str], Indicator] = {}
    for d in part:
        for kind, value in sorted(d.verdict.adds.destinations)[:20]:
            if len(marks) >= MARKS_PER_CHUNK:
                break
            marks.setdefault(
                (kind, value),
                Indicator(kind, value, "indicator", "investigation"),  # type: ignore[arg-type]
            )
    severe = [d for d in part if d.verdict.outcome == "changed"]
    top = max((SEVERITIES.index(_severity(d.subject)) for d in severe), default=None)
    try:
        async with conn.begin_nested():
            await service.apply(
                ACTOR, case.id,
                Link(tuple(Member(d.subject.investigation_id, "actor", None) for d in part),
                     tuple(marks.values()), None if top is None else SEVERITIES[top]),
                expected_version=None,
            )  # fmt: skip
    except CaseRefused as exc:
        return exc.message
    except DBAPIError as exc:  # a value the table refuses: only its own link is lost
        return type(exc).__name__
    return None


async def apply_decisions(
    engine: AsyncEngine, case: Tracked, decisions: Sequence[Decision], result: CaseResult
) -> None:  # fmt: skip
    """Write the decisions in one transaction under the opener's lock: the silent links and the
    notes on the case, the rows that say what ARGUS decided, and what the changes brought."""
    if not decisions:
        return
    async with engine.begin() as conn:
        await conn.execute(text("SELECT pg_advisory_xact_lock(:k)"),
                           {"k": opener.OPENER_LOCK_KEY})  # fmt: skip
        service = await CaseService.start(conn)
        if case.stopped:
            held = {d.subject.investigation_id for d in decisions}
        else:
            current = await service.get(case.id, lock=True)
            if (
                current is None
                or current.notified_at is None
                or current.state not in ("open", "assigned")
            ):  # the case changed since the pass began: nothing is written
                return
            held = await _join(conn, service, case, decisions, result)
        done = [d for d in decisions if d.subject.investigation_id in held]
        kept = await settled(conn, done)
        for d in done:
            then = kept[d.subject.investigation_id]
            await conn.execute(
                _UPSERT,
                {"i": d.subject.investigation_id, "c": case.id, "v": d.subject.version,
                 "o": then.outcome, "w": then.why, "cv": then.changed_version},
            )  # fmt: skip
            if then.outcome == "known":
                result.known += 1
            elif d.verdict.outcome == "changed":
                result.changed += 1
            else:  # decided known again while its change waits for a person: it stays a change
                result.kept += 1
        if not case.stopped:
            for kind, value in _fresh_keys(case.fingerprint, done):
                await conn.execute(_KEY, {"c": case.id, "k": kind, "v": value, "s": "change"})
        result.unjudged += sum(1 for d in done if not d.verdict.volume_judged)


# --------------------------------------------------------------------------- reminders and ending

_ACTIVITY = text(
    "SELECT max(i.last_event_at) FROM case_members m JOIN investigations i"
    " ON i.id = m.investigation_id WHERE m.case_id = :c AND m.removed_at IS NULL"
    " AND i.last_event_at > :since AND i.first_event_at <= :now"
)
_NOTICES = text(
    "SELECT count(*) FROM case_notices n WHERE n.case_id = :c AND n.kind = 'owner'"  # noqa: S608
    f" AND {AFTER_WITHDRAWAL}"
)
_REMIND = text(
    "INSERT INTO case_reminders (case_id, kind, why) VALUES (:c, :k, :w)"
    " ON CONFLICT (case_id, kind) DO NOTHING"
)
# A proposal at the case's current version is asked: it is waiting (its expiry is ahead of the
# database's clock) or a person answered it. One that expired unanswered is not, so the proposal
# is made again on a later pass (D-181: keyed by the expiry, not only by the case version).
_ASKED = text(
    "SELECT 1 FROM approval_requests r JOIN cases c ON c.id = r.case_id"
    " WHERE r.case_id = :c AND r.case_version = c.version AND (r.expires_at > now()"
    " OR EXISTS (SELECT 1 FROM approval_decisions d WHERE d.request_id = r.id))"
)


def reminder_words(kind: str, notified_at: datetime, now: datetime) -> str:
    days = (now - notified_at).days
    if kind == "notify_again":
        return site.say(
            f"Still active {days} days after the owner was told: consider telling the owner"
            " again, and the {units2} contact."
        )
    return (
        f"Still active {days} days after the owner was told: consider asking for network-side"
        " action. The case's block list is ready."
    )


def stop_words(case: Tracked, rules: Rules) -> str:
    assert case.notified_at is not None
    return (
        f"no matching activity for {rules.quiet_days} days since the owner was told"
        f" ({case.notified_at:%Y-%m-%d} UTC)"
    )


async def housekeeping(
    engine: AsyncEngine, ctx: Context, case: Tracked, now: datetime, result: CaseResult
) -> None:  # fmt: skip
    """The reminders a still-active case earns and, for one that went quiet, the proposal to close
    it as "stopped after notice" (a person approves it)."""
    assert case.notified_at is not None
    async with engine.connect() as conn:
        activity = (
            await conn.execute(_ACTIVITY, {"c": case.id, "since": case.notified_at, "now": now})
        ).scalar_one()
        notices = int((await conn.execute(_NOTICES, {"c": case.id})).scalar_one())
        asked = (await conn.execute(_ASKED, {"c": case.id})).first() is not None
    wanted = known.reminders(
        now, case.notified_at, notices, case.blocked_at is not None, activity, ctx.rules
    )
    if wanted:
        async with engine.begin() as conn:
            for kind in wanted:
                words = reminder_words(kind, case.notified_at, now)
                done = await conn.execute(_REMIND, {"c": case.id, "k": kind, "w": words})
                if done.rowcount:
                    result.reminders.append(kind)
    if known.stopped(now, case.notified_at, activity, ctx.rules) and not asked:
        async with engine.begin() as conn:
            service = await CaseService.start(conn)
            current = await service.get(case.id)  # the pass's own links moved the version on
            if current is None or current.notified_at is None:
                return
            candidate = proposer.Candidate(
                case.id, case.number, current.version, "stopped_after_notice",
                stop_words(case, ctx.rules),
            )  # fmt: skip
            proposed = await proposer.propose(service, candidate)
        if proposed.request_id is not None:
            result.proposed = True
        else:
            result.notes.append(f"closing not proposed: {proposed.refused}")


# --------------------------------------------------------------------------- a pass


async def _case(
    engine: AsyncEngine, ctx: Context, case: Tracked, now: datetime, result: CaseResult
) -> None:  # fmt: skip
    if not case.stopped and not case.seeded:
        async with engine.begin() as conn:
            await conn.execute(text("SELECT pg_advisory_xact_lock(:k)"),
                               {"k": opener.OPENER_LOCK_KEY})  # fmt: skip
            fp, marked = await seed(conn, ctx, case, now)
        case = replace(case, fingerprint=fp, seeded=True)
        result.known += marked
    async with engine.connect() as conn:
        gone = [] if case.stopped else await gone_devices(conn, case, case.fingerprint, now)
        moves = {} if case.stopped else await moved_addresses(conn, case)
        ids = await candidates(conn, ctx, case, now, gone)
        found = await subjects(conn, ctx, ids, now)
    decisions, problems = decide(ctx, case, case.fingerprint, found, gone, moves)
    result.problems.extend(problems)
    await apply_decisions(engine, case, decisions, result)
    if not case.stopped:
        await housekeeping(engine, ctx, case, now, result)


async def run(engine: AsyncEngine, ctx: Context, now: datetime) -> Report:
    """One pass over every case the infection is tracked for. A case's failure is a problem in the
    report; the others go on."""
    report = Report()
    async with engine.connect() as conn:
        cases = await tracked(conn, ctx, now)
    for case in cases:
        result = CaseResult(case.number)
        report.cases.append(result)
        try:
            await _case(engine, ctx, case, now, result)
        except Exception as exc:  # one case's failure leaves the others to run
            report.problems.append(f"case {case.number}: {type(exc).__name__}")
            log.warning("known infection of case %s failed: %s", case.number, type(exc).__name__)
        report.problems.extend(f"case {case.number}: {p}" for p in result.problems)
    return report
