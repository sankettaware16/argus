"""Case titles from the database (D-230): the facts of a case, its title, and the pass that keeps
ARGUS's own titles current.

:mod:`argus.cases.naming` makes a title from :class:`~argus.cases.naming.Facts`; this module reads
them from ARGUS's own database (never the SIEM): the member investigations' rule names, evidence
flags and threat-listed values, the case's indicators, the outside answers cached for them, the
campus web sites the investigations name, and whether a stored web check showed a config or backup
file served. :func:`facts_of` is the pure part, so the reading is testable without a database.

**Who wrote a title.** The actor of the newest ``suspected``, ``opened`` or ``retitled`` case
event. ARGUS refreshes (:func:`refresh`) the titles it wrote when the new title differs, as
``argus:title``, and never one a person wrote or set (``argus case retitle``): the service refuses
it. New cases get their title from the same facts before they exist (:func:`for_members`), so the
first title is the one the refresh would keep. A case with no facts to say anything from (a merged
case holds no investigations) keeps its title.
"""

from __future__ import annotations

import ipaddress
import re
import uuid
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from functools import lru_cache
from typing import Any

from sqlalchemy import Text, bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus import site
from argus.assess import raised
from argus.assets.classify import IpClass, IpClassifier
from argus.cases import naming
from argus.cases.machine import CaseRefused, Retitle
from argus.cases.model import Actor, Indicator
from argus.cases.service import CaseService
from argus.outside import facts as outside_facts

PART = "title"  # ARGUS acts as ``argus:title``
MAX_PER_PASS = 100  # titles one pass changes (the rest wait for the next pass)
MEMBERS_READ = 600  # investigations of a case that are read
INDICATORS_READ = 1500
SITES_READ = 500
OUTSIDE_READ = 1500
CAMPUS = frozenset({IpClass.ASSET, IpClass.CAMPUS, IpClass.INTERNAL})
_PRIVATE = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)


@lru_cache(maxsize=1)
def _policy_domains() -> tuple[str, ...]:
    from argus.llm.privacy import load_policy

    return load_policy(require_domains=False).campus_domains  # sends nothing to a model


def default_campus_domains() -> tuple[str, ...]:
    """The organisation's own domains: ``site.own_domains``, and the extra ones the privacy
    policy (``config/llm_data_policy.yaml``) lists."""
    return site.own_domains(_policy_domains())


@dataclass(frozen=True)
class Context:
    """What the reading needs besides the database: the asset map's classes (a campus address, and
    the place the asset map names it in) and the campus domains (a campus web site)."""

    classifier: IpClassifier | None = None
    campus_domains: tuple[str, ...] = field(default_factory=default_campus_domains)


@dataclass(frozen=True)
class Found:
    """What the database holds for a case (or for the investigations and indicators of a case about
    to open): the stuff :func:`facts_of` turns into naming's facts."""

    members: Sequence[tuple[str, Sequence[str], Sequence[str]]] = ()  # rule, flags, listed
    indicators: Sequence[tuple[str, str, str]] = ()  # kind, value, role
    outside: Sequence[tuple[str, str, str, str, Mapping[str, Any]]] = ()  # source, kind, value,
    # status, answer: the newest first
    sites: Sequence[str] = ()  # campus domains the investigations name, the commonest first
    served: bool = False
    follows: int = 0  # the number of the closed case this one follows (0: none)


# --------------------------------------------------------------------------- the pure part


def _campus(value: str, classifier: IpClassifier | None) -> bool:
    if classifier is not None:
        return classifier.classify(value).ip_class in CAMPUS
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(address.version == n.version and address in n for n in _PRIVATE)


def _device(value: str, kind: str, classifier: IpClassifier | None) -> naming.Device:
    """A campus device with the place and kind of site the asset map gives its network."""
    if classifier is None or kind != "ip":
        return naming.Device(value, kind)
    match = classifier.classify(value).asset
    if match is None:
        return naming.Device(value, kind)
    types = {e.fields.get("site.type") for e in match.entries}
    places = {e.fields.get("site.building") or e.fields.get("site.department")
              for e in match.entries}  # fmt: skip
    return naming.Device(
        value, kind,
        next(iter(types)) if len(types) == 1 else None,
        next(iter(places)) if len(places) == 1 else None,
    )  # fmt: skip


def _labels(answer: Mapping[str, Any]) -> list[str]:
    """The words an outside answer may name a family in: its tags, and a family or a threat label
    if the answer holds one."""
    out: list[str] = []
    for key in ("family", "threat_label", "malware"):
        value = answer.get(key)
        if isinstance(value, str):
            out.append(value)
    tags = answer.get("tags")
    out += [t for t in tags if isinstance(t, str)] if isinstance(tags, list) else []
    return out


def facts_of(found: Found, ctx: Context) -> naming.Facts:
    """The title's facts from what the database holds (pure)."""
    classifier = ctx.classifier
    rules = Counter(rule for rule, _, _ in found.members if rule)
    flags = frozenset(f for _, flagged, _ in found.members for f in flagged)
    listed = tuple(sorted({v for _, _, values in found.members for v in values}))
    devices: list[naming.Device] = []
    outsiders: list[str] = []
    accounts = 0
    others: list[tuple[str, str, str]] = []
    for kind, value, role in found.indicators:
        if role == "actor":
            if kind == "user":
                accounts += 1
            elif kind == "host" or (kind == "ip" and _campus(value, classifier)):
                devices.append(_device(value, kind, classifier))
            elif kind == "ip":
                outsiders.append(value)
        else:
            others.append((kind, value, role))
    answers: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    flagged_values: list[str] = []
    newest: set[tuple[str, str, str]] = set()
    for source, kind, value, status, answer in found.outside:  # the newest answer first
        if (source, kind, value) in newest:
            continue
        newest.add((source, kind, value))
        answers.setdefault((kind, value), []).append(answer)
        if outside_facts.flagged(source, status, answer, outside_facts.DEFAULT_THRESHOLD):
            flagged_values.append(value)
    c2 = sorted(value for kind, value, role in others if role == "c2" and kind in ("ip", "domain"))
    held = {value for kind, value, _ in others if kind in ("ip", "domain")}
    servers = list(dict.fromkeys([*c2, *sorted(v for v in flagged_values if v in held)]))
    servers = [v for v in servers if not _campus(v, classifier)]
    servers += [v for v in listed if v in held and v not in servers and v not in set(outsiders)
                and not _campus(v, classifier)]  # fmt: skip
    campus_domains = ctx.campus_domains
    names = sorted({v for k, v, role in others if k == "domain" and role != "c2"})
    sites = list(found.sites)
    sites += [v for v in names if _is_campus_domain(v, campus_domains) and v not in sites]
    campus_servers = sum(
        1 for kind, value, role in others
        if kind == "ip" and role != "c2" and _campus(value, classifier)
    )  # fmt: skip
    labels = [
        label
        for value in (*servers, *outsiders)
        for kind in ("ip", "domain")
        for answer in answers.get((kind, value), ())
        for label in _labels(answer)
    ]
    return naming.Facts(
        rules=tuple(sorted(rules.items(), key=lambda kv: (-kv[1], kv[0]))),
        flags=flags,
        devices=tuple(devices),
        outsiders=tuple(sorted(set(outsiders))),
        accounts=accounts,
        servers=tuple(servers),
        domains=tuple(n for n in names if not _is_campus_domain(n, campus_domains)),
        sites=tuple(sites),
        campus_servers=campus_servers,
        listed=listed,
        served=found.served,
        labels=tuple(labels),
        follows=found.follows,
        probed=naming.probed(v for k, v, role in others if k == "url"),
    )


def _is_campus_domain(name: str, domains: Iterable[str]) -> bool:
    low = name.lower().rstrip(".")
    return any(low == d or low.endswith("." + d) for d in domains)


def title_of(found: Found, ctx: Context) -> str | None:
    """The title the facts give, or None when they have nothing to say (no investigation, no
    indicator): the case keeps the title it has."""
    if not found.members and not found.indicators:
        return None
    facts = facts_of(found, ctx)
    if naming.title(replace(facts, follows=0)) == naming.EMPTY:
        return None  # nothing to say: the title stays
    return naming.title(facts)


# --------------------------------------------------------------------------- reading

_IDS = bindparam("ids", type_=ARRAY(UUID(as_uuid=True)))
_MEMBERS = text(
    "SELECT coalesce(i.rule_name, i.rule_id) AS rule, r.flags, d.local_signals, d.signals,"
    " d.listed FROM investigations i LEFT JOIN investigation_raises r"
    " ON r.investigation_id = i.id AND r.version = i.version"
    " LEFT JOIN LATERAL (SELECT body -> 'local_signals' AS local_signals,"
    "  body -> 'signals' AS signals, body #> '{context,pack,ti,listed}' AS listed"
    "  FROM dossiers WHERE investigation_id = i.id ORDER BY version DESC, created_at DESC"
    "  LIMIT 1) d ON true"
    " WHERE i.id = ANY(:ids) ORDER BY i.first_event_at NULLS LAST, i.id LIMIT :n"
).bindparams(_IDS)
_OUTSIDE = text(
    "SELECT source, kind, indicator, status, answer FROM outside_lookups"
    " WHERE status IN ('found', 'not_found') AND ((kind = 'ip' AND indicator = ANY(:ips))"
    " OR (kind = 'domain' AND indicator = ANY(:domains))) ORDER BY fetched_at DESC LIMIT :n"
).bindparams(bindparam("ips", type_=ARRAY(Text)), bindparam("domains", type_=ARRAY(Text)))
_SITES = text(
    "SELECT e.value FROM investigation_entities e WHERE e.investigation_id = ANY(:ids)"
    " AND e.kind = 'domain' AND e.value ~* :campus GROUP BY e.value"
    " ORDER BY count(*) DESC, e.value LIMIT :n"
).bindparams(_IDS)
_SERVED = (
    "SELECT e.params, e.snapshot FROM evidence e WHERE e.investigation_id = ANY(:ids)"
    " AND e.template = 'web.path_outcomes' AND e.status IN ('ok', 'empty')"
    " AND e.snapshot IS NOT NULL ORDER BY e.collected_at {order}, e.task_key LIMIT :n"
)
SERVED_READ = 50  # stored web checks read: the first and the newest


def _strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(v for v in value if isinstance(v, str))


def _flags_of(row: Any) -> tuple[str, ...]:
    """An investigation's evidence flags: the ones stored for its current version (the outside
    detections are added there), and the ones its newest dossier's signals give. Raising skips a
    reviewed investigation, so a case a person's verdict opened has the dossier's alone."""
    return tuple(
        dict.fromkeys([*_strings(row.flags), *raised.flags_of(row.local_signals, row.signals)])
    )


def _campus_pattern(domains: Iterable[str]) -> str:
    return r"(^|\.)(" + "|".join(re.escape(d) for d in domains) + r")$" if domains else "$^"


async def _served(conn: AsyncConnection, ids: Sequence[uuid.UUID]) -> bool:
    """Whether a stored web check of these investigations shows a config or backup file served
    (the responder's fact ``sensitive_file_served``, from the first and the newest answers)."""
    from argus.context import paths
    from argus.responder import facts as responder_facts

    served: list[str] = []
    for order in ("ASC", "DESC"):
        statement = text(_SERVED.format(order=order)).bindparams(_IDS)
        for row in await conn.execute(statement, {"ids": list(ids), "n": SERVED_READ}):
            asked = row.params.get("paths") if isinstance(row.params, Mapping) else None
            served += [
                o.path
                for o in responder_facts.outcomes_of(row.snapshot, asked)
                if o.outcome == paths.SUCCESS
            ]
    return "sensitive_file_served" in responder_facts.from_parts([], [], served).present


async def read(
    conn: AsyncConnection, members: Sequence[uuid.UUID],
    indicators: Iterable[tuple[str, str, str]], ctx: Context,
) -> Found:  # fmt: skip
    """What the database holds for these investigations and indicators (bounded statements, ARGUS's
    own tables only)."""
    ids = list(members)[:MEMBERS_READ]
    held = list(indicators)[:INDICATORS_READ]
    rows = (await conn.execute(_MEMBERS, {"ids": ids, "n": MEMBERS_READ})).all() if ids else []
    found_members = [
        (str(r.rule or ""), _flags_of(r), _strings(r.listed)) for r in rows
    ]  # fmt: skip
    ips = sorted({v for k, v, r in held if k == "ip" and r != "actor"})
    domains = sorted({v for k, v, r in held if k == "domain"})
    outside: list[tuple[str, str, str, str, Mapping[str, Any]]] = []
    if ips or domains:
        outside = [
            (r.source, r.kind, r.indicator, r.status,
             r.answer if isinstance(r.answer, Mapping) else {})
            for r in await conn.execute(
                _OUTSIDE, {"ips": ips, "domains": domains, "n": OUTSIDE_READ}
            )
        ]  # fmt: skip
    sites: list[str] = []
    served = False
    if ids:
        pattern = _campus_pattern(ctx.campus_domains)
        sites = [
            str(v) for v in (await conn.execute(
                _SITES, {"ids": ids, "campus": pattern, "n": SITES_READ}
            )).scalars()
        ]  # fmt: skip
        served = await _served(conn, ids)
    return Found(found_members, held, outside, sites, served)


async def for_case(conn: AsyncConnection, case_id: uuid.UUID, ctx: Context) -> str | None:
    """The title the case's facts give now (None when it holds nothing to name)."""
    members = (
        await conn.execute(
            text("SELECT investigation_id FROM case_members WHERE case_id = :c"
                 " AND removed_at IS NULL"), {"c": case_id},
        )
    ).scalars().all()  # fmt: skip
    marks = [
        (str(r.kind), str(r.value), str(r.role))
        for r in await conn.execute(
            text("SELECT kind, value, role FROM case_indicators WHERE case_id = :c"
                 " AND removed_at IS NULL ORDER BY role, kind, value"), {"c": case_id},
        )
    ]  # fmt: skip
    found = await read(conn, list(members), marks, ctx)
    parent = await conn.scalar(
        text("SELECT p.number FROM cases c JOIN cases p ON p.id = c.parent_case_id"
             " WHERE c.id = :c"), {"c": case_id},
    )  # fmt: skip
    return title_of(replace(found, follows=int(parent or 0)), ctx)


async def for_members(
    conn: AsyncConnection, members: Sequence[uuid.UUID], indicators: Iterable[Indicator],
    ctx: Context, fallback: str, follows: uuid.UUID | None = None,
) -> str:  # fmt: skip
    """The title of a case about to open with these investigations and indicators (``fallback``
    when they give none); ``follows``: the closed case it follows."""
    marks = [(i.kind, i.value, i.role) for i in indicators]
    found = await read(conn, members, marks, ctx)
    if follows is not None:
        number = await conn.scalar(text("SELECT number FROM cases WHERE id = :p"), {"p": follows})
        found = replace(found, follows=int(number or 0))
    return title_of(found, ctx) or fallback


# --------------------------------------------------------------------------- the pass

_CASES = text(
    "SELECT c.id, c.number, c.title, c.state, coalesce((SELECT e.actor_user_id IS NOT NULL"
    " FROM case_events e WHERE e.case_id = c.id AND e.kind IN ('suspected', 'opened', 'retitled')"
    " ORDER BY e.case_version DESC LIMIT 1), false) AS by_person FROM cases c"
    " WHERE (:everything OR c.state <> 'closed') AND (CAST(:only AS uuid) IS NULL OR c.id = :only)"
    " ORDER BY c.number"
)


@dataclass(frozen=True)
class Change:
    case_id: uuid.UUID
    number: int
    old: str
    new: str


@dataclass
class Report:
    looked: int = 0
    kept: int = 0  # cases whose title a person wrote: left alone
    changes: list[Change] = field(default_factory=list)  # titles that differ (applied or not)
    applied: int = 0
    skipped: list[str] = field(default_factory=list)

    def line(self) -> str:
        return (f"titles: looked {self.looked}, a person's {self.kept}, changed {self.applied}"
                f" of {len(self.changes)}")  # fmt: skip


async def refresh(
    engine: AsyncEngine, ctx: Context, *, dry_run: bool = False, everything: bool = False,
    only: uuid.UUID | None = None, limit: int = MAX_PER_PASS,
) -> Report:  # fmt: skip
    """Make ARGUS's titles current. The cases that are not closed (``everything``: every case, a
    closed one too), the titles a person wrote left alone; for each other, the title its facts give
    now, and when it differs, a ``retitled`` event as ``argus:title`` (unless ``dry_run``). At
    most ``limit`` titles change in one call. A failure on one case is said and the rest go on."""
    report = Report()
    async with engine.connect() as conn:
        cases = (await conn.execute(_CASES, {"everything": everything, "only": only})).all()
    actor = Actor.argus(PART)
    for case in cases:
        report.looked += 1
        if case.by_person:
            report.kept += 1
            continue
        if len(report.changes) >= limit:
            continue
        try:
            async with engine.connect() as conn:
                new = await for_case(conn, case.id, ctx)
        except DBAPIError as exc:
            report.skipped.append(f"case {case.number}: read failed ({_state(exc)})")
            continue
        if new is None or new == naming.EMPTY or new == case.title:
            continue
        change = Change(case.id, int(case.number), case.title, new)
        report.changes.append(change)
        if dry_run:
            continue
        try:
            async with engine.begin() as conn:
                service = await CaseService.start(conn)
                await service.apply(actor, case.id, Retitle(new), expected_version=None)
        except CaseRefused as exc:
            report.skipped.append(f"case {case.number}: {exc.message}")
            continue
        except DBAPIError as exc:
            report.skipped.append(f"case {case.number}: refused by the database ({_state(exc)})")
            continue
        report.applied += 1
    return report


def _state(exc: DBAPIError) -> str:
    return str(getattr(exc.orig, "sqlstate", None))
