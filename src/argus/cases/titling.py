"""Case titles from the database: the facts of a case, its title, and the pass that keeps ARGUS's
own titles current. :mod:`argus.cases.naming` makes a title from its facts; this module reads them
from ARGUS's own database (:func:`facts_of` is the pure part): which device did what (the members'
entities and evidence flags), the stored web checks (the sites a follow-up names, its 2xx answers,
the path checks), the verdicts (people's reviews and decisions, ARGUS's proposals and readings),
the threat names ARGUS stores, and the earlier case a server belongs to. No log is read.

ARGUS refreshes (:func:`refresh`) the titles it wrote, as ``argus:title``, and never one a person
wrote or set (``argus case retitle``), and only on a material change (:func:`material`): the
words or the certainty changed, a count shrank or grew by half, or a count-only change waited
:data:`COALESCE`. New cases get their title from the same facts before they exist
(:func:`for_members`); a case with no facts to say anything from keeps its title."""

from __future__ import annotations

import ipaddress
import re
import uuid
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from types import MappingProxyType
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
from argus.normalize.fields import values as field_values
from argus.outside import facts as outside_facts

PART = "title"  # ARGUS acts as ``argus:title``
MAX_PER_PASS = 100  # titles one pass changes (the rest wait for the next pass)
MEMBERS_READ = 600  # investigations of a case that are read
INDICATORS_READ = 1500
ENTITIES_READ = 6000
SITES_READ = 500
OUTSIDE_READ = 1500
ASSESSMENTS_READ = 1200
CHECKS_READ = 50  # stored web checks of each kind read: the first and the newest
COALESCE = naming.COALESCE  # a count-only change waits this long after the last title change
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
    """What the reading needs besides the database: the asset map's classes (an internal address,
    and the place the asset map names it in) and the internal domains (an internal web site)."""

    classifier: IpClassifier | None = None
    campus_domains: tuple[str, ...] = field(default_factory=default_campus_domains)


@dataclass(frozen=True)
class Member:
    """One investigation of a case, as the title reads it."""

    rule: str
    flags: Sequence[str] = ()  # ARGUS's evidence flags
    listed: Sequence[str] = ()  # the values a threat list holds
    entities: Sequence[tuple[str, str]] = ()  # (kind, value): the addresses and names it names
    threats: Sequence[str] = ()  # the threat names stored with its threat-list hits
    reviewed: str | None = None  # a person's review of its current version
    said: tuple[str, str] | None = None  # ARGUS's own: ("proposal" or "reading", outcome)


MemberRow = Member | tuple[str, Sequence[str], Sequence[str]]


def _no_cases() -> Mapping[str, int]:
    return MappingProxyType({})


@dataclass(frozen=True)
class Found:
    """What the database holds for a case (or for the investigations and indicators of a case about
    to open): the stuff :func:`facts_of` turns into naming's facts."""

    members: Sequence[MemberRow] = ()  # a tuple is (rule, flags, listed)
    indicators: Sequence[tuple[str, str, str]] = ()  # kind, value, role
    outside: Sequence[tuple[str, str, str, str, Mapping[str, Any]]] = ()  # source, kind, value,
    # status, answer: the newest first
    sites: Sequence[str] = ()  # internal domains the investigations name, the commonest first
    answered: Sequence[tuple[str, str]] = ()  # (site, path): a stored follow-up's 2xx answer
    outcomes: Sequence[tuple[str, str, str]] = ()  # (site, path, outcome): stored path checks
    checks: frozenset[str] = frozenset()  # the statuses of the stored follow-ups
    follows: int = 0  # the number of the closed case this one follows (0: none)
    decision: str | None = None  # the outcome of a person's newest decision on the report
    opened: bool = False  # a person opened or confirmed the case
    server_cases: Mapping[str, int] = field(default_factory=_no_cases)  # server -> earlier case
    current: str | None = None  # the case's title now: the site or destination it names stays


def _member(row: MemberRow) -> Member:
    if isinstance(row, Member):
        return row
    rule, flags, listed = row
    return Member(rule, tuple(flags), tuple(listed))


def _campus(value: str, classifier: IpClassifier | None) -> bool:
    if classifier is not None:
        return classifier.classify(value).ip_class in CAMPUS
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(address.version == n.version and address in n for n in _PRIVATE)


def _names(text: str, value: str) -> bool:
    """Whether the title ``text`` names ``value`` as a whole address or name."""
    pattern = r"(?<![\w.-])" + re.escape(value.rstrip(".")) + r"(?![\w.-])"
    return re.search(pattern, text, re.IGNORECASE) is not None


def sticky(order: Sequence[str], weight: Mapping[str, int], current: str | None) -> list[str]:
    """``order`` with the value the current title names first, while it is still there and the
    leader's weight is not :data:`naming.GROWTH` times its own: a site or a destination of about
    the same weight does not take the lead at every pass (and retitle the case)."""
    out = list(order)
    kept = next((v for v in out if _names(current, v)), None) if current and out else None
    if kept is None or kept == out[0]:
        return out
    lead = weight.get(out[0], 0)
    if lead > 0 and lead >= naming.GROWTH * weight.get(kept, 0):
        return out
    return [kept, *(v for v in out if v != kept)]


def _one(found: set[Any]) -> Any:
    return next(iter(found)) if len(found) == 1 else None


def _device(value: str, kind: str, classifier: IpClassifier | None) -> naming.Device:
    """An internal device with the place and the zone the asset map gives its network (a network
    the map lists twice with different places or zones names none)."""
    if classifier is None or kind != "ip":
        return naming.Device(value, kind)
    match = classifier.classify(value).asset
    if match is None:
        return naming.Device(value, kind)
    types = {e.fields.get("site.type") for e in match.entries}
    places = {e.fields.get("site.building") or e.fields.get("site.department")
              for e in match.entries}  # fmt: skip
    zones = {e.fields.get("site.zone") for e in match.entries}
    return naming.Device(value, kind, _one(types), _one(places), _one(zones))


def answer_labels(answer: Mapping[str, Any]) -> list[str]:
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


def people(outcomes: Sequence[str]) -> str | None:
    """The outcome people hold: the one their reviews agree on, or that two thirds of them hold,
    else inconclusive (they disagree); None when nobody reviewed."""
    if not outcomes:
        return None
    top, n = sorted(Counter(outcomes).items(), key=lambda kv: (-kv[1], kv[0]))[0]
    return top if 3 * n >= 2 * len(outcomes) else naming.INCONCLUSIVE


def verdict_of(members: Sequence[Member], decision: str | None, opened: bool) -> naming.Verdict:
    """The verdicts a certainty word is chosen from: a person's decision on the report, else
    people's reviews; whether a person opened the case; ARGUS's proposals and its readings."""
    said = [m.said for m in members if m.said is not None]
    return naming.Verdict(
        person=decision or people([m.reviewed for m in members if m.reviewed]),
        opened=opened,
        proposals=tuple(o for kind, o in said if kind == "proposal"),
        readings=tuple(o for kind, o in said if kind == "reading"),
    )


def facts_of(found: Found, ctx: Context) -> naming.Facts:
    """The title's facts from what the database holds (pure)."""
    classifier = ctx.classifier
    members = [_member(m) for m in found.members]
    rules = Counter(m.rule for m in members if m.rule)
    flags = frozenset(f for m in members for f in m.flags)
    listed = tuple(sorted({v for m in members for v in m.listed}))
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
    engines: dict[str, int] = {}
    newest: set[tuple[str, str, str]] = set()
    for source, kind, value, status, answer in found.outside:  # the newest answer first
        if (source, kind, value) in newest:
            continue
        newest.add((source, kind, value))
        answers.setdefault((kind, value), []).append(answer)
        if outside_facts.flagged(source, status, answer, outside_facts.DEFAULT_THRESHOLD):
            flagged_values.append(value)
            if source == "virustotal":
                engines[value] = max(engines.get(value, 0), outside_facts.malicious(answer))
    c2 = sorted(value for kind, value, role in others if role == "c2" and kind in ("ip", "domain"))
    held = {value for kind, value, _ in others if kind in ("ip", "domain")}
    servers = list(dict.fromkeys([*c2, *sorted(v for v in flagged_values if v in held)]))
    servers = [v for v in servers if not _campus(v, classifier)]
    servers += [v for v in listed if v in held and v not in servers and v not in set(outsiders)
                and not _campus(v, classifier)]  # fmt: skip
    campus_domains = ctx.campus_domains
    names = sorted({v for k, v, role in others if k == "domain" and role != "c2"})
    checked = [s for s, _ in found.answered] + [s for s, _, _ in found.outcomes]
    sites = list(dict.fromkeys(found.sites))
    sites += [v for v in names if _is_campus_domain(v, campus_domains) and v not in sites]
    sites += [v for v in dict.fromkeys(checked) if v and v not in sites
              and _is_campus_domain(v, campus_domains)]  # fmt: skip
    campus_servers = sum(
        1 for kind, value, role in others
        if kind == "ip" and role != "c2" and _campus(value, classifier)
    )  # fmt: skip
    labels = [
        label
        for value in (*servers, *outsiders)
        for kind in ("ip", "domain")
        for answer in answers.get((kind, value), ())
        for label in answer_labels(answer)
    ]
    labels += [t for m in members for t in m.threats]
    device_values = {d.value for d in devices}
    doing: dict[str, frozenset[str]] = {}
    reaches: dict[str, set[str]] = {}
    timed: dict[str, set[str]] | None = None
    campaign: dict[str, set[str]] | None = None
    if any(m.entities for m in members):
        doing = {flag: frozenset() for flag in (*flags, naming.BEACON_PORTS)}
        timed, campaign = {}, {}
        for m in members:
            mine = frozenset(v for _, v in m.entities if v in device_values)
            if not mine:
                continue
            for flag in m.flags:
                doing[flag] = doing[flag] | mine
            if naming.BEACON in m.flags and naming.PORTS in m.flags:
                doing[naming.BEACON_PORTS] |= mine
            for kind, value in m.entities:
                if kind in ("ip", "domain") and value not in device_values:
                    reaches.setdefault(value, set()).update(mine)
                    if naming.BEACON in m.flags:
                        timed.setdefault(value, set()).update(mine)
                    if naming.CAMPAIGN in m.flags:
                        campaign.setdefault(value, set()).update(mine)
    named = set(servers)
    destinations = sorted(
        (v for v in reaches if v not in named and not _campus(v, classifier)
         and not _is_campus_domain(v, campus_domains)),
        key=lambda v: (-len(reaches[v]), v),
    )  # fmt: skip
    destinations = sticky(destinations, {v: len(reaches[v]) for v in destinations}, found.current)
    weights = Counter(v for m in members for v in {v for k, v in m.entities if k == "domain"})
    sites = sticky(sites, weights, found.current)
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
        labels=tuple(labels),
        follows=found.follows,
        paths=tuple(sorted({v for k, v, _ in others if k == "url"})),
        verdict=verdict_of(members, found.decision, found.opened),
        doing=MappingProxyType(doing),
        reaches=MappingProxyType({k: frozenset(v) for k, v in reaches.items()}),
        beacon_reaches=_paired(timed),
        campaign_reaches=_paired(campaign),
        destinations=tuple(destinations),
        vt=MappingProxyType(engines),
        answered=tuple(dict.fromkeys(found.answered)),
        outcomes=tuple(dict.fromkeys(found.outcomes)),
        checks=found.checks,
        # the case it follows is said once, at the end ("— follows case N")
        server_cases=MappingProxyType(
            {k: v for k, v in found.server_cases.items() if v != found.follows}
        ),
    )


def _paired(table: dict[str, set[str]] | None) -> Mapping[str, frozenset[str]] | None:
    return None if table is None else MappingProxyType({k: frozenset(v) for k, v in table.items()})


def _is_campus_domain(name: str, domains: Iterable[str]) -> bool:
    low = name.lower().rstrip(".")
    return any(low == d or low.endswith("." + d) for d in domains)


def titled_of(found: Found, ctx: Context) -> naming.Titled | None:
    """The title the facts give, or None when they have nothing to say (no investigation, no
    indicator, or only "Alert"): the case keeps the title it has."""
    if not found.members and not found.indicators:
        return None
    facts = facts_of(found, ctx)
    if naming.title(replace(facts, follows=0)) == naming.EMPTY:
        return None  # nothing to say: the title stays
    return naming.titled(facts)


def title_of(found: Found, ctx: Context) -> str | None:
    """The text of :func:`titled_of`."""
    made = titled_of(found, ctx)
    return None if made is None else made.text


# -- the reads -------------------------------------------------------------------------------------

_IDS = bindparam("ids", type_=ARRAY(UUID(as_uuid=True)))
_MEMBERS = text(
    "SELECT i.id, coalesce(i.rule_name, i.rule_id) AS rule, r.flags, d.local_signals, d.signals,"
    " d.listed, d.answers, s.outcome AS reviewed FROM investigations i"
    " LEFT JOIN investigation_raises r ON r.investigation_id = i.id AND r.version = i.version"
    " LEFT JOIN review_state s ON s.investigation_id = i.id AND s.action = 'reviewed'"
    "  AND s.version = i.version"
    " LEFT JOIN LATERAL (SELECT body -> 'local_signals' AS local_signals,"
    "  body -> 'signals' AS signals, body #> '{context,pack,ti,listed}' AS listed,"
    "  body #> '{context,pack,ti,answers}' AS answers"
    "  FROM dossiers WHERE investigation_id = i.id ORDER BY version DESC, created_at DESC"
    "  LIMIT 1) d ON true"
    " WHERE i.id = ANY(:ids) ORDER BY i.first_event_at NULLS LAST, i.id LIMIT :n"
).bindparams(_IDS)
_ENTITIES = text(
    "SELECT investigation_id, kind, value FROM investigation_entities"
    " WHERE investigation_id = ANY(:ids) AND kind IN ('ip', 'domain', 'host')"
    " ORDER BY investigation_id, kind, value LIMIT :n"
).bindparams(_IDS)
_ASSESSMENTS = text(
    "SELECT a.investigation_id AS member, a.assessor, a.status, a.outcome, a.reasons,"
    " false AS shared FROM assessments a JOIN investigations i ON i.id = a.investigation_id"
    " AND i.version = a.version WHERE a.investigation_id = ANY(:ids)"
    " AND a.status IN ('proposed', 'no_decision')"
    " UNION ALL SELECT s.investigation_id AS member, a.assessor, a.status, a.outcome, a.reasons,"
    " true AS shared FROM assessment_shares s JOIN assessments a ON a.id = s.assessment_id"
    " JOIN investigations i ON i.id = s.investigation_id AND i.version = s.version"
    " WHERE s.investigation_id = ANY(:ids) AND a.status IN ('proposed', 'no_decision')"
    " ORDER BY 1, 2, 3 LIMIT :n"
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
_CHECKS = (
    "SELECT e.params, e.status, e.snapshot FROM evidence e WHERE e.investigation_id = ANY(:ids)"
    " AND e.template = :t AND e.status IN ('ok', 'empty', 'skipped_budget')"
    " ORDER BY e.collected_at {order}, e.task_key LIMIT :n"
)
_DECISION = text(
    "SELECT coalesce(d.outcome, r.verdict_outcome) AS outcome FROM incident_report_decisions d"
    " JOIN incident_reports r ON r.id = d.report_id WHERE r.case_id = :c"
    " ORDER BY d.id DESC LIMIT 1"
)
_SERVER_CASES = text(
    "SELECT i.value, min(c.number) AS number FROM case_indicators i JOIN cases c"
    " ON c.id = i.case_id WHERE i.value = ANY(:v) AND i.removed_at IS NULL AND i.role <> 'actor'"
    " AND i.kind IN ('ip', 'domain') AND (CAST(:me AS uuid) IS NULL OR c.id <> :me)"
    " AND (:mine = 0 OR c.number < :mine) GROUP BY i.value"
).bindparams(bindparam("v", type_=ARRAY(Text)))


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


def threat_names(answers: Any, listed: Iterable[str]) -> tuple[str, ...]:
    """The threat names a dossier's threat-list answers store for the values listed (each
    match's ``description``): where a family such as PS1Bot shows."""
    wanted = set(listed)
    out: list[str] = []
    for answer in answers if isinstance(answers, list) else []:
        if not isinstance(answer, Mapping) or answer.get("value") not in wanted:
            continue
        sources = answer.get("sources")
        for per in sources.values() if isinstance(sources, Mapping) else ():
            matches = per.get("match") if isinstance(per, Mapping) else None
            for match in matches if isinstance(matches, list) else ():
                said = match.get("description") if isinstance(match, Mapping) else None
                if isinstance(said, str) and said:
                    out.append(said[:200])
    return tuple(dict.fromkeys(out))


def best_said(rows: Iterable[Any]) -> dict[Any, tuple[str, str]]:
    """ARGUS's own word on each investigation (as the report's verdict ranks them): a proposal
    before a reading, the investigator's before the decision engine's, its own before a shared
    one. A reading is the one an investigator run's report stores."""
    from argus.agent import reading as agent_reading

    best: dict[Any, tuple[tuple[int, int, int], str, str]] = {}
    for r in rows:
        agent = int(str(r.assessor).startswith("agent"))
        own = 0 if r.shared else 1
        if r.status == "proposed" and r.outcome:
            rank, kind, outcome = (2, agent, own), "proposal", str(r.outcome)
        else:
            reasons = r.reasons if isinstance(r.reasons, list) else []
            report = next((x for x in reasons if isinstance(x, Mapping)), None)
            got = agent_reading.of(report, [x for x in reasons if isinstance(x, str)])
            if got is None:
                continue
            rank, kind, outcome = (1, agent, own), "reading", str(got.outcome)
        kept = best.get(r.member)
        if kept is None or rank > kept[0]:
            best[r.member] = (rank, kind, outcome)
    return {k: (kind, outcome) for k, (_, kind, outcome) in best.items()}


def _campus_pattern(domains: Iterable[str]) -> str:
    return r"(^|\.)(" + "|".join(re.escape(d) for d in domains) + r")$" if domains else "$^"


@dataclass(frozen=True)
class WebChecks:
    """What the stored web checks of a case's investigations show."""

    answered: tuple[tuple[str, str], ...] = ()  # (site, path) of a follow-up's 2xx answer
    outcomes: tuple[tuple[str, str, str], ...] = ()  # (site, path, outcome) of a path check
    checks: frozenset[str] = frozenset()  # the follow-ups' statuses


def _status_2xx(source: Mapping[str, Any]) -> bool:
    for value in field_values(source, "http.response.status_code"):
        try:
            code = int(str(value))
        except ValueError:
            continue
        if 200 <= code < 300:
            return True
    return False


def followup_answers(snapshot: Any) -> list[tuple[str, str]]:
    """(site, path) of each 2xx answer a stored ``web.followups`` answer shows (the template asks
    for 2xx answers only; a row without a site or a path is left out)."""
    rows = snapshot.get("rows") if isinstance(snapshot, Mapping) else None
    out: list[tuple[str, str]] = []
    for row in rows if isinstance(rows, list) else []:
        source = row.get("_source") if isinstance(row, Mapping) else None
        if not isinstance(source, Mapping) or not _status_2xx(source):
            continue
        sites = [str(v) for v in field_values(source, "url.domain")][:1]
        paths = [str(v)[:300] for v in field_values(source, "url.path")][:1]
        if sites and paths:
            out.append((sites[0], paths[0]))
    return out


async def web_checks(conn: AsyncConnection, ids: Sequence[uuid.UUID]) -> WebChecks:
    """The stored web checks of these investigations (the first and the newest of each kind):
    the follow-ups' statuses and 2xx answers, and the path checks' outcomes."""
    from argus.responder import facts as responder_facts

    answered: list[tuple[str, str]] = []
    outcomes: list[tuple[str, str, str]] = []
    statuses: set[str] = set()
    for template in ("web.followups", "web.path_outcomes"):
        for order in ("ASC", "DESC"):
            statement = text(_CHECKS.format(order=order)).bindparams(_IDS)
            params = {"ids": list(ids), "t": template, "n": CHECKS_READ}
            for row in await conn.execute(statement, params):
                if template == "web.followups":
                    statuses.add(str(row.status))
                    answered += followup_answers(row.snapshot)
                    continue
                asked = row.params.get("paths") if isinstance(row.params, Mapping) else None
                where = row.params.get("site") if isinstance(row.params, Mapping) else None
                outcomes += [
                    (str(where or ""), o.path, o.outcome)
                    for o in responder_facts.outcomes_of(row.snapshot, asked)
                ]
    return WebChecks(
        tuple(dict.fromkeys(answered)), tuple(dict.fromkeys(outcomes)), frozenset(statuses)
    )


async def read(
    conn: AsyncConnection, members: Sequence[uuid.UUID],
    indicators: Iterable[tuple[str, str, str]], ctx: Context,
) -> Found:  # fmt: skip
    """What the database holds for these investigations and indicators (bounded statements, ARGUS's
    own tables only)."""
    ids = list(members)[:MEMBERS_READ]
    held = list(indicators)[:INDICATORS_READ]
    rows = (await conn.execute(_MEMBERS, {"ids": ids, "n": MEMBERS_READ})).all() if ids else []
    entities: dict[Any, list[tuple[str, str]]] = {}
    said: dict[Any, tuple[str, str]] = {}
    if ids:
        for r in await conn.execute(_ENTITIES, {"ids": ids, "n": ENTITIES_READ}):
            entities.setdefault(r.investigation_id, []).append((str(r.kind), str(r.value)))
        said = best_said(await conn.execute(_ASSESSMENTS, {"ids": ids, "n": ASSESSMENTS_READ}))
    found_members = [
        Member(
            str(r.rule or ""), _flags_of(r), _strings(r.listed), tuple(entities.get(r.id, ())),
            threat_names(r.answers, _strings(r.listed)), r.reviewed, said.get(r.id),
        )
        for r in rows
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
    checks = WebChecks()
    if ids:
        pattern = _campus_pattern(ctx.campus_domains)
        sites = [
            str(v) for v in (await conn.execute(
                _SITES, {"ids": ids, "campus": pattern, "n": SITES_READ}
            )).scalars()
        ]  # fmt: skip
        checks = await web_checks(conn, ids)
    return Found(
        found_members, held, outside, sites, checks.answered, checks.outcomes, checks.checks
    )


async def server_cases(
    conn: AsyncConnection, values: Iterable[str], me: uuid.UUID | None, mine: int
) -> Mapping[str, int]:
    """The earliest other case (one before case ``mine``; any, when 0) that holds each server as
    an indicator."""
    wanted = sorted(set(values))[:INDICATORS_READ]
    if not wanted:
        return MappingProxyType({})
    rows = await conn.execute(_SERVER_CASES, {"v": wanted, "me": me, "mine": mine})
    return MappingProxyType({str(r.value): int(r.number) for r in rows})


def _servers_named(found: Found, ctx: Context) -> list[str]:
    """The values a title may name as a server: the flagged ones and the destinations."""
    facts = facts_of(found, ctx)
    return [*facts.servers, *facts.destinations]


async def _engine_title(
    conn: AsyncConnection, case_id: uuid.UUID, ctx: Context
) -> naming.Titled | None:
    """The engine incident's title for its case, or None (no such incident, or no facts)."""
    from argus.risk import titles  # the engine names its own cases; imported here: no cycle

    row = (
        await conn.execute(
            text("SELECT id, view ->> 'certainty' AS word FROM risk_incidents"
                 " WHERE case_id = :c AND parent_id IS NULL ORDER BY id DESC LIMIT 1"),
            {"c": case_id},
        )
    ).first()  # fmt: skip
    if row is None:
        return None
    facts = await titles.read_facts(conn, int(row.id), titles.Context(ctx.classifier))
    word = row.word if row.word in naming.CERTAINTIES else naming.SUSPECTED
    if facts is None:
        return None
    made = titles.titled_for_incident(facts, word)
    return None if made.text == naming.EMPTY else made


async def titled_for_case(
    conn: AsyncConnection, case_id: uuid.UUID, ctx: Context
) -> naming.Titled | None:
    """The title the case's facts give now (None when it holds nothing to name); a case the
    incident engine presents is named from its incident's own facts, led by the engine's
    certainty word (naming v2 phase 2)."""
    engine = await _engine_title(conn, case_id, ctx)
    if engine is not None:
        return engine
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
    case = (
        await conn.execute(
            text("SELECT c.number, c.title, c.opened_at IS NOT NULL AS opened,"
                 " p.number AS parent FROM cases c LEFT JOIN cases p ON p.id = c.parent_case_id"
                 " WHERE c.id = :c"),
            {"c": case_id},
        )
    ).first()  # fmt: skip
    decision = await conn.scalar(_DECISION, {"c": case_id})
    number = int(case.number) if case is not None else 0
    found = replace(
        found,
        follows=int(case.parent or 0) if case is not None else 0,
        decision=str(decision) if decision else None,
        opened=bool(case.opened) if case is not None else False,
        current=str(case.title) if case is not None else None,
    )
    linked = await server_cases(conn, _servers_named(found, ctx), case_id, number)
    return titled_of(replace(found, server_cases=linked), ctx)


async def for_case(conn: AsyncConnection, case_id: uuid.UUID, ctx: Context) -> str | None:
    """The text of :func:`titled_for_case`."""
    made = await titled_for_case(conn, case_id, ctx)
    return None if made is None else made.text


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
    linked = await server_cases(conn, _servers_named(found, ctx), None, 0)
    return title_of(replace(found, server_cases=linked), ctx) or fallback


# -- the refresh -----------------------------------------------------------------------------------

_CASES = text(
    "SELECT c.id, c.number, c.title, c.state, coalesce(t.by_person, false) AS by_person,"
    " t.at AS titled_at FROM cases c"
    " LEFT JOIN LATERAL (SELECT e.actor_user_id IS NOT NULL AS by_person, e.occurred_at AS at"
    "  FROM case_events e WHERE e.case_id = c.id AND e.kind IN ('suspected', 'opened', 'retitled')"
    "  ORDER BY e.case_version DESC LIMIT 1) t ON true"
    " WHERE (:everything OR c.state <> 'closed') AND (CAST(:only AS uuid) IS NULL OR c.id = :only)"
    " ORDER BY c.number"
)


@dataclass(frozen=True)
class Change:
    case_id: uuid.UUID
    number: int
    old: str
    new: str
    change: naming.Change = "words"
    claims: tuple[Mapping[str, str], ...] = ()


@dataclass
class Report:
    looked: int = 0
    kept: int = 0  # cases whose title a person wrote: left alone
    changes: list[Change] = field(default_factory=list)  # titles that differ (applied or not)
    applied: int = 0
    waiting: int = 0  # count-only changes held back: not material yet
    skipped: list[str] = field(default_factory=list)

    def line(self) -> str:
        return (f"titles: looked {self.looked}, a person's {self.kept}, changed {self.applied}"
                f" of {len(self.changes)}, waiting {self.waiting}")  # fmt: skip


def material(
    old: str, new: str, titled_at: datetime | None, now: datetime, wait: timedelta = COALESCE
) -> bool:
    """Whether ARGUS's new title is worth a retitle: its words or its certainty changed, or only
    its numbers did and a count shrank (the old one would be false), grew by half, or the title
    last changed ``wait`` ago or more. A count that only grew a little waits."""
    change = naming.change_of(old, new)
    if change == "same":
        return False
    if change != "counts" or naming.counts_moved(old, new):
        return True
    return titled_at is None or now - titled_at >= wait


def why(change: naming.Change, old: str, new: str) -> str:
    """The reason a retitle records: what changed, in plain words."""
    if change == "certainty":
        was, _ = naming.split_certainty(old)
        now, _ = naming.split_certainty(new)
        return f"the certainty changed: {was or 'none'} → {now or 'none'}"
    if change == "counts":
        return "the counts changed"
    return "the facts changed"


async def refresh(
    engine: AsyncEngine, ctx: Context, *, dry_run: bool = False, everything: bool = False,
    only: uuid.UUID | None = None, limit: int = MAX_PER_PASS, now: datetime | None = None,
    wait: timedelta = COALESCE,
) -> Report:  # fmt: skip
    """Make ARGUS's titles current. The cases that are not closed (``everything``: every case, a
    closed one too), the titles a person wrote left alone; for each other, the title its facts give
    now, and when it differs materially (:func:`material`), a ``retitled`` event as
    ``argus:title`` with what changed and the new title's claims (unless ``dry_run``). At most
    ``limit`` titles change in one call. A failure on one case is said and the rest go on."""
    report = Report()
    at = now or datetime.now(UTC)
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
                made = await titled_for_case(conn, case.id, ctx)
        except DBAPIError as exc:
            report.skipped.append(f"case {case.number}: read failed ({_state(exc)})")
            continue
        if made is None or made.text in (naming.EMPTY, case.title):
            continue
        new = made.text
        if not material(case.title, new, case.titled_at, at, wait):
            report.waiting += 1
            continue
        change = naming.change_of(case.title, new)
        claims = tuple(made.explain())
        report.changes.append(Change(case.id, int(case.number), case.title, new, change, claims))
        if dry_run:
            continue
        command = Retitle(new, why(change, case.title, new), change=change, claims=claims)
        try:
            async with engine.begin() as conn:
                service = await CaseService.start(conn)
                await service.apply(actor, case.id, command, expected_version=None)
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
