"""What opens a case: deterministic rules over verdicts and proposals, never model similarity.

A person's true-positive verdict opens a case when its investigation shows an impact or
internal-host signal; ARGUS's own proposals make *suspected* cases until a person confirms them.
An investigation joins an active case that shares an actor, C2 or indicator
(:mod:`argus.cases.membership`) only when one case holds the strongest match, never through a shared
address; other matches are suggested, and a tie opens at most one case. Activity after a closure
makes a new case that follows it. At most :data:`MAX_NEW_PER_HOUR` new cases an hour; each verdict
or proposal is decided once (``case_openings``), so runs can repeat or overlap safely."""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus import site
from argus.assets.classify import IpClass, IpClassifier
from argus.cases import membership, naming, titling
from argus.cases.machine import (
    AfterClosure,
    CaseRefused,
    ConfirmByVerdict,
    Link,
    NewActivity,
    Open,
)
from argus.cases.membership import NO_SHARED, Shared
from argus.cases.model import SEVERITIES, Actor, Cause, Indicator, Member, Severity, State
from argus.cases.service import CaseService

MAX_NEW_PER_HOUR = 20
WATCH_AFTER_CLOSURE = timedelta(days=14)  # the watch lasts 14 days after closure
BEACON = 0.3  # proxy.regularity below this is a regular beacon (as the decision engine's floor)
RARE = 1
ASSISTANT = "argus-assistant"
OPENER_LOCK_KEY = int.from_bytes(b"ARGUSOPN", "big")
TIE_OPENED = "opened on its own merits after a tie between cases"  # in case_openings.reasons
# The backfill reaches back to a fixed start, not only history.window.
BACKFILL_FROM = datetime(2026, 10, 14, tzinfo=UTC)
LINKABLE = frozenset({IpClass.ASSET, IpClass.INTERNAL, IpClass.PUBLIC})
CAMPUS = frozenset({IpClass.ASSET, IpClass.INTERNAL, IpClass.CAMPUS})
# Identity fields: who acted. Other user.* and host.* fields (user.domain, host.os.name,
# user.group.name, user.roles) are shared by many people and hosts and never link.
HOST_FIELDS = frozenset({"host.name", "host.hostname", "host.id"})
USER_FIELDS = frozenset({"user.name", "user.id", "user.email", "user.target.name"})
# Values many unrelated actors share (brute-force account names, placeholders); compared in
# lower case.
GENERIC_ACTORS = frozenset(
    {
        "0.0.0.0",  # noqa: S104 - a value to refuse, not an address to bind
        "-", "127.0.0.1", "::", "::1", "admin", "administrator", "anonymous",
        "default", "ftp", "guest", "localhost", "n/a", "none", "nobody", "null", "oracle",
        "pi", "postgres", "root", "sa", "system", "test", "ubuntu", "unknown", "user",
        "www-data",
    }
)  # fmt: skip
Decision = Literal["opened", "suspected", "linked", "member_already", "attempt", "deferred"]


@dataclass(frozen=True)
class Candidate:
    """A true-positive verdict or proposal and what its investigation shows."""

    source: Literal["review", "assessment"]
    source_id: int
    investigation_id: uuid.UUID
    by_person: bool  # a person's verdict; False: ARGUS's own proposal
    at: datetime
    rule_name: str | None
    severity: Severity
    actors: tuple[Indicator, ...]  # who acted, if linkable
    campus_actor: bool  # an actor is an internal host
    entities: frozenset[tuple[str, str]]  # (kind, value) the investigation involves
    listed: tuple[str, ...]  # its threat-listed values
    signals: Mapping[str, tuple[str, Any]] = field(default_factory=dict)  # name: (status, value)
    held_by: uuid.UUID | None = None  # the case it is in already (a closed one included)
    by_user_id: int | None = None  # the person whose verdict it is
    campus_keys: frozenset[tuple[str, str]] = frozenset()  # the actors that are internal devices


@dataclass
class Indexed:
    """A case the planner can link to: one in the database, or one this plan opens.
    ``tie_of``: the cases whose tie opened this one (empty when it was not opened by a tie).
    ``cause``: why it was opened; a suggested case (``raised``) is confirmed by a person's
    Confirm, never by a verdict on one of its investigations."""

    ref: uuid.UUID | str
    number: int
    state: State
    closed_at: datetime | None
    members: set[uuid.UUID]
    indicators: dict[tuple[str, str], str]  # (kind, value): role
    tie_of: frozenset[uuid.UUID | str] = frozenset()
    cause: Cause = "person"


@dataclass(frozen=True)
class Opening:
    candidate: Candidate
    decision: Decision
    reasons: tuple[str, ...]
    case_ref: uuid.UUID | str | None = None
    link: str | None = None
    link_value: str | None = None
    parent: uuid.UUID | None = None
    title: str | None = None
    indicators: tuple[Indicator, ...] = ()
    suggested: tuple[membership.Suggested, ...] = ()  # cases it matches but does not join


def _known(candidate: Candidate, name: str) -> Any:
    status, value = candidate.signals.get(name, ("missing", None))
    return value if status == "known" else None


def _no_impact() -> str:
    """ "no impact or internal-host signal": the site's word joined to "host" with a hyphen, as a
    modifier ("host of your network" reads as it stands)."""
    phrase = site.say("{own:host}")
    return f"no impact or {phrase if ' of ' in phrase else phrase.replace(' ', '-')} signal"


def impact(candidate: Candidate) -> list[str]:
    """The impact or internal-host signals that make a person's verdict open a case."""
    out = []
    if (_known(candidate, "web.successes_after") or 0) > 0:
        out.append("successful answers after the attack")
    regularity = _known(candidate, "proxy.regularity")
    if regularity is not None and regularity < BEACON:
        out.append("a regular beacon")
    if candidate.campus_actor and (_known(candidate, "ti.listed") or 0) > 0:
        out.append(site.say("{a_own:host} in contact with a threat-listed address"))
    return out


def floor(candidate: Candidate) -> list[str]:
    """Floor signals that are known and present (a suspected case needs one)."""
    out = impact(candidate)
    if (_known(candidate, "ti.listed") or 0) > 0 and not candidate.campus_actor:
        out.append("a threat-listed value")
    rare = _known(candidate, "proxy.hosts_to_destination")
    if rare is not None and rare <= RARE:
        out.append(site.say("a destination few {own:hosts} reach"))
    if (_known(candidate, "ports.risky") or 0) > 0:
        out.append("remote-admin, P2P or anonymizer ports")
    if candidate.severity in ("high", "critical"):
        out.append(f"severity {candidate.severity}")
    return out


def title(candidate: Candidate, reasons: Sequence[str]) -> str:
    """The case's title from what the one investigation shows (:mod:`argus.cases.naming`); the
    title that is stored is made again from the database's facts (:func:`run`)."""
    return naming.title(title_facts(candidate, reasons))


def reason_flags(reasons: Sequence[str]) -> frozenset[str]:
    """The signals that made an investigation a candidate, as the evidence flags' words."""
    flags = set()
    if "a regular beacon" in reasons:
        flags.add(naming.BEACON)
    if any("threat-listed" in r for r in reasons):
        flags.add(naming.LISTED)
    if "successful answers after the attack" in reasons:
        flags.add(naming.SUCCESS)
    return frozenset(flags)


def title_facts(candidate: Candidate, reasons: Sequence[str]) -> naming.Facts:
    """What the title can say from the candidate alone: its rule, who acted (internal devices,
    outside addresses, accounts), the threat-listed values it reached, and the signals that made
    it a candidate (as the evidence flags' words)."""
    flags = reason_flags(reasons)
    campus = set(candidate.campus_keys)
    if not campus and candidate.campus_actor:
        campus = {(a.kind, a.value) for a in candidate.actors if a.kind in ("ip", "host")}
    actors = {a.value for a in candidate.actors}
    outsiders = sorted(
        a.value for a in candidate.actors if a.kind == "ip" and (a.kind, a.value) not in campus
    )
    return naming.Facts(
        rules=((candidate.rule_name, 1),) if candidate.rule_name else (),
        flags=flags,
        devices=tuple(naming.Device(value, kind) for kind, value in sorted(campus)),
        outsiders=tuple(outsiders),
        accounts=sum(1 for a in candidate.actors if a.kind == "user"),
        servers=tuple(v for v in candidate.listed if v not in actors),
        listed=candidate.listed,
    )


def _label(case: Indexed) -> str:
    return f"case {case.number}" if isinstance(case.ref, uuid.UUID) else f"case {case.ref}"


def _new_indicators(candidate: Candidate) -> tuple[Indicator, ...]:
    actors = {(a.kind, a.value) for a in candidate.actors}
    c2 = [
        Indicator("domain" if not _looks_ip(v) else "ip", v, "c2", "threat_intel")
        for v in candidate.listed
        if ("ip", v) not in actors and ("domain", v) not in actors
    ]
    return tuple(sorted({*candidate.actors, *c2}))


def _looks_ip(value: str) -> bool:
    return value.replace(".", "").isdigit() or ":" in value


def _strongly_matches(candidate: Candidate, case: Indexed, shared: Shared) -> bool:
    return any(m.strong for m in membership.keys(candidate, case.indicators, shared))


def plan(
    candidates: Iterable[Candidate],
    cases: Iterable[Indexed],
    *,
    now: datetime,
    created_last_hour: int,
    shared: Shared = NO_SHARED,
) -> list[Opening]:
    """The decision for each candidate, in order (oldest first). Pure. ``shared`` is the shared
    infrastructure no match is trusted through (:mod:`argus.cases.membership`)."""
    index = [replace(c, members=set(c.members), indicators=dict(c.indicators)) for c in cases]
    budget = MAX_NEW_PER_HOUR - created_last_hour
    out: list[Opening] = []
    placeholders = 0
    for candidate in sorted(candidates, key=lambda c: (c.at, c.source, c.source_id)):
        verdict = impact(candidate) if candidate.by_person else []
        held = next((c for c in index if candidate.investigation_id in c.members), None)
        if held is not None and held.state == "suspected" and verdict and held.cause != "raised":
            confirms = f"a person's true-positive verdict confirms suspected {_label(held)}"
            out.append(Opening(candidate, "opened", (confirms, *verdict), held.ref))
            held.state = "open"
            continue
        holding = held.ref if held is not None else candidate.held_by
        if holding is not None:  # in a case already, a closed one included
            out.append(Opening(candidate, "member_already", ("already in this case",), holding))
            continue
        active = [c for c in index if c.state != "closed"]
        resolution = membership.resolve(candidate, active, shared)
        if resolution.join is not None:
            pick = resolution.join
            case, link, value = pick.case, pick.match.link, pick.match.value
            assert isinstance(case, Indexed)
            also = [f"also matches case {s.case.number} (suggested, not joined)"
                    for s in resolution.suggest]  # fmt: skip
            reasons: tuple[str, ...] = (f"same {link} {value}", *also)
            marks = _new_indicators(candidate)
            decision: Decision = "linked"
            if case.state == "suspected" and verdict and case.cause != "raised":
                confirms = f"a person's true-positive verdict confirms suspected {_label(case)}"
                reasons, decision = (reasons[0], confirms, *verdict, *also), "opened"
                case.state = "open"
            out.append(Opening(candidate, decision, reasons, case.ref, link, value,
                               indicators=marks, suggested=resolution.suggest))  # fmt: skip
            case.members.add(candidate.investigation_id)
            for mark in marks:
                case.indicators.setdefault((mark.kind, mark.value), mark.role)
            continue
        unjoined = tuple(f"{s.words()} (suggested, not joined)" for s in resolution.suggest)
        recent = [
            c for c in index
            if c.state == "closed" and c.closed_at is not None
            and now - c.closed_at <= WATCH_AFTER_CLOSURE
            and _strongly_matches(candidate, c, shared)
        ]  # fmt: skip
        parent = min(recent, key=lambda c: c.number) if recent else None
        signals = impact(candidate) if candidate.by_person else floor(candidate)
        if not signals:
            why = _no_impact() if candidate.by_person else "no floor signal"
            out.append(Opening(candidate, "attempt", (why, *unjoined),
                               suggested=resolution.suggest))  # fmt: skip
            continue
        tied = frozenset(s.case.ref for s in resolution.suggest if s.kind == "tie")
        if resolution.ambiguous:  # a tie opens at most one case, and only on a person's verdict
            born = next((c for c in active if c.tie_of and (c.ref in tied or tied <= c.tie_of)),
                        None)  # fmt: skip
            if not candidate.by_person:
                why = "it matches several cases equally well: a proposal opens no case on a tie"
            elif born is not None:
                why = f"{_label(born)} was opened by this tie: it is suggested to each, not opened"
            else:
                why = ""
            if why:
                out.append(Opening(candidate, "attempt", (why, *unjoined),
                                   suggested=resolution.suggest))  # fmt: skip
                continue
        if budget <= 0:
            out.append(
                Opening(candidate, "deferred", (f"over {MAX_NEW_PER_HOUR} new cases an hour",))
            )
            continue
        budget -= 1
        placeholders += 1
        ref = f"new:{placeholders}"
        marks = _new_indicators(candidate)
        follows = () if parent is None else (f"follows closed case {parent.number}",)
        decision = "opened" if candidate.by_person else "suspected"
        by_tie = (TIE_OPENED,) if resolution.ambiguous else ()
        out.append(
            Opening(
                candidate, decision, (*signals, *follows, *by_tie, *unjoined), ref,
                parent=parent.ref if parent is not None and isinstance(parent.ref, uuid.UUID)
                else None,
                title=title(candidate, signals), indicators=marks,
                suggested=resolution.suggest,
            )
        )  # fmt: skip
        index.append(
            Indexed(
                ref,
                10**9 + placeholders,
                "open" if candidate.by_person else "suspected",
                None,
                {candidate.investigation_id},
                {(m.kind, m.value): m.role for m in marks},
                tied if resolution.ambiguous else frozenset(),
            )
        )
    return out


def _actors(group_key: str, classifier: IpClassifier) -> tuple[tuple[Indicator, ...], bool]:
    try:
        pairs = json.loads(group_key)
    except ValueError:
        return (), False
    if not isinstance(pairs, list):
        return (), False
    out: list[Indicator] = []
    campus = False
    for pair in pairs:
        if not (isinstance(pair, list) and len(pair) == 2 and isinstance(pair[1], str)):
            continue
        name, value = str(pair[0]), pair[1]
        kind = _actor_kind(name)
        if kind is None or not value or len(value) > 512:
            continue
        if value.strip().lower() in GENERIC_ACTORS:  # shared by unrelated actors
            continue
        if kind == "ip":
            ip_class = classifier.classify(value).ip_class
            campus |= ip_class in CAMPUS
            if ip_class not in LINKABLE:  # a shared egress address links nothing
                continue
        elif kind == "host":
            campus = True
        out.append(Indicator(kind, value, "actor", "investigation"))  # type: ignore[arg-type]
    return tuple(sorted(set(out))), campus


def actors_of(group_key: str, classifier: IpClassifier) -> tuple[tuple[Indicator, ...], bool]:
    """Who acted in an investigation (identity fields only, never a shared egress address or a
    generic value) and whether one of them is an internal host."""
    return _actors(group_key, classifier)


def is_campus_actor(group_key: str, classifier: IpClassifier) -> bool:
    """Whether an investigation's group key names an internal host or address (the test
    :func:`observe` and :func:`candidates` make, without a query)."""
    return _actors(group_key, classifier)[1]


def _actor_kind(name: str) -> str | None:
    if name.rsplit(".", 1)[-1] == "ip":
        return "ip"
    if name in HOST_FIELDS:
        return "host"
    return "user" if name in USER_FIELDS else None


def _severity(value: str | None) -> Severity:
    low = (value or "").lower()
    return low if low in SEVERITIES else "medium"


async def candidates(
    conn: AsyncConnection, *, since: datetime, classifier: IpClassifier
) -> list[Candidate]:
    """Undecided true-positive verdicts (each investigation's newest review) and proposals
    since ``since``, with what their investigations show. A verdict opens a case only if it is a
    person's and was made under an ELK check that showed the privileges (``kibana_ok``): not the
    emergency account's, not a session ARGUS could not verify. Such a verdict is still the
    newest one, so an older true positive does not open a case behind it."""
    rows = (
        await conn.execute(
            text(
                "WITH newest AS (SELECT DISTINCT ON (r.investigation_id) r.id,"
                " r.investigation_id, r.outcome, r.created_at, r.user_id, r.kibana_ok,"
                " u.kind FROM review_events r JOIN users u ON u.id = r.user_id"
                " WHERE r.action = 'reviewed' AND u.username <> :assistant"
                " AND u.kind <> 'service'"
                " ORDER BY r.investigation_id, r.id DESC)"
                " SELECT 'review' AS source, n.id, n.investigation_id, n.created_at AS at,"
                " true AS by_person, n.user_id AS by_user_id FROM newest n"
                " WHERE n.outcome = 'true_positive' AND n.created_at >= :since"
                " AND n.kind = 'person' AND n.kibana_ok"
                " AND NOT EXISTS (SELECT 1 FROM case_openings o WHERE o.source = 'review'"
                " AND o.source_id = n.id)"
                " UNION ALL"
                " SELECT 'assessment', a.id, a.investigation_id, a.created_at, false,"
                " CAST(NULL AS bigint) FROM assessments a WHERE a.status = 'proposed'"
                " AND a.outcome = 'true_positive'"
                " AND a.created_at >= :since AND NOT EXISTS (SELECT 1 FROM case_openings o"
                " WHERE o.source = 'assessment' AND o.source_id = a.id)"
                " ORDER BY 4, 1, 2"
            ),
            {"since": since, "assistant": ASSISTANT},
        )
    ).all()
    out = []
    for row in rows:
        out.append(await _candidate(conn, row, classifier))
    return out


async def _candidate(conn: AsyncConnection, row: Any, classifier: IpClassifier) -> Candidate:
    inv = (
        await conn.execute(
            text("SELECT rule_name, severity, group_key FROM investigations WHERE id = :i"),
            {"i": row.investigation_id},
        )
    ).one()
    entities = frozenset(
        (str(k), str(v))
        for k, v in await conn.execute(
            text("SELECT kind, value FROM investigation_entities WHERE investigation_id = :i"),
            {"i": row.investigation_id},
        )
    )
    body = (
        await conn.execute(
            text(
                "SELECT body FROM dossiers WHERE investigation_id = :i"
                " ORDER BY version DESC, created_at DESC LIMIT 1"
            ),
            {"i": row.investigation_id},
        )
    ).scalar_one_or_none() or {}
    signals: dict[str, tuple[str, Any]] = {}
    for signal in [*(body.get("local_signals") or []), *(body.get("signals") or [])]:
        if isinstance(signal, Mapping) and isinstance(signal.get("name"), str):
            signals[signal["name"]] = (str(signal.get("status")), signal.get("value"))
    ti = ((body.get("context") or {}).get("pack") or {}).get("ti") or {}
    listed = tuple(sorted({str(v) for v in ti.get("listed") or () if isinstance(v, str)}))[:50]
    actors, campus = _actors(inv.group_key, classifier)
    keys = frozenset(
        (a.kind, a.value)
        for a in actors
        if a.kind == "host" or (a.kind == "ip" and classifier.classify(a.value).ip_class in CAMPUS)
    )
    held = (
        await conn.execute(
            text(
                "SELECT case_id FROM case_members WHERE investigation_id = :i"
                " AND removed_at IS NULL"
            ),
            {"i": row.investigation_id},
        )
    ).scalar_one_or_none()
    return Candidate(
        source=row.source,
        source_id=int(row.id),
        investigation_id=row.investigation_id,
        by_person=bool(row.by_person),
        at=row.at,
        rule_name=inv.rule_name,
        severity=_severity(inv.severity),
        actors=actors,
        campus_actor=campus,
        entities=entities,
        listed=listed,
        signals=signals,
        held_by=held,
        by_user_id=None if row.by_user_id is None else int(row.by_user_id),
        campus_keys=keys,
    )


@dataclass(frozen=True)
class Observed:
    """An investigation as membership sees it: who acted, what it involves, when."""

    investigation_id: uuid.UUID
    rule_name: str | None
    severity: Severity
    actors: tuple[Indicator, ...]
    campus_actor: bool
    entities: frozenset[tuple[str, str]]
    last_event_at: datetime | None


async def observe(
    conn: AsyncConnection, investigation_id: uuid.UUID, classifier: IpClassifier
) -> Observed | None:
    """The investigation's identity facts (the same reading :func:`candidates` makes of one), or
    None when it is gone."""
    inv = (
        await conn.execute(
            text(
                "SELECT rule_name, severity, group_key, last_event_at FROM investigations"
                " WHERE id = :i"
            ),
            {"i": investigation_id},
        )
    ).first()
    if inv is None:
        return None
    entities = frozenset(
        (str(k), str(v))
        for k, v in await conn.execute(
            text("SELECT kind, value FROM investigation_entities WHERE investigation_id = :i"),
            {"i": investigation_id},
        )
    )
    actors, campus = _actors(inv.group_key, classifier)
    return Observed(investigation_id, inv.rule_name, _severity(inv.severity), actors, campus,
                    entities, inv.last_event_at)  # fmt: skip


async def index(conn: AsyncConnection, now: datetime) -> list[Indexed]:
    """Active cases, and cases closed within the watch, with members and indicators."""
    cases = (
        await conn.execute(
            text(
                "SELECT id, number, state, closed_at, cause FROM cases WHERE state <> 'closed'"
                " OR closed_at >= :since ORDER BY number"
            ),
            {"since": now - WATCH_AFTER_CLOSURE},
        )
    ).all()
    return await _indexed(conn, cases)


async def fresh(
    conn: AsyncConnection, candidate: Candidate, now: datetime
) -> tuple[Candidate, list[Indexed]]:
    """The candidate and the cases it could be in, join or follow, as they are now: cases that
    hold its investigation, and active or recently closed cases sharing one of its actors or
    values (called under the opener's lock, so another run's cases are seen)."""
    keys = sorted({(a.kind, a.value) for a in candidate.actors} | set(candidate.entities))
    params = {
        "inv": candidate.investigation_id,
        "since": now - WATCH_AFTER_CLOSURE,
        "kinds": [k for k, _ in keys],
        "values": [v for _, v in keys],
    }
    cases = (
        await conn.execute(
            text(
                "SELECT id, number, state, closed_at, cause FROM cases c WHERE EXISTS (SELECT 1"
                " FROM case_members m WHERE m.case_id = c.id AND m.investigation_id = :inv"
                " AND m.removed_at IS NULL) OR ((state <> 'closed' OR closed_at >= :since)"
                " AND EXISTS (SELECT 1 FROM case_indicators i WHERE i.case_id = c.id"
                " AND i.removed_at IS NULL AND (i.kind, i.value) IN (SELECT k, v FROM"
                " unnest(CAST(:kinds AS text[]), CAST(:values AS text[])) AS u(k, v))))"
                " ORDER BY number"
            ),
            params,
        )
    ).all()
    indexed = await _indexed(conn, cases)
    held = next((c.ref for c in indexed if candidate.investigation_id in c.members), None)
    assert held is None or isinstance(held, uuid.UUID)
    return replace(candidate, held_by=held), indexed


async def _indexed(conn: AsyncConnection, cases: Sequence[Any]) -> list[Indexed]:
    out = []
    for case in cases:
        members = set(
            (
                await conn.execute(
                    text(
                        "SELECT investigation_id FROM case_members WHERE case_id = :c"
                        " AND removed_at IS NULL"
                    ),
                    {"c": case.id},
                )
            ).scalars()
        )
        marks = {
            (str(k), str(v)): str(r)
            for k, v, r in await conn.execute(
                text(
                    "SELECT kind, value, role FROM case_indicators WHERE case_id = :c"
                    " AND removed_at IS NULL"
                ),
                {"c": case.id},
            )
        }
        out.append(Indexed(case.id, int(case.number), case.state, case.closed_at, members, marks,
                           await _tie_of(conn, case.id), case.cause))  # fmt: skip
    return out


async def _tie_of(conn: AsyncConnection, case_id: uuid.UUID) -> frozenset[uuid.UUID | str]:
    """The cases whose tie opened this one: the tie suggestions of the investigation it was
    opened for, when its opening says it was opened after a tie."""
    rows = await conn.execute(
        text(
            "SELECT DISTINCT s.case_id FROM case_openings o JOIN case_suggestions s ON"
            " s.investigation_id = o.investigation_id AND s.kind = 'tie' WHERE o.case_id = :c"
            " AND o.decision IN ('opened', 'suspected') AND o.reasons @> CAST(:marker AS jsonb)"
        ),
        {"c": case_id, "marker": json.dumps([TIE_OPENED])},
    )
    return frozenset(rows.scalars())


async def created_last_hour(conn: AsyncConnection) -> int:
    """The opener's new cases in the last hour. Suggested cases (cause ``raised``) have their own
    budget (:data:`argus.cases.suggest.MAX_SUGGESTED_PER_HOUR`) and never use this one up."""
    count: int = (
        await conn.execute(
            text(
                "SELECT count(*) FROM cases WHERE cause NOT IN ('person', 'raised')"
                " AND created_at > now() - interval '1 hour'"
            )
        )
    ).scalar_one()
    return count


@dataclass
class Report:
    planned: list[Opening]
    applied: dict[str, int] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)
    replanned: list[str] = field(default_factory=list)  # decided otherwise under the lock

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for opening in self.planned:
            out[opening.decision] = out.get(opening.decision, 0) + 1
        return out


async def run(
    engine: AsyncEngine,
    *,
    window: timedelta,
    classifier: IpClassifier,
    dry_run: bool,
    part: str = "opener",
    since: datetime | None = None,
    shared: Shared | None = None,
) -> Report:
    """Plan over the undecided verdicts and proposals of the last ``window`` (and back to
    ``since``, if that is earlier); apply each decision in its own transaction unless
    ``dry_run``. ``shared``: the shared infrastructure (default ``config/shared_infrastructure
    .yaml``) plus the values the database shows in very many investigations."""
    base = membership.load_shared() if shared is None else shared
    async with engine.connect() as conn:
        now = (await conn.execute(text("SELECT now()"))).scalar_one()
        start = now - window if since is None else min(now - window, since)
        found = await candidates(conn, since=start, classifier=classifier)
        known = await index(conn, now)
        recent = await created_last_hour(conn)
        wanted: set[tuple[str, str]] = {(a.kind, a.value) for c in found for a in c.actors}
        wanted |= {key for c in found for key in c.entities}
        shared = base.with_common(
            base.common | await membership.common_values(conn, wanted, now - window)
        )
    report = Report(plan(found, known, now=now, created_last_hour=recent, shared=shared))
    titles = titling.Context(classifier)
    if dry_run:
        async with engine.connect() as conn:
            report.planned = [await _titled(conn, o, titles) for o in report.planned]
        return report
    actor = Actor.argus(part)
    for planned in report.planned:
        if planned.decision == "deferred":
            continue
        try:
            async with engine.begin() as conn:
                await conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": OPENER_LOCK_KEY})
                if await _decided(conn, planned.candidate):
                    report.skipped.append(f"{_name(planned)}: decided meanwhile")
                    continue
                # planned again against the cases as they are now (another run may have opened
                # or linked cases since this run looked), with the hour's count taken again
                candidate, cases = await fresh(conn, planned.candidate, now)
                opening = plan([candidate], cases, now=now,
                               created_last_hour=await created_last_hour(conn),
                               shared=shared)[0]  # fmt: skip
                if opening.decision == "deferred":
                    report.skipped.append(
                        f"{_name(planned)}: over {MAX_NEW_PER_HOUR} new cases an hour"
                        " (another run opened them)"
                    )
                    continue
                opening = await _titled(conn, opening, titles)
                case_id = await _apply(conn, actor, opening)
                await _record(conn, actor, opening, case_id)
            if opening.decision != planned.decision:
                report.replanned.append(
                    f"{_name(planned)}: {opening.decision} instead of {planned.decision}"
                    f" (the cases changed meanwhile): {'; '.join(opening.reasons)}"
                )
        except CaseRefused as exc:
            report.skipped.append(f"{_name(planned)}: {exc.message}")
            continue
        except DBAPIError as exc:  # one candidate's failure leaves the others to run
            code = getattr(exc.orig, "sqlstate", None)
            report.skipped.append(f"{_name(planned)}: refused by the database ({code})")
            continue
        report.applied[opening.decision] = report.applied.get(opening.decision, 0) + 1
    return report


async def _titled(conn: AsyncConnection, opening: Opening, ctx: titling.Context) -> Opening:
    """The opening with the title made from the database's facts: the investigation's
    flags, threat-listed values, outside answers, internal sites and stored web checks."""
    if opening.title is None or opening.decision not in ("opened", "suspected"):
        return opening
    title = await titling.for_members(
        conn,
        [opening.candidate.investigation_id],
        opening.indicators,
        ctx,
        opening.title,
        follows=opening.parent,
    )
    return replace(opening, title=title)


def _name(opening: Opening) -> str:
    return f"{opening.candidate.source} {opening.candidate.source_id}"


async def _decided(conn: AsyncConnection, candidate: Candidate) -> bool:
    found = (
        await conn.execute(
            text("SELECT 1 FROM case_openings WHERE source = :s AND source_id = :i"),
            {"s": candidate.source, "i": candidate.source_id},
        )
    ).first()
    return found is not None


async def _apply(conn: AsyncConnection, actor: Actor, opening: Opening) -> uuid.UUID | None:
    """One decision, planned against the cases as they are now: a placeholder reference is a
    case this decision opens, any other is a case in the database."""
    candidate = opening.candidate
    service = await CaseService.start(conn)
    ref = opening.case_ref
    if opening.decision == "opened" and isinstance(ref, uuid.UUID):  # confirms a suspected case
        if candidate.by_user_id is None:
            raise CaseRefused("conflict", "only a person's verdict confirms a suspected case")
        link = () if opening.link is None else (
            Member(candidate.investigation_id, opening.link, opening.link_value),  # type: ignore[arg-type]
        )  # fmt: skip
        await service.apply(actor, ref, ConfirmByVerdict(candidate.source_id,
                                                         candidate.by_user_id, link,
                                                         opening.indicators,
                                                         candidate.severity),
                            expected_version=None)  # fmt: skip
        return ref
    case_id = ref if isinstance(ref, uuid.UUID) else None
    if opening.decision in ("opened", "suspected"):
        assert opening.title is not None
        assert isinstance(ref, str)
        verdict = candidate.source == "review"
        command = Open(
            opening.title, candidate.severity, "verdict" if verdict else "proposal",
            (Member(candidate.investigation_id, "verdict" if verdict else "proposal"),),
            opening.indicators,
            suspected=not verdict,
            cause_review_id=candidate.source_id if verdict else None,
            cause_assessment_id=None if verdict else candidate.source_id,
            parent_case_id=opening.parent,
        )  # fmt: skip
        applied = await service.open(actor, command)
        if opening.parent is not None:
            await service.apply(actor, opening.parent, AfterClosure(applied.case.id),
                                expected_version=None)  # fmt: skip
        return applied.case.id
    if opening.decision == "linked":
        if case_id is None:
            raise CaseRefused("conflict", "the case it links to was not opened")
        case = await service.get(case_id, lock=True)
        if case is None:
            raise CaseRefused("conflict", "the case it links to is gone")
        member = Member(candidate.investigation_id, opening.link, opening.link_value)  # type: ignore[arg-type]
        if case.state == "contained":
            summary = (
                f"{opening.link} {opening.link_value} again in investigation"
                f" {candidate.investigation_id}"
            )
            await service.apply(actor, case_id, NewActivity(summary, (member,), opening.indicators,
                                                            candidate.severity),
                                expected_version=None)  # fmt: skip
        else:
            await service.apply(actor, case_id, Link((member,), opening.indicators,
                                                     candidate.severity),
                                expected_version=None)  # fmt: skip
        return case_id
    return case_id


async def _record(
    conn: AsyncConnection, actor: Actor, opening: Opening, case_id: uuid.UUID | None
) -> None:
    decision = opening.decision
    await conn.execute(
        text(
            "INSERT INTO case_openings (source, source_id, investigation_id, decision, case_id,"
            " reasons, decided_by) VALUES (:s, :i, :inv, :d, :c, CAST(:r AS jsonb), :by)"
        ),
        {"s": opening.candidate.source, "i": opening.candidate.source_id,
         "inv": opening.candidate.investigation_id, "d": decision,
         "c": case_id if decision != "attempt" else None,
         "r": json.dumps(list(opening.reasons)), "by": actor.name},
    )  # fmt: skip
    await suggest(conn, opening.candidate.investigation_id, opening.suggested)


async def suggest(
    conn: AsyncConnection, investigation_id: uuid.UUID, suggested: Iterable[membership.Suggested]
) -> list[uuid.UUID]:
    """Record the cases an investigation matches but does not join (once each: a person's
    dismissal stands); returns the cases newly suggested. Cases this plan has not opened yet
    (placeholders) are left out."""
    added: list[uuid.UUID] = []
    for item in suggested:
        case = item.case
        assert isinstance(case, Indexed)
        if not isinstance(case.ref, uuid.UUID):
            continue
        result = await conn.execute(
            text(
                "INSERT INTO case_suggestions (investigation_id, case_id, link, link_value, kind,"
                " why) VALUES (:inv, :case, :link, :value, :kind, :why)"
                " ON CONFLICT (investigation_id, case_id) DO NOTHING"
            ),
            {"inv": investigation_id, "case": case.ref, "link": item.match.link,
             "value": item.match.value[:512], "kind": item.kind, "why": item.words()[:300]},
        )  # fmt: skip
        if result.rowcount:
            added.append(case.ref)
    return added


def describe(opening: Opening) -> str:
    """One line for a dry run or a report."""
    c = opening.candidate
    who = "a person's verdict" if c.by_person else "a proposal"
    target = "" if opening.case_ref is None else f" -> {opening.case_ref}"
    return (
        f"{opening.decision:<15} {c.source} {c.source_id} ({who}, investigation"
        f" {c.investigation_id}){target}: {'; '.join(opening.reasons)}"
    )
