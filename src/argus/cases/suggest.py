"""Suggest a case from evidence across investigations: the story a person pieces together by hand.

Three kinds of generic evidence (never a rule's name) within 72 hours of unreviewed
investigations: a **campaign** (several internal devices reaching one flagged destination, or one
operator's destinations; ``argus.campaigns``), a **host seen by several rules** or with the same
flag on several days when one of its investigations needs attention, and **actors that hit the
same rare targets**. Evidence sharing an investigation is one component, which becomes one
*suspected* case for a person to confirm or dismiss (ARGUS opens nothing), or links into the
raised suspected case it touches, or is suggested to the active cases holding its siblings. What
an open case already holds is never suggested into a new one; a campaign is offered only to a
case holding one of its indicators. A person's "no" stands for :data:`DISMISSAL_STANDS`. New
cases and offers have hourly budgets of their own. :func:`plan` is pure; :func:`run` applies each
action in its own transaction."""

from __future__ import annotations

import uuid
from collections import Counter, defaultdict
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import date, datetime, timedelta
from itertools import combinations
from typing import Literal

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus import site
from argus.assess.patterns import day_of
from argus.assess.raised import raises
from argus.assets.classify import IpClassifier
from argus.campaigns.analysis import MIN_SERVER_HOSTS, Campaign
from argus.cases import membership, naming, opener, titling
from argus.cases.machine import RAISED_REASON, CaseRefused, Link, Open
from argus.cases.membership import NO_SHARED, Shared
from argus.cases.model import SEVERITIES, Actor, Indicator, Member, Severity
from argus.cases.service import CaseService

PART = "raise"  # ARGUS acts as ``argus:raise``
WINDOW = timedelta(hours=72)
MIN_RULES = 2  # rules that fired for one host
MIN_DAYS = 2  # days the same flag was seen on one host
MAX_RARE_ACTORS = 6  # a target more actors than this reach is not rare
MIN_SHARED = 2  # rare targets two actors must share to be one story
MAX_MEMBERS = 200  # investigations in one suggested case
MAX_TARGETS = 20  # shared targets kept as the case's indicators
MAX_SUGGESTED_PER_HOUR = 20  # new suggested cases an hour: its own pool, apart from the opener's
MAX_OFFERS_PER_HOUR = 30  # offers to open cases an hour (one for each new device)
MAX_CAMPAIGN_KEYS = 250  # a campaign's domains and servers a case stores (MAX_MEMBERS in all)
MAX_ACTORS = 200  # devices a suggested case stores as actors
MAX_ENTITIES = 50  # addresses and names read per investigation (a scanner has thousands)
DISMISSAL_STANDS = timedelta(days=14)  # how long a person's "no" holds (as the opener's watch)
PREVALENCE = timedelta(days=5)  # the window of the "very many investigations" test
PATH_FIELD = "url.path"
PATH_SEGMENTS = 2
PATH_CHARS = 200
TARGET_KINDS = ("ip", "domain")
Key = tuple[str, str]  # (kind, value)


@dataclass(frozen=True)
class Held:
    """The case an investigation is in already."""

    case_id: uuid.UUID
    number: int
    state: str
    cause: str


@dataclass(frozen=True)
class Seen:
    """An unreviewed investigation as the suggester sees it."""

    investigation_id: uuid.UUID
    rule: str  # the rule's name (a rule recreated in Kibana keeps it), else its id
    severity: Severity
    day: date  # its local day
    at: datetime  # its last alert
    actors: frozenset[Key]  # who acted: addresses and hosts, never accounts
    campus: frozenset[Key]  # the actors that are internal hosts
    flags: tuple[str, ...]  # the evidence's generic flags (investigation_raises)
    targets: frozenset[Key]  # what it reached: ("ip" | "domain" | "url", value)
    held: Held | None = None


@dataclass(frozen=True)
class Existing:
    """A raised case a person has not confirmed yet: later investigations of its actors join it."""

    ref: uuid.UUID
    number: int
    actors: frozenset[Key]
    indicators: frozenset[Key] = frozenset()  # the addresses and names it holds


@dataclass(frozen=True)
class Live:
    """Any other case that is not closed (suspected by a person's verdict, open, assigned,
    contained): what it holds is never suggested into a new case."""

    ref: uuid.UUID
    number: int
    state: str
    actors: frozenset[Key]
    indicators: frozenset[Key] = frozenset()


@dataclass(frozen=True)
class Dismissed:
    """A suggested case a person dismissed: who it was about, the addresses and names it held and
    the flag kinds its members had."""

    actors: frozenset[Key]
    flags: frozenset[str]
    indicators: frozenset[Key] = frozenset()


@dataclass(frozen=True)
class OpenCase:
    members: tuple[Seen, ...]
    actors: tuple[Indicator, ...]
    targets: tuple[Indicator, ...]
    flags: tuple[str, ...]
    severity: Severity
    title: str
    attention: str


@dataclass(frozen=True)
class LinkCase:
    case: Existing
    members: tuple[Seen, ...]
    actors: tuple[Indicator, ...]
    targets: tuple[Indicator, ...]
    severity: Severity
    reason: str


@dataclass(frozen=True)
class SuggestMembers:
    """Investigations that may belong to an active case (``case_suggestions``): a person joins."""

    case_id: uuid.UUID
    number: int
    kind: Literal["also", "tie"]
    members: tuple[Seen, ...]
    reason: str


Action = OpenCase | LinkCase | SuggestMembers


def path_target(value: str) -> str | None:
    """A request path as the directory it names: no query or fragment, at most two segments
    (``/~user5/.git/HEAD`` is ``/~user5/.git``), and None for the site's root or no path."""
    path = value.split("?", 1)[0].split("#", 1)[0]
    parts = [p for p in path.split("/") if p.strip()]
    if not parts:
        return None
    return ("/" + "/".join(parts[:PATH_SEGMENTS]))[:PATH_CHARS]


@dataclass(frozen=True)
class _Evidence:
    members: frozenset[uuid.UUID]
    reason: str
    actors: frozenset[Key]
    targets: frozenset[Key] = frozenset()
    counted: bool = False  # the reason leads with how many investigations the case holds
    campaign: bool = False  # from ``argus.campaigns``: its targets are the campaign's indicators

    def words(self, kept: Collection[uuid.UUID]) -> str:
        """The reason, counting only the investigations that go into the case or offer (``kept``)
        and not the ones another case holds already."""
        if not self.counted:
            return self.reason
        n = len(self.members & set(kept))
        many = "investigation" if n == 1 else "investigations"
        return f"{n} {many} of one {site.own('host')}: {self.reason}"


def _hosts(seen: Sequence[Seen]) -> list[_Evidence]:
    """An internal host with investigations from two or more rules (one of them flagged), or the
    same flag on two or more days, when one of its investigations is in Needs attention
    (``raises``): the pair without a raise was most of the noise."""
    by_host: dict[Key, list[Seen]] = defaultdict(list)
    for s in seen:
        for host in s.campus:
            by_host[host].append(s)
    out = []
    for host in sorted(by_host):
        group = by_host[host]
        if not any(raises(s.flags) for s in group):
            continue
        rules = {s.rule for s in group}
        flagged = [s for s in group if s.flags]
        parts = []
        if len(rules) >= MIN_RULES and flagged:
            parts.append(f"{len(rules)} rules fired")
        repeated = sorted(
            f for f in {f for s in flagged for f in s.flags}
            if len({s.day for s in flagged if f in s.flags}) >= MIN_DAYS
        )  # fmt: skip
        if repeated:
            days = max(len({s.day for s in flagged if f in s.flags}) for f in repeated)
            parts.append(f"the same flag on {days} days ({', '.join(repeated)})")
        if parts:
            out.append(_Evidence(frozenset(s.investigation_id for s in group), " and ".join(parts),
                                 frozenset({host}), counted=True))  # fmt: skip
    return out


def _campaigns(seen: Sequence[Seen], campaigns: Iterable[Campaign]) -> list[_Evidence]:
    """Each campaign as evidence: the unreviewed investigations of the window that belong to it
    (the investigations of its hosts that hold its names or reach its servers)."""
    here = {s.investigation_id for s in seen}
    out = []
    for c in campaigns:
        members = c.members & here
        if members:
            out.append(_Evidence(frozenset(members), c.reason(), frozenset(c.hosts), c.keys(),
                                 campaign=True))  # fmt: skip
    return out


def in_attention(s: Seen) -> bool:
    """Whether the pages put the investigation in Needs attention: the rule rates it high or
    critical, or ARGUS raised it (``raises``)."""
    return s.severity in ("high", "critical") or raises(s.flags)


def _shared_targets(seen: Sequence[Seen], shared: Shared) -> list[_Evidence]:
    """Actors that reach the same rare targets: two actors are one story when they share
    :data:`MIN_SHARED` targets that no more than :data:`MAX_RARE_ACTORS` actors reach, and one of
    the investigations of the story is in Needs attention (without that, most suggestions were
    such stories of low, unraised investigations)."""
    reach: dict[Key, set[Key]] = defaultdict(set)
    for s in seen:
        for target in s.targets:
            if shared.reason(*target) is None:
                reach[target].update(s.actors)
    rare = {t: who for t, who in reach.items() if 2 <= len(who) <= MAX_RARE_ACTORS}
    together: dict[tuple[Key, Key], int] = defaultdict(int)
    for who in rare.values():
        for pair in combinations(sorted(who), 2):
            together[pair] += 1
    parent: dict[Key, Key] = {}

    def find(x: Key) -> Key:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for (a, b), n in together.items():
        if n >= MIN_SHARED:
            parent[find(a)] = find(b)
    clusters: dict[Key, set[Key]] = defaultdict(set)
    for actor in list(parent):
        clusters[find(actor)].add(actor)
    out = []
    for root in sorted(clusters):
        actors = frozenset(clusters[root])
        targets = frozenset(t for t, who in rare.items() if len(who & actors) >= 2)
        involved = [s for s in seen if s.actors & actors]
        if not any(in_attention(s) for s in involved):
            continue
        members = frozenset(s.investigation_id for s in involved)
        reason = f"{len(actors)} actors reached the same {len(targets)} rare targets"
        out.append(_Evidence(members, reason, actors, targets))
    return out


def _components(evidence: Iterable[_Evidence]) -> list[list[_Evidence]]:
    """The evidence that shares an investigation, merged (an investigation is in one case)."""
    parent: dict[uuid.UUID, uuid.UUID] = {}

    def find(x: uuid.UUID) -> uuid.UUID:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    items = list(evidence)
    items = [item for item in items if item.members]
    for item in items:
        ordered = sorted(item.members)
        for other in ordered[1:]:
            parent[find(other)] = find(ordered[0])
        find(ordered[0])
    groups: dict[uuid.UUID, list[_Evidence]] = defaultdict(list)
    for item in items:
        groups[find(min(item.members))].append(item)
    return [groups[root] for root in sorted(groups)]


def _severity(seen: Iterable[Seen]) -> Severity:
    """The highest of the members', and at least medium: ARGUS saw evidence of something."""
    rank = max((SEVERITIES.index(s.severity) for s in seen), default=0)
    return SEVERITIES[max(rank, SEVERITIES.index("medium"))]


def _facts(
    members: Sequence[Seen], actors: frozenset[Key], targets: frozenset[Key], keys: frozenset[Key]
) -> naming.Facts:
    """What the title can say from the investigations alone (:mod:`argus.cases.naming`): their
    rules and flags, who acted, a campaign's flagged servers (``keys``) and the names reached.
    The title that is stored is made again from the database's facts (:func:`run`)."""
    campus = frozenset(a for a in actors if any(a in s.campus for s in members))
    rules = Counter(s.rule for s in members if s.rule)
    return naming.Facts(
        rules=tuple(sorted(rules.items(), key=lambda kv: (-kv[1], kv[0]))),
        flags=frozenset(f for s in members for f in s.flags),
        devices=tuple(naming.Device(v, k) for k, v in sorted(campus) if k in ("ip", "host")),
        outsiders=tuple(v for k, v in sorted(actors - campus) if k == "ip"),
        servers=tuple(v for k, v in sorted(keys) if k in ("ip", "domain")),
        domains=tuple(v for k, v in sorted(targets) if k == "domain"),
    )


def _indicators(keys: Iterable[Key], role: Literal["actor", "indicator"]) -> tuple[Indicator, ...]:
    return tuple(
        Indicator(kind, value, role, "investigation")  # type: ignore[arg-type]
        for kind, value in sorted(keys)
        if value and len(value) <= 512
    )


def _with_devices(s: Seen, devices: Mapping[uuid.UUID, frozenset[Key]]) -> Seen:
    """``s`` with the internal devices a campaign found behind it as actors too."""
    extra = devices.get(s.investigation_id)
    return replace(s, actors=s.actors | extra, campus=s.campus | extra) if extra else s


def _unshared(s: Seen, shared: Shared) -> Seen:
    """``s`` without the actors that are shared infrastructure: an address in a content-delivery or
    cloud network, or a value in very many investigations, says nothing about who is behind it."""
    drop = {a for a in s.actors if shared.reason(*a) is not None}
    return replace(s, actors=s.actors - drop, campus=s.campus - drop) if drop else s


def _why(group: Iterable[_Evidence], kept: Sequence[Seen]) -> str:
    """The reason of a component, counting the investigations in ``kept`` only."""
    ids = [s.investigation_id for s in kept]
    return "; ".join(dict.fromkeys(e.words(ids) for e in group))


def _declined(
    actors: frozenset[Key], flags: Iterable[str], dismissed: Iterable[Dismissed],
    keys: frozenset[Key] = frozenset(),
) -> bool:  # fmt: skip
    """Whether a person said no to this already: dismissed suggestions about these actors (or a
    larger set of them), or, for a campaign, that held all of its domains and servers (``keys``,
    as many as a case stores), had every one of the flags."""
    stored = frozenset(sorted(keys)[:MAX_CAMPAIGN_KEYS])
    same = [
        d for d in dismissed
        if (actors and actors <= d.actors) or (stored and stored <= d.indicators)
    ]  # fmt: skip
    return bool(same) and set(flags) <= {f for d in same for f in d.flags}


def _priority(case: OpenCase) -> tuple[bool, int, float, str]:
    """The order new suggestions are spent in: flagged first, then the most severe, then the
    newest (a stable last tie)."""
    return (not case.flags, -SEVERITIES.index(case.severity),
            -max(s.at for s in case.members).timestamp(),
            str(min(s.investigation_id for s in case.members)))  # fmt: skip


def plan(
    seen: Iterable[Seen],
    existing: Iterable[Existing],
    *,
    now: datetime,
    shared: Shared = NO_SHARED,
    new_budget: int = MAX_SUGGESTED_PER_HOUR,
    dismissed: Iterable[Dismissed] = (),
    campaigns: Iterable[Campaign] = (),
    live: Iterable[Live] = (),
    offer_budget: int = MAX_OFFERS_PER_HOUR,
    offered: Collection[tuple[uuid.UUID, uuid.UUID]] = (),
) -> list[Action]:
    """The suggestions for the unreviewed investigations of the last :data:`WINDOW`. Pure, and
    the same for the same investigations in any order. At most ``new_budget`` new cases, the
    flagged, most severe and newest first; none that a person dismissed already, and none for
    what an open case holds (``existing``: suggested cases nobody confirmed yet; ``live``: every
    other case that is not closed): that is linked or offered to the case instead, at most
    ``offer_budget`` offers (one for each new device), and not an investigation that was offered
    to that case already (``offered``: (investigation, case) pairs; a person's answer stands)."""
    found = list(campaigns)
    devices: dict[uuid.UUID, frozenset[Key]] = {}
    for c in found:  # a campaign knows the devices behind an investigation its key does not name
        for i, hosts in c.member_hosts.items():
            devices[i] = devices.get(i, frozenset()) | hosts
    window = sorted(
        (_unshared(_with_devices(s, devices), shared) for s in seen if now - WINDOW <= s.at <= now),
        key=lambda s: (s.at, s.investigation_id),
    )
    by_id = {s.investigation_id: s for s in window}
    raised = sorted(existing, key=lambda e: e.number)
    suggested = {e.ref for e in raised}
    cases = sorted((c for c in live if c.ref not in suggested), key=lambda c: c.number)
    refused = list(dismissed)
    actions: list[Action] = []
    wanted: list[OpenCase] = []
    covered: set[uuid.UUID] = set()
    evidence = [*_campaigns(window, found), *_hosts(window), *_shared_targets(window, shared)]
    for group in _components(evidence):
        members = sorted(
            (by_id[i] for e in group for i in e.members), key=lambda s: (s.at, s.investigation_id)
        )
        members = list({s.investigation_id: s for s in members}.values())
        covered.update(s.investigation_id for s in members)
        actors = frozenset(a for e in group for a in e.actors)
        targets = frozenset(t for e in group for t in e.targets)
        keys = frozenset(t for e in group if e.campaign for t in e.targets)
        campaign = any(e.campaign for e in group)
        free = [s for s in members if s.held is None]
        if not free:
            continue
        first, last = free[:MAX_MEMBERS], free[-MAX_MEMBERS:]

        holding = {s.held.case_id: s.held for s in members if s.held is not None}
        active = [h for h in holding.values() if h.state != "closed"]
        if campaign:  # its case is the one that holds its domains or servers, and no other
            touched = [e for e in raised if e.indicators & keys]
            owners = [c for c in cases if c.indicators & keys]
        else:
            touched = [e for e in raised if _holds(e, holding, actors, targets)]
            owners = [c for c in cases if _holds(c, holding, actors, targets)]
        if len(touched) == 1 and not owners:
            actions.append(_link(touched[0], free, actors, targets, _why(group, last), keys))
        elif touched and not owners:
            actions.extend(
                SuggestMembers(e.ref, e.number, "tie", tuple(first),
                               f"matches several suggested cases: {_why(group, first)}")
                for e in touched
            )  # fmt: skip
        elif touched or owners:  # what a case holds is never suggested into a new one
            kind: Literal["also", "tie"] = "also" if len(touched) + len(owners) == 1 else "tie"
            both: list[Existing | Live] = [*touched, *owners]
            for owner in sorted(both, key=lambda c: c.number):
                actions.extend(_offers(owner.ref, owner.number, owner.actors, kind, free,
                                       _why(group, free)))  # fmt: skip
        elif active and not campaign:
            actions.extend(
                SuggestMembers(h.case_id, h.number, "also", tuple(first), _why(group, first))
                for h in sorted(active, key=lambda h: h.number)
            )  # fmt: skip
        elif (campaign and len({d for s in free for d in s.campus}) >= MIN_SERVER_HOSTS) or (
            not campaign and len(free) >= 2
        ):  # a campaign still meets its threshold with the free members only
            case = _open(last, actors, targets, _why(group, last), campaign=campaign, keys=keys,
                         elsewhere=_elsewhere(members, active))  # fmt: skip
            if not _declined(actors, case.flags, refused, keys):
                wanted.append(case)
    actions.extend(sorted(wanted, key=_priority)[: max(new_budget, 0)])
    for s in window:  # an investigation of a suggested case's actor arriving later joins it
        if s.held is not None or s.investigation_id in covered:
            continue
        hits = [e for e in raised if e.actors & s.actors]
        if len(hits) == 1:
            actions.append(_link(hits[0], [s], s.actors & hits[0].actors, frozenset(),
                                 "an actor of this suggested case"))  # fmt: skip
    return _budgeted(_merged(actions), set(offered), offer_budget)


def _budgeted(
    actions: list[Action], offered: set[tuple[uuid.UUID, uuid.UUID]], budget: int
) -> list[Action]:  # fmt: skip
    """``actions`` with the offers cut to the hourly budget, each without the investigations that
    were offered to that case already (an offer with none left is dropped)."""
    out: list[Action] = []
    left = max(budget, 0)
    for action in actions:
        if isinstance(action, SuggestMembers):
            fresh = tuple(m for m in action.members if (m.investigation_id, action.case_id)
                          not in offered)  # fmt: skip
            if not fresh or left <= 0:
                continue
            left -= 1
            action = replace(action, members=fresh)
        out.append(action)
    return out


def _elsewhere(members: Sequence[Seen], active: Sequence[Held]) -> str:
    """The open cases that hold some of a campaign's investigations, in words ("also in case 7
    (3 investigations), case 9 (1 investigation)"): they stay there, the campaign's case does not
    take them."""
    count: dict[int, int] = defaultdict(int)
    open_cases = {h.case_id: h.number for h in active}
    for s in members:
        if s.held is not None and s.held.case_id in open_cases:
            count[open_cases[s.held.case_id]] += 1
    parts = [f"case {n} ({k} investigation{'s' if k != 1 else ''})"
             for n, k in sorted(count.items())]  # fmt: skip
    return "also in " + ", ".join(parts[:5]) if parts else ""


def _holds(
    case: Existing | Live, holding: Mapping[uuid.UUID, Held], actors: frozenset[Key],
    targets: frozenset[Key],
) -> bool:  # fmt: skip
    """Whether a case holds some of a component: one of its investigations, one of its hosts or
    actors, or one of the addresses and names its evidence reached."""
    return case.ref in holding or bool(case.actors & actors) or bool(case.indicators & targets)


def _offers(
    ref: uuid.UUID, number: int, held: frozenset[Key], kind: Literal["also", "tie"],
    free: Sequence[Seen], reason: str,
) -> list[SuggestMembers]:  # fmt: skip
    """The investigations of hosts the case does not have yet, offered to it: one offer for each new
    host (its investigations together). One of a host the case has already gets nothing."""
    by_host: dict[Key, list[Seen]] = defaultdict(list)
    for s in free:
        new = s.actors - held
        if s.actors and not new:
            continue
        by_host[min(new) if new else ("investigation", str(s.investigation_id))].append(s)
    return [
        SuggestMembers(ref, number, kind, tuple(by_host[host][:MAX_MEMBERS]), reason)
        for host in sorted(by_host)
    ]


def _stored_targets(targets: frozenset[Key], keys: frozenset[Key]) -> tuple[Indicator, ...]:
    """The addresses and names a case stores: a campaign's domains and servers (``keys``, up to
    :data:`MAX_CAMPAIGN_KEYS`: a dismissal is compared against them) and some other targets."""
    kept = set(sorted(keys)[:MAX_CAMPAIGN_KEYS]) | set(sorted(targets - keys)[:MAX_TARGETS])
    return _indicators(kept, "indicator")


def _open(
    free: Sequence[Seen], actors: frozenset[Key], targets: frozenset[Key], reason: str,
    *, campaign: bool = False, keys: frozenset[Key] = frozenset(), elsewhere: str = "",
) -> OpenCase:  # fmt: skip
    members = tuple(free)
    flags = tuple(dict.fromkeys(f for s in members for f in s.flags))
    attention = f"{RAISED_REASON}{reason}."
    if elsewhere:
        attention += f" {elsewhere[0].upper()}{elsewhere[1:]}."
    if flags:
        attention += f" Flags: {', '.join(flags)}."
    return OpenCase(
        members,
        _indicators(sorted(actors)[:MAX_ACTORS], "actor"),
        _stored_targets(targets, keys),
        flags,
        _severity(members),
        naming.title(_facts(members, actors, targets, keys if campaign else frozenset())),
        attention[:500],
    )


def _link(
    case: Existing, free: Sequence[Seen], actors: frozenset[Key], targets: frozenset[Key],
    reason: str, keys: frozenset[Key] = frozenset(),
) -> LinkCase:  # fmt: skip
    return LinkCase(case, tuple(free[-MAX_MEMBERS:]),
                    _indicators(sorted(actors)[:MAX_ACTORS], "actor"),
                    _stored_targets(targets, keys), _severity(free), reason)  # fmt: skip


def _merged(actions: list[Action]) -> list[Action]:
    """Several links into one case become one (the case takes one change at a time)."""
    out: list[Action] = []
    links: dict[uuid.UUID, LinkCase] = {}
    for action in actions:
        if not isinstance(action, LinkCase):
            out.append(action)
            continue
        before = links.get(action.case.ref)
        if before is None:
            links[action.case.ref] = action
            out.append(action)
            continue
        merged = LinkCase(
            before.case, tuple(dict.fromkeys([*before.members, *action.members]))[-MAX_MEMBERS:],
            tuple(sorted({*before.actors, *action.actors})),
            tuple(sorted({*before.targets, *action.targets})),
            _severity([*before.members, *action.members]), before.reason,
        )  # fmt: skip
        links[action.case.ref] = merged
        out[out.index(before)] = merged
    return out


_SEEN = """
SELECT i.id, coalesce(i.rule_name, i.rule_id) AS rule, i.severity, i.bucket_start,
       i.last_event_at, i.group_key, r.flags, m.case_id, c.number, c.state, c.cause
FROM investigations i
LEFT JOIN investigation_raises r ON r.investigation_id = i.id AND r.version = i.version
LEFT JOIN case_members m ON m.investigation_id = i.id AND m.removed_at IS NULL
LEFT JOIN cases c ON c.id = m.case_id
WHERE i.last_event_at >= :since
  AND NOT EXISTS (SELECT 1 FROM review_events e WHERE e.investigation_id = i.id
                  AND e.action = 'reviewed' AND e.version = i.version)
ORDER BY i.last_event_at DESC, i.id
LIMIT :limit
"""
_ENTITIES = """
SELECT investigation_id, kind, value FROM (
  SELECT x.investigation_id, x.kind, x.value,
         row_number() OVER (
           PARTITION BY x.investigation_id
           ORDER BY (coalesce(n.investigations, 1) BETWEEN 2 AND :shared_from - 1) DESC,
                    coalesce(n.investigations, 1) DESC, x.kind, x.value
         ) AS rn
  FROM investigation_entities x
  LEFT JOIN entities n ON n.kind = x.kind AND n.value = x.value
  WHERE x.investigation_id = ANY(:ids) AND x.kind = ANY(:kinds)
) ranked
WHERE rn <= :cap
"""
_PATHS = """
SELECT DISTINCT ON (d.investigation_id) d.investigation_id,
       d.body #> CAST(:path AS text[]) AS top
FROM dossiers d JOIN investigations i ON i.id = d.investigation_id AND i.version = d.version
WHERE d.investigation_id = ANY(:ids)
ORDER BY d.investigation_id, d.created_at DESC, d.pack DESC
"""
_RAISED = """
SELECT c.id, c.number FROM cases c WHERE c.cause = 'raised' AND c.state = 'suspected'
"""
_ACTORS = """
SELECT case_id, kind, value FROM case_indicators
WHERE case_id = ANY(:ids) AND role = 'actor' AND removed_at IS NULL
"""
_INDICATORS = """
SELECT case_id, kind, value FROM case_indicators
WHERE case_id = ANY(:ids) AND role IN ('c2', 'indicator') AND removed_at IS NULL
"""
_LIVE = """
SELECT c.id, c.number, c.state FROM cases c
WHERE c.state <> 'closed' AND NOT (c.cause = 'raised' AND c.state = 'suspected')
"""
_DISMISSED = """
SELECT c.id FROM cases c
WHERE c.cause = 'raised' AND c.state = 'closed' AND c.closed_at >= :since
  AND EXISTS (SELECT 1 FROM case_events e WHERE e.case_id = c.id AND e.kind = 'dismissed')
"""
_FLAGS = """
SELECT m.case_id, r.flags FROM case_members m
JOIN investigation_raises r ON r.investigation_id = m.investigation_id
WHERE m.case_id = ANY(:ids) AND m.removed_at IS NULL
"""
_SUGGESTED_LAST_HOUR = """
SELECT count(*) FROM cases WHERE cause = 'raised' AND created_at > now() - interval '1 hour'
"""
_OFFERED_LAST_HOUR = """
SELECT count(*) FROM (
  SELECT DISTINCT case_id, coalesce(link_value, investigation_id::text)
  FROM case_suggestions WHERE created_at > now() - interval '1 hour'
) offers
"""
_OFFERED = """
SELECT investigation_id, case_id FROM case_suggestions WHERE investigation_id = ANY(:ids)
"""
LOAD_LIMIT = 5000


def _severity_of(value: str | None) -> Severity:
    low = (value or "").lower()
    return low if low in SEVERITIES else "medium"


async def load_seen(conn: AsyncConnection, now: datetime, classifier: IpClassifier) -> list[Seen]:
    """The unreviewed investigations of the last :data:`WINDOW` with their actors, flags, targets
    and the case that holds them. Of each investigation's addresses and names it reads at most
    :data:`MAX_ENTITIES`: the ones other investigations share and fewer than "very many" do
    (the most frequent first), the rest after them."""
    rows = (await conn.execute(text(_SEEN), {"since": now - WINDOW, "limit": LOAD_LIMIT})).all()
    ids = [r.id for r in rows]
    targets: dict[uuid.UUID, set[Key]] = defaultdict(set)
    if ids:
        for inv, kind, value in await conn.execute(
            text(_ENTITIES),
            {"ids": ids, "kinds": list(TARGET_KINDS), "cap": MAX_ENTITIES,
             "shared_from": membership.COMMON_INVESTIGATIONS},
        ):  # fmt: skip
            targets[inv].add((str(kind), str(value)))
        for inv, top in await conn.execute(
            text(_PATHS), {"ids": ids, "path": ["context", "pack", "fields", PATH_FIELD, "top"]}
        ):
            for item in top if isinstance(top, list) else []:
                value = item[0] if isinstance(item, list) and item else None
                found = path_target(value) if isinstance(value, str) else None
                if found is not None:
                    targets[inv].add(("url", found))
    out = []
    for r in rows:
        indicators, _ = opener.actors_of(r.group_key, classifier)
        actors = {(a.kind, a.value) for a in indicators if a.kind in ("ip", "host")}
        campus = {
            key for key in actors
            if key[0] == "host" or classifier.classify(key[1]).ip_class in opener.CAMPUS
        }  # fmt: skip
        flags = tuple(f for f in r.flags or () if isinstance(f, str))
        held = None if r.case_id is None else Held(r.case_id, int(r.number), r.state, r.cause)
        out.append(
            Seen(
                r.id,
                r.rule,
                _severity_of(r.severity),
                day_of(r.bucket_start),
                r.last_event_at,
                frozenset(actors),
                frozenset(campus),
                flags,
                frozenset(
                    t
                    for t in targets[r.id]
                    if t not in actors
                    and t[1].strip().lower() not in opener.GENERIC_ACTORS
                    and (t[0] != "ip" or classifier.classify(t[1]).ip_class in opener.LINKABLE)
                ),
                held,
            )
        )
    return out


async def _held(
    conn: AsyncConnection, ids: Sequence[uuid.UUID]
) -> tuple[dict[uuid.UUID, set[Key]], dict[uuid.UUID, set[Key]]]:
    """What cases hold: their actors, and the addresses and names they hold as c2 or other
    indicators."""
    actors: dict[uuid.UUID, set[Key]] = defaultdict(set)
    indicators: dict[uuid.UUID, set[Key]] = defaultdict(set)
    if ids:
        for case_id, kind, value in await conn.execute(text(_ACTORS), {"ids": list(ids)}):
            actors[case_id].add((str(kind), str(value)))
        for case_id, kind, value in await conn.execute(text(_INDICATORS), {"ids": list(ids)}):
            indicators[case_id].add((str(kind), str(value)))
    return actors, indicators


async def load_existing(conn: AsyncConnection) -> list[Existing]:
    cases = (await conn.execute(text(_RAISED))).all()
    actors, indicators = await _held(conn, [c.id for c in cases])
    return [
        Existing(c.id, int(c.number), frozenset(actors[c.id]), frozenset(indicators[c.id]))
        for c in cases
    ]


async def load_live(conn: AsyncConnection) -> list[Live]:
    """Every case that is not closed and not a suggested case nobody confirmed (those are
    :func:`load_existing`'s): what they hold is never suggested into a new case."""
    cases = (await conn.execute(text(_LIVE))).all()
    actors, indicators = await _held(conn, [c.id for c in cases])
    return [
        Live(c.id, int(c.number), str(c.state), frozenset(actors[c.id]),
             frozenset(indicators[c.id]))
        for c in cases
    ]  # fmt: skip


async def load_dismissed(conn: AsyncConnection, now: datetime) -> list[Dismissed]:
    """The suggested cases a person dismissed in the last :data:`DISMISSAL_STANDS`, with their
    actors and the flag kinds their investigations had."""
    ids = list((await conn.execute(text(_DISMISSED), {"since": now - DISMISSAL_STANDS})).scalars())
    if not ids:
        return []
    actors, indicators = await _held(conn, ids)
    flags: dict[uuid.UUID, set[str]] = defaultdict(set)
    for case_id, stored in await conn.execute(text(_FLAGS), {"ids": ids}):
        flags[case_id].update(f for f in stored or () if isinstance(f, str))
    return [
        Dismissed(frozenset(actors[i]), frozenset(flags[i]), frozenset(indicators[i])) for i in ids
    ]


async def suggested_last_hour(conn: AsyncConnection) -> int:
    """New suggested cases in the last hour: what the suggester's own budget has spent."""
    return int((await conn.execute(text(_SUGGESTED_LAST_HOUR))).scalar_one())


async def offered_last_hour(conn: AsyncConnection) -> int:
    """Offers made in the last hour (a case and a device each): what the offers' budget has spent.
    The opener's suggestions to a case are counted too (one pool, no marker to tell them apart)."""
    return int((await conn.execute(text(_OFFERED_LAST_HOUR))).scalar_one())


async def load_offered(
    conn: AsyncConnection, ids: Sequence[uuid.UUID]
) -> set[tuple[uuid.UUID, uuid.UUID]]:  # fmt: skip
    """The (investigation, case) pairs already offered, a person's dismissal included."""
    if not ids:
        return set()
    return {(r[0], r[1]) for r in await conn.execute(text(_OFFERED), {"ids": list(ids)})}


@dataclass
class Report:
    planned: list[Action]
    applied: dict[str, int] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for action in self.planned:
            out[_name(action)] = out.get(_name(action), 0) + 1
        return out


def _name(action: Action) -> str:
    return {OpenCase: "suggested", LinkCase: "linked", SuggestMembers: "offered"}[type(action)]


def describe(action: Action) -> str:
    """One line for a dry run: counts and words, and the new case's title (values of a strict shape
    only: :mod:`argus.cases.naming`)."""
    if isinstance(action, OpenCase):
        return f"suggested   {len(action.members)} investigations: {action.title}"
    if isinstance(action, LinkCase):
        return f"linked      {len(action.members)} to suggested case {action.case.number}"
    return f"offered     {len(action.members)} to case {action.number} ({action.kind})"


async def run(
    engine: AsyncEngine,
    *,
    classifier: IpClassifier,
    dry_run: bool,
    shared: Shared | None = None,
    now: datetime | None = None,
    campaigns: Sequence[Campaign] = (),
    offers_per_hour: int = MAX_OFFERS_PER_HOUR,
) -> Report:
    """Plan over the unreviewed investigations of the last 72 hours; apply each action in its own
    transaction unless ``dry_run``. ``shared``: the shared infrastructure (default
    ``config/shared_infrastructure.yaml``) plus the values the database shows in very many
    investigations. ``campaigns``: what ``argus.campaigns`` found in the history window.
    ``offers_per_hour``: the hourly budget of offers to open cases (``cases.offers_per_hour``)."""
    base = membership.load_shared() if shared is None else shared
    async with engine.connect() as conn:
        clock = now or (await conn.execute(text("SELECT now()"))).scalar_one()
        seen = await load_seen(conn, clock, classifier)
        existing = await load_existing(conn)
        live = await load_live(conn)
        recent = await suggested_last_hour(conn)
        offers = await offered_last_hour(conn)
        offered = await load_offered(conn, [s.investigation_id for s in seen])
        dismissed = await load_dismissed(conn, clock)
        wanted = {t for s in seen for t in s.targets} | {a for s in seen for a in s.actors}
        common = await membership.common_values(conn, wanted, clock - PREVALENCE)
        shared = base.with_common(base.common | common)
    report = Report(plan(seen, existing, now=clock, shared=shared, dismissed=dismissed,
                         new_budget=MAX_SUGGESTED_PER_HOUR - recent, campaigns=campaigns,
                         live=live, offer_budget=offers_per_hour - offers,
                         offered=offered))  # fmt: skip
    report.planned = await _titled(engine, report.planned, classifier)
    if dry_run:
        return report
    actor = Actor.argus(PART)
    for action in report.planned:
        try:
            async with engine.begin() as conn:
                await conn.execute(
                    text("SELECT pg_advisory_xact_lock(:k)"), {"k": opener.OPENER_LOCK_KEY}
                )
                changed = await _apply(conn, actor, action)
        except CaseRefused as exc:
            report.skipped.append(f"{_name(action)}: {exc.message}")
            continue
        except DBAPIError as exc:  # one action's failure leaves the others to run
            code = getattr(exc.orig, "sqlstate", None)
            report.skipped.append(f"{_name(action)}: refused by the database ({code})")
            continue
        if changed:
            report.applied[_name(action)] = report.applied.get(_name(action), 0) + 1
    return report


async def _titled(
    engine: AsyncEngine, actions: list[Action], classifier: IpClassifier
) -> list[Action]:  # fmt: skip
    """The actions with each new case's title made from the database's facts: the
    investigations' flags and threat-listed values, the outside answers cached for the servers,
    the internal sites and the stored web checks."""
    if not any(isinstance(a, OpenCase) for a in actions):
        return actions
    ctx = titling.Context(classifier)
    out: list[Action] = []
    async with engine.connect() as conn:
        for action in actions:
            if isinstance(action, OpenCase):
                ids = [m.investigation_id for m in action.members]
                title = await titling.for_members(
                    conn, ids, (*action.actors, *action.targets), ctx, action.title
                )
                action = replace(action, title=title)
            out.append(action)
    return out


def _members(seen: Sequence[Seen], actors: Sequence[Indicator]) -> tuple[Member, ...]:
    """Each investigation joins through the actor it has (the case's first when it has none)."""
    keys = {(a.kind, a.value) for a in actors}
    out = []
    for s in seen:
        mine = sorted(s.actors & keys)
        out.append(Member(s.investigation_id, "actor", mine[0][1] if mine else None))
    return tuple(out)


async def _apply(conn: AsyncConnection, actor: Actor, action: Action) -> bool:
    """Make one action; whether it changed anything (a suggestion already made does not)."""
    service = await CaseService.start(conn)
    if isinstance(action, OpenCase):
        await service.open(
            actor,
            Open(action.title, action.severity, "raised", _members(action.members, action.actors),
                 (*action.actors, *action.targets), suspected=True,
                 attention=action.attention),
        )  # fmt: skip
        return True
    if isinstance(action, LinkCase):
        case = await service.get(action.case.ref, lock=True)
        if case is None or case.state != "suspected" or case.cause != "raised":
            raise CaseRefused("conflict", "the suggested case was confirmed or closed meanwhile")
        await service.apply(
            actor, action.case.ref,
            Link(_members(action.members, action.actors), (*action.actors, *action.targets),
                 action.severity),
            expected_version=None,
        )  # fmt: skip
        return True
    added = 0
    for s in action.members:
        result = await conn.execute(
            text(
                "INSERT INTO case_suggestions (investigation_id, case_id, link, link_value, kind,"
                " why) VALUES (:inv, :case, 'actor', :value, :kind, :why)"
                " ON CONFLICT (investigation_id, case_id) DO NOTHING"
            ),
            {"inv": s.investigation_id, "case": action.case_id,
             "value": next(iter(sorted(v for _, v in s.actors)), None),
             "kind": "tie" if action.kind == "tie" else "also", "why": action.reason[:300]},
        )  # fmt: skip
        added += int(result.rowcount or 0)
    return added > 0


def words(counts: Mapping[str, int]) -> str:
    return " ".join(f"{k} {v}" for k, v in sorted(counts.items())) or "nothing"
