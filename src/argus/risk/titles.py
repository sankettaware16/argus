"""Incident titles from the engine's own facts (naming v2, phase 2): the linker's incidents
(``argus.risk.link``, ``lifecycle``, ``incidents``) and what the checking lane verified
(``argus.risk.exposure``) become :class:`argus.cases.naming.Facts`, and :func:`naming.titled`
words them (phase 1's grammar, catalogues and checker). :func:`naming_facts`,
:func:`title_for_incident` and :func:`retitle` are pure; :func:`read_facts` takes an incident's
facts from the engine's tables (Postgres only: no SIEM request, no model).

- **Who did it** is the incident's own device objects (a device's days, and an address and the
  host name a host link ties to it, are one device, but days of one address that host links tie
  to different hosts are those hosts: a reused DHCP address is not one machine), never alert
  rows; a count is the devices whose own alert groups carry the activity's evidence ("4 of 7
  internal devices"), and M counts the devices a capped read did not reach.
- **Where it went** is an outside thing the linker's links carry, or one a device's own
  beacon-timed alert group names; "the server of case N" is an earlier incident whose links
  carry it (or that holds the far end of a link the caps kept apart), by its case number.
- **The site** is one of the incident's site objects (E3's attribution); "served" only when the
  checking lane verified a file served (or a bulk take); a 2xx it judged the site's catch-all
  page is no answer, and any other 2xx "got HTTP 200, not verified".
- **The family** is a :data:`naming.FAMILIES` name in the threat names stored for a flagged
  (or threat-listed) outside thing the activity names, or for a threat of an
  ``argus.campaigns`` binding that ties the things or the devices it names; an unflagged
  destination's outside tags never name one. **The place** is the asset map's building,
  department or zone of the counted devices.
- **The certainty word** is the caller's (the presenter decides it), Suspected by default.
- **A retitle** (:func:`retitle`) follows only the lifecycle's material change; between them
  only the certainty word follows the caller's, while the title still keeps the checker's
  bounds. A person's confirmation is never taken back, and a person's title is theirs."""

from __future__ import annotations

import re
import uuid
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import date, timedelta
from types import MappingProxyType
from typing import Any, Literal

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.assets.classify import IpClassifier
from argus.cases import naming
from argus.cases.titling import answer_labels, threat_names
from argus.context.paths import POSSIBLE, SUCCESS
from argus.outside import facts as outside_facts
from argus.outside.psl import registered_parent
from argus.risk import exposure, exposure_db
from argus.risk.config import Exposure
from argus.risk.exposure import CheckRow, PairFacts
from argus.risk.identity import DAY_MARK, latest_address, read_used, same_devices
from argus.risk.observe import ObjectRef

# an evidence kind of ``config/risk.yaml`` -> the naming flag it is (kinds with no title word
# are left out: a tunnel suspicion or a rare destination says no activity of the catalogue)
EVIDENCE_FLAGS: Mapping[str, str] = MappingProxyType({
    "beacon": naming.BEACON, "ports": naming.PORTS, "outside": naming.OUTSIDE,
    "ti": naming.LISTED, "operator": naming.OPERATOR, "success": naming.SUCCESS,
})  # fmt: skip
FLAGGED_BY = frozenset({"outside", "ti", "operator", "person"})  # a flag a title says "flagged"
THROUGH = frozenset({"flagged", "rare", "bare_ip"})  # links through one outside thing
CAMPAIGN_KEY = "campaign:"  # a binding of ``argus.campaigns`` (else ``threat:``: a flagged thing)
OUTSIDE_KINDS = ("ip", "domain")
GROUPS_READ = 600
OBJECTS_READ = 20_000  # a campaign's devices are each of their days (caps count a device once)
ROWS_READ = 20_000
LINKS_READ = 2_000
OUTSIDE_READ = 1_500


def _no_map() -> Mapping[Any, Any]:
    return MappingProxyType({})


@dataclass(frozen=True)
class GroupFacts:
    """One alert group of an incident, as its title reads it."""

    id: uuid.UUID
    rule: str = ""  # the rule's name: only the attributed fallback quotes it
    # the incident's objects it was observed on -> the evidence kinds it showed on each
    objects: Mapping[ObjectRef, frozenset[str]] = field(default_factory=_no_map)
    entities: tuple[tuple[str, str, str], ...] = ()  # (kind, value, role) of its alerts
    answered: tuple[tuple[str, str], ...] = ()  # (site, path): its stored follow-ups' 2xx answers
    checks: frozenset[str] = frozenset()  # its stored follow-ups' statuses (ok, empty, ...)


@dataclass(frozen=True)
class LinkFacts:
    """One kept link of the incident (``b`` None: why ``a`` is in it)."""

    a: ObjectRef
    b: ObjectRef | None
    via: str
    value: str


@dataclass(frozen=True)
class IncidentFacts:
    """What an engine incident's title rests on. Outside things are ``kind:value`` (a domain as
    its registered parent, as the engine keys them) in ``flags``; bare values elsewhere."""

    objects: Mapping[ObjectRef, str] = field(default_factory=_no_map)  # ref -> actor | affected
    groups: tuple[GroupFacts, ...] = ()
    links: tuple[LinkFacts, ...] = ()
    flags: Mapping[str, str] = field(default_factory=_no_map)  # thing -> its flag's source
    vt: Mapping[str, int] = field(default_factory=_no_map)  # value -> VirusTotal engines
    labels: Mapping[str, tuple[str, ...]] = field(default_factory=_no_map)  # value -> threat names
    listed: frozenset[str] = frozenset()  # values a threat list in the groups' dossiers holds
    others: Mapping[str, int] = field(default_factory=_no_map)  # value -> another incident's case
    follows: int = 0  # the case number of the sealed incident this one continues (0: none)
    # address -> (building or department, zone) as the asset map gives its network
    places: Mapping[str, tuple[str | None, str | None]] = field(default_factory=_no_map)
    exposure: tuple[PairFacts, ...] = ()  # what the checking lane found per (source, site)
    catch_all: frozenset[tuple[str, str]] = frozenset()  # (site, path): judged the catch-all page
    # devices and accounts of the incident past the bounded object read (counted, never named)
    more_devices: int = 0
    more_accounts: int = 0
    # device -> the device it is with other addresses (identity.same_devices, D-334)
    same: Mapping[ObjectRef, str] = field(default_factory=_no_map)
    latest: Mapping[str, str] = field(default_factory=_no_map)  # joined device -> last address


@dataclass(frozen=True)
class Title:
    """An incident's title: its text, the certainty word it leads with, and its parts (naming's
    joining words and claims, each claim with the fact it rests on: :func:`naming.check` takes
    them). ``reason``: why it is the title to store (:func:`retitle`). A certainty-only retitle
    (``certainty``) keeps the stored title's other words, which rest on the facts they were
    written from: its parts are the new word's claim and those words as one piece, so
    :func:`naming.check` does not take them (:func:`retitle` holds them to the length and the
    activity's place itself); ``fit``: the stored words would not fit the new word, so the facts'
    own title, which the checker passed."""

    text: str
    certainty: str
    parts: tuple[naming.Part, ...] = ()
    reason: Literal["new", "material", "certainty", "fit"] = "new"

    @property
    def checkable(self) -> bool:
        """Whether :func:`naming.check` takes the parts (all but a certainty-only retitle's)."""
        return self.reason != "certainty"

    @property
    def claims(self) -> tuple[naming.Claim, ...]:
        return tuple(p for p in self.parts if isinstance(p, naming.Claim))

    @property
    def empty(self) -> bool:
        """The facts said nothing (``naming.EMPTY``): a caller keeps its own title."""
        return self.text == naming.EMPTY or self.text.startswith(naming.EMPTY + " — ")

    @property
    def kibana(self) -> str:
        """The title without its certainty word (Kibana's form)."""
        word, rest = split_certainty(self.text)
        if word != self.certainty:
            return self.text
        return rest[:1].upper() + rest[1:]

    def explain(self) -> list[dict[str, str]]:
        return [{"slot": c.slot, "words": c.words, "fact": c.fact} for c in self.claims]


# --------------------------------------------------------------------------- the facts, pure


def thing(kind: str, value: str) -> str:
    """An outside value as the engine keys it: ``ip:<address>``, ``domain:<registered parent>``."""
    low = value.strip().rstrip(".").lower() if kind == "domain" else value.strip()
    return f"domain:{registered_parent(low) or low}" if kind == "domain" else f"{kind}:{low}"


def _bare(item: str) -> str:
    return item.split(":", 1)[1] if ":" in item else item


def campaign_threats(value: str) -> list[str]:
    """The outside things a campaign link's binding key names (``campaign:domain:a,ip:b`` or
    ``threat:ip:b``)."""
    _, _, rest = value.partition(":")
    return [t for t in rest.split(",") if t.split(":", 1)[0] in OUTSIDE_KINDS and ":" in t]


def _device_names(f: IncidentFacts) -> dict[ObjectRef, tuple[str, str]]:
    """Each device object -> the device it is, as (value, kind). A host link joins the key it was
    made on and the host name; an address's days are one device, unless host links tie its days
    to different hosts (a reused DHCP address): then each host is its own device, and the days no
    host link ties are one more. A device is named by an address no other device holds, else by
    its host name."""
    refs = sorted(r for r in f.objects if r.kind == "device")
    root = {r: r for r in refs}
    hosted = {r for r in refs if r.key.startswith("host:")}  # the roots that hold a host name

    def find(r: ObjectRef) -> ObjectRef:
        while root[r] != r:
            r = root[r]
        return r

    def join(a: ObjectRef, b: ObjectRef) -> None:
        x, y = find(a), find(b)
        if x == y:
            return
        keep, gone = min(x, y), max(x, y)
        root[gone] = keep
        if gone in hosted:
            hosted.discard(gone)
            hosted.add(keep)

    for lk in sorted(f.links, key=lambda lk: (lk.a, lk.b or lk.a, lk.via, lk.value)):
        if lk.via == "host" and lk.b is not None and lk.a in root and lk.b in root:
            join(lk.a, lk.b)
    days: dict[str, list[ObjectRef]] = defaultdict(list)
    for r in refs:
        if r.key.startswith("ip:"):
            days[r.key[3:].split(DAY_MARK, 1)[0]].append(r)
    for keys in (days[a] for a in sorted(days)):
        tied = {find(r) for r in keys} & hosted
        loose = keys if len(tied) <= 1 else [r for r in keys if find(r) not in hosted]
        for r in loose[1:]:
            join(loose[0], r)
    moved: dict[str, list[ObjectRef]] = defaultdict(list)
    for r in refs:  # one account's addresses that were never active together: one device
        if r in f.same:
            moved[f.same[r]].append(r)
    for keys in (moved[k] for k in sorted(moved)):
        for r in keys[1:]:
            join(keys[0], r)
    members: dict[ObjectRef, list[ObjectRef]] = defaultdict(list)
    for r in refs:
        members[find(r)].append(r)
    holders: Counter[str] = Counter()
    addresses: dict[ObjectRef, list[str]] = {}
    for top, held in members.items():
        addresses[top] = sorted({r.key[3:].split(DAY_MARK, 1)[0] for r in held
                                 if r.key.startswith("ip:")})  # fmt: skip
        holders.update(addresses[top])
    out: dict[ObjectRef, tuple[str, str]] = {}
    for top, held in members.items():
        own = [a for a in addresses[top] if holders[a] == 1]
        # a device that moved is named by the address it was last seen under
        recent = {f.latest.get(f.same[r]) for r in held if r in f.same}
        own = [a for a in own if a in recent] or own
        hosts = sorted({r.key[5:] for r in held if r.key.startswith("host:")})
        name = (own[0], "ip") if own else (hosts[0], "host") if hosts else (
            (addresses[top][0], "ip") if addresses[top] else None)  # fmt: skip
        for r in held:
            out[r] = name or (r.key, "host")
    return out


def _places(
    f: IncidentFacts, dev: Mapping[ObjectRef, tuple[str, str]]
) -> dict[str, tuple[str | None, str | None]]:
    """Each device -> the building or department, and the zone, that all of its addresses share
    (the asset map's; none where they differ)."""
    seen: dict[str, set[tuple[str | None, str | None]]] = defaultdict(set)
    for r, (value, _) in dev.items():
        if r.key.startswith("ip:"):
            seen[value].add(f.places.get(r.key[3:].split(DAY_MARK, 1)[0], (None, None)))
    out: dict[str, tuple[str | None, str | None]] = {}
    for value, held in seen.items():
        buildings, zones = {b for b, _ in held}, {z for _, z in held}
        out[value] = (next(iter(buildings)) if len(buildings) == 1 else None,
                      next(iter(zones)) if len(zones) == 1 else None)  # fmt: skip
    return out


def _site_name(ref: ObjectRef) -> str:
    return ref.key.split(":", 1)[1] if ":" in ref.key else ref.key


def _ranked(table: Mapping[str, set[str]], values: Iterable[str]) -> list[str]:
    return sorted(dict.fromkeys(values), key=lambda v: (-len(table.get(v, ())), v))


def _verified(f: IncidentFacts, sites: set[str], sources: set[str]) -> list[PairFacts]:
    return sorted((p for p in f.exposure if p.site in sites and p.source in sources),
                  key=lambda p: (p.site, p.source))  # fmt: skip


def naming_facts(f: IncidentFacts) -> naming.Facts:
    """The incident's facts as :mod:`argus.cases.naming` reads them (see the module)."""
    dev = _device_names(f)
    groups = sorted(f.groups, key=lambda g: str(g.id))
    doing: dict[str, set[str]] = {
        flag: set() for flag in (*EVIDENCE_FLAGS.values(), naming.BEACON_PORTS, naming.CAMPAIGN)
    }
    reaches: dict[str, set[str]] = defaultdict(set)  # full outside value -> devices
    timed: dict[str, set[str]] = defaultdict(set)  # ... whose beacon-timed group names it
    weight: Counter[str] = Counter()  # device -> its groups
    site_weight: Counter[str] = Counter()
    sites = {r for r in f.objects if r.kind == "site"}
    site_groups: list[GroupFacts] = []
    for g in groups:
        acted = {dev[r][0] for r in g.objects if r in dev}
        beat: set[str] = set()
        for r, kinds in g.objects.items():
            if r not in dev:
                continue
            for kind in kinds:
                if kind in EVIDENCE_FLAGS:
                    doing[EVIDENCE_FLAGS[kind]].add(dev[r][0])
            if "beacon" in kinds:
                beat.add(dev[r][0])
                if "ports" in kinds:
                    doing[naming.BEACON_PORTS].add(dev[r][0])
        weight.update(acted)
        if acted:
            for kind, value, role in g.entities:
                if role == "threat" and kind in OUTSIDE_KINDS and value:
                    reaches[value] |= acted
                    if beat:
                        timed[value] |= beat
        on_sites = [r for r in g.objects if r in sites]
        if on_sites:
            site_groups.append(g)
            site_weight.update(_site_name(r) for r in on_sites)
    # the campaigns' devices and outside things (L4: a campaign link binds them); only a
    # campaign of ``argus.campaigns`` (names under a rare parent) is the DNS campaign flag, a
    # flagged thing several devices reached binds them without it
    bound_things: set[str] = set()
    families: set[str] = set()
    family_things: set[str] = set()
    for lk in f.links:
        if lk.via == "campaign":
            who = {dev[r][0] for r in (lk.a, lk.b) if r is not None and r in dev}
            bound_things.update(campaign_threats(lk.value))
            if lk.value.startswith(CAMPAIGN_KEY):
                families |= who
                family_things.update(campaign_threats(lk.value))
    doing[naming.CAMPAIGN] = families
    campaign_reaches = {v: who & families for v, who in reaches.items()
                        if thing(_kind(v), v) in family_things and who & families}  # fmt: skip
    things = {v: thing(_kind(v), v) for v in reaches}
    # flagged outside things the devices reached, by the engine's flags
    by_thing: dict[str, set[str]] = defaultdict(set)
    for v, who in reaches.items():
        by_thing[things[v]] |= who
    flagged = [t for t in by_thing if f.flags.get(t) in FLAGGED_BY]
    servers = _ranked({_bare(t): by_thing[t] for t in flagged}, (_bare(t) for t in flagged))
    listed = sorted(_bare(t) for t in flagged if f.flags.get(t) == "ti")
    # destinations: what the linker's links carry, then what a beacon-timed group names
    linked = [lk.value for lk in f.links if lk.via in THROUGH]
    linked += sorted(bound_things)
    named = {t for t in linked if t.split(":", 1)[0] in OUTSIDE_KINDS}
    named |= {things[v] for v in timed}
    held = set(servers)
    destinations = _ranked({_bare(t): by_thing.get(t, set()) for t in named},
                           (_bare(t) for t in named if _bare(t) not in held))  # fmt: skip
    # the sites at risk and who attacked them (inbound: the outside actors of their groups)
    site_names = sorted({_site_name(r) for r in sites if not r.key.startswith("ip:")},
                        key=lambda s: (-site_weight[s], s))  # fmt: skip
    own_servers = sum(1 for r in sites if r.key.startswith("ip:"))
    outsiders = sorted(
        {v for g in site_groups for k, v, role in g.entities if _attacker(k, v, role)}
    )
    paths = sorted({v for g in site_groups for k, v, _ in g.entities if k == "url_pattern"})
    pairs = _verified(f, set(site_names), set(outsiders))
    served = [(p.site, path, naming.PATH_SERVED) for p in pairs for path in p.served]
    served += [(p.site, p.bulk_prefix, naming.PATH_SERVED) for p in pairs
               if p.bulk and p.bulk_prefix]  # fmt: skip
    proven = {(p.site, path) for p in pairs for path in p.served}
    answered = [a for g in site_groups for a in g.answered if a not in f.catch_all]
    answered += [(p.site, path) for p in pairs for path in p.through
                 if (p.site, path) not in proven]  # fmt: skip
    answered = sorted(dict.fromkeys(answered))
    outcomes = list(dict.fromkeys(served))
    if not outcomes and not answered and f.catch_all:
        outcomes = [(s, p, naming.PATH_CATCH_ALL) for s, p in sorted(f.catch_all)
                    if s in set(site_names)]  # fmt: skip
    checks = frozenset(c for g in site_groups for c in g.checks)
    flags = {flag for flag, who in doing.items() if who and flag in naming.EVIDENCE}
    if any("success" in k for g in site_groups for r, k in g.objects.items() if r in sites):
        flags.add(naming.SUCCESS)
    labelled = _labelled(f, dev, {*by_thing, *named})
    labels = [label for v in (*servers, *sorted(labelled)) for label in labelled.get(v, ())]
    device_order = sorted({d for d, _ in dev.values()}, key=lambda d: (-weight[d], d))
    kind_of = dict(dev.values())
    where = _places(f, dev)
    devices = tuple(naming.Device(d, kind_of[d], None, *where.get(d, (None, None)))
                    for d in device_order)  # fmt: skip
    domains = sorted({v for v in reaches if _kind(v) == "domain"})
    rules = Counter(g.rule for g in groups if g.rule)
    return naming.Facts(
        rules=tuple(sorted(rules.items(), key=lambda kv: (-kv[1], kv[0]))),
        flags=frozenset(flags),
        devices=devices,
        outsiders=tuple(outsiders),
        accounts=sum(1 for r in f.objects if r.kind == "account") + max(0, f.more_accounts),
        servers=tuple(servers),
        domains=tuple(domains),
        sites=tuple(site_names),
        own_servers=own_servers,
        listed=tuple(listed),
        labels=tuple(dict.fromkeys(labels)),
        labelled=MappingProxyType(labelled),
        more_devices=max(0, f.more_devices),
        follows=f.follows,
        paths=tuple(paths),
        doing=MappingProxyType({k: frozenset(v) for k, v in doing.items()}),
        reaches=MappingProxyType({k: frozenset(v) for k, v in reaches.items()}),
        beacon_reaches=MappingProxyType({k: frozenset(v) for k, v in timed.items()}),
        campaign_reaches=MappingProxyType({k: frozenset(v) for k, v in campaign_reaches.items()}),
        destinations=tuple(destinations),
        vt=MappingProxyType({v: n for v, n in f.vt.items() if v in held and n > 0}),
        answered=tuple(answered),
        outcomes=tuple(outcomes),
        checks=checks,
        server_cases=MappingProxyType(
            {v: n for v, n in f.others.items() if n > 0 and n != f.follows}
        ),
    )


def _labelled(
    f: IncidentFacts, dev: Mapping[ObjectRef, tuple[str, str]], reached: Iterable[str]
) -> dict[str, tuple[str, ...]]:
    """Where a family may come from: a flagged outside thing (by the engine's flags, or on a
    threat list of the groups' dossiers) or a threat of an ``argus.campaigns`` binding -> its own
    stored threat names, and a device such a binding ties -> the names of that binding's
    threats. An outside thing nobody flagged (a beacon-timed or rare destination) gives none,
    whatever its outside answers' tags say."""
    out: dict[str, list[str]] = defaultdict(list)
    for t in sorted(set(reached)):
        if f.flags.get(t) in FLAGGED_BY or _bare(t) in f.listed:
            out[_bare(t)] += f.labels.get(_bare(t), ())
    for lk in sorted(f.links, key=lambda lk: (lk.a, lk.b or lk.a, lk.via, lk.value)):
        if lk.via != "campaign" or not lk.value.startswith(CAMPAIGN_KEY):
            continue
        names = [n for t in campaign_threats(lk.value) for n in f.labels.get(_bare(t), ())]
        for t in campaign_threats(lk.value):
            out[_bare(t)] += f.labels.get(_bare(t), ())
        for r in (lk.a, lk.b):
            if r is not None and r in dev:
                out[dev[r][0]] += names
    return {k: tuple(dict.fromkeys(v)) for k, v in sorted(out.items()) if v}


def _attacker(kind: str, value: str, role: str) -> bool:
    """An outside address that acted on an own site (not one of the site's own networks)."""
    return role == "actor" and kind == "ip" and not naming.own_address(value)


def _kind(value: str) -> str:
    return "ip" if naming.address(value) is not None else "domain"


# --------------------------------------------------------------------------- the title, pure


def titled_for_incident(facts: IncidentFacts, certainty: str = naming.SUSPECTED) -> naming.Titled:
    """:func:`title_for_incident`'s naming result itself (its claims explainable): the case
    titler's own form, for a case the engine presents."""
    if certainty not in naming.CERTAINTIES:
        raise ValueError(f"not a certainty word: {certainty!r}")
    return naming.titled(replace(naming_facts(facts), verdict=naming.Verdict(given=certainty)))


def title_for_incident(facts: IncidentFacts, certainty: str = naming.SUSPECTED) -> Title:
    """The incident's title (pure): :func:`naming.titled` over :func:`naming_facts`, led by
    ``certainty`` (a word of :data:`naming.CERTAINTIES`, the caller's)."""
    if certainty not in naming.CERTAINTIES:
        raise ValueError(f"not a certainty word: {certainty!r}")
    made = naming.titled(replace(naming_facts(facts), verdict=naming.Verdict(given=certainty)))
    return Title(made.text, certainty, made.parts)


def split_certainty(text: str) -> tuple[str | None, str]:
    """:func:`naming.split_certainty`, and the fallback's word with its colon ("Suspected:
    alerts of rule ...")."""
    for word in naming.CERTAINTIES:
        lead = word + ": "
        if text.startswith(lead) and len(text) > len(lead):
            return word, text[len(lead) :]
    return naming.split_certainty(text)


def _lead(word: str, rest: str) -> str:
    """The certainty word as it leads ``rest``: with a colon for the words that take one, and
    before the fallback's attributed rule ("Suspected: alerts of rule ...")."""
    fallback = rest.startswith(naming.ACTIVITIES["rule"] + " ")
    return word + (": " if word in naming.COLON or fallback else " ")


_SCAN_KIND = "(?:" + "|".join(re.escape(k) for k in naming.SCAN_KINDS) + ")"
_SCAN = re.compile(
    rf"(?:{_SCAN_KIND}(?: and {_SCAN_KIND})*|{re.escape(naming.WEB_SCAN)}) scan(?= |$)"
)
_FAMILY_FIRST = sorted(naming.FAMILIES, key=len, reverse=True)


def activity_end(rest: str) -> int | None:
    """Where the activity ends in a title's words after its certainty word (a family of
    :data:`naming.FAMILIES` may come first, then an activity of the catalogue or a scan), or
    None when the words start with neither."""
    at = next((len(n) + 1 for n in _FAMILY_FIRST if rest.startswith(n + " ")), 0)
    tail = rest[at:]
    found = [len(w) for w in naming.ACTIVITIES.values() if tail == w or tail.startswith(w + " ")]
    if (scan := _SCAN.match(tail)) is not None:
        found.append(scan.end())
    return at + max(found) if found else None


def fits(text: str, rest: str) -> bool:
    """Whether a title whose words after its certainty word are ``rest`` keeps the checker's
    bounds: at most :data:`naming.MAX_TITLE` characters, the activity ending within
    :data:`naming.FRONT`."""
    end = activity_end(rest)
    return (end is not None and len(text) <= naming.MAX_TITLE
            and len(text) - len(rest) + end <= naming.FRONT)  # fmt: skip


def retitle(
    current: str | None, facts: IncidentFacts, certainty: str = naming.SUSPECTED, *,
    material: bool, confirmed: bool = False, by_person: bool = False,
) -> Title | None:  # fmt: skip
    """The title to store now, or None to keep ``current``. A person's title (``by_person``) is
    kept. With no title yet, the facts' title. ``material``: the lifecycle re-queued the
    incident since ``current`` was written (its version rose): the facts' title. Otherwise the
    words stay and only the certainty word follows ``certainty``, as long as the title still
    fits (:func:`fits`); when it would not, the facts' own title (reason ``fit``).
    ``confirmed``: a person confirmed the incident, so its word is Confirmed whatever
    ``certainty`` says (nothing ARGUS computes takes a person's confirmation back). Facts that
    say nothing keep ``current``."""
    if by_person and current:
        return None
    word = naming.CONFIRMED if confirmed else certainty
    made = title_for_incident(facts, word)
    if not current:
        return None if made.empty else made
    if made.empty or made.text == current:
        return None
    if material:
        return replace(made, reason="material")
    if split_certainty(current)[1] == split_certainty(made.text)[1]:
        return replace(made, reason="certainty")
    was, rest = split_certainty(current)
    if was is None or was == word:
        return None
    lead = _lead(word, rest)
    if not fits(lead + rest, rest):
        return replace(made, reason="fit")
    claim = naming.Claim("certainty", lead.rstrip(), f"certainty:{word}")
    return Title(lead + rest, word, (claim, " ", rest), "certainty")


def material_since(titled_version: int | None, version: int) -> bool:
    """Whether the lifecycle changed the incident materially since its title was written at
    ``titled_version`` (None: never titled): its version rises only on a material change."""
    return titled_version is None or version > titled_version


# --------------------------------------------------------------------------- the checks, pure


def _sizes(item: Mapping[str, Any]) -> list[int]:
    out = []
    for s in item.get("sizes") or {}:
        try:
            out.append(int(s))
        except (TypeError, ValueError):
            continue
    return out


def catch_all_of(
    rows: Iterable[CheckRow], pairs: Mapping[tuple[str, str], PairFacts]
) -> frozenset[tuple[str, str]]:
    """(site, path) of each 2xx a paths check got, with its body sizes, that the site's
    soft-404 check of that day judged its catch-all page (the derived facts did not let it
    through); a 2xx with no size or no soft-404 check stays unverified."""
    held = list(rows)
    pages: dict[str, list[date]] = defaultdict(list)
    for r in held:
        if r.kind == "catchall" and r.site and r.verdict != "unknown":
            pages[r.site].append(r.day)
    out: set[tuple[str, str]] = set()
    for r in held:
        if r.kind != "paths" or not r.site or not r.source:
            continue
        if not any(abs((d - r.day).days) <= 1 for d in pages.get(r.site, ())):
            continue
        pair = pairs.get((r.source, r.site))
        through = set(pair.through) if pair is not None else set()
        for item in r.facts.get("paths") or []:
            if not isinstance(item, Mapping):
                continue
            path = str(item.get("path") or "")
            answered = item.get("outcome") in (SUCCESS, POSSIBLE) and _sizes(item)
            if path and answered and path not in through:
                out.add((r.site, path))
    return frozenset(out)


# --------------------------------------------------------------------------- the reads


@dataclass(frozen=True)
class Context:
    """What the reading needs besides the database: the asset map (a device's place and zone)
    and the exposure settings the checks' facts are derived with."""

    classifier: IpClassifier | None = None
    exposure: Exposure = field(default_factory=Exposure)
    threshold: int = outside_facts.DEFAULT_THRESHOLD  # VirusTotal engines that flag a value


def place_of(value: str, classifier: IpClassifier | None) -> tuple[str | None, str | None]:
    """(building or department, zone) the asset map gives an address's network (a network the
    map lists with different ones names none)."""
    if classifier is None:
        return None, None
    match = classifier.classify(value).asset
    if match is None:
        return None, None
    places = {e.fields.get("site.building") or e.fields.get("site.department")
              for e in match.entries}  # fmt: skip
    zones = {e.fields.get("site.zone") for e in match.entries}
    one = next(iter(places)) if len(places) == 1 else None
    zone = next(iter(zones)) if len(zones) == 1 else None
    return (one if isinstance(one, str) else None), (zone if isinstance(zone, str) else None)


_INCIDENT = text("SELECT id, follows_id, case_id FROM risk_incidents WHERE id = :i")
_OBJECTS = text(
    "SELECT b.id, b.kind, b.key, m.role FROM risk_incident_objects m"
    " JOIN risk_objects b ON b.id = m.object_id WHERE m.incident_id = :i"
    " ORDER BY CASE b.kind WHEN 'device' THEN 0 WHEN 'site' THEN 1 ELSE 2 END, b.kind, b.key"
    " LIMIT :n"
)
# past a capped read: the devices (an address's days as one) and accounts it did not reach
_UNREAD = text(
    "SELECT count(DISTINCT x.device) FILTER (WHERE x.kind = 'device'"
    "  AND NOT (x.device = ANY(CAST(:held AS text[])))) AS devices,"
    " count(*) FILTER (WHERE x.kind = 'account') AS accounts FROM ("
    " SELECT b.kind, CASE WHEN b.key LIKE 'ip:%' THEN split_part(b.key, '@', 1) ELSE b.key END"
    "  AS device FROM risk_incident_objects m JOIN risk_objects b ON b.id = m.object_id"
    "  WHERE m.incident_id = :i AND b.kind IN ('device', 'account')"
    "  AND NOT (b.id = ANY(CAST(:read AS bigint[])))) x"
)
_GROUPS = text(
    "SELECT m.investigation_id AS id, coalesce(r.name, i.rule_name, i.rule_id) AS rule"
    " FROM risk_incident_groups m JOIN investigations i ON i.id = m.investigation_id"
    " LEFT JOIN rules r ON r.rule_id = i.rule_id WHERE m.incident_id = :i"
    " ORDER BY m.joined_at, m.investigation_id LIMIT :n"
)
_OBSERVATIONS = text(
    "SELECT object_id, investigation_id, source_kind, source_key FROM risk_observations"
    " WHERE investigation_id = ANY(CAST(:g AS uuid[])) AND object_id = ANY(CAST(:o AS bigint[]))"
    " ORDER BY investigation_id, object_id, source_key LIMIT :n"
)
_ENTITIES = text(
    "SELECT investigation_id, kind, value, role FROM risk_entities"
    " WHERE investigation_id = ANY(CAST(:g AS uuid[])) AND kind IN ('ip', 'domain', 'url_pattern')"
    " AND role IN ('actor', 'threat') ORDER BY investigation_id, kind, value LIMIT :n"
)
_LINKS = text(
    "SELECT a_object, b_object, via, value, kept FROM risk_links WHERE incident_id = :i"
    " AND removed_at IS NULL ORDER BY priority, id LIMIT :n"
)
_FLAGS = text("SELECT threat, flag_source FROM risk_threats WHERE threat = ANY(CAST(:t AS text[]))")
_OUTSIDE = text(
    "SELECT source, kind, indicator, status, answer FROM outside_lookups"
    " WHERE status IN ('found', 'not_found') AND ((kind = 'ip' AND indicator = ANY(CAST(:ips AS"
    " text[]))) OR (kind = 'domain' AND indicator = ANY(CAST(:domains AS text[]))))"
    " ORDER BY fetched_at DESC LIMIT :n"
)
_LISTS = text(
    "SELECT d.listed, d.answers FROM unnest(CAST(:g AS uuid[])) AS g(id) JOIN LATERAL"
    " (SELECT body #> '{context,pack,ti,listed}' AS listed,"
    "  body #> '{context,pack,ti,answers}' AS answers FROM dossiers"
    "  WHERE investigation_id = g.id ORDER BY version DESC, created_at DESC LIMIT 1) d ON true"
)
# an earlier incident (with a case) whose links carry the value, or that holds the far end of
# one of this incident's links the caps or a merge blocker kept apart
_OTHERS = text(
    "SELECT value, min(number) AS number FROM ("
    " SELECT l.value, c.number FROM risk_links l JOIN risk_incidents i ON i.id = l.incident_id"
    "  JOIN cases c ON c.id = i.case_id WHERE l.value = ANY(CAST(:t AS text[]))"
    "  AND l.incident_id < :i AND l.removed_at IS NULL AND i.state <> 'merged'"
    "  AND (CAST(:mine AS uuid) IS NULL OR c.id <> :mine)"
    " UNION ALL SELECT l.value, c.number FROM risk_links l JOIN risk_incident_objects m"
    "  ON m.object_id IN (l.a_object, l.b_object) AND m.incident_id < :i"
    "  JOIN risk_incidents i ON i.id = m.incident_id JOIN cases c ON c.id = i.case_id"
    "  WHERE l.incident_id = :i AND NOT l.kept AND l.removed_at IS NULL AND i.state <> 'merged'"
    "  AND (CAST(:mine AS uuid) IS NULL OR c.id <> :mine)) x GROUP BY value"
)
_CASE_OF = text(
    "SELECT c.number FROM risk_incidents i JOIN cases c ON c.id = i.case_id WHERE i.id = :i"
)
_STATUSES = text(
    "SELECT investigation_id, status FROM evidence WHERE investigation_id = ANY(CAST(:g AS"
    " uuid[])) AND template = 'web.followups' AND status IN ('ok', 'empty', 'skipped_budget')"
)
_DAYS = text(
    "SELECT min(day) AS lo, max(day) AS hi FROM risk_groups"
    " WHERE investigation_id = ANY(CAST(:g AS uuid[]))"
)


def _strings(value: Any) -> tuple[str, ...]:
    return tuple(v for v in value if isinstance(v, str)) if isinstance(value, list) else ()


async def read_facts(conn: AsyncConnection, incident_id: int, ctx: Context) -> IncidentFacts | None:
    """An engine incident's title facts from ARGUS's own tables (bounded statements; no SIEM
    request): its objects, alert groups (their evidence and entities), kept links, the flags
    and outside answers of what it reached, the stored threat-list names, earlier incidents' cases
    that carry the same outside things, the case it follows, its sites' stored follow-ups and
    the checking lane's checks. None when there is no such incident."""
    inc = (await conn.execute(_INCIDENT, {"i": incident_id})).first()
    if inc is None:
        return None
    by_id: dict[int, ObjectRef] = {}
    objects: dict[ObjectRef, str] = {}
    for r in await conn.execute(_OBJECTS, {"i": incident_id, "n": OBJECTS_READ}):
        ref = ObjectRef(r.kind, r.key)
        by_id[int(r.id)] = ref
        objects[ref] = str(r.role)
    more_devices = more_accounts = 0
    if len(by_id) >= OBJECTS_READ:  # capped: count what the read left out
        held = sorted({_device_key(r) for r in objects if r.kind == "device"})
        unread = (await conn.execute(_UNREAD, {"i": incident_id, "held": held,
                                               "read": sorted(by_id)})).first()  # fmt: skip
        if unread is not None:
            more_devices, more_accounts = int(unread.devices or 0), int(unread.accounts or 0)
    rows = (await conn.execute(_GROUPS, {"i": incident_id, "n": GROUPS_READ})).all()
    ids = [r.id for r in rows]
    seen: dict[uuid.UUID, dict[ObjectRef, set[str]]] = defaultdict(dict)
    entities: dict[uuid.UUID, list[tuple[str, str, str]]] = defaultdict(list)
    if ids and by_id:
        for r in await conn.execute(_OBSERVATIONS, {"g": ids, "o": sorted(by_id), "n": ROWS_READ}):
            kinds = seen[r.investigation_id].setdefault(by_id[int(r.object_id)], set())
            if r.source_kind == "evidence" and str(r.source_key).startswith("ev:"):
                kinds.add(str(r.source_key)[3:])
    if ids:
        for r in await conn.execute(_ENTITIES, {"g": ids, "n": ROWS_READ}):
            entities[r.investigation_id].append((str(r.kind), str(r.value), str(r.role)))
    links: list[LinkFacts] = []
    far: list[str] = []
    for r in await conn.execute(_LINKS, {"i": incident_id, "n": LINKS_READ}):
        a = by_id.get(int(r.a_object))
        b = by_id.get(int(r.b_object)) if r.b_object is not None else None
        if r.kept and a is not None and (r.b_object is None or b is not None):
            links.append(LinkFacts(a, b, str(r.via), str(r.value)))
        elif not r.kept:
            far.append(str(r.value))
    on_sites = [r.id for r in rows if any(o.kind == "site" for o in seen.get(r.id, {}))]
    answered: dict[uuid.UUID, list[tuple[str, str]]] = defaultdict(list)
    statuses: dict[uuid.UUID, set[str]] = defaultdict(set)
    if on_sites:
        for gid, found in (await exposure_db.followups(conn, on_sites)).items():
            answered[gid] = [(s, p) for s, p, code in found if code is None or 200 <= code < 300]
        for r in await conn.execute(_STATUSES, {"g": on_sites}):
            statuses[r.investigation_id].add(str(r.status))
    groups = tuple(
        GroupFacts(
            r.id, str(r.rule or ""),
            MappingProxyType({o: frozenset(k) for o, k in seen.get(r.id, {}).items()}),
            tuple(entities.get(r.id, ())), tuple(answered.get(r.id, ())),
            frozenset(statuses.get(r.id, ())),
        )
        for r in rows
    )  # fmt: skip
    reached = sorted({thing(k, v) for es in entities.values() for k, v, role in es
                      if role == "threat" and k in OUTSIDE_KINDS})  # fmt: skip
    carried = sorted({*reached, *(lk.value for lk in links if lk.via in THROUGH), *far,
                      *(t for lk in links if lk.via == "campaign"
                        for t in campaign_threats(lk.value))})  # fmt: skip
    flags: dict[str, str] = {}
    if carried:
        for r in await conn.execute(_FLAGS, {"t": carried}):
            flags[str(r.threat)] = str(r.flag_source)
    outsiders = sorted({v for gid in on_sites for k, v, role in entities.get(gid, ())
                        if _attacker(k, v, role)})  # fmt: skip
    vt, labels = await _outside(conn, carried, outsiders, ctx)
    listed = await _listed_names(conn, ids, set(carried), set(outsiders))
    for value, names in listed.items():
        labels[value] += names
    others: dict[str, int] = {}
    if carried:
        for r in await conn.execute(_OTHERS, {"t": carried, "i": incident_id,
                                              "mine": inc.case_id}):  # fmt: skip
            others[_bare(str(r.value))] = int(r.number)
    follows = 0
    if inc.follows_id is not None:
        follows = int(await conn.scalar(_CASE_OF, {"i": inc.follows_id}) or 0)
    pairs: tuple[PairFacts, ...] = ()
    catch: frozenset[tuple[str, str]] = frozenset()
    if outsiders and on_sites:
        span = (await conn.execute(_DAYS, {"g": on_sites})).first()
        if span is not None and span.lo is not None:
            lo, hi = span.lo - timedelta(days=1), span.hi + timedelta(days=1)
            mine = await exposure_db.checks(conn, lo=lo, hi=hi, sources=outsiders)
            where = sorted({r.site for r in mine if r.site})
            near = await exposure_db.checks(conn, lo=lo, hi=hi, sites=where) if where else mine
            derived = exposure.derive(near, ctx.exposure)
            pairs = tuple(derived[k] for k in sorted(derived))
            catch = catch_all_of(near, derived)
    places = {}
    for ref in objects:
        if ref.kind == "device" and ref.key.startswith("ip:"):
            address = ref.key[3:].split(DAY_MARK, 1)[0]
            places[address] = place_of(address, ctx.classifier)
    used = await read_used(conn, sorted(r.key for r in objects if r.kind == "device"))
    same = same_devices(used)
    return IncidentFacts(
        objects=MappingProxyType(objects),
        groups=groups,
        links=tuple(links),
        flags=MappingProxyType(flags),
        vt=MappingProxyType(vt),
        labels=MappingProxyType({k: tuple(dict.fromkeys(v)) for k, v in labels.items() if v}),
        listed=frozenset(listed),
        others=MappingProxyType(others),
        follows=follows,
        places=MappingProxyType(places),
        exposure=pairs,
        catch_all=catch,
        more_devices=more_devices,
        more_accounts=more_accounts,
        same=MappingProxyType(same),
        latest=MappingProxyType(latest_address(used, same)),
    )


def _device_key(ref: ObjectRef) -> str:
    """A device object's key with an address's day dropped (as :data:`_UNREAD` keys it)."""
    return ref.key.split(DAY_MARK, 1)[0] if ref.key.startswith("ip:") else ref.key


async def _outside(
    conn: AsyncConnection, carried: Sequence[str], outsiders: Sequence[str], ctx: Context
) -> tuple[dict[str, int], dict[str, list[str]]]:
    """VirusTotal's engines for each value and the threat names its outside answers store (the
    newest answer of each source)."""
    ips = sorted({_bare(t) for t in carried if t.startswith("ip:")} | set(outsiders))
    domains = sorted({_bare(t) for t in carried if t.startswith("domain:")})
    vt: dict[str, int] = {}
    labels: dict[str, list[str]] = defaultdict(list)
    if not ips and not domains:
        return vt, labels
    newest: set[tuple[str, str, str]] = set()
    for r in await conn.execute(_OUTSIDE, {"ips": ips, "domains": domains, "n": OUTSIDE_READ}):
        key = (str(r.source), str(r.kind), str(r.indicator))
        if key in newest:
            continue
        newest.add(key)
        answer = r.answer if isinstance(r.answer, Mapping) else {}
        labels[str(r.indicator)] += answer_labels(answer)
        if r.source == "virustotal" and outside_facts.flagged(
            str(r.source), str(r.status), answer, ctx.threshold
        ):
            vt[str(r.indicator)] = max(vt.get(str(r.indicator), 0), outside_facts.malicious(answer))
    return vt, labels


async def _listed_names(
    conn: AsyncConnection, ids: Sequence[uuid.UUID], carried: set[str], outsiders: set[str]
) -> dict[str, list[str]]:
    """Value -> the threat names the groups' newest dossiers store for it (each match's
    description: where a family such as PS1Bot shows), for a listed value the incident carries
    (a name under a carried domain is that domain's) or an outside address that attacked it."""
    out: dict[str, list[str]] = defaultdict(list)
    if not ids or not (carried or outsiders):
        return out
    for r in await conn.execute(_LISTS, {"g": list(ids)[:GROUPS_READ]}):
        for value in _strings(r.listed):
            key = thing(_kind(value), value)
            where = _bare(key) if key in carried else value if value in outsiders else None
            if where is not None:
                out[where] += threat_names(r.answers, (value,))
    return out


async def title_for(
    conn: AsyncConnection, incident_id: int, ctx: Context, certainty: str = naming.SUSPECTED
) -> Title | None:
    """:func:`title_for_incident` over :func:`read_facts` (None: no such incident)."""
    facts = await read_facts(conn, incident_id, ctx)
    return None if facts is None else title_for_incident(facts, certainty)
