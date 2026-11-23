"""What the families and the outside answers say together: detected parents, operator ties (an
identical set of name servers, the same /24 or autonomous system unless a big hoster), the campaign
shape (many hosts and names under one rare parent), campaigns (a detected parent or flagged address
that several hosts reached, with everything tied to it) and the flags these give investigations.
Pure: the world (sightings, cached readings, flagged servers) is given."""

from __future__ import annotations

import ipaddress
import uuid
from collections import defaultdict
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, datetime
from typing import Any

from argus import site
from argus.assess.raised import CAMPAIGN, OPERATOR, OUTSIDE
from argus.campaigns import families as fam
from argus.campaigns.families import Family, Key, Sighting
from argus.cases.membership import NO_SHARED, Shared
from argus.outside import facts

MIN_FLAG_HOSTS = 3  # campaign shape: internal hosts under one rare parent ...
MIN_FLAG_NAMES = 20  # ... and distinct names under it
MIN_SERVER_HOSTS = 2  # internal hosts that make a flagged server a campaign
MIN_NAME_SERVERS = 2  # name servers in an identical set that tie two families
# name servers a DNS host gives each account its own pair of (a shared host otherwise)
ACCOUNT_NAME_SERVERS = (".ns.cloudflare.com",)


@dataclass(frozen=True)
class Reading:
    """What outside intel says about a family's parent. ``ranked`` is whether a web-popularity list
    ranks it (:func:`argus.outside.facts.popularity`); None when the answer does not say (one kept
    before the popularity fields): nothing is then inferred from it. ``asn``/``owner``/``address``
    come from the look-up of the first public address."""

    found: bool  # VirusTotal has a record of the domain
    malicious: int = 0
    suspicious: int = 0
    engines: int = 0
    ranked: bool | None = None
    best_rank: int | None = None
    created: date | None = None
    registrar: str | None = None
    name_servers: tuple[str, ...] = ()
    addresses: tuple[str, ...] = ()
    address: str | None = None
    asn: int | None = None
    owner: str | None = None

    def detected(self, threshold: int) -> bool:
        return self.found and self.malicious >= max(threshold, 1)

    @property
    def unranked(self) -> bool:
        """No popularity list ranks it (VirusTotal does not know it, or says it is not ranked)."""
        return not self.found or self.ranked is False

    @property
    def popular(self) -> bool:
        return self.ranked is True

    def benign(self) -> bool:
        """Popular on the web and no engine calls it malicious: what ARGUS recommends closing. Age
        alone is not enough (a command-and-control domain registered in 2019 is old)."""
        return self.found and self.malicious == 0 and self.popular


def reading_of(
    status: str, answer: Mapping[str, Any], ip_answer: Mapping[str, Any] | None = None,
    address: str | None = None,
) -> Reading:  # fmt: skip
    """The reading of a cached VirusTotal answer for a domain (``status`` found or not_found), with
    the cached answer for the address that was looked up after it, if any."""
    if status != "found":
        return Reading(found=False)

    def count(key: str) -> int:
        return facts.number(answer.get(key)) or 0

    ranked = answer.get("ranked")
    created = answer.get("created")
    try:
        born = date.fromisoformat(created) if isinstance(created, str) else None
    except ValueError:
        born = None
    ip = ip_answer if ip_answer is not None else {}
    return Reading(
        True, count("malicious"), count("suspicious"), count("engines"),
        ranked if isinstance(ranked, bool) else None, facts.number(answer.get("best_rank"), 1),
        born, facts.clean(answer.get("registrar"), 60),
        tuple(facts.names(answer.get("name_servers"))),
        tuple(a for a in (facts.canonical("ip", v) for v in _list(answer.get("addresses"))) if a),
        address if ip_answer is not None else None,
        facts.number(ip.get("asn"), 0, 4_294_967_295), facts.clean(ip.get("owner"), 60),
    )  # fmt: skip


def current(status: str, answer: Mapping[str, Any]) -> bool:
    """Whether a cached domain answer carries the family fields (``Outside.lookup``'s ``fresh``):
    a record of the shape this module reads, or no record at all."""
    return facts.current_domain(status, answer)


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def net_of(address: str) -> str:
    """The network an address's neighbours share: its /24 (IPv4) or /48 (IPv6)."""
    ip = ipaddress.ip_address(address)
    return str(ipaddress.ip_network(f"{address}/{24 if ip.version == 4 else 48}", strict=False))


_PRIVATE = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                      "100.64.0.0/10", "fc00::/7")
)  # fmt: skip


def tie_address(address: str, shared: Shared) -> bool:
    """Whether an address can say who is behind a domain: it is outside the shared networks and is
    not special-purpose (loopback, unspecified, private, link-local: where a taken-down domain
    points, for thousands of unrelated domains). Documentation ranges count (they are the
    tests' public addresses)."""
    if shared.reason("ip", address) is not None:
        return False
    ip = ipaddress.ip_address(address)
    if ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast or ip.is_reserved:
        return False
    return not any(ip.version == n.version and ip in n for n in _PRIVATE)


def first_tie_address(reading: Reading, shared: Shared) -> str | None:
    """The first address of the family outside shared networks (see :func:`tie_address`)."""
    return next((a for a in reading.addresses if tie_address(a, shared)), None)


def name_server_set(reading: Reading, shared: Shared) -> frozenset[str]:
    """The family's name servers as a set, empty when there are fewer than
    :data:`MIN_NAME_SERVERS` (one server alone is no account's own pair) or when every one is a
    shared DNS host's default (Namecheap's ``registrar-servers.com`` pair serves all its
    customers alike); Cloudflare's pairs are each account's own, so they stand."""
    servers = frozenset(reading.name_servers)
    if len(servers) < MIN_NAME_SERVERS:
        return frozenset()
    if all(
        shared.reason("domain", s) is not None and not s.endswith(ACCOUNT_NAME_SERVERS)
        for s in servers
    ):
        return frozenset()
    return servers


def operator_keys(reading: Reading, shared: Shared) -> frozenset[tuple[str, str]]:
    """What can tie a family to another, and nothing else: an identical set of two or more
    name servers (``ns``: Cloudflare gives each account a fixed pair and Route53 each zone its own
    set, so it stands even when the provider is a shared domain; a pool of servers that merely
    share a registered domain ties nothing), the /24 of the first address outside the shared
    networks (``net``) and the autonomous system of that address (``as``) unless it is one of the
    big hosters of the shared-infrastructure list."""
    keys: set[tuple[str, str]] = set()
    servers = name_server_set(reading, shared)
    if servers:
        keys.add(("ns", ",".join(sorted(servers))))
    first = first_tie_address(reading, shared)
    if first is not None:
        keys.add(("net", net_of(first)))
    if (
        reading.asn is not None
        and reading.address is not None
        and tie_address(reading.address, shared)
        and shared.reason("as", str(reading.asn)) is None
    ):
        keys.add(("as", str(reading.asn)))
    return frozenset(keys)


@dataclass(frozen=True)
class World:
    """What the analysis reads: the investigations that hold domain names, what the cache says
    about their parents, and the addresses VirusTotal flags with the investigations that reached
    them."""

    sightings: tuple[Sighting, ...]
    readings: Mapping[str, Reading] = field(default_factory=dict)  # by registered parent
    servers: Mapping[str, frozenset[uuid.UUID]] = field(default_factory=dict)  # flagged address
    # the internal devices of each investigation
    hosts: Mapping[uuid.UUID, frozenset[Key]] = field(default_factory=dict)
    threshold: int = 3


@dataclass(frozen=True)
class Campaign:
    """Internal devices and the infrastructure they reached that belong together."""

    members: frozenset[uuid.UUID]
    hosts: frozenset[Key]
    parents: tuple[str, ...]  # domain families in it, the widest first
    servers: tuple[str, ...]  # flagged addresses in it
    flagged: tuple[str, ...]  # of the two, those VirusTotal flags
    infrastructure: tuple[str, ...]  # the networks and name servers that tie them, in words
    benign: tuple[str, ...]  # benign families in the same alerts (see ``_campaign``)
    random_share: float  # of the names under its domains that look random
    # the internal devices of each member investigation (the suggester treats them as its actors)
    member_hosts: Mapping[uuid.UUID, frozenset[Key]] = field(default_factory=dict)

    def keys(self) -> frozenset[Key]:
        """The indicators a case holds for it."""
        return frozenset({("domain", p) for p in self.parents} | {("ip", s) for s in self.servers})

    def reason(self) -> str:
        """The campaign in a line: "one operator, 47 internal devices: ..."."""
        n = len(self.hosts)
        devices = f"{n} {site.own('device' if n == 1 else 'devices')}"
        what = [*self.parents, *self.servers]
        shown = ", ".join(what[:4]) + (f" and {len(what) - 4} more" if len(what) > 4 else "")
        flagged = f" (flagged outside: {', '.join(self.flagged[:3])})" if self.flagged else ""
        text = f"one operator, {devices}: {shown}{flagged}"
        if self.infrastructure:
            text += f"; infrastructure: {', '.join(self.infrastructure[:3])}"
        if self.random_share >= 0.5:
            text += f"; {round(self.random_share * 100)}% of the names look random"
        if self.benign:
            text += (
                f". Also in these alerts (benign, ARGUS recommends closing):"
                f" {', '.join(self.benign[:4])}"
            )
        return text


@dataclass(frozen=True)
class Result:
    campaigns: tuple[Campaign, ...]
    flags: Mapping[str, frozenset[uuid.UUID]]  # flag in words -> investigations that carry it
    families: Mapping[str, Family]


def analyse(
    world: World, *, shared: Shared = NO_SHARED, now: datetime | None = None,
    usable: Callable[[str], bool] = lambda parent: True,
) -> Result:  # fmt: skip
    """The campaigns and flags the world shows. ``usable(parent)``: the parent may be asked about
    outside (``Eligibility``); a family that may not is never read as rare, tied or flagged.
    ``now`` is kept for the callers: a reading no longer depends on the clock (the rank's age is
    judged when the answer is parsed)."""
    found = fam.families_of(world.sightings)
    readings = {
        p: r for p, r in world.readings.items()
        if p in found and usable(p) and shared.reason("domain", p) is None
    }  # fmt: skip
    detected = {  # a popular site flagged by a few engines is a false positive far more often
        p for p, r in readings.items() if r.detected(world.threshold) and not r.popular
    }  # fmt: skip
    rare = {p for p, f in found.items() if f.candidate and p in readings and readings[p].unranked}
    shape = rare - detected  # large, rare, looked at, and not flagged themselves: tied or not
    # operator ties: a union over parents (and flagged addresses) that share a key
    elements: dict[Key, set[Key]] = {}
    for p in sorted(detected | shape):
        elements[("domain", p)] = set(operator_keys(readings[p], shared))
    # an address that a popular family points at is the popular service's, not a campaign's
    popular_at = {a for r in readings.values() if r.popular for a in r.addresses}
    servers = {
        a: ids for a, ids in world.servers.items()
        if shared.reason("ip", a) is None and a not in popular_at
    }  # fmt: skip
    for a in sorted(servers):  # an address in a shared network says nothing of who is behind it
        elements[("ip", a)] = {("net", net_of(a))}
    parent_of: dict[Key, Key] = {}

    def root(x: Key) -> Key:
        parent_of.setdefault(x, x)
        while parent_of[x] != x:
            parent_of[x] = parent_of[parent_of[x]]
            x = parent_of[x]
        return x

    first_with: dict[tuple[str, str], Key] = {}
    for element in sorted(elements):
        root(element)
        for key in sorted(elements[element]):
            if key in first_with:
                parent_of[root(element)] = root(first_with[key])
            else:
                first_with[key] = element
    for a in sorted(servers):  # a family that points at a flagged address is tied to it
        for p in sorted(detected | shape):
            if a in readings[p].addresses:
                parent_of[root(("ip", a))] = root(("domain", p))
    groups: dict[Key, list[Key]] = defaultdict(list)
    for element in sorted(elements):
        groups[root(element)].append(element)

    def hosts_of(ids: Iterable[uuid.UUID]) -> frozenset[Key]:
        return frozenset(h for i in ids for h in world.hosts.get(i, ()))

    def reached(element: Key) -> frozenset[uuid.UUID]:
        kind, value = element
        return servers[value] if kind == "ip" else found[value].investigations

    flags: dict[str, set[uuid.UUID]] = {OUTSIDE: set(), OPERATOR: set(), CAMPAIGN: set()}
    for p in detected:
        flags[OUTSIDE] |= found[p].investigations
    for p, f in found.items():
        if p in rare and len(f.hosts) >= MIN_FLAG_HOSTS and len(f.names) >= MIN_FLAG_NAMES:
            flags[CAMPAIGN] |= f.investigations
    campaigns: list[Campaign] = []
    for members_of_group in groups.values():
        flagged_in = [
            e for e in members_of_group
            if (e[0] == "domain" and e[1] in detected) or e[0] == "ip"
        ]  # fmt: skip
        if not flagged_in:
            continue  # nothing in the group is flagged: rare and alike, but no proof of harm
        for kind, value in members_of_group:
            if kind == "domain" and value in shape:
                flags[OPERATOR] |= found[value].investigations
        ids: set[uuid.UUID] = set()
        for e in members_of_group:
            ids |= reached(e)
        hosts = hosts_of(ids)
        if len(hosts) < MIN_SERVER_HOSTS:
            continue
        campaigns.append(_campaign(members_of_group, ids, hosts, found, readings, detected,
                                   world, shared))  # fmt: skip
    campaigns.sort(key=lambda c: (-len(c.hosts), c.parents, c.servers))
    return Result(tuple(campaigns), {k: frozenset(v) for k, v in flags.items()}, found)


def _infrastructure(
    parents: Sequence[str], readings: Mapping[str, Reading], shared: Shared
) -> list[str]:
    """What the campaign's domains share, in words: the autonomous system each is hosted in (when
    it is not one of the big hosters, where it says nothing), a /24 two of them share and an
    identical set of name servers two of them share."""
    ties: list[str] = []
    seen_as: set[int] = set()
    nets: dict[str, set[str]] = defaultdict(set)
    sets: dict[tuple[str, ...], set[str]] = defaultdict(set)
    for p in parents:
        r = readings[p]
        if r.asn is not None and r.asn not in seen_as and shared.reason("as", str(r.asn)) is None:
            seen_as.add(r.asn)
            ties.append(f"AS{r.asn}" + (f" ({r.owner})" if r.owner else ""))
        first = first_tie_address(r, shared)
        if first is not None:
            nets[net_of(first)].add(p)
        servers = tuple(sorted(name_server_set(r, shared)))
        if servers:
            sets[servers].add(p)
    ties.extend(f"network {net}" for net, who in sorted(nets.items()) if len(who) >= 2)
    ties.extend("name servers " + " and ".join(servers) for servers, who in sorted(sets.items())
                if len(who) >= 2)  # fmt: skip
    return ties


def _campaign(
    elements: Collection[Key], ids: set[uuid.UUID], hosts: frozenset[Key],
    found: Mapping[str, Family], readings: Mapping[str, Reading], detected: Collection[str],
    world: World, shared: Shared,
) -> Campaign:  # fmt: skip
    parents = sorted(
        (v for k, v in elements if k == "domain"),
        key=lambda p: (-len(found[p].hosts), -len(found[p].names), p),
    )
    servers = sorted(v for k, v in elements if k == "ip")
    flagged = [p for p in parents if p in detected] + servers
    ties = _infrastructure(parents, readings, shared)
    random = sum(found[p].random for p in parents)
    below = sum(found[p].below for p in parents)
    taken = set(parents)
    alerted = frozenset(r for p in parents for r in found[p].rules)  # the rules that raised them

    def same_alerts(p: str) -> bool:
        """In the campaign's own investigations, or raised by the same rule (a rule that makes an
        investigation for each rare domain lists the popular ones beside the campaign's, asked for
        by other devices)."""
        family = found[p]
        return bool(family.investigations & ids) or bool(family.rules & alerted)

    benign = sorted(
        (
            p
            for p, r in readings.items()
            if p not in taken and r.benign() and found[p].candidate and same_alerts(p)
        ),
        key=lambda p: (-len(found[p].hosts), p),
    )
    return Campaign(
        frozenset(ids), hosts, tuple(parents), tuple(servers), tuple(flagged), tuple(ties),
        tuple(benign), random / below if below else 0.0,
        {i: world.hosts[i] for i in sorted(ids) if i in world.hosts},
    )  # fmt: skip
