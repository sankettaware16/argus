"""Case titles: what happened, to or from whom, with the key values.

:func:`title` is pure: the same :class:`Facts` give the same title, at most :data:`MAX_TITLE`
characters. A title reaches Kibana, terminals and PDFs whose readers may lack log access, so it
holds only values of a strict shape (an IP address, a host or domain name, an asset-map name, a
family from :data:`FAMILIES`, a rule's plain name, counts); anything else is dropped for a count.
The shapes, the first that fits: DNS look-ups of look-alike domains under a parent, internal
devices and flagged servers, threat-listed outside addresses at internal servers, outside addresses
at internal web sites, else ``<rule name>: <actor> → <target>``. Each shape lists wordings from the
most to the least specific, so a long value falls back to a count and never to a cut."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from argus import site
from argus.outside import facts as outside_facts
from argus.outside.psl import registered_parent

MAX_TITLE = 110
MAX_VALUE = 45  # the longest address or name a title spells out
MAX_RULE = 60  # the longest rule name a title holds
EMPTY = "Alert"  # the title of facts that say nothing: a refresh never writes it

# the evidence flags a title reads (the words of ``argus.assess.raised`` and
# ``argus.evaluation.gold``; a test holds them equal)
BEACON = "regular traffic, like a beacon"
LISTED = "on a threat list"
OUTSIDE = "flagged by outside threat intel"
OPERATOR = "same operator as a flagged destination"
SUCCESS = "successful answers after the alert"
SERVED_WORDS = "served successfully"  # in the name of a rule that reports a served file

# malware families a title may name: a table's spelling, matched as whole words in the outside
# labels (tags) and the rules' names. Longer names first, so "Cobalt Strike" is not "Cobalt".
FAMILIES: tuple[str, ...] = (
    "Agent Tesla", "Amadey", "AsyncRAT", "Cobalt Strike", "DarkGate", "DCRat", "Dridex",
    "Emotet", "Formbook", "Gafgyt", "GootLoader", "IcedID", "Lokibot", "Lumma", "Mirai", "Mozi",
    "Njrat", "Pikabot", "Qakbot", "Raccoon", "RedLine", "Remcos", "Sliver", "SmokeLoader",
    "Stealc", "TrickBot", "Vidar", "XMRig", "Metasploit", "Havoc", "BumbleBee", "Rhadamanthys",
    "Socks5Systemz", "Latrodectus", "SystemBC", "Warzone", "Quasar", "NanoCore", "Ursnif",
    "Zloader", "BlackMatter", "PlugX", "ShadowPad", "Gh0st", "Konni", "Kimsuky",
)  # fmt: skip

_NORMAL = re.compile(r"[^a-z0-9]+")
_HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_PLACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 .&()/-]{0,39}")
_KIND = re.compile(r"[a-z][a-z0-9 -]{0,14}")
_RULE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 :,.()/&+-]{0,119}")


def _squash(text: str) -> str:
    return " ".join(text.split())


def _key(text: str) -> str:
    """``text`` as lowercase words joined by single spaces (a label to match a family in)."""
    return " ".join(_NORMAL.sub(" ", text.lower()).split())


_FAMILY_KEYS = tuple(
    sorted(((_key(name), name) for name in FAMILIES), key=lambda kv: (-len(kv[0]), kv[0]))
)


@dataclass(frozen=True)
class Device:
    """An internal device a case names: an address or a host name, with what the asset map says of
    the network it is in (``site.type``: "hostel"; ``site.building``/``site.department``)."""

    value: str
    kind: str = "ip"  # "ip" or "host"
    type: str | None = None
    place: str | None = None


@dataclass(frozen=True)
class Facts:
    """What a title is made of. Every field is optional: a case with few facts gets a plainer
    title. Values are untrusted text until :func:`title` has checked them."""

    rules: tuple[tuple[str, int], ...] = ()  # (rule name, investigations), commonest first
    flags: frozenset[str] = frozenset()  # ARGUS's evidence flags on the investigations
    devices: tuple[Device, ...] = ()  # internal devices that acted
    outsiders: tuple[str, ...] = ()  # outside addresses that acted
    accounts: int = 0  # user accounts that acted (never named)
    servers: tuple[str, ...] = ()  # flagged, listed or command-and-control addresses and names
    domains: tuple[str, ...] = ()  # outside names the devices asked for
    sites: tuple[str, ...] = ()  # internal web sites that were reached
    campus_servers: int = 0  # internal addresses that were reached (not devices that acted)
    listed: tuple[str, ...] = ()  # values a local threat list holds
    served: bool = False  # a config or backup file got a successful answer
    labels: tuple[str, ...] = ()  # outside intel's tags and names: where a family may show
    follows: int = 0  # the number of the closed case this one follows (0: none)
    probed: str | None = None  # what the attackers' paths looked for, in PROBES' words


# What attacked paths look for, in fixed words (a title never repeats a path): the first kind
# whose marks a path holds; a case names a kind when at least 60 % of its paths share it.
PROBES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("path traversal", ("/@fs/", "../", "..%2f", "%2e%2e", "/etc/passwd", "/proc/")),
    (".env secrets files", (".env",)),
    ("Git repository folders", ("/.git",)),
    ("WordPress pages", ("wp-", "wordpress", "xmlrpc.php")),
    ("backup files", (".bak", "backup", ".sql", ".zip", ".tar", ".old", "~")),
    ("admin pages", ("admin", "phpmyadmin", "/manager/")),
    ("config files", ("config", ".yml", ".yaml", ".ini", ".xml", ".json", ".conf")),
)
PROBE_SHARE = 0.6


def probed(paths: Iterable[str]) -> str | None:
    """The kind most of ``paths`` look for, in PROBES' words, or None."""
    kinds: list[str] = []
    for path in paths:
        low = path.lower()
        kinds.append(next((kind for kind, marks in PROBES if any(m in low for m in marks)), ""))
    if not kinds:
        return None
    best, count = Counter(k for k in kinds if k).most_common(1)[0] if any(kinds) else ("", 0)
    return best if best and count >= PROBE_SHARE * len(kinds) else None


def address(value: str) -> str | None:
    """``value`` as a valid IP address in one spelling, or None."""
    found = outside_facts.canonical("ip", value)
    return found if found is not None and len(found) <= MAX_VALUE else None


def domain(value: str) -> str | None:
    """``value`` as a domain name of letters, digits, hyphens and dots (two labels or more)."""
    found = outside_facts.canonical("domain", value)
    if found is None or len(found) > MAX_VALUE or "_" in found or not found.isascii():
        return None
    return found


def host(value: str) -> str | None:
    """``value`` as a host name (one label or more) of letters, digits, hyphens and dots."""
    text = value.strip().rstrip(".")
    if not text or len(text) > MAX_VALUE:
        return None
    return text if all(_HOST_LABEL.fullmatch(label) for label in text.split(".")) else None


def name_of(value: str) -> str | None:
    """An address or a domain name, or None."""
    return address(value) or domain(value)


def place(value: str | None) -> str | None:
    """A building or department from the asset map: plain words, one space between them."""
    text = _squash(value or "")
    return text if _PLACE.fullmatch(text) else None


def kind_word(value: str | None) -> str | None:
    """A kind of site from the asset map ("hostel"), lowercase."""
    text = _squash((value or "").lower().replace("_", " "))
    return text if _KIND.fullmatch(text) else None


def rule_name(value: str) -> str | None:
    """A rule's name when it is plain words, cut at a word at most :data:`MAX_RULE` long."""
    text = _squash(value)
    if not _RULE.fullmatch(text):
        return None
    if len(text) <= MAX_RULE:
        return text
    return text[:MAX_RULE].rsplit(" ", 1)[0].rstrip(" :,-/&+") or None


def family_of(labels: Iterable[str]) -> str | None:
    """The first family of :data:`FAMILIES` that a label names as whole words (the table's
    spelling), in the order of the labels."""
    for label in labels:
        padded = f" {_key(label)} "
        for key, name in _FAMILY_KEYS:
            if f" {key} " in padded:
                return name
    return None


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))


def _devices(f: Facts, *, where: bool = True) -> str:
    """Who acted inside the network: the device, or a count with the place or kind they share."""
    devices = list(dict.fromkeys(f.devices))
    named = [(d, host(d.value) if d.kind == "host" else address(d.value)) for d in devices]
    if len(devices) == 1:
        return named[0][1] or site.a_own("device")
    n = len(devices)
    if where:
        places = {place(d.place) for d in devices}
        if len(places) == 1 and None not in places:
            return f"{n} {site.own('devices')} in {next(iter(places))}"
        kinds = {kind_word(d.type) for d in devices}
        if len(kinds) == 1 and None not in kinds:
            return f"{n} {next(iter(kinds))} devices"
    return f"{n} {site.own('devices')}"


def _outsiders(f: Facts) -> str:
    seen = _unique(f.outsiders)
    if len(seen) == 1:
        return address(seen[0]) or "an outside address"
    return f"{len(seen)} outside addresses"


def _servers_reached(f: Facts) -> str:
    """ "an internal server" / "3 internal servers": the own addresses that were reached."""
    if f.campus_servers == 1:
        return site.a_own("server")
    return f"{f.campus_servers} {site.own('servers')}"


def _more(first: str, total: int, noun: str) -> str:
    """``first`` and the others in words: "a and 2 more flagged servers"."""
    if total <= 1:
        return first
    more = total - 1
    return f"{first} and {more} more {noun}{'' if more == 1 else 's'}"


def _servers(f: Facts, *, named: bool = True) -> str:
    seen = _unique(f.servers)
    if not seen:
        return "flagged servers"
    first = next((v for v in map(name_of, seen) if v), None) if named else None
    if first is None:
        return "a flagged server" if len(seen) == 1 else f"{len(seen)} flagged servers"
    return _more(first, len(seen), "flagged server")


def _family(f: Facts) -> str | None:
    return family_of([*f.labels, *(name for name, _ in f.rules)])


def _served(f: Facts) -> bool:
    """Whether a config or backup file got a successful answer: a stored check says so, or a
    rule's own name does ("... Served Successfully"). Only the title's wording depends on it."""
    return f.served or any(SERVED_WORDS in name.lower() for name, _ in f.rules)


def _what(f: Facts) -> str:
    """What the web attack got, as the end of a title."""
    if _served(f):
        return " — config files served"
    return " — attacks got successful answers" if SUCCESS in f.flags else ""


def _dns(f: Facts) -> list[str] | None:
    """Internal devices that asked for many names under one or a few parent domains."""
    if not f.devices:
        return None
    sites = set(map(domain, f.sites))
    names = _unique(d for d in map(domain, f.domains) if d and d not in sites)
    parents = Counter(p for p in map(registered_parent, names) if p)
    groups = sorted(((p, c) for p, c in parents.items() if c >= 2), key=lambda pc: (-pc[1], pc[0]))
    addresses = [v for v in _unique(f.servers) if address(v)]
    if not groups or sum(c for _, c in groups) < len(addresses):
        return None
    n = sum(c for _, c in groups)
    first = groups[0][0]
    if len(groups) == 1:
        under = first
    elif len(groups) == 2:
        under = f"{first} and {groups[1][0]}"
    else:
        under = _more(first, len(groups), "domain")
    head = f"DNS lookups of {n} look-alike domains"
    return [
        f"{head} under {under} from {_devices(f)}",
        f"{head} under {under} from {_devices(f, where=False)}",
        f"{head} under {first} from {_devices(f, where=False)}",
        f"{head} from {_devices(f, where=False)}",
        f"DNS lookups of look-alike domains from {site.own('devices')}",
    ]


def _beacon(f: Facts) -> list[str] | None:
    """Internal devices in contact with flagged servers, or beaconing."""
    if not f.devices:
        return None
    beacon = BEACON in f.flags
    servers = bool(_unique(f.servers))
    if not (servers or beacon or f.flags & {LISTED, OUTSIDE, OPERATOR}):
        return None
    family = _family(f)
    out = [
        _contact(family, beacon, servers, _devices(f, where=where), _servers(f, named=named))
        for where, named in ((True, True), (False, True), (False, False))
    ]
    out.append(_contact(None, beacon, False, site.own("devices"), ""))
    return out


def _contact(family: str | None, beacon: bool, servers: bool, who: str, to: str) -> str:
    """One wording: with the servers ``to`` when the case names some, else without them."""
    if family:
        verb = "beaconing" if beacon else "contact"
        return f"{family} {verb} from {who}" + (f" to {to}" if servers else "")
    if not servers:
        return f"{'Beaconing' if beacon else 'Contact with flagged servers'} from {who}"
    if beacon:
        return f"Beaconing to {to} from {who}"
    flagged = (
        to if "flagged" in to else f"flagged server {to}"
    )  # one name alone: say why it matters
    return f"Contact with {flagged} from {who}"


def _sites(f: Facts) -> str | None:
    seen = _unique(f.sites)
    if not seen:
        return None
    first = next((v for v in map(domain, seen) if v), None)
    if first is None:
        return site.a_own("site") if len(seen) == 1 else f"{len(seen)} {site.own('sites')}"
    more = len(seen) - 1
    if more < 1:
        return first
    return f"{first} and {more} more {site.own('site' if more == 1 else 'sites')}"


def _target(f: Facts) -> str:
    """The internal servers or sites reached, for "probing ..."."""
    if f.campus_servers > 0:
        return _servers_reached(f)
    sites = _sites(f)
    if sites is not None and len(_unique(f.sites)) == 1:
        return sites
    if sites is not None:
        return f"{len(_unique(f.sites))} {site.own('web sites')}"
    return site.own("servers")


def _probe(f: Facts) -> list[str] | None:
    """Outside addresses a local threat list holds, probing internal servers."""
    if f.devices:
        return None
    outsiders = _unique(f.outsiders)
    listed = set(f.listed)
    hits = [o for o in outsiders if o in listed]
    if not hits or not (f.sites or f.campus_servers):
        return None
    target = _target(f)
    tail = _what(f) if f.sites else ""
    if len(hits) == 1:
        one = address(hits[0])
        head = f"Threat-listed {one}" if one else "A threat-listed outside address"
        return [
            f"{head} probing {target}{tail}",
            f"{head} probing {site.own('servers')}",
            f"A threat-listed outside address probing {site.own('servers')}",
        ]
    head = f"{len(hits)} threat-listed outside addresses"
    return [f"{head} probing {target}{tail}", f"{head} probing {site.own('servers')}"]


def _web(f: Facts) -> list[str] | None:
    """Outside addresses that reached internal web sites."""
    if f.devices or not _unique(f.outsiders):
        return None
    who = _outsiders(f)
    tail = _what(f)
    if _unique(f.sites):
        sites = _sites(f) or site.own("sites")
        count = len(_unique(f.sites))
        plain = site.a_own("site") if count == 1 else f"{count} {site.own('sites')}"
        return [
            f"Web scanning of {sites} by {who}{tail}",
            f"Web scanning of {plain} by {who}{tail}",
            f"Web scanning of {plain} by outside addresses{tail}",
        ]
    kind = f.probed if f.probed in {k for k, _ in PROBES} else None
    answered = " — some got successful answers" if SUCCESS in f.flags else ""
    if kind is not None:
        if _served(f):
            answered = " — config files served"
        return [
            f"Probing for {kind} by {who}{answered}",
            f"Probing for {kind} by outside addresses{answered}",
        ]
    if SUCCESS in f.flags:
        return [
            f"Web attack by {who} got successful answers",
            "Web attack by outside addresses got successful answers",
        ]
    return None


def _actor(f: Facts) -> str | None:
    if f.devices:
        return _devices(f)
    if _unique(f.outsiders):
        return _outsiders(f)
    if f.accounts > 0:
        return "a user account" if f.accounts == 1 else f"{f.accounts} user accounts"
    return None


def _destination(f: Facts) -> str | None:
    servers = _unique(f.servers)
    if servers:
        return _servers(f).replace("flagged servers", "servers").replace("flagged server", "server")
    sites = _unique(f.sites)
    if sites:
        return _sites(f)
    names = _unique(d for d in map(domain, f.domains) if d)
    if names:
        parents = _unique(p for p in map(registered_parent, names) if p)
        if parents:
            return _more(parents[0], len(parents), "domain")
        return _more(names[0], len(names), "domain")
    if f.campus_servers:
        return _servers_reached(f)
    return None


def _fallback(f: Facts) -> list[str]:
    """The rule's name, the actor and the target."""
    rule = next((r for r in (rule_name(name) for name, _ in f.rules) if r), EMPTY)
    join = " — " if ":" in rule else ": "
    actor, target = _actor(f), _destination(f)
    out = []
    if actor and target:
        out.append(f"{rule}{join}{actor} → {target}")
    if actor:
        out.append(f"{rule}{join}{actor}")
    out += [rule, EMPTY]
    return out


def _fit(options: Sequence[str], limit: int = MAX_TITLE) -> str:
    for option in options:
        if len(option) <= limit:
            return option
    last = options[-1]
    return last[:limit].rsplit(" ", 1)[0] or last[:limit]


def title(facts: Facts) -> str:
    """The case's title (pure): the first shape that fits the facts, in its most specific wording
    that is at most :data:`MAX_TITLE` characters. A case that follows a closed one ends with
    " — follows case N" (within the same bound)."""
    tail = f" — follows case {facts.follows}" if facts.follows > 0 else ""
    limit = MAX_TITLE - len(tail)
    for shape in (_dns, _beacon, _probe, _web):
        options = shape(facts)
        if options:
            return _fit(options, limit) + tail
    return _fit(_fallback(facts), limit) + tail
