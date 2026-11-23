"""Case titles (naming v2): a title is a list of claims, and each claim rests on a named fact.

:func:`titled` is pure: :class:`Facts` in, a :class:`Titled` out, whose parts are fixed joining
words (:data:`JOINS`) and :class:`Claim` s. :func:`check` refuses a title that holds a claim no fact
backs, a number that is not the size of its set, a certainty word the verdicts do not give, a
joining word outside the list or a broken length bound; :func:`titled` only returns a wording that
passes it (each shape lists wordings from the most to the least specific, the facts' values falling
to counts). The grammar:

    [Certainty] [Family] Activity Object · Actors (N of M) [Place] — Outcome [— follows case N]

The words are fixed phrases that facts choose (the activity catalogue, the outcome ladder), never a
rule's name: a rule's name shows only quoted and attributed, in the fallback ("alerts of rule
'…'"). A title reaches Kibana, terminals and PDFs, so a value in it has a strict shape (an IP
address, a host or domain name, an asset-map place or zone, a family from :data:`FAMILIES`, a
rule's plain name, counts); anything else is dropped for a count. :func:`title` is the text."""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from functools import lru_cache
from types import MappingProxyType
from typing import Literal

from argus import site
from argus.assess import raised
from argus.outside import facts as outside_facts
from argus.outside.psl import registered_parent

MAX_TITLE = 100  # a stored title
FRONT = 48  # the activity ends within the first 48 characters (the Inbox, a narrow list)
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
PORTS = "remote-admin, P2P or anonymizer ports"
CAMPAIGN = raised.CAMPAIGN  # a stored key; shown in the site's words
EVIDENCE = frozenset({BEACON, LISTED, OUTSIDE, OPERATOR, SUCCESS, PORTS, CAMPAIGN})
BEACON_PORTS = f"{BEACON} + {PORTS}"  # a per-device set: both flags on one investigation
# a stored path check's outcomes (``argus.context.paths``; a test holds them equal)
PATH_SERVED = "success"
PATH_CATCH_ALL = "catch_all"

# the certainty words (D-309): who decided, never the verdict sentence
CONFIRMED = "Confirmed"  # a person's true positive
LIKELY = "Likely"  # ARGUS's own proposal of a true positive
SUSPECTED = "Suspected"  # raised from ARGUS's evidence, no proposal
UNCLEAR = "Unclear"  # the evidence raised it, a verdict says otherwise or the verdicts disagree
HARMLESS = "Likely harmless"  # a benign proposal or reading and no contrary evidence
CERTAINTIES = (HARMLESS, CONFIRMED, LIKELY, SUSPECTED, UNCLEAR)  # the longest first, to parse
COLON = frozenset({UNCLEAR, HARMLESS})  # followed by a colon: "Unclear: beaconing ..."
TRUE_POSITIVE = "true_positive"
INCONCLUSIVE = "inconclusive"

# malware families a title may name: a table's spelling, matched as whole words in the threat
# names ARGUS stores (outside answers' tags and labels, the threat lists' descriptions), never in a
# rule's name. Longer names first, so "Cobalt Strike" is not "Cobalt".
FAMILIES: tuple[str, ...] = (
    "Agent Tesla", "Amadey", "AsyncRAT", "Cobalt Strike", "DarkGate", "DCRat", "Dridex",
    "Emotet", "Formbook", "Gafgyt", "GootLoader", "IcedID", "Lokibot", "Lumma", "Mirai", "Mozi",
    "Njrat", "Pikabot", "Qakbot", "Raccoon", "RedLine", "Remcos", "Sliver", "SmokeLoader",
    "Stealc", "TrickBot", "Vidar", "XMRig", "Metasploit", "Havoc", "BumbleBee", "Rhadamanthys",
    "Socks5Systemz", "Latrodectus", "SystemBC", "Warzone", "Quasar", "NanoCore", "Ursnif",
    "Zloader", "BlackMatter", "PlugX", "ShadowPad", "Gh0st", "Konni", "Kimsuky", "PS1Bot",
)  # fmt: skip

_NORMAL = re.compile(r"[^a-z0-9]+")
_HOST_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_PLACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 .&()/-]{0,39}")
_KIND = re.compile(r"[a-z][a-z0-9 -]{0,14}")
_RULE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 :,.()/&+-]{0,119}")
_QUOTED = re.compile(r"'[^']*'")


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
    the network it is in. ``place`` is ``site.building`` or ``site.department``; ``zone`` is
    ``site.zone`` (hostel, department). ``type`` (``site.type``) is the network equipment the asset
    map lists for the range (switch, gateway): it is kept and never said in a title."""

    value: str
    kind: str = "ip"  # "ip" or "host"
    type: str | None = None
    place: str | None = None
    zone: str | None = None


@dataclass(frozen=True)
class Verdict:
    """Who said what about the case, for the certainty word: the outcome people hold (a person's
    decision on the report, else the outcome most of their reviews hold), whether a person opened or
    confirmed the case, and ARGUS's own proposals and readings (one outcome per investigation).
    ``given``: a word of :data:`CERTAINTIES` the caller decided (the incident engine's presenter),
    which stands for all of them."""

    person: str | None = None
    opened: bool = False
    proposals: tuple[str, ...] = ()
    readings: tuple[str, ...] = ()
    given: str | None = None


def _no_sets() -> Mapping[str, frozenset[str]]:
    return MappingProxyType({})


def _no_counts() -> Mapping[str, int]:
    return MappingProxyType({})


@dataclass(frozen=True)
class Facts:
    """What a title is made of. Every field is optional: a case with few facts gets a plainer
    title. Values are untrusted text until :func:`titled` has checked them.

    The per-device sets (``doing``: evidence flag -> the devices whose investigations carry it;
    ``reaches``: destination -> the devices whose investigations name it) say who did what, so a
    count in a title is the size of the set of devices that carry the activity's fact. When a set
    is not given (a planner that holds one investigation), the case's flags stand for every device.
    The incident engine's per-entity facts plug in here."""

    rules: tuple[tuple[str, int], ...] = ()  # (rule name, investigations), commonest first
    flags: frozenset[str] = frozenset()  # ARGUS's evidence flags on the investigations
    devices: tuple[Device, ...] = ()  # internal devices that acted
    outsiders: tuple[str, ...] = ()  # outside addresses that acted
    accounts: int = 0  # user accounts that acted (never named)
    servers: tuple[str, ...] = ()  # flagged, listed or command-and-control addresses and names
    domains: tuple[str, ...] = ()  # outside names the devices asked for
    sites: tuple[str, ...] = ()  # internal web sites that were reached (entities, stored checks)
    own_servers: int = 0  # internal addresses that were reached (not devices that acted)
    listed: tuple[str, ...] = ()  # values a local threat list holds
    labels: tuple[str, ...] = ()  # threat names ARGUS stores: where a family may show
    follows: int = 0  # the number of the closed case this one follows (0: none)
    probed: str | None = None  # what the attackers' paths looked for (a planner's guess)
    verdict: Verdict = field(default_factory=Verdict)
    doing: Mapping[str, frozenset[str]] = field(default_factory=_no_sets)
    reaches: Mapping[str, frozenset[str]] = field(default_factory=_no_sets)
    destinations: tuple[str, ...] = ()  # outside addresses and names the devices' alerts name
    vt: Mapping[str, int] = field(default_factory=_no_counts)  # server -> VirusTotal engines
    paths: tuple[str, ...] = ()  # the attacked paths (the case's URL indicators)
    answered: tuple[tuple[str, str], ...] = ()  # (site, path): a stored follow-up's 2xx answer
    outcomes: tuple[tuple[str, str, str], ...] = ()  # (site, path, outcome): stored path checks
    checks: frozenset[str] = frozenset()  # the statuses of the stored follow-ups (ok, empty, ...)
    server_cases: Mapping[str, int] = field(default_factory=_no_counts)  # server -> earlier case
    # destination -> the devices whose beacon-timed investigations name it (None: not known, the
    # beacon devices that reach it stand in)
    beacon_reaches: Mapping[str, frozenset[str]] | None = None
    # destination -> the devices whose investigations with the campaign flag name it (None: not
    # known, the campaign devices that reach it stand in)
    campaign_reaches: Mapping[str, frozenset[str]] | None = None
    # an outside thing or a device -> the threat names a family may come from when a device title
    # names that thing or counts that device among its actors (None: not known, ``labels`` stand
    # for the case). The incident engine gives a flagged or bound thing's own names, and a
    # device the names of the campaigns that bind it.
    labelled: Mapping[str, tuple[str, ...]] | None = None
    more_devices: int = 0  # devices of the case past what ``devices`` lists (a bounded read)


# -- values ----------------------------------------------------------------------------------------


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
    """A zone from the asset map ("hostel"), lowercase."""
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


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


# -- what attacked paths look for, and what answered ---------------------------------------------

# (scan words, marks): the first kind whose marks a path holds. A case names a kind when at least
# 60 % of its paths share it, or two kinds of at least 25 % each.
SCANS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("path-traversal", ("/@fs/", "../", "..%2f", "%2e%2e", "/etc/passwd", "/proc/")),
    (".env", (".env",)),
    ("Git-folder", ("/.git",)),
    ("WordPress", ("wp-", "wordpress", "xmlrpc.php")),
    ("backup", (".bak", "backup", ".sql", ".zip", ".tar", ".old", "~")),
    ("admin-page", ("admin", "phpmyadmin", "/manager/")),
    ("config-file", ("config", ".yml", ".yaml", ".ini", ".xml", ".json", ".conf")),
)
SCAN_KINDS = tuple(k for k, _ in SCANS)
SCAN_SHARE = 0.6
PAIR_SHARE = 0.25
WEB_SCAN = "web"  # no kind: "web scan"
# (key, what answered, marks): a path's kind as an answer, the most telling first ("wp-config.php"
# is a config file, not a WordPress page); a path of no kind is an ordinary page
FILES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (".env", ".env file", (".env",)),
    ("git", "Git file", ("/.git",)),
    ("config", "config file", ("config", "settings.php", ".yml", ".yaml", ".ini", ".conf")),
    ("backup", "backup file", (".bak", "backup", ".sql", ".zip", ".tar", ".old", "~")),
    ("admin", "admin page", ("admin", "phpmyadmin", "/manager/")),
    ("wordpress", "WordPress page", ("wp-", "wordpress", "xmlrpc.php")),
)
FILE_KEYS = tuple(k for k, _, _ in FILES)
ORDINARY = "ordinary"
# what a scan kind expects to get (so ".env scan ... got HTTP 200" does not name the kind twice)
EXPECTS = {".env": ".env", "Git-folder": "git", "WordPress": "wordpress", "backup": "backup",
           "admin-page": "admin", "config-file": "config"}  # fmt: skip


def _scan_kind(path: str) -> str:
    low = path.lower()
    return next((kind for kind, marks in SCANS if any(m in low for m in marks)), "")


def file_kind(path: str) -> str:
    """What answered at ``path``: a key of :data:`FILES`, or :data:`ORDINARY`."""
    low = path.lower()
    return next((key for key, _, marks in FILES if any(m in low for m in marks)), ORDINARY)


def scan_kinds(paths: Iterable[str]) -> tuple[str, ...]:
    """The kinds ``paths`` look for, in :data:`SCANS`' words: one kind that 60 % share, or two of
    at least 25 % each (the commoner first), else none."""
    kinds = [_scan_kind(p) for p in paths]
    if not kinds:
        return ()
    tally = Counter(k for k in kinds if k)
    ranked = sorted(tally.items(), key=lambda kv: (-kv[1], SCAN_KINDS.index(kv[0])))
    if ranked and ranked[0][1] >= SCAN_SHARE * len(kinds):
        return (ranked[0][0],)
    pair = [k for k, n in ranked[:2] if n >= PAIR_SHARE * len(kinds)]
    return tuple(pair) if len(pair) == 2 else ()


def probed(paths: Iterable[str]) -> str | None:
    """The one kind most of ``paths`` look for, in :data:`SCANS`' words, or None."""
    kinds = scan_kinds(paths)
    return kinds[0] if len(kinds) == 1 else None


# -- certainty -------------------------------------------------------------------------------------


def _evidence(f: Facts) -> bool:
    """Whether ARGUS's own evidence raised the case: a flag, a flagged server, a threat list."""
    return bool(f.flags & EVIDENCE) or bool(_unique(f.servers)) or bool(_unique(f.listed))


AGREE = 2 / 3  # the share of verdicts one outcome needs, else they disagree: Unclear


def _said(outcomes: Iterable[str], evidence: bool, all_true: str) -> str:
    """The word for one source's verdicts: the outcome at least two thirds of them hold (a true
    positive: ``all_true``; inconclusive: Unclear; benign: Likely harmless, or Unclear when ARGUS's
    evidence raised the case), else Unclear."""
    tally = Counter(outcomes)
    top, n = sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))[0]
    if n < AGREE * sum(tally.values()):
        return UNCLEAR
    if top == TRUE_POSITIVE:
        return all_true
    if top == INCONCLUSIVE:
        return UNCLEAR
    return UNCLEAR if evidence else HARMLESS


def certainty(f: Facts) -> str:
    """The certainty word the verdicts give: a person's outcome first (a true positive:
    Confirmed), then a person's opening of the case (Confirmed), then ARGUS's proposals (all true
    positive: Likely), then its readings (all true positive: Suspected), else Suspected. A benign
    word with ARGUS's evidence behind the case, an inconclusive one, or verdicts that disagree:
    Unclear; benign with no evidence: Likely harmless. A word the caller gave stands."""
    v = f.verdict
    if v.given in CERTAINTIES:
        return v.given
    evidence = _evidence(f)
    if v.person is not None:
        return _said((v.person,), evidence, CONFIRMED)
    if v.opened:
        return CONFIRMED
    if v.proposals:
        return _said(v.proposals, evidence, LIKELY)
    if v.readings:
        return _said(v.readings, evidence, SUSPECTED)
    return SUSPECTED


def split_certainty(text: str) -> tuple[str | None, str]:
    """(the certainty word that leads an ARGUS title, the rest), or (None, ``text``)."""
    for word in CERTAINTIES:
        lead = word + (": " if word in COLON else " ")
        if text.startswith(lead) and len(text) > len(lead):
            return word, text[len(lead) :]
    return None, text


def without_certainty(text: str, word: str | None) -> str:
    """``text`` without the certainty word ``word`` it starts with (Kibana's form: only confirmed
    cases go there), its first letter capitalised; ``text`` as it is when it does not start so."""
    found, rest = split_certainty(text)
    if word is None or found != word:
        return text
    return rest[:1].upper() + rest[1:]


# -- the parts of a title ------------------------------------------------------------------------

Slot = Literal[
    "certainty", "family", "activity", "object", "actors", "place", "outcome", "follows", "rule"
]
# the words that join claims: nothing else is in a title
JOINS = frozenset({
    " ", " to ", " from ", " of ", " by ", " for ", " in ", " with ", " — ", " (", ")", ", ",
    " and ", " under ", " +",
})  # fmt: skip


@dataclass(frozen=True)
class Claim:
    """One claim of a title: the exact words it adds, and the fact they rest on (``fact`` names
    it: ``"server:203.0.113.5"``, ``"actors:beacon:12:22"``, ``"outcome:unverified:.env"``)."""

    slot: Slot
    words: str
    fact: str


Part = Claim | str


@dataclass(frozen=True)
class Titled:
    """A title as its parts: joining words (:data:`JOINS`) and claims."""

    parts: tuple[Part, ...]

    @property
    def text(self) -> str:
        return "".join(p.words if isinstance(p, Claim) else p for p in self.parts)

    @property
    def claims(self) -> tuple[Claim, ...]:
        return tuple(p for p in self.parts if isinstance(p, Claim))

    def explain(self) -> list[dict[str, str]]:
        """Each claim with the fact it rests on ("why this title"), as stored with a retitle."""
        return [{"slot": c.slot, "words": c.words, "fact": c.fact} for c in self.claims]


# -- the sets a title counts -----------------------------------------------------------------------


def _device_values(f: Facts) -> list[str]:
    return _unique(d.value for d in f.devices)


def _backers(f: Facts, flag: str) -> frozenset[str]:
    """The devices whose investigations carry ``flag`` (every device when the facts hold no
    per-device set and the case carries the flag)."""
    devices = frozenset(_device_values(f))
    if flag in f.doing:
        return f.doing[flag] & devices
    return devices if flag in f.flags else frozenset()


def _reaching(f: Facts, values: Iterable[str]) -> frozenset[str]:
    """The devices whose investigations name one of ``values``, or a name under one of them (a
    domain is reached through its hosts); every device when the facts hold no per-device set (a
    planner's single investigation names them all)."""
    devices = frozenset(_device_values(f))
    if not f.reaches:
        return devices
    return _under(f.reaches, values) & devices


SCAN_NAMES = 64  # up to this many names a table is scanned, past it indexed


def _suffixes(table: Mapping[str, frozenset[str]]) -> dict[str, set[str]]:
    """Each domain the table's names are under -> who the names under it give."""
    index: dict[str, set[str]] = {}
    for named, who in table.items():
        low = named.lower().rstrip(".")
        at = low.find(".")
        while at >= 0:
            index.setdefault(low[at + 1 :], set()).update(who)
            at = low.find(".", at + 1)
    return index


def _under(table: Mapping[str, frozenset[str]], values: Iterable[str]) -> frozenset[str]:
    """Who ``table`` (value -> devices) gives one of ``values``, or a name under one of them."""
    out: set[str] = set()
    index: dict[str, set[str]] | None = None
    for value in values:
        out |= table.get(value, frozenset())
        if (name := domain(value)) is None:
            continue
        if len(table) <= SCAN_NAMES:
            for named, who in table.items():
                if named.lower().rstrip(".").endswith("." + name):
                    out |= who
        else:  # many names (a DNS campaign): index them once for this call
            index = _suffixes(table) if index is None else index
            out |= index.get(name, set())
    return frozenset(out)


def _paired(
    f: Facts, table: Mapping[str, frozenset[str]] | None, flag: str, values: Iterable[str]
) -> frozenset[str]:
    """The devices whose investigations that carry ``flag`` themselves name one of ``values`` (or a
    name under one), by ``table`` (destination -> those devices); without a table, the devices
    that carry the flag and reach one of ``values``."""
    values = list(values)
    if table is None:
        return _backers(f, flag) & _reaching(f, values)
    devices = frozenset(_device_values(f))
    return _under(table, values) & devices & _backers(f, flag)


def _timed(f: Facts, values: Iterable[str]) -> frozenset[str]:
    """The devices whose beacon-timed investigations themselves name one of ``values`` (or a name
    under one): "beaconing to X" needs the timing and X on the same investigation."""
    return _paired(f, f.beacon_reaches, BEACON, values)


def _dns_timed(f: Facts, parent: str) -> frozenset[str]:
    """The devices whose investigations with the beacon timing or the campaign flag name a name
    under ``parent``: "DNS beaconing to P" needs the flag and P's names on the same
    investigation."""
    return _timed(f, (parent,)) | _paired(f, f.campaign_reaches, CAMPAIGN, (parent,))


def _flagged(f: Facts) -> list[str]:
    devices = set(_device_values(f))
    return [v for v in _unique(f.servers) if v not in devices]


def _lookalikes(f: Facts) -> tuple[list[tuple[str, int]], list[str], list[str]]:
    """The parents with at least two look-alike names under them (the commonest first), the
    names, and the raw values they were given as."""
    sites = set(map(domain, f.sites))
    names = _unique(d for d in map(domain, f.domains) if d and d not in sites)
    parents = Counter(p for p in map(registered_parent, names) if p)
    groups = sorted(((p, c) for p, c in parents.items() if c >= 2), key=lambda pc: (-pc[1], pc[0]))
    held = {p for p, _ in groups}
    raw = [v for v in _unique(f.domains) if (d := domain(v)) and d not in sites
           and registered_parent(d) in held]  # fmt: skip
    return groups, [n for n in names if registered_parent(n) in held], raw


@dataclass(frozen=True)
class _Act:
    """What a device shape counts: the activity, the devices that did it, and its objects (raw
    values: flagged servers, destinations or look-alike parents)."""

    activity: str  # a key of ACTIVITIES
    backers: frozenset[str]
    objects: tuple[str, ...]
    flagged: bool = False  # the objects are flagged servers


def _device_activity(f: Facts) -> _Act | None:
    """The device activity the facts back, the strongest first (the catalogue's order). Look-alike
    names lead unless a flagged server is beacon-timed: "DNS beaconing" counts the devices whose
    own timed or campaign investigations name the names, and names only those names' parents;
    without such a device it is "DNS look-ups"."""
    if not f.devices:
        return None
    flagged = _flagged(f)
    timed = _timed(f, flagged) if flagged else frozenset()
    groups, names, raw = _lookalikes(f)
    addresses = [v for v in _unique(f.servers) if address(v)]
    if groups and len(names) >= len(addresses) and not timed:
        backers = _reaching(f, raw)
        if backers:
            parents = [p for p, _ in groups]
            by_parent = {p: _dns_timed(f, p) for p in parents}
            dns = frozenset().union(*by_parent.values())
            if dns:
                return _Act("dns_beacon", dns, tuple(p for p in parents if by_parent[p]))
            return _Act("dns_lookups", backers, tuple(parents))
    beacon = _backers(f, BEACON)
    if BEACON_PORTS in f.doing:  # the port flag on the beacon's own investigation
        ports = f.doing[BEACON_PORTS] & frozenset(_device_values(f))
    else:
        ports = beacon & _backers(f, PORTS)
    if flagged:
        reach = _reaching(f, flagged)
        if timed & ports:
            return _Act("beacon_port", timed & ports, tuple(flagged), True)
        if timed:
            return _Act("beacon", timed, tuple(flagged), True)
        if reach:
            return _Act("contact", reach, tuple(flagged), True)
    others = [v for v in _unique(f.destinations) if v not in set(flagged)]
    if beacon:
        named = tuple(v for v in others if _timed(f, (v,))) if f.reaches else ()
        timed = _timed(f, named)
        if timed & ports:
            return _Act("beacon_port", timed & ports, named)
        if timed:
            return _Act("beacon", timed, named)
        if beacon & ports:
            return _Act("beacon_port", beacon & ports, ())
        return _Act("beacon", beacon, ())
    touched = frozenset().union(*(_backers(f, flag) for flag in (LISTED, OUTSIDE, OPERATOR)))
    if touched:
        return _Act("contact", touched, ())
    return None


ACTIVITIES: Mapping[str, str] = MappingProxyType({
    "dns_beacon": "DNS beaconing",
    "dns_lookups": "DNS look-ups",
    "beacon": "beaconing",
    "beacon_port": "beaconing on a remote-admin port",
    "contact": "contact",
    "probing": "probing",
    "rule": "alerts",
})  # fmt: skip


def _scan_words(kinds: Sequence[str]) -> str:
    return " and ".join(kinds) + " scan" if kinds else "web scan"


def _web_kinds(f: Facts) -> tuple[str, ...]:
    paths = _unique(f.paths)
    if paths:
        return scan_kinds(paths)
    return (f.probed,) if f.probed in SCAN_KINDS else ()


def _web_ok(f: Facts) -> bool:
    if f.devices or not _unique(f.outsiders):
        return False
    return bool(
        _unique(f.paths) or _unique(f.sites) or SUCCESS in f.flags or f.answered or f.outcomes
        or f.checks or f.probed in SCAN_KINDS
    )  # fmt: skip


def _probe_ok(f: Facts) -> bool:
    if f.devices or f.own_servers < 1:
        return False
    return bool(set(_unique(f.outsiders)) & set(f.listed))


# -- the outcome ladder (web) ----------------------------------------------------------------------

Rung = Literal["served", "catch_all", "unverified", "ordinary", "empty", "skipped", "none"]
RUNGS: tuple[Rung, ...] = (
    "served", "catch_all", "unverified", "ordinary", "empty", "skipped", "none",
)  # fmt: skip


def _ranked(kinds: Iterable[str]) -> list[str]:
    return sorted({k for k in kinds if k != ORDINARY}, key=FILE_KEYS.index)


def outcome_of(f: Facts) -> tuple[Rung, str]:
    """The strongest outcome ARGUS's stored checks back, with the kind of file it is about ("":
    none): only ARGUS's own path check (``web.path_outcomes``) says served; a follow-up's 2xx
    answer is "got HTTP 200, not verified"; a rule's name changes nothing."""
    served = [p for _, p, o in f.outcomes if o == PATH_SERVED]
    if served:
        kinds = _ranked(map(file_kind, served))
        return "served", (kinds[0] if kinds else ORDINARY)
    if f.outcomes and all(o == PATH_CATCH_ALL for _, _, o in f.outcomes):
        return "catch_all", ""
    answered = _unique(p for _, p in f.answered)
    if answered:
        kinds = _ranked(map(file_kind, answered))
        return ("unverified", kinds[0]) if kinds else ("ordinary", "")
    if SUCCESS in f.flags:
        return "unverified", ""
    if "empty" in f.checks:
        return "empty", ""
    if "skipped_budget" in f.checks:
        return "skipped", ""
    return "none", ""


def outcome_sites(f: Facts) -> frozenset[str] | None:
    """The sites (as :func:`domain` spells them) whose stored checks back :func:`outcome_of`'s
    outcome: empty when no site's check does (the success flag alone); None when the outcome says
    nothing of a site (no HTTP 200 after the alerts, a skipped check, no check yet)."""
    rung, kind = outcome_of(f)
    rows: list[tuple[str, str]]
    if rung == "served":
        rows = [(s, p) for s, p, o in f.outcomes if o == PATH_SERVED and file_kind(p) == kind]
    elif rung == "catch_all":
        rows = [(s, p) for s, p, _ in f.outcomes]
    elif rung == "unverified":
        rows = [(s, p) for s, p in f.answered if file_kind(p) == kind]
    elif rung == "ordinary":
        rows = list(f.answered)
    else:
        return None
    return frozenset(d for s, _ in rows if (d := domain(s)) is not None)


def _files(kind: str, n: int) -> str:
    one = next((word for key, word, _ in FILES if key == kind), "page")
    return f"a {one}" if n == 1 else f"{one}s"


UNVERIFIED = "got HTTP 200, not verified"


def _outcome_words(
    f: Facts, rung: Rung, kind: str, scan: Sequence[str], *, short: bool = False
) -> str:
    """The outcome's fixed words; ``short`` leaves out the kind of file that got HTTP 200."""
    if rung == "unverified" and short:
        return UNVERIFIED
    if rung == "served":
        served = {p for _, p, o in f.outcomes if o == PATH_SERVED and file_kind(p) == kind}
        return f"{_files(kind, len(served))} served" if kind != ORDINARY else "pages served"
    if rung == "catch_all":
        return "the site answers every path alike"
    if rung == "unverified":
        expected = EXPECTS.get(scan[0]) if len(scan) == 1 else None
        if not kind or kind == expected:
            return UNVERIFIED
        n = len({p for _, p in f.answered if file_kind(p) == kind})
        return f"{_files(kind, n)} {UNVERIFIED}"
    return {
        "ordinary": "only ordinary pages got HTTP 200",
        "empty": "no HTTP 200 after the alerts",
        "skipped": "web check skipped (budget)",
        "none": "no web check yet",
    }[rung]


# -- wordings ------------------------------------------------------------------------------------


def _cert(f: Facts, *, colon: bool = False) -> list[Part]:
    word = certainty(f)
    said = word + (":" if word in COLON or colon else "")
    return [Claim("certainty", said, f"certainty:{word}"), " "]


def family_for(f: Facts, act: _Act | None) -> str | None:
    """The family a device title may name: one the case's labels name, or (``labelled`` given)
    one the labels of the things the activity names, then of the devices that did it, name."""
    if f.labelled is None:
        return family_of(f.labels)
    if act is None:
        return None
    table = f.labelled
    keys = (*act.objects, *sorted(act.backers))
    return family_of(label for key in keys for label in table.get(key, ()))


def _family(f: Facts, act: _Act | None) -> list[Part]:
    found = family_for(f, act)
    return [Claim("family", found, f"family:{found}"), " "] if found else []


def _place_parts(f: Facts, backers: Iterable[str], *, one: bool) -> list[Part]:
    """Where the counted devices are: the building or department they all share ("(Dept North)" for
    one, "in Hostel 12" for several), else the zone that all or at least 60 % of them share ("in
    hostels", "(19 in hostels)"). Never the network equipment (``site.type``). A device the map
    lists in two places has none."""
    chosen = set(backers)
    places: dict[str, set[str | None]] = {}
    zones: dict[str, set[str | None]] = {}
    for d in dict.fromkeys(f.devices):
        if d.value in chosen:
            places.setdefault(d.value, set()).add(place(d.place))
            zones.setdefault(d.value, set()).add(kind_word(d.zone))
    shared = {next(iter(p)) if len(p) == 1 else None for p in places.values()}
    if len(shared) == 1 and (name := next(iter(shared))) is not None:
        if one:
            return [" (", Claim("place", name, f"place:{name}"), ")"]
        return [" in ", Claim("place", name, f"place:{name}")]
    if one or not zones:
        return []
    each = [next(iter(z)) if len(z) == 1 else None for z in zones.values()]
    tally = Counter(z for z in each if z)
    if not tally:
        return []
    zone, n = sorted(tally.items(), key=lambda kv: (-kv[1], kv[0]))[0]
    if n == len(each):
        return [" in ", Claim("place", f"{zone}s", f"zone:{zone}:{n}")]
    if n >= 0.6 * len(each):
        return [" (", Claim("place", f"{n} in {zone}s", f"zone:{zone}:{n}"), ")"]
    return []


def _device_words(value: str, f: Facts) -> str | None:
    if any(d.kind == "host" for d in f.devices if d.value == value):
        return host(value)
    return address(value)


def _actor_words(f: Facts, activity: str, backers: frozenset[str]) -> list[tuple[str, str]]:
    """(fact, words) for who did it: the one device by name, or "N of M internal devices" (N: the
    devices that carry the activity's fact; M: the case's devices, with those past a bounded read),
    the most specific first."""
    n, m = len(backers), len(_device_values(f)) + max(0, f.more_devices)
    out: list[tuple[str, str]] = []
    if n == 1:
        value = next(iter(backers))
        if (words := _device_words(value, f)) is not None:
            out.append((f"device:{value}", words))
    if n == 1 and m == 1:
        out.append((f"actors:{activity}:1:1", site.a_own("device")))
    else:
        noun = site.own("device" if n == 1 else "devices")
        words = f"{n} of {m} {site.own('devices')}" if n < m else f"{n} {noun}"
        out.append((f"actors:{activity}:{n}:{m}", words))
    return out


def _actors(f: Facts, activity: str, backers: frozenset[str]) -> list[Part]:
    fact, words = _actor_words(f, activity, backers)[0]
    return [Claim("actors", words, fact)]


def _source(f: Facts, value: str) -> list[Part]:
    """Who flagged a server: "(VirusTotal: 4 engines)", "(on a threat list)", or nothing."""
    engines = f.vt.get(value, 0)
    if engines > 0:
        words = f"VirusTotal: {_plural(engines, 'engine')}"
        return [" (", Claim("object", words, f"vt:{value}:{engines}"), ")"]
    if value in set(f.listed):
        return [" (", Claim("object", "on a threat list", f"listed:{value}"), ")"]
    return []


def _objects(f: Facts, act: _Act, *, named: bool, source: bool, link: bool) -> list[Part]:
    """The servers: the first by name with who flagged it and the case it is the server of, then
    "+N flagged servers"; or a count."""
    values = act.objects
    kind, noun = ("server", "flagged server") if act.flagged else ("dest", "outside server")
    first = next((v for v in values if name_of(v)), None) if named else None
    if first is None:
        words = f"a {noun}" if len(values) == 1 else _plural(len(values), noun)
        return [Claim("object", words, f"count:{kind}s:{len(values)}")]
    name = name_of(first)
    assert name is not None
    out: list[Part] = [Claim("object", name, f"{kind}:{first}")]
    if source and act.flagged:
        out += _source(f, first)
    if link and (case := f.server_cases.get(first, 0)) > 0:
        out += [", ", Claim("object", f"the server of case {case}", f"case:{first}:{case}")]
    if (more := len(values) - 1) > 0:
        out += [" +", Claim("object", _plural(more, noun), f"more:{kind}s:{more}")]
    return out


def _dns_titles(f: Facts, act: _Act, family: list[Part]) -> list[list[Part]]:
    _, names, _ = _lookalikes(f)
    parents = list(act.objects)
    head: list[Part] = [Claim("activity", ACTIVITIES[act.activity], f"activity:{act.activity}")]
    more: list[Part] = []
    if len(parents) > 1:
        more = [" +", Claim("object", _plural(len(parents) - 1, "domain"),
                            f"more:parents:{len(parents) - 1}")]  # fmt: skip
    first = Claim("object", parents[0], f"parent:{parents[0]}")
    objects: list[list[Part]]
    if act.activity == "dns_beacon":
        both: list[Part] = [" to ", first]
        if len(parents) == 2:
            both += [" and ", Claim("object", parents[1], f"parent:{parents[1]}")]
        else:
            both += more
        objects = [both, [" to ", first, *more]]
    else:
        count = Claim("object", f"{len(names)} look-alike names", f"count:names:{len(names)}")
        objects = [[" of ", count, " under ", first, *more], [" of ", count]]
    who = _actors(f, act.activity, act.backers)
    where = _place_parts(f, act.backers, one=len(act.backers) == 1)
    out: list[list[Part]] = []
    for fam in (family, []):
        for obj in objects:
            out.append([*_cert(f), *fam, *head, *obj, " from ", *who, *where])
            out.append([*_cert(f), *fam, *head, *obj, " from ", *who])
    return out


def _device_titles(f: Facts) -> list[list[Part]] | None:
    act = _device_activity(f)
    if act is None:
        return None
    family = _family(f, act)
    if act.activity in ("dns_beacon", "dns_lookups"):
        return _dns_titles(f, act, family)
    head: list[Part] = [Claim("activity", ACTIVITIES[act.activity], f"activity:{act.activity}")]
    one = len(act.backers) == 1
    who = _actors(f, act.activity, act.backers)
    contact = act.activity == "contact"
    out: list[list[Part]] = []
    ladder = ((True, True, True, True), (False, True, True, True), (False, False, True, True),
              (False, False, False, True), (False, False, False, False))  # fmt: skip
    for fam in (family, []):
        for where, source, link, named in ladder:
            place_ = _place_parts(f, act.backers, one=one) if where else []
            if not act.objects:
                target: list[Part] = []
                if contact:
                    target = [" with ", Claim("object", "a flagged server", "flag:contact")]
                out.append([*_cert(f), *fam, *head, *target, " from ", *who, *place_])
                continue
            obj = _objects(f, act, named=named, source=source, link=link and one)
            if contact:
                out.append([*_cert(f), *fam, *head, " with ", *obj, " from ", *who, *place_])
            elif one:  # one device: the device leads, then where it went
                out.append([*_cert(f), *fam, *head, " from ", *who, *place_, " to ", *obj])
            else:
                out.append([*_cert(f), *fam, *head, " to ", *obj, " from ", *who, *place_])
    return out


def _outsiders(f: Facts, *, named: bool, listed: bool) -> list[Part]:
    seen = _unique(f.outsiders)
    hits = [o for o in seen if o in set(f.listed)]
    if len(seen) == 1 and named and (one := address(seen[0])) is not None:
        out: list[Part] = [Claim("actors", one, f"outsider:{seen[0]}")]
        if listed and hits:
            out += [" (", Claim("actors", "on a threat list", f"listed:{seen[0]}"), ")"]
        return out
    words = "an outside IP" if len(seen) == 1 else f"{len(seen)} outside IPs"
    out = [Claim("actors", words, f"outsiders:{len(seen)}")]
    if listed and hits:
        words = f"{len(hits)} on a threat list"
        out += [" (", Claim("actors", words, f"listed_actors:{len(hits)}"), ")"]
    return out


SiteWords = Literal["named", "first", "count", "none"]


def lead_site(f: Facts) -> str | None:
    """The site a title names: the first in the facts' order (the commonest, or the one the title
    names now) whose own checks back the outcome, else the first; None when no site has a name's
    shape."""
    seen = [v for v in _unique(f.sites) if domain(v)]
    backing = outcome_sites(f) or frozenset()
    return next((v for v in seen if domain(v) in backing), seen[0] if seen else None)


def _site_tied(f: Facts, value: str) -> bool:
    """Whether the outcome may follow ``value`` named alone (no "+N sites"): the case has one site,
    the outcome says nothing of a site, or the site's own checks back it."""
    backing = outcome_sites(f)
    return backing is None or len(_unique(f.sites)) <= 1 or domain(value) in backing


def _site_parts(f: Facts, how: SiteWords) -> list[Part]:
    """The attacked sites: the lead site (:func:`lead_site`) by name and "+N sites" (``named``),
    the lead alone (``first``), a count (``count``), or nothing."""
    seen = _unique(f.sites)
    if not seen or how == "none":
        return []
    first = lead_site(f) if how != "count" else None
    if first is None:
        words = site.a_own("site") if len(seen) == 1 else f"{len(seen)} {site.own('sites')}"
        return [" of ", Claim("object", words, f"count:sites:{len(seen)}")]
    name = domain(first)
    assert name is not None
    out: list[Part] = [" of ", Claim("object", name, f"site:{first}")]
    if len(seen) > 1 and how == "named":
        more = len(seen) - 1
        out += [" +", Claim("object", _plural(more, "site"), f"more:sites:{more}")]
    return out


# the web wordings, the most specific first: (sites, the outcome's full words, the threat-list
# count of the attackers); the site is named as long as it fits
WEB_LADDER: tuple[tuple[SiteWords, bool, bool], ...] = (
    ("named", True, True), ("named", True, False), ("first", True, False), ("named", False, False),
    ("first", False, False), ("count", True, False), ("count", False, False), ("none", True, False),
    ("none", False, False),
)  # fmt: skip


def _web_titles(f: Facts) -> list[list[Part]] | None:
    if not _web_ok(f):
        return None
    kinds = _web_kinds(f)
    rung, kind = outcome_of(f)
    fact = f"outcome:{rung}:{kind}"
    out: list[list[Part]] = []
    lead = lead_site(f)
    alone = lead is None or _site_tied(f, lead)  # the outcome is the lead site's own
    named = [step for step in WEB_LADDER if step[0] == "named" or (step[0] == "first" and alone)]
    rest = [step for step in WEB_LADDER if step[0] not in ("named", "first")]
    for steps in (named, rest):  # the site stays named, as "web scan" if it must, before a count
        for scan in dict.fromkeys((kinds, ())):
            words_ = _scan_words(scan)
            act = Claim("activity", words_, f"activity:scan:{'+'.join(scan) or WEB_SCAN}")
            for how, full, listed in steps:
                said = _outcome_words(f, rung, kind, kinds, short=not full)
                who = _outsiders(f, named=how != "count", listed=listed)
                tail: list[Part] = [" — ", Claim("outcome", said, fact)]
                out.append([*_cert(f), act, *_site_parts(f, how), " by ", *who, *tail])
    return out


def _probe_titles(f: Facts) -> list[list[Part]] | None:
    if not _probe_ok(f):
        return None
    n = f.own_servers
    servers = site.a_own("server") if n == 1 else f"{n} {site.own('servers')}"
    act = Claim("activity", ACTIVITIES["probing"], "activity:probing")
    target = Claim("object", servers, f"count:own_servers:{n}")
    return [
        [*_cert(f), act, " of ", target, " by ", *_outsiders(f, named=named, listed=True)]
        for named in (True, False)
    ]


def _anyone(f: Facts) -> list[Part]:
    devices = frozenset(_device_values(f))
    if devices:
        return _actors(f, "rule", devices)
    if _unique(f.outsiders):
        return _outsiders(f, named=True, listed=False)
    if f.accounts > 0:
        words = "a user account" if f.accounts == 1 else f"{f.accounts} user accounts"
        return [Claim("actors", words, f"accounts:{f.accounts}")]
    return []


def _fallback(f: Facts) -> list[list[Part]]:
    """Alerts of a rule, quoted and attributed: the rule's words are its claim, not ARGUS's."""
    rule = next((r for r in (rule_name(name) for name, _ in f.rules) if r), None)
    who = _anyone(f)
    head = [*_cert(f, colon=True), Claim("activity", ACTIVITIES["rule"], "activity:rule")]
    out: list[list[Part]] = []
    if rule is not None:
        quoted = Claim("rule", f"rule '{rule}'", f"rule:{rule}")
        if who:
            out.append([*head, " of ", quoted, " for ", *who])
        out.append([*head, " of ", quoted])
    if (n := len({name for name, _ in f.rules})) > 0 and who:
        out.append([*head, " of ", Claim("rule", _plural(n, "rule"), f"rules:{n}"), " for ", *who])
    if who:
        out.append([*head, " for ", *who])
    return out


# -- the checker -----------------------------------------------------------------------------------


class _Held(dict[str, set[str]]):
    def put(self, fact: str, *words: str) -> None:
        self.setdefault(fact, set()).update(words)

    def take(self, parts: Iterable[Part]) -> None:
        for part in parts:
            if isinstance(part, Claim):
                self.put(part.fact, part.words)


def held(f: Facts) -> dict[str, set[str]]:
    """Every fact the facts back, with the words each may be said in: the checker's table, made
    from the facts by the same rules that choose the words (the activity catalogue, the counts,
    the outcome ladder), never from a title."""
    out = _Held()
    word = certainty(f)
    out.put(f"certainty:{word}", word, word + ":")
    devices = frozenset(_device_values(f))
    act = _device_activity(f)
    if (found := family_for(f, act)) is not None:
        out.put(f"family:{found}", found)
    if act is not None:
        out.put(f"activity:{act.activity}", ACTIVITIES[act.activity])
        for fact, words in _actor_words(f, act.activity, act.backers):
            out.put(fact, words)
        kind, noun = ("server", "flagged server") if act.flagged else ("dest", "outside server")
        if act.activity in ("dns_beacon", "dns_lookups"):
            _, names, _ = _lookalikes(f)
            for p in act.objects:
                out.put(f"parent:{p}", p)
            more = len(act.objects) - 1
            out.put(f"more:parents:{more}", _plural(more, "domain"))
            out.put(f"count:names:{len(names)}", f"{len(names)} look-alike names")
        else:
            for value in act.objects:
                if (name := name_of(value)) is not None:
                    out.put(f"{kind}:{value}", name)
                if (case := f.server_cases.get(value, 0)) > 0 and len(act.backers) == 1:
                    out.put(f"case:{value}:{case}", f"the server of case {case}")
            n = len(act.objects)
            out.put(f"count:{kind}s:{n}", f"a {noun}" if n == 1 else _plural(n, noun))
            out.put(f"more:{kind}s:{n - 1}", _plural(n - 1, noun))
            if act.flagged and act.objects:
                out.take(_source(f, next((v for v in act.objects if name_of(v)), act.objects[0])))
        for one in (True, False):
            out.take(_place_parts(f, act.backers, one=one))
        if act.activity == "contact" and not act.objects:
            out.put("flag:contact", "a flagged server")
    if _web_ok(f):
        kinds = _web_kinds(f)
        for scan in (kinds, ()):
            out.put(f"activity:scan:{'+'.join(scan) or WEB_SCAN}", _scan_words(scan))
        rung, kind = outcome_of(f)
        for short in (False, True):
            out.put(f"outcome:{rung}:{kind}", _outcome_words(f, rung, kind, kinds, short=short))
        for how in ("named", "count"):
            out.take(_site_parts(f, how))
    if _probe_ok(f):
        out.put("activity:probing", ACTIVITIES["probing"])
        n = f.own_servers
        servers = site.a_own("server") if n == 1 else f"{n} {site.own('servers')}"
        out.put(f"count:own_servers:{n}", servers)
    for named in (True, False):
        for listed in (True, False):
            out.take(_outsiders(f, named=named, listed=listed))
    if devices:
        for fact, words in _actor_words(f, "rule", devices):
            out.put(fact, words)
    out.take(_anyone(f))
    out.put("activity:rule", ACTIVITIES["rule"])
    for name, _ in f.rules:
        if (rule := rule_name(name)) is not None:
            out.put(f"rule:{rule}", f"rule '{rule}'")
    if (n := len({name for name, _ in f.rules})) > 0:
        out.put(f"rules:{n}", _plural(n, "rule"))
    if f.follows > 0:
        out.put(f"follows:{f.follows}", f"follows case {f.follows}")
    return dict(out)


def check(
    made: Titled,
    facts: Facts,
    *,
    limit: int = MAX_TITLE,
    table: Mapping[str, set[str]] | None = None,
) -> list[str]:
    """Why ``made`` may not stand for ``facts`` (empty: it may). It refuses joining words outside
    :data:`JOINS`; a claim whose fact the facts do not back, or whose words are not that fact's
    words (a count that is not its set's size, "served" with no path check, a certainty word the
    verdicts do not give, a family not in :data:`FAMILIES`); a certainty word that does not lead;
    quoted words outside a rule claim; more than ``limit`` characters; an activity that ends after
    character :data:`FRONT`; an outcome after a site named alone that another site's checks back
    (it keeps "+N sites"). :data:`EMPTY` says nothing and passes."""
    parts = made.parts
    if parts[:1] == (EMPTY,):
        return _claims_backed(Titled(parts[1:]), facts, table)
    problems = _claims_backed(made, facts, table)
    claims = made.claims
    if not claims or claims[0].slot != "certainty":
        problems.append("the certainty word does not lead the title")
    if sum(1 for c in claims if c.slot == "certainty") > 1:
        problems.append("a title has one certainty word")
    text = made.text
    if len(text) > limit:
        problems.append(f"the title has {len(text)} characters, more than {limit}")
    activity = next((c for c in claims if c.slot == "activity"), None)
    if activity is None:
        problems.append("the title names no activity")
    elif (end := _offset(made, activity) + len(activity.words)) > FRONT:
        problems.append(f"the activity ends at character {end}, after {FRONT}")
    return problems + _untied(claims, facts)


def _untied(claims: Sequence[Claim], facts: Facts) -> list[str]:
    """An outcome after a site named alone (no "+N sites") must be that site's own."""
    if not any(c.slot == "outcome" for c in claims):
        return []
    if any(c.fact.startswith("more:sites:") for c in claims):
        return []
    return [
        f"the outcome is not {c.words}'s own: another site's checks back it"
        for c in claims
        if c.fact.startswith("site:") and not _site_tied(facts, c.fact.removeprefix("site:"))
    ]


def _claims_backed(made: Titled, facts: Facts, table: Mapping[str, set[str]] | None) -> list[str]:
    problems: list[str] = []
    for part in made.parts:
        if isinstance(part, str) and part not in JOINS:
            problems.append(f"the joining words {part!r} are not in the list")
    known = held(facts) if table is None else table
    for claim in made.claims:
        words = known.get(claim.fact)
        if words is None:
            problems.append(f"{claim.slot} {claim.words!r} rests on {claim.fact}: no such fact")
        elif claim.words not in words:
            problems.append(f"{claim.slot} {claim.words!r} is not what {claim.fact} says")
        if claim.slot == "family" and claim.words not in FAMILIES:
            problems.append(f"{claim.words!r} is not a family of the table")
        if claim.slot == "rule" and not claim.fact.startswith(("rule:", "rules:")):
            problems.append("a rule claim names the rule it quotes")
        if claim.slot != "rule" and "'" in claim.words:
            problems.append(f"{claim.slot} {claim.words!r} quotes words outside a rule claim")
    return problems


def _offset(made: Titled, claim: Claim) -> int:
    at = 0
    for part in made.parts:
        if part is claim:
            return at
        at += len(part.words if isinstance(part, Claim) else part)
    return at


# -- the title -------------------------------------------------------------------------------------


def _follows(f: Facts) -> list[Part]:
    if f.follows <= 0:
        return []
    return [" — ", Claim("follows", f"follows case {f.follows}", f"follows:{f.follows}")]


SHAPES: tuple[Callable[[Facts], list[list[Part]] | None], ...] = (
    _device_titles, _web_titles, _probe_titles,
)  # fmt: skip


def titled(facts: Facts) -> Titled:
    """The case's title (pure) as claims: the first shape that fits the facts, in its most specific
    wording that :func:`check` accepts; a case that follows a closed one ends with
    " — follows case N"; facts that say nothing give :data:`EMPTY`."""
    table = held(facts)
    tail = _follows(facts)
    for shape in (*SHAPES, _fallback):
        for parts in shape(facts) or ():
            made = Titled((*parts, *tail))
            if not check(made, facts, table=table):
                return made
    return Titled((EMPTY, *tail))


def title(facts: Facts) -> str:
    """The text of :func:`titled`."""
    return titled(facts).text


# -- what changed ----------------------------------------------------------------------------------

Change = Literal["same", "certainty", "counts", "words"]
GROWTH = 1.5  # a count-only change is material when a count grows by half, or shrinks
COALESCE = timedelta(hours=6)  # else it waits this long after the title last changed


@lru_cache(maxsize=8)
def _count_pattern(*own: str) -> re.Pattern[str]:
    nouns = sorted(
        {re.escape(w) for w in own}
        | {r"(?:outside IP|outside server|flagged server|engine|site|domain|user account|rule)s?",
           "on a threat list", "look-alike names"},
        key=len, reverse=True,
    )  # fmt: skip
    return re.compile(
        r"(?<![^ +(])(\d+)(?: of (\d+))?(?= (?:" + "|".join(nouns) + r")(?![\w-]))"
        r"|(?<=\()(\d+)(?= in [a-z][a-z0-9 -]{0,15}s\))"
    )


def counts_in(text: str) -> tuple[str, tuple[int, ...]]:
    """``text`` with each count of a title blanked ("#"), and the counts in order. A count is a
    number before one of the title's count nouns ("12 of 22 internal devices", "+1 site",
    "VirusTotal: 4 engines", "6 outside IPs", "(19 in hostels)"); a number in an address, a name,
    a place ("Hostel 12"), a rule's quoted name, "case N" or "HTTP 200" is a word."""
    own = (site.own("device"), site.own("devices"), site.own("sites"), site.own("servers"))
    quoted = [m.span() for m in _QUOTED.finditer(text)]
    shape: list[str] = []
    found: list[int] = []
    at = 0
    for m in _count_pattern(*own).finditer(text):
        if any(a <= m.start() < b for a, b in quoted):
            continue
        for group in (1, 2, 3):
            if m.group(group) is not None:
                start, end = m.span(group)
                shape.append(text[at:start] + "#")
                found.append(int(m.group(group)))
                at = end
    shape.append(text[at:])
    return "".join(shape), tuple(found)


def change_of(old: str, new: str) -> Change:
    """What differs between two of ARGUS's titles: nothing, only the certainty word, only counts
    (:func:`counts_in`), or words (an activity, an object, an address, a site, a place, a case, an
    outcome, a family)."""
    if old == new:
        return "same"
    was_word, was = split_certainty(old)
    now_word, now = split_certainty(new)
    if was == now:
        return "certainty"
    if was_word == now_word and counts_in(was)[0] == counts_in(now)[0]:
        return "counts"
    return "words"


def counts_moved(old: str, new: str, growth: float = GROWTH) -> bool:
    """Whether a count-only change is material: a count shrank (the old count would now be
    false) or grew to at least ``growth`` times."""
    pairs = zip(counts_in(old)[1], counts_in(new)[1], strict=False)
    return any(b < a or (a > 0 and b >= a * growth) for a, b in pairs)


# -- the Inbox row ---------------------------------------------------------------------------------

ROW_FLAGS: tuple[tuple[str, str], ...] = (
    (BEACON, "beacon-timed"),
    (PORTS, "remote-admin port"),
    (SUCCESS, "got HTTP 200 after"),
    (LISTED, "on a threat list"),
    (OUTSIDE, "flagged by outside intel"),
    (OPERATOR, "operator of a flagged server"),
    (CAMPAIGN, "rare domain, many devices"),
)
_ACTOR_FIELDS = ("source.", "client.", "host.")
_ACCOUNT_FIELDS = ("user.", "related.user", "email.")
_OBJECT_FIELDS = ("destination.", "server.", "url.", "dns.question.")
RowSide = Literal["actor", "object", "account"]


def _side_of(name: str) -> RowSide | None:
    """Which side of a key a field is on: an account (``user.*``, and ``*.user.*`` such as
    ``source.user.name``: checked first, so an account is never an actor's address), who acted,
    or what they acted on."""
    if name.startswith(_ACCOUNT_FIELDS) or ".user." in name:
        return "account"
    if name.startswith(_ACTOR_FIELDS):
        return "actor"
    if name.startswith(_OBJECT_FIELDS):
        return "object"
    return None


def _row_values(value: object) -> list[str]:
    if isinstance(value, list | tuple):
        return [str(v) for v in value if v is not None and not isinstance(v, dict | list)]
    if value is None or isinstance(value, dict):
        return []
    return [str(value)]


def _row_side(
    pairs: Sequence[tuple[str, object]], side: RowSide, ours: Callable[[str], bool]
) -> str | None:
    """One side of a key in plain words: a value, or a count ("8 internal devices", "3 outside IPs",
    "1 account"); an account is counted, never named."""
    values = [(n, v) for n, value in pairs if _side_of(n) == side for v in _row_values(value)]
    if not values:
        return None
    if side == "account":
        return _plural(len(_unique(v for _, v in values)), "account")
    ips = _unique(a for _, v in values if (a := address(v)))
    names = _unique(d for _, v in values if not address(v) and (d := domain(v) or host(v)))
    if len(ips) == 1 and not names:
        return ips[0]
    if len(names) == 1 and not ips:
        return names[0]
    if ips and not names:
        inside = sum(1 for v in ips if ours(v))
        if inside == len(ips):
            return f"{len(ips)} {site.own('devices')}"
        return (
            f"{len(ips)} outside IPs" if inside == 0 else _plural(len(ips), "address", "addresses")
        )
    total = len(ips) + len(names)
    return _plural(total, "value") if total else None


_PRIVATE = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)


def own_address(value: str) -> bool:
    """Whether ``value`` is an address of the site's own networks or a private (RFC 1918) one."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip.version == n.version and ip in n for n in (*site.own_networks(), *_PRIVATE))


def row_title(
    key_fields: Sequence[tuple[str, object]], flags: Iterable[str], alerts: int,
    ours: Callable[[str], bool] = own_address,
) -> tuple[str, str]:  # fmt: skip
    """An Inbox row's two lines from the investigation's own facts (its key, its evidence flags,
    its alert count), never the rule's name: line 1 "<who> → <what> · <activity>" ("→ <what>"
    when the key names no one who acted), at most :data:`FRONT` characters, the details dropped
    first; line 2 the key in plain words ("from 10.0.0.7 to 203.0.113.5", "to 203.0.113.5",
    "for 2 accounts"). A value keeps its side: a destination is never said as "from"."""
    pairs = [(str(k), v) for k, v in key_fields]
    who = _row_side(pairs, "actor", ours)
    what = _row_side(pairs, "object", ours)
    account = _row_side(pairs, "account", ours)
    if who is None and what is not None:
        who, account = account, None  # an account acted on what the key names
    elif what is None and who is not None:
        what, account = account, None  # what an actor acted on: the accounts
    have = set(flags)
    words = [w for flag, w in ROW_FLAGS if flag in have]
    count = _plural(max(alerts, 0), "alert")
    if who and what:
        sides = [f"{who} → {what}", who]
    elif who or what:
        sides = [who or f"→ {what}"]
    else:
        sides = [account] if account else []
    options = [f"{s} · {d}" for s in sides for d in (", ".join(words), *words[:1], count) if d]
    options += [*words[:1], count]
    line1 = next(o for o in options if len(o) <= FRONT)
    plain = [*([f"from {who}"] if who else []), *([f"to {what}"] if what else []),
             *([f"for {account}"] if account else [])]  # fmt: skip
    return line1, " ".join(plain) if plain else "one alert, no key"
