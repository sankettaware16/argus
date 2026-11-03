"""What an outside threat-intel answer is, as ARGUS keeps and says it. An *answer* is the small
parsed JSON object a source's reply is reduced to (never the raw reply); a *fact* is an answer
attached to an item (``{"source", "kind", "value", "status", "answer", "flagged"}``) in its
``outside`` list. :func:`describe` says a fact in plain words, the same sentence everywhere. Text
a source supplies is cleaned on parsing and quoted in sentences. Pure: no I/O, no settings."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

VIRUSTOTAL = "virustotal"
SHODAN = "shodan"
CENSYS = "censys"
SOURCES = (VIRUSTOTAL, SHODAN, CENSYS)
NAMES = {VIRUSTOTAL: "VirusTotal", SHODAN: "Shodan", CENSYS: "Censys"}
KINDS = ("ip", "domain", "url", "hash")
THIS = {"ip": "IP", "domain": "domain", "url": "URL", "hash": "file"}
FOUND = "found"
NOT_FOUND = "not_found"

DEFAULT_WINDOW = timedelta(days=7)  # outside.cache_window's default
DEFAULT_CLEAN_WINDOW = timedelta(days=1)  # outside.clean_cache_window's default
DEFAULT_THRESHOLD = 3  # outside.flag_threshold's default
FLAG = "flagged by outside threat intel"  # the evidence flag (evaluation.gold.flags, assess.raised)

MAX_URL = 2048
DOMAIN_SHAPE = 3  # a VirusTotal domain answer with the family fields says so
# Web popularity: VirusTotal's ``popularity_ranks`` mixes lists that measure how many
# people visit a site (Majestic's backlinks, Tranco, Cloudflare Radar's top buckets) with lists
# that measure how many devices *query* a name (Cisco Umbrella, and Cloudflare Radar below its top
# buckets), which a command-and-control domain scores on too because infected devices ask for it.
# Only the first kind makes a domain "popular". A list name in lowercase -> the worst rank that
# still counts (None: any rank). A rank older than ``RANK_FRESH`` (VirusTotal keeps Alexa's from
# 2020) says nothing about today.
WEB_LISTS: Mapping[str, int | None] = {"majestic": None, "tranco": None, "cloudflare radar": 10_000}
RANK_FRESH = timedelta(days=365)
MAX_RANK_LISTS = 6  # per-list ranks kept in an answer, for display
MAX_LIST_NAME = 30
MAX_NAME_SERVERS = 5  # a domain's name servers kept (sorted: the set is what ties two domains)
MAX_ANSWER_JSON = 4096  # a parsed answer is cut to this many bytes of JSON at most
_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?")
_HASH = re.compile(r"(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})")
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}")
_TAG = re.compile(r"[a-z0-9][a-z0-9 _.+-]{0,29}")
_DAY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_NOISE = re.compile(r"[^\w .,:;/@()+*'#-]")


def canonical(kind: str, value: object) -> str | None:
    """The indicator in the one spelling the cache keys by, or None when it is not a valid
    ``kind``: an IP address as ``ipaddress`` writes it (IPv4-mapped as IPv4, an IPv6 zone such as
    ``%eth0`` dropped), a domain lowercase without a trailing dot (punycode for non-ASCII labels),
    a file hash in lowercase hex of an MD5, SHA-1 or SHA-256 length, a URL with an http or https
    scheme and a host."""
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > MAX_URL:
        return None
    if kind == "ip":
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return None
        if isinstance(address, ipaddress.IPv6Address):
            if address.scope_id is not None:  # %eth0: where the sender is, not who is addressed
                address = ipaddress.IPv6Address(int(address))
            if address.ipv4_mapped is not None:
                return str(address.ipv4_mapped)
        return str(address)
    if kind == "domain":
        return _domain(text)
    if kind == "hash":
        lowered = text.lower()
        return lowered if _HASH.fullmatch(lowered) else None
    if kind == "url":
        return _url(text)
    return None


def _domain(text: str) -> str | None:
    name = text.rstrip(".").lower()
    if not name.isascii():
        try:
            name = ".".join(
                label if label.isascii() else label.encode("idna").decode("ascii")
                for label in name.split(".")
            )
        except UnicodeError:
            return None
    labels = name.split(".")
    if len(name) > 253 or len(labels) < 2:
        return None
    if not all(_LABEL.fullmatch(label) for label in labels):
        return None
    if labels[-1].isdigit():  # a dotted number is an address, not a name
        return None
    return name


def _url(text: str) -> str | None:
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in text):
        return None
    scheme, sep, rest = text.partition("://")
    if sep != "://" or scheme.lower() not in ("http", "https"):
        return None
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    if not authority or "@" in authority:
        return None  # no user or password in a URL we send anywhere
    return scheme.lower() + "://" + rest


def host_of(url: str) -> str:
    """The host of a URL ``canonical`` accepted (a name or an address, lowercase)."""
    authority = re.split(r"[/?#]", url.partition("://")[2], maxsplit=1)[0]
    if authority.startswith("["):
        return authority[1:].partition("]")[0].lower()
    return authority.rsplit(":", 1)[0].lower() if authority.count(":") == 1 else authority.lower()


def clean(value: object, limit: int = 80) -> str | None:
    """Text a source supplied, reduced to plain characters and cut: None when nothing is left."""
    if not isinstance(value, str):
        return None
    text = " ".join(_NOISE.sub(" ", value).split())[:limit].strip()
    return text or None


def names(values: object, limit: int = 5) -> list[str]:
    """Host names a source listed: valid, lowercase, distinct, at most ``limit``."""
    out: list[str] = []
    for value in values if isinstance(values, list) else []:
        name = _domain(value) if isinstance(value, str) else None
        if name is not None and name not in out:
            out.append(name)
    return out[:limit]


def cves(values: object, limit: int = 10) -> list[str]:
    found = {v for v in (values if isinstance(values, list) else []) if _CVE.fullmatch(str(v))}
    return sorted(found)[:limit]


def tags(values: object, limit: int = 5) -> list[str]:
    out: list[str] = []
    for value in values if isinstance(values, list) else []:
        text = value.lower().strip() if isinstance(value, str) else ""
        if _TAG.fullmatch(text) and text not in out:
            out.append(text)
    return out[:limit]


def number(value: object, low: int = 0, high: int = 10**9) -> int | None:
    """A whole number from a source, in range (a bool or a float with a fraction is none)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, int) and low <= value <= high:
        return value
    return None


def web_listed(name: str, rank: int) -> bool:
    """Whether ``rank`` in the popularity list ``name`` is web popularity (:data:`WEB_LISTS`)."""
    key = " ".join(name.lower().split())
    if key not in WEB_LISTS:
        return False
    worst = WEB_LISTS[key]
    return worst is None or rank <= worst


def web_popular(ranks: Mapping[str, int]) -> bool:
    """Whether any of the ranks (list name -> rank) is web popularity: the rule that makes a
    domain "popular". Give it current ranks only (see :func:`popularity`)."""
    return any(web_listed(name, rank) for name, rank in ranks.items())


def best_web_rank(ranks: Mapping[str, int]) -> int | None:
    """The best rank among the web-popularity lists, None when no list counts."""
    found = [rank for name, rank in ranks.items() if web_listed(name, rank)]
    return min(found) if found else None


def popularity(raw: object, now: datetime) -> dict[str, Any]:
    """What VirusTotal's ``popularity_ranks`` says, as the fields of a domain answer:
    ``ranks`` (each list's rank, bounded: the web-popularity lists first, then the best of the
    others), ``ranked`` (a web-popularity list ranks the domain) and ``best_rank`` (the best of
    those). Only a rank with a timestamp inside :data:`RANK_FRESH` of ``now`` counts: VirusTotal
    keeps ranks from lists that stopped years ago. A reply that carries nothing usable is
    unranked (not "unknown": the reply is of the shape this version reads)."""
    current: dict[str, int] = {}
    for name, entry in (raw if isinstance(raw, Mapping) else {}).items():
        if not isinstance(name, str) or not isinstance(entry, Mapping):
            continue
        label = clean(name, MAX_LIST_NAME)
        rank = number(entry.get("rank"), 1)
        seen = number(entry.get("timestamp"), 0, 4_102_444_800)
        if label is None or rank is None or seen is None:
            continue
        if now - datetime.fromtimestamp(seen, UTC) > RANK_FRESH:
            continue
        current[label] = min(rank, current.get(label, rank))
    order = sorted(current.items(), key=lambda kv: (not web_listed(*kv), kv[1], kv[0]))
    return {
        "ranked": web_popular(current),
        "best_rank": best_web_rank(current),
        "ranks": dict(order[:MAX_RANK_LISTS]),
    }


def current_domain(status: str, answer: Mapping[str, Any]) -> bool:
    """Whether a cached VirusTotal answer for a domain is of the shape this version reads
    (:data:`DOMAIN_SHAPE`) or is no record at all: an older one is asked again, and never read."""
    return status != FOUND or answer.get("shape") == DOMAIN_SHAPE


def ports(values: object, limit: int = 40) -> list[int]:
    found = {p for p in (number(v, 0, 65535) for v in (values if isinstance(values, list) else []))
             if p is not None}  # fmt: skip
    return sorted(found)[:limit]


def malicious(answer: Mapping[str, Any]) -> int:
    """VirusTotal engines that call the indicator malicious (0 for any other answer)."""
    return number(answer.get("malicious")) or 0


def flagged(source: str, status: str, answer: Mapping[str, Any], threshold: int) -> bool:
    """Whether an answer is a detection: VirusTotal found the indicator and at least
    ``threshold`` of its engines call it malicious. Shodan and Censys describe a server; they
    never flag one."""
    return source == VIRUSTOTAL and status == FOUND and malicious(answer) >= max(threshold, 1)


def kept_for(
    source: str, status: str, answer: Mapping[str, Any], threshold: int, window: timedelta,
    clean_window: timedelta | None = None,
) -> timedelta:  # fmt: skip
    """How long an answer is kept (and an indicator not asked again): ``window`` for a
    detection and for a server's description (Shodan or Censys found it), the shorter
    ``clean_window`` for everything else (no record, or VirusTotal's engines below the
    threshold), so a fresh server that nobody flags yet is looked at again soon. A domain that
    VirusTotal ranks among the popular sites is kept for ``window`` too, clean or not: a
    popular site changes little in a week, and asking again each day spent the family budget."""
    if clean_window is None:
        return window
    long = status == FOUND and (
        source != VIRUSTOTAL
        or flagged(source, status, answer, threshold)
        or answer.get("ranked") is True
    )
    return window if long else min(clean_window, window)


def fact(
    source: str, kind: str, value: str, status: str, answer: Mapping[str, Any], threshold: int
) -> dict[str, Any]:
    return {
        "source": source, "kind": kind, "value": value, "status": status, "answer": dict(answer),
        "flagged": flagged(source, status, answer, threshold),
    }  # fmt: skip


def any_flagged(facts: object) -> bool:
    return (
        isinstance(facts, Sequence)
        and not isinstance(facts, str)
        and any(isinstance(f, Mapping) and f.get("flagged") is True for f in facts)
    )


def with_flag(found: Sequence[str], facts: object) -> tuple[str, ...]:
    """``found`` (the evidence flags) with :data:`FLAG` added last when ``facts`` hold a
    detection."""
    out = tuple(found)
    return (*out, FLAG) if any_flagged(facts) and FLAG not in out else out


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def describe(entry: Mapping[str, Any], quote: Callable[[str], str] = str) -> str:
    """One plain sentence for a fact. ``quote`` wraps the text a source supplied (names,
    organisations, products); numbers and fixed words are ARGUS's own."""
    source = str(entry.get("source"))
    name = NAMES.get(source, source)
    this = THIS.get(str(entry.get("kind")), "indicator")
    answer = entry.get("answer")
    answer = answer if isinstance(answer, Mapping) else {}
    if entry.get("status") != FOUND:
        return f"{name}: has no record of this {this}"
    if source == VIRUSTOTAL:
        return _virustotal(name, this, answer) + _domain_note(this, answer, quote)
    parts = _server(answer, quote)
    return f"{name}: " + (
        "; ".join(parts) if parts else f"has a record of this {this} but no detail"
    )


def _virustotal(name: str, this: str, answer: Mapping[str, Any]) -> str:
    bad = malicious(answer)
    engines = number(answer.get("engines")) or 0
    odd = number(answer.get("suspicious")) or 0
    if engines <= 0:
        return f"{name}: has a record of this {this} but no engine has scored it"
    if bad == 0 and odd == 0:
        return f"{name}: no engine of {engines} flags this {this}"
    if bad == 0:
        return (
            f"{name}: no engine of {engines} calls this {this} malicious, {odd} call it suspicious"
        )
    more = f", {odd} more call it suspicious" if odd else ""
    return f"{name}: {bad} of {engines} engines flag this {this}{more}"


def _domain_note(this: str, answer: Mapping[str, Any], quote: Callable[[str], str] = str) -> str:
    """What VirusTotal's answer for a domain adds: whether it is among the
    popular sites (and, when it is not, the other lists that rank it: a DNS-volume list says how
    many devices ask for a name, not how many people visit it) and when it was registered.
    Nothing for an answer that does not carry them."""
    if this != "domain":
        return ""
    parts: list[str] = []
    ranked = answer.get("ranked")
    best = number(answer.get("best_rank"), 1)
    if ranked is True:
        where = f" (rank {best})" if best else ""
        parts.append("among the popular sites" + where)
    elif ranked is False:
        others = _other_ranks(answer.get("ranks"), quote)
        more = f" (other lists: {others})" if others else ""
        parts.append("not among the popular sites" + more)
    created = answer.get("created")
    if isinstance(created, str) and _DAY.fullmatch(created):
        parts.append(f"registered {created}")
    return "; " + "; ".join(parts) if parts else ""


def _other_ranks(ranks: object, quote: Callable[[str], str]) -> str:
    """The ranks of lists that are not web popularity, in words ("Cisco Umbrella 706434")."""
    out: list[str] = []
    for name, rank in (ranks if isinstance(ranks, Mapping) else {}).items():
        shown = clean(name, MAX_LIST_NAME) if isinstance(name, str) else None
        value = number(rank, 1)
        if shown and value is not None and not web_listed(shown, value):
            out.append(f"{quote(shown)} {value}")
    return ", ".join(out[:3])


def _server(answer: Mapping[str, Any], quote: Callable[[str], str]) -> list[str]:
    parts: list[str] = []
    open_ports = ports(answer.get("ports"))
    if open_ports:
        shown = ", ".join(str(p) for p in open_ports[:12])
        more = len(open_ports) - 12
        parts.append(f"open ports {shown}" + (f" and {more} more" if more > 0 else ""))
    products = [p for p in (answer.get("products") or []) if isinstance(p, str)][:4]
    if products:
        parts.append("software " + ", ".join(quote(p) for p in products))
    hosts = names(answer.get("hostnames"), 3)
    if hosts:
        parts.append("names " + ", ".join(quote(h) for h in hosts))
    org = clean(answer.get("org"), 60)
    if org:
        parts.append("run by " + quote(org))
    country = clean(answer.get("country"), 2)
    if country:
        parts.append(f"in {country.upper()}")
    found = cves(answer.get("vulns"))
    if found:
        parts.append(_plural(len(found), "known CVE", "known CVEs"))
    return parts


def facts_of(value: object) -> list[dict[str, Any]]:
    """The facts in an item's ``outside`` list, the well-formed ones only (a stored or model-side
    value of the wrong shape is never a fact)."""
    out: list[dict[str, Any]] = []
    for entry in value if isinstance(value, list) else []:
        if (
            isinstance(entry, dict)
            and entry.get("source") in SOURCES
            and entry.get("kind") in KINDS
            and isinstance(entry.get("value"), str)
            and entry.get("status") in (FOUND, NOT_FOUND)
        ):
            out.append(entry)
    return out


def merge(
    old: Iterable[Mapping[str, Any]], new: Iterable[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    """Facts by (source, kind, value), a newer one replacing an older one."""
    keyed: dict[tuple[Any, ...], dict[str, Any]] = {}
    for entry in [*old, *new]:
        keyed[(entry.get("source"), entry.get("kind"), entry.get("value"))] = dict(entry)
    return list(keyed.values())
