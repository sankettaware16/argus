"""Threat intelligence in one typed shape (plan §6 R9, D-057).

The sources are the site's (``site.ti_sources``, D-293): each an index with one of two
schemas, ``ecs`` (ECS ``threat.indicator.*``) or ``ioc`` (``ioc_type`` / ``ioc_value`` /
``intel_source``), read whole (``mirror``) or per value (``lookup``). Every document becomes
``Indicator``s of its source (the source's id is its index); values are canonical (R3's IP and
domain rules), so a lookup of ``10.0.0.1`` finds ``::ffff:10.0.0.1`` and ``Example.COM.``
finds ``example.com``.

A source is stale when its newest indicator is older than 7 days. An answer per value is a
match (the indicators) or, per source, ``no_match{source, freshness, stale}``: a miss in a
stale source is not "clean" (D-023).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from argus.normalize.canon import canon_domain, canon_ip

STALE_AFTER = timedelta(days=7)
KINDS = ("ip", "domain", "url", "hash", "email", "other")
TEXT_CHARS = 512

# Indicator types, as each source writes them, to ARGUS's kinds (lower-cased first).
_TYPES = {
    "ipv4-addr": "ip",
    "ipv6-addr": "ip",
    "ip": "ip",
    "ipv4": "ip",
    "ipv6": "ip",
    "ip-dst": "ip",
    "ip-src": "ip",
    "ip_address": "ip",
    "domain-name": "domain",
    "domain": "domain",
    "hostname": "domain",
    "fqdn": "domain",
    "url": "url",
    "uri": "url",
    "file": "hash",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "hash": "hash",
    "email-addr": "email",
    "email": "email",
    "e-mail": "email",
    "ipv4-address": "ip",
    "ipv6-address": "ip",
    "ip-address": "ip",
    "url-address": "url",
    "file-hash": "hash",
    "sha-256": "hash",
    "sha-1": "hash",
}
_ECS_VALUE_FIELDS = {
    "ip": ("ip",),
    "domain": ("domain", "url.domain"),
    "url": ("url.full", "url.original"),
    "hash": ("file.hash.sha256", "file.hash.sha1", "file.hash.md5"),
    "email": ("email.address",),
}


@dataclass(frozen=True)
class Indicator:
    source: str
    kind: str
    value: str
    type_raw: str
    first_seen: datetime | None
    last_seen: datetime | None
    confidence: str | None
    description: str | None


_HASH = re.compile(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}")
_DOMAIN = re.compile(r"[a-z0-9_-]+(\.[a-z0-9_-]+)+")
_DEFAULT_PORTS = {"http": 80, "https": 443}


def kind_of(type_raw: Any) -> str:
    """ARGUS's kind for a source's type name, however it is spelled (``IPv4 Address``)."""
    if not type_raw:
        return "other"
    key = re.sub(r"[\s_]+", "-", str(type_raw).strip().lower())
    return _TYPES.get(key, "other")


def guess_kind(raw: str) -> str | None:
    """The kind of a value typed by a person, by its shape (a hash before a domain)."""
    text = raw.strip()
    if _HASH.fullmatch(text):
        return "hash"
    if canonical("ip", text) is not None:
        return "ip"
    if "@" in text and canonical("email", text) is not None:
        return "email"
    if "://" in text or "/" in text:
        return "url" if canonical("url", text) is not None else None
    return "domain" if canonical("domain", text) is not None else None


def canonical(kind: str, value: Any) -> str | None:
    """The value as lookups compare it; None if it is not a value of that kind."""
    if value is None or isinstance(value, bool):
        return None
    if kind == "ip":
        ip, issue = canon_ip(value)
        return ip if issue is None and isinstance(ip, str) else None
    if kind == "domain":
        domain, issue = canon_domain(value)
        if issue is not None or not isinstance(domain, str) or not _DOMAIN.fullmatch(domain):
            return None
        return None if domain.rsplit(".", 1)[-1].isdigit() else domain
    text = str(value).strip()
    if not text or len(text) > 2048:
        return None
    if kind == "url":
        return _url(text)
    if kind == "email":
        local, at, domain = text.rpartition("@")
        host = canonical("domain", domain) if at and local else None
        return f"{local.lower()}@{host}" if host else None
    if kind == "hash":
        return text.lower() if _HASH.fullmatch(text) else None
    return text.lower()


def _url(text: str) -> str | None:
    """Scheme and host lower-cased, the default port and the fragment dropped; the path and
    query as written (they are case-sensitive)."""
    try:
        parsed = urlsplit(text if "://" in text else "//" + text)
        host = (parsed.hostname or "").rstrip(".")
        port = parsed.port
    except ValueError:
        return None
    if not host or any(c.isspace() or not c.isprintable() for c in host):
        return None  # no host has blanks or control characters (`@ 0` once became ` 0`)
    scheme = parsed.scheme.lower()
    netloc = host if port is None or _DEFAULT_PORTS.get(scheme) == port else f"{host}:{port}"
    rebuilt = urlunsplit((scheme, netloc, parsed.path, parsed.query, ""))
    return rebuilt if "://" in text else rebuilt.removeprefix("//")


def variants(kind: str, value: str) -> list[str]:
    """Spellings a source may store a canonical value in: an exact-term lookup asks for each."""
    found = [value]
    if kind in ("hash", "domain", "email", "other"):
        found.append(value.upper())
    if kind == "ip" and ":" not in value:
        found.append("::ffff:" + value)
    return list(dict.fromkeys(found))


def _readable(kind: str, raw: Any) -> tuple[str, str] | None:
    """(kind, canonical value): the source's type first, then the value's shape (a source
    that files 10.0.0.7 as a domain still means that address)."""
    value = canonical(kind, raw)
    if value is not None:
        return kind, value
    if raw is None or isinstance(raw, bool):
        return None
    guessed = guess_kind(str(raw))
    if guessed is None or guessed == kind:
        return None
    other = canonical(guessed, raw)
    return (guessed, other) if other is not None else None


def _get(doc: Mapping[str, Any], path: str) -> Any:
    """A dotted field, flat (``"a.b": 1``) or nested (``{"a": {"b": 1}}``)."""
    if path in doc:
        return doc[path]
    head, _, rest = path.partition(".")
    inner = doc.get(head)
    return _get(inner, rest) if rest and isinstance(inner, Mapping) else None


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text[:TEXT_CHARS] or None


def from_ecs(source: str, doc: Mapping[str, Any]) -> list[Indicator]:
    """The indicators of one document of an ``ecs`` source (ECS ``threat.indicator``)."""
    ind = _get(doc, "threat.indicator")
    if not isinstance(ind, Mapping):
        return []
    type_raw = str(ind.get("type") or "")
    kind = kind_of(type_raw)
    fields = _ECS_VALUE_FIELDS.get(kind, ()) if kind != "other" else ()
    candidates = [_get(ind, f) for f in fields] or [ind.get("name")]
    first_seen = _time(ind.get("first_seen"))
    last_seen = _time(ind.get("last_seen")) or _time(doc.get("@timestamp"))
    confidence = _text(ind.get("confidence"))
    description = _text(ind.get("description") or _get(doc, "threat.feed.name"))
    found: list[Indicator] = []
    for raw in candidates:
        for one in raw if isinstance(raw, list) else [raw]:
            got = _readable(kind, one)
            if got is not None:
                found.append(
                    Indicator(
                        source,
                        got[0],
                        got[1],
                        type_raw[:64],
                        first_seen,
                        last_seen,
                        confidence,
                        description,
                    )
                )
    return found


def from_ioc(source: str, doc: Mapping[str, Any]) -> list[Indicator]:
    """The indicator of one row of an ``ioc`` source (``ioc_type`` / ``ioc_value``)."""
    type_raw = str(doc.get("ioc_type") or "")
    got = _readable(kind_of(type_raw), doc.get("ioc_value"))
    if got is None:
        return []
    kind, value = got
    seen = _time(doc.get("last_seen")) or _time(doc.get("@timestamp"))
    return [
        Indicator(
            source=source,
            kind=kind,
            value=value,
            type_raw=type_raw[:64],
            first_seen=_time(doc.get("first_seen")),
            last_seen=seen,
            confidence=_text(doc.get("confidence")),
            description=_text(doc.get("intel_source")),
        )
    ]


def from_document(schema: str, source: str, doc: Mapping[str, Any]) -> list[Indicator]:
    """The indicators of one document of a source with this schema."""
    return from_ecs(source, doc) if schema == "ecs" else from_ioc(source, doc)


def indicators_of(doc: Mapping[str, Any]) -> list[Indicator]:
    """The indicators of one stored lookup row, whichever schema its source has (an ECS
    document has ``threat.indicator``, a row of the other kind ``ioc_value``): evidence keeps
    rows, not the source they came from, so the indicators have no source."""
    return from_ecs("", doc) if _get(doc, "threat.indicator") else from_ioc("", doc)


def values_of(doc: Mapping[str, Any]) -> set[str]:
    """The canonical values one stored lookup row lists."""
    return {i.value for i in indicators_of(doc)}


# ----------------------------------------------------------------------------- answers


@dataclass(frozen=True)
class Freshness:
    source: str
    newest: datetime | None  # the newest indicator the source holds
    checked_at: datetime | None  # the last successful sync or lookup

    def stale(self, now: datetime) -> bool:
        """Stale: nothing known, or the newest indicator older than 7 days."""
        return self.newest is None or now - self.newest > STALE_AFTER

    def as_dict(self, now: datetime) -> dict[str, Any]:
        return {
            "source": self.source,
            "newest": None if self.newest is None else self.newest.isoformat(),
            "checked_at": None if self.checked_at is None else self.checked_at.isoformat(),
            "stale": self.stale(now),
        }


def answer(
    value: str,
    matches: Iterable[Indicator],
    sources: Sequence[Freshness],
    now: datetime,
) -> dict[str, Any]:
    """What ARGUS knows about one value: per source a match (its indicators) or a no-match
    with that source's freshness."""
    found = sorted(
        (m for m in matches if m.value == value), key=lambda m: (m.source, m.kind, m.type_raw)
    )
    per_source: dict[str, Any] = {}
    for source in sorted(sources, key=lambda s: s.source):
        hits = [m for m in found if m.source == source.source]
        if hits:
            per_source[source.source] = {
                "match": [
                    {
                        "kind": m.kind,
                        "type": m.type_raw,
                        "first_seen": None if m.first_seen is None else m.first_seen.isoformat(),
                        "last_seen": None if m.last_seen is None else m.last_seen.isoformat(),
                        "confidence": m.confidence,
                        "description": m.description,
                    }
                    for m in hits
                ],
                "freshness": source.as_dict(now),
            }
        else:
            per_source[source.source] = {"no_match": source.as_dict(now)}
    return {"value": value, "sources": per_source}
