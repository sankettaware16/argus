"""The three outside sources: VirusTotal (public API v3), Shodan (host lookup; the free InternetDB
with no key) and Censys (Platform API host lookup). ``prepare`` builds a request and ``parse``
reduces a reply to a small :class:`Parsed` answer; neither does I/O, and a key goes only in the
headers or query parameters of the request. :class:`HttpxTransport` is the only code that touches
the network: HTTPS to the source's own host, no redirects or proxies, a deadline, a size cap, and
no exception text that could hold a URL."""

from __future__ import annotations

import asyncio
import base64
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import quote

import httpx

from argus.outside import facts

MAX_REPLY_BYTES = 2_000_000
FOUND = "found"
NOT_FOUND = "not_found"
LIMITED = "limited"  # HTTP 429: the source is stopped for the window
REFUSED = "refused"  # HTTP 401 or 403: the key is not accepted
ERROR = "error"  # anything else: a failure, a reply that is not what the source documents


@dataclass(frozen=True)
class Prepared:
    """A request to send. Its headers and parameters may hold the key, so its repr shows
    neither."""

    url: str
    headers: Mapping[str, str] = field(default_factory=dict, repr=False)
    params: Mapping[str, str] = field(default_factory=dict, repr=False)


@dataclass(frozen=True)
class Parsed:
    outcome: str  # found | not_found | limited | refused | error
    answer: Mapping[str, Any] = field(default_factory=dict)
    retry_after: int | None = None  # seconds, from a 429's Retry-After (capped)


@dataclass(frozen=True)
class Reply:
    status: int
    body: bytes
    retry_after: str | None = None


class Transport(Protocol):
    async def get(self, request: Prepared, timeout_s: float) -> Reply: ...


class TransportError(Exception):
    """A request that got no reply (a deadline, a refused connection, a reply too large). The
    message is a fixed word or an exception's type, never a URL."""


class Provider(Protocol):
    source: str
    kinds: frozenset[str]
    host: str

    def prepare(self, kind: str, indicator: str, key: str) -> Prepared: ...

    def parse(self, kind: str, reply: Reply, now: datetime | None = None) -> Parsed: ...


def _json(body: bytes) -> Mapping[str, Any] | None:
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):  # not JSON, or nested past what the parser reads
        return None
    return data if isinstance(data, dict) else None


MAX_RETRY = 86_400  # a Retry-After is trusted up to a day


def _retry(value: str | None) -> int | None:
    """A Retry-After in seconds (a date is not read), at most a day. Only ASCII digits count
    (``int`` takes other scripts' digits and refuses a very long number); 0 is "now", not unset."""
    text = "" if value is None else value.strip()
    if not (text.isascii() and text.isdigit()):
        return None
    digits = text.lstrip("0")
    return MAX_RETRY if len(digits) > 6 else min(int(digits or "0"), MAX_RETRY)


def _limit_answer(answer: dict[str, Any]) -> dict[str, Any]:
    """Drop empty values, and refuse to keep more than ``facts.MAX_ANSWER_JSON`` bytes (every
    parser keeps its lists short, so this is a backstop)."""
    kept = {k: v for k, v in answer.items() if v not in (None, [], "", {})}
    if len(json.dumps(kept, separators=(",", ":"))) > facts.MAX_ANSWER_JSON:
        raise ValueError("answer too large")
    return kept


def _status(reply: Reply) -> Parsed | None:
    """What a status alone settles, or None when the body must be read."""
    if reply.status == 429:
        return Parsed(LIMITED, retry_after=_retry(reply.retry_after))
    if reply.status in (401, 403):
        return Parsed(REFUSED)
    if reply.status == 404:
        return Parsed(NOT_FOUND)
    if reply.status != 200:
        return Parsed(ERROR)
    return None


_VT_PATHS = {"ip": "ip_addresses", "domain": "domains", "hash": "files", "url": "urls"}


class VirusTotal:
    source = facts.VIRUSTOTAL
    kinds = frozenset({"ip", "domain", "hash", "url"})
    host = "www.virustotal.com"
    base = "https://www.virustotal.com/api/v3/"

    def prepare(self, kind: str, indicator: str, key: str) -> Prepared:
        if kind == "url":  # the URL's identifier: unpadded URL-safe base64
            ident = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
        else:
            ident = quote(indicator, safe=":")
        return Prepared(f"{self.base}{_VT_PATHS[kind]}/{ident}", {"x-apikey": key})

    def parse(self, kind: str, reply: Reply, now: datetime | None = None) -> Parsed:
        settled = _status(reply)
        if settled is not None:
            return settled
        data = _json(reply.body)
        attributes = (data or {}).get("data", {}) if isinstance(data, dict) else {}
        attributes = attributes.get("attributes") if isinstance(attributes, dict) else None
        stats = attributes.get("last_analysis_stats") if isinstance(attributes, dict) else None
        if not isinstance(attributes, dict) or not isinstance(stats, dict):
            return Parsed(ERROR)
        counts = {k: facts.number(stats.get(k)) or 0 for k in
                  ("malicious", "suspicious", "harmless", "undetected")}  # fmt: skip
        answer: dict[str, Any] = {
            **counts,
            "engines": sum(counts.values()),
            "reputation": facts.number(attributes.get("reputation"), -(10**6), 10**6),
            "owner": facts.clean(attributes.get("as_owner"), 60),
            "asn": facts.number(attributes.get("asn")),
            "country": _country(attributes.get("country")),
            "tags": facts.tags(attributes.get("tags")),
            "analysed": _day(attributes.get("last_analysis_date")),
            "created": _day(attributes.get("creation_date")),
        }
        if kind == "domain":
            answer.update(_domain_fields(attributes, now or datetime.now(UTC)))
        try:
            return Parsed(FOUND, _limit_answer(answer))
        except ValueError:
            return Parsed(ERROR)


def _domain_fields(attributes: Mapping[str, Any], now: datetime) -> dict[str, Any]:
    """What a domain's answer adds to the counts: whether VirusTotal ranks it
    among the popular sites (a web-popularity list, a rank from the last year: see
    :func:`facts.popularity`; the other lists are kept as ``ranks`` for display), who registered
    it, and where it points (its name servers and A records, from ``last_dns_records``). ``ranked``
    is always set: a reply with no qualifying rank is unranked. Every list is short and every
    text cleaned."""
    out: dict[str, Any] = {
        "shape": facts.DOMAIN_SHAPE,  # a cached answer without it is asked again for the family
        "registrar": facts.clean(attributes.get("registrar"), 60),
        **facts.popularity(attributes.get("popularity_ranks"), now),
    }
    servers: list[Any] = []
    addresses: list[str] = []
    for record in _dicts(attributes.get("last_dns_records")):
        value = record.get("value")
        if record.get("type") == "NS":
            servers.append(value)
        elif record.get("type") == "A":
            address = facts.canonical("ip", value)
            if address is not None and address not in addresses:
                addresses.append(address)
    out["name_servers"] = sorted(facts.names(servers, 50))[: facts.MAX_NAME_SERVERS]  # one order
    out["addresses"] = addresses[:5]
    return out


class Shodan:
    source = facts.SHODAN
    kinds = frozenset({"ip"})
    host = "api.shodan.io"

    def prepare(self, kind: str, indicator: str, key: str) -> Prepared:
        return Prepared(f"https://{self.host}/shodan/host/{quote(indicator, safe=':')}",
                        {}, {"key": key})  # fmt: skip

    def parse(self, kind: str, reply: Reply, now: datetime | None = None) -> Parsed:
        settled = _status(reply)
        if settled is not None:
            return settled
        data = _json(reply.body)
        if data is None or not isinstance(data.get("ip_str"), str):
            return Parsed(ERROR)  # a host object always names its address
        services = _dicts(data.get("data"))
        products = []
        for service in services:
            product = facts.clean(service.get("product"), 40)
            if product:
                version = facts.clean(service.get("version"), 20)
                text = f"{product} {version}" if version else product
                if text not in products:
                    products.append(text)
        answer: dict[str, Any] = {
            "ports": facts.ports(data.get("ports"))
            or facts.ports([s.get("port") for s in services]),
            "products": products[:6],
            "hostnames": facts.names(data.get("hostnames")),
            "org": facts.clean(data.get("org"), 60),
            "country": _country(data.get("country_code")),
            "asn": _asn(data.get("asn")),
            "os": facts.clean(data.get("os"), 30),
            "tags": facts.tags(data.get("tags")),
            "vulns": facts.cves(_listed(data.get("vulns"))),
        }
        try:
            return Parsed(FOUND, _limit_answer(answer))
        except ValueError:
            return Parsed(ERROR)


class InternetDB:
    """Shodan's free InternetDB: ``GET https://internetdb.shodan.io/{ip}``, no key,
    for the ``shodan`` source when no key with host access is set. It answers the address's open
    ports, host names, CPEs (software), tags and known CVEs, nothing more: no organisation, no
    network. A 404 is "no record". The same limits as Shodan's host lookup apply."""

    source = facts.SHODAN
    kinds = frozenset({"ip"})
    host = "internetdb.shodan.io"

    def prepare(self, kind: str, indicator: str, key: str) -> Prepared:
        return Prepared(f"https://{self.host}/{quote(indicator, safe=':')}")

    def parse(self, kind: str, reply: Reply, now: datetime | None = None) -> Parsed:
        settled = _status(reply)
        if settled is not None:
            return settled
        data = _json(reply.body)
        if data is None or not isinstance(data.get("ip"), str):
            return Parsed(ERROR)  # a record always names its address
        products: list[str] = []
        for cpe in _listed(data.get("cpes")):
            text = _cpe(cpe)
            if text and text not in products:
                products.append(text)
        answer: dict[str, Any] = {
            "ports": facts.ports(data.get("ports")),
            "products": products[:6],
            "hostnames": facts.names(data.get("hostnames")),
            "tags": facts.tags(data.get("tags")),
            "vulns": facts.cves(_listed(data.get("vulns"))),
        }
        try:
            return Parsed(FOUND, _limit_answer(answer))
        except ValueError:
            return Parsed(ERROR)


def _cpe(value: object) -> str | None:
    """A CPE (``cpe:/a:apache:http_server:2.4.41`` or ``cpe:2.3:a:apache:http_server:2.4.41:...``)
    as its product and version (``http server 2.4.41``), or None."""
    if not isinstance(value, str) or not value.startswith("cpe:"):
        return None
    parts = value.split(":")
    fields = parts[3:] if parts[1:2] == ["2.3"] else parts[2:]  # after "cpe:2.3:" or "cpe:/"
    if len(fields) < 2:
        return None
    product = facts.clean(fields[1].replace("_", " "), 40)
    version = facts.clean(
        fields[2] if len(fields) > 2 and fields[2] not in ("*", "-") else None, 20
    )
    if not product:
        return None
    return f"{product} {version}" if version else product


class Censys:
    """The Platform API (the legacy Search v2 and its API id and secret are retired). The host
    object's shape is read tolerantly: ``result.resource`` (or ``result``) with ``services``
    (port, protocol, software), ``autonomous_system`` and ``location``."""

    source = facts.CENSYS
    kinds = frozenset({"ip"})
    host = "api.platform.censys.io"

    def prepare(self, kind: str, indicator: str, key: str) -> Prepared:
        return Prepared(
            f"https://{self.host}/v3/global/asset/host/{quote(indicator, safe=':')}",
            {"Authorization": f"Bearer {key}",
             "Accept": "application/vnd.censys.api.v3.host.v1+json"},
        )  # fmt: skip

    def parse(self, kind: str, reply: Reply, now: datetime | None = None) -> Parsed:
        settled = _status(reply)
        if settled is not None:
            return settled
        data = _json(reply.body)
        result = data.get("result") if data else None
        host = result.get("resource", result) if isinstance(result, dict) else None
        if not isinstance(host, dict):
            return Parsed(ERROR)
        services = _dicts(host.get("services"))
        products: list[str] = []
        for service in services:
            for software in _dicts(service.get("software")):
                product = facts.clean(software.get("product"), 40)
                if product and product not in products:
                    products.append(product)
        system = host.get("autonomous_system")
        system = system if isinstance(system, dict) else {}
        place = host.get("location")
        place = place if isinstance(place, dict) else {}
        dns = host.get("dns")
        reverse = (dns.get("reverse_dns") or {}).get("names") if isinstance(dns, dict) else None
        answer: dict[str, Any] = {
            "ports": facts.ports([s.get("port") for s in services]),
            "products": products[:6],
            "hostnames": facts.names(reverse),
            "org": facts.clean(system.get("name"), 60),
            "country": _country(place.get("country_code") or system.get("country_code")),
            "asn": _asn(system.get("asn")),
            "tags": facts.tags(host.get("labels")),
        }
        try:
            return Parsed(FOUND, _limit_answer(answer))
        except ValueError:
            return Parsed(ERROR)


def _dicts(value: object) -> list[dict[str, Any]]:
    """The objects of a list (anything else is none)."""
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def _listed(value: object) -> list[Any]:
    """A list of ids, or the keys of an object keyed by them (Shodan writes both)."""
    if isinstance(value, dict):
        return list(value)
    return value if isinstance(value, list) else []


def _country(value: object) -> str | None:
    text = value.strip().upper() if isinstance(value, str) else ""
    return text if re.fullmatch(r"[A-Z]{2}", text) else None


def _asn(value: object) -> int | None:
    if isinstance(value, str) and value.upper().startswith("AS"):
        value = value[2:]
    if isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 10:
        value = int(value)
    return facts.number(value, 0, 4_294_967_295)


def _day(value: object) -> str | None:
    """A UNIX time as a UTC day (``2026-10-23``)."""
    seconds = facts.number(value, 0, 4_102_444_800)
    return datetime.fromtimestamp(seconds, UTC).date().isoformat() if seconds else None


PROVIDERS: Mapping[str, Provider] = {
    facts.VIRUSTOTAL: VirusTotal(),
    facts.SHODAN: Shodan(),
    facts.CENSYS: Censys(),
}
INTERNETDB = InternetDB()  # the ``shodan`` source's keyless way (see ``Outside``)


class HttpxTransport:
    """The real transport: one client, HTTPS only, to the sources' own hosts."""

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client
        self._hosts = {p.host for p in (*PROVIDERS.values(), INTERNETDB)}

    def _get(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                follow_redirects=False,
                trust_env=False,  # no proxy or certificate settings from the environment
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()

    async def get(self, request: Prepared, timeout_s: float) -> Reply:
        host = httpx.URL(request.url).host
        if not request.url.startswith("https://") or host not in self._hosts:
            raise TransportError("not one of the sources' hosts")
        try:
            async with (
                asyncio.timeout(timeout_s),
                self._get().stream(
                    "GET", request.url, headers=dict(request.headers),
                    params=dict(request.params), timeout=httpx.Timeout(timeout_s),
                ) as response,
            ):  # fmt: skip
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > MAX_REPLY_BYTES:
                        raise TransportError("reply too large")
                    chunks.append(chunk)
                return Reply(response.status_code, b"".join(chunks),
                             response.headers.get("retry-after"))  # fmt: skip
        except TimeoutError:
            raise TransportError("deadline") from None
        except httpx.HTTPError as exc:  # its text can hold the URL, and Shodan's key is in it
            raise TransportError(type(exc).__name__) from None
