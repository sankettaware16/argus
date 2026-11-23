"""The database side of the campaign analysis: what the stored investigations hold (sightings: the
domain names and internal devices of each investigation in the window), what the outside cache
says about each parent and its first address (readings) and the addresses VirusTotal flags that
investigations reached (servers). Read only; nothing here asks an outside source."""

from __future__ import annotations

import json
import logging
import uuid
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timedelta

from sqlalchemy import Text, bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.assets.assetmap import IPNetwork, parse_address
from argus.assets.classify import IpClass, IpClassifier
from argus.campaigns import analysis
from argus.campaigns.families import Key, Sighting
from argus.cases import opener
from argus.outside import facts
from argus.outside.psl import registered_parent
from argus.outside.read import View

log = logging.getLogger("argus.campaigns")

MAX_ROWS = 200_000  # domain names read in one pass (a scanner can hold thousands)
# The classes of an address among an investigation's entities that are a device: the
# organisation's own addresses. Private space that no network of the asset map covers
# (INTERNAL) is infrastructure (a resolver, a gateway) as often as a device, and the entities
# do not say which side of the traffic an address was on, so it is not counted as a device here.
DEVICE_CLASSES = frozenset({IpClass.ASSET, IpClass.OWN})
# The fields of a grouping key that name who asked (the source side of the traffic). A DNS rule
# groups by the rare domain and lists every source address in its key.
SOURCE_FIELDS = frozenset({"source.ip", "client.ip"})
MAX_LISTED = 5_000  # source addresses read from one key

_NAMES = text(
    "SELECT e.investigation_id, e.value, i.group_key, coalesce(i.rule_name, i.rule_id)"
    " FROM investigation_entities e JOIN investigations i ON i.id = e.investigation_id"
    " WHERE e.kind = 'domain' AND i.last_event_at >= :since"
    " ORDER BY e.investigation_id, e.value LIMIT :limit"
)
_FLAGGED_ADDRESSES = text(
    "SELECT e.investigation_id, e.value, i.group_key FROM investigation_entities e"
    " JOIN outside_lookups o ON o.kind = 'ip' AND o.indicator = e.value"
    " AND o.source = 'virustotal' AND o.status = 'found' AND o.fetched_at >= :fresh"
    " AND CAST(COALESCE(NULLIF(o.answer ->> 'malicious', ''), '0') AS integer) >= :threshold"
    " JOIN investigations i ON i.id = e.investigation_id"
    " WHERE e.kind = 'ip' AND i.last_event_at >= :since"
    " ORDER BY e.value, e.investigation_id LIMIT :limit"
)
_ADDRESSES = text(
    "SELECT investigation_id, value FROM investigation_entities"
    " WHERE kind = 'ip' AND investigation_id = ANY(:ids) ORDER BY investigation_id, value"
).bindparams(bindparam("ids", type_=ARRAY(UUID)))
_ANSWERS = text(
    "SELECT kind, indicator, status, answer, fetched_at FROM outside_lookups"
    " WHERE source = 'virustotal' AND kind = :kind AND indicator = ANY(:values)"
    " AND fetched_at >= :since"
).bindparams(bindparam("values", type_=ARRAY(Text)))


def listed_sources(group_key: str, classifier: IpClassifier) -> frozenset[Key]:
    """The internal addresses a key lists under a source field (a DNS rule's many source
    addresses: ``[["source.ip", ["10.x", "10.y"]]]``). The key says which side of the traffic an
    address was on, which the entities do not."""
    try:
        pairs = json.loads(group_key)
    except ValueError:
        return frozenset()
    out: set[Key] = set()
    for pair in pairs if isinstance(pairs, list) else []:
        if not (isinstance(pair, list) and len(pair) == 2 and pair[0] in SOURCE_FIELDS):
            continue
        values = pair[1] if isinstance(pair[1], list) else []
        for value in values[:MAX_LISTED]:
            got = classifier.classify(value) if isinstance(value, str) else None
            if got is not None and got.address is not None and got.ip_class in opener.OWN_CLASSES:
                out.add(("ip", got.address))
    return frozenset(out)


def actors_of(group_key: str, classifier: IpClassifier) -> frozenset[Key]:
    """The internal devices a grouping key names: its internal addresses and host names, and the
    internal addresses it lists under a source field."""
    actors, _ = opener.actors_of(group_key, classifier)
    named = frozenset(
        (a.kind, a.value)
        for a in actors
        if a.kind == "host"
        or (a.kind == "ip" and classifier.classify(a.value).ip_class in opener.OWN_CLASSES)
    )
    return named | listed_sources(group_key, classifier)


def is_resolver(key: Key, resolvers: Sequence[IPNetwork]) -> bool:
    """Whether a device key is an address of one of the resolvers named in
    ``campaigns.resolvers`` (a resolver asks for every name its users ask for: it is no device)."""
    if key[0] != "ip" or not resolvers:
        return False
    address = parse_address(key[1])
    return address is not None and any(
        address.version == n.version and address in n for n in resolvers
    )


async def hosts_for(
    conn: AsyncConnection, groups: Mapping[uuid.UUID, str], classifier: IpClassifier,
    resolvers: Sequence[IPNetwork] = (),
) -> dict[uuid.UUID, frozenset[Key]]:  # fmt: skip
    """The internal devices of each investigation in ``groups`` (its grouping key): the devices
    its key names or lists as sources and the internal addresses among its entities, except the
    resolvers in ``campaigns.resolvers`` and, among the entities (which do not say which side an
    address was on), addresses that are only private space (:data:`DEVICE_CLASSES`). How many
    investigations hold an address says nothing here: a device infected with a DGA is in hundreds
    of them."""
    found: dict[uuid.UUID, set[Key]] = {i: set(actors_of(k, classifier)) for i, k in groups.items()}
    if groups:
        rows = await conn.execute(_ADDRESSES, {"ids": list(groups)})
        for investigation_id, value in rows:
            if classifier.classify(value).ip_class in DEVICE_CLASSES:
                found[investigation_id].add(("ip", value))
    kept = {i: frozenset(k for k in keys if not is_resolver(k, resolvers))
            for i, keys in found.items()}  # fmt: skip
    return {i: keys for i, keys in kept.items() if keys}


ByInvestigation = dict[uuid.UUID, str]


async def sightings(
    conn: AsyncConnection, now: datetime, window: timedelta, *, limit: int = MAX_ROWS
) -> tuple[dict[uuid.UUID, frozenset[str]], ByInvestigation, ByInvestigation]:
    """The domain names each investigation of the window holds (canonical spelling; a value that
    is not a plain name is left out), its grouping key and the rule that raised it."""
    names: dict[uuid.UUID, set[str]] = defaultdict(set)
    keys: dict[uuid.UUID, str] = {}
    rules: dict[uuid.UUID, str] = {}
    rows = await conn.execute(_NAMES, {"since": now - window, "limit": limit})
    count = 0
    for investigation_id, value, group_key, rule in rows:
        count += 1
        name = facts.canonical("domain", value)
        if name is not None:
            names[investigation_id].add(name)
            keys[investigation_id] = group_key
            rules[investigation_id] = str(rule)
    if count >= limit:  # the window holds more names than one pass reads: part of it is not seen
        log.warning("campaigns: the cap of %d domain names was reached; the window is read in "
                    "part", limit)  # fmt: skip
    return {i: frozenset(n) for i, n in names.items()}, keys, rules


async def servers(
    conn: AsyncConnection, now: datetime, window: timedelta, view: View, *, limit: int = MAX_ROWS
) -> tuple[dict[str, frozenset[uuid.UUID]], dict[uuid.UUID, str]]:  # fmt: skip
    """The addresses VirusTotal flags (inside the cache's detection window) and the investigations
    of the window that reached each, with their grouping keys."""
    reached: dict[str, set[uuid.UUID]] = defaultdict(set)
    keys: dict[uuid.UUID, str] = {}
    rows = await conn.execute(
        _FLAGGED_ADDRESSES,
        {"since": now - window, "fresh": now - view.window, "threshold": view.threshold,
         "limit": limit},
    )  # fmt: skip
    count = 0
    for investigation_id, value, group_key in rows:
        count += 1
        address = facts.canonical("ip", value)
        if address is not None:
            reached[address].add(investigation_id)
            keys[investigation_id] = group_key
    if count >= limit:
        log.warning("campaigns: the cap of %d flagged-address rows was reached; the window is "
                    "read in part", limit)  # fmt: skip
    return {a: frozenset(ids) for a, ids in reached.items()}, keys


async def _answers(
    conn: AsyncConnection, kind: str, values: Sequence[str], now: datetime, view: View
) -> dict[str, tuple[str, Mapping[str, object]]]:
    """The cached VirusTotal answers for ``values`` that are still kept, by indicator."""
    if not values:
        return {}
    out: dict[str, tuple[str, Mapping[str, object]]] = {}
    rows = await conn.execute(_ANSWERS, {"kind": kind, "values": list(values),
                                         "since": now - view.window})  # fmt: skip
    for row in rows:
        if row.fetched_at >= now - view.kept_for("virustotal", row.status, row.answer):
            out[row.indicator] = (row.status, row.answer)
    return out


def first_address(
    addresses: Sequence[str], allowed: Callable[[str], bool]
) -> str | None:  # fmt: skip
    """The first of a parent's addresses that may be asked about (public, not shared)."""
    return next((a for a in addresses if allowed(a)), None)


async def readings(
    conn: AsyncConnection, parents: Sequence[str], now: datetime, view: View,
    allowed: Callable[[str], bool],
) -> dict[str, analysis.Reading]:  # fmt: skip
    """What the cache says about each of ``parents``: its domain answer, with the network of the
    first address that ``allowed`` lets be asked about. A parent with no kept answer, or one in
    the shape this version does not read, has no reading (the look-up step asks again)."""
    domains = await _answers(conn, "domain", parents, now, view)
    base = {
        p: analysis.reading_of(status, answer)
        for p, (status, answer) in domains.items()
        if analysis.current(status, answer)
    }
    target = {p: first_address(r.addresses, allowed) for p, r in base.items()}
    wanted = sorted({a for a in target.values() if a is not None})
    ips = await _answers(conn, "ip", wanted, now, view)
    out: dict[str, analysis.Reading] = {}
    for parent, reading in base.items():
        address = target[parent]
        got = ips.get(address) if address is not None else None
        if got is None or got[0] != "found":
            out[parent] = reading
            continue
        status, answer = domains[parent]
        out[parent] = analysis.reading_of(status, answer, got[1], address)
    return out


async def world(
    conn: AsyncConnection, now: datetime, *, window: timedelta, classifier: IpClassifier,
    view: View, allowed: Callable[[str], bool], resolvers: Sequence[IPNetwork] = (),
) -> analysis.World:  # fmt: skip
    """The sightings, readings and flagged servers of the window, ready for ``analysis.analyse``."""
    names, keys, rules = await sightings(conn, now, window)
    flagged, more = await servers(conn, now, window, view)
    hosts = await hosts_for(conn, {**keys, **more}, classifier, resolvers)
    seen = tuple(
        Sighting(i, hosts.get(i, frozenset()), n, rules.get(i, ""))
        for i, n in sorted(names.items())
    )
    parents = sorted({p for s in seen for n in s.names if (p := registered_parent(n))})
    known = await readings(conn, parents, now, view, allowed)
    return analysis.World(seen, known, flagged, hosts, view.threshold)
