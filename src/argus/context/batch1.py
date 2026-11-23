"""Evidence templates, batch 1: the five templates' catalogue, the rules each request must pass,
the builders that make their parameters from an investigation, and their first production runs.

The five: ``proxy.pair`` and ``proxy.contact`` (beacon.py), ``dns.host_domains`` (dns.py),
``web.path_outcomes`` (paths.py), ``logs.source_events`` (source_events.py). Before a request
(``admit``) the first refusal wins and nothing is sent: the template is switched on (after its
first production run passed), not in the quiet hours, the SIEM is NORMAL, the prevalence gate (a
value ARGUS sees in 50 or more investigations is too common to query), and the template's own
daily server time is under 90 s. ``send`` is the one way a batch-1 request goes out.
"""

from __future__ import annotations

import asyncio
import ipaddress
from collections.abc import Awaitable, Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any, Literal

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus import site
from argus.assets.classify import IpClass
from argus.context import beacon, dns, paths, source_events
from argus.context.bounds import clamp, quiet, utf16_len
from argus.context.evidence import COMPLETE, SignalValue, canonical
from argus.context.packs import TaskSpec
from argus.gateway import health as health_core
from argus.gateway.errors import DeferredError
from argus.gateway.gateway import Gateway, Result, SendCheck, Targets
from argus.gateway.health import HealthConfig, HealthState
from argus.gateway.indices import daily_indices
from argus.gateway.state import GatewayState
from argus.gateway.templates import Params, Purpose, Template, Window
from argus.gateway.validator import FORCED_SEARCH_PARAMS, FinalRequest, validate
from argus.site import Role, active, reads, say, source_param

TEMPLATES: dict[str, type[Template]] = {
    beacon.ProxyPair.name: beacon.ProxyPair,
    beacon.ProxyContact.name: beacon.ProxyContact,
    dns.DnsHostDomains.name: dns.DnsHostDomains,
    paths.WebPathOutcomes.name: paths.WebPathOutcomes,
    source_events.LogsSourceEvents.name: source_events.LogsSourceEvents,
}
# The first production run's limit, in server time: over it, the template
# stays off.
FIRST_RUN_MS = {
    "proxy.pair": 10_000,
    "proxy.contact": 10_000,
    "dns.host_domains": 10_000,
    "web.path_outcomes": 3_000,
    "logs.source_events": 3_000,
}
# What each template can close: the gap detector matches on these.
CLOSES = {
    "proxy.pair": ("beacon", "timeline", "still_active"),
    "proxy.contact": ("scope", "still_active"),
    "dns.host_domains": ("name_lookup", "dns_tunnel"),
    "web.path_outcomes": ("attack_success",),
    "logs.source_events": ("source_events",),
}
# The field types the five templates rely on, per log source: the site's families' mappings
# (``LogFamily.field_types``). A site's own captured mappings (where a capture exists) are
# compared with them by a test. "text+keyword" is text with a ``.keyword``
# sub-field of the family's ``ignore_above``.
TEMPLATE_ROLES = {
    "proxy.pair": (Role.PROXY,),
    "proxy.contact": (Role.PROXY,),
    "dns.host_domains": (Role.DNS,),
    "web.path_outcomes": (Role.WEB,),
    "logs.source_events": (Role.PROXY, Role.WEB, Role.DNS),
}


class _SourceFields(Mapping[str, dict[str, str]]):
    """The mapping facts of each family a batch-1 template reads: source -> field path -> type."""

    def _names(self) -> list[str]:
        roles = {Role.PROXY, Role.DNS, Role.WEB}
        return [f.name for f in active().families if f.role in roles]

    def __getitem__(self, source: str) -> dict[str, str]:
        if source not in self._names():
            raise KeyError(source)
        family = active().family(source)
        assert family is not None
        return family.field_types()

    def __iter__(self) -> Iterator[str]:
        return iter(self._names())

    def __len__(self) -> int:
        return len(self._names())


class _TemplateSources(Mapping[str, tuple[str, ...]]):
    """The families each batch-1 template reads: the site's families of its roles."""

    def __getitem__(self, template: str) -> tuple[str, ...]:
        return tuple(f.name for role in TEMPLATE_ROLES[template] for f in active().of_role(role))

    def __iter__(self) -> Iterator[str]:
        return iter(TEMPLATE_ROLES)

    def __len__(self) -> int:
        return len(TEMPLATE_ROLES)


FIELDS: Mapping[str, dict[str, str]] = _SourceFields()
SOURCES: Mapping[str, tuple[str, ...]] = _TemplateSources()


def mapping(source: str) -> dict[str, Any]:
    """``FIELDS[source]`` as an index mapping's properties (es-local builds its indices so)."""
    properties: dict[str, Any] = {}
    family = active().family(source)
    ignore_above = family.ignore_above if family is not None else 256
    for field, kind in FIELDS[source].items():
        node = properties
        *parents, leaf = field.split(".")
        for part in parents:
            node = node.setdefault(part, {"properties": {}})["properties"]
        if kind == "text+keyword":
            node[leaf] = {"type": "text", "fields": {"keyword": {"type": "keyword",
                          "ignore_above": ignore_above}}}  # fmt: skip
        else:
            node[leaf] = {"type": kind}
    return {"date_detection": False, "properties": properties}


DAILY_CAP_MS = 90_000  # a template's own server time a day
INVESTIGATIONS_LIMIT = 50  # in history.window: above it a value is too common to query
HOSTS_LIMIT = 25  # internal hosts that reached a destination
CO_ADDRESSES = 20_000  # addresses read beside a destination; that many is common anyway
FIELD_VALUE_CHARS = 100  # the field facts' cap (generic.VALUE_CHARS): a value this long may be cut
PURPOSE_COMPONENT = "enrichment"

Code = Literal["off", "quiet_hours", "not_normal", "too_common", "daily_cap", "no_subject"]
SENTENCES: dict[str, str] = {
    "off": "this check is switched off until its first run on the SIEM has passed",
    "quiet_hours": "this check does not run between {quiet}, the SIEM's busy time",
    "not_normal": "the SIEM is not in its normal state, so this check waits",
    "too_common": "could not tell: too common to query",
    "daily_cap": "this check's SIEM time for today is used up",
    "no_subject": "there is nothing this check could be asked about",
}


@dataclass(frozen=True)
class Refusal:
    code: Code
    detail: str = ""

    @property
    def sentence(self) -> str:
        return say(SENTENCES[self.code])


# ----------------------------------------------------------------------------- the gate


@dataclass(frozen=True)
class Key:
    """A value a template is keyed on, as the prevalence gate sees it."""

    kind: Literal["host", "destination", "path"]
    value: str


def keys(name: str, params: Params) -> tuple[Key, ...]:
    """What the prevalence gate checks for a request. ``proxy.pair`` and the DNS template are
    bounded by one internal host (a NAT or a resolver is a shared address); ``proxy.contact``
    by its destination, or, with watched hosts, by each of them (a NAT watched is as shared
    as a NAT paired); the path template by its client and its paths (the site
    bounds the rest); the source events are no aggregation (medium cost)."""
    if isinstance(params, beacon.PairParams):
        return (Key("host", params.host),)
    if isinstance(params, beacon.ContactParams):
        if params.hosts:
            return tuple(Key("host", h) for h in params.hosts)
        return (Key("destination", params.destination),)
    if isinstance(params, dns.DomainsParams):
        return (Key("host", params.ip),)
    if isinstance(params, paths.PathParams):
        return (Key("host", params.ip), *(Key("path", p) for p in params.paths))
    if isinstance(params, source_events.SourceParams):
        return ()
    raise TypeError(f"{name} is not a batch-1 template")


@dataclass(frozen=True)
class Prevalence:
    investigations: int
    own_hosts: int  # 0 for a host or a path


def too_common(key: Key, seen: Prevalence) -> bool:
    if key.kind == "path":
        return key.value in paths.COMMON_PATHS
    if seen.investigations >= INVESTIGATIONS_LIMIT:
        return True
    return key.kind == "destination" and seen.own_hosts >= HOSTS_LIMIT


async def prevalence(
    conn: AsyncConnection, key: Key, since: datetime, is_own: Callable[[str], bool]
) -> Prevalence:
    """How common ``key`` is in ARGUS's own store: investigations naming it whose activity
    reaches into ``since``, and (a destination) the internal addresses those investigations
    name. Paths are not entities: the gate judges them by ``COMMON_PATHS`` alone."""
    if key.kind == "path":
        return Prevalence(0, 0)
    found = (
        await conn.execute(
            text(
                "SELECT count(DISTINCT e.investigation_id) FROM investigation_entities e"
                " JOIN investigations i ON i.id = e.investigation_id"
                " WHERE e.kind = 'ip' AND e.value = :v AND i.last_event_at >= :since"
            ),
            {"v": key.value, "since": since},
        )
    ).scalar_one()
    hosts = 0
    if key.kind == "destination":
        others = list(
            (
                await conn.execute(
                    text(
                        "SELECT DISTINCT o.value FROM investigation_entities e"
                        " JOIN investigations i ON i.id = e.investigation_id"
                        " JOIN investigation_entities o ON o.investigation_id ="
                        " e.investigation_id AND o.kind = 'ip' AND o.value <> e.value"
                        " WHERE e.kind = 'ip' AND e.value = :v AND i.last_event_at >= :since"
                        " LIMIT :n"
                    ),
                    {"v": key.value, "since": since, "n": CO_ADDRESSES},
                )
            ).scalars()
        )
        for value in others:
            hosts += is_own(str(value))
            if hosts >= HOSTS_LIMIT:
                break
        if len(others) >= CO_ADDRESSES:  # more addresses than ARGUS reads: common, whatever
            hosts = max(hosts, HOSTS_LIMIT)
    return Prevalence(int(found), hosts)


async def spent_today(conn: AsyncConnection, name: str, now: datetime) -> int:
    """The template's server time charged today (UTC), from the gateway's ledger."""
    day = now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    spent = (
        await conn.execute(
            text(
                "SELECT coalesce(sum(took_ms), 0) FROM siem_requests"
                " WHERE template = :t AND at >= :day"
            ),
            {"t": name, "day": day},
        )
    ).scalar_one()
    return int(spent)


def private_or(classify: Callable[[str], str] | None) -> Callable[[str], bool]:
    """Internal addresses: the asset map's classes when given, else private space."""

    def ours(value: str) -> bool:
        if classify is not None:
            return classify(value) in INTERNAL
        try:
            return ipaddress.ip_address(value).is_private
        except ValueError:
            return False

    return ours


class Reservations:
    """Server time of batch-1 requests in flight, per template and UTC day: each is reserved
    at its template's timeout when admitted and released once it finished (its real time is
    then in the ledger), so requests admitted together cannot all pass the daily cap. Within
    one process; one lock per template makes admitting and reserving one step."""

    def __init__(self) -> None:
        self._held: dict[int, tuple[str, date, int]] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._next = 0

    def lock(self, name: str) -> asyncio.Lock:
        return self._locks.setdefault(name, asyncio.Lock())

    def held(self, name: str, now: datetime) -> int:
        day = now.astimezone(UTC).date()
        return sum(ms for n, d, ms in self._held.values() if n == name and d == day)

    def take(self, name: str, now: datetime, ms: int) -> int:
        self._next += 1
        self._held[self._next] = (name, now.astimezone(UTC).date(), ms)
        return self._next

    def release(self, token: int) -> None:
        self._held.pop(token, None)


RESERVED = Reservations()


async def admit(
    conn: AsyncConnection,
    state: GatewayState,
    task: TaskSpec,
    *,
    enabled: Iterable[str],
    now: datetime,
    history: timedelta,
    is_own: Callable[[str], bool],
    health_config: HealthConfig | None = None,
    reservations: Reservations = RESERVED,
) -> Refusal | None:
    """None when ``task`` may go to the gateway now; otherwise the first rule it breaks."""
    name = type(task.template).name
    if name not in TEMPLATES or type(task.template) is not TEMPLATES[name]:
        raise TypeError(f"{name} is not a batch-1 template")
    if name not in set(enabled):
        return Refusal("off")
    if quiet(now):
        return Refusal("quiet_hours")
    memory = health_core.effective(await state.health(), now, health_config or HealthConfig())
    if memory.state is not HealthState.NORMAL:
        return Refusal("not_normal", str(memory.state))
    for key in keys(name, task.params):
        if too_common(key, await prevalence(conn, key, now - history, is_own)):
            return Refusal("too_common", key.kind)
    if await spent_today(conn, name, now) + reservations.held(name, now) >= DAILY_CAP_MS:
        return Refusal("daily_cap")
    return None


def send_check(state: GatewayState, health_config: HealthConfig | None = None) -> SendCheck:
    """The rules that must still hold when the gateway sends (after any wait, before a
    retry): not in the quiet hours, and the SIEM NORMAL. The gateway itself allows enrichment in
    CAUTION and knows no quiet hours."""
    config = health_config or HealthConfig()

    async def check(now: datetime) -> None:
        if quiet(now):
            raise DeferredError(
                f"{site.quiet_hours().start} to {site.quiet_hours().end} UTC: batch-1 checks wait"
            )
        memory = health_core.effective(await state.health(), now, config)
        if memory.state is not HealthState.NORMAL:
            raise DeferredError(f"the SIEM is {memory.state}: batch-1 checks run in NORMAL only")

    return check


async def send(
    conn: AsyncConnection,
    gateway: Gateway,
    task: TaskSpec,
    *,
    enabled: Iterable[str],
    history: timedelta,
    is_own: Callable[[str], bool],
    deadline: datetime,
    health_config: HealthConfig | None = None,
    reservations: Reservations = RESERVED,
    purpose: Purpose = Purpose.ENRICH,
    component: str = PURPOSE_COMPONENT,
) -> Result | Refusal:
    """The one way a batch-1 request goes out: ``admit`` and the reservation as one step,
    then the gateway with ``send_check``; the reservation is released when it finished.
    ``purpose`` and ``component`` say whose lane it spends (default: enrichment's; the
    deterministic wave and "Check more" pass the investigation lane).
    Raises the gateway's errors (a DeferredError when a rule stopped it on the way)."""
    name = type(task.template).name
    timeout_ms = int(type(task.template).timeout.total_seconds() * 1000)
    async with reservations.lock(name):
        now = gateway.clock()
        refused = await admit(conn, gateway.state, task, enabled=enabled, now=now,
                              history=history, is_own=is_own,
                              health_config=health_config,
                              reservations=reservations)  # fmt: skip
        if refused is not None:
            return refused
        token = reservations.take(name, now, timeout_ms)
    try:
        return await gateway.run(
            task.template,
            task.params,
            purpose=purpose,
            component=component,
            deadline=deadline,
            check=send_check(gateway.state, health_config),
        )
    finally:
        reservations.release(token)


# ----------------------------------------------------------------------------- builders


INTERNAL = frozenset({IpClass.ASSET.value, IpClass.OWN.value, IpClass.INTERNAL.value})


def _top(fields: Mapping[str, Any], path: str) -> list[str]:
    return [str(v) for v, _ in (fields.get(path) or {}).get("top", [])]


def _when(facts: Mapping[str, Any], name: str) -> datetime | None:
    value = facts.get(name)
    return None if not value else datetime.fromisoformat(str(value))


def _task(template: Template, make: Callable[[], Params]) -> TaskSpec | Refusal:
    try:
        return TaskSpec(template, make())
    except (ValidationError, ValueError) as exc:
        return Refusal("no_subject", type(exc).__name__)


def pair_task(
    facts: Mapping[str, Any],
    fields: Mapping[str, Any],
    ips: Mapping[str, Any],
    now: datetime,
    indices: Sequence[str] | None = None,
) -> TaskSpec | Refusal:
    """The investigation's first internal host and first public destination, over its hours
    ± 1 h (at most 12 h, the newest kept), in one daily index, before the ingest margin; in the
    proxy family the rule's ``indices`` name (the site's first when it has several)."""
    hosts = [v for v in _top(fields, "source.ip") if ips.get(v, {}).get("class") in INTERNAL]
    outside = [v for v in _top(fields, "destination.ip") if ips.get(v, {}).get("class") == "public"]
    first, last = _when(facts, "first_event_at"), _when(facts, "last_event_at")
    if not hosts or not outside or first is None or last is None:
        return Refusal("no_subject")
    span = clamp(first - timedelta(hours=1), last + timedelta(hours=1), now, beacon.PAIR_LONGEST)
    if span is None:
        return Refusal("no_subject", "window")
    return _task(
        beacon.ProxyPair(),
        lambda: beacon.PairParams(
            host=hosts[0],
            destination=outside[0],
            start=span[0],
            end=span[1],
            source=source_param(Role.PROXY, indices),
        ),
    )


def contact_task(
    destination: str,
    now: datetime,
    hosts: Sequence[str] = (),
    day: datetime | None = None,
    indices: Sequence[str] | None = None,
) -> TaskSpec | Refusal:
    """Who reached ``destination`` on ``day`` (UTC; default today, up to the ingest margin):
    01:00 to 22:59 UTC, the part one daily index holds alone."""
    base = (day or now).astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    span = clamp(base, base + timedelta(days=1), now, beacon.CONTACT_LONGEST)
    if span is None:
        return Refusal("no_subject", "window")
    return _task(
        beacon.ProxyContact(),
        lambda: beacon.ContactParams(
            destination=destination,
            hosts=tuple(hosts),
            start=span[0],
            end=span[1],
            source=source_param(Role.PROXY, indices),
        ),
    )


def dns_task(
    host: str, around: datetime, now: datetime, indices: Sequence[str] | None = None
) -> TaskSpec | Refusal:
    """An internal host's lookups in the 2 hours around ``around`` (one daily index)."""
    span = clamp(around - timedelta(hours=1), around + timedelta(hours=1), now, dns.LONGEST)
    if span is None:
        return Refusal("no_subject", "window")
    return _task(
        dns.DnsHostDomains(),
        lambda: dns.DomainsParams(
            ip=host, start=span[0], end=span[1], source=source_param(Role.DNS, indices)
        ),
    )


@dataclass(frozen=True)
class PathPlan:
    task: TaskSpec | Refusal
    left_out: tuple[tuple[str, str], ...]  # (path, why): too common, too long, possibly cut


def paths_task(
    client: str,
    site: str,
    tried: Sequence[str],
    first: datetime,
    now: datetime,
    *,
    from_field_facts: bool = True,
    indices: Sequence[str] | None = None,
) -> PathPlan:
    """Did the paths a client tried on a site succeed, from its first alert for 6 hours?
    Paths every site serves, paths over the family's ``ignore_above`` and (from the
    field facts, whose values are cut at 100 characters) paths that may have been cut are left out,
    each with its reason: their outcome cannot be told."""
    keep: list[str] = []
    left: list[tuple[str, str]] = []
    source = source_param(Role.WEB, indices)
    path_limit = paths.path_chars(source)  # what the family indexes (ignore_above)
    for path in dict.fromkeys(tried):
        if path in paths.COMMON_PATHS:
            left.append((path, "too_common"))
        elif utf16_len(path) > path_limit:
            left.append((path, "too_long"))
        elif from_field_facts and len(path) >= FIELD_VALUE_CHARS:
            left.append((path, "maybe_cut"))
        elif len(keep) < paths.MAX_PATHS:
            keep.append(path)
        else:
            left.append((path, "over_limit"))
    span = clamp(first, first + paths.LONGEST, now, paths.LONGEST)
    if not keep or span is None:
        return PathPlan(Refusal("no_subject"), tuple(left))
    task = _task(
        paths.WebPathOutcomes(),
        lambda: paths.PathParams(
            ip=client,
            site=site,
            paths=tuple(keep),
            start=span[0],
            end=span[1],
            source=source,
        ),
    )
    return PathPlan(task, tuple(left))


def source_task(normalized: Mapping[str, Any], indices: Sequence[str]) -> TaskSpec | Refusal:
    found = source_events.from_alert(normalized, indices)
    if isinstance(found, str):
        return Refusal("no_subject", found)
    return TaskSpec(source_events.LogsSourceEvents(), found)


# ----------------------------------------------------------------------------- reading


def read(
    version: int, task: TaskSpec, ref: Mapping[str, Any], snapshot: Mapping[str, Any] | None
) -> list[SignalValue]:
    """The signals of one batch-1 answer (``ref``: its evidence reference; ``snapshot``: the
    stored snapshot). A refused or failed check gives each signal as unknown, with its
    status as the reason (evidence.derived)."""
    snap = snapshot or {}
    params = task.params
    if isinstance(params, beacon.PairParams):
        return beacon.read_pair(version, params, ref, snap)
    if isinstance(params, beacon.ContactParams):
        return beacon.read_contact(version, params, ref, snap)
    if isinstance(params, dns.DomainsParams):
        return dns.read(version, params, ref, snap)
    if isinstance(params, paths.PathParams):
        return paths.read(version, params, ref, snap)
    if isinstance(params, source_events.SourceParams):
        return source_events.read(version, params, ref, snap)
    raise TypeError(f"{type(task.template).name} is not a batch-1 template")


def is_batch1(ref: Mapping[str, Any]) -> bool:
    """Whether an evidence reference is an answer of one of the five templates (any version)."""
    return str(ref.get("template") or "").rpartition("@")[0] in TEMPLATES


def task_of(ref: Mapping[str, Any]) -> TaskSpec | None:
    """The task a stored evidence reference stands for (its ``template`` as ``name@version``
    and its ``params``), or None when it is not a batch-1 answer of the template versions
    deployed or its parameters no longer validate."""
    name, _, version = str(ref.get("template") or "").rpartition("@")
    cls = TEMPLATES.get(name)
    if cls is None or not version.isdigit() or cls.version != int(version):
        return None
    try:
        params = cls.params_model.model_validate_json(canonical(ref.get("params")))
    except (ValidationError, TypeError, ValueError):
        return None
    return TaskSpec(cls(), params)


def signals(
    version: int, evidence: Mapping[str, Mapping[str, Any]], snapshots: Mapping[str, Any]
) -> list[SignalValue]:
    """The signals of the batch-1 answers among ``evidence`` (references that carry their
    ``params``: the wave's and "Check more"'s). A pack reads one subject per template:
    the first complete answer by task key, else the first by task key, so the same evidence
    always gives the same signals. A reference without readable parameters gives nothing."""
    by: dict[str, list[tuple[str, Mapping[str, Any], TaskSpec]]] = {}
    for key, ref in sorted(evidence.items()):
        task = task_of(ref)
        if task is not None:
            by.setdefault(type(task.template).name, []).append((key, ref, task))
    out: list[SignalValue] = []
    for name in sorted(by):
        group = by[name]
        key, ref, task = next((g for g in group if g[1].get("status") in COMPLETE), group[0])
        out += read(version, task, ref, snapshots.get(key) or {})
    return out


def answers(derived_: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    """Sentences for the note's steps from the derived signals of every batch-1 module."""
    told: dict[str, str] = {}
    for module in (beacon, dns, paths, source_events):
        for step, sentence in module.answers(derived_).items():
            told[step] = f"{told[step]} {sentence}" if step in told else sentence
    return told


# ----------------------------------------------------------------------------- first runs

Run = Callable[[Template, Params], Awaitable[Result]]


async def subjects(conn: AsyncConnection) -> dict[str, Any]:
    """What each first run asks about, from the newest stored alerts: an internal proxy host and
    a public destination (squid), the pair of both from one alert (they talked once at
    least), a web client with its site and paths (nginx), and the newest
    threshold or ES|QL alert with its rule's indices."""
    found: dict[str, Any] = {"host": None, "destination": None, "pair": None, "web": None,
                             "alert": None}  # fmt: skip
    # only the parts read, not whole alerts (in nested or flat form: fields.values reads both)
    rows = await conn.execute(
        text(
            "SELECT jsonb_strip_nulls(jsonb_build_object("
            "'kibana.alert.rule.indices', raw -> 'kibana.alert.rule.indices',"
            " 'source', raw -> 'source', 'source.ip', raw -> 'source.ip',"
            " 'destination', raw -> 'destination', 'destination.ip', raw -> 'destination.ip',"
            " 'url', raw -> 'url', 'url.domain', raw -> 'url.domain', 'url.path',"
            " raw -> 'url.path')) AS raw,"
            " CASE WHEN normalized ->> 'rule_type' IN ('threshold', 'esql') THEN normalized"
            " END AS normalized FROM alert_records WHERE status = 'normalized'"
            " ORDER BY detected_at DESC NULLS LAST, alert_id LIMIT 2000"
        )
    )
    from argus.normalize.fields import values

    for row in rows:
        raw, norm = row.raw or {}, row.normalized or {}
        indices = [str(i) for i in raw.get("kibana.alert.rule.indices") or []]
        squid = reads(indices, Role.PROXY)
        nginx = reads(indices, Role.WEB)
        src = next(iter(values(raw, "source.ip")), None)
        dst = next(iter(values(raw, "destination.ip")), None)
        if squid and found["host"] is None and _private(src):
            found["host"] = str(src)
        if squid and found["destination"] is None and _public(dst):
            found["destination"] = str(dst)
            _remember(found, "destination_source", Role.PROXY, indices)
        if squid and found["pair"] is None and _private(src) and _public(dst):
            found["pair"] = (str(src), str(dst))
            _remember(found, "pair_source", Role.PROXY, indices)
        site = next(iter(values(raw, "url.domain")), None)
        tried = [str(p) for p in values(raw, "url.path")]
        if nginx and found["web"] is None and src and site and tried:
            found["web"] = (str(src), str(site), tried)
            if _remember(found, "web_source", Role.WEB, indices):
                found["web_indices"] = indices
        if found["alert"] is None and norm.get("rule_type") in ("threshold", "esql"):
            found["alert"] = (norm, indices)
        if all(v is not None for v in found.values()):
            break
    return found


def _remember(found: dict[str, Any], key: str, role: Role, indices: Sequence[str]) -> bool:
    """Note which of the site's families of ``role`` the rule of the alert a subject came from
    reads, for the first run's request: only when the site has two or more (a one-family site's
    requests carry no source, and its subjects stay what they were)."""
    named = source_param(role, indices)
    if named is None:
        return False
    found[key] = named
    return True


def _private(value: Any) -> bool:
    try:
        return ipaddress.ip_address(str(value)).is_private
    except ValueError:
        return False


def _public(value: Any) -> bool:
    try:
        return ipaddress.ip_address(str(value)).is_global
    except ValueError:
        return False


def longest(now: datetime, length: timedelta) -> tuple[datetime, datetime] | None:
    """The longest window of ``length`` a one-index template may read now: today's up to the
    ingest margin, or yesterday's last part of its index when today's is shorter."""
    midnight = now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    spans = [clamp(now - timedelta(days=1), now, now, length),
             clamp(midnight - timedelta(days=1), midnight, now, length)]  # fmt: skip
    found = [span for span in spans if span is not None]
    return max(found, key=lambda span: span[1] - span[0], default=None)


def first_task(name: str, who: Mapping[str, Any], now: datetime) -> TaskSpec | Refusal:
    """The one request of a template's first run: as large as the template's production
    builders make it, so its server time says what production will cost:
    ``proxy.pair`` 12 h, ``proxy.contact`` a whole day's index (01:00 to 22:59 UTC),
    ``dns.host_domains`` 2 h, ``web.path_outcomes`` 6 h, each the newest such window in one
    daily index; ``logs.source_events`` the newest threshold or ES|QL alert's own window."""
    if name == "proxy.pair":
        pair, span = who.get("pair"), longest(now, beacon.PAIR_LONGEST)
        if pair is None or span is None:
            return Refusal("no_subject")
        (host, destination), (start, end) = pair, span
        pair_source = who.get("pair_source")
        return _task(
            beacon.ProxyPair(),
            lambda: beacon.PairParams(
                host=host, destination=destination, start=start, end=end, source=pair_source
            ),
        )
    if name == "proxy.contact":
        destination, span = who["destination"], longest(now, beacon.CONTACT_LONGEST)
        if destination is None or span is None:
            return Refusal("no_subject")
        start, end = span
        contact_source = who.get("destination_source")
        return _task(
            beacon.ProxyContact(),
            lambda: beacon.ContactParams(
                destination=destination, start=start, end=end, source=contact_source
            ),
        )
    if name == "dns.host_domains":
        span = longest(now, dns.LONGEST)
        if who["host"] is None or span is None:
            return Refusal("no_subject")
        return dns_task(who["host"], span[0] + dns.LONGEST / 2, now)
    if name == "web.path_outcomes":
        span = longest(now, paths.LONGEST)
        if who["web"] is None or span is None:
            return Refusal("no_subject")
        client, site, tried = who["web"]
        return paths_task(
            client, site, tried, span[0], now, from_field_facts=False,
            indices=who.get("web_indices"),
        ).task  # fmt: skip
    if name == "logs.source_events":
        if who["alert"] is None:
            return Refusal("no_subject")
        return source_task(*who["alert"])
    raise ValueError(f"{name} is not a batch-1 template")


def matched(body: Any) -> bool:
    """Whether an answer found anything at all: an empty answer costs little and measures
    nothing."""
    if not isinstance(body, Mapping):
        return False
    aggs = body.get("aggregations")
    if isinstance(aggs, Mapping):
        counts = [(aggs.get(key) or {}).get("value") for key in ("requests", "queries")]
        return any(isinstance(c, int | float) and not isinstance(c, bool) and c > 0
                   for c in counts)  # fmt: skip
    hits = body.get("hits")
    return isinstance(hits, Mapping) and bool(hits.get("hits"))


def describe(window: Window | None) -> str:
    """A request's window as the first run prints it, with its length (the cost's size)."""
    if window is None:
        return "none"
    minutes = int((window.end - window.start).total_seconds() // 60)
    return (f"{window.source}, {window.start:%Y-%m-%d %H:%M} to {window.end:%H:%M} UTC"
            f" ({minutes // 60} h {minutes % 60:02d} min)")  # fmt: skip


Gate = Callable[[TaskSpec], Awaitable[Refusal | None]]


async def first_run(
    conn: AsyncConnection, run: Run, name: str, now: datetime, gate: Gate | None = None
) -> list[str]:
    """A template's first production run: one request, its server time against its limit.
    ``gate`` is ``admit`` with the template counted as on: every other rule holds for the
    first run too. The last line is FIRST RUN PASSED, FAILED or INCONCLUSIVE (the request
    matched nothing, so it measured nothing); only a pass may switch the template on."""
    if quiet(now):
        busy = site.quiet_hours()
        return [
            f"not now: {busy.start} to {busy.end} UTC is the SIEM's busy time",
            "FIRST RUN FAILED",
        ]
    task = first_task(name, await subjects(conn), now)
    if isinstance(task, Refusal):
        return [f"{name}: {task.sentence} ({task.detail or 'no subject'})", "FIRST RUN FAILED"]
    refused = None if gate is None else await gate(task)
    if refused is not None:
        return [f"{name}: {refused.sentence} ({refused.detail or refused.code})",
                "FIRST RUN FAILED"]  # fmt: skip
    plan = task.template.plan(task.params)
    window = plan.window
    lines = [] if window is None else [f"{name}: {describe(window)}"]
    result = await run(task.template, task.params)
    limit = FIRST_RUN_MS[name]
    slow = result.took_ms > limit
    verdict = ", too slow: it stays off" if slow else ""
    lines.append(f"{name}: {result.took_ms} ms server time (limit {limit} ms){verdict};"
                 f" {_shape(result.body)}")  # fmt: skip
    if slow:
        lines.append("FIRST RUN FAILED")
    elif not matched(result.body):
        lines.append("nothing matched, so this measured nothing; it stays off. Run it again"
                     " when the subject is active.")  # fmt: skip
        lines.append("FIRST RUN INCONCLUSIVE")
    else:
        lines.append("FIRST RUN PASSED")
    return lines


def final_request(task: TaskSpec, targets: Targets, now: datetime) -> FinalRequest:
    """The request the gateway would send for ``task`` (its indices from the window, the
    complete-results parameters, the timeout), checked by the validator; for a dry run and
    for the tests. Raises TemplateRejectedError or UnsupportedValueError."""
    plan = task.template.plan(task.params)
    assert plan.window is not None  # every batch-1 template reads one log source
    family = targets.family(plan.window.source)
    indices = (
        daily_indices(family.prefix, plan.window.start, plan.window.end)
        if family.daily
        else (family.pattern,)
    )
    seconds = max(1, int(type(task.template).timeout.total_seconds()))
    body = {**plan.body, "timeout": f"{seconds}s"}
    params = (*plan.url_params, *FORCED_SEARCH_PARAMS.items())
    final = FinalRequest(plan.spec, indices, None, params, body)
    validate(final)
    return final


def _shape(body: Any) -> str:
    """The answer's size in counts only: no value from the logs is printed."""
    if not isinstance(body, Mapping):
        return "no answer body"
    aggs = body.get("aggregations")
    if isinstance(aggs, Mapping) and aggs:
        parts = []
        for key, node in sorted(aggs.items()):
            if isinstance(node, Mapping) and "buckets" in node:
                parts.append(f"{key} {len(node.get('buckets') or [])} buckets")
            elif isinstance(node, Mapping) and "value" in node:
                parts.append(f"{key} {'set' if node.get('value') is not None else 'none'}")
            elif isinstance(node, Mapping) and "doc_count" in node:
                parts.append(f"{key} {node.get('doc_count')}")
        return ", ".join(parts)
    hits = (body.get("hits") or {}).get("hits") if isinstance(body.get("hits"), Mapping) else None
    return f"{len(hits or [])} rows"
