"""The engine's own evidence for its outbound incidents (D-323), on the checking lane.

The engine presents beaconing incidents whose only facts are its alerts: an analyst cannot tell
a real command server from a popular service one feed flagged. One pass (``argus risk check``,
after the exposure checks) asks the SIEM, for each presented incident of the top bands, the few
questions that decide it:

1. **Which incidents**: live root incidents of ``outbound.bands`` that people see (a case, or
   shown on Today) and that have an outbound alert group: the top band first, then the newest
   material version. An inbound incident keeps E3's checks (``argus.risk.checking``).
2. **What is asked**, once an incident's material version: for its most telling device and
   outside address (a beacon-timed alert group first, then a flagged address, then the newest),
   ``proxy.pair`` (the device's requests to it over ``pair_hours``: their rhythm, count and
   bytes) and ``proxy.contact`` (how many internal devices reached that address that day). An
   incident with no outside address to time, but an internal device and an outside domain or a
   tunnel suspicion, gets ``dns.host_domains`` (the device's lookups around its last alert).
   Only an outside address is timed (the proxy logs say nothing of inside-to-inside traffic). An
   address ARGUS's own alerts already show with 25 internal devices is answered from the store
   ("too common to ask about"); an answer about the same subject and day at most
   ``reuse_hours`` old is reused for another incident or version, with no request. A count of
   a day still going on is a count so far: it is asked again, once, after that day is over.
3. **The limits**: only the templates the evidence switch holds (``enrichment.templates``); not
   in the quiet hours and only while the SIEM is NORMAL (the gateway's own check holds it
   during waits too); at most ``pass_requests`` a pass and ``day_requests`` a day, each heavy;
   before each, this lane's share of the day (``outbound.day_ms``) and the checking lane's whole
   day (``exposure.day_ms``) must hold the request's full timeout, and the template's own
   90 s a day must not be spent. A refusal or a struggling SIEM ends the pass's requests (the
   answers it reuses are still stored); a request the SIEM could not answer is stored as
   unknown and asked again after ``recheck_hours``.
4. **What it changes**: the answers are stored (``risk_evidence``) and the incident's
   alert groups are marked for the engine's next pass, which reads them as signals
   (:func:`argus.risk.outbound_db.attach`): a measured regular rhythm is a beacon fact, a
   destination no other internal device reached a rare one. Those can only add to a score. What
   speaks against the incident (no regular timing, a destination many devices reach) shows as
   a check, an alternative that fits and so the certainty word, never as a lower priority
   (``argus.risk.alternatives``).
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime, timedelta
from typing import Any, Literal, Protocol

from sqlalchemy.ext.asyncio import AsyncEngine

from argus.context import batch1, beacon, dns
from argus.context.bounds import clamp, iso
from argus.context.packs import TaskSpec
from argus.gateway import health as health_core
from argus.gateway.errors import (
    GatewayError,
    RefusedError,
    SourceMissingError,
    TemplateRejectedError,
    UnsupportedValueError,
)
from argus.gateway.gateway import Result, SendCheck
from argus.gateway.health import HealthConfig
from argus.gateway.templates import Params, Purpose, Template, plan_key
from argus.risk import alternatives as alt
from argus.risk import checking
from argus.risk.config import Outbound
from argus.site import Role, source_param

log = logging.getLogger("argus.risk.outbound")
COMPONENT = "checking-evidence"  # the ledger's component: this lane's share is counted by it
TEMPLATES = frozenset({"proxy.pair", "proxy.contact", "dns.host_domains"})
BANDS = ("P1", "P2", "P3", "P4")
AFTER = timedelta(minutes=30)  # a pair window reaches past the device's last alert by this
DEADLINE = checking.DEADLINE
COMMON_HOSTS = batch1.HOSTS_LIMIT  # ARGUS's own alerts show this many internal devices: common
Kind = Literal["pair", "contact", "dns"]
KIND_OF: Mapping[str, Kind] = {"proxy.pair": "pair", "proxy.contact": "contact",
                               "dns.host_domains": "dns"}  # fmt: skip
# what a struggling SIEM's error says, and what is wrong with one request only
ONE_REQUEST = (SourceMissingError, TemplateRejectedError, UnsupportedValueError)


class Sender(Protocol):
    """What the pass needs of the gateway (``argus.gateway.gateway.Gateway``)."""

    async def run(self, template: Template, params: Params, *, purpose: Purpose, component: str,
                  deadline: datetime, check: SendCheck | None = None) -> Result: ...  # fmt: skip


# --------------------------------------------------------------------------- inputs


@dataclass(frozen=True)
class Pair:
    """An internal device and an outside address one of the incident's outbound alert groups names
    together: when it last did, and whether that group was beacon-timed or the address flagged."""

    device: str
    destination: str
    at: datetime
    beat: bool = False
    flagged: bool = False


@dataclass(frozen=True)
class Target:
    """A presented engine incident the pass may check."""

    id: int
    version: int
    band: str
    priority: int
    material_at: datetime | None
    last_seen: datetime
    pairs: tuple[Pair, ...] = ()  # most telling first
    devices: tuple[str, ...] = ()  # internal actor addresses of its outbound groups, newest first
    domains: bool = False  # its outbound groups name an outside domain
    tunnel: bool = False  # a DNS tunnel suspicion is among its evidence

    def order(self) -> tuple[Any, ...]:
        """Top band first, then the newest material version, the higher priority, the id."""
        newest = self.material_at or self.last_seen
        rank = BANDS.index(self.band) if self.band in BANDS else len(BANDS)
        return (rank, -newest.timestamp(), -self.priority, self.id)


def ranked(pairs: Iterable[Pair]) -> list[Pair]:
    """One entry per (device, address), its newest sighting; beacon-timed first, then flagged,
    then the newest."""
    best: dict[tuple[str, str], Pair] = {}
    for p in pairs:
        key = (p.device, p.destination)
        held = best.get(key)
        if held is None:
            best[key] = p
        else:
            best[key] = replace(held, at=max(held.at, p.at), beat=held.beat or p.beat,
                                flagged=held.flagged or p.flagged)  # fmt: skip
    return sorted(best.values(), key=lambda p: (not p.beat, not p.flagged, -p.at.timestamp(),
                                                p.device, p.destination))  # fmt: skip


@dataclass(frozen=True)
class Stored:
    """One stored answer (``risk_evidence``)."""

    incident: int
    version: int
    kind: Kind
    subject: str
    device: str | None
    destination: str | None
    day: date
    verdict: str
    facts: Mapping[str, Any]
    checked_at: datetime

    def measured(self) -> alt.Measured:
        return alt.Measured(self.kind, self.verdict, self.device, self.destination, self.facts)


@dataclass
class Inputs:
    targets: list[Target] = field(default_factory=list)
    done: set[tuple[int, int, str, str]] = field(default_factory=set)  # incident, version, ...
    reusable: dict[tuple[str, str, date], Stored] = field(default_factory=dict)  # kind, subject


def subject(kind: Kind, device: str | None, destination: str | None) -> str:
    if kind == "pair":
        return f"{device} {destination}"
    return str(destination if kind == "contact" else device)


@dataclass(frozen=True)
class Ask:
    """One check of a pass: a request, or an answer that needs none (reused, or the store's)."""

    target: Target
    kind: Kind
    device: str | None
    destination: str | None
    day: date
    task: TaskSpec | None = None
    reuse: Stored | None = None

    @property
    def subject(self) -> str:
        return subject(self.kind, self.device, self.destination)

    @property
    def name(self) -> str:
        assert self.task is not None
        return type(self.task.template).name

    @property
    def timeout_ms(self) -> int:
        if self.task is None:
            return 0
        return int(type(self.task.template).timeout.total_seconds() * 1000)


# --------------------------------------------------------------------------- planning (pure)


def pair_window(at: datetime, now: datetime, config: Outbound) -> tuple[datetime, datetime] | None:
    """The ``pair_hours`` up to just after the device's last alert naming the address, in one
    daily index and before the ingest margin (1-minute buckets up to 6 hours)."""
    length = timedelta(hours=config.pair_hours)
    return clamp(at + AFTER - length, at + AFTER, now, min(length, beacon.PAIR_LONGEST))


def _pair_task(p: Pair, span: tuple[datetime, datetime]) -> TaskSpec | None:
    """The pair's request, or None when its parameters are refused (the same two addresses)."""
    try:
        params = beacon.PairParams(host=p.device, destination=p.destination, start=span[0],
                                   end=span[1], source=source_param(Role.PROXY, None))  # fmt: skip
    except ValueError:
        return None
    return TaskSpec(beacon.ProxyPair(), params)


def plan(inputs: Inputs, now: datetime, config: Outbound, enabled: frozenset[str]) -> list[Ask]:
    """The checks of one pass, most telling first (not yet cut to the pass's limits)."""
    asks: list[Ask] = []
    planned: set[tuple[int, int, str, str]] = set()

    def due(t: Target, kind: Kind, device: str | None, destination: str | None) -> bool:
        key = (t.id, t.version, kind, subject(kind, device, destination))
        if key in inputs.done or key in planned:
            return False
        planned.add(key)
        return True

    def reused(kind: Kind, device: str | None, destination: str | None,
               day: date) -> Stored | None:  # fmt: skip
        return inputs.reusable.get((kind, subject(kind, device, destination), day))

    for t in sorted(inputs.targets, key=Target.order):
        if t.band not in config.bands:
            continue
        chosen = ranked(t.pairs)[: config.pairs]
        for p in chosen:
            if "proxy.pair" in enabled and due(t, "pair", p.device, p.destination):
                span = pair_window(p.at, now, config)
                if span is not None and span[1] > p.at - timedelta(hours=config.pair_hours):
                    day = span[1].astimezone(UTC).date()
                    held = reused("pair", p.device, p.destination, day)
                    task = None if held else _pair_task(p, span)
                    if held or task:
                        asks.append(Ask(t, "pair", p.device, p.destination, day, task, held))
        for dst, at in _destinations(chosen):
            if "proxy.contact" in enabled and due(t, "contact", None, dst):
                day = at.astimezone(UTC).date()
                held = reused("contact", None, dst, day)
                made = None if held else batch1.contact_task(dst, now, day=at)
                task = made if isinstance(made, TaskSpec) else None
                if held or task:
                    asks.append(Ask(t, "contact", None, dst, day, task, held))
        if not chosen and t.devices and (t.domains or t.tunnel) and "dns.host_domains" in enabled:
            device = t.devices[0]
            if due(t, "dns", device, None):
                around = min(t.last_seen, now)
                made = batch1.dns_task(device, around, now)
                if isinstance(made, TaskSpec):
                    assert isinstance(made.params, dns.DomainsParams)
                    day = made.params.end.astimezone(UTC).date()
                    held = reused("dns", device, None, day)
                    asks.append(Ask(t, "dns", device, None, day, None if held else made, held))
    return asks


def outside_only(targets: Iterable[Target], is_own: Callable[[str], bool]) -> list[Target]:
    """The targets with only their pairs to an outside address: the proxy logs say nothing of a
    device's traffic to another internal address."""
    return [replace(t, pairs=tuple(p for p in t.pairs if not is_own(p.destination)))
            for t in targets]  # fmt: skip


def _destinations(pairs: Sequence[Pair]) -> list[tuple[str, datetime]]:
    out: dict[str, datetime] = {}
    for p in pairs:
        out[p.destination] = max(out.get(p.destination, p.at), p.at)
    return list(out.items())


# --------------------------------------------------------------------------- reading answers


def _aggs(body: Any) -> Mapping[str, Any]:
    aggs = body.get("aggregations") if isinstance(body, Mapping) else None
    return aggs if isinstance(aggs, Mapping) else {}


def _value(aggs: Mapping[str, Any], name: str) -> int | None:
    node = aggs.get(name)
    value = node.get("value") if isinstance(node, Mapping) else None
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return int(value)


def _at(value: int | None) -> str | None:
    return None if value is None else iso(datetime.fromtimestamp(value / 1000, UTC))


def read_pair(params: beacon.PairParams, body: Any) -> tuple[str, dict[str, Any]]:
    """The verdict and facts of a ``proxy.pair`` answer: ``regular`` (a rhythm the template's
    strict test calls regular), ``irregular`` (enough requests, no rhythm), ``few`` (too few
    to tell) or ``none`` (no request in the window)."""
    aggs = _aggs(body)
    got = beacon.cadence(aggs, params.start, params.end)
    requests = got.requests or 0
    if got.period is not None:
        verdict = "regular"
    elif got.regular_share is not None:
        verdict = "irregular"
    else:
        verdict = "few" if requests > 0 else "none"
    hours = round((params.end - params.start).total_seconds() / 3600, 1)
    facts = {
        "requests": requests, "beats": got.beats,
        "period_s": None if got.period is None else int(got.period.total_seconds()),
        "jitter_s": None if got.jitter is None else int(got.jitter.total_seconds()),
        "regular_share": got.regular_share, "bytes": _value(aggs, "bytes"),
        "first": None if got.first is None else iso(got.first),
        "last": None if got.last is None else iso(got.last),
        "still_active": got.still_active, "hours": f"{hours:g}",
        "window": [iso(params.start), iso(params.end)],
        "day": params.end.astimezone(UTC).date().isoformat(),
    }  # fmt: skip
    return verdict, facts


def whole_day(params: beacon.ContactParams) -> bool:
    """Whether a contact window holds its day's whole index (01:00 to 22:59 UTC), not a day
    still going on: a count so far may be the device's own requests alone."""
    day = params.start.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    full = clamp(day, day + timedelta(days=1), day + timedelta(days=2), beacon.CONTACT_LONGEST)
    return full is not None and params.end >= full[1]


def read_contact(params: beacon.ContactParams, body: Any, device: str | None = None
                 ) -> tuple[str, dict[str, Any]]:  # fmt: skip
    """``common`` (at least ``alternatives.COMMON`` internal devices that day), ``rare`` (at most
    ``alternatives.RARE``), ``some`` between, ``none`` (no request at all). ``complete``: the
    window held the whole day; a day still going on is asked again once it is over."""
    aggs = _aggs(body)
    count, listed = beacon.contacts(aggs)
    devices = count or 0
    if devices <= 0:
        verdict = "none"
    elif devices >= alt.COMMON:
        verdict = "common"
    elif devices <= alt.RARE:
        verdict = "rare"
    else:
        verdict = "some"
    facts = {
        "devices": devices, "requests": _value(aggs, "requests"),
        "first": _at(_value(aggs, "first")), "last": _at(_value(aggs, "last")),
        "day": params.start.astimezone(UTC).date().isoformat(),
        "window": [iso(params.start), iso(params.end)],
        "with_device": None if device is None else any(c.host == device for c in listed),
        "complete": whole_day(params),
    }  # fmt: skip
    return verdict, facts


def read_dns(params: dns.DomainsParams, body: Any) -> tuple[str, dict[str, Any]]:
    """``tunnel`` (most rarely asked names under one parent, carrying data), ``plain`` or
    ``none`` (no lookup)."""
    got = dns.lookups(_aggs(body))
    queries = got.queries or 0
    verdict = "tunnel" if got.tunnel_parent else ("plain" if queries > 0 else "none")
    facts = {"lookups": queries, "names": got.names, "tunnel_parent": got.tunnel_parent,
             "window": [iso(params.start), iso(params.end)],
             "day": params.end.astimezone(UTC).date().isoformat()}  # fmt: skip
    return verdict, facts


def read(ask: Ask, result: Result) -> tuple[str, dict[str, Any]]:
    assert ask.task is not None
    params = ask.task.params
    if isinstance(params, beacon.PairParams):
        return read_pair(params, result.body)
    if isinstance(params, beacon.ContactParams):
        return read_contact(params, result.body, _device_of(ask))
    if isinstance(params, dns.DomainsParams):
        return read_dns(params, result.body)
    raise TypeError(f"{ask.name} is not a check of the engine's evidence")


@dataclass(frozen=True)
class Row:
    """One answer, ready to store."""

    incident: int
    version: int
    kind: Kind
    subject: str
    device: str | None
    destination: str | None
    day: date
    template: str
    template_version: int
    task_key: str | None
    verdict: str
    facts: Mapping[str, Any]
    took_ms: int | None  # None: no request (reused, or the store's)


def row_of(ask: Ask, verdict: str, facts: Mapping[str, Any], took_ms: int | None) -> Row:
    if ask.task is not None:
        cls = type(ask.task.template)
        name, version = cls.name, cls.version
        key: str | None = plan_key(ask.task.template.plan(ask.task.params), ask.task.params)
    else:
        name = {"pair": "proxy.pair", "contact": "proxy.contact", "dns": "dns.host_domains"}[
            ask.kind]  # fmt: skip
        version = batch1.TEMPLATES[name].version
        key = None
    return Row(ask.target.id, ask.target.version, ask.kind, ask.subject, ask.device,
               ask.destination, ask.day, name, version, key, verdict, dict(facts),
               took_ms)  # fmt: skip


def reused_row(ask: Ask) -> Row:
    assert ask.reuse is not None
    facts = {**ask.reuse.facts, "reused_from": ask.reuse.incident}
    return row_of(ask, ask.reuse.verdict, facts, None)


def common_row(ask: Ask, seen: batch1.Prevalence) -> Row:
    """An address ARGUS's own alerts already show with many internal devices: too common to ask
    about, and a common service's shape (no request)."""
    facts = {"devices": seen.own_hosts, "investigations": seen.investigations,
             "from": "argus", "day": ask.day.isoformat()}  # fmt: skip
    return row_of(ask, "common", facts, None)


def unknown_row(ask: Ask, reason: str) -> Row:
    return row_of(ask, "unknown", {"reason": reason[:200], "day": ask.day.isoformat()}, None)


# --------------------------------------------------------------------------- the pass


@dataclass
class Report:
    planned: int = 0
    sent: int = 0
    reused: int = 0
    from_store: int = 0
    failed: int = 0
    stored: int = 0
    incidents: int = 0  # incidents whose alert groups were marked for the engine
    spent_ms: int = 0  # this lane share's server time today, this pass's included
    requests_today: int = 0
    pruned: int = 0
    stopped: str | None = None
    by_kind: dict[str, int] = field(default_factory=dict)

    def line(self) -> str:
        kinds = ", ".join(f"{k} {v}" for k, v in sorted(self.by_kind.items())) or "none"
        why = f"; stopped: {self.stopped}" if self.stopped else ""
        return (
            f"incident evidence: {self.planned} checks planned, {self.sent} sent ({kinds}),"
            f" {self.reused} reused, {self.from_store} from ARGUS's own alerts, {self.failed}"
            f" failed, {self.stored} answers stored, {self.incidents} incidents marked for the"
            f" engine; {self.requests_today} requests and {self.spent_ms / 1000:.1f} s of server"
            f" time today{why}"
        )


@dataclass(frozen=True)
class Spent:
    """Today's (UTC) use: this share's requests and server time, and the whole lane's time."""

    requests: int = 0
    ms: int = 0
    lane_ms: int = 0


@dataclass
class Budget:
    """What may still be sent in this pass (see the module, 3)."""

    config: Outbound
    lane_day_ms: int
    spent: Spent
    sent: int = 0
    ms: int = 0  # this pass's server time, a failure counted at its full timeout

    def refuses(self, ask: Ask) -> str | None:
        c = self.config
        if self.sent >= c.pass_requests:
            return "the pass's request limit"
        if self.spent.requests + self.sent >= c.day_requests:
            return "today's requests for the incidents' evidence are used up"
        if self.spent.ms + self.ms + ask.timeout_ms > c.day_ms:
            return "today's server time for the incidents' evidence is used up"
        if self.spent.lane_ms + self.ms + ask.timeout_ms > self.lane_day_ms:
            return "the checking lane's server time for today is used up"
        return None


async def run_pass(
    engine: AsyncEngine, gateway: Sender, health: Callable[[], Any], *, now: datetime,
    config: Outbound, lane_day_ms: int, enabled: Iterable[str], clock: Callable[[], datetime],
    is_own: Callable[[str], bool], history: timedelta,
    health_config: HealthConfig | None = None, check: SendCheck | None = None,
) -> Report:  # fmt: skip
    """One pass (see the module). ``health``: the gateway's stored health memory (awaitable);
    ``enabled``: the evidence switch; ``is_own`` and ``history``: the prevalence read of
    ARGUS's own alerts; ``check``: the gateway's send rule (``batch1.send_check``)."""
    from argus.risk import outbound_db as db

    report = Report()
    async with engine.begin() as conn:
        report.pruned = await db.prune(conn, now, config)
    on = frozenset(enabled) & TEMPLATES
    if not on or config.pass_requests == 0 or config.day_requests == 0:
        report.stopped = "no evidence check is switched on (enrichment.templates, outbound)"
        return report
    memory = health_core.effective(await health(), now, health_config or HealthConfig())
    why = checking.allowed(memory, now)
    if why is not None:
        report.stopped = why
        return report
    async with engine.connect() as conn:
        found = await db.inputs(conn, now, config)
        spent = await db.spent_today(conn, now, COMPONENT)
    found.targets = outside_only(found.targets, is_own)
    asks = plan(found, now, config, on)
    report.planned = len(asks)
    budget = Budget(config, lane_day_ms, spent)
    rows: list[Row] = []
    over: set[str] = set()  # templates whose own day is spent
    for ask in asks:
        if ask.reuse is not None:  # no request: stored even after the pass stopped sending
            rows.append(reused_row(ask))
            report.reused += 1
            continue
        assert ask.task is not None
        if ask.kind == "contact" and ask.destination is not None:
            async with engine.connect() as conn:
                seen = await batch1.prevalence(
                    conn, batch1.Key("destination", ask.destination), now - history, is_own
                )
            if seen.own_hosts >= COMMON_HOSTS:
                rows.append(common_row(ask, seen))
                report.from_store += 1
                continue
        if report.stopped is not None or ask.name in over:  # a request: not after a stop
            continue
        refused = budget.refuses(ask)
        if refused is not None:
            report.stopped = refused
            continue
        async with engine.connect() as conn:
            if await batch1.spent_today(conn, ask.name, now) >= batch1.DAILY_CAP_MS:
                over.add(ask.name)
                continue
        try:
            result = await gateway.run(
                ask.task.template, ask.task.params, purpose=Purpose.CHECK, component=COMPONENT,
                deadline=clock() + DEADLINE, check=check,
            )  # fmt: skip
        except ONE_REQUEST as exc:  # this request alone: stored as unknown, the pass goes on
            rows.append(unknown_row(ask, f"the SIEM refused this request ({type(exc).__name__})"))
            report.failed += 1
            continue
        except RefusedError as exc:
            report.stopped = f"refused: {exc}"
            continue
        except GatewayError as exc:  # sent and failed: its server time is the ledger's
            budget.sent += 1
            budget.ms += ask.timeout_ms
            report.failed += 1
            rows.append(unknown_row(ask, f"the SIEM did not answer ({type(exc).__name__})"))
            log.warning("incident evidence: %s failed (%s)", ask.name, type(exc).__name__)
            if checking.struggling(exc):
                report.stopped = (f"the SIEM did not answer in full ({type(exc).__name__});"
                                  " the next pass tries again")  # fmt: skip
            continue
        budget.sent += 1
        budget.ms += max(result.took_ms, 0)
        report.sent += 1
        report.by_kind[ask.kind] = report.by_kind.get(ask.kind, 0) + 1
        verdict, facts = read(ask, result)
        rows.append(row_of(ask, verdict, facts, max(result.took_ms, 0)))
    report.spent_ms = spent.ms + budget.ms
    report.requests_today = spent.requests + budget.sent
    async with engine.begin() as conn:
        report.stored = await db.save(conn, rows, now)
        changed = sorted({r.incident for r in rows if r.verdict != "unknown"})
        await db.touch(conn, changed)
        report.incidents = len(changed)
    return report


def _device_of(ask: Ask) -> str | None:
    """The incident's device the contact check is about (its timed pair's), if any."""
    for p in ask.target.pairs:
        if p.destination == ask.destination:
            return p.device
    return None
