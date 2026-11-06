"""The checking lane (P4-F E3): the incident engine's few targeted SIEM checks, on their own
gateway lane (``checking``: NORMAL only, never in the quiet hours, about 10 minutes of server
time a day), for exposure candidates only.

One pass (``argus risk check``):

1. **Nothing** is planned in the quiet hours or unless the SIEM is NORMAL; only the templates
   ``exposure.templates`` switches on are asked (none by default).
2. **Site lookup**, at most once every ``lookup_every_minutes``: the outside addresses of recent
   inbound alert groups whose site is unknown (no target in their alerts, no stored web
   evidence, no lookup yet), at most 50 in **one** request (``web.source_sites``).
3. **Checks of the candidates**: an outside address that got a 2xx from a campus site for a
   sensitive path (its stored web evidence), or that the lookup found with a 2xx: the site's
   soft-404 check (``web.catchall``, once a site and day), what the address took
   (``web.bulk_take``, when it got many answers or only the lookup knows it) and the outcome
   of its sensitive paths (``web.path_outcomes``). The most telling candidates first.
   Each check reads the daily index that holds the scan's start (never the next day's, whose
   index starts at 01:00 and holds other hours), and a check whose window would not overlap
   the scan is not sent.
4. Every request goes through the gateway (``Purpose.CHECK``); before each, the lane's own day
   cap (``exposure.day_ms``) must hold the request's whole timeout, so the lane never spends
   more than its cap. A refusal (health, quiet hours, the lane's budget, a kill switch) or a
   SIEM that did not answer in full (a timeout, a partial result, overload) ends the pass;
   nothing is retried in it.
5. The answers are stored (``exposure_checks``, 180 days) and the alert groups they change are
   marked for the engine's next pass, which turns them into facts on the sites (L5).
"""

from __future__ import annotations

import contextlib
import logging
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any, Protocol

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus import site
from argus.context import batch1, bounds, paths
from argus.context.bounds import clamp
from argus.context.packs import TaskSpec
from argus.gateway import health as health_core
from argus.gateway.errors import GatewayError, RefusedError, ResponseError, SiemError
from argus.gateway.gateway import Result
from argus.gateway.health import HealthConfig, HealthMemory, HealthState
from argus.gateway.indices import PAD
from argus.gateway.templates import Params, Purpose, Template, plan_key
from argus.risk import exposure, exposure_db, webchecks
from argus.risk.config import Exposure
from argus.risk.exposure_db import Found
from argus.site import Role

log = logging.getLogger("argus.risk.checking")
COMPONENT = "checking"
MARGIN = timedelta(minutes=15)
DEADLINE = timedelta(seconds=90)  # a request's own deadline, budget waits included
FIRST_RUN_MS = {**webchecks.FIRST_RUN_MS, "web.path_outcomes": batch1.FIRST_RUN_MS[
    "web.path_outcomes"]}  # fmt: skip
TEMPLATES = frozenset(FIRST_RUN_MS)
PATH_CHARS = 512  # a path as stored in a check's facts


class Sender(Protocol):
    """What the pass needs of the gateway (``argus.gateway.gateway.Gateway``)."""

    async def run(self, template: Template, params: Params, *, purpose: Purpose, component: str,
                  deadline: datetime) -> Result: ...  # fmt: skip


# --------------------------------------------------------------------------- inputs


@dataclass
class Pair:
    """An outside address on a campus site, on one UTC day: what the stored evidence, the lookup
    and earlier take checks say it got."""

    source: str
    site: str
    day: date
    first_at: datetime
    last_at: datetime
    paths: dict[str, int] = field(default_factory=dict)  # 2xx path -> answers
    rows: int = 0  # stored 2xx answers (the follow-up search keeps at most 20)
    lookup_ok: bool | None = False  # the lookup: a 2xx between them is likely (None: maybe)
    origin: str = "evidence"


@dataclass(frozen=True)
class Pending:
    """An outside address of an inbound alert group whose site is unknown."""

    source: str
    first_at: datetime
    last_at: datetime


@dataclass
class Inputs:
    pairs: list[Pair] = field(default_factory=list)
    pending: list[Pending] = field(default_factory=list)
    done: set[tuple[str, str, str, date]] = field(default_factory=set)
    last_lookup: datetime | None = None
    rare: frozenset[str] = frozenset()  # rare 2xx paths (as files) of the window
    sources_of: dict[tuple[str, date], set[str]] = field(default_factory=dict)  # site, day


@dataclass(frozen=True)
class Ask:
    kind: str  # sites | catchall | paths | take
    task: TaskSpec
    day: date
    source: str | None = None
    site: str | None = None
    touches: tuple[str, ...] = ()  # the outside addresses whose groups its answer changes
    rare: tuple[str, ...] = ()  # (paths) the asked paths that are rare

    @property
    def name(self) -> str:
        return type(self.task.template).name

    @property
    def timeout_ms(self) -> int:
        return int(type(self.task.template).timeout.total_seconds() * 1000)


# --------------------------------------------------------------------------- planning (pure)


def _day_window(first: datetime, last: datetime, now: datetime,
                longest: timedelta) -> tuple[datetime, datetime] | None:  # fmt: skip
    return clamp(first - MARGIN, last + MARGIN, now, longest)


def held_to(start: datetime, now: datetime) -> datetime:
    """``now``, held back so a window from ``start`` stays in the daily index that holds its
    first readable minute: ``clamp`` keeps the index that holds a window's end, so a window
    asked the next day would read that day's index from 01:00 instead of the scan (23:00 to
    00:59 is read from the next day's index)."""
    day = (start.astimezone(UTC) + PAD).date()
    last = datetime(day.year, day.month, day.day, tzinfo=UTC) + timedelta(days=1) - PAD
    return min(now, last - timedelta(minutes=1) + bounds.MARGIN)


def anchored(start: datetime, end: datetime, now: datetime,
             longest: timedelta) -> tuple[datetime, datetime] | None:  # fmt: skip
    """The part of [start, end) a one-index check may read now, in the index of its start."""
    return clamp(start, end, held_to(start, now), longest)


def overlaps(span: tuple[datetime, datetime] | None, first: datetime, last: datetime) -> bool:
    """Whether a window read anything of the scan [first, last] (else it cannot answer)."""
    return span is not None and span[0] <= last and span[1] > first


def _site_window(pairs: Sequence[Pair], now: datetime) -> tuple[datetime, datetime] | None:
    """The soft-404 check's window of one site and day: the readable window from one of its
    scans' start (``SITE_WINDOW`` long) that overlaps the most of its scans (the earliest of
    equals), so it sees as many probes as it can."""
    best: tuple[int, float] | None = None
    chosen = None
    for begin in sorted({p.first_at - MARGIN for p in pairs}):
        span = anchored(begin, begin + webchecks.SITE_WINDOW, now, webchecks.SITE_WINDOW)
        held = sum(overlaps(span, p.first_at, p.last_at) for p in pairs)
        if span is None or not held:
            continue
        rank = (held, -begin.timestamp())
        if best is None or rank > best:
            best, chosen = rank, span
    return chosen


def _sensitive(pair: Pair, config: Exposure) -> list[str]:
    found = [p for p in pair.paths if exposure.sensitive(p, config.sensitive)]
    return sorted(found, key=lambda p: (-pair.paths[p], p))


def priority(pair: Pair, config: Exposure) -> tuple[Any, ...]:
    """The most telling candidates first: more sensitive paths that got a 2xx, more answers,
    then the newest."""
    return (-len(_sensitive(pair, config)), -pair.rows, -pair.last_at.timestamp(), pair.source,
            pair.site)  # fmt: skip


def candidates(inputs: Inputs, now: datetime, config: Exposure) -> list[Pair]:
    """The pairs worth checking: recent, and a 2xx for a sensitive path, or a lookup's 2xx."""
    since = now - timedelta(hours=config.candidate_hours)
    out = []
    for pair in inputs.pairs:
        if pair.last_at < since:
            continue
        if _sensitive(pair, config) or (pair.origin == "lookup" and pair.lookup_ok is not False):
            out.append(pair)
    return sorted(out, key=lambda p: priority(p, config))


def _task(template: Template, model: type[Params], **values: Any) -> TaskSpec | None:
    """The request, or None when its parameters are refused (a site or path too long)."""
    with contextlib.suppress(ValueError):
        return TaskSpec(template, model(**values))
    return None


def plan(inputs: Inputs, now: datetime, config: Exposure,
         enabled: frozenset[str]) -> list[Ask]:  # fmt: skip
    """The requests of one pass, most telling first (not yet cut to the pass's limit)."""
    asks: list[Ask] = []
    every = timedelta(minutes=config.lookup_every_minutes)
    lookup_due = inputs.last_lookup is None or now - inputs.last_lookup >= every
    if "web.source_sites" in enabled and lookup_due and inputs.pending:
        newest = max(inputs.pending, key=lambda p: (p.last_at, p.source))
        day = newest.last_at.astimezone(UTC).date()
        same = sorted((p for p in inputs.pending if p.last_at.astimezone(UTC).date() == day),
                      key=lambda p: (-p.last_at.timestamp(), p.source))  # fmt: skip
        chosen: dict[str, Pending] = {}
        for p in same:
            if len(chosen) < webchecks.MAX_SOURCES:
                chosen.setdefault(p.source, p)
        span = _day_window(min(p.first_at for p in chosen.values()),
                           max(p.last_at for p in chosen.values()), now, webchecks.DAY)  # fmt: skip
        if span is not None:
            ips = tuple(sorted(chosen))
            task = _task(webchecks.WebSourceSites(), webchecks.SitesParams, ips=ips,
                         start=span[0], end=span[1], source=_web_source())  # fmt: skip
            if task is not None:  # stored on the day the groups are looked up by
                asks.append(Ask("sites", task, day, touches=ips))
    planned: set[tuple[str, str, str, date]] = set()

    def due(kind: str, source: str, site_: str, day: date) -> bool:
        key = (kind, source, site_, day)
        if key in inputs.done or key in planned:
            return False
        planned.add(key)
        return True

    pairs = candidates(inputs, now, config)
    probes: dict[tuple[str, date], dict[str, int]] = defaultdict(dict)
    scans: dict[tuple[str, date], list[Pair]] = defaultdict(list)
    for pair in pairs:
        for path in _sensitive(pair, config):
            held = probes[(pair.site, pair.day)]
            held[path] = held.get(path, 0) + 1
        if _sensitive(pair, config):
            scans[(pair.site, pair.day)].append(pair)
    for pair in pairs:
        sens = _sensitive(pair, config)
        key_sd = (pair.site, pair.day)
        if "web.catchall" in enabled and probes[key_sd] and due("catchall", "", pair.site,
                                                                pair.day):  # fmt: skip
            tried = sorted(probes[key_sd], key=lambda p: (-probes[key_sd][p], p))
            tried = [p for p in tried if len(p) <= paths.path_chars(_web_source())]
            span = _site_window(scans[key_sd], now)  # the site's answers around its scans
            if span is not None and tried:
                task = _task(webchecks.WebCatchall(), webchecks.CatchallParams, site=pair.site,
                             paths=tuple(tried[: webchecks.MAX_PROBES]), start=span[0],
                             end=span[1], source=_web_source())  # fmt: skip
                if task is not None:
                    who = tuple(sorted(inputs.sources_of.get(key_sd, {pair.source})))
                    asks.append(Ask("catchall", task, pair.day, None, pair.site, who))
        many = pair.rows >= config.take_hint or (pair.origin == "lookup" and not sens)
        if "web.bulk_take" in enabled and many and due("take", pair.source, pair.site, pair.day):
            span = anchored(pair.first_at - MARGIN, pair.last_at + timedelta(hours=6) + MARGIN,
                            now, webchecks.DAY)  # fmt: skip
            if span is not None and overlaps(span, pair.first_at, pair.last_at):
                task = _task(webchecks.WebBulkTake(), webchecks.TakeParams, ip=pair.source,
                             site=pair.site, start=span[0], end=span[1],
                             source=_web_source())  # fmt: skip
                if task is not None:
                    asks.append(Ask("take", task, pair.day, pair.source, pair.site,
                                    (pair.source,)))  # fmt: skip
        if "web.path_outcomes" in enabled and sens and due("paths", pair.source, pair.site,
                                                            pair.day):  # fmt: skip
            begin = pair.first_at - MARGIN
            made = batch1.paths_task(pair.source, pair.site, sens, begin, held_to(begin, now),
                                     from_field_facts=False)  # fmt: skip
            asked = made.task.params if isinstance(made.task, TaskSpec) else None
            if isinstance(asked, paths.PathParams) and overlaps(
                (asked.start, asked.end), pair.first_at, pair.last_at
            ):
                assert isinstance(made.task, TaskSpec)
                rare = tuple(p for p in asked.paths if paths.same_file(p) in inputs.rare)
                asks.append(Ask("paths", made.task, pair.day, pair.source, pair.site,
                                (pair.source,), rare))  # fmt: skip
    return asks


def _web_source() -> str | None:
    families = site.active().of_role(Role.WEB)
    return None if len(families) < 2 else families[0].name


# --------------------------------------------------------------------------- reading answers


def _cut(path: str) -> str:
    return path[:PATH_CHARS]


def found_of(ask: Ask, result: Result, config: Exposure) -> list[Found]:
    """The stored rows of one answer."""
    name, version = ask.name, type(ask.task.template).version
    key = plan_key(ask.task.template.plan(ask.task.params), ask.task.params)
    params = ask.task.params
    body = result.body

    def row(kind: str, source: str | None, site_: str | None, verdict: str,
            facts: Mapping[str, Any]) -> Found:  # fmt: skip
        return Found(kind, source, site_, ask.day, name, version, key, verdict, dict(facts),
                     result.took_ms)  # fmt: skip

    if isinstance(params, webchecks.SitesParams):
        hits = webchecks.read_sites(body, params.ips)
        span = [params.start.isoformat(), params.end.isoformat()]
        return [
            row("sites", ip, None, "found" if found else "none",
                {"sites": [{"site": h.site[:600], "requests": h.requests, "ok": h.ok}
                           for h in found], "window": span})
            for ip, found in sorted(hits.items())
        ]  # fmt: skip
    if isinstance(params, webchecks.CatchallParams):
        c = webchecks.read_catchall(body, params.paths, config.served_min_bytes)
        facts = {
            "requests": c.requests,
            "answered": {_cut(p): {str(s): n for s, n in sz.items()}
                         for p, sz in c.answered.items()},
            "not_found": {str(s): n for s, n in c.not_found.items()},
            "pages": {str(s): n for s, n in c.pages.items()},
            "catch": [[_cut(p), s] for p, s in c.catch],
            "served": [_cut(p) for p in c.served],
            "paths": [_cut(p) for p in params.paths],
        }  # fmt: skip
        return [row("catchall", None, params.site, c.verdict, facts)]
    if isinstance(params, paths.PathParams):
        aggs = body.get("aggregations") if isinstance(body, Mapping) else None
        found = paths.outcomes(aggs, params.paths)
        items = [{"path": _cut(o.path), "outcome": o.outcome, "ok": o.ok, "requests": o.requests,
                  "sizes": {str(s): n for s, n in o.ok_sizes.items()}} for o in found]  # fmt: skip
        verdict = ("found" if any(o.outcome in (paths.SUCCESS, paths.POSSIBLE) for o in found)
                   else "none" if any(o.requests for o in found) else "unknown")  # fmt: skip
        return [row("paths", params.ip, params.site, verdict,
                    {"paths": items, "rare": [_cut(p) for p in ask.rare]})]  # fmt: skip
    if isinstance(params, webchecks.TakeParams):
        t = webchecks.read_take(body)
        facts = {"paths": t.paths, "sizes": t.sizes, "bytes": t.bytes,
                 "top": [[_cut(p), n] for p, n in t.top]}  # fmt: skip
        count, where = exposure.bulk_of(facts, config)
        facts["prefix"] = where
        return [row("take", params.ip, params.site, "bulk" if count else "no_bulk", facts)]
    raise TypeError(f"{name} is not a check of the checking lane")


def matched(body: Any) -> bool:
    """Whether an answer found anything at all (an empty one measures nothing)."""
    aggs = body.get("aggregations") if isinstance(body, Mapping) else None
    if not isinstance(aggs, Mapping):
        return False
    for node in aggs.values():
        if not isinstance(node, Mapping):
            continue
        if node.get("buckets") or (node.get("doc_count") or 0) > 0:
            return True
        value = node.get("value")
        if isinstance(value, int | float) and not isinstance(value, bool) and value > 0:
            return True
    return False


# --------------------------------------------------------------------------- the pass


@dataclass
class Report:
    planned: int = 0
    sent: int = 0
    stored: int = 0
    failed: int = 0
    spent_ms: int = 0  # the lane's server time today, this pass's included
    touched: int = 0
    pruned: int = 0
    stopped: str | None = None  # why the pass sent nothing more
    by_kind: dict[str, int] = field(default_factory=dict)

    def line(self) -> str:
        kinds = ", ".join(f"{k} {v}" for k, v in sorted(self.by_kind.items())) or "none"
        why = f"; stopped: {self.stopped}" if self.stopped else ""
        return (
            f"checking lane: {self.planned} checks planned, {self.sent} sent ({kinds}),"
            f" {self.failed} failed, {self.stored} answers stored, {self.touched} alert groups"
            f" marked for the engine; {self.spent_ms / 1000:.1f} s of server time today{why}"
        )


def allowed(memory: HealthMemory, now: datetime) -> str | None:
    """Why no check may be sent now (None: they may)."""
    if site.in_quiet_hours(now):
        quiet = site.quiet_hours()
        return f"the quiet hours ({quiet.start} to {quiet.end} UTC)"
    if memory.state is not HealthState.NORMAL:
        return f"the SIEM is {memory.state} (the checking lane runs in NORMAL only)"
    return None


def struggling(exc: GatewayError) -> bool:
    """Whether a failed check says the SIEM is struggling (a timeout, a partial result,
    overload, no usable answer or a server error), not that this one request was wrong."""
    if isinstance(exc, SiemError):
        return exc.status >= 500
    return isinstance(exc, ResponseError)


async def send(
    asks: Sequence[Ask], gateway: Sender, *, now: datetime, clock: Callable[[], datetime],
    spent_ms: int, config: Exposure, report: Report,
) -> list[tuple[Ask, Result]]:  # fmt: skip
    """Send ``asks`` in order, at most ``pass_requests``, while the lane's day cap holds each
    request's whole timeout; a refusal or a struggling SIEM ends it. Returns the answers."""
    out: list[tuple[Ask, Result]] = []
    spent = spent_ms
    for ask in asks:
        if report.sent + report.failed >= config.pass_requests:
            report.stopped = report.stopped or "the pass's request limit"
            break
        if spent + ask.timeout_ms > config.day_ms:
            report.stopped = "the checking lane's server time for today is used up"
            break
        try:
            result = await gateway.run(
                ask.task.template, ask.task.params, purpose=Purpose.CHECK, component=COMPONENT,
                deadline=clock() + DEADLINE,
            )  # fmt: skip
        except RefusedError as exc:
            report.stopped = f"refused: {exc}"
            break
        except GatewayError as exc:  # sent and failed: its server time is the ledger's
            report.failed += 1
            spent += ask.timeout_ms
            log.warning("checking lane: %s failed (%s)", ask.name, type(exc).__name__)
            if struggling(exc):  # a slow SIEM needs no more heavy checks now
                report.stopped = (f"the SIEM did not answer in full ({type(exc).__name__});"
                                  " the next pass tries again")  # fmt: skip
                break
            continue
        report.sent += 1
        report.by_kind[ask.kind] = report.by_kind.get(ask.kind, 0) + 1
        spent += max(result.took_ms, 0)
        out.append((ask, result))
    report.spent_ms = spent
    return out


async def spent_today(conn: AsyncConnection, now: datetime) -> int:
    """The checking lane's server time today (UTC), from the gateway's ledger."""
    day = now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    found = await conn.execute(
        text(
            "SELECT coalesce(sum(took_ms), 0) FROM siem_requests"
            " WHERE lane = 'checking' AND at >= :day"
        ),
        {"day": day},
    )
    return int(found.scalar_one())


async def inputs(conn: AsyncConnection, now: datetime, config: Exposure,
                 web_families: Sequence[str]) -> Inputs:  # fmt: skip
    """What a pass plans from: the window's inbound groups of the web families, their stored
    2xx answers, the lookups and the checks already made."""
    since = now - timedelta(days=config.window_days)
    rows = (
        await conn.execute(
            text(
                "SELECT g.investigation_id AS id, i.first_event_at, i.last_event_at,"
                " e.value AS source, EXISTS (SELECT 1 FROM risk_observations o"
                "  WHERE o.investigation_id = g.investigation_id) AS placed"
                " FROM risk_groups g JOIN investigations i ON i.id = g.investigation_id"
                " JOIN rules ru ON ru.rule_id = i.rule_id"
                " JOIN risk_entities e ON e.investigation_id = g.investigation_id"
                "  AND e.kind = 'ip' AND e.role = 'actor'"
                " WHERE g.direction = 'inbound' AND g.at >= :since AND g.at <= :now"
                " AND ru.family = ANY(CAST(:families AS text[]))"
            ),
            {"since": since, "now": now, "families": list(web_families)},
        )
    ).all()
    rows = [r for r in rows if exposure.is_outside(r.source)]
    stored = await exposure_db.followups(conn, sorted({r.id for r in rows}))
    days = {r.last_event_at.astimezone(UTC).date() for r in rows}
    sources = sorted({r.source for r in rows})
    looked = await exposure_db.lookups(conn, sources, days)
    takes = await exposure_db.checks(conn, lo=since.date(), hi=now.date(), sources=sources,
                                     kinds=("take",))  # fmt: skip
    out = Inputs()
    pairs: dict[tuple[str, str, date], Pair] = {}
    seen: dict[str, set[str]] = defaultdict(set)
    lookup_since = now - timedelta(hours=config.lookup_hours)

    def pair(source: str, site_: str, day: date, r: Any, origin: str) -> Pair:
        key = (source, site_, day)
        held = pairs.get(key)
        if held is None:
            held = pairs[key] = Pair(source, site_, day, r.first_event_at, r.last_event_at,
                                     origin=origin)  # fmt: skip
        held.first_at = min(held.first_at, r.first_event_at)
        held.last_at = max(held.last_at, r.last_event_at)
        return held

    for r in rows:
        day = r.last_event_at.astimezone(UTC).date()
        answers = stored.get(r.id, [])
        for site_, path, _ in answers:
            p = pair(r.source, site_, day, r, "evidence")
            p.paths[path] = p.paths.get(path, 0) + 1
            p.rows += 1
            seen[paths.same_file(path)].add(r.source)
        hits = looked.get((r.source, day))
        if not answers and hits:
            for hit in hits:
                site_ = str(hit.get("site") or "")
                if site_:
                    p = pair(r.source, site_, day, r, "lookup")
                    ok = hit.get("ok")
                    p.lookup_ok = True if ok is True else (None if ok is None else p.lookup_ok)
        if not answers and hits is None and not r.placed and r.last_event_at >= lookup_since:
            out.pending.append(Pending(r.source, r.first_event_at, r.last_event_at))
    for t in takes:
        if t.source and t.site:
            held = pairs.get((t.source, t.site, t.day))
            if held is not None:
                for path, n in t.facts.get("top") or []:
                    held.paths.setdefault(str(path), int(n))
    out.pairs = list(pairs.values())
    for p in out.pairs:
        out.sources_of.setdefault((p.site, p.day), set()).add(p.source)
    out.rare = exposure.rare_paths(seen, config)
    done = await conn.execute(
        text(
            "SELECT kind, coalesce(source, '') AS source, coalesce(site, '') AS site, day"
            " FROM exposure_checks WHERE day >= :lo AND (verdict <> 'unknown'"
            " OR checked_at >= :recheck)"
        ),
        {"lo": since.date(), "recheck": now - timedelta(hours=config.recheck_hours)},
    )
    out.done = {(r.kind, r.source, r.site, r.day) for r in done}
    out.last_lookup = (
        await conn.execute(text("SELECT max(checked_at) FROM exposure_checks WHERE kind = 'sites'"))
    ).scalar_one()
    return out


def web_families() -> list[str]:
    return [f.name for f in site.active().of_role(Role.WEB)]


async def run_pass(
    engine: AsyncEngine, gateway: Sender, health: Callable[[], Any], *, now: datetime,
    config: Exposure, clock: Callable[[], datetime], health_config: HealthConfig | None = None,
    only: frozenset[str] | None = None,
) -> Report:  # fmt: skip
    """One pass of the checking lane (see the module). ``health``: the gateway's stored health
    memory (awaitable). ``only``: these templates alone (a first run), still within the switched
    on ones unless given."""
    report = Report()
    enabled = frozenset(config.templates) & TEMPLATES if only is None else only & TEMPLATES
    async with engine.begin() as conn:
        report.pruned = await exposure_db.prune(conn, now, config)
    if not enabled:
        report.stopped = "no check is switched on (exposure.templates)"
        return report
    memory = health_core.effective(await health(), now, health_config or HealthConfig())
    why = allowed(memory, now)
    if why is not None:
        report.stopped = why
        return report
    async with engine.connect() as conn:
        found_in = await inputs(conn, now, config, web_families())
        spent = await spent_today(conn, now)
    asks = plan(found_in, now, config, enabled)
    report.planned = len(asks)
    answers = await send(asks, gateway, now=now, clock=clock, spent_ms=spent, config=config,
                         report=report)  # fmt: skip
    rows: list[Found] = []
    touches: dict[date, set[str]] = defaultdict(set)
    for ask, result in answers:
        rows += found_of(ask, result, config)
        touches[ask.day].update(ask.touches)
    async with engine.begin() as conn:
        report.stored = await exposure_db.save(conn, rows, now)
        for day, who in sorted(touches.items()):
            start = datetime(day.year, day.month, day.day, tzinfo=UTC)
            report.touched += await exposure_db.touch(
                conn, sorted(who), start - timedelta(days=1), start + timedelta(days=2)
            )
    return report


async def first_run(
    engine: AsyncEngine, gateway: Sender, health: Callable[[], Any], name: str, *,
    now: datetime, config: Exposure, clock: Callable[[], datetime],
    health_config: HealthConfig | None = None,
) -> list[str]:  # fmt: skip
    """A check's first production run: the pass's most telling request of ``name`` alone, sent
    once on the checking lane (every rule of a pass holds), its server time against its limit.
    The last line is FIRST RUN PASSED, FAILED or INCONCLUSIVE (it matched nothing, so it
    measured nothing); only a pass may switch the check on (``exposure.templates``)."""
    if name not in TEMPLATES:
        return [f"{name} is not a check of the checking lane", "FIRST RUN FAILED"]
    memory = health_core.effective(await health(), now, health_config or HealthConfig())
    why = allowed(memory, now)
    if why is not None:
        return [f"not now: {why}", "FIRST RUN FAILED"]
    async with engine.connect() as conn:
        found_in = await inputs(conn, now, config, web_families())
        spent = await spent_today(conn, now)
    if name == "web.source_sites":
        found_in.last_lookup = None
    asks = [a for a in plan(found_in, now, config, frozenset({name})) if a.name == name][:1]
    if not asks:
        return [f"{name}: there is nothing this check could be asked about now",
                "FIRST RUN FAILED"]  # fmt: skip
    report = Report()
    single = Exposure.model_validate({**config.model_dump(), "pass_requests": 1})
    answers = await send(asks, gateway, now=now, clock=clock, spent_ms=spent, config=single,
                         report=report)  # fmt: skip
    if not answers:
        return [f"{name}: not sent ({report.stopped or 'the request failed'})", "FIRST RUN FAILED"]
    ask, result = answers[0]
    async with engine.begin() as conn:
        await exposure_db.save(conn, found_of(ask, result, config), now)
    limit = FIRST_RUN_MS[name]
    plan_ = ask.task.template.plan(ask.task.params)
    lines = [] if plan_.window is None else [f"{name}: {batch1.describe(plan_.window)}"]
    slow = result.took_ms > limit
    lines.append(f"{name}: {result.took_ms} ms server time (limit {limit} ms)"
                 + (", too slow: it stays off" if slow else ""))  # fmt: skip
    if slow:
        lines.append("FIRST RUN FAILED")
    elif not matched(result.body):
        lines += [
            "nothing matched, so this measured nothing; it stays off",
            "FIRST RUN INCONCLUSIVE",
        ]
    else:
        lines.append("FIRST RUN PASSED")
    return lines
