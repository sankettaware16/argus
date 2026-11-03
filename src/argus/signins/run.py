"""The sign-in pass: run by the assessment loop (``argus assess run``) and by
``argus signins run``.

Each pass plans the requests (:mod:`argus.signins.plan`) for the internal addresses of the active
investigations and sends at most ``signins.max_requests_per_pass`` through the Elastic Gateway:
heavy, the investigation lane, only while the SIEM is NORMAL, never between 00:00 and 01:30 UTC, at
least ``signins.gap`` apart. Each answer is parsed strictly and stored in one transaction; one that
was not whole is stored as incomplete. A batch the database refuses is stored address by address, so
one bad row never repeats the same heavy request; a partial or badly shaped answer stops the pass.
A database lock keeps two passes from planning the same batches; the retention
(``signins.keep_days``) is applied whether the pass sends or not. Nothing about an account is
logged."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections import defaultdict
from collections.abc import AsyncIterator, Awaitable, Callable, Collection
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import site
from argus.assets.classify import IpClassifier
from argus.config.settings import Settings, SigninsSettings
from argus.context import batch1
from argus.db.errors import DB_ERRORS
from argus.gateway.errors import (
    AuthFailedError,
    GatewayError,
    LaneBusyError,
    OverloadedError,
    PartialResultError,
    RefusedError,
    SourceMissingError,
    TransportFailedError,
)
from argus.gateway.gateway import Gateway, Targets, in_quiet_hours
from argus.gateway.health import HealthConfig
from argus.gateway.state import GatewayState
from argus.gateway.templates import Purpose
from argus.signins import model as m
from argus.signins import parse as parse_
from argus.signins import plan as plan_
from argus.signins import store
from argus.signins.template import DayParams, SigninsDay

log = logging.getLogger("argus.signins")

COMPONENT = "signins"
PURPOSE = Purpose.INVESTIGATE
ASK_DEADLINE = timedelta(seconds=45)  # one request, budget waits included
PASS_BUDGET = timedelta(minutes=4)  # a pass starts no request after this long
READ_LIMIT = 20_000  # investigations read for their addresses in a pass
LOCK_KEY = int.from_bytes(b"ARGUSSIG", "big")  # one pass at a time, across processes

Sleep = Callable[[float], Awaitable[None]]


@dataclass
class Report:
    """What a pass did, in counts."""

    said: list[str] = field(default_factory=list)
    warned: list[str] = field(default_factory=list)
    sent: int = 0
    addresses: int = 0
    sightings: int = 0
    incomplete: int = 0
    waiting: int = 0
    stopped: str | None = None
    unstorable: int = 0  # address-days whose answer the database refused


def utcnow() -> datetime:
    return datetime.now(UTC)


def verdict_of(exc: GatewayError, *, kept: bool = True) -> tuple[bool, str | None]:
    """(go on, the reason to store the batch as incomplete or None to store nothing) for an error
    of the gateway. Anything refused before sending stores nothing and ends the pass; an answer
    that was not whole is stored and ends the pass (the contract and the SIEM disagree: one request
    shows it, six do not help); a request that reached the SIEM and failed is stored (so it is not
    asked again at once) and ends the pass. A missing index of a day the logs should still hold
    (``kept``) is stored as ``index_missing`` and tried again later; of a day older than
    the logs are kept, as ``logs_gone``."""
    if isinstance(exc, SourceMissingError):
        if exc.reason == "source_expired":
            return True, m.MISSING if kept else m.GONE
        return True, None
    if isinstance(exc, PartialResultError):
        return False, m.PARTIAL
    if isinstance(exc, LaneBusyError | RefusedError | AuthFailedError):
        return False, None
    if isinstance(exc, TransportFailedError) and not exc.reached:
        return False, None
    if isinstance(exc, OverloadedError):
        return False, m.FAILED
    return False, m.FAILED


def why_words(exc: GatewayError) -> str:
    """A reason a person reads, from the error's fixed reason code (never its message)."""
    return {
        "stopped": "the kill switch or the SIEM's STOP",
        "deferred": "the SIEM's health does not allow it now",
        "breaker_open": "the SIEM reported overload",
        "skipped_budget": "the day's budget is spent",
        "deadline_passed": "the lane's budget frees up too late",
        "template_rejected": "the gateway's contract refused the request",
        "auth_failed": "the SIEM refused the key",
        "partial_result": "the SIEM's answer was partial (timed out or lost shards)",
    }.get(exc.reason, exc.reason)


class _NoTransport:
    async def send(self, request: Any) -> Any:  # pragma: no cover - a dry run sends nothing
        raise RuntimeError("a dry run sends nothing")


def preview_gateway(targets: Targets) -> Gateway:
    """A gateway that can only validate (for a dry run): it has no transport and no state."""
    return Gateway(_NoTransport(), None, targets=targets)  # type: ignore[arg-type]


@contextlib.asynccontextmanager
async def pass_lock(engine: AsyncEngine, *, needed: bool = True) -> AsyncIterator[bool]:
    """Whether this process holds the pass's lock (a session advisory lock on its own connection,
    held until the pass ends; a dead connection gives it up). Two passes (the assessment loop's
    and ``argus signins run``) would plan the same batches and send them twice. ``needed``
    False (a dry run, which sends nothing) takes none."""
    if not needed:
        yield True
        return
    async with engine.connect() as holder:
        got = bool(
            (
                await holder.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": LOCK_KEY})
            ).scalar()
        )
        await holder.commit()
        try:
            yield got
        finally:
            if got:
                try:
                    await holder.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": LOCK_KEY})
                    await holder.commit()
                except Exception:  # a connection we cannot trust must not keep the lock
                    await holder.invalidate()


async def prune(
    engine: AsyncEngine, cfg: SigninsSettings, now: datetime, *, strict: bool = True
) -> list[str]:
    """Remove what is older than ``signins.keep_days`` and say so: whether or not the pass sends
    anything, and whether or not the feature is on, because the rows are personal data and the
    retention is a promise about them. ``strict`` False (the feature is off): a database
    without the tables yet (before ``argus db upgrade``) has nothing to prune and is no error."""
    if not cfg.keep_days:
        return []
    try:
        async with engine.begin() as conn:
            removed = await store.prune(conn, m.utc_day(now), cfg.keep_days)
    except DB_ERRORS:
        if strict:
            raise
        return []
    if not removed:
        return []
    return [f"signins: {removed} sightings older than {cfg.keep_days} days removed"]


async def run_pass(
    engine: AsyncEngine,
    gateway: Gateway | None,
    state: GatewayState | None,
    settings: Settings,
    classifier: IpClassifier | None,
    *,
    clock: Callable[[], datetime] = utcnow,
    sleep: Sleep = asyncio.sleep,
    max_requests: int | None = None,
    dry_run: bool = False,
    health_config: HealthConfig | None = None,
    ask_deadline: timedelta = ASK_DEADLINE,
    budget: timedelta = PASS_BUDGET,
) -> Report:
    """One pass. ``gateway`` None: nothing can be sent (the plan is still said). A database
    failure is raised to the caller; an SIEM failure ends the pass and is said."""
    report = Report()
    cfg = settings.signins
    began = clock()
    if not dry_run:
        report.said += await prune(engine, cfg, began, strict=cfg.enabled)
    if not cfg.enabled and not dry_run:
        report.said.append("signins: off (signins.enabled)")
        return report
    if in_quiet_hours(began):
        end = site.quiet_hours().end
        report.said.append(f"signins: waiting for the end of the quiet hours ({end} UTC)")
        return report
    if classifier is None:
        report.warned.append("signins: no asset map, so no address is known to be internal")
        return report
    async with pass_lock(engine, needed=not dry_run) as got:
        if not got:
            report.said.append("signins: another pass is running; this one does nothing")
            return report
        await _pass(
            engine, gateway, state, settings, classifier, report, began=began, clock=clock,
            sleep=sleep, max_requests=max_requests, dry_run=dry_run, health_config=health_config,
            ask_deadline=ask_deadline, budget=budget,
        )  # fmt: skip
    report.said.append(
        f"signins: {report.sent} requests, {report.addresses} addresses stored,"
        f" {report.sightings} account sightings, {report.incomplete} incomplete"
        + (f"; stopped: {report.stopped}" if report.stopped else "")
    )
    log.info(
        "signins pass: %d requests, %d addresses, %d sightings, %d incomplete, %d waiting",
        report.sent, report.addresses, report.sightings, report.incomplete, report.waiting,
    )  # fmt: skip
    return report


async def _pass(
    engine: AsyncEngine,
    gateway: Gateway | None,
    state: GatewayState | None,
    settings: Settings,
    classifier: IpClassifier,
    report: Report,
    *,
    began: datetime,
    clock: Callable[[], datetime],
    sleep: Sleep,
    max_requests: int | None,
    dry_run: bool,
    health_config: HealthConfig | None,
    ask_deadline: timedelta,
    budget: timedelta,
) -> None:
    """Plan from the database and send (the body of :func:`run_pass`, under its lock)."""
    cfg = settings.signins
    rules = m.rules_of(cfg)
    since = m.day_start(m.oldest_kept(m.utc_day(began), rules.retention_days)) - rules.pad
    async with engine.connect() as conn:
        wanted = await store.wants(
            conn, classifier, tuple(settings.campaigns.resolvers), since, READ_LIMIT
        )
        found = await store.records(
            conn, {w.address for w in wanted}, m.utc_day(since), m.utc_day(began)
        )
    planned = plan_.plan(wanted, found, rules, now=began, max_requests=max_requests)
    report.waiting = planned.waiting
    pairs = f"{planned.pairs} address-days wanted, {len(planned.requests)} requests planned"
    report.said.append(f"signins: {pairs}, {planned.waiting} addresses waiting")
    if planned.stuck:
        report.warned.append(
            f"signins: {planned.stuck} address-days could not be stored {m.MAX_STORE_FAILURES}"
            " times and are left alone (argus signins show --address ... says which)"
        )
    if dry_run:
        preview = preview_gateway(Targets(log_sources=frozenset({m.source()})))
        for request in planned.requests:
            params = DayParams(
                day=request.day, addresses=request.addresses, actions=rules.actions,
                end=request.end,
            )  # fmt: skip
            final = preview.preview(SigninsDay(), params, deadline=began + ASK_DEADLINE, now=began)
            report.said.append(
                f"signins: would read {request.day} up to {request.end:%H:%M}Z for"
                f" {len(request.addresses)} addresses ({final.indices[0]})"
            )
        return
    if gateway is None or state is None:
        report.warned.append("signins: the SIEM is not set up here (no key or pinned certificate)")
        return
    check = batch1.send_check(state, health_config)
    for n, request in enumerate(planned.requests):
        if n:
            await sleep(cfg.gap.total_seconds())
        if clock() - began > budget:
            report.said.append("signins: the pass's time is up; the rest waits")
            break
        params = DayParams(
            day=request.day, addresses=request.addresses, actions=rules.actions, end=request.end
        )
        report.sent += 1
        stored, go = await _ask(engine, gateway, params, check, clock, report, ask_deadline, rules)
        report.addresses += stored
        if not go:
            break


async def _ask(
    engine: AsyncEngine,
    gateway: Gateway,
    params: DayParams,
    check: Any,
    clock: Callable[[], datetime],
    report: Report,
    ask_deadline: timedelta,
    rules: m.Rules,
) -> tuple[int, bool]:
    """Send one request and store what came of it. (addresses stored, whether to go on)."""
    try:
        result = await gateway.run(
            SigninsDay(), params, purpose=PURPOSE, component=COMPONENT,
            deadline=clock() + ask_deadline, check=check,
        )  # fmt: skip
    except GatewayError as exc:
        kept = params.day >= m.oldest_kept(m.utc_day(clock()), rules.retention_days)
        go, reason = verdict_of(exc, kept=kept)
        if reason is None and not go:
            report.stopped = why_words(exc)
            report.warned.append(f"signins: stopped, {report.stopped}")
            return 0, False
        if reason is None:  # the day's index is not there yet: nothing to say about it
            return 0, True
        await _store_incomplete(engine, params, params.addresses, clock(), reason, report)
        if not go:
            report.stopped = why_words(exc)
            report.warned.append(f"signins: stopped, {report.stopped}")
        return 0, go
    at = clock()
    try:
        parsed = parse_.parse(params, result.body, m.stamp(params.day, params.end, at))
    except parse_.BadAnswer as exc:
        report.warned.append(f"signins: an answer was not the contract's shape ({exc})")
        await _store_incomplete(engine, params, params.addresses, at, m.BAD_ANSWER, report)
        report.stopped = "the SIEM's answer was not the contract's shape"
        return 0, False  # the contract and the SIEM disagree: more requests would only repeat it
    return await _store(engine, parsed, params, at, report), True


async def _store(
    engine: AsyncEngine, parsed: parse_.Parsed, params: DayParams, at: datetime, report: Report
) -> int:
    """Store an answer: whole, in one transaction. If the database refuses it, address by
    address (so one row it cannot take costs that address, not the batch), and an address it
    cannot take is recorded as incomplete (``store_failed``) with a retry time: it is
    not asked again for six hours, and after three tries not at all. Returns the addresses
    stored."""
    try:
        async with engine.begin() as conn:
            await store.save(conn, parsed.lookups, parsed.sightings)
    except Exception as exc:  # the database refused; why is in no message (it may hold a name)
        await _alive(engine)  # a database that is down is not a bad row: the caller's to handle
        report.warned.append(
            f"signins: the database refused an answer ({type(exc).__name__}); storing it by address"
        )
    else:
        report.sightings += len(parsed.sightings)
        report.incomplete += sum(not lk.complete for lk in parsed.lookups)
        return len(parsed.lookups)
    mine: dict[str, list[m.Sighting]] = defaultdict(list)
    for sighting in parsed.sightings:
        mine[sighting.address].append(sighting)
    failed: list[str] = []
    stored = 0
    for lookup in parsed.lookups:
        try:
            async with engine.begin() as conn:
                await store.save(conn, [lookup], mine.get(lookup.address, ()))
        except Exception:
            failed.append(lookup.address)
        else:
            stored += 1
            report.sightings += len(mine.get(lookup.address, ()))
            report.incomplete += not lookup.complete
    if failed:
        report.unstorable += len(failed)
        report.warned.append(
            f"signins: {len(failed)} address-days could not be stored; they wait six hours"
        )
        await _store_incomplete(engine, params, failed, at, m.STORE_FAILED, report)
    return stored


async def _alive(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))


async def _store_incomplete(
    engine: AsyncEngine,
    params: DayParams,
    addresses: Collection[str],
    at: datetime,
    reason: str,
    report: Report,
) -> None:
    lookups = parse_.incomplete(params, at, reason, only=addresses)
    async with engine.begin() as conn:
        await store.save(conn, lookups, ())
    report.incomplete += len(lookups)
