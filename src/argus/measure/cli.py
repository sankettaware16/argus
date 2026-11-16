"""``scripts/measure_capacity.py``: re-measure the SIEM load budget.

    uv run python scripts/measure_capacity.py [plan]          # dry run (the default): nothing sent
    uv run python scripts/measure_capacity.py run --live      # the session: a person, at a terminal
    uv run python scripts/measure_capacity.py verify data/measure/<UTC>/session.json
    uv run python scripts/measure_capacity.py report [--since DATE] [--decision]
    uv run python scripts/measure_capacity.py kibana          # the local Kibana tier only

``run`` without ``--live`` is the dry run as well. A live run needs a terminal, a typed
confirmation word, NORMAL health and the hours outside the quiet hours; it stops at the first
CAUTION signal (``argus.measure.session``). Nothing here writes to the SIEM or changes ARGUS's
configuration: the lanes are proposed (``report --decision``) and adopted by the operator.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import sys
import tempfile
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TextIO

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import site
from argus.config.errors import ConfigError
from argus.config.settings import Settings, load_settings
from argus.context.bounds import quiet
from argus.db.engine import create_engine
from argus.db.errors import DB_ERRORS, short_db_error
from argus.gateway.builtin import NodeStats
from argus.gateway.errors import GatewayError
from argus.gateway.gateway import Gateway
from argus.gateway.health import HealthConfig, effective
from argus.gateway.pgstore import PgStore
from argus.gateway.service import (
    collector_config,
    health_config,
    lane_plan,
    probe,
    targets,
    transport,
)
from argus.gateway.transport import Transport, WireRequest, WireResponse
from argus.measure import kibana, lanes
from argus.measure.session import (
    COMPONENT,
    LIMITS,
    MINUTE,
    CappedTransport,
    MeasureStore,
    Plan,
    Session,
    SessionReport,
    build_plan,
    caution_signals,
    describe,
    gather_subjects,
    refused,
    verify,
)
from argus.observability.logs import configure_logging
from argus.observability.redaction import register_secret

CONFIRM_WORDS = ("amber", "birch", "cedar", "delta", "ember", "fjord", "grove", "harbor")
OUT = Path("data/measure")
# pg advisory lock: one measuring session at a time per database (so across every checkout that
# uses production's database; a checkout on another database has its own lock, budget and
# ledger, which readiness refuses: it shows no running ARGUS)
LOCK = 0x61726775_6D73
DAY = timedelta(hours=24)
# the collector probes every minute (collector.runner): a database without such a probe this
# recently is not the one production's ARGUS writes to
PRODUCTION_PROBE = timedelta(minutes=2)


class NoSend:
    """The dry run's transport: it never sends; reaching it is a bug."""

    async def send(self, request: WireRequest) -> WireResponse:
        raise AssertionError("the dry run sends nothing")


def _say(out: TextIO, text: str) -> None:
    out.write(text + "\n")


def _err(text: str) -> None:
    sys.stderr.write(text + "\n")


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _settings(config: Path | None) -> Settings:
    settings = load_settings(config)
    for secret in settings.secret_values():
        register_secret(secret)
    configure_logging(settings.logging.level, settings.logging.format)
    return settings


async def readiness(store: MeasureStore, now: datetime, config: HealthConfig) -> list[str]:
    """Why a live session would refuse to start now (empty: it would start, and then probes
    the SIEM first), from what ARGUS stored: no request to the SIEM. A stored health memory too old
    to trust is no reason: the session's own first probe decides. A database where no other
    component probed the SIEM in the last 2 minutes is: its budget, switches and ledger are not
    production's (a leftover ``ARGUS_DATABASE__NAME``), so pacing against it means nothing."""
    found = []
    recent = await store.requests_since(now - PRODUCTION_PROBE)
    if not any(r.template == NodeStats.name and r.component != COMPONENT for r in recent):
        found.append("this database shows no running ARGUS (no collector probe in the last 2"
                     " minutes): check ARGUS_DATABASE__NAME and the collector")  # fmt: skip
    if quiet(now) or quiet(now + LIMITS.max_duration):
        found.append(f"the time: no measuring from {site.quiet_hours().words(LIMITS.max_duration)}")
    stopped = (await store.switches()).stopped
    if stopped:
        found.append(f"kill switch stopped: {', '.join(sorted(stopped))}")
    ok, _until = await store.breaker_peek(now)
    if not ok:
        found.append("the overload breaker is open")
    memory = await store.health()
    fresh = memory.probed_at is not None and now - memory.probed_at < config.stale_degraded
    if fresh:
        latest = await store.latest_probe()
        found.extend(caution_signals(effective(memory, now, config), latest, None, now, config,
                                     fresh=config.stale_degraded))  # fmt: skip
    return found


async def plan_for(settings: Settings, engine: AsyncEngine, now: datetime) -> Plan:
    async with engine.connect() as conn:
        subjects = await gather_subjects(conn)
    return build_plan(
        subjects,
        now,
        history=settings.history.window,
        log_queries=settings.enrichment.log_queries,
        proxy_aggregations=settings.enrichment.proxy_aggregations,
    )


def _store(settings: Settings, engine: AsyncEngine) -> PgStore:
    """The store with the allowances every ARGUS process uses (the collector's lane and the
    lane plan, whose enrichment lane the measuring session spends, D-321), so the shared budget
    row is never refilled past the collector's share by this process."""
    return PgStore(engine, collector_config(settings.siem), lane_plan(settings.siem))


async def dry_run(settings: Settings, engine: AsyncEngine, now: datetime) -> list[str]:
    store = _store(settings, engine)
    plan = await plan_for(settings, engine, now)
    gateway = Gateway(NoSend(), store, targets=targets(settings.siem))
    lines = [f"dry run at {now:%Y-%m-%d %H:%M} UTC: nothing is sent to the SIEM", *describe(
        plan, gateway, now)]  # fmt: skip
    blockers = await readiness(store, now, health_config(settings.siem))
    if blockers:
        lines.append("a live run would not start now: " + "; ".join(blockers))
    else:
        lines.append("a live run could start now (it probes the SIEM first)")
    return lines


def _human_at_a_terminal() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


async def live_run(
    settings: Settings,
    engine: AsyncEngine,
    *,
    sender: Transport,
    confirm: Callable[[str], bool],
    out: Path,
    clock: Callable[[], datetime] = _utcnow,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    echo: Callable[[str], None] | None = None,
) -> tuple[SessionReport | None, list[str]]:
    """The session: the plan shown, checked, confirmed, run, saved and verified; one at a time
    (an advisory lock across every checkout). ``sender`` is the transport to the SIEM; the
    session wraps it in its CappedTransport."""
    say = echo or (lambda line: _say(sys.stdout, line))
    store = _store(settings, engine)
    now = clock()
    plan = await plan_for(settings, engine, now)
    counter = CappedTransport(sender, clock)
    config = health_config(settings.siem)
    gateway = Gateway(counter, store, targets=targets(settings.siem), health_config=config,
                      clock=clock, sleep=sleep, listing_component=COMPONENT)  # fmt: skip
    for line in describe(plan, gateway, now):
        say(line)
    blockers = await readiness(store, now, config)
    blockers += [f"the gateway would refuse {item}" for item in refused(plan, gateway, now)]
    if blockers:
        return None, ["not started: " + "; ".join(blockers)]
    async with engine.connect() as holder:
        got = (await holder.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": LOCK})).scalar()
        await holder.commit()
        if not got:
            return None, ["not started: another measuring session is running"]
        try:
            before = [r for r in await store.requests_since(now - DAY) if r.component == COMPONENT]
            if before:
                say(f"The ledger holds {len(before)} measuring requests from the last 24 hours.")
            word = secrets.choice(CONFIRM_WORDS)
            say(f"This sends up to {LIMITS.max_requests} read-only requests ({plan.heavy} heavy)"
                " to the SIEM (production) within ARGUS's budget; it stops at the first CAUTION"
                " signal.")  # fmt: skip
            if not confirm(word):
                return None, ["not confirmed: nothing was sent"]
            blockers = await readiness(store, clock(), config)  # the prompt may have waited
            if blockers:
                return None, ["not started: " + "; ".join(blockers)]

            async def probe_once() -> Any:
                return await probe(gateway, store, settings.siem, clock(), component=COMPONENT)

            session = Session(gateway, store, plan, counter=counter, probe=probe_once,
                              health_config=config, clock=clock, sleep=sleep)  # fmt: skip
            try:
                report = await session.run()
            except BaseException:  # interrupted: keep what was measured
                save(session.report, out)
                raise
        finally:
            await holder.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": LOCK})
            await holder.commit()
    path = save(report, out)
    lines = summary(report)
    lines.append(f"saved {path}")
    verdict = await verify_stored(store, report.started, report.ended or clock(), config,
                                  now=clock(), requests_sent=report.requests_sent)  # fmt: skip
    lines.extend(verdict)
    return report, lines


def summary(report: SessionReport) -> list[str]:
    lines = [
        f"{len(report.samples)} of {report.planned} measured; {report.requests_sent} requests"
        f" sent ({report.heavy_sent} heavy)",
    ]
    for sample in report.samples:
        took = "" if sample.took_ms is None else f" {sample.took_ms} ms"
        lines.append(f"  {sample.label}: {sample.outcome}{took}")
    if report.stopped:
        lines.append(f"STOPPED EARLY: {report.stopped}")
    lines.extend(f"note: {note}" for note in report.notes)
    return lines


def save(report: SessionReport, out: Path) -> Path:
    """data/measure/<UTC>/session.json, readable by this user only (no query values in it)."""
    folder = out / report.started.strftime("%Y%m%dT%H%M%SZ")
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = folder / "session.json"
    descriptor, name = tempfile.mkstemp(prefix=".session-", dir=folder)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(report.to_json(), handle, indent=1, sort_keys=True)
        os.chmod(name, 0o600)
        os.replace(name, path)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise
    return path


VERIFIED = "SESSION VERIFIED"
NOT_VERIFIED = "SESSION NOT VERIFIED"
SO_FAR = "SESSION VERIFIED SO FAR"  # the 5 minutes after a busy minute have not passed


async def verify_stored(
    store: MeasureStore,
    start: datetime,
    end: datetime,
    config: HealthConfig,
    *,
    now: datetime | None = None,
    requests_sent: int | None = None,
) -> list[str]:
    """The verdict on a session from the ledger and the readings, judged at ``now``; its last
    line is VERIFIED, NOT_VERIFIED, or SO_FAR with the time to verify again."""
    now = now or _utcnow()
    second = timedelta(seconds=1)
    rows = await store.requests_since(start - MINUTE, end + MINUTE + second)
    probes = await store.probes_since(start, end + LIMITS.attribution + second)
    verdict = verify(rows, probes, start, end, config=config, requests_sent=requests_sent,
                     now=now)  # fmt: skip
    lines = list(verdict.facts)
    lines.extend(f"problem: {problem}" for problem in verdict.problems)
    if not verdict.passed:
        lines.append(NOT_VERIFIED)
    elif verdict.pending_until is not None:
        lines.append(f"{SO_FAR}: run verify again after {_minute_after(verdict.pending_until)}")
    else:
        lines.append(VERIFIED)
    return lines


def _minute_after(moment: datetime) -> str:
    """``moment`` as HH:MM UTC, rounded up to the minute."""
    whole = moment.replace(second=0, microsecond=0)
    return f"{whole if whole == moment else whole + MINUTE:%H:%M} UTC"


def load_session(path: Path) -> tuple[datetime, datetime, int | None]:
    """The session's start, end and request count from its file; ValueError (a plain message)
    for anything that is not a usable session file of this script."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("format") != 1 or data.get("component") != COMPONENT:
        raise ValueError(f"{path}: not a session file of this script")
    try:
        started = datetime.fromisoformat(data["started"])
        ended = datetime.fromisoformat(data["ended"]) if data.get("ended") else started
        sent = data.get("requests_sent")
        if sent is not None and (isinstance(sent, bool) or not isinstance(sent, int)):
            raise TypeError("requests_sent")
    except (KeyError, TypeError, ValueError):
        raise ValueError(f"{path}: not a usable session file (its times or counts)") from None
    if started.tzinfo is None or ended.tzinfo is None or ended < started:
        raise ValueError(f"{path}: the session's times are not usable")
    return started, ended, sent


async def report_lines(
    store: MeasureStore,
    since: datetime,
    until: datetime,
    *,
    cores: int,
    spare_share: float,
    plan: dict[str, Any] | None,
    decision: bool,
) -> tuple[list[str], dict[str, Any]]:
    rows = await store.requests_since(since, until)
    probes = await store.probes_since(since, until)
    stats = lanes.template_stats(rows)
    rates, unowned = lanes.observed_rates(rows, until)
    if plan:
        rates = lanes.apply_plan(rates, plan)
    room = lanes.headroom(probes, cores=cores, spare_share=spare_share)
    results = lanes.derive(stats, rates, room)
    head = (f"from {since:%Y-%m-%d %H:%M} to {until:%Y-%m-%d %H:%M} UTC: {len(rows)} requests,"
            f" {len(probes)} probe readings")  # fmt: skip
    lines = [head, *lanes.report_lines(results, stats, room, unowned)]
    if decision:
        lines.append("")
        lines.append(lanes.decision_draft(results, room, since, until))
    return lines, lanes.to_json(results, stats, room)


def _when(value: str) -> datetime:
    moment = datetime.fromisoformat(value)
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(prog="measure_capacity.py", description=__doc__.split("\n")[0])
    top.add_argument("--config", "-c", type=Path, default=None, help="YAML config file")
    sub = top.add_subparsers(dest="command")
    sub.add_parser("plan", help="the dry run: the session's requests, nothing sent")
    run = sub.add_parser("run", help="the session (a dry run unless --live)")
    run.add_argument("--live", action="store_true", help="send the requests (production)")
    run.add_argument("--out", type=Path, default=OUT)
    check = sub.add_parser("verify", help="check a session from the ledger and the readings")
    check.add_argument("session", type=Path)
    rep = sub.add_parser("report", help="the derivation: lanes from the ledger and the readings")
    rep.add_argument("--since", type=_when, default=lanes.HARDWARE_CHANGE)
    rep.add_argument("--until", type=_when, default=None)
    rep.add_argument("--cores", type=int, default=16)
    rep.add_argument("--spare-share", type=float, default=0.02)
    rep.add_argument("--plan", type=Path, default=None, help="planned rates (JSON)")
    rep.add_argument("--json", type=Path, default=None, help="write the result here")
    rep.add_argument("--decision", action="store_true", help="print the DECISIONS draft")
    kib = sub.add_parser("kibana", help="Kibana's relative costs on the local tier")
    kib.add_argument("--url", default=os.environ.get("KIBANA_TIER_URL", "https://127.0.0.1:55610"))
    kib.add_argument("--rounds", type=int, default=5)
    kib.add_argument("--json", type=Path, default=None)
    return top


def _tier_dir() -> Path:
    return Path(
        os.environ.get("KIBANA_TIER_DIR") or Path.home() / ".local/share/argus-kibana-tier"
    ).expanduser()


def kibana_command(args: argparse.Namespace, out: TextIO) -> int:
    try:
        url = kibana.loopback_url(args.url)
    except ValueError as exc:
        _err(f"error: {exc}")
        return 2
    tier = _tier_dir()
    try:
        data = json.loads((tier / "secrets.json").read_text(encoding="utf-8"))
        password = data["passwords"]["elastic"]
    except (OSError, ValueError, KeyError, TypeError):
        _err(f"error: no tier secrets in {tier} (scripts/kibana_tier.py init)")
        return 2
    register_secret(password)
    run = secrets.token_hex(4)
    try:
        with kibana.client(url, str(tier / "ca" / "ca.crt"), "elastic", password) as http:
            result = kibana.measure(http, run=run, rounds=args.rounds)
    except (kibana.TierError, OSError, ValueError) as exc:
        _err(f"error: {exc}")
        return 1
    except Exception as exc:  # httpx's errors: the tier is not up
        _err(f"error: the tier did not answer: {type(exc).__name__}")
        return 1
    for line in kibana.lines(result):
        _say(out, line)
    if args.json:
        args.json.write_text(json.dumps(kibana.to_json(result), indent=1), encoding="utf-8")
    return 0


async def _with_engine(settings: Settings, use: Callable[[AsyncEngine], Any]) -> Any:
    engine = create_engine(settings.database, role="app")
    try:
        return await use(engine)
    finally:
        await engine.dispose()


def main(argv: Sequence[str] | None = None, *, out: TextIO = sys.stdout) -> int:
    args = parser().parse_args(argv)
    command = args.command or "plan"
    if command == "kibana":
        return kibana_command(args, out)
    try:
        settings = _settings(args.config)
    except ConfigError as exc:
        _err(f"error: {exc}")
        return 2
    try:
        if command == "plan" or (command == "run" and not args.live):
            lines = asyncio.run(_with_engine(settings, lambda e: dry_run(settings, e, _utcnow())))
            _say(out, "\n".join(lines))
            return 0
        if command == "run":
            return _live(settings, args.out, out)
        if command == "verify":
            lines = asyncio.run(
                _with_engine(settings, lambda e: _verify(settings, e, args.session))
            )
            _say(out, "\n".join(lines))
            return _exit(lines[-1])
        lines, data = asyncio.run(_with_engine(settings, lambda e: _report(e, args)))
        _say(out, "\n".join(lines))
        if args.json:
            args.json.write_text(json.dumps(data, indent=1), encoding="utf-8")
        return 0
    except DB_ERRORS as exc:
        _err(f"error: {short_db_error(exc)}")
        return 1
    except (ValueError, OSError) as exc:
        _err(f"error: {exc}")
        return 1


def _exit(last: str) -> int:
    """0: verified; 3: verified so far (verify again later); 1: not verified."""
    return 0 if last == VERIFIED else 3 if last.startswith(SO_FAR) else 1


async def _verify(
    settings: Settings, engine: AsyncEngine, session: Path, now: datetime | None = None
) -> list[str]:
    start, end, sent = load_session(session)
    return await verify_stored(PgStore(engine), start, end, health_config(settings.siem),
                               now=now, requests_sent=sent)  # fmt: skip


async def _report(
    engine: AsyncEngine, args: argparse.Namespace
) -> tuple[list[str], dict[str, Any]]:
    plan = json.loads(args.plan.read_text(encoding="utf-8")) if args.plan else None
    return await report_lines(PgStore(engine), args.since, args.until or _utcnow(),
                              cores=args.cores, spare_share=args.spare_share, plan=plan,
                              decision=args.decision)  # fmt: skip


def _live(settings: Settings, folder: Path, out: TextIO) -> int:
    if not _human_at_a_terminal():
        _err("error: the measuring session is run by a person at a terminal")
        return 2
    if quiet(_utcnow()) or quiet(_utcnow() + LIMITS.max_duration):
        _err(
            f"error: no measuring from {site.quiet_hours().words(LIMITS.max_duration)}"
            " (the SIEM's busy time)"
        )
        return 2
    try:
        sender = transport(settings.siem)
    except ConfigError as exc:
        _err(f"error: {exc}")
        return 2

    def confirm(word: str) -> bool:
        return input(f"Type '{word}' to confirm: ").strip() == word

    async def use(engine: AsyncEngine) -> tuple[SessionReport | None, list[str]]:
        try:
            return await live_run(settings, engine, sender=sender, confirm=confirm, out=folder,
                                  echo=lambda line: _say(out, line))  # fmt: skip
        finally:
            await sender.aclose()

    try:
        report, lines = asyncio.run(_with_engine(settings, use))
    except GatewayError as exc:
        _err(f"error: {exc.reason}: {exc}")
        return 1
    _say(out, "\n".join(lines))
    if report is None or not report.complete:
        return 1
    return _exit(lines[-1])
