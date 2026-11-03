"""``argus kibana sync ...``: the read-back and reconciliation. Read-only.

- ``run``: the service, a cycle every 10 minutes in NORMAL, 20 in CAUTION, hourly in DEGRADED, none
  in STOP; needs ``kibana.enabled`` and ``kibana.sync.enabled`` (else it says so and exits 0).
- ``once``: one cycle now (``--dry-run`` prints the first requests and sends nothing).
- ``first-read``: a first live read of status, licence, cases and alerts, each checked against the
  strict answer models, with what each cost.
- ``report`` (the read-only days' figures), ``model`` (the read load at projected case counts),
  ``status`` (state, open findings, paused cases) and ``resume-case`` (lift the pause on a case).
"""

from __future__ import annotations

import logging
import math
from datetime import UTC, datetime, timedelta
from typing import Annotated

import typer
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import site
from argus.config.errors import ConfigError
from argus.config.settings import Settings
from argus.gateway.cli import ConfigOption, _run, engine_for, load, owner_engine_for
from argus.gateway.errors import GatewayError
from argus.gateway.kibana.paths import KEndpoint, wire_path
from argus.gateway.kibana.templates import (
    CasesConfigure,
    CasesFind,
    FindParams,
    KibanaStatus,
    NoParams,
)
from argus.kibana_sync import readmodel
from argus.kibana_sync.classify import Intervals
from argus.kibana_sync.cycle import COMPONENT, SyncConfig, Syncer

log = logging.getLogger("argus.kibana_sync")
sync_app = typer.Typer(no_args_is_help=True, help="Kibana read-back and reconciliation.")
FIRST_READ_COMPONENT = "kibana-first-read"
FIRST_READ_PER_PAGE = 10


def config_of(settings: Settings) -> SyncConfig:
    s = settings.kibana.sync
    return SyncConfig(
        author=settings.kibana.service_user,
        team=settings.case_team.users() if s.team_cases else (),
        intervals=Intervals(s.normal, s.caution, s.degraded),
        overlap=s.overlap,
        per_page=s.per_page,
        discovery_every=s.discovery_every,
        discovery_calls=s.discovery_calls,
        diff_calls=s.diff_calls,
        clock_alarm=s.clock_alarm,
        window=settings.history.window,
    )


def build(settings: Settings, engine: AsyncEngine) -> Syncer:
    """The read-back as the service runs it: the Kibana lane, the Elasticsearch gateway for
    ``alerts.case_links`` (the reader key), the gateway's store and the mirror's."""
    from argus.caseteam import verdicts
    from argus.gateway.kibana.service import build_kibana_gateway
    from argus.gateway.service import build_gateway, health_config
    from argus.kibana_sync.store import PgSyncStore

    es, store = build_gateway(settings.siem, engine)
    kibana = build_kibana_gateway(settings, store, es_gateway=es)

    async def team_verdicts(deadline: datetime) -> None:
        """After a complete cycle, the case team's cases are read for a person's
        ``Verdict:`` comment (the same lane, the same reader key)."""
        report = await verdicts.read_all(
            engine,
            kibana,
            service_user=settings.kibana.service_user,
            elk=settings.web.elk_signin,
        )
        if report.recorded or report.stopped:
            for line in report.lines():
                log.info(line)

    return Syncer(
        kibana,
        PgSyncStore(engine),
        store,
        es=es,
        config=config_of(settings),
        health_config=health_config(settings.siem),
        after_cycle=team_verdicts,
    )


def _plan(settings: Settings) -> list[str]:
    space = site.active().space
    base = settings.kibana.shown_url + settings.kibana.base_path
    reporters = config_of(settings).reporters
    names = (reporters,) if isinstance(reporters, str) else reporters
    who = "&".join(f"reporters={n}" for n in names)
    lines = []
    for what, endpoint, query in (
        ("kibana.status (hourly)", KEndpoint.STATUS, ""),
        (
            "change poll",
            KEndpoint.CASES_FIND,
            f"?owner=securitySolution&{who}&sortField=updatedAt&sortOrder=desc",
        ),
        (
            "listing (open, in-progress; closed daily, or when the probe's total moves)",
            KEndpoint.CASES_FIND,
            f"?owner=securitySolution&{who}&status=open&sortField=createdAt",
        ),
        (
            "closed probe (each cycle: one case, its total)",
            KEndpoint.CASES_FIND,
            f"?owner=securitySolution&{who}&status=closed&perPage=1",
        ),
    ):
        method, path = wire_path(endpoint, space)
        lines.append(f"{what}: Kibana {method} {base}{path}{query}")
    lines.append("each changed case: Kibana GET .../api/cases/<id>/user_actions/_find")
    lines.append(
        f"hourly, not 00:00-01:30 UTC: Elasticsearch POST"
        f" {settings.siem.shown_url}/{site.active().alerts_index_of(space)}/_search"
        f" (alerts.case_links, at most {settings.kibana.sync.diff_calls}"
        f" + {settings.kibana.sync.discovery_calls} searches)"
    )
    return lines


def _enabled(settings: Settings) -> None:
    if not settings.kibana.enabled:
        typer.echo("error: kibana.enabled is false: the Kibana lane is off", err=True)
        raise typer.Exit(2)


@sync_app.command("run")
def sync_run(config: ConfigOption = None) -> None:
    """The service: a cycle every 10/20/60 minutes by the SIEM's health, none in STOP. While
    ``kibana.enabled`` or ``kibana.sync.enabled`` is false it says so and exits 0 (the unit
    restarts only after a failure: an enabled unit of an off read-back does not loop)."""
    settings = load(config)
    for off, name in (
        (not settings.kibana.enabled, "kibana.enabled"),
        (not settings.kibana.sync.enabled, "kibana.sync.enabled"),
    ):
        if off:
            typer.echo(f"{name} is false: the read-back does not run (Q-D3's production step)")
            raise typer.Exit(0)

    async def go() -> None:
        engine = engine_for(settings)
        try:
            await build(settings, engine).run()
        finally:
            await engine.dispose()

    _run(go())


@sync_app.command("once")
def sync_once(
    dry_run: Annotated[bool, typer.Option("--dry-run", help="print, send nothing")] = False,
    config: ConfigOption = None,
) -> None:
    """One cycle now (read-only)."""
    settings = load(config)
    if dry_run:
        for line in _plan(settings):
            typer.echo(line)
        typer.echo("dry run: nothing was sent")
        return
    _enabled(settings)

    async def go() -> list[str]:
        engine = engine_for(settings)
        try:
            syncer = build(settings, engine)
            started = datetime.now(UTC)
            record = await syncer.cycle(deadline=started + timedelta(minutes=9))
        finally:
            await engine.dispose()
        return [
            f"cycle {record.outcome}" + (f" ({record.reason})" if record.reason else ""),
            f"reads {record.reads}, changed cases {record.changed}, new findings"
            f" {record.findings}, stale {record.stale}, clock offset {record.clock_offset_ms} ms",
        ]

    try:
        lines = _run(go())
    except ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from None
    for line in lines:
        typer.echo(line)


@sync_app.command("first-read")
def sync_first_read(
    dry_run: Annotated[bool, typer.Option("--dry-run", help="print, send nothing")] = False,
    config: ConfigOption = None,
) -> None:
    """The first live read: status, licence, a find of 10, the case
    configuration and one small alerts.case_links search; read-only."""
    settings = load(config)
    space = site.active().space
    base = settings.kibana.shown_url + settings.kibana.base_path
    if dry_run:
        for template, _params, query in (
            (KibanaStatus(), NoParams(), ""),
            (
                CasesFind(),
                FindParams(reporters="argus", per_page=FIRST_READ_PER_PAGE),
                f"?owner=securitySolution&reporters=argus&perPage={FIRST_READ_PER_PAGE}",
            ),
            (CasesConfigure(), NoParams(), "?owner=securitySolution"),
        ):
            method, path = wire_path(type(template).endpoint, space)
            typer.echo(f"Kibana {method} {base}{path}{query} (reader key)")
        typer.echo(f"Elasticsearch GET {settings.siem.shown_url}/_license (reader key)")
        alerts = site.active().alerts_index_of(space)
        typer.echo(
            f"Elasticsearch POST {settings.siem.shown_url}/{alerts}/_search"
            " (alerts.case_links, at most 10 known alerts; reader key)"
        )
        typer.echo("dry run: nothing was sent")
        return
    _enabled(settings)
    _run(_first_read(settings))


async def _first_read(settings: Settings) -> None:
    from argus.gateway.builtin import AlertCaseLinks, CaseLinksParams, ClusterLicense
    from argus.gateway.templates import NoParams as EsNoParams
    from argus.gateway.templates import Purpose
    from argus.kibana_sync.model import parse_case, parse_links
    from argus.kibana_sync.store import PgSyncStore

    engine = engine_for(settings)
    try:
        syncer = build(settings, engine)
        deadline = datetime.now(UTC) + timedelta(minutes=2)
        kb, es = syncer.kibana, syncer.es
        assert es is not None
        c = FIRST_READ_COMPONENT
        try:
            status = await kb.read(KibanaStatus(), NoParams(), component=c, deadline=deadline)
            typer.echo(f"kibana.status: {status.body[0]} {status.body[1]} ({status.elapsed_ms} ms)")
            lic = await es.run(
                ClusterLicense(),
                EsNoParams(),
                purpose=Purpose.KIBANA_READ,
                component=c,
                deadline=deadline,
            )
            typer.echo(f"cluster.license: {ClusterLicense.summary(lic.body)} ({lic.took_ms} ms)")
            found = await kb.read(
                CasesFind(),
                FindParams(reporters="argus", per_page=FIRST_READ_PER_PAGE),
                component=c,
                deadline=deadline,
            )
            cases = [parse_case(x) for x in found.body["cases"]]
            typer.echo(
                f"cases.find: {found.body['total']} cases of argus, {len(cases)} read"
                f" and checked ({found.elapsed_ms} ms)"
            )
            conf = await kb.read(CasesConfigure(), NoParams(), component=c, deadline=deadline)
            blocked = CasesConfigure.blocks_creates(conf.body)
            typer.echo(
                f"cases.configure: {len(conf.body)} configurations; a required custom"
                f" field blocks creates: {blocked} ({conf.elapsed_ms} ms)"
            )
            alerts = await PgSyncStore(engine).known_alerts(None, deadline - timedelta(days=5), 10)
            if alerts:
                params = CaseLinksParams(alert_ids=tuple(a for a, _ in alerts), size=10)
                links = await es.run(
                    AlertCaseLinks(),
                    params,
                    purpose=Purpose.KIBANA_READ,
                    component=c,
                    deadline=deadline,
                )
                hits, _ = parse_links(links.body)
                with_cases = sum(1 for h in hits if h.case_ids)
                typer.echo(
                    f"alerts.case_links: {len(alerts)} known alerts, {with_cases} on a"
                    f" case ({links.took_ms} ms)"
                )
            else:
                typer.echo("alerts.case_links: no known alert in history.window: not sent")
        except GatewayError as exc:
            typer.echo(f"error: {exc.reason}: {exc}", err=True)
            raise typer.Exit(1) from None
        typer.echo(
            "first read done: every answer passed its check; costs are in the ledger"
            f" (component {c}); `argus kibana sync report` shows them"
        )
    finally:
        await engine.dispose()


@sync_app.command("report")
def sync_report(
    days: Annotated[float, typer.Option(help="how many days back")] = 3.0,
    config: ConfigOption = None,
) -> None:
    """The read-only days' figures: cycles complete (≥ 99 %), staleness,
    only reads, production costs, the lag with its n."""
    settings = load(config)

    async def go() -> list[str]:
        engine = engine_for(settings)
        try:
            return await report(engine, datetime.now(UTC) - timedelta(days=days))
        finally:
            await engine.dispose()

    for line in _run(go()):
        typer.echo(line)


def _percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math.ceil(q * len(ordered)) - 1))]


async def report(engine: AsyncEngine, since: datetime) -> list[str]:
    async with engine.connect() as conn:
        cycles = (
            await conn.execute(
                text(
                    "SELECT outcome, count(*) AS n, count(*) FILTER (WHERE stale) AS stale"
                    " FROM kibana_sync_cycles WHERE started_at >= :since GROUP BY outcome"
                ),
                {"since": since},
            )
        ).all()
        requests = (
            await conn.execute(
                text(
                    "SELECT template, target, count(*) AS n, sum(took_ms) AS took,"
                    " percentile_cont(0.95) WITHIN GROUP (ORDER BY elapsed_ms) AS p95,"
                    " count(*) FILTER (WHERE write_class IS NOT NULL) AS writes"
                    " FROM siem_requests WHERE at >= :since AND component IN (:a, :b)"
                    " GROUP BY template, target ORDER BY template"
                ),
                {"since": since, "a": COMPONENT, "b": FIRST_READ_COMPONENT},
            )
        ).all()
        lags = [
            float(r.lag_s)
            for r in await conn.execute(
                text(
                    "SELECT lag_s FROM kibana_findings WHERE found_at >= :since"
                    " AND lag_s IS NOT NULL"
                ),
                {"since": since},
            )
        ]
        open_findings = (
            await conn.execute(
                text(
                    "SELECT severity, count(*) AS n FROM kibana_findings"
                    " WHERE resolved_at IS NULL GROUP BY severity"
                )
            )
        ).all()
    total = sum(r.n for r in cycles)
    complete = sum(r.n for r in cycles if r.outcome == "complete")
    stale = sum(r.stale for r in cycles)
    lines = [f"since {since:%Y-%m-%d %H:%M} UTC"]
    share = f"{100 * complete / total:.1f} %" if total else "n/a"
    lines.append(f"cycles: {total}, complete {complete} ({share}; the gate needs >= 99 %)")
    lines += [f"  {r.outcome}: {r.n}" for r in cycles]
    lines.append(f"staleness breaches: {stale} (the gate needs 0)")
    writes = sum(r.writes for r in requests)
    lines.append(f"requests: {sum(r.n for r in requests)}, of them writes: {writes} (must be 0)")
    for r in requests:
        lines.append(
            f"  {r.template} ({r.target}): {r.n}, {r.took or 0} ms charged,"
            f" p95 round trip {0 if r.p95 is None else round(r.p95)} ms"
        )
    if lags:
        lines.append(
            f"lag of people's changes: n = {len(lags)}, median {_percentile(lags, 0.5):.0f} s,"
            f" p95 {_percentile(lags, 0.95):.0f} s, max {max(lags):.0f} s"
            + (" (n < 20: the scripted local test proves the bound)" if len(lags) < 20 else "")
        )
    else:
        lines.append("lag of people's changes: n = 0 (the scripted local test proves the bound)")
    lines.append(
        "open findings: " + (", ".join(f"{r.severity} {r.n}" for r in open_findings) or "none")
    )
    return lines


@sync_app.command("model")
def sync_model(
    open_cases: Annotated[int | None, typer.Option(help="open cases of ARGUS")] = None,
    in_progress: Annotated[int, typer.Option(help="in-progress cases")] = 0,
    closed: Annotated[int, typer.Option(help="closed cases")] = 0,
    changed: Annotated[int, typer.Option(help="changed cases a day")] = 0,
    writes: Annotated[int, typer.Option(help="writes a day (their read-backs)")] = 0,
) -> None:
    """The read load at projected case counts: four scenarios, or your own numbers."""
    scenarios = dict(readmodel.SCENARIOS)
    if open_cases is not None:
        scenarios = {
            "yours": readmodel.Load(open_cases, in_progress, closed, changed, writes),
        }
    for name, load_ in scenarios.items():
        e = readmodel.estimate(load_)
        typer.echo(
            f"{name}: {e.reads_per_day} reads a day, {e.lane_ms_per_day / 1000:.0f} s of the"
            f" Kibana read lane's 240 s ({100 * e.lane_day_share:.0f} %); a quiet cycle"
            f" {e.cycle_reads} reads, {e.cycle_minutes:.1f} min of its minute share;"
            f" every alert looked at within {e.sweep_hours} h;"
            f" {'fits' if e.fits else 'DOES NOT FIT'}"
        )
        typer.echo("  " + ", ".join(f"{k} {v}" for k, v in e.parts.items()))


@sync_app.command("status")
def sync_status(config: ConfigOption = None) -> None:
    """The read-back's state, open findings by kind and paused cases (no request to Kibana)."""
    settings = load(config)

    async def go() -> list[str]:
        engine = engine_for(settings)
        try:
            async with engine.connect() as conn:
                state = (
                    await conn.execute(text("SELECT * FROM kibana_sync_state WHERE id = 1"))
                ).first()
                kinds = (
                    await conn.execute(
                        text(
                            "SELECT kind, severity, count(*) AS n FROM kibana_findings"
                            " WHERE resolved_at IS NULL GROUP BY kind, severity ORDER BY kind"
                        )
                    )
                ).all()
                paused = (
                    await conn.execute(
                        text(
                            "SELECT kibana_case_id, paused_reason FROM kibana_mirror"
                            " WHERE paused_reason IS NOT NULL ORDER BY kibana_case_id"
                        )
                    )
                ).all()
        finally:
            await engine.dispose()
        lines = []
        if state is not None:
            m = state._mapping
            for key in (
                "last_cycle_at",
                "last_complete_at",
                "changes_from",
                "last_discovery_at",
                "clock_offset_ms",
            ):
                lines.append(f"{key}: {m[key]}")
        lines.append(
            "open findings: "
            + (", ".join(f"{r.kind} ({r.severity}) {r.n}" for r in kinds) or "none")
        )
        lines += [f"paused: {r.kibana_case_id}: {r.paused_reason}" for r in paused]
        return lines

    for line in _run(go()):
        typer.echo(line)


@sync_app.command("resume-case")
def sync_resume_case(
    kibana_case_id: Annotated[str, typer.Argument(help="the Kibana case id")],
    reason: Annotated[str, typer.Option(help="why (kept in the audit trail)")],
    config: ConfigOption = None,
) -> None:
    """Lift the pause of ARGUS's writes to one Kibana case, as the database owner."""
    settings = load(config)
    engine = owner_engine_for(settings, f"kibana sync resume-case {kibana_case_id}")

    async def go() -> bool:
        from sqlalchemy.ext.asyncio import AsyncSession

        from argus.db.audit import record_audit

        try:
            async with engine.begin() as conn:
                row = (
                    await conn.execute(
                        text(
                            "UPDATE kibana_mirror SET paused_reason = NULL WHERE kibana_case_id"
                            " = :k AND paused_reason IS NOT NULL RETURNING case_id"
                        ),
                        {"k": kibana_case_id},
                    )
                ).first()
                if row is not None:
                    session = AsyncSession(bind=conn)
                    await record_audit(
                        session,
                        actor="cli",
                        action="kibana.case_resume",
                        target_type="case",
                        target_id=str(row.case_id),
                        details={"kibana_case_id": kibana_case_id, "reason": reason},
                    )
                    await session.close()
                return row is not None
        finally:
            await engine.dispose()

    changed = _run(go())
    typer.echo(f"{kibana_case_id}: " + ("resumed" if changed else "not paused"))
