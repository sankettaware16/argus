"""``argus risk ...``: the incident engine v2 in shadow (P4-F E1). It reads ARGUS's database
only (no SIEM request, no model) and writes its own tables; today's queue is unchanged."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Coroutine
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import typer
from sqlalchemy import text

from argus import site
from argus.assets import load_asset_map
from argus.assets.classify import IpClassifier
from argus.campaigns import lookups as campaign_lookups
from argus.cases import naming
from argus.cases.membership import load_shared
from argus.config.errors import ConfigError
from argus.db.errors import DB_ERRORS, short_db_error
from argus.gateway.cli import ConfigOption, engine_for, load
from argus.llm.privacy import Privacy, load_policy
from argus.outside.eligible import Eligibility
from argus.risk import (
    checking,
    identity,
    incident_config,
    incidents,
    outbound,
    present,
    run,
    titles,
)
from argus.risk import config as risk_config
from argus.signins import model as signin_model

risk_app = typer.Typer(
    no_args_is_help=True,
    help="The incident engine v2 in shadow: observations, scores and lanes (no SIEM, no model).",
)
AtOption = Annotated[
    str | None,
    typer.Option("--at", help="Score as of this ISO time (UTC); default now. For a copy's past."),
]


def _run[T](work: Coroutine[Any, Any, T]) -> T:
    try:
        return asyncio.run(work)
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None


def _when(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    except ValueError:
        typer.echo(f"error: --at {value!r} is not an ISO time", err=True)
        raise typer.Exit(2) from None


def setup_for(settings: Any) -> run.Setup:
    """What a pass needs, from the settings: the engine's weights, the address classes (the
    asset map when imported), the site's log families, domains and threat-intel feeds, the shared
    list and the outside cache's view."""
    try:
        config = risk_config.load()
        shared = load_shared()
    except ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from None
    profile = site.active()
    assets = load_asset_map(settings.assets.map_path)
    classifier = IpClassifier(assets, settings.site.own_networks)
    view = run.view_of(settings, shared)
    presenter = present.Options(settings.risk.present, settings.risk.shown_per_day)
    return run.Setup(
        config, classifier, profile.families, profile.own_domains,
        run.feed_modes(profile.ti_sources), shared, view,
        linking=link_setup(settings, classifier, assets, shared, view), presenter=presenter,
    )  # fmt: skip


def link_setup(
    settings: Any, classifier: IpClassifier, assets: Any, shared: Any, view: Any
) -> incidents.LinkSetup:
    """The linker's settings (``config/risk-incidents.yaml``), identity from the asset map, the
    stored sign-ins' rules, and argus.campaigns' analysis (read only; nothing is asked)."""
    try:
        linking = incident_config.load()
    except ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from None
    resolvers = tuple(settings.campaigns.resolvers)
    who = identity.Identity(classifier, linking.identity, linking.hubs.roles, resolvers)
    campaigns = None
    if assets is not None:
        privacy = Privacy.build(load_policy(), assets, settings.site.own_networks)
        eligibility = Eligibility(privacy.classifier, privacy.ours, privacy.ours_for)
        window = timedelta(hours=linking.campaign.hours)

        async def campaigns(now: datetime) -> Any:
            engine = engine_for(settings)
            try:
                _, result = await campaign_lookups.evaluate(
                    engine, now, window=window, classifier=classifier, view=view,
                    eligibility=eligibility, shared=shared, resolvers=resolvers,
                )  # fmt: skip
            finally:
                await engine.dispose()
            return result.campaigns

    return incidents.LinkSetup(
        linking, who, signin_model.rules_of(settings.signins), campaigns,
        settings.outside.flag_threshold,
    )  # fmt: skip


@risk_app.command("run")
def risk_run(
    once: Annotated[bool, typer.Option(help="One pass, then stop.")] = False,
    every: Annotated[int, typer.Option(min=10, help="Seconds between passes.")] = 120,
    at: AtOption = None,
    config: ConfigOption = None,
) -> None:
    """Read the alert groups whose inputs changed, write their observations, rescore the window
    and record the lanes. ``--at`` (a past time on a copy) implies ``--once``."""
    settings = load(config)
    setup = setup_for(settings)
    fixed = _when(at)

    async def main() -> None:
        engine = engine_for(settings)
        try:
            while True:
                now = fixed or datetime.now(UTC)
                if once or fixed is not None:
                    typer.echo((await run.step(engine, setup, now)).line())
                    return
                try:  # a failed pass is said; the next one tries again
                    typer.echo((await run.step(engine, setup, now)).line())
                except Exception as exc:
                    typer.echo(f"warning: the engine's pass failed ({type(exc).__name__});"
                               " retrying", err=True)  # fmt: skip
                await asyncio.sleep(every)
        finally:
            await engine.dispose()

    _run(main())


@risk_app.command("rescore")
def risk_rescore(at: AtOption = None, config: ConfigOption = None) -> None:
    """Rescore every object of the window from its stored observations, and say how long it
    took (reading, scoring, writing)."""
    settings = load(config)
    setup = setup_for(settings)
    now = _when(at) or datetime.now(UTC)

    async def main() -> None:
        engine = engine_for(settings)
        try:
            report = run.Report()
            started = time.perf_counter()
            await run.rescore(engine, setup.config, now, report)
            report.seconds["total"] = time.perf_counter() - started
            typer.echo(report.line())
        finally:
            await engine.dispose()

    _run(main())


@risk_app.command("check")
def risk_check(
    once: Annotated[bool, typer.Option(help="One pass, then stop.")] = False,
    every: Annotated[int, typer.Option(min=60, help="Seconds between passes.")] = 600,
    first_run: Annotated[
        str | None,
        typer.Option(
            "--first-run",
            help="One request of this check, its server time against its limit (a person's"
            " first production run; the check need not be switched on yet).",
        ),
    ] = None,
    config: ConfigOption = None,
) -> None:
    """The checking lane (P4-F E3): find the own site of thin inbound alerts and check only
    the exposure candidates (soft-404, served paths, bulk takes), then gather the deciding
    evidence of the engine's presented outbound incidents (D-323: a device's timing to its
    destination, how many internal devices reach it, its lookups), on the gateway's checking lane
    (NORMAL only, never in the quiet hours, at most ``exposure.day_ms`` a day). Only the checks
    ``exposure.templates`` and ``enrichment.templates`` switch on are sent."""
    from argus.context import batch1
    from argus.gateway.service import build_gateway, health_config

    settings = load(config)
    try:
        engine_config = risk_config.load()
    except ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from None
    exposure = engine_config.exposure
    classifier = IpClassifier(load_asset_map(settings.assets.map_path), settings.site.own_networks)
    is_own = batch1.private_or(lambda v: classifier.classify(v).ip_class)

    async def main() -> int:
        engine = engine_for(settings)
        try:
            gateway, store = build_gateway(settings.siem, engine)
        except ConfigError as exc:
            await engine.dispose()
            typer.echo(f"error: {exc}", err=True)
            return 2
        cfg = health_config(settings.siem)
        try:
            if first_run is not None:
                lines = await checking.first_run(
                    engine, gateway, store.health, first_run, now=datetime.now(UTC),
                    config=exposure, clock=gateway.clock, health_config=cfg,
                )  # fmt: skip
                for line in lines:
                    typer.echo(line)
                return 0 if lines[-1] == "FIRST RUN PASSED" else 1

            async def exposure_pass() -> Any:
                return await checking.run_pass(
                    engine, gateway, store.health, now=datetime.now(UTC), config=exposure,
                    clock=gateway.clock, health_config=cfg,
                )  # fmt: skip

            async def evidence_pass() -> Any:
                return await outbound.run_pass(
                    engine, gateway, store.health, now=datetime.now(UTC),
                    config=engine_config.outbound, lane_day_ms=exposure.day_ms,
                    enabled=settings.enrichment.templates, clock=gateway.clock,
                    is_own=is_own, history=settings.history.window, health_config=cfg,
                    check=batch1.send_check(store, cfg),
                )  # fmt: skip

            while True:
                failed: Exception | None = None
                for what, step in (("checking", exposure_pass), ("incident evidence",
                                                                  evidence_pass)):  # fmt: skip
                    try:  # one failing pass never keeps the other from running
                        typer.echo((await step()).line())
                    except Exception as exc:
                        failed = failed or exc
                        typer.echo(f"warning: the {what} pass failed ({type(exc).__name__})",
                                   err=True)  # fmt: skip
                if once:
                    if failed is not None:
                        raise failed
                    return 0
                await asyncio.sleep(every)
        finally:
            await gateway.transport.aclose()  # type: ignore[attr-defined]
            await engine.dispose()

    code = _run(main())
    if code:
        raise typer.Exit(code)


_STATUS = (
    ("alert groups read", "SELECT count(*) FROM risk_groups"),
    ("observations", "SELECT count(*) FROM risk_observations"),
    ("objects scored", "SELECT count(*) FROM risk_objects"),
    ("objects in a lane now", "SELECT count(*) FROM risk_objects WHERE cardinality(lanes) > 0"),
    ("lane crossings", "SELECT count(*) FROM risk_crossings"),
    ("new items", "SELECT count(DISTINCT (object_id, at)) FROM risk_crossings WHERE new_item"),
    (
        "sites in the exposure lane now",
        "SELECT count(*) FROM risk_objects WHERE kind = 'site' AND 'exposure' = ANY(lanes)",
    ),
    ("checks stored (exposure, 180 days)", "SELECT count(*) FROM exposure_checks"),
    ("incident evidence stored (180 days)", "SELECT count(*) FROM risk_evidence"),
    ("incidents active or quiet",
     "SELECT count(*) FROM risk_incidents WHERE state IN ('active', 'quiet')"
     " AND parent_id IS NULL"),
    ("incidents sealed", "SELECT count(*) FROM risk_incidents WHERE state = 'sealed'"),
    ("links (kept, recommended)",
     "SELECT count(*) FILTER (WHERE kept) || ', ' || count(*) FILTER (WHERE NOT kept)"
     " FROM risk_links"),
    ("outside things flagged", "SELECT count(*) FROM risk_threats"),
)  # fmt: skip


@risk_app.command("status")
def risk_status(config: ConfigOption = None) -> None:
    """What the shadow engine holds: counts, and the alert groups of each digest category of the
    last seven days."""
    settings = load(config)

    async def main() -> None:
        engine = engine_for(settings)
        try:
            async with engine.connect() as conn:
                for label, sql in _STATUS:
                    typer.echo(f"{label}: {(await conn.execute(text(sql))).scalar_one()}")
                rows = await conn.execute(
                    text(
                        "SELECT coalesce(category, 'not scored yet') AS c, count(*) AS n"
                        " FROM risk_groups WHERE day >= current_date - 7 GROUP BY 1 ORDER BY 2 DESC"
                    )
                )
                typer.echo("alert groups by where they ended (7 days):")
                for row in rows:
                    typer.echo(f"  {row.c}: {row.n}")
        finally:
            await engine.dispose()

    _run(main())


@risk_app.command("incidents")
def risk_incidents(
    limit: Annotated[int, typer.Option(min=1, max=500, help="Incidents to show.")] = 20,
    config: ConfigOption = None,
) -> None:
    """The shadow engine's live incidents, newest change first: lane, devices, alert groups,
    version and what changed, with the first reasons that link its objects."""
    settings = load(config)

    async def main() -> None:
        engine = engine_for(settings)
        try:
            async with engine.connect() as conn:
                rows = (await conn.execute(
                    text(
                        "SELECT id, state, devices, groups, version, changed, view, band"
                        " FROM risk_incidents WHERE state IN ('active', 'quiet')"
                        " AND parent_id IS NULL ORDER BY updated_at DESC, id DESC LIMIT :n"
                    ),
                    {"n": limit},
                )).all()  # fmt: skip
                for r in rows:
                    view = r.view or {}
                    typer.echo(
                        f"#{r.id} {r.state}, {view.get('lane', '?')}: {r.devices} devices,"
                        f" {r.groups} alert groups, version {r.version}"
                        f" ({'; '.join(r.changed) or 'no change'})"
                    )
                    reasons = await conn.execute(
                        text(
                            "SELECT reason FROM risk_links WHERE incident_id = :i AND kept"
                            " AND b_object IS NOT NULL ORDER BY priority, id LIMIT 3"
                        ),
                        {"i": r.id},
                    )
                    for (reason,) in reasons:
                        typer.echo(f"    linked: {reason}")
                if not rows:
                    typer.echo("no live incidents")
        finally:
            await engine.dispose()

    _run(main())


@risk_app.command("titles")
def risk_titles(
    limit: Annotated[int, typer.Option(min=1, max=500, help="Incidents to title.")] = 20,
    certainty: Annotated[str, typer.Option(help="The certainty word to lead with.")] = "Suspected",
    explain: Annotated[bool, typer.Option(help="Each claim with the fact it rests on.")] = False,
    config: ConfigOption = None,
) -> None:
    """The title each live incident's own facts give (naming v2 on the engine's facts), newest
    change first. Read only: nothing is stored or retitled."""
    settings = load(config)
    if certainty not in naming.CERTAINTIES:
        typer.echo(f"error: --certainty is one of {', '.join(naming.CERTAINTIES)}", err=True)
        raise typer.Exit(2)
    try:
        exposure = risk_config.load().exposure
    except ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from None
    classifier = IpClassifier(load_asset_map(settings.assets.map_path), settings.site.own_networks)
    ctx = titles.Context(classifier, exposure, settings.outside.flag_threshold)

    async def main() -> None:
        engine = engine_for(settings)
        try:
            async with engine.connect() as conn:
                ids = (await conn.execute(
                    text("SELECT id FROM risk_incidents WHERE state IN ('active', 'quiet')"
                         " AND parent_id IS NULL ORDER BY updated_at DESC, id DESC LIMIT :n"),
                    {"n": limit},
                )).scalars().all()  # fmt: skip
                for incident in ids:
                    made = await titles.title_for(conn, int(incident), ctx, certainty)
                    if made is None:
                        continue
                    typer.echo(f"#{incident} {made.text}")
                    for claim in made.claims if explain else ():
                        typer.echo(f"    {claim.slot}: {claim.words!r} <- {claim.fact}")
                if not ids:
                    typer.echo("no live incidents")
        finally:
            await engine.dispose()

    _run(main())
