"""``argus assess ...``: queue and run assessments, the decision engine."""

from __future__ import annotations

import asyncio
import os
import socket
from collections.abc import Coroutine
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

import typer
from sqlalchemy import text

from argus import raising
from argus.agent.registry import Trigger
from argus.assess import engine as decision
from argus.assess import patterns, queue, runner
from argus.assets.store import NoAssetMapError
from argus.db.errors import DB_ERRORS, short_db_error
from argus.gateway.cli import ConfigOption, engine_for, load
from argus.llm.privacy import Privacy, PrivacyConfigError, load_policy, privacy_map

assess_app = typer.Typer(no_args_is_help=True, help="Assessments: proposed outcomes (Phase 2).")


def _run[T](work: Coroutine[Any, Any, T]) -> T:
    try:
        return asyncio.run(work)
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None


def _privacy(settings: Any) -> Privacy:
    try:
        assets = privacy_map(settings)
    except NoAssetMapError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None
    try:
        return Privacy.build(load_policy(), assets, settings.site.own_networks)
    except PrivacyConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None


@assess_app.command("run")
def assess_run(
    once: Annotated[bool, typer.Option(help="One pass, then stop.")] = False,
    every: Annotated[int, typer.Option(help="Seconds between passes.")] = 300,
    agent: Annotated[
        bool, typer.Option(help="Also run the investigation agent after the engine.")
    ] = False,
    agent_per_day: Annotated[
        int, typer.Option(min=0, help="At most this many agent runs (patterns) a day.")
    ] = 100,
    agent_batch: Annotated[int, typer.Option(min=1, help="Agent runs per pass.")] = 3,
    tuning: Annotated[
        bool, typer.Option(help="Also write the weekly rule-tuning reports.")
    ] = False,
    config: ConfigOption = None,
) -> None:
    """Queue what needs assessing and assess it with the decision engine, forever (a service) or
    once. The engine relearns its keys every pass. Each pass also reads the evidence of new
    dossiers and raises the flagged ones into Needs attention, and every 15 minutes suggests cases
    from evidence across investigations (``cases.suggest``). With a VirusTotal key
    (``ARGUS_OUTSIDE__VIRUSTOTAL_API_KEY``) it also looks up the outside destinations of
    beacon-flagged investigations within a daily budget, and writes the incident report of each
    suggested or open case whose evidence changed (``incident.*``). With --agent, what the engine
    cannot decide goes to the investigation agent once per pattern, within a daily quota; the
    agent's files are checked every pass, and while they are refused the agent is off and the
    engine keeps running."""
    settings = load(config)
    privacy = _privacy(settings)
    owner = f"{socket.gethostname()}:{os.getpid()}"

    async def loop() -> None:
        db = engine_for(settings)
        outside, shared, close_outside = raising.outside_for(settings, privacy, db)
        investigator, close = (None, None)
        incident_prose: Any = None  # the summary's prose for the incident reports, when on
        close_prose: Any = None
        prose_off = False  # the gateway could not be built: not tried again this run
        off: str | None = None  # why the agent is off, as last said
        suggested_at: datetime | None = None  # when cases were last suggested
        titled_at: datetime | None = None  # when the case titles were last refreshed
        titles = raising.titles_for(settings, privacy)
        deep = await _investigation(settings, privacy, db)  # the wave and "Check more"
        classifier = getattr(privacy, "classifier", None)
        known = raising.known_for(
            settings, privacy, shared, None if outside is None else outside.view
        )
        try:
            while True:
                now = datetime.now(UTC)
                async with db.begin() as conn:
                    learned = await decision.learn(conn)
                    stamp = learned.fingerprint()
                    again = await queue.requeue(
                        conn, decision.NAME, f"{decision.NAME}#{stamp}", now
                    )
                    queued = await runner.schedule(conn, privacy, decision.NAME, now)
                counts = {"queued": queued, "requeued": again}
                while True:
                    done = await runner.run_once(
                        db, decision.Engine(learned, now, outside.view), owner,
                        lambda: datetime.now(UTC), 50,
                    )  # fmt: skip
                    for k, v in done.items():
                        counts[k] = counts.get(k, 0) + v
                    if not any(done.values()):
                        break
                typer.echo(" ".join(f"{k} {v}" for k, v in counts.items()))
                owed: set[Any] = set()
                if deep is not None:  # deterministic checks before any model is asked
                    from argus.investigation import wave

                    done_ = await wave.run_pass(deep[0], owner, wave=settings.investigation.wave)
                    typer.echo("investigation: " + " ".join(f"{k} {v}" for k, v in done_.items()))
                    if settings.investigation.wave:
                        async with db.connect() as conn:
                            owed = await wave.owed(deep[0], conn, datetime.now(UTC))
                flagged = await raising.run(
                    db, classifier, now,
                    suggesting=settings.cases.suggest, last=suggested_at,
                    outside=outside, shared=shared, window=settings.history.window,
                    resolvers=settings.campaigns.resolvers,
                    offers_per_hour=settings.cases.offers_per_hour,
                    known=known, titles=titles, titled_last=titled_at,
                )  # fmt: skip
                suggested_at = flagged.suggested_at
                titled_at = flagged.titled_at
                for line in flagged.said:
                    typer.echo(line)
                for line in flagged.warned:
                    typer.echo(line, err=True)
                if settings.incident.enabled:  # the incident reports: a failure never stops it
                    from argus.incident import run as incident_run

                    if (
                        settings.incident.prose
                        and incident_prose is None
                        and not prose_off
                        and _no_model() is None
                    ):
                        incident_prose, close_prose, prose_off = await _incident_prose(
                            settings, privacy, db
                        )
                    wrote = await incident_run.run_pass(
                        db, settings, now, classifier=classifier, prose_fn=incident_prose
                    )
                    for line in wrote.said:
                        typer.echo(line)
                    for line in wrote.warned:
                        typer.echo(line, err=True)
                if settings.signins.enabled:  # who was behind an address; never stops the pass
                    await _signins(settings, db, deep, classifier)
                else:  # the retention of what was kept holds with the switch off
                    await _signins_retention(settings, db)
                agents, refused = _agents() if agent else (None, None)
                keyless = _no_model() if agent or tuning else None
                if refused is None and agents is not None and keyless is not None:
                    from argus.agent.loader import AgentError

                    agents, refused = None, AgentError(keyless)
                if refused is not None:
                    why = str(refused)
                    if why != off:
                        typer.echo(f"warning: the investigation agent is off: {why}. The"
                                   " decision engine runs without it; what waits for the"
                                   " agent stays queued.", err=True)  # fmt: skip
                    off = why
                    from argus.agent.loader import AgentOffError

                    switched = isinstance(refused, AgentOffError)
                    because = (
                        "switched off in code"
                        if switched
                        else "no model key"
                        if keyless is not None
                        else "its files are refused"
                    )
                    typer.echo(f"agent: off ({because})")  # fmt: skip
                elif agents is not None:
                    if off is not None:
                        typer.echo("the investigation agent is on again: its files load", err=True)
                        off = None
                    if investigator is None:
                        investigator, close = _agent(settings, privacy, db, agents, outside)
                    handed = patterns.Scheduled(0, 0)
                    if investigator.takes(Trigger.ENGINE_NO_DECISION):  # its file may say not
                        async with db.begin() as conn:
                            handed = await patterns.schedule(
                                conn, privacy, investigator.name, now, limit=agent_batch,
                                after=decision.NAME, per_day=agent_per_day, skip=owed,
                            )  # fmt: skip
                    done = await runner.run_once(
                        db, investigator, owner, lambda: datetime.now(UTC), agent_batch
                    )
                    shown = " ".join(f"{k} {v}" for k, v in done.items() if v)
                    said = f"queued {handed.queued} patterns, shared {handed.shared}"
                    typer.echo(f"agent: {said} {shown}".rstrip())
                if tuning and await _tuning_due(db, now):
                    from argus.tuning.cli import run as tune

                    for line in await tune(settings, model=keyless is None):
                        typer.echo(f"tuning: {line}")
                if once:
                    return
                await asyncio.sleep(every)
        finally:
            await close_outside()
            if close is not None:
                await close()
            if close_prose is not None:
                await close_prose()
            if deep is not None:
                await deep[1]()
            await db.dispose()

    _run(loop())


async def _signins(settings: Any, db: Any, deep: Any, classifier: Any) -> None:
    """The sign-in pass: a few requests for the SSO sign-ins of the investigations'
    internal addresses, through the gateway the wave uses. A failure is said and goes on."""
    from argus.signins import run as signins_run

    env = None if deep is None else deep[0]
    try:
        report = await signins_run.run_pass(
            db, None if env is None else env.gateway, None if env is None else env.state,
            settings, classifier, health_config=None if env is None else env.health_config,
        )  # fmt: skip
    except DB_ERRORS as exc:
        typer.echo(f"signins: {short_db_error(exc)}", err=True)
        return
    except Exception as exc:  # a failed pass is said and the loop goes on
        typer.echo(f"signins: failed ({type(exc).__name__})", err=True)
        return
    for line in report.said:
        typer.echo(line)
    for line in report.warned:
        typer.echo(line, err=True)


async def _signins_retention(settings: Any, db: Any) -> None:
    """With the sign-in lookups switched off, what they kept is still pruned at ``keep_days``
    (personal data). Silent unless something was removed; a database without the tables yet is
    no error."""
    from argus.signins import run as signins_run

    try:
        for line in await signins_run.prune(db, settings.signins, datetime.now(UTC), strict=False):
            typer.echo(line)
    except Exception as exc:  # retention is best effort here and never stops the pass
        typer.echo(f"signins: retention failed ({type(exc).__name__})", err=True)


def _no_model() -> str | None:
    """Why no model can be called (no keys file, or no enabled provider with a key), or None.
    Then the agent is off, the tuning reports carry no suggestions and the incident reports keep
    their deterministic text: nothing waits on a call that cannot be made."""
    from argus.llm.providers import callable_providers, load_config

    try:
        config = load_config()
    except (OSError, ValueError) as exc:
        return f"the LLM configuration cannot be read ({type(exc).__name__})"
    if callable_providers(config):
        return None
    if config.keys_file is None:
        return "no model key (llm keys_file: none): ARGUS investigates deterministically"
    return f"no enabled provider has a key in {config.keys_file}"


async def _incident_prose(settings: Any, privacy: Privacy, db: Any) -> tuple[Any, Any, bool]:
    """The summary's prose for the incident reports (``incident.prose``): a function that
    words a report's summary through the LLM gateway and the citation checks, its close function,
    and whether it could not be built (then reports keep their deterministic text and the pass says
    so once). Never raises: the pass goes on without it."""
    from argus.incident import prose
    from argus.llm.providers import load_config
    from argus.llm.service import build_gateway
    from argus.llm.wire import HttpxLlmTransport

    try:
        llm = load_config()
        transport = HttpxLlmTransport(llm)
        gateway = build_gateway(db, llm, transport)
    except Exception as exc:  # no keys, no providers file: the text stays deterministic
        typer.echo(f"incident reports: no model for the summary ({type(exc).__name__}):"
                   " deterministic text only", err=True)  # fmt: skip
        return None, None, True

    async def words(report: Any) -> Any:
        return await prose.improve(report, gateway.complete, privacy.campus)

    return words, transport.aclose, False


async def _investigation(settings: Any, privacy: Privacy, db: Any) -> Any:
    """The wave's environment with the real gateway and its close function, or None when
    the SIEM cannot be reached from here (the wave and "Check more" then wait)."""
    from argus.investigation import service

    opened = await service.open_env(settings, db, getattr(privacy, "classifier", None))
    if opened is None and settings.investigation.wave:
        typer.echo("warning: investigation.wave is on, but the SIEM is not set up here (no key or"
                   " pinned certificate): the wave and Check more wait", err=True)  # fmt: skip
    return opened


async def _tuning_due(db: Any, now: datetime) -> bool:
    """A week since the newest tuning report (or none yet)."""
    from argus.tuning import store as tuning_store

    async with db.connect() as conn:
        last = await tuning_store.last_week_end(conn)
    return last is None or now - last >= timedelta(days=7)


def _agents() -> tuple[Any, Any]:
    """The investigation agent's files (``config/agents/``), pinned and enabled, and None;
    or None and the refusal (a refused file never runs the agent; ``loader.AgentOffError``
    when it is switched off in code), an OSError's reason made one too."""
    from argus.agent import loader

    try:
        return loader.load(), None
    except loader.AgentError as exc:
        return None, exc
    except OSError as exc:
        return None, loader.AgentError(str(exc))


def _agent(
    settings: Any, privacy: Privacy, db: Any, agents: Any, outside: Any = None
) -> tuple[Any, Any]:
    """The investigation agent with every provider (fallback in order), the SIEM's evidence
    through the Elastic gateway (when it can be built; else its asks are unavailable) and outside
    threat intel (``outside``: a source without a key answers that it is off)."""
    from argus.agent import service
    from argus.agent.agent import Agent
    from argus.config.errors import ConfigError
    from argus.context.packs import default_registry
    from argus.gateway.service import build_gateway as siem_gateway
    from argus.llm.providers import load_config
    from argus.llm.service import build_gateway
    from argus.llm.wire import HttpxLlmTransport

    packs = default_registry(
        privacy.classifier,
        remote_ti=settings.reference.ti_sync,
        log_queries=settings.enrichment.log_queries,
        proxy_aggregations=settings.enrichment.proxy_aggregations,
    )
    try:
        siem = siem_gateway(settings.siem, db)[0]
    except ConfigError:
        siem = None
    llm = load_config()
    transport = HttpxLlmTransport(llm)  # one pinned client per provider
    fetch, snapshots = service.evidence(db, siem, packs, lambda: datetime.now(UTC))
    gateway = build_gateway(db, llm, transport)
    investigator = Agent(privacy, gateway.complete, packs, fetch, snapshots, privacy.classifier,
                         agents=agents, outside=outside)  # fmt: skip

    async def close() -> None:
        await transport.aclose()
        if siem is not None:
            await siem.transport.aclose()  # type: ignore[attr-defined]

    return investigator, close


@assess_app.command("status")
def assess_status(config: ConfigOption = None) -> None:
    """Assessments by assessor and status, and the current proposals by outcome."""
    settings = load(config)

    async def use() -> list[Any]:
        db = engine_for(settings)
        try:
            async with db.connect() as conn:
                rows = await conn.execute(
                    text(
                        "SELECT assessor, status, coalesce(outcome, '-'), count(*)"
                        " FROM assessments GROUP BY 1, 2, 3 ORDER BY 1, 2, 3"
                    )
                )
                return list(rows.all())
        finally:
            await db.dispose()

    rows = _run(use())
    if not rows:
        typer.echo("no assessments yet")
    for assessor, status, outcome, count in rows:
        typer.echo(f"{assessor:12} {status:12} {outcome:20} {count}")


@assess_app.command("keys")
def assess_keys(config: ConfigOption = None) -> None:
    """The keys the engine has learned, with their support and what each may decide."""
    settings = load(config)

    async def use() -> decision.Learned:
        db = engine_for(settings)
        try:
            async with db.connect() as conn:
                return await decision.learn(conn)
        finally:
            await db.dispose()

    now = datetime.now(UTC)
    learned = _run(use())
    rows = list(decision.describe(learned, now))
    deciding = [r for r in rows if r[2]]
    typer.echo(f"{len(rows)} keys, {len(deciding)} may decide")
    for key, support, outcome in deciding:
        typer.echo(f"- {' / '.join(key)}: {support} labels -> {outcome}")
