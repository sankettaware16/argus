"""``argus gold ...``: store the chosen gold set and show its progress (P2, D-080)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated, Any

import typer

from argus.db.errors import DB_ERRORS, short_db_error
from argus.evaluation import measures as qg2
from argus.evaluation import store
from argus.gateway.cli import ConfigOption, engine_for, load

gold_app = typer.Typer(no_args_is_help=True, help="The gold set: the answer key (P2).")
MANIFEST = Path("data/gold/candidates-v1.json")


def _named(set_name: str) -> str | None:
    return store.ANY if set_name == "all" else set_name


@gold_app.command("import")
def gold_import(
    file: Annotated[
        Path, typer.Option(help="The manifest from scripts/gold_select.py.")
    ] = MANIFEST,
    set_name: Annotated[str, typer.Option("--set", help="The set's name.")] = store.SET,
    config: ConfigOption = None,
) -> None:
    """Store the chosen set once (a set is frozen); each item is checked against its dossier."""
    settings = load(config)
    try:
        records = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        typer.echo(f"error: cannot read {file}: {type(exc).__name__}", err=True)
        raise typer.Exit(1) from None

    async def use() -> int:
        engine = engine_for(settings)
        try:
            async with engine.begin() as conn:
                return await store.import_set(conn, records, set_name)
        except store.GoldError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(1) from None
        except DB_ERRORS as exc:
            typer.echo(f"error: {short_db_error(exc)}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()

    typer.echo(f"stored {asyncio.run(use())} items as the gold set {set_name!r}")


@gold_app.command("status")
def gold_status(
    set_name: Annotated[str, typer.Option("--set", help="The set's name, or all.")] = store.SET,
    config: ConfigOption = None,
) -> None:
    """How many items a person has answered."""
    settings = load(config)

    async def use() -> dict[str, int]:
        engine = engine_for(settings)
        try:
            async with engine.connect() as conn:
                return await store.progress(conn, _named(set_name))
        except DB_ERRORS as exc:
            typer.echo(f"error: {short_db_error(exc)}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()

    p = asyncio.run(use())
    typer.echo(
        f"{p['answered']} of {p['items']} answered (dev {p['dev_answered']},"
        f" test {p['test_answered']})"
    )


@gold_app.command("score")
def gold_score(
    split: Annotated[str, typer.Option(help="dev, test or all.")] = "test",
    by: Annotated[str, typer.Option(help="suggestions or engine.")] = "suggestions",
    set_name: Annotated[str, typer.Option("--set", help="The set's name, or all.")] = store.SET,
    config: ConfigOption = None,
) -> None:
    """Score a decision-maker against the person's answers: ARGUS's own pre-filled
    suggestions (the baseline), or the decision engine (P4) at each item's gold dossier."""
    from datetime import UTC, datetime

    from sqlalchemy import text

    from argus.assess import engine as decision
    from argus.evaluation import harness

    settings = load(config)

    async def use() -> tuple[list[store.GoldRow], dict[str, str | None]]:
        engine = engine_for(settings)
        try:
            async with engine.connect() as conn:
                rows = await store.items(conn, _named(set_name))
                if by != "engine":
                    return rows, {
                        str(r.investigation_id): r.suggestion.get("outcome") for r in rows
                    }
                learned = await decision.learn(conn)
                now = datetime.now(UTC)
                out: dict[str, str | None] = {}
                for r in rows:
                    body = await conn.scalar(
                        text(
                            "SELECT d.body FROM gold_items g JOIN dossiers d ON"
                            " d.investigation_id = g.investigation_id AND d.version = g.version"
                            " AND d.pack = g.pack AND d.dossier_hash = g.dossier_hash"
                            " WHERE (CAST(:s AS text) IS NULL OR g.set_name = :s)"
                            " AND g.investigation_id = :i"
                        ),
                        {"s": _named(set_name), "i": r.investigation_id},
                    )
                    d = decision.decide(
                        body, learned, now, await decision.first_seen(conn, r.investigation_id),
                        await decision.spike(conn, r.investigation_id),
                    )  # fmt: skip
                    out[str(r.investigation_id)] = d.outcome
                return rows, out
        except DB_ERRORS as exc:
            typer.echo(f"error: {short_db_error(exc)}", err=True)
            raise typer.Exit(1) from None
        finally:
            await engine.dispose()

    rows, predicted = asyncio.run(use())
    items = harness.from_gold(list(rows), predicted, None if split == "all" else split)
    title = "the decision engine" if by == "engine" else "ARGUS's suggestions"
    for line in harness.report(harness.score(items), f"{title}, {split} part"):
        typer.echo(line)


@gold_app.command("compare")
def gold_compare(
    arms_: Annotated[
        str | None, typer.Option("--arms", help="Comma-separated arms (default: all but A-real).")
    ] = None,
    provider: Annotated[str, typer.Option(help="The one provider (the model is pinned).")] = (
        "openai"
    ),
    tier: Annotated[str, typer.Option(help="Model tier.")] = "small",
    limit: Annotated[int | None, typer.Option(help="Only the first N items.")] = None,
    out: Annotated[Path, typer.Option(help="Answers kept here (resumable).")] = Path(
        "data/gate/p2/compare/answers.json"
    ),
    allow_disabled: Annotated[
        bool, typer.Option(help="Use the provider even if config/llm.yaml disables it.")
    ] = False,
    config: ConfigOption = None,
) -> None:
    """The privacy comparison (D-078): every answered gold item through each arm, one pinned
    model, low priority; then the scores and the decision. The labels are never sent."""
    from argus.assess.cli import _privacy
    from argus.evaluation import comparison
    from argus.llm.providers import Tier, load_config, pinned
    from argus.llm.service import build_gateway
    from argus.llm.wire import HttpxLlmTransport

    settings = load(config)
    privacy = _privacy(settings)
    try:
        llm = pinned(load_config(), provider, allow_disabled=allow_disabled)
        model = f"{provider}/{llm.providers[0].models[Tier(tier)].name}"
    except (ValueError, KeyError) as exc:
        typer.echo(f"error: {exc if isinstance(exc, ValueError) else f'no tier {tier}'}",
                   err=True)  # fmt: skip
        raise typer.Exit(1) from None
    _licensed(llm)
    names = tuple(a.strip() for a in arms_.split(",")) if arms_ else comparison.DEFAULT_ARMS

    async def use() -> list[str]:
        engine = engine_for(settings)
        transport = HttpxLlmTransport(llm)
        try:
            async with engine.connect() as conn:
                cases = await comparison.gold_cases(conn)
            cases = cases[:limit] if limit is not None else cases
            gateway = build_gateway(engine, llm, transport)
            result = await comparison.run(cases, privacy, gateway.complete, out, names, Tier(tier),
                                          model=model)  # fmt: skip
            return comparison.report(cases, result)
        finally:
            await transport.aclose()
            await engine.dispose()

    try:
        lines = asyncio.run(use())
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None
    for line in lines:
        typer.echo(line)


@gold_app.command("agent")
def gold_agent(
    tools: Annotated[bool, typer.Option(help="Let the agent ask the SIEM for evidence.")] = False,
    inject: Annotated[
        bool, typer.Option(help="The prompt-injection test instead (no tools).")
    ] = False,
    provider: Annotated[str, typer.Option(help="The one provider (models pinned).")] = "openai",
    limit: Annotated[int | None, typer.Option(help="Only the first N items.")] = None,
    out: Annotated[Path, typer.Option(help="Verdicts kept here (resumable).")] = Path(
        "data/gate/p6/agent-gold.json"
    ),
    allow_disabled: Annotated[
        bool, typer.Option(help="Use the provider even if config/llm.yaml disables it.")
    ] = False,
    repeat: Annotated[
        int,
        typer.Option(
            help="A repeat of the same run, kept apart (Q-G2: 1 for the cloud's repeat).",
            min=0,
            max=9,
        ),
    ] = 0,
    attacks: Annotated[
        bool,
        typer.Option(
            help="With --inject: every payload in turn, small-model attacks included (Q-G2)."
        ),
    ] = False,
    measures: Annotated[
        Path | None,
        typer.Option(
            help="Also write the ladder's measure under this folder (Q-G2: data/gate/q-g2)."
        ),
    ] = None,
    config: ConfigOption = None,
) -> None:
    """The investigation agent (P6) on every answered gold item, scored against the person's
    answers. Without --tools no evidence is asked of the SIEM (the frozen dossier only)."""
    from datetime import UTC, datetime

    from argus.agent import loader, service
    from argus.agent.agent import Agent
    from argus.assess.cli import _privacy
    from argus.context.packs import TaskSpec, default_registry
    from argus.evaluation import agent_eval, comparison
    from argus.gateway.service import build_gateway as siem_gateway
    from argus.llm import budget
    from argus.llm.providers import EVALUATE, load_config, models_of, pinned
    from argus.llm.service import build_gateway
    from argus.llm.wire import HttpxLlmTransport

    settings = load(config)
    tools = tools and not inject
    try:
        agents = loader.load()  # the pinned, enabled files (Q-H1)
    except loader.AgentError as exc:
        typer.echo(f"error: the investigation agent is refused: {exc}", err=True)
        raise typer.Exit(1) from None
    privacy = _privacy(settings)
    try:
        llm = pinned(load_config(), provider, allow_disabled=allow_disabled)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None
    _licensed(llm)
    models = models_of(llm)
    packs = default_registry(
        privacy.classifier,
        remote_ti=settings.reference.ti_sync,
        log_queries=settings.enrichment.log_queries,
        proxy_aggregations=settings.enrichment.proxy_aggregations,
    )

    def clock() -> datetime:
        return datetime.now(UTC)

    async def use() -> list[str]:
        engine = engine_for(settings)
        transport = HttpxLlmTransport(llm)
        siem = siem_gateway(settings.siem, engine)[0] if tools else None
        try:
            fetch, snapshots = service.evidence(engine, siem, packs, clock)
            fetch = agent_eval.outside_siem_pause(fetch, clock)  # never 00:00-01:30 UTC
            if not tools:

                async def fetch(inv: Any, version: int, spec: TaskSpec) -> Any:
                    ref = spec.ref()
                    return {"task_key": ref["task_key"], "status": service.UNAVAILABLE,
                            "template": f"{ref['template']}@{ref['version']}", "coverage": {},
                            "row_count": None, "truncated": False, "result_hash": None}  # fmt: skip

            gateway = build_gateway(engine, llm, transport)
            # an evaluation: the pinned, enabled files (Q-H1); the providers' "evaluate"
            # allowlists, low priority, overnight, and the wall clock of the pinned provider's
            # timeout (Q-G1)
            agent = Agent(privacy, gateway.complete, packs, fetch, snapshots, privacy.classifier,
                          agents=agents, purpose=EVALUATE, priority=budget.Priority.LOW,
                          provider_timeout_s=llm.providers[0].timeout_s)  # fmt: skip
            async with engine.connect() as conn:
                cases = await comparison.gold_cases(conn)
                rows = await store.items(conn)
            cases = cases[:limit] if limit is not None else cases

            if inject:
                lines, measured = await agent_eval.injection_measured(
                    engine, cases, agent, out, models, rotate=attacks
                )
                if measured is not None and measures is not None:
                    where = qg2.folder(measures, provider) / "agent-injection.json"
                    qg2.write(where, qg2.wrapped(llm, measured.model_dump()))
                    lines.append(f"measure written to {where}")
                return lines

            async def progress(iid: str) -> None:
                typer.echo(f"  assessed {iid}", err=True)

            verdicts, stopped = await agent_eval.evaluate(engine, cases, agent, out, tools,
                                                          progress, models, repeat)  # fmt: skip
            lines = agent_eval.report(rows, verdicts)
            if stopped:
                lines.append(f"stopped early: {stopped} (run again to resume)")
            elif measures is not None:
                name = "agent.json" if not repeat else f"agent-r{repeat}.json"
                where = qg2.folder(measures, provider) / name
                qg2.write(where, qg2.wrapped(llm, agent_eval.verdict_measure(verdicts, models,
                                                                              repeat)))  # fmt: skip
                lines.append(f"measure written to {where}")
            return lines
        finally:
            await transport.aclose()
            if siem is not None:
                await siem.transport.aclose()  # type: ignore[attr-defined]
            await engine.dispose()

    try:
        lines = asyncio.run(use())
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None
    for line in lines:
        typer.echo(line)


def _licensed(llm: Any) -> None:
    """Evaluation calls to a campus model wait for its licence's confirmation (Q-G2)."""
    why = qg2.require_licence(llm)
    if why is not None:
        typer.echo(f"error: {why}", err=True)
        raise typer.Exit(1)


@gold_app.command("task")
def gold_task(
    task: Annotated[str, typer.Option(help="extract, triage, summary, notes or fallback.")],
    provider: Annotated[str, typer.Option(help="The one provider (the model is pinned).")] = (
        "local"
    ),
    items: Annotated[
        int,
        typer.Option(
            help="extract, summary, notes: the item set's size (frozen at the first run).", min=1
        ),
    ] = 250,
    inject: Annotated[
        bool,
        typer.Option(
            help="Also the first items clean again and with a planted"
            " instruction (the payloads in turn)."
        ),
    ] = False,
    inject_items: Annotated[
        int, typer.Option(help="How many items the injection test takes.", min=1)
    ] = 36,
    limit: Annotated[int | None, typer.Option(help="Only the first N items.")] = None,
    measures: Annotated[Path, typer.Option(help="The measures' folder.")] = qg2.ROOT,
    allow_disabled: Annotated[
        bool, typer.Option(help="Use the provider even if config/llm.yaml disables it.")
    ] = False,
    config: ConfigOption = None,
) -> None:
    """A helper task (Q-G2) on its gold set, checked against the text each item sent:
    triage and the fallback on the answered gold items, the others on a frozen set of
    items. Evaluation calls (low priority, overnight); resumable; writes the ladder's
    measure. The labels are never sent."""
    from argus.assess.cli import _privacy
    from argus.evaluation import taskrun, tasks
    from argus.llm.providers import load_config, models_of, pinned
    from argus.llm.service import build_gateway
    from argus.llm.wire import HttpxLlmTransport

    spec = tasks.SPECS.get(task)
    if spec is None:
        typer.echo(f"error: no task {task!r} ({', '.join(tasks.SPECS)})", err=True)
        raise typer.Exit(1)
    settings = load(config)
    privacy = _privacy(settings)
    try:
        llm = pinned(load_config(), provider, allow_disabled=allow_disabled)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None
    _licensed(llm)
    here = qg2.folder(measures, provider)

    async def use() -> list[str]:
        engine = engine_for(settings)
        transport = HttpxLlmTransport(llm)
        try:
            notes: list[str] = []
            async with engine.connect() as conn:
                if task in (tasks.TRIAGE, tasks.FALLBACK):
                    cases = await qg2.gold_cases(conn)
                else:
                    cases, notes = await qg2.item_set(conn, measures / "task-items.json", items)
            cases = cases[:limit] if limit is not None else cases
            gateway = build_gateway(engine, llm, transport)
            scored = await taskrun.run_task(spec, cases, privacy, gateway.complete, llm,
                                            here / f"task-{task}.answers.json", models_of(llm),
                                            inject, inject_items)  # fmt: skip
            measured = taskrun.measure(spec, cases, scored)
            lines = [*notes, f"{task} on {provider}: {len(cases)} items, {scored.calls} calls,"
                             f" {scored.usable} usable; {measured.items} items answered,"
                             f" {len(measured.failed)} failing the check;"
                             f" {scored.too_large} too large for the model"]  # fmt: skip
            if scored.stopped:
                lines.append(f"stopped early: {scored.stopped} (run again to resume)")
            else:
                qg2.write(here / f"task-{task}.json", qg2.wrapped(llm, measured.model_dump()))
                lines.append(f"measure written to {here / f'task-{task}.json'}")
            return lines
        finally:
            await transport.aclose()
            await engine.dispose()

    try:
        lines = asyncio.run(use())
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None
    for line in lines:
        typer.echo(line)


@gold_app.command("ladder")
def gold_ladder(
    provider: Annotated[str, typer.Option(help="The model's provider.")] = "local",
    cloud: Annotated[
        str | None, typer.Option(help="The cloud run its gold answers are compared with.")
    ] = "openai",
    task: Annotated[str | None, typer.Option(help="One task (default: all).")] = None,
    measures: Annotated[Path, typer.Option(help="The measures' folder.")] = qg2.ROOT,
    config: ConfigOption = None,
) -> None:
    """The evaluation ladder (Q-G2, plan §7.4): how far the model got on each task, rung by
    rung, from what has been measured. It promotes nothing: a promotion is a person's
    decision. Writes the report as JSON beside the measures."""
    from argus.evaluation import ladder, tasks
    from argus.llm.providers import Trust, load_config, pinned

    settings = load(config)
    try:
        llm = pinned(load_config(), provider, allow_disabled=True)
        other = pinned(load_config(), cloud, allow_disabled=True) if cloud else None
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None
    if other is not None and (cloud == provider or other.providers[0].trust is not Trust.CLOUD):
        # F6: the model compared with itself, or with another campus model, proves nothing
        typer.echo(f"error: --cloud must name a cloud provider other than {provider}, not"
                   f" {cloud}", err=True)  # fmt: skip
        raise typer.Exit(1)
    names = [task] if task else [*sorted(tasks.SPECS), "assess"]

    async def use() -> tuple[ladder.Measures, list[str]]:
        engine = engine_for(settings)
        try:
            async with engine.connect() as conn:
                return await qg2.build(conn, llm, measures, other)
        finally:
            await engine.dispose()

    try:
        built, notes = asyncio.run(use())
        ladders = [ladder.judge(name, built) for name in names]
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None
    lines = ladder.report(ladders)
    lines += [f"note: {n}" for n in notes]
    where = qg2.folder(measures, provider) / "ladder.json"
    qg2.write(where, {"measures": built.model_dump(), "report": lines})
    for line in lines:
        typer.echo(line)
    typer.echo(f"report written to {where}")
