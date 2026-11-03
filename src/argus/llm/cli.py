"""``argus llm ...``: the LLM gateway's budgets, ledger and kill switch; the providers' probes
and alarms."""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any

import typer
from sqlalchemy import text

from argus.assess.cli import _privacy
from argus.db.errors import DB_ERRORS, short_db_error
from argus.gateway.cli import ConfigOption, engine_for, load, owner_engine_for
from argus.llm import budget
from argus.llm.gateway import Call, LlmError, NoCapacity
from argus.llm.privacy import Request
from argus.llm.probe import probe
from argus.llm.prompts import PING_SCHEMA
from argus.llm.providers import LlmConfig, Tier, Trust, load_config, load_keys, pinned
from argus.llm.service import build_gateway
from argus.llm.store import PgLlmStore
from argus.llm.wire import HttpxLlmTransport

llm_app = typer.Typer(no_args_is_help=True, help="The LLM gateway: budgets, ledger, kill switch.")

PING_INSTRUCTIONS = 'This is a connection test. Answer with the JSON object {"ok": true} only.'
PING_TEXT = "Connection test from ARGUS. Reply in JSON."


def ping_call(request: Request, tier: Tier) -> Call:
    """`argus llm ping`'s call: a fixed test text, high priority, a strict schema."""
    return Call(request, PING_INSTRUCTIONS, "ping", tier, budget.Priority.HIGH, max_output=200,
                schema=PING_SCHEMA)  # fmt: skip


def _chosen(llm: LlmConfig, provider: str | None) -> LlmConfig:
    """Every provider, or the one named (a disabled one too: the person asked for it)."""
    if provider is None:
        return llm
    try:
        chosen = pinned(llm, provider, allow_disabled=True)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None
    if not next(p for p in llm.providers if p.name == provider).enabled:
        typer.echo(f"note: {provider} is disabled for ARGUS's own work; used because you named it",
                   err=True)  # fmt: skip
    return chosen


def _run[T](work: Coroutine[Any, Any, T]) -> T:
    try:
        return asyncio.run(work)
    except DB_ERRORS as exc:
        typer.echo(f"error: {short_db_error(exc)}", err=True)
        raise typer.Exit(1) from None


@llm_app.command("status")
def llm_status(config: ConfigOption = None) -> None:
    """The kill switch, this month's cost against the cap, today's use per limit, cool-downs,
    breakers, and the ledger's totals per provider."""
    settings = load(config)
    llm = load_config()
    present = load_keys(llm.keys_file, {k for p in llm.providers for k in p.keys})

    async def use() -> tuple[budget.State, list[Any]]:
        db = engine_for(settings)
        try:
            state = await PgLlmStore(db).state()
            async with db.connect() as conn:
                rows = await conn.execute(
                    text(
                        "SELECT provider, count(*), count(*) FILTER (WHERE outcome = 'ok'),"
                        " coalesce(sum(input_tokens + output_tokens), 0),"
                        " coalesce(sum(cost_usd), 0) FROM llm_calls"
                        " WHERE at >= date_trunc('month', now()) GROUP BY 1 ORDER BY 1"
                    )
                )
                return state, list(rows.all())
        finally:
            await db.dispose()

    state, rows = _run(use())
    now = datetime.now(UTC)
    typer.echo(f"kill switch: {'STOPPED' if state.stopped else 'off (calls allowed)'}")
    spent = state.spent_usd if state.month == budget.month_of(now) else 0.0
    typer.echo(f"this month: ${spent:.6f} of ${llm.monthly_cap_usd:.2f}")
    today = state.day_spent_usd if state.day == now.date().isoformat() else 0.0
    cap = f" of ${llm.daily_cap_usd:.2f}" if llm.daily_cap_usd is not None else " (no daily cap)"
    typer.echo(f"today: ${today:.6f}{cap}")
    for p in llm.providers:
        key = "key present" if any(k in present for k in p.keys) else "NO KEY"
        tiers = ", ".join(f"{t.value}={m.name}" for t, m in p.models.items())
        tasks = "every task" if p.tasks is None else "only " + ", ".join(p.tasks)
        typer.echo(f"- {p.name} ({p.trust}, {tasks}): {key}{'' if p.enabled else ', disabled'};"
                   f" {tiers}")  # fmt: skip
        alarm = state.alarms.get(p.name)
        if alarm is not None:
            typer.echo(f"    ALARM {alarm.kind} since {alarm.at:%Y-%m-%d %H:%M} UTC:"
                       f" {alarm.detail}")  # fmt: skip
        held = [end for end in state.leases.get(p.name, {}).values() if end > now]
        if p.concurrency is not None:
            typer.echo(f"    calls in flight: {len(held)} of {p.concurrency}")
        names = {b.name: b.limits for t in p.models for b in p.buckets(t)}
        for name, lim in sorted(names.items()):
            w = state.windows.get(name, budget.Window()).at(now)
            parts = [f"day {w.day_requests} req" + (f"/{lim.rpd}" if lim.rpd else "")]
            parts.append(f"{w.day_tokens} tok" + (f"/{lim.tpd}" if lim.tpd else ""))
            typer.echo(f"    {name}: {', '.join(parts)}")
        for name in [p.name, *(f"{p.name}/{m.name}" for m in p.models.values())]:
            until = state.cooldowns.get(name)
            if until is not None and until > now:
                typer.echo(f"    {name}: cooling down until {until:%H:%M:%S} UTC")
        for name in [p.name, *(f"{p.name}/{m.name}" for m in p.models.values())]:
            b = state.breakers.get(name)
            if b is not None and b.is_open(now):
                typer.echo(f"    {name}: breaker open until {b.open_until:%H:%M:%S} UTC")
        for m in sorted({m.name for m in p.models.values()}):
            recent = state.latency.get(f"{p.name}/{m}")
            if recent:
                median = sorted(recent)[len(recent) // 2] / 1000
                typer.echo(f"    {p.name}/{m}: median {median:.1f} s over the last"
                           f" {len(recent)} calls (slow above {p.slow_s:.0f} s)")  # fmt: skip
    typer.echo("ledger this month (provider, attempts, ok, tokens, cost):")
    for provider, n, ok, tokens, cost in rows:
        typer.echo(f"  {provider:12} {n:6} {ok:6} {tokens:10} ${cost:.6f}")


def _switch(stopped: bool, reason: str | None, config: Any) -> None:
    settings = load(config)
    # a stop runs as the runtime login; a resume only as the owner
    db = engine_for(settings) if stopped else owner_engine_for(settings, "llm resume")

    async def use() -> bool:
        try:
            return await PgLlmStore(db).set_stopped(stopped, actor="cli", reason=reason)
        finally:
            await db.dispose()

    changed = _run(use())
    state = "stopped" if stopped else "resumed"
    typer.echo(f"LLM calls {state}" if changed else f"LLM calls were already {state}")


@llm_app.command("stop")
def llm_stop(
    reason: Annotated[str | None, typer.Option(help="Why (audited).")] = None,
    config: ConfigOption = None,
) -> None:
    """Kill switch: no call to any model until resumed (assessments wait, nothing is lost)."""
    _switch(True, reason, config)


@llm_app.command("resume")
def llm_resume(
    reason: Annotated[str | None, typer.Option(help="Why (audited).")] = None,
    config: ConfigOption = None,
) -> None:
    """Allow calls to models again."""
    _switch(False, reason, config)


@llm_app.command("reconcile")
def llm_reconcile(config: ConfigOption = None) -> None:
    """Set this month's spend to the ledger's settled costs (reservations never settled are
    dropped); audited."""
    settings = load(config)

    async def use() -> tuple[float, float]:
        db = engine_for(settings)
        try:
            return await PgLlmStore(db).reconcile(datetime.now(UTC), actor="cli")
        finally:
            await db.dispose()

    before, after = _run(use())
    typer.echo(f"this month's spend: ${before:.6f} -> ${after:.6f} (the ledger's settled costs)")


@llm_app.command("ping")
def llm_ping(
    provider: Annotated[str | None, typer.Option(help="Only this provider.")] = None,
    tier: Annotated[Tier, typer.Option(help="Model tier.")] = Tier.SMALL,
    config: ConfigOption = None,
) -> None:
    """One tiny call with a fixed test text (no site data), through the whole gateway:
    validator, budget, ledger. Shows which provider and model answered and what it cost."""
    settings = load(config)
    privacy = _privacy(settings)
    llm = _chosen(load_config(), provider)
    request = Request(PING_TEXT, (), (), (), (), privacy.campus)
    call = ping_call(request, tier)

    async def use() -> str:
        db = engine_for(settings)
        transport = HttpxLlmTransport(llm)
        try:
            done = await build_gateway(db, llm, transport).complete(call)
            return (
                f"{done.provider} {done.model}: {done.text.strip()[:80]!r}"
                f" ({done.input_tokens}+{done.output_tokens} tokens, ${done.cost_usd:.6f},"
                f" {done.latency_ms} ms)"
            )
        except NoCapacity as exc:
            return f"no capacity now (try after {exc.until:%H:%M:%S} UTC): {exc}"
        except LlmError as exc:
            return f"refused: {exc}"
        finally:
            await transport.aclose()
            await db.dispose()

    typer.echo(_run(use()))


async def _record_up(settings: Any, names: list[str]) -> list[str]:
    """The providers found up: their alarms and cool-downs end in the shared state (audited);
    what was cleared, as lines to show."""
    db = engine_for(settings)
    try:
        store = PgLlmStore(db)
        lines = []
        for name in names:
            cleared = await store.probe_up(name, datetime.now(UTC), actor="cli")
            if cleared is not None:
                lines.append(f"{name}: alarm cleared ({cleared.kind} since"
                             f" {cleared.at:%Y-%m-%d %H:%M} UTC); calls may go now")  # fmt: skip
        return lines
    finally:
        await db.dispose()


@llm_app.command("probe")
def llm_probe(
    provider: Annotated[str | None, typer.Option(help="Only this provider.")] = None,
    config: ConfigOption = None,
) -> None:
    """Ask each enabled provider with a probe (or the one named, enabled or not) whether it is
    there: GET /v1/models, no prompt and no site data. Up, down, loading, unauthorized,
    tls_failed or model_mismatch. A provider found up has its alarm and cool-down cleared
    (audited), so ARGUS calls it again at once; exit 1 unless every one asked is up."""
    llm = _chosen(load_config(), provider)
    asked = [p for p in llm.providers if provider is not None or (p.probe and p.enabled)]
    if not asked:
        typer.echo("no enabled provider has a probe (probe: true in config/llm.yaml); name one")
        raise typer.Exit(1)
    keys = load_keys(llm.keys_file, {k for p in asked for k in p.keys})

    async def use() -> list[tuple[str, str, bool]]:
        transport = HttpxLlmTransport(llm)
        out = []
        try:
            for p in asked:
                key = next((keys[k] for k in p.keys if k in keys), None)
                if key is None:
                    out.append((p.name, "no key", False))
                    continue
                result = await probe(p, key, transport)
                out.append((p.name, f"{result.state}: {result.detail} ({result.latency_ms} ms)",
                            result.state == "up"))  # fmt: skip
        finally:
            await transport.aclose()
        return out

    results = asyncio.run(use())
    for name, line, _ in results:
        typer.echo(f"{name}: {line}")
    up = [name for name, _, ok in results if ok]
    unrecorded = "note: not recorded, so an alarm stays until a call succeeds"
    if up:
        try:
            for line in asyncio.run(_record_up(load(config), up)):
                typer.echo(line)
        except typer.Exit:  # no settings here: load() said why
            typer.echo(unrecorded, err=True)
        except DB_ERRORS as exc:
            typer.echo(f"{unrecorded} ({short_db_error(exc)})", err=True)
    if not all(ok for _, _, ok in results):
        raise typer.Exit(1)


@llm_app.command("drill")
def llm_drill(
    provider: Annotated[str, typer.Option(help="The provider (a self-hosted model).")] = "local",
    measures: Annotated[Path, typer.Option(help="The measures' folder.")] = Path("data/gate/q-g2"),
    config: ConfigOption = None,
) -> None:
    """The robustness drill and the hardening check: synthetic calls only (no site data), each
    fault made on ARGUS's side (the port, the deadline, the model, the certificate, the key, a
    held slot, an over-long prompt); each must defer within an hour (the overflow: no proposal),
    never answer, never benign. Runs on its own in-memory state: it raises no alarm in ARGUS's
    shared state. Writes the ladder's measure; exit 1 unless every case and check passed."""
    from argus.evaluation import ladder, robustness
    from argus.evaluation import measures as qg2

    settings = load(config)
    privacy = _privacy(settings)
    llm = _chosen(load_config(), provider)
    if llm.providers[0].trust is not Trust.CAMPUS:
        typer.echo("error: the drill checks the campus machine (trust: campus)", err=True)
        raise typer.Exit(1)
    keys = load_keys(llm.keys_file, set(llm.providers[0].keys))
    if not any(k in keys for k in llm.providers[0].keys):
        typer.echo(f"error: no key for {provider} in {llm.keys_file}", err=True)
        raise typer.Exit(1)
    result = asyncio.run(robustness.drill(llm, keys, privacy.campus, HttpxLlmTransport))
    where = qg2.folder(measures, provider) / "drill.json"
    qg2.write(where, result.as_json(datetime.now(UTC)))
    for check, ok in result.hardening.items():
        typer.echo(f"hardening {check}: {'ok' if ok else 'FAILED'}")
    for case, got in result.cases.items():
        wait = f" ({got.wait_s:.0f} s)" if got.wait_s is not None else ""
        typer.echo(f"{case}: {got.outcome}{wait}: {got.detail}")
    measured = ladder.Measures(provider=provider, model=result.model, trust="campus",
                               hardening=result.hardening, robustness=result.cases)  # fmt: skip
    rung = ladder.robustness_rung(measured)
    typer.echo(f"measure written to {where}")
    hardened = all(result.hardening.get(h, False) for h in ladder.HARDENING)
    if rung.state is not ladder.State.PASS or not hardened:
        for line in rung.lines if rung.state is not ladder.State.PASS else ():
            typer.echo(f"  - {line}")
        raise typer.Exit(1)


@llm_app.command("shadow")
def llm_shadow(
    task: Annotated[str, typer.Option(help="extract, triage, summary, notes or fallback.")],
    provider: Annotated[str, typer.Option(help="The model's provider.")] = "local",
    hours: Annotated[float, typer.Option(help="Live items: dossiers this recent.", min=1)] = 24,
    limit: Annotated[int, typer.Option(help="At most this many items a run.", min=1)] = 50,
    allow_disabled: Annotated[
        bool, typer.Option(help="Use the provider even if config/llm.yaml disables it.")
    ] = False,
    config: ConfigOption = None,
) -> None:
    """The model answers live items for one helper task in shadow: evaluation calls
    (low priority, overnight, the evaluation budget), stored in llm_shadow and never shown.
    Resumable: items already answered by this model are skipped."""
    from argus.evaluation import measures as qg2
    from argus.evaluation import shadow, tasks

    spec = tasks.SPECS.get(task)
    if spec is None:
        typer.echo(f"error: no task {task!r} ({', '.join(tasks.SPECS)})", err=True)
        raise typer.Exit(1)
    settings = load(config)
    privacy = _privacy(settings)
    try:  # live items are real data: a disabled provider only when asked
        llm = pinned(load_config(), provider, allow_disabled=allow_disabled)
    except ValueError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from None
    why = qg2.require_licence(llm)
    if why is not None:
        typer.echo(f"error: {why}", err=True)
        raise typer.Exit(1)
    if settings.web.database_role != "api":
        # the shadow is never shown; the runtime login the web uses until then may read it
        typer.echo("error: shadow answers are never shown, and the web logs in as"
                   f" {settings.database.user}, which may read llm_shadow: give the web its own"
                   " login first (Q-A2: ARGUS_DATABASE__API_PASSWORD, `argus db bootstrap`,"
                   " web.database_role: api)", err=True)  # fmt: skip
        raise typer.Exit(1)
    model = llm.providers[0].models[Tier.SMALL].name

    async def use() -> shadow.ShadowRun:
        db = engine_for(settings)
        transport = HttpxLlmTransport(llm)
        try:
            gateway = build_gateway(db, llm, transport)
            since = datetime.now(UTC) - timedelta(hours=hours)
            return await shadow.run(db, spec, privacy, gateway.complete, llm, provider, model,
                                    since, limit)  # fmt: skip
        finally:
            await transport.aclose()
            await db.dispose()

    done = _run(use())
    typer.echo(f"{task} in shadow on {provider}/{model}: {done.stored} stored ({done.usable}"
               f" usable), {done.skipped} skipped")  # fmt: skip
    if done.stopped:
        typer.echo(f"stopped early: {done.stopped} (run again to resume)")
