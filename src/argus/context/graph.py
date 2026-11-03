"""The context graph (plan §8, D-054).

``START → run_kind → load → resolve_family → local_context → derive_local_signals →
plan_wave → (Send per task → collect_evidence, or straight on) → validate_evidence →
(↺ plan_wave while waves remain) → derive_signals → persist_dossier → END``

The state holds references only (evidence refs keyed by task key, a bounded facts digest);
snapshots live in Postgres. Every node's output is measured as the saver stores it, and a
state over ``STATE_LIMIT`` is a bug. Nothing here retries or times out: the gateway owns
both. What a run needs besides its state (database, gateway, packs, the job's claim, the
deadline) comes from the runtime context, which is never checkpointed.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Annotated, Any, Protocol, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.runtime import Runtime
from langgraph.types import Checkpointer, Send
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.context import store
from argus.context.checkpoints import state_bytes
from argus.context.evidence import (
    COMPLETE,
    PackBug,
    SourceUnavailable,
    content,
    extract,
    merge_evidence,
    outcome_of,
    sha256,
)
from argus.context.packs import (
    MAX_TASKS_PER_RUN,
    MAX_TASKS_PER_WAVE,
    Pack,
    PackRegistry,
    rebuild,
)
from argus.db.errors import is_connection_failure
from argus.freshness.shadow import Policy, log_zeros
from argus.freshness.shadow import apply as apply_freshness
from argus.gateway.errors import GatewayError
from argus.gateway.gateway import Result
from argus.gateway.templates import CostClass, Params, Purpose, Template
from argus.jobs.queue import Claim

log = logging.getLogger("argus.context")

STATE_LIMIT = 64 * 1024
RUN_KINDS = ("collect", "rederive")
CONTEXT_PARTIAL = "context_partial"


class EvidenceGateway(Protocol):
    async def run(
        self,
        template: Template,
        params: Params,
        *,
        purpose: Purpose,
        component: str,
        deadline: datetime,
    ) -> Result: ...


class NodeHooks(Protocol):
    """Test seams (crash injection): called around every node."""

    async def before(self, node: str, state: Mapping[str, Any]) -> None: ...
    async def after(self, node: str, update: Mapping[str, Any]) -> None: ...


class StateTooLarge(Exception):  # noqa: N818 - a defect
    pass


class RunAborted(Exception):  # noqa: N818
    """Another task of this run failed and this one was not cancelled meanwhile."""


class Gate:
    """The run's share of the gateway (plan §8 ``max_concurrency``): at most ``slots`` calls
    at once, and none after any call failed in a way that ends the run: the tasks still
    waiting park until LangGraph cancels them (only the first failure surfaces). LangGraph's
    own ``max_concurrency`` is not used: when a task fails, the tasks waiting for a slot would
    each start their call before LangGraph's cancellation reached them (and its gate leaves
    their coroutines unawaited)."""

    def __init__(self, slots: int, park: float = 60.0) -> None:
        self._slots = asyncio.Semaphore(slots)
        self._park = park
        self.closed = False

    @contextlib.asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        async with self._slots:
            if self.closed:
                await asyncio.sleep(self._park)  # cancelled long before, normally
                raise RunAborted("another task of this run failed")
            try:
                yield
            except BaseException:  # task-level gateway errors are handled inside
                self.closed = True
                raise


class StaleThread(Exception):  # noqa: N818
    """The checkpoint names a pack this process no longer has (a new version was deployed):
    the thread is started again from the beginning."""


@dataclass(frozen=True)
class Ctx:
    engine: AsyncEngine
    gateway: EvidenceGateway | None
    packs: PackRegistry
    claim: Claim | None  # None: evidence only (the P6 agent), never a dossier
    deadline: datetime
    clock: Callable[[], datetime]
    history: timedelta = timedelta(days=5)
    no_remote: bool = False  # deferred 24 h: remote tasks are recorded deferred, not run
    hooks: NodeHooks | None = None
    gate: Gate | None = None  # the run's share of the gateway
    origin: str = "pack"  # who asks for the evidence (evidence_requests.origin, Q-F2)
    freshness: Policy | None = None  # verified zeros (Q-F1): None is off


class GraphState(TypedDict):
    investigation_id: str
    version: int
    run_kind: str
    facts: dict[str, Any]
    facts_version: int
    context: dict[str, Any]
    family: str
    pack: str
    max_waves: int
    local_signals: list[dict[str, Any]]
    wave: int
    planned: list[dict[str, Any]]
    wave_tasks: int  # how many tasks the last wave planned (none: the pack is done)
    spent: dict[str, int]
    evidence: Annotated[dict[str, Any], merge_evidence]
    signals: list[dict[str, Any]]
    report: dict[str, Any]
    dossier: dict[str, Any] | None


class TaskInput(TypedDict):
    investigation_id: str
    version: int
    task: dict[str, Any]


def initial_state(claim: Claim, run_kind: str = "collect") -> GraphState:
    return {
        "investigation_id": str(claim.investigation_id),
        "version": claim.version,
        "run_kind": run_kind,
        "facts": {},
        "facts_version": claim.version,
        "context": {},
        "family": "",
        "pack": "",
        "max_waves": 0,
        "local_signals": [],
        "wave": 0,
        "planned": [],
        "wave_tasks": 0,
        "spent": {},
        "evidence": {},
        "signals": [],
        "report": {},
        "dossier": None,
    }


def thread_id(claim: Claim) -> str:
    return f"ctx:{claim.investigation_id}:v{claim.version}"


Node = Callable[[Any, Ctx], Awaitable[dict[str, Any]]]


def _node(name: str, fn: Node, *, full_state: bool = True) -> Any:
    async def run(state: Any, runtime: Runtime[Ctx]) -> dict[str, Any]:
        ctx = runtime.context
        if ctx.hooks is not None:
            await ctx.hooks.before(name, state)
        update = await fn(state, ctx)
        merged = {**state, **update} if full_state else dict(update)
        if full_state and "evidence" in update:
            merged["evidence"] = merge_evidence(state.get("evidence"), update["evidence"])
        size = state_bytes(merged)
        if size > STATE_LIMIT:
            raise StateTooLarge(f"{name}: state {size} bytes > {STATE_LIMIT}")
        if ctx.hooks is not None:
            await ctx.hooks.after(name, update)
        return update

    run.__name__ = name
    return run


def _pack(ctx: Ctx, state: Mapping[str, Any]) -> Pack:
    pack = ctx.packs.get(state["pack"])
    if pack is None:
        raise StaleThread(f"pack {state['pack']} is not available")
    return pack


def _inv(state: Mapping[str, Any]) -> uuid.UUID:
    return uuid.UUID(str(state["investigation_id"]))


# ----------------------------------------------------------------------------- nodes


async def run_kind(state: GraphState, ctx: Ctx) -> dict[str, Any]:
    if state["run_kind"] not in RUN_KINDS:
        raise PackBug(f"unknown run kind {state['run_kind']!r}")
    return {}


async def load(state: GraphState, ctx: Ctx) -> dict[str, Any]:
    async with ctx.engine.connect() as conn:
        await conn.execution_options(isolation_level="REPEATABLE READ")
        async with conn.begin():
            facts = await store.load_facts(conn, _inv(state))
    return {"facts": facts, "facts_version": facts["version"]}


async def resolve_family(state: GraphState, ctx: Ctx) -> dict[str, Any]:
    pack = ctx.packs.resolve(state["facts"])
    return {"family": pack.family, "pack": pack.ident, "max_waves": pack.max_waves}


async def local_context(state: GraphState, ctx: Ctx) -> dict[str, Any]:
    pack = _pack(ctx, state)
    async with ctx.engine.connect() as conn:
        context = await store.local_context(conn, state["facts"], ctx.history)
        context["pack"] = await pack.extra_context(conn, state["facts"])
    return {"context": context}


async def derive_local_signals(state: GraphState, ctx: Ctx) -> dict[str, Any]:
    signals = _pack(ctx, state).local_signals(state["facts"], state["context"])
    return {"local_signals": sorted((s.as_dict() for s in signals), key=lambda s: s["name"])}


async def plan_wave(state: GraphState, ctx: Ctx) -> dict[str, Any]:
    """Plan the next wave and allocate the pack's per-run budget: reused evidence is free,
    the rest is charged in (priority, task key) order; what does not fit is recorded
    ``skipped_budget`` without a call."""
    pack = _pack(ctx, state)
    wave = state["wave"] + 1
    if wave > pack.max_waves:
        return {"wave": wave, "planned": []}
    specs = pack.plan(wave, state["facts"], state["context"], state["evidence"])
    tasks: dict[str, dict[str, Any]] = {}
    for spec in specs:
        ref = spec.ref()
        if ref["task_key"] not in state["evidence"]:
            tasks.setdefault(ref["task_key"], ref)
    if len(tasks) > MAX_TASKS_PER_WAVE or len(tasks) + len(state["evidence"]) > MAX_TASKS_PER_RUN:
        raise PackBug(f"{pack.ident} planned too many tasks ({len(tasks)} in wave {wave})")
    ordered = sorted(tasks.values(), key=lambda t: (t["priority"], t["task_key"]))
    async with ctx.engine.connect() as conn:
        reusable = await store.reusable(conn, _inv(state), [t["task_key"] for t in ordered])
    spent = dict(state["spent"])
    planned = []
    for task in ordered:
        if task["task_key"] in reusable:
            mode = "reuse"
        elif state["run_kind"] == "rederive":
            mode = "skip_rederive"  # a re-derivation never asks the SIEM; recorded as not asked
        elif ctx.no_remote:
            mode = "deferred"
        elif spent.get(task["cost"], 0) < pack.budget.get(CostClass(task["cost"]), 0):
            spent[task["cost"]] = spent.get(task["cost"], 0) + 1
            mode = "collect"
        else:
            mode = "skip_budget"
        planned.append({**task, "mode": mode})
    if planned:  # each request's E-id, numbered in the plan's order (Q-F2)
        async with ctx.engine.begin() as conn:
            await store.register_requests(
                conn, _inv(state), state["version"], planned, ctx.origin, ctx.clock()
            )
    return {"wave": wave, "planned": planned, "spent": spent}


def dispatch(state: GraphState) -> Any:
    if not state["planned"]:
        return "validate_evidence"
    return [
        Send(
            "collect_evidence",
            {
                "investigation_id": state["investigation_id"],
                "version": state["version"],
                "task": task,
            },
        )
        for task in sorted(state["planned"], key=lambda t: t["task_key"])
    ]


async def collect_evidence(payload: TaskInput, ctx: Ctx) -> dict[str, Any]:
    ref = await evidence_step(ctx, _inv(payload), payload["version"], payload["task"])
    return {"evidence": {ref["task_key"]: ref}}


async def evidence_step(
    ctx: Ctx, inv: uuid.UUID, version: int, task: Mapping[str, Any]
) -> dict[str, Any]:
    """One task, idempotently: this version's ok/empty row if there is one, else an earlier
    version's (copied, no call), else the gateway; the result is written before returning."""
    key = str(task["task_key"])
    async with ctx.engine.begin() as conn:
        await store.register_requests(conn, inv, version, [task], ctx.origin, ctx.clock())
        row = await store.evidence_row(conn, inv, version, key)
        if row is not None and row["status"] in COMPLETE:
            return store.ref_of(row, reused=row["reused_from_version"] is not None)
        earlier = await store.reusable(conn, inv, [key])
        if key in earlier and earlier[key] != version:
            row = await store.copy_evidence(conn, inv, version, key, earlier[key], ctx.clock())
            return store.ref_of(row, reused=True)
        purged = key not in earlier and await store.purged(conn, inv, key)
    record: dict[str, Any] = {
        "investigation_id": inv,
        "version": version,
        "task_key": key,
        "template": task["template"],
        "template_version": task["version"],
        "params": task["params"],
        "coverage": {},
        "source_watermark": None,
        "row_count": None,
        "truncated": False,
        "snapshot": None,
        "result_hash": None,
        "took_ms": None,
        "reused_from_version": None,
        "error": None,
        "asked_at": None,
    }
    if purged:  # never asked again: recorded as not checked, read as unknown, never negative
        record.update(status="skipped_budget", coverage={"reason": "purged"})
        return await _store(ctx, record)
    mode = "deferred" if ctx.no_remote and task["mode"] == "collect" else task["mode"]
    if mode == "reuse":
        raise PackBug(f"task {key[:12]} was planned as reusable but nothing is stored")
    if mode != "collect":
        if mode == "deferred":
            record.update(status="deferred", coverage={"reason": CONTEXT_PARTIAL})
        elif mode == "skip_rederive":
            record.update(status="skipped_budget", coverage={"reason": "rederive"})
        else:
            record.update(status="skipped_budget", coverage={"reason": "pack_budget"})
        return await _store(ctx, record)
    template, params = rebuild(task)
    if ctx.gateway is None:
        raise SourceUnavailable("no_gateway")
    # The slot covers the call and the write: a call is in flight until its result is stored.
    async with ctx.gate.slot() if ctx.gate else contextlib.nullcontext():
        record["asked_at"] = ctx.clock()  # a verified zero needs a reading from before (Q-F1)
        try:
            result = await ctx.gateway.run(
                template,
                params,
                purpose=Purpose.ENRICH,
                component="enrichment",
                deadline=ctx.deadline,
            )
        except GatewayError as exc:
            outcome = outcome_of(exc)  # raises for run-level unavailability and pack bugs
            record.update(status=outcome.status, coverage=outcome.coverage, error=outcome.error)
        else:
            got = extract(result.body, max_rows=task["max_rows"], max_bytes=task["max_bytes"])
            record.update(
                status="ok" if got.has_data else "empty",
                coverage={} if got.exact_total else {"total": "lower_bound"},
                row_count=got.row_count,
                truncated=got.truncated,
                snapshot=got.snapshot,
                result_hash=got.result_hash,
                took_ms=result.took_ms,
            )
        try:
            return await _store(ctx, record)
        except DBAPIError as exc:  # the answer cannot be stored: never ask for it again
            if is_connection_failure(exc) or record["status"] not in COMPLETE:
                raise
            record.update(
                status="failed", coverage={"unstorable": True}, row_count=None,
                truncated=False, snapshot=None, result_hash=None, error="unstorable_result",
            )  # fmt: skip
            return await _store(ctx, record)


async def _store(ctx: Ctx, record: dict[str, Any]) -> dict[str, Any]:
    record["collected_at"] = ctx.clock()
    async with ctx.engine.begin() as conn:
        stored = await store.write_evidence(conn, record)
    return store.ref_of(stored, reused=False)


async def validate_evidence(state: GraphState, ctx: Ctx) -> dict[str, Any]:
    missing = [t["task_key"] for t in state["planned"] if t["task_key"] not in state["evidence"]]
    if missing:
        raise PackBug(f"{len(missing)} planned tasks have no evidence after the wave")
    return {"planned": [], "wave_tasks": len(state["planned"])}


def route_after_wave(state: GraphState) -> str:
    if state["wave"] < state["max_waves"] and state["wave_tasks"] > 0:
        return "plan_wave"
    return "derive_signals"


async def derive_signals(state: GraphState, ctx: Ctx) -> dict[str, Any]:
    pack = _pack(ctx, state)
    evidence = state["evidence"]
    snaps: dict[str, Any] = {}
    if evidence:
        async with ctx.engine.connect() as conn:
            snaps = await store.snapshots(conn, _inv(state), state["version"], evidence)
    signals = pack.signals(state["facts"], state["context"], evidence, snaps)
    policy = ctx.freshness
    if policy is not None and policy.mode != "off" and log_zeros(signals):
        try:  # shadow: stored only; on: verified zeros known. A failure leaves them unknown.
            async with ctx.engine.begin() as conn:
                judged = await apply_freshness(
                    conn, policy, _inv(state), state["version"], state["pack"], signals,
                    ctx.clock(),
                )  # fmt: skip
            signals = judged
        except Exception as exc:
            log.warning("freshness verdicts not stored: %s", type(exc).__name__)
    names = [s.name for s in signals] + [s["name"] for s in state["local_signals"]]
    if len(names) != len(set(names)):
        raise PackBug(f"{pack.ident} emitted a signal name twice")
    derived = sorted((s.as_dict() for s in signals), key=lambda s: s["name"])
    return {
        "signals": derived,
        "report": pack.report(state["facts"], state["context"], evidence, derived),
    }


def dossier_of(state: Mapping[str, Any]) -> dict[str, Any]:
    """The dossier row (without its job): status from the evidence, hash over content only."""
    refs = [content(state["evidence"][k]) for k in sorted(state["evidence"])]
    body = {
        "investigation_id": state["investigation_id"],
        "version": state["version"],
        "facts_version": state["facts_version"],
        "run_kind": state["run_kind"],
        "family": state["family"],
        "pack": state["pack"],
        "facts": state["facts"],
        "context": state["context"],
        "local_signals": state["local_signals"],
        "signals": state["signals"],
        "report": state.get("report", {}),
        "evidence": refs,
    }
    good = sum(r["status"] in COMPLETE for r in refs)
    if good == len(refs):
        status, reason = "evidence_ready", None
    else:
        status = "evidence_failed" if good == 0 else "evidence_partial"
        if any(r["coverage"].get("reason") == CONTEXT_PARTIAL for r in refs):
            reason = CONTEXT_PARTIAL
        else:
            reason = ",".join(sorted({r["status"] for r in refs} - COMPLETE))
    return {
        "facts_version": state["facts_version"],
        "run_kind": state["run_kind"],
        "family": state["family"],
        "pack": state["pack"],
        "status": status,
        "partial_reason": reason,
        "hash": sha256(body),
        "body": body,
    }


async def persist_dossier(state: GraphState, ctx: Ctx) -> dict[str, Any]:
    dossier = dossier_of(state)
    signals = [*state["local_signals"], *state["signals"]]
    if ctx.claim is None:
        raise PackBug("a dossier is persisted only under a job's claim")
    async with ctx.engine.begin() as conn:
        again = await store.persist_dossier(conn, ctx.claim, dossier, signals, ctx.clock())
    return {"dossier": {"hash": dossier["hash"], "status": dossier["status"], "requeued": again}}


def route_after_dossier(state: GraphState) -> str:
    return END  # Phase 2 appends decide → reason → validate_findings → persist_assessment


# ----------------------------------------------------------------------------- graph

NODES: tuple[tuple[str, Node], ...] = (
    ("run_kind", run_kind),
    ("load", load),
    ("resolve_family", resolve_family),
    ("local_context", local_context),
    ("derive_local_signals", derive_local_signals),
    ("plan_wave", plan_wave),
    ("validate_evidence", validate_evidence),
    ("derive_signals", derive_signals),
    ("persist_dossier", persist_dossier),
)


def build(checkpointer: Checkpointer) -> CompiledStateGraph[Any, Any, Any, Any]:
    graph = StateGraph(GraphState, context_schema=Ctx)
    for name, fn in NODES:
        graph.add_node(name, _node(name, fn))
    graph.add_node(
        "collect_evidence",
        _node("collect_evidence", collect_evidence, full_state=False),
        input_schema=TaskInput,
    )
    graph.add_edge(START, "run_kind")
    graph.add_edge("run_kind", "load")
    graph.add_edge("load", "resolve_family")
    graph.add_edge("resolve_family", "local_context")
    graph.add_edge("local_context", "derive_local_signals")
    graph.add_edge("derive_local_signals", "plan_wave")
    graph.add_conditional_edges("plan_wave", dispatch, ["collect_evidence", "validate_evidence"])
    graph.add_edge("collect_evidence", "validate_evidence")
    graph.add_conditional_edges(
        "validate_evidence", route_after_wave, ["plan_wave", "derive_signals"]
    )
    graph.add_edge("derive_signals", "persist_dossier")
    graph.add_conditional_edges("persist_dossier", route_after_dossier, [END])
    return graph.compile(checkpointer=checkpointer)
