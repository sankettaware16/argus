"""The context graph's nodes one at a time, exactly (mutation testing): the initial state, the
state-size limit, every defect a pack can make, every way a task is recorded without a call,
the dossier's status and reason, the run gate."""

from __future__ import annotations

import asyncio
import uuid
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.context import graph
from argus.context.evidence import COMPLETE, SignalValue, SourceUnavailable, local
from argus.context.packs import PackBug, TaskSpec
from argus.jobs.queue import Claim
from tests.integration.context.conftest import NOW, seed
from tests.integration.context.kit import CountParams, CountTemplate, FakeGateway, TwoWavePack
from tests.integration.context.kit import registry as kit_registry

pytestmark = pytest.mark.integration


def claim(inv: uuid.UUID, version: int = 1) -> Claim:
    return Claim(job_id=1, investigation_id=inv, version=version, claim=1, owner="t")


def ctx(engine: AsyncEngine, inv: uuid.UUID, **kw: Any) -> graph.Ctx:
    base: dict[str, Any] = {"engine": engine, "gateway": None, "packs": kit_registry(),
                            "claim": claim(inv), "deadline": NOW + timedelta(minutes=5),
                            "clock": lambda: NOW}  # fmt: skip
    return graph.Ctx(**{**base, **kw})


def test_the_initial_state_and_thread() -> None:
    inv = uuid.uuid4()
    state = graph.initial_state(claim(inv, 3))
    assert state == {
        "investigation_id": str(inv), "version": 3, "run_kind": "collect", "facts": {},
        "facts_version": 3, "context": {}, "family": "", "pack": "", "max_waves": 0,
        "local_signals": [], "wave": 0, "planned": [], "wave_tasks": 0, "spent": {},
        "evidence": {}, "signals": [], "report": {}, "dossier": None,
    }  # fmt: skip
    assert graph.initial_state(claim(inv), "rederive")["run_kind"] == "rederive"
    assert graph.thread_id(claim(inv, 3)) == f"ctx:{inv}:v3"
    assert graph.STATE_LIMIT == 65536
    assert graph.RUN_KINDS == ("collect", "rederive")


class _Runtime:
    def __init__(self, context: Any) -> None:
        self.context = context


class _Hooks:
    def __init__(self) -> None:
        self.seen: list[tuple[str, str]] = []

    async def before(self, node: str, state: Any) -> None:
        self.seen.append((node, "before"))

    async def after(self, node: str, update: Any) -> None:
        self.seen.append((node, "after"))


async def test_a_node_checks_the_state_size_and_calls_its_hooks(app_engine: AsyncEngine) -> None:
    hooks = _Hooks()
    c = ctx(app_engine, uuid.uuid4(), hooks=hooks)
    n = graph.STATE_LIMIT  # the longest value that fits exactly (msgpack headers vary)
    while graph.state_bytes({"x": "y" * n}) > graph.STATE_LIMIT:
        n -= 1
    assert graph.state_bytes({"x": "y" * n}) == graph.STATE_LIMIT

    async def fill(state: Any, _: Any) -> dict[str, Any]:
        return {"x": "y" * (n + 1)}  # one byte over

    async def fits(state: Any, _: Any) -> dict[str, Any]:
        return {"x": "y" * n}  # exactly the limit

    ok = graph._node("fits", fits)
    assert ok.__name__ == "fits"
    assert await ok({}, _Runtime(c)) == {"x": "y" * n}
    with pytest.raises(graph.StateTooLarge, match=r"^big: state 65537 bytes > 65536$"):
        await graph._node("big", fill)({}, _Runtime(c))
    assert hooks.seen == [("fits", "before"), ("fits", "after"), ("big", "before")]
    # a task node's update is checked on its own; a full node merges evidence first
    big = {"k" * 40 + str(n): {"task_key": "k" * 40 + str(n), "status": "ok", "x": "y" * 1200}
           for n in range(60)}  # fmt: skip

    async def more(state: Any, _: Any) -> dict[str, Any]:
        return {"evidence": {"new": {"task_key": "new", "status": "ok"}}}

    with pytest.raises(graph.StateTooLarge):
        await graph._node("merge", more)({"evidence": big}, _Runtime(c))
    assert await graph._node("task", more, full_state=False)({"evidence": big}, _Runtime(c))


async def test_defects_a_pack_or_a_thread_can_make(app_engine: AsyncEngine) -> None:
    c = ctx(app_engine, uuid.uuid4())
    with pytest.raises(PackBug, match="unknown run kind 'replay'"):
        await graph.run_kind({"run_kind": "replay"}, c)  # type: ignore[typeddict-item]
    assert await graph.run_kind({"run_kind": "rederive"}, c) == {}  # type: ignore[typeddict-item]
    with pytest.raises(graph.StaleThread, match="pack gone@9 is not available"):
        graph._pack(c, {"pack": "gone@9"})
    with pytest.raises(PackBug, match="2 planned tasks have no evidence after the wave"):
        await graph.validate_evidence({"planned": [{"task_key": "a"}, {"task_key": "b"}],  # type: ignore[typeddict-item]
                                       "evidence": {}}, c)  # fmt: skip
    done = await graph.validate_evidence({"planned": [{"task_key": "a"}],  # type: ignore[typeddict-item]
                                          "evidence": {"a": {}}}, c)  # fmt: skip
    assert done == {"planned": [], "wave_tasks": 1}

    class Twice(TwoWavePack):
        name = "test-twice"

        def signals(self, *args: Any) -> list[SignalValue]:
            return [local("alert_count", self.version, 1)]  # also a local signal

    twice = ctx(app_engine, uuid.uuid4(), packs=kit_registry(Twice()))
    state = {"pack": Twice().ident, "evidence": {}, "facts": {}, "context": {},
             "local_signals": [{"name": "alert_count"}], "version": 1,
             "investigation_id": str(uuid.uuid4())}  # fmt: skip
    with pytest.raises(PackBug, match=f"{Twice().ident} emitted a signal name twice"):
        await graph.derive_signals(state, twice)  # type: ignore[arg-type]


def test_routes() -> None:
    assert graph.route_after_wave({"wave": 1, "max_waves": 2, "wave_tasks": 3}) == "plan_wave"  # type: ignore[typeddict-item]
    assert graph.route_after_wave({"wave": 1, "max_waves": 2, "wave_tasks": 0}) == "derive_signals"  # type: ignore[typeddict-item]
    assert graph.route_after_wave({"wave": 2, "max_waves": 2, "wave_tasks": 3}) == "derive_signals"  # type: ignore[typeddict-item]
    assert graph.dispatch({"planned": []}) == "validate_evidence"  # type: ignore[typeddict-item]
    sent = graph.dispatch({"planned": [{"task_key": "b"}, {"task_key": "a"}],  # type: ignore[typeddict-item]
                           "investigation_id": "i", "version": 2})  # fmt: skip
    assert [s.arg["task"]["task_key"] for s in sent] == ["a", "b"]
    assert {s.node for s in sent} == {"collect_evidence"}
    assert sent[0].arg["version"] == 2
    assert graph.route_after_dossier({}) == graph.END  # type: ignore[arg-type]


class Many(TwoWavePack):
    name = "test-many"
    first = 33


class Budgeted(TwoWavePack):
    name = "test-budgeted"
    first = 4
    budget = {CountTemplate.cost: 2}  # noqa: RUF012


async def planned(engine: AsyncEngine, pack: Any, **kw: Any) -> dict[str, Any]:
    (inv,) = await seed(engine, [(1, "r1", "10.0.0.1")])
    c = ctx(engine, inv, packs=kit_registry(pack), **kw)
    state = {"pack": pack.ident, "wave": 0, "facts": {"investigation_id": str(inv)},
             "investigation_id": str(inv), "version": 1,
             "context": {}, "evidence": {}, "spent": {},
             "run_kind": kw.pop("run_kind", "collect")}  # fmt: skip
    return await graph.plan_wave(state, c)  # type: ignore[arg-type]


async def test_plan_modes_and_limits(app_engine: AsyncEngine) -> None:
    with pytest.raises(PackBug, match=r"test-many@1 planned too many tasks \(33 in wave 1\)"):
        await planned(app_engine, Many())


async def test_the_budget_decides_collect_or_skip(app_engine: AsyncEngine) -> None:
    got = await planned(app_engine, Budgeted())
    assert got["wave"] == 1
    assert [t["mode"] for t in got["planned"]] == ["collect", "collect", "skip_budget",
                                                   "skip_budget"]  # fmt: skip
    assert got["spent"] == {"light": 2}
    keys = [t["task_key"] for t in got["planned"]]
    assert keys == sorted(keys)  # priority 0 for all: by key


async def test_no_remote_defers_every_task(app_engine: AsyncEngine) -> None:
    got = await planned(app_engine, Budgeted(), no_remote=True)
    assert {t["mode"] for t in got["planned"]} == {"deferred"}
    assert got["spent"] == {}


async def test_past_the_last_wave_plans_nothing(app_engine: AsyncEngine) -> None:
    (inv,) = await seed(app_engine, [(1, "r1", "10.0.0.1")])
    pack = TwoWavePack()
    c = ctx(app_engine, inv, packs=kit_registry(pack))
    got = await graph.plan_wave({"pack": pack.ident, "wave": 2}, c)  # type: ignore[typeddict-item]
    assert got == {"wave": 3, "planned": []}


def task(inv: uuid.UUID, n: int, mode: str) -> dict[str, Any]:
    ref = TaskSpec(CountTemplate(), CountParams(investigation=str(inv), n=n)).ref()
    return {**ref, "mode": mode}


async def test_tasks_recorded_without_a_call(app_engine: AsyncEngine) -> None:
    (inv,) = await seed(app_engine, [(1, "r1", "10.0.0.1")])
    gateway = FakeGateway()
    c = ctx(app_engine, inv, gateway=gateway)
    got = {}
    for n, mode in enumerate(("deferred", "skip_rederive", "skip_budget")):
        got[mode] = await graph.evidence_step(c, inv, 1, task(inv, n, mode))
    assert got["deferred"]["status"] == "deferred"
    assert got["deferred"]["coverage"] == {"reason": "context_partial"}
    assert got["skip_rederive"]["status"] == "skipped_budget"
    assert got["skip_rederive"]["coverage"] == {"reason": "rederive"}
    assert got["skip_budget"]["coverage"] == {"reason": "pack_budget"}
    assert gateway.calls == []
    with pytest.raises(PackBug, match="was planned as reusable but nothing is stored"):
        await graph.evidence_step(c, inv, 1, task(inv, 7, "reuse"))
    no_gateway = ctx(app_engine, inv)
    with pytest.raises(SourceUnavailable, match="no_gateway"):
        await graph.evidence_step(no_gateway, inv, 1, task(inv, 8, "collect"))
    deferred = ctx(app_engine, inv, gateway=gateway, no_remote=True)
    late = await graph.evidence_step(deferred, inv, 1, task(inv, 9, "collect"))
    assert (late["status"], gateway.calls) == ("deferred", [])
    asked = await graph.evidence_step(c, inv, 1, task(inv, 10, "collect"))
    assert asked["status"] in COMPLETE
    assert gateway.calls == [10]
    again = await graph.evidence_step(c, inv, 1, task(inv, 10, "collect"))
    assert (again["task_key"], gateway.calls) == (asked["task_key"], [10])  # stored: no call


def ref(key: str, status: str, coverage: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"task_key": key, "status": status, "coverage": coverage or {}, "template": "t@1",
            "row_count": 1, "truncated": False, "result_hash": "h", "reused_from_version": None,
            "source_watermark": None}  # fmt: skip


def dossier_state(**evidence: dict[str, Any]) -> dict[str, Any]:
    return {"investigation_id": "i", "version": 2, "facts_version": 2, "run_kind": "collect",
            "family": "f", "pack": "p@1", "facts": {"a": 1}, "context": {},
            "local_signals": [], "signals": [], "report": {"r": 1},
            "evidence": evidence}  # fmt: skip


def test_the_dossiers_status_and_reason() -> None:
    ready = graph.dossier_of(dossier_state(a=ref("a", "ok"), b=ref("b", "empty")))
    assert (ready["status"], ready["partial_reason"]) == ("evidence_ready", None)
    assert set(ready["body"]) == {"investigation_id", "version", "facts_version", "run_kind",
                                  "family", "pack", "facts", "context", "local_signals",
                                  "signals", "report", "evidence"}  # fmt: skip
    assert (ready["facts_version"], ready["run_kind"], ready["family"], ready["pack"]) == (
        2, "collect", "f", "p@1")  # fmt: skip
    assert ready["body"]["report"] == {"r": 1}
    assert [r["task_key"] for r in ready["body"]["evidence"]] == ["a", "b"]
    partial = graph.dossier_of(dossier_state(a=ref("a", "ok"), b=ref("b", "failed"),
                                             c=ref("c", "timed_out")))  # fmt: skip
    assert (partial["status"], partial["partial_reason"]) == ("evidence_partial",
                                                              "failed,timed_out")  # fmt: skip
    waiting = ref("b", "deferred", {"reason": "context_partial"})
    late = graph.dossier_of(dossier_state(a=ref("a", "ok"), b=waiting))
    assert late["partial_reason"] == "context_partial"
    failed = graph.dossier_of(dossier_state(a=ref("a", "failed")))
    assert failed["status"] == "evidence_failed"
    assert graph.dossier_of(dossier_state())["status"] == "evidence_ready"
    state = dossier_state(a=ref("a", "ok"))
    del state["report"]
    assert graph.dossier_of(state)["body"]["report"] == {}
    assert ready["hash"] != graph.dossier_of({**dossier_state(a=ref("a", "ok"), b=ref(
        "b", "empty")), "facts": {"a": 2}})["hash"]  # fmt: skip


async def test_the_gate_parks_tasks_after_a_failure() -> None:
    gate = graph.Gate(1, park=0.01)
    with pytest.raises(ValueError, match="boom"):
        async with gate.slot():
            raise ValueError("boom")
    assert gate.closed
    with pytest.raises(graph.RunAborted, match="another task of this run failed"):
        async with gate.slot():
            pass
    fine = graph.Gate(2)
    async with fine.slot():
        pass
    assert not fine.closed
    waited = graph.Gate(1, park=0.2)
    waited.closed = True
    started = asyncio.get_running_loop().time()
    with pytest.raises(graph.RunAborted):
        async with waited.slot():
            pass
    assert asyncio.get_running_loop().time() - started >= 0.2
    assert graph.Gate(1)._park == 60.0
