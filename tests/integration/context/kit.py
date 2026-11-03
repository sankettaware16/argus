"""Test kit for the context graph: a registered test template, a pack with two waves of
remote tasks, a fake gateway that counts calls (and can fail or crash inside one), crash hooks
for every node, and a reset that empties everything R8 writes."""

from __future__ import annotations

import asyncio
import random
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.context.evidence import SignalValue, derived, local
from argus.context.packs import Pack, PackRegistry, StubPack, TaskSpec
from argus.gateway.errors import GatewayError
from argus.gateway.gateway import Result
from argus.gateway.templates import (
    CostClass,
    Endpoint,
    Family,
    Params,
    Purpose,
    RequestPlan,
    Template,
    register,
)

TABLES = (
    "signals, dossiers, evidence, jobs, investigation_entities, entities, investigation_alerts,"
    " investigations, alert_records, collector_cursors, reconciliation_runs, coverage_gaps,"
    " langgraph.checkpoints, langgraph.checkpoint_blobs, langgraph.checkpoint_writes"
)


class Killed(BaseException):
    """The process died here: nothing in ARGUS catches it."""


class CountParams(Params):
    investigation: str
    n: int


@register
class CountTemplate(Template):
    name = "test.ctx.count"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.ALERTS
    cost = CostClass.LIGHT
    params_model = CountParams

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, CountParams)
        return RequestPlan(self.spec(), body={"size": 0, "query": {"term": {"n": params.n}}})


class TwoWavePack(Pack):
    """Wave 1: ``first`` tasks; wave 2: one task per odd count seen in wave 1."""

    name = "test-two-wave"
    version = 1
    family = "test"
    max_waves = 2
    budget: ClassVar[Mapping[CostClass, int]] = {CostClass.LIGHT: 64}
    first = 6

    def local_signals(
        self, facts: Mapping[str, Any], context: Mapping[str, Any]
    ) -> list[SignalValue]:
        return [local("alert_count", self.version, facts["alert_count"])]

    def plan(
        self,
        wave: int,
        facts: Mapping[str, Any],
        context: Mapping[str, Any],
        evidence: Mapping[str, Mapping[str, Any]],
    ) -> Sequence[TaskSpec]:
        inv = str(facts["investigation_id"])
        if wave == 1:
            return [
                TaskSpec(CountTemplate(), CountParams(investigation=inv, n=n))
                for n in range(self.first)
            ]
        odd = sorted(r["row_count"] for r in evidence.values() if (r["row_count"] or 0) % 2)
        return [TaskSpec(CountTemplate(), CountParams(investigation=inv, n=100 + n)) for n in odd]

    def signals(
        self,
        facts: Mapping[str, Any],
        context: Mapping[str, Any],
        evidence: Mapping[str, Mapping[str, Any]],
        snapshots: Mapping[str, Any],
    ) -> list[SignalValue]:
        refs = list(evidence.values())
        return [
            derived(
                "remote_total", self.version, refs, lambda: sum(r["row_count"] for r in refs),
                counts=True,
            )
        ]  # fmt: skip


def registry(pack: Pack | None = None) -> PackRegistry:
    """Every investigation goes to ``pack`` (the stub pack stays the default family)."""

    class One(PackRegistry):
        def resolve(self, facts: Mapping[str, Any]) -> Pack:
            return chosen

    chosen = pack or TwoWavePack()
    return One([StubPack(), chosen])


def count_of(params: Params) -> int:
    assert isinstance(params, CountParams)
    return (params.n * 7 + 3) % 5  # 3, 0, 2, 4, 1, ...: some odd, some even, some empty


@dataclass
class FakeGateway:
    """Answers CountTemplate deterministically by its parameters (``took`` and shard counts
    vary, to show the dossier never depends on them). ``fail`` maps a parameter n to an error
    to raise; ``crash_on_call`` kills the process inside the k-th call, after the SIEM answered
    and before the result is stored."""

    delay: Callable[[], float] = lambda: 0.0
    fail: dict[int, GatewayError] = field(default_factory=dict)
    crash_on_call: int | None = None
    calls: list[int] = field(default_factory=list)
    completed: list[int] = field(default_factory=list)  # in the order the SIEM answered
    rng: random.Random = field(default_factory=lambda: random.Random(0))

    async def run(
        self,
        template: Template,
        params: Params,
        *,
        purpose: Purpose,
        component: str,
        deadline: datetime,
    ) -> Result:
        assert purpose is Purpose.ENRICH
        assert component == "enrichment"
        assert isinstance(params, CountParams)
        self.calls.append(params.n)
        await asyncio.sleep(self.delay())
        if params.n in self.fail:
            raise self.fail[params.n]
        if self.crash_on_call is not None and len(self.calls) == self.crash_on_call:
            raise Killed(f"inside call {len(self.calls)}")
        count = count_of(params)
        self.completed.append(params.n)
        body = {
            "took": self.rng.randrange(1, 500),
            "_shards": {"total": 1, "successful": 1, "failed": 0},
            "hits": {"total": {"value": count, "relation": "eq"}, "hits": []},
        }
        return Result(body, body["took"], ("alerts",))


@dataclass
class Hooks:
    """Records every node event; raises Killed at ``crash`` = (node, when, occurrence)."""

    crash: tuple[str, str, int] | None = None
    events: list[tuple[str, str, int]] = field(default_factory=list)
    on: Callable[[str, str], Any] | None = None

    async def _event(self, node: str, when: str) -> None:
        seen = sum(1 for n, w, _ in self.events if (n, w) == (node, when))
        event = (node, when, seen + 1)
        self.events.append(event)
        if self.on is not None:
            await self.on(node, when)
        if event == self.crash:
            raise Killed(f"{when} {node} #{seen + 1}")

    async def before(self, node: str, state: Mapping[str, Any]) -> None:
        await self._event(node, "before")

    async def after(self, node: str, update: Mapping[str, Any]) -> None:
        await self._event(node, "after")


async def reset(owner: AsyncEngine) -> None:
    async with owner.begin() as conn:
        await conn.execute(text(f"TRUNCATE {TABLES} CASCADE"))


async def dossiers(engine: AsyncEngine) -> list[Any]:
    async with engine.connect() as conn:
        rows = await conn.execute(
            text(
                "SELECT investigation_id, version, status, partial_reason, dossier_hash"
                " FROM dossiers ORDER BY 1, 2"
            )
        )
        return list(rows.all())


async def scalar(engine: AsyncEngine, query: str, **params: Any) -> Any:
    async with engine.connect() as conn:
        return (await conn.execute(text(query), params)).scalar_one()
