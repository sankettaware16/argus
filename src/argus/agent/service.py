"""Wiring the agent to a running ARGUS: its evidence goes through the worker's own evidence
step (idempotent, stored, inside the Elastic gateway's budget and health), with no job claim
and never a dossier."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine

from argus.agent.agent import Fetch, Snapshots
from argus.context import graph, store
from argus.context.evidence import SourceUnavailable
from argus.context.graph import Ctx, EvidenceGateway, Gate
from argus.context.packs import PackRegistry, TaskSpec

ATTEMPT = timedelta(minutes=2)
UNAVAILABLE = "unavailable"  # the SIEM refused the run (stopped, degraded, maintenance)


def evidence(
    engine: AsyncEngine,
    gateway: EvidenceGateway | None,
    packs: PackRegistry,
    clock: Callable[[], datetime],
) -> tuple[Fetch, Snapshots]:
    async def fetch(inv: uuid.UUID, version: int, spec: TaskSpec) -> Mapping[str, Any]:
        ctx = Ctx(engine=engine, gateway=gateway, packs=packs, claim=None,
                  deadline=clock() + ATTEMPT, clock=clock, gate=Gate(1),
                  origin="agent")  # fmt: skip
        task = {**spec.ref(), "mode": "collect"}
        try:
            return await graph.evidence_step(ctx, inv, version, task)
        except SourceUnavailable as exc:  # unknown, never negative: nothing stored
            return {
                "task_key": task["task_key"],
                "template": f"{task['template']}@{task['version']}",
                "status": UNAVAILABLE,
                "coverage": {"reason": str(exc)[:80]},
                "row_count": None,
                "truncated": False,
                "result_hash": None,
                "reused": False,
            }

    async def snapshots(inv: uuid.UUID, version: int, keys: list[str]) -> Mapping[str, Any]:
        async with engine.connect() as conn:
            return await store.snapshots(conn, inv, version, keys)

    return fetch, snapshots
