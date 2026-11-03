"""The agent's evidence wiring (P6): the worker's evidence step, stored and idempotent, no
claim, never a dossier; the SIEM refusing the run is unknown, not an error."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.agent import service
from argus.context.packs import TaskSpec
from argus.gateway.errors import StoppedError
from tests.integration.context.conftest import NOW, seed
from tests.integration.context.kit import CountParams, CountTemplate, FakeGateway
from tests.integration.context.kit import registry as kit_registry

pytestmark = pytest.mark.integration


async def test_evidence_is_stored_once_and_read_back(app_engine: AsyncEngine) -> None:
    (inv,) = await seed(app_engine, [(1, "r1", "10.0.0.1")])
    gateway = FakeGateway()
    fetch, snapshots = service.evidence(app_engine, gateway, kit_registry(), lambda: NOW)
    spec = TaskSpec(CountTemplate(), CountParams(investigation=str(inv), n=3))
    first = await fetch(inv, 1, spec)
    again = await fetch(inv, 1, spec)
    assert first["status"] == "ok"
    assert gateway.calls == [3]
    assert again["task_key"] == first["task_key"]
    snaps = await snapshots(inv, 1, [str(first["task_key"])])
    assert set(snaps) == {first["task_key"]}
    async with app_engine.connect() as conn:
        rows = (await conn.execute(text("SELECT count(*) FROM evidence"))).scalar_one()
        dossiers = (await conn.execute(text("SELECT count(*) FROM dossiers"))).scalar_one()
    assert (rows, dossiers) == (1, 0)


async def test_siem_refusing_the_run_is_unavailable_and_stores_nothing(
    app_engine: AsyncEngine,
) -> None:
    (inv,) = await seed(app_engine, [(1, "r1", "10.0.0.1")])
    gateway = FakeGateway(fail={4: StoppedError("maintenance")})
    fetch, _ = service.evidence(app_engine, gateway, kit_registry(), lambda: NOW)
    spec = TaskSpec(CountTemplate(), CountParams(investigation=str(inv), n=4))
    got = await fetch(inv, 1, spec)
    ref = spec.ref()
    assert got == {"task_key": ref["task_key"], "template": "test.ctx.count@1",
                   "status": service.UNAVAILABLE, "coverage": {"reason": "stopped"},
                   "row_count": None, "truncated": False, "result_hash": None,
                   "reused": False}  # fmt: skip
    none, _ = service.evidence(app_engine, None, kit_registry(), lambda: NOW)
    assert (await none(inv, 1, spec))["coverage"] == {"reason": "no_gateway"}
    async with app_engine.connect() as conn:
        assert (await conn.execute(text("SELECT count(*) FROM evidence"))).scalar_one() == 0


async def test_the_deadline_and_a_long_refusal(
    app_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    from datetime import timedelta

    from argus.context import graph
    from argus.context.evidence import SourceUnavailable

    assert service.UNAVAILABLE == "unavailable"
    assert timedelta(minutes=2) == service.ATTEMPT
    (inv,) = await seed(app_engine, [(1, "r1", "10.0.0.1")])
    seen: dict[str, object] = {}

    class Recording(FakeGateway):
        async def run(self, template, params, *, purpose, component, deadline):  # type: ignore[no-untyped-def]
            seen["deadline"] = deadline
            return await super().run(template, params, purpose=purpose,
                                     component=component, deadline=deadline)  # fmt: skip

    fetch, _ = service.evidence(app_engine, Recording(), kit_registry(), lambda: NOW)
    await fetch(inv, 1, TaskSpec(CountTemplate(), CountParams(investigation=str(inv), n=5)))
    assert seen["deadline"] == NOW + timedelta(minutes=2)

    async def refuse(*a: object, **k: object) -> None:
        raise SourceUnavailable("r" * 100)

    monkeypatch.setattr(graph, "evidence_step", refuse)
    got = await fetch(inv, 1, TaskSpec(CountTemplate(), CountParams(investigation=str(inv), n=6)))
    assert got["coverage"] == {"reason": "r" * 80}
