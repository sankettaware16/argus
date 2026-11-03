from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.context.worker import Worker
from tests.integration.context.conftest import NOW, seed

pytestmark = pytest.mark.integration


async def test_stub_pack_writes_a_dossier_per_investigation(app_engine: AsyncEngine, saver) -> None:
    await seed(app_engine, [(1, "r1", "10.0.0.1"), (2, "r1", "10.0.0.2"), (3, "r2", "10.0.0.1")])
    worker = Worker(app_engine, saver, clock=lambda: NOW)
    results = await worker.run_once(limit=10)
    print(results)
    async with app_engine.connect() as conn:
        rows = (await conn.execute(text("SELECT status, family, pack, body FROM dossiers"))).all()
        sig = (await conn.execute(text("SELECT name, value FROM signals ORDER BY 1"))).all()
        cps = (await conn.execute(text("SELECT count(*) FROM langgraph.checkpoints"))).scalar_one()
    print(rows[0].body["context"], sig[:8], cps)
    assert {r.outcome for r in results} == {"done"}
    assert len(rows) == 3
