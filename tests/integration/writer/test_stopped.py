"""D-322: the writer service is cancelled when it is stopped (``argus.ops.stopping``). A run cut
short that way is recorded as stopped, so it is not taken for a clean run on the ramp (before, the
process died of the signal and no run was recorded at all)."""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.writer import ramp
from argus.writer.sender import Writer
from tests.integration.cases.conftest import Person
from tests.integration.cases.test_service import _kibana_actor
from tests.integration.writer.kit import many_alerts, rig

pytestmark = pytest.mark.integration


async def test_a_run_the_stop_cancelled_is_recorded_as_stopped(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person], monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    await many_alerts(app_engine, migrated_engine, _kibana_actor(people["asha"]), investigations=1)
    real = Writer._next
    looked = {"n": 0}

    async def stopped_after_the_first_unit(self, cls, attempted):  # type: ignore[no-untyped-def]
        looked["n"] += 1
        if looked["n"] > 1:  # the service is stopped between two units
            raise asyncio.CancelledError
        return await real(self, cls, attempted)

    monkeypatch.setattr(Writer, "_next", stopped_after_the_first_unit)
    with pytest.raises(asyncio.CancelledError):
        await r.run("W1", limit=5)
    good = f"SELECT sent, verified, stopped, ({ramp.GOOD_RUN}) AS good FROM kibana_writer_runs"  # noqa: S608
    runs = await r.sql(good)
    assert len(runs) == 1
    assert runs[0].sent >= 1
    assert runs[0].stopped == "the writer service was stopped"
    assert runs[0].good is False
