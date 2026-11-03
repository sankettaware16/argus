"""R11 gate (D-060): the TI module answers the notes' reputation steps from the feeds,
counts other investigations naming a listed indicator, and never calls a miss in a source
that was not checked (or is stale) clean."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.context.display import entry
from argus.context.packs import default_registry
from argus.context.worker import Worker
from argus.gateway.gateway import Result
from argus.gateway.templates import Params, Purpose, Template
from argus.reference import store as reference
from argus.reference.templates import LookupParams, TiLookup
from tests.integration.context.conftest import NOW
from tests.integration.context.test_generic import alert, dossiers
from tests.integration.grouping.test_grouping import ingest
from tests.integration.reference.sources import mirror_source
from tests.integration.reference.test_reference import FakeTI

pytestmark = pytest.mark.integration

NOTE = "### Investigation Steps\n1. Reputation-check `destination.ip` (VirusTotal)."
C2 = "77.221.155.150"
ABUSE = [
    {
        "@timestamp": "2026-10-09T00:00:00Z",
        "threat": {"indicator": {"type": "ipv4-addr", "ip": C2, "description": "PS1Bot C2"}},
    }
]


async def prepare(engine: AsyncEngine, docs: list[dict[str, Any]], *, mirror: bool) -> None:
    await ingest(engine, docs)
    async with engine.begin() as conn:
        await reference.refresh_rules(conn, NOW, hold=timedelta(0))
        if mirror:
            await reference.sync_mirror(conn, FakeTI(ABUSE, []).run, NOW, mirror_source())


async def run(engine: AsyncEngine, saver: AsyncPostgresSaver, **kw: Any) -> list[Any]:
    worker = Worker(
        engine,
        saver,
        packs=default_registry(clock=lambda: NOW, **kw),
        clock=lambda: NOW,
        gateway=kw.pop("gateway", None) if "gateway" in kw else None,
    )
    while await worker.run_once(limit=10):
        pass
    return await dossiers(engine)


def contact(n: int, ip: str, host: str = "10.0.0.1") -> dict[str, Any]:
    d = alert(n, note=NOTE, destination={"ip": ip})
    d["_source"]["source"]["ip"] = host
    return d


async def test_a_listed_destination_answers_the_reputation_step(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    await prepare(app_engine, [contact(1, C2), contact(2, C2, host="10.0.0.2")], mirror=True)
    got = await run(app_engine, saver)
    d = next(d for d in got if d.body["facts"]["alert_count"] >= 1)
    (step,) = d.body["report"]["steps"]
    assert step["status"] == "answered"
    assert step["sentence"].startswith(f"Threat intel: 1 of 1 on a list ({C2}).")
    assert "abuse-ioc: fresh" in step["sentence"]
    assert "acme-threat-intel: not checked" in step["sentence"]
    signals = {s["name"]: s for s in d.body["signals"]}
    assert signals["ti.listed"]["value"] == 1
    assert signals["same_ioc.investigations"]["value"] >= 0
    assert all(entry(name) is not None for name in signals)
    ti = d.body["context"]["pack"]["ti"]
    assert ti["listed"] == [C2]
    assert ti["values"] == [["ip", C2]]


async def test_no_fresh_source_means_unknown_never_clean(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    await prepare(app_engine, [contact(1, "45.9.9.9")], mirror=False)
    (d,) = await run(app_engine, saver)
    (step,) = d.body["report"]["steps"]
    assert step["status"] == "deferred"  # nothing fresh asked: still waiting for TI
    signals = {s["name"]: s for s in d.body["signals"]}
    assert (signals["ti.listed"]["status"], signals["ti.listed"]["unknown_reason"]) == (
        "unknown",
        "source_not_checked",
    )


async def test_private_addresses_are_not_indicators(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    from argus.assets.classify import IpClassifier

    await prepare(app_engine, [contact(1, "192.168.1.9")], mirror=True)
    (d,) = await run(app_engine, saver, classifier=IpClassifier(None))
    ti = d.body["context"]["pack"]["ti"]
    assert ["ip", "192.168.1.9"] not in ti["values"]
    assert ["ip", "10.0.0.1"] not in ti["values"]


class TiGateway:
    """acme-threat-intel through the gateway seam: one row for 45.9.9.9."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    async def run(
        self, template: Template, params: Params, *, purpose: Purpose, component: str, deadline: Any
    ) -> Result:
        assert isinstance(template, TiLookup)
        assert isinstance(params, LookupParams)
        assert purpose is Purpose.ENRICH
        self.calls.append(params.values)
        rows = [{"_source": {"ioc_type": "ip", "ioc_value": "45.9.9.9", "intel_source": "feodo"}}]
        hits = [r for r in rows if r["_source"]["ioc_value"] in params.values]
        return Result({"hits": {"total": {"value": len(hits)}, "hits": hits}}, 4, ("ti",))


async def test_with_sync_on_the_large_feed_is_asked_as_a_budgeted_task(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    await prepare(app_engine, [contact(1, "45.9.9.9")], mirror=True)
    gateway = TiGateway()
    worker = Worker(
        app_engine,
        saver,
        packs=default_registry(remote_ti=True),
        clock=lambda: NOW,
        gateway=gateway,
    )
    while await worker.run_once(limit=10):
        pass
    (d,) = await dossiers(app_engine)
    assert len(gateway.calls) == 1
    assert "45.9.9.9" in gateway.calls[0]
    signals = {s["name"]: s for s in d.body["signals"]}
    assert signals["ti.listed_remote"]["value"] == 1
    async with app_engine.connect() as conn:
        statuses = (await conn.execute(text("SELECT status FROM evidence"))).scalars().all()
    assert statuses == ["ok"]


async def test_the_context_counts_exactly(app_engine: AsyncEngine) -> None:
    """Same indicator elsewhere, when each address was last seen elsewhere, the alerts'
    regularity: exact values (R11 mutation testing)."""
    from argus.context import intel

    docs = [contact(n, C2) for n in (1, 2, 3, 4)]  # one a minute: perfectly regular
    docs.append(contact(5, C2, host="10.0.0.2"))  # another investigation names the C2
    docs.append(contact(6, "45.9.9.9", host="10.0.0.3"))
    await prepare(app_engine, docs, mirror=True)
    async with app_engine.connect() as conn:
        rows = (await conn.execute(text(
            "SELECT i.id, i.last_event_at, e.value FROM investigations i JOIN"
            " investigation_entities e ON e.investigation_id = i.id AND e.kind = 'ip'"
            " ORDER BY i.alert_count DESC, e.value"))).all()  # fmt: skip
        mine = rows[0].id
        other = next(r for r in rows if r.id != mine and r.value == C2)
        got = await intel.context(conn, {"investigation_id": mine}, {}, None)
        assert got["values"] == [["ip", C2]]  # 10.0.0.1 is private
        assert got["cut"] is False
        assert got["listed"] == [C2]
        assert got["same_ioc"] == {C2: 1}
        assert got["host_last_seen"] == {"10.0.0.1": None, C2: other.last_event_at.isoformat()}
        assert (got["cadence_cv"], got["cadence_alerts"]) == (0.0, 4)
        alone = next(r.id for r in rows if r.value == "10.0.0.3")
        lone = await intel.context(conn, {"investigation_id": alone}, {}, None)
        assert lone["same_ioc"] == {}
        assert (lone["cadence_cv"], lone["cadence_alerts"]) == (None, 1)
        signals = {s.name: s for s in intel.signals(1, lone, {}, {})}
        cadence = signals["alerts.cadence_cv"]
        assert (cadence.status, cadence.unknown_reason) == ("unknown", "too_few_alerts")
        assert signals["ti.values"].value == 1
        assert signals["same_ioc.investigations"].value == 0
        mine_signals = {s.name: s for s in intel.signals(1, got, {}, {})}
        assert mine_signals["alerts.cadence_cv"].value == 0.0
        assert mine_signals["same_ioc.investigations"].value == 1
        assert mine_signals["ti.listed"].value == 1
