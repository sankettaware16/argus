"""R12 (D-060): the proxy module answers the notes' prevalence, timeline and pivot steps from
squid's logs, only with enrichment.log_queries on, within two daily indices and the margin."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assets.classify import IpClassifier
from argus.context import proxy
from argus.context.packs import default_registry
from argus.context.worker import Worker
from argus.gateway.gateway import Result
from argus.gateway.indices import daily_indices
from argus.gateway.templates import Params, Purpose, Template
from argus.reference import store as reference
from tests.integration.context.conftest import NOW
from tests.integration.context.test_generic import alert, dossiers
from tests.integration.grouping.test_grouping import ingest

pytestmark = pytest.mark.integration

NOTE = """### Investigation Steps
1. How many internal hosts reach `destination.ip`?
2. Check periodicity: regular intervals suggest a beacon.
3. Pivot on `source.ip` for the last 24h: how many destinations?
"""
INDICES = ["acme-logs-squid-*"]


class LogGateway:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def run(
        self, template: Template, params: Params, *, purpose: Purpose, component: str, deadline: Any
    ) -> Result:
        assert purpose is Purpose.ENRICH
        self.calls.append(template.name)
        if template.name == "proxy.host":
            slots = [{"doc_count": 1 if n % 6 == 0 else 0} for n in range(60)]
            aggs = {
                "destinations": {"buckets": []},
                "destination_count": {"value": 7},
                "bytes": {"value": 12_345},
                "statuses": {"buckets": []},
                "actions": {"buckets": []},
                "timeline": {"buckets": slots},
            }
        else:
            aggs = {"host_count": {"value": 3}, "hosts": {"buckets": []}, "urls": {"buckets": []}}
        return Result({"aggregations": aggs, "hits": {"hits": []}}, 300, ("squid",))


async def prepare(engine: AsyncEngine) -> None:
    d = alert(
        1, note=NOTE, destination={"ip": "45.9.9.9"}, **{"kibana.alert.rule.indices": INDICES}
    )
    d["_source"]["source"]["ip"] = "10.0.0.1"
    await ingest(engine, [d])
    async with engine.begin() as conn:
        await reference.refresh_rules(conn, NOW, hold=timedelta(0))


async def run(engine: AsyncEngine, saver: AsyncPostgresSaver, gateway: Any, **kw: Any) -> Any:
    packs = default_registry(IpClassifier(None), **kw)
    worker = Worker(engine, saver, packs=packs, gateway=gateway, clock=lambda: NOW)
    while await worker.run_once(limit=10):
        pass
    (d,) = await dossiers(engine)
    return d


async def test_with_log_queries_the_steps_are_answered_from_the_logs(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(proxy, "datetime", _Fixed)  # "now" a day after the alerts
    await prepare(app_engine)
    gateway = LogGateway()
    d = await run(app_engine, saver, gateway, proxy_aggregations=True)
    assert sorted(gateway.calls) == ["proxy.destination", "proxy.host"]
    steps = d.body["report"]["steps"]
    assert [s["status"] for s in steps] == ["answered", "answered", "answered"]
    assert steps[0]["sentence"] == (
        "Proxy logs: 3 internal hosts reached the destination in the window."
    )
    assert steps[1]["sentence"].startswith("Proxy logs: traffic in 10 ten-minute slots")
    signals = {s["name"]: s["value"] for s in d.body["signals"]}
    assert (signals["proxy.destinations"], signals["proxy.bytes"]) == (7, 12_345)
    assert signals["proxy.regularity"] == 0.0  # a slot every hour exactly


async def test_without_log_queries_nothing_is_asked(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    await prepare(app_engine)
    gateway = LogGateway()
    d = await run(app_engine, saver, gateway)
    assert gateway.calls == []
    assert [s["status"] for s in d.body["report"]["steps"]] == ["deferred"] * 3


class _Fixed(datetime):
    @classmethod
    def now(cls, tz: Any = None) -> datetime:  # type: ignore[override]
        return NOW + timedelta(days=1)


@given(
    st.integers(0, 60 * 24 * 330),
    st.integers(0, 60 * 30),
    st.integers(0, 60 * 48),
)
def test_the_window_fits_two_indices_and_the_margin(offset: int, minutes: int, lag: int) -> None:
    first = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(minutes=offset)
    last = first + timedelta(minutes=minutes)
    now = last + timedelta(minutes=lag)
    span = proxy.window(
        {"first_event_at": first.isoformat(), "last_event_at": last.isoformat()}, now
    )
    if span is None:
        return
    lo, hi = span
    assert hi <= now - proxy.MARGIN
    assert lo < hi
    assert hi - lo <= proxy.MAX_WINDOW
    assert len(daily_indices("p-", lo, hi)) <= 2
    assert proxy.applies(["acme-logs-squid-*"])
    assert not proxy.applies(["x-nginx-*"])


async def test_web_queries_alone_never_aggregate_squid(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D-069: the web follow-up and the proxy aggregations are switched on separately."""
    monkeypatch.setattr(proxy, "datetime", _Fixed)
    await prepare(app_engine)
    gateway = LogGateway()
    await run(app_engine, saver, gateway, log_queries=True)
    assert [c for c in gateway.calls if c.startswith("proxy.")] == []


async def test_an_investigation_asks_the_logs_once(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D-070: a later version (new alerts, a later "now") plans the same requests again, so
    the stored answers are reused: the SIEM is asked once per investigation."""
    monkeypatch.setattr(proxy, "datetime", _Fixed)
    await prepare(app_engine)
    gateway = LogGateway()
    first = await run(app_engine, saver, gateway, proxy_aggregations=True)
    assert sorted(gateway.calls) == ["proxy.destination", "proxy.host"]
    later = alert(2, note=NOTE, destination={"ip": "45.9.9.9"},
                  **{"kibana.alert.rule.indices": INDICES})  # fmt: skip
    later["_source"]["source"]["ip"] = "10.0.0.1"
    await ingest(app_engine, [later])
    packs = default_registry(IpClassifier(None), proxy_aggregations=True)
    worker = Worker(app_engine, saver, packs=packs, gateway=gateway,
                    clock=lambda: NOW + timedelta(hours=2))  # fmt: skip
    async with app_engine.begin() as conn:
        await conn.execute(text("UPDATE jobs SET run_after = :t WHERE status = 'queued'"),
                           {"t": NOW})  # fmt: skip
    while await worker.run_once(limit=10):
        pass
    assert sorted(gateway.calls) == ["proxy.destination", "proxy.host"]  # no new request
    async with app_engine.connect() as conn:
        query = "SELECT version, template, reused_from_version FROM evidence ORDER BY 1, 2"
        rows = (await conn.execute(text(query))).all()
    assert [tuple(r) for r in rows] == [
        (1, "proxy.destination", None),
        (1, "proxy.host", None),
        (2, "proxy.destination", 1),
        (2, "proxy.host", 1),
    ]
    assert first.body["context"]["pack"]["earlier_logs"] == {}
