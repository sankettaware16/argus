"""R13 (D-060): the web module on a real-shaped WAF alert: decoded paths, the NAXSI class,
and, with log queries on, whether the client then got successful answers."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assets.classify import IpClassifier
from argus.context import web
from argus.context.packs import default_registry
from argus.context.worker import Worker
from argus.gateway.gateway import Result
from argus.gateway.templates import Params, Purpose, Template
from argus.reference import store as reference
from tests.integration.context.conftest import NOW
from tests.integration.context.test_generic import alert, dossiers
from tests.integration.context.test_proxy import _Fixed
from tests.integration.grouping.test_grouping import ingest

pytestmark = pytest.mark.integration

NOTE = """### Investigation Steps
1. Look at `url.path` and `rule.id`.
2. Pivot on `source.ip`: did the same client get any 200 responses?
"""


class WebGateway:
    def __init__(self, rows: int) -> None:
        self.rows, self.calls = rows, 0

    async def run(
        self, template: Template, params: Params, *, purpose: Purpose, component: str, deadline: Any
    ) -> Result:
        assert template.name == "web.followups"
        assert purpose is Purpose.ENRICH
        self.calls += 1
        hits = [
            {"_source": {"url": {"path": f"/ok/{n}"}, "http": {"response": {"status_code": 200}}}}
            for n in range(self.rows)
        ]
        return Result({"hits": {"hits": hits}}, 12, ("nginx",))


async def prepare(engine: AsyncEngine) -> None:
    d = alert(1, note=NOTE, **{"kibana.alert.rule.indices": ["acme-logs-nginx-*"]})
    d["_source"].update(
        {
            "url": {"path": "/?x=%252e%252e%252fetc%252fpasswd", "domain": "www.site.example"},
            "rule": {"id": "1013"},
            "user_agent": {"original": "sqlmap/1.7"},
        }
    )
    d["_source"]["source"]["ip"] = "45.9.9.9"
    await ingest(engine, [d])
    async with engine.begin() as conn:
        await reference.refresh_rules(conn, NOW, hold=timedelta(0))


async def run(engine: AsyncEngine, saver: AsyncPostgresSaver, gateway: Any, **kw: Any) -> Any:
    worker = Worker(
        engine,
        saver,
        packs=default_registry(IpClassifier(None), **kw),
        gateway=gateway,
        clock=lambda: NOW,
    )
    while await worker.run_once(limit=10):
        pass
    (d,) = await dossiers(engine)
    return d


async def test_the_attack_is_described_from_the_alerts(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    await prepare(app_engine)
    gateway = WebGateway(0)
    d = await run(app_engine, saver, gateway)
    assert gateway.calls == 0  # log queries off
    w = d.body["context"]["pack"]["web"]
    assert w["decoded_paths"] == ["/?x=../etc/passwd"]
    assert w["categories"] == ["traversal"]
    assert w["naxsi"] == [{"id": "1013", "class": "directory traversal", "alerts": 1}]
    assert w["scanner_agents"] == ["sqlmap/1.7"]
    assert "NAXSI rule 1013: directory traversal (1 alerts)" in d.body["report"]["summary"]
    steps = d.body["report"]["steps"]
    assert [s["status"] for s in steps] == ["answered", "deferred"]


@pytest.mark.parametrize(
    ("rows", "sentence"),
    [
        (
            2,
            "nginx logs: 2 successful (2xx) answers to the client in the hours after the first"
            " alert.",
        ),
        (0, None),  # 0 from logs says nothing until ingest is measured (D-063)
    ],
)
async def test_with_log_queries_the_follow_up_is_answered(
    app_engine: AsyncEngine,
    saver: AsyncPostgresSaver,
    monkeypatch: pytest.MonkeyPatch,
    rows: int,
    sentence: str | None,
) -> None:
    monkeypatch.setattr(web, "datetime", _Fixed)
    await prepare(app_engine)
    gateway = WebGateway(rows)
    d = await run(app_engine, saver, gateway, log_queries=True)
    assert gateway.calls == 1
    step = d.body["report"]["steps"][1]
    signal = next(s for s in d.body["signals"] if s["name"] == "web.successes_after")
    if sentence is None:
        assert step["status"] == "deferred"
        assert (signal["status"], signal["unknown_reason"]) == ("unknown", "ingest_not_verified")
    else:
        assert (step["status"], step["sentence"]) == ("answered", sentence)
        assert signal["value"] == rows
