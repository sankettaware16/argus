"""Q-B2's measurement of criterion 14 at twice the exit's scale (plan §8): 350,010 investigations
over 90 days, a fifth of them reviewed (the seed of Q-A1's ``test_scale.py``), on this machine.
Opt in (``RUN_SCALE_TEST=1``; a few minutes, about 1 GB in a throwaway database):

- the endpoints Q-B2 added, in process: 40 samples each, p95 at most 300 ms (the dashboard's own
  reads are measured too, for the record);
- the Inbox through ``/app`` in pinned Chromium: the first interactive row (30 cold runs, 30 warm
  runs) at most 1.5 s at p95, and a selection change (a key, until the right pane shows the other
  investigation) at most 300 ms at p95.
"""

from __future__ import annotations

import json
import os
import random
import statistics
import subprocess
import tempfile
import time
from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web.app import create_app
from tests.integration.web.conftest import BASE, NOW, PASSWORD, SAME_ORIGIN
from tests.integration.web.test_external import BIN, ROOT, free_port, started
from tests.integration.web.test_scale import DAYS, PER_DAY, huge, p95

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("RUN_SCALE_TEST") != "1",
        reason="opt-in: RUN_SCALE_TEST=1 (exit-scale measurement)",
    ),
]
__all__ = ["huge"]  # the fixture, imported for the tests below
SAMPLES, LIMIT_MS = 40, 300
RUNS = 30  # cold and warm runs of the browser measurements
FIRST_ROW_MS, SELECTION_MS = 1_500, 300
REPORT = ROOT / "data" / "gate" / "q-b2-scale.json"  # local, not committed
DOSSIER = {
    "report": {"steps": [{"number": 1, "text": "Check the source", "fields": ["source.ip"],
                          "shown": ["source.ip"], "status": "answered", "sentence": "Answered.",
                          "needs": []}], "summary": ["3 requests"], "has_note": True,
               "complete": True, "alerts_read": 1},
    "local_signals": [], "signals": [{"name": "ti.listed", "status": "known", "value": 0}],
    "context": {"pack": {"fields": {"source.ip": {"top": [["10.0.0.1", 1]], "distinct": 1}},
                         "ips": {}, "web": {}}, "related": []},
}  # fmt: skip


async def add_dossiers(engine: AsyncEngine, n: int) -> list[str]:
    """A dossier on ``n`` investigations picked at random, and the open ones' ``ti.listed``."""
    async with engine.begin() as conn:
        rows = (await conn.execute(text(
            "SELECT id, version FROM investigations ORDER BY md5(id::text) LIMIT :n"),
            {"n": n})).all()  # fmt: skip
        for row in rows:
            await conn.execute(
                text("INSERT INTO dossiers (investigation_id, version, pack, facts_version, job_id,"
                     " run_kind, family, status, dossier_hash, body, evidence_count, created_at)"
                     " VALUES (:i, :v, 'generic@12', :v, 1, 'collect', 'generic', 'evidence_ready',"
                     " :h, CAST(:b AS jsonb), 0, :t)"),
                {"i": row.id, "v": row.version, "h": "c" * 64, "b": json.dumps(DOSSIER),
                 "t": NOW},
            )  # fmt: skip
    return [str(r.id) for r in rows]


def record(name: str, value: Any) -> None:
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(REPORT, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        data = {}
    data[name] = value
    with open(REPORT, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


@pytest.mark.timeout(3600)
async def test_the_new_endpoints_at_twice_the_exits_scale(
    huge: AsyncEngine, migrated_engine: AsyncEngine, web_engine: AsyncEngine
) -> None:
    ids = await add_dossiers(migrated_engine, 200)
    rnd = random.Random(14)
    app = create_app(web_engine, clock=lambda: NOW + timedelta(days=1))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE,
                                 headers=SAME_ORIGIN) as http:  # fmt: skip
        for _ in range(
            2
        ):  # the second sign-in has a previous visit: "since" has something to count
            made = await http.post("/api/login", json={"username": "asha", "password": PASSWORD})
            assert made.status_code == 200
        checks = {
            "since": ["/api/v1/since"] * SAMPLES,
            "threat lists, 7 days": ["/api/v1/dashboard/threat-lists?range=7d"] * SAMPLES,
            "threat lists, 90 days": ["/api/v1/dashboard/threat-lists?range=90d"] * SAMPLES,
            "threat lists, a rule": [
                "/api/v1/dashboard/threat-lists?range=90d&rule=rule-3"] * SAMPLES,
            "report of an investigation": [f"/api/v1/investigations/{rnd.choice(ids)}/reports"
                                           for _ in range(SAMPLES)],
            "an investigation (the right pane)": [f"/api/v1/investigations/{rnd.choice(ids)}"
                                                  for _ in range(SAMPLES)],
        }  # fmt: skip
        results = {name: await p95(http, paths) for name, paths in checks.items()}
        for_the_record = {
            "dashboard, 24 hours (record)": ["/api/v1/dashboard?range=24h"] * 10,
            "dashboard, 7 days (record)": ["/api/v1/dashboard?range=7d"] * 10,
            "dashboard, 90 days (record)": ["/api/v1/dashboard?range=90d"] * 10,
        }
        record_results = {name: await p95(http, paths) for name, paths in for_the_record.items()}
    shown = {name: round(ms) for name, ms in {**results, **record_results}.items()}
    print("p95 ms at 350,010 investigations:", shown)
    record("api_p95_ms", shown)
    slow = {name: ms for name, ms in shown.items() if ms > LIMIT_MS and "(record)" not in name}
    assert slow == {}, slow


@pytest.fixture
async def huge_server(huge: AsyncEngine, test_database: str) -> AsyncIterator[str]:
    port = free_port()
    env = {k: v for k, v in os.environ.items() if not k.startswith("ARGUS_")}
    env.update(ARGUS_DATABASE__NAME=test_database, ARGUS_WEB__PORT=str(port))
    from tests.conftest import suite_config

    env["ARGUS_CONFIG"] = str(suite_config())  # the suite's site, not this checkout's
    log = tempfile.TemporaryFile()  # noqa: SIM115 - closed below
    process = subprocess.Popen(  # noqa: S603, ASYNC220 - our own CLI, started once
        [str(BIN / "argus"), "web"], cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=log
    )
    url = f"http://127.0.0.1:{port}"
    try:
        started(url, process, log)
        yield url
    finally:
        process.terminate()
        process.wait(timeout=10)
        log.close()


def quantile95(values: list[float]) -> float:
    return statistics.quantiles(values, n=20)[-1]


@pytest.mark.timeout(3600)
async def test_the_inbox_through_the_app_at_twice_the_exits_scale(
    huge_server: str, migrated_engine: AsyncEngine
) -> None:
    from playwright.async_api import async_playwright

    await add_dossiers(migrated_engine, 200)
    async with httpx.AsyncClient(base_url=huge_server) as http:
        login = await http.post("/api/login", json={"username": "asha", "password": PASSWORD},
                                headers={"Origin": huge_server})  # fmt: skip
    assert login.status_code == 200
    cookie = {"name": "argus_session", "value": login.cookies["argus_session"],
              "url": huge_server}  # fmt: skip
    first_rows_cold: list[float] = []
    first_rows_warm: list[float] = []
    selections: list[float] = []
    async with async_playwright() as play:
        browser = await play.chromium.launch()
        version = browser.version
        for _ in range(RUNS):  # cold: nothing cached, a new context each time
            context = await browser.new_context(viewport={"width": 1440, "height": 900})
            await context.add_cookies([cookie])
            page = await context.new_page()
            page.set_default_timeout(60_000)
            await page.goto(f"{huge_server}/app/inbox?view=attention", wait_until="commit")
            await page.locator("[role=grid] [role=row]").nth(1).wait_for()
            first_rows_cold.append(await page.evaluate("() => performance.now()"))
            await context.close()
        context = await browser.new_context(viewport={"width": 1440, "height": 900})
        await context.add_cookies([cookie])
        page = await context.new_page()
        page.set_default_timeout(60_000)
        await page.goto(f"{huge_server}/app/inbox?view=attention")
        await page.locator("[role=grid] [role=row]").nth(1).wait_for()
        for _ in range(RUNS):  # warm: the code is cached, the page and its reads are new
            await page.goto(f"{huge_server}/app/inbox?view=attention", wait_until="commit")
            await page.locator("[role=grid] [role=row]").nth(1).wait_for()
            first_rows_warm.append(await page.evaluate("() => performance.now()"))
        await page.goto(f"{huge_server}/app/inbox?view=open")
        await page.get_by_test_id("investigation-id").wait_for()
        await page.get_by_role("grid", name="Investigations").focus()
        for n in range(RUNS):  # a selection change: a key, until the other investigation shows
            before = await page.get_by_test_id("investigation-id").inner_text()
            started_at = time.perf_counter()
            await page.keyboard.press("ArrowDown" if n % 2 == 0 else "j")
            await page.wait_for_function(  # the other investigation's id, its page drawn
                "(was) => { const id = document.querySelector('[data-testid=investigation-id]');"
                " return id !== null && id.textContent !== was"
                " && document.querySelector('article[aria-busy=true]') === null; }",
                arg=before,
            )
            selections.append((time.perf_counter() - started_at) * 1000)
            await page.wait_for_timeout(150)
        await browser.close()

    def spread(values: list[float]) -> dict[str, int]:
        return {"p95": round(quantile95(values)), "median": round(statistics.median(values)),
                "max": round(max(values))}  # fmt: skip

    result = {
        "browser": f"Chromium {version}", "runs": RUNS, "investigations": DAYS * PER_DAY,
        "first_row_cold_ms": spread(first_rows_cold), "first_row_warm_ms": spread(first_rows_warm),
        "selection_ms": spread(selections),
    }  # fmt: skip
    print("the Inbox through /app:", result)
    record("browser", result)
    assert result["first_row_cold_ms"]["p95"] <= FIRST_ROW_MS, result  # type: ignore[index]
    assert result["first_row_warm_ms"]["p95"] <= FIRST_ROW_MS, result  # type: ignore[index]
    assert result["selection_ms"]["p95"] <= SELECTION_MS, result  # type: ignore[index]
