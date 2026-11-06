"""R7 gate checks with the real server (``argus web`` as a process, throwaway database):
Schemathesis over the whole API (0 failures), a hostile-content browser suite (0 script
execution) and axe (0 serious or critical accessibility violations) on every page."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.grouping.test_grouping import doc, ingest
from tests.integration.web.conftest import NOW, PASSWORD

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[3]
BIN = Path(sys.executable).parent
HOSTILE = '<script>window.__pwned=1</script><img src=x onerror="window.__pwned=2">‮"'


STARTUP = 60.0  # seconds: under a full suite's load, imports and the privacy layer are slow


def started(url: str, process: subprocess.Popen[bytes], log: Any, verify: Any = True) -> None:
    """Wait until ``argus web`` answers, or fail with its log. It once had about 10 seconds,
    and under load it sometimes needed more (the intermittent failures of 10-21/22)."""
    deadline = time.monotonic() + STARTUP
    while time.monotonic() < deadline and process.poll() is None:
        try:
            if httpx.get(f"{url}/signin", verify=verify, timeout=1).status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.2)
    log.seek(0)
    raise AssertionError(f"argus web did not start (exit {process.poll()}):\n"
                         + log.read().decode(errors="replace"))  # fmt: skip


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


@pytest.fixture
async def server(seeded: AsyncEngine, test_database: str) -> Iterator[str]:
    bad = doc(900, "rule-x", "10.9.9.9", NOW - timedelta(minutes=5))
    bad["_source"]["kibana.alert.rule.name"] = HOSTILE
    bad["_source"]["host"] = {"name": HOSTILE}
    await ingest(seeded, [bad])
    await plant_dossiers(seeded)
    await plant_assessments(seeded)
    port = free_port()
    env = {k: v for k, v in os.environ.items() if not k.startswith("ARGUS_")}
    env.update(ARGUS_DATABASE__NAME=test_database, ARGUS_WEB__PORT=str(port))
    from tests.conftest import suite_config

    env["ARGUS_CONFIG"] = str(suite_config())  # the suite's site, not this checkout's
    log = tempfile.TemporaryFile()  # noqa: SIM115 - closed below
    # never a pipe: nobody reads it while the tests run, so after 64 KB of log lines the server
    # blocks on its next write and every request hangs (the browser test's timeouts, 10-21)
    process = subprocess.Popen(  # noqa: S603, ASYNC220 - our own CLI, started once
        [str(BIN / "argus"), "web"], cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=log,
    )  # fmt: skip
    url = f"http://127.0.0.1:{port}"
    try:
        started(url, process, log)
        yield url
    finally:
        process.terminate()
        process.wait(timeout=10)
        log.close()


def cost_bar_start() -> str:
    """The cost bar's text before its call count, on no spend, for the caps the server runs with:
    ``argus web`` reads this checkout's config/llm.yaml with the installation's llm.local.yaml laid
    over it (a site may set its own budget), so the expected caps are read the same way."""
    from argus.llm.providers import load_config

    llm = load_config()
    daily = "" if llm.daily_cap_usd is None else f" of ${llm.daily_cap_usd:.2f}"
    return f"$0.00 of ${llm.monthly_cap_usd:.2f} this month · today $0.00{daily} ("


async def plant_dossiers(engine: AsyncEngine) -> None:
    """Every investigation's dossier (the generic pack, nothing asked of the SIEM), so the report
    page (Q-F2) has a report to show, the hostile one's included."""
    from langgraph.checkpoint.memory import InMemorySaver

    from argus.context.packs import default_registry
    from argus.context.worker import Worker

    worker = Worker(engine, InMemorySaver(), packs=default_registry(), clock=lambda: NOW)
    while await worker.run_once(limit=20):
        pass


async def plant_assessments(engine: AsyncEngine) -> None:
    """A hostile proposal, no-decision and tuning report, for P8's pages (D-091)."""
    from argus.assess import queue
    from argus.tuning import advise
    from argus.tuning import store as tuning_store
    from argus.tuning.report import RuleReport, ValueStat
    from argus.web import queries

    async with engine.begin() as conn:
        a, b = (await queries.inbox(conn, "all"))[:2]
        for inv, n in ((a, 1), (b, 2)):
            await queue.enqueue(conn, inv.id, inv.version, "generic@12", "a" * 64,
                                f"{n:064x}", "agent@1", NOW)  # fmt: skip
        first, second = await queue.claim(conn, "w", NOW, "agent@1", 2)
        report = {"kind": "agent@1", "answer": {
            "outcome": "true_positive", "confidence": 0.5, "explanation": HOSTILE,
            "hypotheses": [{"name": HOSTILE, "for": [HOSTILE], "against": [HOSTILE]}],
            "cites": [HOSTILE]},
            "checks": [{"tool": HOSTILE, "value": HOSTILE, "result": HOSTILE}],
            "specialists": [{"domain": HOSTILE, "notes": HOSTILE}], "rounds": 1, "calls": 1,
            "tiers": [], "models": [HOSTILE], "cost_usd": 0.0, "seconds": 1.0}  # fmt: skip
        await queue.propose(conn, first, NOW, "true_positive", f"agent@1#{HOSTILE}",
                            [HOSTILE, report], 0.5)  # fmt: skip
        await queue.no_decision(conn, second, NOW, "agent@1#m", [HOSTILE])
        rep = RuleReport(HOSTILE, NOW, NOW, 1, (), 1, 1, 0, 100, {HOSTILE: 1}, {},
                         (ValueStat(HOSTILE, HOSTILE, 1, 1, {}),))  # fmt: skip
        got = advise.Advice([advise.Suggestion("exception", HOSTILE, HOSTILE, HOSTILE,
                                               HOSTILE, (HOSTILE,), HOSTILE)], [HOSTILE],
                            HOSTILE, 0.0)  # fmt: skip
        await tuning_store.save(conn, rep, got)


def login(url: str) -> tuple[str, str]:
    response = httpx.post(
        f"{url}/api/login", json={"username": "asha", "password": PASSWORD}, headers={"Origin": url}
    )
    assert response.status_code == 200, response.text
    return response.cookies["argus_session"], response.json()["csrf_token"]


def test_schemathesis_finds_no_failure(server: str) -> None:
    session, csrf = login(server)
    result = subprocess.run(  # noqa: S603 - our own dev tool
        [str(BIN / "schemathesis"), "run", f"{server}/api/openapi.json",
         "--checks", "all", "--max-examples", "40", "--exclude-path", "/api/logout",
         "-H", f"Cookie: argus_session={session}", "-H", f"X-CSRF-Token: {csrf}",
         "-H", f"Origin: {server}", "--no-color"],
        capture_output=True, text=True, timeout=900, check=False,
    )  # fmt: skip
    report = ROOT / "data" / "gate" / "schemathesis-report.txt"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(result.stdout)
    assert result.returncode == 0, f"see {report}"


async def test_hostile_content_never_runs_and_pages_are_accessible(server: str) -> None:
    from axe_playwright_python.async_playwright import Axe
    from playwright.async_api import async_playwright

    session, _ = login(server)
    with httpx.Client(base_url=server, cookies={"argus_session": session}) as api:
        listed = api.get("/api/investigations", params={"view": "all", "rule": "rule-x"})  # noqa: ASYNC212
        (hostile,) = listed.json()
        detail = api.get(f"/api/investigations/{hostile['id']}").json()  # noqa: ASYNC212
    alert_id = detail["alerts"][0]["alert_id"]
    pages = ["/", "/?view=open", "/?view=reviewed", "/?view=all", "/rules", "/hosts", "/health",
             "/glossary",
             "/patterns", "/proposals", "/tuning", "/metrics", "/dashboard",
             "/dashboard?range=24h&severity=critical&severity=high&state=unreviewed",
             f"/investigations/{hostile['id']}",
             f"/investigations/{hostile['id']}?columns=set&cols=source.ip&cols=host.name",
             f"/investigations/{hostile['id']}/alerts/{alert_id}",
             f"/investigations/{hostile['id']}/report"]  # fmt: skip
    problems: list[str] = []
    async with async_playwright() as play:
        browser = await play.chromium.launch()
        page = await browser.new_page()
        page.set_default_timeout(90_000)  # a loaded machine (a mutation run) is slow
        page.on("dialog", lambda d: problems.append(f"dialog: {d.message}"))
        page.on("pageerror", lambda e: problems.append(f"page error: {e}"))
        await page.goto(f"{server}/login")
        axe = Axe()
        report = await axe.run(page)
        serious = [v for v in report.response["violations"]
                   if v["impact"] in ("serious", "critical")]  # fmt: skip
        assert serious == [], ("/login", serious)
        await page.fill("#username", "asha")
        await page.fill("#password", PASSWORD)
        async with page.expect_navigation(url=f"{server}/"):  # waiting starts before the click
            await page.click("button[type=submit]")  # the login worked: a real form post
        assert await page.locator("h1").inner_text() == "Needs attention"
        await page.wait_for_function(  # the cost bar's script runs under the CSP (D-094)
            "document.getElementById('cost-text').textContent.includes('this month')"
        )
        bar = await page.locator("#cost-text").inner_text()
        assert bar.startswith(cost_bar_start())
        await page.goto(f"{server}/dashboard")  # the filter form, as a person uses it (10-21)
        await page.check('input[name="severity"][value="high"]')
        await page.click('form.filters button[type="submit"]')
        await page.wait_for_load_state()
        assert await page.locator("h1").inner_text() == "Dashboard", await page.content()
        assert "severity=high" in page.url
        assert await page.locator("ul.active-filters").count() == 1
        for path in pages:
            await page.goto(server + path)
            assert await page.evaluate("window.__pwned") is None, path
            assert await page.locator("img[src=x]").count() == 0, path
            report = await axe.run(page)
            serious = [v for v in report.response["violations"]
                       if v["impact"] in ("serious", "critical")]  # fmt: skip
            assert serious == [], (path, serious)
        await browser.close()
    assert problems == []
