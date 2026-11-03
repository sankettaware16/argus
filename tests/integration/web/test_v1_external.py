"""Q-A1 gate checks with the real server (``argus web`` as a process, throwaway database):
Schemathesis ``--checks all`` over ``/api/v1`` (0 failures); the sign-in and step-up pages in
a real browser (no script runs, axe finds nothing serious); and a link followed from another
site (Kibana) that keeps the SameSite=Strict session through the same-site bounce."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web import queries
from tests.integration.web.b3_support import World
from tests.integration.web.conftest import PASSWORD
from tests.integration.web.test_external import BIN, ROOT, login, server  # noqa: F401

pytestmark = pytest.mark.integration
# A 5xx is a failure everywhere but where the contract names one for this server (Q-B3 review
# R3-8): the AI investigator is not configured here (no asset map, so no privacy layer) and
# answers 503 "unavailable", and this server has no key to sign approvals, so the two decisions
# answer 503 "no key to sign approvals". The 503 of an unreachable database is documented for every
# operation but is no part of this run: a database error hides behind it (R3-3). The session
# cookie and the CSRF token are the spec's two security schemes: Schemathesis sets them itself, so
# it can also leave them out and check that every operation then refuses (ignored_auth).
CONFIG = """
[generation]
with-security-parameters = false

[auth.openapi.session]
api_key = "${ARGUS_TEST_SESSION}"

[auth.openapi.csrf]
api_key = "${ARGUS_TEST_CSRF}"

[[operations]]
include-name = "POST /api/v1/investigations/{investigation_id}/assess"

[operations.checks.not_a_server_error]
expected-statuses = ["2xx", "3xx", "4xx", "503"]

[[operations]]
include-name = "POST /api/v1/approvals/{request_id}/decision"

[operations.checks.not_a_server_error]
expected-statuses = ["2xx", "3xx", "4xx", "503"]

[[operations]]
include-name = "POST /api/v1/approvals/group"

[operations.checks.not_a_server_error]
expected-statuses = ["2xx", "3xx", "4xx", "503"]

# Eight changes have a refusal their schema cannot state, and say so with a 422 and the reason
# (documented in the contract): "Check more" (which addresses and domains a template may be asked
# about is the server's to judge: the campus's own, the kinds a template takes), a closure request
# (a reason that rests on a statement needs words), a merge (a confirmed case needs the hash of
# the preview, a suspected one has none), an assignment (whether the id is an active person is the
# server's to judge), the two kinds of note (a person adds at most 30 an hour) and the notice
# and the block (the day a person says it happened is not in the future and not a year back:
# a time zone's date the schema cannot bound, AR4b).
[[operations]]
include-name = "POST /api/v1/investigations/{investigation_id}/checks"

[operations.checks.positive_data_acceptance]
expected-statuses = ["2xx", "3xx", "401", "403", "404", "409", "422", "429", "5xx"]

[[operations]]
include-name = "POST /api/v1/cases/{case_id}/closure-requests"

[operations.checks.positive_data_acceptance]
expected-statuses = ["2xx", "3xx", "401", "403", "404", "409", "422", "429", "5xx"]

[[operations]]
include-name = "POST /api/v1/cases/{case_id}/merge"

[operations.checks.positive_data_acceptance]
expected-statuses = ["2xx", "3xx", "401", "403", "404", "409", "422", "429", "5xx"]

[[operations]]
include-name = "POST /api/v1/cases/{case_id}/assign"

[operations.checks.positive_data_acceptance]
expected-statuses = ["2xx", "3xx", "401", "403", "404", "409", "422", "429", "5xx"]

[[operations]]
include-name = "POST /api/v1/cases/{case_id}/notes"

[operations.checks.positive_data_acceptance]
expected-statuses = ["2xx", "3xx", "401", "403", "404", "409", "422", "429", "5xx"]

[[operations]]
include-name = "POST /api/v1/entity-notes"

[operations.checks.positive_data_acceptance]
expected-statuses = ["2xx", "3xx", "401", "403", "404", "409", "422", "429", "5xx"]

[[operations]]
include-name = "POST /api/v1/cases/{case_id}/notices"

[operations.checks.positive_data_acceptance]
expected-statuses = ["2xx", "3xx", "401", "403", "404", "409", "422", "429", "5xx"]

[[operations]]
include-name = "POST /api/v1/cases/{case_id}/blocks"

[operations.checks.positive_data_acceptance]
expected-statuses = ["2xx", "3xx", "401", "403", "404", "409", "422", "429", "5xx"]
"""


async def test_schemathesis_finds_no_failure_in_v1(server: str, seeded: AsyncEngine) -> None:  # noqa: F811
    # the signed-in account may manage cases, so the case actions are fuzzed, not only refused
    async with seeded.begin() as conn:
        await conn.execute(
            text("UPDATE users SET capabilities = :c WHERE username = 'asha'"),
            {"c": ["view", "see_logs", "review", "answer_gold", "manage_cases", "reopen"]},
        )
        found = await queries.inbox(conn, "all", limit=100, sort="oldest")
    ground = World(seeded, seeded, [i.id for i in found], Path(), seeded)
    planted = await ground.open_case(2, by="asha")
    session, csrf = login(server)
    async with httpx.AsyncClient(base_url=server, cookies={"argus_session": session}) as http:
        listed = await http.get("/api/v1/investigations", params={"view": "all", "limit": 1})
    real = listed.json()["items"][0]["id"]  # a real investigation, so changes reach the store
    with tempfile.TemporaryDirectory() as folder:
        config = Path(folder) / "schemathesis.toml"
        ids = f'"path.investigation_id" = "{real}"\n"path.case_id" = "{planted}"\n'
        config.write_text(CONFIG + "\n[parameters]\n" + ids)
        result = subprocess.run(  # noqa: S603, ASYNC221 - our own dev tool, run to the end
            [str(BIN / "schemathesis"), "--config-file", str(config), "run",
             f"{server}/api/v1/openapi.json", "--checks", "all", "--max-examples", "40",
             "--exclude-operation-id", "endSession",  # it would end the run's own session
             "-H", f"Origin: {server}", "--no-color"],
            capture_output=True, text=True, timeout=1500, check=False, cwd=folder,
            env={**os.environ, "ARGUS_TEST_SESSION": session, "ARGUS_TEST_CSRF": csrf},
        )  # fmt: skip
    report = ROOT / "data" / "gate" / "schemathesis-v1-report.txt"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(result.stdout + "\n" + result.stderr)
    assert result.returncode == 0, f"see {report}"
    async with httpx.AsyncClient(base_url=server, cookies={"argus_session": session}) as http:
        assert (await http.get("/api/v1/session")).status_code == 200  # the session survived


async def test_sign_in_and_step_up_in_a_browser(server: str) -> None:  # noqa: F811
    from axe_playwright_python.async_playwright import Axe
    from playwright.async_api import async_playwright

    problems: list[str] = []
    async with async_playwright() as play:
        browser = await play.chromium.launch()
        page = await browser.new_page()
        page.set_default_timeout(90_000)
        page.on("pageerror", lambda e: problems.append(f"page error: {e}"))
        page.on("console", lambda m: problems.append(m.text) if "Content Security" in m.text
                else None)  # fmt: skip
        await page.goto(f"{server}/signin?next=/rules")
        # the page runs no script: even an injected one is blocked by its policy
        blocked = await page.evaluate("""() => new Promise(done => {
            document.addEventListener('securitypolicyviolation', e => done(e.violatedDirective));
            const s = document.createElement('script'); s.src = '/static/cost.js';
            document.body.appendChild(s); setTimeout(() => done('not blocked'), 3000);
        })""")
        assert blocked.startswith("script-src"), blocked
        axe = Axe()
        for path in ("/signin", "/signin?why=ended"):
            await page.goto(server + path)
            report = await axe.run(page)
            serious = [v for v in report.response["violations"]
                       if v["impact"] in ("serious", "critical")]  # fmt: skip
            assert serious == [], (path, serious)
        await page.goto(f"{server}/signin?next=/rules")
        await page.fill("#username", "asha")
        await page.fill("#password", PASSWORD)
        async with page.expect_navigation(url=f"{server}/rules"):
            await page.click("button[type=submit]")
        await page.goto(f"{server}/stepup?next=/proposals")
        report = await axe.run(page)
        serious = [v for v in report.response["violations"]
                   if v["impact"] in ("serious", "critical")]  # fmt: skip
        assert serious == [], ("/stepup", serious)
        await page.fill("#password", PASSWORD)
        async with page.expect_navigation(url=f"{server}/proposals"):
            await page.click("button[type=submit]")
        session = await page.request.get(f"{server}/api/v1/session")
        assert (await session.json())["stepped_up_at"] is not None
        await browser.close()
    assert [p for p in problems if "script-src" not in p] == []


async def test_a_link_from_another_site_keeps_the_session(
    server: str,  # noqa: F811
    seeded: AsyncEngine,
) -> None:
    """Kibana's case description links ``/go/investigation/<uuid>``; the session cookie is
    SameSite=Strict, so the browser leaves it off a navigation from another site. The bounce
    page opens the target again from this site, with the cookie."""
    from playwright.async_api import Route, async_playwright

    async with seeded.connect() as conn:
        inv = (await conn.execute(text("SELECT id FROM investigations LIMIT 1"))).scalar_one()
    other_site = "http://kibana.test"

    async def kibana(route: Route) -> None:
        html = (f'<a id="deep" href="{server}/go/investigation/{inv}">case</a>'
                f'<a id="direct" href="{server}/investigations/{inv}">page</a>')  # fmt: skip
        await route.fulfill(body=html, content_type="text/html")

    async with async_playwright() as play:
        browser = await play.chromium.launch()
        context = await browser.new_context()
        page = await context.new_page()
        page.set_default_timeout(90_000)
        await page.goto(f"{server}/signin")
        await page.fill("#username", "asha")
        await page.fill("#password", PASSWORD)
        async with page.expect_navigation(url=f"{server}/"):
            await page.click("button[type=submit]")
        await context.route(f"{other_site}/**", kibana)
        await page.goto(f"{other_site}/case")
        await page.click("#direct")  # without the bounce: the cookie stays behind
        await page.wait_for_url(re.compile(r".*/signin.*"))
        await page.goto(f"{other_site}/case")
        await page.click("#deep")
        await page.wait_for_url(f"{server}/investigations/{inv}")
        assert await page.locator("#inv").count() == 1  # the investigation, signed in
        await browser.close()
