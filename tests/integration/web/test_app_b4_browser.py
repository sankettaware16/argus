"""Q-B4's browser gate (plan §5 Q-B4, §7.5) on the real server with the switch on
(``ARGUS_WEB__CLASSIC=fallback``; ``argus web`` as a process, throwaway database), in Chromium and
Firefox. These are the counterparts of the classic browser tests:

- the classic pages' hostile-content and axe test (``test_external``) for the pages the app did not
  have before Q-B4: By rule, By host or IP, Patterns, Health, Glossary, Metrics, Tuning and the Gold
  set: no policy violation, no script, nothing becomes markup, axe finds nothing serious (light and
  dark, 390 and 1440 px), no sideways scroll at phone width;
- the classic sign-in test's end (a person lands on the Inbox with the cost bar): signing in leads
  to the app, whose status bar reads the cost and the SIEM;
- the redirects as a browser follows them, the query kept, the fallback at ``/classic`` read-only
  and left by opening the app, and a permanent link followed from another site
  (``test_v1_external``);
- ``test_r15``'s pattern review: a group marked reviewed from the exact request, a changed
  investigation left alone.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from collections.abc import AsyncIterator
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.grouping.test_grouping import doc, ingest
from tests.integration.web.b2_support import (
    BROWSERS,
    SPAN,
    Watch,
    open_context,
    seed_more,
    sign_in,
)
from tests.integration.web.conftest import NOW, PASSWORD
from tests.integration.web.test_external import (
    BIN,
    HOSTILE,
    ROOT,
    free_port,
    plant_assessments,
    plant_dossiers,
    started,
)

pytestmark = pytest.mark.integration
WCAG = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22a", "wcag22aa"]
PAGES = [
    ("By rule", "/app/rules"),
    ("By host or IP", "/app/hosts"),
    ("Patterns", "/app/patterns"),
    ("Health", "/app/health"),
    ("Glossary", "/app/glossary"),
    ("Metrics", "/app/metrics"),
    ("Rule tuning", "/app/tuning"),
    ("Gold set", "/app/gold"),
]


@pytest.fixture
async def switched(
    seeded: AsyncEngine, test_database: str
) -> AsyncIterator[tuple[str, dict[str, Any]]]:
    """``test_external``'s server (a hostile record, dossiers, assessments, a tuning report), with
    the switch on, and Q-B2's richer records (a gold item, reviews, a group of proposals)."""
    bad = doc(900, "rule-x", "10.9.9.9", NOW - timedelta(minutes=5))
    bad["_source"]["kibana.alert.rule.name"] = HOSTILE
    bad["_source"]["host"] = {"name": HOSTILE}
    await ingest(seeded, [bad])
    await plant_dossiers(seeded)
    await plant_assessments(seeded)
    records = await seed_more(seeded)
    port = free_port()
    env = {k: v for k, v in os.environ.items() if not k.startswith("ARGUS_")}
    env.update(ARGUS_DATABASE__NAME=test_database, ARGUS_WEB__PORT=str(port),
               ARGUS_WEB__CLASSIC="fallback")  # fmt: skip
    from tests.conftest import suite_config

    env["ARGUS_CONFIG"] = str(suite_config())  # the suite's site, not this checkout's
    log = tempfile.TemporaryFile()  # noqa: SIM115 - closed below; never a pipe nobody reads
    process = subprocess.Popen(  # noqa: S603, ASYNC220 - our own CLI, started once
        [str(BIN / "argus"), "web"], cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=log
    )  # fmt: skip
    url = f"http://127.0.0.1:{port}"
    try:
        started(url, process, log)
        yield url, records
    finally:
        process.terminate()
        process.wait(timeout=10)
        log.close()


async def heading_of(page: Any) -> str:
    await page.locator("main h1").first.wait_for(state="attached")
    return str(await page.locator("main h1").first.inner_text())


@pytest.mark.parametrize("name", BROWSERS)
async def test_the_pages_added_for_parity_are_inert_accessible_and_fit_a_phone(
    switched: tuple[str, dict[str, Any]], name: str
) -> None:
    from axe_playwright_python.async_playwright import Axe
    from playwright.async_api import async_playwright

    server, _ = switched
    axe = Axe()
    problems: list[Any] = []
    wide: list[tuple[str, int]] = []
    watch = Watch()
    async with async_playwright() as play:
        for scheme in ("light", "dark"):
            for width in (390, 1440):
                browser, context = await open_context(
                    play, name, viewport={"width": width, "height": 900}, color_scheme=scheme
                )
                page = await context.new_page()
                page.set_default_timeout(60_000)
                watch.attach(page)
                await sign_in(page, server, "/app")
                for label, where in PAGES:
                    await page.goto(server + where)
                    assert await heading_of(page) == label
                    await page.wait_for_load_state("networkidle")
                    await page.wait_for_function(
                        "() => !document.querySelector('[aria-busy=true]')"
                    )
                    assert await page.evaluate("window.__pwned") is None, where
                    assert await page.locator("main img, main script, main iframe").count() == 0
                    assert await page.locator("main a[href*='evil'], main a[href^='javascript']"
                                              ).count() == 0  # fmt: skip
                    over = await page.evaluate(
                        "document.documentElement.scrollWidth"
                        " - document.documentElement.clientWidth"
                    )
                    if over > 0:
                        wide.append((where, over))
                    await page.evaluate("() => document.querySelectorAll('details')"
                                        ".forEach((d) => { d.open = true; })")  # fmt: skip
                    report = await axe.run(page, options={"runOnly": {"type": "tag",
                                                                      "values": WCAG}})  # fmt: skip
                    ran = {r["id"] for kind in ("passes", "incomplete", "violations")
                           for r in report.response.get(kind, [])}  # fmt: skip
                    assert {"color-contrast", "target-size"} & ran, ran
                    for v in report.response["violations"]:
                        if v["impact"] in ("serious", "critical"):
                            targets = [n["target"] for n in v["nodes"]][:4]
                            problems.append((scheme, width, label, v["id"], targets))
                violations = await watch.violations(page)
                assert violations == [], (scheme, width, violations)
                await browser.close()
    assert not problems, "\n".join(map(str, problems))
    assert wide == []
    assert watch.errors == []


@pytest.mark.parametrize("name", BROWSERS)
async def test_signing_in_leads_to_the_app_whose_status_bar_reads_the_cost_and_the_siem(
    switched: tuple[str, dict[str, Any]], name: str
) -> None:
    """The counterpart of the classic sign-in test: the form post lands on the Inbox with the cost
    bar's words. Here ``/`` leads to ``/app``."""
    from playwright.async_api import async_playwright

    server, _ = switched
    watch = Watch()
    async with async_playwright() as play:
        browser, context = await open_context(play, name)
        page = await context.new_page()
        page.set_default_timeout(60_000)
        watch.attach(page)
        await page.goto(f"{server}/signin")
        await page.fill("#username", "asha")
        await page.fill("#password", PASSWORD)
        async with page.expect_navigation(url=re.compile(re.escape(server) + r"/app/?$")):
            await page.click("button[type=submit]")
        assert await heading_of(page) == "Home"
        await page.wait_for_function(  # the status bar reads the cost, under the policy
            "() => document.body.textContent.includes('this month')"
        )
        bar = await page.get_by_role("link", name=re.compile("AI cost")).inner_text()
        assert re.search(
            r"\$0\.00 of \$40\.00 this month · today \$0\.00 of \$1\.50 \(0 calls\)", bar
        ), bar
        siem = page.get_by_role("link", name=re.compile("SIEM"))
        await siem.first.wait_for()  # its own request; Home's queue reads can finish first
        assert await siem.count() == 1
        assert await watch.violations(page) == []
        await browser.close()
    assert watch.errors == []


@pytest.mark.parametrize("name", BROWSERS)
async def test_classic_addresses_lead_to_the_app_and_the_fallback_is_read_only(
    switched: tuple[str, dict[str, Any]], name: str
) -> None:
    from playwright.async_api import async_playwright

    server, records = switched
    inv = records["agent"]["investigation_id"]
    watch = Watch()
    async with async_playwright() as play:
        browser, context = await open_context(play, name, viewport={"width": 1440, "height": 900})
        page = await context.new_page()
        page.set_default_timeout(60_000)
        watch.attach(page)
        await page.goto(f"{server}/signin?next=/rules")  # sign-in goes back to a classic address
        await page.fill("#username", "asha")
        await page.fill("#password", PASSWORD)
        async with page.expect_navigation(url=f"{server}/app/rules"):  # which leads to the app
            await page.click("button[type=submit]")
        assert await heading_of(page) == "By rule"
        await page.goto(f"{server}/dashboard?{SPAN}&severity=high")
        assert await heading_of(page) == "Dashboard"
        assert page.url == f"{server}/app/dashboard?{SPAN}&severity=high"
        await page.goto(f"{server}/?view=all&kind=ip&value=10.0.0.1")
        assert page.url == f"{server}/app/inbox?view=all&kind=ip&value=10.0.0.1"
        await page.locator("[role=grid]").wait_for()
        await page.goto(f"{server}/investigations/{inv}/report?assessment=1")
        await page.get_by_role("tab", selected=True).wait_for()
        assert page.url == f"{server}/app/investigations/{inv}?tab=report"
        assert await page.get_by_role("tab", selected=True).inner_text() == "Report"
        # a rule's link inside the app opens the app's Inbox, not a classic page
        await page.goto(f"{server}/app/rules")
        await page.get_by_role("table", name="Rules").get_by_role("link").first.click()
        await page.wait_for_url(re.compile(r".*/app/inbox\?.*rule=.*"))
        # the fallback: chosen from the menu, read-only, left by opening the app
        await page.goto(f"{server}/app/rules")
        await page.get_by_role("link", name="Classic pages (read-only)").click()
        await page.wait_for_url(f"{server}/")
        await page.get_by_text("Classic pages, read-only.").wait_for()
        await page.goto(f"{server}/investigations/{inv}")
        await page.get_by_text("Classic pages, read-only.").wait_for()
        assert await page.locator("form[action$='/review']").is_hidden()
        assert (
            await page.locator("form[action$='/accept']").count() == 0
            or await page.locator("form[action$='/accept']").first.is_hidden()
        )
        refused = await page.request.post(  # the page's own session, no console noise
            f"{server}/investigations/{inv}/review",
            form={"x": "1"},
            headers={"Origin": server},
        )
        assert refused.status == 403
        assert "read-only" in await refused.text()
        await page.get_by_role("link", name="/app", exact=True).click()
        await page.wait_for_url(re.compile(r".*/app/?$"))
        await page.goto(f"{server}/health")
        assert page.url == f"{server}/app/health"
        assert await watch.violations(page) == []
        await browser.close()
    assert watch.errors == []


async def test_a_link_from_another_site_opens_the_investigation_in_the_app(
    switched: tuple[str, dict[str, Any]],
) -> None:
    """``test_v1_external``'s bounce, with the switch on: the SameSite=Strict cookie is not sent on
    the first navigation from another site, the bounce page opens the target again from this
    site, and the target is the app's page."""
    from playwright.async_api import Route, async_playwright

    server, records = switched
    inv = records["agent"]["investigation_id"]
    other_site = "http://kibana.test"

    async def kibana(route: Route) -> None:
        html = f'<a id="deep" href="{server}/go/investigation/{inv}">case</a>'
        await route.fulfill(body=html, content_type="text/html")

    async with async_playwright() as play:
        browser = await play.chromium.launch()
        context = await browser.new_context()
        page = await context.new_page()
        page.set_default_timeout(60_000)
        await sign_in(page, server, "/app")
        await context.route(f"{other_site}/**", kibana)
        await page.goto(f"{other_site}/case")
        await page.click("#deep")
        await page.wait_for_url(f"{server}/app/investigations/{inv}")
        await page.get_by_role("heading", name="Your review").wait_for()
        await browser.close()


@pytest.mark.parametrize("name", BROWSERS)
async def test_a_pattern_is_reviewed_together_from_its_exact_request_and_a_changed_one_is_left(
    switched: tuple[str, dict[str, Any]], seeded: AsyncEngine, name: str
) -> None:
    """The counterpart of ``test_r15``'s pattern test, in a browser."""
    from playwright.async_api import async_playwright

    server, _ = switched
    watch = Watch()
    async with async_playwright() as play:
        browser, context = await open_context(play, name, viewport={"width": 1440, "height": 900})
        page = await context.new_page()
        page.set_default_timeout(60_000)
        watch.attach(page)
        await sign_in(page, server, "/app")
        await page.goto(f"{server}/app/patterns")
        assert await heading_of(page) == "Patterns"
        await page.wait_for_load_state("networkidle")
        groups = page.get_by_role("region", name=re.compile("^Pattern:"))
        assert await groups.count() >= 1, await page.locator("main").inner_text()
        group = groups.first
        button = group.get_by_role("button", name=re.compile("reviewed$"))
        assert await button.is_disabled()  # no outcome chosen yet
        await group.get_by_label("Outcome").select_option("benign_expected")
        heading = await group.get_by_role("heading").inner_text()
        shown_count = int(re.search(r"(\d+) investigation", heading)[1])  # type: ignore[index]
        await button.click()
        dialog = page.get_by_role("alertdialog")
        await dialog.wait_for()
        body = await dialog.get_by_test_id("payload").inner_text()
        assert '"outcome": "benign_expected"' in body
        assert body.count('"investigation_id"') == min(shown_count, 200)
        assert "/api/v1/patterns/review" in await dialog.inner_text()
        ids = re.findall(r'"investigation_id": "([0-9a-f-]{36})"', body)
        async with seeded.begin() as conn:  # one of them changes while the dialog is open
            await conn.execute(text("UPDATE investigations SET version = version + 1"
                                    " WHERE id = :i"), {"i": ids[0]})  # fmt: skip
        await dialog.get_by_role("button", name=re.compile("^Mark \\d+ reviewed$")).click()
        await page.get_by_text(
            re.compile(r"^\d+ reviewed\.( \d+ changed since you looked)?")
        ).first.wait_for()
        say = await page.get_by_text(re.compile(r"^\d+ reviewed\.")).first.inner_text()
        assert (
            f"{len(ids) - 1} reviewed. 1 changed since you looked and were left as they are." == say
        )
        async with seeded.connect() as conn:
            reviewed = (await conn.execute(text(
                "SELECT count(*), min(outcome) FROM review_events WHERE note = :n"
                " AND investigation_id = ANY(CAST(:ids AS uuid[]))"),
                {"n": "Reviewed with its pattern.", "ids": ids})).one()  # fmt: skip
        assert tuple(reviewed) == (len(ids) - 1, "benign_expected")
        assert await watch.violations(page) == []
        await browser.close()
    assert watch.errors == []
