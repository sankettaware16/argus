"""P4-F Track 2's browser check on the real server (``argus web`` as a process on the web's own
database login, a throwaway database): the decisions a person makes in the UI v2, as they make them
(docs/p4f-ui-spec.md §5.4, §5.5, §7.1, §8).

- A possible incident's page: the sticky decision bar says ARGUS's call in words; Confirm incident…
  opens the dialog with the plain words first and the exact request one click away, and the case
  is an incident; another is closed from the "Not an incident" menu's one-line sheet as "a scan or
  attempt", the consequence read before anything is sent; no page names the command line.
- An alert group is decided with the five outcomes: Real but harmless is chosen with the key 2
  and saved as a review; Can't tell yet keeps it for a follow-up; Real asks first.
- axe with the WCAG 2.2 rules on Today (Home while the engine's Today is not served), Incidents,
  an incident's tabs with the dismiss menu open, the alert group's page, Search, Reports and an
  entity page, light and dark, 390 and 1440 px: 0 serious or critical; no sideways scroll at 390
  px; no CSP or Trusted Types violation on the way.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.model import Indicator
from tests.integration.web.b2_support import BROWSERS, Watch, open_context
from tests.integration.web.b3_support import Live, make_world, start_server
from tests.integration.web.test_app_b3_browser import WCAG, person, sign_in_as

pytestmark = pytest.mark.integration
__all__ = ["live"]


@pytest.fixture
async def live(
    seeded: AsyncEngine,
    web_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    test_database: str,
    make_api_login: Any,
    tmp_path: Path,
) -> AsyncIterator[Live]:
    world = await make_world(seeded, web_engine, migrated_engine, tmp_path)
    login = await make_api_login()
    async for server in start_server(world, test_database, login, tmp_path):
        yield server


@pytest.mark.parametrize("name", BROWSERS)
async def test_a_possible_incident_is_confirmed_and_another_dismissed_in_the_app(
    live: Live, name: str
) -> None:
    from playwright.async_api import async_playwright

    world = live.world
    first = await world.open_suspected(4, "Possible beacon from the lab")
    second = await world.open_suspected(5, "Possible scan of the web server")
    async with async_playwright() as play:
        browser, _, page, watch = await person(play, name, live.url, "mina", "/app")
        await page.goto(f"{live.url}/app/incidents/{first}")
        await page.get_by_role("heading", level=1, name=re.compile("Possible beacon")).wait_for()
        bar = page.get_by_test_id("decision-bar")
        call = await bar.get_by_test_id("bar-call").inner_text()
        assert re.search(r"\(\d+\)", call) is None  # never the 0-100 number (I-2)
        main = await page.locator("main").inner_text()
        assert "argus case" not in main
        assert "case command" not in main
        assert "Owner:" not in main
        await bar.get_by_role("button", name="Confirm incident…").click()
        dialog = page.get_by_role("alertdialog")
        await dialog.wait_for()
        what = await dialog.get_by_test_id("what-happens").inner_text()
        assert "ARGUS sends nothing there" in what  # posting is off in the suite
        assert not await dialog.get_by_test_id("payload").is_visible()  # plain words first
        await dialog.get_by_text("Show the exact request").click()
        assert json.loads(await dialog.get_by_test_id("payload").inner_text()) == {
            "expected_version": 1
        }
        await dialog.get_by_role("button", name=re.compile("^Confirm (incident|anyway)$")).click()
        await page.get_by_text("Incident #1 is confirmed.").first.wait_for()
        await page.locator("[data-testid=decision-bar][data-state=open]").wait_for()
        # the second: not an incident, a scan or attempt, from the menu's one-line sheet
        await page.goto(f"{live.url}/app/incidents/{second}")
        bar = page.get_by_test_id("decision-bar")
        await bar.get_by_role("button", name="Not an incident ▾").click()
        menu = page.get_by_role("menu", name="Why is it not an incident?")
        await menu.locator("[data-reason=attempt_no_impact]").click()
        sheet = page.get_by_test_id("dismiss-sheet")
        assert "two weeks" in await sheet.get_by_test_id("dismiss-consequence").inner_text()
        await sheet.get_by_role("textbox", name=re.compile("Note")).fill("every answer 404")
        await sheet.get_by_role("button", name="Close it").click()
        await page.get_by_text(re.compile("Incident #2 closed")).first.wait_for()
        assert await watch.violations(page) == []
        assert watch.errors == []
        await browser.close()
    rows = await world.rows(
        "SELECT id, state, closure_reason FROM cases WHERE id = ANY(:ids)", ids=[first, second]
    )
    got = {r.id: (r.state, r.closure_reason) for r in rows}
    assert got == {first: ("open", None), second: ("closed", "attempt_no_impact")}


@pytest.mark.parametrize("name", BROWSERS)
async def test_an_alert_group_is_decided_with_the_five_outcomes(live: Live, name: str) -> None:
    from playwright.async_api import async_playwright

    world = live.world
    one, two = world.investigations[8], world.investigations[9]
    async with async_playwright() as play:
        browser, _, page, watch = await person(play, name, live.url, "rita", "/app")
        await page.goto(f"{live.url}/app/alert-groups/{one}")
        form = page.get_by_role("form", name="Your decision")
        await form.wait_for()
        names = [await r.get_attribute("value") for r in await form.get_by_role("radio").all()]
        assert names == ["true_positive", "benign_expected", "benign_policy",
                         "rule_false_positive", "inconclusive"]  # fmt: skip
        await page.evaluate("() => document.activeElement && document.activeElement.blur()")
        await page.keyboard.press("2")
        assert await form.get_by_role("radio", name=re.compile("Real but harmless")).is_checked()
        await form.get_by_role("button", name="Save decision").click()
        await page.get_by_text("Saved: your decision.").first.wait_for()
        await page.goto(f"{live.url}/app/alert-groups/{two}")
        form = page.get_by_role("form", name="Your decision")
        await form.get_by_role("radio", name=re.compile("Can't tell yet")).check(force=True)
        follow = form.get_by_role("checkbox", name=re.compile("Come back to it"))
        assert await follow.is_checked()
        await form.get_by_role("button", name="Save, and come back to it").click()
        await page.get_by_text("Saved: kept for a follow-up.").first.wait_for()
        assert await watch.violations(page) == []
        assert watch.errors == []
        await browser.close()
    rows = await world.rows(
        "SELECT investigation_id, action, outcome FROM review_events"
        " WHERE investigation_id = ANY(:ids) ORDER BY id",
        ids=[one, two],
    )
    assert [(r.investigation_id, r.action, r.outcome) for r in rows] == [
        (one, "reviewed", "benign_expected"),
        (two, "follow_up", "inconclusive"),
    ]


async def test_axe_finds_nothing_serious_on_the_v2_pages_light_dark_narrow_and_wide(
    live: Live,
) -> None:
    from axe_playwright_python.async_playwright import Axe
    from playwright.async_api import async_playwright

    world = live.world
    case = await world.open_suspected(4, "Possible beacon from the lab")
    await world.open_case(1, start=6, indicators=(Indicator("ip", "10.0.0.1", "actor"),))
    pages = [("incident", f"/app/incidents/{case}"),
             ("story", f"/app/incidents/{case}?tab=story"),
             ("activity", f"/app/incidents/{case}?tab=activity"),
             ("alert group", f"/app/alert-groups/{world.investigations[8]}"),
             ("today", "/app"), ("incidents", "/app/incidents"),
             ("search", "/app/search?q=10.0.0.1"), ("reports", "/app/reports"),
             ("entity", "/app/entities/device/10.0.0.1")]  # fmt: skip
    axe = Axe()
    problems: list[Any] = []
    watch = Watch()
    async with async_playwright() as play:
        for scheme in ("light", "dark"):
            for width in (390, 1440):
                browser, context = await open_context(
                    play, "chromium", viewport={"width": width, "height": 900},
                    color_scheme=scheme,
                )  # fmt: skip
                page = await context.new_page()
                page.set_default_timeout(60_000)
                watch.attach(page)
                await sign_in_as(page, live.url, "mina")
                for label, where in pages:
                    await page.goto(live.url + where)
                    await page.locator("main").wait_for()
                    await page.wait_for_load_state("networkidle")
                    if label == "incident":
                        bar = page.get_by_test_id("decision-bar")
                        await bar.get_by_role("button", name="Not an incident ▾").click()
                        await page.get_by_role("menu").wait_for()
                    elif label == "alert group":
                        await page.get_by_role("form", name="Your decision").wait_for()
                    await page.evaluate(
                        "() => document.querySelectorAll('details')"
                        ".forEach((d) => { d.open = true; })"
                    )
                    report = await axe.run(
                        page, options={"runOnly": {"type": "tag", "values": WCAG}}
                    )
                    problems += [
                        (scheme, width, label, v["id"], [n["target"] for n in v["nodes"]][:4])
                        for v in report.response["violations"]
                        if v["impact"] in ("serious", "critical")
                    ]
                    if width <= 390:
                        wide = await page.evaluate(
                            "document.documentElement.scrollWidth"
                            " - document.documentElement.clientWidth"
                        )
                        culprits = await page.evaluate(
                            "() => [...document.querySelectorAll('body *')]"
                            ".filter((e) => e.getBoundingClientRect().right > innerWidth + 1)"
                            ".slice(0, 6).map((e) => e.tagName + '.' + e.className.toString()"
                            ".slice(0, 80) + ' ' + Math.round(e.getBoundingClientRect().right))"
                        )
                        assert wide <= 0, (label, wide, culprits)
                assert await watch.violations(page) == [], (scheme, width)
                await browser.close()
    assert not problems, "\n".join(map(str, problems))
    assert watch.errors == []
