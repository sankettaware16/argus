"""P4-F Track 2's layout checks in a real browser on the real server (docs/p4f-ui-spec.md §16):
what fits in the first screen. ``GET /api/v1/today`` is not served before the engine's presenter
lands, and old cases carry no engine block, so the page's own requests for them are answered from
made-up fixtures (§16.1: documentation addresses, invented campus names) by the browser's route
interception; everything else is the server's.

- Today at 1440 x 900: the summary and the first card with its buttons in the first screen (T-1),
  2 to 10 cards in it (T-2); at 390 x 844 three card titles and "Urgent:" in it (T-14, T-15).
- An incident at 1440 x 900 and 390 x 844: the decision bar in the first screen, and still after
  scrolling to the end of the Overview (I-1); the Overview ends within 2 screens at 1440 x 900 and
  4 at 390 x 844 (I-3, I-4).
- No sideways page scroll at 320 x 640 on Today, Incidents, the incident's tabs, Search, Reports
  and an entity page (G-2).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.web.b2_support import open_context
from tests.integration.web.b3_support import Live, make_world, start_server
from tests.integration.web.test_app_b3_browser import sign_in_as

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


def engine(band: str, priority: int, title_words: str, *, n: int = 0) -> dict[str, Any]:
    return {
        "priority": priority,
        "band": band,
        "lane": "decisive",
        "certainty": "Likely",
        "why": [
            {"op": "+", "points": priority - 30, "text": "VirusTotal: 7 of 94 engines"},
            {"op": "+", "points": 20, "text": "Regular timing, like a beacon"},
            {"op": "+", "points": 10, "text": f"Five campus devices, {title_words}"},
        ],
        "checks": [
            {"state": "checked", "text": "Threat lists: on 1 list"},
            {"state": "ruled_out", "text": "Other campus servers talking to it: none in 5 days"},
            {"state": "unknown", "text": "Who used the devices: no sign-in data"},
            {"state": "unknown", "text": "What the POSTs carried: the proxy keeps no body"},
        ],
        "alternatives": [
            {"name": "A software update check", "state": "ruled_out", "test": "no vendor domain"},
            {"name": "A remote-management tool the lab installed", "state": "fits",
             "test": "ask the lab admin whether such a tool runs"},
        ],
        "objects": [
            {"kind": "device", "label": f"lab-pc-{17 + n}", "role": "affected"},
            {"kind": "device", "label": "lab-pc-21", "role": "affected"},
            {"kind": "device", "label": "203.0.113.40", "role": "actor"},
        ],
        "raised_by_ai": n == 0,
        "active": True,
        "first_seen": "2026-11-04T03:40:00Z",
        "last_seen": "2026-11-06T13:25:00Z",
        "version": 3,
        "changed": ["2 more campus devices"] if n == 0 else [],
    }  # fmt: skip


def today(ids: list[str]) -> dict[str, Any]:
    bands = ["P1", "P2", "P3", "P3", "P4", "P4"]
    cards = [
        {"kind": "incident", "id": i, "number": k + 1, "state": "suspected", "version": 1,
         "title": f"Likely beaconing from 5 campus devices to 203.0.113.{40 + k}",
         "engine": engine(bands[k % len(bands)], 82 - 8 * k, "same destination", n=k),
         "taken_by": None, "notified_at": None, "in_kibana": False, "kibana_wait": None,
         "waiting_since": "2026-11-04T04:00:00Z"}
        for k, i in enumerate(ids)
    ]  # fmt: skip
    return {
        "mode": "present",
        "needs_you": cards,
        "more_waiting": 3,
        "new_activity": [],
        "gray": [],
        "handled": {"since": "2026-11-04T10:40:00Z", "count": 1140, "audit": None,
                    "categories": [{"key": "noise", "label": "Known noise", "count": 1020}]},
    }  # fmt: skip


async def serve_fixtures(page: Any, ids: list[str]) -> None:
    async def today_route(route: Any) -> None:
        await route.fulfill(
            status=200, content_type="application/json", body=json.dumps(today(ids))
        )

    async def case_route(route: Any) -> None:
        response = await route.fetch()
        body = await response.json()
        if isinstance(body, dict) and "case" in body:
            body["engine"] = engine("P1", 82, "same destination")
        await route.fulfill(response=response, body=json.dumps(body))

    await page.route("**/api/v1/today*", today_route)
    for i in ids:
        await page.route(f"**/api/v1/cases/{i}", case_route)


async def inside(page: Any, locator: Any, height: int) -> bool:
    box = await locator.bounding_box()
    return box is not None and box["y"] >= 0 and box["y"] + box["height"] <= height


async def test_today_and_the_incident_fit_their_first_screens(live: Live) -> None:
    from playwright.async_api import async_playwright

    world = live.world
    ids = [str(await world.open_suspected(k, f"Possible beacon {k}")) for k in range(4, 10)]
    async with async_playwright() as play:
        for width, height in ((1440, 900), (390, 844)):
            browser, context = await open_context(
                play, "chromium", viewport={"width": width, "height": height}
            )
            page = await context.new_page()
            page.set_default_timeout(60_000)
            await serve_fixtures(page, ids)
            await sign_in_as(page, live.url, "mina")
            await page.get_by_test_id("today-summary").wait_for()
            cards = page.get_by_test_id("incident-card")
            await cards.first.wait_for()
            assert await inside(page, page.get_by_test_id("today-summary"), height)
            if width == 1440:
                assert await inside(page, cards.first, height), "T-1"
                assert await inside(
                    page, cards.first.get_by_role("button", name="Confirm incident…"), height
                )
                seen = 0
                for k in range(await cards.count()):
                    box = await cards.nth(k).bounding_box()
                    if box and box["y"] < height and box["y"] + box["height"] > 0:
                        seen += 1
                assert 2 <= seen <= 10, ("T-2", seen)
            else:
                titles = page.get_by_test_id("card-title")
                shown = [await inside(page, titles.nth(k), height) for k in range(3)]
                assert all(shown), ("T-14", shown)
                assert await inside(page, page.get_by_text("Urgent:", exact=False).first, height), (
                    "T-15"
                )
            # the incident: the bar in the first screen, and after scrolling to the Overview's end
            await page.goto(f"{live.url}/app/incidents/{ids[0]}")
            bar = page.get_by_test_id("decision-bar")
            await page.get_by_test_id("overview").wait_for()
            await page.get_by_test_id("why-points").wait_for()
            assert await inside(page, bar, height), ("I-1", width)
            last = page.locator("[data-testid=overview] [data-region]").last
            box = await last.bounding_box()
            scroll = await page.evaluate("window.scrollY")
            bottom = (box["y"] + box["height"] + scroll) if box else 0
            assert bottom <= (1800 if width == 1440 else 3376), ("I-3/I-4", width, bottom)
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            assert await inside(page, bar, height), ("I-1 after scrolling", width)
            await browser.close()


async def test_no_page_scrolls_sideways_at_320(live: Live) -> None:
    from playwright.async_api import async_playwright

    world = live.world
    ids = [str(await world.open_suspected(k, f"Possible beacon {k}")) for k in range(4, 7)]
    paths = ["/app", "/app/incidents", *(f"/app/incidents/{ids[0]}?tab={t}" for t in
             ("overview", "story", "evidence", "entities", "alert-groups", "report", "activity")),
             "/app/search?q=203.0.113.40", "/app/reports", "/app/entities/device/lab-pc-17",
             "/app/entities/outside/203.0.113.40"]  # fmt: skip
    wide: list[tuple[str, int]] = []
    async with async_playwright() as play:
        browser, context = await open_context(
            play, "chromium", viewport={"width": 320, "height": 640}
        )
        page = await context.new_page()
        page.set_default_timeout(60_000)
        await serve_fixtures(page, ids)
        await sign_in_as(page, live.url, "mina")
        for path in paths:
            await page.goto(live.url + path)
            await page.locator("main").wait_for()
            await page.wait_for_load_state("networkidle")
            over = await page.evaluate("document.documentElement.scrollWidth - 320")
            if over > 0:
                wide.append((path, over))
        await browser.close()
    assert wide == [], wide
