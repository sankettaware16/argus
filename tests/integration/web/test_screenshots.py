"""The documentation's screenshots (D-329), from a demo installation, never from production:
``argus web`` as a process on a throwaway database seeded by ``demo_world`` (synthetic, neutral
data), each page captured at 1440 x 900 into ``docs/images/screenshots/``.

Opt-in: ``ARGUS_SCREENSHOTS=1 uv run pytest -q tests/integration/web/test_screenshots.py``.
"""

from __future__ import annotations

import os
import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import signing
from argus.web import queries
from tests.integration.grouping.test_grouping import ingest
from tests.integration.web import demo_world as demo
from tests.integration.web.b2_support import Watch, open_context
from tests.integration.web.b3_support import Live, World, start_server
from tests.integration.web.conftest import PASSWORD

# read once and taken out: the configuration refuses an ARGUS_ variable it does not know
ASKED = os.environ.pop("ARGUS_SCREENSHOTS", None) == "1"
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not ASKED,
                       reason="screenshots are made on request: ARGUS_SCREENSHOTS=1"),
]  # fmt: skip
ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "docs" / "images" / "screenshots"
VIEW = {"width": 1440, "height": 900}


@pytest.fixture
async def live(
    app_engine: AsyncEngine,
    web_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    test_database: str,
    make_api_login: Any,
    tmp_path: Path,
) -> AsyncIterator[Live]:
    from tests.conftest import suite_checkout

    now = datetime.now(UTC).replace(microsecond=0)
    await demo.add_people(app_engine)
    await ingest(app_engine, demo.demo_docs(now), now)
    async with app_engine.connect() as conn:
        found = await queries.inbox(conn, "all", limit=500, sort="oldest")
    key = signing.new_key()
    path = tmp_path / "approval.key"
    signing.write_key(path, key)
    world = World(app_engine, web_engine, [i.id for i in found], path, migrated_engine)
    await demo.plant_dossiers(app_engine, now)
    await demo.raise_flags(migrated_engine, now)
    print("engine:", await demo.run_engine(app_engine, now))
    await demo.work_the_cases(app_engine, now)
    await demo.health_state(migrated_engine, now)
    root = suite_checkout(tmp_path / "checkout")
    await demo.reports(app_engine, root, now)
    await demo.admin_state(migrated_engine, root, now)
    login = await make_api_login()
    async for server in start_server(world, test_database, login, tmp_path):
        yield server


MAX_BYTES = 400_000


def fit(path: Path) -> None:
    """The image as small as it goes without loss; one still over MAX_BYTES (a large gradient)
    with 256 colours, dithered."""
    from PIL import Image

    with Image.open(path) as im:
        im.load()
    im.save(path, "PNG", optimize=True)
    if path.stat().st_size > MAX_BYTES:
        im.convert("RGB").quantize(colors=256, dither=Image.Dither.FLOYDSTEINBERG).save(
            path, "PNG", optimize=True
        )


async def shoot(page: Any, name: str, *, full: bool = False) -> None:
    await page.wait_for_load_state("networkidle")
    await page.evaluate("() => document.activeElement && document.activeElement.blur()")
    await page.wait_for_timeout(500)
    await page.screenshot(path=str(OUT / f"{name}.png"), full_page=full)
    fit(OUT / f"{name}.png")


async def visit(page: Any, url: str, name: str, *, full: bool = False) -> None:
    await page.goto(url)
    await page.locator("main h1").first.wait_for()
    await shoot(page, name, full=full)


async def setup_chapters(page: Any, app: str) -> None:
    """The first-time setup as a new installation shows it (the demo is set up already, so its
    settings say the setup is still needed), its first chapter and the access chapter."""
    import json

    async def needed(route: Any) -> None:
        answer = await route.fetch()
        body = await answer.json()
        await route.fulfill(response=answer, body=json.dumps({**body, "setup_needed": True}))

    await page.route("**/api/v1/admin/settings", needed)
    await page.goto(f"{app}/setup")
    await page.get_by_role("button", name="Begin").wait_for()
    await shoot(page, "setup-start")
    await page.get_by_role("button", name="Begin").click()
    await page.get_by_label("Organisation name").fill("Example University")
    await page.get_by_label("Security team's name").fill("Example CSIRT")
    await page.get_by_label("What kind of organisation").fill("university")
    await page.get_by_label("Your own domains").fill("example.edu")
    await page.get_by_label("Your public networks").fill("198.51.100.0/24")
    await page.get_by_label("Time zone").fill("Asia/Kolkata")
    await page.get_by_label("Short label for it").fill("IST")
    await page.get_by_label("Incident id prefix").fill("CSIRT-IR")
    await page.wait_for_timeout(700)
    await shoot(page, "setup-organisation")
    await page.get_by_role("button", name="Continue").click()
    await page.get_by_label("The SIEM's address").fill("https://siem.example.org:9200")
    await page.get_by_role("radio", name=re.compile("My system already trusts it")).click()
    await page.get_by_role("button", name="Continue").click()
    await page.get_by_role("radio", name=re.compile("Let ARGUS create its own access")).click()
    await page.get_by_label("Administrator's user name").fill("elastic-admin")
    await page.wait_for_timeout(700)
    await shoot(page, "setup")
    await page.unroute("**/api/v1/admin/settings")


async def signed_in(play: Any, url: str, scheme: str, scale: int,
                    user: str = "asha") -> tuple[Any, Any, Watch]:  # fmt: skip
    browser, context = await open_context(play, "chromium", viewport=VIEW,
                                          device_scale_factor=scale, color_scheme=scheme,
                                          timezone_id="Asia/Kolkata")  # fmt: skip
    page = await context.new_page()
    page.set_default_timeout(60_000)
    watch = Watch()
    watch.attach(page)
    await page.goto(f"{url}/signin?next=/app")
    await page.fill("#username", user)
    if scheme == "light":
        await page.wait_for_load_state("networkidle")
        await page.screenshot(path=str(OUT / "signin.png"))
        fit(OUT / "signin.png")
    await page.fill("#password", PASSWORD)
    async with page.expect_navigation(url=re.compile(re.escape(url + "/app") + r"/?$")):
        await page.click("button[type=submit]")
    await page.locator("main h1").first.wait_for()
    return browser, page, watch


async def test_the_screenshots(live: Live) -> None:
    from playwright.async_api import async_playwright

    OUT.mkdir(parents=True, exist_ok=True)
    url = live.url
    scale = int(os.environ.get("SCREENSHOT_SCALE", "2"))
    waiting = await live.world.rows(
        "SELECT c.id FROM cases c JOIN risk_incidents r ON r.case_id = c.id"
        " WHERE c.state = 'suspected' ORDER BY r.band, r.priority DESC LIMIT 1"
    )
    group = await live.world.rows(
        "SELECT id FROM investigations WHERE rule_id = 'demo-c2-beacon'"
        " ORDER BY alert_count DESC, id LIMIT 1"
    )
    errors: list[str] = []
    async with async_playwright() as play:
        browser, page, watch = await signed_in(play, url, "light", scale)
        await shoot(page, "today")
        app = f"{url}/app"
        await visit(page, f"{app}/incidents?view=all", "incidents")
        await visit(page, f"{app}/incidents/{waiting[0].id}", "incident")
        await visit(page, f"{app}/alert-groups/{group[0].id}", "investigation")
        await visit(page, f"{app}/search?q=203.0.113.45", "search")
        await visit(page, f"{app}/reports", "reports")
        await visit(page, f"{app}/settings?section=siem", "settings")
        await visit(page, f"{app}/users", "users")
        await setup_chapters(page, app)
        await visit(page, f"{app}/ai", "ai-agents")
        await visit(page, f"{app}/threat-intel", "threat-intel")
        await visit(page, f"{app}/costs", "costs")
        await page.goto(f"{app}/health")
        services = page.get_by_test_id("services")
        await services.get_by_text("Checked").wait_for()
        await services.scroll_into_view_if_needed()
        await page.evaluate("() => window.scrollBy(0, -320)")
        await shoot(page, "system-health")
        errors += watch.errors
        await browser.close()
        # another person, on their first visit: what ARGUS handled meanwhile shows
        browser, page, watch = await signed_in(play, url, "dark", scale, "mina")
        await shoot(page, "today-dark")
        await visit(page, f"{app}/incidents?view=all", "incidents-dark")
        errors += watch.errors
        await browser.close()
    assert errors == []
