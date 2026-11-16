"""P4-H track H5's browser check on the real server (``argus web`` as a process, a throwaway
database): the administration screens as an administrator uses them (D-327).

- Settings: a change to the history window is saved and shows as waiting (argus-admin is not
  running in the suite, and the page says so); the row is in ``admin_changes`` with the validated
  value and nothing else was sent.
- Users and roles: after confirming the password, a person is added and the one-time link is
  shown once; the person exists with the chosen role.
- axe with the WCAG 2.2 rules on Settings, Users and roles and the first-time setup, light and
  dark, 390 and 1440 px: 0 serious or critical; no sideways scroll at 390 px.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web import auth
from argus.web.capabilities import Capability
from tests.integration.web.b2_support import BROWSERS, Watch, open_context
from tests.integration.web.b3_support import Live, make_world, start_server
from tests.integration.web.conftest import PASSWORD
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
    async with world.runtime.begin() as conn:
        await auth.add_user(conn, "ada", "Ada Admin", PASSWORD, capabilities=list(Capability))
    login = await make_api_login()
    async for server in start_server(world, test_database, login, tmp_path):
        yield server


@pytest.mark.parametrize("name", BROWSERS)
async def test_a_setting_is_changed_and_a_person_added_from_the_app(live: Live, name: str) -> None:
    from playwright.async_api import async_playwright

    async with async_playwright() as play:
        browser, _, page, watch = await person(play, name, live.url, "ada", "/app")
        await page.goto(f"{live.url}/app/settings")
        await page.get_by_role("heading", level=1, name="Settings").wait_for()
        banner = await page.get_by_test_id("applier-down").inner_text()
        assert "argus-admin is not running" in banner
        await page.get_by_label("Search the settings").fill("history.window")
        field = page.get_by_test_id("setting-history.window")
        await field.wait_for()
        box = field.locator("input").first
        await box.fill("36h")
        await page.get_by_role("button", name="Save 1 change").click()
        outcome = page.get_by_test_id("outcome")
        await outcome.get_by_text("Waiting for argus-admin to apply it.").wait_for()
        async with live.world.runtime.connect() as conn:
            rows = (
                await conn.execute(text("SELECT key, value, risk, reset FROM admin_changes"))
            ).all()
        assert [(r.key, r.value, r.risk, r.reset) for r in rows] == [
            ("history.window", "36h", "normal", False)
        ]

        # the people: a new person needs the password confirmed again
        await page.goto(f"{live.url}/stepup?next=/app/users")
        await page.fill("#password", PASSWORD)
        async with page.expect_navigation(url=f"{live.url}/app/users"):
            await page.click("button[type=submit]")
        await page.get_by_role("heading", level=1, name="Users and roles").wait_for()
        await page.get_by_role("button", name="Add a person").click()
        dialog = page.get_by_role("dialog")
        await dialog.get_by_label(re.compile("^Name")).fill("Sam Roy")
        await dialog.get_by_label(re.compile("^Sign-in name")).fill("sam")
        await dialog.get_by_label("Role").select_option("lead")
        await dialog.get_by_role("button", name="Add the person").click()
        shown = dialog.get_by_test_id("link-shown")
        await shown.wait_for()
        assert "works once, for 72 hours" in await shown.inner_text()
        link = await shown.locator("input").input_value()
        assert link.startswith(live.url)
        assert "/welcome" in link
        await shown.get_by_role("button", name="I have given it").click()
        await page.get_by_role("row", name=re.compile("Sam Roy")).wait_for()
        assert "/welcome" not in await page.locator("main").inner_text()
        async with live.world.runtime.connect() as conn:
            made = (
                await conn.execute(text("SELECT display_name FROM users WHERE username = 'sam'"))
            ).scalar_one()
        assert made == "Sam Roy"
        assert await watch.violations(page) == []
        await browser.close()
    assert watch.errors == []


async def test_axe_finds_nothing_serious_on_the_administration_screens(live: Live) -> None:
    from axe_playwright_python.async_playwright import Axe
    from playwright.async_api import async_playwright

    pages = [("settings", "/app/settings"), ("users", "/app/users"), ("setup", "/app/setup")]
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
                await sign_in_as(page, live.url, "ada")
                for label, where in pages:
                    await page.goto(live.url + where)
                    await page.locator("main h1").wait_for()
                    await page.wait_for_load_state("networkidle")
                    await page.evaluate(
                        "() => document.querySelectorAll('details')"
                        ".forEach((d) => { d.open = true; })"
                    )
                    report = await axe.run(
                        page, options={"runOnly": {"type": "tag", "values": WCAG}}
                    )
                    problems += [
                        (scheme, width, label, v["id"], v["impact"], v["help"])
                        for v in report.response["violations"]
                        if v["impact"] in ("serious", "critical")
                    ]
                    if width <= 390:
                        wide = await page.evaluate(
                            "document.documentElement.scrollWidth"
                            " - document.documentElement.clientWidth"
                        )
                        assert wide <= 0, (label, wide)
                assert await watch.violations(page) == [], (scheme, width)
                await browser.close()
    assert not problems, "\n".join(map(str, problems))
    assert watch.errors == []
