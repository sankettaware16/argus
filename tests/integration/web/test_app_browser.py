"""Q-B1's browser gate (plan §5 Q-B1, §7.5) on the real server (``argus web`` as a process,
throwaway database), in Chromium and Firefox:

- the CSP tripwire: 0 violations of the policy or of Trusted Types while every part of /app is
  used (the shell, the design page, the confirm dialog, messages, tabs, the menu at phone width);
- hostile fixtures inert: no script runs, nothing becomes markup, a link or a style, and hidden
  characters and look-alike domains are shown (the design page's fixtures, and a hostile name in
  the shell);
- axe with the WCAG 2.2 rules: 0 serious or critical, light and dark, 390 and 1440 px;
- the stale-build check: one reload, never a loop (a changed build id, and a deleted chunk).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web import spa
from tests.integration.web.conftest import PASSWORD
from tests.integration.web.test_external import BIN, HOSTILE, ROOT, free_port, server, started

pytestmark = pytest.mark.integration
BROWSERS = ["chromium", "firefox"]
WCAG = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22a", "wcag22aa"]
# records every policy violation before any of the page's scripts run
TRIPWIRE = """
window.__violations = [];
document.addEventListener('securitypolicyviolation', (e) => {
  const where = `${e.sourceFile}:${e.lineNumber}`;
  window.__violations.push(`${e.violatedDirective} ${e.blockedURI} ${where}`);
});
"""
__all__ = ["server"]  # the fixture, imported for the tests below


def _aborted_font(text: str) -> bool:
    """Firefox says a font load the page itself cut short (NS_BINDING_ABORTED: the test moved on
    first) as a console error; a font that failed for any other reason still counts."""
    return "downloadable font: download failed" in text and "status=2152398850" in text


class Watch:
    """What went wrong in a page: policy violations, page errors, console errors."""

    def __init__(self) -> None:
        self.errors: list[str] = []

    def attach(self, page: Any) -> None:
        page.on("pageerror", lambda e: self.errors.append(f"page error: {e}"))
        page.on("console", self._console)

    def _console(self, m: Any) -> None:
        if m.type != "error" or _aborted_font(m.text):
            return
        where = str((m.location or {}).get("url", ""))
        # GET /api/v1/today answers 404 until the engine's presenter is served: the app's signal to
        # show Home (docs/p4f-ui-spec.md §2.4), not a failure
        if "404" in m.text and where.endswith("/api/v1/today"):
            return
        self.errors.append(f"console {m.type}: {m.text} ({where})")

    async def violations(self, page: Any) -> list[str]:
        found: list[str] = await page.evaluate("window.__violations || []")
        return found


async def sign_in(page: Any, base: str, next_path: str = "/app") -> None:
    await page.goto(f"{base}/signin?next={next_path}")
    await page.fill("#username", "asha")
    await page.fill("#password", PASSWORD)
    async with page.expect_navigation(url=re.compile(re.escape(base + next_path) + r"/?$")):
        await page.click("button[type=submit]")


async def open_context(play: Any, name: str, **options: Any) -> tuple[Any, Any]:
    browser = await getattr(play, name).launch()
    context = await browser.new_context(**options)
    await context.add_init_script(TRIPWIRE)
    return browser, context


@pytest.mark.parametrize("name", BROWSERS)
async def test_the_tripwire_stays_silent_and_hostile_values_stay_inert(
    server: str,
    seeded: AsyncEngine,
    name: str,
) -> None:
    from playwright.async_api import async_playwright

    async with seeded.begin() as conn:  # the shell shows the person's name: make it hostile
        await conn.execute(text("UPDATE users SET display_name = :n WHERE username = 'asha'"),
                           {"n": "Asha \u202eevil\u202c" + HOSTILE[:40]})  # fmt: skip
    watch = Watch()
    async with async_playwright() as play:
        browser, context = await open_context(play, name, viewport={"width": 1440, "height": 900})
        page = await context.new_page()
        page.set_default_timeout(60_000)
        watch.attach(page)
        await sign_in(page, server)
        await page.get_by_role("heading", name="Home").wait_for()
        totals = page.get_by_test_id("totals")  # Home's counts (it has no tiles, P4-F U20)
        await totals.locator("strong").first.filter(has_text=re.compile(r"^\d")).wait_for()
        assert await page.locator("header .ut-mark").count() >= 1  # the name's RLO, shown
        assert await page.locator("header img, header script, header a.ut").count() == 0
        # an in-app navigation (the side nav's Reports), then the design page (More's entry is an
        # admin's): its hostile fixtures
        nav = page.get_by_role("navigation", name="Main")
        await nav.get_by_role("link", name="Reports").click()
        await page.get_by_role("heading", name="Reports", exact=True).wait_for()
        assert page.url == f"{server}/app/reports"
        await page.goto(f"{server}/app/design")
        await page.get_by_role("heading", name="Design system").wait_for()
        # hostile fixtures: nothing ran, nothing became markup, a link or a style
        assert await page.evaluate("window.__pwned") is None
        region = page.get_by_test_id("hostile")
        assert await region.locator("a, img, svg, script, style, iframe, link, b").count() == 0
        attributes = await region.evaluate("""r => [...r.querySelectorAll('*')].flatMap(
            e => e.getAttributeNames().filter(a => a === 'style' || a.startsWith('on')))""")
        assert attributes == []
        shown = await region.inner_text()
        assert "<script>" in shown
        assert "\u202e" not in shown
        assert "xn--pple-43d.com" in shown
        assert "example.com" in shown
        assert await region.locator(".ut-mark", has_text="RLO").count() >= 1
        assert await region.locator(".ut-mark", has_text="TAG i").count() >= 1
        await region.get_by_role("button", name="Show all").first.click()
        # the confirm dialog: the exact request, markers included; Cancel has the focus
        await page.get_by_role("button", name="Review this example").click()
        dialog = page.get_by_role("alertdialog")
        await dialog.wait_for()
        # Base UI moves the focus in the next frame: wait for it (under load it takes a moment)
        await page.wait_for_function("() => document.activeElement?.textContent === 'Cancel'")
        assert await dialog.locator(".ut-mark", has_text="RLO").count() == 1
        assert await dialog.locator(".ut-mark", has_text="PDF").count() == 1
        await dialog.get_by_role("button", name="Send the review").click()
        await dialog.wait_for(state="hidden")
        await page.get_by_text("Nothing was sent: this was an example.").first.wait_for()
        await page.get_by_role("button", name="A failure").click()
        alert = page.get_by_test_id("live-assertive")
        assert "could not be saved" in await alert.inner_text()
        await page.get_by_role("tab", name="evidence").click()
        await page.get_by_text("Evidence, each fact with where it came from.").wait_for()
        await page.keyboard.press("ArrowRight")
        await page.goto(f"{server}/app/no/such/page")  # the app's own "not found", in the shell
        await page.get_by_role("heading", name="Page not found").wait_for()
        assert await page.get_by_role("navigation", name="Main").count() == 1
        assert await page.title() == "Not found \u00b7 ARGUS"
        await page.set_viewport_size({"width": 390, "height": 844})
        # a phone: the four pages are the bottom tab bar (Today is Home until Today is served)
        await page.get_by_test_id("bottom-bar").get_by_role("link", name="Today").click()
        await page.get_by_role("heading", name="Home").wait_for()
        assert await page.title() == "Today \u00b7 ARGUS"
        await page.wait_for_function("() => document.activeElement?.id === 'main'")  # focus moved
        assert await page.evaluate("window.__pwned") is None
        violations = await watch.violations(page)
        await browser.close()
    assert violations == []
    assert watch.errors == []


# where a text is drawn: the left edge of the first text node under root that holds it
POSITIONS = """([root, needles]) => needles.map((needle) => {
  const walk = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  for (let n = walk.nextNode(); n; n = walk.nextNode()) {
    const i = n.textContent.indexOf(needle);
    if (i < 0) continue;
    const range = document.createRange();
    range.setStart(n, i);
    range.setEnd(n, i + needle.length);
    return range.getBoundingClientRect().left;
  }
  return null;
})"""


@pytest.mark.parametrize("name", BROWSERS)
async def test_right_to_left_letters_keep_addresses_in_order_and_nothing_hides(
    server: str,
    seeded: AsyncEngine,
    name: str,
) -> None:
    """Review F4 and F3 in real browsers: right-to-left letters (no control character) between
    two addresses do not swap them; characters drawn as nothing are markers."""
    from playwright.async_api import async_playwright

    hidden = (0x2065, 0xFFF0, 0x1BCA0, 0x1D173, 0xE0080, 0xE01F0)
    value = "from \u05d0 10.0.0.1 \u05d0 192.168.1.1 " + "".join(chr(c) for c in hidden)
    async with seeded.begin() as conn:
        await conn.execute(text("UPDATE users SET display_name = :n WHERE username = 'asha'"),
                           {"n": value})  # fmt: skip
    watch = Watch()
    async with async_playwright() as play:
        browser, context = await open_context(play, name, viewport={"width": 1440, "height": 900})
        page = await context.new_page()
        page.set_default_timeout(60_000)
        watch.attach(page)
        await sign_in(page, server)
        await page.get_by_role("heading", name="Home").wait_for()
        name_box = page.locator("header [data-untrusted]").first
        await name_box.wait_for()
        assert await name_box.locator(".ut-mark").count() == len(hidden)
        assert await name_box.locator("bdi[dir=rtl]").count() == 2
        first, second = await page.evaluate(POSITIONS, [await name_box.element_handle(),
                                                        ["10.0.0.1", "192.168.1.1"]])  # fmt: skip
        assert first is not None
        assert second is not None
        assert first < second, (first, second)
        await page.goto(f"{server}/app/design")
        await page.get_by_role("heading", name="Design system").wait_for()
        region = page.get_by_test_id("hostile")
        first, second = await page.evaluate(POSITIONS, [await region.element_handle(),
                                                        ["10.0.0.1", "192.168.1.1"]])  # fmt: skip
        assert first is not None
        assert second is not None
        assert first < second, (first, second)
        assert await region.locator(".ut-mark", has_text="U+E0080").count() == 1
        violations = await watch.violations(page)
        await browser.close()
    assert violations == []
    assert watch.errors == []


@pytest.mark.parametrize("name", BROWSERS)
async def test_axe_finds_nothing_serious_in_light_dark_narrow_and_wide(
    server: str,
    name: str,
) -> None:
    from axe_playwright_python.async_playwright import Axe
    from playwright.async_api import async_playwright

    axe = Axe()
    problems: list[Any] = []
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
                await sign_in(page, server, "/app/design")
                await page.get_by_role("heading", name="Design system").wait_for()
                for where in ("/app", "/app/design", "dialog"):
                    if where == "dialog":
                        await page.get_by_role("button", name="Review this example").click()
                        await page.get_by_role("alertdialog").wait_for()
                    else:
                        await page.goto(server + where)
                        await page.locator("main h1").wait_for()
                        await page.wait_for_load_state("networkidle")
                    report = await axe.run(
                        page, options={"runOnly": {"type": "tag", "values": WCAG}}
                    )
                    ran = {r["id"] for kind in ("passes", "incomplete", "violations")
                           for r in report.response.get(kind, [])}  # fmt: skip
                    assert {"color-contrast", "target-size", "label"} & ran, ran  # axe ran
                    assert len(ran) >= 15, ran
                    for v in report.response["violations"]:
                        if v["impact"] in ("serious", "critical"):
                            targets = [n["target"] for n in v["nodes"]][:5]
                            problems.append((scheme, width, where, v["id"], targets))
                violations = await watch.violations(page)
                assert violations == [], (scheme, width, violations)
                await browser.close()
    assert problems == []
    assert watch.errors == []


# --------------------------------------------------------------------------- the stale build


@pytest.fixture
def build_copy(tmp_path: Path) -> Path:
    other = tmp_path / "spa"
    shutil.copytree(spa.BUILD_DIR, other)
    return other


@pytest.fixture
async def stale_server(
    seeded: AsyncEngine, test_database: str, build_copy: Path
) -> AsyncIterator[str]:
    port = free_port()
    env = {k: v for k, v in os.environ.items() if not k.startswith("ARGUS_")}
    env.update(ARGUS_DATABASE__NAME=test_database, ARGUS_WEB__PORT=str(port),
               ARGUS_WEB__SPA_DIR=str(build_copy))  # fmt: skip
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


def set_build_id(folder: Path, build: str) -> None:
    index = folder / "index.html"
    index.write_text(re.sub(r'(name="argus-build" content=")[0-9a-f]{16}', rf"\g<1>{build}",
                            index.read_text()))  # fmt: skip


@pytest.mark.parametrize("name", BROWSERS)
async def test_a_stale_page_reloads_once_never_in_a_loop(
    stale_server: str, build_copy: Path, name: str
) -> None:
    from playwright.async_api import async_playwright

    watch = Watch()
    async with async_playwright() as play:
        browser, context = await open_context(play, name)
        page = await context.new_page()
        page.set_default_timeout(60_000)
        watch.attach(page)
        loads: list[str] = []
        page.on("load", lambda: loads.append(page.url))
        await sign_in(page, stale_server)
        await page.get_by_role("heading", name="Home").wait_for()
        loads.clear()
        # a deploy: the server now serves another build (the page in the browser is older)
        set_build_id(build_copy, "0123456789abcdef")
        await page.get_by_role("link", name="Overview").count()  # still the same page
        await page.reload()  # the page itself is the old code with the new page's id ...
        await page.get_by_role("heading", name="Home").wait_for()
        loads.clear()
        # ... and the server's answers say another id: the next navigation reloads, once
        nav = page.get_by_role("navigation", name="Main")
        await nav.get_by_role("link", name="Reports").click()
        await page.get_by_role("heading", name="Reports", exact=True).wait_for()
        await page.wait_for_load_state("networkidle")
        assert loads == [f"{stale_server}/app/reports"]
        # still stale after that one reload (the code cannot match the id): no loop
        await nav.get_by_role("link", name="Today").click()
        await page.get_by_role("heading", name="Home").wait_for()
        await page.wait_for_timeout(1_500)
        assert loads == [f"{stale_server}/app/reports"]
        await page.get_by_text("ARGUS was updated on the server").wait_for()
        violations = await watch.violations(page)
        await browser.close()
    assert violations == []
    assert [e for e in watch.errors if "404" not in e] == []


@pytest.mark.parametrize("name", BROWSERS)
async def test_a_missing_chunk_reloads_once_then_says_so(
    stale_server: str, build_copy: Path, name: str
) -> None:
    from playwright.async_api import async_playwright

    async with async_playwright() as play:
        browser, context = await open_context(play, name)
        page = await context.new_page()
        page.set_default_timeout(60_000)
        loads: list[str] = []
        page.on("load", lambda: loads.append(page.url))
        await sign_in(page, stale_server)
        await page.get_by_role("heading", name="Home").wait_for()
        loads.clear()
        for chunk in (build_copy / "assets").glob("Reports-*.js"):  # a deploy removed it
            chunk.unlink()
        nav = page.get_by_role("navigation", name="Main")
        await nav.get_by_role("link", name="Reports").click()
        await page.get_by_role("heading", name="This page could not be shown").wait_for()
        await page.wait_for_timeout(1_500)
        assert len(loads) == 1  # one reload, then the message: never a loop
        assert await page.get_by_role("button", name="Reload").count() >= 1
        missing = await page.request.get(f"{stale_server}/app/assets/Reports-gone.js")
        assert missing.status == 404
        await browser.close()


def test_both_browsers_are_installed() -> None:
    """Chromium and Firefox are both downloaded (Q-B1: `uv run playwright install firefox`)."""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as play:
        for name in BROWSERS:
            path = Path(getattr(play, name).executable_path)
            assert path.is_file(), f"{name} is not installed: uv run playwright install {name}"
