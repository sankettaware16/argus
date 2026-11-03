"""Q-B2's browser gate (plan §5 Q-B2, §7.5) on the real server (``argus web`` as a process,
throwaway database), in Chromium and Firefox:

- parity: the dashboard's and the Inbox's numbers in the app equal the classic pages' on the same
  records (the same queries behind both);
- the pages are used end to end without a CSP or Trusted Types violation, and hostile values stay
  inert;
- the Inbox by keyboard alone: the grid's ARIA attributes, the focus after each key, the help
  dialog, the off switch, one pane below 1024 px;
- review (with the 409 kept), Accept, Ask the AI investigator, the gold box and a group's
  confirmation, as a person does them, and what is said when a request fails;
- the list stays light with a thousand investigations (the window, not the list, is in the page);
- axe with the WCAG 2.2 rules: 0 serious or critical, light and dark, 390 and 1440 px.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.web.b2_support import (
    BROWSERS,
    SPAN,
    Watch,
    numbers,
    open_context,
    review_as,
    rich_server,
    server,
    sign_in,
)

pytestmark = pytest.mark.integration
PROBES = Path(__file__).parent / "probes"


def probe(name: str) -> str:
    """A function the page runs to read what it shows (tests/integration/web/probes/<name>.js)."""
    return (PROBES / f"{name}.js").read_text(encoding="utf-8").strip()


__all__ = ["rich_server", "server"]  # the fixtures, imported for the tests below

CLASSIC_DASHBOARD = probe("classic_dashboard")

APP_DASHBOARD = probe("app_dashboard")


def tame(cell: str) -> str:
    """The hostile record's name is written with its own markers on each page: only that it is
    the same row matters here (the browser suite below reads what each page shows of it)."""
    return "HOSTILE" if "<script>" in cell else cell


def digits(rows: list[list[str]], *, skip: int = 1) -> list[list[str]]:
    return [[*(tame(c) for c in r[:skip]), *(numbers(c) for c in r[skip:])] for r in rows]


@pytest.mark.parametrize("name", BROWSERS)
@pytest.mark.parametrize(
    "query",
    [
        SPAN,
        f"{SPAN}&severity=high",
        f"{SPAN}&state=unreviewed&state=follow_up",
        f"{SPAN}&verdict=none&ai=none",
        f"{SPAN}&rule=rule-1",
    ],
)
async def test_the_dashboard_has_the_classic_pages_numbers(
    rich_server: tuple[str, dict[str, Any]], name: str, query: str
) -> None:
    from playwright.async_api import async_playwright

    server, _ = rich_server
    async with async_playwright() as play:
        browser, context = await open_context(play, name, viewport={"width": 1440, "height": 900})
        page = await context.new_page()
        page.set_default_timeout(60_000)
        await sign_in(page, server, "/app")
        await page.goto(f"{server}/dashboard?{query}")
        classic = await page.evaluate(CLASSIC_DASHBOARD)
        await page.goto(f"{server}/app/dashboard?{query}")
        await page.locator("ul[aria-label='Key numbers']").wait_for()
        await page.wait_for_load_state("networkidle")
        app = await page.evaluate(APP_DASHBOARD)
        await browser.close()
    # the headline numbers, every one of the classic page's tiles
    assert set(app["kpis"]) == set(classic["kpis"]), (app["kpis"], classic["kpis"])
    for label, value in classic["kpis"].items():
        same = (
            numbers(app["kpis"][label]) == numbers(value)
            if re.search(r"\d", value)
            else app["kpis"][label] == value
        )
        assert same, (label, app["kpis"][label], value)
    assert classic["kpis"]["Investigations"] != "0", "the records are in the span"
    for part in (
        "states",
        "severities",
        "verdicts",
        "ai",
    ):  # equal counts may stand in either order
        for rows in (app[part], classic[part]):
            counts = [int(numbers(r[1])) for r in rows]
            assert counts == sorted(counts, reverse=True), part
        assert sorted(digits(app[part])) == sorted(digits(classic[part])), part
    assert digits(app["rules"], skip=2) == digits(classic["rules"], skip=2), "top rules"
    for kind in ("ip", "host", "domain", "user"):
        assert digits(app[kind]) == digits(classic[kind]), kind
    for part in ("incidents", "open"):
        mine = [[tame(r[0]), numbers(r[1]), r[2], r[3]] for r in app[part]]
        theirs = [[tame(r[0]), numbers(r[1]), r[2], r[3]] for r in classic[part]]
        assert mine == theirs, part


CLASSIC_INBOX = probe("classic_inbox")
APP_INBOX = probe("app_inbox")
STATE_WORDS = {
    "unreviewed": "Not reviewed",
    "follow up": "Follow-up",
    "changed since review": "Changed since review",
    "reviewed": "Reviewed",
}


@pytest.mark.parametrize("name", BROWSERS)
@pytest.mark.parametrize("view", ["attention", "open", "reviewed", "all"])
async def test_the_inbox_lists_the_classic_pages_investigations_in_its_order(
    rich_server: tuple[str, dict[str, Any]], name: str, view: str
) -> None:
    from playwright.async_api import async_playwright

    server, _ = rich_server
    async with async_playwright() as play:
        browser, context = await open_context(play, name, viewport={"width": 1440, "height": 4000})
        page = await context.new_page()
        page.set_default_timeout(60_000)
        await sign_in(page, server, "/app")
        await page.goto(
            f"{server}/?view={view}&sort={'reviewed' if view == 'reviewed' else 'newest'}"
        )
        classic = await page.evaluate(CLASSIC_INBOX)
        await page.goto(f"{server}/app/inbox?view={view}")
        await page.locator("[role=grid] [role=row]").nth(1).wait_for()
        await page.wait_for_load_state("networkidle")
        app = await page.evaluate(APP_INBOX)
        await browser.close()
    assert len(classic) >= 1
    assert len(app) == len(classic), (len(app), len(classic))
    for mine, theirs in zip(app, classic, strict=True):
        assert tame(mine["name"]) == tame(theirs["name"])
        assert numbers(mine["alerts"]) == numbers(theirs["alerts"])
        assert mine["severity"] == theirs["severity"]
        assert mine["state"] == STATE_WORDS[theirs["state"]]


async def sql_count(engine: AsyncEngine, query: str) -> int:
    async with engine.connect() as conn:
        return int((await conn.execute(text(query))).scalar_one())


@pytest.mark.parametrize("name", BROWSERS)
async def test_every_page_runs_without_a_policy_violation_and_hostile_values_stay_inert(
    rich_server: tuple[str, dict[str, Any]], name: str
) -> None:
    from playwright.async_api import async_playwright

    server, seeded = rich_server
    hostile = seeded["hostile"].id
    watch = Watch()
    async with async_playwright() as play:
        browser, context = await open_context(play, name, viewport={"width": 1440, "height": 900})
        page = await context.new_page()
        page.set_default_timeout(60_000)
        watch.attach(page)
        await sign_in(page, server, "/app")
        for where in (f"/app/dashboard?{SPAN}",
                      f"/app/dashboard?{SPAN}&rule=rule-x&kind=ip&value=10.9.9.9",
                      "/app/inbox?view=all", "/app/proposals"):  # fmt: skip
            await page.goto(server + where)
            await page.locator("main h1").first.wait_for(state="attached")
            await page.wait_for_load_state("networkidle")
        for tab in ("overview", "report", "ai", "checked", "alerts", "history"):
            await page.goto(f"{server}/app/investigations/{hostile}?tab={tab}")
            await page.get_by_role("tab", selected=True).wait_for()
            await page.wait_for_load_state("networkidle")
            if tab == "alerts":  # the raw alert on demand
                await page.get_by_role("button", name="Show raw").first.click()
                await page.wait_for_load_state("networkidle")
        await page.goto(f"{server}/app/investigations/{hostile}?tab=report")
        await page.get_by_role("heading", name="Verdict").wait_for()
        assert await page.evaluate("window.__pwned") is None
        assert (
            await page.locator("main img, main script, main iframe, main svg foreignObject").count()
            == 0
        )
        assert await page.locator("main a[href*='evil'], main a[href^='javascript']").count() == 0
        marks = await page.locator("main .ut-mark").count()
        assert marks >= 1
        violations = await watch.violations(page)
        await browser.close()
    assert violations == []
    assert watch.errors == []


# --------------------------------------------------------------------------- the keyboard

GRID_STATE = probe("grid_state")


async def tab_to_grid(page: Any, *, skip: bool = False) -> int:
    """Tab from the top of the page until the grid has the focus; how many presses it took. With
    ``skip``, the first stop is the "Skip to content" link, used with Enter."""
    await page.evaluate("document.activeElement && document.activeElement.blur()")
    if skip:
        await page.keyboard.press("Tab")
        assert await page.evaluate("document.activeElement.textContent.trim()") == "Skip to content"
        await page.keyboard.press("Enter")
        await page.wait_for_function("() => document.activeElement?.id === 'main'")
    for presses in range(1, 60):
        await page.keyboard.press("Tab")
        if await page.evaluate("document.activeElement?.getAttribute('role') === 'grid'"):
            return presses
    raise AssertionError("the grid cannot be reached with the Tab key")


@pytest.mark.parametrize("name", BROWSERS)
async def test_the_inbox_by_keyboard_alone(
    rich_server: tuple[str, dict[str, Any]], name: str
) -> None:
    from playwright.async_api import async_playwright

    server, _ = rich_server
    watch = Watch()
    async with async_playwright() as play:
        browser, context = await open_context(play, name, viewport={"width": 1440, "height": 900})
        page = await context.new_page()
        page.set_default_timeout(60_000)
        watch.attach(page)
        await sign_in(page, server, "/app/inbox?view=all")
        await page.locator("[role=grid] [role=row]").nth(1).wait_for()
        await page.wait_for_function(
            "() => document.querySelector('#investigation-title')"
        )  # the pane opened the first
        assert await tab_to_grid(page, skip=True) <= 9  # past the menu; five views since AR4
        state = await page.evaluate(GRID_STATE)
        assert state["onGrid"]
        assert state["tabindex"] == "0"
        assert state["columns"] == "3"
        assert state["headers"] == ["Investigation", "Status", "Alerts and last alert"]
        total = len(state["indexes"]) - 1
        assert total >= 10
        assert state["rows"] == str(total + 1)  # every row and the header: nothing more to read
        assert state["indexes"] == [
            str(i) for i in range(1, total + 2)
        ]  # rows in order, the header first
        assert len(state["selected"]) == 1  # the pane opened the first one: the cursor is on it
        first = state["selected"][0]
        assert first["index"] == "2"
        assert state["descendant"] == first["id"]
        # a single tab stop: the next Tab leaves the grid for the pane, not for a row
        await page.keyboard.press("Tab")
        state = await page.evaluate(GRID_STATE)
        assert not state["onGrid"]
        assert state["focus"]["role"] != "row"
        await page.keyboard.press("Shift+Tab")
        assert (await page.evaluate(GRID_STATE))["onGrid"]
        # j, Down, k move the cursor and name it; the focus stays on the grid
        await page.keyboard.press("j")
        state = await page.evaluate(GRID_STATE)
        assert state["onGrid"]
        assert [s["index"] for s in state["selected"]] == ["3"]
        assert state["descendant"] == state["selected"][0]["id"]
        second = state["selected"][0]["name"]
        await page.keyboard.press("ArrowDown")
        assert [s["index"] for s in (await page.evaluate(GRID_STATE))["selected"]] == ["4"]
        await page.keyboard.press("k")
        state = await page.evaluate(GRID_STATE)
        assert [s["index"] for s in state["selected"]] == ["3"]
        await page.keyboard.press("End")
        assert [s["index"] for s in (await page.evaluate(GRID_STATE))["selected"]] == [
            str(total + 1)
        ]
        await page.keyboard.press("Home")
        await page.keyboard.press("j")
        # the pane follows the cursor once it rests
        await page.wait_for_function(
            "(n) => document.querySelector('#investigation-title')?.textContent.includes(n)",
            arg=second[:20],
        )
        # Enter opens it and moves the focus into the pane
        await page.keyboard.press("Enter")
        await page.wait_for_function("() => document.activeElement?.id === 'detail-pane'")
        await page.keyboard.press("Tab")
        state = await page.evaluate(GRID_STATE)
        assert state["focus"]["inPane"]
        assert state["focus"]["id"] != "detail-pane"
        # Escape from the pane is back to the list
        await page.keyboard.press("Escape")
        assert (await page.evaluate(GRID_STATE))["onGrid"]
        # ? lists the keys; the focus is in the dialog; Escape closes it and gives the focus back
        await page.keyboard.press("Shift+Slash")
        dialog = page.get_by_role("dialog", name="Keyboard shortcuts in the Inbox")
        await dialog.wait_for()
        assert (await page.evaluate(GRID_STATE))["focus"]["inDialog"]
        await page.keyboard.press("Escape")
        await dialog.wait_for(state="hidden")
        await page.wait_for_function(
            "() => document.activeElement?.getAttribute('role') === 'grid'"
        )
        # the off switch is a checkbox: Space switches the letters off, the arrows still work
        switch = page.get_by_label("Single-key shortcuts (j, k, ?)")
        await switch.focus()
        await page.keyboard.press("Space")
        assert not await switch.is_checked()
        await tab_to_grid(page)
        before = (await page.evaluate(GRID_STATE))["selected"][0]["index"]
        await page.keyboard.press("j")
        await page.keyboard.press("Shift+Slash")
        state = await page.evaluate(GRID_STATE)
        assert state["selected"][0]["index"] == before
        assert await page.get_by_role("dialog").count() == 0
        await page.keyboard.press("ArrowDown")
        assert (await page.evaluate(GRID_STATE))["selected"][0]["index"] == str(int(before) + 1)
        violations = await watch.violations(page)
        await browser.close()
    assert violations == []
    assert watch.errors == []


@pytest.mark.parametrize("name", BROWSERS)
async def test_below_1024_px_the_inbox_is_one_pane_at_a_time(
    rich_server: tuple[str, dict[str, Any]], name: str
) -> None:
    from playwright.async_api import async_playwright

    server, _ = rich_server
    async with async_playwright() as play:
        browser, context = await open_context(play, name, viewport={"width": 1023, "height": 800})
        page = await context.new_page()
        page.set_default_timeout(60_000)
        await sign_in(page, server, "/app/inbox?view=all")
        await page.locator("[role=grid] [role=row]").nth(1).wait_for()
        assert (
            await page.locator("#detail-pane").count() == 0
        )  # the list alone; nothing opened by itself
        assert "id=" not in page.url
        await tab_to_grid(page)
        await page.keyboard.press("ArrowDown")
        await page.keyboard.press("ArrowDown")
        await page.wait_for_timeout(400)
        assert "id=" not in page.url  # moving the cursor opens nothing
        await page.keyboard.press("Enter")
        await page.locator("#investigation-title").wait_for()
        assert await page.locator("[role=grid]").count() == 0  # the investigation alone
        await page.wait_for_function("() => document.activeElement?.id === 'detail-pane'")
        await page.keyboard.press("Tab")
        assert (
            await page.evaluate("document.activeElement.textContent.trim()") == "← Back to the list"
        )
        await page.keyboard.press("Enter")
        await page.locator("[role=grid]").wait_for()
        await page.wait_for_function(
            "() => document.activeElement?.getAttribute('role') === 'grid'"
        )
        assert await page.locator("#detail-pane").count() == 0
        # the same page at 1024 px has both panes
        await page.set_viewport_size({"width": 1024, "height": 800})
        await page.locator("#detail-pane").wait_for()
        assert await page.locator("[role=grid]").count() == 1
        await browser.close()


# --------------------------------------------------------------------------- changing things


async def open_investigation(
    page: Any, server: str, investigation_id: str, tab: str = "overview"
) -> None:
    await page.goto(f"{server}/app/investigations/{investigation_id}?tab={tab}")
    await page.get_by_role("heading", name="Your review").wait_for()


def review_outcome(page: Any) -> Any:
    return page.get_by_role("form", name="Review this investigation").locator("select")


async def reviews_of(
    engine: AsyncEngine, investigation_id: Any
) -> list[tuple[str, str, str | None]]:
    async with engine.connect() as conn:
        rows = await conn.execute(text(
            "SELECT u.username, e.action, e.outcome FROM review_events e"
            " JOIN users u ON u.id = e.user_id"
            " WHERE e.investigation_id = :i ORDER BY e.id"), {"i": investigation_id})  # fmt: skip
        return [(r[0], r[1], r[2]) for r in rows]


@pytest.mark.parametrize("name", BROWSERS)
async def test_a_review_whose_investigation_moved_on_is_refused_and_keeps_what_was_typed(
    rich_server: tuple[str, dict[str, Any]], seeded: AsyncEngine, name: str
) -> None:
    from playwright.async_api import async_playwright

    server, records = rich_server
    racy = records["racy"]
    watch = Watch()
    async with async_playwright() as play:
        browser, context = await open_context(play, name, viewport={"width": 1440, "height": 900})
        page = await context.new_page()
        page.set_default_timeout(60_000)
        watch.attach(page)
        await sign_in(page, server, "/app")
        await open_investigation(page, server, str(racy.id))
        await review_outcome(page).select_option("true_positive")
        await page.get_by_label("Note", exact=True).fill("It beacons; I checked the host.")
        # someone else reviews it while she reads
        done = review_as(server, "ravi", racy, "benign_expected")
        assert done.status_code == 201, done.text
        await page.get_by_role("button", name="Mark reviewed").click()
        conflict = page.get_by_text(
            "Someone else reviewed this, or new alerts arrived, while you were reading."
            " Nothing was saved."
        )
        await conflict.wait_for()
        assert await conflict.get_attribute("role") == "alert"
        assert (
            await page.get_by_label("Note", exact=True).input_value()
            == "It beacons; I checked the host."
        )
        assert await review_outcome(page).input_value() == "true_positive"
        await page.get_by_text(
            "Reviewed", exact=True
        ).first.wait_for()  # the investigation was read again
        assert await reviews_of(seeded, racy.id) == [
            ("ravi", "reviewed", "benign_expected")
        ]  # nothing of hers
        # what she is looking at is not what she saw: nothing goes until she says she looked (B2-R1)
        await page.get_by_text("This investigation changed while you were typing").wait_for()
        await page.get_by_role("button", name="Mark reviewed").click(force=True)  # aria-disabled
        await page.wait_for_timeout(300)
        assert await reviews_of(seeded, racy.id) == [("ravi", "reviewed", "benign_expected")]
        await page.get_by_role("button", name="I have looked at what changed").click()
        await page.get_by_role("button", name="Mark reviewed").click()
        await page.get_by_text("Saved: marked reviewed.").first.wait_for()
        assert await reviews_of(seeded, racy.id) == [
            ("ravi", "reviewed", "benign_expected"),
            ("asha", "reviewed", "true_positive"),
        ]
        await page.get_by_role("tab", name=re.compile("History")).click()
        await page.get_by_text("It beacons; I checked the host.").wait_for()
        violations = await watch.violations(page)
        await browser.close()
    assert violations == []
    assert [e for e in watch.errors if "409" not in e] == []


@pytest.mark.parametrize("name", BROWSERS)
async def test_accepting_a_proposal_shows_what_is_sent_and_a_stale_accept_says_why(
    rich_server: tuple[str, dict[str, Any]], seeded: AsyncEngine, name: str
) -> None:
    from playwright.async_api import async_playwright

    server, records = rich_server
    agent = records["agent"]
    stale = records["group"][0]
    async with async_playwright() as play:
        browser, context = await open_context(play, name, viewport={"width": 1440, "height": 900})
        page = await context.new_page()
        page.set_default_timeout(60_000)
        await sign_in(page, server, "/app")
        # a proposal of the AI investigator: the dialog first, then the review
        await open_investigation(page, server, agent["investigation_id"], "ai")
        await page.get_by_role("button", name="Accept: True positive").first.click()
        dialog = page.get_by_role("alertdialog")
        await dialog.wait_for()
        await page.wait_for_function("() => document.activeElement?.textContent === 'Cancel'")
        assert (
            await dialog.get_by_test_id("payload").inner_text()
        ) == f'{{\n  "assessment_id": {agent["assessment_id"]}\n}}'
        assert (
            f"/api/v1/investigations/{agent['investigation_id']}/accept"
            in await dialog.inner_text()
        )
        await dialog.get_by_role("button", name="Accept", exact=True).click()
        await dialog.wait_for(state="hidden")
        await page.get_by_text("Accepted: True positive.").first.wait_for()
        assert await reviews_of(seeded, agent["investigation_id"]) == [
            ("asha", "reviewed", "true_positive")
        ]
        # a proposal gone stale while the page was open: refused, said in the dialog, nothing saved
        await open_investigation(page, server, str(stale.id), "ai")
        await page.get_by_role("button", name=re.compile("^Accept:")).first.wait_for()
        assert review_as(server, "ravi", stale, "inconclusive").status_code == 201
        await page.get_by_role("button", name=re.compile("^Accept:")).first.click()
        await dialog.wait_for()
        await dialog.get_by_role("button", name="Accept", exact=True).click()
        problem = dialog.get_by_role("alert")
        await problem.wait_for()
        assert "the proposal changed" in await problem.inner_text()
        assert "nothing was saved" in await problem.inner_text()
        await dialog.get_by_role("button", name="Cancel").click()
        await dialog.wait_for(state="hidden")
        assert await reviews_of(seeded, stale.id) == [("ravi", "reviewed", "inconclusive")]
        await page.get_by_role("button", name=re.compile("^Accept:")).first.wait_for(
            state="detached"
        )  # read again: no proposal to accept
        await browser.close()


@pytest.mark.parametrize("name", BROWSERS)
async def test_asking_the_ai_investigator_shows_the_exact_request_first(
    rich_server: tuple[str, dict[str, Any]], name: str
) -> None:
    from playwright.async_api import async_playwright

    server, records = rich_server
    plain = records["plain"]
    sent: list[str] = []
    async with async_playwright() as play:
        browser, context = await open_context(play, name, viewport={"width": 1440, "height": 900})
        page = await context.new_page()
        page.set_default_timeout(60_000)
        await sign_in(page, server, "/app")

        async def detail(
            route: Any,
        ) -> None:  # this server has no AI investigator: pretend it has one
            response = await route.fetch()
            body = await response.json()
            body["ask_available"] = True
            await route.fulfill(response=response, json=body)

        async def assess(route: Any) -> None:
            sent.append(
                f"{route.request.method} {route.request.url.removeprefix(server)}"
                f" {route.request.post_data or ''}".strip()
            )
            await route.fulfill(status=202, json={"result": "queued"})

        await page.route(re.compile(rf"/api/v1/investigations/{plain.id}$"), detail)
        await page.route(re.compile(rf"/api/v1/investigations/{plain.id}/assess$"), assess)
        await open_investigation(page, server, str(plain.id), "ai")
        await page.get_by_role("button", name="Ask the AI investigator now").click()
        dialog = page.get_by_role("alertdialog")
        await dialog.wait_for()
        assert "No body: the request sends nothing else." in await dialog.inner_text()
        await dialog.get_by_role("button", name="Ask now").click()
        await page.get_by_text(
            "Asked. The AI investigator looks within a few minutes"
        ).first.wait_for()
        assert sent == [f"POST /api/v1/investigations/{plain.id}/assess"]
        await browser.close()


@pytest.mark.parametrize("name", BROWSERS)
async def test_the_gold_box_saves_the_answer_and_a_review_can_save_it_too(
    rich_server: tuple[str, dict[str, Any]], seeded: AsyncEngine, name: str
) -> None:
    from playwright.async_api import async_playwright

    server, records = rich_server
    gold = records["gold"]
    async with async_playwright() as play:
        browser, context = await open_context(play, name, viewport={"width": 1440, "height": 900})
        page = await context.new_page()
        page.set_default_timeout(60_000)
        await sign_in(page, server, "/app")
        await open_investigation(page, server, str(gold.id))
        box = page.get_by_role("region", name="Gold set: your answer")
        await box.wait_for()
        assert "the suggestion is ARGUS's, not an answer" in await box.inner_text()
        await box.get_by_label("Correct outcome").select_option("benign_expected")
        await box.get_by_role("button", name="Save answer").click()
        await page.get_by_text("Saved your gold-set answer.").first.wait_for()
        await box.get_by_text("No unanswered gold-set item is left.").wait_for()
        async with seeded.connect() as conn:
            labels = (await conn.execute(text("SELECT outcome FROM gold_labels"))).scalars().all()
        assert list(labels) == ["benign_expected"]
        # the review form's box saves the outcome as the gold answer too, when the person ticks it:
        # it starts unticked, so ARGUS's suggestion is never the default answer (AR4 review, D-186)
        await review_outcome(page).select_option("true_positive")
        also = page.get_by_label("Also save the outcome as my gold-set answer")
        assert not await also.is_checked()
        await also.check()
        await page.get_by_role("button", name="Mark reviewed").click()
        await page.get_by_text("Also saved as your gold-set answer.").first.wait_for()
        async with seeded.connect() as conn:
            labels = (
                (await conn.execute(text("SELECT outcome FROM gold_labels ORDER BY id")))
                .scalars()
                .all()
            )
        assert list(labels) == ["benign_expected", "true_positive"]
        await browser.close()


@pytest.mark.parametrize("name", BROWSERS)
async def test_a_group_is_confirmed_from_its_sample_and_what_changed_meanwhile_is_skipped(
    rich_server: tuple[str, dict[str, Any]], seeded: AsyncEngine, name: str
) -> None:
    from playwright.async_api import async_playwright

    server, records = rich_server
    group = records["group"]
    watch = Watch()
    async with async_playwright() as play:
        browser, context = await open_context(play, name, viewport={"width": 1440, "height": 900})
        page = await context.new_page()
        page.set_default_timeout(60_000)
        watch.attach(page)
        await sign_in(page, server, "/app/proposals")
        card = page.get_by_role("region", name="Benign: expected activity: 4 investigations")
        await card.wait_for()
        assert await card.locator("h3 + ul li").count() == 3  # the audit sample
        await card.get_by_text("All 4", exact=True).click()
        assert await card.locator("details li").count() == 1  # the rest
        assert (
            review_as(server, "ravi", group[3], "benign_policy").status_code == 201
        )  # one is reviewed while she looks
        await card.get_by_role("button", name="Confirm all 4 as Benign: expected activity").click()
        dialog = page.get_by_role("alertdialog")
        await dialog.wait_for()
        shown = await dialog.get_by_test_id("payload").inner_text()
        assert re.fullmatch(
            r'\{\n  "group": "engine@1#fp: steps / rule-1 / 1:answered",\n'
            r'  "assessment_ids": \[\n(    \d+,?\n){4}  \]\n\}',
            shown,
        ), shown
        await dialog.get_by_role("button", name="Confirm 4").click()
        await dialog.wait_for(state="hidden")
        await page.get_by_text("Confirmed 3; 1 skipped because they changed.").first.wait_for()
        async with seeded.connect() as conn:
            mine = (
                await conn.execute(
                    text(
                        "SELECT count(*) FROM review_events e JOIN users u ON u.id = e.user_id"
                        " WHERE u.username = 'asha' AND e.assessment_id IS NOT NULL"
                    )
                )
            ).scalar_one()
        assert mine == 3
        await page.get_by_role("region", name=re.compile("Benign: expected activity")).wait_for(
            state="detached"
        )
        violations = await watch.violations(page)
        await browser.close()
    assert violations == []


# --------------------------------------------------------------------------- when a request fails


@pytest.mark.parametrize("name", BROWSERS)
async def test_failures_are_said_plainly_and_never_retried(
    rich_server: tuple[str, dict[str, Any]], name: str
) -> None:
    from playwright.async_api import async_playwright

    server, records = rich_server
    plain = records["plain"]
    async with async_playwright() as play:
        browser, context = await open_context(play, name, viewport={"width": 1440, "height": 900})
        page = await context.new_page()
        page.set_default_timeout(60_000)
        await sign_in(page, server, "/app")
        await open_investigation(page, server, str(plain.id))
        answer: dict[str, Any] = {}
        calls = {"review": 0, "session": 0}

        async def review(route: Any) -> None:
            calls["review"] += 1
            await route.fulfill(**answer)

        await page.route(re.compile(rf"/api/v1/investigations/{plain.id}/reviews$"), review)
        page.on(
            "request",
            lambda r: (
                calls.__setitem__("session", calls["session"] + 1)
                if r.url.endswith("/api/v1/session")
                else None
            ),
        )
        cases: list[tuple[dict[str, Any], str]] = [
            (
                {
                    "status": 403,
                    "json": {"detail": "missing or wrong X-CSRF-Token", "code": "csrf"},
                },
                "This page was out of date with the server, so it has been refreshed."
                " Nothing was changed: try again.",
            ),
            (
                {
                    "status": 403,
                    "json": {
                        "detail": "your account may not do this: it needs the review capability",
                        "code": "forbidden",
                    },
                },
                "your account may not do this: it needs the review capability",
            ),
            (
                {"status": 429, "body": "slow down"},
                "ARGUS did not accept",
            ),  # replaced below: a bare 429 is said as one
            (
                {
                    "status": 503,
                    "json": {
                        "detail": "ARGUS cannot reach its database; try again in a minute",
                        "code": "unavailable",
                    },
                },
                "ARGUS cannot reach its database; try again in a minute",
            ),
            (
                {"status": 500, "json": {"detail": "boom", "code": "internal"}},
                "Something went wrong in ARGUS; it has been logged.",
            ),
        ]
        cases[2] = (
            {"status": 429, "json": {"detail": "slow down", "code": "internal"}},
            "Too many requests just now; wait a minute and try again.",
        )
        for n, (reply, words) in enumerate(cases):
            answer.clear()
            answer.update(reply)
            calls["review"], calls["session"] = 0, 0
            await review_outcome(page).select_option("inconclusive")
            await page.get_by_role("button", name="Mark reviewed").click()
            problem = page.get_by_role("form", name="Review this investigation").get_by_role(
                "alert"
            )
            await problem.filter(has_text=words).wait_for()
            await page.wait_for_timeout(400)
            assert calls["review"] == 1, (reply, calls)  # never sent again
            assert calls["session"] == (1 if n == 0 else 0), (
                reply,
                calls,
            )  # the session is read again once for a refused CSRF token only
        # the session ended: the way to sign in, and back
        await page.unroute(re.compile(rf"/api/v1/investigations/{plain.id}/reviews$"))
        await page.route(
            re.compile(r"/api/v1/investigations\?"),
            lambda route: route.fulfill(
                status=401, json={"detail": "sign in first", "code": "unauthenticated"}
            ),
        )
        # this session is still good, so the real sign-in page would send her straight back:
        # stop at the address
        await page.route(
            re.compile(r"/signin\?"),
            lambda route: route.fulfill(
                status=200, body="<p>Sign in</p>", content_type="text/html"
            ),
        )
        await page.goto(f"{server}/app/inbox?view=open")
        await page.wait_for_url(re.compile(r"/signin\?"))
        assert "why=ended" in page.url
        assert "next=%2Fapp%2Finbox%3Fview%3Dopen" in page.url
        await browser.close()


@pytest.mark.parametrize("name", BROWSERS)
async def test_an_unreadable_page_says_so_once_and_offers_another_try_only_where_it_helps(
    rich_server: tuple[str, dict[str, Any]], name: str
) -> None:
    from playwright.async_api import async_playwright

    server, _ = rich_server
    async with async_playwright() as play:
        browser, context = await open_context(play, name, viewport={"width": 1440, "height": 900})
        page = await context.new_page()
        page.set_default_timeout(60_000)
        await sign_in(page, server, "/app")
        asked: list[str] = []
        status = {"now": 503}

        async def dashboard(route: Any) -> None:
            asked.append(route.request.url)
            if status["now"] == 503:
                await route.fulfill(
                    status=503,
                    json={
                        "detail": "ARGUS cannot reach its database; try again in a minute",
                        "code": "unavailable",
                    },
                )
            elif status["now"] == 403:
                await route.fulfill(
                    status=403,
                    json={
                        "detail": "your account may not do this: it needs the view capability",
                        "code": "forbidden",
                    },
                )
            else:
                await route.continue_()

        await page.route(re.compile(r"/api/v1/dashboard\?"), dashboard)
        await page.goto(f"{server}/app/dashboard?{SPAN}")
        problem = page.get_by_role("alert").filter(has_text="The dashboard could not be shown.")
        await problem.wait_for()
        assert (
            "ARGUS cannot reach its database; try again in a minute" in await problem.inner_text()
        )
        await page.wait_for_timeout(500)
        assert len(asked) == 1  # not retried by itself
        status["now"] = 200
        await problem.get_by_role("button", name="Try again").click()  # the person's own second try
        await page.get_by_role("list", name="Key numbers").wait_for()
        assert len(asked) == 2
        status["now"] = 403
        await page.goto(f"{server}/app/dashboard?{SPAN}&severity=low")
        forbidden = page.get_by_role("alert").filter(has_text="The dashboard could not be shown.")
        await forbidden.wait_for()
        assert (
            await forbidden.get_by_role("button").count() == 0
        )  # a refusal is not retried: no button
        await browser.close()


# --------------------------------------------------------------------------- a long list


BULK = """
INSERT INTO investigations (id, grouping_version, rule_id, rule_name, group_key, bucket_start,
  bucket_end, previous_id, alert_count, first_event_at, last_event_at, severity, version)
SELECT md5('bulk-' || n)::uuid, '1', 'bulk-' || (n % 7), 'Bulk rule ' || (n % 7),
  '[["source.ip","10.1.' || (n % 250) || '.1"]]', now() - interval '3 days',
  now() - interval '2 days', md5('prev-' || n)::uuid, 1, now() - make_interval(mins => n),
  now() - make_interval(mins => n), 'low', 1
FROM generate_series(1, 1200) n
"""


@pytest.mark.parametrize("name", BROWSERS)
async def test_a_long_list_keeps_only_its_window_in_the_page_and_reads_more_as_it_is_scrolled(
    rich_server: tuple[str, dict[str, Any]], migrated_engine: AsyncEngine, name: str
) -> None:
    from playwright.async_api import async_playwright

    server, _ = rich_server
    async with migrated_engine.begin() as conn:
        await conn.execute(text(BULK))
    offsets: list[str] = []
    watch = Watch()
    async with async_playwright() as play:
        browser, context = await open_context(play, name, viewport={"width": 1440, "height": 900})
        page = await context.new_page()
        page.set_default_timeout(60_000)
        watch.attach(page)
        page.on(
            "request",
            lambda r: (
                offsets.append(re.search(r"offset=(\d+)", r.url).group(1))
                if "/api/v1/investigations?" in r.url and "offset=" in r.url
                else None
            ),
        )  # type: ignore[union-attr]
        await sign_in(page, server, "/app/inbox?view=all")
        grid = page.get_by_role("grid", name="Investigations")
        await grid.wait_for()
        await page.locator("[role=grid] [role=row]").nth(5).wait_for()
        assert (
            await grid.get_attribute("aria-rowcount") == "-1"
        )  # more to read: the total is not known
        assert await page.locator("[role=grid] [role=row]").count() < 40
        # the End key goes to the last row read, the end of the window: the next page is read
        await tab_to_grid(page, skip=True)
        await page.keyboard.press("End")
        await page.wait_for_function(
            "() => document.querySelector('[role=grid] [aria-selected=true]')"
            "?.getAttribute('aria-rowindex') === '101'"
        )
        for _ in range(30):
            if "100" in offsets:
                break
            await page.wait_for_timeout(200)
        assert offsets[:2] == ["0", "100"], offsets
        assert await page.locator("[role=grid] [role=row]").count() < 40  # still only the window
        # and a scroll wheel does the same: far down the list there are still a few rows in the page
        await page.locator("[role=grid]").evaluate("(el) => { el.scrollTop = el.scrollHeight; }")
        await page.wait_for_timeout(500)
        assert await page.locator("[role=grid] [role=row]").count() < 40
        violations = await watch.violations(page)
        await browser.close()
    assert violations == []
    assert watch.errors == []


# --------------------------------------------------------------------------- accessibility

WCAG = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22a", "wcag22aa"]


@pytest.mark.parametrize("name", BROWSERS)
async def test_axe_finds_nothing_serious_on_the_new_pages_light_dark_narrow_and_wide(
    rich_server: tuple[str, dict[str, Any]], name: str
) -> None:
    from axe_playwright_python.async_playwright import Axe
    from playwright.async_api import async_playwright

    server, records = rich_server
    agent, gold = records["agent"]["investigation_id"], str(records["gold"].id)
    pages = [
        ("dashboard", f"/app/dashboard?{SPAN}"),
        (
            "dashboard, filtered",
            f"/app/dashboard?{SPAN}&severity=high&state=unreviewed&rule=rule-1",
        ),
        ("inbox", "/app/inbox?view=all"),
        ("inbox, with a search", "/app/inbox?view=all&kind=ip&value=10.0.0.1"),
        *[
            (f"investigation, {tab}", f"/app/investigations/{agent}?tab={tab}")
            for tab in ("overview", "report", "ai", "checked", "alerts", "history")
        ],
        ("investigation, gold set", f"/app/investigations/{gold}"),
        ("proposals", "/app/proposals"),
    ]
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
                await sign_in(page, server, "/app")
                await page.get_by_role("heading", name="Home").wait_for()
                for label, where in pages:
                    await page.goto(server + where)
                    await page.locator("main").wait_for()
                    await page.wait_for_load_state("networkidle")
                    if "investigations/" in where:
                        await page.get_by_role("heading", name="Your review").wait_for()
                        await page.wait_for_load_state("networkidle")
                    elif "inbox" in where:
                        await page.locator("[role=grid] [role=row]").nth(1).wait_for()
                    for _ in range(2):  # open every details, then look again
                        await page.evaluate(
                            "() => document.querySelectorAll('details')"
                            ".forEach((d) => { d.open = true; })"
                        )
                        report = await axe.run(
                            page, options={"runOnly": {"type": "tag", "values": WCAG}}
                        )
                        ran = {
                            r["id"]
                            for kind in ("passes", "incomplete", "violations")
                            for r in report.response.get(kind, [])
                        }
                        assert {"color-contrast", "target-size", "label"} & ran, ran
                        assert len(ran) >= 15, ran
                        for v in report.response["violations"]:
                            if v["impact"] in ("serious", "critical"):
                                problems.append(
                                    (
                                        scheme,
                                        width,
                                        label,
                                        v["id"],
                                        [n["target"] for n in v["nodes"]][:4],
                                    )
                                )
                        break
                # the dialogs: the exact-request one and the key list
                await page.goto(f"{server}/app/investigations/{agent}?tab=ai")
                await page.get_by_role("heading", name="Your review").wait_for()
                await page.get_by_role("button", name=re.compile("^Accept:")).first.click()
                await page.get_by_role("alertdialog").wait_for()
                report = await axe.run(page, options={"runOnly": {"type": "tag", "values": WCAG}})
                problems += [
                    (scheme, width, "accept dialog", v["id"], [n["target"] for n in v["nodes"]][:4])
                    for v in report.response["violations"]
                    if v["impact"] in ("serious", "critical")
                ]
                await page.keyboard.press("Escape")
                if width >= 1024:
                    await page.goto(f"{server}/app/inbox?view=all")
                    await page.locator("[role=grid] [role=row]").nth(1).wait_for()
                    await page.get_by_role("button", name="Show keyboard shortcuts").click()
                    await page.get_by_role("dialog").wait_for()
                    report = await axe.run(
                        page, options={"runOnly": {"type": "tag", "values": WCAG}}
                    )
                    problems += [
                        (
                            scheme,
                            width,
                            "keys dialog",
                            v["id"],
                            [n["target"] for n in v["nodes"]][:4],
                        )
                        for v in report.response["violations"]
                        if v["impact"] in ("serious", "critical")
                    ]
                violations = await watch.violations(page)
                assert violations == [], (scheme, width, violations)
                await browser.close()
    assert not problems, "\n".join(map(str, problems))
    assert watch.errors == []


async def focus_of(page: Any) -> str:
    """What has the focus: its tag, id and words."""
    return await page.evaluate(
        "(() => { const a = document.activeElement; return a ? a.tagName + '#' + a.id + '|'"
        " + (a.textContent || '').trim().slice(0, 30) : 'none'; })()"
    )


@pytest.mark.parametrize("name", BROWSERS)
async def test_the_focus_stays_with_the_person_through_a_keyboard_review_and_accept(
    rich_server: tuple[str, dict[str, Any]], name: str
) -> None:
    """Review B2-R5: a disabled button that has the focus drops it to the page, and the Accept
    button is gone once the proposal is accepted. The focus stays on the button pressed through a
    review, comes back to Accept after Escape, and goes to the investigation's title after the
    request is sent."""
    from playwright.async_api import async_playwright

    server, records = rich_server
    watch = Watch()
    async with async_playwright() as play:
        browser, context = await open_context(play, name, viewport={"width": 1440, "height": 900})
        page = await context.new_page()
        page.set_default_timeout(60_000)
        watch.attach(page)
        await sign_in(page, server, "/app")
        await open_investigation(page, server, str(records["plain"].id))
        await review_outcome(page).select_option("benign_policy")
        review = page.get_by_role("button", name="Mark reviewed")
        await review.focus()
        await page.keyboard.press("Enter")
        await page.get_by_text("Saved: marked reviewed.").first.wait_for()
        await page.wait_for_timeout(500)
        assert await focus_of(page) == "BUTTON#|Mark reviewed"
        agent = records["agent"]["investigation_id"]
        await open_investigation(page, server, agent, "ai")
        accept = page.get_by_role("button", name=re.compile("^Accept:")).first
        await accept.focus()
        await page.keyboard.press("Enter")
        dialog = page.get_by_role("alertdialog")
        await dialog.wait_for()
        await page.wait_for_function("() => document.activeElement?.textContent === 'Cancel'")
        await page.keyboard.press("Escape")
        await dialog.wait_for(state="hidden")
        await page.wait_for_function(
            "() => document.activeElement?.textContent?.startsWith('Accept:')"
        )
        await page.keyboard.press("Enter")
        await dialog.wait_for()
        await page.wait_for_function("() => document.activeElement?.textContent === 'Cancel'")
        await page.keyboard.press("Tab")
        assert await focus_of(page) == "BUTTON#|Accept"
        await page.keyboard.press("Enter")
        await dialog.wait_for(state="hidden")
        await page.get_by_role("button", name=re.compile("^Accept:")).first.wait_for(
            state="detached"
        )
        await page.wait_for_function("() => document.activeElement?.id === 'investigation-title'")
        violations = await watch.violations(page)
        await browser.close()
    assert violations == []
    assert watch.errors == []


@pytest.mark.parametrize("name", BROWSERS)
async def test_no_page_scrolls_sideways_at_phone_width(
    rich_server: tuple[str, dict[str, Any]], name: str
) -> None:
    """Review B2-R6: a table's visually hidden header cell sat outside its scrolling box and made
    the Dashboard 122 px wider than a 390 px screen."""
    from playwright.async_api import async_playwright

    server, records = rich_server
    where = [
        f"/app/dashboard?{SPAN}",
        "/app/dashboard",
        "/app/inbox?view=all",
        "/app/proposals",
        "/app",
        *(
            f"/app/investigations/{records[key].id}?tab={tab}"
            for key in ("plain", "hostile")
            for tab in ("overview", "report", "ai", "checked", "alerts", "history")
        ),
    ]
    wide: list[tuple[str, int]] = []
    async with async_playwright() as play:
        browser, context = await open_context(play, name, viewport={"width": 390, "height": 800})
        page = await context.new_page()
        page.set_default_timeout(60_000)
        await sign_in(page, server, "/app")
        for path in where:
            await page.goto(server + path)
            await page.wait_for_load_state("networkidle")
            await page.wait_for_timeout(300)
            over = await page.evaluate(
                "document.documentElement.scrollWidth - document.documentElement.clientWidth"
            )
            if over > 0:
                wide.append((path, over))
        await browser.close()
    assert wide == []
