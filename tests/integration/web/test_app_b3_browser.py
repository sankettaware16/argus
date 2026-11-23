"""Q-B3's browser gate (plan §5 Q-B3, §7.5) on the real server (``argus web`` as a process on the
web's own database login, throwaway database), in Chromium and Firefox:

- the case flow as people do it: take a case by keyboard and dialog, ask to close it with the
  preview first, another person confirms it is them (the server's step-up page) and approves, and
  the case is closed, with no CSP or Trusted Types violation on the way;
- hostile values (a title, a note, a Kibana comment, an approval's words) stay inert, and words that
  look like ARGUS's own stay in a person's frame;
- a view-only account sees every action disabled with its reason; a case that moved is said in the
  dialog and read again;
- "Check more" from the investigation page, queued under the person's own name;
- axe with the WCAG 2.2 rules on every new page: 0 serious or critical, light and dark, 320, 390
  and 1440 px; no page scrolls sideways at 320 or 390 px (WCAG 1.4.10).
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.model import Indicator
from tests.integration.web.b2_support import BROWSERS, Watch, open_context
from tests.integration.web.b3_support import Live, make_world, start_server
from tests.integration.web.conftest import PASSWORD


def everything(case: object) -> str:
    """The incident page with every part on one page (the UI v2 keeps the old case page there)."""
    return f"/app/incidents/{case}?tab=all"


pytestmark = pytest.mark.integration
WCAG = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22a", "wcag22aa"]
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


async def sign_in_as(page: Any, base: str, user: str, next_path: str = "/app") -> None:
    await page.goto(f"{base}/signin?next={quote(next_path, safe='/')}")
    await page.fill("#username", user)
    await page.fill("#password", PASSWORD)
    async with page.expect_navigation(url=re.compile(re.escape(base + next_path) + r"/?$")):
        await page.click("button[type=submit]")


async def person(
    play: Any, name: str, base: str, user: str, next_path: str = "/app", **options: Any
) -> tuple[Any, Any, Any, Watch]:
    browser, context = await open_context(
        play, name, viewport={"width": 1440, "height": 900}, **options
    )
    page = await context.new_page()
    page.set_default_timeout(60_000)
    watch = Watch()
    watch.attach(page)
    await sign_in_as(page, base, user, next_path)
    return browser, context, page, watch


async def focus_id(page: Any) -> str:
    found: str = await page.evaluate("document.activeElement ? document.activeElement.id : ''")
    return found


@pytest.mark.parametrize("name", BROWSERS)
async def test_a_case_is_taken_closed_by_request_and_approved_by_another_person(
    live: Live, name: str
) -> None:
    from playwright.async_api import async_playwright

    world = live.world
    case = await world.open_case(1, title="Beaconing to the lab printer",
                                 indicators=(Indicator("ip", "10.0.0.1", "actor"),))  # fmt: skip
    await world.open_case(1, title="A second case", start=1)
    async with async_playwright() as play:
        path = "/app/incidents?view=all"
        browser, _, page, watch = await person(play, name, live.url, "mina", path)
        await page.get_by_role("heading", name="Incidents", exact=True).wait_for()
        rows = page.get_by_test_id("incident-row")
        await rows.filter(has_text="Beaconing to the lab printer").wait_for()
        assert await rows.count() == 2
        await rows.get_by_role("link", name=re.compile("Beaconing to the lab printer")).click()
        await page.wait_for_url(f"{live.url}/app/incidents/{case}")
        await page.get_by_test_id("decision-bar").wait_for()  # the page is drawn: nothing pending
        await page.wait_for_load_state("networkidle")
        await page.goto(f"{live.url}{everything(case)}")
        await page.get_by_role("heading", level=1, name=re.compile("Beaconing")).wait_for()
        assert await page.title() == "Incident · ARGUS"
        # by keyboard: the dialog opens on Enter, Cancel has the focus, Escape gives it back
        take = page.get_by_role("button", name="Take", exact=True)
        await take.focus()
        await page.keyboard.press("Enter")
        dialog = page.get_by_role("alertdialog")
        await dialog.wait_for()
        await page.wait_for_function("document.activeElement?.textContent === 'Cancel'")
        assert json.loads(await dialog.get_by_test_id("payload").text_content()) == {
            "expected_version": 1
        }
        await page.keyboard.press("Escape")
        await dialog.wait_for(state="hidden")
        await page.get_by_role("button", name="Take", exact=True).click()
        await page.get_by_role("alertdialog").get_by_role("button", name="Take").click()
        await page.get_by_text("You took case 1.").first.wait_for()
        await page.get_by_text("Taken by: Mina Manager").first.wait_for()
        assert await focus_id(page) == "case-title"
        # ask to close it: the writes are read first
        await page.get_by_role("button", name="Request closure").click()
        await page.get_by_role("radio", name=re.compile("Benign: expected activity")).check()
        await page.get_by_role("textbox", name=re.compile("Your words")).fill(
            "a lab printer, says the lab"
        )
        await page.get_by_role("button", name="Show what it would write").click()
        box = page.get_by_role("region", name="What asking would write")
        await box.get_by_text(re.compile("Nothing is written to Kibana")).wait_for()
        await box.get_by_test_id("fingerprint").wait_for()
        read_by_mina = await box.get_by_test_id("fingerprint").inner_text()
        await box.get_by_role("button", name="Ask for this closure").click()
        shown = json.loads(
            await page.get_by_role("alertdialog").get_by_test_id("payload").text_content()
        )
        assert shown["reason"] == "benign_expected"
        assert shown["note"] == "a lab printer, says the lab"
        assert shown["expected_version"] == 2
        assert len(shown["payload_hash"]) == 64
        await (
            page.get_by_role("alertdialog")
            .get_by_role("button", name="Ask for the closure")
            .click()
        )
        await page.get_by_text(
            re.compile("Asked to close case 1 as benign: expected activity")
        ).first.wait_for()
        await page.get_by_text(re.compile("1 request waiting for an approver")).first.wait_for()
        # another person confirms it is them, on the server's own page, and approves
        browser2, _, omar, watch2 = await person(play, name, live.url, "omar", "/app/approvals")
        card = omar.get_by_role("region", name="Close case 1: benign: expected activity")
        await card.wait_for()
        # what the approver reads is what the requester read: one fingerprint of the same writes
        assert await card.get_by_test_id("fingerprint").inner_text() == read_by_mina
        assert (
            await card.get_by_role("button", name=re.compile("^Approve")).get_attribute(
                "aria-disabled"
            )
            == "true"
        )
        await omar.get_by_role("link", name="Confirm it is you").click()
        await omar.wait_for_url(re.compile(r"/stepup\?next="))
        await omar.fill("#password", PASSWORD)
        async with omar.expect_navigation(url=f"{live.url}/app/approvals"):
            await omar.click("button[type=submit]")
        await omar.get_by_text(
            re.compile("You typed your password again, so you can approve until")
        ).wait_for()
        await (
            omar.get_by_role("region", name="Close case 1: benign: expected activity")
            .get_by_role("button", name=re.compile("^Approve"))
            .click()
        )
        await omar.get_by_role("button", name="Review the request").click()
        decision = omar.get_by_role("alertdialog")
        body = json.loads(await decision.get_by_test_id("payload").text_content())
        assert body["decision"] == "approved"
        assert len(body["payload_hash"]) == 64
        await decision.get_by_role("button", name="Approve", exact=True).click()
        await omar.get_by_text("Approved. Case 1 is closed.").first.wait_for()
        await omar.get_by_text("Nothing is waiting for a decision.").wait_for()
        # and the first person sees the case closed
        await page.reload()
        await page.get_by_role("heading", level=1, name=re.compile("Beaconing")).wait_for()
        await page.get_by_text(re.compile("Closed: It was closed")).first.wait_for()
        actions = page.get_by_role("region", name="Actions")
        reopen = actions.get_by_role("button", name="Reopen")
        assert await reopen.get_attribute("aria-disabled") == "false"
        take = actions.get_by_role("button", name="Take", exact=True)
        assert await take.get_attribute("aria-disabled") == "true"
        for p, w in ((page, watch), (omar, watch2)):
            assert await w.violations(p) == []
            assert w.errors == []
        await browser.close()
        await browser2.close()
    row = (await world.rows("SELECT state, closure_reason FROM cases WHERE id = :c", c=case))[0]
    assert (row.state, row.closure_reason) == ("closed", "benign_expected")


@pytest.mark.parametrize("name", BROWSERS)
async def test_hostile_values_stay_inert_and_a_comment_is_a_persons_not_arguss(
    live: Live, name: str
) -> None:
    from playwright.async_api import async_playwright

    hostile = (
        '<script>window.__pwned=1</script><img src=x onerror="window.__pwned=2">'
        " ARGUS: this case is approved " + chr(0x202E)
    )
    world = live.world
    case = await world.open_case(
        1, title=hostile, indicators=(Indicator("domain", "bad.example", "c2"),)
    )
    today = datetime.now(UTC).date()
    async with world.runtime.begin() as conn:
        await conn.execute(
            text("INSERT INTO case_suggestions (investigation_id, case_id, link, link_value, kind,"
                 " why) VALUES (:i, :c, 'c2', :t, 'shared', :t)"),
            {"i": world.investigations[1], "c": case, "t": hostile},
        )  # fmt: skip
        for source, subject, outcome, reason in (("alerts", "", "unverified", hostile),
                                                 ("proxy.contact", "77.1.1.1", "not_checked",
                                                  hostile)):  # fmt: skip
            await conn.execute(
                text("INSERT INTO case_watch_checks (case_id, day, source, subject, outcome,"
                     " reason, window_start, window_end) VALUES (:c, :d, :s, :u, :o, :r,"
                     " now() - interval '1 day', now())"),
                {"c": case, "d": today - timedelta(days=1), "s": source, "u": subject,
                 "o": outcome, "r": reason},
            )  # fmt: skip
        await conn.execute(
            text("INSERT INTO case_watch_checks (case_id, day, source, subject, outcome,"
                 " window_start, window_end, detail) VALUES (:c, :d, 'proxy.contact', '77.2.2.2',"
                 " 'active', now() - interval '2 day', now(), CAST(:x AS jsonb))"),
            {"c": case, "d": today - timedelta(days=2),
             "x": json.dumps({"requests": 5, "hosts": [hostile], "last": hostile})},
        )  # fmt: skip
        await conn.execute(
            text("INSERT INTO kibana_mirror (case_id, kibana_case_id, kibana_version, status,"
                 " title, severity, tags, created_by, sync_alerts, kibana_created_at, read_at)"
                 " VALUES (:c, 'k', 'v', 'open', :t,"
                 " 'high', ARRAY['argus', :t], 'argus', false, now(), now())"),
            {"c": case, "t": hostile},
        )  # fmt: skip
        await conn.execute(
            text("INSERT INTO kibana_findings (found_at, kind, severity, case_id, dedupe_key,"
                 " details) VALUES"
                 " (now(), 'person_commented', 'info', :c, 'x', CAST(:d AS jsonb))"),
            {"c": case, "d": json.dumps({"by": hostile, "comment": hostile})},
        )  # fmt: skip
    async with async_playwright() as play:
        browser, _, page, watch = await person(play, name, live.url, "mina", everything(case))
        await page.locator("main h1").first.wait_for()
        for body in (hostile, "ARGUS: approved " + hostile):
            await page.get_by_role("textbox", name=re.compile("Add a note to this case")).fill(body)
            await (
                page.get_by_role("region", name="Notes")
                .get_by_role("button", name="Add the note")
                .click()
            )
            await page.get_by_text("Saved: note added.").first.wait_for()
        await page.get_by_test_id("finding").first.wait_for()
        await page.get_by_test_id("suggestion").first.wait_for()
        watch_block = page.get_by_role("region", name="The still-active watch")
        await watch_block.get_by_test_id("watch-day").first.wait_for()
        assert hostile.split(" ARGUS")[0] in await page.get_by_test_id("suggestion").inner_text()
        assert "ARGUS: this case is approved" in await watch_block.inner_text()
        assert await page.evaluate("window.__pwned") is None
        main = page.locator("main")
        assert await main.locator("img, script, iframe, style, link").count() == 0
        attributes = await main.evaluate("""r => [...r.querySelectorAll('*')].flatMap(
            e => e.getAttributeNames().filter(a => a === 'style' || a.startsWith('on')))""")
        assert attributes == []
        assert await main.locator(".ut-mark", has_text="RLO").count() >= 8
        finding = page.get_by_test_id("finding").first
        assert "ARGUS: this case is approved" in await finding.locator("blockquote").inner_text()
        assert await finding.get_by_text("What the person wrote in Kibana").count() == 1
        # nothing that speaks for ARGUS holds the look-alike banner
        spoken = await page.evaluate("""() => [...document.querySelectorAll(
            '[role=alert], [role=status], [data-testid^=live-]')]
            .map(e => e.textContent).filter(t => t.includes('this case is approved'))""")
        assert spoken == []
        assert len(await world.rows("SELECT id FROM case_notes")) == 2
        await page.goto(f"{live.url}/app/incidents?view=all")
        await page.get_by_test_id("incident-row").first.wait_for()
        assert await page.evaluate("window.__pwned") is None
        assert await page.locator("main img").count() == 0
        assert await watch.violations(page) == []
        assert watch.errors == []
        await browser.close()


@pytest.mark.parametrize("name", BROWSERS)
async def test_a_view_only_account_sees_actions_disabled_and_a_moved_case_is_said(
    live: Live, name: str
) -> None:
    from playwright.async_api import async_playwright

    world = live.world
    case = await world.open_case(1)
    async with async_playwright() as play:
        browser, _, vera, _ = await person(play, name, live.url, "vera", everything(case))
        await vera.get_by_role("heading", level=1, name=re.compile("Regular beaconing")).wait_for()
        region = vera.get_by_role("region", name="Actions")
        buttons = region.get_by_role("button")
        assert await buttons.count() == 7
        for i in range(7):
            assert await buttons.nth(i).get_attribute("aria-disabled") == "true"
        assert "Your account may not take cases" in await region.inner_text()
        await vera.get_by_text(
            re.compile("Your account may view only: adding a note needs")
        ).wait_for()
        await vera.goto(f"{live.url}/app/approvals")
        await vera.get_by_role("heading", name="Approvals").wait_for()
        await vera.get_by_text("Nothing is waiting for a decision.").wait_for()
        await browser.close()
        # a case that moved while a person looked at it
        browser, _, mina, _ = await person(play, name, live.url, "mina", everything(case))
        await mina.get_by_role("heading", level=1, name=re.compile("Regular beaconing")).wait_for()
        with httpx.Client(base_url=live.url, headers={"Origin": live.url}) as other:
            made = other.post("/api/login", json={"username": "nora", "password": PASSWORD})  # noqa: ASYNC212
            assert made.status_code == 200, made.text
            took = other.post(f"/api/v1/cases/{case}/take",  # noqa: ASYNC212
                              headers={"X-CSRF-Token": made.json()["csrf_token"]},
                              json={"expected_version": 1})  # fmt: skip
            assert took.status_code == 200, took.text
        await mina.get_by_role("button", name="Take", exact=True).click()
        dialog = mina.get_by_role("alertdialog")
        await dialog.get_by_role("button", name="Take").click()
        alert = dialog.get_by_role("alert")
        await alert.wait_for()
        assert "it is at version 2, you saw 1" in await alert.inner_text()
        await dialog.get_by_role("button", name="Cancel").click()
        await mina.get_by_text("Taken by: Nora NoReopen").first.wait_for()  # read again
        await browser.close()
    assert [
        r.kind
        for r in await world.rows(
            "SELECT kind FROM case_events WHERE case_id = :c ORDER BY case_version", c=case
        )
    ] == ["opened", "taken"]


@pytest.mark.parametrize("name", BROWSERS)
async def test_check_more_is_queued_under_the_persons_own_name_and_its_record_is_shown(
    live: Live, name: str
) -> None:
    from playwright.async_api import async_playwright

    world = live.world
    investigation = world.investigations[0]
    async with async_playwright() as play:
        browser, _, page, watch = await person(
            play, name, live.url, "mina", f"/app/alert-groups/{investigation}"
        )
        region = page.get_by_role("region", name="Check more")
        await region.get_by_role("combobox", name="Check").select_option("ti.lookup")
        await region.get_by_label("Address or domain").fill("203.0.113.9")
        await region.get_by_test_id("check-cost").wait_for()
        assert "A light check" in await region.get_by_test_id("check-cost").inner_text()
        await region.get_by_role("button", name="Review the request").click()
        dialog = page.get_by_role("alertdialog")
        body = json.loads(await dialog.get_by_test_id("payload").text_content())
        assert body["template"] == "ti.lookup"
        assert body["entity"] == "203.0.113.9"
        assert "requested_by" not in body
        await dialog.get_by_role("button", name="Ask for this check").click()
        await page.get_by_text(
            re.compile("Queued\\. ARGUS runs it when the SIEM allows")
        ).first.wait_for()
        await region.get_by_test_id("check-record").first.wait_for()
        assert (
            "Waiting for ARGUS's service to run it"
            in await region.get_by_test_id("check-record").first.inner_text()
        )
        assert await watch.violations(page) == []
        assert watch.errors == []
        await browser.close()
    rows = await world.rows(
        "SELECT requested_by, kind, source, status, entity FROM investigation_checks"
    )
    assert [tuple(r) for r in rows] == [("mina", "check", "person", "queued", "203.0.113.9")]


async def served_pages(live: Live) -> list[tuple[str, str]]:
    world = live.world
    case = await world.open_case(
        2,
        title="Beaconing to the lab printer",
        kibana=True,
        indicators=(Indicator("ip", "10.0.0.1", "actor"),),
    )
    asked = [(case, "benign_policy")]
    for k in range(4):
        asked.append(
            (await world.open_case(1, title=f"Benign case {k}", start=2 + k), "benign_expected")
        )
    with httpx.Client(base_url=live.url, headers={"Origin": live.url}) as http:
        made = http.post("/api/login", json={"username": "mina", "password": PASSWORD})  # noqa: ASYNC212
        assert made.status_code == 200, made.text
        for target, reason in asked:
            seen = http.get(f"/api/v1/cases/{target}/closure-preview", params={"reason": reason})  # noqa: ASYNC212
            assert seen.status_code == 200, seen.text
            done = http.post(f"/api/v1/cases/{target}/closure-requests",  # noqa: ASYNC212
                             headers={"X-CSRF-Token": made.json()["csrf_token"]},
                             json={"expected_version": 1, "reason": reason,
                                   "payload_hash": seen.json()["payload_hash"]})  # fmt: skip
            assert done.status_code == 201, done.text
    return [
        ("cases", "/app/incidents?view=open"),
        ("cases, searched", "/app/cases?view=all&q=beacon"),
        ("case", f"/app/incidents/{case}?tab=all"),
        ("approvals", "/app/approvals"),
        ("investigation", f"/app/alert-groups/{world.investigations[0]}"),
    ]


@pytest.mark.parametrize("name", BROWSERS)
async def test_axe_finds_nothing_serious_on_the_new_pages_light_dark_narrow_and_wide(
    live: Live, name: str
) -> None:
    from axe_playwright_python.async_playwright import Axe
    from playwright.async_api import async_playwright

    pages = await served_pages(live)
    axe = Axe()
    problems: list[Any] = []
    watch = Watch()
    async with async_playwright() as play:
        for scheme in ("light", "dark"):
            for width in (320, 390, 1440):
                browser, context = await open_context(
                    play, name, viewport={"width": width, "height": 900}, color_scheme=scheme
                )
                page = await context.new_page()
                page.set_default_timeout(60_000)
                watch.attach(page)
                await sign_in_as(page, live.url, "omar")
                for label, where in pages:
                    await page.goto(live.url + where)
                    await page.locator("main").wait_for()
                    await page.wait_for_load_state("networkidle")
                    if "/incidents/" in where:
                        await page.get_by_role(
                            "heading", level=1, name=re.compile("Beaconing to the lab printer")
                        ).wait_for()
                        await page.get_by_role("button", name="Request closure").click()
                        await page.get_by_role(
                            "radio", name=re.compile("Benign: expected activity")
                        ).check()
                        await page.get_by_role("button", name="Show what it would write").click()
                        await page.get_by_test_id("fingerprint").wait_for()
                    elif where == "/app/approvals":
                        await page.get_by_test_id("request").first.wait_for()
                    elif "alert-groups/" in where:
                        await page.get_by_role("region", name="Check more").wait_for()
                    else:
                        await page.get_by_test_id("incident-row").first.wait_for()
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
                    problems += [
                        (scheme, width, label, v["id"], [n["target"] for n in v["nodes"]][:4])
                        for v in report.response["violations"]
                        if v["impact"] in ("serious", "critical")
                    ]
                    if width <= 390:  # no page scrolls sideways at phone width, nor at 320 px
                        wide = await page.evaluate(
                            "document.documentElement.scrollWidth"
                            " - document.documentElement.clientWidth"
                        )
                        assert wide <= 0, (label, wide)
                violations = await watch.violations(page)
                assert violations == [], (scheme, width, violations)
                await browser.close()
    assert not problems, "\n".join(map(str, problems))
    assert watch.errors == []
