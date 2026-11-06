"""AR4's browser gate (D-182) on the real server (``argus web`` as a process on the web's own
database login, throwaway database), in Chromium and Firefox:

- the TA's walk: the queue on Home lists the suggested case first with ARGUS's verdict; open its
  first investigation, the card says what ARGUS recommends; C confirms (the proposal is accepted),
  N lands on the next investigation of the case; the keys do nothing while the note is being typed;
  4 chooses a decision and the focus goes to Save decision; no policy violation on the way;
- a notified case on the case page: the notice is recorded through the form and its exact request,
  the case leaves the queue and is counted ("Notified, still active"), a reminder is shown and
  dismissed, a block is recorded, the block list is viewed and downloaded, the notice is withdrawn;
- the dashboard's "Notified, still active" tile and table, and the Inbox's and Home's counts, equal
  the classic pages' on the same records;
- axe with the WCAG 2.2 rules on the new screens: 0 serious or critical, light and dark, 320, 390
  and 1440 px; no page scrolls sideways at 320 or 390 px.
"""

from __future__ import annotations

import csv
import io
import json
import re
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import text

from argus.cases.machine import Open
from argus.cases.model import Actor, Indicator, Member
from argus.cases.service import CaseService
from tests.integration.web.b2_support import BROWSERS, Watch, open_context
from tests.integration.web.b3_support import Live, World
from tests.integration.web.conftest import PASSWORD
from tests.integration.web.test_app_b3_browser import WCAG, live, person, sign_in_as
from tests.integration.web.test_queue_review_ar4 import bulk, lows, match, raise_it


def everything(case: object) -> str:
    """The incident page with every part on one page (the UI v2 keeps the old case page there)."""
    return f"/app/incidents/{case}?tab=all"


pytestmark = pytest.mark.integration
__all__ = ["live"]
PROBES = Path(__file__).parent / "probes"
SERVER = "77.221.155.150"
HOST = "10.0.0.1"
SHORTCUTS = "Single-key shortcuts (C, 1–5, N)"  # noqa: RUF001 - the box's label, with its en dash


def probe(name: str) -> str:
    """A function the page runs to read what it shows (tests/integration/web/probes/<name>.js)."""
    return (PROBES / f"{name}.js").read_text(encoding="utf-8").strip()


async def proposal(world: World, inv: uuid.UUID, outcome: str = "true_positive") -> int:
    """The AI investigator's proposal for an investigation at its current version."""
    async with world.owner.begin() as conn:
        made = (
            await conn.execute(
                text(
                    "INSERT INTO assessments (investigation_id, version, pack, dossier_hash,"
                    " view_hash, assessor, run_after, status, outcome, confidence, decided_by,"
                    " reasons, finished_at) SELECT :i, i.version, 'p', repeat('a', 64),"
                    " md5(CAST(:i AS text)) || md5(CAST(:i AS text)), 'agent@1', now(),"
                    " 'proposed', :o, 0.8, 'agent@1#m', '[\"It beacons.\"]'::jsonb, now()"
                    " FROM investigations i WHERE i.id = :i RETURNING id"
                ),
                {"i": inv, "o": outcome},
            )
        ).scalar_one()
    return int(made)


async def suggested_case(world: World, first: uuid.UUID, second: uuid.UUID) -> uuid.UUID:
    """A case ARGUS suggests from its own proposals over two investigations."""
    cause = await proposal(world, first)
    await proposal(world, second)
    async with world.runtime.begin() as conn:
        service = await CaseService.start(conn)
        applied = await service.open(
            Actor.argus("opener"),
            Open("Beaconing from two hostel laptops", "high", "proposal",
                 (Member(first, "proposal"), Member(second, "proposal")), suspected=True,
                 cause_assessment_id=cause),
        )  # fmt: skip
    return applied.case.id


@contextmanager
def api_as(live: Live, user: str = "mina") -> Iterator[httpx.Client]:
    with httpx.Client(base_url=live.url, headers={"Origin": live.url}) as http:
        made = http.post("/api/login", json={"username": user, "password": PASSWORD})
        assert made.status_code == 200, made.text
        http.headers["X-CSRF-Token"] = made.json()["csrf_token"]
        yield http


# --------------------------------------------------------------------------- the TA's walk


@pytest.mark.parametrize("name", BROWSERS)
async def test_the_ta_walks_the_queue_confirms_with_c_and_lands_on_the_next_with_n(
    live: Live, name: str
) -> None:
    from playwright.async_api import async_playwright

    world = live.world
    ids = world.investigations
    await suggested_case(world, ids[0], ids[1])
    async with async_playwright() as play:
        browser, _, page, watch = await person(play, name, live.url, "mina", "/app")
        await page.get_by_role(
            "heading", name="1. Possible incidents and incidents that need you"
        ).wait_for()
        first_case = page.get_by_test_id("queue-case").first
        await first_case.wait_for()
        assert "Beaconing from two hostel laptops" in await first_case.inner_text()
        stance = await first_case.get_by_test_id("queue-stance").inner_text()
        assert stance == "ARGUS's call: Real: act on it (80%)"
        assert "Possible incident" in await first_case.inner_text()
        assert (await page.title()) == "Home · ARGUS"
        headings = await page.locator("main h2").all_inner_texts()
        assert [h for h in headings if re.match(r"\d\. ", h)] == [
            "1. Possible incidents and incidents that need you",
            "2. Patterns ARGUS recommends closing",
            "3. Single investigations that need attention",
        ]
        # open the case's first investigation from the queue
        await first_case.get_by_role("link", name="Look at the first alert group").click()
        await page.wait_for_url(re.compile(r"/app/alert-groups/[0-9a-f-]{36}$"))
        first_id = page.url.rsplit("/", 1)[1]
        assert first_id in {str(ids[0]), str(ids[1])}
        second_id = str(ids[1]) if first_id == str(ids[0]) else str(ids[0])
        headline = page.get_by_test_id("verdict-headline")
        await headline.wait_for()
        assert await headline.inner_text() == "ARGUS's call: Real: act on it (80%)"
        await page.get_by_text(
            re.compile(r"\d+ more in the queue after this one\.")
        ).first.wait_for()
        # C confirms: the proposal is accepted
        await page.keyboard.press("c")
        saved = "Saved: you accepted ARGUS's call, Real: act on it."
        await page.get_by_text(saved).first.wait_for()
        async with world.runtime.connect() as conn:
            reviews = (
                await conn.execute(
                    text("SELECT outcome, assessment_id, user_id FROM review_events"
                         " WHERE investigation_id = :i AND action = 'reviewed'"),
                    {"i": first_id},
                )
            ).all()  # fmt: skip
        assert [(r.outcome, r.user_id) for r in reviews] == [
            ("true_positive", await world.user_id("mina"))
        ]
        assert reviews[0].assessment_id is not None  # accepted as a proposal, not a plain verdict
        # N lands on the next item of the queue: the case's other investigation
        await page.keyboard.press("n")
        await page.wait_for_url(re.compile(f"/app/alert-groups/{second_id}$"))
        await headline.wait_for()
        assert await headline.inner_text() == "ARGUS's call: Real: act on it (80%)"
        # the keys are not for the note: typing c, n and 5 there is typing
        note = page.get_by_label("Note")
        await note.click()
        await page.keyboard.type("c n 5")
        assert await note.input_value() == "c n 5"
        assert page.url.endswith(second_id)
        async with world.runtime.connect() as conn:
            count = await conn.scalar(
                text("SELECT count(*) FROM review_events WHERE investigation_id = :i"),
                {"i": second_id},
            )
        assert count == 0
        await note.fill("")
        # 4 chooses "Wrong alert" and the focus goes to Save decision
        await headline.click()
        await page.keyboard.press("4")
        assert (
            await page.locator(
                'form[aria-label="Your decision"] input[type="radio"]:checked'
            ).get_attribute("value")
            == "rule_false_positive"
        )
        await page.wait_for_function("document.activeElement?.textContent === 'Save decision'")
        await page.keyboard.press("Enter")
        await page.get_by_text("Saved: your decision.").first.wait_for()
        async with world.runtime.connect() as conn:
            outcomes = (
                await conn.execute(
                    text("SELECT outcome FROM review_events WHERE investigation_id = :i"
                         " AND action = 'reviewed'"),
                    {"i": second_id},
                )
            ).scalars().all()  # fmt: skip
        assert outcomes == ["rule_false_positive"]
        # N again: past the case, to a single investigation of the queue
        await page.keyboard.press("n")
        await page.wait_for_url(re.compile(r"/app/alert-groups/[0-9a-f-]{36}$"))
        assert page.url.rsplit("/", 1)[1] not in {first_id, second_id}
        assert await watch.violations(page) == []
        await browser.close()
    assert watch.errors == []


@pytest.mark.parametrize("name", BROWSERS)
async def test_the_keys_can_be_switched_off_and_a_reading_has_nothing_to_confirm(
    live: Live, name: str
) -> None:
    from playwright.async_api import async_playwright

    world = live.world
    inv = world.investigations[0]
    reasons = [
        {
            "answer": {"outcome": "true_positive", "confidence": 0.7, "explanation": "It beacons.",
                       "cites": ["every 300 s", "made up"]},
            "reading": {"kind": "citation", "checked": [True, False], "blocked": []},
        },
        "a cited fact is not in the item",
    ]  # fmt: skip
    async with world.owner.begin() as conn:
        await conn.execute(
            text("INSERT INTO assessments (investigation_id, version, pack, dossier_hash,"
                 " view_hash, assessor, run_after, status, reasons, finished_at) SELECT :i,"
                 " i.version, 'p', repeat('a', 64), repeat('b', 64), 'agent@1', now(),"
                 " 'no_decision', CAST(:r AS jsonb), now() FROM investigations i WHERE i.id = :i"),
            {"i": inv, "r": json.dumps(reasons)},
        )  # fmt: skip
    async with async_playwright() as play:
        browser, _, page, watch = await person(
            play, name, live.url, "mina", f"/app/alert-groups/{inv}"
        )
        headline = page.get_by_test_id("verdict-headline")
        await headline.wait_for()
        assert (
            await headline.inner_text()
            == "ARGUS leans to: Real: act on it (70%), but did not propose it"
        )
        assert await page.get_by_role("button", name=re.compile("^Accept ARGUS")).count() == 0
        await page.keyboard.press("c")  # nothing to accept: it says so and sends nothing
        await page.get_by_text("ARGUS made no call to accept here").first.wait_for()
        chosen = page.locator('form[aria-label="Your decision"] input[type="radio"]:checked')
        await page.get_by_label(SHORTCUTS).uncheck()
        await page.keyboard.press("1")
        assert await chosen.count() == 0
        await page.get_by_label(SHORTCUTS).check()
        await page.keyboard.press("1")
        assert await chosen.get_attribute("value") == "true_positive"
        assert await watch.violations(page) == []
        await browser.close()
    assert watch.errors == []


# --------------------------------------------------------------------------- the whole queue


async def api_json(live: Live, path: str, **params: Any) -> Any:
    with api_as(live) as http:
        got = http.get(path, params=params)
        assert got.status_code == 200, got.text
        return got.json()


@pytest.mark.parametrize("name", BROWSERS)
async def test_home_holds_the_whole_queue_in_order_and_its_lists_equal_the_apis(
    live: Live, name: str
) -> None:
    """A case someone owns with new work, more than twenty singles rated high or critical, a
    low-rated one ARGUS raised and one that changed since a notice: Home lists the owned case, puts
    the changed and the raised singles first, says how many there are in all, and its lists are the
    API's and the Inbox's in the same order (compared as lists, not as numbers)."""
    from playwright.async_api import async_playwright

    world = live.world
    low = await lows(world)
    raised, moved = low[0], low[1]
    await bulk(world, 30, "high", "h")
    await bulk(world, 12, "critical", "c")
    await raise_it(world, raised)
    notified = await world.open_case(1, title="A notified laptop", severity="medium",
                                     start=world.investigations.index(low[2]))  # fmt: skip
    owned_member = low[3]
    async with world.runtime.begin() as conn:
        await conn.execute(text("UPDATE investigations SET severity = 'high' WHERE id = :i"),
                           {"i": owned_member})  # fmt: skip
    owned = await world.open_case(1, title="Owned by Mina", severity="medium",
                                  start=world.investigations.index(owned_member))  # fmt: skip
    with api_as(live) as http:
        told = {"expected_version": 1, "told": "the warden", "how": "phone"}
        assert http.post(f"/api/v1/cases/{notified}/notices", json=told).status_code == 200
        assert (
            http.post(f"/api/v1/cases/{owned}/take", json={"expected_version": 1}).status_code
            == 200
        )
    await match(world, notified, moved, "changed")
    queue = await api_json(live, "/api/v1/queue")
    singles = [x["investigation"]["id"] for x in queue["singles"]]
    assert singles[:2] == [str(moved), str(raised)]
    assert len(singles) == 20
    inbox = await api_json(live, "/api/v1/investigations", view="attention", sort="queue",
                           limit=100)  # fmt: skip
    members = {str(r.investigation_id) for r in await world.rows(
        "SELECT investigation_id FROM case_members WHERE removed_at IS NULL")}  # fmt: skip
    assert [i["id"] for i in inbox["items"] if i["id"] not in members][:20] == singles
    async with async_playwright() as play:
        browser, _, page, watch = await person(play, name, live.url, "mina", "/app")
        await page.get_by_test_id("queue-single").first.wait_for()
        await page.get_by_test_id("queue-case").first.wait_for()
        # the numbers say everything, the lists say the first ones
        summary = await page.get_by_test_id("queue-summary").inner_text()
        assert summary == (
            f"{queue['cases_total']} cases and {queue['singles_total']} single investigations"
            f" need a person ({queue['order_total']} investigations to look at)."
        )
        assert queue["singles_total"] >= 44
        # the owned case is there, saying why: it holds new work although somebody owns it
        card = page.get_by_test_id("queue-case").filter(has_text="Owned by Mina")
        await card.wait_for()
        text_of_card = await card.inner_text()
        assert "New work in a worked case" in text_of_card
        assert "1 new investigation in a case someone owns." in text_of_card
        # the singles on the page are the API's, in the API's order
        hrefs = await page.get_by_test_id("queue-single").evaluate_all(
            "(items) => items.map((i) => i.querySelector('a').getAttribute('href'))"
        )
        assert hrefs == [f"/app/alert-groups/{i}" for i in singles]
        assert (
            await page.get_by_text(
                re.compile(rf"The 20 first of {queue['singles_total']} are shown\.")
            ).count()
            == 1
        )
        # the same cards are the case list's "queue" view
        cards = await page.get_by_test_id("queue-case").evaluate_all(
            "(items) => items.map((i) => i.querySelector('a').textContent)"
        )
        await page.get_by_role("link", name="These cases in the cases list").click()
        table = page.get_by_role("table", name="Cases")
        await table.get_by_role("link", name=re.compile("^Case ")).first.wait_for()
        assert page.url.endswith("/app/incidents?view=needs-you")
        listed = await table.get_by_role("link", name=re.compile("^Case ")).all_inner_texts()
        assert sorted(listed) == sorted(cards)
        # and the singles' link is the Inbox in the same order
        async with page.expect_response(
            re.compile(r"/api/v1/investigations\?.*sort=queue")
        ) as asked:
            await page.goto(f"{live.url}/app/search?advanced=1&view=attention&sort=queue")
        shown = (await (await asked.value).json())["items"]
        assert [i["id"] for i in shown if i["id"] not in members][:20] == singles
        assert await watch.violations(page) == []
        await browser.close()
    assert watch.errors == []


@pytest.mark.parametrize("name", BROWSERS)
async def test_the_end_of_the_walk_never_says_nothing_else_needs_a_person_while_more_do(
    live: Live, name: str
) -> None:
    from playwright.async_api import async_playwright

    world = live.world
    await bulk(world, 30, "critical", "c")
    queue = await api_json(live, "/api/v1/queue")
    assert queue["order_total"] > len(queue["order"])  # the walk is capped at the 20 singles
    last = queue["order"][-1]
    async with async_playwright() as play:
        browser, _, page, watch = await person(
            play, name, live.url, "mina", f"/app/alert-groups/{last}"
        )
        more = queue["order_total"] - len(queue["order"])
        walked = len(queue["order"])
        words = (
            f"This is the last of the {walked} most urgent; {more} more need a person in the Inbox."
        )
        await page.get_by_text(words).first.wait_for()
        await page.keyboard.press("n")
        await page.get_by_text(words.replace("This is", "That was")).first.wait_for()
        assert await page.get_by_text("nothing else needs a person").count() == 0
        await page.get_by_role("link", name="Open them in the Inbox").click()
        await page.wait_for_url(re.compile(r"/app/search\?advanced=1&view=attention&sort=queue"))
        assert await watch.violations(page) == []
        await browser.close()
    assert watch.errors == []


@pytest.mark.parametrize("name", BROWSERS)
async def test_confirm_keeps_what_the_form_holds_and_the_focus_goes_on(
    live: Live, name: str
) -> None:
    from playwright.async_api import async_playwright

    world = live.world
    ids = world.investigations
    await proposal(world, ids[0])
    await proposal(world, ids[1])
    async with async_playwright() as play:
        browser, _, page, watch = await person(
            play, name, live.url, "mina", f"/app/alert-groups/{ids[0]}"
        )
        headline = page.get_by_test_id("verdict-headline")
        await headline.wait_for()
        confirm = page.get_by_role("button", name="Accept ARGUS's call: Real: act on it")
        # another outcome chosen, a note written: accepting waits and says why; nothing is sent
        await page.get_by_role("radio", name=re.compile("Allowed by policy")).check(force=True)
        await page.get_by_label("Note").fill("a lab printer, says the lab")
        await page.get_by_test_id("confirm-hold").wait_for()
        assert await confirm.get_attribute("aria-disabled") == "true"
        await confirm.click(force=True)  # aria-disabled: Playwright waits for it otherwise
        async with world.runtime.connect() as conn:
            before = await conn.scalar(text("SELECT count(*) FROM review_events"))
        assert before == 0
        # Save decision saves the person's own choice and the note
        await page.get_by_role("button", name="Save decision", exact=True).click()
        await page.get_by_text("Saved: your decision.").first.wait_for()
        async with world.runtime.connect() as conn:
            saved = (
                await conn.execute(text("SELECT outcome, note, assessment_id FROM review_events"))
            ).all()
        assert [(r.outcome, r.note, r.assessment_id) for r in saved] == [
            ("benign_policy", "a lab printer, says the lab", None)]  # fmt: skip
        # the next one: Shift+C and a capital do nothing, C confirms, and the focus lands on Next
        await page.goto(f"{live.url}/app/alert-groups/{ids[1]}")
        await headline.wait_for()
        await page.get_by_role("button", name="Accept ARGUS's call: Real: act on it").wait_for()
        await page.keyboard.press("Shift+C")
        await page.keyboard.press("Shift+N")
        assert page.url.endswith(str(ids[1]))
        async with world.runtime.connect() as conn:
            assert await conn.scalar(text("SELECT count(*) FROM review_events")) == 1
        await page.keyboard.press("c")
        await page.get_by_text(
            "Saved: you accepted ARGUS's call, Real: act on it."
        ).first.wait_for()
        await page.wait_for_function(
            "() => document.activeElement !== document.body"
            " && (document.activeElement?.textContent?.startsWith('Next')"
            " || document.activeElement?.dataset.testid === 'verdict-headline')"
        )
        # ? lists the keys on this page
        await page.keyboard.press("?")
        keys = page.get_by_role("dialog", name="Keyboard shortcuts on an investigation")
        await keys.wait_for()
        assert "accept ARGUS's call" in await keys.inner_text()
        await page.keyboard.press("Escape")
        assert await watch.violations(page) == []
        await browser.close()
    assert watch.errors == []


@pytest.mark.parametrize("name", BROWSERS)
async def test_an_account_that_may_only_view_has_no_confirm_and_its_keys_do_nothing(
    live: Live, name: str
) -> None:
    from playwright.async_api import async_playwright

    world = live.world
    ids = world.investigations
    await proposal(world, ids[0])
    async with async_playwright() as play:
        browser, _, page, watch = await person(
            play, name, live.url, "vera", f"/app/alert-groups/{ids[0]}"
        )
        headline = page.get_by_test_id("verdict-headline")
        await headline.wait_for()
        assert await page.get_by_role("button", name=re.compile("^Accept ARGUS")).count() == 0
        await page.keyboard.press("4")
        await page.keyboard.press("c")
        body = await page.locator("body").inner_text()
        assert "Chosen:" not in body
        assert "no call to accept" not in body
        async with world.runtime.connect() as conn:
            assert await conn.scalar(text("SELECT count(*) FROM review_events")) == 0
        await browser.close()
    assert watch.errors == []


# --------------------------------------------------------------------------- a notified case


@pytest.mark.parametrize("name", BROWSERS)
async def test_the_notice_dialog_reads_the_time_in_ist_twelve_hour_form(
    live: Live, name: str
) -> None:
    from playwright.async_api import async_playwright

    world = live.world
    case = await world.open_case(1, title="Beaconing", indicators=(Indicator("ip", HOST, "actor"),))
    async with async_playwright() as play:
        browser, _, page, watch = await person(play, name, live.url, "mina", everything(case))
        section = page.get_by_role("region", name="Owner notified")
        await section.wait_for()
        await section.get_by_role("button", name="Record that the owner was told").click()
        await section.get_by_label(re.compile("^Who was told")).fill("Hostel 5 warden")
        await section.get_by_label("How").select_option("phone")
        await section.get_by_label(re.compile(r"^When \(IST\)")).fill("2026-10-26T19:20")
        await section.get_by_role("button", name="Review the request").click()
        dialog = page.get_by_role("alertdialog")
        await dialog.wait_for()
        assert "It is dated 26 Oct 2026, 7:20 PM IST." in await dialog.inner_text()
        shown = json.loads(await dialog.get_by_test_id("payload").text_content())
        assert shown["at"] == "2026-10-26T19:20:00+05:30"
        await dialog.get_by_role("button", name="Record the notice").click()
        await page.get_by_text("Recorded: the owner of case 1 was told.").first.wait_for()
        told = await section.get_by_test_id("notice").first.inner_text()
        assert "26 Oct 2026, 7:20 PM IST" in told
        assert await watch.violations(page) == []
        await browser.close()
    assert watch.errors == []


@pytest.mark.parametrize("name", BROWSERS)
async def test_a_notice_is_recorded_listed_blocked_downloaded_and_withdrawn(
    live: Live, name: str
) -> None:
    from playwright.async_api import async_playwright

    world = live.world
    case = await world.open_case(
        1, title="Beaconing from a hostel laptop", severity="medium",
        indicators=(Indicator("ip", HOST, "actor"), Indicator("ip", SERVER, "c2")),
    )  # fmt: skip
    async with async_playwright() as play:
        browser, _, page, watch = await person(play, name, live.url, "mina", everything(case))
        section = page.get_by_role("region", name="Owner notified")
        await section.wait_for()
        assert "Not told yet" in await section.get_by_test_id("managed-words").inner_text()
        # the form checks first and shows nothing until it is right
        await section.get_by_role("button", name="Record that the owner was told").click()
        await section.get_by_role("button", name="Review the request").click(force=True)
        await section.get_by_text("Choose how the owner was told.").first.wait_for()
        assert await page.get_by_role("alertdialog").count() == 0
        await section.get_by_label(re.compile("^Who was told")).fill("Hostel 5 warden")
        await section.get_by_label("How").select_option("phone")
        await section.get_by_role("button", name="Review the request").click()
        dialog = page.get_by_role("alertdialog")
        await dialog.wait_for()
        shown = json.loads(await dialog.get_by_test_id("payload").text_content())
        assert shown == {"expected_version": 1, "told": "Hostel 5 warden", "how": "phone"}
        await dialog.get_by_role("button", name="Record the notice").click()
        await page.get_by_text("Recorded: the owner of case 1 was told.").first.wait_for()
        assert await page.evaluate("document.activeElement?.id") == "case-title"
        # the section now says who was told, personal devices, and what ARGUS counts
        notice = section.get_by_test_id("notice").first
        await notice.wait_for()
        told = await notice.inner_text()
        assert "Owner told" in told
        assert "Hostel 5 warden (By phone)" in told
        assert "personal" in told
        words = await section.get_by_test_id("managed-words").inner_text()
        assert "Personal devices" in words
        assert "cannot wipe or isolate it" in words
        # the case is counted, not queued
        await page.goto(f"{live.url}/app")
        totals = page.get_by_test_id("totals")
        await page.wait_for_function(
            "() => { const t = document.querySelector(\"[data-testid='totals']\")?.textContent"
            " ?? ''; return t.includes('(1 case:') && !t.includes('…'); }"
        )
        assert (
            "Notified, still active: 0" in await totals.inner_text()
        )  # nothing of it is known yet
        assert await page.get_by_test_id("queue-case").count() == 0
        await page.get_by_role("link", name="the list").click()
        table = page.get_by_role("table", name="Cases")
        await table.get_by_role("link", name=re.compile("Case 1:")).wait_for()
        assert page.url.endswith("/app/incidents?view=owner-told")
        # a reminder is suggested by the pass; the person sees it and dismisses it
        async with world.runtime.begin() as conn:
            await conn.execute(
                text("INSERT INTO case_reminders (case_id, kind, why) VALUES (:c, 'notify_again',"
                     " 'Still active 7 days after the owner was told.')"),
                {"c": case},
            )  # fmt: skip
        await page.goto(f"{live.url}/app/incidents/{case}?tab=all")
        reminder = page.get_by_test_id("reminder")
        await reminder.wait_for()
        assert "Tell the owner again" in await reminder.inner_text()
        await reminder.get_by_role("button", name="Dismiss this reminder").click()
        await page.get_by_role("alertdialog").get_by_role("button", name="Dismiss").click()
        await page.get_by_text("Dismissed: ARGUS will not suggest it again.").first.wait_for()
        await page.get_by_text("None due.").first.wait_for()
        # a network block
        await section.get_by_role("button", name="Record a network block").click()
        await section.get_by_label("Who blocked it").fill("the network team")
        await section.get_by_label(re.compile("^Where")).fill("DNS")
        await section.get_by_role("button", name="Review the request").click()
        await page.get_by_role("alertdialog").get_by_role("button", name="Record the block").click()
        await page.get_by_text(
            "Recorded: the case 1 servers were blocked at the network."
        ).first.wait_for()
        await section.get_by_text("Blocked at the network").first.wait_for()
        # the block list: viewed, then downloaded as CSV and as text
        assert "1 entry ready." in await section.inner_text()
        await section.get_by_text("View the list").click()
        listing = section.get_by_role("table", name="Block list")
        await listing.wait_for()
        row = await listing.get_by_role("row").nth(1).inner_text()
        assert SERVER in row
        assert "no outside record yet" in row
        assert HOST not in await listing.inner_text()  # a campus device is never a block
        async with page.expect_download() as downloading:
            await section.get_by_role("link", name="Download as CSV").click()
        saved = await (await downloading.value).path()
        assert saved.read_bytes().startswith(
            b"\xef\xbb\xbf"
        )  # UTF-8 with a mark: Excel reads it right
        rows = list(csv.reader(io.StringIO(saved.read_text(encoding="utf-8-sig"))))
        assert rows[0][:2] == ["type", "value"]
        assert rows[1][:2] == ["address", SERVER]
        async with page.expect_download() as downloading_text:
            await section.get_by_role("link", name=re.compile("^Download as text")).click()
        mail = (await (await downloading_text.value).path()).read_text(encoding="utf-8")
        assert "To the head of cybersecurity," in mail
        assert SERVER in mail
        # a notice recorded by mistake is withdrawn, and the case is not notified any more
        await section.get_by_role("button", name="Withdraw a notice recorded by mistake").click()
        await section.get_by_label(re.compile("^Why it was a mistake")).fill("wrong case")
        await section.get_by_role("button", name="Review the request").click()
        await (
            page.get_by_role("alertdialog")
            .get_by_role("button", name="Withdraw the notice")
            .click()
        )
        await page.get_by_text("Withdrawn: case 1 is not notified any more.").first.wait_for()
        await section.get_by_text(
            "(withdrawn: recorded by mistake; kept as it was said)"
        ).first.wait_for()
        async with world.runtime.connect() as conn:
            gone = await conn.scalar(
                text("SELECT notified_at FROM cases WHERE id = :c"), {"c": case}
            )
        assert gone is None
        assert await watch.violations(page) == []
        await browser.close()
    assert watch.errors == []


@pytest.mark.parametrize("name", BROWSERS)
async def test_a_view_only_account_sees_why_it_may_not_record_a_notice(
    live: Live, name: str
) -> None:
    from playwright.async_api import async_playwright

    world = live.world
    case = await world.open_case(1, title="Beaconing", indicators=(Indicator("ip", HOST, "actor"),))
    async with async_playwright() as play:
        browser, _, page, watch = await person(play, name, live.url, "vera", everything(case))
        section = page.get_by_role("region", name="Owner notified")
        await section.wait_for()
        button = section.get_by_role("button", name="Record that the owner was told")
        assert await button.get_attribute("aria-disabled") == "true"
        assert "manage_cases" in await section.inner_text()
        await button.click(force=True)
        assert await section.get_by_label(re.compile("^Who was told")).count() == 0
        await browser.close()
    assert watch.errors == []


# --------------------------------------------------------------------------- the classic pages


async def notified_world(live: Live) -> uuid.UUID:
    """A notified case with known investigations (the owner was told; ARGUS counts them) and a
    change waiting, as the pass leaves them."""
    world = live.world
    with api_as(live) as http:
        listed = http.get("/api/v1/investigations", params={"view": "attention"})
        assert listed.status_code == 200, listed.text
        attention = [uuid.UUID(i["id"]) for i in listed.json()["items"]]
    assert len(attention) >= 3  # the seeded records have severe ones
    case = await world.open_case(
        1, title="A notified laptop", severity="medium",
        start=world.investigations.index(attention[0]),
        indicators=(Indicator("ip", HOST, "actor"), Indicator("ip", SERVER, "c2")),
    )  # fmt: skip
    with api_as(live) as http:
        done = http.post(
            f"/api/v1/cases/{case}/notices",
            json={"expected_version": 1, "told": "Hostel 5 warden", "how": "phone",
                  "at": datetime.now(UTC).isoformat()},
        )  # fmt: skip
        assert done.status_code == 200, done.text
    async with world.runtime.begin() as conn:
        for inv in attention[:2]:
            await conn.execute(
                text("INSERT INTO case_known_matches (investigation_id, case_id, version, outcome)"
                     " SELECT :i, :c, i.version, 'known' FROM investigations i WHERE i.id = :i"),
                {"i": inv, "c": case},
            )  # fmt: skip
        await conn.execute(
            text("INSERT INTO case_known_matches (investigation_id, case_id, version, outcome, why,"
                 " changed_version) SELECT :i, :c, i.version, 'changed', 'a new flagged"
                 " destination: 203.0.113.9', i.version FROM investigations i WHERE i.id = :i"),
            {"i": attention[2], "c": case},
        )  # fmt: skip
    return case


@pytest.mark.parametrize("name", BROWSERS)
async def test_the_dashboard_tile_and_the_counts_equal_the_classic_pages(
    live: Live, name: str
) -> None:
    from playwright.async_api import async_playwright

    await notified_world(live)
    async with async_playwright() as play:
        browser, _, page, watch = await person(play, name, live.url, "mina", "/app")
        await page.goto(f"{live.url}/dashboard?range=90d")
        classic = await page.evaluate(probe("ar4_classic_dashboard"))
        await page.goto(f"{live.url}/")
        summary = await page.evaluate(probe("ar4_classic_summary"))
        await page.goto(f"{live.url}/app/overview?range=90d")
        await page.locator("ul[aria-label='Key numbers'] li").first.wait_for()
        await page.get_by_role("table", name="Notified cases").wait_for()
        await page.wait_for_load_state("networkidle")
        app = await page.evaluate(probe("ar4_app_dashboard"))
        assert classic["tile"] == "2"  # the two investigations the notice covers
        assert app["tile"] == classic["tile"]
        assert app["attention"] == classic["attention"]
        assert "(1 case)" in classic["sub"]
        assert app["sub"] == classic["sub"]
        assert len(app["rows"]) == len(classic["rows"]) == 1
        # case, owner told (both pages write IST in 12-hour form), days, alerts since, alerts a
        # day, network block, suggestions
        mine, theirs = app["rows"][0], classic["rows"][0]
        assert mine[0].startswith("Case 1")
        assert theirs[0].startswith("Case 1")
        assert re.search(r"\d{1,2}:\d\d [AP]M IST$", mine[1]), mine[1]
        assert mine[1:] == theirs[1:]
        # Home's two numbers are the classic Inbox's summary line
        await page.goto(f"{live.url}/app")
        totals = page.get_by_test_id("totals")
        await totals.get_by_role("link", name=re.compile("^Needs attention")).wait_for()
        await page.wait_for_function(
            "() => !document.querySelector(\"[data-testid='totals']\").textContent.includes('…')"
        )
        line = await totals.inner_text()
        assert f"Needs attention: {summary['need attention']}" in line
        assert f"Notified, still active: {summary['notified, still active']}" in line
        # the tile's list is the Inbox's known view, and it holds the same investigations
        await page.goto(f"{live.url}/app/overview?range=90d")
        await page.locator(
            "ul[aria-label='Key numbers'] a", has_text="Notified, still active"
        ).click()
        await page.wait_for_url(re.compile(r"/app/search\?advanced=1&view=known"))
        grid = page.get_by_role("grid", name="Investigations")
        await grid.wait_for()
        assert int(await grid.get_attribute("aria-rowcount") or "0") - 1 == int(classic["tile"])
        assert await watch.violations(page) == []
        await browser.close()
    assert watch.errors == []


# --------------------------------------------------------------------------- accessibility


@pytest.mark.parametrize("name", BROWSERS)
async def test_axe_finds_nothing_serious_on_the_new_screens_light_dark_narrow_and_wide(
    live: Live, name: str
) -> None:
    from axe_playwright_python.async_playwright import Axe
    from playwright.async_api import async_playwright

    world = live.world
    ids = world.investigations
    await suggested_case(world, ids[4], ids[5])
    notified = await notified_world(live)
    async with world.runtime.begin() as conn:
        await conn.execute(
            text("INSERT INTO case_reminders (case_id, kind, why) VALUES (:c, 'notify_again',"
                 " 'Still active 7 days after the owner was told.')"),
            {"c": notified},
        )  # fmt: skip
    pages = [
        ("home", "/app", "queue"),
        ("investigation", f"/app/alert-groups/{ids[4]}", "card"),
        ("case, notified", f"/app/incidents/{notified}?tab=all", "notified"),
        ("cases, notified", "/app/incidents?view=owner-told", "cases"),
        ("dashboard", "/app/overview?range=90d", "dashboard"),
        ("inbox, known", "/app/search?advanced=1&view=known", "inbox"),
    ]
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
                await sign_in_as(page, live.url, "mina")
                for label, where, what in pages:
                    await page.goto(live.url + where)
                    await page.locator("main").wait_for()
                    if what == "queue":
                        await page.get_by_test_id("queue-case").first.wait_for()
                    elif what == "card":
                        await page.get_by_test_id("verdict-headline").wait_for()
                        await page.get_by_role(
                            "button", name=re.compile("^Accept ARGUS")
                        ).wait_for()
                    elif what == "notified":
                        section = page.get_by_role("region", name="Owner notified")
                        await section.wait_for()
                        await section.get_by_role("button", name="Record another notice").click()
                        await section.get_by_text("View the list").click()
                        await section.get_by_role("table", name="Block list").wait_for()
                    elif what == "cases":
                        await page.get_by_role("table", name="Cases").wait_for()
                    elif what == "dashboard":
                        await page.get_by_role("table", name="Notified cases").wait_for()
                    else:
                        await page.get_by_role("grid", name="Investigations").wait_for()
                    await page.wait_for_load_state("networkidle")
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
                assert await watch.violations(page) == [], (scheme, width)
                await browser.close()
    assert not problems, "\n".join(map(str, problems))
    assert watch.errors == []
