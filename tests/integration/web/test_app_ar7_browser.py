"""AR7's browser gate (D-190) on the real server (``argus web`` as a process on the web's own
database login, throwaway database), in Chromium and Firefox:

- a TA's walk: open the case, read the report (summary and verdict first; every evidence line has
  its query and a Discover link that opens read-only in a new tab), reject it with a reason in the
  form and its exact request, and see the decision recorded on the page and as labels in the
  database (the review path), with nothing closed and no policy violation on the way;
- axe with the WCAG 2.2 rules on the report, light and dark, at 320, 390 and 1440 px, with the
  reject form open: 0 serious or critical, and no page scrolls sideways at 320 or 390 px.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

import pytest

from tests.integration.incident import kit
from tests.integration.web.b2_support import BROWSERS, Watch, open_context
from tests.integration.web.b3_support import Live
from tests.integration.web.test_app_ar4_browser import api_as
from tests.integration.web.test_app_b3_browser import WCAG, live, person, sign_in_as
from tests.integration.web.test_incident_report_ar7 import a_case, write_report


def everything(case: object) -> str:
    """The incident page with every part on one page (the UI v2 keeps the old case page there)."""
    return f"/app/incidents/{case}?tab=all"


pytestmark = pytest.mark.integration
__all__ = ["live"]
REASON = "It is the department's backup tool; the vendor confirmed it."


@pytest.mark.parametrize("name", BROWSERS)
async def test_a_ta_reads_the_report_and_rejects_it_with_a_reason(live: Live, name: str) -> None:
    from playwright.async_api import async_playwright

    world = live.world
    case = await a_case(world, 3)
    await kit.pair_evidence(
        world.owner, world.investigations[0], "77.221.155.150", 42, datetime.now(UTC)
    )
    await write_report(world, case)
    async with async_playwright() as play:
        browser, _, page, watch = await person(play, name, live.url, "mina", everything(case))
        region = page.get_by_role("region", name="Report")
        await region.wait_for()
        assert (await page.title()).startswith("Incident")
        headline = await region.get_by_test_id("report-headline").inner_text()
        # the state and ARGUS's call apart (P4-F U3)
        assert headline.startswith("Open · ARGUS's call: Real: act on it")
        assert "Real: act on it" in await region.get_by_test_id("verdict-line").inner_text()
        assert (await region.get_by_test_id("incident-id").inner_text()).startswith("ACME-IR-")

        # the summary and the verdict come before the decision, which comes before the parts
        names = await page.evaluate(
            "() => Array.from(document.querySelectorAll('#report [role=group], #report details"
            " summary')).map((e) => e.getAttribute('aria-label') || e.textContent.trim())"
        )
        assert names[:3] == ["Report summary", "ARGUS's call", "Your decision"]
        assert names[3:5] == ["Timeline", "Actors and roles"]

        # every evidence line: the exact query and a read-only link into Discover, in a new tab
        lines = region.get_by_test_id("evidence-line")
        assert await lines.count() >= 2
        for n in range(await lines.count()):
            link = lines.nth(n).get_by_role("link", name=re.compile("Open this query"))
            assert re.match(r"https://", await link.get_attribute("href") or "")
            assert await link.get_attribute("target") == "_blank"
            assert await link.get_attribute("rel") == "noopener noreferrer"
        assert "FROM acme-logs-squid-*" in await region.inner_text()

        # Reject with a reason: the form, the exact request, then it is recorded
        await region.get_by_role("button", name="Reject with a reason…").click()
        review = region.get_by_role("button", name="Review the request")
        assert await review.get_attribute("aria-disabled") == "true"  # nothing to send yet
        await region.get_by_text("Choose the outcome you hold instead.").wait_for()
        await region.get_by_label("What it is instead").select_option("benign_expected")
        await region.get_by_label(re.compile("^Why the report is wrong")).fill(REASON)
        await region.get_by_role("button", name="Review the request").click()
        dialog = page.get_by_role("alertdialog")
        await dialog.wait_for()
        assert f"POST/api/v1/cases/{case}/report/reject" in (
            await dialog.text_content() or ""
        ).replace("\n", "")
        assert REASON in await dialog.get_by_test_id("payload").text_content()
        await dialog.get_by_role("button", name="Reject with this reason").click()
        await dialog.wait_for(state="detached")
        line = await region.get_by_test_id("decision-line").inner_text()
        assert "Rejected by Mina Manager" in line
        assert REASON in line
        assert "3 investigations labelled" in line
        assert await watch.violations(page) == []
        await browser.close()
    assert watch.errors == []

    labels = await world.rows(
        "SELECT r.outcome, r.note FROM review_events r JOIN case_members m"
        " ON m.investigation_id = r.investigation_id WHERE m.case_id = :c",
        c=case,
    )
    assert [r.outcome for r in labels] == ["benign_expected"] * 3
    assert all(REASON in r.note for r in labels)
    (state,) = await world.rows("SELECT state FROM cases WHERE id = :c", c=case)
    assert state.state == "open"  # nothing was closed
    assert await world.rows("SELECT id FROM approval_requests WHERE case_id = :c", c=case) == []
    with api_as(live) as http:
        shown = http.get(f"/api/v1/cases/{case}/report").json()
    assert shown["decision"]["decision"] == "rejected"
    assert shown["decision"]["reason"] == REASON


@pytest.mark.parametrize("name", BROWSERS)
async def test_axe_finds_nothing_serious_on_the_report_light_dark_narrow_and_wide(
    live: Live, name: str
) -> None:
    from axe_playwright_python.async_playwright import Axe
    from playwright.async_api import async_playwright

    world = live.world
    case = await a_case(world, 3)
    await kit.pair_evidence(
        world.owner, world.investigations[0], "77.221.155.150", 42, datetime.now(UTC)
    )
    await write_report(world, case)
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
                await page.goto(f"{live.url}/app/incidents/{case}?tab=all")
                region = page.get_by_role("region", name="Report")
                await region.wait_for()
                await region.get_by_test_id("evidence-line").first.wait_for()
                await region.get_by_role("button", name="Reject with a reason…").click()
                await region.get_by_label("What it is instead").wait_for()
                await page.wait_for_load_state("networkidle")
                await page.evaluate(
                    "() => document.querySelectorAll('details').forEach((d) => { d.open = true; })"
                )
                report = await axe.run(page, options={"runOnly": {"type": "tag", "values": WCAG}})
                ran = {
                    r["id"]
                    for kind in ("passes", "incomplete", "violations")
                    for r in report.response.get(kind, [])
                }
                assert {"color-contrast", "target-size", "label"} & ran, ran
                problems += [
                    (scheme, width, v["id"], [n["target"] for n in v["nodes"]][:4])
                    for v in report.response["violations"]
                    if v["impact"] in ("serious", "critical")
                ]
                if width <= 390:  # no page scrolls sideways at phone width, nor at 320 px
                    wide = await page.evaluate(
                        "document.documentElement.scrollWidth"
                        " - document.documentElement.clientWidth"
                    )
                    assert wide <= 0, (scheme, width, wide)
                assert await watch.violations(page) == [], (scheme, width)
                await browser.close()
    assert not problems, "\n".join(map(str, problems))
    assert watch.errors == []
