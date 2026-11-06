"""AR8's browser gate (D-195) on the real server (``argus web`` as a process on the web's own
database login, throwaway database), in Chromium and Firefox:

- a TA's walk: open the case, read the Kibana case preview (posting is off: a dry run; the six
  users' steps in order, the lead's verdict last), open a step to its exact comment and request,
  and see that nothing was written; an approver confirms it is them on the server's own page, comes
  back to the case, reads the exact request, approves exactly the plan they read (signed, and the
  writer's check accepts it), and the page says so;
- axe with the WCAG 2.2 rules on the preview, light and dark, at 320, 390 and 1440 px, with every
  step open and the approval box shown: 0 serious or critical, and no page scrolls sideways at 320
  or 390 px.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

import pytest

from argus.cases import signing
from argus.caseteam import approvals
from tests.integration.incident import kit
from tests.integration.web.b2_support import BROWSERS, Watch, open_context
from tests.integration.web.b3_support import PASSWORD, Live
from tests.integration.web.test_app_b3_browser import WCAG, live, person, sign_in_as
from tests.integration.web.test_incident_report_ar7 import a_case, write_report


def everything(case: object) -> str:
    """The incident page with every part on one page (the UI v2 keeps the old case page there)."""
    return f"/app/incidents/{case}?tab=all"


pytestmark = pytest.mark.integration
__all__ = ["live"]


async def a_reported_case(live: Live) -> Any:
    world = live.world
    case = await a_case(world, 3)
    await kit.pair_evidence(
        world.owner, world.investigations[0], "77.221.155.150", 42, datetime.now(UTC)
    )
    await write_report(world, case)
    return case


@pytest.mark.parametrize("name", BROWSERS)
async def test_a_ta_reads_the_preview_and_an_approver_approves_exactly_what_they_read(
    live: Live, name: str
) -> None:
    from playwright.async_api import async_playwright

    world = live.world
    case = await a_reported_case(live)
    async with async_playwright() as play:
        browser, _, page, watch = await person(play, name, live.url, "mina", everything(case))
        region = page.get_by_role("region", name="Kibana case preview")
        await region.wait_for()
        assert (await page.title()).startswith("Incident")
        decision = await region.get_by_test_id("team-decision").inner_text()
        assert "Posting is off: a dry run" in decision
        assert "ACME-IR-" in decision
        assert "from report version 1" in decision

        # the steps in the fixed order, each by its own Kibana user; the lead's verdict is last
        steps = region.get_by_test_id("team-step")
        count = await steps.count()
        assert count >= 8
        authors = [
            await steps.nth(n).locator("summary span").nth(1).inner_text() for n in range(count)
        ]
        assert authors[0] == "argus-lead"
        assert authors[-1] == "argus-lead"
        assert "argus-evidence" in authors
        assert "argus-hunter" in authors
        assert authors.count("argus-reporter") == 5  # the four files and the comment listing them
        assert authors.index("argus-evidence") < authors.index("argus-visualiser")
        assert authors.index("argus-visualiser") < authors.index("argus-hunter")
        assert (
            authors.index("argus-evidence")
            < authors.index("argus-hunter")
            < authors.index("argus-reporter")
        )
        assert "the lead's verdict is last" in await region.inner_text()

        # a step opens to the exact comment and request; a file is its name and hash, not its bytes
        evidence = steps.filter(has_text="comments (evidence)").first
        await evidence.locator("summary").click()
        text = await evidence.get_by_test_id("team-text").inner_text()
        assert text.startswith("## Evidence")
        request = await evidence.get_by_test_id("team-request").inner_text()
        assert request.startswith("POST /s/acme-soc/api/cases/NEWCASE/comments")
        pdf = steps.filter(has_text="Incident_Report").first
        await pdf.locator("summary").click()
        assert "multipart/form-data" in await pdf.get_by_test_id("team-request").inner_text()
        assert await pdf.get_by_test_id("team-text").count() == 0
        verdict = steps.last
        await verdict.locator("summary").click()
        assert (await verdict.get_by_test_id("team-text").inner_text()).endswith(
            "Confirm or reject in a comment."
        )

        # a manager may not approve; the page says why and does nothing
        box = region.get_by_test_id("team-approval")
        await box.wait_for()
        button = box.get_by_role("button", name="Approve these steps")
        assert await button.get_attribute("aria-disabled") == "true"
        assert "approve capability" in await box.inner_text()
        assert await watch.violations(page) == []

        # an approver: confirm it is them, back to the case, read the request, approve
        browser2, _, omar, watch2 = await person(play, name, live.url, "omar", everything(case))
        box2 = omar.get_by_role("region", name="Kibana case preview").get_by_test_id(
            "team-approval"
        )
        await box2.wait_for()
        assert (
            await box2.get_by_role("button", name="Approve these steps").get_attribute(
                "aria-disabled"
            )
            == "true"
        )
        await box2.get_by_role("link", name="Confirm it is you").click()
        await omar.wait_for_url(re.compile(r"/stepup\?next="))
        await omar.fill("#password", PASSWORD)
        async with omar.expect_navigation(
            url=re.compile(rf"{re.escape(live.url)}/app/incidents/{case}\?tab=all")
        ):
            await omar.click("button[type=submit]")
        box2 = omar.get_by_role("region", name="Kibana case preview").get_by_test_id(
            "team-approval"
        )
        await box2.wait_for()
        approve = box2.get_by_role("button", name="Approve these steps")
        await approve.click()
        dialog = omar.get_by_role("alertdialog")
        await dialog.wait_for()
        assert f"POST/api/v1/cases/{case}/team/approve" in (
            await dialog.text_content() or ""
        ).replace("\n", "")
        shown = json.loads(await dialog.get_by_test_id("payload").text_content())
        assert re.fullmatch(r"[0-9a-f]{64}", shown["plan_hash"])
        await dialog.get_by_role("button", name="Approve these steps").click()
        await dialog.wait_for(state="detached")
        await (
            omar.get_by_role("region", name="Kibana case preview")
            .get_by_test_id("team-approved")
            .wait_for()
        )
        assert await watch.violations(page) == []
        assert await watch2.violations(omar) == []
        await browser.close()
        await browser2.close()
    assert watch.errors == []
    assert watch2.errors == []

    # recorded and signed; the writer's check accepts it for that plan and no other
    [row] = await world.rows(
        "SELECT plan_hash, approver_user_id, signature FROM case_team_approvals WHERE case_id = :c",
        c=case,
    )
    assert row.plan_hash == shown["plan_hash"]
    assert row.approver_user_id == await world.user_id("omar")
    verifier = signing.Verifier([signing.load_key(world.key_file)])
    async with world.runtime.connect() as conn:
        assert (
            await approvals.problem(conn, verifier, case, row.plan_hash, datetime.now(UTC)) is None
        )
        other = await approvals.problem(conn, verifier, case, "0" * 64, datetime.now(UTC))
        assert other == "no person has approved this plan yet"
    # looking and approving wrote nothing to Kibana's side: no post, no step
    assert await world.rows("SELECT 1 FROM case_team_posts") == []
    assert await world.rows("SELECT 1 FROM case_team_steps") == []


@pytest.mark.parametrize("name", BROWSERS)
async def test_axe_finds_nothing_serious_on_the_preview_light_dark_narrow_and_wide(
    live: Live, name: str
) -> None:
    from axe_playwright_python.async_playwright import Axe
    from playwright.async_api import async_playwright

    case = await a_reported_case(live)
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
                region = page.get_by_role("region", name="Kibana case preview")
                await region.wait_for()
                await region.get_by_test_id("team-step").first.wait_for()
                await region.get_by_test_id("team-approval").wait_for()
                await page.wait_for_load_state("networkidle")
                await page.evaluate(
                    "() => document.querySelectorAll('#kibana-case details')"
                    ".forEach((d) => { d.open = true; })"
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
