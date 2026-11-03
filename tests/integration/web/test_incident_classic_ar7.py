"""The classic pages' read-only view of the incident report (AR7, D-190): a signed-in viewer reads
it (summary, verdict, each part, every evidence line's query and a Discover link that opens in a
new tab); it holds no form, no button and nothing that changes a case; the classic investigation
page links to it; a missing case or version is a 404 page; a signed-out request goes to sign-in."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.web.b3_support import World, make_world, sign_in
from tests.integration.web.test_incident_report_ar7 import a_case, write_report

pytestmark = pytest.mark.integration


@pytest.fixture
async def world(
    seeded: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> World:
    return await make_world(seeded, web_engine, migrated_engine, tmp_path)


async def test_a_viewer_reads_the_report_on_a_classic_page_and_nothing_there_changes_anything(
    world: World,
) -> None:
    case = await a_case(world, 2)
    await write_report(world, case)
    async with world.app() as http:
        await sign_in(http, "mina")
        found = await http.get(f"/cases/{case}/report")
        assert found.status_code == 200
        html = found.text
        assert re.search(r"<h1>Incident report ACME-IR-\d{4}-\d{4}-\d{2}</h1>", html)
        for heading in (
            "Summary", "ARGUS's verdict", "Timeline (IST)", "Actors and roles", "Affected assets",
            "Evidence", "Hypotheses", "Indicators", "Recommended actions", "Queries to verify",
            "Scope and limits",
        ):  # fmt: skip
            assert f"<h2>{heading}</h2>" in html
        assert "A true positive" in html
        assert "the AI investigator" in html
        assert 'target="_blank" rel="noopener noreferrer"' in html
        assert "https://" in html
        assert "FROM .alerts-security.alerts-" in html
        main = html.split("<main", 1)[1]
        assert "<form" not in main
        assert "<button" not in main
        assert "confirm or reject it, open the case in the new app" in html
        assert f"/api/v1/cases/{case}/report/files/indicators.csv" in html
        newer = await http.get(f"/cases/{case}/report", params={"version": 9})
        assert newer.status_code == 404
        assert "No such case, or no such version" in newer.text
        none = await http.get("/cases/00000000-0000-4000-8000-000000000000/report")
        assert none.status_code == 404


async def test_the_classic_investigation_page_links_to_the_report_of_its_case(
    world: World,
) -> None:
    case = await a_case(world, 2)
    inv = world.investigations[0]
    async with world.app() as http:
        await sign_in(http, "mina")
        before = await http.get(f"/investigations/{inv}")
        assert before.status_code == 200
        assert "incident report of case" not in before.text
        await write_report(world, case)
        after = await http.get(f"/investigations/{inv}")
    assert after.status_code == 200
    assert f'<a href="/cases/{case}/report">read it</a>' in after.text
    assert "ARGUS has written the incident report of case" in after.text


async def test_a_signed_out_request_goes_to_sign_in(world: World) -> None:
    case = await a_case(world, 1)
    await write_report(world, case)
    async with world.app() as http:
        out = await http.get(f"/cases/{case}/report", follow_redirects=False)
    assert out.status_code in (303, 401)
    if out.status_code == 303:
        assert out.headers["location"].startswith("/signin")
