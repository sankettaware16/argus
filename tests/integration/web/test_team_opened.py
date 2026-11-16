"""D-322: a case the case team opened in Kibana stops waiting for Kibana. Case 8 kept "Waiting for
someone who may open cases in Kibana" after the team opened it and posted its updates: the wait
was cleared only by a person's ``Publish``, and the pages knew only ARGUS's own Kibana create."""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import machine
from argus.cases.model import WAITING_FOR_KIBANA
from argus.cases.service import CaseService
from argus.caseteam import opened
from argus.web import needsyou
from tests.integration.web.b3_support import V1, World, make_world, sign_in

pytestmark = pytest.mark.integration


@pytest.fixture
async def world(
    seeded: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> World:
    return await make_world(seeded, web_engine, migrated_engine, tmp_path)


async def post(world: World, case: uuid.UUID, ir: str, kibana_case_id: str | None) -> None:
    """The case team's post as its writer leaves it (the owner writes it here)."""
    async with world.owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO case_team_posts (case_id, incident_id, kibana_case_id, opened_at)"
                " VALUES (:c, :i, :k, CASE WHEN CAST(:k AS text) IS NULL THEN NULL ELSE now() END)"
            ),
            {"c": case, "i": ir, "k": kibana_case_id},
        )


async def page(world: World, case: uuid.UUID) -> dict[str, Any]:
    async with world.app() as http:
        await sign_in(http, "mina")
        got = await http.get(f"{V1}/cases/{case}")
        assert got.status_code == 200, got.text
        found: dict[str, Any] = got.json()
        return found


async def listed(world: World, **params: str) -> list[str]:
    async with world.app() as http:
        await sign_in(http, "mina")
        got = await http.get(f"{V1}/cases", params={"view": "all", **params})
        assert got.status_code == 200, got.text
        return [c["id"] for c in got.json()["items"]]


async def held(world: World) -> int:
    async with world.app() as http:
        await sign_in(http, "vera")
        return int((await http.get(f"{V1}/health")).json()["case_team"]["held"])


async def test_the_case_teams_kibana_case_ends_the_wait_everywhere(world: World) -> None:
    case = await world.open_case(1, start=6)  # confirmed; nobody who may open it in Kibana
    still = await world.open_case(1, start=7)  # posted, its create not read back yet
    await post(world, case, "SOC-IR-2026-1107-01", "k-team-1")
    await post(world, still, "SOC-IR-2026-1107-02", None)
    # the pages know the team's case before ARGUS records it on the case
    before = await page(world, case)
    assert before["case"]["in_kibana"] is True
    assert before["mirror"]["state"] == "mirrored"
    assert "SOC-IR-2026-1107-01" in before["mirror"]["words"]
    assert before["mirror"]["kibana_case_id"] == "k-team-1"
    assert set(await listed(world, kibana="in")) == {str(case)}
    assert (await page(world, still))["case"]["in_kibana"] is False
    assert set(await listed(world, kibana="waiting")) == {str(still)}
    assert await held(world) == 1

    done = await opened.clear_waits(world.runtime)
    numbers = {r.id: r.number for r in await world.rows("SELECT id, number FROM cases")}
    assert (done.recorded, done.skipped) == ([numbers[case]], [])
    assert done.lines() == [f"case team: recorded its Kibana case on case(s) {numbers[case]}"]
    after = await page(world, case)
    assert after["case"]["kibana_wait"] is None
    assert after["case"]["in_kibana"] is True
    said = [h["text"] for h in after["history"] if "Kibana" in h["text"]]
    assert said == ["The case team opened the case in Kibana as SOC-IR-2026-1107-01"]
    assert set(await listed(world, kibana="waiting")) == {str(still)}
    assert await held(world) == 1
    other = await page(world, still)
    assert (other["case"]["kibana_wait"], other["mirror"]["state"]) == (
        WAITING_FOR_KIBANA, "waiting",
    )  # fmt: skip
    # the case's history replays to the stored case (the event carries the change)
    async with world.runtime.connect() as conn:
        service = await CaseService.start(conn)
        stored = await service.get(case)
        events = await service.events(case)
    assert stored is not None
    assert machine.same_case(machine.replay(events), stored)
    assert [(e.kind, e.details.get("by")) for e in events][-1] == ("published", "case_team")
    # once more: nothing waits that the team opened
    again = await opened.clear_waits(world.runtime)
    assert (again.recorded, again.skipped) == ([], [])


async def test_one_predicate_says_in_kibana_for_every_page(world: World) -> None:
    """Today's cards, the case list and the reports list share ``needsyou.IN_KIBANA``: ARGUS's
    own create planned, or the team's case read back; a post still on its way is neither."""
    ours = await world.open_case(1, start=5, kibana=True)
    team = await world.open_case(1, start=6)
    sent = await world.open_case(1, start=7)
    await post(world, team, "SOC-IR-2026-1107-03", "k-team-3")
    await post(world, sent, "SOC-IR-2026-1107-04", None)
    found = {
        r.id: r.in_kibana
        for r in await world.rows(f"SELECT c.id, {needsyou.IN_KIBANA} AS in_kibana FROM cases c")  # noqa: S608
    }
    assert (found[ours], found[team], found[sent]) == (True, True, False)
