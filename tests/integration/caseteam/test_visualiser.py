"""AR10, D-250: the seventh user, ``argus-visualiser``, is optional. Without its key the glance is
skipped (the reason in the step, not a failure and not a hold) and the rest of the case is posted
as ever; once the key is installed a later round brings the glance as a first one."""

from __future__ import annotations

from dataclasses import replace

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.caseteam.sender import ALL_USERS, Poster
from tests.integration.cases.conftest import VERIFIER, Person
from tests.integration.caseteam.kit import CONFIG, Rig, a_case, rig, save_version
from tests.integration.caseteam.test_updates import newer

pytestmark = pytest.mark.integration
GLANCE = "comment:glance:1"
WITHOUT = replace(CONFIG, keys=frozenset(ALL_USERS - {"argus-visualiser"}))
SIX = ["argus-evidence", "argus-evidence", "argus-intel", "argus-responder", "argus-hunter"]


async def glance_rows(r: Rig, case: object) -> list[tuple[int, str, str | None]]:
    rows = await r.sql(
        "SELECT gen, state, state_reason FROM case_team_steps WHERE key = :k AND case_id = :c"
        " ORDER BY id",
        k=GLANCE,
        c=case,
    )
    return [(x.gen, x.state, x.state_reason) for x in rows]


async def test_without_the_key_the_glance_is_skipped_and_the_case_is_posted_whole(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine, config=WITHOUT)
    case = await a_case(migrated_engine, app_engine, people["asha"])

    prep = await r.prepared(case)
    assert prep.problems == []  # a missing seventh key stops nothing
    assert any("skipped: no visualiser key" in note for note in prep.notes), prep.notes
    assert prep.plan is not None
    assert [s.part for s in prep.plan.steps].count("glance") == 1  # the plan is key-independent

    report = await r.run(case)
    assert report.stopped is None, report.lines()
    assert report.held == []
    assert "no visualiser key" in (report.note or "")
    assert await glance_rows(r, case) == [(1, "skipped", "no visualiser key")]
    states = await r.states(case)
    assert set(states) == {"verified", "skipped"}
    assert states["skipped"] == 1

    [kibana_case] = r.kibana.team_cases()
    users = [u for u, _ in r.kibana.user_comments(kibana_case["id"])]
    assert users == [*SIX, "argus-reporter", "argus-lead"]
    assert all(user != "argus-visualiser" for user, _ in r.kibana.by_user)
    [post] = await r.sql(
        "SELECT state, held_reason FROM case_team_posts WHERE case_id = :c", c=case
    )
    assert post.state == "active"
    assert post.held_reason is None

    writes = len(r.kibana.writes)
    again = await r.run(case)
    assert again.sent == 0
    assert len(r.kibana.writes) == writes


async def test_a_round_without_the_key_does_not_plan_the_glance_at_all(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine, config=WITHOUT)
    case = await a_case(migrated_engine, app_engine, people["asha"])
    assert (await r.run(case)).stopped is None
    await save_version(app_engine, case, newer)
    r.advance(7 * 3600)
    report = await r.run(case)
    assert report.decision.action == "update", report.lines()
    assert report.stopped is None, report.lines()
    assert await glance_rows(r, case) == [(1, "skipped", "no visualiser key")]  # no new row
    [kibana_case] = r.kibana.team_cases()
    fresh = r.kibana.user_comments(kibana_case["id"])[len(SIX) + 2 :]
    assert [u for u, _ in fresh] == ["argus-evidence", "argus-reporter", "argus-lead"]


async def test_once_the_key_is_installed_the_next_round_brings_the_glance_as_a_first_one(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine, config=WITHOUT)
    case = await a_case(migrated_engine, app_engine, people["asha"])
    assert (await r.run(case)).stopped is None
    with_key = Poster(
        writer_engine,
        r.gateway,
        CONFIG,
        verifier=VERIFIER,
        clock=r.clock,
        sleep=r.clock.sleep,
        wait_for_gaps=True,
    )
    await save_version(app_engine, case, newer)
    r.advance(7 * 3600)
    r.healthy()
    report = await with_key.run_case(case)
    assert report.stopped is None, report.lines()
    [kibana_case] = r.kibana.team_cases()
    comments = r.kibana.user_comments(kibana_case["id"])
    by_visualiser = [text for user, text in comments if user == "argus-visualiser"]
    assert len(by_visualiser) == 1
    assert by_visualiser[0].startswith("## Incident at a glance\n")  # not "Update: ..."
    assert by_visualiser[0].count("!{lens{") == 4
    rows = await glance_rows(r, case)
    assert rows[0] == (1, "skipped", "no visualiser key")
    assert rows[1][1] == "verified"
