"""P4-B1 (D-270): Kibana sync reads the case team's cases back. A sync cycle over the team's fake
Kibana, with the mirror in Postgres (the runtime login): the posted case is mirrored and every
step explained by the step that wrote it; a person's title edit, close and delete reach the mirror
within one cycle and nothing is reverted; ARGUS's own retitle is explained; an action no step
explains is an alarm; a deleted case is never written to again and the verdict pass is not stopped
by it."""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.caseteam import store, verdicts
from argus.config.settings import CaseTeamSettings
from argus.kibana_sync.cycle import SyncConfig, Syncer
from argus.kibana_sync.store import PgSyncStore
from tests.integration.cases.conftest import Person
from tests.integration.caseteam.kit import Rig, a_case, rig, save_version
from tests.integration.caseteam.test_edits import NEW_TITLE, retitled

pytestmark = pytest.mark.integration
PERSON = "asha.k"


def syncer_for(r: Rig, app: AsyncEngine) -> Syncer:
    return Syncer(
        r.gateway,
        PgSyncStore(app),
        r.lane,
        es=None,
        config=SyncConfig(team=CaseTeamSettings().users()),
        clock=r.clock,
        sleep=r.clock.sleep,
    )


async def cycle(r: Rig, syncer: Syncer) -> Any:
    r.advance(600)
    record = await syncer.cycle(deadline=r.clock.now + timedelta(minutes=9))
    assert record.outcome == "complete", record.reason
    return record


async def posted(
    app: AsyncEngine, owner: AsyncEngine, writer: AsyncEngine, person: Person
) -> tuple[Rig, Syncer, uuid.UUID, str]:
    r = rig(owner, writer)
    case = await a_case(owner, app, person)
    assert (await r.run(case)).stopped is None
    [kibana_case] = r.kibana.team_cases()
    return r, syncer_for(r, app), case, str(kibana_case["id"])


async def findings(r: Rig) -> list[tuple[str, str | None]]:
    rows = await r.sql("SELECT kind, details ->> 'field' AS field FROM kibana_findings ORDER BY id")
    return [(x.kind, x.field) for x in rows]


async def mirror(r: Rig, case: uuid.UUID) -> Any:
    [row] = await r.sql("SELECT * FROM kibana_mirror WHERE case_id = :c", c=case)
    return row


async def test_a_posted_case_is_mirrored_and_every_step_is_explained(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, syncer, case, kid = await posted(app_engine, migrated_engine, writer_engine, people["asha"])

    await cycle(r, syncer)

    row = await mirror(r, case)
    assert (row.kibana_case_id, row.created_by, row.deleted_at) == (kid, "argus-lead", None)
    assert row.actions_seen == len(r.kibana.actions[kid])
    assert await findings(r) == [], "every action is an ARGUS identity's and a step explains it"
    assert row.argus_actions["argus-lead:create"] == 1
    assert row.paused_reason is None
    assert not (await r.lane.kibana_lane()).paused
    again = await cycle(r, syncer)
    assert again.changed == 0, "nothing changed: no user actions read again"


async def test_a_persons_edit_close_and_delete_are_in_arguss_record_within_a_cycle(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, syncer, case, kid = await posted(app_engine, migrated_engine, writer_engine, people["asha"])
    await cycle(r, syncer)

    r.kibana.set_field(kid, PERSON, "title", "Our own name for this")
    await cycle(r, syncer)
    row = await mirror(r, case)
    assert (row.title, "title" in row.unmanaged) == ("Our own name for this", True)
    assert await findings(r) == [("person_edited", "title")]

    r.kibana.set_status(kid, PERSON, "closed")
    await cycle(r, syncer)
    assert (await mirror(r, case)).status == "closed"
    assert [k for k, _ in await findings(r)] == ["person_edited", "closed_in_kibana"]

    # ARGUS goes on with the case and never reverts what the person did
    before = len(r.kibana.writes)
    r.advance(7 * 3600)
    await r.run(case)
    assert r.kibana.cases[kid]["title"] == "Our own name for this"
    assert r.kibana.cases[kid]["status"] == "closed"
    assert [w for w in r.kibana.writes[before:] if w.method == "PATCH"] == []

    r.kibana.delete(kid)
    await cycle(r, syncer)
    row = await mirror(r, case)
    assert row.deleted_at is not None
    assert [k for k, _ in await findings(r)][-1] == "deleted_in_kibana"
    async with r.engine.connect() as conn:
        assert await store.kibana_deleted_at(conn, case) == row.deleted_at


async def test_arguss_own_retitle_is_explained_by_its_step(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, syncer, case, kid = await posted(app_engine, migrated_engine, writer_engine, people["asha"])
    await cycle(r, syncer)
    await save_version(app_engine, case, retitled(NEW_TITLE))
    r.advance(180)
    assert (await r.run(case)).stopped is None
    assert r.kibana.cases[kid]["title"] == NEW_TITLE

    await cycle(r, syncer)

    row = await mirror(r, case)
    assert row.title == NEW_TITLE
    assert row.argus_actions["argus-lead:title"] == 1
    assert "title" not in row.unmanaged, "ARGUS's own retitle is not a person's"
    assert await findings(r) == []


async def test_an_action_no_step_explains_is_an_alarm(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, syncer, case, kid = await posted(app_engine, migrated_engine, writer_engine, people["asha"])
    await cycle(r, syncer)
    r.kibana.comment(kid, "argus-hunter", "a comment that no step wrote")
    await cycle(r, syncer)
    assert await findings(r) == [("unexplained_argus_action", None)]
    row = await mirror(r, case)
    assert row.unexplained == {"argus-hunter:comment": 1}
    assert (await r.lane.kibana_lane()).paused


async def test_a_case_is_found_before_the_poster_recorded_its_kibana_id(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    """The create landed and the run ended before the id was recorded: the incident ID among the
    tags and the open step that was sent are the link."""
    r, syncer, case, kid = await posted(app_engine, migrated_engine, writer_engine, people["asha"])
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE case_team_posts SET kibana_case_id = NULL WHERE case_id = :c"), {"c": case}
        )
    await cycle(r, syncer)
    assert (await mirror(r, case)).kibana_case_id == kid
    assert await findings(r) == []


async def test_a_team_case_with_no_post_is_an_alarm_and_never_adopted(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, syncer, _, _ = await posted(app_engine, migrated_engine, writer_engine, people["asha"])
    stray = r.kibana.create(by="argus-lead", tags=("ACME-IR-2026-1026-77", "incident"))
    await cycle(r, syncer)
    assert ("unexplained_argus_case", None) in await findings(r)
    assert await r.sql("SELECT 1 FROM kibana_mirror WHERE kibana_case_id = :k", k=stray) == []


async def test_the_steps_the_mirror_counts_are_the_case_teams_own(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    _, _, case, kid = await posted(app_engine, migrated_engine, writer_engine, people["asha"])
    sync_store = PgSyncStore(app_engine)
    writes = (await sync_store.sent_writes([case]))[case]
    by_op: dict[tuple[str, str], int] = {}
    for w in writes:
        by_op[(w.by, w.op)] = by_op.get((w.by, w.op), 0) + w.sent_count
    assert by_op[("argus-lead", "create")] == 1
    assert by_op[("argus-lead", "attach")] >= 1
    assert by_op[("argus-lead", "comment")] >= 1  # the verdict
    assert by_op[("argus-evidence", "comment")] >= 1
    assert by_op[("argus-reporter", "comment")] >= 1  # the files' comment and the files
    assert all(op != "tag" for _, op in by_op), "tagging alerts is no action on the case"
    [post] = await sync_store.team_posts([kid], [])
    assert (post.case_id, post.kibana_case_id, post.opens, post.opener) == (
        case,
        kid,
        1,
        "argus-lead",
    )
    assert await sync_store.team_posts(["nothing"], ["ACME-IR-0000-0000-00"]) == []


async def test_a_deleted_case_is_not_written_to_again_and_the_verdict_pass_goes_on(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r, syncer, case, kid = await posted(app_engine, migrated_engine, writer_engine, people["asha"])
    await cycle(r, syncer)
    r.kibana.delete(kid)
    await cycle(r, syncer)
    assert (await mirror(r, case)).deleted_at is not None

    # a newer report would be an update; the poster leaves the case alone
    await save_version(app_engine, case, retitled("A title after the deletion"))
    r.advance(7 * 3600)
    async with r.engine.connect() as conn:
        assert case not in await store.candidates(conn, 40)
    writes = len(r.kibana.writes)
    reports = await r.poster.run_pass()
    assert all(rep.case_id != case for rep in reports)
    assert len(r.kibana.writes) == writes

    # the verdict pass does not ask Kibana for a case that is gone, so it is not stopped by it
    r.healthy()
    asked = len(r.kibana.requests)
    report = await verdicts.read_all(app_engine, r.gateway, clock=r.clock)
    assert report.stopped is None
    assert not [w for w in r.kibana.requests[asked:] if f"/cases/{kid}" in w.path]
