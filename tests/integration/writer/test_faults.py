"""Q-D4: what the writer does with each answer Kibana can give to a write. Nothing is sent
twice: a 409 is "not changed" and a person decides; a refusal pauses the row; a 5xx is in doubt;
a read-back that does not match pauses the class; a 401 stops Kibana."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.machine import Take
from tests.integration.cases.conftest import Person
from tests.integration.cases.test_service import _apply, _kibana_actor
from tests.integration.writer.fake import Fault, patches, posts
from tests.integration.writer.kit import created, mirrored_case, rig

pytestmark = pytest.mark.integration


async def test_a_409_storm_sends_each_change_once_and_leaves_the_rest_to_people(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    cases = []
    for n in range(3):
        case_id, kid = await created(r, people, ip=f"10.2.0.{n + 1}")
        await _apply(app_engine, people["ravi"].actor(), case_id, Take(), 1)
        cases.append((case_id, kid))
    r.kibana.faults.append(Fault(patches(), "status", status=409, times=1000))

    for _ in range(4):
        await r.run("W2", limit=10)
        r.advance(3600)

    assert r.kibana.attempts("PATCH") == 3  # one try for each, never a second
    for case_id, kid in cases:
        assert [s for _, _, s in await r.outbox(case_id)][1:] == ["conflict", "planned"]
        assert r.kibana.cases[kid]["status"] == "open"  # nothing changed
    # only the creates' opening comments and attachments (two each): no W2 comment was sent
    assert r.kibana.attempts("POST", "/comments") == 6


async def test_a_refused_create_pauses_its_row_and_is_not_sent_again(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await mirrored_case(
        app_engine, migrated_engine, people["asha"], _kibana_actor(people["asha"])
    )
    r.kibana.faults.append(Fault(posts("/api/cases"), "status", status=400, times=10))

    await r.run("W1", limit=1)
    await r.run("W1", limit=1)

    assert r.kibana.attempts("POST", "/api/cases") == 1
    assert await r.outbox(case_id) == [("W1", "create", "paused")]
    reason = (await r.sql("SELECT state_reason FROM kibana_outbox"))[0].state_reason
    assert "refused the request (400)" in reason
    assert "nothing was changed" in reason


async def test_a_server_error_on_a_change_is_in_doubt_and_the_look_replans_it(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id, kid = await created(r, people)
    await _apply(app_engine, people["ravi"].actor(), case_id, Take(), 1)
    r.kibana.faults.append(Fault(patches(), "timeout", land_after=0))  # applied; answer lost

    report = await r.run("W2", limit=1)

    assert (report.ambiguous, report.sent) == (1, 1)
    assert r.kibana.cases[kid]["status"] == "in-progress"  # Kibana did it
    r.advance(121)
    await r.writer.run_lookups()  # re-read, planned again: nothing left to do, so it landed
    states = [s for _, _, s in await r.outbox(case_id)]
    assert states[1] == "verified"
    assert r.kibana.count("PATCH") == 1


async def test_a_change_that_did_not_land_is_replanned_never_resent(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id, kid = await created(r, people)
    await _apply(app_engine, people["ravi"].actor(), case_id, Take(), 1)
    r.kibana.faults.append(Fault(patches(), "status", status=500))  # failed after, or before?

    await r.run("W2", limit=1)
    in_doubt = r.clock.now
    for seconds in (121, 301, 901, 1801):
        r.advance(seconds - (r.clock.now - in_doubt).total_seconds())
        await r.writer.run_lookups()

    assert r.kibana.attempts("PATCH") == 1
    assert r.kibana.cases[kid]["status"] == "open"
    reason = (await r.sql("SELECT state_reason FROM kibana_outbox WHERE op = 'update'"))[0]
    assert reason.state_reason.startswith("resend?")  # a person decides; nothing resends itself
    assert (await r.run("W2", limit=1)).sent == 0


async def test_a_read_back_that_does_not_match_pauses_the_class(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person], monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await mirrored_case(
        app_engine, migrated_engine, people["asha"], _kibana_actor(people["asha"])
    )
    original = r.kibana._create

    def lossy(body):  # type: ignore[no-untyped-def]
        answer = original(body)
        stored = r.kibana.cases[answer["id"]]
        stored["tags"] = [t for t in stored["tags"] if not t.startswith("argus:state")]
        return answer  # the answer is right; what Kibana keeps is not

    monkeypatch.setattr(r.kibana, "_create", lossy)

    report = await r.run("W1", limit=1)

    assert report.mismatches == 1
    assert "paused" in (report.stopped or "")
    assert await r.outbox(case_id) == [("W1", "create", "conflict")]
    lane = await r.lane.kibana_lane()
    assert "W1" in lane.paused
    assert "read-back" in lane.paused["W1"]
    findings = await r.sql("SELECT kind FROM kibana_findings")
    assert [f.kind for f in findings] == ["answer_unexpected"]
    assert (await r.run("W1", limit=1)).sent == 0  # the class stays paused until the owner resumes


async def test_a_401_stops_kibana_work_and_pauses_the_row(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await mirrored_case(
        app_engine, migrated_engine, people["asha"], _kibana_actor(people["asha"])
    )
    r.kibana.faults.append(Fault(posts("/api/cases"), "status", status=401))

    report = await r.run("W1", limit=1)

    assert "writer key" in (report.stopped or "")
    assert (await r.lane.kibana_lane()).stopped == "401"
    assert await r.outbox(case_id) == [("W1", "create", "paused")]
    assert (await r.run("W1", limit=1)).sent == 0


async def test_a_person_can_skip_a_write_that_cannot_go_on_and_the_case_goes_on(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    from datetime import UTC, datetime

    from argus.writer import cli, store

    r = rig(migrated_engine, app_engine, writer_engine)
    case_id, _ = await created(r, people)
    await _apply(app_engine, people["ravi"].actor(), case_id, Take(), 1)
    r.kibana.faults.append(Fault(patches(), "status", status=409))
    await r.run("W2", limit=1)
    assert [s for _, _, s in await r.outbox(case_id)][1:] == ["conflict", "planned"]
    update = int((await r.sql("SELECT id FROM kibana_outbox WHERE op = 'update'"))[0].id)

    said = await cli.skip_item(
        writer_engine, table=store.OUTBOX, item_id=update, reason="done by hand in Kibana",
        by="asha", now=datetime.now(UTC),
    )  # fmt: skip

    assert "is skipped (it was conflict)" in said
    states = [s for _, _, s in await r.outbox(case_id)]
    assert states[1] == "skipped"
    audit = await r.sql(
        "SELECT details FROM audit_events WHERE action = 'kibana.write.skipped_by_person'"
    )
    assert audit[0].details["by"] == "asha"
    assert audit[0].details["was"] == "conflict"
    again = await cli.skip_item(writer_engine, table=store.OUTBOX, item_id=update, reason="x",
                                by="asha", now=datetime.now(UTC))  # fmt: skip
    assert "not skipped" in again  # a skipped write is final
    done = await cli.skip_item(writer_engine, table=store.OUTBOX, item_id=1, reason="x", by="a",
                               now=datetime.now(UTC))  # fmt: skip
    assert "not skipped" in done  # nor is a verified one
    # the comment that explained the skipped change is skipped too, not sent as if it had been made
    await r.run("W2", limit=1)
    assert [s for _, _, s in await r.outbox(case_id)][1:] == ["skipped", "skipped"]
