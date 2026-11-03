"""Q-D4's gate for unknown outcomes (plan §7.1): "sending" is committed first; nothing is
retried or resent; a write in doubt is looked for at 2, 5, 15 and 30 minutes by its tag and by
``reporters=argus``; a "resend?" item needs a person; a duplicate after an approved resend is
flagged within a cycle; a crash between sending and the answer loses and doubles nothing."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.kibana_sync.cycle import SyncConfig, Syncer
from argus.kibana_sync.store import PgSyncStore
from argus.writer import lookup
from tests.integration.cases.conftest import Person
from tests.integration.cases.test_service import _kibana_actor
from tests.integration.writer.fake import Fault, posts
from tests.integration.writer.kit import Rig, approve_resend, mirrored_case, rig

pytestmark = pytest.mark.integration
TIMEOUT = 15  # ARGUS's own timeout; a landing is that many seconds later than the request


class Crash(BaseException):
    """The process dies here (not an Exception: nothing in the writer may swallow it)."""


async def _doubt_at(r: Rig) -> datetime:
    """When the write became ambiguous (the first look is due two minutes later)."""
    first = (await r.sql("SELECT min(due_at) AS d FROM kibana_lookups"))[0].d
    return first - timedelta(minutes=2)


async def _lookups(r: Rig, base: datetime, until: float) -> None:
    """Time passes to ``until`` seconds after ``base``; the service's tick makes due looks."""
    r.advance(until - (r.clock.now - base).total_seconds())
    await r.writer.run_lookups()


@pytest.mark.parametrize("after", [10, 140, 200])
async def test_a_create_landing_after_the_timeout_is_found_and_never_sent_twice(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person], after: int,
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await mirrored_case(
        app_engine, migrated_engine, people["asha"], _kibana_actor(people["asha"])
    )
    r.kibana.faults.append(Fault(posts("/cases"), "timeout", land_after=TIMEOUT + after))

    report = await r.run("W1", limit=1)

    assert (report.sent, report.ambiguous, report.verified) == (1, 1, 0), report.lines()
    assert await r.outbox(case_id) == [("W1", "create", "ambiguous")]
    assert await r.steps(case_id) == []  # nothing follows a create that may not exist
    assert (await r.run("W1", limit=1)).sent == 0  # a second run does not send it again
    base = await _doubt_at(r)
    lookups = await r.sql("SELECT attempt, due_at FROM kibana_lookups ORDER BY attempt")
    assert [(row.due_at - base).total_seconds() for row in lookups] == [120, 300, 900, 1800]

    await _lookups(r, base, 119)
    assert await r.outbox(case_id) == [("W1", "create", "ambiguous")]  # not due yet
    await _lookups(r, base, 121)
    seen = list(await r.sql("SELECT outcome FROM kibana_lookups ORDER BY attempt"))
    if after == 10:  # it landed at 25 s: the first look finds it
        assert seen[0].outcome == "found"
    else:  # 155 s and 215 s: the 2-minute look finds nothing, the 5-minute one the case
        assert seen[0].outcome == "not_found"
        assert await r.outbox(case_id) == [("W1", "create", "ambiguous")]
        await _lookups(r, base, 301)
        after_five = await r.sql("SELECT outcome FROM kibana_lookups ORDER BY attempt")
        assert [o.outcome for o in after_five][:2] == ["not_found", "found"]  # fmt: skip

    assert await r.outbox(case_id) == [("W1", "create", "verified")]
    [case] = r.kibana.ours()
    kid = (await r.sql("SELECT kibana_case_id FROM kibana_outbox"))[0].kibana_case_id
    assert kid == case["id"]
    assert case["created_by"]["username"] == "argus"
    assert r.kibana.count("POST", "/api/cases") == 1  # one create ever reached Kibana
    r.advance(80 * 60)  # a timeout is charged in full to the write lane: it repays that first
    assert (await r.run("W1", limit=1)).verified == 2  # the opening comment and the alerts follow
    assert r.kibana.count("POST", "/api/cases") == 1
    left = await r.sql("SELECT count(*) AS n FROM kibana_lookups WHERE done_at IS NULL")
    assert left[0].n == 0  # the looks still waiting were closed


async def test_four_looks_that_find_nothing_ask_for_a_resend_and_a_person_decides(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine, people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, api_engine, writer_engine)
    case_id = await mirrored_case(
        api_engine, migrated_engine, people["asha"], _kibana_actor(people["asha"])
    )
    r.kibana.faults.append(Fault(posts("/cases"), "timeout", land_after=None))  # never lands
    await r.run("W1", limit=1)
    base = await _doubt_at(r)
    for seconds in (121, 301, 901, 1801):
        await _lookups(r, base, seconds)
    outcomes = [
        o.outcome for o in await r.sql("SELECT outcome FROM kibana_lookups ORDER BY attempt")
    ]
    assert outcomes == ["not_found"] * 4
    reason = (await r.sql("SELECT state_reason FROM kibana_outbox"))[0].state_reason
    assert reason.startswith("resend?")
    assert await r.outbox(case_id) == [("W1", "create", "ambiguous")]
    assert [row.id for row in await lookup.resend_items(r.writer)] != []
    assert (await r.run("W1", limit=1)).sent == 0  # nothing sends it without a person

    row_id = (await r.sql("SELECT id FROM kibana_outbox"))[0].id
    await approve_resend(r, api_engine, people, row_id)
    r.advance(80 * 60)  # the timeout's charge to the write lane is repaid first
    report = await r.run("W1", limit=1)  # the approved resend: planned, then sent once more

    assert report.verified >= 1, report.lines()
    assert await r.outbox(case_id) == [("W1", "create", "verified")]
    sent = (await r.sql("SELECT sent_count, resends FROM kibana_outbox"))[0]
    assert (sent.sent_count, sent.resends) == (2, 1)
    assert len(r.kibana.ours()) == 1


async def test_an_approved_resend_whose_first_create_lands_later_is_flagged_within_a_cycle(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine, people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, api_engine, writer_engine)
    case_id = await mirrored_case(
        api_engine, migrated_engine, people["asha"], _kibana_actor(people["asha"])
    )
    r.kibana.faults.append(Fault(posts("/cases"), "timeout", land_after=7200))  # two hours late
    await r.run("W1", limit=1)
    base = await _doubt_at(r)
    for seconds in (121, 301, 901, 1801):
        await _lookups(r, base, seconds)
    row_id = (await r.sql("SELECT id FROM kibana_outbox"))[0].id
    await approve_resend(r, api_engine, people, row_id)
    r.advance(80 * 60)
    await r.run("W1", limit=1)
    assert len(r.kibana.ours()) == 1  # the resend made the case

    await _lookups(r, base, 9000)  # the first create reaches Kibana at last
    assert len(r.kibana.ours()) == 2

    syncer = Syncer(r.gateway, PgSyncStore(app_engine), r.lane, es=r.es, config=SyncConfig(),
                    clock=r.clock, sleep=r.clock.sleep)  # fmt: skip
    r.advance(600)
    await syncer.cycle(deadline=r.clock.now + timedelta(minutes=9))
    kinds = [f.kind for f in await r.sql("SELECT kind FROM kibana_findings")]
    assert "duplicate_case" in kinds  # flagged, never deleted
    assert len(r.kibana.ours()) == 2
    assert case_id


async def test_a_crash_between_the_answer_and_its_record_loses_and_doubles_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person], monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await mirrored_case(
        app_engine, migrated_engine, people["asha"], _kibana_actor(people["asha"])
    )

    async def dies(*args: object, **kwargs: object) -> None:
        raise Crash

    monkeypatch.setattr(type(r.writer), "_sent", dies)  # Kibana made the case; the record is lost
    with pytest.raises(Crash):
        await r.run("W1", limit=1)
    monkeypatch.undo()
    assert await r.outbox(case_id) == [("W1", "create", "sending")]  # committed before the send
    assert len(r.kibana.ours()) == 1

    r.advance(300)  # a restarted writer: the row is in doubt; the look finds the case
    r.writer.clock = r.clock
    await r.run("W1", limit=1)
    r.advance(130)
    await r.writer.run_lookups()
    assert await r.outbox(case_id) == [("W1", "create", "verified")]
    assert r.kibana.count("POST", "/api/cases") == 1


async def test_a_crash_before_the_request_leaves_asks_for_a_resend_never_sends_by_itself(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await mirrored_case(
        app_engine, migrated_engine, people["asha"], _kibana_actor(people["asha"])
    )
    original = r.kibana.send

    async def dies(request):  # type: ignore[no-untyped-def]
        if request.method == "POST" and request.target == "kibana":
            raise Crash  # after "sending" was committed, before anything reached Kibana
        return await original(request)

    r.kibana.send = dies  # type: ignore[method-assign]
    with pytest.raises(Crash):
        await r.run("W1", limit=1)
    r.kibana.send = original  # type: ignore[method-assign]
    assert await r.outbox(case_id) == [("W1", "create", "sending")]

    r.advance(300)
    await r.run("W1", limit=1)  # recovers: ambiguous, and nothing is sent
    assert await r.outbox(case_id) == [("W1", "create", "ambiguous")]
    base = await _doubt_at(r)
    for seconds in (121, 301, 901, 1801):
        await _lookups(r, base, seconds)
    assert (await r.sql("SELECT state_reason FROM kibana_outbox"))[0].state_reason.startswith(
        "resend?"
    )
    assert len(r.kibana.ours()) == 0
    assert r.kibana.count("POST", "/api/cases") == 0
