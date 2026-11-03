"""The watch's tables as the runtime role sees them (Q-C2): a decided answer is never replaced,
the shape of an answer (and 20 requests at most in one row) are the database's own rules, the cap
of 6 to 20 a case a day is the runner's (review R11: three rows of 20 are accepted), suggestions
can be dismissed and nothing else, and the watch cause needs a parent."""

from __future__ import annotations

import uuid
from datetime import date

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.cases import watch, watchrun
from argus.cases.machine import CaseRefused, Open
from argus.cases.model import Indicator, Member
from argus.cases.service import CaseService
from tests.integration.cases.conftest import Person
from tests.integration.cases.watchkit import C2, H1, H2, World, at

pytestmark = pytest.mark.integration

DAY = date(2026, 10, 14)
INSERT = (
    "INSERT INTO case_watch_checks (case_id, day, source, subject, part, outcome, reason,"
    " window_start, window_end, asked_at, asked_on, requests, attempts, detail) VALUES (:c, :d,"
    " :source, :subject, 0, :outcome, :reason, :ws, :we, NULL, :on, :n, 1, '{}')"
)


@pytest.fixture
async def case_id(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, people: dict[str, Person]
) -> uuid.UUID:
    world = World(migrated_engine, app_engine)
    inv = await world.investigation(H1, [at(0, 9)])
    return await world.open_case(people["asha"], [inv], [H1], at(0, 10))


def row(case_id: uuid.UUID, **values: object) -> dict[str, object]:
    base: dict[str, object] = {
        "c": case_id, "d": DAY, "source": "proxy.contact", "subject": C2, "outcome": "quiet",
        "reason": None, "ws": at(0, 1, 40), "we": at(0, 22, 59), "on": None, "n": 0,
    }  # fmt: skip
    return {**base, **values}


async def put(engine: AsyncEngine, **values: object) -> None:
    async with engine.begin() as conn:
        await conn.execute(text(INSERT), values)


async def answer(conn: AsyncConnection, case_id: uuid.UUID, outcome: str) -> bool:
    """The watch's own write of a proxy answer for DAY."""
    window = (at(0, 1, 40), at(0, 22, 59))
    judged = watch.Judged(outcome, None, {})  # type: ignore[arg-type]
    return await watchrun.put(conn, case_id, DAY, "proxy.contact", C2, 0, judged, window)


async def test_a_decided_answer_is_never_replaced(
    app_engine: AsyncEngine, case_id: uuid.UUID
) -> None:
    await put(app_engine, **row(case_id))
    for statement in (
        "UPDATE case_watch_checks SET reason = 'x', attempts = attempts + 1",
        "UPDATE case_watch_checks SET outcome = 'active', attempts = attempts + 1",
    ):
        with pytest.raises(DBAPIError, match="a decided answer is not replaced"):
            async with app_engine.begin() as conn:
                await conn.execute(text(statement))
    async with app_engine.connect() as conn:
        assert (await conn.execute(text("SELECT outcome FROM case_watch_checks"))).scalar_one() == (
            "quiet"
        )
    # the watch's own write leaves a decided answer as it is (the upsert's condition)
    async with app_engine.begin() as conn:
        assert await answer(conn, case_id, "active") is False


async def test_only_a_not_checked_answer_is_replaced_and_each_try_is_counted(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, case_id: uuid.UUID
) -> None:
    await put(app_engine, **row(case_id, outcome="not_checked", reason="the SIEM is stopped"))
    with pytest.raises(DBAPIError, match="each new try is counted once"):
        async with app_engine.begin() as conn:
            await conn.execute(text("UPDATE case_watch_checks SET reason = 'again'"))
    change = "UPDATE case_watch_checks SET day = day + 1, attempts = attempts + 1"
    with pytest.raises(DBAPIError, match="permission denied"):  # the runtime has no such column
        async with app_engine.begin() as conn:
            await conn.execute(text(change))
    with pytest.raises(DBAPIError, match="its identity cannot change"):  # nor has the owner
        async with migrated_engine.begin() as conn:
            await conn.execute(text(change))
    async with app_engine.begin() as conn:
        assert await answer(conn, case_id, "quiet") is True
        assert await answer(conn, case_id, "active") is False
        stored = await conn.execute(text("SELECT outcome, attempts FROM case_watch_checks"))
        found = stored.one()
    assert (found.outcome, found.attempts) == ("quiet", 2)


@pytest.mark.parametrize(
    ("values", "constraint"),
    [
        ({"source": "alerts"}, "alerts_have_no_subject"),  # an alerts answer is about the case
        ({"source": "alerts", "subject": "", "on": DAY, "n": 1}, "alerts_are_local"),
        ({"on": DAY, "n": 21}, "requests_valid"),  # 20 in a row; the sum a day is the runner's
        ({"n": 1}, "requests_have_a_day"),
        ({"outcome": "unverified"}, "reason_given"),
        ({"outcome": "maybe", "reason": "x"}, "outcome_valid"),
        ({"source": "siem"}, "source_valid"),
        ({"we": at(0, 1, 40)}, "window_valid"),
    ],
)
async def test_the_shape_of_an_answer_is_checked_by_the_database(
    values: dict[str, object], constraint: str, app_engine: AsyncEngine, case_id: uuid.UUID
) -> None:
    with pytest.raises(IntegrityError, match=constraint):
        await put(app_engine, **row(case_id, **values))


async def test_an_answer_is_unique_for_its_case_day_source_and_address(
    app_engine: AsyncEngine, case_id: uuid.UUID
) -> None:
    await put(app_engine, **row(case_id))
    await put(app_engine, **row(case_id, subject="198.51.100.4"))  # another address: fine
    with pytest.raises(IntegrityError, match="uq_case_watch_checks"):
        await put(app_engine, **row(case_id))
    async with app_engine.connect() as conn:  # and the runtime cannot delete one
        with pytest.raises(DBAPIError, match="permission denied"):
            await conn.execute(text("DELETE FROM case_watch_checks"))


async def test_a_suggestion_can_be_dismissed_and_nothing_else_changed(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    case_id: uuid.UUID,
    people: dict[str, Person],
) -> None:
    world = World(migrated_engine, app_engine)
    other = await world.investigation(H2, [at(1, 8)])
    async with app_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO case_suggestions (investigation_id, case_id, link, link_value,"
                " kind, why) VALUES (:i, :c, 'c2', :v, 'shared', 'a CDN')"
            ),
            {"i": other, "c": case_id, "v": C2},
        )
    with pytest.raises(DBAPIError, match="permission denied"):
        async with app_engine.begin() as conn:
            await conn.execute(text("UPDATE case_suggestions SET kind = 'tie'"))
    with pytest.raises(IntegrityError, match="dismissal_complete"):
        async with app_engine.begin() as conn:
            await conn.execute(text("UPDATE case_suggestions SET dismissed_at = now()"))
    async with app_engine.begin() as conn:
        await conn.execute(
            text("UPDATE case_suggestions SET dismissed_at = now(), dismissed_by = :u"),
            {"u": people["asha"].user_id},
        )
    with pytest.raises(IntegrityError, match="uq_case_suggestions"):
        async with app_engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO case_suggestions (investigation_id, case_id, link, kind, why)"
                    " VALUES (:i, :c, 'actor', 'tie', 'again')"
                ),
                {"i": other, "c": case_id},
            )


async def test_the_watch_cause_is_only_for_a_suspected_case_that_follows_a_closed_one(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, case_id: uuid.UUID
) -> None:
    world = World(migrated_engine, app_engine)
    inv = await world.investigation(H2, [at(1, 8)])
    from argus.cases.model import Actor

    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        no_parent = Open("Activity", "high", "watch", (Member(inv, "actor"),), suspected=True)
        with pytest.raises(CaseRefused, match="follows a closed one"):
            await service.open(Actor.argus("watch"), no_parent)
        not_suspected = Open(
            "Activity", "high", "watch", (Member(inv, "actor"),), parent_case_id=case_id
        )
        with pytest.raises(CaseRefused, match="only from a person's verdict"):
            await service.open(Actor.argus("watch"), not_suspected)
        opened = await service.open(
            Actor.argus("watch"),
            Open("Activity", "high", "watch", (Member(inv, "actor"),),
                 (Indicator("ip", H2, "actor"),), suspected=True, parent_case_id=case_id),
        )  # fmt: skip
    assert opened.case.state == "suspected"
    assert opened.case.cause == "watch"
