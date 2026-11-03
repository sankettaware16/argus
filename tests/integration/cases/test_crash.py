"""Outbox ⇔ event under crashes between every statement (Q-C1's gate): a command that dies
after any of its statements leaves nothing of itself behind, and the database's invariants
hold afterwards: every event has exactly its outbox rows, every version its event, replay
rebuilds every case, and both hash chains verify."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import chain
from argus.cases.machine import CaseRefused, Link, Open, Release, Take, replay
from argus.cases.model import KIBANA_TO_OPEN, Member
from argus.cases.service import CaseService
from tests.integration.cases.conftest import (
    APPROVER,
    Person,
    asking,
    investigation,
    make_person,
    signed_for,
)


class Crash(Exception):  # noqa: N818 - a simulated crash
    pass


class _Counter:
    """Counts the statements sent on ``engine``; raises Crash before statement ``crash_at``."""

    def __init__(self, engine: AsyncEngine, crash_at: int | None = None) -> None:
        self.engine, self.crash_at, self.sent = engine, crash_at, 0

    def __enter__(self) -> _Counter:
        event.listen(self.engine.sync_engine, "before_cursor_execute", self._before)
        return self

    def __exit__(self, *exc: object) -> None:
        event.remove(self.engine.sync_engine, "before_cursor_execute", self._before)

    def _before(self, *args: Any, **kwargs: Any) -> None:
        self.sent += 1
        if self.crash_at is not None and self.sent == self.crash_at:
            raise Crash(f"crashed before statement {self.sent}")


async def state(engine: AsyncEngine) -> dict[str, Any]:
    async with engine.connect() as conn:
        counts = {
            table: (await conn.execute(text(f"SELECT count(*) FROM {table}"))).scalar_one()  # noqa: S608
            for table in (
                "cases",
                "case_events",
                "kibana_outbox",
                "audit_events",
                "case_members",
                "case_indicators",
                "approval_decisions",
            )
        }
        counts["heads"] = await chain.heads(conn)
        counts["versions"] = (
            await conn.execute(text("SELECT coalesce(sum(version), 0) FROM cases"))
        ).scalar_one()
    return counts


async def invariants(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        mismatched = (
            await conn.execute(
                text(
                    "SELECT count(*) FROM case_events e WHERE e.kibana_rows <>"
                    " (SELECT count(*) FROM kibana_outbox o WHERE o.case_event_id = e.id)"
                )
            )
        ).scalar_one()
        unrecorded = (
            await conn.execute(
                text(
                    "SELECT count(*) FROM cases c WHERE c.version <>"
                    " (SELECT count(*) FROM case_events e WHERE e.case_id = c.id)"
                    " OR NOT EXISTS (SELECT 1 FROM case_events e WHERE e.case_id = c.id"
                    " AND e.case_version = c.version AND e.to_state = c.state)"
                )
            )
        ).scalar_one()
        assert (mismatched, unrecorded) == (0, 0)
        service = await CaseService.start(conn)
        for (case_id,) in (await conn.execute(text("SELECT id FROM cases"))).all():
            assert replay(await service.events(case_id)) == await service.get(case_id)
        assert [r.problems for r in await chain.verify_all(conn)] == [[], []]


Command = Callable[[AsyncEngine], Awaitable[Any]]


async def crash_everywhere(engine: AsyncEngine, command: Command) -> int:
    """Run ``command`` crashing before its 1st, 2nd, ... statement, each from the same state,
    until it runs through; return how many statements it took."""
    crash_at = 1
    while True:
        before = await state(engine)
        try:
            with _Counter(engine, crash_at):
                await command(engine)
        except Crash:
            assert await state(engine) == before, f"crash before statement {crash_at} left traces"
            await invariants(engine)
            crash_at += 1
            continue
        await invariants(engine)
        return crash_at - 1


def _kibana(person: Person) -> Any:
    return person.actor(APPROVER, kibana=KIBANA_TO_OPEN,
                        checked_at=datetime.now(UTC) - timedelta(seconds=1))  # fmt: skip


async def test_every_command_is_all_or_nothing(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    asha, ravi = people["asha"], people["ravi"]
    invs = [await investigation(migrated_engine, actor=(("source.ip", f"10.2.0.{n}"),))
            for n in range(3)]  # fmt: skip

    async def open_case(engine: AsyncEngine) -> uuid.UUID:
        async with engine.begin() as conn:
            applied = await (await CaseService.start(conn)).open(
                _kibana(asha), Open("A case", "high", "person", (Member(invs[0], "person"),))
            )
        return applied.case.id

    assert (
        await crash_everywhere(api_engine, open_case) >= 6
    )  # now, case, members, event, ..., audit
    case_id = await _only_case(api_engine)

    async def take(engine: AsyncEngine) -> None:
        async with engine.begin() as conn:
            service = await CaseService.start(conn)
            case = await service.get(case_id)
            assert case is not None
            command = Take() if case.state == "open" else Release()
            await service.apply(_kibana(ravi), case_id, command, expected_version=case.version)

    await crash_everywhere(api_engine, take)

    async def link(engine: AsyncEngine) -> None:
        async with engine.begin() as conn:
            service = await CaseService.start(conn)
            case = await service.get(case_id)
            assert case is not None
            fresh = next(i for i in invs if i not in case.members)
            await service.apply(_kibana(ravi), case_id, Link((Member(fresh, "person"),)),
                                expected_version=case.version)  # fmt: skip

    await crash_everywhere(api_engine, link)

    async def close(engine: AsyncEngine) -> None:
        async with engine.begin() as conn:
            service = await CaseService.start(conn)
            case = await service.get(case_id)
            assert case is not None
            _, request = await service.request_closure(
                asha.actor(), case_id, expected_version=case.version, reason="benign_policy",
                session_token=asha.session_token, check=await asking(conn, asha),
            )  # fmt: skip
            await service.decide(_kibana(ravi), request, session_token=ravi.session_token,
                                 decision="approved",
                                 signed=await signed_for(conn, ravi, request))  # fmt: skip

    await crash_everywhere(api_engine, close)
    async with api_engine.connect() as conn:
        case = await (await CaseService.start(conn)).get(case_id)
    assert case is not None
    assert case.state == "closed"
    await invariants(api_engine)


async def _only_case(engine: AsyncEngine) -> uuid.UUID:
    async with engine.connect() as conn:
        found: uuid.UUID = (await conn.execute(text("SELECT id FROM cases"))).scalar_one()
    return found


@settings(
    max_examples=12, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(st.lists(st.tuples(st.sampled_from(["take", "release", "link", "open"]),
                          st.integers(1, 30)), min_size=1, max_size=6))  # fmt: skip
async def test_random_commands_crashing_anywhere_keep_the_invariants(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, steps: list[tuple[str, int]]
) -> None:
    person = await make_person(api_engine, f"p{uuid.uuid4().hex[:10]}")
    inv = await investigation(migrated_engine, actor=(("source.ip", "10.3.0.1"),))
    async with api_engine.begin() as conn:
        case_id = (
            await (await CaseService.start(conn)).open(
                _kibana(person), Open("Random", "low", "person", (Member(inv, "person"),))
            )
        ).case.id
    for name, crash_at in steps:
        extra = await investigation(migrated_engine, actor=(("source.ip", "10.3.0.2"),))
        before = await state(api_engine)
        crashed = refused = False
        try:
            with _Counter(api_engine, crash_at):
                async with api_engine.begin() as conn:
                    service = await CaseService.start(conn)
                    case = await service.get(case_id)
                    assert case is not None
                    if name == "open":
                        more = Open("More", "low", "person", (Member(extra, "person"),))
                        await service.open(_kibana(person), more)
                    else:
                        command = {"take": Take(), "release": Release(),
                                   "link": Link((Member(extra, "person"),))}[name]  # fmt: skip
                        await service.apply(_kibana(person), case_id, command,
                                            expected_version=case.version)  # fmt: skip
        except Crash:
            crashed = True
        except CaseRefused:  # a refusal (taking a case one owns, say) changes nothing
            refused = True
        if crashed or refused:
            assert await state(api_engine) == before
        await invariants(api_engine)
