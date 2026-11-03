"""Q-F2's gate: every evidence request has one opaque id (E1, E2 …), unique in its
investigation, numbered in the plan's order and never changed; every evidence row has its id
(the database refuses one without); the ledger records each request's task key, so a ledger
row joins its evidence; the migration gives every stored row its id."""

from __future__ import annotations

import asyncio
import random
from datetime import timedelta
from typing import Any

import pytest
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.context import graph, store
from argus.context.graph import Ctx, Gate
from argus.db import migrate
from argus.gateway.gateway import Gateway
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.pgstore import PgStore
from argus.gateway.templates import task_key
from argus.llm.wire import LlmCassette
from argus.reference.templates import LOOKUP_SIZE, LookupParams, TiLookup
from tests.integration.context.conftest import NOW, seed
from tests.integration.report import scenario
from tests.integration.report.test_agent_inputs import CASSETTE
from tests.unit.gateway.fakes import FakeClock, FakeTransport

pytestmark = pytest.mark.integration


async def rows(engine: AsyncEngine, sql: str, **params: Any) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(sql), params)).all())


async def day(engine: AsyncEngine, saver: AsyncPostgresSaver) -> scenario.Day:
    found = await scenario.collect(engine, saver)
    await scenario.assess(engine, found, LlmCassette(CASSETTE))
    return found


async def test_each_request_has_one_opaque_id(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    await day(app_engine, saver)
    ids = await rows(app_engine, "SELECT investigation_id, eid, task_key, template, origin,"
                     " first_version FROM evidence_requests ORDER BY 1, 2")  # fmt: skip
    by: dict[Any, list[Any]] = {}
    for r in ids:
        by.setdefault(r.investigation_id, []).append(r)
    assert len(by) == 4
    for found in by.values():
        assert [r.eid for r in found] == list(range(1, len(found) + 1))  # E1..En, no gap
        assert len({r.task_key for r in found}) == len(found)
        pack = [r.task_key for r in found if r.origin == "pack"]
        assert pack == sorted(pack)  # the wave's plan order: priority, then task key
        assert all(r.eid < s.eid for r in found if r.origin == "pack"
                   for s in found if s.origin == "agent")  # fmt: skip
    joined = (
        "SELECT e.investigation_id, e.task_key, r.eid FROM evidence e"
        " LEFT JOIN evidence_requests r USING (investigation_id, task_key)"
    )
    every = await rows(app_engine, joined)
    assert every
    assert all(r.eid is not None for r in every)
    origins = {(r.template, r.origin) for r in ids}
    assert ("web.followups", "agent") in origins  # asked by the investigator only
    assert ("proxy.host", "pack") in origins  # c2b's retry keeps the wave's request and id
    retried = await rows(app_engine, "SELECT count(*) FROM evidence_requests"
                         " WHERE template = 'proxy.host'")  # fmt: skip
    assert retried[0][0] == 2  # c2's and c2b's: the agent's retry kept c2b's request


async def test_numbering_follows_the_order_given_and_never_changes(app_engine: AsyncEngine) -> None:
    (inv,) = await seed(app_engine, [(1, "r1", "10.0.0.1")])
    tasks = [{"task_key": f"{n:064x}", "template": "t", "version": 1} for n in range(6)]
    shuffled = random.Random(7).sample(tasks, len(tasks))
    async with app_engine.begin() as conn:
        got = await store.register_requests(conn, inv, 1, shuffled, "pack", NOW)
    assert got == {t["task_key"]: n for n, t in enumerate(shuffled, start=1)}
    async with app_engine.begin() as conn:
        again = await store.register_requests(conn, inv, 2, [*tasks, *tasks], "agent",
                                              NOW + timedelta(hours=1))  # fmt: skip
        more = await store.register_requests(conn, inv, 2, [{"task_key": "f" * 64,
                                                              "template": "u", "version": 2}],
                                             "person", NOW, reason="asked")  # fmt: skip
        assert await store.register_requests(conn, inv, 2, [], "pack", NOW) == {}
    assert again == got  # an id never changes; later origins do not overwrite the first
    assert more == {"f" * 64: 7}
    stored = await rows(app_engine, "SELECT eid, origin, first_version, reason, template_version"
                        " FROM evidence_requests ORDER BY eid")  # fmt: skip
    assert [tuple(r) for r in stored][-1] == (7, "person", 2, "asked", 2)
    assert {r.origin for r in stored[:6]} == {"pack"}
    assert {r.first_version for r in stored[:6]} == {1}


async def test_concurrent_requests_get_unique_ids_without_gaps(app_engine: AsyncEngine) -> None:
    (inv,) = await seed(app_engine, [(1, "r1", "10.0.0.1")])

    async def one(key: str) -> dict[str, int]:
        async with app_engine.begin() as conn:
            return await store.register_requests(
                conn, inv, 1, [{"task_key": key, "template": "t", "version": 1}], "agent", NOW
            )

    keys = [f"{n:064x}" for n in range(20)]
    got = await asyncio.gather(*(one(k) for k in [*keys, *keys[:5]]))
    ids = {k: e for g in got for k, e in g.items()}
    assert sorted(ids.values()) == list(range(1, 21))
    assert all(g[k] == ids[k] for g in got for k in g)  # a key asked twice keeps its one id


async def test_the_runtime_role_cannot_change_or_remove_an_id(app_engine: AsyncEngine) -> None:
    (inv,) = await seed(app_engine, [(1, "r1", "10.0.0.1")])
    async with app_engine.begin() as conn:
        await store.register_requests(conn, inv, 1, [{"task_key": "a" * 64, "template": "t",
                                                       "version": 1}], "pack", NOW)  # fmt: skip
    for statement in ("UPDATE evidence_requests SET eid = 9", "DELETE FROM evidence_requests",
                      "UPDATE evidence_requests SET origin = 'agent'"):  # fmt: skip
        async with app_engine.connect() as conn:
            with pytest.raises(DBAPIError, match="permission denied"):
                await conn.execute(text(statement))
    for bad in ({"origin": "model"}, {"eid": 0}, {"task_key": "x"}, {"reason": "r" * 201}):
        row = {"inv": inv, "eid": 5, "key": "b" * 64, "origin": "pack", "reason": None, **{
            {"eid": "eid", "task_key": "key"}.get(k, k): v for k, v in bad.items()}}  # fmt: skip
        async with app_engine.connect() as conn:
            with pytest.raises(DBAPIError, match="check"):
                await conn.execute(text(
                    "INSERT INTO evidence_requests (investigation_id, eid, task_key, template,"
                    " template_version, origin, reason, first_version, created_at) VALUES"
                    " (:inv, :eid, :key, 't', 1, :origin, :reason, 1, now())"), row)  # fmt: skip


async def test_the_ledger_records_the_evidence_task_key(app_engine: AsyncEngine) -> None:
    """Through the real gateway on Postgres: the ledger row of an evidence request carries the
    evidence row's task key, and the request has its E-id first."""
    (inv,) = await seed(app_engine, [(1, "r1", "10.0.0.1")])
    clock = FakeClock()
    state = PgStore(app_engine)
    await state.save_health(HealthMemory(state=HealthState.NORMAL, probed_at=clock()))
    gateway = Gateway(FakeTransport(clock=clock), state, clock=clock, sleep=clock.sleep)
    params = LookupParams(values=("45.9.9.9",), size=LOOKUP_SIZE)
    from argus.context.packs import TaskSpec
    from tests.integration.context.kit import registry

    task = {**TaskSpec(TiLookup(), params).ref(), "mode": "collect"}
    ctx = Ctx(engine=app_engine, gateway=gateway, packs=registry(), claim=None,
              deadline=clock() + timedelta(minutes=2), clock=clock, gate=Gate(1),
              origin="agent")  # fmt: skip
    ref = await graph.evidence_step(ctx, inv, 1, task)
    (ledger,) = await rows(app_engine, "SELECT template, task_key, outcome FROM siem_requests")
    assert tuple(ledger) == ("ti.lookup", ref["task_key"], "ok")
    assert ref["task_key"] == task_key(TiLookup(), params)
    (request,) = await rows(app_engine, "SELECT eid, origin, template, template_version"
                            " FROM evidence_requests")  # fmt: skip
    assert tuple(request) == (1, "agent", "ti.lookup", 1)
    joined = await rows(app_engine, "SELECT count(*) FROM evidence e JOIN siem_requests l"
                        " USING (task_key)")  # fmt: skip
    assert joined[0][0] == 1
    with pytest.raises(DBAPIError, match="check"):
        async with app_engine.connect() as conn:
            await conn.execute(text(
                "INSERT INTO siem_requests (at, component, purpose, template, version, indices,"
                " outcome, took_ms, elapsed_ms, response_bytes, attempts, task_key) VALUES"
                " (now(), 'c', 'p', 't', 1, '{}', 'ok', 0, 0, 0, 1, 'nope')"))  # fmt: skip


async def test_the_migration_gives_every_stored_row_its_id(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    await day(app_engine, saver)
    stored = await rows(app_engine, "SELECT investigation_id, task_key, min(version),"
                        " min(collected_at) FROM evidence GROUP BY 1, 2")  # fmt: skip
    listed = {(r[0], r[1]) for r in await rows(
        app_engine, "SELECT d.investigation_id, e.value ->> 'task_key' FROM dossiers d"
        " CROSS JOIN LATERAL jsonb_array_elements(d.body -> 'evidence') e")}  # fmt: skip
    await migrate.downgrade(migrated_engine, "0020")
    column = (
        "SELECT 1 FROM information_schema.columns WHERE table_name = 'siem_requests'"
        " AND column_name = 'task_key'"
    )
    assert not await rows(migrated_engine, column)
    await migrate.upgrade(migrated_engine)
    ids = await rows(app_engine, "SELECT investigation_id, eid, task_key, origin, first_version,"
                     " created_at FROM evidence_requests ORDER BY 1, 2")  # fmt: skip
    assert {(r.investigation_id, r.task_key) for r in ids} == {(r[0], r[1]) for r in stored}
    first = {(r[0], r[1]): (r[2], r[3]) for r in stored}
    by: dict[Any, list[Any]] = {}
    for r in ids:
        by.setdefault(r.investigation_id, []).append(r)
        assert r.origin == ("pack" if (r.investigation_id, r.task_key) in listed else "agent")
        assert (r.first_version, r.created_at) == first[(r.investigation_id, r.task_key)]
    for found in by.values():
        assert [r.eid for r in found] == list(range(1, len(found) + 1))
        order = [(r.first_version, r.created_at, r.task_key) for r in found]
        assert order == sorted(order)
    one = (
        "UPDATE evidence SET task_key = :k WHERE (investigation_id, version, task_key) ="
        " (SELECT investigation_id, version, task_key FROM evidence LIMIT 1)"
    )
    with pytest.raises(DBAPIError, match="foreign key"):  # the tie holds again
        async with migrated_engine.begin() as conn:
            await conn.execute(text(one), {"k": "c" * 64})
