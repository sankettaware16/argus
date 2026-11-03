"""Q-F3 on Postgres: the queue of waves and "Check more", the service's pass (a person's request
first, the engine's waves by importance and within the day's cap, nothing while the SIEM is not
normal), what the AI investigator waits for, the table's grants and its cascade."""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assess import runner
from argus.gateway.errors import TimedOutError
from argus.gateway.health import HealthState
from argus.gateway.templates import Purpose
from argus.investigation import checks, store, wave
from tests.integration.investigation.kit import (
    NOW,
    FakeGateway,
    body,
    env,
    healthy,
    seed,
    unknown,
)
from tests.unit.investigation.kit import C2, HOST, step

pytestmark = pytest.mark.integration
TIMELINE = [step(2, "deferred", ["timeline"])]
ZERO = {"queued": 0, "done": 0, "refused": 0, "failed": 0, "waiting": 0}


async def rows(engine: AsyncEngine, sql: str, **params: Any) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(sql), params)).all())


async def queue(
    engine: AsyncEngine, inv: uuid.UUID, kind: str, source: str, **kw: Any
) -> int | None:
    async with engine.begin() as conn:
        return await store.enqueue(conn, inv, 1, kind, source, NOW, **kw)


# ----------------------------------------------------------------------------- the queue


async def test_a_wave_is_queued_once_per_version_and_a_request_once_while_open(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    assert await queue(app_engine, inv, "wave", "engine") is not None
    assert await queue(app_engine, inv, "wave", "engine") is None  # the engine's, once a version
    first = await queue(app_engine, inv, "check", "person", template="proxy.host",
                        entity=HOST, requested_by="asha")  # fmt: skip
    assert first is not None
    assert (
        await queue(
            app_engine,
            inv,
            "check",
            "person",
            template="proxy.host",
            entity=HOST,
            requested_by="bina",
        )
        is None
    )  # the same, still open
    other = await queue(app_engine, inv, "check", "person", template="proxy.host",
                        entity="10.20.3.9", requested_by="asha")  # fmt: skip
    assert other is not None
    async with app_engine.begin() as conn:
        await conn.execute(
            text(
                "UPDATE investigation_checks SET status = 'running', lease_until = :n WHERE id = :i"
            ),
            {"n": NOW, "i": first},
        )
        await store.finish(conn, first, "done", {}, NOW)
    # once over, the same request may be made again
    assert (
        await queue(
            app_engine,
            inv,
            "check",
            "person",
            template="proxy.host",
            entity=HOST,
            requested_by="bina",
        )
        is not None
    )


async def test_a_persons_request_is_claimed_first_then_the_oldest(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    a = await seed(migrated_engine, body(steps=TIMELINE))
    b = await seed(migrated_engine, body(steps=TIMELINE))
    c = await seed(migrated_engine, body(steps=TIMELINE))
    first = await queue(app_engine, a, "wave", "engine")
    second = await queue(app_engine, b, "wave", "engine")
    person = await queue(app_engine, c, "check", "person", template="proxy.host", entity=HOST,
                         requested_by="asha")  # fmt: skip
    async with app_engine.begin() as conn:
        got = await store.claim(conn, "w", NOW, 3)
    assert [r.id for r in got] == [person, first, second]
    assert [r.source for r in got] == ["person", "engine", "engine"]
    assert all(r.claims == 1 for r in got)
    async with app_engine.begin() as conn:
        assert await store.claim(conn, "w", NOW, 3) == []  # leased
    async with app_engine.begin() as conn:  # a lease that ran out is claimed again
        again = await store.claim(conn, "w", NOW + store.LEASE + timedelta(seconds=1), 1)
    assert [r.claims for r in again] == [2]


async def test_a_request_whose_workers_keep_dying_is_given_up(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    await queue(app_engine, inv, "wave", "engine")
    when = NOW
    for _ in range(store.MAX_CLAIMS):
        async with app_engine.begin() as conn:
            assert len(await store.claim(conn, "w", when, 1)) == 1
        when += store.LEASE + timedelta(seconds=1)
    async with app_engine.begin() as conn:
        assert await store.claim(conn, "w", when, 1) == []
    (row,) = await rows(app_engine, "SELECT status, outcome FROM investigation_checks")
    assert row.status == "failed"
    assert "worker died" in row.outcome["error"]


async def test_only_a_running_request_can_end(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    request = await queue(app_engine, inv, "wave", "engine")
    assert request is not None
    async with app_engine.begin() as conn:
        await store.finish(conn, request, "done", {"x": 1}, NOW)  # still queued: nothing
        with pytest.raises(ValueError, match="does not end"):
            await store.finish(conn, request, "running", {}, NOW)
    assert (await rows(app_engine, "SELECT status FROM investigation_checks"))[0].status == "queued"


# ----------------------------------------------------------------------------- the service


async def test_a_pass_runs_a_queued_person_check_and_records_its_cost(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(), decided=True)
    gateway = FakeGateway(healthy())
    e = env(app_engine, gateway)
    # the dossier has no contact answer: who else reached the destination is a new subject
    await queue(app_engine, inv, "check", "person", template="proxy.contact", entity=C2,
                requested_by="asha")  # fmt: skip
    assert await wave.run_pass(e, "w", wave=False) == {**ZERO, "done": 1}
    assert [c[:3] for c in gateway.calls] == [
        ("proxy.contact", Purpose.INVESTIGATE, "investigation")
    ]
    (row,) = await rows(app_engine, "SELECT status, outcome, finished_at FROM investigation_checks")
    assert row.status == "done"
    assert row.finished_at is not None
    out = row.outcome
    assert (out["requests"], out["heavy"], out["server_ms"]) == (1, 1, 7)
    assert out["checks"][0]["eid"] == "E1"
    assert (
        out["checks"][0]["reason"]
        == "which campus hosts reached the destination that day — a person asked"
    )
    assert out["dossier"] == "generic+wave.1@12"
    (req,) = await rows(app_engine, "SELECT origin, reason FROM evidence_requests")
    assert req.origin == "person"
    assert (await rows(app_engine, "SELECT count(*) AS n FROM dossiers"))[0].n == 2


async def test_a_check_about_another_subject_is_a_check_of_its_own(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """The dossier's own host is not replaced by one a person asked about: the answer is stored
    and shown beside it, but the pack does not read it."""
    inv = await seed(migrated_engine, body(steps=TIMELINE), decided=True)
    gateway = FakeGateway(healthy())
    e = env(app_engine, gateway)
    own = await queue(app_engine, inv, "check", "person", template="proxy.host", entity=HOST,
                      requested_by="asha")  # fmt: skip
    assert own is not None
    assert (await wave.run_pass(e, "w", wave=False))["done"] == 1
    other = await queue(app_engine, inv, "check", "person", template="proxy.host",
                        entity="10.20.3.9", requested_by="asha")  # fmt: skip
    assert other is not None
    assert (await wave.run_pass(e, "w", wave=False))["done"] == 1
    assert len(await rows(app_engine, "SELECT 1 FROM evidence")) == 2
    assert len(await rows(app_engine, "SELECT 1 FROM dossiers")) == 2  # the second made none
    done = await rows(app_engine, "SELECT outcome FROM investigation_checks ORDER BY id")
    assert done[1].outcome["dossier"] is None
    assert done[1].outcome["checks"][0]["eid"] == "E2"


async def test_a_request_the_catalogue_refuses_is_refused_with_its_reason(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(), decided=True)
    gateway = FakeGateway(healthy())
    e = env(app_engine, gateway)
    await queue(app_engine, inv, "check", "person", template="proxy.host", entity=C2,
                requested_by="asha")  # fmt: skip
    await queue(app_engine, inv, "check", "person", template="logs.source_events",
                entity=HOST, requested_by="asha")  # fmt: skip
    assert await wave.run_pass(e, "w", wave=False, limit=5) == {**ZERO, "refused": 2}
    got = await rows(app_engine, "SELECT status, outcome FROM investigation_checks ORDER BY id")
    assert [r.status for r in got] == ["refused", "refused"]
    assert "takes an internal address, not a public one" in got[0].outcome["error"]
    assert "not a check a person may ask for" in got[1].outcome["error"]
    assert gateway.calls == []


async def test_a_failed_check_of_a_person_is_still_done_and_shown(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(), decided=True)
    gateway = FakeGateway(healthy(), fail={"proxy.contact": TimedOutError("slow")})
    await queue(app_engine, inv, "check", "person", template="proxy.contact", entity=C2,
                requested_by="asha")  # fmt: skip
    assert (await wave.run_pass(env(app_engine, gateway), "w", wave=False))["done"] == 1
    (row,) = await rows(app_engine, "SELECT outcome FROM investigation_checks")
    assert row.outcome["checks"][0]["status"] == "timeout"
    assert row.outcome["server_ms"] == 0


async def test_requests_wait_while_siem_is_not_normal(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(), decided=True)
    await queue(app_engine, inv, "check", "person", template="proxy.contact", entity=C2,
                requested_by="asha")  # fmt: skip
    gateway = FakeGateway(healthy(HealthState.CAUTION))
    assert await wave.run_pass(env(app_engine, gateway), "w", wave=True) == ZERO
    assert (await rows(app_engine, "SELECT status FROM investigation_checks"))[0].status == "queued"
    assert gateway.calls == []


async def test_the_engines_waves_go_by_importance_within_the_days_cap(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    plain = await seed(migrated_engine, body(steps=TIMELINE), severity="low")
    high = await seed(migrated_engine, body(steps=TIMELINE), severity="high")
    floor = await seed(migrated_engine, body([unknown("proxy.regularity", "timeout")]),
                       severity="low")  # fmt: skip
    nothing = await seed(migrated_engine, body([unknown("web.successes_after",
                                                        "ingest_not_verified")]))  # fmt: skip
    decided = await seed(migrated_engine, body(steps=TIMELINE), decided=True)
    gateway = FakeGateway(healthy())
    e = env(app_engine, gateway, per_day=2)
    async with app_engine.connect() as conn:
        chosen = await wave.select(e, conn, NOW, 10)
    # a floor gap first, then severity; none for an item with nothing to ask or already decided
    assert [p.current.investigation_id for p in chosen] == [floor, high, plain]
    assert await wave.run_pass(e, "w", wave=True, limit=5) == {**ZERO, "queued": 2, "done": 2}
    queued = await rows(app_engine, "SELECT investigation_id FROM investigation_checks"
                        " ORDER BY id")  # fmt: skip
    assert [r.investigation_id for r in queued] == [floor, high]
    assert {nothing, decided}.isdisjoint(r.investigation_id for r in queued)
    # the day's cap is used up: no more are queued, and the investigator no longer waits
    assert await wave.run_pass(e, "w", wave=True, limit=5) == ZERO
    async with app_engine.connect() as conn:
        assert await wave.owed(e, conn, NOW) == set()


async def test_the_ai_investigator_waits_for_the_waves_it_is_owed(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    owed = await seed(migrated_engine, body(steps=TIMELINE))
    nothing = await seed(migrated_engine, body())
    e = env(app_engine, FakeGateway(healthy()))
    async with app_engine.connect() as conn:
        assert await wave.owed(e, conn, NOW) == {owed}
    queue_id = await queue(app_engine, owed, "wave", "engine")
    assert queue_id is not None
    async with app_engine.connect() as conn:
        assert await wave.owed(e, conn, NOW) == {owed}  # queued is still owed
    async with app_engine.begin() as conn:
        await conn.execute(text("UPDATE investigation_checks SET status = 'running',"
                                " lease_until = :n"), {"n": NOW})  # fmt: skip
        await store.finish(conn, queue_id, "done", {}, NOW)
    async with app_engine.connect() as conn:
        assert await wave.owed(e, conn, NOW) == set()  # done: it may go to the investigator
    # the investigator's queue leaves the owed ones alone
    privacy = SimpleNamespace(request=lambda items: SimpleNamespace(text=json.dumps(items,
                              default=str)))  # fmt: skip
    again = await seed(migrated_engine, body(steps=TIMELINE))
    async with app_engine.begin() as conn:
        held = await runner.schedule(conn, privacy, "agent@1", NOW, after="engine@1",
                                     skip={again})  # fmt: skip
        assert held == 2  # `nothing` and the done one are queued, `again` is not
    queued = await rows(app_engine, "SELECT investigation_id FROM assessments"
                        " WHERE assessor = 'agent@1'")  # fmt: skip
    ids = {r.investigation_id for r in queued}
    assert again not in ids
    assert ids == {owed, nothing}


async def test_the_investigator_does_not_wait_for_a_wave_that_cannot_run(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    for state in (HealthState.CAUTION, HealthState.DEGRADED, HealthState.STOP):
        e = env(app_engine, FakeGateway(healthy(state)))
        async with app_engine.connect() as conn:
            assert await wave.owed(e, conn, NOW) == set()
    quiet = NOW.replace(hour=0, minute=30)
    e = env(app_engine, FakeGateway(healthy(at=quiet), now=quiet), now=quiet)
    async with app_engine.connect() as conn:
        assert await wave.owed(e, conn, quiet) == set()
    e = env(app_engine, FakeGateway(healthy()))
    async with app_engine.connect() as conn:
        assert await wave.owed(e, conn, NOW) == {inv}


async def test_the_wave_dossier_is_the_one_the_engine_assesses_next(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    await wave.run_pass(env(app_engine, FakeGateway(healthy())), "w", wave=True)
    privacy = SimpleNamespace(request=lambda items: SimpleNamespace(text=json.dumps(items,
                              default=str)))  # fmt: skip
    async with app_engine.begin() as conn:
        assert await runner.schedule(conn, privacy, "engine@1", NOW) == 1
    (row,) = await rows(app_engine, "SELECT pack FROM assessments WHERE assessor = 'engine@1'"
                        " AND status = 'queued'")  # fmt: skip
    assert row.pack == "generic+wave.1@12"
    assert inv


# ----------------------------------------------------------------------------- the table


async def test_the_runtime_cannot_delete_or_rewrite_what_a_request_asked(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    assert await queue(app_engine, inv, "wave", "engine") is not None
    for sql in ("DELETE FROM investigation_checks", "UPDATE investigation_checks SET kind = 'wave'",
                "UPDATE investigation_checks SET requested_by = 'x'",
                "TRUNCATE investigation_checks"):  # fmt: skip
        async with app_engine.connect() as conn:
            with pytest.raises((ProgrammingError, DBAPIError)):
                await conn.execute(text(sql))


async def test_a_request_without_its_name_or_target_is_refused_by_the_table(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    bad = [
        ("check", "person", "", "", "asha"),  # a check names its template and entity
        ("wave", "person", "proxy.host", HOST, "asha"),  # a wave names neither
        ("check", "engine", "proxy.host", HOST, None),  # the engine asks no entity
        ("check", "person", "proxy.host", HOST, None),  # a person is named
        ("check", "person", "Proxy Host", HOST, "asha"),  # a template's shape
        ("check", "person", "proxy.host", "x\ny", "asha"),  # no control characters
        ("wave", "somebody", "", "", None),
    ]
    for kind, source, template, entity, by in bad:
        async with app_engine.connect() as conn:
            with pytest.raises(DBAPIError):
                await conn.execute(
                    text(
                        "INSERT INTO investigation_checks (investigation_id, version, kind,"
                        " source, template, entity, requested_by, requested_at, status)"
                        " VALUES (:i, 1, :k, :s, :t, :e, :b, now(), 'queued')"
                    ),
                    {"i": inv, "k": kind, "s": source, "t": template, "e": entity, "b": by},
                )


async def test_the_web_may_queue_a_request_and_read_it_and_nothing_more(
    web_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    async with web_engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO investigation_checks (investigation_id, version, template,"
                 " entity, requested_by, requested_at) VALUES (:i, 1, 'proxy.host', :e, 'asha',"
                 " now())"), {"i": inv, "e": HOST})  # fmt: skip
        got = (await conn.execute(text("SELECT status FROM investigation_checks"))).scalar_one()
        assert got == "queued"  # the status is the table's own, not the web's to set
    for sql in ("UPDATE investigation_checks SET status = 'done'",
                "DELETE FROM investigation_checks"):  # fmt: skip
        async with web_engine.connect() as conn:
            with pytest.raises((ProgrammingError, DBAPIError)):
                await conn.execute(text(sql))
    async with web_engine.connect() as conn:
        with pytest.raises((ProgrammingError, DBAPIError)):  # nor set its own status
            await conn.execute(
                text(
                    "INSERT INTO investigation_checks (investigation_id, version, template,"
                    " entity, requested_by, requested_at, status) VALUES (:i, 1, 'proxy.host',"
                    " '10.0.0.1', 'asha', now(), 'done')"
                ),
                {"i": inv},
            )
    # the service sees the web's request
    async with app_engine.begin() as conn:
        (request,) = await store.claim(conn, "w", NOW, 1)
    assert (request.template, request.entity, request.requested_by) == ("proxy.host", HOST, "asha")


async def test_requests_go_with_their_investigation(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    await queue(app_engine, inv, "wave", "engine")
    async with migrated_engine.begin() as conn:
        for table in ("assessments", "dossiers"):
            await conn.execute(text(f"DELETE FROM {table} WHERE investigation_id = :i"), {"i": inv})  # noqa: S608
        await conn.execute(text("DELETE FROM investigations WHERE id = :i"), {"i": inv})
    assert await rows(migrated_engine, "SELECT 1 FROM investigation_checks") == []


async def test_a_finished_request_is_audited_without_its_entity(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(), decided=True)
    await queue(app_engine, inv, "check", "person", template="proxy.contact", entity=C2,
                requested_by="asha")  # fmt: skip
    await wave.run_pass(env(app_engine, FakeGateway(healthy())), "w", wave=False)
    (event,) = await rows(app_engine, "SELECT actor, action, outcome, target_id, details"
                          " FROM audit_events WHERE action = 'investigation.check'")  # fmt: skip
    assert (event.actor, event.outcome, event.target_id) == ("user:asha", "success", str(inv))
    assert event.details["template"] == "proxy.contact"
    assert (event.details["requests"], event.details["heavy"]) == (1, 1)
    assert event.details["dossier"] == "generic+wave.1@12"
    assert C2 not in json.dumps(event.details)
    # a refused request is audited as a failure, the engine's wave as the investigation's own
    await queue(app_engine, inv, "check", "person", template="proxy.host", entity=C2,
                requested_by="bina")  # fmt: skip
    await wave.run_pass(env(app_engine, FakeGateway(healthy())), "w", wave=False)
    refused = await rows(app_engine, "SELECT actor, outcome FROM audit_events"
                         " WHERE action = 'investigation.check' ORDER BY id")  # fmt: skip
    assert [(r.actor, r.outcome) for r in refused] == [("user:asha", "success"),
                                                      ("user:bina", "failure")]  # fmt: skip


async def test_a_check_is_requested_validated_and_queued_for_the_service(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(), decided=True)
    async with app_engine.begin() as conn:
        assert await checks.request(conn, inv, 1, "logs.source_events", HOST, "asha", NOW) == (
            "refused", "that is not a check a person may ask for")  # fmt: skip
        assert (await checks.request(conn, inv, 1, "proxy.host", "x y", "asha", NOW))[
            0
        ] == "refused"
        state, request_id = await checks.request(conn, inv, 1, "proxy.host", " 10.20.3.4 ",
                                                 "asha", NOW)  # fmt: skip
        assert state == "queued"
        assert isinstance(request_id, int)
        again, why = await checks.request(conn, inv, 1, "proxy.host", HOST, "bina", NOW)
        assert (again, why) == ("open", "the same request is queued or running already")
    (row,) = await rows(app_engine, "SELECT entity, requested_by, source, status"
                        " FROM investigation_checks")  # fmt: skip
    assert (row.entity, row.requested_by, row.source, row.status) == (HOST, "asha", "person",
                                                                      "queued")  # fmt: skip


async def test_one_investigations_damaged_dossier_never_stops_the_others(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    good = await seed(migrated_engine, body(steps=TIMELINE))
    bad = await seed(migrated_engine, body(steps=TIMELINE))
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "UPDATE dossiers SET body = jsonb_set(body, '{facts}', '[]')"
                " WHERE investigation_id = :i"
            ),
            {"i": bad},
        )
    e = env(app_engine, FakeGateway(healthy()))
    async with app_engine.connect() as conn:
        assert [p.current.investigation_id for p in await wave.select(e, conn, NOW, 10)] == [good]
        assert await wave.owed(e, conn, NOW) == {good}


async def test_a_person_may_not_fill_the_queue(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(), decided=True)
    async with app_engine.begin() as conn:
        for n in range(checks.OPEN_PER_PERSON):
            state, _ = await checks.request(conn, inv, 1, "proxy.host", f"10.20.3.{n + 1}",
                                            "asha", NOW)  # fmt: skip
            assert state == "queued"
        state, why = await checks.request(conn, inv, 1, "proxy.host", "10.20.9.9", "asha", NOW)
        assert state == "refused"
        assert "5 checks waiting" in str(why)
        assert (await checks.request(conn, inv, 1, "proxy.host", "10.20.9.9", "bina", NOW))[0] == (
            "queued"
        )  # someone else may still ask
