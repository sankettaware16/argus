"""Q-F3 review: one regression test per finding (R1 to R11), each shown failing on the tree the
reviewer attacked. The reviewer's repros are adapted here; ``tests/unit/investigation/
test_review.py`` holds the pure ones."""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import CliRunner

from argus.assess import runner
from argus.cli import app
from argus.context import batch1
from argus.context.packs import default_registry
from argus.gateway.breaker import BreakerState
from argus.gateway.errors import BreakerOpenError, DeferredError, StoppedError, TimedOutError
from argus.gateway.gateway import Gateway, Targets
from argus.gateway.health import HealthMemory
from argus.gateway.state import MemoryStore
from argus.investigation import checks, measure, service, store, wave
from argus.investigation.plan import Caps
from tests.integration.investigation.kit import (
    NOW,
    ON,
    FakeGateway,
    body,
    env,
    healthy,
    seed,
    unknown,
)
from tests.integration.investigation.test_cli import gold
from tests.integration.test_cli_db import cli_env  # noqa: F401
from tests.unit.gateway.fakes import FakeClock, FakeTransport, listing, ok
from tests.unit.investigation.kit import step

pytestmark = pytest.mark.integration
TIMELINE = [step(2, "deferred", ["timeline"])]
IDLE = {"queued": 0, "done": 0, "refused": 0, "failed": 0, "waiting": 0}


async def rows(engine: AsyncEngine, sql: str, **params: Any) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(sql), params)).all())


async def review(owner: AsyncEngine, inv: uuid.UUID) -> None:
    """A person reviews the investigation (version 1)."""
    async with owner.begin() as conn:
        user = (await conn.execute(text("SELECT id FROM users ORDER BY id LIMIT 1"))).scalar()
        if user is None:
            user = (await conn.execute(text(
                "INSERT INTO users (username, display_name, password_hash)"
                " VALUES ('asha', 'Asha', 'x') RETURNING id"))).scalar_one()  # fmt: skip
        await conn.execute(
            text("INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                 " action, outcome) VALUES (:i, 1, 4, :u, 'reviewed', 'benign_expected')"),
            {"i": inv, "u": user},
        )  # fmt: skip


async def run(e: wave.Env, inv: uuid.UUID, origin: str = "wave") -> dict[str, Any]:
    """One wave for ``inv`` as the pass would run it: prepare, plan, execute."""
    async with e.engine.connect() as conn:
        prep = await wave.prepare(e, conn, inv, e.clock())
        assert prep is not None
        plan = await wave.plan_wave(e, conn, prep, e.clock())
    return await wave.execute(e, prep, plan, origin)


async def finished_wave(owner: AsyncEngine, app_engine: AsyncEngine) -> uuid.UUID:
    """An engine wave that ran today (it counts against the day's cap)."""
    inv = await seed(owner, body(steps=TIMELINE))
    async with app_engine.begin() as conn:
        made = await store.enqueue(conn, inv, 1, "wave", "engine", NOW)
        assert made is not None
        (request,) = await store.claim(conn, "w", NOW, 1, only=[made])
        await store.finish(conn, request.id, "done", {}, NOW)
    return inv


# ----------------------------------------------------------------------------- R1: lane debt


def a_heavy_answer(took: int) -> dict[str, Any]:
    return {
        "took": took, "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
        "hits": {"total": {"value": 3, "relation": "eq"}, "hits": []},
        "aggregations": {
            "destination_count": {"value": 3}, "bytes": {"value": 10},
            "timeline": {"buckets": [{"doc_count": 1}, {"doc_count": 0}, {"doc_count": 1}]},
        },
    }  # fmt: skip


async def test_r1_the_lanes_own_debt_is_a_wait_never_a_stored_timeout(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """One heavy answer of 2 s puts the investigation lane (400 ms a minute) in debt for about
    five minutes. The next wave's request used to get "frees up too late" at once, was stored as
    a SIEM timeout, and the investigation's only engine wave was spent."""
    await seed(migrated_engine, body(steps=TIMELINE))
    await seed(migrated_engine, body(steps=TIMELINE))
    clock = FakeClock(now=NOW)
    transport = FakeTransport(clock=clock, latency=timedelta(milliseconds=2000))
    days = ("2026.10.23", "2026.10.24", "2026.10.25")
    transport.on("_resolve", ok(listing(*(f"acme-logs-squid-{d}" for d in days))))
    transport.on("_search", ok(a_heavy_answer(2000)))
    memory = MemoryStore(memory=HealthMemory(probed_at=NOW))
    gateway = Gateway(transport, memory, targets=Targets(log_sources=frozenset({"squid"})),
                      clock=clock, sleep=clock.sleep)  # fmt: skip
    e = wave.Env(engine=app_engine, state=memory, gateway=gateway, packs=default_registry(),
                 switches=ON, is_campus=batch1.private_or(None), caps=Caps(), per_day=120,
                 clock=clock)  # fmt: skip

    def searches() -> int:
        return sum("_search" in c.path for c in transport.calls)

    memory.memory = HealthMemory(probed_at=clock.now)
    first = await wave.run_pass(e, "w", wave=True, limit=2)
    assert (first["done"], first["waiting"], first["failed"]) == (1, 1, 0)
    assert searches() == 1
    stored = await rows(app_engine, "SELECT status FROM evidence")
    assert [r.status for r in stored] == ["ok"]  # the debt is no SIEM timeout
    after = await rows(app_engine, "SELECT status, outcome FROM investigation_checks"
                       " ORDER BY id")  # fmt: skip
    assert [r.status for r in after] == ["done", "queued"]
    assert after[1].outcome is None or set(after[1].outcome) == {"progress"}
    assert e.hold_until is not None
    assert e.hold_until - clock.now > timedelta(minutes=2)  # planned against the lane's retry
    # until the lane has paid its debt, a pass claims nothing and sends nothing
    memory.memory = HealthMemory(probed_at=clock.now)
    assert await wave.run_pass(e, "w", wave=True, limit=2) == IDLE
    assert searches() == 1
    clock.advance(e.hold_until - clock.now + timedelta(seconds=1))
    memory.memory = HealthMemory(probed_at=clock.now)
    later = await wave.run_pass(e, "w", wave=True, limit=2)
    assert (later["done"], later["waiting"]) == (1, 0)
    assert searches() == 2
    states = await rows(app_engine, "SELECT status FROM evidence")
    assert [r.status for r in states] == ["ok", "ok"]
    done = await rows(app_engine, "SELECT status FROM investigation_checks ORDER BY id")
    assert [r.status for r in done] == ["done", "done"]


# ----------------------------------------------------------------------------- R2: stopped waves


@pytest.mark.parametrize(
    "failure",
    [DeferredError("the SIEM is caution: investigate waits"), StoppedError("stop"),
     BreakerOpenError(None)],
    ids=["deferred", "stopped", "breaker"],
)  # fmt: skip
async def test_r2_a_wave_stopped_by_the_siem_goes_back_in_the_queue_unspent(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, failure: Exception
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    flapping = FakeGateway(healthy(), fail={"proxy.host": failure})
    e = env(app_engine, flapping)
    first = await wave.run_pass(e, "w", wave=True)
    assert (first["queued"], first["done"], first["waiting"], first["failed"]) == (1, 0, 1, 0)
    (row,) = await rows(app_engine, "SELECT status, started_at, claims, outcome, finished_at"
                        " FROM investigation_checks")  # fmt: skip
    assert (row.status, row.started_at, row.claims, row.finished_at) == ("queued", None, 0, None)
    assert row.outcome is None or set(row.outcome) == {"progress"}
    assert (await rows(app_engine, "SELECT count(*) AS n FROM evidence"))[0].n == 0
    async with app_engine.connect() as conn:
        assert await store.waves_today(conn, NOW) == 0  # not counted against the day's cap
        assert await wave.owed(e, conn, NOW) == {inv}  # and still owed
    # the same process waits before it asks again
    assert e.hold_until is not None
    assert await wave.run_pass(e, "w", wave=True) == IDLE
    # The SIEM is well again: the investigation gets its engine wave, once
    good = FakeGateway(healthy())
    second = await wave.run_pass(env(app_engine, good), "w", wave=True)
    assert (second["done"], second["queued"]) == (1, 0)
    assert [c[0] for c in good.calls] == ["proxy.host"]
    third = await wave.run_pass(env(app_engine, good), "w", wave=True)
    assert third["done"] == 0
    (row,) = await rows(app_engine, "SELECT status FROM investigation_checks")
    assert row.status == "done"


async def test_r2_a_check_stopped_by_the_siem_is_put_back_too(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE), decided=True)
    async with app_engine.begin() as conn:
        await checks.request(conn, inv, 1, "proxy.host", "10.20.3.9", "asha", NOW)
    flapping = FakeGateway(healthy(), fail={"proxy.host": DeferredError("busy")})
    counts = await wave.run_pass(env(app_engine, flapping), "w", wave=False)
    assert (counts["waiting"], counts["done"]) == (1, 0)
    (row,) = await rows(app_engine, "SELECT status, outcome FROM investigation_checks")
    assert row.status == "queued"
    good = FakeGateway(healthy())
    assert (await wave.run_pass(env(app_engine, good), "w", wave=False))["done"] == 1


async def test_r2_a_last_moment_health_refusal_puts_the_wave_back(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The batch-1 rules said no between planning and sending (the SIEM left NORMAL): a run-level
    stop, not a stored "deferred" check that spends the wave."""
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    e = env(app_engine, FakeGateway(healthy()))
    async with app_engine.connect() as conn:
        prep = await wave.prepare(e, conn, inv, NOW)
        assert prep is not None
        plan = await wave.plan_wave(e, conn, prep, NOW)

    async def say_no(env_: Any, task: Any, deadline: Any) -> Any:
        raise wave._Refused(batch1.Refusal("not_normal", "caution"))

    monkeypatch.setattr(wave, "_dispatch", say_no)
    outcome = await wave.execute(e, prep, plan, "wave")
    assert outcome["later"] is not None
    assert outcome["dossier"] is None
    assert (await rows(app_engine, "SELECT count(*) AS n FROM evidence"))[0].n == 0


async def test_r2_a_kill_switch_or_an_open_breaker_means_no_wave_can_run(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await seed(migrated_engine, body(steps=TIMELINE))
    for stopped in ({"investigation"}, {"global"}):
        state = healthy()
        state.stopped = set(stopped)
        e = env(app_engine, FakeGateway(state))
        assert not await wave.ready(e, NOW), stopped
        assert await wave.run_pass(e, "w", wave=True) == IDLE
        async with app_engine.connect() as conn:
            assert await wave.owed(e, conn, NOW) == set()  # the investigator does not wait
    other = healthy()
    other.stopped = {"collector"}  # another component's switch is none of the wave's business
    assert await wave.ready(env(app_engine, FakeGateway(other)), NOW)
    tripped = healthy()
    tripped.breaker = BreakerState(level=1, open_until=NOW + timedelta(minutes=5))
    assert not await wave.ready(env(app_engine, FakeGateway(tripped)), NOW)
    after = NOW + timedelta(minutes=6)
    tripped.memory = HealthMemory(probed_at=after)  # and the SIEM was probed since
    assert await wave.ready(env(app_engine, FakeGateway(tripped, now=after), now=after), after)
    assert (await rows(app_engine, "SELECT count(*) AS n FROM investigation_checks"))[0].n == 0


async def test_r2_a_wave_that_stopped_part_way_goes_on_where_it_left_off(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """Two checks; the second hits a stop. The first answer is kept and not asked again, the
    wave's caps count both runs, and the dossier is left once, by the run that finishes."""
    dossier = body([unknown("proxy.hosts_to_destination", "failed")], TIMELINE)
    inv = await seed(migrated_engine, dossier)
    flapping = FakeGateway(healthy(), fail={"proxy.host": DeferredError("busy")})
    first = await wave.run_pass(env(app_engine, flapping), "w", wave=True)
    assert first["waiting"] == 1
    assert [c[0] for c in flapping.calls] == ["proxy.destination", "proxy.host"]
    (row,) = await rows(app_engine, "SELECT outcome FROM investigation_checks")
    assert row.outcome["progress"]["requests"] == 1  # the answered one is remembered
    assert [r.status for r in await rows(app_engine, "SELECT status FROM evidence")] == ["ok"]
    good = FakeGateway(healthy())
    second = await wave.run_pass(env(app_engine, good), "w", wave=True)
    assert second["done"] == 1
    assert [c[0] for c in good.calls] == ["proxy.host"]  # only what was still to ask
    (done,) = await rows(app_engine, "SELECT outcome FROM investigation_checks")
    assert done.outcome["requests"] == 2  # the record counts both runs
    packs = [r.pack for r in await rows(app_engine, "SELECT pack FROM dossiers"
                                        " WHERE investigation_id = :i", i=inv)]  # fmt: skip
    assert sorted(packs) == ["generic+wave.1@12", "generic@12"]


# ----------------------------------------------------------------------------- R3: stale waves


async def test_r3_a_wave_queued_before_a_person_reviewed_is_refused(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    async with app_engine.begin() as conn:
        await store.enqueue(conn, inv, 1, "wave", "engine", NOW)
    await review(migrated_engine, inv)
    gateway = FakeGateway(healthy())
    counts = await wave.run_pass(env(app_engine, gateway), "w", wave=True, limit=1)
    assert (counts["refused"], counts["done"]) == (1, 0)
    assert gateway.calls == []  # not a request of the lane's budget
    (row,) = await rows(app_engine, "SELECT status, outcome FROM investigation_checks")
    assert row.status == "refused"
    assert "reviewed" in row.outcome["error"]
    async with app_engine.connect() as conn:
        assert await store.waves_today(conn, NOW) == 0  # a refused wave costs the cap nothing


async def test_r3_nor_is_a_wave_run_for_an_investigation_the_engine_has_decided_since(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    async with app_engine.begin() as conn:
        await store.enqueue(conn, inv, 1, "wave", "engine", NOW)
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE assessments SET status = 'proposed',"
                                " outcome = 'benign_expected', confidence = 0.9"))  # fmt: skip
    gateway = FakeGateway(healthy())
    counts = await wave.run_pass(env(app_engine, gateway), "w", wave=True, limit=1)
    assert (counts["refused"], counts["done"]) == (1, 0)
    assert gateway.calls == []
    (row,) = await rows(app_engine, "SELECT outcome FROM investigation_checks")
    assert "decided" in row.outcome["error"]


async def test_r3_nor_for_an_investigation_that_has_a_newer_version(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    async with app_engine.begin() as conn:
        await store.enqueue(conn, inv, 1, "wave", "engine", NOW)
    async with migrated_engine.begin() as conn:
        await conn.execute(text(
            "INSERT INTO dossiers (investigation_id, version, facts_version, job_id, run_kind,"
            " family, pack, status, dossier_hash, body, evidence_count, created_at)"
            " SELECT investigation_id, 2, 2, job_id, run_kind, family, pack, status,"
            " repeat('b', 64), body, evidence_count, created_at + interval '1 minute'"
            " FROM dossiers"))  # fmt: skip
        await conn.execute(text("UPDATE investigations SET version = 2"))
    gateway = FakeGateway(healthy())
    counts = await wave.run_pass(env(app_engine, gateway), "w", wave=True, limit=1)
    assert (counts["refused"], counts["done"]) == (1, 0)
    assert gateway.calls == []
    (row,) = await rows(app_engine, "SELECT outcome FROM investigation_checks")
    assert "newer version" in row.outcome["error"]


async def test_r3_a_persons_check_still_runs_on_a_reviewed_investigation(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """Only the engine's own wave is withdrawn: a person asked for their check by name."""
    inv = await seed(migrated_engine, body(steps=TIMELINE), decided=True)
    await review(migrated_engine, inv)
    async with app_engine.begin() as conn:
        await checks.request(conn, inv, 1, "proxy.host", "10.20.3.9", "asha", NOW)
    gateway = FakeGateway(healthy())
    counts = await wave.run_pass(env(app_engine, gateway), "w", wave=False)
    assert counts["done"] == 1
    assert [c[0] for c in gateway.calls] == ["proxy.host"]


# ----------------------------------------------------------------------------- R4: the queue


async def test_r4_the_days_cap_is_spent_by_waves_that_run_and_a_critical_one_goes_first(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    lows = [await seed(migrated_engine, body(steps=TIMELINE), severity="low") for _ in range(3)]
    e = env(app_engine, FakeGateway(healthy()), per_day=3)
    first = await wave.run_pass(e, "w", wave=True)
    assert (first["queued"], first["done"]) == (1, 1)  # nothing is queued that will not run now
    critical = await seed(migrated_engine, body(steps=TIMELINE), severity="critical")
    second = await wave.run_pass(e, "w", wave=True)
    assert (second["queued"], second["done"]) == (1, 1)
    order = [r.investigation_id for r in await rows(
        app_engine, "SELECT investigation_id FROM investigation_checks ORDER BY id")]  # fmt: skip
    assert order[1] == critical
    assert order[0] in lows
    assert (await wave.run_pass(e, "w", wave=True))["done"] == 1
    assert (await wave.run_pass(e, "w", wave=True))["done"] == 0  # the cap of 3 is spent
    assert len(await rows(app_engine, "SELECT 1 FROM investigation_checks")) == 3


async def test_r4_an_open_engine_wave_keeps_the_investigator_waiting_after_the_cap(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """``owed`` returned nothing once the cap was spent, whatever was still queued, so agent@1
    ran before the wave it was held back for."""
    waved = await finished_wave(migrated_engine, app_engine)
    waiting = await seed(migrated_engine, body(steps=TIMELINE))
    free = await seed(migrated_engine, body(steps=TIMELINE))
    async with app_engine.begin() as conn:
        await store.enqueue(conn, waiting, 1, "wave", "engine", NOW)
    e = env(app_engine, FakeGateway(healthy()), per_day=1)  # the cap is spent: one wave ran
    async with app_engine.connect() as conn:
        assert await store.waves_today(conn, NOW) == 1
        owed = await wave.owed(e, conn, NOW)
    assert owed == {waiting}  # the open wave still holds the investigator; `free` will not run
    privacy = SimpleNamespace(
        request=lambda items: SimpleNamespace(text=json.dumps(items, default=str))
    )
    async with app_engine.begin() as conn:
        await runner.schedule(conn, privacy, "agent@1", NOW, after="engine@1", skip=owed)
    got = {r.investigation_id for r in await rows(
        app_engine,
        "SELECT investigation_id FROM assessments WHERE assessor = 'agent@1'")}  # fmt: skip
    assert waiting not in got
    assert {waved, free} <= got


async def test_r4_a_wave_stuck_for_days_stops_holding_the_investigator(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await finished_wave(migrated_engine, app_engine)
    stale = await seed(migrated_engine, body(steps=TIMELINE))
    fresh = await seed(migrated_engine, body(steps=TIMELINE))
    async with app_engine.begin() as conn:
        await store.enqueue(conn, stale, 1, "wave", "engine", NOW - timedelta(days=2))
        await store.enqueue(conn, fresh, 1, "wave", "engine", NOW)
    e = env(app_engine, FakeGateway(healthy()), per_day=1)
    async with app_engine.connect() as conn:
        assert await wave.owed(e, conn, NOW) == {fresh}  # an outage must not hold it for ever


# ----------------------------------------------------------------------------- R10: starvation


async def test_r10_one_accounts_checks_cannot_keep_the_engine_waves_waiting(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    for _ in range(5):
        await seed(migrated_engine, body(steps=TIMELINE))
    target = await seed(migrated_engine, body(steps=TIMELINE), decided=True)
    e = env(app_engine, FakeGateway(healthy()), per_day=120)
    for n in range(12):
        async with app_engine.begin() as conn:
            for k in range(checks.OPEN_PER_PERSON):  # topped up to what the cap allows
                await checks.request(conn, target, 1, "proxy.host", f"10.77.{n}.{k + 1}",
                                     "asha", NOW)  # fmt: skip
        await wave.run_pass(e, "w", wave=True, limit=1)
    by = await rows(app_engine, "SELECT source, status, count(*) AS n FROM investigation_checks"
                    " GROUP BY 1, 2")  # fmt: skip
    engine_done = sum(r.n for r in by if r.source == "engine" and r.status == "done")
    person_done = sum(r.n for r in by if r.source == "person" and r.status == "done")
    assert engine_done >= 2, [tuple(r) for r in by]
    assert person_done > engine_done  # people are still first


async def test_r10_a_person_has_a_daily_limit_on_checks(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE), decided=True)
    results = []
    for n in range(checks.PER_PERSON_PER_DAY + 3):
        async with app_engine.begin() as conn:
            got = await checks.request(conn, inv, 1, "proxy.host", f"10.88.0.{n + 1}", "asha", NOW)
            await conn.execute(text("UPDATE investigation_checks SET status = 'done',"
                                    " finished_at = now()"))  # fmt: skip
        results.append(got[0])
    assert results.count("queued") == checks.PER_PERSON_PER_DAY
    assert set(results[checks.PER_PERSON_PER_DAY :]) == {"refused"}
    async with app_engine.begin() as conn:  # another person is not held up by it
        other = await checks.request(conn, inv, 1, "proxy.host", "10.88.9.9", "ravi", NOW)
    assert other[0] == "queued"


# ----------------------------------------------------------------------------- R11: the CLI


@pytest.mark.usefixtures("cli_env")
async def test_r11_the_cli_claims_only_the_request_it_asked_for(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("argus.investigation.cli._now", lambda: NOW)
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    async with app_engine.begin() as conn:
        for n in range(3):  # three people's checks waiting for the service
            await store.enqueue(conn, inv, 1, "check", "person", NOW - timedelta(minutes=10 - n),
                                template="proxy.host", entity=f"10.20.3.{n + 10}",
                                requested_by=f"p{n}")  # fmt: skip
    gateway = FakeGateway(healthy())

    async def fake_open(settings: Any, engine: AsyncEngine, classifier: Any) -> Any:
        async def close() -> None:
            return None

        return env(engine, gateway), close

    monkeypatch.setattr(service, "open_env", fake_open)
    monkeypatch.setattr("argus.investigation.cli.secrets.choice", lambda words: words[0])

    def invoke() -> tuple[int, str]:
        result = CliRunner().invoke(app, ["investigation", "wave", "--id", str(inv)],
                                    input="amber\n")  # fmt: skip
        return result.exit_code, result.output + result.stderr

    code, out = await asyncio.to_thread(invoke)
    assert code == 0, out
    got = await rows(app_engine, "SELECT requested_by, status, claims FROM investigation_checks"
                     " ORDER BY id")  # fmt: skip
    mine = [r for r in got if str(r.requested_by).startswith("cli:")]
    others = [r for r in got if not str(r.requested_by).startswith("cli:")]
    assert [r.status for r in mine] == ["done"]
    assert [(r.status, r.claims) for r in others] == [("queued", 0)] * 3


# ----------------------------------------------------------------------------- the claim itself


async def test_claim_takes_only_the_requested_ids_and_a_source(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    async with app_engine.begin() as conn:
        a = await store.enqueue(conn, inv, 1, "check", "person", NOW, template="proxy.host",
                                entity="10.20.3.4", requested_by="p")  # fmt: skip
        b = await store.enqueue(conn, inv, 1, "wave", "engine", NOW)
        assert a is not None
        assert b is not None
        assert await store.claim(conn, "w", NOW, 5, only=[]) == []
        taken = await store.claim(conn, "w", NOW, 5, only=[b])
        assert [r.id for r in taken] == [b]
        assert await store.claim(conn, "w", NOW, 5, source="engine") == []
        again = await store.claim(conn, "w", NOW, 5, source="person")
        assert [r.id for r in again] == [a]


async def test_a_running_request_can_be_put_back_and_only_that(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    async with app_engine.begin() as conn:
        a = await store.enqueue(conn, inv, 1, "wave", "engine", NOW)
        assert a is not None
        assert not await store.requeue(conn, a, NOW)  # not running: nothing to put back
        (taken,) = await store.claim(conn, "w", NOW, 1)
        assert taken.claims == 1
        assert await store.requeue(conn, a, NOW, {"requests": 1})
        (row,) = (await conn.execute(text("SELECT status, claims, started_at, lease_until, outcome"
                                          " FROM investigation_checks"))).all()  # fmt: skip
        assert (row.status, row.claims, row.started_at, row.lease_until) == (
            "queued", 0, None, None)  # fmt: skip
        assert row.outcome == {"progress": {"requests": 1}}
        with pytest.raises((ValueError, DBAPIError)):
            await store.finish(conn, a, "queued", {}, NOW)


# ----------------------------------------------------------------------------- R5: the retry


async def active(owner: AsyncEngine, **kw: Any) -> uuid.UUID:
    """An investigation still going on: its last alert was 50 minutes before NOW, so the window
    of a proxy request follows the clock."""
    d = body(steps=TIMELINE)
    d["facts"] = {**d["facts"], "last_event_at": (NOW - timedelta(minutes=50)).isoformat()}
    return await seed(owner, d, **kw)


async def test_r5_a_retry_on_a_still_active_investigation_is_the_same_request(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """The window of a request about an investigation that is still going on follows the
    clock, so asked again it had a key of its own: its answer was paid for and stored but the
    dossier held the failed one (``feed`` refuses another key of a template it has), it was
    never shown, and every later wave asked again."""
    inv = await active(migrated_engine)
    first = await run(env(app_engine, FakeGateway(healthy(), fail={"proxy.host": TimedOutError(
        "slow")})), inv)  # fmt: skip
    assert first["checks"][0]["status"] == "timeout"
    later = NOW + timedelta(minutes=70)
    good = FakeGateway(healthy(at=later))
    second = await run(env(app_engine, good, now=later), inv)
    assert second["requests"] == 1
    evidence = await rows(app_engine, "SELECT task_key, status FROM evidence")
    assert [r.status for r in evidence] == ["ok"]  # the failed row was replaced, not joined
    newest = (await rows(app_engine, "SELECT body -> 'report' -> 'steps' -> 0 ->> 'status' AS s"
                         " FROM dossiers ORDER BY created_at DESC, pack DESC"
                         " LIMIT 1"))[0]  # fmt: skip
    assert newest.s == "answered"  # and the person sees the answer
    again = NOW + timedelta(minutes=140)
    third_gateway = FakeGateway(healthy(at=again))
    third = await run(env(app_engine, third_gateway, now=again), inv)
    assert third["requests"] == 0  # nothing more to ask
    assert third_gateway.calls == []


async def test_r5_a_persons_retry_of_a_failed_check_replaces_it(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await active(migrated_engine, decided=True)
    async with app_engine.begin() as conn:
        await checks.request(conn, inv, 1, "proxy.host", "10.20.3.9", "asha", NOW)
    flaky = FakeGateway(healthy(), fail={"proxy.host": TimedOutError("slow")})
    assert (await wave.run_pass(env(app_engine, flaky), "w", wave=False))["done"] == 1
    later = NOW + timedelta(minutes=70)
    async with app_engine.begin() as conn:
        await checks.request(conn, inv, 1, "proxy.host", "10.20.3.9", "asha", later)
    good = FakeGateway(healthy(at=later))
    assert (await wave.run_pass(env(app_engine, good, now=later), "w", wave=False))["done"] == 1
    assert [r.status for r in await rows(app_engine, "SELECT status FROM evidence")] == ["ok"]


async def test_r5_another_subject_is_still_a_check_of_its_own(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """Only the same subject is the same request: a check about another host is not folded
    into the failed one, so it cannot replace the dossier's own subject."""
    inv = await active(migrated_engine, decided=True)
    async with app_engine.begin() as conn:
        await checks.request(conn, inv, 1, "proxy.host", "10.20.3.9", "asha", NOW)
    flaky = FakeGateway(healthy(), fail={"proxy.host": TimedOutError("slow")})
    await wave.run_pass(env(app_engine, flaky), "w", wave=False)
    async with app_engine.begin() as conn:
        await checks.request(conn, inv, 1, "proxy.host", "10.20.3.77", "asha", NOW)
    good = FakeGateway(healthy())
    await wave.run_pass(env(app_engine, good), "w", wave=False)
    found = await rows(app_engine, "SELECT params ->> 'ip' AS ip, status FROM evidence"
                       " ORDER BY ip")  # fmt: skip
    assert [(r.ip, r.status) for r in found] == [("10.20.3.77", "ok"), ("10.20.3.9", "timeout")]


# ----------------------------------------------------------------------------- R6: the leak


async def test_r6_the_gold_measurement_keeps_the_dev_split_apart(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    ids = [await seed(migrated_engine, body(steps=TIMELINE)) for _ in range(6)]
    await gold(migrated_engine, dict.fromkeys(ids, "true_positive"))  # even items dev, odd test
    e = env(app_engine, FakeGateway(healthy()))
    async with app_engine.connect() as conn:
        default = await measure.measure(e, conn)
        everything = await measure.measure(e, conn, split=None)
        dev = await measure.measure(e, conn, split="dev")
    assert set(default.splits.values()) == {"test"}
    assert len(default.answers) == 3
    assert set(everything.splits.values()) == {"dev", "test"}
    assert len(everything.answers) == 6
    assert set(dev.splits.values()) == {"dev"}
    text_ = "\n".join(measure.report(everything))
    assert text_.index("== test split ==") < text_.index("== dev split ==")
    assert "== dev split" not in "\n".join(measure.report(default))


# ----------------------------------------------------------------------------- R8: the entity


@pytest.mark.parametrize(
    "entity",
    ["fe80::1%a\x07b", "fe80::1%" + "a" * 300, "fe80::1%a\x00b", "fe80::1%gooda\u202eb",
     "fe80::1%eth0", "10.0.0.1\n10.0.0.2", "\u202eevil.example"],
    ids=["bell", "long", "nul", "bidi", "scope", "newline", "reversed"],
)  # fmt: skip
async def test_r8_a_value_the_table_would_refuse_is_a_typed_refusal(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, entity: str
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    async with app_engine.begin() as conn:
        got = await checks.request(conn, inv, 1, "ti.lookup", entity, "asha", NOW)
    assert got[0] == "refused"
    assert (await rows(app_engine, "SELECT count(*) AS n FROM investigation_checks"))[0].n == 0


# ----------------------------------------------------------------------------- R9: the caps


async def test_r9_eight_requests_at_once_cannot_pass_the_same_count(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every request reads the person's open count before any of them inserts (a barrier makes
    the race certain instead of likely): the count was the only guard, so all eight passed and
    twelve checks were open against a cap of five."""
    inv = await seed(migrated_engine, body(steps=TIMELINE), decided=True)
    barrier = asyncio.Barrier(8)
    counted = store.open_requests

    async def read_then_wait(conn: Any, by: str) -> Any:
        got = await counted(conn, by)
        await barrier.wait()
        return got

    monkeypatch.setattr(store, "open_requests", read_then_wait)
    async with app_engine.begin() as conn:
        for n in range(checks.OPEN_PER_PERSON - 1):
            await store.enqueue(conn, inv, 1, "check", "person", NOW, template="proxy.host",
                                entity=f"10.20.3.{n + 10}", requested_by="asha")  # fmt: skip

    async def one(n: int) -> tuple[str, int | str]:
        async with app_engine.begin() as conn:
            return await checks.request(conn, inv, 1, "proxy.host", f"10.20.4.{n}", "asha", NOW)

    got_all = await asyncio.gather(*[one(n) for n in range(8)])
    assert sorted(g[0] for g in got_all) == ["queued"] + ["refused"] * 7
    open_ = await rows(app_engine, "SELECT count(*) AS n FROM investigation_checks"
                       " WHERE requested_by = 'asha' AND status = 'queued'")  # fmt: skip
    assert open_[0].n == checks.OPEN_PER_PERSON
    assert all("waiting" in str(g[1]) for g in got_all if g[0] == "refused")


async def insert_as_web(engine: AsyncEngine, inv: uuid.UUID, by: str, entity: str,
                        extra: str = "", values: str = "") -> None:  # fmt: skip
    async with engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO investigation_checks (investigation_id, version, template, entity,"  # noqa: S608
                 f" requested_by, requested_at{extra}) VALUES (:i, 1, 'proxy.host', :e, :b, now()"
                 f"{values})"),
            {"i": inv, "e": entity, "b": by},
        )  # fmt: skip


@pytest.mark.parametrize("column", ["kind", "source", "created_at", "status", "claims"])
async def test_r9_the_web_cannot_set_what_makes_a_request_the_engines(
    web_engine: AsyncEngine, migrated_engine: AsyncEngine, column: str
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    value = {"kind": "'wave'", "source": "'engine'", "created_at": "now() - interval '2 days'",
             "status": "'running'", "claims": "0"}[column]  # fmt: skip
    with pytest.raises(DBAPIError) as info:
        await insert_as_web(web_engine, inv, "victim", "10.9.9.9", f", {column}", f", {value}")
    assert "permission denied" in str(info.value)


async def test_r9_what_the_web_adds_is_a_persons_check_and_nothing_else(
    web_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    await insert_as_web(web_engine, inv, "asha", "10.9.9.9")
    (row,) = await rows(migrated_engine, "SELECT kind, source, status FROM investigation_checks")
    assert (row.kind, row.source, row.status) == ("check", "person", "queued")
    with pytest.raises(DBAPIError):  # no template or entity: it would be a wave, which it cannot be
        async with web_engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO investigation_checks (investigation_id, version, requested_by,"
                     " requested_at) VALUES (:i, 1, 'the-lead', now())"), {"i": inv})  # fmt: skip


async def test_r9_the_table_holds_the_limits_against_the_web_too(
    web_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    for n in range(checks.OPEN_PER_PERSON):
        await insert_as_web(web_engine, inv, "victim", f"10.9.9.{n + 1}")
    with pytest.raises(DBAPIError) as info:
        await insert_as_web(web_engine, inv, "victim", "10.9.9.99")
    assert getattr(info.value.orig, "sqlstate", None) == "AR001"
    assert "you have 5 checks waiting already" in str(info.value.orig)
    await insert_as_web(web_engine, inv, "ravi", "10.9.8.1")  # another person is not held up


async def test_r9_nor_can_more_than_a_hundred_checks_wait(
    web_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    for n in range(checks.OPEN_IN_ALL):
        await insert_as_web(web_engine, inv, f"person{n}", f"10.9.{n // 200}.{n % 200 + 1}")
    with pytest.raises(DBAPIError) as info:
        await insert_as_web(web_engine, inv, "one-more", "10.9.99.1")
    assert "too many checks are waiting" in str(info.value.orig)
