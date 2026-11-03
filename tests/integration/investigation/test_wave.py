"""Q-F3 on Postgres: the deterministic wave for an undecided investigation, end to end with a
fake gateway. Each test seeds investigations with a dossier as the generic pack stores it."""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.gateway.errors import DeferredError, StoppedError, TemplateRejectedError, TimedOutError
from argus.gateway.health import HealthState
from argus.gateway.templates import Purpose
from argus.investigation import store, wave
from argus.investigation.catalogue import Switches
from argus.investigation.plan import Caps
from argus.report import store as report_store
from tests.integration.investigation.kit import (
    NOW,
    FakeGateway,
    body,
    env,
    healthy,
    seed,
    unknown,
)
from tests.unit.investigation.kit import TI_UNANSWERED, step

pytestmark = pytest.mark.integration
TIMELINE = [step(2, "deferred", ["timeline"])]


async def rows(engine: AsyncEngine, sql: str, **params: Any) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(sql), params)).all())


async def run(e: wave.Env, inv: uuid.UUID, origin: str = "wave") -> dict[str, Any]:
    async with e.engine.connect() as conn:
        prep = await wave.prepare(e, conn, inv, e.clock())
        assert prep is not None
        plan = await wave.plan_wave(e, conn, prep, e.clock())
    return await wave.execute(e, prep, plan, origin)


async def packs(engine: AsyncEngine, inv: uuid.UUID) -> list[str]:
    found = await rows(engine, "SELECT pack FROM dossiers WHERE investigation_id = :i"
                       " ORDER BY created_at, pack DESC", i=inv)  # fmt: skip
    return [r.pack for r in found]


async def test_a_wave_asks_the_ranked_check_and_leaves_a_dossier(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    gateway = FakeGateway(healthy())
    e = env(app_engine, gateway)
    async with app_engine.connect() as conn:
        prep = await wave.prepare(e, conn, inv, NOW)
        assert prep is not None
        plan = await wave.plan_wave(e, conn, prep, NOW)
    assert [c.template for c in plan.sends] == ["proxy.host"]
    outcome = await wave.execute(e, prep, plan, "wave")
    # sent through the investigation lane, never the enrichment lane
    assert gateway.calls == [("proxy.host", Purpose.INVESTIGATE, "investigation")]
    assert (outcome["requests"], outcome["heavy"], outcome["server_ms"]) == (1, 1, 7)
    assert outcome["dossier"] == "generic+wave.1@12"
    assert outcome["stopped"] is None
    (request,) = await rows(
        app_engine, "SELECT eid, template, origin, reason FROM evidence_requests"
    )
    assert request.eid == 1
    assert (request.template, request.origin) == ("proxy.host", "wave")
    assert "Step 2 of the rule's note" in request.reason
    assert await packs(app_engine, inv) == ["generic@12", "generic+wave.1@12"]
    (new,) = await rows(app_engine, "SELECT body, status, evidence_count FROM dossiers"
                        " WHERE pack = 'generic+wave.1@12'")  # fmt: skip
    assert new.body["report"]["steps"][0]["status"] == "answered"
    assert new.body["pack"] == "generic+wave.1@12"
    assert new.body["wave"]["round"] == 1
    assert new.body["wave"]["of"] == "generic@12"
    assert new.status == "evidence_ready"
    assert new.evidence_count == len(new.body["evidence"]) == 1
    signals = await rows(app_engine, "SELECT name FROM signals WHERE pack = 'generic+wave.1@12'")
    assert {"proxy.busy_slots", "proxy.destinations"} <= {s.name for s in signals}
    audit = await rows(app_engine, "SELECT action, details FROM audit_events"
                       " WHERE action = 'dossier.wave'")  # fmt: skip
    assert len(audit) == 1
    assert audit[0].details["round"] == 1


async def test_a_second_wave_adds_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    gateway = FakeGateway(healthy())
    e = env(app_engine, gateway)
    first = await run(e, inv)
    assert first["requests"] == 1
    before = await rows(app_engine, "SELECT count(*) AS n FROM evidence")
    again = await run(e, inv)  # the newest dossier is now the wave's: nothing is left to ask
    assert again["requests"] == 0
    assert again["dossier"] is None
    assert again["checks"] == []
    assert len(gateway.calls) == 1
    assert (await rows(app_engine, "SELECT count(*) AS n FROM evidence"))[0].n == before[0].n
    assert await packs(app_engine, inv) == ["generic@12", "generic+wave.1@12"]
    # and over the old dossier too: the stored answer is reused, not asked again
    async with app_engine.connect() as conn:
        old = await conn.execute(text("SELECT body FROM dossiers WHERE pack = 'generic@12'"))
        current = store.Current(inv, 1, "generic@12", "x" * 64, old.scalar_one(), NOW, "m", False)
        stale = await wave.prepare_from(e, conn, current, NOW)
        plan = await wave.plan_wave(e, conn, stale, NOW)
    assert [c.mode for c in plan.checks] == ["reuse"]


async def test_each_check_has_its_e_id_in_plan_order_and_its_reason(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    dossier = body([unknown("proxy.hosts_to_destination", "failed")],
                   [*TIMELINE, step(3, "deferred", ["log_pivot"])])  # fmt: skip
    inv = await seed(migrated_engine, dossier)
    e = env(app_engine, FakeGateway(healthy()))
    outcome = await run(e, inv)
    found = await rows(app_engine, "SELECT eid, template, reason FROM evidence_requests"
                       " ORDER BY eid")  # fmt: skip
    assert [(r.eid, r.template) for r in found] == [(1, "proxy.destination"), (2, "proxy.host")]
    assert "Hosts reaching the destination" in found[0].reason
    assert "Step 2" in found[1].reason
    assert "Step 3" in found[1].reason  # one check answers both steps
    assert all(len(r.reason) <= 200 for r in found)
    assert [c["eid"] for c in outcome["checks"]] == ["E1", "E2"]
    assert outcome["requests"] == 2
    assert outcome["heavy"] == 2


async def test_the_caps_of_a_wave_hold(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    dossier = body(
        [
            unknown("ti.listed", "source_not_checked"),
            unknown("proxy.hosts_to_destination", "failed"),
            unknown("web.successes_after", "failed"),
        ],
        TIMELINE,
        ti=TI_UNANSWERED,
    )
    inv = await seed(migrated_engine, dossier)
    gateway = FakeGateway(healthy())
    e = env(app_engine, gateway, caps=Caps(requests=2, heavy=1))
    outcome = await run(e, inv)
    assert outcome["requests"] == 2
    assert [c[0] for c in gateway.calls] == ["ti.lookup", "proxy.destination"]
    # the server time cap is kept as answers arrive: a first answer over it stops the wave
    inv2 = await seed(migrated_engine, dossier)
    slow = FakeGateway(healthy(), took=5_000)
    e2 = env(app_engine, slow, caps=Caps(requests=4, heavy=2, server_ms=4_000))
    out2 = await run(e2, inv2)
    assert out2["requests"] == 1
    assert out2["server_ms"] == 5_000
    assert out2["stopped"] == "this wave's limit of requests or SIEM time"
    assert [c.get("why_not") for c in out2["checks"]][1:] == [out2["stopped"]] * 2


async def test_siem_becoming_unavailable_stops_the_wave_and_stores_no_negative(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    dossier = body([unknown("proxy.hosts_to_destination", "failed")], TIMELINE)
    inv = await seed(migrated_engine, dossier)
    gateway = FakeGateway(healthy(), fail={"proxy.destination": DeferredError("busy")})
    outcome = await run(env(app_engine, gateway), inv)
    assert outcome["requests"] == 0
    assert outcome["dossier"] is None
    assert "not available" in outcome["stopped"]
    assert [c["template"] for c in outcome["checks"]] == ["proxy.destination", "proxy.host"]
    assert (await rows(app_engine, "SELECT count(*) AS n FROM evidence"))[0].n == 0
    assert await packs(app_engine, inv) == ["generic@12"]
    stopped = FakeGateway(healthy(), fail={"proxy.destination": StoppedError("stop")})
    assert (await run(env(app_engine, stopped), inv))["dossier"] is None


async def test_a_timeout_is_unknown_never_negative_and_is_asked_again_later(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    flaky = FakeGateway(healthy(), fail={"proxy.host": TimedOutError("slow")})
    outcome = await run(env(app_engine, flaky), inv)
    assert outcome["requests"] == 1
    assert outcome["checks"][0]["status"] == "timeout"
    assert outcome["dossier"] == "generic+wave.1@12"  # the failed check is part of the record
    (row,) = await rows(app_engine, "SELECT status, snapshot FROM evidence")
    assert (row.status, row.snapshot) == ("timeout", None)
    (step_,) = (await rows(app_engine, "SELECT body -> 'report' -> 'steps' AS s FROM dossiers"
                           " WHERE pack = 'generic+wave.1@12'"))[0].s  # fmt: skip
    assert step_["status"] == "deferred"  # a failure answers nothing
    # a moment later nothing is asked again; half an hour later the same request is retried
    again = await run(env(app_engine, flaky, now=NOW + timedelta(minutes=5)), inv)
    assert again["requests"] == 0
    later = NOW + timedelta(minutes=31)
    good = FakeGateway(healthy(at=later))
    final = await run(env(app_engine, good, now=later), inv)
    assert final["requests"] == 1
    assert final["checks"][0]["eid"] == "E1"  # the same request keeps its id
    assert (await rows(app_engine, "SELECT status FROM evidence"))[0].status == "ok"
    assert await packs(app_engine, inv) == [
        "generic@12", "generic+wave.1@12", "generic+wave.2@12"
    ]  # fmt: skip


async def test_a_template_the_validator_refuses_is_recorded_and_never_retried_at_once(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    refused = FakeGateway(healthy(), fail={"proxy.host": TemplateRejectedError("rule", "no")})
    outcome = await run(env(app_engine, refused), inv)
    (row,) = await rows(app_engine, "SELECT status, error FROM evidence")
    assert (row.status, row.error) == ("failed", "rejected")
    assert outcome["requests"] == 1


async def test_nothing_is_asked_unless_siem_is_normal(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    for state in (HealthState.CAUTION, HealthState.DEGRADED, HealthState.STOP):
        gateway = FakeGateway(healthy(state))
        e = env(app_engine, gateway)
        assert not await wave.ready(e, NOW)
        async with app_engine.connect() as conn:
            prep = await wave.prepare(e, conn, inv, NOW)
            assert prep is not None
            plan = await wave.plan_wave(e, conn, prep, NOW)
        assert plan.sends == ()
        assert gateway.calls == []
        assert "normal state" in plan.left[0][1]
    quiet = NOW.replace(hour=0, minute=30)
    e = env(app_engine, FakeGateway(healthy(at=quiet), now=quiet), now=quiet)
    assert not await wave.ready(e, quiet)
    assert await wave.run_pass(e, "t", wave=True) == {"queued": 0, "done": 0, "refused": 0,
                                                      "failed": 0, "waiting": 0}  # fmt: skip


async def test_a_switched_off_check_is_not_asked(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    gateway = FakeGateway(healthy())
    e = env(app_engine, gateway, switches=Switches())
    outcome = await run(e, inv)
    assert gateway.calls == []
    assert outcome["requests"] == 0
    assert outcome["left"][0][0] == "step:2"
    assert "switched off" in outcome["left"][0][1]


async def test_a_gap_the_logs_could_not_settle_is_not_asked_about(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    dossier = body([unknown("web.successes_after", "ingest_not_verified")])
    inv = await seed(migrated_engine, dossier)
    gateway = FakeGateway(healthy())
    outcome = await run(env(app_engine, gateway), inv)
    assert gateway.calls == []
    assert outcome["gaps"][0]["closable"] is False
    assert outcome["requests"] == 0


async def test_what_a_wave_found_is_in_report_2_with_its_reason_and_provenance(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    await run(env(app_engine, FakeGateway(healthy())), inv)
    async with app_engine.connect() as conn:
        report = await report_store.report(conn, inv)
    assert report is not None
    assert report.pack == "generic+wave.1@12"
    assert report.recomputed
    (prov,) = report.provenance
    assert prov.eid == "E1"
    assert prov.origin == "wave"
    assert prov.reason is not None
    assert "asked by ARGUS's wave" in prov.line
    assert "Step 2 of the rule's note" in prov.line
    assert report.found.checks == 1
    assert any(item.kind == "new" for item in report.found.items)
    assert any(c.key == "step:2" for c in report.found.new.steps_answered)
    assert report.strength.steps_answered == 1


async def plant(owner: AsyncEngine, value: str, investigations: int) -> None:
    """``investigations`` other investigations naming this address (the prevalence gate counts
    them in history.window)."""
    async with owner.begin() as conn:
        for n in range(investigations):
            inv = uuid.uuid4()
            await conn.execute(
                text(
                    "INSERT INTO investigations (id, grouping_version, rule_id, group_key,"
                    " bucket_start, bucket_end, previous_id, last_event_at) VALUES (:id, 'g1',"
                    " 'r1', :k, :s, :e, :id, :last)"
                ),
                {"id": inv, "k": f"k-{value}-{n}", "s": NOW - timedelta(hours=4),
                 "e": NOW + timedelta(hours=20), "last": NOW - timedelta(hours=1)},
            )  # fmt: skip
            await conn.execute(
                text("INSERT INTO investigation_entities (investigation_id, kind, value)"
                     " VALUES (:i, 'ip', :v)"), {"i": inv, "v": value})  # fmt: skip


async def spend(owner: AsyncEngine, template: str, lane: str, took_ms: int) -> None:
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO siem_requests (at, component, purpose, template, version, indices,"
                " outcome, took_ms, elapsed_ms, response_bytes, attempts, lane) VALUES (:at, 'x',"
                " 'investigate', :t, 1, '{}', 'ok', :ms, :ms, 0, 1, :lane)"
            ),
            {"at": NOW - timedelta(hours=2), "t": template, "ms": took_ms, "lane": lane},
        )


async def test_a_value_too_common_to_query_is_not_asked_about(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """Caps limit the answer, not the work (plan §7.3): the wave never aggregates over an
    address ARGUS sees in 50 investigations, whichever template asks."""
    dossier = body([unknown("proxy.hosts_to_destination", "failed")], TIMELINE)
    inv = await seed(migrated_engine, dossier)
    await plant(migrated_engine, "10.20.3.4", 50)  # the campus host: a NAT, say
    gateway = FakeGateway(healthy())
    outcome = await run(env(app_engine, gateway), inv)
    assert [c[0] for c in gateway.calls] == ["proxy.destination"]  # the host search is refused
    by = {c["template"]: c for c in outcome["checks"]}
    assert "too common to query" in by["proxy.host"]["why_not"]
    # and the destination likewise
    inv2 = await seed(migrated_engine, dossier)
    await plant(migrated_engine, "185.220.101.5", 50)
    other = FakeGateway(healthy())
    out2 = await run(env(app_engine, other), inv2)
    assert other.calls == []
    assert out2["requests"] == 0


async def test_a_template_has_a_daily_cap_on_the_investigation_lane_alone(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    inv = await seed(migrated_engine, body(steps=TIMELINE))
    # the pack's own searches on the collector's lane do not count against the wave
    await spend(migrated_engine, "proxy.host", "collector", 500_000)
    gateway = FakeGateway(healthy())
    assert (await run(env(app_engine, gateway), inv))["requests"] == 1
    inv2 = await seed(migrated_engine, body(steps=TIMELINE))
    await spend(migrated_engine, "proxy.host", "investigation", 90_000)
    capped = FakeGateway(healthy())
    out = await run(env(app_engine, capped), inv2)
    assert [c[0] for c in capped.calls] == ["proxy.pair"]  # the next closer goes on
    only_host = FakeGateway(healthy())
    inv3 = await seed(migrated_engine, body(steps=TIMELINE))
    out = await run(env(app_engine, only_host, switches=Switches(proxy_aggregations=True)), inv3)
    assert only_host.calls == []
    assert "used up" in out["left"][0][1]
