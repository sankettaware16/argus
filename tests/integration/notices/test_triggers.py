"""The five triggers against Postgres (Q-H4): what ARGUS's own tables say is worth a notice, from
rows written the way the watch, the case service, the approval desk, the dossiers and the gateway
write them. Nothing here asks the SIEM, and nothing is e-mailed.

Two clocks meet in these tests: the world of the watch runs on fake days (October 14 on); an
event's ``occurred_at`` and a request's ``requested_at`` are the database's own. Each test passes
the ``now`` that fits the rows it reads."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, time, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assets.classify import IpClassifier
from argus.cases.machine import AfterClosure, Notify, Open
from argus.cases.model import KIBANA_TO_OPEN, LOCAL_CAPABILITIES, Actor, Indicator, Member
from argus.cases.service import CaseService
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.kibana import writes as kibana_writes
from argus.gateway.pgstore import health_to_json
from argus.notices import triggers
from argus.notices.model import Condition, Target
from tests.integration.cases.conftest import APPROVER, KIBANA, Person, asking
from tests.integration.cases.test_closure_approval import _closed, _desk_decide, _mirror
from tests.integration.cases.test_opener import _review
from tests.integration.cases.test_service import _open
from tests.integration.cases.watchkit import C2, D0, H1, FakeAsker, World, at, context

pytestmark = pytest.mark.integration

CLASSIFIER = IpClassifier(None)


async def read(engine: AsyncEngine, step: Any, *args: Any) -> list[Condition]:
    async with engine.connect() as conn:
        found: list[Condition] = await step(conn, *args)
        return found


def real_now() -> datetime:
    return datetime.now(UTC)


# --------------------------------------------------------------------------- 1: still active


async def test_a_case_whose_host_alerts_again_after_the_verdict_is_still_active(
    world: World, people: dict[str, Person]
) -> None:
    ctx = context(None)
    inv = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(people["asha"], [inv], [H1], at(0, 10))
    await world.run(ctx, at(1, 3))  # day 0: the alerts that made the case; nothing since
    assert await read(world.runtime, triggers.case_active, at(1, 4)) == []
    await world.add_alert(inv, at(1, 5))
    await world.run(ctx, at(2, 3))
    (one,) = await read(world.runtime, triggers.case_active, at(2, 4))
    assert one == Condition("case_active", str(case_id), "high", 1, Target("case", case_id))
    await world.add_alert(inv, at(2, 8))
    await world.run(ctx, at(3, 3))
    (two,) = await read(world.runtime, triggers.case_active, at(3, 4))
    assert two.count == 2  # two days since the verdict
    # three days after the last sign of it the case is no longer "still active"
    assert await read(world.runtime, triggers.case_active, at(7, 4)) == []


async def test_a_notified_case_is_not_a_still_active_notice(
    world: World, people: dict[str, Person]
) -> None:
    """AR4b (D-169): the owner was told and the alerts are counted; mailing "still active" every
    day would repeat what everybody knows."""
    ctx = context(None)
    inv = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(people["asha"], [inv], [H1], at(0, 10))
    await world.add_alert(inv, at(1, 5))
    await world.run(ctx, at(2, 3))
    assert len(await read(world.runtime, triggers.case_active, at(2, 4))) == 1
    async with world.runtime.begin() as conn:
        await (await CaseService.start(conn)).apply(
            people["asha"].actor(), case_id, Notify("the owner", "email"), expected_version=None
        )
    assert await read(world.runtime, triggers.case_active, at(2, 4)) == []


async def put_active_day(owner: AsyncEngine, case_id: uuid.UUID, day: datetime) -> None:
    """The watch's own row for a day on which the case's alerts were seen."""
    start = day.replace(hour=0, minute=0, second=0, microsecond=0)
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO case_watch_checks (case_id, day, source, subject, part, outcome,"
                " window_start, window_end, requests) VALUES (:c, :d, 'alerts', '', 0, 'active',"
                " :s, :e, 0)"
            ),
            {"c": case_id, "d": start.date(), "s": start, "e": start + timedelta(days=1)},
        )


async def test_a_closed_case_is_never_still_active_whatever_the_watch_wrote(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, app_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    now = real_now()
    open_case, _ = await _waiting(api_engine, migrated_engine, people, 1)
    closed = await _closed(api_engine, migrated_engine, people)
    for case_id in (open_case, closed.case_id):
        await put_active_day(migrated_engine, case_id, now + timedelta(days=1))  # the same row
    found = await read(app_engine, triggers.case_active, now + timedelta(days=1, hours=6))
    assert [c.subject for c in found] == [str(open_case)]


async def test_after_containment_new_activity_is_still_active_and_at_least_high(
    world: World, people: dict[str, Person]
) -> None:
    asha = people["asha"]
    ctx = context(FakeAsker())
    first = await world.investigation(H1, [at(0, 9)])
    marks = (Indicator("ip", H1, "actor"),)
    async with world.runtime.begin() as conn:  # a low-severity case (the world opens high ones)
        service = CaseService(conn, at(0, 10))
        opened = await service.open(
            asha.actor(LOCAL_CAPABILITIES, kibana=KIBANA, checked_at=at(0, 10)),
            Open("Regular beaconing from a campus host", "low", "person",
                 (Member(first, "person"),), marks),
        )  # fmt: skip
    case_id = opened.case.id
    for n in (1, 2, 3, 4, 5):
        await world.run(ctx, at(n, 3))
    assert (await world.contain(ctx, asha, case_id, at(5, 4))).case.state == "contained"
    assert await read(world.runtime, triggers.case_active, at(5, 5)) == []  # quiet since
    await world.add_alert(first, at(5, 12))
    await world.run(ctx, at(6, 3))
    assert (await world.case(case_id)).state == "open"  # the watch reopened it: "new activity"
    (found,) = await read(world.runtime, triggers.case_active, at(6, 4))
    # a low case, but its containment failed; two days: the one of the alert (after the
    # containment moment of the same day, review R3) and the event's own (the database's clock)
    assert (found.severity, found.count) == ("high", 2)


# --------------------------------------------------------------------------- 2: after closure


async def test_activity_after_closure_is_told_for_three_days_and_leads_to_the_follower(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, app_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    closed = await _closed(api_engine, migrated_engine, people)
    watch = Actor.argus("watch")
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        await service.apply(watch, closed.case_id, AfterClosure(summary="Activity after closure"),
                            expected_version=None)  # fmt: skip
    (note,) = await read(app_engine, triggers.after_closure, real_now())
    assert note == Condition(
        "after_closure", str(closed.case_id), "high", 1, Target("case", closed.case_id)
    )
    # a follower: the link leads to the new case, the subject stays the closed one
    inv = await _investigation(migrated_engine)
    child = await _open(app_engine, people["asha"].actor(), [inv])
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        await service.apply(watch, closed.case_id, AfterClosure(child_case_id=child),
                            expected_version=None)  # fmt: skip
    (both,) = await read(app_engine, triggers.after_closure, real_now())
    assert (both.subject, both.count, both.target) == (
        str(closed.case_id),
        2,
        Target("case", child),
    )
    assert await read(app_engine, triggers.after_closure, real_now() + timedelta(days=4)) == []


async def _investigation(owner: AsyncEngine) -> uuid.UUID:
    from tests.integration.cases.conftest import investigation

    return await investigation(owner, actor=(("source.ip", "10.4.4.4"),))


# --------------------------------------------------------------------------- 3: closure waiting


async def _waiting(
    api: AsyncEngine, owner: AsyncEngine, people: dict[str, Person], tag: int = 1,
    reason: str = "benign_expected",
) -> tuple[uuid.UUID, int]:  # fmt: skip
    """An open, mirrored case with a closure asked for. The request is made as if at 10:00 UTC
    tomorrow, so it lives to the end of the window of the day after: at least 31 hours from the
    database's own clock (whatever time of day the test runs)."""
    asha = people["asha"]
    inv = await _investigation_for(owner, tag)
    async with api.begin() as conn:
        now = (await conn.execute(text("SELECT now()"))).scalar_one()
    case_id = await _open(api, asha.actor(APPROVER, kibana=KIBANA_TO_OPEN, checked_at=now), [inv])
    await _mirror(owner, case_id)
    asked = datetime.combine((now + timedelta(days=1)).date(), time(10, 0), UTC)
    async with api.begin() as conn:
        service = CaseService(conn, asked)
        _, request_id = await service.request_closure(
            asha.actor(), case_id, expected_version=1, reason=reason,  # type: ignore[arg-type]
            session_token=asha.session_token, note="the host was cleaned and checked by IT",
            check=await asking(conn, asha),
        )  # fmt: skip
    return case_id, request_id


async def _investigation_for(owner: AsyncEngine, tag: int) -> uuid.UUID:
    from tests.integration.cases.conftest import investigation

    return await investigation(owner, actor=(("source.ip", f"10.5.{tag}.4"),))


async def request_times(api: AsyncEngine, request_id: int) -> tuple[datetime, datetime]:
    async with api.connect() as conn:
        row = (
            await conn.execute(
                text("SELECT requested_at, expires_at FROM approval_requests WHERE id = :i"),
                {"i": request_id},
            )
        ).one()
    return row.requested_at, row.expires_at


async def test_a_closure_waiting_more_than_twelve_hours_is_told_until_it_expires(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case_id, request_id = await _waiting(api_engine, migrated_engine, people)
    asked, expires = await request_times(api_engine, request_id)
    assert expires - asked >= timedelta(hours=31)
    assert await read(api_engine, triggers.closure_waiting, asked + timedelta(hours=11)) == []
    (found,) = await read(api_engine, triggers.closure_waiting, asked + timedelta(hours=13))
    assert (found.kind, found.subject) == ("closure_waiting", str(case_id))
    assert (found.count, found.target) == (13, Target("case", case_id))
    left = expires - (asked + timedelta(hours=13))
    assert found.severity == ("high" if left <= timedelta(hours=12) else "medium")
    (urgent,) = await read(api_engine, triggers.closure_waiting, expires - timedelta(hours=11))
    assert urgent.severity == "high"
    assert await read(api_engine, triggers.closure_waiting, expires + timedelta(minutes=1)) == []


async def test_a_closure_that_is_decided_is_no_longer_waiting(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    approved_case, approved = await _waiting(api_engine, migrated_engine, people, 1)
    rejected_case, rejected = await _waiting(api_engine, migrated_engine, people, 2)
    asked, _ = await request_times(api_engine, approved)
    later = asked + timedelta(hours=25)
    assert {c.subject for c in await read(api_engine, triggers.closure_waiting, later)} == {
        str(approved_case), str(rejected_case),
    }  # fmt: skip
    assert await _desk_decide(api_engine, people["ravi"], approved) == "approved"
    assert await _desk_decide(api_engine, people["ravi"], rejected, "rejected") == "rejected"
    assert await read(api_engine, triggers.closure_waiting, later) == []


async def test_a_two_person_closure_with_one_approval_is_still_waiting(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case_id, request_id = await _waiting(api_engine, migrated_engine, people, 3, "risk_accepted")
    assert await _desk_decide(api_engine, people["ravi"], request_id) == "pending"
    asked, _ = await request_times(api_engine, request_id)
    (found,) = await read(api_engine, triggers.closure_waiting, asked + timedelta(hours=25))
    assert found.subject == str(case_id)


# --------------------------------------------------------------------------- 4: a known-bad address


def dossier_body(listed: list[str], confidence: dict[str, str]) -> dict[str, Any]:
    return {
        "signals": [{"name": "ti.listed", "status": "known", "value": len(listed)}],
        "local_signals": [],
        "context": {
            "pack": {
                "ti": {
                    "listed": listed,
                    "answers": [
                        {
                            "value": value,
                            "kind": "ip",
                            "sources": {"abuse-ioc": {"match": [{"confidence": level}]}},
                        }
                        for value, level in confidence.items()
                    ],
                }
            }
        },
    }


async def put_dossier(
    owner: AsyncEngine, inv: uuid.UUID, body: dict[str, Any], version: int = 1
) -> None:
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO dossiers (investigation_id, version, pack, facts_version, job_id,"
                " run_kind, family, status, dossier_hash, body, evidence_count, created_at)"
                " VALUES (:i, :v, 'generic@11', :v, 1, 'collect', 'proxy', 'evidence_ready',"
                " repeat('c', 64), CAST(:b AS jsonb), 0, now())"
            ),
            {"i": inv, "v": version, "b": json.dumps(body)},
        )


async def hit(
    world: World, host: str = H1, level: str = "high", ago: float = 1, **kw: Any
) -> uuid.UUID:
    when = real_now() - timedelta(hours=ago)
    inv = await world.investigation(host, [when], **kw)
    await put_dossier(world.owner, inv, dossier_body([C2], {C2: level}))
    return inv


async def test_a_campus_host_that_reached_a_high_confidence_indicator_is_told(world: World) -> None:
    inv = await hit(world)
    found = await read(world.runtime, triggers.ioc_hit, real_now(), CLASSIFIER)
    assert found == [Condition("ioc_hit", str(inv), "high", 1, Target("investigation", inv))]


async def test_a_known_infections_investigation_is_not_an_indicator_notice(
    world: World, people: dict[str, Person]
) -> None:
    """AR4b (D-169): an investigation that belongs to a notified case's known infection is
    counted, not mailed."""
    inv = await hit(world)
    other = await world.investigation(H1, [real_now() - timedelta(hours=2)])
    case_id = await world.open_case(people["asha"], [other], [H1], at(0, 10))
    async with world.runtime.begin() as conn:
        await (await CaseService.start(conn)).apply(
            people["asha"].actor(), case_id, Notify("the owner", "email"), expected_version=None
        )
    assert len(await read(world.runtime, triggers.ioc_hit, real_now(), CLASSIFIER)) == 1
    async with world.owner.begin() as conn:
        await conn.execute(
            text("INSERT INTO case_known_matches (investigation_id, case_id, version, outcome)"
                 " SELECT id, :c, version, 'known' FROM investigations WHERE id = :i"),
            {"c": case_id, "i": inv},
        )  # fmt: skip
    assert await read(world.runtime, triggers.ioc_hit, real_now(), CLASSIFIER) == []


async def test_a_critical_alert_makes_it_critical(world: World) -> None:
    await hit(world, severity="critical")
    (found,) = await read(world.runtime, triggers.ioc_hit, real_now(), CLASSIFIER)
    assert found.severity == "critical"


@pytest.mark.parametrize(
    "case",
    ["medium confidence", "an outside host", "reviewed", "old", "not listed"],
)
async def test_what_is_not_a_high_confidence_hit_by_a_campus_host_is_not_told(
    world: World, people: dict[str, Person], case: str
) -> None:
    if case == "medium confidence":
        await hit(world, level="medium")
    elif case == "an outside host":
        await hit(world, host="8.8.8.8")
    elif case == "old":
        await hit(world, ago=30)
    elif case == "reviewed":
        inv = await hit(world)
        await _review(world.runtime, people["asha"], inv, "true_positive")
    else:
        inv = await world.investigation(H1, [real_now() - timedelta(hours=1)])
        await put_dossier(world.owner, inv, dossier_body([], {C2: "high"}))
    assert await read(world.runtime, triggers.ioc_hit, real_now(), CLASSIFIER) == []


async def test_a_look_by_the_assistant_or_a_service_is_not_a_person_looking(
    world: World, people: dict[str, Person]
) -> None:
    from argus.web import auth

    inv = await hit(world)
    async with world.owner.begin() as conn:
        assistant = await auth.add_user(
            conn, "argus-assistant", "Assistant", "correct horse battery"
        )
    robot = Person(assistant, "argus-assistant", "x")
    await _review(world.runtime, robot, inv, "benign_expected")  # the assistant's verdict (D-071)
    found = await read(world.runtime, triggers.ioc_hit, real_now(), CLASSIFIER)
    assert [c.subject for c in found] == [str(inv)]  # still told: no person has looked
    await _review(world.runtime, people["asha"], inv, "benign_expected")
    assert await read(world.runtime, triggers.ioc_hit, real_now(), CLASSIFIER) == []


async def test_the_newest_dossier_is_the_one_that_counts(world: World) -> None:
    inv = await hit(world, level="low")
    await put_dossier(world.owner, inv, dossier_body([C2], {C2: "high"}), version=2)
    async with world.owner.begin() as conn:
        await conn.execute(text("UPDATE investigations SET version = 2 WHERE id = :i"), {"i": inv})
    found = await read(world.runtime, triggers.ioc_hit, real_now(), CLASSIFIER)
    assert [c.subject for c in found] == [str(inv)]


# --------------------------------------------------------------------------- 5: an outage


async def put_state(owner: AsyncEngine, name: str, state: dict[str, Any]) -> None:
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO siem_state (name, state) VALUES (:n, CAST(:s AS jsonb))"
                " ON CONFLICT (name) DO UPDATE SET state = EXCLUDED.state"
            ),
            {"n": name, "s": json.dumps(state)},
        )


async def outages(engine: AsyncEngine, now: datetime, mode: str = "off") -> dict[str, Condition]:
    async with engine.connect() as conn:
        found = await triggers._outages(conn, now, watch_mode=mode, health=None)
    return {c.subject: c for c in found}


async def test_nothing_is_an_outage_on_a_database_with_no_gateway_history(
    app_engine: AsyncEngine,
) -> None:
    assert await outages(app_engine, real_now()) == {}


async def test_siem_degraded_or_stopped_is_an_outage_from_when_the_state_began(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    now = real_now()
    began = now - timedelta(hours=3)
    memory = HealthMemory(HealthState.STOP, began, now, reasons=("disk_stop",))
    await put_state(migrated_engine, "health", health_to_json(memory))
    found = await outages(app_engine, now)
    assert found["siem"].severity == "high"
    assert found["siem"].since == began
    healthy = HealthMemory(HealthState.NORMAL, began, now)
    await put_state(migrated_engine, "health", health_to_json(healthy))
    assert await outages(app_engine, now) == {}
    await put_state(migrated_engine, "health", health_to_json(healthy))
    quiet = await outages(app_engine, now + timedelta(hours=2))  # the probe went quiet
    assert quiet["siem"].severity == "high"


async def test_a_stopped_kibana_lane_and_a_paused_class_are_outages(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    now = real_now()
    lane = kibana_writes.KibanaLaneState(stopped="a 401", stopped_at=now - timedelta(hours=2))
    lane = kibana_writes.pause(lane, kibana_writes.WriteClass.W2, "a 403")
    await put_state(migrated_engine, "kibana", kibana_writes.to_json(lane))
    found = await outages(app_engine, now)
    assert set(found) == {"kibana", "kibana:W2"}
    assert found["kibana"].since == now - timedelta(hours=2)


async def test_the_watch_that_is_on_and_has_not_run_is_an_outage(
    world: World, people: dict[str, Person]
) -> None:
    now = real_now()
    assert "watch" in await outages(world.runtime, now, "local")  # never ran
    assert "watch" not in await outages(world.runtime, now, "off")
    inv = await world.investigation(H1, [at(0, 9)])
    await world.open_case(people["asha"], [inv], [H1], at(0, 10))
    await world.run(context(None), at(1, 3))  # writes the audit row ``watch.run`` now
    assert "watch" not in await outages(world.runtime, real_now(), "local")
    late = await outages(world.runtime, real_now() + timedelta(hours=40), "local")
    assert late["watch"].severity == "medium"


async def test_an_open_gap_of_arguss_own_is_an_outage_and_a_siems_truncation_is_not(
    world: World,
) -> None:
    await world.gap(datetime.now(UTC) - timedelta(hours=5), None)  # source_stalled squid
    async with world.owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO coverage_gaps (kind, subject, start_at) VALUES"
                " ('argus_collector_lag', 'collector', now() - interval '2 hours'),"
                " ('truncated_execution', 'rule-1', now() - interval '9 hours'),"
                " ('rule_not_running', 'rule-2', now() - interval '9 hours')"
            )
        )
    found = await outages(world.runtime, real_now())
    assert set(found) == {"gap:source_stalled", "gap:argus_collector_lag"}
    assert found["gap:argus_collector_lag"].severity == "high"
    assert found["gap:source_stalled"].since is not None


# --------------------------------------------------------------------------- all five


async def test_compute_reads_every_trigger_and_names_the_ones_it_could_not_read(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    await hit(world)
    got = await triggers.compute(world.runtime, real_now(), classifier=CLASSIFIER)
    assert [c.kind for c in got.conditions] == ["ioc_hit"]
    assert got.failed == set()

    async def broken(conn: Any, now: datetime) -> list[Condition]:
        raise RuntimeError("secret detail: host 10.8.235.157")

    monkeypatch.setattr(triggers, "closure_waiting", broken)
    broken_got = await triggers.compute(world.runtime, real_now(), classifier=CLASSIFIER)
    assert broken_got.failed == {"closure_waiting"}
    assert [c.kind for c in broken_got.conditions] == ["ioc_hit"]  # the others are intact
    assert D0  # the world's first day, imported for the helpers' times
