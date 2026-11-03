"""Q-D5's gate on the real database, through the real Kibana lane and a fake Kibana: the status
call's answer is checked and any mismatch pauses the class; previous statuses are kept; the
read-back decides after a timeout; the SIEM's disk and blocks switch write-back off; people who may
not write are excluded; the caps and the gap hold; one run at a time with the case writer; and a
second run writes nothing."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import writeback, writeback_sender
from argus.gateway.health import HealthConfig, HealthMemory, Readings, evaluate
from argus.gateway.kibana.writes import KibanaLaneState, WriteCaps, WriteClass, resume
from argus.writeback_sender import Operator
from argus.writer import store
from tests.integration.grouping.test_grouping import reset
from tests.integration.writeback.kit import Fault, Kibana, Rig, rig
from tests.integration.writeback.test_writeback import alerts, diff, plan, review, reviewed, rows

pytestmark = pytest.mark.integration


async def ready(
    app: AsyncEngine, owner: AsyncEngine, writer: AsyncEngine, n: int, **kw: Any
) -> Rig:
    """A rig with one planned review of ``n`` alerts, all open in the fake Kibana."""
    r = rig(owner, writer, **kw)
    await reviewed(app, n)
    assert await plan(app) == 1
    await r.seed_world()
    return r


# --------------------------------------------------------------------------- the answer


@pytest.mark.parametrize(
    "body",
    [
        {"failures": [{"cause": {"type": "cluster_block_exception"}, "status": 429}]},
        {"version_conflicts": 2},
        {"timed_out": True},
        {"total": 0},  # an id Kibana did not find: a 200 that changed nothing
        {"noops": 1},
        {"deleted": 1},
        {"updated": 3},
    ],
)
async def test_any_mismatch_in_the_answer_pauses_the_class(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    body: dict[str, Any],
) -> None:
    r = await ready(app_engine, migrated_engine, writer_engine, 5)
    r.world.faults.append(Fault("body", apply=0, body=body))
    paused = await r.run()
    assert paused.paused is not None
    assert paused.paused.startswith("Kibana's answer")
    assert "WA" in r.lane.kibana.paused  # the class is paused until someone resumes it
    assert [tuple(x) for x in await rows(app_engine)] == [("paused", "closed", 0)]
    again = await r.run()  # a paused class sends nothing, however long we wait
    r.clock.now += timedelta(hours=3)
    again = await r.run()
    assert len(r.world.calls) == 1
    assert again.paused is not None
    assert "class_paused" in again.paused


async def test_a_partial_write_is_counted_by_the_next_runs_read_not_by_the_answer(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    """Kibana changed 2 of 5 and said so with failures: the row stays where it was, the class is
    paused; once resumed, the next run reads first, counts the 2 (their previous statuses were
    kept) and sends only the other 3."""
    r = await ready(app_engine, migrated_engine, writer_engine, 5)
    r.world.faults.append(
        Fault("body", apply=2, body={"failures": [{"cause": {"type": "es_rejected"}}]})
    )
    paused = await r.run()
    assert paused.paused is not None
    row = await r.row()
    assert (row.state, row.sent_count, row.written_count) == ("paused", 0, 0)
    assert len(row.previous) == 5  # every alert's previous status was kept before the request
    r.lane.kibana = KibanaLaneState()  # an operator resumed the class
    r.clock.now += timedelta(minutes=10)
    result = await r.run()
    assert (result.sent_alerts, result.credited_alerts, result.sent_rows) == (3, 2, 1)
    assert all(n == 1 for n in r.world.transitions.values())
    assert len(r.world.transitions) == 5
    assert all(s == "closed" for s in r.world.statuses.values())


async def test_a_clean_answer_is_still_read_back(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    """Kibana says 5 of 5 updated but Elasticsearch shows otherwise (a lie, or a different
    space): the read-back pauses the class and nothing counts."""
    r = await ready(app_engine, migrated_engine, writer_engine, 5)

    class Liar(Kibana):
        async def send(self, request: Any) -> Any:
            answer = await super().send(request)
            if request.path.endswith("/signals/status"):
                for alert_id in self.world.statuses:  # as if the update went elsewhere
                    self.world.statuses[alert_id] = "open"
            return answer

    r.gateway.transport = Liar(r.world)
    paused = await r.run()
    assert paused.paused is not None
    assert "read-back" in paused.paused
    assert "WA" in r.lane.kibana.paused
    row = await r.row()
    assert (row.state, row.sent_count, row.written_count) == ("paused", 0, 0)


# --------------------------------------------------------------------------- previous, second run


async def test_previous_statuses_are_kept_and_a_second_run_writes_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    r = await ready(app_engine, migrated_engine, writer_engine, 5)
    ids = sorted(r.world.statuses)
    r.world.statuses[ids[1]] = "acknowledged"
    first = await r.run()
    assert (first.sent_alerts, first.sent_rows, first.calls, first.paused) == (5, 1, 1, None)
    row = await r.row()
    assert row.previous == {a: ("acknowledged" if a == ids[1] else "open") for a in ids}
    assert (row.state, row.sent_count, row.written_count) == ("sent", 5, 5)
    again = await r.run()  # R17's gate: a second run writes 0
    assert (again.sent_alerts, again.calls, again.sent_rows) == (0, 0, 0)
    assert await plan(app_engine) == 0
    assert len(r.world.calls) == 1
    audit = await r.sql("SELECT action, details FROM audit_events WHERE action LIKE 'writeback.%'")
    assert [a.action for a in audit] == ["writeback.batch"]
    assert audit[0].details["written"] == 5


async def test_the_read_back_and_the_caps_are_in_the_lane(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    r = await ready(app_engine, migrated_engine, writer_engine, 5)
    await r.run()
    ledger = [e for e in r.lane.ledger if e.purpose == "writeback"]
    assert {e.template for e in ledger} >= {"alerts.status", "alerts.mget"}
    status = next(e for e in ledger if e.template == "alerts.status")
    assert (status.write_class, status.http_status, status.outcome) == ("WA", 200, "ok")
    assert status.payload_hash
    assert status.outbox_id.startswith("writeback-")


# --------------------------------------------------------------------------- timeouts


@pytest.mark.parametrize(
    ("land_after", "written", "again"),
    [(0.0, 5, 0), (None, 0, 5), (100.0, 0, 0)],
    ids=["landed at once", "never landed", "landed late"],
)
async def test_after_a_timeout_the_read_back_decides(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    land_after: float | None,
    written: int,
    again: int,
) -> None:
    r = await ready(app_engine, migrated_engine, writer_engine, 5)
    r.world.faults.append(Fault("timeout", land_after=land_after))
    first = await r.run()
    assert first.paused is not None
    assert first.paused.startswith("Kibana did not answer")
    assert first.sent_alerts == written
    row = await r.row()
    assert (row.sent_count, row.written_count) == (written, written)
    r.clock.now += timedelta(hours=2)  # a timeout is charged to the lane for a while
    second = await r.run()
    assert second.sent_alerts == again
    assert second.credited_alerts == (5 if land_after == 100.0 else 0)  # found, not written
    assert all(n <= 1 for n in r.world.transitions.values())  # nothing changed twice
    assert all(s == "closed" for s in r.world.statuses.values())
    assert len(r.world.written()) == 5
    if land_after is None:
        assert len(r.world.calls) == 2  # the one that never landed is sent once more
    else:
        assert len(r.world.calls) == 1  # the late one is found by the pre-read, not resent


async def test_a_refused_connection_sends_nothing_and_a_5xx_is_read_back(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    r = await ready(app_engine, migrated_engine, writer_engine, 5)
    r.world.faults.append(Fault("lose"))
    first = await r.run()
    assert first.paused is not None
    assert "did not answer" in first.paused
    assert "read-back" not in first.paused  # no connection was made: nothing could have landed
    assert (await r.row()).state == "paused"
    r.clock.now += timedelta(hours=1)
    r.world.faults.append(Fault("status", status=502, apply=5))  # applied, then the gateway failed
    second = await r.run()
    assert second.paused is not None
    assert second.paused.startswith("Kibana answered 502")
    assert (second.sent_alerts, (await r.row()).written_count) == (5, 5)  # the read-back found it


async def test_elasticsearch_down_for_the_read_back_leaves_the_row_for_the_next_run(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    r = await ready(app_engine, migrated_engine, writer_engine, 5)

    class Dies(Kibana):
        async def send(self, request: Any) -> Any:
            answer = await super().send(request)
            if request.path.endswith("/signals/status"):
                self.world.es_down = True  # the answer arrived; the read-back cannot be made
            return answer

    r.gateway.transport = Dies(r.world)
    paused = await r.run()
    assert paused.paused is not None
    assert "read-back could not be made" in paused.paused
    assert (await r.row()).sent_count == 0
    r.world.es_down = False
    r.clock.now += timedelta(minutes=5)
    after = await r.run()  # the pre-read finds all five done: nothing is sent again
    # the pre-read finds all five at the status and in the row's kept previous statuses: ours
    assert (after.sent_alerts, after.credited_alerts, after.sent_rows) == (0, 5, 1)
    assert len(r.world.calls) == 1


# --------------------------------------------------------------------------- disk and blocks


@pytest.mark.parametrize(
    ("readings", "says"),
    [
        (Readings(at=None, disk_percent=85.0), "disk_caution"),  # type: ignore[arg-type]
        (Readings(at=None, disk_percent=92.0), "disk_degraded"),  # type: ignore[arg-type]
        (Readings(at=None, disk_percent=96.0), "disk_stop"),  # type: ignore[arg-type]
        (Readings(at=None, blocked_indices=(".alerts-x",)), "index_blocked"),  # type: ignore[arg-type]
        (Readings(at=None, probe_ok=False), "probe_failed"),  # type: ignore[arg-type]
    ],
)
async def test_write_back_is_off_at_disk_85_or_any_block(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    readings: Readings,
    says: str,
) -> None:
    r = await ready(app_engine, migrated_engine, writer_engine, 5)
    memory = evaluate(
        HealthMemory(probed_at=r.clock.now), replace(readings, at=r.clock.now), HealthConfig()
    )
    r.lane.memory = replace(memory, probed_at=r.clock.now + timedelta(hours=2))
    result = await r.sender().run()
    assert result.paused is not None
    assert says in result.paused
    assert (r.world.calls, r.world.mgets) == ([], [])  # not even a read
    assert (await r.row()).sent_count == 0


async def test_disk_just_under_85_percent_writes(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    r = await ready(app_engine, migrated_engine, writer_engine, 5)
    r.lane.memory = evaluate(
        HealthMemory(probed_at=r.clock.now),
        Readings(at=r.clock.now, disk_percent=84.9),
        HealthConfig(),
    )
    r.lane.memory = replace(r.lane.memory, probed_at=r.clock.now + timedelta(hours=2))
    assert (await r.sender().run()).sent_alerts == 5


async def test_disk_rising_between_batches_stops_the_next_one(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(writeback_sender, "FIRST_RUN", 100)
    r = await ready(
        app_engine, migrated_engine, writer_engine, 6, caps=WriteCaps(status_per_call=3)
    )

    class Fills(Kibana):
        async def send(self, request: Any) -> Any:
            answer = await super().send(request)
            if request.path.endswith("/signals/status"):
                r.lane.memory = HealthMemory(
                    state=evaluate(
                        HealthMemory(probed_at=r.clock.now),
                        Readings(at=r.clock.now, disk_percent=88.0),
                        HealthConfig(),
                    ).state,
                    probed_at=r.clock.now + timedelta(hours=2),
                    reasons=("disk_caution",),
                )
            return answer

    r.gateway.transport = Fills(r.world)
    result = await r.sender(run_limit=100).run()
    assert result.sent_alerts == 3  # its read-back still went: it reads, it does not write
    assert result.paused is not None
    assert "disk_caution" in result.paused
    assert len(r.world.calls) == 1
    r.clock.now = (r.clock.now + timedelta(days=1)).replace(hour=9, minute=0)
    after = await r.run(run_limit=100)  # healthy again
    assert (after.sent_alerts, after.sent_rows, after.paused) == (3, 1, None)
    assert len(r.world.calls) == 2
    assert all(count == 1 for count in r.world.transitions.values())


# --------------------------------------------------------------------------- caps and gaps


async def test_calls_are_at_most_the_batch_and_60_seconds_apart(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(writeback_sender, "FIRST_RUN", 100)
    r = await ready(app_engine, migrated_engine, writer_engine, 12)
    result = await r.run(run_limit=100)
    assert [len(ids) for ids, _ in r.world.calls] == [5, 5, 2]
    gaps = [b - a for a, b in zip(r.world.call_times, r.world.call_times[1:], strict=False)]
    assert all(gap >= timedelta(seconds=60) for gap in gaps)
    assert (result.sent_alerts, result.sent_rows, result.calls) == (12, 1, 3)


async def test_the_gap_is_shared_with_the_case_writers_attaches(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    r = await ready(app_engine, migrated_engine, writer_engine, 3)
    counters = replace(r.lane.kibana.counters, last_alert_call=r.clock.now - timedelta(seconds=10))
    r.lane.kibana = replace(r.lane.kibana, counters=counters)  # a W1 attach 10 s ago
    started = r.clock.now
    await r.run()
    assert r.world.call_times[0] - started >= timedelta(seconds=50)  # waited out the rest of 60 s


async def test_the_daily_alert_mutation_cap_is_shared_with_attaches(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    r = await ready(app_engine, migrated_engine, writer_engine, 5)
    counters = replace(
        r.lane.kibana.counters,
        day=r.clock.now.date(),
        alert_mutations=998,  # attachments used the day's allowance
    )
    r.lane.kibana = replace(r.lane.kibana, counters=counters)
    result = await r.run()
    assert result.paused is not None
    assert "alert_daily_cap" in result.paused
    assert r.world.calls == []
    assert (await r.row()).sent_count == 0


async def test_a_batch_may_be_raised_to_100_by_the_setting(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(writeback_sender, "FIRST_RUN", 1000)
    r = await ready(
        app_engine, migrated_engine, writer_engine, 100, caps=WriteCaps(status_per_call=100)
    )
    result = await r.run(run_limit=1000)
    assert [len(ids) for ids, _ in r.world.calls] == [100]
    assert (result.sent_alerts, result.sent_rows) == (100, 1)
    with pytest.raises(ValueError, match="at most 100"):
        WriteCaps(status_per_call=101)


async def test_the_lane_refuses_more_than_the_cap_whatever_the_sender_asks(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    from argus.gateway.kibana.models import AlertStatusChange
    from argus.gateway.kibana.templates import SetAlertStatus

    r = await ready(app_engine, migrated_engine, writer_engine, 6)
    ids = tuple(sorted(r.world.statuses))
    params = AlertStatusChange(signal_ids=ids, status="closed")
    from argus.gateway.kibana.errors import WriteRefusedError
    from argus.gateway.kibana.gateway import WriteContext

    run = await r.gateway.start_run(component="t", deadline=r.clock.now + timedelta(minutes=1))
    ctx = WriteContext(
        WriteClass.WA, "writeback-x", r.gateway.payload_hash(SetAlertStatus(), params)
    )
    with pytest.raises(WriteRefusedError, match="alerts_per_call"):
        await r.gateway.write(
            SetAlertStatus(), params, run=run, context=ctx, component="t",
            deadline=r.clock.now + timedelta(minutes=1),
        )  # fmt: skip
    assert r.world.calls == []


# --------------------------------------------------------------------------- who may write


async def test_an_earlier_review_needs_an_operator_signed_in_with_their_own_account(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    r = rig(migrated_engine, writer_engine)
    await alerts(app_engine, 3)
    await review(app_engine, "benign_expected", ready=False)  # local mode: no alert-write check
    assert await plan(app_engine) == 0  # the default plan never plans it
    async with app_engine.begin() as conn:
        assert await writeback.plan(conn, older=True) == 1
    assert await diff(app_engine) == {"needs_operator": {"reviews": 1, "alerts": 3}}
    await r.seed_world()
    plain = await r.run()  # no operator: nothing is sent
    assert (plain.sent_alerts, len(plain.waiting)) == (0, 1)
    stale = Operator("ravi", "uid", r.clock.now - timedelta(minutes=31))
    old = await r.run(operator=stale)
    assert (old.sent_alerts, len(old.waiting)) == (0, 1)
    assert r.world.calls == []
    sent = await r.run(operator=Operator("ravi", "uid", r.clock.now))
    assert (sent.sent_alerts, sent.sent_rows) == (3, 1)
    row = await r.row()
    assert (row.operator, row.needs_operator) == ("ravi", True)
    audit = await r.sql("SELECT details FROM audit_events WHERE action = 'writeback.batch'")
    assert audit[0].details["operator"] == "ravi"


@pytest.mark.parametrize("kind", ["break_glass", "service"])
async def test_break_glass_and_service_accounts_never_reach_kibana(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, kind: str
) -> None:
    await alerts(app_engine, 3)
    await review(app_engine, "benign_expected", ready=True)
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE users SET kind = :k"), {"k": kind})
    async with app_engine.begin() as conn:
        assert await writeback.plan(conn, older=True) == 0
    assert await diff(app_engine) == {}


async def test_what_records_a_send_is_the_writers_alone(
    app_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    await reviewed(app_engine, 3)
    await plan(app_engine)
    for column in ("written_count", "previous", "operator"):  # 0045's columns
        async with app_engine.connect() as conn:
            with pytest.raises(DBAPIError, match="permission denied"):
                await conn.execute(text(f"UPDATE writeback_outbox SET {column} = {column}"))  # noqa: S608
    async with writer_engine.begin() as conn:  # the writer moves rows but plans nothing
        await conn.execute(text("UPDATE writeback_outbox SET written_count = 0, previous = '{}'"))
    for statement in (
        "UPDATE writeback_outbox SET status = 'closed'",
        "DELETE FROM writeback_outbox",
    ):
        async with writer_engine.connect() as conn:
            with pytest.raises(DBAPIError, match="permission denied"):
                await conn.execute(text(statement))


async def test_a_benign_verdict_resting_on_f1_waits_for_the_audit(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    r = rig(migrated_engine, writer_engine)
    await reviewed(app_engine, 3)
    async with migrated_engine.begin() as conn:
        inv = (await conn.execute(text("SELECT id FROM investigations"))).scalar_one()
        await conn.execute(
            text(
                "INSERT INTO freshness_shadow (investigation_id, version, pack, signal, mode,"
                " verdict, reason, bridged_verdict, complete_to, refs, margins, decided_at)"
                " VALUES (:i, 1, 'p', 's', 'on', 'known_zero', 'verified', 'known_zero', now(),"
                " '[]', '{}', now())"
            ),
            {"i": inv},
        )
    assert await plan(app_engine) == 1
    assert await diff(app_engine) == {"held": {"reviews": 1, "alerts": 3}}
    await r.seed_world()
    waiting = await r.run()
    assert (waiting.sent_alerts, len(waiting.waiting)) == (0, 1)
    audited = await r.run(f1_audited=True)  # the user's decision that Q-F1's audit passed
    assert (audited.sent_alerts, audited.sent_rows) == (3, 1)


async def test_a_newer_review_after_the_plan_stops_the_row_at_send_time(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    r = await ready(app_engine, migrated_engine, writer_engine, 3)
    await review(app_engine, "inconclusive")  # the reviewer changed their mind; no new plan yet
    result = await r.run()
    assert (result.sent_alerts, r.world.calls) == (0, [])
    assert (await r.row()).state == "skipped"


# --------------------------------------------------------------------------- the key, the lock


@pytest.mark.parametrize("extra", ["delete", "all", "create_index", "manage"])
async def test_a_key_that_holds_too_much_sends_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine, extra: str
) -> None:
    r = await ready(app_engine, migrated_engine, writer_engine, 3)
    r.world.extra_privileges.add(extra)
    result = await r.run()
    assert result.paused is not None
    assert "failed its self-test" in result.paused
    assert (r.world.calls, r.world.mgets) == ([], [])


async def test_a_self_test_that_cannot_be_made_is_not_a_verdict(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    r = await ready(app_engine, migrated_engine, writer_engine, 3)
    r.world.down = True
    result = await r.run()
    assert result.paused is not None
    assert "could not be checked" in result.paused


async def test_a_case_writers_run_holds_the_same_lock(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    r = await ready(app_engine, migrated_engine, writer_engine, 3)
    async with writer_engine.connect() as holder:
        got = (
            await holder.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": store.LOCK_KEY})
        ).scalar()
        assert got
        with pytest.raises(writeback.WritebackRefused, match="another writer"):
            await r.run()
        await holder.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": store.LOCK_KEY})
    assert r.world.calls == []
    assert (await r.run()).sent_alerts == 3  # the lock was free again


async def test_write_back_off_by_default() -> None:
    from argus.config.settings import Settings

    settings = Settings()
    assert settings.writeback.enabled is False
    assert settings.writeback.batch == 5
    assert "WA" not in settings.kibana.write_classes


# --------------------------------------------------------------------------- the invariants


FAULTS = st.lists(
    st.sampled_from(["none", "429", "timeout_lands", "timeout_lost", "partial", "lie_5xx"]),
    min_size=1,
    max_size=6,
)


@settings(
    max_examples=20, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(FAULTS, st.integers(min_value=1, max_value=12))
async def test_sent_count_invariants_under_any_sequence_of_faults(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    sequence: list[str],
    n: int,
) -> None:
    """Whatever Kibana does call by call, an alert's status moves at most once, the row's counts
    stay in range and in step with what Elasticsearch shows, and once Kibana behaves the row is
    done and a further run writes nothing."""
    await reset(migrated_engine)
    async with migrated_engine.begin() as conn:
        await conn.execute(text("TRUNCATE writeback_outbox"))
    r = rig(migrated_engine, writer_engine, caps=WriteCaps(status_per_call=3))
    await reviewed(app_engine, n)
    assert await plan(app_engine) == 1
    ids = await r.seed_world()
    faults = {
        "429": lambda: Fault("status", status=429),
        "timeout_lands": lambda: Fault("timeout", land_after=0.0),
        "timeout_lost": lambda: Fault("timeout", land_after=None),
        "partial": lambda: Fault("body", apply=1, body={"failures": [{"cause": "x"}]}),
        "lie_5xx": lambda: Fault("status", status=502, apply=3),
    }
    for k, kind in enumerate(sequence, 1):
        if kind != "none":
            fault = faults[kind]()
            fault.when = lambda _ids, k=k: len(r.world.calls) == k  # type: ignore[misc]
            r.world.faults.append(fault)
    for _ in range(len(sequence) + 6):
        # a day on, at 09:00 UTC: breakers close, timeouts are paid for, the window is open
        r.clock.now = (r.clock.now + timedelta(days=1)).replace(hour=9, minute=0)
        r.lane.kibana = resume(r.lane.kibana, WriteClass.WA)  # an operator resumes the class
        await r.run()
        row = await r.row()
        assert 0 <= row.written_count <= row.sent_count <= len(row.alert_ids)
        assert all(count <= 1 for count in r.world.transitions.values())
        assert row.written_count <= sum(r.world.statuses[a] == "closed" for a in ids)
        assert row.written_count <= len(r.world.transitions)
    row = await r.row()
    assert (row.state, row.sent_count) == ("sent", n)
    assert all(r.world.statuses[a] == "closed" for a in ids)
    before = len(r.world.calls)
    assert (await r.run()).sent_alerts == 0
    assert len(r.world.calls) == before


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE writeback_outbox SET sent_count = cardinality(alert_ids) + 1",
        "UPDATE writeback_outbox SET sent_count = 1, written_count = 2",
        "UPDATE writeback_outbox SET written_count = -1",
        "UPDATE writeback_outbox SET held = 'because'",
        "UPDATE writeback_outbox SET previous = '[]'::jsonb",
        "UPDATE writeback_outbox SET needs_operator = true, sent_count = 1, written_count = 1",
        "UPDATE writeback_outbox SET review_id = NULL",  # neither a review nor a closure
        "UPDATE writeback_outbox SET closure_request_id = 1, case_id = NULL",
    ],
)
async def test_the_database_keeps_the_counts_and_the_sources_apart(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, statement: str
) -> None:
    await reviewed(app_engine, 3)
    await plan(app_engine)
    async with migrated_engine.connect() as conn:
        with pytest.raises(DBAPIError, match=r"violates|foreign key"):
            await conn.execute(text(statement))


@pytest.mark.parametrize(
    ("status", "lane"),
    [
        (400, None),
        (401, "stopped"),
        (403, "WA"),
        (404, None),
        (409, None),
        (500, None),
        (503, None),
    ],
)
async def test_every_error_status_ends_the_run_with_one_call_and_no_retry(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    status: int,
    lane: str | None,
) -> None:
    r = await ready(app_engine, migrated_engine, writer_engine, 5)
    r.world.faults.append(Fault("status", status=status, times=5))
    result = await r.run()
    assert result.paused is not None
    assert result.paused.startswith(f"Kibana answered {status}: paused, nothing retried")
    assert len(r.world.calls) == 1  # never retried, not even once
    row = await r.row()
    assert (row.state, row.sent_count, row.written_count) == ("paused", 0, 0)
    # a refusal before any change (401) leaves nothing to restore; any other answer may have landed
    assert len(row.previous) == (0 if status == 401 else 5)
    if lane == "stopped":
        assert r.lane.kibana.stopped is not None  # a 401 stops Kibana work
    elif lane == "WA":
        assert "WA" in r.lane.kibana.paused  # a 403 pauses the class
    r.world.faults.clear()
    again = await r.run()  # a new run: a stop, a pause or Kibana's breaker holds it back
    if status in (401, 403, 503):
        assert (again.sent_alerts, len(r.world.calls)) == (0, 1)
    else:
        assert (again.sent_alerts, len(r.world.calls)) == (5, 2)
