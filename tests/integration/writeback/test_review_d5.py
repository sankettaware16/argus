"""Q-D5 adversarial review: each test fails on the reviewed head (bb5e9a1) and names its finding."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import writeback, writeback_sender
from argus.gateway.errors import TransportFailedError
from argus.gateway.kibana.writes import WriteCaps
from argus.writeback_sender import Operator
from tests.integration.cases.conftest import Person
from tests.integration.cases.test_service import _kibana_actor
from tests.integration.grouping.test_grouping import NOW, doc, ingest
from tests.integration.writeback.kit import Es, Fault, rig
from tests.integration.writeback.test_v2 import ready
from tests.integration.writeback.test_writeback import alerts, plan, review, reviewed
from tests.integration.writer.kit import approved_closure, mirrored_case

pytestmark = pytest.mark.integration


# --- R1-R3: checks precede the wait


async def test_r1_a_newer_review_arriving_during_the_gap_wait_is_not_overwritten(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`_superseded` runs at the top of `_once`, before the 61 s gap wait, the pre-read, the lease
    and `start_run`; nothing re-checks it in `before_send`. A true-positive review made while the
    sender waits still has the benign row's second batch closed."""
    monkeypatch.setattr(writeback_sender, "FIRST_RUN", 100)
    r = rig(migrated_engine, writer_engine, caps=WriteCaps(status_per_call=2))
    await reviewed(app_engine, 4)
    assert await plan(app_engine) == 1
    await r.seed_world()
    fired: list[float] = []

    async def hook(seconds: float) -> None:
        if seconds > 30 and not fired:
            fired.append(seconds)
            await review(app_engine, "true_positive")
        await r.clock.sleep(seconds)

    r.healthy()
    await r.sender(sleep=hook, run_limit=100).run()
    assert fired
    assert len(r.world.calls) == 1, f"second batch went out after a newer review: {r.world.calls}"


async def test_r2_a_case_reopened_during_the_gap_wait_still_has_its_alerts_closed(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    api_engine: AsyncEngine,
    people: dict[str, Person],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same root cause for a closure row: the reopen check is before the wait."""
    monkeypatch.setattr(writeback_sender, "FIRST_RUN", 100)
    r = rig(migrated_engine, writer_engine, caps=WriteCaps(status_per_call=2))
    case_id = await mirrored_case(
        app_engine, migrated_engine, people["asha"], _kibana_actor(people["asha"]), alerts=4
    )
    await approved_closure(
        r, api_engine, people, case_id, "kibana-case-1", "benign_expected",  # type: ignore[arg-type]
        version="WzEsMV0=",
    )  # fmt: skip
    await r.seed_world()
    assert await plan(app_engine) == 1
    fired: list[float] = []

    async def hook(seconds: float) -> None:
        if seconds > 30 and not fired:
            fired.append(seconds)
            async with migrated_engine.begin() as conn:
                await conn.execute(text("ALTER TABLE cases DISABLE TRIGGER USER"))
                await conn.execute(
                    text(
                        "UPDATE cases SET state = 'open', closed_at = NULL, closure_reason = NULL,"
                        " closure_request_id = NULL WHERE id = :c"
                    ),
                    {"c": case_id},
                )
        await r.clock.sleep(seconds)

    r.healthy()
    await r.sender(sleep=hook, run_limit=100).run()
    assert fired
    assert len(r.world.calls) == 1, f"alerts of a reopened case were closed: {r.world.calls}"


async def test_r3_an_operator_check_is_not_used_after_it_is_30_minutes_old(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`_operator_fresh` is tested before the gap wait; a check 29.5 minutes old sends the next
    batch at 30.5 minutes."""
    monkeypatch.setattr(writeback_sender, "FIRST_RUN", 100)
    r = rig(migrated_engine, writer_engine, caps=WriteCaps(status_per_call=2))
    await alerts(app_engine, 4)
    await review(app_engine, "benign_expected", ready=False)
    async with app_engine.begin() as conn:
        assert await writeback.plan(conn, older=True) == 1
    await r.seed_world()
    checked = r.clock.now - timedelta(minutes=29, seconds=30)
    r.healthy()
    await r.sender(operator=Operator("ravi", "uid", checked), run_limit=100).run()
    assert r.world.call_times
    late = [t for t in r.world.call_times if t - checked > writeback_sender.OPERATOR_FRESH]
    assert not late, f"{len(late)} call(s) sent on an operator check older than 30 minutes"


# --- R4: flags trusted from the runtime


async def test_r4_the_sender_does_not_send_a_row_whose_author_had_no_alert_write(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    """The runtime could INSERT `needs_operator` and `held` (0045) and the sender believed them,
    never looking at `review_events.kibana_ok`. Now the runtime may not name those columns, and
    a row made without them (the defaults: false, NULL) for a review without an alert-write
    check is not sent without an operator: the sender derives both at send time."""
    r = rig(migrated_engine, writer_engine)
    await alerts(app_engine, 3)
    await review(app_engine, "benign_expected", ready=False)
    insert = (
        "INSERT INTO writeback_outbox (review_id, investigation_id, status, alert_ids{cols})"
        " SELECT e.id, e.investigation_id, 'closed',"
        " ARRAY(SELECT alert_id FROM alert_records ORDER BY 1){vals} FROM review_events e"
    )
    for column in ("needs_operator", "held"):  # the flags are not the runtime's to write
        async with app_engine.connect() as conn:
            with pytest.raises(DBAPIError, match="permission denied"):
                await conn.execute(text(insert.format(cols=f", {column}", vals=", NULL")))
    async with app_engine.begin() as conn:  # as the runtime login, with its own grants
        await conn.execute(text(insert.format(cols="", vals="")))
    await r.seed_world()
    result = await r.run()
    assert r.world.calls == [], "a no-alert-write author's review was written without an operator"
    assert len(result.waiting) == 1


# --- R5: credit for alerts we never changed


async def test_r5_alerts_a_person_closed_are_not_credited_as_ours_after_a_failed_call(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    """`previous` is committed before the request leaves, also when the request then never
    reaches Kibana (connection refused). A person closes 3 alerts in Kibana meanwhile; the next
    run finds them at the status, sees them in `previous` and counts them in `written_count`,
    though ARGUS changed none of them (and the first-run flag `written_count > 0` flips)."""
    r = await ready(app_engine, migrated_engine, writer_engine, 5)
    ids = sorted(r.world.statuses)
    r.world.faults.append(Fault("lose"))
    first = await r.run()
    assert first.paused is not None
    assert (await r.row()).written_count == 0
    for a in ids[:3]:  # the TA closes them in Kibana
        r.world.statuses[a] = "closed"
    r.clock.now += timedelta(minutes=10)
    second = await r.run()
    row = await r.row()
    assert second.credited_alerts == 0, "alerts ARGUS never changed were credited to ARGUS"
    assert row.written_count == 2  # only the 2 ARGUS changed


# --- R6: a licence read failure crashes the run


async def test_r6_a_failed_licence_read_pauses_the_run_instead_of_raising(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    """`_write` -> `start_run` reads the licence through the Elasticsearch gateway; its
    ResponseErrors are not Refused/KibanaResponseError, so `_once` does not catch them and
    `run()` raises (no summary, a traceback at the terminal)."""
    r = await ready(app_engine, migrated_engine, writer_engine, 3)

    class NoLicence(Es):
        async def send(self, request: Any) -> Any:
            if request.path.endswith("/_license"):
                raise TransportFailedError("connection reset", retriable=False, reached=False)
            return await super().send(request)

    r.es.transport = NoLicence(r.world)  # type: ignore[assignment]
    result = await r.run()
    assert result.paused is not None
    assert r.world.calls == []


# --- R7: a stale `previous` wins


async def test_r7_previous_is_the_status_before_the_call_that_landed_not_before_one_that_did_not(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    """`CAST(:p AS jsonb) || previous` keeps the first value even when the earlier attempt landed
    nothing. A person acknowledges an alert between two attempts; ARGUS closes it from
    'acknowledged' but records 'open' as the status to restore."""
    r = await ready(app_engine, migrated_engine, writer_engine, 3)
    ids = sorted(r.world.statuses)
    r.world.faults.append(Fault("status", status=500, apply=0))
    first = await r.run()
    assert first.paused is not None
    assert not r.world.applied
    r.world.statuses[ids[0]] = "acknowledged"  # by a person, in Kibana
    r.clock.now += timedelta(minutes=10)
    second = await r.run()
    assert second.sent_alerts == 3
    row = await r.row()
    assert row.previous[ids[0]] == "acknowledged"


# ------------------------------------------------------------------ the rest of the review


async def test_r8_a_row_skipped_while_its_batch_is_in_flight_stays_skipped(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finding 6: `_account` updated by id with no state guard, so a plan's concurrent `skipped`
    was overwritten by `sent`."""
    r = await ready(app_engine, migrated_engine, writer_engine, 3)
    sender = r.sender()
    original = sender._read_back

    async def skipped_meanwhile(*args: Any) -> Any:
        async with migrated_engine.begin() as conn:
            await conn.execute(
                text("UPDATE writeback_outbox SET state = 'skipped', error = 'superseded'")
            )
        return await original(*args)

    monkeypatch.setattr(sender, "_read_back", skipped_meanwhile)
    r.healthy()
    await sender.run()
    assert r.world.calls  # the batch went out; the row is not brought back
    assert (await r.row()).state == "skipped"


async def test_r9_the_newer_decision_is_sent_last_whatever_the_row_ids(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    api_engine: AsyncEngine,
    people: dict[str, Person],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finding 7: a closure planned in the same call as a later true-positive review got the
    higher row id and was sent last, so the older closure overwrote the newer `acknowledged`."""
    from tests.integration.writeback.test_closure import closed_case

    monkeypatch.setattr(writeback_sender, "FIRST_RUN", 100)
    r, _ = await closed_case(app_engine, migrated_engine, writer_engine, api_engine, people)
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                " action, outcome, kibana_ok, created_at) SELECT i.id, i.version, i.alert_count,"
                " :u, 'reviewed', 'true_positive', true,"
                " (SELECT max(closed_at) FROM cases) + interval '1 hour' FROM investigations i"
            ),
            {"u": people["asha"].user_id},
        )
    assert await plan(app_engine) == 2
    result = await r.run()
    assert result.sent_rows == 2
    assert set(r.world.statuses.values()) == {"acknowledged"}


async def test_r10_a_row_whose_alerts_cannot_be_read_does_not_block_the_rows_after_it(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    """Finding 8: a `GatewayError` in the read of one row ended the whole run."""
    r = rig(migrated_engine, writer_engine)
    await alerts(app_engine, 2)
    await review(app_engine, "benign_expected")
    await ingest(
        app_engine, [doc(k, "r2", "10.0.0.2", NOW - timedelta(minutes=k)) for k in (50, 51)]
    )
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                " action, outcome, kibana_ok) SELECT i.id, i.version, i.alert_count,"
                " (SELECT min(user_id) FROM review_events), 'reviewed', 'benign_expected', true"
                " FROM investigations i WHERE NOT EXISTS (SELECT 1 FROM review_events e"
                " WHERE e.investigation_id = i.id)"
            )
        )
    assert await plan(app_engine) == 2
    await r.seed_world()
    first, second = await r.sql("SELECT alert_ids FROM writeback_outbox ORDER BY id")
    bad = set(first.alert_ids)

    class Broken(Es):
        async def send(self, request: Any) -> Any:
            if request.path.endswith("/_mget") and bad & set(json.loads(request.body)["ids"]):
                raise TransportFailedError("reset", retriable=False, reached=False)
            return await super().send(request)

    r.es.transport = Broken(r.world)  # type: ignore[assignment]
    result = await r.run()
    assert {r.world.statuses[a] for a in second.alert_ids} == {"closed"}
    assert {r.world.statuses[a] for a in first.alert_ids} == {"open"}
    assert any("could not be read" in line for line in result.waiting)
    assert (await r.row(0)).state == "planned"


async def test_r11_an_alert_a_person_changed_after_the_pre_read_is_not_written_over(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finding 9: the pre-read came before `start_run` and the lease wait; an alert changed in
    between was written with a stale `previous`. The read is repeated at the last step."""
    r = await ready(app_engine, migrated_engine, writer_engine, 3)
    ids = sorted(r.world.statuses)
    sender = r.sender()
    original = sender._started
    done: list[bool] = []

    async def person_acts_first() -> Any:
        if not done:
            done.append(True)
            r.world.statuses[ids[0]] = "acknowledged"
        return await original()

    monkeypatch.setattr(sender, "_started", person_acts_first)
    r.healthy()
    await sender.run()
    assert all(s == "closed" for s in r.world.statuses.values())
    assert (await r.row()).previous[ids[0]] == "acknowledged"
    assert len(r.world.calls) == 1, "the stale plan went out"


async def test_r12_a_verdict_that_rests_on_f1_after_the_plan_is_held_at_send_time(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    """Finding 2: `held` is derived when sending, not trusted from the plan's cache."""
    r = await ready(app_engine, migrated_engine, writer_engine, 3)
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
    result = await r.run()
    assert (r.world.calls, len(result.waiting)) == ([], 1)


async def test_r13_the_writer_reads_only_the_review_columns_it_uses(
    writer_engine: AsyncEngine,
) -> None:
    """Finding 10: a column grant, notes excluded."""
    async with writer_engine.connect() as conn:
        await conn.execute(
            text(
                "SELECT id, investigation_id, action, outcome, kibana_ok,"
                " user_id, created_at FROM review_events"
            )
        )
    for column in ("note", "version"):
        async with writer_engine.connect() as conn:
            with pytest.raises(DBAPIError, match="permission denied"):
                await conn.execute(text(f"SELECT {column} FROM review_events"))  # noqa: S608


async def test_r14_doctor_finds_a_writer_whose_column_grants_drifted(
    writer_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """The role check reads column by column where a grant is by columns."""
    from argus.db import roles

    assert await roles.writer_role_problems(writer_engine) == []
    login = writer_engine.url.username
    async with migrated_engine.begin() as conn:
        await conn.execute(text(f'GRANT SELECT (note) ON review_events TO "{login}"'))
        await conn.execute(
            text(f"REVOKE SELECT (kibana_ok) ON review_events FROM {roles.WRITER_ROLE}")  # noqa: S608
        )
        await conn.execute(text(f'GRANT SELECT (reason) ON freshness_shadow TO "{login}"'))
        await conn.execute(text(f'GRANT INSERT (held) ON writeback_outbox TO "{login}"'))
    problems = await roles.writer_role_problems(writer_engine)
    assert "can read review_events.note" in problems
    assert "cannot read review_events.kibana_ok" in problems
    assert "can read freshness_shadow.reason" in problems
    assert "can insert writeback_outbox.held" in problems


async def test_r15_the_runtime_cannot_write_the_flags_the_sender_derives(
    app_engine: AsyncEngine,
) -> None:
    from argus.db import roles

    grant = roles.RUNTIME_GRANTS["writeback_outbox"]
    assert not {"needs_operator", "held"} & set(grant.insert + grant.update)
    assert {"needs_operator", "held"} <= set(roles.WRITER_GRANTS["writeback_outbox"].update)
