"""R17's gate (D-061, D-062, D-063), carried over to the v2 sender (Q-D5) and its fake Kibana:
at most 5 alerts while nothing was ever written; no alert sent twice (limits, refusals, errors,
concurrent runs); 429 pauses without retries; the kill switch stops writes; only the newest
decision, over the alerts the reviewer saw. Where v2 differs the test says so."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import writeback, writeback_sender
from argus.gateway.kibana.writes import WriteCaps
from argus.web import auth
from argus.web.capabilities import Capability
from argus.web.reviews import add_review
from tests.integration.grouping.test_grouping import NOW, doc, ingest
from tests.integration.writeback.kit import Fault, Kibana, Rig, rig

pytestmark = pytest.mark.integration


async def alerts(engine: AsyncEngine, n: int, first: int = 0) -> None:
    docs = [doc(k, "r1", "10.0.0.1", NOW - timedelta(minutes=k)) for k in range(first, first + n)]
    await ingest(engine, docs)


async def review(
    engine: AsyncEngine, outcome: str | None, action: str = "reviewed", *, ready: bool = True
) -> None:
    """A review by asha. ``ready``: made under an ELK check that showed the alert-status
    privileges in a verified session (``kibana_ok``), the only kind that may reach Kibana."""
    async with engine.begin() as conn:
        found = await auth.login(conn, "asha", "correct horse battery", NOW)
        if found is None:
            await auth.add_user(conn, "asha", "Asha", "correct horse battery")
            found = await auth.login(conn, "asha", "correct horse battery", NOW)
        assert found is not None
        who = found[1]
        if ready:
            who = replace(
                who, mode="elk", capabilities=frozenset({Capability.VIEW, Capability.REVIEW})
            )
        assert who.kibana_ok is ready
        inv, version = (await conn.execute(text("SELECT id, version FROM investigations"))).one()
        latest = (await conn.execute(text("SELECT max(id) FROM review_events"))).scalar_one()
        await add_review(
            conn, who, inv, action=action, outcome=outcome,  # type: ignore[arg-type]
            note=None, seen_review=latest, seen_version=version,
        )  # fmt: skip


async def reviewed(engine: AsyncEngine, n: int, outcome: str = "benign_expected") -> None:
    await alerts(engine, n)
    await review(engine, outcome)


async def plan(engine: AsyncEngine) -> int:
    async with engine.begin() as conn:
        return await writeback.plan(conn)


async def diff(engine: AsyncEngine) -> dict[str, Any]:
    async with engine.connect() as conn:
        return await writeback.diff(conn)


async def rows(engine: AsyncEngine) -> list[Any]:
    async with engine.connect() as conn:
        return list(
            await conn.execute(
                text("SELECT state, status, sent_count FROM writeback_outbox ORDER BY id")
            )
        )


def batches(r: Rig) -> list[tuple[str, ...]]:
    return [ids for ids, _ in r.world.calls]


async def test_first_run_five_then_the_rest_and_never_twice(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    r = rig(migrated_engine, writer_engine)
    await reviewed(app_engine, 8)
    assert await plan(app_engine) == 1
    assert await plan(app_engine) == 0  # one row per review
    assert await diff(app_engine) == {"closed": {"reviews": 1, "alerts": 8}}
    await r.seed_world()
    first = await r.run()
    assert (first.sent_alerts, first.sent_rows) == (5, 0)  # the row is not done yet
    assert await diff(app_engine) == {"closed": {"reviews": 1, "alerts": 3}}
    rest = await r.run()
    again = await r.run()
    assert (rest.sent_alerts, rest.sent_rows, again.sent_alerts, again.sent_rows) == (3, 1, 0, 0)
    assert len(r.world.written()) == len(set(r.world.written())) == 8  # every alert exactly once
    assert [status for _, status in r.world.calls] == ["closed", "closed"]
    assert [tuple(x) for x in await rows(app_engine)] == [("sent", "closed", 8)]


async def test_the_first_run_limit_is_not_the_callers_choice(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    r = rig(migrated_engine, writer_engine)
    await reviewed(app_engine, 7)
    await plan(app_engine)
    await r.seed_world()
    assert (await r.run(run_limit=100)).sent_alerts == 5  # nothing was ever written
    assert (await r.run(run_limit=100)).sent_alerts == 2


async def test_a_pause_mid_row_resumes_after_the_sent_batches(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(writeback_sender, "FIRST_RUN", 100)
    r = rig(migrated_engine, writer_engine, caps=WriteCaps(status_per_call=2))
    await reviewed(app_engine, 5)
    await plan(app_engine)
    await r.seed_world()
    # the first call goes through, the second is refused with 429
    r.world.faults.append(Fault("status", when=lambda ids: len(r.world.calls) == 2, status=429))
    paused = await r.run(run_limit=100)
    assert (paused.sent_alerts, paused.sent_rows) == (2, 0)
    assert paused.paused is not None
    assert paused.paused.startswith("Kibana answered 429: paused, nothing retried")
    assert await diff(app_engine) == {"closed": {"reviews": 1, "alerts": 3}}
    r.clock.now += timedelta(minutes=10)  # Kibana's breaker opened for a while
    resumed = await r.run(run_limit=100)
    assert (resumed.sent_alerts, resumed.sent_rows) == (3, 1)
    first, refused, retried, *_ = batches(r)
    assert retried == refused  # the refused batch is the first one sent again
    assert len(r.world.written()) == len(set(r.world.written())) == 5
    assert not set(first) & set(retried)


async def test_an_error_from_kibana_pauses_and_keeps_the_batches_it_answered(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(writeback_sender, "FIRST_RUN", 100)
    r = rig(migrated_engine, writer_engine, caps=WriteCaps(status_per_call=2))
    await reviewed(app_engine, 5)
    await plan(app_engine)
    await r.seed_world()
    r.world.faults.append(
        Fault("timeout", when=lambda ids: len(r.world.calls) == 2, land_after=None)
    )  # the second call is never answered and never lands
    paused = await r.run(run_limit=100)
    assert paused.paused is not None
    assert paused.paused.startswith("Kibana did not answer")
    assert [tuple(x) for x in await rows(app_engine)] == [("paused", "closed", 2)]
    r.clock.now += timedelta(hours=2)  # a timeout is charged its whole 15 s to the lane's budget
    await r.run(run_limit=100)
    accepted, unanswered, *rest = batches(r)
    later = {a for ids in rest for a in ids}
    assert not set(accepted) & later  # an accepted batch is never sent again
    assert rest[0] == unanswered  # only the unanswered batch repeats
    assert set(accepted) | later == {a for ids in batches(r) for a in ids}
    assert len(set(accepted) | later) == 5


async def test_two_runs_at_once_never_send_the_same_alerts(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    r = rig(migrated_engine, writer_engine)
    await reviewed(app_engine, 3)
    await plan(app_engine)
    await r.seed_world()

    class Slow(Kibana):
        async def send(self, request: Any) -> Any:
            await asyncio.sleep(0.3)
            return await super().send(request)

    r.gateway.transport = Slow(r.world)
    r.healthy()
    results = await asyncio.gather(r.sender().run(), r.sender().run(), return_exceptions=True)
    refused = [x for x in results if isinstance(x, writeback.WritebackRefused)]
    assert len(refused) == 1
    assert "another writer or write-back run" in str(refused[0])
    assert len(r.world.written()) == len(set(r.world.written())) == 3


async def test_a_refusal_pauses_and_the_kill_switch_stops(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    r = rig(migrated_engine, writer_engine)
    await reviewed(app_engine, 3, outcome="true_positive")
    await plan(app_engine)
    await r.seed_world()
    r.world.faults.append(Fault("status", status=429))
    paused = await r.run()
    assert paused.paused is not None
    assert paused.paused.startswith("Kibana answered 429: paused, nothing retried")
    assert len(r.world.calls) == 1  # no retry storm

    r.lane.stopped.add("writeback")
    halted = await r.run()
    assert halted.paused == "stopped by the kill switch"
    assert len(r.world.calls) == 1
    assert [tuple(x) for x in await rows(app_engine)] == [("paused", "acknowledged", 0)]


async def test_only_the_alerts_the_reviewer_saw(app_engine: AsyncEngine) -> None:
    await reviewed(app_engine, 3)
    await alerts(app_engine, 3, first=10)  # an escalation after the benign review
    assert await plan(app_engine) == 1
    assert await diff(app_engine) == {"closed": {"reviews": 1, "alerts": 3}}


@pytest.mark.parametrize(
    ("later", "expected"),
    [
        ("inconclusive", {}),  # the newest decision says: do nothing
        ("true_positive", {"acknowledged": {"reviews": 1, "alerts": 3}}),
    ],
)
async def test_a_newer_decision_supersedes_an_unsent_one(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    later: str,
    expected: dict[str, Any],
) -> None:
    r = rig(migrated_engine, writer_engine)
    await reviewed(app_engine, 3)
    await plan(app_engine)
    await review(app_engine, later)
    await plan(app_engine)
    assert await diff(app_engine) == expected
    await r.seed_world()
    await r.run()
    assert {status for _, status in r.world.calls} <= {"acknowledged"}
    assert (await rows(app_engine))[0].state == "skipped"


async def test_a_review_that_was_not_kibana_ready_is_never_planned(app_engine: AsyncEngine) -> None:
    await alerts(app_engine, 3)
    await review(app_engine, "benign_expected", ready=False)  # local mode, break-glass, unverified
    assert await plan(app_engine) == 0
    assert await diff(app_engine) == {}
    await review(app_engine, "benign_expected", ready=True)
    assert await plan(app_engine) == 1


async def test_a_newer_review_that_was_not_ready_supersedes_an_unsent_ready_one(
    app_engine: AsyncEngine,
) -> None:
    await reviewed(app_engine, 3)
    assert await plan(app_engine) == 1
    await review(app_engine, "true_positive", ready=False)
    assert await plan(app_engine) == 0
    assert await diff(app_engine) == {}  # the older verdict is not sent behind the newer one
    assert (await rows(app_engine))[0].state == "skipped"


async def test_both_reviews_unplanned_only_the_newest_is_planned(app_engine: AsyncEngine) -> None:
    await reviewed(app_engine, 3)
    await review(app_engine, "inconclusive")
    assert await plan(app_engine) == 0
    assert await diff(app_engine) == {}


async def test_alerts_changed_or_gone_since_the_plan_are_skipped(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    """v2: Elasticsearch decides (``alerts.mget``), not ARGUS's older copy of the status."""
    r = rig(migrated_engine, writer_engine)
    await reviewed(app_engine, 4)
    await plan(app_engine)
    ids = await r.seed_world()
    r.world.statuses[ids[0]] = "closed"  # a person closed it in Kibana since the plan
    async with migrated_engine.begin() as conn:  # reconciliation: gone from the SIEM
        await conn.execute(
            text("UPDATE alert_records SET source_missing_at = now() WHERE alert_id = :a"),
            {"a": ids[1]},
        )
    result = await r.run()
    assert sorted(r.world.written()) == sorted(ids[2:])
    assert (result.sent_alerts, result.skipped_alerts, result.sent_rows) == (2, 2, 1)
    assert (await r.run()).sent_alerts == 0


def test_a_real_run_needs_everything() -> None:
    with pytest.raises(writeback.WritebackRefused, match="enabled is false"):
        writeback.refuse_unless_ready(False, "key", True)
    with pytest.raises(writeback.WritebackRefused, match="no writer key"):
        writeback.refuse_unless_ready(True, None, True)
    with pytest.raises(writeback.WritebackRefused, match="no writer key"):
        writeback.refuse_unless_ready(True, SecretStr(""), True)
    with pytest.raises(writeback.WritebackRefused, match="no writer key"):
        writeback.refuse_unless_ready(True, "", True)
    with pytest.raises(writeback.WritebackRefused, match="terminal"):
        writeback.refuse_unless_ready(True, SecretStr("k"), True, terminal=False)
    with pytest.raises(writeback.WritebackRefused, match="confirm"):
        writeback.refuse_unless_ready(True, "key", False)
    writeback.refuse_unless_ready(True, SecretStr("k"), True)
