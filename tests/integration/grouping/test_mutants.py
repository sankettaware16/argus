"""Grouping and job-queue tests written for mutation survivors (D-040)."""

from __future__ import annotations

import asyncio
import dataclasses
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.grouping import assign as ga
from argus.grouping.store import COALESCE, Grouped, group
from argus.jobs import queue
from argus.normalize import NormalizedAlert, normalize
from tests.integration.grouping.test_grouping import NOW, WINDOW, doc, ingest

pytestmark = pytest.mark.integration


def alert(n: int, **changes: object) -> NormalizedAlert:
    d = doc(n, "rule-a", "10.0.0.1", NOW)
    d["_source"].update(changes)
    result = normalize(d)
    assert isinstance(result, NormalizedAlert)
    return result


def test_ids_are_pinned_forever() -> None:
    assert ("2", timedelta(hours=24)) == (ga.GROUPING_VERSION, ga.WINDOW)
    assert {"source", "client", "host", "user"} == ga.ACTOR_NAMESPACES
    assert uuid.UUID("6f0c4a52-6a53-5b5e-9a43-7a2b9c1d0e11") == ga.NAMESPACE
    assert datetime(2026, 1, 1, 18, 30, tzinfo=UTC) == ga.anchor()
    start = datetime(2026, 10, 8, 18, 30, tzinfo=UTC)
    expected = uuid.uuid5(ga.NAMESPACE, "2|rule-a|k|2026-10-08T18:30:00+00:00")
    assert ga.investigation_id("rule-a", "k", start) == expected
    a = ga.assign(alert(1))
    assert a.next_id == ga.investigation_id("rule-a", a.key, a.bucket_start + WINDOW)
    assert a.previous_id == ga.investigation_id("rule-a", a.key, a.bucket_start - WINDOW)
    with pytest.raises(dataclasses.FrozenInstanceError):
        a.key = "x"  # type: ignore[misc]


def keyed(fields: tuple[str, ...], values: tuple[object, ...]) -> NormalizedAlert:
    plain = alert(1)
    key = plain.group_key.model_copy(update={"fields": fields, "values": values})
    return plain.model_copy(update={"group_key": key})


def test_the_actor_is_the_key() -> None:
    """D-053: who acted, not what was touched; no per-rule setting."""
    plain = alert(1)
    assert ga.group_key(plain) == '[["source.ip","10.0.0.1"]]'
    many = keyed(("user.name", "host.name", "destination.ip", "client.ip", "url.path"),
                 ("u", "h", "1.2.3.4", "9.9.9.9", "/x"))  # fmt: skip
    assert ga.group_key(many) == ('[["client.ip","9.9.9.9"],["host.name","h"],["user.name","u"]]')
    targets_only = keyed(("destination.ip", "destination.port"), ("1.2.3.4", 22))
    assert ga.group_key(targets_only) == targets_only.group_key.canonical  # kept whole
    no_actor_value = keyed(("source.ip", "destination.ip"), (None, "1.2.3.4"))
    assert ga.group_key(no_actor_value) == no_actor_value.group_key.canonical
    assert ga.group_key(keyed(("sourcey.ip",), ("x",))) == plain.group_key.canonical


def test_a_singleton_or_keyless_alert_stands_alone() -> None:
    plain = alert(1)
    singleton = plain.model_copy(update={"group_key": plain.group_key.model_copy(
        update={"singleton": "all_null"})})  # fmt: skip
    assert ga.group_key(singleton) == f"alert:{plain.alert_id}"
    keyless = plain.model_copy(update={"group_key": plain.group_key.model_copy(
        update={"canonical": None})})  # fmt: skip
    assert ga.group_key(keyless) == f"alert:{plain.alert_id}"


async def test_group_reports_what_it_did(app_engine: AsyncEngine) -> None:
    assert timedelta(minutes=30) == COALESCE
    async with app_engine.begin() as conn:
        assert await group(conn, [], NOW) == Grouped(0, 0, 0)
    d1, d2 = doc(1, "rule-a", "10.0.0.1", NOW), doc(2, "rule-a", "10.0.0.1", NOW)
    async with app_engine.begin() as conn:
        from argus.collector import store

        await store.ingest(conn, [d1, d2], "live", NOW)
        result = await group(conn, [alert(1), alert(2)], NOW)
        again = await group(conn, [alert(1)], NOW)
    assert result == Grouped(1, 2, 1)
    assert again == Grouped(1, 0, 0)
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.linked = 0  # type: ignore[misc]


async def test_manual_runs_are_late_and_entities_are_indexed(app_engine: AsyncEngine) -> None:
    manual = doc(1, "rule-a", "10.0.0.1", NOW)
    manual["_source"]["kibana.alert.rule.execution.type"] = "manual"
    await ingest(app_engine, [manual, doc(2, "rule-a", "10.0.0.2", NOW)])
    async with app_engine.connect() as conn:
        late = dict((await conn.execute(text(
            "SELECT alert_id, late_arrival FROM investigation_alerts"))).all())  # fmt: skip
        ents = (await conn.execute(text(
            "SELECT kind, value, investigations FROM entities WHERE value LIKE '10.0.0.%'"
            " ORDER BY value"))).all()  # fmt: skip
        query = "SELECT count(*) FROM investigation_entities WHERE value LIKE '10.0.0.%'"
        linked = (await conn.execute(text(query))).scalar_one()
    assert late == {f"{1:040x}": True, f"{2:040x}": False}
    assert ents == [("ip", "10.0.0.1", 1), ("ip", "10.0.0.2", 1)]
    assert linked == 2


async def test_continues_links_whichever_day_comes_first(app_engine: AsyncEngine) -> None:
    for order in ((1, 2), (4, 3)):  # earlier day first, then later day first
        days = {1: NOW - WINDOW, 2: NOW, 3: NOW - WINDOW, 4: NOW}
        for n in order:
            await ingest(app_engine, [doc(n, f"rule-{order[0]}", "10.0.0.7", days[n])])
    async with app_engine.connect() as conn:
        rows = (await conn.execute(text(
            "SELECT rule_id, continues_id IS NOT NULL FROM investigations"
            " WHERE rule_id IN ('rule-1', 'rule-4') ORDER BY rule_id, bucket_start"
        ))).all()  # fmt: skip
    assert rows == [("rule-1", False), ("rule-1", True), ("rule-4", False), ("rule-4", True)]


async def test_concurrent_groupers_of_different_alerts_count_them_all(
    app_engine: AsyncEngine,
) -> None:
    """Different pages, one investigation: only the row lock makes the recount see the
    others' alerts."""
    docs = [doc(n, "rule-a", "10.0.0.1", NOW - timedelta(minutes=n)) for n in range(160)]

    async def grouper(part: int) -> None:
        mine = docs[part::8]
        for at in range(0, len(mine), 4):
            await ingest(app_engine, mine[at : at + 4])

    await asyncio.gather(*(grouper(part) for part in range(8)))
    async with app_engine.connect() as conn:
        counts = (await conn.execute(text("SELECT alert_count FROM investigations"))).all()
    assert counts == [(160,)]


async def test_job_constants_renewal_and_lost_leases(app_engine: AsyncEngine) -> None:
    assert (
        timedelta(minutes=10), timedelta(minutes=30), 5, timedelta(minutes=2),
    ) == (queue.LEASE, queue.COALESCE, queue.MAX_FAILURES, queue.BACKOFF)  # fmt: skip
    await ingest(app_engine, [doc(1, "rule-a", "10.0.0.1", NOW)])
    async with app_engine.begin() as conn:
        (job,) = await queue.claim(conn, "w", NOW)
    with pytest.raises(dataclasses.FrozenInstanceError):
        job.claim = 9  # type: ignore[misc]
    later = NOW + timedelta(minutes=9)
    async with app_engine.begin() as conn:
        await queue.renew(conn, job, later)
        until = (await conn.execute(text("SELECT lease_until FROM jobs"))).scalar_one()
    assert until == later + queue.LEASE
    async with app_engine.begin() as conn:  # still ours after the old lease would have ended
        assert await queue.claim(conn, "x", NOW + timedelta(minutes=11)) == []
    gone = later + queue.LEASE + timedelta(seconds=1)
    for action in (queue.renew, lambda c, j, n: queue.fail(c, j, n, "e")):
        with pytest.raises(queue.LeaseLostError):
            async with app_engine.begin() as conn:
                await action(conn, job, gone)


async def test_a_failure_keeps_500_characters(app_engine: AsyncEngine) -> None:
    await ingest(app_engine, [doc(1, "rule-a", "10.0.0.1", NOW)])
    async with app_engine.begin() as conn:
        (job,) = await queue.claim(conn, "w", NOW)
        await queue.fail(conn, job, NOW, "x" * 600)
        error = (await conn.execute(text("SELECT error FROM jobs"))).scalar_one()
    assert len(error) == 500


async def test_regroup_rebuilds_the_same_and_protects_reviews(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    from argus.grouping.regroup import ReviewsExistError, regroup

    docs = [doc(n, f"rule-{n % 2}", f"10.0.0.{n % 3}", NOW - timedelta(hours=n)) for n in range(30)]
    await ingest(app_engine, docs)

    async def state() -> list[tuple[object, ...]]:
        async with app_engine.connect() as conn:
            query = "SELECT alert_id, investigation_id FROM investigation_alerts ORDER BY 1"
            return [tuple(r) for r in await conn.execute(text(query))]

    before = await state()
    async with migrated_engine.begin() as conn:  # a leftover of an older grouping version
        await conn.execute(text(
            "INSERT INTO investigations (id, grouping_version, rule_id, group_key, bucket_start,"
            " bucket_end, previous_id) VALUES (gen_random_uuid(), '1', 'old', 'k', now(),"
            " now() + interval '1 day', gen_random_uuid())"))  # fmt: skip
        await conn.execute(text(  # an E-id of a current investigation (Q-F2): derived too
            "INSERT INTO evidence_requests (investigation_id, eid, task_key, template,"
            " template_version, origin, first_version, created_at) VALUES (:i, 1, :k,"
            " 'proxy.host', 1, 'pack', 1, now())"), {"i": before[0][1], "k": "a" * 64})  # fmt: skip
    assert await regroup(migrated_engine, NOW) == (30, len({inv for _, inv in before}))
    assert await state() == before
    async with app_engine.connect() as conn:
        assert await conn.scalar(text("SELECT count(*) FROM evidence_requests")) == 0
    async with app_engine.begin() as conn:
        user = (await conn.execute(text(
            "INSERT INTO users (username, display_name, password_hash) VALUES ('ab', 'A', 'x')"
            " RETURNING id"))).scalar_one()  # fmt: skip
        await conn.execute(text(
            "INSERT INTO review_events (investigation_id, version, alert_count, user_id, action)"
            " VALUES (:i, 1, 1, :u, 'reviewed')"), {"i": before[0][1], "u": user})  # fmt: skip
    with pytest.raises(ReviewsExistError):
        await regroup(migrated_engine, NOW)
    assert await state() == before


async def test_regroup_protects_the_gold_set(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    from argus.grouping.regroup import ReviewsExistError, regroup

    await ingest(
        app_engine, [doc(n, "rule-0", "10.0.0.1", NOW - timedelta(hours=n)) for n in range(3)]
    )
    async with migrated_engine.begin() as conn:
        inv = (await conn.execute(text("SELECT id, version FROM investigations LIMIT 1"))).one()
        await conn.execute(text(
            "INSERT INTO gold_items (set_name, investigation_id, version, pack, dossier_hash,"
            " rule_name, split, why, suggestion) VALUES ('v1', :i, :v, 'p', :h, 'r', 'dev', '{}',"
            " '{}'::jsonb)"), {"i": inv.id, "v": inv.version, "h": "a" * 64})  # fmt: skip
    with pytest.raises(ReviewsExistError, match="1 gold-set items refer"):
        await regroup(migrated_engine, NOW)
    async with app_engine.connect() as conn:
        assert await conn.scalar(text("SELECT count(*) FROM gold_items")) == 1
