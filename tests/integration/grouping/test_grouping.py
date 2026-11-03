"""R6 gate: grouping is independent of order, batching and concurrency; the job queue is
fenced; killed workers lose and duplicate nothing; a real day folds at least 12 times."""

from __future__ import annotations

import asyncio
import copy
import gzip
import json
import random
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.collector import store
from argus.grouping.assign import WINDOW, anchor, assign, bucket_start
from argus.grouping.store import group
from argus.jobs import queue
from argus.normalize import NormalizedAlert, normalize
from tests.integration.collector.fake_es import INDEX, alert

pytestmark = pytest.mark.integration

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
CORPUS = Path(__file__).resolve().parents[3] / "data" / "corpus" / "2026-10-08" / "alerts.jsonl.gz"
TABLES = (
    "jobs, investigation_entities, entities, investigation_alerts, investigations,"
    " alert_records, collector_cursors, reconciliation_runs, coverage_gaps"
)


def doc(n: int, rule: str, ip: str, at: datetime) -> dict[str, Any]:
    alert_id = f"{n:040x}"
    source = alert(alert_id, at, rule)
    source["kibana.alert.original_time"] = at.isoformat().replace("+00:00", "Z")
    source["source"]["ip"] = ip
    for ancestor in source["kibana.alert.ancestors"]:  # its own source event: not a duplicate
        ancestor["id"] = f"event-{n}"
    return {"_index": INDEX, "_id": alert_id, "found": True, "_source": source}


async def ingest(engine: AsyncEngine, docs: Sequence[dict[str, Any]], now: datetime = NOW) -> None:
    async with engine.begin() as conn:
        await store.ingest(conn, docs, "live", now)
        normalized = [a for a in map(normalize, docs) if isinstance(a, NormalizedAlert)]
        await group(conn, normalized, now)


async def reset(owner: AsyncEngine) -> None:
    async with owner.begin() as conn:
        await conn.execute(text(f"TRUNCATE {TABLES} CASCADE"))


async def snapshot(engine: AsyncEngine) -> dict[str, Any]:
    async with engine.connect() as conn:
        links = (await conn.execute(text(
            "SELECT alert_id, investigation_id, duplicate_of FROM investigation_alerts"
            " ORDER BY alert_id"))).all()  # fmt: skip
        investigations = (await conn.execute(text(
            "SELECT id, rule_id, group_key, bucket_start, alert_count, duplicate_count,"
            " first_event_at, last_event_at, severity, rule_name, continues_id"
            " FROM investigations ORDER BY id"))).all()  # fmt: skip
        entities = (await conn.execute(text(
            "SELECT * FROM investigation_entities ORDER BY 1, 2, 3"))).all()  # fmt: skip
        counts = (await conn.execute(text("SELECT * FROM entities ORDER BY 1, 2"))).all()
        queued = "SELECT investigation_id FROM jobs WHERE status = 'queued' ORDER BY 1"
        jobs = (await conn.execute(text(queued))).all()
    return {"links": links, "inv": investigations, "ent": entities, "counts": counts,
            "jobs": jobs}  # fmt: skip


SPECS = st.lists(
    st.tuples(
        st.sampled_from(["rule-a", "rule-b", "rule-c"]),
        st.sampled_from(["10.0.0.1", "10.0.0.2", "10.0.0.3"]),
        st.integers(0, 3 * 24 * 60),  # minutes over three days
        st.booleans(),  # an exact duplicate of the previous detection
    ),
    min_size=1,
    max_size=20,
)


def docs_for(specs: list[tuple[str, str, int, bool]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for n, (rule, ip, minutes, duplicate) in enumerate(specs):
        if duplicate and out:
            twin = copy.deepcopy(out[-1])
            alert_id = f"{n:040x}"
            twin["_id"] = alert_id
            twin["_source"]["kibana.alert.uuid"] = alert_id
            out.append(twin)
        else:
            out.append(doc(n, rule, ip, NOW - timedelta(minutes=minutes)))
    return out


# --------------------------------------------------------------------------- pure ids


def test_buckets_start_at_midnight_ist() -> None:
    assert anchor().hour == 18 and anchor().minute == 30  # noqa: PT018
    at = datetime(2026, 10, 9, 18, 29, 59, tzinfo=UTC)
    assert bucket_start(at) == datetime(2026, 10, 8, 18, 30, tzinfo=UTC)
    assert bucket_start(at + timedelta(seconds=1)) == datetime(2026, 10, 9, 18, 30, tzinfo=UTC)
    first = normalize(doc(1, "r", "10.0.0.1", NOW))
    assert isinstance(first, NormalizedAlert)
    a = assign(first)
    assert a.bucket_end - a.bucket_start == WINDOW
    assert a.investigation_id == assign(first).investigation_id  # pure


# --------------------------------------------------------------------------- invariance


@settings(
    max_examples=max(25, settings().max_examples // 4),
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
@given(specs=SPECS, seed=st.integers(0, 2**32 - 1), cuts=st.integers(1, 5))
async def test_any_order_and_batch_split_give_the_same_investigations(
    specs: list[tuple[str, str, int, bool]],
    seed: int,
    cuts: int,
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
) -> None:
    docs = docs_for(specs)
    await reset(migrated_engine)
    await ingest(app_engine, docs)
    expected = await snapshot(app_engine)
    await reset(migrated_engine)
    shuffled = docs[:]
    random.Random(seed).shuffle(shuffled)
    size = max(1, len(shuffled) // cuts)
    for at in range(0, len(shuffled), size):
        await ingest(app_engine, shuffled[at : at + size])
    assert await snapshot(app_engine) == expected


async def test_eight_concurrent_groupers_agree_with_one(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    rnd = random.Random(8)
    specs = [(rnd.choice("abc"), f"10.0.0.{rnd.randint(1, 4)}", rnd.randint(0, 4000),
              rnd.random() < 0.2) for _ in range(120)]  # fmt: skip
    docs = docs_for(specs)
    await ingest(app_engine, docs)
    expected = await snapshot(app_engine)
    await reset(migrated_engine)

    async def grouper(seed: int) -> None:
        mine = docs[:]
        random.Random(seed).shuffle(mine)
        for at in range(0, len(mine), 15):  # no retries: a deadlock or conflict fails the test
            await ingest(app_engine, mine[at : at + 15])

    await asyncio.gather(*(grouper(seed) for seed in range(8)))
    assert await snapshot(app_engine) == expected


async def test_duplicates_continues_and_the_first_job(app_engine: AsyncEngine) -> None:
    day = doc(1, "rule-a", "10.0.0.9", NOW)
    twin = copy.deepcopy(day)
    twin["_id"] = twin["_source"]["kibana.alert.uuid"] = f"{2:040x}"
    before = doc(3, "rule-a", "10.0.0.9", NOW - WINDOW)
    await ingest(app_engine, [twin, day])
    await ingest(app_engine, [before])  # the previous day arrives late
    async with app_engine.connect() as conn:
        rows = (await conn.execute(text(
            "SELECT alert_count, duplicate_count, continues_id IS NOT NULL, version"
            " FROM investigations ORDER BY bucket_start"))).all()  # fmt: skip
        dup = (await conn.execute(text(
            "SELECT duplicate_of FROM investigation_alerts WHERE alert_id = :a"),
            {"a": f"{2:040x}"})).scalar_one()  # fmt: skip
        jobs = (await conn.execute(text("SELECT count(*) FROM jobs"))).scalar_one()
    assert rows == [(1, 0, False, 1), (1, 1, True, 1)]
    assert dup == f"{1:040x}"  # the smaller id is the original
    assert jobs == 2


# --------------------------------------------------------------------------- the job queue


async def one_job(engine: AsyncEngine, n: int = 1) -> None:
    await ingest(engine, [doc(n, "rule-a", "10.0.0.1", NOW - timedelta(hours=1))])


async def test_a_lost_lease_cannot_complete(app_engine: AsyncEngine) -> None:
    await one_job(app_engine)
    async with app_engine.begin() as conn:
        (first,) = await queue.claim(conn, "w1", NOW)
    later = NOW + queue.LEASE + timedelta(seconds=1)
    async with app_engine.begin() as conn:
        (second,) = await queue.claim(conn, "w2", later)  # w1 presumed dead
    assert (second.job_id, second.claim) == (first.job_id, 2)
    with pytest.raises(queue.LeaseLostError):
        async with app_engine.begin() as conn:
            await queue.complete(conn, first, later)
    async with app_engine.begin() as conn:
        assert await queue.complete(conn, second, later) is False
        assert await queue.claim(conn, "w3", later) == []


async def test_a_change_while_running_queues_the_job_again(app_engine: AsyncEngine) -> None:
    await one_job(app_engine)
    async with app_engine.begin() as conn:
        (job,) = await queue.claim(conn, "w", NOW)
    await ingest(app_engine, [doc(2, "rule-a", "10.0.0.1", NOW - timedelta(hours=2))])
    async with app_engine.begin() as conn:
        assert await queue.complete(conn, job, NOW) is True
        assert await queue.claim(conn, "w", NOW + timedelta(minutes=29)) == []
        (again,) = await queue.claim(conn, "w", NOW + queue.COALESCE)
    assert again.version == job.version + 1


async def test_failures_back_off_then_give_up(app_engine: AsyncEngine) -> None:
    await one_job(app_engine)
    now = NOW
    statuses = []
    for _ in range(queue.MAX_FAILURES):
        async with app_engine.begin() as conn:
            (job,) = await queue.claim(conn, "w", now)
            statuses.append(await queue.fail(conn, job, now, "boom"))
        now += timedelta(hours=2)
    assert statuses == ["queued"] * (queue.MAX_FAILURES - 1) + ["failed"]


async def test_100_worker_kills_lose_and_duplicate_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The clock jumps a quarter lease per kill, faster than any heartbeat renews, so healthy
    # runs are taken over too; the limit on dying workers (MAX_LOST, D-055) has its own test.
    monkeypatch.setattr(queue, "MAX_LOST", 10_000)
    async with migrated_engine.begin() as conn:
        await conn.execute(text(
            "CREATE TABLE test_effects (investigation_id uuid, version int)"))  # fmt: skip
        await conn.execute(text("GRANT SELECT, INSERT ON test_effects TO argus_runtime"))
    for n in range(30):
        await ingest(app_engine, [doc(n, f"rule-{n}", "10.0.0.1", NOW - timedelta(hours=1))])
    clock = [NOW]
    rnd = random.Random(100)

    async def work(name: str) -> None:
        while True:
            async with app_engine.begin() as conn:
                claims = await queue.claim(conn, name, clock[0])
            if not claims:
                await asyncio.sleep(0.005)
                continue
            (job,) = claims
            await asyncio.sleep(rnd.uniform(0, 0.01))  # the work
            try:
                async with app_engine.begin() as conn:
                    await conn.execute(text("INSERT INTO test_effects VALUES (:i, :v)"),
                                       {"i": job.investigation_id, "v": job.version})  # fmt: skip
                    await asyncio.sleep(rnd.uniform(0, 0.005))
                    await queue.complete(conn, job, clock[0])
            except queue.LeaseLostError:
                continue  # too slow: the effect rolled back, the job is someone else's now

    kills = 0
    workers = [asyncio.create_task(work(f"w{n}")) for n in range(4)]
    while kills < 100:
        await asyncio.sleep(rnd.uniform(0.001, 0.01))
        victim = rnd.randrange(len(workers))
        workers[victim].cancel()
        kills += 1
        workers[victim] = asyncio.create_task(work(f"w{kills}-{victim}"))
        clock[0] += queue.LEASE / 4  # dead workers' leases expire as time goes by
    for _ in range(400):
        clock[0] += queue.LEASE / 4
        await asyncio.sleep(0.01)
        async with app_engine.connect() as conn:
            open_jobs = (await conn.execute(text(
                "SELECT count(*) FROM jobs WHERE status <> 'done'"))).scalar_one()  # fmt: skip
        if not open_jobs:
            break
    for worker in workers:
        worker.cancel()
    await asyncio.gather(*workers, return_exceptions=True)
    async with app_engine.connect() as conn:
        query = "SELECT investigation_id, version, count(*) FROM test_effects GROUP BY 1, 2"
        effects = (await conn.execute(text(query))).all()
        versions = dict((await conn.execute(text("SELECT id, version FROM investigations"))).all())
    assert open_jobs == 0
    assert {count for _, _, count in effects} == {1}  # never twice
    assert {(inv, v) for inv, v, _ in effects} == set(versions.items())  # never lost


# --------------------------------------------------------------------------- a real day


@pytest.mark.skipif(not CORPUS.is_file(), reason="no local corpus")
async def test_a_real_day_folds_at_least_twelve_times(app_engine: AsyncEngine) -> None:
    with gzip.open(CORPUS, "rt") as handle:
        hits = [json.loads(line) for line in handle]
    for hit in hits:
        hit["found"] = True
    for at in range(0, len(hits), 1000):
        await ingest(app_engine, hits[at : at + 1000])
    async with app_engine.connect() as conn:
        alerts, investigations = (await conn.execute(text(
            "SELECT (SELECT count(*) FROM investigation_alerts),"
            " (SELECT count(*) FROM investigations)"))).one()  # fmt: skip
    assert alerts == len(hits)
    print(f"real day: {alerts} alerts in {investigations} investigations")
    assert alerts / investigations >= 12, (alerts, investigations)
    uuid.UUID(str((await snapshot(app_engine))["inv"][0][0]))
