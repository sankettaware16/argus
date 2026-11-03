"""R8 runtime: state size, pruning, deferral and its 24 h cap, task outcomes, dead letters,
lost leases, reuse across versions, the per-run budget, and 100 worker kills."""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Mapping, Sequence
from datetime import timedelta
from typing import Any, ClassVar

import pytest
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.context import checkpoints
from argus.context.graph import STATE_LIMIT
from argus.context.packs import MAX_TASKS_PER_RUN, TaskSpec
from argus.context.worker import Worker, WorkerConfig
from argus.gateway.errors import (
    BreakerOpenError,
    BudgetExhaustedError,
    DeadlinePassedError,
    PartialResultError,
    SiemError,
    SourceMissingError,
    StoppedError,
    TemplateRejectedError,
    TimedOutError,
    UnsupportedValueError,
)
from argus.gateway.templates import CostClass
from argus.jobs import queue
from tests.integration.context.conftest import NOW, seed
from tests.integration.context.kit import (
    CountParams,
    CountTemplate,
    FakeGateway,
    Hooks,
    TwoWavePack,
    dossiers,
    registry,
    scalar,
)
from tests.integration.grouping.test_grouping import doc, ingest

pytestmark = pytest.mark.integration


def make(
    engine: AsyncEngine,
    saver: AsyncPostgresSaver,
    gateway: FakeGateway | None = None,
    *,
    pack: Any = None,
    at: Any = NOW,
    **kw: Any,
) -> Worker:
    clock = at if callable(at) else (lambda: at)
    return Worker(engine, saver, packs=registry(pack), gateway=gateway, clock=clock, **kw)


async def rows(engine: AsyncEngine, query: str, **params: Any) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(query), params)).all())


# ----------------------------------------------------------------------------- state size


class WidePack(TwoWavePack):
    """As many tasks as a run may have, over three waves."""

    name = "test-wide"
    max_waves = 3
    budget: ClassVar[Mapping[CostClass, int]] = {CostClass.LIGHT: MAX_TASKS_PER_RUN}

    def plan(self, wave: int, facts: Any, context: Any, evidence: Any) -> Sequence[TaskSpec]:
        inv = str(facts["investigation_id"])
        per_wave = {1: 32, 2: 24, 3: 8}[wave]
        return [
            TaskSpec(CountTemplate(), CountParams(investigation=inv, n=wave * 1000 + n))
            for n in range(per_wave)
        ]


async def test_state_stays_under_64_kb_per_super_step(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    """A worst case: 400 alerts with long, distinct entity values, related investigations,
    and the most tasks a run may have. Every checkpoint is measured as stored."""
    long = ".".join(c * 60 for c in "abc")
    docs = []
    for n in range(400):
        d = doc(n, "wide", "10.0.0.9", NOW - timedelta(hours=1))
        d["_source"]["url"] = {"domain": f"n{n}.{long}.example"}
        d["_source"]["destination"] = {"ip": f"10.1.{n // 250}.{n % 250}"}
        docs.append(d)
    docs += [doc(1000 + n, f"other-{n}", "10.0.0.9", NOW - timedelta(hours=1)) for n in range(30)]
    await ingest(app_engine, docs)
    sizes: list[int] = []
    target = await scalar(
        app_engine, "SELECT investigation_id FROM jobs j JOIN investigations i"
        " ON i.id = j.investigation_id WHERE i.rule_id = 'wide'"
    )  # fmt: skip

    async def measure(node: str, when: str) -> None:
        if node == "persist_dossier" and when == "before":
            thread = f"ctx:{target}:v1"
            sizes.extend(await checkpoints.thread_bytes(app_engine, thread))

    async with app_engine.begin() as conn:
        await conn.execute(text("UPDATE jobs SET run_after = run_after + interval '1 day'"
                                " WHERE investigation_id <> :t"), {"t": target})  # fmt: skip
    gateway = FakeGateway()
    worker = make(app_engine, saver, gateway, pack=WidePack(), hooks=Hooks(on=measure))
    results = await worker.run_once(limit=1)
    assert [r.outcome for r in results] == ["done"]
    assert len(gateway.calls) == MAX_TASKS_PER_RUN
    assert len(sizes) > 10
    assert max(sizes) <= STATE_LIMIT, sizes
    print(f"checkpoints: {len(sizes)}, largest {max(sizes)} bytes")
    facts = await scalar(app_engine, "SELECT body -> 'facts' FROM dossiers")
    assert facts["alert_count"] == 400
    assert len(facts["entities"]["domain"]) == len(facts["entities"]["ip"]) == 20
    assert facts["entity_counts"]["domain"] == 400


# ----------------------------------------------------------------------------- pruning


async def test_threads_are_deleted_after_persist_and_others_pruned_after_48h(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    (_inv,) = await seed(app_engine, [(1, "r1", "10.0.0.1")])
    gateway = FakeGateway(fail={2: BreakerOpenError(None)})
    (result,) = await make(app_engine, saver, gateway).run_once()
    assert result.outcome == "deferred"
    assert (await checkpoints.usage(app_engine))["threads"] == 1  # kept: it resumes from here
    async with app_engine.connect() as conn:
        newest = (await conn.execute(text(
            "SELECT max((checkpoint ->> 'ts')::timestamptz) FROM langgraph.checkpoints"
        ))).scalar_one()  # fmt: skip
    assert await checkpoints.prune(app_engine, newest + timedelta(hours=47)) == 0
    assert await checkpoints.prune(app_engine, newest + timedelta(hours=48, seconds=1)) == 1
    for table in checkpoints.TABLES:
        assert await scalar(app_engine, f"SELECT count(*) FROM langgraph.{table}") == 0  # noqa: S608
    gateway.fail.clear()
    later = NOW + timedelta(minutes=2)
    (result,) = await make(app_engine, saver, gateway, at=later).run_once()
    assert result.outcome == "done"  # a pruned thread starts over; the evidence was kept
    assert (await checkpoints.usage(app_engine))["threads"] == 0


# ----------------------------------------------------------------------------- deferral


async def test_unavailable_siem_defers_with_backoff_then_resumes(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    (_inv,) = await seed(app_engine, [(1, "r1", "10.0.0.1")])
    gateway = FakeGateway(fail={3: StoppedError("kill switch")})
    now = NOW
    waits = []
    for _ in range(6):
        (result,) = await make(app_engine, saver, gateway, at=now).run_once()
        assert result.outcome == "deferred"
        after = await scalar(app_engine, "SELECT run_after FROM jobs")
        waits.append(after - now)
        now = after
    assert waits == [timedelta(minutes=m) for m in (1, 2, 4, 8, 10, 10)]
    job = (await rows(app_engine, "SELECT failures, deferrals, deferred_since, error FROM jobs"))[0]
    assert (job.failures, job.deferrals, job.deferred_since) == (0, 6, NOW)
    assert job.error == "deferred: stopped"
    gateway.fail.clear()
    (result,) = await make(app_engine, saver, gateway, at=now).run_once()
    assert result.outcome == "done"
    # resumed from the checkpoint: only the refused task was asked more than once
    assert len(set(gateway.calls)) == 8
    assert all(gateway.calls.count(n) == 1 for n in set(gateway.calls) - {3})
    assert gateway.calls.count(3) == 7
    (d,) = await dossiers(app_engine)
    assert d.status == "evidence_ready"


async def test_after_24h_deferred_the_dossier_is_partial_without_calls(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    gateway = FakeGateway(fail={n: BreakerOpenError(None) for n in range(200)})
    (result,) = await make(app_engine, saver, gateway).run_once()
    assert result.outcome == "deferred"
    assert len(gateway.calls) == 1
    later = NOW + timedelta(hours=24, minutes=1)
    (result,) = await make(app_engine, saver, gateway, at=later).run_once()
    assert result.outcome == "done"
    assert len(gateway.calls) == 1
    (d,) = await dossiers(app_engine)
    assert (d.status, d.partial_reason) == ("evidence_failed", "context_partial")
    statuses = await rows(app_engine, "SELECT DISTINCT status, coverage FROM evidence")
    assert statuses == [("deferred", {"reason": "context_partial"})]
    remote = (await rows(app_engine, "SELECT status, unknown_reason FROM signals"
                                     " WHERE name = 'remote_total'"))[0]  # fmt: skip
    assert tuple(remote) == ("unknown", "deferred")


async def test_postgres_unavailable_defers(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver, monkeypatch: pytest.MonkeyPatch
) -> None:
    import psycopg

    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    worker = make(app_engine, saver, FakeGateway())

    async def down(*args: Any, **kwargs: Any) -> Any:
        raise psycopg.OperationalError("connection refused")

    monkeypatch.setattr(worker.graph, "aget_state", down)
    (result,) = await worker.run_once()
    assert (result.outcome, result.detail.split(";")[0]) == ("deferred", "postgres")


# ----------------------------------------------------------------------------- outcomes


@pytest.mark.parametrize(
    ("error", "status", "coverage"),
    [
        (TimedOutError(), "timeout", {"timed_out": True}),
        (DeadlinePassedError("late"), "timeout", {"timed_out": True}),
        (PartialResultError("shards"), "failed", {"partial": True}),
        (SiemError(500, "x"), "failed", {}),
        (SourceMissingError("source_expired", ("2026.10.01",)), "source_expired",
         {"missing_indices": ["2026.10.01"]}),
        (SourceMissingError("source_not_ready", ("2026.10.09",)), "source_lag",
         {"missing_indices": ["2026.10.09"]}),
        (BudgetExhaustedError("day"), "skipped_budget", {}),
        (UnsupportedValueError("long"), "unsupported_value", {}),
    ],
)  # fmt: skip
async def test_task_outcomes_become_evidence_statuses(
    app_engine: AsyncEngine,
    saver: AsyncPostgresSaver,
    error: Exception,
    status: str,
    coverage: dict[str, Any],
) -> None:
    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    gateway = FakeGateway(fail={0: error})  # type: ignore[dict-item]
    (result,) = await make(app_engine, saver, gateway).run_once()
    assert (result.outcome, result.detail) == ("done", "evidence_partial")
    got = await rows(app_engine, "SELECT status, coverage, result_hash, error FROM evidence"
                                 " WHERE params ->> 'n' = '0'")  # fmt: skip
    assert [(g.status, g.coverage, g.result_hash) for g in got] == [(status, coverage, None)]
    (d,) = await dossiers(app_engine)
    assert d.partial_reason == status
    remote = await rows(app_engine, "SELECT status, unknown_reason FROM signals"
                                    " WHERE name = 'remote_total'")  # fmt: skip
    assert [tuple(r) for r in remote] == [("unknown", status)]


async def test_all_remote_evidence_failing_is_evidence_failed(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    gateway = FakeGateway(fail={n: SiemError(500, None) for n in range(6)})
    (result,) = await make(app_engine, saver, gateway).run_once()
    assert (result.outcome, result.detail) == ("done", "evidence_failed")
    assert len(gateway.calls) == 6  # no wave 2: nothing odd was seen


async def test_a_retry_replaces_a_failed_row_but_never_an_ok_one(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    gateway = FakeGateway(fail={0: TimedOutError()})
    await make(app_engine, saver, gateway).run_once()
    await ingest(app_engine, [doc(2, "r1", "10.0.0.1", NOW - timedelta(minutes=30))])
    gateway.fail.clear()
    later = NOW + timedelta(hours=1)
    (result,) = await make(app_engine, saver, gateway, at=later).run_once()
    assert (result.outcome, result.detail) == ("done", "evidence_ready")
    assert gateway.calls.count(0) == 2  # the failed one was asked again
    v2 = await rows(app_engine, "SELECT params ->> 'n' AS n, status, reused_from_version"
                                " FROM evidence WHERE version = 2 ORDER BY 1")  # fmt: skip
    reused = {r.n for r in v2 if r.reused_from_version == 1}
    assert "0" not in reused
    assert len(reused) == len(v2) - 1
    assert len(gateway.calls) == 8 + 1


# ----------------------------------------------------------------------------- defects


async def test_a_rejected_template_is_a_dead_letter(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    gateway = FakeGateway(fail={1: TemplateRejectedError("field_not_allowed", "x")})
    (result,) = await make(app_engine, saver, gateway).run_once()
    assert result.outcome == "dead"
    job = (await rows(app_engine, "SELECT status, error FROM jobs"))[0]
    assert job.status == "failed"
    assert job.error.startswith("bug: PackBug: template rejected")


async def test_a_recursion_error_is_a_dead_letter(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    config = WorkerConfig(recursion_limit=5)
    (result,) = await make(app_engine, saver, FakeGateway(), config=config).run_once()
    assert result.outcome == "dead"
    assert "GraphRecursionError" in (result.detail or "")


async def test_the_full_graph_fits_the_recursion_limit_of_25(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    hooks = Hooks()
    (result,) = await make(
        app_engine, saver, FakeGateway(), pack=WidePack(), hooks=hooks
    ).run_once()
    assert result.outcome == "done"
    steps = len({(n, i) for n, w, i in hooks.events if w == "before" and n != "collect_evidence"})
    assert steps + 3 <= 25  # + one super-step per wave of evidence


async def test_a_different_dossier_for_the_same_version_is_refused(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    (inv,) = await seed(app_engine, [(1, "r1", "10.0.0.1")])
    (result,) = await make(app_engine, saver, FakeGateway()).run_once()
    assert result.outcome == "done"
    async with migrated_engine.begin() as conn:  # as if a run of v1 happened again
        await conn.execute(text("INSERT INTO jobs (investigation_id, trigger, run_after)"
                                " VALUES (:i, 'created', :t)"), {"i": inv, "t": NOW})  # fmt: skip
        await conn.execute(text("UPDATE investigations SET alert_count = 99"))
    (result,) = await make(app_engine, saver, FakeGateway()).run_once()
    assert result.outcome == "dead"
    assert "DossierConflict" in (result.detail or "")
    assert len(await dossiers(app_engine)) == 1


# ----------------------------------------------------------------------------- leases


async def test_a_lost_lease_rolls_the_dossier_back(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    await seed(app_engine, [(1, "r1", "10.0.0.1")])

    async def steal(node: str, when: str) -> None:
        if (node, when) == ("persist_dossier", "before"):
            async with app_engine.begin() as conn:
                await queue.claim(conn, "thief", NOW + queue.LEASE + timedelta(seconds=1))

    (result,) = await make(app_engine, saver, FakeGateway(), hooks=Hooks(on=steal)).run_once()
    assert result.outcome == "lost"
    assert await dossiers(app_engine) == []
    assert await scalar(app_engine, "SELECT count(*) FROM signals") == 0


async def test_the_heartbeat_keeps_a_long_run_alive_and_cancels_a_lost_one(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    start = time.monotonic()
    # 1.5 s leases, renewed every 0.5 s: under load (the mutation runs) a stall of up to a
    # second is tolerated; the run itself (8 calls x 0.25 s) is longer than one lease
    config = WorkerConfig(lease=timedelta(seconds=1.5))
    gateway = FakeGateway(delay=lambda: 0.25)

    def tick() -> Any:  # real time: the lease runs out unless it is renewed
        return NOW + timedelta(seconds=time.monotonic() - start)

    (result,) = await make(app_engine, saver, gateway, at=tick, config=config).run_once()
    assert result.outcome == "done"  # 8 calls x 0.25 s > the 1.5 s lease: renewed meanwhile

    await ingest(app_engine, [doc(2, "r1", "10.0.0.1", NOW - timedelta(minutes=30))])
    async with app_engine.begin() as conn:
        await conn.execute(text("UPDATE jobs SET run_after = :t WHERE status = 'queued'"),
                           {"t": tick()})  # fmt: skip
    gateway = FakeGateway(delay=lambda: 2.5)  # each evidence call outlives the lease

    async def stolen(node: str, when: str) -> None:
        if (node, when) == ("collect_evidence", "before"):
            async with app_engine.begin() as conn:
                await conn.execute(text("UPDATE jobs SET claims = claims + 1"
                                        " WHERE status = 'running'"))  # fmt: skip

    worker = make(app_engine, saver, gateway, at=tick, config=config, hooks=Hooks(on=stolen))
    (result,) = await asyncio.wait_for(worker.run_once(), timeout=30)
    assert result.outcome == "lost"


# ----------------------------------------------------------------------------- budget


class Thrifty(TwoWavePack):
    name = "test-thrifty"
    budget: ClassVar[Mapping[CostClass, int]] = {CostClass.LIGHT: 4}


async def test_the_per_run_budget_skips_the_rest_without_calls(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    gateway = FakeGateway()
    (result,) = await make(app_engine, saver, gateway, pack=Thrifty()).run_once()
    assert (result.outcome, result.detail) == ("done", "evidence_partial")
    assert len(gateway.calls) == 4
    got = await rows(app_engine, "SELECT status, count(*) FROM evidence GROUP BY 1 ORDER BY 1")
    assert dict(got)["skipped_budget"] >= 2  # wave 1's last two, and any wave 2 task


# ----------------------------------------------------------------------------- kills


async def test_100_worker_kills_lose_and_duplicate_no_dossier(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The clock jumps a quarter lease per kill, faster than any heartbeat renews, so healthy
    # runs are taken over too; the limit on dying workers (MAX_LOST) has its own test.
    monkeypatch.setattr(queue, "MAX_LOST", 10_000)
    specs = [(n, f"rule-{n % 5}", f"10.0.0.{n // 5}") for n in range(40)]
    invs = await seed(app_engine, specs)
    assert len(invs) == 40
    clock = [NOW]
    rnd = random.Random(8)
    gateway = FakeGateway(delay=lambda: rnd.uniform(0, 0.003))

    async def work(name: str) -> None:
        w = make(app_engine, saver, gateway, at=lambda: clock[0], owner=name,
                 config=WorkerConfig(run_concurrency=3))  # fmt: skip
        while True:
            if not await w.run_once(limit=1):
                await asyncio.sleep(0.005)

    workers = [asyncio.create_task(work(f"w{n}")) for n in range(4)]
    for kill in range(100):
        await asyncio.sleep(rnd.uniform(0.002, 0.03))
        victim = rnd.randrange(len(workers))
        workers[victim].cancel()
        await asyncio.gather(workers[victim], return_exceptions=True)
        workers[victim] = asyncio.create_task(work(f"w{kill}-{victim}"))
        clock[0] += queue.LEASE / 4
    for _ in range(600):
        if not await scalar(app_engine, "SELECT count(*) FROM jobs WHERE status <> 'done'"):
            break
        clock[0] += queue.LEASE / 4
        await asyncio.sleep(0.02)
    for w in workers:
        w.cancel()
    await asyncio.gather(*workers, return_exceptions=True)
    assert await scalar(app_engine, "SELECT count(*) FROM jobs WHERE status <> 'done'") == 0
    got = await dossiers(app_engine)
    assert sorted(d.investigation_id for d in got) == sorted(invs)  # one each, none lost
    ok = await scalar(app_engine, "SELECT count(*) FROM evidence WHERE status IN ('ok', 'empty')")
    assert ok == 40 * 8
    # each repeated call was in flight when its worker died: at most 3 per kill
    assert len(gateway.calls) - ok <= 100 * 3
    assert await scalar(app_engine, "SELECT count(*) FROM evidence WHERE status NOT IN"
                                    " ('ok', 'empty')") == 0  # fmt: skip
