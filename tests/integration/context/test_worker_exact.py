"""The worker's less common paths, exactly (mutation testing): the long-running loop (pruning,
logs, a failing claim, a job that raises), a thread whose pack is gone, a finished thread,
retries that give up, outcomes that cannot be recorded, renewals and deletions that fail."""

from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import Any

import pytest
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.context import worker as worker_module
from argus.context.worker import RunResult, WorkerConfig, _short
from argus.jobs import queue
from tests.integration.context.conftest import NOW, seed
from tests.integration.context.kit import FakeGateway, Hooks, Killed, TwoWavePack
from tests.integration.context.test_runtime import make, rows

pytestmark = pytest.mark.integration


def test_defaults_and_short_errors() -> None:
    c = WorkerConfig()
    assert (c.concurrency, c.run_concurrency, c.attempt, c.lease, c.poll) == (
        4, 1, timedelta(minutes=4), queue.LEASE, timedelta(seconds=5))  # fmt: skip
    assert (c.defer_cap, c.recursion_limit, c.history) == (
        timedelta(hours=24), 25, timedelta(days=5))  # fmt: skip
    assert timedelta(hours=1) == worker_module.PRUNE_EVERY
    assert worker_module.log.name == "argus.worker"
    long = _short(ValueError("x" * 500))
    assert long.startswith("ValueError: xxx")
    assert len(long) == 400
    assert "secret" not in _short(ValueError("Authorization: ApiKey secret123"))


def logged(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == "argus.worker"]


async def run_loop(w: Any, seconds: float) -> None:
    stop = asyncio.Event()
    task = asyncio.create_task(w.run_forever(stop))
    await asyncio.sleep(seconds)
    stop.set()
    await asyncio.wait_for(task, 20)


async def test_the_loop_prunes_runs_and_logs(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver,
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
) -> None:  # fmt: skip
    await seed(app_engine, [(1, "r1", "10.0.0.1"), (2, "r1", "10.0.0.2")])
    pruned: list[Any] = []

    async def prune(engine: Any, now: Any) -> int:
        pruned.append(now)
        return 3

    monkeypatch.setattr(worker_module.checkpoints, "prune", prune)
    w = make(app_engine, saver, FakeGateway(), config=WorkerConfig(poll=timedelta(seconds=0.1)))
    caplog.set_level(logging.INFO, logger="argus.worker")
    await run_loop(w, 3)
    assert len(pruned) == 1  # at the start, then every hour of the clock (a fixed clock here)
    assert "pruned 3 checkpoint threads" in caplog.text
    done = [r for r in caplog.records if r.getMessage().startswith("job ")]
    assert len(done) == 2
    assert all(r.getMessage().endswith(" done evidence_ready") for r in done)
    got = await rows(app_engine, "SELECT status, count(*) FROM jobs GROUP BY 1")
    assert dict(got) == {"done": 2}


async def test_the_loop_survives_a_failing_claim_and_a_failing_job(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver,
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
) -> None:  # fmt: skip
    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    w = make(app_engine, saver, FakeGateway(), config=WorkerConfig(poll=timedelta(seconds=0.1)))
    calls = {"claim": 0}
    real_claim = w.claim

    async def flaky_claim(limit: int) -> list[queue.Claim]:
        calls["claim"] += 1
        if calls["claim"] == 1:
            raise RuntimeError("database hiccup")
        return await real_claim(limit)

    async def broken(job: queue.Claim) -> RunResult:
        raise ValueError("unexpected")

    monkeypatch.setattr(w, "claim", flaky_claim)
    monkeypatch.setattr(w, "run_job", broken)
    caplog.set_level(logging.INFO, logger="argus.worker")
    await run_loop(w, 1.5)
    assert "worker: RuntimeError: database hiccup" in logged(caplog)
    assert "worker: a job ended with ValueError: unexpected" in logged(caplog)
    assert calls["claim"] >= 2


async def test_a_full_worker_claims_nothing_more(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver, monkeypatch: pytest.MonkeyPatch
) -> None:
    await seed(app_engine, [(n, "r1", f"10.0.0.{n}") for n in range(1, 4)])
    w = make(app_engine, saver, FakeGateway(delay=lambda: 0.5),
             config=WorkerConfig(concurrency=1, poll=timedelta(seconds=0.05)))  # fmt: skip
    asked: list[int] = []
    real_claim = w.claim

    async def counting(limit: int) -> list[queue.Claim]:
        asked.append(limit)
        return await real_claim(limit)

    monkeypatch.setattr(w, "claim", counting)
    await run_loop(w, 1.0)
    assert asked
    assert set(asked) == {1}


async def test_a_thread_whose_pack_is_gone_starts_over(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    old = TwoWavePack()
    crash = Hooks(crash=("plan_wave", "after", 1))
    with pytest.raises(Killed):
        await make(app_engine, saver, FakeGateway(), pack=old, hooks=crash).run_once()
    async with app_engine.begin() as conn:  # the lease of the killed run expires
        await conn.execute(text("UPDATE jobs SET lease_until = :t"), {"t": NOW})

    class Newer(TwoWavePack):
        version = 2

    gateway = FakeGateway()
    (result,) = await make(app_engine, saver, gateway, pack=Newer(),
                           at=NOW + timedelta(minutes=1)).run_once()  # fmt: skip
    assert (result.outcome, result.detail) == ("done", "evidence_ready")
    (pack,) = [r.pack for r in await rows(app_engine, "SELECT pack FROM dossiers")]
    assert pack == Newer().ident


class _Snapshot:
    def __init__(self, values: dict[str, Any], next_: tuple[str, ...]) -> None:
        self.values, self.next = values, next_


async def test_a_finished_thread_completes_or_starts_over(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver, monkeypatch: pytest.MonkeyPatch
) -> None:
    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    w = make(app_engine, saver, FakeGateway())

    async def finished(config: Any) -> _Snapshot:
        return _Snapshot({"dossier": {}}, ())

    monkeypatch.setattr(w.graph, "aget_state", finished)
    (result,) = await w.run_once()
    assert (result.outcome, result.detail) == ("retry", "finished thread without a dossier")
    monkeypatch.undo()
    async with app_engine.begin() as conn:
        await conn.execute(text("UPDATE jobs SET run_after = :t, status = 'queued'"), {"t": NOW})
    real = make(app_engine, saver, FakeGateway())
    (ran,) = await real.run_once()
    assert ran.outcome == "done"
    async with app_engine.begin() as conn:  # claimed again although its dossier is stored
        await conn.execute(text("UPDATE jobs SET status = 'queued', finished_at = NULL"))
    again = make(app_engine, saver, FakeGateway())
    monkeypatch.setattr(again.graph, "aget_state", finished)
    (verified,) = await again.run_once()
    assert (verified.outcome, verified.detail) == ("done", "verified")


class Explodes(TwoWavePack):
    name = "test-explodes"

    def local_signals(self, facts: Any, context: Any) -> list[Any]:
        raise RuntimeError("pack trouble")


async def test_retries_give_up_after_the_last_failure(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver, caplog: pytest.LogCaptureFixture
) -> None:
    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    async with app_engine.begin() as conn:
        await conn.execute(text("UPDATE jobs SET failures = :n"), {"n": queue.MAX_FAILURES - 2})
    caplog.set_level(logging.WARNING, logger="argus.worker")
    w = make(app_engine, saver, FakeGateway(), pack=Explodes())
    (first,) = await w.run_once()
    assert (first.outcome, first.detail) == ("retry", "RuntimeError: pack trouble")
    assert "job 1: RuntimeError: pack trouble" in logged(caplog)
    async with app_engine.begin() as conn:
        await conn.execute(text("UPDATE jobs SET run_after = :t"), {"t": NOW})
    (last,) = await w.run_once()
    assert last.outcome == "failed"


async def test_an_outcome_that_cannot_be_recorded_leaves_the_lease_to_expire(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver,
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
) -> None:  # fmt: skip
    await seed(app_engine, [(1, "r1", "10.0.0.1")])

    async def broken(*args: Any) -> str:
        raise ValueError("cannot write")

    monkeypatch.setattr(worker_module.queue, "fail", broken)
    caplog.set_level(logging.ERROR, logger="argus.worker")
    (result,) = await make(app_engine, saver, FakeGateway(), pack=Explodes()).run_once()
    assert (result.outcome, result.detail) == ("lost", "retry not recorded; the lease will expire")
    assert "job 1: could not record retry: ValueError: cannot write" in logged(caplog)

    async def gone(*args: Any) -> str:
        raise queue.LeaseLostError("taken")

    monkeypatch.setattr(worker_module.queue, "fail", gone)
    async with app_engine.begin() as conn:
        await conn.execute(text("UPDATE jobs SET lease_until = :t"), {"t": NOW})
    (lost,) = await make(app_engine, saver, FakeGateway(), pack=Explodes(),
                         at=NOW + timedelta(minutes=1)).run_once()  # fmt: skip
    assert (lost.outcome, lost.detail) == ("lost", "RuntimeError: pack trouble")


async def test_renewal_and_deletion_failures_are_logged(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver,
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
) -> None:  # fmt: skip
    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    renewals = {"n": 0}
    real_renew = queue.renew

    async def flaky_renew(*args: Any, **kw: Any) -> None:
        renewals["n"] += 1
        if renewals["n"] == 1:
            raise RuntimeError("renew hiccup")
        await real_renew(*args, **kw)

    monkeypatch.setattr(worker_module.queue, "renew", flaky_renew)
    # renewals every 1.5 s: the first fails on purpose, the second (at 3 s) must land before
    # the lease ends (4.5 s), so a stall of 1.5 s under load is tolerated; the run takes > 3 s
    w = make(app_engine, saver, FakeGateway(delay=lambda: 0.6),
             config=WorkerConfig(lease=timedelta(seconds=4.5)))  # fmt: skip

    async def undeletable(thread: str) -> None:
        raise RuntimeError("delete hiccup")

    monkeypatch.setattr(w.checkpointer, "adelete_thread", undeletable)
    caplog.set_level(logging.WARNING, logger="argus.worker")
    (result,) = await w.run_once()
    assert result.outcome == "done"  # one failed renewal is not a lost lease
    assert "job 1: lease renewal failed: RuntimeError: renew hiccup" in logged(caplog)
    thread = next(m for m in logged(caplog) if m.startswith("checkpoint "))
    assert thread.startswith("checkpoint ctx:")
    assert thread.endswith(":v1 not deleted: RuntimeError: delete hiccup")
    assert renewals["n"] >= 2


class Wider(TwoWavePack):
    version = 2
    first = 8  # two tasks more than version 1


async def test_a_rederivation_asks_siem_for_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    """Found in mutation testing: `argus worker rederive` queued 'pack_changed' jobs, which
    ran as collections (D-055 §6 says a re-derivation never asks)."""
    from argus.context.cli import queue_rederive

    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    gateway = FakeGateway()
    (first,) = await make(app_engine, saver, gateway).run_once()
    assert first.outcome == "done"
    asked = list(gateway.calls)
    assert await queue_rederive(app_engine, Wider().ident) == 1
    (trigger,) = [r.trigger for r in await rows(
        app_engine, "SELECT trigger FROM jobs WHERE status = 'queued'")]  # fmt: skip
    assert trigger == "rederive"
    async with migrated_engine.begin() as conn:  # due on the test's clock
        await conn.execute(text("UPDATE jobs SET run_after = :t WHERE status = 'queued'"),
                           {"t": NOW})  # fmt: skip
    (again,) = await make(app_engine, saver, gateway, pack=Wider()).run_once()
    assert again.outcome == "done"
    assert gateway.calls == asked  # reused or recorded as not asked
    skipped = await rows(app_engine, "SELECT status, coverage FROM evidence WHERE version = 1"
                         " AND status = 'skipped_budget'")  # fmt: skip
    assert len(skipped) == 2
    assert all(r.coverage == {"reason": "rederive"} for r in skipped)
    (kind,) = [r.run_kind for r in await rows(
        app_engine, "SELECT run_kind FROM dossiers WHERE pack = :p", p=Wider().ident)]  # fmt: skip
    assert kind == "rederive"


async def test_a_rederivation_job_of_a_new_version_collects(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE jobs SET trigger = 'rederive'"))
    gateway = FakeGateway()
    (result,) = await make(app_engine, saver, gateway).run_once()
    assert result.outcome == "done"
    assert gateway.calls  # no dossier at this version yet: a collection
    (kind,) = [r.run_kind for r in await rows(app_engine, "SELECT run_kind FROM dossiers")]
    assert kind == "collect"


async def test_a_stolen_lease_cancels_a_run_waiting_on_siem(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    import time

    await seed(app_engine, [(1, "r1", "10.0.0.1")])

    async def steal(node: str, when: str) -> None:
        if (node, when) == ("collect_evidence", "before"):
            async with app_engine.begin() as conn:
                await conn.execute(text("UPDATE jobs SET claims = claims + 1"))

    w = make(app_engine, saver, FakeGateway(delay=lambda: 30), hooks=Hooks(on=steal),
             config=WorkerConfig(lease=timedelta(seconds=0.9)))  # fmt: skip
    started = time.monotonic()
    (result,) = await asyncio.wait_for(w.run_once(), 20)
    assert (result.outcome, result.detail) == ("lost", "lease lost while running")
    assert time.monotonic() - started < 10  # cancelled, not waited out
    stored = await rows(app_engine, "SELECT count(*) AS n FROM evidence")
    assert stored[0].n == 0


async def test_siem_unavailable_defers_with_the_next_try(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    from argus.gateway.errors import DeferredError

    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    gateway = FakeGateway(fail={n: DeferredError("degraded") for n in range(6)})
    (result,) = await make(app_engine, saver, gateway).run_once()
    assert result.outcome == "deferred"
    assert result.detail is not None
    assert result.detail.startswith("deferred; next try ")
    assert result.detail.endswith(" UTC")


class Nowhere(TwoWavePack):
    name = "test-nowhere"


async def test_a_pack_that_never_resolves_is_retried_and_a_defect_is_logged(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver,
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
) -> None:  # fmt: skip
    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    w = make(app_engine, saver, FakeGateway(), pack=Nowhere())
    monkeypatch.setattr(w.packs, "get", lambda ident: None)  # resolves, then is never found
    (stale,) = await w.run_once()
    assert stale.outcome == "retry"
    assert stale.detail is not None
    assert stale.detail.startswith("StaleThread: pack test-nowhere@1 is not available")


class TooMany(TwoWavePack):
    name = "test-too-many"
    first = 33


async def test_a_defect_is_dead_lettered_and_logged(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver, caplog: pytest.LogCaptureFixture
) -> None:
    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    caplog.set_level(logging.ERROR, logger="argus.worker")
    (result,) = await make(app_engine, saver, FakeGateway(), pack=TooMany()).run_once()
    assert result.outcome == "dead"
    (defect,) = [m for m in logged(caplog) if "defect" in m]
    assert defect.startswith("job 1: defect: PackBug: test-too-many@1 planned too many tasks")


async def test_a_job_again_for_an_investigated_version_is_a_collection(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    """Only a ``rederive`` job re-derives: any other job of a version that has its dossier
    runs as a collection again (the same dossier, so no conflict)."""
    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    gateway = FakeGateway()
    (first,) = await make(app_engine, saver, gateway).run_once()
    assert first.outcome == "done"
    async with migrated_engine.begin() as conn:
        again_due = text("UPDATE jobs SET status = 'queued', run_after = :t, finished_at = NULL")
        await conn.execute(again_due, {"t": NOW})
    (again,) = await make(app_engine, saver, gateway).run_once()
    assert (again.outcome, again.detail) == ("done", "evidence_ready")
