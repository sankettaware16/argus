"""The worker (plan §8 driver, D-054): claims jobs from the queue (R6) and runs each one as a
context-graph thread ``ctx:{investigation}:v{version}``.

* no checkpoint: start the graph with the job's input; a checkpoint with pending nodes:
  resume it (``ainvoke(None)``); a finished thread: check its dossier and complete the job.
* the lease is renewed while the run goes on; if it is lost the run is cancelled (its effects
  roll back: completion is fenced).
* the SIEM or Postgres unavailable: the job is deferred (no failure counted); a defect (a refused
  template, too large a state, a recursion error, a non-deterministic dossier): dead letter;
  anything else: retried with backoff by the queue, then given up.
* a persisted thread is deleted; others are pruned after 48 h.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import socket
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
import psycopg_pool
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.errors import GraphRecursionError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.context import checkpoints
from argus.context.evidence import PackBug, SourceUnavailable
from argus.context.graph import (
    Ctx,
    EvidenceGateway,
    Gate,
    NodeHooks,
    StaleThread,
    StateTooLarge,
    build,
    initial_state,
    thread_id,
)
from argus.context.packs import PackRegistry, default_registry
from argus.context.store import DossierConflict, MissingInvestigation
from argus.db.errors import is_connection_failure
from argus.freshness.shadow import Policy
from argus.jobs import queue
from argus.observability.redaction import redact_text

log = logging.getLogger("argus.worker")

DEFECTS = (PackBug, StateTooLarge, DossierConflict, GraphRecursionError, MissingInvestigation)
PRUNE_EVERY = timedelta(hours=1)


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class WorkerConfig:
    concurrency: int = 4  # jobs at once in this process
    run_concurrency: int = 1  # evidence tasks at once within a run (its share of the gateway)
    attempt: timedelta = timedelta(minutes=4)  # time budget of one attempt (its deadline)
    lease: timedelta = queue.LEASE
    poll: timedelta = timedelta(seconds=5)
    defer_cap: timedelta = timedelta(hours=24)
    recursion_limit: int = 25
    history: timedelta = timedelta(days=5)
    freshness: Policy | None = None  # verified zeros (Q-F1): None or "off" reads nothing


@dataclass(frozen=True)
class RunResult:
    job_id: int
    outcome: str  # done | requeued | skipped | deferred | retry | failed | dead | lost
    detail: str | None = None


PURGED = (
    "skipped: the retention purge removed this investigation's raw alerts or evidence, so its"
    " stored dossier stays as it is"
)


def _postgres_down(exc: BaseException) -> bool:
    if isinstance(exc, psycopg.OperationalError | psycopg_pool.PoolTimeout):
        return True
    return is_connection_failure(exc)


def _short(exc: BaseException) -> str:
    return redact_text(f"{type(exc).__name__}: {exc}")[:400]


class Worker:
    def __init__(
        self,
        engine: AsyncEngine,
        checkpointer: BaseCheckpointSaver[Any],
        *,
        packs: PackRegistry | None = None,
        gateway: EvidenceGateway | None = None,
        config: WorkerConfig | None = None,
        clock: Callable[[], datetime] = utcnow,
        owner: str | None = None,
        hooks: NodeHooks | None = None,
    ) -> None:
        self.engine = engine
        self.checkpointer = checkpointer
        self.packs = packs or default_registry()
        self.gateway = gateway
        self.config = config or WorkerConfig()
        self.clock = clock
        self.owner = owner or f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        self.hooks = hooks
        self.graph = build(checkpointer)

    # ------------------------------------------------------------------ loops

    async def claim(self, limit: int) -> list[queue.Claim]:
        async with self.engine.begin() as conn:
            return await queue.claim(conn, self.owner, self.clock(), limit, self.config.lease)

    async def run_once(self, limit: int | None = None) -> list[RunResult]:
        """Claim up to ``limit`` due jobs (default: the concurrency) and run them."""
        claims = await self.claim(limit or self.config.concurrency)
        return list(await asyncio.gather(*(self.run_job(c) for c in claims)))

    async def run_forever(self, stop: asyncio.Event) -> None:
        """Keep up to ``concurrency`` jobs running until ``stop`` is set; then let the running
        ones finish (or their leases expire if the process is killed)."""
        running: set[asyncio.Task[RunResult]] = set()
        pruned = self.clock() - PRUNE_EVERY
        while not stop.is_set():
            try:
                if self.clock() - pruned >= PRUNE_EVERY:
                    removed = await checkpoints.prune(self.engine, self.clock())
                    pruned = self.clock()
                    if removed:
                        log.info("pruned %d checkpoint threads", removed)
                free = self.config.concurrency - len(running)
                claims = await self.claim(free) if free > 0 else []
            except Exception as exc:
                log.warning("worker: %s", _short(exc))
                claims = []
            for job in claims:
                running.add(asyncio.create_task(self.run_job(job)))
            waiters: set[asyncio.Future[Any]] = {asyncio.ensure_future(stop.wait()), *running}
            done, _ = await asyncio.wait(
                waiters,
                timeout=self.config.poll.total_seconds() if not claims else 0.05,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in done:
                if task in running:
                    running.discard(task)
                    try:
                        result = task.result()
                    except Exception as exc:  # never the loop's end
                        log.error("worker: a job ended with %s", _short(exc))
                        continue
                    log.info("job %d: %s %s", result.job_id, result.outcome, result.detail or "")
            for waiter in waiters - set(running):
                if not waiter.done():
                    waiter.cancel()
        if running:
            await asyncio.gather(*running, return_exceptions=True)

    # ------------------------------------------------------------------ one job

    async def run_job(self, job: queue.Claim) -> RunResult:
        now = self.clock()
        thread = thread_id(job)
        ctx = Ctx(
            engine=self.engine,
            gateway=self.gateway,
            packs=self.packs,
            claim=job,
            deadline=now + self.config.attempt,
            clock=self.clock,
            history=self.config.history,
            no_remote=job.deferred_since is not None
            and now - job.deferred_since >= self.config.defer_cap,
            hooks=self.hooks,
            gate=Gate(self.config.run_concurrency),
            freshness=self.config.freshness,
        )
        lost = asyncio.Event()
        task = asyncio.current_task()
        assert task is not None
        beat = asyncio.create_task(self._heartbeat(job, task, lost))
        try:
            try:
                return await self._drive(job, thread, ctx)
            except StaleThread:  # a new pack version: start the thread over, at no cost
                await self._delete(thread)
                return await self._drive(job, thread, ctx)
        except asyncio.CancelledError:
            if lost.is_set():
                return RunResult(job.job_id, "lost", "lease lost while running")
            raise
        except queue.LeaseLostError:
            return RunResult(job.job_id, "lost", "lease lost")
        except SourceUnavailable as exc:
            return await self._settle(job, "deferred", exc.reason)
        except StaleThread as exc:
            await self._delete(thread)
            return await self._settle(job, "retry", _short(exc))
        except DEFECTS as exc:
            log.error("job %d: defect: %s", job.job_id, _short(exc))
            return await self._settle(job, "dead", _short(exc))
        except Exception as exc:
            if _postgres_down(exc):
                return await self._settle(job, "deferred", "postgres")
            log.warning("job %d: %s", job.job_id, _short(exc))
            return await self._settle(job, "retry", _short(exc))
        finally:
            beat.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await beat

    async def _drive(self, job: queue.Claim, thread: str, ctx: Ctx) -> RunResult:
        if await self._purged(job):
            return await self._skip(job, thread, PURGED)
        config: Any = {
            "configurable": {"thread_id": thread},
            "recursion_limit": self.config.recursion_limit,
        }
        snapshot = await self.graph.aget_state(config)
        if not snapshot.values:
            run_input: Any = initial_state(job, await self._run_kind(job))
        elif snapshot.next:
            run_input = None  # resume where the last attempt stopped
        else:
            return await self._finished(job, thread)
        result = await self.graph.ainvoke(run_input, config, context=ctx, durability="sync")
        dossier = result["dossier"]
        await self._delete(thread)
        return RunResult(
            job.job_id, "requeued" if dossier["requeued"] else "done", dossier["status"]
        )

    async def _purged(self, job: queue.Claim) -> bool:
        """Whether the retention purge (Q-A4) removed raw alerts or evidence snapshots of this
        investigation: a dossier derived now would read ``{}`` and empty snapshots as if the
        logs had shown nothing."""
        async with self.engine.connect() as conn:
            found = (
                await conn.execute(
                    text(
                        "SELECT EXISTS (SELECT 1 FROM investigation_alerts l JOIN alert_records a"
                        " ON a.alert_id = l.alert_id WHERE l.investigation_id = :i"
                        " AND a.raw_purged_at IS NOT NULL) OR EXISTS (SELECT 1 FROM evidence e"
                        " WHERE e.investigation_id = :i AND e.snapshot_purged_at IS NOT NULL)"
                    ),
                    {"i": job.investigation_id},
                )
            ).scalar_one()
        return bool(found)

    async def _skip(self, job: queue.Claim, thread: str, reason: str) -> RunResult:
        async with self.engine.begin() as conn:
            await queue.skip(conn, job, self.clock(), reason)
        await self._delete(thread)
        return RunResult(job.job_id, "skipped", reason)

    async def _run_kind(self, job: queue.Claim) -> str:
        """``rederive`` (no SIEM request, D-055) only for a re-derivation of a version that
        was investigated already: new alerts that joined a queued re-derivation job made a new
        version, which is collected like any other."""
        if job.trigger != "rederive":
            return "collect"
        async with self.engine.connect() as conn:
            seen = (
                await conn.execute(
                    text(
                        "SELECT 1 FROM dossiers WHERE investigation_id = :i AND version = :v"
                        " LIMIT 1"
                    ),
                    {"i": job.investigation_id, "v": job.version},
                )
            ).first()
        return "rederive" if seen is not None else "collect"

    async def _finished(self, job: queue.Claim, thread: str) -> RunResult:
        """The thread ran to the end, so its dossier was persisted with the job's completion;
        the job is claimed again only if that did not happen. Complete it if the dossier is
        there, else start the thread over."""
        async with self.engine.begin() as conn:
            stored = (
                await conn.execute(
                    text("SELECT 1 FROM dossiers WHERE investigation_id = :i AND version = :v"),
                    {"i": job.investigation_id, "v": job.version},
                )
            ).first()
            if stored is not None:
                again = await queue.complete(conn, job, self.clock())
        await self._delete(thread)
        if stored is None:
            return await self._settle(job, "retry", "finished thread without a dossier")
        return RunResult(job.job_id, "requeued" if again else "done", "verified")

    async def _settle(self, job: queue.Claim, outcome: str, detail: str) -> RunResult:
        try:
            async with self.engine.begin() as conn:
                now = self.clock()
                if outcome == "deferred":
                    after = await queue.defer(conn, job, now, detail)
                    detail = f"{detail}; next try {after:%H:%M} UTC"
                elif outcome == "dead":
                    await queue.dead_letter(conn, job, now, detail)
                else:
                    status = await queue.fail(conn, job, now, detail)
                    outcome = "failed" if status == "failed" else "retry"
        except queue.LeaseLostError:
            return RunResult(job.job_id, "lost", detail)
        except Exception as exc:  # the lease expires and the job is taken over
            if not _postgres_down(exc):
                log.error("job %d: could not record %s: %s", job.job_id, outcome, _short(exc))
            return RunResult(job.job_id, "lost", f"{outcome} not recorded; the lease will expire")
        return RunResult(job.job_id, outcome, detail)

    async def _heartbeat(
        self, job: queue.Claim, run: asyncio.Task[Any], lost: asyncio.Event
    ) -> None:
        every = self.config.lease.total_seconds() / 3
        while True:
            await asyncio.sleep(every)
            try:
                async with self.engine.begin() as conn:
                    await queue.renew(conn, job, self.clock(), self.config.lease)
            except queue.LeaseLostError:
                lost.set()
                run.cancel()
                return
            except Exception as exc:
                log.warning("job %d: lease renewal failed: %s", job.job_id, _short(exc))

    async def _delete(self, thread: str) -> None:
        try:
            await self.checkpointer.adelete_thread(thread)
        except Exception as exc:  # pruned later
            log.warning("checkpoint %s not deleted: %s", thread, _short(exc))
