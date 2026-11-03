"""The collector as a service (``argus collect run``): one process, one loop, every job on its
own schedule. A job that fails is logged and tried again at its next turn; a failed or
refused poll opens a coverage gap and, once polls work again, the gap is closed and the hours
it covered are reconciled."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from argus.collector import store
from argus.collector.collector import LIVE, Collector, PollResult
from argus.gateway.errors import BreakerOpenError, GatewayError, RefusedError

log = logging.getLogger("argus.collector")

PROBE_EVERY = timedelta(minutes=1)
POLL_EVERY = timedelta(minutes=1)
STATES_EVERY = timedelta(minutes=15)
RECONCILE_EVERY = timedelta(hours=1)
RECONCILE_SPAN = timedelta(hours=24)
BACKFILL_RETRY = timedelta(minutes=1)
TICK = 5.0  # seconds between looks at the schedule
GAP_KINDS = ("argus_collector_lag", "breaker_open")
SUBJECT = "alerts"


@dataclass
class Runner:
    collector: Collector
    probe: Callable[[], Awaitable[Any]]
    due: dict[str, datetime] = field(default_factory=dict)
    backfill_done: bool = False
    reconcile_from: datetime | None = None  # start-up, or the start of an outage
    # other components' jobs on the same schedule: (name, every, job)
    extra: list[tuple[str, timedelta, Callable[[], Awaitable[Any]]]] = field(default_factory=list)

    @property
    def engine(self) -> Any:
        return self.collector.engine

    def now(self) -> datetime:
        return self.collector.clock()

    async def guarded_poll(self) -> PollResult | None:
        """One poll; on failure a coverage gap from the cursor, on success the gaps closed."""
        now = self.now()
        try:
            result = await self.collector.poll()
        except Exception as exc:  # any failure, not only the gateway's: never a silent stall
            kind = "breaker_open" if isinstance(exc, BreakerOpenError) else "argus_collector_lag"
            reason = exc.reason if isinstance(exc, GatewayError) else type(exc).__name__
            async with self.engine.begin() as conn:
                start = await store.cursor(conn, LIVE) or now
                await store.open_gap(conn, kind, SUBJECT, start, reason)
            if self.reconcile_from is None or start < self.reconcile_from:
                self.reconcile_from = start
            log.warning("poll failed: %s", reason)
            return None
        async with self.engine.begin() as conn:
            closed = await store.close_gaps(conn, GAP_KINDS, SUBJECT, now)
        if closed:
            self.due["reconcile"] = now  # reconcile what the outage may have hidden
        return result

    async def reconcile(self) -> None:
        now = self.now()
        start = now - RECONCILE_SPAN
        if self.reconcile_from is not None:
            start = max(min(start, self.reconcile_from), now - self.collector.window)
        result = await self.collector.reconcile(start, now)
        self.reconcile_from = None
        log.info(
            "reconciled %d hours: %d differed, %d recovered, %d gone from the SIEM",
            result.hours, len(result.mismatched), result.recovered, result.missing_in_es,
        )  # fmt: skip

    async def step(self) -> None:
        """Run whatever is due now (each job guarded on its own)."""
        now = self.now()
        jobs: list[tuple[str, timedelta, Callable[[], Awaitable[Any]]]] = [
            ("probe", PROBE_EVERY, self.probe),
            ("poll", POLL_EVERY, self.guarded_poll),
            ("states", STATES_EVERY, self.collector.sync_states),
            *self.extra,
        ]
        if self.backfill_done:
            jobs.append(("reconcile", RECONCILE_EVERY, self.reconcile))
        for name, every, job in jobs:
            if now < self.due.get(name, now):
                continue
            self.due[name] = now + every
            try:
                await job()
            except RefusedError as exc:  # the health state or the budget said not now
                log.warning("collector job %s refused: %s: %s", name, exc.reason, exc)
            except Exception:
                log.exception("collector job %s failed", name)
        if not self.backfill_done and now >= self.due.get("backfill", now):
            try:
                self.backfill_done = await self.collector.backfill_step() is None
            except Exception:
                self.due["backfill"] = now + BACKFILL_RETRY
                log.exception("backfill step failed")
            if self.backfill_done:
                self.reconcile_from = now - self.collector.window
                self.due["reconcile"] = now

    async def run(self, stop: asyncio.Event, tick: float = TICK) -> None:
        while not stop.is_set():
            await self.step()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=tick)
