"""The freshness lane's reader (Q-F1, plan §5 WS-F): one size-1 search per log source every
5 minutes (every 15 in DEGRADED; none in STOP or 00:00-01:30 UTC), each stored as a reading,
each source's watermark advanced.

It runs inside the collector's process as one of its jobs (``argus collect run``), only when
``freshness.mode`` is ``shadow`` or ``on``. Every request goes through ``Gateway.run`` with
``Purpose.FRESHNESS``: the ``freshness`` and global kill switches, the breaker, the SIEM's
health, the quiet hours and the freshness lane's own budget all apply there (Q-D2); this
module only keeps the schedule and stores what came back. A request the gateway refused or
that failed is stored too, with its reason, and leaves a gap in the readings.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Coroutine, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine

from argus import site
from argus.config.errors import ConfigError
from argus.freshness import store
from argus.freshness.model import EMPTY, FAILED, OK, REFUSED, Reading, lags
from argus.freshness.shadow import Policy
from argus.freshness.store import Stored
from argus.freshness.template import Watermark, WatermarkParams, newest
from argus.gateway.errors import GatewayError, RefusedError
from argus.gateway.gateway import Gateway, in_quiet_hours
from argus.gateway.health import HealthState, effective
from argus.gateway.templates import Purpose

log = logging.getLogger("argus.freshness")

DEADLINE = timedelta(seconds=20)  # one reading, budget waits included
EVERY = timedelta(seconds=30)  # how often the collector's loop asks what is due
COMPONENT = "freshness"


def utcnow() -> datetime:
    return datetime.now(UTC)


def policy_of(settings: Any) -> Policy:
    """``freshness.*`` as a Policy; ConfigError for a margin of a source that is not one of
    the site's watched families (a typo would otherwise leave that source without one)."""
    f = settings.freshness
    unknown = sorted(set(f.margins) - set(site.active().watched_sources))
    if unknown:
        raise ConfigError("freshness.margins names what is not a log source: " + ", ".join(unknown))
    return Policy(mode=f.mode, margins=dict(f.margins), gap=f.gap, bridge=f.bridge)


FUTURE_SLACK = timedelta(minutes=5)  # an ingest time this far ahead of the answer is a skewed clock


class Reader:
    def __init__(
        self,
        gateway: Gateway,
        engine: AsyncEngine,
        sources: Sequence[str],
        *,
        interval: timedelta = timedelta(minutes=5),
        degraded_interval: timedelta = timedelta(minutes=15),
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not sources:
            raise ValueError("the reader needs at least one log source")
        if interval <= timedelta(0) or degraded_interval < interval:
            raise ValueError("the intervals are positive, DEGRADED's at least the normal one")
        self.gateway = gateway
        self.engine = engine
        self.sources = tuple(sources)
        self.interval = interval
        self.degraded_interval = degraded_interval
        self.clock = clock or gateway.clock
        self.last: dict[str, datetime] = {}  # each source's last attempt in this process

    def due(self, state: HealthState, now: datetime) -> list[str]:
        """The sources to read now: none in STOP or the quiet hours, every ``interval`` in
        NORMAL and CAUTION, every ``degraded_interval`` in DEGRADED."""
        if state is HealthState.STOP or in_quiet_hours(now):
            return []
        every = self.degraded_interval if state is HealthState.DEGRADED else self.interval
        due = [s for s in self.sources if s not in self.last or now - self.last[s] >= every]
        # the longest overdue first; ``step`` reads one a call, so the four sources spread
        # over the lane's minutes instead of spending its whole 100 ms at once (review F2)
        return sorted(due, key=lambda s: self.last.get(s, datetime.min.replace(tzinfo=UTC)))

    async def step(self) -> list[Stored]:
        """One reading at most: the most overdue source that is due (F2)."""
        now = self.clock()
        memory = effective(await self.gateway.state.health(), now, self.gateway.health_config)
        out = []
        for source in self.due(memory.state, now)[:1]:  # one reading a step (F2)
            self.last[source] = now
            stored = await self.read(source, memory.state.value)
            async with self.engine.begin() as conn:
                await store.record(conn, stored)
            out.append(stored)
        return out

    async def read(self, source: str, health: str | None = None) -> Stored:
        sent = self.clock()
        try:
            result = await self.gateway.run(
                Watermark(),
                WatermarkParams(source=source, now=sent),
                purpose=Purpose.FRESHNESS,
                component=COMPONENT,
                deadline=sent + DEADLINE,
            )
        except RefusedError as exc:
            return Stored(
                Reading(source, max(self.clock(), sent), REFUSED), sent, exc.reason, health
            )
        except GatewayError as exc:
            return Stored(
                Reading(source, max(self.clock(), sent), FAILED), sent, exc.reason, health
            )
        at = max(self.clock(), sent)
        try:
            doc = newest(result.body)
        except ValueError:
            return Stored(Reading(source, at, FAILED), sent, "malformed_answer", health)
        if doc is None:
            return Stored(Reading(source, at, EMPTY), sent, None, health, result.took_ms)
        ingested, event_at = doc
        if ingested > at + FUTURE_SLACK:  # a skewed clock, never a watermark (review F9)
            return Stored(Reading(source, at, FAILED), sent, "future_ingested", health)
        reading = Reading(source, at, OK, ingested, event_at)
        return Stored(reading, sent, None, health, result.took_ms)


async def current_lags(engine: AsyncEngine, now: datetime) -> dict[str, timedelta]:
    """Each source's lag now, from its newest reading with a document (the probe's input
    for the health trip wire, DQ19, once ``freshness.mode`` is on)."""
    async with engine.connect() as conn:
        return lags(await store.latest(conn), await store.latest_ok(conn), now)


def jobs(
    settings: Any, engine: AsyncEngine, gateway: Gateway
) -> list[tuple[str, timedelta, Callable[[], Awaitable[Any]]]]:
    """The collector's extra job for the readings; none while ``freshness.mode`` is off."""
    f = settings.freshness
    if f.mode == "off":
        return []
    policy_of(settings)  # refuses a margin for an unknown source before anything is read
    reader = Reader(
        gateway,
        engine,
        site.active().watched_sources,
        interval=f.interval,
        degraded_interval=f.degraded_interval,
    )
    return [("freshness", EVERY, Detached(reader.step))]


class Detached:
    """The reader's step as the collector's job: started as a task of its own, so a slow or
    hanging reading never holds up the collector's loop (its poll every minute); a step still
    running when the job comes round again is not started twice."""

    def __init__(self, step: Callable[[], Coroutine[Any, Any, Any]]) -> None:
        self.step = step
        self.task: asyncio.Task[Any] | None = None

    async def __call__(self) -> None:
        task = self.task
        if task is not None and not task.done():
            return
        if task is not None and not task.cancelled() and task.exception() is not None:
            exc = task.exception()
            log.warning("freshness readings failed: %s", type(exc).__name__)
        self.task = asyncio.create_task(self.step())
