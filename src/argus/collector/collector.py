"""The collector: every alert the SIEM writes ends up in ``alert_records`` exactly once, and stays.

``poll`` reads ids from ``cursor - OVERLAP`` to now and fetches the ones not stored, one
transaction per page; ``check`` compares counts per (hour, rule) with the SIEM and ``sync_hour``
diffs the ids of any hour that differs (backfill and reconciliation both use it); ``sync_states``
reads the workflow status of alerts that are not ``open``. Every transaction that stores alerts
also groups them. Only the gateway talks to the SIEM; nothing half-done is committed.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine

from argus.collector import store
from argus.collector.templates import (
    STATUS_FIELD,
    AlertCounts,
    AlertStates,
    CountsParams,
    StatesParams,
)
from argus.gateway.builtin import AlertIds, AlertIdsParams, AlertsMget, MgetParams
from argus.gateway.gateway import Gateway, Result, utcnow
from argus.gateway.templates import Params, Purpose, Template
from argus.grouping.store import group

HOUR = timedelta(hours=1)
OVERLAP = timedelta(minutes=5)  # late writes and equal timestamps around the cursor
PAGE = 1000  # ids per page
MGET = 200  # documents per mget
CHUNK_HOURS = 6  # hours per counts request
DEADLINE = timedelta(seconds=30)
STATE_REFETCH = 2_000  # alerts re-read per state sweep whose triage changed (rest: next sweep)
LIVE, BACKFILL = "live", "backfill"

Checkpoint = Callable[[str], Awaitable[None]]


def floor_hour(moment: datetime) -> datetime:
    return moment.astimezone(UTC).replace(minute=0, second=0, microsecond=0)


def from_epoch_ms(value: Any) -> datetime:
    return datetime.fromtimestamp(int(value) / 1000, UTC)


def epoch_ms(moment: datetime) -> int:
    return int(moment.timestamp() * 1000)


def written(hits: Sequence[Mapping[str, Any]]) -> dict[str, datetime]:
    """Each listed alert's ``@timestamp`` as Elasticsearch sorted it."""
    return {hit["_id"]: from_epoch_ms(hit["sort"][0]) for hit in hits if hit.get("sort")}


def source_value(source: Mapping[str, Any], path: str) -> Any:
    """A field of ``_source`` given as one dotted key or as nested objects."""
    if path in source:
        return source[path]
    parts = path.split(".")
    for cut in range(len(parts) - 1, 0, -1):
        inner = source.get(".".join(parts[:cut]))
        if isinstance(inner, Mapping):
            return source_value(inner, ".".join(parts[cut:]))
    return None


@dataclass(frozen=True)
class PollResult:
    pages: int
    new: int
    cursor: datetime


@dataclass(frozen=True)
class CheckResult:
    hours: int
    mismatched: tuple[datetime, ...]
    recovered: int
    missing_in_es: int


class Collector:
    def __init__(
        self,
        gateway: Gateway,
        engine: AsyncEngine,
        *,
        window: timedelta,
        clock: Callable[[], datetime] = utcnow,
        checkpoint: Checkpoint | None = None,
        before_chunk: Callable[[], Awaitable[Any]] | None = None,
    ) -> None:
        self.gateway = gateway
        self.engine = engine
        self.window = window
        self.clock = clock
        self.checkpoint = checkpoint
        self.before_chunk = before_chunk  # e.g. a health probe, for long manual runs

    # ------------------------------------------------------------------ the SIEM reads

    async def _run(self, template: Template, params: Params, purpose: Purpose) -> Result:
        return await self.gateway.run(
            template,
            params,
            purpose=purpose,
            component="collector",
            deadline=self.clock() + DEADLINE,
        )

    async def _point(self, name: str) -> None:
        if self.checkpoint is not None:
            await self.checkpoint(name)

    async def _ids(
        self, start: datetime, end: datetime, purpose: Purpose
    ) -> AsyncIterator[list[dict[str, Any]]]:
        """Pages of id hits (``_id``, ``_index``, ``sort``) written in [start, end), oldest
        first."""
        after: tuple[str | int, ...] | None = None
        while True:
            if self.before_chunk is not None:  # a long catch-up must not outlive its probe
                await self.before_chunk()
            params = AlertIdsParams(start=start, end=end, size=PAGE, after=after)
            hits: list[dict[str, Any]] = (await self._run(AlertIds(), params, purpose)).body[
                "hits"
            ]["hits"]
            await self._point("ids")
            if hits:
                yield hits
            if len(hits) < PAGE:
                return
            after = tuple(hits[-1]["sort"])

    async def _fetch(
        self, hits: Sequence[Mapping[str, Any]], purpose: Purpose
    ) -> list[dict[str, Any]]:
        by_index: dict[str, list[str]] = defaultdict(list)
        for hit in hits:
            by_index[hit["_index"]].append(hit["_id"])
        docs: list[dict[str, Any]] = []
        for index, ids in sorted(by_index.items()):
            for at in range(0, len(ids), MGET):
                params = MgetParams(index=index, ids=tuple(ids[at : at + MGET]))
                docs += (await self._run(AlertsMget(), params, purpose)).body["docs"]
                await self._point("mget")
        return docs

    # ------------------------------------------------------------------ live poll

    async def poll(self) -> PollResult:
        now = self.clock()
        async with self.engine.connect() as conn:
            cursor = await store.cursor(conn, LIVE)
        # min(): a cursor ahead of the clock (the clock was stepped back) must not skip time
        start = min(cursor or now, now) - OVERLAP
        pages = new = 0
        async for hits in self._ids(start, now, Purpose.COLLECT):
            async with self.engine.connect() as conn:
                known = await store.known_ids(conn, [hit["_id"] for hit in hits])
            fresh = [hit for hit in hits if hit["_id"] not in known]
            docs = await self._fetch(fresh, Purpose.COLLECT) if fresh else []
            last = from_epoch_ms(hits[-1]["sort"][0])
            async with self.engine.begin() as conn:
                stored = await store.ingest(conn, docs, "live", now, written(hits))
                await group(conn, stored.alerts, now)
                if cursor is None or last > cursor:
                    cursor = last
                    await store.set_cursor(conn, LIVE, cursor)
                await self._point("commit")
            pages += 1
            new += stored.new
        async with self.engine.begin() as conn:  # everything visible up to now is stored
            if cursor is None or now > cursor:
                cursor = now
                await store.set_cursor(conn, LIVE, cursor)
        return PollResult(pages, new, cursor)

    # ------------------------------------------------------------------ hours

    async def sync_hour(
        self, hour: datetime, recovered_by: str, purpose: Purpose
    ) -> tuple[int, int]:
        """Make the store hold exactly the SIEM's alerts of one hour: (recovered, missing in ES)."""
        async with self.engine.connect() as conn:  # before the listing: never mark as gone
            held = await store.ids_between(conn, hour, hour + HOUR)  # what a writer adds later
        es: dict[str, dict[str, Any]] = {}
        async for hits in self._ids(hour, hour + HOUR, purpose):
            es.update((hit["_id"], hit) for hit in hits)
        missing = [es[alert_id] for alert_id in sorted(es.keys() - held)]
        recovered = 0
        for at in range(0, len(missing), PAGE):
            page = missing[at : at + PAGE]
            docs = await self._fetch(page, purpose)
            async with self.engine.begin() as conn:
                stored = await store.ingest(conn, docs, recovered_by, self.clock(), written(page))
                await group(conn, stored.alerts, self.clock())
                recovered += stored.new
                await self._point("commit")
        gone = held - es.keys()
        async with self.engine.begin() as conn:
            marked = await store.mark_missing(conn, gone, self.clock())
        return recovered, marked

    async def check(
        self, start: datetime, hours: int, recovered_by: str, purpose: Purpose
    ) -> CheckResult:
        """Compare counts per (hour, rule) for ``hours`` (≤ 6) whole hours from ``start``; sync
        every hour that differs."""
        if self.before_chunk is not None:
            await self.before_chunk()
        result = await self._run(AlertCounts(), CountsParams(start=start, hours=hours), purpose)
        es_rules, es_totals, overflow = AlertCounts.counts(result.body)
        async with self.engine.connect() as conn:
            db_rules, db_totals = await store.counts_between(conn, start, start + hours * HOUR)
        mismatched: list[datetime] = []
        for n in range(hours):
            hour = start + n * HOUR
            key = epoch_ms(hour)
            es_total = es_totals.get(key, 0)
            es_hour: dict[str | None, int] = {
                rule: count for (at, rule), count in es_rules.items() if at == key
            }
            unruled = es_total - sum(es_hour.values())
            if unruled:
                es_hour[None] = unruled
            db_hour = {rule: count for (at, rule), count in db_rules.items() if at == hour}
            if key in overflow or es_total != db_totals.get(hour, 0) or es_hour != db_hour:
                mismatched.append(hour)
        recovered = missing = 0
        for hour in mismatched:
            got, gone = await self.sync_hour(hour, recovered_by, purpose)
            recovered += got
            missing += gone
        return CheckResult(hours, tuple(mismatched), recovered, missing)

    async def reconcile(self, start: datetime, end: datetime) -> CheckResult:
        """Reconcile the whole hours in [start, end) and record the run."""
        started = self.clock()
        first, last = floor_hour(start), floor_hour(end)
        total = CheckResult(0, (), 0, 0)
        outcome = "ok"
        try:
            at = first
            while at < last:
                hours = min(CHUNK_HOURS, int((last - at) / HOUR))
                part = await self.check(at, hours, "reconciliation", Purpose.RECONCILE)
                total = CheckResult(
                    total.hours + part.hours,
                    total.mismatched + part.mismatched,
                    total.recovered + part.recovered,
                    total.missing_in_es + part.missing_in_es,
                )
                at += hours * HOUR
        except Exception as exc:
            outcome = getattr(exc, "reason", type(exc).__name__)
            raise
        finally:
            if last > first:
                async with self.engine.begin() as conn:
                    await store.record_run(
                        conn,
                        started_at=started,
                        finished_at=self.clock(),
                        window_start=first,
                        window_end=last,
                        hours=total.hours,
                        hours_mismatched=len(total.mismatched),
                        recovered=total.recovered,
                        missing_in_es=total.missing_in_es,
                        outcome=outcome,
                    )
        return total

    async def backfill_step(self) -> CheckResult | None:
        """One chunk of the backfill, newest first; None once ``history.window`` is covered."""
        now = self.clock()
        oldest = floor_hour(now - self.window)
        async with self.engine.connect() as conn:
            done_to = await store.cursor(conn, BACKFILL)
        top = done_to if done_to is not None else floor_hour(now) + HOUR
        if top <= oldest:
            return None
        start = max(oldest, top - CHUNK_HOURS * HOUR)
        result = await self.check(start, int((top - start) / HOUR), "backfill", Purpose.BACKFILL)
        async with self.engine.begin() as conn:
            await store.set_cursor(conn, BACKFILL, start)
        return result

    # ------------------------------------------------------------------ workflow status

    async def sync_states(self) -> int:
        """The non-default sweep, then a re-read of the alerts whose triage changed (up to
        STATE_REFETCH a sweep), so their raw document and state hash follow Kibana."""
        now = self.clock()
        start = now - self.window
        statuses: dict[str, str] = {}
        after: tuple[str | int, ...] | None = None
        while True:
            params = StatesParams(start=start, end=now, after=after)
            hits = (await self._run(AlertStates(), params, Purpose.RECONCILE)).body["hits"]["hits"]
            for hit in hits:
                status = source_value(hit.get("_source") or {}, STATUS_FIELD)
                if isinstance(status, str):
                    statuses[hit["_id"]] = status
            if len(hits) < PAGE:
                break
            after = tuple(hits[-1]["sort"])
        async with self.engine.begin() as conn:
            changed = await store.set_statuses(conn, statuses, start, now)
        if changed:
            async with self.engine.connect() as conn:
                where = await store.indices_of(conn, changed[:STATE_REFETCH])
            hits = [{"_id": alert_id, "_index": index} for alert_id, index in where.items()]
            docs = await self._fetch(hits, Purpose.RECONCILE)
            async with self.engine.begin() as conn:
                stored = await store.ingest(conn, docs, "reconciliation", self.clock())
                await group(conn, stored.alerts, self.clock())
        return len(changed)
