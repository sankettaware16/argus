"""LangGraph's checkpoints: the official Postgres saver in schema
``langgraph`` (tables from the migrations, never ``setup()``), on its own small psycopg pool
logged in as the runtime role, with a strict serializer: no pickle, no JSON constructors,
msgpack only for safe built-in types. The graph state holds plain JSON-like values only.

A thread is deleted after its dossier is persisted; failed, deferred and superseded threads
are pruned once their last checkpoint is older than ``KEEP``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any

from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import DatabaseSettings

SCHEMA = "langgraph"
KEEP = timedelta(hours=48)
TABLES = ("checkpoints", "checkpoint_blobs", "checkpoint_writes")
_THREADS = f"SELECT count(DISTINCT thread_id) FROM {SCHEMA}.checkpoints"  # noqa: S608 - constant fragments; values are bound
_SIZE = "SELECT " + " + ".join(f"pg_total_relation_size('{SCHEMA}.{t}')" for t in TABLES)
_THREAD_BYTES = (
    "SELECT c.checkpoint_id, octet_length(c.checkpoint::text)"  # noqa: S608 - constant fragments; values are bound
    " + octet_length(c.metadata::text)"
    " + coalesce((SELECT sum(octet_length(b.blob)) FROM"
    f"  {SCHEMA}.checkpoint_blobs b WHERE b.thread_id = c.thread_id"
    "   AND b.checkpoint_ns = c.checkpoint_ns"
    "   AND (c.checkpoint -> 'channel_versions') ->> b.channel = b.version), 0)"
    " + coalesce((SELECT sum(octet_length(w.blob)) FROM"
    f"  {SCHEMA}.checkpoint_writes w WHERE w.thread_id = c.thread_id"
    "   AND w.checkpoint_id = c.checkpoint_id), 0)"
    f" FROM {SCHEMA}.checkpoints c WHERE c.thread_id = :t ORDER BY c.checkpoint_id"
)
_STALE = (
    f"SELECT thread_id FROM {SCHEMA}.checkpoints GROUP BY thread_id"  # noqa: S608 - constant fragments; values are bound
    " HAVING max((checkpoint ->> 'ts')::timestamptz) < :before"
)
_DELETE = {t: f"DELETE FROM {SCHEMA}.{t} WHERE thread_id = ANY(:t)" for t in TABLES}  # noqa: S608 - constant fragments; values are bound


def serializer() -> JsonPlusSerializer:
    return JsonPlusSerializer(
        pickle_fallback=False, allowed_json_modules=None, allowed_msgpack_modules=None
    )


def state_bytes(values: dict[str, Any]) -> int:
    """The size of a state as the saver stores it (one blob per channel)."""
    serde = serializer()
    return sum(len(serde.dumps_typed(value)[1]) for value in values.values())


@asynccontextmanager
async def open_saver(
    settings: DatabaseSettings, *, database: str | None = None, max_size: int = 4
) -> AsyncIterator[AsyncPostgresSaver]:
    url = settings.url(database=database)  # the runtime role
    statement_ms = int(settings.statement_timeout.total_seconds() * 1000)
    pool = AsyncConnectionPool(
        conninfo="",
        kwargs={
            "host": url.host,
            "port": url.port,
            "dbname": url.database,
            "user": url.username,
            "password": url.password,
            "connect_timeout": int(settings.connect_timeout.total_seconds()),
            "application_name": "argus-checkpoints",
            "options": f"-c search_path={SCHEMA},pg_temp -c TimeZone=UTC"
            f" -c statement_timeout={statement_ms} -c idle_in_transaction_session_timeout=60000",
            "autocommit": True,
            "prepare_threshold": 0,
            "row_factory": dict_row,
        },
        min_size=1,
        max_size=max_size,
        open=False,
    )
    await pool.open(wait=True, timeout=float(settings.connect_timeout.total_seconds()) + 5)
    try:
        yield AsyncPostgresSaver(pool, serde=serializer())  # type: ignore[arg-type]
    finally:
        await pool.close()


async def usage(engine: AsyncEngine) -> dict[str, int]:
    """Threads and bytes held in the checkpoint tables (for ``/api/health`` and status)."""
    async with engine.connect() as conn:
        threads = (await conn.execute(text(_THREADS))).scalar_one()
        size = (await conn.execute(text(_SIZE))).scalar_one()
    return {"threads": int(threads), "bytes": int(size)}


async def thread_bytes(engine: AsyncEngine, thread_id: str) -> list[int]:
    """Per checkpoint of a thread: the bytes it stores (checkpoint, its blobs and writes)."""
    async with engine.connect() as conn:
        rows = await conn.execute(text(_THREAD_BYTES), {"t": thread_id})
        return [int(size) for _, size in rows]


async def prune(engine: AsyncEngine, now: datetime, keep: timedelta = KEEP) -> int:
    """Delete threads whose newest checkpoint is older than ``keep``. Returns how many."""
    async with engine.begin() as conn:
        stale = await conn.execute(text(_STALE), {"before": now - keep})
        threads = list(stale.scalars())
        for table in TABLES:
            await conn.execute(text(_DELETE[table]), {"t": threads})
    return len(threads)
