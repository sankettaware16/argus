"""The database side of the outside lookups: the cache (``outside_lookups``: the parsed answer for
one source, kind and indicator, and when it was fetched), the ledger (``outside_requests``: a row
per request, written *before* it is sent so a crash can only over-count) and the limits, counted
from the ledger under an advisory lock per source; a 429 writes ``stopped_until``. The ledger
never holds a key or an indicator."""

# ruff: noqa: S608 - every statement is built from this module's constants; values are bound
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.config.settings import OutsideSettings
from argus.outside import facts
from argus.outside.read import View

PURPOSES = ("agent", "prefetch", "families")
# The ledger holds the time a request was reserved, not the time it was sent, and the two can
# differ by a transaction or a scheduling delay. A rate a source allows (one request a second) is
# therefore kept with a margin: two requests are at least this far apart in the ledger.
SPACING = 1.25
ALL_SOURCES = facts.SOURCES


@dataclass(frozen=True)
class Limit:
    """At most ``maximum`` requests in a window: the last ``seconds`` (rolling), or the UTC day
    or month so far (what the free plans count)."""

    kind: Literal["rolling", "day", "month"]
    maximum: int
    seconds: float = 0

    def since(self, now: datetime) -> datetime:
        if self.kind == "rolling":
            return now - timedelta(seconds=self.seconds)
        if self.kind == "day":
            return now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
        return now.astimezone(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    def resets(self, oldest: datetime | None, now: datetime) -> datetime:
        """When the window has room again: the oldest request in it leaves (rolling), or the
        next UTC midnight or first of the month."""
        if self.kind == "rolling":
            return (oldest or now) + timedelta(seconds=self.seconds)
        start = self.since(now)
        if self.kind == "day":
            return start + timedelta(days=1)
        return (start + timedelta(days=32)).replace(day=1)


def limits_of(source: str, settings: OutsideSettings) -> tuple[Limit, ...]:
    """The limits of ``source``, each below the free plan's (``config.settings.OutsideSettings``).
    Shodan and Censys also keep one request a second at most, with a margin (:data:`SPACING`;
    Censys's free tier runs one at a time)."""
    if source == facts.VIRUSTOTAL:
        return (
            Limit("rolling", settings.virustotal_per_minute, 60),
            Limit("day", settings.virustotal_per_day),
        )
    if source == facts.SHODAN:
        return (
            Limit("rolling", 1, SPACING),
            Limit("rolling", settings.shodan_per_minute, 60),
            Limit("day", settings.shodan_per_day),
        )
    return (
        Limit("rolling", 1, SPACING),
        Limit("day", settings.censys_per_day),
        Limit("month", settings.censys_per_month),
    )


def _lock_key(source: str) -> int:
    """A stable advisory-lock number for ``source`` (a signed 64-bit integer)."""
    digest = hashlib.sha256(f"argus.outside:{source}".encode()).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


@dataclass(frozen=True)
class Cached:
    status: str
    answer: Mapping[str, Any]
    fetched_at: datetime


async def cached(
    conn: AsyncConnection, source: str, kind: str, indicator: str, now: datetime, view: View
) -> Cached | None:
    """The answer for an indicator that is still kept (a detection and a server's description
    for the view's window, every other answer for its shorter clean window)."""
    row = (
        await conn.execute(
            text(
                "SELECT status, answer, fetched_at FROM outside_lookups WHERE source = :s"
                " AND kind = :k AND indicator = :i AND fetched_at >= :since"
            ),
            {"s": source, "k": kind, "i": indicator, "since": now - view.window},
        )
    ).first()
    if row is None or row.fetched_at < now - view.kept_for(source, row.status, row.answer):
        return None
    return Cached(row.status, row.answer, row.fetched_at)


async def put(
    conn: AsyncConnection, source: str, kind: str, indicator: str, status: str,
    answer: Mapping[str, Any], size: int, now: datetime,
) -> None:  # fmt: skip
    await conn.execute(
        text(
            "INSERT INTO outside_lookups (source, kind, indicator, status, answer, answer_bytes,"
            " fetched_at) VALUES (:s, :k, :i, :st, CAST(:a AS jsonb), :n, :now)"
            " ON CONFLICT (source, kind, indicator) DO UPDATE SET status = EXCLUDED.status,"
            " answer = EXCLUDED.answer, answer_bytes = EXCLUDED.answer_bytes,"
            " fetched_at = EXCLUDED.fetched_at"
        ),
        {"s": source, "k": kind, "i": indicator, "st": status, "n": size, "now": now,
         "a": json.dumps(dict(answer), separators=(",", ":"))},
    )  # fmt: skip


async def prune(conn: AsyncConnection, before: datetime) -> int:
    """Delete answers fetched before ``before`` (long past their cache window)."""
    done = await conn.execute(text("DELETE FROM outside_lookups WHERE fetched_at < :b"),
                              {"b": before})  # fmt: skip
    return done.rowcount


@dataclass(frozen=True)
class Blocked:
    reason: str  # "stopped" | "limit" | "budget"
    until: datetime


async def reserve(
    conn: AsyncConnection, source: str, kind: str, purpose: str, limits: Sequence[Limit],
    now: datetime, *, purpose_day_cap: int | None = None,
) -> int | Blocked:  # fmt: skip
    """Take one request from ``source``'s allowance, or say why not. Under the source's advisory
    lock: a stop from a 429 still in force, then each limit, then (for the prefetch) its own cap
    for today. On success the ledger row exists (outcome ``reserved``) and its id is returned.
    Call it in a transaction that commits before the request is sent."""
    await conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _lock_key(source)})
    stop = (
        await conn.execute(
            text(
                "SELECT max(stopped_until) FROM outside_requests WHERE source = :s"
                " AND stopped_until > :now"
            ),
            {"s": source, "now": now},
        )
    ).scalar_one()
    if stop is not None:
        return Blocked("stopped", stop)
    for limit in limits:
        # a rolling window is the last N seconds, so a request exactly N seconds old has left it
        edge = ">" if limit.kind == "rolling" else ">="
        used, oldest = (
            await conn.execute(
                text(
                    "SELECT count(*), min(at) FROM outside_requests WHERE source = :s"
                    f" AND at {edge} :since"
                ),
                {"s": source, "since": limit.since(now)},
            )
        ).one()
        if used >= limit.maximum:
            return Blocked("limit", limit.resets(oldest, now))
    if purpose_day_cap is not None:
        day = Limit("day", purpose_day_cap)
        spent = (
            await conn.execute(
                text(
                    "SELECT count(*) FROM outside_requests WHERE source = :s AND purpose = :p"
                    " AND at >= :since"
                ),
                {"s": source, "p": purpose, "since": day.since(now)},
            )
        ).scalar_one()
        if spent >= purpose_day_cap:
            return Blocked("budget", day.resets(None, now))
    request_id: int = (
        await conn.execute(
            text(
                "INSERT INTO outside_requests (at, source, kind, purpose, outcome)"
                " VALUES (:now, :s, :k, :p, 'reserved') RETURNING id"
            ),
            {"now": now, "s": source, "k": kind, "p": purpose},
        )
    ).scalar_one()
    return request_id


async def finish(
    conn: AsyncConnection, request_id: int, outcome: str, status: int | None, size: int | None,
    stopped_until: datetime | None = None,
) -> None:  # fmt: skip
    await conn.execute(
        text(
            "UPDATE outside_requests SET outcome = :o, http_status = :h, answer_bytes = :n,"
            " stopped_until = :u WHERE id = :i"
        ),
        {"o": outcome, "h": status, "n": size, "u": stopped_until, "i": request_id},
    )


async def used_since(conn: AsyncConnection, source: str, since: datetime) -> int:
    """Requests of ``source``, whatever their purpose, since ``since``."""
    spent: int = (
        await conn.execute(
            text("SELECT count(*) FROM outside_requests WHERE source = :s AND at >= :since"),
            {"s": source, "since": since},
        )
    ).scalar_one()
    return spent


async def used_today(conn: AsyncConnection, source: str, purpose: str, now: datetime) -> int:
    """Requests ``purpose`` has made of ``source`` since 00:00 UTC."""
    spent: int = (
        await conn.execute(
            text(
                "SELECT count(*) FROM outside_requests WHERE source = :s AND purpose = :p"
                " AND at >= :since"
            ),
            {"s": source, "p": purpose, "since": Limit("day", 0).since(now)},
        )
    ).scalar_one()
    return spent
