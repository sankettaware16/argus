"""A threat-intel source's key tested from the app (D-328): one lookup of a public address
(``TEST_ADDRESS``, never site data) through the source's own client, counted in the request
ledger (purpose ``check``) under the same limits as ARGUS's own lookups, so a test can never
push a free plan over its limit. Also the usage argus-admin publishes for the app's cost page."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import ConfigError, OutsideSettings, load_settings
from argus.outside import providers, store

TEST_ADDRESS = "8.8.8.8"
SOURCES = tuple(providers.PROVIDERS)
_LEDGER = {"found": "ok", "not_found": "not_found", "limited": "limited"}
_SAID = {
    "found": "the key works",
    "not_found": "the key works (the test address is not in its data)",
    "limited": "the key works but the source is over its limit right now",
    "refused": "the source refused the key: check it and save it again",
    "error": "the source answered with an error",
}


def outside_settings(root: Path) -> OutsideSettings:
    return load_settings(root / "config" / "argus.yaml", env_file=root / ".env").outside


async def check(engine: AsyncEngine, root: Path, source: str, now: datetime,
                transport: providers.Transport | None = None) -> dict[str, Any]:  # fmt: skip
    """Whether ``source``'s key works; raises ValueError when it cannot be tested."""
    if source not in providers.PROVIDERS:
        raise ValueError(f"a source of {', '.join(SOURCES)}")
    try:
        settings = outside_settings(root)
    except ConfigError as exc:
        raise ValueError(f"the settings do not load: {str(exc)[:200]}") from None
    key = settings.key_of(source)
    if key is None:
        raise ValueError(f"{source} has no key yet: add one first")
    target = f"outside:{source}"
    async with engine.begin() as conn:
        got = await store.reserve(conn, source, "ip", "check", store.limits_of(source, settings),
                                  now)  # fmt: skip
    if isinstance(got, store.Blocked):
        return {"target": target, "ok": False,
                "output": [f"{source} is at its limit ({got.reason}) until {got.until:%H:%M} UTC:"
                           " try again then"]}  # fmt: skip
    provider = providers.PROVIDERS[source]
    own = transport or providers.HttpxTransport()
    status: int | None = None
    size: int | None = None
    why: str | None = None
    try:
        reply = await own.get(provider.prepare("ip", TEST_ADDRESS, key),
                              settings.timeout.total_seconds())  # fmt: skip
        status, size = reply.status, len(reply.body)
        outcome = provider.parse("ip", reply, now).outcome
    except providers.TransportError as exc:
        outcome, why = "error", str(exc)
    finally:
        if transport is None:
            await own.aclose()  # type: ignore[attr-defined]
    async with engine.begin() as conn:
        await store.finish(conn, got, _LEDGER.get(outcome, "error"), status, size)
    said = _SAID.get(outcome, _SAID["error"])
    if why:
        said = f"no answer from {source} ({why})"
    elif status is not None and outcome not in ("found", "not_found"):
        said = f"{said} (HTTP {status})"
    return {"target": target, "ok": outcome in ("found", "not_found", "limited"),
            "output": [f"{source}: {said}"]}  # fmt: skip


async def usage(engine: AsyncEngine, root: Path, now: datetime) -> dict[str, Any]:
    """Each source's requests a day for the last 31 days, today's and this month's, its limits
    and whether it has a key: what the app's cost page shows (the ledger itself stays here)."""
    try:
        settings: OutsideSettings | None = outside_settings(root)
    except ConfigError:
        settings = None
    since = (now - timedelta(days=30)).replace(hour=0, minute=0, second=0, microsecond=0)
    async with engine.connect() as conn:
        rows = await conn.execute(
            text("SELECT source, date_trunc('day', at) AS day, purpose, count(*) AS n,"
                 " count(*) FILTER (WHERE outcome IN ('ok', 'not_found')) AS answered"
                 " FROM outside_requests WHERE at >= :since GROUP BY 1, 2, 3"),
            {"since": since},
        )  # fmt: skip
        found = list(rows)
    out = []
    for source in SOURCES:
        mine = [r for r in found if r.source == source]
        days: dict[str, int] = {}
        for r in mine:
            days[r.day.date().isoformat()] = days.get(r.day.date().isoformat(), 0) + r.n
        today = now.date().isoformat()
        month = sum(r.n for r in mine if (r.day.year, r.day.month) == (now.year, now.month))
        limits = [] if settings is None else [
            {"window": "minute" if lim.kind == "rolling" else lim.kind,
             "maximum": lim.maximum} for lim in store.limits_of(source, settings)
            if lim.kind != "rolling" or lim.seconds == 60]  # fmt: skip
        out.append({
            "source": source,
            "key_set": settings is not None and settings.key_of(source) is not None,
            "enabled": settings is not None and settings.enabled(source),
            "today": days.get(today, 0), "month": month,
            "answered_month": sum(r.answered for r in mine
                                  if (r.day.year, r.day.month) == (now.year, now.month)),
            "today_by_purpose": {p: sum(r.n for r in mine if r.purpose == p
                                        and r.day.date() == now.date())
                                 for p in {r.purpose for r in mine}},
            "days": [{"day": d, "requests": n} for d, n in sorted(days.items())],
            "limits": limits,
        })  # fmt: skip
    return {"at": now.isoformat(), "sources": out}
