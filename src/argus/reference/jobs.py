"""Reference-data jobs on the collector's schedule: the rules registry every 15
minutes (local SQL), threat intel every 6 hours when ``reference.ti_sync`` is on."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine

from argus import site
from argus.gateway.gateway import Gateway, Result
from argus.gateway.templates import Params, Purpose, Template
from argus.reference import store

log = logging.getLogger("argus.reference")

RULES_EVERY = timedelta(minutes=15)
TI_EVERY = timedelta(hours=6)
DEADLINE = timedelta(seconds=60)


def runner_for(gateway: Gateway) -> store.Run:
    async def run(template: Template, params: Params) -> Result:
        deadline = datetime.now(UTC) + DEADLINE
        return await gateway.run(
            template, params, purpose=Purpose.ENRICH, component="reference", deadline=deadline
        )

    return run


async def refresh_rules(engine: AsyncEngine) -> dict[str, int]:
    """Catch up in short transactions of at most ``store.BATCH`` alerts each."""
    total = {"rules": 0, "new_revisions": 0, "new_truncated": 0, "pending": 1}
    while total["pending"]:
        async with engine.begin() as conn:
            got = await store.refresh_rules(conn, datetime.now(UTC))
        total = {**got, **{k: total[k] + got[k] for k in ("new_revisions", "new_truncated")}}
    if total["new_revisions"] or total["new_truncated"]:
        log.info("rules: %s", total)
    return total


async def sync_ti(engine: AsyncEngine, gateway: Gateway) -> dict[str, Any]:
    """Mirror each mirror source and read how fresh each lookup source is, each in its own
    transaction; the first that cannot be read stops the run (the next run starts again). No
    source configured: threat intel is off, and the answer says so."""
    run = runner_for(gateway)
    now = datetime.now(UTC)
    profile = site.active()
    if not profile.ti_sources:
        log.info("threat intel: no source is configured (site.ti_sources); nothing to sync")
        return {"sources": 0, "mirror": {}, "newest": {}}
    mirrors: dict[str, Any] = {}
    newest: dict[str, Any] = {}
    for source in profile.ti_mirrors:
        async with engine.begin() as conn:
            mirrors[source.index] = await store.sync_mirror(conn, run, now, source)
    for source in profile.ti_lookups:
        async with engine.begin() as conn:
            newest[source.index] = await store.sync_newest(conn, run, now, source)
    log.info("threat intel: mirrors %s; newest of the looked-up sources %s", mirrors, newest)
    return {"sources": len(profile.ti_sources), "mirror": mirrors, "newest": newest}


async def soak_sample(engine: AsyncEngine) -> None:
    from argus import soak

    async with engine.begin() as conn:
        await soak.sample(conn, datetime.now(UTC))


def jobs(
    engine: AsyncEngine, gateway: Gateway, *, ti_sync: bool
) -> list[tuple[str, timedelta, Callable[[], Awaitable[Any]]]]:
    found: list[tuple[str, timedelta, Callable[[], Awaitable[Any]]]] = [
        ("rules", RULES_EVERY, lambda: refresh_rules(engine)),
        ("soak", timedelta(hours=1), lambda: soak_sample(engine)),  # local SQL only
    ]
    if ti_sync:
        found.append(("ti", TI_EVERY, lambda: sync_ti(engine, gateway)))
    return found
