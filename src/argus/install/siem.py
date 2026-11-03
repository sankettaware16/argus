"""The reads ``argus init`` makes of the SIEM and Kibana, through the existing gateways (the
ledger, the budget, the health states): the key's identity and privileges, discovery, the
self-test, and Kibana's reader self-test. Read-only; nothing is written to the SIEM (D-297).
Init takes these as an object, so its tests give fakes."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from argus.config.settings import Settings

DEADLINE = timedelta(seconds=40)


class SiemReads(Protocol):
    def check_key(self, settings: Settings, names: list[str]) -> list[str]:
        """What is wrong with the SIEM key (empty: nothing): it authenticates as an API key,
        holds ``monitor`` and ``read`` on ``names``, and none of the write canaries."""

    def discover(self, settings: Settings) -> Any:
        """``argus discover``'s proposal (``argus.discover.propose.Proposal``)."""

    def selftest(self, settings: Settings) -> list[str]:
        """``argus siem selftest``'s problems for the site the settings name."""

    def kibana_check(self, settings: Settings) -> list[str] | None:
        """``argus kibana selftest --key reader``'s problems."""


class GatewayReads:
    """The real reads, each in its own event loop (init is synchronous). ``sender``: another
    transport than the SIEM's own (the tests)."""

    def __init__(self, sender: Any = None) -> None:
        self.sender = sender

    def check_key(self, settings: Settings, names: list[str]) -> list[str]:
        return asyncio.run(_check_key(settings, names, self.sender))

    def discover(self, settings: Settings) -> Any:
        from argus.discover.cli import _discover
        from argus.discover.run import MAX_MAPPINGS

        return asyncio.run(_discover(settings, MAX_MAPPINGS, not settings.kibana.enabled))

    def selftest(self, settings: Settings) -> list[str]:
        return asyncio.run(_selftest(settings, self.sender))

    def kibana_check(self, settings: Settings) -> list[str] | None:
        return asyncio.run(_kibana_check(settings))


async def _close(transport: Any) -> None:
    close = getattr(transport, "aclose", None)
    if close is not None:
        await close()


async def _check_key(settings: Settings, names: list[str], sender: Any = None) -> list[str]:
    from argus.db.engine import create_engine
    from argus.gateway.builtin import Authenticate, HasPrivileges, PrivilegeParams
    from argus.gateway.service import build_discovery_gateway, probe
    from argus.gateway.templates import NoParams, Purpose

    engine = create_engine(settings.database)
    try:
        gateway, store = build_discovery_gateway(settings.siem, engine, sender=sender)
        try:
            now = datetime.now(UTC)
            store.adopt(await probe(gateway, store, settings.siem, now, component="init",
                                    indices=False))  # fmt: skip
            deadline = now + DEADLINE
            auth = await gateway.run(Authenticate(), NoParams(), purpose=Purpose.SELFTEST,
                                     component="init", deadline=deadline)  # fmt: skip
            problems = []
            body = auth.body
            if not isinstance(body, dict) or body.get("authentication_type") != "api_key":
                problems.append("the key does not authenticate as an API key")
            held = await gateway.run(
                HasPrivileges(), PrivilegeParams(indices=tuple(names)), purpose=Purpose.SELFTEST,
                component="init", deadline=deadline,
            )  # fmt: skip
            return problems + HasPrivileges.problems(held.body)
        finally:
            await _close(gateway.transport)
    finally:
        await engine.dispose()


async def _selftest(settings: Settings, sender: Any = None) -> list[str]:
    from argus.db.engine import create_engine
    from argus.gateway.service import build_discovery_gateway, probe, selftest

    engine = create_engine(settings.database)
    try:
        gateway, store = build_discovery_gateway(settings.siem, engine, sender=sender)
        try:
            store.adopt(await probe(gateway, store, settings.siem, component="init"))
            return await selftest(gateway, settings.siem)
        finally:
            await _close(gateway.transport)
    finally:
        await engine.dispose()


async def _kibana_check(settings: Settings) -> list[str] | None:
    """The Kibana key's problems, or None when its lane could not take the check in time (the
    lane is paced: discovery's Kibana reads may have spent its minute)."""
    from argus.db.engine import create_engine
    from argus.gateway.errors import DeadlinePassedError
    from argus.gateway.kibana import selftest as core
    from argus.gateway.kibana.service import build_kibana_gateway
    from argus.gateway.kibana.templates import KeyRole
    from argus.gateway.pgstore import PgStore
    from argus.gateway.service import collector_config, lane_plan

    engine = create_engine(settings.database)
    try:
        store = PgStore(engine, collector_config(settings.siem), lane_plan(settings.siem))
        gateway = build_kibana_gateway(settings, store)
        try:
            _version, verdict = await core.run_selftest(
                gateway, KeyRole.READER, deadline=datetime.now(UTC) + DEADLINE, component="init"
            )
        except DeadlinePassedError:
            return None
        return list(verdict.problems)
    finally:
        await engine.dispose()
