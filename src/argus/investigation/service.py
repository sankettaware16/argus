"""Putting the wave together from the settings: the gateway, the pack that reads the
answers, the switches and the caps. Used by the assessment service (``argus assess run``, which
runs a pass of the wave beside the decision engine) and by ``argus investigation ...``."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assets.classify import IpClassifier
from argus.config.errors import ConfigError
from argus.config.settings import Settings
from argus.context import batch1
from argus.context.packs import default_registry
from argus.freshness.reader import policy_of
from argus.gateway.gateway import Gateway
from argus.gateway.service import build_gateway, health_config
from argus.gateway.state import GatewayState
from argus.investigation import catalogue
from argus.investigation.plan import Caps
from argus.investigation.wave import Env


def build_env(
    settings: Settings,
    engine: AsyncEngine,
    classifier: IpClassifier | None,
    state: GatewayState,
    gateway: Gateway | None,
) -> Env:
    """The wave's environment. ``gateway`` None: a dry run, nothing can be sent."""
    inv = settings.investigation
    campus = batch1.private_or(
        None if classifier is None else lambda v: classifier.classify(v).ip_class
    )
    return Env(
        engine=engine,
        state=state,
        gateway=gateway,
        packs=default_registry(
            classifier,
            remote_ti=settings.reference.ti_sync,
            log_queries=settings.enrichment.log_queries,
            proxy_aggregations=settings.enrichment.proxy_aggregations,
        ),
        switches=catalogue.switches_of(settings),
        is_campus=campus,
        history=settings.history.window,
        caps=Caps(inv.item_requests, inv.item_heavy, inv.item_server_ms),
        per_day=inv.wave_per_day,
        freshness=policy_of(settings),
        health_config=health_config(settings.siem),
    )


async def open_env(
    settings: Settings, engine: AsyncEngine, classifier: IpClassifier | None
) -> tuple[Env, Callable[[], Awaitable[None]]] | None:
    """The wave's environment with the real gateway, or None when the SIEM cannot be reached from
    here (no key, no pinned certificate): the wave and "Check more" then wait. The returned
    function closes the gateway's connection."""
    try:
        gateway, state = build_gateway(settings.siem, engine)
    except ConfigError:
        return None

    async def close() -> None:
        await gateway.transport.aclose()  # type: ignore[attr-defined]

    return build_env(settings, engine, classifier, state, gateway), close


def dry_env(settings: Settings, engine: AsyncEngine, classifier: IpClassifier | None) -> Env:
    """The environment of a dry run: the stored health, no gateway (nothing is sent). The
    health is read from Postgres, so it is the real one."""
    from argus.gateway.pgstore import PgStore
    from argus.gateway.service import collector_config, lane_plan

    state: Any = PgStore(engine, collector_config(settings.siem), lane_plan(settings.siem))
    return build_env(settings, engine, classifier, state, None)
