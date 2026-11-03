"""Putting the gateway together from the settings, and the two jobs that run on it besides
everyone's queries: the health probe (plan §5.1) and the identity self-test (plan §5.3)."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine

from argus import site
from argus.config.errors import ConfigError
from argus.config.settings import SiemSettings
from argus.gateway.budget import BudgetConfig
from argus.gateway.builtin import (
    Authenticate,
    BlocksParams,
    ClusterInfo,
    HasPrivileges,
    IndexBlocks,
    NodeStats,
    PrivilegeParams,
)
from argus.gateway.errors import AuthFailedError, GatewayError, RefusedError, SourceMissingError
from argus.gateway.gateway import Gateway, LiveLimits, Targets, utcnow
from argus.gateway.health import (
    HealthConfig,
    HealthMemory,
    Readings,
    evaluate,
    readings_from_node_stats,
)
from argus.gateway.indices import day_suffix
from argus.gateway.lanes import Lane, LanePlan, plan_from
from argus.gateway.pgstore import PgStore
from argus.gateway.state import DiscoveryStore, GatewayState
from argus.gateway.templates import NoParams, Params, Purpose, Template
from argus.gateway.transport import HttpxTransport, Transport, pinned_context
from argus.observability.redaction import redact_text

log = logging.getLogger("argus.gateway")

PROBE_DEADLINE = timedelta(seconds=20)
MAX_PROBED_FAMILIES = 7  # index blocks name at most 8 indices: the alerts index and these


def targets(settings: SiemSettings) -> Targets:
    """What the gateway may read: the site profile's alerts index, every one of its log
    families (also the ones the health probe does not watch) and its threat-intel indices."""
    profile = site.active()
    return Targets(
        alerts=profile.alerts_index_name,
        alerts_backing=profile.alerts_backing_prefix,
        families=profile.families,
        log_sources=frozenset(profile.all_sources),
        ti=frozenset(profile.ti_indices),
    )


def budget_config(settings: SiemSettings) -> BudgetConfig:
    """D-022's ceiling (``siem.budget``)."""
    config: BudgetConfig = settings.ceiling()
    return config


def lane_plan(settings: SiemSettings) -> LanePlan:
    """The lane budgets (plan §7.8): ``siem.lanes`` where set, else each lane's share of the
    ceiling; ValueError if they exceed it."""
    return plan_from(budget_config(settings), settings.lane_specs())


def collector_config(settings: SiemSettings) -> BudgetConfig:
    """The collector's lane, which is the original budget's bucket (``budget_admit``)."""
    return lane_plan(settings).config(Lane.COLLECTOR)


def health_config(settings: SiemSettings) -> HealthConfig:
    h = settings.health
    return HealthConfig(
        disk_caution=h.disk_caution,
        disk_degraded=h.disk_degraded,
        disk_stop=h.disk_stop,
        heap_caution=h.heap_caution,
        load_caution=h.load_caution,
        ingest_lag_degraded=h.ingest_lag_degraded,
    )


def transport(settings: SiemSettings) -> HttpxTransport:
    """The HTTPS transport to the SIEM; ConfigError without a key or the pinned CA."""
    if settings.api_key is None or not settings.api_key.get_secret_value():
        raise ConfigError("siem.api_key is not set (ARGUS_SIEM__API_KEY in .env)")
    if not settings.ca_file.is_file():
        raise ConfigError(f"siem.ca_file {settings.ca_file} does not exist")
    return HttpxTransport(settings.address(), pinned_context(settings.ca_file), settings.api_key)


def build_gateway(
    settings: SiemSettings,
    engine: AsyncEngine,
    *,
    sender: Transport | None = None,
    live: LiveLimits | None = None,
) -> tuple[Gateway, PgStore]:
    store = PgStore(engine, collector_config(settings), lane_plan(settings))
    gateway = Gateway(
        sender or transport(settings),
        store,
        targets=targets(settings),
        health_config=health_config(settings),
        live=live,
    )
    return gateway, store


def build_discovery_gateway(
    settings: SiemSettings,
    engine: AsyncEngine,
    *,
    sender: Transport | None = None,
) -> tuple[Gateway, DiscoveryStore]:
    """The gateway ``argus discover`` uses: the real store's budget, breakers, kill switches and
    ledger, but no failure remembered (``DiscoveryStore``)."""
    gateway, store = build_gateway(settings, engine, sender=sender)
    shadow = DiscoveryStore(store)
    gateway.state = shadow
    return gateway, shadow


async def probe(
    gateway: Gateway,
    store: GatewayState,
    settings: SiemSettings,
    now: datetime | None = None,
    *,
    component: str = "probe",
    ingest_lag: Mapping[str, timedelta] | None = None,
    indices: bool = True,
) -> HealthMemory:
    """One health probe: node stats and index blocks in, the new health state saved. If the
    gateway itself refused to send (its probe allowance, the deadline), nothing was learnt
    about the SIEM: the memory is left as it is and goes stale on its own. ``component`` names
    the probe's caller on its ledger rows (the re-measurement counts its own, Q-A3).
    ``ingest_lag``: each log source's lag, from the freshness lane's readings (Q-F1, once
    switched on): the health trip wire's input (DQ19). ``indices=False``: node stats only, no
    index blocks (``argus discover`` on an Elastic whose indices are not configured yet). Such
    a reading is partial: the index blocks, the ingest lag and the stale rules are conditions
    that only a fuller reading clears, so it is evaluated and returned but never saved."""
    now = now or utcnow()
    deadline = now + PROBE_DEADLINE
    try:
        result = await gateway.run(
            NodeStats(), NoParams(), purpose=Purpose.PROBE, component=component, deadline=deadline
        )
        readings = readings_from_node_stats(result.body, now)
    except AuthFailedError:
        readings = Readings(at=now, probe_ok=False, auth_failed=True)
    except RefusedError as exc:
        if isinstance(exc, SourceMissingError):  # an answer from the SIEM, not a local refusal
            readings = Readings(at=now, probe_ok=False)
        else:
            return await store.health()
    except GatewayError:
        readings = Readings(at=now, probe_ok=False)
    if readings.probe_ok and indices:
        t = targets(settings)
        today = day_suffix(now.date())
        profile = site.active()
        watched = [family.probe_name(today) for family in profile.families if family.watch]
        names = (t.alerts, *watched[:MAX_PROBED_FAMILIES])
        try:
            blocks = await gateway.run(
                IndexBlocks(),
                BlocksParams(indices=names),
                purpose=Purpose.PROBE,
                component=component,
                deadline=deadline,
            )
            seen = isinstance(blocks.body, dict) and any(
                isinstance(name, str) and name.startswith(t.alerts_backing) for name in blocks.body
            )
            readings = replace(
                readings,
                probe_ok=seen,  # the alerts index must answer, else the probe failed
                blocked_indices=tuple(IndexBlocks.blocked(blocks.body)),
            )
        except AuthFailedError:
            readings = replace(readings, probe_ok=False, auth_failed=True)
        except RefusedError as exc:
            if not isinstance(exc, SourceMissingError):
                return await store.health()
            readings = replace(readings, probe_ok=False)
        except GatewayError:
            readings = replace(readings, probe_ok=False)
    if ingest_lag:  # each source's lag from the freshness lane (Q-F1, mode on only)
        readings = replace(readings, ingest_lag=dict(ingest_lag))
    switches = await store.switches()
    memory = evaluate(
        await store.health(),
        readings,
        health_config(settings),
        kill_switch="global" in switches.stopped,
    )
    if not indices:  # a partial reading must not clear what a full one found (F2)
        return memory
    await store.save_health(memory)
    try:  # the readings are kept for Q-A3; losing one never fails the probe
        await store.record_probe(readings, memory)
    except Exception as exc:
        log.warning("probe readings not stored: %s", redact_text(f"{type(exc).__name__}: {exc}"))
    return memory


async def selftest(
    gateway: Gateway, settings: SiemSettings, now: datetime | None = None
) -> list[str]:
    """What is wrong with the connection or the key (empty: all good). The key must
    authenticate as an API key, read the ARGUS families and hold none of the canaries."""
    now = now or utcnow()
    deadline = now + PROBE_DEADLINE

    async def call(template: Template, params: Params) -> Any:
        result = await gateway.run(
            template, params, purpose=Purpose.SELFTEST, component="selftest", deadline=deadline
        )
        return result.body

    problems: list[str] = []
    info = await call(ClusterInfo(), NoParams())
    version = info.get("version", {}).get("number") if isinstance(info, dict) else None
    allowed = site.active().elastic_range
    if not isinstance(version, str) or not allowed.allows(version):
        problems.append(f"server version {version!s:.20} is not {allowed.describe()}")
    auth = await call(Authenticate(), NoParams())
    if not isinstance(auth, dict) or auth.get("authentication_type") != "api_key":
        problems.append("not authenticated with an API key")
    t = targets(settings)
    names = (t.alerts, *site.active().checked_log_patterns, *sorted(t.ti))
    held = await call(HasPrivileges(), PrivilegeParams(indices=names))
    problems += HasPrivileges.problems(held)
    return problems
