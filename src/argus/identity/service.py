"""Putting the identity lane together from the settings (Q-E1)."""

from __future__ import annotations

from typing import Any

from argus import site
from argus.config.errors import ConfigError
from argus.config.settings import Settings
from argus.gateway.gateway import LaneGate
from argus.gateway.service import health_config, lane_plan
from argus.gateway.transport import pinned_context
from argus.identity import capmap
from argus.identity.lane import AdminAccounts, IdentityLane, IdentityState, gateway_index_check
from argus.identity.names import NamePolicy
from argus.identity.transport import HttpxIdentityTransport, IdentityTransport


def names(settings: Settings) -> NamePolicy:
    """The names refused before any request: the reserved ones and ``argus`` always, the
    Kibana lane's service user and ``identity.refused_names``."""
    return NamePolicy.of([settings.kibana.service_user, *settings.identity.refused_names])


def targets(settings: Settings) -> capmap.Targets:
    profile = site.active()
    return capmap.Targets(space=profile.space, log_patterns=profile.checked_log_patterns)


def transport(settings: Settings) -> HttpxIdentityTransport:
    """The identity lane's own HTTPS client to the SIEM's Elasticsearch (the pinned CA)."""
    if not settings.siem.ca_file.is_file():
        raise ConfigError(f"siem.ca_file {settings.siem.ca_file} does not exist")
    return HttpxIdentityTransport(
        settings.siem.address(),
        pinned_context(settings.siem.ca_file),
        connect_timeout_s=settings.identity.connect_timeout.total_seconds(),
        total_timeout_s=settings.identity.timeout.total_seconds(),
    )


def build_identity_lane(
    settings: Settings,
    store: Any,
    *,
    sender: IdentityTransport | None = None,
    es_gateway: Any = None,
) -> IdentityLane:
    """The lane on ``store`` (a ``PgStore`` or ``MemoryStore``: gateway and identity state).
    ``es_gateway`` (ARGUS's own key) makes the security-index check; without it a 401 is
    never a denial, only "unavailable"."""
    lane_plan(settings.siem)  # the lanes must fit the ceiling (ValueError otherwise)
    state: IdentityState = store
    return IdentityLane(
        sender or transport(settings),
        state,
        LaneGate(store, health_config=health_config(settings.siem)),
        names=names(settings),
        targets=targets(settings),
        index_check=None if es_gateway is None else gateway_index_check(es_gateway),
        admin_accounts=AdminAccounts(settings.identity.admin_accounts),
        timeout_s=settings.identity.timeout.total_seconds(),
    )
