"""Putting the Kibana lane together from the settings (Q-D2). Nothing is built while
``kibana.enabled`` is false: no transport, no key read."""

from __future__ import annotations

from datetime import time

from pydantic import SecretStr

from argus import site
from argus.config.errors import ConfigError
from argus.config.settings import Settings
from argus.gateway.gateway import Gateway
from argus.gateway.kibana.gateway import KibanaGateway, KibanaTargets, Store
from argus.gateway.kibana.templates import KeyRole
from argus.gateway.kibana.transport import HttpxKibanaTransport, KibanaTransport
from argus.gateway.kibana.writes import WriteCaps, WriteClass
from argus.gateway.service import health_config
from argus.gateway.transport import pinned_context


def caps(settings: Settings) -> WriteCaps:
    start, end = (time.fromisoformat(t) for t in settings.kibana.write_window)
    team = settings.case_team
    return WriteCaps(
        window=(start, end),
        status_per_call=settings.writeback.batch,
        team_alerts_per_call=team.alerts_per_call,
        team_alert_gap=team.alert_pause,
    )


def team_keys(settings: Settings) -> dict[str, SecretStr]:
    """The case team's six keys by Kibana user (AR8); only those installed."""
    return settings.case_team.keys()


def keys(settings: Settings) -> dict[KeyRole, SecretStr]:
    k = settings.kibana
    found = {
        KeyRole.READER: k.reader_api_key,
        KeyRole.CASES: k.cases_writer_api_key,
        KeyRole.ALERTS: k.alert_writer_api_key,
    }
    return {role: key for role, key in found.items() if key and key.get_secret_value()}


def transport(settings: Settings) -> HttpxKibanaTransport:
    """The HTTPS transport to Kibana (and Elasticsearch, for the keys' self-checks)."""
    k = settings.kibana
    if not k.enabled:
        raise ConfigError("kibana.enabled is false: the Kibana lane is off")
    found = keys(settings)
    if KeyRole.READER not in found:
        raise ConfigError("kibana.reader_api_key is not set (ARGUS_KIBANA__READER_API_KEY)")
    if not k.ca_file.is_file():
        raise ConfigError(f"kibana.ca_file {k.ca_file} does not exist")
    return HttpxKibanaTransport(
        k.address(), settings.siem.address(), pinned_context(k.ca_file), found,
        space=site.active().space, base_path=k.base_path, team_keys=team_keys(settings),
    )  # fmt: skip


def build_kibana_gateway(
    settings: Settings,
    store: Store,
    *,
    es_gateway: Gateway | None = None,
    sender: KibanaTransport | None = None,
) -> KibanaGateway:
    if not settings.kibana.enabled:
        raise ConfigError("kibana.enabled is false: the Kibana lane is off")
    k = settings.kibana
    return KibanaGateway(
        sender or transport(settings),
        store,
        targets=KibanaTargets(author=k.service_user),
        caps=caps(settings),
        classes=frozenset(WriteClass(c) for c in k.write_classes),
        health_config=health_config(settings.siem),
        es_gateway=es_gateway,
        timeout=k.timeout,
    )
