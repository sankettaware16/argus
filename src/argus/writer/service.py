"""Putting the writer together from the settings, and what must hold before it writes."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import signing
from argus.config.errors import ConfigError
from argus.config.settings import Settings
from argus.writer.sender import Writer

CREDENTIAL = "approval-signing.key"


def verifier_of(settings: Settings) -> signing.Verifier | None:
    """The approval keys the writer verifies with: ``kibana.writer.approval_keys``, else the
    credential the unit loads (``$CREDENTIALS_DIRECTORY/approval-signing.key``)."""
    paths = list(settings.kibana.writer.approval_keys)
    folder = os.environ.get("CREDENTIALS_DIRECTORY")
    if not paths and folder and (Path(folder) / CREDENTIAL).is_file():
        paths = [Path(folder) / CREDENTIAL]
    if not paths:
        return None
    try:
        return signing.Verifier([signing.load_key(path) for path in paths])
    except (signing.KeyFileError, OSError) as exc:
        raise ConfigError(f"the approval key cannot be read ({type(exc).__name__})") from None


def build_writer(settings: Settings, engine: AsyncEngine, *, wait_for_gaps: bool) -> Writer:
    """The writer as the service and the terminal run it: the Kibana lane (all three keys of
    its account), the Elasticsearch gateway for the licence and the alerts' case ids, the
    gateway's store."""
    from argus.gateway.kibana.service import build_kibana_gateway
    from argus.gateway.service import build_gateway

    es, store = build_gateway(settings.siem, engine)
    kibana = build_kibana_gateway(settings, store, es_gateway=es)
    return Writer(
        engine,
        kibana,
        es=es,
        verifier=verifier_of(settings),
        link_base=settings.web.link_base,
        author=settings.kibana.service_user,
        wait_for_gaps=wait_for_gaps,
        accepted_residual=settings.kibana.accepted_residual,
    )


def gate_problems(settings: Settings, write_class: str, now: datetime | None = None) -> list[str]:
    """What stops a class from running at this host now (nothing here is the lane's own check
    of the window, health or caps, which the gateway makes before every request)."""
    now = now or datetime.now(UTC)
    k = settings.kibana
    problems: list[str] = []
    if not k.enabled:
        problems.append("kibana.enabled is false")
    if write_class not in k.write_classes:
        problems.append(f"{write_class} is not switched on at this host (kibana.write_classes)")
    expires = k.cases_writer_api_key_expires
    if k.cases_writer_api_key is None:
        problems.append("the cases writer's key is not installed")
    elif expires is None:
        problems.append(
            "no expiry is recorded for the cases writer's key"
            " (ARGUS_KIBANA__CASES_WRITER_API_KEY_EXPIRES)"
        )
    elif expires < now.date():
        problems.append(f"the cases writer's key expired on {expires}: mint a new one")
    if write_class == "W1" and settings.web.public_url is None:
        problems.append(
            "web.public_url is not set: the link to ARGUS in a Kibana case would not open"
            " for people (DQ29)"
        )
    if verifier_of(settings) is None and write_class == "W3":
        problems.append("no approval key is configured: the writer cannot check signatures")
    return problems
