"""Putting the case team's poster together from the settings, and what must hold before it writes
(AR8, D-195). Nothing here sends anything; ``gate_problems`` only reads the configuration."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncEngine

from argus import site
from argus.caseteam.sender import PostConfig, Poster
from argus.config.settings import Settings
from argus.writer.service import verifier_of

TEAM = ("lead", "evidence", "intel", "responder", "hunter", "reporter")


def post_config(settings: Settings, *, writer: bool = False) -> PostConfig:
    """The poster's settings. The six keys are the writer's alone (custody), so only ``writer``
    reads which are installed; the web and the preview leave that to the writer."""
    t = settings.case_team
    kibana = (settings.incident.kibana_url or settings.kibana.url or "").rstrip("/")
    return PostConfig(
        post=t.post,
        auto=t.auto,
        auto_min_confidence=t.auto_min_confidence,
        per_day=t.per_day,
        canary=t.canary,
        max_alerts=t.max_alerts,
        alerts_per_call=t.alerts_per_call,
        alert_pause=t.alert_pause,
        min_update_gap=t.min_update_gap,
        look=t.look,
        link_base=settings.web.link_base,
        kibana_prefixes=(kibana,) if kibana else (),
        space=site.active().space,
        keys=frozenset(t.keys()) if writer else None,
    )


def preview_poster(settings: Settings, engine: AsyncEngine) -> Poster:
    """A poster that can only prepare and describe (no Kibana lane is built, no key is read)."""
    return Poster(engine, None, post_config(settings), verifier=verifier_of(settings))


def refresh_poster(settings: Settings, engine: AsyncEngine, *, writer: bool) -> Poster:
    """A poster for ``argus case team refresh``: no Kibana lane (it only plans, in ARGUS's
    database); with ``writer`` it knows which of the six keys are installed, as the writer does."""
    return Poster(
        engine, None, post_config(settings, writer=writer), verifier=verifier_of(settings)
    )


def build_poster(settings: Settings, engine: AsyncEngine, *, wait_for_gaps: bool) -> Poster:
    """The poster as the terminal and the pass run it: the Kibana lane with the reader key and
    the six users' keys, the Elasticsearch gateway for the licence, the gateway's store, and the
    closures' approval key to verify a canary."""
    from argus.gateway.kibana.service import build_kibana_gateway
    from argus.gateway.service import build_gateway

    es, store = build_gateway(settings.siem, engine)
    kibana = build_kibana_gateway(settings, store, es_gateway=es)
    return Poster(
        engine,
        kibana,
        post_config(settings, writer=True),
        verifier=verifier_of(settings),
        wait_for_gaps=wait_for_gaps,
    )


def gate_problems(settings: Settings, now: datetime | None = None) -> list[str]:
    """What stops a live post at this host now (the lane still checks the window, health, caps
    and breakers before every request)."""
    now = now or datetime.now(UTC)
    k, t = settings.kibana, settings.case_team
    problems: list[str] = []
    if not t.post:
        problems.append("case_team.post is false (posting is off: dry runs only)")
    if not k.enabled:
        problems.append("kibana.enabled is false")
    if "WC" not in k.write_classes:
        problems.append("WC is not switched on at this host (kibana.write_classes)")
    if k.reader_api_key is None:
        problems.append("the Kibana reader key is not installed (it reads before and after)")
    have = t.keys()
    missing = [f"argus-{u}" for u in TEAM if f"argus-{u}" not in have]
    if missing:
        problems.append("no key is installed for " + ", ".join(missing))
    if have and t.keys_expire is None:
        problems.append(
            "no expiry is recorded for the case team's keys (ARGUS_CASE_TEAM__KEYS_EXPIRE)"
        )
    elif t.keys_expire is not None and t.keys_expire < now.date():
        problems.append(f"the case team's keys expired on {t.keys_expire}: mint new ones")
    if settings.web.public_url is None:
        problems.append("web.public_url is not set: the link to ARGUS in a case would not open")
    if t.canary > 0 and verifier_of(settings) is None:
        problems.append("no approval key is configured: the canary's approval cannot be checked")
    return problems
