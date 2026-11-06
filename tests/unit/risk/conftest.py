"""Builders for the incident engine's unit tests: the repo's settings, a classifier of the suite's
made-up site (ACME: private space and 131.21.124.0/22 are its own), groups and observations."""

from __future__ import annotations

import ipaddress
import json
import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Any

from argus.assets.classify import IpClassifier
from argus.risk import config as risk_config
from argus.risk.observe import Context, Group, ObjectRef, Observation
from argus.risk.rulemeta import RuleMeta

NOW = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
CONFIG = risk_config.load()
CLASSIFIER = IpClassifier(None, (ipaddress.ip_network("131.21.124.0/22"),))
CAMPUS = ("example.edu",)


def context(**more: Any) -> Context:
    return Context(CONFIG, CLASSIFIER, CAMPUS, **more)


def group(
    *, actor: str | list[str] = "10.1.1.1", field: str = "source.ip", rule: str = "rule-a",
    severity: str = "low", risk_score: float | None = None, hours_ago: float = 1.0,
    fields: dict[str, list[object]] | None = None, signals: dict[str, Any] | None = None,
    flags: tuple[str, ...] = (), outcomes: tuple[str, ...] = (), known: bool = False,
    gid: uuid.UUID | None = None, alerts: int = 3, indices: tuple[str, ...] = (),
) -> Group:  # fmt: skip
    at = NOW - timedelta(hours=hours_ago)
    key = json.dumps([[field, actor]], separators=(",", ":"))
    return Group(
        gid or uuid.uuid4(), 1, rule, severity, risk_score, key, at - timedelta(minutes=30), at,
        alerts, (at + timedelta(hours=5, minutes=30)).date(), fields or {}, outcomes,
        signals or {}, flags, known, indices,
    )  # fmt: skip


def meta(rule: str = "rule-a", *, lineage: str | None = None, stages: int = 0,
         family: str | None = "squid", first: datetime | None = None) -> RuleMeta:  # fmt: skip
    return RuleMeta(rule, lineage or f"L-{rule}", stages, family,
                    first or datetime(2026, 9, 1, tzinfo=UTC))  # fmt: skip


def obs(
    source: str = "rule:L1", *, key: str = "ip:10.1.1.1", kind: str = "device",
    role: str = "actor", hours_ago: float = 1.0, base: float = 20.0, outcome: float = 1.0,
    stages: int = 0, family: str | None = None, strong: bool = False,
    threats: tuple[str, ...] = (), gid: uuid.UUID | None = None, day: date | None = None,
) -> Observation:  # fmt: skip
    at = NOW - timedelta(hours=hours_ago)
    return Observation(
        ObjectRef(kind, key), role, "rule" if source.startswith("rule:") else "evidence",  # type: ignore[arg-type]
        source, gid or uuid.uuid4(), 1, at, day or (at + timedelta(hours=5, minutes=30)).date(),
        base, outcome, stages, family, strong, threats,
    )  # fmt: skip
