"""A small world for the incident engine's integration tests, written as the schema owner into
the test's throwaway database: rules with a stored alert that carries their tactics and indices,
alert groups (investigations) with their alerts, entities, newest dossier, signals and raise
flags. Addresses and names are made up (the suite's ACME site)."""

from __future__ import annotations

import ipaddress
import json
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import site
from argus.assets.classify import IpClassifier
from argus.grouping import assign
from argus.risk import config as risk_config
from argus.risk import run

NOW = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
C2 = {"framework": "MITRE ATT&CK", "tactic": {"id": "TA0011", "name": "Command and Control"}}
EXFIL = {"framework": "MITRE ATT&CK", "tactic": {"id": "TA0010", "name": "Exfiltration"}}
ACCESS = {"framework": "MITRE ATT&CK", "tactic": {"id": "TA0001", "name": "Initial Access"}}
RULE_FIELDS: dict[str, dict[str, Any]] = {}  # every alert of a rule carries its definition


def setup() -> run.Setup:
    classifier = IpClassifier(None, (ipaddress.ip_network("131.21.124.0/22"),))
    profile = site.active()
    return run.Setup(risk_config.load(), classifier, profile.families, profile.own_domains,
                     run.feed_modes(profile.ti_sources))  # fmt: skip


async def rule(
    owner: AsyncEngine, rule_id: str, name: str, *, severity: str = "low",
    threat: Sequence[dict[str, Any]] = (C2,), indices: Sequence[str] = ("acme-logs-squid-*",),
    first: datetime = NOW - timedelta(days=30), ancestor: str | None = None,
) -> None:  # fmt: skip
    """A rule in the registry and one stored alert of it carrying its definition (made from the
    index ``ancestor``, if given)."""
    raw = {"kibana.alert.rule.threat": list(threat), "kibana.alert.rule.indices": list(indices),
           "kibana.alert.rule.name": name}  # fmt: skip
    RULE_FIELDS[rule_id] = raw
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO rules (rule_id, name, severity, alerts, first_alert_at,"
                " last_alert_at, definition_at, execution_status, refreshed_at)"
                " VALUES (:r, :n, :s, 1, :f, :t, :f, 'ok', :t)"
            ),
            {"r": rule_id, "n": name, "s": severity, "f": first, "t": NOW},
        )
        await conn.execute(
            text(
                "INSERT INTO alert_records (alert_id, index, status, normalizer_version, rule_id,"
                " raw, normalized, content_hash, state_hash, recovered_by, detected_at, event_time)"
                " VALUES (:a, 'alerts', 'normalized', 'test', :r, CAST(:raw AS jsonb),"
                " CAST(:n AS jsonb), 'h', 'h', 'live', :t, :t)"
            ),
            {"a": f"def-{rule_id}", "r": rule_id, "raw": json.dumps(raw),
             "n": json.dumps({"entities": [], "ancestors": [{"index": ancestor}] if ancestor
                              else []}), "t": NOW - timedelta(days=1)},
        )  # fmt: skip


@dataclass(frozen=True)
class Made:
    id: uuid.UUID
    version: int


async def group(
    owner: AsyncEngine, rule_id: str, *, actor: str | list[str] = "10.1.1.1",
    severity: str = "low", risk_score: float | None = None, hours_ago: float = 2.0,
    fields: dict[str, list[Any]] | None = None, signals: dict[str, Any] | None = None,
    flags: Sequence[str] = (), outcome: str | None = None, alerts: int = 2,
    index: str | None = None, stored_after: timedelta = timedelta(0),
    raised_at: datetime | None = None,
) -> Made:  # fmt: skip
    """An alert group of ``rule_id`` with ``actor`` as its key, its alerts (their entities and
    ECS ``fields``, made from the index ``index``, stored ``stored_after`` their event), a
    dossier with ``signals`` and the stored raise ``flags`` (last evaluated at ``raised_at``, by
    default the group's last alert)."""
    gid = uuid.uuid4()
    last = NOW - timedelta(hours=hours_ago)
    first = last - timedelta(minutes=20)
    start = assign.bucket_start(first)
    key = json.dumps([["source.ip", actor]], separators=(",", ":"))
    actors = actor if isinstance(actor, list) else [actor]
    entities = [{"kind": "ip", "field": "source.ip", "value": a} for a in actors[:16]]
    raw: dict[str, Any] = {**RULE_FIELDS.get(rule_id, {}), **(fields or {})}
    for name, values in (fields or {}).items():
        kind = {"destination.ip": "ip", "url.domain": "domain", "host.name": "host",
                "user.name": "user"}.get(name)  # fmt: skip
        if kind:
            entities.extend({"kind": kind, "field": name, "value": v} for v in values)
    if outcome is not None:
        raw["event.outcome"] = outcome
    ancestors = [{"index": "acme-logs-*"}, {"index": index}] if index else []
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO investigations (id, grouping_version, rule_id, rule_name, group_key,"
                " bucket_start, bucket_end, previous_id, severity, risk_score, alert_count,"
                " version, first_event_at, last_event_at)"
                " VALUES (:id, '2', :rule, 'not read by the engine', :key, :start, :end, :prev,"
                " :sev, :rs, :n, 1, :first, :last)"
            ),
            {"id": gid, "rule": rule_id, "key": key, "start": start,
             "end": start + assign.WINDOW, "prev": uuid.uuid4(), "sev": severity,
             "rs": risk_score, "n": alerts, "first": first, "last": last},
        )  # fmt: skip
        for e in {(e["kind"], e["value"]) for e in entities}:
            await conn.execute(
                text("INSERT INTO investigation_entities (investigation_id, kind, value)"
                     " VALUES (:i, :k, :v)"),
                {"i": gid, "k": e[0], "v": e[1]},
            )  # fmt: skip
        for n in range(alerts):
            alert = f"{gid.hex}-{n}"
            await conn.execute(
                text(
                    "INSERT INTO alert_records (alert_id, index, status, normalizer_version,"
                    " rule_id, raw, normalized, content_hash, state_hash, recovered_by,"
                    " detected_at, event_time, first_seen_at, last_seen_at) VALUES (:a,"
                    " 'alerts', 'normalized', 'test', :r, CAST(:raw AS jsonb), CAST(:n AS jsonb),"
                    " 'h', 'h', 'live', :t, :t, :seen, :seen)"
                ),
                {"a": alert, "r": rule_id, "raw": json.dumps(raw),
                 "n": json.dumps({"entities": entities, "ancestors": ancestors}),
                 "t": first + timedelta(minutes=n),
                 "seen": first + timedelta(minutes=n) + stored_after},
            )  # fmt: skip
            await conn.execute(
                text("INSERT INTO investigation_alerts (alert_id, investigation_id)"
                     " VALUES (:a, :i)"),
                {"a": alert, "i": gid},
            )  # fmt: skip
    await dossier(owner, gid, 1, signals or {})
    if flags:
        async with owner.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO investigation_raises (investigation_id, version, dossier_hash,"
                    " flags, evaluated_at) VALUES (:i, 1, :h, CAST(:f AS jsonb), :at)"
                ),
                {"i": gid, "h": "0" * 64, "f": json.dumps(list(flags)), "at": raised_at or last},
            )
    return Made(gid, 1)


async def dossier(
    owner: AsyncEngine, gid: uuid.UUID, version: int, signals: dict[str, Any]
) -> None:
    """The group's newest dossier (``version``) with its signals, all known."""
    async with owner.begin() as conn:
        await conn.execute(
            text("UPDATE investigations SET version = :v WHERE id = :i"), {"v": version, "i": gid}
        )
        await conn.execute(
            text(
                "INSERT INTO dossiers (investigation_id, version, pack, facts_version, job_id,"
                " run_kind, family, status, dossier_hash, body, evidence_count, created_at)"
                " VALUES (:i, :v, 'generic@12', :v, 1, 'collect', 'proxy', 'evidence_ready', :h,"
                " '{}'::jsonb, 0, now())"
            ),
            {"i": gid, "v": version, "h": f"{version}{gid.hex}".ljust(64, "0")[:64]},
        )
        for name, value in signals.items():
            await conn.execute(
                text(
                    "INSERT INTO signals (investigation_id, version, pack, name, value, status,"
                    " completeness, evidence, definition_version) VALUES (:i, :v, 'generic@12',"
                    " :n, CAST(:val AS jsonb), 'known', 'exact', '{}', 1)"
                ),
                {"i": gid, "v": version, "n": name, "val": json.dumps(value)},
            )


async def scalar(engine: AsyncEngine, sql: str, **params: Any) -> Any:
    async with engine.connect() as conn:
        return (await conn.execute(text(sql), params)).scalar_one()


async def all_rows(engine: AsyncEngine, sql: str, **params: Any) -> list[Any]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(sql), params)).all())
