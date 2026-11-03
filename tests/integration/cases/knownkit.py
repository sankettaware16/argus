"""A small world for the known infection of a notified case (AR4b, D-169): the Amadey incident of
D-169's acceptance in miniature. One campus host beacons to four servers that VirusTotal flags;
its investigations, dossiers, raises and alerts are made at chosen times; a case is opened for
them and a person records that the owner was told. Time is always passed in, never read."""

from __future__ import annotations

import json
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assets.classify import IpClassifier
from argus.cases import knownrun
from argus.cases.known import Rules
from argus.cases.machine import Notify, Open
from argus.cases.model import Indicator, Member
from argus.cases.service import CaseService
from argus.outside.read import View
from tests.integration.cases.conftest import Person, investigation

HOST = "10.198.36.230"
OTHER_HOST = "10.55.7.9"
SERVERS = ("77.221.155.150", "77.221.155.151", "77.221.155.152", "77.221.155.153")
NEW_SERVER = "185.9.9.9"
BEACON = "regular traffic, like a beacon"
OUTSIDE = "flagged by outside threat intel"
SUCCESS = "successful answers after the alert"
CLASSIFIER = IpClassifier(None, ())
VIEW = View(timedelta(days=7), 3, timedelta(days=1))
RULES = Rules()
# The first day of the incident, 40 days before today: the pass takes its time as a parameter,
# but the case service dates a person's notice against the database's clock (never in the future,
# not a year back), and the longest story here runs 40 days.
D0 = datetime.now(UTC).replace(hour=9, minute=0, second=0, microsecond=0) - timedelta(days=40)


def at(day: int, hour: int = 9, minute: int = 0) -> datetime:
    """``hour:minute`` UTC, ``day`` days after the first day of the incident."""
    return D0.replace(hour=hour, minute=minute) + timedelta(days=day)


def context(**more: Any) -> knownrun.Context:
    values: dict[str, Any] = {"classifier": CLASSIFIER, "view": VIEW, "rules": RULES}
    values.update(more)
    return knownrun.Context(**values)


async def flag_server(owner: AsyncEngine, ip: str, when: datetime, *, malicious: int = 7) -> None:
    """VirusTotal's cached answer for an address: ``malicious`` of 94 engines flag it."""
    answer = {"malicious": malicious, "suspicious": 0, "engines": 94}
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO outside_lookups (source, kind, indicator, status, answer,"
                " answer_bytes, fetched_at) VALUES ('virustotal', 'ip', :ip, 'found',"
                " CAST(:a AS jsonb), :n, :t) ON CONFLICT DO NOTHING"
            ),
            {"ip": ip, "a": json.dumps(answer), "n": len(json.dumps(answer)), "t": when},
        )


async def make(
    owner: AsyncEngine,
    *,
    when: datetime,
    host: str = HOST,
    servers: Sequence[str] = SERVERS,
    flags: Sequence[str] = (BEACON, OUTSIDE),
    nbytes: int | None = 1_000_000,
    severity: str = "low",
    extra: Sequence[tuple[str, str]] = (),
    listed: Sequence[str] = (),
    rule: str = "beacon",
    alerts: int = 3,
) -> uuid.UUID:
    """An unreviewed investigation of ``host`` that reached ``servers``, last alerting at ``when``,
    with its dossier (a beacon rhythm and a byte count), its raised flags and its alerts."""
    inv = await investigation(
        owner, rule=rule, actor=(("source.ip", host),),
        entities=(*[("ip", s) for s in servers], *extra), severity=severity, alerts=alerts,
    )  # fmt: skip
    signals: list[dict[str, Any]] = [
        {"name": "proxy.regularity", "status": "known", "value": 0.0 if BEACON in flags else 0.9}
    ]
    if nbytes is not None:
        signals.append({"name": "proxy.bytes", "status": "known", "value": nbytes})
    body = {"local_signals": signals, "signals": [],
            "context": {"pack": {"ti": {"listed": list(listed)}}}}  # fmt: skip
    digest = f"1{inv.hex}".ljust(64, "0")[:64]
    async with owner.begin() as conn:
        await conn.execute(
            text("UPDATE investigations SET first_event_at = :t, last_event_at = :t WHERE id = :i"),
            {"t": when, "i": inv},
        )
        await conn.execute(
            text(
                "UPDATE alert_records SET event_time = :t, detected_at = :t WHERE alert_id IN"
                " (SELECT alert_id FROM investigation_alerts WHERE investigation_id = :i)"
            ),
            {"t": when, "i": inv},
        )
        await conn.execute(
            text(
                "INSERT INTO dossiers (investigation_id, version, pack, facts_version, job_id,"
                " run_kind, family, status, dossier_hash, body, evidence_count, created_at)"
                " VALUES (:i, 1, 'generic@12', 1, 1, 'collect', 'proxy', 'evidence_ready', :h,"
                " CAST(:b AS jsonb), 0, :t)"
            ),
            {"i": inv, "h": digest, "b": json.dumps(body), "t": when},
        )
        await conn.execute(
            text(
                "INSERT INTO investigation_raises (investigation_id, version, dossier_hash,"
                " flags, evaluated_at) VALUES (:i, 1, :h, CAST(:f AS jsonb), :t)"
            ),
            {"i": inv, "h": digest, "f": json.dumps(list(flags)), "t": when},
        )
    return inv


async def open_case(
    engine: AsyncEngine, person: Person, members: Sequence[uuid.UUID], *,
    host: str = HOST, servers: Sequence[str] = SERVERS,
) -> uuid.UUID:  # fmt: skip
    """A confirmed case for the host: its investigations, the host as its actor, the servers as
    its command-and-control."""
    async with engine.begin() as conn:
        service = await CaseService.start(conn)
        applied = await service.open(
            person.actor(),
            Open(
                "Regular beaconing from a campus host", "high", "person",
                tuple(Member(m, "actor", host) for m in members),
                (Indicator("ip", host, "actor"), *(Indicator("ip", s, "c2") for s in servers)),
            ),
        )  # fmt: skip
    return applied.case.id


async def notify(
    engine: AsyncEngine, person: Person, case_id: uuid.UUID, when: datetime,
    *, told: str = "the owner, Hostel 5", how: str = "email",
) -> None:  # fmt: skip
    """A person records that the owner was told, at ``when``."""
    async with engine.begin() as conn:
        service = await CaseService.start(conn)
        await service.apply(person.actor(), case_id, Notify(told, how, at=when),  # type: ignore[arg-type]
                            expected_version=None)  # fmt: skip


async def known_rows(
    engine: AsyncEngine, case_id: uuid.UUID
) -> dict[uuid.UUID, tuple[str, str | None]]:
    async with engine.connect() as conn:
        found = await conn.execute(
            text(
                "SELECT investigation_id, outcome, why FROM case_known_matches WHERE case_id = :c"
            ),
            {"c": case_id},
        )
        return {r.investigation_id: (r.outcome, r.why) for r in found}


async def members(engine: AsyncEngine, case_id: uuid.UUID) -> set[uuid.UUID]:
    async with engine.connect() as conn:
        found = await conn.execute(
            text(
                "SELECT investigation_id FROM case_members WHERE case_id = :c"
                " AND removed_at IS NULL"
            ),
            {"c": case_id},
        )
        return set(found.scalars())
