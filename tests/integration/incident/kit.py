"""The Amadey-shaped synthetic case in a database, for the incident report's integration tests: the
host's investigations (a download rule and a beacon rule over five days) with their dossiers, flags
and alerts (the alerts carry the fields a real nginx or proxy alert has), the pair checks that ran,
VirusTotal's cached answers for the four servers, the AI investigator's proposal on each
investigation, and a case that holds them. Every address is documentation or private; nothing here
is a real alert."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import Settings
from argus.incident import discover, run
from argus.incident.build import Context
from tests.integration.cases.conftest import Person
from tests.integration.cases.knownkit import (
    BEACON,
    HOST,
    OUTSIDE,
    SERVERS,
    flag_server,
    make,
    open_case,
)

NOW = datetime.now(UTC).replace(microsecond=0)
D0 = (NOW - timedelta(days=6)).replace(hour=9, minute=0, second=0)
RULES = [("download", 0), ("beacon", 1), ("download", 2), ("beacon", 3), ("beacon", 4)]
CFG = discover.Config(kibana_url="https://kibana.example", space="acme-soc")


def day(n: int, hour: int = 9) -> datetime:
    return D0.replace(hour=hour) + timedelta(days=n)


def context(now: datetime = NOW, **more: Any) -> Context:
    values: dict[str, Any] = {"cfg": CFG, "as_at": now}
    values.update(more)
    return Context(**values)


def settings() -> Settings:
    return Settings()


async def pair_evidence(
    owner: AsyncEngine, inv: uuid.UUID, server: str, n: int, when: datetime
) -> None:
    params = {
        "host": HOST,
        "destination": server,
        "start": (when - timedelta(hours=1)).isoformat(),
        "end": (when + timedelta(hours=5)).isoformat(),
    }
    snapshot = {"aggregations": {"requests": {"value": n}, "bytes": {"value": 123_000}}}
    key = uuid.uuid4().hex + uuid.uuid4().hex
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO evidence_requests (investigation_id, eid, task_key, template,"
                " template_version, origin, first_version, created_at) VALUES (:i,"
                " (SELECT coalesce(max(eid), 0) + 1 FROM evidence_requests WHERE investigation_id"
                " = :i), :k, 'proxy.pair', 1, 'pack', 1, :t)"
            ),
            {"i": inv, "k": key, "t": when},
        )
        await conn.execute(
            text(
                "INSERT INTO evidence (investigation_id, version, task_key, template,"
                " template_version, params, status, coverage, row_count, snapshot, result_hash,"
                " collected_at) VALUES (:i, 1, :k, 'proxy.pair', 1, CAST(:p AS jsonb), 'ok',"
                " '{}'::jsonb, :n, CAST(:s AS jsonb), :h, :t)"
            ),
            {
                "i": inv, "k": key, "p": json.dumps(params),
                "n": n, "s": json.dumps(snapshot), "h": "f" * 64, "t": when,
            },
        )  # fmt: skip


async def propose(owner: AsyncEngine, inv: uuid.UUID, outcome: str = "true_positive") -> None:
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO assessments (investigation_id, version, pack, dossier_hash, view_hash,"
                " assessor, run_after, status, outcome, confidence, reasons, finished_at)"
                " SELECT :i, i.version, 'generic@12', repeat('a', 64), repeat('b', 64), 'agent@1',"
                " now(), 'proposed', :o, 0.8, '[]'::jsonb, now() FROM investigations i"
                " WHERE i.id = :i"
            ),
            {"i": inv, "o": outcome},
        )


async def rich_alerts(owner: AsyncEngine, inv: uuid.UUID, when: datetime) -> None:
    """Alerts that carry what a real alert does: the source and destination, the user agent."""
    doc = {
        "@timestamp": when.isoformat(),
        "source": {"ip": HOST},
        "destination": {"ip": SERVERS[0], "as": {"organization": {"name": "Example Hosting AB"}}},
        "user_agent": {"original": "Mozilla/5.0 (X11; Linux) Example"},
        "kibana.alert.rule.threat.technique.id": ["T1071"],
    }
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "UPDATE alert_records SET raw = CAST(:d AS jsonb) WHERE alert_id IN"
                " (SELECT alert_id FROM investigation_alerts WHERE investigation_id = :i)"
            ),
            {"d": json.dumps(doc), "i": inv},
        )


async def amadey(
    owner: AsyncEngine, app: AsyncEngine, person: Person, *, rules: list[tuple[str, int]] = RULES
) -> tuple[uuid.UUID, list[uuid.UUID]]:
    """The incident in the database: returns the case and its investigations."""
    for ip in SERVERS:
        await flag_server(owner, ip, day(0))
    invs: list[uuid.UUID] = []
    for n, (rule, offset) in enumerate(rules):
        when = day(offset)
        inv = await make(owner, when=when, rule=rule, flags=(BEACON, OUTSIDE), alerts=7)
        await rich_alerts(owner, inv, when)
        await pair_evidence(owner, inv, SERVERS[n % 4], 40 + n, when + timedelta(hours=1))
        await propose(owner, inv)
        invs.append(inv)
    case = await open_case(app, person, invs)
    return case, invs


async def write(engine: AsyncEngine, case: uuid.UUID, now: datetime = NOW) -> Any:
    """The case's report written as a pass would write it."""
    ctx = run.context_for(settings(), now)
    made = await run.make(engine, case, ctx)
    assert made is not None
    stored, new = await run.write(engine, made, "test-key", now)
    assert stored is not None
    return stored, new
