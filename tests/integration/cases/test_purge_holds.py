"""The retention purge's legal hold (Q-A4, DQ27) with real cases: an open case, and a closed one
whose approval request has not expired, keep everything of their investigations; a closed case
keeps only its investigations' rows (case records are never purged in Phase 3), and so does
one whose approval request has expired; an investigation in no case goes."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.machine import Dismiss, Open
from argus.cases.model import Actor, Member
from argus.cases.service import CaseService
from argus.config.settings import Settings
from argus.ops import purge
from tests.integration.cases.conftest import Person, investigation, rows
from tests.integration.cases.test_service import (
    _apply,
    _chains_ok,
    _decide,
    _kibana_actor,
    _open,
    _request,
)


async def _age(engine: AsyncEngine, user: int) -> None:
    """Every investigation 200 days old, reviewed 100 days ago, with one evidence snapshot."""
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "UPDATE alert_records SET detected_at = detected_at - interval '200 days',"
                " first_seen_at = first_seen_at - interval '200 days'"
            )
        )
        await conn.execute(
            text(
                "UPDATE investigations SET bucket_start = bucket_start - interval '200 days',"
                " bucket_end = bucket_end - interval '200 days'"
            )
        )
        for (inv,) in (await conn.execute(text("SELECT id FROM investigations"))).all():
            key = hashlib.sha256(str(inv).encode()).hexdigest()
            await conn.execute(
                text(
                    "INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                    " action, outcome, created_at) VALUES (:i, 1, 2, :u, 'reviewed',"
                    " 'benign_expected', now() - interval '100 days')"
                ),
                {"i": inv, "u": user},
            )
            await conn.execute(
                text(
                    "INSERT INTO evidence_requests (investigation_id, eid, task_key, template,"
                    " template_version, origin, first_version, created_at)"
                    " VALUES (:i, 1, :k, 'proxy.pair', 1, 'pack', 1, now())"
                ),
                {"i": inv, "k": key},
            )
            await conn.execute(
                text(
                    "INSERT INTO evidence (investigation_id, version, task_key, template,"
                    " template_version, params, status, coverage, snapshot, result_hash,"
                    " collected_at) VALUES (:i, 1, :k, 'proxy.pair', 1, '{}', 'ok', '{}',"
                    " '{\"rows\": [1]}', :k, now())"
                ),
                {"i": inv, "k": key},
            )


async def _state(engine: AsyncEngine, inv: uuid.UUID) -> tuple[bool, int, int]:
    """(the investigation is there, its alerts with raw data, its evidence snapshots)."""
    found = await rows(engine, "SELECT 1 FROM investigations WHERE id = :i", i=inv)
    raw = await rows(
        engine,
        "SELECT a.alert_id FROM alert_records a JOIN investigation_alerts l"
        " ON l.alert_id = a.alert_id WHERE l.investigation_id = :i AND a.raw_purged_at IS NULL",
        i=inv,
    )
    snaps = await rows(
        engine,
        "SELECT 1 FROM evidence WHERE investigation_id = :i AND snapshot IS NOT NULL",
        i=inv,
    )
    return bool(found), len(raw), len(snaps)


async def test_open_cases_and_pending_approvals_hold_everything(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    asha, ravi = people["asha"], people["ravi"]
    in_open = await investigation(migrated_engine, rule="r-open")
    in_pending = await investigation(migrated_engine, rule="r-pending")
    in_closed = await investigation(migrated_engine, rule="r-closed")
    free = await investigation(migrated_engine, rule="r-free")
    await _open(api_engine, _kibana_actor(asha), [in_open])
    pending = await _open(api_engine, _kibana_actor(asha), [in_pending])
    await _decide(api_engine, ravi, await _request(api_engine, asha, pending, 1))
    async with migrated_engine.begin() as conn:
        proposal = (
            await conn.execute(
                text(
                    "INSERT INTO assessments (investigation_id, version, pack, dossier_hash,"
                    " view_hash, assessor, run_after, status, outcome) VALUES (:i, 1, 'p',"
                    " repeat('a', 64), repeat('b', 64), 'agent', now(), 'proposed',"
                    " 'true_positive') RETURNING id"
                ),
                {"i": in_closed},
            )
        ).scalar_one()
    async with api_engine.begin() as conn:
        service = await CaseService.start(conn)
        suspected = await service.open(
            Actor.argus("opener"),
            Open("Suspected beacon", "medium", "proposal", (Member(in_closed, "proposal"),),
                 suspected=True, cause_assessment_id=proposal),
        )  # fmt: skip
    await _apply(api_engine, asha.actor(), suspected.case.id, Dismiss("benign_expected", "ok"), 1)
    states = {str(c.state) for c in await rows(api_engine, "SELECT state FROM cases")}
    assert states == {"open", "closed"}
    await _age(migrated_engine, asha.user_id)
    records = "SELECT (SELECT count(*) FROM case_events) + (SELECT count(*) FROM case_members)"
    before = await rows(api_engine, records)

    cut = purge.cutoffs(Settings(), datetime.now(UTC))
    outcome = await purge.run(migrated_engine, cut)
    assert purge.differences(outcome.planned, outcome.done) == []
    assert outcome.holds_intact
    assert outcome.holds_before["held"] == 2  # memory keeps 3: the closed case's one too
    assert await _state(migrated_engine, in_open) == (True, 2, 1)
    assert await _state(migrated_engine, in_pending) == (True, 2, 1)
    assert await _state(migrated_engine, in_closed) == (True, 0, 0)  # case records keep it
    assert await _state(migrated_engine, free) == (False, 0, 0)
    done = outcome.done.changed
    assert done["raw_source"]["alert_records.raw"] == 4  # the closed case's and the free ones
    assert outcome.done.held == {"raw_source": 4, "quarantine": 0, "evidence": 2, "memory": 3}
    assert done["memory"]["investigations"] == 1
    # the case records are as they were, and both hash chains still verify
    assert await rows(api_engine, records) == before
    await _chains_ok(api_engine)
    # 73 hours on, the closure's approval request has expired (at most 72 h): the closed case
    # holds nothing more; its investigation keeps its row (case records), not its data
    later = purge.cutoffs(Settings(), datetime.now(UTC) + timedelta(hours=73))
    expired = await purge.run(migrated_engine, later)
    assert expired.holds_intact, expired.holds_changed
    assert expired.holds_before["held"] == 1
    assert await _state(migrated_engine, in_pending) == (True, 0, 0)
    assert await _state(migrated_engine, in_open) == (True, 2, 1)
    assert await rows(api_engine, records) == before
