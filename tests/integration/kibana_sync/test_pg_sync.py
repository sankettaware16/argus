"""The read-back on Postgres as the runtime role (migration 0030): a whole cycle against the
fake Kibana with ``PgSyncStore``; the mirror adopted through its ARGUS case's sent create;
findings once each; a case's pause set by the runtime and lifted only by the owner; cycles
and findings append-only for the runtime; known alerts and WA rows read for discovery."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.machine import Open
from argus.cases.model import Member
from argus.cases.service import CaseService
from argus.kibana_sync.model import Kind
from argus.kibana_sync.store import PgSyncStore
from tests.integration.cases.conftest import Person, investigation, make_person
from tests.integration.cases.test_crash import _kibana
from tests.unit.kibana_sync.fake import Rig, rig

PERSON = "ra-anita"


async def _case_with_a_sent_create(app: AsyncEngine, owner: AsyncEngine, asha: Person) -> uuid.UUID:
    inv = await investigation(owner, actor=(("source.ip", "10.9.0.1"),))
    async with app.begin() as conn:
        applied = await (await CaseService.start(conn)).open(
            _kibana(asha), Open("A case", "high", "person", (Member(inv, "person"),))
        )
    case_id = applied.case.id
    async with owner.begin() as conn:  # the writer (Q-D4) sent its create
        for state in ("approved", "sending", "sent"):
            await conn.execute(
                text(
                    "UPDATE kibana_outbox SET state = :s, sent_count = sent_count"
                    " + CASE WHEN :s = 'sending' THEN 1 ELSE 0 END"
                    " WHERE case_id = :c AND op = 'create'"
                ),
                {"s": state, "c": case_id},
            )
    return case_id


def _pg_rig(app: AsyncEngine) -> Rig:
    r = rig()
    r.store = PgSyncStore(app)  # type: ignore[assignment]
    r.syncer.store = r.store  # type: ignore[assignment]
    return r


async def _findings(engine: AsyncEngine) -> list[str]:
    async with engine.connect() as conn:
        return sorted(r[0] for r in await conn.execute(text("SELECT kind FROM kibana_findings")))


async def test_a_whole_cycle_on_postgres_as_the_runtime(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    asha = await make_person(app_engine, "asha")
    case_id = await _case_with_a_sent_create(app_engine, migrated_engine, asha)
    r = _pg_rig(app_engine)
    kid = r.kibana.create(argus_case=case_id)
    record = await r.cycle()
    assert record.outcome == "complete", record.reason
    mirrors = await r.store.mirrors()  # type: ignore[attr-defined]
    assert mirrors[kid].case_id == case_id
    assert dict(mirrors[kid].argus_actions) == {"create": 1}
    r.kibana.comment(kid, PERSON, "hello")
    r.kibana.add_tags(kid, PERSON, "argus:owner:ra-anita")
    await r.cycle()
    assert await _findings(app_engine) == [Kind.ARGUS_TAGS_CHANGED, Kind.PERSON_COMMENTED]
    await r.cycle()
    assert len(await _findings(app_engine)) == 2, "each finding once"
    async with app_engine.connect() as conn:
        paused = (await conn.execute(text("SELECT paused_reason FROM kibana_mirror"))).scalar()
        cycles = (await conn.execute(text("SELECT count(*) FROM kibana_sync_cycles"))).scalar()
        state = (await conn.execute(text("SELECT * FROM kibana_sync_state"))).one()
    assert paused == "a person changed ARGUS's tags in Kibana"
    assert cycles == 3
    assert state.last_complete_at is not None
    assert state.changes_from is not None
    # the runtime may pause, never lift a pause
    with pytest.raises(DBAPIError, match="only the owner lifts"):
        async with app_engine.begin() as conn:
            await conn.execute(text("UPDATE kibana_mirror SET paused_reason = NULL"))
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE kibana_mirror SET paused_reason = NULL"))
    # a delete is confirmed by a get, then recorded
    r.kibana.delete(kid)
    await r.cycle()
    assert Kind.DELETED_IN_KIBANA in await _findings(app_engine)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE kibana_findings SET resolved_at = now()",
        "DELETE FROM kibana_findings",
        "UPDATE kibana_sync_cycles SET outcome = 'complete'",
        "DELETE FROM kibana_sync_cycles",
        "DELETE FROM kibana_mirror",
        "DELETE FROM kibana_people_cases",
        "INSERT INTO kibana_sync_state (id) VALUES (2)",
    ],
)
async def test_what_the_runtime_may_not_do(app_engine: AsyncEngine, statement: str) -> None:
    with pytest.raises(DBAPIError, match="permission denied"):
        async with app_engine.begin() as conn:
            await conn.execute(text(statement))


async def test_known_alerts_rotate_and_wa_rows_explain(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    now = datetime.now(UTC)
    async with migrated_engine.begin() as conn:
        for n in range(5):
            await conn.execute(
                text(
                    "INSERT INTO alert_records (alert_id, index, status, normalizer_version, raw,"
                    " content_hash, state_hash, recovered_by, first_seen_at) VALUES (:a,"
                    " 'alerts', 'normalized', 't', '{}', 'h', 'h', 'live', :at)"
                ),
                {"a": f"al-{n}", "at": now - timedelta(minutes=n)},
            )
        await conn.execute(
            text(
                "INSERT INTO writeback_outbox (review_id, investigation_id, status, alert_ids,"
                " state, sent_count) VALUES (1, :i, 'closed', ARRAY['al-1','al-2'], 'sent', 1)"
            ),
            {"i": uuid.uuid4()},
        )
    store = PgSyncStore(app_engine)
    first = await store.known_alerts(None, now - timedelta(hours=1), 2)
    assert [a for a, _ in first] == ["al-4", "al-3"]
    rest = await store.known_alerts(first[-1][1], now - timedelta(hours=1), 10)
    assert [a for a, _ in rest] == ["al-2", "al-1", "al-0"]
    assert await store.explained_alerts(["al-0", "al-1", "al-2"]) == {"al-1", "al-2"}


async def test_doctor_names_a_missing_case_pause_guard(migrated_engine: AsyncEngine) -> None:
    from argus.db import migrate

    assert await migrate.missing_resume_triggers(migrated_engine) == []
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("ALTER TABLE kibana_mirror DISABLE TRIGGER kibana_mirror_resume_needs_owner")
        )
    missing = await migrate.missing_resume_triggers(migrated_engine)
    assert any("kibana_mirror_resume_needs_owner" in m for m in missing)


async def test_alert_states_are_kept_for_the_next_discovery(app_engine: AsyncEngine) -> None:
    from argus.kibana_sync.model import AlertState

    store = PgSyncStore(app_engine)
    now = datetime.now(UTC)
    await store.save_alert_states([AlertState("al-1", "open", None, None, now)])
    await store.save_alert_states([AlertState("al-1", "closed", "ra", now, now)])
    got = await store.alert_states(["al-1", "al-9"])
    assert list(got) == ["al-1"]
    assert (got["al-1"].status, got["al-1"].user) == ("closed", "ra")
    assert await store.alert_states([]) == {}


async def test_the_read_only_days_report_reads_cycles_requests_and_lags(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    from argus.kibana_sync.cli import report
    from argus.kibana_sync.store import CycleRecord

    store = PgSyncStore(app_engine)
    now = datetime.now(UTC)
    for outcome, stale in (("complete", False), ("complete", False), ("partial", True)):
        await store.record_cycle(
            CycleRecord(now, now, outcome, None, "normal", 3, 0, 0, 10, stale, 250)
        )
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO siem_requests (at, component, purpose, template, version, indices,"
                " outcome, http_status, took_ms, elapsed_ms, response_bytes, attempts, lane,"
                " target) VALUES (:at, 'kibana-sync', 'kibana_read', 'cases.find', 1, '{}',"
                " 'ok', 200, 100, 40, 10, 1, 'kibana_read', 'kibana')"
            ),
            {"at": now},
        )
    lines = await report(app_engine, now - timedelta(hours=1))
    text_ = "\n".join(lines)
    assert "cycles: 3, complete 2 (66.7 %" in text_
    assert "staleness breaches: 1" in text_
    assert "of them writes: 0" in text_
    assert "cases.find (kibana): 1, 100 ms charged, p95 round trip 40 ms" in text_
    assert "n = 0" in text_
