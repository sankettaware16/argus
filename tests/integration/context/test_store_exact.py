"""Exact behaviour of the context store and the checkpoint saver (R8), pinned where mutation
testing found the other tests too loose."""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import DatabaseSettings
from argus.context import store
from argus.context.checkpoints import open_saver
from argus.jobs import queue
from tests.integration.context.conftest import NOW, seed
from tests.integration.grouping.test_grouping import doc, ingest

pytestmark = pytest.mark.integration


async def row(engine: AsyncEngine, query: str, **params: Any) -> Any:
    async with engine.connect() as conn:
        return (await conn.execute(text(query), params)).one()


async def facts_of(engine: AsyncEngine, inv: uuid.UUID) -> dict[str, Any]:
    async with engine.connect() as conn:
        return await store.load_facts(conn, inv)


def test_the_bounds() -> None:
    assert (store.SAMPLE_ALERTS, store.ENTITY_SAMPLE, store.VALUE_CHARS) == (10, 20, 256)
    assert (store.RELATED, store.SUPERNODE) == (20, 200)


async def test_the_facts_digest_field_by_field(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    (inv,) = await seed(app_engine, [(1, "r1", "10.0.0.1")])
    await ingest(app_engine, [doc(2, "r1", "10.0.0.1", NOW - timedelta(minutes=58))])
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE investigations SET rule_name = :n, group_key = :k,"
                                " severity = 'high', risk_score = 73.5, last_event_at ="
                                " first_event_at + interval '125 seconds'"),
                           {"n": "n" * 300, "k": "k" * 600})  # fmt: skip
    i = await row(app_engine, "SELECT * FROM investigations")
    facts = await facts_of(app_engine, inv)
    assert facts == {
        "investigation_id": str(inv),
        "version": i.version,
        "rule_id": "r1",
        "rule_name": "n" * 256,
        "group_key": "k" * 512,
        "bucket_start": i.bucket_start.isoformat(),
        "bucket_end": i.bucket_end.isoformat(),
        "alert_count": 2,
        "duplicate_count": 0,
        "late_arrivals": 0,
        "first_event_at": i.first_event_at.isoformat(),
        "last_event_at": (i.first_event_at + timedelta(seconds=125)).isoformat(),
        "span_minutes": 2,
        "severity": "high",
        "risk_score": 73.5,
        "continues_id": None,
        "sample_alerts": [f"{1:040x}", f"{2:040x}"],
        "entity_counts": facts["entity_counts"],
        "entities": facts["entities"],
    }
    assert facts["entity_counts"]["ip"] >= 1
    assert "10.0.0.1" in facts["entities"]["ip"]
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE investigations SET rule_name = NULL,"
                                " first_event_at = NULL, continues_id = :c"),
                           {"c": uuid.UUID(int=7)})  # fmt: skip
    facts = await facts_of(app_engine, inv)
    assert (facts["rule_name"], facts["span_minutes"]) == (None, None)
    assert facts["continues_id"] == str(uuid.UUID(int=7))
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE investigations SET first_event_at = last_event_at,"
                                " last_event_at = NULL"))  # fmt: skip
    assert (await facts_of(app_engine, inv))["span_minutes"] is None


async def test_a_missing_investigation_is_refused(app_engine: AsyncEngine) -> None:
    with pytest.raises(store.MissingInvestigation, match=str(uuid.UUID(int=1))):
        await facts_of(app_engine, uuid.UUID(int=1))


async def test_related_investigations_exactly_and_within_the_window(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await seed(app_engine, [(1, "r1", "10.0.0.1"), (2, "r2", "10.0.0.1"), (3, "r3", "10.0.0.9")])
    async with app_engine.connect() as conn:
        rows = await conn.execute(text("SELECT id, rule_id, bucket_start FROM investigations"))
        ids = {r.rule_id: r for r in rows.all()}
    facts = await facts_of(app_engine, ids["r1"].id)
    async with app_engine.connect() as conn:
        context = await store.local_context(conn, facts, timedelta(days=5))
    by_rule = {r["rule_id"]: r for r in context["related"]}
    assert [r["rule_id"] for r in context["related"]] == ["r2", "r3"]  # strongest first
    assert by_rule["r2"]["shared"] > by_rule["r3"]["shared"] >= 1  # r2 also shares the IP
    assert by_rule["r2"] == {"investigation_id": str(ids["r2"].id), "rule_id": "r2",
                             "bucket_start": ids["r2"].bucket_start.isoformat(),
                             "shared": by_rule["r2"]["shared"]}  # fmt: skip
    assert (context["related_total"], context["supernode_entities"]) == (2, 0)
    assert context["continues"] is None
    assert set(context) == {"related", "related_total", "supernode_entities", "continues"}
    day = timedelta(days=1)
    for moved, related in ((-5 * day, 2), (-5 * day - timedelta(seconds=1), 1), (day, 1),
                           (day - timedelta(seconds=1), 2)):  # fmt: skip
        async with migrated_engine.begin() as conn:
            await conn.execute(text("UPDATE investigations SET bucket_start = :s,"
                                    " bucket_end = :s + interval '2 days' WHERE rule_id = 'r2'"),
                               {"s": ids["r1"].bucket_start + moved})  # fmt: skip
        async with app_engine.connect() as conn:
            got = await store.local_context(conn, facts, timedelta(days=5))
        assert got["related_total"] == related, moved
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE entities SET investigations = 201"))
    async with app_engine.connect() as conn:
        got = await store.local_context(conn, facts, timedelta(days=5))
    assert (got["related"], got["related_total"]) == ([], 0)
    assert got["supernode_entities"] == facts["entity_counts"]["ip"] + sum(
        n for k, n in facts["entity_counts"].items() if k != "ip"
    )


async def test_evidence_refs_and_lookups(app_engine: AsyncEngine) -> None:
    (inv,) = await seed(app_engine, [(1, "r1", "10.0.0.1")])
    record = {
        "investigation_id": inv, "version": 1, "task_key": "a" * 64, "template": "t",
        "template_version": 3, "params": {"n": 1}, "status": "ok", "coverage": {},
        "source_watermark": None, "row_count": 4, "truncated": True, "snapshot": {"rows": []},
        "result_hash": "h", "took_ms": 9, "reused_from_version": None, "error": None,
        "collected_at": NOW,
    }  # fmt: skip
    with pytest.raises(IntegrityError, match="evidence_requests"):  # Q-F2: no row without its E-id
        async with app_engine.begin() as conn:
            await store.write_evidence(conn, record)
    task = {"task_key": "a" * 64, "template": "t", "version": 3}
    async with app_engine.begin() as conn:
        assert await store.register_requests(conn, inv, 1, [task], "pack", NOW) == {"a" * 64: 1}
        stored = await store.write_evidence(conn, record)
        assert await store.reusable(conn, inv, []) == {}
        assert await store.reusable(conn, inv, ["a" * 64, "b" * 64]) == {"a" * 64: 1}
        assert await store.snapshots(conn, inv, 1, ["a" * 64]) == {"a" * 64: {"rows": []}}
        assert await store.snapshots(conn, inv, 2, ["a" * 64]) == {}
    assert store.ref_of(stored, reused=True) == {
        "task_key": "a" * 64, "template": "t@3", "status": "ok", "coverage": {},
        "row_count": 4, "truncated": True, "result_hash": "h", "reused": True,
    }  # fmt: skip


async def test_persist_audits_and_reports_a_requeue(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    (inv,) = await seed(app_engine, [(1, "r1", "10.0.0.1")])
    async with app_engine.begin() as conn:
        (job,) = await queue.claim(conn, "w", NOW)
    await ingest(app_engine, [doc(2, "r1", "10.0.0.1", NOW - timedelta(minutes=50))])
    dossier = {"facts_version": 1, "run_kind": "collect", "family": "generic", "pack": "stub@1",
               "status": "evidence_ready", "partial_reason": None, "hash": "c" * 64,
               "body": {"evidence": []}}  # fmt: skip
    async with app_engine.begin() as conn:
        again = await store.persist_dossier(conn, job, dossier, [], NOW)
    assert again is True  # the investigation changed while it ran
    audit = await row(
        app_engine,
        "SELECT actor, action, target_type, target_id, details FROM audit_events"
        " WHERE action = 'dossier.persist'",
    )
    assert (audit.actor, audit.action, audit.target_type, audit.target_id) == (
        "worker",
        "dossier.persist",
        "investigation",
        str(inv),
    )
    assert audit.details == {"version": 1, "job": job.job_id, "status": "evidence_ready",
                             "hash": "c" * 16, "requeued": True, "existing": False}  # fmt: skip
    async with migrated_engine.begin() as conn:  # run again for the same version
        await conn.execute(text("DELETE FROM jobs WHERE id <> :id"), {"id": job.job_id})
        await conn.execute(text("UPDATE jobs SET status = 'running', lease_owner = 'w',"
                                " lease_until = :u WHERE id = :id"),
                           {"u": NOW + queue.LEASE, "id": job.job_id})  # fmt: skip
    async with app_engine.begin() as conn:
        assert await store.persist_dossier(conn, job, dossier, [], NOW) is True
    details = (
        await row(
            app_engine,
            "SELECT details FROM audit_events WHERE action ="
            " 'dossier.persist' ORDER BY id DESC LIMIT 1",
        )
    ).details
    assert details["existing"] is True
    other = {**dossier, "hash": "d" * 64}
    with pytest.raises(store.DossierConflict) as info:
        async with app_engine.begin() as conn:
            await store.persist_dossier(conn, job, other, [], NOW)
    assert str(info.value) == f"{inv} v1: stored {'c' * 12}, new {'d' * 12}"


async def test_the_saver_pool(
    db_settings: DatabaseSettings, test_database: str, app_engine: AsyncEngine
) -> None:
    async with open_saver(db_settings, database=test_database) as saver:
        pool: Any = saver.conn
        assert (pool.min_size, pool.max_size) == (1, 4)
        async with pool.connection() as conn:
            assert conn.autocommit is True
            assert conn.prepare_threshold == 0
            got = await (await conn.execute(
                "SELECT current_setting('application_name') AS a,"
                " (SELECT setting FROM pg_settings WHERE name = 'statement_timeout') AS s,"
                " current_setting('search_path') AS p, current_setting('TimeZone') AS z,"
                " current_setting('idle_in_transaction_session_timeout') AS i,"
                " current_user AS u")).fetchone()  # fmt: skip
        timeout = int(db_settings.statement_timeout.total_seconds() * 1000)
        assert got == {"a": "argus-checkpoints", "s": str(timeout), "p": "langgraph,pg_temp",
                       "z": "UTC", "i": "1min", "u": db_settings.user}  # fmt: skip
    assert pool.closed
    async with open_saver(db_settings, database=test_database, max_size=2) as saver:
        assert saver.conn.max_size == 2  # type: ignore[union-attr]
