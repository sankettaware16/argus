"""The audit hash chain (Q-C1, plan §7.9): the owner's trigger, the legacy seal, and
``argus audit verify`` catching every kind of tampering."""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

import argus.db.migrate as migrate
from argus.cases import chain
from argus.db.audit import record_audit
from argus.db.engine import session_factory


async def _audit(engine: AsyncEngine, n: int = 1, **kwargs: object) -> list[int]:
    ids = []
    for i in range(n):
        async with session_factory(engine)() as session, session.begin():
            event = await record_audit(
                session,
                **{"actor": "test", "action": f"unit.test{i}", "details": {"i": i}, **kwargs},  # type: ignore[arg-type]
            )
            ids.append(event.id)
    return ids


async def _verify(engine: AsyncEngine, name: str = "audit_events") -> chain.ChainReport:
    async with engine.connect() as conn:
        return await chain.verify(conn, name, batch=7)


async def _owner(engine: AsyncEngine, *statements: str) -> None:
    async with engine.begin() as conn:
        for statement in statements:
            await conn.execute(text(statement))


async def test_a_fresh_database_has_two_empty_chains(migrated_engine: AsyncEngine) -> None:
    async with migrated_engine.connect() as conn:
        assert await chain.heads(conn) == {
            "audit_events": (0, chain.seal([])[0]),
            "case_events": (0, chain.CASE_EVENTS_GENESIS),
        }
        reports = await chain.verify_all(conn)
    assert [r.ok for r in reports] == [True, True]
    assert reports[0].summary() == f"0 rows chained; head 0 {chain.seal([])[0][:16]}"


async def test_every_audit_row_is_chained_by_the_database(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    ids = await _audit(app_engine, 12, target_id="ünïcode 🙂", correlation_id=None)
    async with migrated_engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT id, occurred_at, actor, action, outcome, target_type, target_id,"
                    " correlation_id, details::text AS details, chain_seq, prev_hash, row_hash"
                    " FROM audit_events ORDER BY chain_seq"
                )
            )
        ).all()
    assert [r.id for r in rows] == ids
    prev = chain.seal([])[0]
    for seq, r in enumerate(rows, start=1):
        row = chain.AuditRow(*r[:9])
        assert (r.chain_seq, r.prev_hash) == (seq, prev)
        assert r.row_hash == chain.digest(chain.audit_message(seq, prev, row))
        prev = r.row_hash
    report = await _verify(app_engine)  # the runtime role can verify (read only)
    assert (report.ok, report.chained, report.head_seq, report.head_hash) == (True, 12, 12, prev)


async def test_the_runtime_role_cannot_write_the_chain(app_engine: AsyncEngine) -> None:
    for statement in (
        "INSERT INTO audit_events (actor, action, chain_seq) VALUES ('a', 'b', 1)",
        "INSERT INTO audit_events (actor, action, row_hash) VALUES ('a', 'b', 'x')",
        "UPDATE chain_heads SET seq = 0",
        "INSERT INTO chain_heads (chain, seq, head_hash, genesis_hash, legacy_rows,"
        " legacy_max_id) VALUES ('x', 0, 'a', 'a', 0, 0)",
        "DELETE FROM chain_heads",
    ):
        with pytest.raises(DBAPIError, match="permission denied"):
            async with app_engine.begin() as conn:
                await conn.execute(text(statement))
    async with app_engine.connect() as conn:  # a trigger of its own on a temporary table
        await conn.execute(text("CREATE TEMP TABLE audit_events (id int)"))
        with pytest.raises(DBAPIError, match="permission denied for function"):
            await conn.execute(
                text(
                    "CREATE TRIGGER t BEFORE INSERT ON pg_temp.audit_events FOR EACH ROW"
                    " EXECUTE FUNCTION public.argus_chain_append()"
                )
            )


async def test_the_owner_cannot_supply_its_own_chain_values(migrated_engine: AsyncEngine) -> None:
    await _owner(
        migrated_engine,
        "INSERT INTO audit_events (actor, action, chain_seq, prev_hash, row_hash)"
        " VALUES ('a', 'b', 99, 'forged', 'forged')",
    )
    assert (await _verify(migrated_engine)).ok
    async with migrated_engine.connect() as conn:
        seq = (await conn.execute(text("SELECT chain_seq FROM audit_events"))).scalar_one()
    assert seq == 1


def _legacy_rows() -> list[tuple[str, str, str | None, str | None, dict[str, object]]]:
    return [
        ("cli", "db.upgrade", None, None, {}),
        ("worker", "dossier.persist", "investigation", str(uuid.uuid4()), {"v": 1, "h": "ab"}),
        ("user:asha", "login", None, None, {"client": "10.0.0.1", "z": [1, 2.5, None, True]}),
        ("web", "login", None, "ünïcode ​", {"username": "x", "nested": {"a": {"b": "c"}}}),
    ]


async def test_rows_before_the_chain_are_sealed_into_its_genesis(empty_engine: AsyncEngine) -> None:
    await migrate.upgrade(empty_engine, "0025")
    async with empty_engine.begin() as conn:
        for actor, action, target_type, target_id, details in _legacy_rows():
            await conn.execute(
                text(
                    "INSERT INTO audit_events (actor, action, target_type, target_id, details)"
                    " VALUES (:a, :b, :t, :i, CAST(:d AS jsonb))"
                ),
                {"a": actor, "b": action, "t": target_type, "i": target_id,
                 "d": json.dumps(details)},
            )  # fmt: skip
    await migrate.upgrade(empty_engine)
    async with empty_engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT id, occurred_at, actor, action, outcome, target_type, target_id,"
                    " correlation_id, details::text AS details FROM audit_events ORDER BY id"
                )
            )
        ).all()
        head = (
            await conn.execute(text("SELECT * FROM chain_heads WHERE chain = 'audit_events'"))
        ).one()
    expected, count = chain.seal(chain.AuditRow(*r) for r in rows)
    assert (head.genesis_hash, head.head_hash, head.legacy_rows, head.seq) == (
        expected,
        expected,
        count,
        0,
    )
    assert count == 4
    assert head.legacy_max_id == rows[-1].id
    await _audit(empty_engine, 3)
    report = await _verify(empty_engine)
    assert (report.ok, report.legacy, report.chained) == (True, 4, 3)


async def _tampered(engine: AsyncEngine, *statements: str) -> list[str]:
    """Run ``statements`` as the owner with the append-only guards off (what someone holding the
    owner's password could do), then verify."""
    await _owner(
        engine,
        "ALTER TABLE audit_events DISABLE TRIGGER audit_events_append_only_rows",
        *statements,
        "ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_append_only_rows",
    )
    report = await _verify(engine)
    assert not report.ok
    return report.problems


@pytest.fixture
async def chained(empty_engine: AsyncEngine) -> AsyncEngine:
    """Two legacy rows, then five chained ones."""
    await migrate.upgrade(empty_engine, "0025")
    await _owner(
        empty_engine,
        "INSERT INTO audit_events (actor, action) VALUES ('old', 'one'), ('old', 'two')",
    )
    await migrate.upgrade(empty_engine)
    await _audit(empty_engine, 5)
    assert (await _verify(empty_engine)).ok
    return empty_engine


async def test_verify_catches_a_changed_row(chained: AsyncEngine) -> None:
    problems = await _tampered(
        chained, "UPDATE audit_events SET actor = 'mallory' WHERE chain_seq = 3"
    )
    assert problems == ["audit_events: row 3 (id 5) was changed after it was written"]


@pytest.mark.parametrize(
    "change",
    [
        "details = details || '{\"x\": 1}'",
        "occurred_at = occurred_at + interval '1 microsecond'",
        "outcome = 'denied'",
        "target_type = 'case'",
        "correlation_id = ''",
    ],
)
async def test_verify_catches_a_change_to_any_field(chained: AsyncEngine, change: str) -> None:
    statement = f"UPDATE audit_events SET {change} WHERE chain_seq = 5"  # noqa: S608 - a test
    problems = await _tampered(chained, statement)
    assert problems == ["audit_events: row 5 (id 7) was changed after it was written"]


async def test_verify_catches_a_changed_row_whose_hash_was_recomputed(
    chained: AsyncEngine,
) -> None:
    """Recomputing the changed row's own hash breaks the link to the row after it."""
    problems = await _tampered(
        chained,
        "UPDATE audit_events SET actor = 'mallory', row_hash = encode(sha256("
        " argus_audit_message(chain_seq, prev_hash, id, occurred_at, 'mallory', action, outcome,"
        " target_type, target_id, correlation_id, details::text)), 'hex') WHERE chain_seq = 2",
    )
    assert problems == ["audit_events: row 3 (id 5) does not follow the row before it"]


async def test_verify_catches_a_removed_row(chained: AsyncEngine) -> None:
    problems = await _tampered(chained, "DELETE FROM audit_events WHERE chain_seq = 2")
    assert problems == [
        "audit_events: rows 2 to 2 of the chain are missing",
        "audit_events: row 3 (id 5) does not follow the row before it",
    ]


async def test_verify_catches_rows_removed_from_the_end(chained: AsyncEngine) -> None:
    problems = await _tampered(chained, "DELETE FROM audit_events WHERE chain_seq >= 4")
    assert problems == [
        "audit_events: the head says 5 rows, the chain has 3 (rows were removed from its end?)"
    ]


async def test_verify_catches_a_rolled_back_head(chained: AsyncEngine) -> None:
    await _owner(chained, "UPDATE chain_heads SET seq = 4 WHERE chain = 'audit_events'")
    report = await _verify(chained)
    assert report.problems == ["audit_events: the head says 4 rows, the chain has 5"]
    await _owner(chained, "UPDATE chain_heads SET seq = 5, head_hash = repeat('0', 64)")
    assert (await _verify(chained)).problems == [
        "audit_events: the head's hash is not the newest row's"
    ]


async def test_verify_catches_reordered_rows(chained: AsyncEngine) -> None:
    problems = await _tampered(
        chained,
        "UPDATE audit_events SET chain_seq = -chain_seq WHERE chain_seq IN (2, 3)",
        "UPDATE audit_events SET chain_seq = CASE chain_seq WHEN -2 THEN 3 ELSE 2 END"
        " WHERE chain_seq IN (-2, -3)",
    )
    assert "audit_events: row 2 (id 5) does not follow the row before it" in problems


async def test_verify_catches_a_changed_or_removed_legacy_row(chained: AsyncEngine) -> None:
    problems = await _tampered(chained, "UPDATE audit_events SET action = 'x' WHERE id = 1")
    assert problems == ["audit_events: a row written before the chain started was changed"]
    problems = await _tampered(chained, "DELETE FROM audit_events WHERE id = 2")
    assert problems == ["audit_events: 2 rows were sealed before the chain started, 1 are left"]


async def test_verify_catches_rows_written_with_the_chain_trigger_off(
    chained: AsyncEngine,
) -> None:
    await _owner(
        chained,
        "ALTER TABLE audit_events DISABLE TRIGGER audit_events_chain",
        "ALTER TABLE audit_events DISABLE TRIGGER audit_events_chain_head",
        "INSERT INTO audit_events (actor, action) VALUES ('sneaky', 'insert')",
        "ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_chain",
        "ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_chain_head",
    )
    assert (await _verify(chained)).problems == [
        "audit_events: 1 rows written after the chain started are not chained"
        " (written with its trigger off?)"
    ]
    assert await migrate.missing_guard_triggers(chained) == []


async def test_doctor_reports_a_disabled_chain_trigger(migrated_engine: AsyncEngine) -> None:
    await _owner(migrated_engine, "ALTER TABLE audit_events ENABLE TRIGGER audit_events_chain")
    assert await migrate.missing_guard_triggers(migrated_engine) == [
        "audit_events.audit_events_chain"
    ]


async def test_concurrent_writers_keep_one_chain(app_engine: AsyncEngine) -> None:
    async def writer(k: int) -> None:
        await _audit(app_engine, 5, actor=f"w{k}")

    await asyncio.gather(*(writer(k) for k in range(8)))
    report = await _verify(app_engine)
    assert (report.ok, report.chained) == (True, 40)


async def test_a_repeatable_read_writer_fails_rather_than_forks(
    app_engine: AsyncEngine,
) -> None:
    """A transaction whose snapshot predates the newest row cannot append: it would take a
    number already used (the unique index refuses it), so the chain never forks."""
    async with app_engine.connect() as first:
        await first.execution_options(isolation_level="REPEATABLE READ")
        await first.begin()
        await first.execute(text("SELECT 1 FROM chain_heads"))  # the snapshot is taken here
        await _audit(app_engine, 1)  # another transaction appends and commits
        with pytest.raises(DBAPIError, match=r"could not serialize|ix_audit_events_chain_seq"):
            await first.execute(
                text("INSERT INTO audit_events (actor, action) VALUES ('rr', 'late')")
            )
        await first.rollback()
    assert (await _verify(app_engine)).ok


_TEXT = st.one_of(st.none(), st.text(max_size=40))


@settings(
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    seq=st.one_of(st.none(), st.integers(min_value=0, max_value=2**62)),
    prev=_TEXT,
    row_id=st.integers(min_value=1, max_value=2**62),
    at=st.datetimes(
        min_value=datetime(2000, 1, 1),  # noqa: DTZ001 - hypothesis takes naive bounds
        max_value=datetime(2100, 1, 1),  # noqa: DTZ001
        timezones=st.just(UTC),
    ),
    values=st.tuples(
        st.text(min_size=1, max_size=20),
        st.text(min_size=1, max_size=20),
        st.text(max_size=10),
        _TEXT,
        _TEXT,
        _TEXT,
        st.text(max_size=60),
    ),
)
async def test_python_and_postgresql_build_the_same_audit_message(
    migrated_engine: AsyncEngine,
    seq: int | None,
    prev: str | None,
    row_id: int,
    at: datetime,
    values: tuple[str, str, str, str | None, str | None, str | None, str],
) -> None:
    clean = tuple(None if v is None else v.replace("\x00", "") for v in values)
    actor, action, outcome, target_type, target_id, correlation_id, details = clean
    prev = None if prev is None else prev.replace("\x00", "")
    row = chain.AuditRow(
        row_id, at, actor or "a", action or "b", outcome or "", target_type, target_id,
        correlation_id, details or "",
    )  # fmt: skip
    async with migrated_engine.connect() as conn:
        sql = (
            await conn.execute(
                text("SELECT argus_audit_message(:s, :p, :i, :t, :a, :b, :o, :tt, :ti, :c, :d)"),
                {
                    "s": seq,
                    "p": prev,
                    "i": row_id,
                    "t": at,
                    "a": row.actor,
                    "b": row.action,
                    "o": row.outcome,
                    "tt": target_type,
                    "ti": target_id,
                    "c": correlation_id,
                    "d": row.details,
                },
            )
        ).scalar_one()
    assert bytes(sql) == chain.audit_message(seq, prev, row)


def test_a_naive_time_is_refused() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        chain.chain_time(datetime(2026, 1, 1))  # noqa: DTZ001


def test_fields_are_self_delimiting() -> None:
    assert chain.chain_field(None) == b"N"
    assert chain.chain_field("") == b"S0:"
    assert chain.chain_field("é") == "S2:é".encode()
    # "ab" + "c" and "a" + "bc" give different bytes
    assert chain.chain_field("ab") + chain.chain_field("c") != chain.chain_field(
        "a"
    ) + chain.chain_field("bc")
    assert chain.chain_time(datetime(2026, 1, 2, 3, 4, 5, 6, tzinfo=UTC)) == (
        "2026-01-02T03:04:05.000006Z"
    )
    ist = datetime(2026, 1, 2, 8, 34, 5, tzinfo=UTC).astimezone(ZoneInfo("Asia/Kolkata"))
    assert chain.chain_time(ist) == "2026-01-02T08:34:05.000000Z"


async def test_many_rows_in_one_transaction_move_the_head_once(app_engine: AsyncEngine) -> None:
    """One statement writing 20,000 audit rows (a bulk review, say) stays linear."""
    async with app_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO audit_events (actor, action, details)"
                " SELECT 'bulk', 'review.reviewed',"
                " jsonb_build_object('n', g) FROM generate_series(1, 20000) g"
            )
        )
        await _audit_in(conn, 3)
    report = await _verify(app_engine)
    assert (report.ok, report.chained, report.head_seq) == (True, 20003, 20003)


async def _audit_in(conn: object, n: int) -> None:
    from sqlalchemy.ext.asyncio import AsyncSession

    session = AsyncSession(bind=conn)  # type: ignore[arg-type]
    try:
        for i in range(n):
            await record_audit(session, actor="test", action=f"same.transaction{i}")
    finally:
        await session.close()


async def test_a_removed_tail_stays_a_gap_after_more_writes(chained: AsyncEngine) -> None:
    await _tampered(chained, "DELETE FROM audit_events WHERE chain_seq >= 4")
    await _audit(chained, 2)  # the next rows follow the head (5), not the shortened end (3)
    report = await _verify(chained)
    assert report.problems == [
        "audit_events: rows 4 to 5 of the chain are missing",
        "audit_events: row 6 (id 8) does not follow the row before it",
    ]
    assert report.head_seq == 7


async def test_verify_reads_one_snapshot(app_engine: AsyncEngine) -> None:
    await _audit(app_engine, 3)
    reports = await chain.verify_snapshot(app_engine, batch=1)
    assert [r.ok for r in reports] == [True, True]
