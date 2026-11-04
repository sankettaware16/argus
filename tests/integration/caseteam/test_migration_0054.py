"""Migration 0054 (the review of AR7/AR8, D-201 to D-210): the poster's rotation
(``case_team_looks``, the writer's), what the sync saw of a posted case
(``case_team_reads``, the runtime's), the verdict comments' key that lets a comment first kept as
``unmatched`` get a second row when a person appears, and the doctor's check that every
append-only table of 0053 still has its guards."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.db import migrate
from tests.integration.cases.conftest import Person
from tests.integration.caseteam.kit import a_case

pytestmark = pytest.mark.integration
HASH = "a" * 64
NOW = datetime(2026, 10, 30, 9, 0, tzinfo=UTC)
SEEN = (
    "INSERT INTO case_team_seen (kibana_comment_id, text_hash, case_id, author, written_at,"
    " verdict, status, detail) VALUES ('c1', :h, :c, 'asha.k', now(), 'true_positive', :s, 'x')"
)


async def with_post(owner: AsyncEngine, app: AsyncEngine, person: Person) -> uuid.UUID:
    case = await a_case(owner, app, person)
    async with owner.begin() as conn:
        await conn.execute(
            text("INSERT INTO case_team_posts (case_id, incident_id) VALUES (:c, :i)"),
            {"c": case, "i": "ACME-IR-2026-1030-01"},
        )
    return case


async def test_the_writer_keeps_the_rotation_and_nobody_else_can_touch_it(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    case = await with_post(migrated_engine, app_engine, people["asha"])
    async with writer_engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO case_team_looks (case_id, examined_at) VALUES (:c, :t)"),
            {"c": case, "t": NOW},
        )
        await conn.execute(text("UPDATE case_team_looks SET examined_at = now()"))
        assert (await conn.execute(text("SELECT count(*) FROM case_team_looks"))).scalar_one() == 1
    with pytest.raises(ProgrammingError):  # a row is never deleted by the writer
        async with writer_engine.begin() as conn:
            await conn.execute(text("DELETE FROM case_team_looks"))
    with pytest.raises(ProgrammingError):  # and the runtime has no say in it
        async with app_engine.begin() as conn:
            await conn.execute(text("UPDATE case_team_looks SET examined_at = now()"))
    with pytest.raises(IntegrityError):  # a look is of a case that exists
        async with writer_engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO case_team_looks (case_id) VALUES (:c)"), {"c": uuid.uuid4()}
            )


async def test_the_runtime_keeps_what_the_sync_saw_and_the_writer_only_reads_the_verdicts(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    case = await with_post(migrated_engine, app_engine, people["asha"])
    insert = (
        "INSERT INTO case_team_reads (case_id, kibana_updated_at, comment_count) VALUES (:c, :t, 7)"
    )
    async with app_engine.begin() as conn:
        await conn.execute(text(insert), {"c": case, "t": NOW})
        await conn.execute(text("UPDATE case_team_reads SET comment_count = 9, read_at = now()"))
        await conn.execute(
            text(
                "INSERT INTO case_team_seen (kibana_comment_id, text_hash, case_id, author,"
                " written_at, verdict, status, counts) VALUES ('c1', :h, :c, 'asha.k', now(),"
                " 'true_positive', 'recorded', CAST('{\"labelled\": 5}' AS jsonb))"
            ),
            {"h": HASH, "c": case},
        )
    with pytest.raises(IntegrityError):  # a count is never negative
        async with app_engine.begin() as conn:
            await conn.execute(text("UPDATE case_team_reads SET comment_count = -1"))
    with pytest.raises(ProgrammingError):  # the writer reads it, it does not write it
        async with writer_engine.begin() as conn:
            await conn.execute(text("UPDATE case_team_reads SET comment_count = 1"))


async def test_a_comment_kept_as_unmatched_can_get_its_decided_row_and_no_status_twice(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    case = await with_post(migrated_engine, app_engine, people["asha"])
    async with app_engine.begin() as conn:
        await conn.execute(text(SEEN), {"h": HASH, "c": case, "s": "unmatched"})
        await conn.execute(text(SEEN), {"h": HASH, "c": case, "s": "recorded"})
    with pytest.raises(IntegrityError):  # the same status is the same row
        async with app_engine.begin() as conn:
            await conn.execute(text(SEEN), {"h": HASH, "c": case, "s": "recorded"})
    for sql in (
        "UPDATE case_team_seen SET detail = 'changed'",
        "DELETE FROM case_team_seen",
    ):  # and it stays append-only
        with pytest.raises(DBAPIError, match="append-only"):
            async with migrated_engine.begin() as conn:
                await conn.execute(text(sql))


async def test_the_clean_downgrade_is_refused_for_two_rows_of_a_comment_and_round_trips(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case = await with_post(migrated_engine, app_engine, people["asha"])
    async with migrated_engine.begin() as conn:
        await conn.execute(text(SEEN), {"h": HASH, "c": case, "s": "unmatched"})
        await conn.execute(text(SEEN), {"h": HASH, "c": case, "s": "ignored"})
    with pytest.raises(DBAPIError, match="two rows"):
        await migrate.downgrade(migrated_engine, "0053")
    assert await migrate.current_revision(migrated_engine) == "0065"
    async with migrated_engine.begin() as conn:  # the owner removes the second row
        await conn.execute(text("ALTER TABLE case_team_seen DISABLE TRIGGER USER"))
        await conn.execute(text("DELETE FROM case_team_seen WHERE status = 'ignored'"))
        await conn.execute(text("ALTER TABLE case_team_seen ENABLE TRIGGER USER"))
    await migrate.downgrade(migrated_engine, "0053")
    assert await migrate.current_revision(migrated_engine) == "0053"
    async with migrated_engine.connect() as conn:
        assert (
            await conn.execute(text("SELECT to_regclass('case_team_looks')"))
        ).scalar_one() is None
        columns = (
            (
                await conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns"
                        " WHERE table_name = 'case_team_seen'"
                    )
                )
            )
            .scalars()
            .all()
        )
    assert "counts" not in columns
    await migrate.upgrade(migrated_engine)
    assert await migrate.current_revision(migrated_engine) == "0065"


# --------------------------------------------------------------------------- the doctor's guards


def test_every_append_only_table_of_0053_is_in_the_doctors_lists() -> None:
    for table in ("case_team_approvals", "case_team_seen"):
        assert f"{table}_append_only_rows" in migrate.GUARD_TRIGGERS[table]
        assert (table, f"{table}_append_only_truncate") in migrate.CHECK_TRIGGERS
        assert (
            migrate.CHECK_TRIGGERS[(table, f"{table}_append_only_truncate")]
            == "argus_reject_truncate_unless_empty"
        )


@pytest.mark.parametrize("table", ["case_team_approvals", "case_team_seen"])
@pytest.mark.parametrize("which", ["rows", "truncate"])
async def test_the_doctor_notices_a_guard_that_is_off(
    table: str, which: str, migrated_engine: AsyncEngine
) -> None:
    assert await migrate.missing_guard_triggers(migrated_engine) == []
    name = f"{table}_append_only_{which}"
    async with migrated_engine.begin() as conn:
        await conn.execute(text(f"ALTER TABLE {table} DISABLE TRIGGER {name}"))
    assert await migrate.missing_guard_triggers(migrated_engine) == [f"{table}.{name}"]
