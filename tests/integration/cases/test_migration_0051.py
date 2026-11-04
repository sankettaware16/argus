"""Migration 0051 (AR4b after the review, D-181): the version a change was decided at, the case
event of a withdrawn notice, and the kind of key that counts new destinations; what the database
refuses, what the runtime login may write, the old rows it fills in, and a downgrade that would
lose a case event."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.machine import WithdrawNotice
from argus.cases.service import CaseService
from argus.db import migrate
from tests.integration.cases.conftest import Person, investigation
from tests.integration.cases.test_migration_0050 import a_notified_case

pytestmark = pytest.mark.integration

INSERT = (
    "INSERT INTO case_known_matches (investigation_id, case_id, version, outcome, why,"
    " changed_version) VALUES (:i, :c, :v, :o, :w, :cv)"
)


async def decided(
    engine: AsyncEngine, case: uuid.UUID, outcome: str, why: str | None, changed: int | None
) -> uuid.UUID:
    inv = await investigation(engine)
    async with engine.begin() as conn:
        await conn.execute(
            text(INSERT),
            {"i": inv, "c": case, "v": 2, "o": outcome, "w": why, "cv": changed},
        )
    return inv


async def test_the_column_exists_and_a_change_names_its_version(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case = await a_notified_case(app_engine, migrated_engine, people["asha"])
    async with migrated_engine.connect() as conn:
        columns = set(
            (
                await conn.execute(
                    text("SELECT column_name FROM information_schema.columns"
                         " WHERE table_name = 'case_known_matches'")
                )
            ).scalars()
        )  # fmt: skip
    assert "changed_version" in columns
    await decided(migrated_engine, case, "changed", "changed since notice: x", 2)
    await decided(migrated_engine, case, "known", None, None)
    for outcome, why, changed in (
        (
            "changed",
            "changed since notice: x",
            None,
        ),  # a change names the version it was decided at
        ("known", None, 2),  # and only a change does
        ("changed", "changed since notice: x", -1),
    ):
        with pytest.raises(DBAPIError, match="changed_version_valid"):
            await decided(migrated_engine, case, outcome, why, changed)


async def test_the_runtime_login_writes_the_version_and_the_web_login_only_reads_it(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case = await a_notified_case(app_engine, migrated_engine, people["asha"])
    inv = await investigation(migrated_engine)
    async with app_engine.begin() as conn:
        await conn.execute(
            text(INSERT), {"i": inv, "c": case, "v": 2, "o": "changed", "w": "x", "cv": 2}
        )
        await conn.execute(
            text("UPDATE case_known_matches SET version = 3, changed_version = 2, why = 'y'"
                 " WHERE investigation_id = :i"), {"i": inv},
        )  # fmt: skip
    # the kinds of key: the new one is accepted, an unknown one is not
    async with app_engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO case_known_keys (case_id, kind, value, source) VALUES"
                 " (:c, 'new_destination', 'ip:91.121.5.50', 'change')"), {"c": case},
        )  # fmt: skip
    with pytest.raises(DBAPIError, match="kind_valid"):
        async with app_engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO case_known_keys (case_id, kind, value, source) VALUES"
                     " (:c, 'new_thing', 'x', 'change')"), {"c": case},
            )  # fmt: skip


async def test_the_withdrawn_notice_is_a_case_event_the_database_accepts_and_keeps(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case = await a_notified_case(app_engine, migrated_engine, people["asha"])
    async with app_engine.begin() as conn:
        await (await CaseService.start(conn)).apply(
            people["asha"].actor(), case, WithdrawNotice("Asha", "wrong case"),
            expected_version=None,
        )  # fmt: skip
    async with migrated_engine.connect() as conn:
        kinds = [
            r.kind
            for r in await conn.execute(
                text("SELECT kind FROM case_events WHERE case_id = :c ORDER BY case_version"),
                {"c": case},
            )
        ]
    assert kinds == ["opened", "notified", "notice_withdrawn"]
    with pytest.raises(DBAPIError, match="append-only"):  # and nobody takes it back
        async with migrated_engine.begin() as conn:
            await conn.execute(text("DELETE FROM case_events WHERE kind = 'notice_withdrawn'"))
    async with migrated_engine.connect() as conn:
        rule = await conn.scalar(
            text("SELECT pg_get_constraintdef(oid) FROM pg_constraint"
                 " WHERE conname = 'ck_case_events_kind_valid'")
        )  # fmt: skip
    assert rule is not None
    assert "notice_withdrawn" in rule
    assert "notice_forgotten" not in rule


async def test_a_downgrade_that_would_lose_a_withdrawal_is_refused(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case = await a_notified_case(app_engine, migrated_engine, people["asha"])
    async with app_engine.begin() as conn:
        await (await CaseService.start(conn)).apply(
            people["asha"].actor(), case, WithdrawNotice("Asha", "wrong case"),
            expected_version=None,
        )  # fmt: skip
    with pytest.raises(DBAPIError, match="append-only"):
        await migrate.downgrade(migrated_engine, "0050")
    assert await migrate.current_revision(migrated_engine) == "0065"


async def test_a_clean_downgrade_drops_the_version_and_the_counts_and_upgrade_fills_it_again(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case = await a_notified_case(app_engine, migrated_engine, people["asha"])
    async with app_engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO case_known_keys (case_id, kind, value, source) VALUES"
                 " (:c, 'new_destination', 'ip:91.121.5.50', 'change'),"
                 " (:c, 'flag', 'x', 'notice')"), {"c": case},
        )  # fmt: skip
    changed = await investigation(migrated_engine)
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(INSERT),
            {"i": changed, "c": case, "v": 4, "o": "changed", "w": "changed since notice: x",
             "cv": 4},
        )  # fmt: skip
    await migrate.downgrade(migrated_engine, "0050")
    async with migrated_engine.connect() as conn:
        columns = set(
            (
                await conn.execute(
                    text("SELECT column_name FROM information_schema.columns"
                         " WHERE table_name = 'case_known_matches'")
                )
            ).scalars()
        )  # fmt: skip
        keys = set(
            (await conn.execute(text("SELECT kind FROM case_known_keys"))).scalars()
        )  # fmt: skip
    assert "changed_version" not in columns
    assert keys == {"flag"}  # the counts of new destinations are derived data
    await migrate.upgrade(migrated_engine)
    assert await migrate.schema_drift(migrated_engine) == []
    async with migrated_engine.connect() as conn:
        found = await conn.scalar(
            text("SELECT changed_version FROM case_known_matches WHERE investigation_id = :i"),
            {"i": changed},
        )
    assert found == 4  # a change decided before 0051 is waiting at the version it was decided at
