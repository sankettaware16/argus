"""Migration 0050 (AR4b, D-169, D-176): what the owner-notified outcome holds in the database, and
what the database refuses whoever asks: a notice only on an open or assigned case, a notice record
nobody may change, the closure reason only the proposer may use, and a downgrade that would lose
a case event."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.machine import Notify, Open
from argus.cases.model import Member
from argus.cases.service import CaseService
from argus.db import migrate
from tests.integration.cases.conftest import Person, investigation

pytestmark = pytest.mark.integration

PROPOSE = (
    "SELECT argus_approval_propose('argus:proposer', :c, :v, 'closure', :r, NULL,"
    " CAST('{}' AS jsonb), repeat('a', 64), NULL, now() + interval '1 hour', NULL)"
)


async def a_notified_case(app: AsyncEngine, owner: AsyncEngine, person: Person) -> uuid.UUID:
    inv = await investigation(owner)
    async with app.begin() as conn:
        service = await CaseService.start(conn)
        opened = await service.open(
            person.actor(), Open("Beacon", "high", "person", (Member(inv, "person"),))
        )
        await service.apply(person.actor(), opened.case.id, Notify("the owner", "email"),
                            expected_version=None)  # fmt: skip
    return opened.case.id


async def propose_as(engine: AsyncEngine, case: uuid.UUID, version: int, reason: str) -> str:
    """What the owner's function answers when the runtime proposes a closure for ``reason``."""
    with pytest.raises(DBAPIError) as refused:
        async with engine.begin() as conn:
            await conn.execute(text(PROPOSE), {"c": case, "v": version, "r": reason})
    return str(refused.value.orig)


async def test_the_new_tables_and_columns_exist(migrated_engine: AsyncEngine) -> None:
    async with migrated_engine.connect() as conn:
        tables = set(
            (
                await conn.execute(
                    text("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
                )
            ).scalars()
        )
        columns = set(
            (
                await conn.execute(
                    text("SELECT column_name FROM information_schema.columns"
                         " WHERE table_name = 'cases'")
                )
            ).scalars()
        )  # fmt: skip
    assert {"case_notices", "case_known_matches", "case_known_keys", "case_reminders"} <= tables
    assert {"notified_at", "blocked_at"} <= columns


async def test_a_notified_case_is_open_or_assigned_the_database_says_so(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case = await a_notified_case(app_engine, migrated_engine, people["asha"])
    # the lifecycle guard is switched off for the statement: the CHECK is what is tested
    async with migrated_engine.begin() as conn:
        await conn.execute(text("ALTER TABLE cases DISABLE TRIGGER cases_guard"))
    try:
        with pytest.raises(DBAPIError, match="ck_cases_notified_valid"):
            async with migrated_engine.begin() as conn:
                await conn.execute(
                    text("UPDATE cases SET state = 'contained' WHERE id = :c"), {"c": case}
                )
        with pytest.raises(DBAPIError, match="ck_cases_blocked_valid"):
            async with migrated_engine.begin() as conn:
                await conn.execute(
                    text("UPDATE cases SET notified_at = NULL, blocked_at = now(), state ="
                         " 'suspected', opened_at = NULL WHERE id = :c"), {"c": case},
                )  # fmt: skip
    finally:
        async with migrated_engine.begin() as conn:
            await conn.execute(text("ALTER TABLE cases ENABLE ALWAYS TRIGGER cases_guard"))


async def test_a_notice_record_cannot_be_changed_or_removed(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    await a_notified_case(app_engine, migrated_engine, people["asha"])
    for statement in (
        "UPDATE case_notices SET told = 'someone else'",
        "DELETE FROM case_notices",
        "TRUNCATE case_notices",
    ):
        with pytest.raises(DBAPIError, match="append-only"):
            async with migrated_engine.begin() as conn:
                await conn.execute(text(statement))


@pytest.mark.parametrize(
    ("kind", "how", "managed"),
    [
        ("owner", "carrier pigeon", True),  # the way is one of the list
        ("owner", "email", None),  # an owner notice says whether the machines are managed
        ("block", "DNS", True),  # a block does not
        ("visit", "email", True),  # the kind is owner or block
    ],
)
async def test_a_malformed_notice_row_is_refused(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person],
    kind: str, how: str, managed: bool | None,
) -> None:  # fmt: skip
    case = await a_notified_case(app_engine, migrated_engine, people["asha"])
    with pytest.raises(DBAPIError, match="violates check constraint"):
        async with migrated_engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO case_notices (case_id, case_version, kind, at, told, how,"
                     " managed, by_user_id) VALUES (:c, 9, :k, now(), 'x', :h, :m, :u)"),
                {"c": case, "k": kind, "h": how, "m": managed, "u": people["asha"].user_id},
            )  # fmt: skip


async def test_the_proposer_may_use_the_new_reason_and_no_reason_it_may_not(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case = await a_notified_case(app_engine, migrated_engine, people["asha"])
    # past the reason check, the function wants the case's own request event (there is none)
    said = await propose_as(app_engine, case, 2, "stopped_after_notice")
    assert "a proposal follows its own request event" in said
    said = await propose_as(app_engine, case, 2, "risk_accepted")
    assert "ARGUS does not propose a closure as risk_accepted" in said


async def test_a_downgrade_that_would_lose_a_notice_is_refused(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    await a_notified_case(app_engine, migrated_engine, people["asha"])
    with pytest.raises(DBAPIError, match="append-only"):
        await migrate.downgrade(migrated_engine, "0049")
    assert await migrate.current_revision(migrated_engine) == migrate.head_revision()


async def test_a_clean_downgrade_takes_the_new_reason_out_of_the_function_and_back(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    inv = await investigation(migrated_engine)
    async with app_engine.begin() as conn:
        opened = await (await CaseService.start(conn)).open(
            people["asha"].actor(), Open("Beacon", "high", "person", (Member(inv, "person"),))
        )
    await migrate.downgrade(migrated_engine, "0049")
    said = await propose_as(migrated_engine, opened.case.id, 1, "stopped_after_notice")
    assert "ARGUS does not propose a closure as stopped_after_notice" in said
    await migrate.upgrade(migrated_engine)
    assert await migrate.schema_drift(migrated_engine) == []
    said = await propose_as(migrated_engine, opened.case.id, 1, "stopped_after_notice")
    assert "a proposal follows its own request event" in said
