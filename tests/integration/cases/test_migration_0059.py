"""Migration 0059 (D-230, a case can be retitled): the case event of a new title, which keeps the
state and is append-only like every case event, and a downgrade that would lose one."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.machine import EVENT_KINDS
from argus.db import migrate, models, roles
from tests.integration.cases.conftest import Person
from tests.integration.cases.test_retitle import retitle
from tests.integration.cases.test_split import make_six

pytestmark = pytest.mark.integration


async def kind_rule(engine: AsyncEngine) -> str:
    async with engine.connect() as conn:
        rule = await conn.scalar(
            text("SELECT pg_get_constraintdef(oid) FROM pg_constraint"
                 " WHERE conname = 'ck_case_events_kind_valid'")
        )  # fmt: skip
    assert rule is not None
    return str(rule)


async def test_the_event_kind_is_allowed_and_the_older_kinds_stay(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    six = await make_six(migrated_engine, app_engine)
    await retitle(app_engine, people["asha"].actor(), six.case, "A new title", "clearer")
    async with migrated_engine.connect() as conn:
        kinds = [
            r.kind
            for r in await conn.execute(
                text("SELECT kind FROM case_events WHERE case_id = :c ORDER BY case_version"),
                {"c": six.case},
            )
        ]
    assert kinds == ["suspected", "retitled"]
    rule = await kind_rule(migrated_engine)
    assert all(f"'{kind}'" in rule for kind in EVENT_KINDS)
    assert set(models.CASE_EVENT_KINDS) == set(EVENT_KINDS)
    with pytest.raises(DBAPIError, match="append-only"):
        async with migrated_engine.begin() as conn:
            await conn.execute(text("DELETE FROM case_events WHERE kind = 'retitled'"))


async def test_a_retitled_event_neither_creates_a_case_nor_ends_one(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    six = await make_six(migrated_engine, app_engine)
    await retitle(app_engine, people["asha"].actor(), six.case, "A new title", "clearer")

    async def insert(from_state: str | None, to_state: str) -> None:
        async with migrated_engine.begin() as conn:  # undone with the failed statement
            await conn.execute(text("ALTER TABLE case_events DISABLE TRIGGER USER"))
            await conn.execute(
                text("INSERT INTO case_events (case_id, case_version, kind, actor, from_state,"
                     " to_state) VALUES (:c, 3, 'retitled', 'user:1', :f, :t)"),
                {"c": six.case, "f": from_state, "t": to_state},
            )  # fmt: skip

    for from_state, to_state in ((None, "suspected"), ("suspected", "closed")):
        with pytest.raises(DBAPIError, match="kind_states"):
            await insert(from_state, to_state)


async def test_the_runtime_login_needs_no_new_grant_and_the_doctor_agrees(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    async with migrated_engine.connect() as conn:
        can = await conn.scalar(
            text("SELECT has_column_privilege('argus_runtime', 'cases', 'title', 'UPDATE')")
        )
    assert can is True  # since 0026
    assert await roles.runtime_role_problems(app_engine) == []


async def test_a_downgrade_that_would_lose_a_retitle_is_refused(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    six = await make_six(migrated_engine, app_engine)
    await retitle(app_engine, people["asha"].actor(), six.case, "A new title", "clearer")
    with pytest.raises(DBAPIError, match="append-only"):
        await migrate.downgrade(migrated_engine, "0058")
    assert await migrate.current_revision(migrated_engine) == "0064"
    assert "retitled" in await kind_rule(migrated_engine)  # nothing was undone


async def test_a_clean_downgrade_takes_the_kind_back_and_upgrades_again(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await migrate.downgrade(migrated_engine, "0058")
    assert await migrate.current_revision(migrated_engine) == "0058"
    assert "retitled" not in await kind_rule(migrated_engine)
    assert "unlinked" in await kind_rule(migrated_engine)  # 0055's kind is kept
    await migrate.upgrade(migrated_engine)
    assert await migrate.current_revision(migrated_engine) == "0064"
    assert "retitled" in await kind_rule(migrated_engine)
    assert await migrate.schema_drift(migrated_engine) == []
    assert await roles.runtime_role_problems(app_engine) == []
