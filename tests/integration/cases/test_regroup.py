"""``argus db regroup`` and the case record (Q-C1): cases name the current investigations, so
a rebuild is refused while any exists; without them it empties the (empty) case tables too."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.grouping.regroup import ReviewsExistError, regroup
from tests.integration.cases.conftest import Person, investigation, rows
from tests.integration.cases.test_service import _open

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)


async def test_regroup_runs_without_cases_and_is_refused_with_one(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    await investigation(migrated_engine, alerts=0)
    assert await regroup(migrated_engine, NOW) == (0, 0)  # the empty case tables emptied too
    inv = await investigation(migrated_engine, alerts=0)
    await _open(app_engine, people["asha"].actor(), [inv])
    with pytest.raises(ReviewsExistError, match="cases or case decisions"):
        await regroup(migrated_engine, NOW)
    assert len(await rows(app_engine, "SELECT 1 FROM cases")) == 1


async def test_an_empty_append_only_table_may_be_truncated_a_full_one_never(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    async with migrated_engine.begin() as conn:
        await conn.execute(text("TRUNCATE entity_notes"))  # empty: nothing is lost
    from argus.cases.service import CaseService

    async with app_engine.begin() as conn:
        await (await CaseService.start(conn)).add_entity_note(
            people["asha"].actor(), "host", "lab-07", "the lab's print server"
        )
    with pytest.raises(DBAPIError, match="append-only"):
        async with migrated_engine.begin() as conn:
            await conn.execute(text("TRUNCATE entity_notes"))
    assert len(await rows(app_engine, "SELECT 1 FROM entity_notes")) == 1
