"""Migration 0063 (P4-D1 part 2, D-284): an incident ID may carry any prefix, in the same shape.
Rows with the earlier fixed prefix still pass; a downgrade keeps the check and every post (the
posts are the record of what was sent to Kibana)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.db import migrate
from tests.integration.cases.conftest import Person
from tests.integration.caseteam.kit import a_case

pytestmark = pytest.mark.integration
POST = "INSERT INTO case_team_posts (case_id, incident_id) VALUES (:c, :i)"
CHECK = (
    "SELECT pg_get_constraintdef(oid) FROM pg_constraint"
    " WHERE conname = 'ck_case_team_posts_id_valid'"
)


async def post(engine: AsyncEngine, case: uuid.UUID, incident_id: str) -> None:
    async with engine.begin() as conn:
        await conn.execute(text(POST), {"c": case, "i": incident_id})


@pytest.mark.parametrize(
    "incident_id",
    [
        "ACME-IR-2026-1030-01",  # ACME's, as before
        "IR-2026-1031-01",  # the neutral default
        "ACME-SOC-2026-1031-02",
        "A-2026-1031-03",
        "A" + "B" * 15 + "-2026-1031-04",  # 16 characters: the longest prefix
    ],
)
async def test_any_prefix_in_the_shape_is_accepted(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    people: dict[str, Person],
    incident_id: str,
) -> None:
    case = await a_case(migrated_engine, app_engine, people["asha"])
    await post(migrated_engine, case, incident_id)


@pytest.mark.parametrize(
    "incident_id",
    [
        "x",
        "ir-2026-1031-01",  # lower case
        "1R-2026-1031-01",  # starts with a digit
        "-IR-2026-1031-01",
        "A" + "B" * 16 + "-2026-1031-01",  # 17 characters
        "IR-2026-1031-1",  # the rank has two digits
        "IR-2026-103-01",
        "IR-26-1031-01",
        "IR-2026-1031-01 ",
        "IR 2026-1031-01",
        "2026-1031-01",
    ],
)
async def test_another_shape_is_still_refused(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    people: dict[str, Person],
    incident_id: str,
) -> None:
    case = await a_case(migrated_engine, app_engine, people["asha"])
    with pytest.raises(IntegrityError, match="id_valid"):
        await post(migrated_engine, case, incident_id)


async def test_the_check_is_one_flat_comparison(migrated_engine: AsyncEngine) -> None:
    async with migrated_engine.begin() as conn:
        definition = (await conn.execute(text(CHECK))).scalar_one()
    assert "'^[A-Z][A-Z0-9-]{0,15}-[0-9]{4}-[0-9]{4}-[0-9]{2}$'" in definition
    assert definition.count("incident_id") == 1
    assert " AND " not in definition  # one comparison, so a restore reparses it the same
    assert " OR " not in definition


async def test_the_downgrade_keeps_the_check_and_every_post_and_round_trips(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    """0053 writes the any-prefix check itself, so going back past 0063 refuses nothing and loses
    no post (the posts are the record of what was sent to Kibana)."""
    first = await a_case(migrated_engine, app_engine, people["asha"])
    other = await a_case(migrated_engine, app_engine, people["asha"])
    await post(migrated_engine, first, "ACME-IR-2026-1030-01")
    await post(migrated_engine, other, "IR-2026-1031-01")
    await migrate.downgrade(migrated_engine, "0062")
    async with migrated_engine.begin() as conn:
        assert (await conn.execute(text("SELECT count(*) FROM case_team_posts"))).scalar_one() == 2
        before = (await conn.execute(text(CHECK))).scalar_one()
    await migrate.upgrade(migrated_engine)
    assert await migrate.current_revision(migrated_engine) == migrate.head_revision()
    async with migrated_engine.begin() as conn:
        assert (await conn.execute(text(CHECK))).scalar_one() == before  # the same text at head
