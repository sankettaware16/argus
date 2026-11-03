"""Migration 0062 (AR10, D-250): the case team's seventh user, ``argus-visualiser``, may write
comment steps; it still may not open a case, touch an alert or upload a file, and a downgrade is
refused while a step of its own exists (the steps are the record of what was sent)."""

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
HASH = "b" * 64
STEP = (
    "INSERT INTO case_team_steps (case_id, gen, seq, key, kind, author, part, report_version,"
    " text_body, request_hash) VALUES (:c, 1, :n, :k, :kind, :who, :part, 1, :body, :h)"
)


async def with_post(owner: AsyncEngine, app: AsyncEngine, person: Person) -> uuid.UUID:
    case = await a_case(owner, app, person)
    async with owner.begin() as conn:
        await conn.execute(
            text("INSERT INTO case_team_posts (case_id, incident_id) VALUES (:c, :i)"),
            {"c": case, "i": "ACME-IR-2026-1030-01"},
        )
    return case


async def put(
    engine: AsyncEngine, case: uuid.UUID, n: int, kind: str, who: str, body: str | None
) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(STEP),
            {
                "c": case,
                "n": n,
                "k": f"k{n}",
                "kind": kind,
                "who": who,
                "part": "glance",
                "body": body,
                "h": HASH,
            },
        )


async def test_the_visualiser_may_comment_and_nothing_else(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    case = await with_post(migrated_engine, app_engine, people["asha"])
    await put(writer_engine, case, 1, "comment", "argus-visualiser", "## Incident at a glance")
    for n, kind in enumerate(("open", "attach", "tag"), 2):  # the lead's alone
        body = "x" if kind == "open" else None
        with pytest.raises(IntegrityError, match="lead_only"):
            await put(writer_engine, case, n, kind, "argus-visualiser", body)
    with pytest.raises(IntegrityError, match="reporter_only"):  # the reporter's alone
        await put(writer_engine, case, 9, "file", "argus-visualiser", None)
    with pytest.raises(IntegrityError, match="author_valid"):  # an eighth user is nobody's
        await put(writer_engine, case, 10, "comment", "argus-eighth", "x")


async def test_the_downgrade_is_refused_while_the_visualiser_has_a_step_and_round_trips(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    case = await with_post(migrated_engine, app_engine, people["asha"])
    await put(writer_engine, case, 1, "comment", "argus-visualiser", "## Incident at a glance")
    with pytest.raises(Exception, match="refused"):
        await migrate.downgrade(migrated_engine, "0061")
    assert await migrate.current_revision(migrated_engine) == "0064"
    async with migrated_engine.begin() as conn:
        await conn.execute(text("DELETE FROM case_team_steps WHERE author = 'argus-visualiser'"))
    await migrate.downgrade(migrated_engine, "0061")
    with pytest.raises(IntegrityError, match="author_valid"):  # the six again
        await put(writer_engine, case, 2, "comment", "argus-visualiser", "x")
    await migrate.upgrade(migrated_engine)
    assert await migrate.current_revision(migrated_engine) == "0064"
    await put(writer_engine, case, 3, "comment", "argus-visualiser", "x")
