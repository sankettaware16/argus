"""Migration 0055 (D-211, a person splits a case): the case event of a split, the grants that let a
removed row come back, the web trigger that now also looks at updates, and a downgrade that would
lose a case event."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.machine import Link
from argus.cases.model import Indicator
from argus.cases.service import CaseService
from argus.db import migrate, roles
from tests.integration.cases.conftest import Person
from tests.integration.cases.test_split import B, do_split, make_six

pytestmark = pytest.mark.integration

REVIVE = {
    "case_members": ("link", "link_value", "added_version", "added_by", "added_at"),
    "case_indicators": (
        "role", "source", "added_version", "added_by", "added_at", "removed_version", "removed_at",
    ),
}  # fmt: skip


async def can_update(engine: AsyncEngine, role: str, table: str, column: str) -> bool:
    async with engine.connect() as conn:
        found = await conn.scalar(
            text("SELECT has_column_privilege(:r, :t, :c, 'UPDATE')"),
            {"r": role, "t": table, "c": column},
        )
    return bool(found)


async def web_trigger(engine: AsyncEngine, table: str) -> tuple[bool, str]:
    """Whether the web's trigger on ``table`` fires on UPDATE, and how it is enabled."""
    async with engine.connect() as conn:
        row = (
            await conn.execute(
                text("SELECT (tgtype & 16) <> 0 AS on_update, tgenabled FROM pg_trigger"
                     " WHERE tgrelid = CAST(:t AS regclass) AND tgname = :n"),
                {"t": table, "n": f"{table}_web_writes"},
            )
        ).one()  # fmt: skip
    return bool(row.on_update), str(row.tgenabled)


async def test_the_split_is_a_case_event_the_database_accepts_and_keeps(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    six = await make_six(migrated_engine, app_engine)
    await do_split(app_engine, people["asha"], six.case, [six.b1])
    async with migrated_engine.connect() as conn:
        kinds = [
            r.kind
            for r in await conn.execute(
                text("SELECT kind FROM case_events WHERE case_id = :c ORDER BY case_version"),
                {"c": six.case},
            )
        ]
        rule = await conn.scalar(
            text("SELECT pg_get_constraintdef(oid) FROM pg_constraint"
                 " WHERE conname = 'ck_case_events_kind_valid'")
        )  # fmt: skip
    assert kinds == ["suspected", "unlinked"]
    assert rule is not None
    assert "unlinked" in rule
    assert "notice_withdrawn" in rule  # the older kinds are kept
    with pytest.raises(DBAPIError, match="append-only"):
        async with migrated_engine.begin() as conn:
            await conn.execute(text("DELETE FROM case_events WHERE kind = 'unlinked'"))


async def test_an_unlinked_event_keeps_the_state_the_tables_own_rule(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """The case guard let the split's event through (the split above); the kind's own CHECK says an
    unlinked event neither creates a case nor ends one."""
    six = await make_six(migrated_engine, app_engine)
    await do_split(app_engine, people["asha"], six.case, [six.b1])

    async def insert(from_state: str | None, to_state: str) -> None:
        async with migrated_engine.begin() as conn:  # undone with the failed statement
            await conn.execute(text("ALTER TABLE case_events DISABLE TRIGGER USER"))
            await conn.execute(
                text("INSERT INTO case_events (case_id, case_version, kind, actor, from_state,"
                     " to_state) VALUES (:c, 3, 'unlinked', 'user:1', :f, :t)"),
                {"c": six.case, "f": from_state, "t": to_state},
            )  # fmt: skip

    for from_state, to_state in ((None, "suspected"), ("suspected", "closed")):
        with pytest.raises(DBAPIError, match="kind_states"):
            await insert(from_state, to_state)


async def test_the_runtime_and_web_logins_may_revive_a_row_and_the_doctor_agrees(
    app_engine: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    for table, columns in REVIVE.items():
        for column in columns:
            assert await can_update(migrated_engine, "argus_runtime", table, column), column
            assert await can_update(migrated_engine, "argus_web", table, column), column
    # what neither may touch: the key and the case's own identity
    for table, key in (("case_members", "investigation_id"), ("case_indicators", "value")):
        assert not await can_update(migrated_engine, "argus_runtime", table, key)
        assert not await can_update(migrated_engine, "argus_web", table, key)
        assert not await can_update(migrated_engine, "argus_runtime", table, "case_id")
    assert await roles.runtime_role_problems(app_engine) == []
    assert await roles.api_role_problems(web_engine) == []


async def test_the_web_trigger_also_fires_on_update_and_the_doctor_still_sees_it(
    migrated_engine: AsyncEngine,
) -> None:
    for table in ("case_members", "case_indicators"):
        assert await web_trigger(migrated_engine, table) == (True, "A")
    assert await migrate.missing_guard_triggers(migrated_engine) == []


async def test_a_downgrade_that_would_lose_a_split_is_refused(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    six = await make_six(migrated_engine, app_engine)
    await do_split(app_engine, people["asha"], six.case, [six.b1])
    with pytest.raises(DBAPIError, match="append-only"):
        await migrate.downgrade(migrated_engine, "0054")
    assert await migrate.current_revision(migrated_engine) == "0064"
    assert await web_trigger(migrated_engine, "case_members") == (True, "A")  # nothing was undone


async def test_a_clean_downgrade_takes_the_grants_and_the_update_trigger_back_and_up_again(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    six = await make_six(migrated_engine, app_engine)
    async with migrated_engine.begin() as conn:  # a removed indicator, as 0054's code could not
        await conn.execute(
            text("UPDATE case_indicators SET removed_version = 2, removed_at = now()"
                 " WHERE case_id = :c AND value = :v"), {"c": six.case, "v": B},
        )  # fmt: skip
    async with app_engine.begin() as conn:  # and a Link that brings it back, row revived
        service = await CaseService.start(conn)
        await service.apply(
            people["asha"].actor(), six.case, Link((), (Indicator("ip", B, "c2"),)),
            expected_version=None,
        )  # fmt: skip
    await migrate.downgrade(migrated_engine, "0054")
    assert await migrate.current_revision(migrated_engine) == "0054"
    assert not await can_update(migrated_engine, "argus_runtime", "case_indicators", "role")
    assert not await can_update(migrated_engine, "argus_web", "case_indicators", "removed_at")
    assert not await can_update(migrated_engine, "argus_runtime", "case_members", "link")
    assert await can_update(migrated_engine, "argus_runtime", "case_members", "removed_at")
    assert await can_update(migrated_engine, "argus_web", "case_members", "removed_version")
    assert await web_trigger(migrated_engine, "case_members") == (False, "A")
    assert await web_trigger(migrated_engine, "case_indicators") == (False, "A")
    async with migrated_engine.connect() as conn:
        rule = await conn.scalar(
            text("SELECT pg_get_constraintdef(oid) FROM pg_constraint"
                 " WHERE conname = 'ck_case_events_kind_valid'")
        )  # fmt: skip
        body = await conn.scalar(
            text("SELECT prosrc FROM pg_proc WHERE proname = 'argus_web_case_writes'")
        )
    assert rule is not None
    assert "unlinked" not in rule
    assert "TG_OP" not in str(body)  # 0042's function again
    assert await migrate.missing_guard_triggers(migrated_engine) == []
    await migrate.upgrade(migrated_engine)
    assert await migrate.current_revision(migrated_engine) == "0064"
    assert await migrate.schema_drift(migrated_engine) == []
    assert await web_trigger(migrated_engine, "case_members") == (True, "A")
    assert await can_update(migrated_engine, "argus_runtime", "case_indicators", "role")
    assert await roles.runtime_role_problems(app_engine) == []
