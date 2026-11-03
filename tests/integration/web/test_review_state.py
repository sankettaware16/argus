"""``review_state`` (migration 0025): each investigation's newest review, kept by a trigger on
``review_events`` so the lists stay fast at the exit's scale (plan §8 criterion 14). It must
always equal what the lists derived before it existed (the newest review that is not a note,
and the newest of any kind), whoever wrote the reviews and in whatever order; ARGUS's runtime
role may only read it; the upgrade fills it from the reviews already there."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.db import migrate

pytestmark = pytest.mark.integration

# The lists' definition before 0025 (queries._STATE until Q-A1), written out on its own.
DERIVED = """
SELECT ids.investigation_id, latest.id AS latest_id, last.id AS decision_id, last.action,
  last.version, last.alert_count, last.outcome, last.created_at AS decided_at, last.user_id
FROM (SELECT DISTINCT investigation_id FROM review_events) ids
LEFT JOIN (
  SELECT DISTINCT ON (r.investigation_id) r.investigation_id, r.id, r.action, r.version,
    r.alert_count, r.outcome, r.created_at, r.user_id
  FROM review_events r WHERE r.action <> 'note' ORDER BY r.investigation_id, r.id DESC
) last ON last.investigation_id = ids.investigation_id
LEFT JOIN (
  SELECT investigation_id, max(id) AS id FROM review_events GROUP BY investigation_id
) latest ON latest.investigation_id = ids.investigation_id
ORDER BY 1
"""
STORED = """
SELECT investigation_id, latest_id, decision_id, action, version, alert_count, outcome,
  decided_at, user_id FROM review_state ORDER BY 1
"""
OUTCOMES = ["benign_expected", "benign_policy", "rule_false_positive", "true_positive",
            "inconclusive", None]  # fmt: skip
REVIEW = st.tuples(
    st.integers(0, 23),  # which investigation (modulo how many there are)
    st.sampled_from(["reviewed", "follow_up", "note"]),
    st.sampled_from(OUTCOMES),
    st.integers(1, 5),  # the version the reviewer saw
    st.integers(0, 40),  # the alert count the reviewer saw
    st.booleans(),  # which person
)


async def rows(conn: AsyncConnection, sql: str) -> list[tuple[Any, ...]]:
    return [tuple(r) for r in await conn.execute(text(sql))]


async def ids_and_users(engine: AsyncEngine) -> tuple[list[Any], list[int]]:
    async with engine.connect() as conn:
        investigations = list(
            (await conn.execute(text("SELECT id FROM investigations ORDER BY id"))).scalars()
        )
        users = list((await conn.execute(text("SELECT id FROM users ORDER BY id"))).scalars())
    return investigations, users


async def add(conn: AsyncConnection, investigation: Any, review: tuple[Any, ...],
              users: list[int]) -> None:  # fmt: skip
    _, action, outcome, version, count, other = review
    await conn.execute(
        text(
            "INSERT INTO review_events (investigation_id, version, alert_count, user_id, action,"
            " outcome, note) VALUES (:i, :v, :c, :u, :a, :o, :n)"
        ),
        {"i": investigation, "v": version, "c": count, "u": users[int(other)], "a": action,
         "o": None if action == "note" else outcome,
         "n": "a note" if action == "note" else None},
    )  # fmt: skip


@settings(
    max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(batches=st.lists(st.lists(REVIEW, min_size=1, max_size=6), min_size=1, max_size=4))
async def test_the_stored_state_is_always_the_derived_one(
    seeded: AsyncEngine, batches: list[list[tuple[Any, ...]]]
) -> None:
    """Reviews by the runtime role, several to a transaction, some rolled back; the state
    builds up across examples and must equal the derived one after every batch."""
    investigations, users = await ids_and_users(seeded)
    for n, batch in enumerate(batches):
        async with seeded.connect() as conn, conn.begin() as tx:
            for review in batch:
                await add(conn, investigations[review[0] % len(investigations)], review, users)
            if n % 3 == 2:
                await tx.rollback()  # a review that never happened leaves no trace
        async with seeded.connect() as conn:
            assert await rows(conn, STORED) == await rows(conn, DERIVED)


async def test_an_older_review_committed_late_never_wins(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """Ids rise with every insert; one written with a smaller id (only the owner can) leaves
    the newer decision in place, and only raises ``latest_id`` when it is the newest."""
    investigations, users = await ids_and_users(seeded)
    target = investigations[0]
    async with seeded.begin() as conn:
        await add(conn, target, (0, "reviewed", "true_positive", 2, 5, False), users)
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO review_events (id, investigation_id, version, alert_count, user_id,"
                " action, outcome) OVERRIDING SYSTEM VALUE VALUES (-5, :i, 1, 1, :u,"
                " 'follow_up', NULL)"
            ),
            {"i": target, "u": users[1]},
        )
        state = (
            await conn.execute(
                text("SELECT action, version FROM review_state WHERE investigation_id = :i"),
                {"i": target},
            )
        ).one()
        assert tuple(state) == ("reviewed", 2)
        assert await rows(conn, STORED) == await rows(conn, DERIVED)


@pytest.mark.parametrize(
    "statement",
    [
        "INSERT INTO review_state (investigation_id, latest_id) SELECT id, 1 FROM investigations"
        " LIMIT 1",
        "UPDATE review_state SET action = 'reviewed'",
        "DELETE FROM review_state",
        "TRUNCATE review_state",
    ],
)
async def test_the_runtime_role_may_only_read_it(seeded: AsyncEngine, statement: str) -> None:
    investigations, users = await ids_and_users(seeded)
    async with seeded.begin() as conn:
        await add(conn, investigations[1], (1, "follow_up", None, 1, 1, False), users)
    async with seeded.connect() as conn:
        assert len(await rows(conn, STORED)) == 1
        with pytest.raises(DBAPIError, match="permission denied"):
            await conn.execute(text(statement))


async def test_the_upgrade_fills_it_from_the_reviews_so_far(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    investigations, users = await ids_and_users(seeded)
    async with seeded.begin() as conn:
        for n, action in enumerate(["reviewed", "note", "follow_up", "note", "reviewed"]):
            review = (n, action, "benign_expected", 1 + n % 2, n, n % 2 == 1)
            await add(conn, investigations[n % 3], review, users)
        await add(conn, investigations[7], (7, "note", None, 1, 1, False), users)  # notes only
    async with migrated_engine.connect() as conn:
        before = await rows(conn, DERIVED)
    await migrate.downgrade(migrated_engine, "0024")
    await migrate.upgrade(migrated_engine)
    async with migrated_engine.connect() as conn:
        assert await rows(conn, STORED) == before
        assert len(before) == 4
    async with seeded.begin() as conn:  # and the trigger is back
        await add(conn, investigations[7], (7, "reviewed", "inconclusive", 1, 2, True), users)
    async with migrated_engine.connect() as conn:
        assert await rows(conn, STORED) == await rows(conn, DERIVED)


async def test_a_temporary_table_of_the_same_name_captures_nothing(seeded: AsyncEngine) -> None:
    """The trigger's function runs as the owner with a pinned search_path (pg_temp last) and a
    qualified name, so a runtime session's own ``review_state`` never receives its rows."""
    investigations, users = await ids_and_users(seeded)
    async with seeded.connect() as conn, conn.begin():
        await conn.execute(text("CREATE TEMP TABLE review_state (LIKE public.review_state)"))
        await add(conn, investigations[2], (2, "reviewed", "benign_policy", 1, 3, False), users)
        assert (await conn.execute(text("SELECT count(*) FROM pg_temp.review_state"))).scalar() == 0
        stored = await conn.execute(text("SELECT count(*) FROM public.review_state"))
        assert stored.scalar() == 1
