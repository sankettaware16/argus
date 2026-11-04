"""Migration 0056 (AR6, D-216): what the database holds and refuses for the sign-in sightings and
lookups, who may read and write them, and a clean round trip."""

from __future__ import annotations

import json
from datetime import UTC, date, datetime
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.db import migrate, roles

pytestmark = pytest.mark.integration

SIGHTING = (
    "INSERT INTO signin_sightings (address, day, user_name, first_at, last_at, events, successes,"
    " failures, hours, user_agents) VALUES (CAST(:a AS inet), :d, :u, :f, :l, :n, :s, :x,"
    " CAST(:h AS smallint[]), CAST(:g AS jsonb))"
)
LOOKUP = (
    "INSERT INTO signin_lookups (address, day, looked_at, complete, accounts, more_accounts,"
    " reason) VALUES (CAST(:a AS inet), :d, :t, :c, :n, :m, :r)"
)
DAY = date(2026, 10, 28)
T1, T2 = datetime(2026, 10, 28, 9, 10, tzinfo=UTC), datetime(2026, 10, 28, 17, 40, tzinfo=UTC)


def sighting(**more: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "a": "10.1.2.3", "d": DAY, "u": "user01", "f": T1, "l": T2, "n": 6, "s": 5, "x": 1,
        "h": [9, 10, 17], "g": json.dumps([{"text": "ua", "events": 6}]),
    }  # fmt: skip
    values.update(more)
    return values


def lookup(**more: Any) -> dict[str, Any]:
    values: dict[str, Any] = {
        "a": "10.1.2.3", "d": DAY, "t": T2, "c": True, "n": 1, "m": 0, "r": None,
    }  # fmt: skip
    values.update(more)
    return values


async def test_the_runtime_login_stores_a_sighting_and_a_lookup(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    async with app_engine.begin() as conn:
        await conn.execute(text(SIGHTING), sighting())
        await conn.execute(text(LOOKUP), lookup())
    async with app_engine.connect() as conn:
        row = (
            await conn.execute(
                text("SELECT host(address) AS a, hours, user_agents FROM signin_sightings")
            )
        ).one()
    assert (row.a, list(row.hours), row.user_agents) == (
        "10.1.2.3", [9, 10, 17], [{"text": "ua", "events": 6}],
    )  # fmt: skip
    assert await migrate.schema_drift(migrated_engine) == []


@pytest.mark.parametrize(
    ("change", "why"),
    [
        ({"u": ""}, "user_name_length"),
        ({"u": "x" * 257}, "user_name_length"),
        ({"f": T2, "l": T1}, "span_valid"),
        ({"n": 0, "s": 0, "x": 0}, "counts_valid"),
        ({"s": 5, "x": 5}, "counts_valid"),  # 10 outcomes in 6 events
        ({"s": -1}, "counts_valid"),
        ({"h": []}, "hours_valid"),
        ({"h": [24]}, "hours_valid"),
        ({"h": [-1, 3]}, "hours_valid"),
        ({"g": json.dumps({"a": 1})}, "agents_valid"),
        ({"g": json.dumps([{}] * 4)}, "agents_valid"),
    ],
)
async def test_the_database_refuses_a_sighting_that_is_not_shaped_right(
    app_engine: AsyncEngine, change: dict[str, Any], why: str
) -> None:
    with pytest.raises(DBAPIError, match=why):
        async with app_engine.begin() as conn:
            await conn.execute(text(SIGHTING), sighting(**change))


async def test_one_account_has_one_row_for_an_address_and_a_day(app_engine: AsyncEngine) -> None:
    async with app_engine.begin() as conn:
        await conn.execute(text(SIGHTING), sighting())
        await conn.execute(text(SIGHTING), sighting(u="user02"))
        await conn.execute(text(SIGHTING), sighting(d=date(2026, 10, 27)))
    with pytest.raises(DBAPIError, match="pk_signin_sightings"):
        async with app_engine.begin() as conn:
            await conn.execute(text(SIGHTING), sighting())


@pytest.mark.parametrize(
    ("change", "why"),
    [
        ({"c": False, "n": 0, "r": None}, "reason_valid"),  # incomplete says why
        ({"c": True, "r": "partial"}, "reason_valid"),  # complete has no reason
        ({"c": False, "n": 0, "r": "because"}, "reason_valid"),
        ({"c": False, "n": 2, "r": "partial"}, "reason_valid"),  # incomplete knows no accounts
        ({"n": 1, "m": 2}, "counts_valid"),  # more than the accounts there are
        ({"n": -1, "m": 0}, "counts_valid"),
    ],
)
async def test_the_database_refuses_a_lookup_that_is_not_shaped_right(
    app_engine: AsyncEngine, change: dict[str, Any], why: str
) -> None:
    with pytest.raises(DBAPIError, match=why):
        async with app_engine.begin() as conn:
            await conn.execute(text(LOOKUP), lookup(**change))


async def test_looked_none_seen_not_looked_incomplete_and_gone_are_four_different_rows(
    app_engine: AsyncEngine,
) -> None:
    async with app_engine.begin() as conn:
        await conn.execute(text(LOOKUP), lookup(a="10.1.2.1", n=0))  # looked, none seen
        await conn.execute(text(LOOKUP), lookup(a="10.1.2.2", c=False, n=0, r="partial"))
        await conn.execute(text(LOOKUP), lookup(a="10.1.2.3", c=False, n=0, r="logs_gone"))
    async with app_engine.connect() as conn:
        rows = (
            await conn.execute(
                text(
                    "SELECT host(address) a, complete, accounts, reason"
                    " FROM signin_lookups ORDER BY 1"
                )
            )
        ).all()
    assert [(r.a, r.complete, r.accounts, r.reason) for r in rows] == [
        ("10.1.2.1", True, 0, None),
        ("10.1.2.2", False, 0, "partial"),
        ("10.1.2.3", False, 0, "logs_gone"),
    ]  # and "not looked yet" is no row at all


async def test_a_lookup_is_updated_in_place_and_a_sighting_is_not(app_engine: AsyncEngine) -> None:
    async with app_engine.begin() as conn:
        await conn.execute(text(SIGHTING), sighting())
        await conn.execute(text(LOOKUP), lookup())
        await conn.execute(
            text(
                "UPDATE signin_lookups SET complete = false, accounts = 0, reason = 'failed'"
                " WHERE address = CAST('10.1.2.3' AS inet)"
            )
        )
        await conn.execute(text("DELETE FROM signin_sightings"))  # the pass replaces and prunes
        await conn.execute(text("DELETE FROM signin_lookups"))
    async with app_engine.begin() as conn:
        await conn.execute(text(SIGHTING), sighting())
    with pytest.raises(DBAPIError, match="permission denied"):
        async with app_engine.begin() as conn:
            await conn.execute(text("UPDATE signin_sightings SET user_name = 'user09'"))
    with pytest.raises(DBAPIError, match="permission denied"):
        async with app_engine.begin() as conn:
            await conn.execute(text("UPDATE signin_lookups SET address = '10.9.9.9'"))


async def test_the_web_reads_and_writes_nothing_of_it(
    app_engine: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with app_engine.begin() as conn:
        await conn.execute(text(SIGHTING), sighting())
        await conn.execute(text(LOOKUP), lookup())
    async with web_engine.connect() as conn:
        assert (await conn.scalar(text("SELECT count(*) FROM signin_sightings"))) == 1
        assert (await conn.scalar(text("SELECT count(*) FROM signin_lookups"))) == 1
    for sql in (
        "INSERT INTO signin_lookups (address, day, looked_at, complete) VALUES ('10.9.9.9', now(),"
        " now(), true)",
        "UPDATE signin_sightings SET events = 1",
        "DELETE FROM signin_sightings",
        "DELETE FROM signin_lookups",
    ):
        with pytest.raises(DBAPIError, match="permission denied"):
            async with web_engine.begin() as conn:
                await conn.execute(text(sql))


async def test_the_doctors_grants_agree_with_what_the_migration_gave(
    app_engine: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    assert await roles.runtime_role_problems(app_engine) == []
    assert await roles.api_role_problems(web_engine) == []
    assert roles.RUNTIME_GRANTS["signin_sightings"].select
    assert roles.RUNTIME_GRANTS["signin_sightings"].delete
    assert roles.API_GRANTS["signin_sightings"] == roles.TableGrant(select=True)


def test_regroup_leaves_the_sightings_alone() -> None:
    """The sign-in logs last five days at the SIEM: these rows are the only copy, so the table that
    regrouping empties does not name them."""
    from pathlib import Path

    from argus.grouping import regroup

    source = Path(regroup.__file__).read_text(encoding="utf-8")
    truncated = source.split("TRUNCATE", 1)[1].split("grouped = 0", 1)[0]
    assert "signin_sightings" not in truncated
    assert "signin_lookups" not in truncated


async def test_a_clean_round_trip_down_and_up_again(migrated_engine: AsyncEngine) -> None:
    await migrate.downgrade(migrated_engine, "0055")
    assert await migrate.current_revision(migrated_engine) == "0055"
    async with migrated_engine.connect() as conn:
        left = await conn.scalar(text("SELECT to_regclass('signin_sightings')"))
    assert left is None
    await migrate.upgrade(migrated_engine)
    assert await migrate.current_revision(migrated_engine) == "0065"
    assert await migrate.schema_drift(migrated_engine) == []
