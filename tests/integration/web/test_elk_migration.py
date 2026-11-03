"""Q-E2: migration 0036 (users, ELK sessions, devices, break-glass): up and down with ELK-only
accounts (down refuses rather than lose them), history and label counts unchanged, the local
hash kept until the person's ELK sign-in has worked."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.db import migrate
from argus.web import auth

pytestmark = pytest.mark.integration
UID = "6f1c1a52-9b0e-4f4e-8d57-0c7a0d2f2b11"


async def counts(engine: AsyncEngine) -> dict[str, int]:
    async with engine.connect() as conn:
        return {
            t: int((await conn.execute(text(f"SELECT count(*) FROM {t}"))).scalar_one())  # noqa: S608
            for t in ("users", "review_events", "gold_labels", "user_sessions", "audit_events")
        }


async def test_up_and_down_with_elk_only_accounts_loses_nothing(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    owner = migrated_engine
    async with owner.begin() as conn:
        await conn.execute(text(
            "INSERT INTO users (username, display_name, kind, realm, elk_username, argus_uid,"
            " capabilities, elk_first_signin_at) VALUES ('elk.only', 'Only', 'person', 'native',"
            " 'Elk.Only', :u, '{}', now())"), {"u": UID})  # fmt: skip
        mine = (
            await conn.execute(text("SELECT id FROM users WHERE username = 'asha'"))
        ).scalar_one()
        await conn.execute(text(
            "INSERT INTO review_events (investigation_id, version, alert_count, user_id, action,"
            " outcome) SELECT id, version, alert_count, :u, 'reviewed', 'inconclusive'"
            " FROM investigations LIMIT 3"), {"u": mine})  # fmt: skip
    before = await counts(owner)
    assert before["review_events"] == 3
    with pytest.raises(RuntimeError, match="signed in through ELK only"):
        await migrate.downgrade(owner, "0035")
    assert await migrate.current_revision(owner) == migrate.head_revision()  # nothing was done
    assert await counts(owner) == before
    async with owner.begin() as conn:  # give the ELK-only account a password: it can go back
        await conn.execute(text("UPDATE users SET password_hash = :h WHERE username = 'elk.only'"),
                           {"h": auth.hash_password("a password for going back")})  # fmt: skip
    await migrate.downgrade(owner, "0035")
    assert await counts(owner) == before  # every row, every id
    async with owner.connect() as conn:
        columns = {
            r[0]
            for r in await conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns WHERE table_name = 'users'"
                )
            )
        }
    assert "elk_username" not in columns
    assert "kind" not in columns
    await migrate.upgrade(owner)
    assert await counts(owner) == before
    async with owner.connect() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT id, kind, realm, elk_username, argus_uid FROM users"
                    " WHERE username = 'asha'"
                )
            )
        ).one()
    assert (row.id, row.kind, row.realm, row.elk_username, row.argus_uid) == (
        mine,
        "person",
        "local",
        None,
        None,
    )  # every local account is a local person, with its id


async def test_argus_assistant_becomes_a_service_identity(migrated_engine: AsyncEngine) -> None:
    owner = migrated_engine
    await migrate.downgrade(owner, "0035")
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO users (username, display_name, password_hash)"
                " VALUES ('argus-assistant', 'Assistant', 'x'), ('asha', 'Asha', 'y')"
            )
        )
    await migrate.upgrade(owner)
    async with owner.connect() as conn:
        kinds = dict((await conn.execute(text("SELECT username, kind FROM users"))).all())
    assert kinds == {"argus-assistant": "service", "asha": "person"}


async def test_a_local_hash_is_kept_until_the_elk_sign_in_has_worked(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    async with migrated_engine.begin() as conn:
        with pytest.raises(IntegrityError, match="ck_users_password_or_elk"):
            async with conn.begin_nested():
                await conn.execute(text("UPDATE users SET password_hash = NULL"
                                        " WHERE username = 'asha'"))  # fmt: skip
        await conn.execute(text("UPDATE users SET elk_username = 'asha.elk', realm = 'native',"
                                " elk_first_signin_at = now()"
                                " WHERE username = 'asha'"))  # fmt: skip
        await conn.execute(text("UPDATE users SET password_hash = NULL WHERE username = 'asha'"))


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE users SET kind = 'robot' WHERE username = 'asha'",
        "UPDATE users SET realm = 'ldap' WHERE username = 'asha'",
        "UPDATE users SET realm = 'native' WHERE username = 'asha'",  # a native account has a name
        "UPDATE users SET elk_username = 'x' WHERE username = 'asha'",  # a named one is native
        "UPDATE users SET argus_uid = 'not-a-uuid' WHERE username = 'asha'",
        "UPDATE users SET argus_uid = upper(:u) WHERE username = 'asha'",
        "UPDATE users SET elk_username = '', realm = 'native' WHERE username = 'asha'",
        "UPDATE users SET kind = 'break_glass', realm = 'native', elk_username = 'b'"
        " WHERE username = 'asha'",
        "UPDATE user_sessions SET mode = 'kiosk'",
        "UPDATE user_sessions SET unverified_why = 'because'",
        "UPDATE user_sessions SET capabilities = '{admin,root}', mode = 'elk', checked_at = now()",
        "UPDATE user_sessions SET mode = 'elk'",  # an ELK session has its snapshot
        "UPDATE user_sessions SET credential = '\\x01'",  # only an ELK session with custody
    ],
)
async def test_the_database_refuses_what_makes_no_sense(
    seeded: AsyncEngine, migrated_engine: AsyncEngine, statement: str
) -> None:
    async with migrated_engine.begin() as conn:
        await conn.execute(text(
            "INSERT INTO user_sessions (token_hash, user_id, csrf_token, last_seen_at, expires_at)"
            " SELECT 'h', id, 'c', now(), now() + interval '1 h' FROM users"
            " WHERE username = 'asha'"))  # fmt: skip
    with pytest.raises(IntegrityError):
        async with migrated_engine.begin() as conn:
            await conn.execute(text(statement), {"u": UID})


async def test_one_live_account_per_elk_name_and_per_argus_uid(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    owner = migrated_engine
    insert = text(
        "INSERT INTO users (username, display_name, kind, realm, elk_username, argus_uid,"
        " capabilities, elk_first_signin_at)"
        " VALUES (:h, 'X', 'person', 'native', :n, :u, '{}', now())"
    )  # fmt: skip
    async with owner.begin() as conn:
        await conn.execute(insert, {"h": "one", "n": "Same.Name", "u": UID})
    for params in (
        {"h": "two", "n": "Same.Name", "u": "11111111-1111-4111-8111-111111111111"},  # the name
        {"h": "two", "n": "Other.Name", "u": UID},  # the uid
    ):
        with pytest.raises(IntegrityError):
            async with owner.begin() as conn:
                await conn.execute(insert, params)
    async with owner.begin() as conn:  # a frozen account does not hold its name any more
        await conn.execute(text("UPDATE users SET frozen_at = now(), disabled = true"
                                " WHERE username = 'one'"))  # fmt: skip
        await conn.execute(insert, {"h": "two", "n": "Same.Name",
                                    "u": "11111111-1111-4111-8111-111111111111"})  # fmt: skip
    # names are exact: ELK tells "same.name" and "Same.Name" apart
    async with owner.begin() as conn:
        await conn.execute(insert, {"h": "three", "n": "same.name",
                                    "u": "22222222-2222-4222-8222-222222222222"})  # fmt: skip


async def test_the_emergency_window_is_at_most_four_hours_and_one_at_a_time(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    owner = migrated_engine
    async with owner.begin() as conn:
        uid = (
            await conn.execute(text("SELECT id FROM users WHERE username = 'asha'"))
        ).scalar_one()
    sql = text("INSERT INTO break_glass (user_id, reason, enabled_by, expires_at)"
               " VALUES (:u, :r, 'me', now() + make_interval(mins => :m))")  # fmt: skip
    for reason, minutes in (
        ("too short", 60),
        ("a good enough reason", 241),
        ("a good enough reason", 0),
    ):
        with pytest.raises(IntegrityError):
            async with owner.begin() as conn:
                await conn.execute(sql, {"u": uid, "r": reason, "m": minutes})
    async with owner.begin() as conn:
        await conn.execute(sql, {"u": uid, "r": "a good enough reason", "m": 240})
    with pytest.raises(IntegrityError):  # one open window at a time
        async with owner.begin() as conn:
            await conn.execute(sql, {"u": uid, "r": "a second good reason", "m": 60})
