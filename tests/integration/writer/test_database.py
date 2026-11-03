"""Q-D4 in the database: the writer's own login (exactly the writer's grants: the outbox moves
only it may make, and no more of the runtime's), the step table's guard, and bootstrap and
doctor for the login."""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable

import pytest
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config import DatabaseSettings
from argus.config.errors import ConfigError
from argus.config.settings import Settings
from argus.db import roles
from argus.doctor import writer_login_check
from argus.writer import store
from tests.integration.cases.conftest import Person
from tests.integration.cases.test_service import _kibana_actor
from tests.integration.writer.kit import mirrored_case, rig

pytestmark = pytest.mark.integration
MakeLogin = Callable[[], Awaitable[DatabaseSettings]]


async def test_the_writers_login_is_exactly_its_own_grants(
    writer_engine: AsyncEngine,
) -> None:
    assert await roles.writer_role_problems(writer_engine) == []


async def test_a_writer_login_with_more_is_found(
    writer_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    login = writer_engine.url.username
    async with migrated_engine.begin() as conn:
        await conn.execute(text(f'GRANT UPDATE ON audit_events TO "{login}"'))
        await conn.execute(text(f'GRANT DELETE ON kibana_steps TO "{login}"'))
    problems = await roles.writer_role_problems(writer_engine)
    assert "can UPDATE audit_events" in problems
    assert "can DELETE kibana_steps" in problems


async def test_a_writer_login_that_reaches_a_table_it_does_not_need_or_the_runtime_is_found(
    writer_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """R8: it is no member of ``argus_runtime``, and every table outside its list is closed."""
    login = writer_engine.url.username
    async with migrated_engine.begin() as conn:
        await conn.execute(text(f'GRANT SELECT ON user_sessions TO "{login}"'))
        await conn.execute(text(f'GRANT UPDATE (disabled) ON users TO "{login}"'))
        await conn.execute(text(f'GRANT {roles.RUNTIME_ROLE} TO "{login}"'))
    problems = await roles.writer_role_problems(writer_engine)
    assert "can read user_sessions" in problems
    assert "can UPDATE users.disabled" in problems or "can UPDATE users" in problems
    assert f"is a member of {roles.RUNTIME_ROLE}" in problems


async def test_only_the_writer_moves_outbox_rows_and_writes_its_tables(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    case_id = await mirrored_case(
        app_engine, migrated_engine, people["asha"], _kibana_actor(people["asha"])
    )
    row = (await store_rows(migrated_engine, case_id))[0]
    for engine, allowed in ((app_engine, False), (writer_engine, True)):
        async with engine.connect() as conn:
            if allowed:
                await conn.execute(
                    text("UPDATE kibana_outbox SET state = 'approved' WHERE id = :i"), {"i": row}
                )
                await conn.rollback()
                continue
            for statement in (
                "UPDATE kibana_outbox SET state = 'approved' WHERE id = :i",
                "INSERT INTO kibana_lookups (subject, subject_id, sent_count, attempt, due_at)"
                " VALUES ('outbox', 1, 1, 1, now())",
                "INSERT INTO kibana_writer_ramp (write_class, step, since, changed_by)"
                " VALUES ('W1', 5, now(), 'x')",
            ):
                with pytest.raises(DBAPIError, match="permission denied"):
                    await conn.execute(text(statement), {"i": row})
                await conn.rollback()
            assert (await conn.execute(text("SELECT count(*) FROM kibana_steps"))).scalar_one() == 0


async def store_rows(engine: AsyncEngine, case_id: uuid.UUID) -> list[int]:
    async with engine.connect() as conn:
        rows = await conn.execute(
            text("SELECT id FROM kibana_outbox WHERE case_id = :c ORDER BY id"), {"c": case_id}
        )
        return [int(i) for i in rows.scalars()]


async def _step(engine: AsyncEngine, case_id: uuid.UUID, outbox: int, key: str = "k:1") -> int:
    async with engine.begin() as conn:
        step_id = await store.insert_step(
            conn, case_id=case_id, outbox_id=outbox, approval_request_id=None, kind="comment",
            seq=0, key=key, write_class="W1", payload={"template": "opened", "params": {}},
        )  # fmt: skip
    assert step_id is not None
    return step_id


async def test_a_step_moves_only_along_the_outbox_edges_and_is_sent_once(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    case_id = await mirrored_case(
        app_engine, migrated_engine, people["asha"], _kibana_actor(people["asha"])
    )
    [outbox] = await store_rows(migrated_engine, case_id)
    step_id = await _step(writer_engine, case_id, outbox)
    assert await _step_insert_again(writer_engine, case_id, outbox) is None  # its key is unique

    async def attempt(sql: str) -> str:
        async with writer_engine.begin() as conn:
            try:
                async with conn.begin_nested():
                    await conn.execute(text(sql), {"i": step_id})
            except DBAPIError as exc:
                return str(exc.orig).splitlines()[0]
        return "ok"

    assert "not a step move" in await attempt(
        "UPDATE kibana_steps SET state = 'sending' WHERE id = :i"
    )
    assert await attempt("UPDATE kibana_steps SET state = 'approved' WHERE id = :i") == "ok"
    assert (
        await attempt("UPDATE kibana_steps SET state = 'sending', sent_count = 1 WHERE id = :i")
        == "ok"
    )
    assert "counted once" in await attempt("UPDATE kibana_steps SET sent_count = 2 WHERE id = :i")
    assert await attempt("UPDATE kibana_steps SET state = 'ambiguous' WHERE id = :i") == "ok"
    # no approval covers a resend of a step: ambiguous never goes back to planned or approved
    assert "not a step move" in await attempt(
        "UPDATE kibana_steps SET state = 'planned' WHERE id = :i"
    )
    assert "not a step move" in await attempt(
        "UPDATE kibana_steps SET state = 'approved' WHERE id = :i"
    )
    assert "permission denied" in await attempt(
        "UPDATE kibana_steps SET payload = '{}' WHERE id = :i"
    )
    assert "permission denied" in await attempt(
        "UPDATE kibana_steps SET key = 'other' WHERE id = :i"
    )
    assert await attempt("UPDATE kibana_steps SET state = 'skipped' WHERE id = :i") == "ok"
    assert "not a step move" in await attempt(
        "UPDATE kibana_steps SET state = 'verified' WHERE id = :i"
    )
    async with writer_engine.connect() as conn:
        with pytest.raises(DBAPIError, match="permission denied"):
            await conn.execute(text("DELETE FROM kibana_steps"))


async def _step_insert_again(engine: AsyncEngine, case_id: uuid.UUID, outbox: int) -> int | None:
    async with engine.begin() as conn:
        return await store.insert_step(
            conn, case_id=case_id, outbox_id=outbox, approval_request_id=None, kind="comment",
            seq=0, key="k:1", write_class="W1", payload={"template": "opened", "params": {}},
        )  # fmt: skip


async def test_a_new_step_is_planned_and_a_compensating_one_needs_a_complete_approval(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    case_id = await mirrored_case(
        app_engine, migrated_engine, people["asha"], _kibana_actor(people["asha"])
    )
    [outbox] = await store_rows(migrated_engine, case_id)
    async with writer_engine.begin() as conn:  # the writer cannot even name a state
        with pytest.raises(DBAPIError, match="permission denied"):
            await conn.execute(
                text(
                    "INSERT INTO kibana_steps (case_id, outbox_id, kind, seq, key, write_class,"
                    " payload, payload_hash, state) VALUES (:c, :o, 'comment', 0, 'x', 'W1', '{}',"
                    " repeat('0', 64), 'approved')"
                ),
                {"c": case_id, "o": outbox},
            )
    async with migrated_engine.begin() as conn:  # and the trigger holds even for the owner
        with pytest.raises(DBAPIError, match="planned and unsent"):
            await conn.execute(
                text(
                    "INSERT INTO kibana_steps (case_id, outbox_id, kind, seq, key, write_class,"
                    " payload, payload_hash, state) VALUES (:c, :o, 'comment', 0, 'x', 'W1', '{}',"
                    " repeat('0', 64), 'approved')"
                ),
                {"c": case_id, "o": outbox},
            )
    async with writer_engine.begin() as conn:
        with pytest.raises(DBAPIError, match="follows an approval of its own outbox row"):
            await conn.execute(
                text(
                    "INSERT INTO kibana_steps (case_id, outbox_id, kind, seq, key, write_class,"
                    " payload, payload_hash) VALUES (:c, :o, 'compensate_update', 0, 'y', 'W2',"
                    " '{}', repeat('0', 64))"
                ),
                {"c": case_id, "o": outbox},
            )
    async with writer_engine.begin() as conn:
        with pytest.raises(DBAPIError, match="only a compensating step carries an approval"):
            await conn.execute(
                text(
                    "INSERT INTO kibana_steps (case_id, outbox_id, approval_request_id, kind, seq,"
                    " key, write_class, payload, payload_hash) VALUES (:c, :o, 1, 'comment', 0,"
                    " 'z', 'W1', '{}', repeat('0', 64))"
                ),
                {"c": case_id, "o": outbox},
            )


async def test_a_writer_that_ran_leaves_the_runtime_grants_matching_the_models(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    """The runtime login reads the writer's records (the web shows them) and cannot change them."""
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await mirrored_case(
        app_engine, migrated_engine, people["asha"], _kibana_actor(people["asha"])
    )
    await r.run("W1", limit=1)
    async with app_engine.connect() as conn:
        for table in ("kibana_steps", "kibana_lookups", "kibana_writer_runs", "kibana_writer_ramp"):
            await conn.execute(text(f"SELECT * FROM {table}"))  # noqa: S608
    assert await roles.runtime_role_problems(app_engine) == []
    assert case_id


# --------------------------------------------------------------------------- bootstrap and doctor


async def test_bootstrap_makes_the_writers_group_and_login_and_repairs_them(
    make_writer_login: MakeLogin, migrated_engine: AsyncEngine, db_settings: DatabaseSettings
) -> None:  # fmt: skip
    login = await make_writer_login()
    async with migrated_engine.begin() as conn:
        again = await roles.ensure_writer_roles(conn, login)
    assert again == []  # nothing to create the second time
    async with migrated_engine.begin() as conn:
        await conn.execute(text(f'GRANT {roles.RUNTIME_ROLE} TO "{login.writer_user}"'))
        await conn.execute(text(f'GRANT pg_read_all_data TO "{login.writer_user}"'))
    repairs: list[str] = []
    async with migrated_engine.begin() as conn:
        await roles.ensure_writer_roles(conn, login, changes=repairs)
    assert f"{login.writer_user} was a member of pg_read_all_data: revoked" in repairs
    # R8: the writer is no member of the runtime role (0037 had made it one)
    assert f"{login.writer_user} was a member of {roles.RUNTIME_ROLE}: revoked" in repairs
    async with migrated_engine.begin() as conn:  # without a password only the group exists
        none = login.model_copy(update={"writer_password": None})
        assert await roles.ensure_writer_roles(conn, none) == []


@pytest.mark.parametrize(
    ("name", "why"),
    [
        ("argus_writer", "may not be argus_writer"),
        ("argus_runtime", "may not be argus_runtime"),
        ("argus_approvals", "may not be argus_approvals"),
        ("argus", "none of database.user"),
        ("argus_api", "none of database.user"),
        ("Writer-Login", "lowercase letters"),
        ("pg_writer", "may not be pg_writer"),
    ],
)
def test_the_writers_login_name_is_checked(name: str, why: str) -> None:
    settings = DatabaseSettings.model_construct(
        **{**DatabaseSettings().model_dump(), "writer_user": name,
           "writer_password": SecretStr("a-long-enough-password-1")}
    )  # fmt: skip
    with pytest.raises(ConfigError, match=why):
        roles.check_writer_settings(settings)


async def test_doctor_on_the_writers_login(
    make_writer_login: MakeLogin, migrated_engine: AsyncEngine, test_database: str
) -> None:  # fmt: skip
    login = (await make_writer_login()).model_copy(update={"name": test_database})
    result = await writer_login_check(Settings(database=login))
    assert (result.label, result.detail) == (
        "PASS", f"{login.writer_user}: exactly the writer's grants")  # fmt: skip
    wrong = login.model_copy(update={"writer_password": SecretStr("not-its-password-at-all")})
    refused = await writer_login_check(Settings(database=wrong))
    assert (refused.label, "run `argus db bootstrap`" in refused.detail) == ("FAIL", True)
    none = login.model_copy(update={"writer_password": None})
    off = await writer_login_check(Settings(database=none))
    assert (off.label, "off until its canary" in off.detail) == ("PASS", True)
