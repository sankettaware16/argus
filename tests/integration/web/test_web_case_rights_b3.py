"""Q-B3, migration 0042: the web's own login may run the case commands a person gives and read the
case record, and nothing more. Whatever it tries directly, the database's guards (lifecycle edges,
versions, closing only on a complete approval, the outbox moves, append-only tables, the hash
chains) hold for it as for every role."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.web.b3_support import World, make_world

pytestmark = pytest.mark.integration


@pytest.fixture
async def world(
    seeded: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> World:
    return await make_world(seeded, web_engine, migrated_engine, tmp_path)


async def refused(web: AsyncEngine, sql: str, **params: object) -> str:
    """The database's refusal of one statement from the web's login (at the statement, or at the
    commit for the checks that wait for it)."""
    with pytest.raises(DBAPIError) as info:
        async with web.begin() as conn:
            await conn.execute(text(sql), params)
    return str(info.value.orig)


async def test_the_web_reads_the_case_record(world: World) -> None:
    case = await world.open_case(1, kibana=True)
    async with world.web.connect() as conn:
        for table in ("cases", "case_members", "case_indicators", "case_events", "case_notes",
                      "entity_notes", "kibana_outbox", "kibana_mirror", "kibana_findings",
                      "approval_requests", "approval_decisions"):  # fmt: skip
            await conn.execute(text(f"SELECT * FROM {table} LIMIT 1"))  # noqa: S608
        found = (await conn.execute(text("SELECT count(*) FROM kibana_outbox WHERE case_id = :c"),
                                    {"c": case})).scalar_one()  # fmt: skip
    assert found == 1


@pytest.mark.parametrize(
    "statement",
    [
        "DELETE FROM cases",
        "DELETE FROM case_events",
        "DELETE FROM case_members",
        "DELETE FROM case_notes",
        "DELETE FROM kibana_outbox",
        "UPDATE case_events SET kind = 'taken'",
        "UPDATE case_notes SET body = 'changed'",
        "UPDATE entity_notes SET body = 'changed'",
        "UPDATE kibana_outbox SET state = 'sent'",
        "UPDATE kibana_outbox SET payload = '{}'",
        "UPDATE approval_requests SET expires_at = expires_at + interval '1 day'",
        "UPDATE approval_decisions SET decision = 'approved'",
        "UPDATE kibana_mirror SET paused_reason = NULL",
        "UPDATE kibana_findings SET resolved_at = now()",
        "UPDATE chain_heads SET seq = 0",
        "SELECT * FROM chain_heads",
        "INSERT INTO chain_heads (chain, seq, head_hash, genesis_hash, legacy_rows, legacy_max_id)"
        " VALUES ('x', 0, repeat('a', 64), repeat('a', 64), 0, 0)",
        "INSERT INTO cases (id, title, state, severity, version, cause) VALUES"
        " (gen_random_uuid(), 't', 'open', 'low', 1, 'person')",
        "UPDATE cases SET number = 99",
        "UPDATE cases SET cause = 'proposal'",
        "UPDATE cases SET created_at = now()",
        "INSERT INTO kibana_mirror (case_id, kibana_case_id, kibana_version, status, title,"
        " severity, tags, created_by, sync_alerts, kibana_created_at, read_at) VALUES"
        " (gen_random_uuid(), 'k', 'v', 'open', 't', 'low', '{}', 'argus', false, now(), now())",
        "INSERT INTO kibana_findings (found_at, kind, severity, dedupe_key) VALUES"
        " (now(), 'person_commented', 'info', 'forged')",
        "INSERT INTO approval_requests (case_id, case_version, kind, payload, payload_hash,"
        " alert_count, alert_digest, required_approvals, requested_by_user_id, expires_at)"
        " VALUES (gen_random_uuid(), 1, 'closure', '{}', repeat('a', 64), 0, repeat('a', 64), 1,"
        " 1, now() + interval '1 hour')",
        "INSERT INTO approval_decisions (request_id, approver_user_id, decision, capabilities)"
        " VALUES (1, 1, 'approved', '[]')",
    ],
)
async def test_the_web_may_not_do_more_than_the_commands_need(world: World, statement: str) -> None:
    await world.open_case(1)
    said = await refused(world.web, statement)
    assert any(w in said for w in ("permission denied", "append-only", "only be updated")), said


async def test_the_database_still_refuses_a_closure_without_a_complete_approval(
    world: World,
) -> None:
    """The web holds UPDATE on the case's columns, and that is not a way round the approval: the
    guard is the database's, and it is the same for every role."""
    case = await world.open_case(1)
    base = "UPDATE cases SET state = 'closed', closed_at = now(), version = 2"
    said = await refused(world.web, f"{base}, closure_reason = 'benign_expected'"
                         " WHERE id = :c", c=case)  # fmt: skip
    assert "needs an approval" in said or "closure_request_id" in said or "check" in said, said
    said = await refused(world.web, "UPDATE cases SET version = 5 WHERE id = :c", c=case)
    assert "does not follow" in said, said
    said = await refused(world.web, "UPDATE cases SET state = 'contained', version = 2"
                         " WHERE id = :c", c=case)  # fmt: skip
    assert "has no case event" in said or "no case event" in said, said
    row = (await world.rows("SELECT state, version FROM cases"))[0]
    assert (row.state, row.version) == ("open", 1)


async def test_the_web_cannot_plan_a_kibana_closure_of_its_own(world: World) -> None:
    case = await world.open_case(1, kibana=True)
    # a W2 change that closes the Kibana case is refused: only an approved W3 write closes one
    async with world.web.connect() as conn:
        event = (await conn.execute(text("SELECT id FROM case_events WHERE case_id = :c"),
                                    {"c": case})).scalar_one()  # fmt: skip
    said = await refused(
        world.web,
        "INSERT INTO kibana_outbox (case_id, case_event_id, position, idempotency_key,"
        " write_class, op, payload, payload_hash) VALUES (:c, :e, 5, 'forged', 'W2',"
        " 'update', '{\"status\": \"closed\"}', repeat('a', 64))",
        c=case, e=event,
    )  # fmt: skip
    assert "outbox" in said, said
