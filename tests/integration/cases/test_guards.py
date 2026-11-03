"""The database's own guarantees (migration 0026), tested by going around CaseService: as the
runtime role (what a compromised ARGUS service could send) and as the owner (who holds every
privilege, so only the triggers stand in the way)."""

from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import approvals, kibana
from argus.cases.machine import Take
from argus.cases.model import KIBANA_TO_OPEN
from argus.cases.service import CaseService
from tests.integration.cases.conftest import (
    APPROVER,
    Person,
    asking,
    investigation,
    rows,
    signed_for,
)
from tests.integration.cases.test_service import _apply, _decide, _open, _request

GUARD = "QC422"


async def _sql(engine: AsyncEngine, *statements: str, **params: object) -> None:
    async with engine.begin() as conn:
        for statement in statements:
            await conn.execute(text(statement), params)


async def _refused(engine: AsyncEngine, match: str, *statements: str, **params: object) -> None:
    with pytest.raises(DBAPIError, match=match):
        await _sql(engine, *statements, **params)


def _close(version: int, request: str = "NULL") -> str:
    return (
        f"UPDATE cases SET state = 'closed', closed_at = now(), closure_reason = 'benign_expected',"  # noqa: S608 - a test
        f" closure_request_id = {request}, version = {version} WHERE id = :c"
    )


async def _event(engine: AsyncEngine, case_id: uuid.UUID, version: int, to: str = "closed") -> str:
    return (
        "INSERT INTO case_events (case_id, case_version, kind, actor, from_state, to_state)"  # noqa: S608 - a test
        f" VALUES (:c, {version}, 'closed', 'mallory', 'open', '{to}')"
    )


@pytest.fixture
async def case_id(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> uuid.UUID:
    inv = await investigation(migrated_engine)
    return await _open(app_engine, people["asha"].actor(), [inv])


async def test_the_runtime_role_cannot_close_a_confirmed_case_on_its_own(
    app_engine: AsyncEngine, case_id: uuid.UUID
) -> None:
    event = await _event(app_engine, case_id, 2)
    await _refused(app_engine, "closing a confirmed case needs an approval", _close(2), event,
                   c=case_id)  # fmt: skip


async def test_an_approval_of_another_case_or_an_incomplete_one_closes_nothing(
    api_engine: AsyncEngine,
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    case_id: uuid.UUID,
    people: dict[str, Person],
) -> None:
    other_inv = await investigation(migrated_engine, actor=(("source.ip", "10.0.0.5"),))
    other = await _open(api_engine, people["asha"].actor(), [other_inv])
    approved = await _request(api_engine, people["asha"], other, 1)
    await _decide(api_engine, people["ravi"], approved)  # closes `other` (now version 3)
    pending = await _request(api_engine, people["asha"], case_id, 1)  # case_id at version 2
    for request in (approved, pending):
        await _refused(app_engine, "does not allow this closure", _close(3, str(request)),
                       await _event(app_engine, case_id, 3), c=case_id)  # fmt: skip


async def test_versions_rise_by_one_along_the_lifecycle_edges(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, case_id: uuid.UUID
) -> None:
    for statement, message in (
        ("UPDATE cases SET version = 3 WHERE id = :c", "does not follow"),
        ("UPDATE cases SET version = 1 WHERE id = :c", "does not follow"),
        ("UPDATE cases SET title = 'x' WHERE id = :c", "does not follow"),
        ("UPDATE cases SET state = 'suspected', opened_at = NULL, version = 2 WHERE id = :c",
         "a fixed field changed"),
    ):  # fmt: skip
        await _refused(app_engine, message, statement, c=case_id)
    await _refused(
        migrated_engine, "a fixed field changed",
        "UPDATE cases SET cause = 'proposal', cause_assessment_id = NULL, version = 2"
        " WHERE id = :c", c=case_id,
    )  # fmt: skip
    for statement in ("UPDATE cases SET cause = 'proposal' WHERE id = :c",
                      "UPDATE cases SET number = 7 WHERE id = :c",
                      "UPDATE cases SET created_at = now() WHERE id = :c",
                      "DELETE FROM cases WHERE id = :c"):  # fmt: skip
        await _refused(app_engine, "permission denied|can only be updated to DEFAULT", statement,
                       c=case_id)  # fmt: skip


async def test_a_move_off_the_lifecycle_is_refused_even_for_the_owner(
    migrated_engine: AsyncEngine, case_id: uuid.UUID
) -> None:
    await _refused(
        migrated_engine, "contained to assigned is not a lifecycle move",
        "UPDATE cases SET state = 'contained', version = 2 WHERE id = :c",
        "INSERT INTO case_events (case_id, case_version, kind, actor, from_state, to_state)"
        " VALUES (:c, 2, 'contained', 'x', 'open', 'contained')",
        "UPDATE cases SET state = 'assigned', owner_user_id = 1, version = 3 WHERE id = :c",
        c=case_id,
    )  # fmt: skip


async def test_every_version_has_its_event_with_its_state(
    app_engine: AsyncEngine, case_id: uuid.UUID
) -> None:
    await _refused(app_engine, "version 2 \\(assigned\\) has no case event",
                   "UPDATE cases SET state = 'assigned', owner_user_id = 1, version = 2"
                   " WHERE id = :c", c=case_id)  # fmt: skip
    await _refused(  # the event names a state the case is not in: refused as it is written
        app_engine, "is not at version 2 \\(open\\)",
        "UPDATE cases SET state = 'assigned', owner_user_id = 1, version = 2 WHERE id = :c",
        "INSERT INTO case_events (case_id, case_version, kind, actor, from_state, to_state)"
        " VALUES (:c, 2, 'taken', 'mallory', 'open', 'open')",
        c=case_id,
    )  # fmt: skip
    await _refused(
        app_engine,
        "has no case event",
        "INSERT INTO cases (id, title, state, severity, version, cause, opened_at)"
        " VALUES (gen_random_uuid(), 't', 'open', 'low', 1, 'person', now())",
    )


async def test_an_event_has_exactly_its_outbox_rows(
    app_engine: AsyncEngine, case_id: uuid.UUID
) -> None:
    event = (
        "INSERT INTO case_events (case_id, case_version, kind, actor, from_state, to_state,"
        " kibana_rows) VALUES (:c, 2, 'taken', 'x', 'open', 'assigned', 1)"
    )
    take = "UPDATE cases SET state = 'assigned', owner_user_id = 1, version = 2 WHERE id = :c"
    await _refused(app_engine, "planned 1 Kibana rows", take, event, c=case_id)
    row = (
        "INSERT INTO kibana_outbox (case_id, case_event_id, position, idempotency_key,"
        " write_class, op, payload, payload_hash) SELECT :c, id, {p}, 'k{p}', 'W2', 'update',"
        " '{{}}', repeat('a', 64) FROM case_events WHERE case_id = :c AND case_version = 2"
    )
    await _refused(app_engine, "does not belong to case event", take, event,
                   row.format(p=1), c=case_id)  # position beyond kibana_rows  # fmt: skip
    await _sql(app_engine, take, event, row.format(p=0), c=case_id)
    await _refused(app_engine, "does not belong to case event|duplicate key", row.format(p=0),
                   c=case_id)  # no row added later  # fmt: skip
    first = (await rows(app_engine, "SELECT id FROM case_events WHERE case_version = 1"))[0].id
    await _refused(
        app_engine, "does not belong to case event",
        "INSERT INTO kibana_outbox (case_id, case_event_id, position, idempotency_key,"
        " write_class, op, payload, payload_hash) VALUES (:c, :e, 0, 'late', 'W2', 'update',"
        " '{}', repeat('a', 64))", c=case_id, e=first,
    )  # fmt: skip


async def test_append_only_tables_stay_as_written(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, case_id: uuid.UUID,
    people: dict[str, Person],
) -> None:  # fmt: skip
    request = await _request(api_engine, people["asha"], case_id, 1)
    await _decide(api_engine, people["ravi"], request, "rejected")
    async with api_engine.begin() as conn:
        await (await CaseService.start(conn)).add_note(people["asha"].actor(), case_id, "seen")
    for table, column in (("case_events", "kind"), ("approval_requests", "note"),
                          ("approval_decisions", "note"), ("case_notes", "body")):  # fmt: skip
        for statement in (f"UPDATE {table} SET {column} = {column}", f"DELETE FROM {table}",  # noqa: S608
                          f"TRUNCATE {table} CASCADE"):  # fmt: skip
            await _refused(migrated_engine, "append-only", statement)
            await _refused(api_engine, "permission denied|append-only", statement)


# --------------------------------------------------------------------------- the outbox


async def _outbox_case(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, person: Person
) -> int:
    from datetime import UTC, datetime, timedelta

    inv = await investigation(migrated_engine)
    actor = person.actor(APPROVER, kibana=KIBANA_TO_OPEN,
                         checked_at=datetime.now(UTC) - timedelta(seconds=1))  # fmt: skip
    await _open(app_engine, actor, [inv])
    return int((await rows(app_engine, "SELECT id FROM kibana_outbox"))[0].id)


async def _move(engine: AsyncEngine, row: int, sets: str) -> None:
    await _sql(engine, f"UPDATE kibana_outbox SET {sets} WHERE id = :o", o=row)  # noqa: S608


async def test_an_outbox_row_moves_only_along_its_edges(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    row = await _outbox_case(app_engine, migrated_engine, people["asha"])
    for sets, message in (
        ("state = 'sent'", "planned to sent is not an outbox move"),
        ("state = 'verified'", "planned to verified is not an outbox move"),
        ("payload = '{\"x\": 1}'", "a fixed field changed"),
        ("idempotency_key = 'other'", "a fixed field changed"),
        ("state = 'approved', sent_count = 1", "each send is counted once"),
    ):
        with pytest.raises(DBAPIError, match=message):
            await _move(migrated_engine, row, sets)
    await _move(migrated_engine, row, "state = 'approved'")
    with pytest.raises(DBAPIError, match="each send is counted once"):
        await _move(migrated_engine, row, "state = 'sending'")
    await _move(migrated_engine, row, "state = 'sending', sent_count = 1")
    await _move(migrated_engine, row, "state = 'ambiguous'")
    with pytest.raises(DBAPIError, match="a resend is counted with its approval"):
        await _move(migrated_engine, row, "state = 'planned'")
    with pytest.raises(DBAPIError, match="a resend needs a person's approval"):
        await _move(migrated_engine, row, "state = 'planned', resends = 1")
    await _refused(migrated_engine, "append-only|never|rejected", "DELETE FROM kibana_outbox")
    # Q-C3: the runtime may move a row's state and reason (the send-time check), nothing else
    for sets in ("sent_count = 1", "payload = '{}'", "resends = 1", "approval_request_id = 1"):
        await _refused(app_engine, "permission denied", f"UPDATE kibana_outbox SET {sets}")  # noqa: S608


async def test_a_resend_goes_out_only_with_a_complete_approval(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    row = await _outbox_case(api_engine, migrated_engine, people["asha"])
    await _move(migrated_engine, row, "state = 'approved'")
    await _move(migrated_engine, row, "state = 'sending', sent_count = 1")
    await _move(migrated_engine, row, "state = 'ambiguous'")
    case = (await rows(api_engine, "SELECT id, version FROM cases"))[0]
    async with api_engine.begin() as conn:
        payload = {"resend": row}
        request = await approvals.request(
            conn, session_token=people["asha"].session_token, case_id=case.id,
            case_version=case.version, kind="resend", reason=None, payload=payload,
            payload_hash=kibana.payload_hash(payload),
            expires=approvals.expires_at(__import__("datetime").datetime.now(
                __import__("datetime").UTC)), outbox_id=row,
            check=(await asking(conn, people["asha"])).snapshot(),
        )  # fmt: skip
    with pytest.raises(DBAPIError, match="a resend needs a person's approval"):
        await _move(migrated_engine, row, "state = 'planned', resends = 1")
    async with api_engine.begin() as conn:
        assert await approvals.decide(
            conn, session_token=people["ravi"].session_token, request_id=request,
            decision="approved", signed=await signed_for(conn, people["ravi"], request),
        ) == "approved"  # fmt: skip
    await _move(migrated_engine, row, "state = 'planned', resends = 1")
    await _move(migrated_engine, row, "state = 'approved'")
    await _move(migrated_engine, row, "state = 'sending', sent_count = 2")
    await _move(migrated_engine, row, "state = 'ambiguous'")
    await _move(migrated_engine, row, "state = 'paused'")
    await _move(migrated_engine, row, "state = 'planned'")
    await _move(migrated_engine, row, "state = 'approved'")
    with pytest.raises(DBAPIError, match="sent_at_most_once"):  # a third send needs another
        await _move(migrated_engine, row, "state = 'sending', sent_count = 3")


async def _resend_request(api_engine: AsyncEngine, person: Person, row: int) -> int:
    from datetime import UTC, datetime

    case = (await rows(api_engine, "SELECT id, version FROM cases"))[0]
    payload = {"resend": row}
    async with api_engine.begin() as conn:
        return await approvals.request(
            conn, session_token=person.session_token, case_id=case.id, case_version=case.version,
            kind="resend", reason=None, payload=payload, payload_hash=kibana.payload_hash(payload),
            expires=approvals.expires_at(datetime.now(UTC)), outbox_id=row,
            check=(await asking(conn, person)).snapshot(),
        )  # fmt: skip


async def test_one_resend_approval_lets_one_resend_through(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """An approved resend is used up by its resend: the next ambiguous send needs a new one,
    even while the first approval has not expired."""
    row = await _outbox_case(api_engine, migrated_engine, people["asha"])
    for sets in ("state = 'approved'", "state = 'sending', sent_count = 1", "state = 'ambiguous'"):
        await _move(migrated_engine, row, sets)
    first = await _resend_request(api_engine, people["asha"], row)
    await _decide(api_engine, people["ravi"], first)
    for sets in ("state = 'planned', resends = 1", "state = 'approved'",
                 "state = 'sending', sent_count = 2", "state = 'ambiguous'"):  # fmt: skip
        await _move(migrated_engine, row, sets)
    with pytest.raises(DBAPIError, match="a resend needs a person's approval"):
        await _move(migrated_engine, row, "state = 'planned', resends = 2")
    second = await _resend_request(api_engine, people["asha"], row)
    with pytest.raises(DBAPIError, match="a resend needs a person's approval"):
        await _move(migrated_engine, row, "state = 'planned', resends = 2")
    await _decide(api_engine, people["meera"], second)
    await _move(migrated_engine, row, "state = 'planned', resends = 2")


async def test_a_take_on_a_mirrored_case_plans_its_rows_with_the_event(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    await _outbox_case(app_engine, migrated_engine, people["asha"])
    case = (await rows(app_engine, "SELECT id FROM cases"))[0]
    applied = await _apply(app_engine, people["ravi"].actor(), case.id, Take(), 1)
    planned = await rows(
        app_engine,
        "SELECT e.kibana_rows, count(o.id) AS n FROM case_events e LEFT JOIN kibana_outbox o"
        " ON o.case_event_id = e.id WHERE e.id = :e GROUP BY e.kibana_rows", e=applied.event_id,
    )  # fmt: skip
    assert (planned[0].kibana_rows, planned[0].n) == (2, 2)
    query = "SELECT before_image FROM kibana_outbox WHERE case_event_id = :e"
    before = await rows(app_engine, query,
                        e=applied.event_id)  # fmt: skip
    assert before[0].before_image is None  # nothing read back from Kibana yet
    assert json.loads(json.dumps(before[0].before_image)) is None


async def test_a_closure_write_is_exactly_what_its_approval_named(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    """Even the runtime role, writing the rows itself, cannot send a different closure than
    the one a person approved."""
    from datetime import UTC, datetime, timedelta

    inv = await investigation(migrated_engine)
    actor = people["asha"].actor(APPROVER, kibana=KIBANA_TO_OPEN,
                                 checked_at=datetime.now(UTC) - timedelta(seconds=1))  # fmt: skip
    case_id = await _open(api_engine, actor, [inv])
    request = await _request(api_engine, people["asha"], case_id, 1)
    async with api_engine.begin() as conn:  # approved, but not applied
        await approvals.decide(conn, session_token=people["ravi"].session_token,
                               request_id=request, decision="approved",
                               signed=await signed_for(conn, people["ravi"], request))  # fmt: skip
    approved = (await rows(app_engine, "SELECT payload FROM approval_requests"))[0].payload
    close, comment = approved["writes"]
    forged = {**close["payload"], "argus_tags": ["argus"]}
    steps = (
        _close(3, str(request)),
        "INSERT INTO case_events (case_id, case_version, kind, actor, from_state, to_state,"
        " kibana_rows) VALUES (:c, 3, 'closed', 'mallory', 'open', 'closed', 2)",
    )
    row = (
        "INSERT INTO kibana_outbox (case_id, case_event_id, position, idempotency_key, write_class,"
        " op, payload, payload_hash, approval_request_id) SELECT :c, id, :p, :k, 'W3', :op,"
        " CAST(:payload AS jsonb), repeat('a', 64), :r FROM case_events WHERE case_version = 3"
    )
    forged_row = {"c": case_id, "p": 0, "k": "x0", "op": "close", "payload": json.dumps(forged),
                  "r": request}  # fmt: skip

    async def forge() -> None:
        async with app_engine.begin() as conn:
            for statement in steps:
                await conn.execute(text(statement), {"c": case_id})
            await conn.execute(text(row), forged_row)

    with pytest.raises(DBAPIError, match="is not a write approval"):
        await forge()
    async with app_engine.begin() as conn:  # the approved writes, in their order, go in
        for statement in steps:
            await conn.execute(text(statement), {"c": case_id})
        for position, write in enumerate((close, comment)):
            await conn.execute(text(row), {"c": case_id, "p": position, "k": f"x{position}",
                                           "op": write["op"],
                                           "payload": json.dumps(write["payload"]),
                                           "r": request})  # fmt: skip


async def test_requests_name_the_acting_persons_session_and_their_own_rows(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    from datetime import UTC, datetime

    inv = await investigation(migrated_engine)
    case_id = await _open(api_engine, people["asha"].actor(), [inv])
    other_inv = await investigation(migrated_engine, actor=(("source.ip", "10.6.0.1"),))
    other = await _open(api_engine, people["asha"].actor(), [other_inv])
    async with api_engine.begin() as conn:
        with pytest.raises(Exception, match="not the acting person's"):
            await (await CaseService.start(conn)).request_closure(
                people["asha"].actor(), case_id, expected_version=1, reason="benign_expected",
                session_token=people["ravi"].session_token,
                check=await asking(conn, people["asha"]),
            )  # fmt: skip
    for kind, target, message in (("merge", "self", "into another case"),
                                  ("merge", "missing", "into another case")):  # fmt: skip
        tid = case_id if target == "self" else uuid.uuid4()
        async with api_engine.begin() as conn:
            payload = {"x": 1}
            with pytest.raises(approvals.ApprovalError, match=message):
                await approvals.request(
                    conn, session_token=people["asha"].session_token, case_id=case_id,
                    case_version=1, kind=kind, reason="duplicate", payload=payload,
                    payload_hash=kibana.payload_hash(payload),
                    expires=approvals.expires_at(datetime.now(UTC)), target_case_id=tid,
                    check=(await asking(conn, people["asha"])).snapshot(),
                )  # fmt: skip
    third = await investigation(migrated_engine, actor=(("source.ip", "10.6.0.2"),))
    opener_ = people["asha"].actor(APPROVER, kibana=KIBANA_TO_OPEN, checked_at=datetime.now(UTC))
    outbox_case = await _open(api_engine, opener_, [third])
    foreign = (await rows(api_engine, "SELECT id FROM kibana_outbox WHERE case_id = :c",
                          c=outbox_case))[0].id  # fmt: skip
    async with api_engine.begin() as conn:
        payload = {"resend": foreign}
        with pytest.raises(approvals.ApprovalError, match="not this case's"):
            await approvals.request(
                conn, session_token=people["asha"].session_token, case_id=other,
                case_version=1, kind="resend", reason=None, payload=payload,
                payload_hash=kibana.payload_hash(payload),
                expires=approvals.expires_at(datetime.now(UTC)), outbox_id=foreign,
                check=(await asking(conn, people["asha"])).snapshot(),
            )  # fmt: skip
