"""Q-C3's gate as a property: whatever happens between an approval and the send (the approver
disabled or denied, the approval expired, a decision's signature changed, the case reopened,
the Kibana case or the case's alerts moved, Sync alerts switched on, the approver's privilege
lost), the closure write leaves ARGUS only when every bound fact still holds, or after a
person's re-confirmation binds the new facts; never on a tampered approval or a reopened case.

A database-backed Hypothesis test keeps a fixed number of examples (40; Q-C1 decision 12)."""

from __future__ import annotations

import uuid
from datetime import timedelta

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import identity
from argus.cases.machine import Reopen
from argus.cases.model import KIBANA_TO_OPEN
from tests.integration.cases.conftest import APPROVER, Person, investigation, make_person, rows
from tests.integration.cases.test_closure_approval import (
    FakeWriter,
    _desk_decide,
    _mirror,
    _owner_sql,
    _state,
    _unguarded,
)
from tests.integration.cases.test_service import _apply, _open, _request

OPS = ("disable", "deny", "expire", "tamper", "reopen", "kibana", "sync", "alerts", "privilege")


async def _apply_op(op: str, api: AsyncEngine, owner: AsyncEngine, approver: Person,
                    case_id: uuid.UUID, requester: Person) -> None:  # fmt: skip
    if op == "disable":
        await _owner_sql(
            owner, "UPDATE users SET disabled = true WHERE id = :u", u=approver.user_id
        )
    elif op in ("deny", "privilege"):
        async with api.begin() as conn:
            now = await identity.database_clock(conn)
            check = (
                identity.LiveCheck(approver.user_id, "denied", "fake", now)
                if op == "deny"
                else identity.LiveCheck(
                    approver.user_id,
                    "ok",
                    "fake",
                    now,
                    "person",
                    APPROVER,
                    frozenset({"createCase"}),
                )
            )
            await identity.record(conn, check, "recheck")
    elif op == "tamper":
        await _owner_sql(owner, *_unguarded(
            "approval_decisions",
            "UPDATE approval_decisions SET signature = left(signature, -1)"
            " || CASE WHEN right(signature, 1) = '0' THEN '1' ELSE '0' END"
            " WHERE request_id IN (SELECT id FROM approval_requests WHERE case_id = :c)",
        ), c=case_id)  # fmt: skip
    elif op == "reopen":
        version = (await rows(api, "SELECT version FROM cases WHERE id = :c", c=case_id))[0]
        await _apply(api, requester.actor(), case_id, Reopen("seen again"), version.version)
    elif op == "kibana":
        await _mirror(owner, case_id, "WzksOV0=")
    elif op == "sync":
        await _owner_sql(owner, "UPDATE kibana_mirror SET sync_alerts = true WHERE case_id = :c",
                         c=case_id)  # fmt: skip
    elif op == "alerts":
        inv = (await rows(api, "SELECT investigation_id FROM case_members WHERE case_id = :c",
                          c=case_id))[0].investigation_id  # fmt: skip
        alert = f"late-{uuid.uuid4().hex[:8]}"
        await _owner_sql(
            owner,
            "INSERT INTO alert_records (alert_id, index, status, normalizer_version, raw,"
            " content_hash, state_hash, recovered_by, detected_at) VALUES (:a, 'alerts',"
            " 'normalized', 'test', '{}', 'h', 'h', 'live', now())",
            "INSERT INTO investigation_alerts (alert_id, investigation_id) VALUES (:a, :i)",
            a=alert, i=inv,
        )  # fmt: skip


@settings(
    max_examples=40, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(st.sets(st.sampled_from(OPS), max_size=3), st.booleans())
async def test_a_closure_write_leaves_only_on_a_valid_approval(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    ops: set[str], reconfirm: bool,
) -> None:  # fmt: skip
    tag = uuid.uuid4().hex[:8]
    asha, ravi, meera = [await make_person(api_engine, f"{n}{tag}") for n in "arm"]
    inv = await investigation(migrated_engine, actor=(("source.ip", f"10.9.{int(tag[:2], 16)}.1"),))
    async with api_engine.begin() as conn:
        now = (await conn.execute(text("SELECT now()"))).scalar_one()
    case_id = await _open(api_engine, asha.actor(APPROVER, kibana=KIBANA_TO_OPEN,
                                                 checked_at=now), [inv])  # fmt: skip
    await _mirror(migrated_engine, case_id)
    request = await _request(api_engine, asha, case_id, 1)
    assert await _desk_decide(api_engine, ravi, request) == "approved"
    row = int((await rows(app_engine, "SELECT id FROM kibana_outbox WHERE case_id = :c"
                                      " AND op = 'close'", c=case_id))[0].id)  # fmt: skip
    for op in sorted(ops):
        await _apply_op(op, api_engine, migrated_engine, ravi, case_id, asha)

    later = None
    if "expire" in ops:  # the writer's first pass after the approval's expiry
        expires = (await rows(app_engine, "SELECT expires_at FROM approval_requests"
                                          " WHERE id = :r", r=request))[0].expires_at  # fmt: skip
        later = expires + timedelta(seconds=1)
    writer = FakeWriter()
    results = await writer.run(app_engine, later)
    if "reopen" in ops:
        expected = "skip"
    elif ops & {"sync", "tamper"}:
        expected = "refuse"
    elif ops:
        expected = "reconfirm"
    else:
        expected = "send"
    assert results[row].verdict == expected, (ops, results[row])
    # the examples share one database: only this example's row is judged
    assert writer.sent.count(row) == (1 if expected == "send" else 0)
    state = (await _state(app_engine, row))[0]
    assert state == {"send": "approved", "skip": "skipped"}.get(expected, "paused")

    asked = await rows(app_engine, "SELECT id FROM approval_requests WHERE kind = 'reconfirm'"
                                   " AND outbox_id = :r", r=row)  # fmt: skip
    assert len(asked) == (1 if expected == "reconfirm" else 0)
    if expected == "reconfirm" and reconfirm:
        assert await _desk_decide(api_engine, meera, int(asked[0].id)) == "approved"
        results = await writer.run(app_engine)
        assert results[row].verdict == "send", (ops, results[row])
        assert writer.sent.count(row) == 1
