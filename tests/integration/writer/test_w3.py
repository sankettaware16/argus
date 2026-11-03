"""Q-D4, W3: an approved closure is checked again at send time, closes the case with its reason
tags and then comments, naming the approver; a revoked approver, a changed alert set or Sync
alerts on send nothing."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.cases.conftest import Person
from tests.integration.writer.kit import approved_closure, created, rig

pytestmark = pytest.mark.integration


async def test_an_approved_closure_closes_with_reason_tags_then_the_comment(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine, people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, api_engine, writer_engine)
    case_id, kid = await created(r, people)
    r.kibana.cases[kid]["tags"].append("team-blue")
    request_id = await approved_closure(r, api_engine, people, case_id, kid)

    report = await r.run("W3", limit=1)

    assert report.stopped is None, report.lines()
    assert (report.units, report.sent, report.verified, report.mismatches) == (1, 2, 2, 0)
    case = r.kibana.cases[kid]
    assert case["status"] == "closed"
    assert {
        "argus:closed",
        "argus:state:closed",
        "argus:reason:benign_expected",
        "team-blue",
    } <= set(case["tags"])
    closing = r.kibana.comments[kid][-1]["comment"]
    assert closing.startswith("Closed by ARGUS on the approval of Ravi (` ravi `)")
    assert "Reason: expected activity (` benign_expected `)" in closing
    states = await r.outbox(case_id)
    assert [s for _, _, s in states][-2:] == ["verified", "verified"]
    ledger = [e for e in r.lane.ledger if e.write_class == "W3"]
    assert len(ledger) == 2
    assert {e.approval_id for e in ledger} == {str(request_id)}
    assert all(e.payload_hash and e.outbox_id for e in ledger)  # bound to the row and its payload
    audit = await r.sql("SELECT details FROM audit_events WHERE action = 'kibana.write.verified'"
                        " AND details->>'class' = 'W3'")  # fmt: skip
    assert {a.details["approval"] for a in audit} == {request_id}
    assert (await r.run("W3", limit=5)).sent == 0  # a second run writes nothing


async def test_an_approver_revoked_between_approval_and_send_gets_nothing_sent(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine, people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, api_engine, writer_engine)
    case_id, kid = await created(r, people)
    await approved_closure(r, api_engine, people, case_id, kid)
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE users SET disabled = true WHERE username = 'ravi'"))
    before = r.kibana.count("PATCH")

    await r.run("W3", limit=5)

    assert r.kibana.count("PATCH") == before
    assert r.kibana.cases[kid]["status"] == "open"
    states = [s for _, op, s in await r.outbox(case_id) if op in ("close",)]
    assert states == ["paused"]  # held back for a re-confirmation by the send-time check


async def test_sync_alerts_on_holds_a_closure_back(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine, people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, api_engine, writer_engine)
    case_id, kid = await created(r, people)
    await approved_closure(r, api_engine, people, case_id, kid)
    r.kibana.cases[kid]["settings"] = {"syncAlerts": True}  # switched on after the mirror was read

    report = await r.run("W3", limit=5)

    assert r.kibana.cases[kid]["status"] == "open"
    assert r.kibana.count("PATCH") == 0
    assert any("Sync alerts is on" in h for h in report.held)
    r.kibana.cases[kid]["settings"] = {"syncAlerts": False}
    assert (await r.run("W3", limit=5)).verified == 2
