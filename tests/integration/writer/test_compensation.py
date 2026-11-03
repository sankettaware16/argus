"""Q-D4: approved compensating writes for W2 and W3 (plan §3 rule 3): the change is put back as
the before-image had it, a correcting comment follows (the earlier comment stays), both are
approved by a person, signed, read back, and done once."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.machine import Take
from tests.integration.cases.conftest import Person
from tests.integration.cases.test_service import _apply
from tests.integration.writer.kit import (
    approve_compensation,
    approved_closure,
    created,
    mirror,
    rig,
)

pytestmark = pytest.mark.integration


async def _taken(r, app, people):  # type: ignore[no-untyped-def]
    case_id, kid = await created(r, people)
    await mirror(r.owner, case_id, kid, version=str(r.kibana.cases[kid]["version"]))
    await _apply(app, people["ravi"].actor(), case_id, Take(), 1)
    await r.run("W2", limit=1)
    row = (await r.sql("SELECT id FROM kibana_outbox WHERE op = 'update'"))[0].id
    return case_id, kid, int(row)


async def test_an_approved_compensating_write_puts_a_w2_change_back(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine, people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, api_engine, writer_engine)
    _, kid, row = await _taken(r, api_engine, people)
    assert r.kibana.cases[kid]["status"] == "in-progress"
    request = await approve_compensation(r, api_engine, people, row)

    report = await r.run("W2", limit=5)

    assert report.stopped is None, report.lines()
    case = r.kibana.cases[kid]
    assert case["status"] == "open"
    assert "argus:owner:argus" in case["tags"]
    assert not any(t.startswith("argus:owner:user-") for t in case["tags"])
    comments = [c["comment"] for c in r.kibana.comments[kid]]
    assert comments[-2].startswith("Taken in ARGUS by")  # the earlier comment stays
    assert comments[-1].startswith("ARGUS corrected the earlier change")
    assert "Ravi" in comments[-1]
    steps = await r.sql("SELECT kind, state, approval_request_id FROM kibana_steps"
                        " WHERE kind LIKE 'compensate%' ORDER BY id")  # fmt: skip
    assert [(s.kind, s.state, s.approval_request_id) for s in steps] == [
        ("compensate_update", "verified", request), ("compensate_comment", "verified", request),
    ]  # fmt: skip
    audit = await r.sql("SELECT action FROM audit_events WHERE action LIKE 'kibana.compensation%'")
    assert [a.action for a in audit] == ["kibana.compensation.planned"]
    patches = r.kibana.count("PATCH")
    await r.run("W2", limit=5)  # done once
    assert r.kibana.count("PATCH") == patches


async def test_an_approved_compensating_write_reopens_a_closed_case(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine, people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, api_engine, writer_engine)
    case_id, kid = await created(r, people)
    await approved_closure(r, api_engine, people, case_id, kid)
    await r.run("W3", limit=1)
    assert r.kibana.cases[kid]["status"] == "closed"
    row = int((await r.sql("SELECT id FROM kibana_outbox WHERE op = 'close'"))[0].id)
    assert (await r.sql("SELECT before_image IS NOT NULL AS b FROM kibana_outbox WHERE id = :i",
                        i=row))[0].b  # fmt: skip
    await approve_compensation(r, api_engine, people, row)

    report = await r.run("W2", limit=5)

    assert report.stopped is None, report.lines()
    case = r.kibana.cases[kid]
    assert case["status"] == "open"
    assert not {"argus:closed", "argus:state:closed"} & set(case["tags"])
    assert not any(t.startswith("argus:reason:") for t in case["tags"])
    assert r.kibana.comments[kid][-1]["comment"].startswith("ARGUS corrected the earlier closure")


async def test_a_compensating_approval_that_does_not_stand_is_not_acted_on(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine, people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, api_engine, writer_engine)
    _, kid, row = await _taken(r, api_engine, people)
    await approve_compensation(r, api_engine, people, row)
    async with migrated_engine.begin() as conn:  # the approver is revoked before the write
        await conn.execute(text("UPDATE users SET disabled = true WHERE username = 'ravi'"))
    before = r.kibana.count("PATCH")

    await r.run("W2", limit=5)

    assert r.kibana.count("PATCH") == before
    assert r.kibana.cases[kid]["status"] == "in-progress"
    assert (await r.sql("SELECT count(*) AS n FROM kibana_steps WHERE kind LIKE 'compensate%'"))[
        0
    ].n == 0


async def test_a_tampered_or_unsigned_approval_and_a_stale_payload_are_refused(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine, people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, api_engine, writer_engine)
    _, _, row = await _taken(r, api_engine, people)
    request = await approve_compensation(r, api_engine, people, row)
    async with migrated_engine.begin() as conn:  # the signature of the decision is changed
        for stmt in (
            "ALTER TABLE approval_decisions DISABLE TRIGGER approval_decisions_append_only_rows",
            "UPDATE approval_decisions SET signature = left(signature, -1) ||"
            " CASE WHEN right(signature, 1) = '0' THEN '1' ELSE '0' END",
            "ALTER TABLE approval_decisions ENABLE ALWAYS TRIGGER"
            " approval_decisions_append_only_rows",
        ):
            await conn.execute(text(stmt))
    refused = await r.writer.apply_compensations()
    assert refused
    assert "no valid signature" in refused[0]
    assert str(request) in refused[0]
    assert (await r.sql("SELECT count(*) AS n FROM kibana_steps WHERE kind LIKE 'compensate%'"))[
        0
    ].n == 0

    # without the key the writer cannot check a signature at all
    r2 = rig(migrated_engine, api_engine, writer_engine, verifier=None)
    assert "no approval key" in (await r2.writer.apply_compensations())[0]
