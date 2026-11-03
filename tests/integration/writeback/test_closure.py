"""Q-D5, DQ11 (a): an approved case closure closes its alerts. The case, its closure request and
the two approvals are the case tests' (the writer kit's); the alerts are written to the fake
Kibana through the real lane."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.cases.conftest import Person
from tests.integration.cases.test_service import _kibana_actor
from tests.integration.writeback.kit import Rig, rig
from tests.integration.writeback.test_writeback import diff, plan, rows
from tests.integration.writer.kit import approved_closure, mirrored_case

pytestmark = pytest.mark.integration


async def closed_case(
    app: AsyncEngine, owner: AsyncEngine, writer: AsyncEngine, api: AsyncEngine,
    people: dict[str, Person], reason: str = "benign_expected", alerts: int = 3,
) -> tuple[Rig, Any]:  # fmt: skip
    r = rig(owner, writer)
    case_id = await mirrored_case(
        app, owner, people["asha"], _kibana_actor(people["asha"]), alerts=alerts
    )
    await approved_closure(
        r, api, people, case_id, "kibana-case-1", reason,  # type: ignore[arg-type]
        version="WzEsMV0=",
    )  # fmt: skip
    await r.seed_world()
    return r, case_id


async def test_an_approved_closure_closes_its_alerts_once(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    api_engine: AsyncEngine, people: dict[str, Person],
) -> None:  # fmt: skip
    r, case_id = await closed_case(app_engine, migrated_engine, writer_engine, api_engine, people)
    assert await plan(app_engine) == 1
    assert await plan(app_engine) == 0
    assert await diff(app_engine) == {"closed": {"reviews": 1, "alerts": 3}}
    row = await r.row()
    assert (row.review_id, row.investigation_id, row.case_id) == (None, None, case_id)
    assert row.closure_request_id is not None
    result = await r.run()
    assert (result.sent_alerts, result.sent_rows) == (3, 1)
    assert all(s == "closed" for s in r.world.statuses.values())
    assert [tuple(x) for x in await rows(app_engine)] == [("sent", "closed", 3)]
    assert (await r.run()).sent_alerts == 0  # a second run writes nothing
    assert await plan(app_engine) == 0


@pytest.mark.parametrize("reason", ["duplicate", "created_in_error"])
async def test_a_closure_that_says_nothing_about_the_alerts_leaves_them(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    api_engine: AsyncEngine, people: dict[str, Person], reason: str,
) -> None:  # fmt: skip
    r, case_id = await closed_case(app_engine, migrated_engine, writer_engine, api_engine, people)
    async with migrated_engine.begin() as conn:  # these two reasons close a case another way
        await conn.execute(text("ALTER TABLE cases DISABLE TRIGGER USER"))
        await conn.execute(
            text("UPDATE cases SET closure_reason = :r WHERE id = :c"), {"r": reason, "c": case_id}
        )
    assert await plan(app_engine) == 0
    assert (await r.run()).sent_alerts == 0
    assert r.world.calls == []


async def test_a_case_reopened_before_the_run_is_not_written(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    api_engine: AsyncEngine, people: dict[str, Person],
) -> None:  # fmt: skip
    r, case_id = await closed_case(app_engine, migrated_engine, writer_engine, api_engine, people)
    assert await plan(app_engine) == 1
    async with migrated_engine.begin() as conn:  # a reopen, as the owner (the case machine's
        await conn.execute(text("ALTER TABLE cases DISABLE TRIGGER USER"))  # triggers off)
        await conn.execute(
            text(
                "UPDATE cases SET state = 'open', closed_at = NULL, closure_reason = NULL,"
                " closure_request_id = NULL WHERE id = :c"
            ),
            {"c": case_id},
        )
    result = await r.run()  # the sender checks the case before each batch
    assert (result.sent_alerts, r.world.calls) == (0, [])
    assert (await r.row()).state == "skipped"
    assert await plan(app_engine) == 0  # and a plan does not bring it back
    assert await diff(app_engine) == {}
