"""Q-D4, W1 on the real database through the real Kibana lane (a writable fake Kibana): a case
is created, then its opening comment and representative alerts, each read back."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.cases.conftest import Person
from tests.integration.cases.test_service import _kibana_actor
from tests.integration.writer.kit import LINK_BASE, mirrored_case, rig

pytestmark = pytest.mark.integration


async def test_a_canary_creates_the_case_comments_and_attaches_its_alerts(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await mirrored_case(
        app_engine, migrated_engine, people["asha"], _kibana_actor(people["asha"]), alerts=3
    )
    assert await r.outbox(case_id) == [("W1", "create", "planned")]

    report = await r.run("W1", limit=1, kind="canary")

    assert report.stopped is None, report.lines()
    assert (report.units, report.sent, report.verified, report.mismatches) == (1, 3, 3, 0)
    assert await r.outbox(case_id) == [("W1", "create", "verified")]
    assert await r.steps(case_id) == [("comment", 0, "verified"), ("attach", 1, "verified")]
    [case] = r.kibana.ours()
    assert case["created_by"]["username"] == "argus"
    assert case["settings"] == {"syncAlerts": False}
    assert case["title"].startswith("[ARGUS 1] ")
    assert f"{LINK_BASE}/go/case/{case_id}" in case["description"]
    assert case["totalComment"] == 1
    assert case["totalAlerts"] == 2
    comments = r.kibana.comments[case["id"]]
    assert len(comments) == 1
    assert comments[0]["comment"].startswith("ARGUS opened this case.")
    run = (await r.sql("SELECT * FROM kibana_writer_runs"))[0]
    assert (run.write_class, run.kind, run.step, run.units, run.sent, run.verified) == (
        "W1", "canary", 1, 1, 3, 3,
    )  # fmt: skip

    again = await r.run("W1", limit=1, kind="canary")  # a second run writes nothing
    assert (again.units, again.sent) == (0, 0)
    assert r.kibana.count("POST") == 3
