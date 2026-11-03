"""Q-D4's gate as a property, through the database and the writer: after any run of case changes
in ARGUS and edits by people in Kibana, every tag a person added is still there, a severity a
person edited is as they left it, a status they moved is not reverted, and ARGUS's own tags in
Kibana are exactly the case's (Kibana equal to ARGUS on what ARGUS manages).

A database-backed Hypothesis test keeps a fixed number of examples (Q-C1 decision 12)."""

from __future__ import annotations

import itertools

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import kibana as intent
from argus.cases.machine import Release, Take
from argus.cases.service import CaseService
from argus.writer import plan
from tests.integration.cases.conftest import Person
from tests.integration.cases.test_service import _apply
from tests.integration.writer.kit import created, mirror, rig

pytestmark = pytest.mark.integration
COUNTER = itertools.count(1)
OPS = ("take", "release", "tag", "severity", "close")


@settings(
    max_examples=25, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(st.lists(st.sampled_from(OPS), min_size=1, max_size=6))
async def test_kibana_ends_equal_to_argus_on_what_argus_manages(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person], ops: list[str],
) -> None:  # fmt: skip
    n = next(COUNTER)
    r = rig(migrated_engine, app_engine, writer_engine)
    r.kibana.ids = itertools.count(n * 100_000)  # Kibana ids are unique in this database
    case_id, kid = await created(r, people, ip=f"10.5.{n // 250}.{n % 250 + 1}")
    await mirror(migrated_engine, case_id, kid, version=str(r.kibana.cases[kid]["version"]))
    ravi = people["ravi"].actor()
    people_tags: list[str] = []
    severity_edited = False
    status_moved: str | None = None
    for step, op in enumerate(ops):
        async with app_engine.connect() as conn:
            case = await (await CaseService.start(conn)).get(case_id)
        assert case is not None
        if op == "take" and case.state == "open":
            await _apply(app_engine, ravi, case_id, Take(), case.version)
        elif op == "release" and case.state == "assigned":
            await _apply(app_engine, ravi, case_id, Release(), case.version)
        elif op == "tag":
            tag = f"team-{step}"
            r.kibana.cases[kid]["tags"].append(tag)
            people_tags.append(tag)
        elif op == "severity" and not severity_edited:
            r.kibana.cases[kid]["severity"] = "low"
            severity_edited = True
            await mirror(migrated_engine, case_id, kid, unmanaged=("severity",))
        elif op == "close" and status_moved is None:
            r.kibana.cases[kid]["status"] = "closed"
            status_moved = "closed"
        report = await r.run("W2", limit=10)
        assert report.stopped is None, report.lines()
        assert report.mismatches == 0
        r.advance(60)

    async with app_engine.connect() as conn:
        final = await (await CaseService.start(conn)).get(case_id)
    assert final is not None
    seen = r.kibana.cases[kid]
    assert {t for t in seen["tags"] if plan.is_managed(t)} == set(intent.argus_tags(final))
    assert set(people_tags) <= set(seen["tags"])  # a person's tags stay
    if severity_edited:
        assert seen["severity"] == "low"  # a person's edit is left alone
    if status_moved:
        assert seen["status"] == "closed"  # never reverted
    else:
        assert seen["status"] == intent.KIBANA_STATUS[final.state]
    assert len(seen["tags"]) == len(set(seen["tags"]))
