"""While the incident engine presents, the investigation agent reads only alert groups a person
reads (D-324): the members of presented P1-P3 incidents whose case is still being decided or
handled, at most three per incident version and within the day's quota; never a P4's, a closed
case's, one in shadow, one already read at its dossier, or (with ``after``) one the deterministic
engine has not found undecided. Made-up site (ACME)."""

from __future__ import annotations

import ipaddress
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assess import presented
from argus.assets import parse_asset_map
from argus.cases.machine import Dismiss
from argus.llm.privacy import Privacy, load_policy
from argus.risk import run as risk_run
from tests.integration.risk.conftest import NOW, all_rows, group, scalar
from tests.integration.risk.test_present import a_person, decide, presenting, world

pytestmark = pytest.mark.integration
AGENT = "agent@1"
LATER = NOW + timedelta(minutes=5)
ASSETS = parse_asset_map(b"networks:\n  - name: Lab block\n    range: 10.1.1.0/24\n")


def privacy() -> Privacy:
    return Privacy.build(load_policy(), ASSETS, (ipaddress.ip_network("198.51.100.0/24"),))


async def schedule(app: AsyncEngine, **more: Any) -> int:
    args: dict[str, Any] = {"limit": 50, "per_day": 100, **more}
    async with app.begin() as conn:
        done = await presented.schedule(conn, privacy(), AGENT, LATER, **args)
    return done.queued


async def queued(owner: AsyncEngine) -> set[Any]:
    rows = await all_rows(owner, "SELECT investigation_id FROM assessments WHERE assessor = :a",
                          a=AGENT)  # fmt: skip
    return {r.investigation_id for r in rows}


async def members(owner: AsyncEngine, bands: tuple[str, ...]) -> set[Any]:
    rows = await all_rows(
        owner, "SELECT g.investigation_id FROM risk_incident_groups g JOIN risk_incidents r"
        " ON r.id = g.incident_id WHERE r.case_id IS NOT NULL AND r.band = ANY(:b)",
        b=list(bands),
    )  # fmt: skip
    return {r.investigation_id for r in rows}


async def test_only_members_of_presented_p1_to_p3_incidents_are_read(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await world(migrated_engine)
    await risk_run.step(app_engine, presenting(True), NOW)
    async with migrated_engine.begin() as conn:  # one incident in P4: never read
        p4 = await conn.scalar(text("SELECT id FROM risk_incidents WHERE case_id IS NOT NULL"
                                    " ORDER BY priority LIMIT 1"))  # fmt: skip
        await conn.execute(text("UPDATE risk_incidents SET band = 'P4' WHERE id = :i"), {"i": p4})
    wanted = await members(migrated_engine, presented.BANDS)
    assert wanted
    assert await schedule(app_engine) == len(wanted)
    assert await queued(migrated_engine) == wanted
    assert not await queued(migrated_engine) & await members(migrated_engine, ("P4",))
    assert await schedule(app_engine) == 0  # read at this dossier already


async def test_at_most_three_per_incident_version_and_the_days_quota(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await world(migrated_engine)
    for hours in (1.0, 1.5, 2.5, 3.5):  # four more groups on the burst device
        await group(migrated_engine, "r-download", actor="10.1.1.1", hours_ago=hours,
                    signals={"proxy.regularity": 0.2})  # fmt: skip
    await risk_run.step(app_engine, presenting(True), NOW)
    burst = await scalar(
        migrated_engine, "SELECT r.id FROM risk_incidents r JOIN risk_incident_objects o"
        " ON o.incident_id = r.id JOIN risk_objects b ON b.id = o.object_id"
        " WHERE b.key = 'ip:10.1.1.1' AND r.parent_id IS NULL",
    )  # fmt: skip
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE risk_incidents SET band = 'P2'"))
    assert await scalar(migrated_engine, "SELECT count(*) FROM risk_incident_groups"
                        " WHERE incident_id = :i", i=burst) == 6  # fmt: skip
    assert await schedule(app_engine, per_day=1) == 1  # the day's quota
    await schedule(app_engine)
    of_burst = await scalar(
        migrated_engine, "SELECT count(*) FROM assessments a JOIN risk_incident_groups g"
        " ON g.investigation_id = a.investigation_id WHERE g.incident_id = :i", i=burst,
    )  # fmt: skip
    assert of_burst == presented.PER_INCIDENT
    assert await schedule(app_engine) == 0
    async with migrated_engine.begin() as conn:  # a material change: three more may be read
        await conn.execute(  # (runs are stamped with the database's clock)
            text("UPDATE risk_incidents SET material_at = clock_timestamp() WHERE id = :i"),
            {"i": burst},
        )
    assert await schedule(app_engine) == presented.PER_INCIDENT


async def test_nothing_is_read_for_a_closed_case_in_shadow_or_before_the_engine_gave_up(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await world(migrated_engine)
    await risk_run.step(app_engine, presenting(False), NOW)
    assert await schedule(app_engine) == 0  # shadow: no case, nothing read
    await risk_run.step(app_engine, presenting(True), NOW + timedelta(minutes=1))
    assert await schedule(app_engine, after="engine@1") == 0  # the engine has not given up
    person = await a_person(migrated_engine)
    for case in await all_rows(migrated_engine, "SELECT id FROM cases"):
        await decide(app_engine, person, case.id, Dismiss("benign_expected"))
    assert await schedule(app_engine) == 0


async def test_an_incident_at_its_limit_never_holds_the_others_back(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # the top incident has more unread members than it may have read: the rows fetched a pass
    # must not all be its members, or the incidents below it are never read
    await world(migrated_engine)
    for hours in (1.0, 1.5, 2.5, 3.5):  # four more groups on the burst device
        await group(migrated_engine, "r-download", actor="10.1.1.1", hours_ago=hours,
                    signals={"proxy.regularity": 0.2})  # fmt: skip
    await risk_run.step(app_engine, presenting(True), NOW)
    burst = await scalar(
        migrated_engine, "SELECT r.id FROM risk_incidents r JOIN risk_incident_objects o"
        " ON o.incident_id = r.id JOIN risk_objects b ON b.id = o.object_id"
        " WHERE b.key = 'ip:10.1.1.1' AND r.parent_id IS NULL",
    )  # fmt: skip
    async with migrated_engine.begin() as conn:  # the burst incident first, all presented
        await conn.execute(
            text("UPDATE risk_incidents SET band = 'P2',"
                 " priority = CASE WHEN id = :i THEN 90 ELSE 40 END"),
            {"i": burst},
        )  # fmt: skip
    monkeypatch.setattr(presented, "FETCH", presented.PER_INCIDENT)
    others = await members(migrated_engine, presented.BANDS) - await scalar_set(
        migrated_engine, burst
    )
    assert others
    for _ in range(4):
        await schedule(app_engine, limit=presented.PER_INCIDENT)
    assert others <= await queued(migrated_engine)


async def scalar_set(owner: AsyncEngine, incident_id: int) -> set[Any]:
    rows = await all_rows(owner, "SELECT investigation_id FROM risk_incident_groups"
                                 " WHERE incident_id = :i", i=incident_id)  # fmt: skip
    return {r.investigation_id for r in rows}
