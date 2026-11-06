"""The presenter keeps its cases straight beside people's (P4-F E5 review fixes): when the
linker merges two presented incidents their cases merge too, and a person's decision blocks the
merge instead; an incident a person's case holds one alert group of is still presented with its
free groups, and a split leaves the engine's case presented; a strong change on the alert groups
a dismissed case holds is told to that case and shown as new activity; a sealed incident's
follow-on keeps the predecessor's dismissal memory, or takes over its open case. Made-up
addresses (the ACME site)."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import splitting
from argus.cases.machine import Confirm, Dismiss, Open
from argus.cases.model import Member
from argus.cases.service import CaseService
from argus.risk import run
from tests.integration.risk.conftest import (
    C2,
    EXFIL,
    NOW,
    all_rows,
    dossier,
    group,
    rule,
    scalar,
    setup,
)
from tests.integration.risk.test_incidents import C2_DOMAIN
from tests.integration.risk.test_present import (
    BEACON,
    OUTSIDE,
    a_person,
    decide,
    incidents,
    members_of,
    presenting,
    today,
    world,
)

pytestmark = pytest.mark.integration
HOUR = timedelta(hours=1)


async def linking_groups(owner: AsyncEngine) -> None:
    """A flagged domain both devices reach: the linker joins their incidents."""
    for actor in ("10.1.1.2", "10.1.1.3"):
        await group(owner, "r-ioc", actor=actor, severity="critical", hours_ago=-0.5,
                    fields=C2_DOMAIN, flags=(OUTSIDE,))  # fmt: skip


async def test_two_presented_incidents_that_merge_keep_one_case(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await world(migrated_engine)
    await run.step(app_engine, presenting(True), NOW)
    found = await incidents(migrated_engine)
    before = {found[k].case_id for k in ("ip:10.1.1.2", "ip:10.1.1.3")}  # type: ignore[attr-defined]
    assert len(before) == 2
    assert None not in before
    await linking_groups(migrated_engine)
    report = await run.step(app_engine, presenting(True), NOW + HOUR)
    assert "1 merged" in report.incidents
    assert "merged 1" in report.presented
    rows = await all_rows(migrated_engine, "SELECT id, state, merged_into, case_id"
                          " FROM risk_incidents ORDER BY id")  # fmt: skip
    gone = [r for r in rows if r.state == "merged"]
    assert len(gone) == 1
    kept = next(r for r in rows if r.id == gone[0].merged_into)
    cases = {c.id: c for c in await all_rows(
        migrated_engine, "SELECT id, state, merged_into_id FROM cases")}  # fmt: skip
    assert (cases[gone[0].case_id].state, cases[gone[0].case_id].merged_into_id) == (
        "closed", kept.case_id,
    )  # fmt: skip
    assert cases[kept.case_id].state == "suspected"
    assert len(cases) == 3
    held = await members_of(migrated_engine, kept.case_id)
    assert await members_of(migrated_engine, gone[0].case_id) == set()
    assert {r.investigation_id for r in await all_rows(
        migrated_engine, "SELECT investigation_id FROM risk_incident_groups WHERE incident_id = :i",
        i=kept.id)} <= held  # fmt: skip
    page = await today(migrated_engine, NOW + HOUR + timedelta(minutes=1))
    ids = {c.id for c in page.needs_you}
    assert str(kept.case_id) in ids
    assert str(gone[0].case_id) not in ids
    assert len(ids) + page.more_waiting == 2
    again = await run.step(app_engine, presenting(True), NOW + 2 * HOUR)
    assert "merged" not in again.presented or "merged 0" in again.presented


async def test_a_persons_decision_keeps_the_incidents_apart_and_the_link_is_recommended(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await world(migrated_engine)
    await run.step(app_engine, presenting(True), NOW)
    found = await incidents(migrated_engine)
    theirs = found["ip:10.1.1.2"]
    await decide(app_engine, await a_person(migrated_engine), theirs.case_id, Confirm())  # type: ignore[attr-defined]
    await linking_groups(migrated_engine)
    report = await run.step(app_engine, presenting(True), NOW + HOUR)
    assert "0 merged" in report.incidents
    after = await incidents(migrated_engine)
    assert after["ip:10.1.1.2"].id == theirs.id  # type: ignore[attr-defined]
    assert after["ip:10.1.1.3"].id == found["ip:10.1.1.3"].id  # type: ignore[attr-defined]
    assert {r.state for r in after.values()} == {"active"}  # type: ignore[attr-defined]
    assert await scalar(migrated_engine, "SELECT count(*) FROM cases") == 3
    assert await scalar(migrated_engine, "SELECT count(*) FROM cases WHERE state = 'closed'") == 0
    recommended = [
        json.loads(r.recommended) if isinstance(r.recommended, str) else r.recommended
        for r in await all_rows(migrated_engine, "SELECT recommended FROM risk_incidents")
    ]
    assert any(recommended), "the link is kept as a recommendation"


async def test_a_persons_case_holding_one_alert_group_does_not_hide_the_incident(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    """The device's only alert group is in a person's open case: nothing to present. A new
    alert group of it is free: the incident is presented with that one, the person's case keeps
    its own, and both are in Needs you."""
    made = await world(migrated_engine)
    person = await a_person(migrated_engine)
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        theirs = await service.open(person, Open(
            "A person's case", "low", "person", (Member(made["outside"].id, "person"),),  # type: ignore[attr-defined]
        ))  # fmt: skip
    report = await run.step(app_engine, presenting(True), NOW)
    assert "1 held by another case" in report.presented
    row = (await incidents(migrated_engine))["ip:10.1.1.3"]
    assert (row.case_id, row.view["elsewhere"]) == (None, str(theirs.case.id))  # type: ignore[attr-defined]
    fresh = await group(migrated_engine, "r-beacon", actor="10.1.1.3", hours_ago=-0.5,
                        flags=(OUTSIDE,), signals={"proxy.regularity": 0.1})  # fmt: skip
    report = await run.step(app_engine, presenting(True), NOW + HOUR)
    assert "held by another case" not in report.presented
    row = (await incidents(migrated_engine))["ip:10.1.1.3"]
    assert row.case_id is not None  # type: ignore[attr-defined]
    assert row.view["elsewhere"] is None  # type: ignore[attr-defined]
    assert row.band in ("P1", "P2")  # type: ignore[attr-defined]
    assert await members_of(migrated_engine, row.case_id) == {fresh.id}  # type: ignore[attr-defined]
    assert await members_of(migrated_engine, theirs.case.id) == {made["outside"].id}  # type: ignore[attr-defined]
    page = await today(migrated_engine, NOW + HOUR + timedelta(minutes=1))
    ids = {c.id for c in page.needs_you}
    assert str(row.case_id) in ids  # type: ignore[attr-defined]
    assert str(theirs.case.id) in ids  # a confirmed case nobody has taken


async def test_a_split_leaves_the_engines_case_presented_and_new_groups_fold_into_it(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    made = await world(migrated_engine)
    await run.step(app_engine, presenting(True), NOW)
    case = (await incidents(migrated_engine))["ip:10.1.1.1"].case_id  # type: ignore[attr-defined]
    person = await a_person(migrated_engine)
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        split = await service.split(
            person, case, [made["burst_b"].id], reason="another thing", expected_version=None,  # type: ignore[attr-defined]
            carry=splitting.carrier(conn, setup().classifier), title="Split off", severity="low",
        )  # fmt: skip
    report = await run.step(app_engine, presenting(True), NOW + timedelta(minutes=10))
    assert "held by another case" not in report.presented
    row = (await incidents(migrated_engine))["ip:10.1.1.1"]
    assert (row.case_id, row.view["elsewhere"]) == (case, None)  # type: ignore[attr-defined]
    page = await today(migrated_engine, NOW + timedelta(minutes=11))
    assert str(case) in {c.id for c in page.needs_you}
    again = await group(migrated_engine, "r-beacon", actor="10.1.1.1", hours_ago=-0.5,
                        signals={"proxy.regularity": 0.1})  # fmt: skip
    report = await run.step(app_engine, presenting(True), NOW + HOUR)
    assert "folded into 1" in report.presented
    assert await members_of(migrated_engine, case) == {made["burst_a"].id, again.id}  # type: ignore[attr-defined]
    assert await members_of(migrated_engine, split.target.case.id) == {made["burst_b"].id}  # type: ignore[attr-defined]
    assert await scalar(migrated_engine, "SELECT count(*) FROM cases") == 4


async def test_a_strong_change_on_a_dismissed_cases_own_alert_group_is_told_and_shown(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    """A person dismissed the beacon; later VirusTotal flags its destination on the same alert
    group. An investigation is in one case at a time, so no new case can take it: the closed
    case is told (its attention, an ``activity_after_closure`` event, once per material
    version) and Today's New activity lists it until a person acts."""
    made = await world(migrated_engine)
    await run.step(app_engine, presenting(True), NOW)
    case = (await incidents(migrated_engine))["ip:10.1.1.1"].case_id  # type: ignore[attr-defined]
    await decide(app_engine, await a_person(migrated_engine), case, Dismiss("benign_expected"))
    await dossier(migrated_engine, made["burst_a"].id, 2, BEACON)  # type: ignore[attr-defined]
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO investigation_raises (investigation_id, version, dossier_hash,"
                " flags, evaluated_at) VALUES (:i, 2, :h, CAST(:f AS jsonb), :at)"
            ),
            {"i": made["burst_a"].id, "h": "1" * 64, "f": json.dumps([OUTSIDE]), "at": NOW},  # type: ignore[attr-defined]
        )
    report = await run.step(app_engine, presenting(True), NOW + HOUR)
    assert "told after closure 1" in report.presented
    assert "cases opened 0" in report.presented
    row = (await incidents(migrated_engine))["ip:10.1.1.1"]
    assert (row.case_id, row.version) == (case, 2)  # type: ignore[attr-defined]
    assert row.view["after_closure"] == 2  # type: ignore[attr-defined]
    assert any("newly flagged" in c for c in row.changed)  # type: ignore[attr-defined]
    state, attention = (await all_rows(migrated_engine, "SELECT state, attention FROM cases"
                                       " WHERE id = :c", c=case))[0]  # fmt: skip
    assert state == "closed"
    assert attention.startswith("New evidence since it was closed: ")
    assert "newly flagged: 45.138.12.9" in attention
    events = await scalar(migrated_engine, "SELECT count(*) FROM case_events WHERE case_id = :c"
                          " AND kind = 'activity_after_closure'", c=case)  # fmt: skip
    assert events == 1
    assert await scalar(migrated_engine, "SELECT count(*) FROM cases") == 3
    page = await today(migrated_engine, NOW + HOUR + timedelta(minutes=1))
    assert str(case) in {c.id for c in page.new_activity}
    assert str(case) not in {c.id for c in page.needs_you}
    told = next(c for c in page.new_activity if c.id == str(case))
    assert told.state == "closed"
    assert told.engine is not None
    assert any("newly flagged" in c for c in told.engine.changed)
    # the next pass reads the flagged group again (the retro-hunt): a new source, no further
    # strong change beyond what was told: told once
    report = await run.step(app_engine, presenting(True), NOW + 2 * HOUR)
    assert "told after closure 1" not in report.presented
    assert await scalar(migrated_engine, "SELECT count(*) FROM case_events WHERE case_id = :c"
                        " AND kind = 'activity_after_closure'", c=case) == 1  # fmt: skip
    page = await today(migrated_engine, NOW + 2 * HOUR + timedelta(minutes=1))
    assert str(case) in {c.id for c in page.new_activity}  # until a person acts on it


T0 = NOW - timedelta(days=30, hours=1)  # the predecessor began before seal_days (30)
BEACON_FIELDS = {"destination.ip": ["45.138.12.9"]}


async def sealed_predecessor(owner: AsyncEngine, app: AsyncEngine) -> object:
    """A presented beacon incident that seals at ``NOW``: begun at ``T0``, active until five
    days ago. Returns its row after the second pass."""
    old = T0 - timedelta(days=60)  # rules with a history already: not on probation at T0
    await rule(owner, "r-beacon", "Beacon rule", threat=(C2, EXFIL), first=old)
    await rule(owner, "r-download", "Download rule", severity="medium", threat=(C2,), first=old)
    await group(owner, "r-beacon", actor="10.1.1.1", hours_ago=(NOW - T0) / HOUR + 2,
                risk_score=35, signals=BEACON, fields=BEACON_FIELDS)  # fmt: skip
    await group(owner, "r-download", actor="10.1.1.1", hours_ago=(NOW - T0) / HOUR + 3,
                signals={"proxy.regularity": 0.2})  # fmt: skip
    await run.step(app, presenting(True), T0)
    await group(owner, "r-beacon", actor="10.1.1.1", hours_ago=5 * 24, risk_score=35,
                signals=BEACON, fields=BEACON_FIELDS)  # fmt: skip
    await run.step(app, presenting(True), NOW - timedelta(days=5, minutes=-30))
    return (await incidents(owner))["ip:10.1.1.1"]


async def test_a_sealed_incidents_follow_on_keeps_the_dismissal_memory(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    first = await sealed_predecessor(migrated_engine, app_engine)
    case = first.case_id  # type: ignore[attr-defined]
    assert case is not None
    # dismissed before the seal (the service's clock; within MEMORY of every pass here)
    await decide(app_engine, await a_person(migrated_engine), case, Dismiss("benign_expected"))
    # the same benign activity after the seal: a follow-on incident, and no new case
    await group(migrated_engine, "r-beacon", actor="10.1.1.1", hours_ago=1, risk_score=35,
                signals=BEACON, fields=BEACON_FIELDS)  # fmt: skip
    report = await run.step(app_engine, presenting(True), NOW)
    rows = await all_rows(migrated_engine, "SELECT id, state, follows_id, case_id, presented"
                          " FROM risk_incidents ORDER BY id")  # fmt: skip
    assert [(r.state, r.follows_id, r.case_id) for r in rows] == [
        ("sealed", None, case), ("active", first.id, None),  # type: ignore[attr-defined]
    ]  # fmt: skip
    assert rows[1].presented == rows[0].presented  # the predecessor's memory, inherited
    assert "cases opened" not in report.presented
    assert await scalar(migrated_engine, "SELECT count(*) FROM cases") == 1
    page = await today(migrated_engine, NOW + timedelta(minutes=1))
    assert page.needs_you == []
    assert page.more_waiting == 0
    # a strong change breaks the memory: a new case follows the old one
    await group(migrated_engine, "r-beacon", actor="10.1.1.1", hours_ago=-0.5, flags=(OUTSIDE,),
                fields={"url.domain": ["bad-example.net"]}, signals=BEACON)  # fmt: skip
    report = await run.step(app_engine, presenting(True), NOW + HOUR)
    assert "cases opened 1" in report.presented
    follow = (await all_rows(migrated_engine, "SELECT case_id, view FROM risk_incidents"
                             " WHERE id = :i", i=rows[1].id))[0]  # fmt: skip
    assert follow.case_id is not None
    assert follow.case_id != case
    assert follow.view["previous_cases"] == [str(case)]
    assert await scalar(migrated_engine, "SELECT state FROM cases WHERE id = :c",
                        c=follow.case_id) == "suspected"  # fmt: skip
    page = await today(migrated_engine, NOW + HOUR + timedelta(minutes=1))
    assert [c.id for c in page.needs_you] == [str(follow.case_id)]


async def test_a_sealed_incidents_follow_on_takes_over_its_open_case(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    """Nobody decided the case in 30 days: the follow-on continues it (one case, one live
    incident), its new alert groups fold in, and Today's card is the follow-on's."""
    first = await sealed_predecessor(migrated_engine, app_engine)
    case = first.case_id  # type: ignore[attr-defined]
    later = await group(migrated_engine, "r-beacon", actor="10.1.1.1", hours_ago=1,
                        risk_score=35, signals=BEACON, fields=BEACON_FIELDS)  # fmt: skip
    report = await run.step(app_engine, presenting(True), NOW)
    assert "cases opened 0, adopted 0, folded into 1" in report.presented
    rows = await all_rows(migrated_engine, "SELECT id, state, follows_id, case_id, shown"
                          " FROM risk_incidents ORDER BY id")  # fmt: skip
    assert [(r.state, r.follows_id, r.case_id, r.shown) for r in rows] == [
        ("sealed", None, None, True), ("active", first.id, case, True),  # type: ignore[attr-defined]
    ]  # fmt: skip
    assert later.id in await members_of(migrated_engine, case)
    assert await scalar(migrated_engine, "SELECT count(*) FROM cases") == 1
    page = await today(migrated_engine, NOW + timedelta(minutes=1))
    assert [(c.id, c.engine.incident_id) for c in page.needs_you if c.engine] == [
        (str(case), rows[1].id),
    ]  # fmt: skip
    again = await run.step(app_engine, presenting(True), NOW + timedelta(minutes=5))
    assert "cases opened" not in again.presented
