"""The presenter on the linker's incidents, against the database as the runtime role (P4-F E5):
in shadow it writes the engine's own tables only and a second pass changes nothing; with
``risk.present`` each shown incident is one suspected case whose members are its alert groups,
and a second pass makes no second case; later groups fold in silently and the lifecycle's
material change is the only re-queue; a dismissal holds the incident until a strong material
change, then a new case follows the old one; an undone dismissal brings it back; a person's
confirm raises no severity; the governor holds P3 back but never P1 or P2; switching off restores
today's raise into Needs attention. Addresses and names are made up (the ACME site)."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.machine import Confirm, Dismiss, Open, Reopen
from argus.cases.model import LOCAL_CAPABILITIES, Actor, Member
from argus.cases.service import CaseService
from argus.risk import present, run
from argus.web import auth, queries
from argus.web.capabilities import Capability
from argus.web.v1 import engine_models as em
from argus.web.v1 import engine_routes
from tests.integration.risk.conftest import ACCESS, C2, EXFIL, NOW, all_rows, group, rule, scalar
from tests.integration.risk.test_incidents import linked

pytestmark = pytest.mark.integration
OUTSIDE = "flagged by outside threat intel"
THREAT = "on a threat list"
BEACON = {"proxy.regularity": 0.1, "ports.risky": 2, "proxy.hosts_to_destination": 1}


def presenting(on: bool, per_day: int = 10) -> run.Setup:
    return replace(linked(), presenter=present.Options(on, per_day))


async def world(owner: AsyncEngine) -> dict[str, object]:
    await rule(owner, "r-beacon", "Beacon rule", threat=(C2, EXFIL))
    await rule(owner, "r-download", "Download rule", severity="medium", threat=(C2, ACCESS))
    await rule(owner, "r-ioc", "IOC rule", severity="critical", indices=("acme-logs-*",))
    return {
        "burst_a": await group(owner, "r-beacon", actor="10.1.1.1", risk_score=35,
                               signals=BEACON, fields={"destination.ip": ["45.138.12.9"]}),
        "burst_b": await group(owner, "r-download", actor="10.1.1.1", hours_ago=3,
                               signals={"proxy.regularity": 0.2}),
        "decisive": await group(owner, "r-ioc", actor="10.1.1.2", severity="critical"),
        "outside": await group(owner, "r-beacon", actor="10.1.1.3", flags=(OUTSIDE,),
                               signals={"proxy.regularity": 0.1}),
        "quiet": await group(owner, "r-beacon", actor="10.1.1.4"),
    }  # fmt: skip


async def incidents(engine: AsyncEngine) -> dict[str, object]:
    """The root incidents by the key of each of their objects."""
    rows = await all_rows(
        engine,
        "SELECT b.key, r.* FROM risk_incidents r JOIN risk_incident_objects o"
        " ON o.incident_id = r.id JOIN risk_objects b ON b.id = o.object_id"
        " WHERE r.parent_id IS NULL AND r.state <> 'merged'",
    )
    return {r.key: r for r in rows}


async def members_of(engine: AsyncEngine, case: object) -> set[object]:
    return {r.investigation_id for r in await all_rows(
        engine, "SELECT investigation_id FROM case_members WHERE case_id = :c"
        " AND removed_at IS NULL", c=case)}  # fmt: skip


async def test_in_shadow_the_presenter_writes_only_the_engines_tables(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await world(migrated_engine)
    report = await run.step(app_engine, presenting(False), NOW)
    assert "presenter: 3 possible incidents (3 new" in report.line()
    found = await incidents(migrated_engine)
    assert set(found) == {"ip:10.1.1.1", "ip:10.1.1.2", "ip:10.1.1.3"}
    assert all(r.case_id is None for r in found.values())  # type: ignore[attr-defined]
    decisive = found["ip:10.1.1.3"]
    view = decisive.view  # type: ignore[attr-defined]
    assert view["lane"] == "decisive"
    assert view["why_line"].startswith("+49 outside detection (VirusTotal) · +15 regular timing")
    assert view["why_line"].endswith("\u00d71.2 still active")
    assert view["why"][0] == {"op": "+", "points": 49.0, "text": "outside detection (VirusTotal)"}
    assert {c["state"] for c in view["checks"]} <= {"checked", "ruled_out", "unknown"}
    assert view["alternatives"]
    assert view["objects"][0]["label"] == "10.1.1.3"
    assert (view["priority"], view["band"]) == (decisive.priority, decisive.band)  # type: ignore[attr-defined]
    assert decisive.certainty == "Likely"  # type: ignore[attr-defined]
    assert decisive.title  # type: ignore[attr-defined]
    assert all(r.shown and r.shown_day is not None for r in found.values())  # type: ignore[attr-defined]
    assert await scalar(migrated_engine, "SELECT count(*) FROM cases") == 0
    assert await scalar(migrated_engine, "SELECT present FROM risk_mode") is False
    # a second pass changes nothing: no new incident, no new version, the same view
    before = {k: (r.id, r.version, r.view, r.title, r.queued_at) for k, r in found.items()}  # type: ignore[attr-defined]
    again = await run.step(app_engine, presenting(False), NOW + timedelta(minutes=2))
    assert "3 possible incidents (0 new, 0 changed), 3 shown" in again.line()
    after = {k: (r.id, r.version, r.view, r.title, r.queued_at)  # type: ignore[attr-defined]
             for k, r in (await incidents(migrated_engine)).items()}  # fmt: skip
    assert after == before
    page = await today(migrated_engine, NOW + timedelta(minutes=3))
    assert page.mode == "shadow"
    assert [c.id for c in page.needs_you] == [
        str(r.id)
        for r in sorted(  # type: ignore[attr-defined]
            found.values(), key=lambda r: (r.band, -r.priority, r.id)
        )
    ]  # type: ignore[attr-defined]
    assert all(c.state is None and c.number is None for c in page.needs_you)


async def test_presenting_makes_one_suspected_case_per_incident_and_never_a_second(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    made = await world(migrated_engine)
    report = await run.step(app_engine, presenting(True), NOW)
    assert "cases opened 3" in report.line()
    cases = await all_rows(migrated_engine, "SELECT id, state, cause, severity, version, attention"
                           " FROM cases ORDER BY number")  # fmt: skip
    assert len(cases) == 3
    assert {c.state for c in cases} == {"suspected"}
    assert {c.cause for c in cases} == {"raised"}
    assert all(c.attention.startswith("ARGUS suggests this case: P") for c in cases)
    found = await incidents(migrated_engine)
    burst = found["ip:10.1.1.1"]
    assert await members_of(migrated_engine, burst.case_id) == {  # type: ignore[attr-defined]
        made["burst_a"].id,
        made["burst_b"].id,
    }  # type: ignore[attr-defined]
    assert burst.presented == burst.material  # type: ignore[attr-defined]
    events = await scalar(migrated_engine, "SELECT count(*) FROM case_events")
    again = await run.step(app_engine, presenting(True), NOW + timedelta(minutes=2))
    assert "cases opened" not in again.line()
    assert await scalar(migrated_engine, "SELECT count(*) FROM cases") == 3
    assert await scalar(migrated_engine, "SELECT count(*) FROM case_events") == events
    assert {tuple(r) for r in await all_rows(migrated_engine, "SELECT id, version FROM cases")} \
        == {(c.id, c.version) for c in cases}  # fmt: skip
    page = await today(migrated_engine, NOW + timedelta(minutes=3))
    assert page.mode == "present"
    assert {c.id for c in page.needs_you} == {str(c.id) for c in cases}
    assert all(c.state == "suspected" and c.number is not None for c in page.needs_you)


async def test_later_groups_fold_in_silently_and_a_material_change_requeues(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await world(migrated_engine)
    await run.step(app_engine, presenting(True), NOW)
    first = (await incidents(migrated_engine))["ip:10.1.1.1"]
    case = first.case_id  # type: ignore[attr-defined]
    later = NOW + timedelta(hours=1)
    # the same rule again on the same device: folded in, no new version
    again = await group(migrated_engine, "r-beacon", actor="10.1.1.1", hours_ago=-0.5,
                        signals={"proxy.regularity": 0.1})  # fmt: skip
    report = await run.step(app_engine, presenting(True), later)
    assert "folded into 1" in report.line()
    row = (await incidents(migrated_engine))["ip:10.1.1.1"]
    assert (row.version, row.case_id, row.queued_at) == (1, case, first.queued_at)  # type: ignore[attr-defined]
    assert again.id in await members_of(migrated_engine, case)
    assert await scalar(migrated_engine, "SELECT count(*) FROM cases") == 3
    # an outside detection on it: new evidence, a new version that says what changed
    await group(migrated_engine, "r-beacon", actor="10.1.1.1", hours_ago=-1.5, flags=(OUTSIDE,),
                signals={"proxy.regularity": 0.1})  # fmt: skip
    when = later + timedelta(hours=1)
    report = await run.step(app_engine, presenting(True), when)
    assert "1 changed" in report.line()
    row = (await incidents(migrated_engine))["ip:10.1.1.1"]
    assert row.version == 2  # type: ignore[attr-defined]
    assert any("new evidence: outside" in c for c in row.changed)  # type: ignore[attr-defined]
    assert row.queued_at == when  # type: ignore[attr-defined]
    assert row.presented == row.material  # type: ignore[attr-defined]
    assert row.case_id == case  # type: ignore[attr-defined]


async def test_a_dismissed_incident_holds_until_a_strong_change_then_a_new_case_follows(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    await world(migrated_engine)
    await run.step(app_engine, presenting(True), NOW)
    first = (await incidents(migrated_engine))["ip:10.1.1.1"]
    await decide(app_engine, await a_person(migrated_engine), first.case_id,  # type: ignore[attr-defined]
                 Dismiss("benign_expected"))  # fmt: skip
    later = NOW + timedelta(hours=1)
    await group(migrated_engine, "r-download", actor="10.1.1.1", hours_ago=-0.5,
                signals={"proxy.regularity": 0.2})  # fmt: skip
    await run.step(app_engine, presenting(True), later)
    row = (await incidents(migrated_engine))["ip:10.1.1.1"]
    assert (row.id, row.case_id) == (first.id, first.case_id)  # type: ignore[attr-defined]
    assert await scalar(migrated_engine, "SELECT count(*) FROM cases") == 3
    page = await today(migrated_engine, later + timedelta(minutes=1))
    assert str(first.case_id) not in {c.id for c in page.needs_you}  # type: ignore[attr-defined]
    # an outside detection on a new destination is a strong change: a new case follows the old
    await group(migrated_engine, "r-beacon", actor="10.1.1.1", hours_ago=-1.5, flags=(OUTSIDE,),
                fields={"url.domain": ["bad-example.net"]},
                signals={"proxy.regularity": 0.1})  # fmt: skip
    report = await run.step(app_engine, presenting(True), later + timedelta(hours=1))
    assert "cases opened 1" in report.line()
    row = (await incidents(migrated_engine))["ip:10.1.1.1"]
    assert row.id == first.id  # type: ignore[attr-defined]
    assert row.case_id is not None  # type: ignore[attr-defined]
    assert row.case_id != first.case_id  # type: ignore[attr-defined]
    assert row.view["previous_cases"] == [str(first.case_id)]  # type: ignore[attr-defined]
    assert await scalar(migrated_engine, "SELECT count(*) FROM cases") == 4
    assert await scalar(migrated_engine, "SELECT state FROM cases WHERE id = :c",
                        c=row.case_id) == "suspected"  # type: ignore[attr-defined]  # fmt: skip
    assert await members_of(migrated_engine, row.case_id)  # type: ignore[attr-defined]
    page = await today(migrated_engine, later + timedelta(hours=1, minutes=1))
    assert str(row.case_id) in {c.id for c in page.needs_you}  # type: ignore[attr-defined]


async def test_the_governor_holds_p3_back_and_never_p1_or_p2(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    """Every presentable incident gets its case (the queue lists it); the daily room decides
    only which are Today's cards (``shown``, in this mode), and the rest are counted."""
    await world(migrated_engine)
    await run.step(app_engine, presenting(True, per_day=1), NOW)
    rows = list((await incidents(migrated_engine)).values())
    for r in rows:
        if r.band in ("P1", "P2"):  # type: ignore[attr-defined]
            assert r.shown  # type: ignore[attr-defined]
    shown = [r for r in rows if r.shown]  # type: ignore[attr-defined]
    held = [r for r in rows if not r.shown]  # type: ignore[attr-defined]
    assert len([r for r in shown if r.band in ("P3", "P4")]) <= 1  # type: ignore[attr-defined]
    assert all(r.case_id is not None for r in rows)  # type: ignore[attr-defined]
    assert all(r.view["shown_in"] == "present" for r in shown)  # type: ignore[attr-defined]
    assert all(r.view["shown_in"] is None for r in held)  # type: ignore[attr-defined]
    assert await scalar(migrated_engine, "SELECT count(*) FROM cases") == len(rows)
    page = await today(migrated_engine, NOW + timedelta(minutes=1))
    assert len(page.needs_you) == len(shown)
    assert page.more_waiting == len(held)


async def test_switching_off_restores_the_raise_into_needs_attention(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    made = await world(migrated_engine)
    raised = await group(migrated_engine, "r-download", actor="10.1.1.9",
                         flags=(THREAT, "regular traffic, like a beacon"))  # fmt: skip
    sql = text(f"SELECT {queries.RAISED} FROM investigations i WHERE i.id = :i")  # noqa: S608

    async def is_raised() -> bool:
        async with app_engine.connect() as conn:
            return bool((await conn.execute(sql, {"i": raised.id})).scalar_one())

    assert await is_raised()  # no switch recorded yet: today's behaviour
    await run.step(app_engine, presenting(True), NOW)
    assert not await is_raised()
    cases = await scalar(migrated_engine, "SELECT count(*) FROM cases")
    await run.step(app_engine, presenting(False), NOW + timedelta(minutes=2))
    assert await is_raised()
    # off, nothing more is presented: a new device in a lane gets no case
    await group(migrated_engine, "r-ioc", actor="10.1.1.7", severity="critical", hours_ago=-0.5)
    await run.step(app_engine, presenting(False), NOW + timedelta(hours=1))
    assert await scalar(migrated_engine, "SELECT count(*) FROM cases") == cases
    assert made  # the world stays as it was


async def test_an_undecided_suggested_case_is_taken_over_not_doubled(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    """Today's suggester made a case for the device nobody decided: presenting, the incident
    takes it as its own (no second case, its device not hidden) and folds in what is new; in
    shadow it is shown as the engine's own card."""
    made = await world(migrated_engine)
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        old = await service.open(Actor.argus("raise"), Open(
            "Suggested before", "medium", "raised", (Member(made["burst_a"].id, "actor"),),  # type: ignore[attr-defined]
            suspected=True, attention="ARGUS suggests this case: two rules",
        ))  # fmt: skip
    await run.step(app_engine, presenting(False), NOW)
    shadow = (await incidents(migrated_engine))["ip:10.1.1.1"]
    assert shadow.case_id is None  # type: ignore[attr-defined]
    assert shadow.shown  # type: ignore[attr-defined]
    report = await run.step(app_engine, presenting(True), NOW + timedelta(minutes=2))
    assert "adopted 1" in report.line()
    row = (await incidents(migrated_engine))["ip:10.1.1.1"]
    assert row.case_id == old.case.id  # type: ignore[attr-defined]
    assert await members_of(migrated_engine, old.case.id) == {
        made["burst_a"].id,
        made["burst_b"].id,
    }  # type: ignore[attr-defined]
    assert await scalar(migrated_engine, "SELECT count(*) FROM cases") == 3


async def a_person(owner: AsyncEngine, name: str = "rita") -> Actor:
    async with owner.begin() as conn:
        user = await auth.add_user(conn, name, name.title(), "a long enough password 1",
                                   capabilities=[Capability.VIEW, Capability.REVIEW])  # fmt: skip
    return Actor.person(int(user), LOCAL_CAPABILITIES, via="test")


async def today(engine: AsyncEngine, now: object) -> em.TodayOut:
    async with engine.connect() as conn:
        return await engine_routes.today(conn, now, None, 0)  # type: ignore[arg-type]


async def decide(engine: AsyncEngine, actor: Actor, case: object, command: object) -> None:
    async with engine.begin() as conn:
        service = await CaseService.start(conn)
        await service.apply(actor, case, command, expected_version=None)  # type: ignore[arg-type]


async def test_an_undone_dismissal_is_back_on_today_and_new_groups_fold_in(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    """A person dismisses a possible incident, a pass runs, they reopen it (Undo): its case is
    in Needs you again, and a later alert group of the device joins it."""
    await world(migrated_engine)
    await run.step(app_engine, presenting(True), NOW)
    person = await a_person(migrated_engine)
    first = (await incidents(migrated_engine))["ip:10.1.1.1"]
    case = first.case_id  # type: ignore[attr-defined]
    await decide(app_engine, person, case, Dismiss("benign_expected"))
    later = NOW + timedelta(minutes=10)
    await run.step(app_engine, presenting(True), later)
    assert str(case) not in {c.id for c in (await today(migrated_engine, later)).needs_you}
    await decide(app_engine, person, case, Reopen("dismissed by mistake"))
    await run.step(app_engine, presenting(True), later + timedelta(minutes=2))
    row = (await incidents(migrated_engine))["ip:10.1.1.1"]
    assert (row.id, row.state, row.case_id) == (first.id, "active", case)  # type: ignore[attr-defined]
    page = await today(migrated_engine, later + timedelta(minutes=3))
    assert str(case) in {c.id for c in page.needs_you}
    again = await group(migrated_engine, "r-beacon", actor="10.1.1.1", hours_ago=-0.5,
                        signals={"proxy.regularity": 0.1})  # fmt: skip
    await run.step(app_engine, presenting(True), NOW + timedelta(hours=1))
    folded = await scalar(migrated_engine, "SELECT case_id FROM case_members WHERE"
                          " investigation_id = :i AND removed_at IS NULL", i=again.id)  # fmt: skip
    assert folded == case
    assert await scalar(migrated_engine, "SELECT count(*) FROM cases") == 3


async def test_alert_groups_people_decided_make_no_card_without_a_case(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    """The old suggester's case holding a device's only alert group was dismissed: the engine
    neither shows nor counts that device (nothing a person could decide) until a new alert
    group of it comes; then it is presented with that group."""
    made = await world(migrated_engine)
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        old = await service.open(Actor.argus("raise"), Open(
            "Suggested before", "high", "raised", (Member(made["decisive"].id, "actor"),),  # type: ignore[attr-defined]
            suspected=True, attention="ARGUS suggests this case: an IOC",
        ))  # fmt: skip
    await decide(app_engine, await a_person(migrated_engine), old.case.id,
                 Dismiss("benign_expected"))  # fmt: skip
    for n in range(3):
        report = await run.step(app_engine, presenting(True), NOW + timedelta(minutes=2 * n))
    assert "1 held by another case" in (report.presented or "")
    row = (await incidents(migrated_engine))["ip:10.1.1.2"]
    assert (row.shown, row.case_id, row.view["elsewhere"]) == (False, None, str(old.case.id))  # type: ignore[attr-defined]
    page = await today(migrated_engine, NOW + timedelta(minutes=5))
    assert all(c.state == "suspected" for c in page.needs_you)
    found = await incidents(migrated_engine)
    others = {r.id for k, r in found.items() if k != "ip:10.1.1.2"}  # type: ignore[attr-defined]
    assert {c.engine.incident_id for c in page.needs_you} == others
    assert page.more_waiting == 0
    fresh = await group(migrated_engine, "r-ioc", actor="10.1.1.2", severity="critical",
                        hours_ago=-0.5)  # fmt: skip
    await run.step(app_engine, presenting(True), NOW + timedelta(hours=1))
    row = (await incidents(migrated_engine))["ip:10.1.1.2"]
    assert row.shown  # type: ignore[attr-defined]
    assert row.case_id is not None  # type: ignore[attr-defined]
    assert row.view["elsewhere"] is None  # type: ignore[attr-defined]
    assert await members_of(migrated_engine, row.case_id) == {fresh.id}  # type: ignore[attr-defined]


async def test_a_persons_confirm_raises_no_severity_when_groups_fold_in(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine
) -> None:
    """The trust factor of a person's confirm is on the card only: the evidence band (the
    lifecycle's material, the case's severity) does not move, and the next alert group that
    folds into the confirmed case leaves the case's severity as the evidence has it."""
    await world(migrated_engine)
    await run.step(app_engine, presenting(True), NOW)
    found = await incidents(migrated_engine)
    p2 = [k for k, r in found.items() if r.band == "P2"]  # type: ignore[attr-defined]
    assert p2
    person = await a_person(migrated_engine)
    for key in p2:
        await decide(app_engine, person, found[key].case_id, Confirm())  # type: ignore[attr-defined]
    await run.step(app_engine, presenting(True), NOW + timedelta(minutes=2))
    confirmed = await incidents(migrated_engine)
    assert {confirmed[k].view["band"] for k in p2} == {"P1"}  # type: ignore[attr-defined]
    assert {confirmed[k].band for k in p2} == {"P2"}  # type: ignore[attr-defined]
    assert {confirmed[k].version for k in p2} == {1}  # type: ignore[attr-defined]
    assert {confirmed[k].certainty for k in p2} == {"Confirmed"}  # type: ignore[attr-defined]
    again = {
        "ip:10.1.1.1": {"rule_id": "r-beacon", "signals": {"proxy.regularity": 0.1}},
        "ip:10.1.1.2": {"rule_id": "r-ioc", "severity": "critical"},
        "ip:10.1.1.3": {"rule_id": "r-beacon", "flags": (OUTSIDE,),
                        "signals": {"proxy.regularity": 0.1}},
    }  # fmt: skip
    for key in p2:  # the same again: no new source, stage or family
        await group(migrated_engine, actor=key.split(":", 1)[1], hours_ago=-0.5, **again[key])  # type: ignore[arg-type]
    await run.step(app_engine, presenting(True), NOW + timedelta(hours=1))
    after = await incidents(migrated_engine)
    for key in p2:
        r = after[key]
        assert (r.band, r.view["band"], r.version) == ("P2", "P1", 1)  # type: ignore[attr-defined]
        assert await scalar(migrated_engine, "SELECT severity FROM cases WHERE id = :c",
                            c=r.case_id) == "high"  # type: ignore[attr-defined]  # fmt: skip
        assert await scalar(migrated_engine, "SELECT count(*) FROM case_events WHERE case_id = :c"
                            " AND kind = 'linked'", c=r.case_id) == 1  # type: ignore[attr-defined]  # fmt: skip
