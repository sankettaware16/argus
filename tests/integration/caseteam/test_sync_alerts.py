"""D-288 (on D-272): a person switched Sync alerts on in Kibana. Kibana then sets each attached
alert to the case's status. For an open case that only re-opens an alert a person had closed, so
the poster leaves the alerts ARGUS records as closed out of the attach calls (and keeps the
totals it expects consistent); for any other status it sends no attach at all. An attach in
doubt is settled by the look against the lowered total. These tests need Docker Postgres."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.caseteam import store
from argus.caseteam.sender import SYNC_NOT_OPEN
from tests.integration.cases.conftest import Person
from tests.integration.caseteam.fake import Fault, writes_by
from tests.integration.caseteam.kit import Rig, a_case, rig, save_version

pytestmark = pytest.mark.integration


def sync_on_once_open(r: Rig, status: str = "open") -> Callable[[Any], bool]:
    """A person switches Sync alerts on (and sets the status) as soon as the case exists, before
    the first attach."""
    done = {"yes": False}

    def flip(wire: Any) -> bool:
        cases = r.kibana.team_cases()
        if cases and not done["yes"]:
            done["yes"] = True
            cases[0]["settings"]["syncAlerts"] = True
            cases[0]["status"] = status
        return False

    return flip


async def alert_ids(r: Rig, case: uuid.UUID) -> dict[str, list[str]]:
    """The alerts of each attach call of the first plan, by step key."""
    prep = await r.prepared(case)
    assert prep.plan is not None
    return {
        s.key: [a for a, _ in s.payload["alerts"]] for s in prep.plan.steps if s.kind == "attach"
    }


async def close_in_argus(owner: AsyncEngine, *alerts: str) -> None:
    async with owner.begin() as conn:
        await conn.execute(
            text("UPDATE alert_records SET workflow_status = 'closed' WHERE alert_id = ANY(:a)"),
            {"a": list(alerts)},
        )


async def test_an_open_case_with_sync_on_gets_every_alert_but_the_closed_ones(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"])
    calls = await alert_ids(r, case)
    assert list(calls) == [f"attach:{n}" for n in range(1, 6)]
    closed = calls["attach:2"][1]
    await close_in_argus(migrated_engine, closed)
    r.kibana.crashes.append((sync_on_once_open(r), False))

    report = await r.run(case)

    assert report.stopped is None, report.lines()
    assert set(await r.states(case)) == {"verified"}
    [kibana_case] = r.kibana.team_cases()
    assert kibana_case["totalAlerts"] == 24  # the closed alert was never attached
    assert closed not in {a for a, _ in r.kibana.synced}  # so Kibana could not re-open it
    assert len(r.kibana.synced) == 24
    assert {status for _, status in r.kibana.synced} == {"open"}
    assert report.note is not None
    assert "attach:2" in report.note
    assert "1 closed alerts left unattached: Sync alerts is on" in report.note

    rows = await r.sql(
        "SELECT key, kibana_ids FROM case_team_steps WHERE kind = 'attach' ORDER BY seq"
    )
    assert [row.kibana_ids.get("left_out", []) for row in rows] == [[], [closed], [], [], []]
    assert [row.kibana_ids["alerts_total"] for row in rows] == [5, 9, 14, 19, 24]
    # a tag changes no alert's status: the incident's alerts are all tagged, as before
    assert closed not in r.kibana.alert_tags  # the tags follow the attached alerts
    assert len(r.kibana.alert_tags) == 24

    async with writer_engine.connect() as conn:
        posted = await store.posted_state(conn, case)
    assert posted is not None
    assert closed not in posted.attached  # the next round tries it again
    assert len(posted.attached) == 24


async def test_a_case_that_is_not_open_gets_no_attach_and_says_why(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"])
    r.kibana.crashes.append((sync_on_once_open(r, "in-progress"), False))

    report = await r.run(case)

    assert report.stopped is None, report.lines()  # the run goes on
    assert report.held == []
    [kibana_case] = r.kibana.team_cases()
    assert kibana_case["totalAlerts"] == 0
    assert r.kibana.synced == []  # no alert's status was touched
    rows = await r.sql(
        "SELECT key, state, state_reason FROM case_team_steps WHERE kind = 'attach' ORDER BY seq"
    )
    assert [row.state for row in rows] == ["skipped"] * 5
    assert {row.state_reason for row in rows} == {SYNC_NOT_OPEN}
    states = await r.states(case)
    assert set(states) == {"verified", "skipped"}
    assert report.note is not None
    assert SYNC_NOT_OPEN in report.note

    # a later round with Sync alerts off attaches them: none was recorded as attached
    kibana_case["settings"]["syncAlerts"] = False

    def more(rep: Any) -> Any:
        line = rep.evidence[-1].model_copy(update={"id": "E99", "title": "A newer check"})
        return rep.model_copy(update={"evidence": (*rep.evidence, line)})

    await save_version(app_engine, case, more)
    r.advance(7 * 3600)
    again = await r.run(case)
    assert again.stopped is None, again.lines()
    assert kibana_case["totalAlerts"] == 25


async def test_an_attach_in_doubt_is_settled_by_the_look_against_the_lowered_total(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    """The second call timed out after it landed; the first left a closed alert out, so the
    case is expected to hold 9, not 10, when the look finds the second call."""
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"])
    calls = await alert_ids(r, case)
    await close_in_argus(migrated_engine, calls["attach:1"][0])
    r.kibana.crashes.append((sync_on_once_open(r), False))
    r.kibana.faults.append(
        Fault(writes_by("argus-lead", "/comments", 2, containing='"alertId"'), "timeout")
    )

    first = await r.run(case)

    assert first.stopped is not None
    assert first.ambiguous == 1
    assert (await r.states(case)).get("ambiguous") == 1
    for _ in range(70):
        r.advance(130)
        report = await r.run(case)
        if report.stopped is None and not report.held:
            break
    else:
        raise AssertionError((report.lines(), await r.steps(case)))
    assert set(await r.states(case)) == {"verified"}
    [kibana_case] = r.kibana.team_cases()
    assert kibana_case["totalAlerts"] == 24
    rows = await r.sql(
        "SELECT key, kibana_ids FROM case_team_steps WHERE kind = 'attach' ORDER BY seq"
    )
    assert rows[1].kibana_ids["alerts_total"] == 9
    assert rows[0].kibana_ids["left_out"] == [calls["attach:1"][0]]


async def test_with_sync_off_a_closed_alert_is_attached_like_any_other(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    r = rig(migrated_engine, writer_engine)
    case = await a_case(migrated_engine, app_engine, people["asha"])
    calls = await alert_ids(r, case)
    await close_in_argus(migrated_engine, calls["attach:1"][0])

    report = await r.run(case)

    assert report.stopped is None, report.lines()
    [kibana_case] = r.kibana.team_cases()
    assert kibana_case["totalAlerts"] == 25
    rows = await r.sql("SELECT kibana_ids FROM case_team_steps WHERE kind = 'attach'")
    assert all("left_out" not in row.kibana_ids for row in rows)
