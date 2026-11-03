"""Q-D4: attaching alerts is an alert write: at most five a call, at least 60 seconds between
calls, each alert on fewer than ten cases before, ``case_ids`` read back after, at most 200
representative alerts, Sync alerts off."""

from __future__ import annotations

import json
from itertools import pairwise

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.cases.conftest import Person
from tests.integration.cases.test_service import _kibana_actor
from tests.integration.writer.fake import make_alert
from tests.integration.writer.kit import many_alerts, rig

pytestmark = pytest.mark.integration


async def test_twelve_alerts_go_in_batches_of_five_a_minute_apart(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    from argus.writer import ramp

    r = rig(migrated_engine, app_engine, writer_engine)
    async with writer_engine.begin() as conn:  # past the canary, where a case holds five
        await ramp.raise_step(conn, "W1", 5, "asha", "looked", r.clock.now)
    case_id = await many_alerts(
        app_engine, migrated_engine, _kibana_actor(people["asha"]), investigations=6
    )

    report = await r.run("W1", limit=1)

    assert report.stopped is None, report.lines()
    steps = await r.steps(case_id)
    assert steps == [("comment", 0, "verified")] + [("attach", n, "verified") for n in (1, 2, 3)]
    [case] = r.kibana.ours()
    assert case["totalAlerts"] == 12
    batches = [
        (len(json.loads(w.body)["alertId"]), at)
        for w, at in zip(r.kibana.writes, r.kibana.written_at, strict=True)
        if w.method == "POST" and b'"alert"' in (w.body or b"")
    ]
    assert [n for n, _ in batches] == [5, 5, 2]  # never more than five a call
    gaps = [(b[1] - a[1]).total_seconds() for a, b in pairwise(batches)]
    assert all(gap >= 60 for gap in gaps), gaps  # alert calls are a minute apart at least
    for alert_id in (a for a, s in r.kibana.alerts.items() if s):
        assert r.kibana.alerts[alert_id]["kibana.alert.case_ids"] == [case["id"]]


async def test_an_alert_on_ten_cases_is_left_out_and_the_rest_attached(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await many_alerts(
        app_engine, migrated_engine, _kibana_actor(people["asha"]), investigations=2
    )
    first = (await r.sql("SELECT alert_id FROM alert_records ORDER BY alert_id"))[0].alert_id
    make_alert(r.kibana, first, cases=10)  # Kibana refuses an eleventh case, half-applied

    report = await r.run("W1", limit=1)

    assert report.stopped is None, report.lines()
    assert report.mismatches == 0
    [case] = r.kibana.ours()
    assert case["totalAlerts"] == 3  # four representatives, one left out
    assert case["id"] not in r.kibana.alerts[first]["kibana.alert.case_ids"]
    steps = await r.steps(case_id)
    assert ("attach", 1, "skipped") in steps
    assert ("attach", 2, "verified") in steps


async def test_case_ids_that_did_not_arrive_pause_the_class(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person], monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await many_alerts(
        app_engine, migrated_engine, _kibana_actor(people["asha"]), investigations=1
    )
    original = r.kibana._comment

    def forgetful(case_id, body):  # type: ignore[no-untyped-def]
        out = original(case_id, body)
        if body["type"] == "alert":  # the attachment is saved; the alerts never list the case
            for alert in body["alertId"]:
                r.kibana.alerts[alert]["kibana.alert.case_ids"] = []
        return out

    monkeypatch.setattr(r.kibana, "_comment", forgetful)

    report = await r.run("W1", limit=1)

    assert report.mismatches == 1
    assert "paused" in (report.stopped or "")
    assert ("attach", 1, "conflict") in await r.steps(case_id)
    assert "W1" in (await r.lane.kibana_lane()).paused


async def test_sync_alerts_on_stops_an_attach(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person], monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await many_alerts(
        app_engine, migrated_engine, _kibana_actor(people["asha"]), investigations=1
    )
    original = r.kibana._comment

    def switch_on(case_id, body):  # type: ignore[no-untyped-def]
        out = original(case_id, body)
        if body["type"] == "user":  # someone switches it on right after the opening comment
            r.kibana.cases[case_id]["settings"] = {"syncAlerts": True}
        return out

    monkeypatch.setattr(r.kibana, "_comment", switch_on)

    report = await r.run("W1", limit=1)

    assert r.kibana.attempts("POST", "/comments") == 1  # the comment only: no attach left ARGUS
    assert any("Sync alerts is on" in h for h in report.held)
    assert ("attach", 1, "planned") in await r.steps(case_id)
    assert [f.kind for f in await r.sql("SELECT kind FROM kibana_findings")] == ["settings_changed"]


async def test_a_lost_attachment_is_not_sent_again(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    from tests.integration.writer.fake import Fault

    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await many_alerts(
        app_engine, migrated_engine, _kibana_actor(people["asha"]), investigations=1
    )
    # the attach's answer is lost and Kibana never did it
    r.kibana.faults.append(
        Fault(
            lambda w: w.method == "POST" and b'"alert"' in (w.body or b""),
            "timeout",
            land_after=None,
        )
    )
    await r.run("W1", limit=1)
    assert ("attach", 1, "ambiguous") in await r.steps(case_id)
    in_doubt = r.clock.now
    for seconds in (121, 301, 901, 1801):
        r.advance(seconds - (r.clock.now - in_doubt).total_seconds())
        await r.writer.run_lookups()
    assert ("attach", 1, "skipped") in await r.steps(case_id)  # lost: a missing one beats a double
    reason = (await r.sql("SELECT state_reason FROM kibana_steps WHERE kind = 'attach'"))[0]
    assert reason.state_reason.startswith("lost:")
    r.advance(5400)
    await r.run("W1", limit=1)
    assert r.kibana.attempts("POST", "/comments") == 2  # the comment and the one attempt


async def test_at_the_canary_a_case_holds_at_most_five_alerts_and_a_second_run_writes_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    from argus.writer import ramp

    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await many_alerts(
        app_engine, migrated_engine, _kibana_actor(people["asha"]), investigations=6
    )

    first = await r.run("W1", limit=1, kind="canary")

    assert first.stopped is None, first.lines()
    [case] = r.kibana.ours()
    assert case["totalAlerts"] == 5
    assert case["totalComment"] == 1
    assert await r.steps(case_id) == [("comment", 0, "verified"), ("attach", 1, "verified")]
    writes = r.kibana.count("POST")
    assert (await r.run("W1", limit=1, kind="canary")).sent == 0  # a second run writes nothing
    assert r.kibana.count("POST") == writes

    async with writer_engine.begin() as conn:  # a person raises the step after looking in Kibana
        await ramp.raise_step(conn, "W1", 5, "asha", "looked", r.clock.now)
    report = await r.run("W1", limit=5)
    assert report.stopped is None, report.lines()
    assert r.kibana.cases[case["id"]]["totalAlerts"] == 12  # the rest of the representatives
