"""The still-active watch against Postgres (Q-C2): membership by alert, the day's answers from
ARGUS's own alerts and the proxy logs, "contained" only on positive evidence, new activity after
containment and closure, the 4-day outage of the PS1Bot replay, and order-free, idempotent runs.
Time is passed in; the gateway is a table of fixture answers (``watchkit.FakeAsker``)."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import watch
from argus.cases.machine import CaseRefused
from tests.integration.cases.conftest import Person
from tests.integration.cases.watchkit import (
    C2,
    D0,
    H1,
    H2,
    H3,
    FakeAsker,
    World,
    at,
    context,
)

pytestmark = pytest.mark.integration

ALERTS, CONTACT = watch.ALERTS, watch.CONTACT


def day(n: int):  # type: ignore[no-untyped-def]
    return D0 + timedelta(days=n)


@pytest.fixture
def world(migrated_engine: AsyncEngine, app_engine: AsyncEngine) -> World:
    return World(migrated_engine, app_engine)


async def test_local_mode_answers_from_alerts_only_and_asks_nothing(
    world: World, people: dict[str, Person]
) -> None:
    first = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(people["asha"], [first], [H1], at(0, 10))
    await world.add_alert(first, at(1, 5))  # the case's own investigation alerts again on day 1
    ctx = context(None)
    report = await world.run(ctx, at(3, 3))
    assert report.mode == "local"
    assert report.asked == 0
    rows = await world.rows(case_id)
    assert rows == {
        (day(0), ALERTS, "", 0): "active",
        (day(1), ALERTS, "", 0): "active",
        (day(2), ALERTS, "", 0): "quiet",
    }
    (entry,) = report.cases
    assert entry.rows == {"active": 2, "quiet": 1}


async def asked_per_day(world: World) -> dict[object, int]:
    async with world.owner.connect() as conn:
        found = await conn.execute(
            text(
                "SELECT asked_on, case_id, sum(requests) AS n FROM case_watch_checks"
                " WHERE asked_on IS NOT NULL GROUP BY asked_on, case_id"
            )
        )
        return {(r.asked_on, r.case_id): int(r.n) for r in found}


async def test_the_ps1bot_replay_with_a_four_day_outage(
    world: World, people: dict[str, Person]
) -> None:
    asha = people["asha"]
    asker = FakeAsker()
    ctx = context(asker)
    asker.beacon(range(0, 6), [H1, H2, H3])  # D0 to D5: all three hosts beacon to one C2
    reports = {}

    # D0: a person confirms the first host; nothing yet tells ARGUS about the other two
    i1 = await world.investigation(H1, [at(0, 9), at(0, 9, 5)])
    case_id = await world.open_case(asha, [i1], [H1], at(0, 10))
    reports[1] = await world.run(ctx, at(1, 3))
    # ARGUS's own alerts come first: they already show the day active, so the SIEM is not asked
    assert await world.rows(case_id) == {(day(0), ALERTS, "", 0): "active"}
    assert asker.asked == []

    # D1 and D2: the other two hosts alert once each; the rule does not fire again
    i2 = await world.investigation(H2, [at(1, 8)])
    reports[2] = await world.run(ctx, at(2, 3))
    i3 = await world.investigation(H3, [at(2, 8)])
    reports[3] = await world.run(ctx, at(3, 3))
    assert await world.members(case_id) == {i1, i2, i3}  # one case, all three hosts
    assert await world.actors(case_id) == {H1, H2, H3}
    async with world.owner.connect() as conn:
        assert (await conn.execute(text("SELECT count(*) FROM cases"))).scalar_one() == 1
    number = (await world.case(case_id)).number
    assert reports[2].case(number).joined == 1
    assert reports[3].case(number).joined == 1
    assert asker.asked == []  # every one of D0 to D2 had alerts: nothing was asked of the SIEM

    # "contained" is refused while the hosts are still beaconing, with the reason
    with pytest.raises(CaseRefused) as refused:
        await world.contain(ctx, asha, case_id, at(3, 4))
    assert refused.value.code == "unavailable"
    assert "not contained" in refused.value.message
    assert "activity" in refused.value.message

    # the outage: the SIEM is stopped from D3 12:00 to D7 12:00 and the collector with it
    await world.cursor(at(3, 12))
    asker.refuse = "stopped"
    world.skip_readings(at(7, 12))
    before = len(asker.asked)
    for n in (4, 5, 6, 7):
        reports[n] = await world.run(ctx, at(n, 3), live=False)
        assert len(asker.asked) == before + (n - 3)  # one refused question a run: no hammering
    for n in (3, 4, 5, 6):  # every day of the outage is flagged by the first run after it
        flagged = [note for note in reports[n + 1].case(number).notes if f"({day(n)})" in note]
        assert any("not checked: ARGUS's reads of the SIEM are stopped" in x for x in flagged), n
        assert any("not checked: the collector had not read alerts" in x for x in flagged), n
    rows = await world.rows(case_id)
    assert [rows[(day(n), CONTACT, C2, 0)] for n in (3, 4, 5, 6)] == ["not_checked"] * 4
    assert (day(3), ALERTS, "", 0) not in rows  # the collector's own answer waits, with a note

    # The SIEM is back at D7 12:00; ARGUS catches up on every day it can still ask about
    asker.refuse = None
    await world.gap(at(3, 12), at(7, 12))
    reports[8] = await world.run(ctx, at(8, 3))
    rows = await world.rows(case_id)
    for n in range(0, 8):  # no day is silently missing: ARGUS's alerts answered each one ...
        assert (day(n), ALERTS, "", 0) in rows, n
    for n in range(3, 8):  # ... and the proxy logs every one the alerts left open
        assert (day(n), CONTACT, C2, 0) in rows, n
    assert asker.asked[-5:] == [("proxy.contact", day(n), C2) for n in (3, 4, 5, 6, 7)]
    assert [rows[(day(n), CONTACT, C2, 0)] for n in range(3, 8)] == [
        "active", "active", "active", "unverified", "unverified",
    ]  # fmt: skip
    assert [rows[(day(n), ALERTS, "", 0)] for n in range(3, 8)] == ["unverified"] * 5
    async with world.owner.connect() as conn:
        reason = (
            await conn.execute(
                text(
                    "SELECT reason FROM case_watch_checks"
                    " WHERE day = :d AND source = 'proxy.contact'"
                ),
                {"d": day(6)},
            )
        ).scalar_one()
    assert "no freshness reading at the start" in reason

    # still not contained: the days around the outage cannot be verified, and it says why
    with pytest.raises(CaseRefused) as unknown:
        await world.contain(ctx, asha, case_id, at(9, 4))
    assert "source stalled" in unknown.value.message

    # three clean, verified days later (D8, D9, D10) the window is verified and a person
    # contains the case with an attestation
    ready = "quiet for 72 hours: a person may contain it"
    for n in (9, 10):  # D8 and D9 are clean, D10 is not yet there: nothing is proposed
        report = await world.run(ctx, at(n, 3))
        assert not any(ready in e for e in report.case(number).events)
    report = await world.run(ctx, at(11, 3))
    assert any(ready in e for e in report.case(number).events)  # the window is verified now
    assert any(
        "alerts, and the proxy logs 01:40-22:59 UTC" in e for e in report.case(number).events
    )
    rows = await world.rows(case_id)
    assert [rows[(day(n), CONTACT, C2, 0)] for n in (8, 9, 10)] == ["quiet"] * 3
    assert [rows[(day(n), ALERTS, "", 0)] for n in (8, 9, 10)] == ["quiet"] * 3
    window = await world.finder_window(ctx, case_id, at(11, 4))
    assert window.verified
    assert f"{day(8)} to {day(10)}" in window.reason
    applied = await world.contain(ctx, asha, case_id, at(11, 4))
    assert applied.case.state == "contained"
    assert (await world.outbox(case_id))[-2:] == [("W2", "update"), ("W2", "comment")]

    # D11 10:30: the beacon resumes; the next run flags it within 24 hours and reopens the case
    asker.contacts[day(11)] = ({H2: 40}, at(11, 10, 30))
    reports[12] = await world.run(ctx, at(12, 3))
    assert at(12, 3) - at(11, 10, 30) < timedelta(hours=24)
    case = await world.case(case_id)
    assert (case.state, case.attention) == ("open", "New activity after containment")
    assert case.owner_user_id is None
    assert (await world.rows(case_id))[(day(11), CONTACT, C2, 0)] == "active"
    assert (await world.events(case_id))[-2:] == ["contained", "new_activity"]
    assert (await world.outbox(case_id))[-2:] == [("W2", "update"), ("W2", "comment")]
    assert any("the case is open again" in e for e in reports[12].case(number).events)

    # a second run adds nothing: no answer, no request, no event
    events, rows, asks = await world.events(case_id), await world.rows(case_id), len(asker.asked)
    again = await world.run(ctx, at(12, 3))
    assert (await world.events(case_id), await world.rows(case_id), len(asker.asked)) == (
        events,
        rows,
        asks,
    )
    assert again.asked == 0
    assert max((await asked_per_day(world)).values()) <= watch.cap_for(1)


# --------------------------------------------------------------------------- order-free, idempotent

SCHEDULES = {
    "daily": [1, 2, 3, 4, 5, 6, 7],
    "every other day": [2, 4, 6, 7],
    "one catch-up": [7],
    "first and last": [1, 7],
}


@pytest.mark.parametrize("schedule", SCHEDULES)
async def test_any_schedule_of_runs_gives_the_same_case_state(
    schedule: str, world: World, people: dict[str, Person]
) -> None:
    """The same data, watched on different days (each run sees only what exists by then): the
    case, its members and every answer for the days the schedule covered end up the same, and a
    run repeated at the same time adds nothing."""
    asha = people["asha"]
    asker = FakeAsker()
    ctx = context(asker)
    asker.beacon(range(0, 3), [H1, H2, H3])
    pending = [
        (at(0, 9), H1, [at(0, 9)]),
        (at(1, 8), H2, [at(1, 8)]),
        (at(2, 8), H3, [at(2, 8)]),
    ]  # fmt: skip
    created: dict[str, object] = {}
    case_id = None

    async def create_due(now):  # type: ignore[no-untyped-def]
        nonlocal case_id
        for when, host, alerts in list(pending):
            if when <= now:
                pending.remove((when, host, alerts))
                inv = await world.investigation(host, alerts)
                created[host] = inv
                if host == H1:
                    case_id = await world.open_case(asha, [inv], [H1], at(0, 10))

    await create_due(at(0, 10))
    for n in SCHEDULES[schedule]:
        await create_due(at(n, 3))
        await world.run(ctx, at(n, 3))
    assert case_id is not None
    rows = await world.rows(case_id)
    # a day is answered once a run after it has seen it; every answer is the same whatever the
    # schedule, and no answer is a guess
    assert {k: v for k, v in rows.items() if k[1] == ALERTS} == {
        (day(0), ALERTS, "", 0): "active",
        (day(1), ALERTS, "", 0): "active",
        (day(2), ALERTS, "", 0): "active",
        **{(day(n), ALERTS, "", 0): "quiet" for n in range(3, 7)},
    }
    assert {k: v for k, v in rows.items() if k[1] == CONTACT} == {
        (day(n), CONTACT, C2, 0): "quiet" for n in range(3, 7)
    }
    assert await world.members(case_id) == set(created.values())  # i1, i2, i3
    assert await world.actors(case_id) == {H1, H2, H3}
    case = await world.case(case_id)
    assert (case.state, case.attention) == ("open", None)
    events, asks = await world.events(case_id), len(asker.asked)
    again = await world.run(ctx, at(SCHEDULES[schedule][-1], 3))
    assert again.asked == 0
    assert (await world.rows(case_id), await world.events(case_id), len(asker.asked)) == (
        rows,
        events,
        asks,
    )


# --------------------------------------------------------------------------- membership

CF = "104.21.5.5"  # inside Cloudflare's 104.16.0.0/13


async def suggestions(world: World) -> list[tuple[str, str]]:
    async with world.owner.connect() as conn:
        found = await conn.execute(text("SELECT kind, link FROM case_suggestions ORDER BY id"))
        return [(r.kind, r.link) for r in found]


async def test_an_investigation_that_matches_two_cases_equally_joins_neither(
    world: World, people: dict[str, Person]
) -> None:
    asha = people["asha"]
    first = await world.investigation(H1, [at(0, 9)], entities=())
    second = await world.investigation(H2, [at(0, 9, 30)], entities=())
    one = await world.open_case(asha, [first], [H1, H3], at(0, 10), c2=None)
    two = await world.open_case(asha, [second], [H2, H3], at(0, 10, 5), c2=None)
    third = await world.investigation(H3, [at(1, 8)], entities=())  # H3 is an actor of both
    ctx = context(None)
    report = await world.run(ctx, at(2, 3))
    assert await world.members(one) == {first}
    assert await world.members(two) == {second}
    assert await suggestions(world) == [("tie", "actor"), ("tie", "actor")]
    assert [c.suggested for c in report.cases] == [1, 1]
    # H3 did alert on D1: that is activity of both cases whoever owns the investigation
    assert (await world.rows(one))[(day(1), ALERTS, "", 0)] == "active"
    assert (await world.rows(two))[(day(1), ALERTS, "", 0)] == "active"
    # the person who knows decides: joining it by hand stays possible, a rerun adds no row
    again = await world.run(ctx, at(2, 3))
    assert [c.suggested for c in again.cases] == [0, 0]
    assert await suggestions(world) == [("tie", "actor"), ("tie", "actor")]
    del third


async def test_a_cdn_address_alone_never_joins_but_a_campus_host_beside_it_does(
    world: World, people: dict[str, Person]
) -> None:
    asha = people["asha"]
    first = await world.investigation(H1, [at(0, 9)], entities=(("ip", CF),))
    case_id = await world.open_case(asha, [first], [H1], at(0, 10), c2=CF)
    other = await world.investigation(H2, [at(1, 8)], entities=(("ip", CF),))  # same CDN address
    mine = await world.investigation(H1, [at(1, 9)], entities=(("ip", CF),))  # same host and CDN
    ctx = context(None)
    report = await world.run(ctx, at(2, 3))
    assert await world.members(case_id) == {first, mine}
    assert other not in await world.members(case_id)
    async with world.owner.connect() as conn:
        shown = (
            await conn.execute(text("SELECT investigation_id, kind, why FROM case_suggestions"))
        ).all()
    assert [(r.investigation_id, r.kind) for r in shown] == [(other, "shared")]
    assert "content-delivery" in shown[0].why
    assert report.case((await world.case(case_id)).number).joined == 1


async def test_an_investigation_the_person_judged_benign_is_not_activity(
    world: World, people: dict[str, Person]
) -> None:
    asha = people["asha"]
    first = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(asha, [first], [H1], at(0, 10))
    benign = await world.investigation(H2, [at(1, 8)])  # reaches the C2, but a person looked
    async with world.owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                " action, outcome, kibana_ok) VALUES (:i, 1, 1, :u, 'reviewed',"
                " 'benign_expected', true)"
            ),
            {"i": benign, "u": asha.user_id},
        )
    await world.run(context(None), at(2, 3))
    assert await world.members(case_id) == {first}
    assert (await world.rows(case_id))[(day(1), ALERTS, "", 0)] == "quiet"


# --------------------------------------------------------------------------- after closure

from argus.cases.service import CaseService  # noqa: E402
from tests.integration.cases.test_service import _decide, _request  # noqa: E402


def clock_at(moment):  # type: ignore[no-untyped-def]
    async def fake(self: object):  # type: ignore[no-untyped-def]
        return moment

    return fake


async def closed_case(  # type: ignore[no-untyped-def]
    world, api, people, monkeypatch, *, reason="remediated_unverified", closed=None, hosts=(H1,)
):
    """A case opened on D0 with ``hosts`` and closed (by the approvals) at ``closed``."""
    asha, ravi, meera = people["asha"], people["ravi"], people["meera"]
    first = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(asha, [first], list(hosts), at(0, 10))
    version = (await world.case(case_id)).version
    request = await _request(api, asha, case_id, version, reason, note="cleaned up")
    monkeypatch.setattr(CaseService, "_clock", clock_at(closed or at(2, 12)))
    await _decide(api, ravi, request)
    if reason in ("remediated_unverified", "risk_accepted"):
        await _decide(api, meera, request)
    assert (await world.case(case_id)).state == "closed"
    return case_id, first


async def test_activity_after_closure_opens_a_suspected_case_that_follows_it(
    world: World, api_engine: AsyncEngine, people: dict[str, Person],
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    parent, first = await closed_case(world, api_engine, people, monkeypatch)
    ctx = context(None)
    await world.run(ctx, at(3, 3))  # nothing yet: the days after closure are quiet
    assert (await world.events(parent))[-1] == "closed"
    new = await world.investigation(H1, [at(3, 9)])
    report = await world.run(ctx, at(4, 3))
    async with world.owner.connect() as conn:
        child = (
            await conn.execute(
                text(
                    "SELECT id, number, state, cause, parent_case_id, opened_at FROM cases"
                    " WHERE parent_case_id = :p"
                ),
                {"p": parent},
            )
        ).one()
    assert (child.state, child.cause, child.opened_at) == ("suspected", "watch", None)
    assert await world.members(child.id) == {new}
    assert await world.outbox(child.id) == []  # suspected cases stay in ARGUS
    closed = await world.case(parent)
    assert closed.state == "closed"  # never a silent reopen
    assert (await world.events(parent))[-2:] == ["closed", "activity_after_closure"]
    assert report.case(closed.number).events == [
        f"activity after closure: suspected case {child.number} follows it"
    ]
    assert (await world.rows(parent))[(day(3), ALERTS, "", 0)] == "active"
    # later activity joins the follower, and a second run changes nothing
    later = await world.investigation(H1, [at(4, 9)])
    await world.run(ctx, at(5, 3))
    assert await world.members(child.id) == {new, later}
    async with world.owner.connect() as conn:
        assert (
            await conn.execute(
                text("SELECT count(*) FROM cases WHERE parent_case_id = :p"), {"p": parent}
            )
        ).scalar_one() == 1
    before = (await world.events(parent), await world.events(child.id))
    await world.run(ctx, at(5, 3))
    assert (await world.events(parent), await world.events(child.id)) == before
    del first


async def test_contact_in_the_logs_after_closure_is_noted_once_on_the_closed_case(
    world: World, api_engine: AsyncEngine, people: dict[str, Person],
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    parent, _ = await closed_case(world, api_engine, people, monkeypatch)
    asker = FakeAsker()
    asker.contacts[day(3)] = ({H1: 30}, at(3, 14))
    ctx = context(asker)
    report = await world.run(ctx, at(4, 3))
    case = await world.case(parent)
    assert (case.state, case.attention) == (
        "closed",
        "Activity after closure, seen in the proxy logs",
    )
    assert (await world.events(parent))[-1] == "activity_after_closure"
    assert report.case(case.number).events == ["activity after closure noted on the closed case"]
    asker.contacts[day(4)] = ({H1: 30}, at(4, 14))
    await world.run(ctx, at(5, 3))
    assert (await world.events(parent)).count("activity_after_closure") == 1  # noted once


async def test_the_watch_lasts_fourteen_days_after_closure_and_only_for_remediation(
    world: World, api_engine: AsyncEngine, people: dict[str, Person],
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    parent, _ = await closed_case(world, api_engine, people, monkeypatch)
    ctx = context(None)
    assert len((await world.run(ctx, at(2, 12) + timedelta(days=14), apply=False)).cases) == 1
    assert (
        await world.run(ctx, at(2, 12) + timedelta(days=14, minutes=1), apply=False)
    ).cases == []
    del parent


async def test_a_benign_closure_is_not_watched(
    world: World, api_engine: AsyncEngine, people: dict[str, Person],
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    await closed_case(world, api_engine, people, monkeypatch, reason="benign_policy")
    new = await world.investigation(H1, [at(3, 9)])
    report = await world.run(context(None), at(4, 3))
    assert report.cases == []
    async with world.owner.connect() as conn:
        assert (await conn.execute(text("SELECT count(*) FROM cases"))).scalar_one() == 1
    del new


# --------------------------------------------------------------------------- the cap and refusals

DESTINATIONS = [f"77.221.155.{n}" for n in range(150, 154)]


async def test_a_case_gets_at_most_six_requests_a_day_and_the_rest_keep_waiting(
    world: World, people: dict[str, Person]
) -> None:
    first = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(people["asha"], [first], [H1], at(0, 10), c2=DESTINATIONS)
    asker = FakeAsker()
    ctx = context(asker)
    report = await world.run(ctx, at(8, 3))  # D1 to D7 are open: 7 days of 4 addresses
    number = (await world.case(case_id)).number
    entry = report.case(number)
    assert (entry.asked, entry.cut_off) == (6, 22)
    assert [(d, c2) for _, d, c2 in asker.asked] == [
        *[(day(1), c) for c in DESTINATIONS], *[(day(2), c) for c in DESTINATIONS[:2]],
    ]  # fmt: skip  # the oldest unanswered day first (Q-C2 review R18)
    rows = await world.rows(case_id)
    waiting = [k for k, v in rows.items() if v == "not_checked"]
    assert len(waiting) == 22
    async with world.owner.connect() as conn:
        reason = (
            await conn.execute(
                text("SELECT reason FROM case_watch_checks WHERE outcome = 'not_checked' LIMIT 1")
            )
        ).scalar_one()
    assert "has asked its 6 proxy-log questions for today" in reason
    assert max((await asked_per_day(world)).values()) == 6
    window = await world.finder_window(ctx, case_id, at(8, 4))
    assert not window.verified  # a cut-off address keeps "cannot verify yet"
    # asking again the same day sends nothing; the next day asks the next six
    assert (await world.run(ctx, at(8, 20))).asked == 0
    assert (await world.run(ctx, at(9, 3))).case(number).asked == 6
    assert max((await asked_per_day(world)).values()) == 6


async def test_without_verified_zeros_a_quiet_window_is_never_reached(
    world: World, api_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    asha = people["asha"]
    first = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(asha, [first], [H1], at(0, 10))
    asker = FakeAsker()
    off = context(asker, fresh="off")
    for n in (1, 2, 3, 4):
        proposed = await world.run(off, at(n, 3))
        assert not any("may contain it" in e for c in proposed.cases for e in c.events)
    assert {v for k, v in (await world.rows(case_id)).items() if k[1] == CONTACT} == {"unverified"}
    with pytest.raises(CaseRefused) as refused:
        await world.contain(off, asha, case_id, at(4, 4))
    assert "not switched on yet (Q-F1)" in refused.value.message
    # switched on later: the days already decided stay as they were; three new days are needed
    on = context(asker)
    for n in (5, 6):
        await world.run(on, at(n, 3))
    held_back = await world.finder_window(on, case_id, at(6, 4))
    assert not held_back.verified  # D3 was decided while zeros were off
    assert "not verified" in held_back.reason
    await world.run(on, at(7, 3))
    window = await world.finder_window(on, case_id, at(7, 4))
    assert window.verified, window.reason
    assert f"{day(4)} to {day(6)}" in window.reason
    # a late alert for a day the stored answers call quiet is seen by the live check
    await world.investigation(H1, [at(6, 10)])
    refused_late = await world.finder_window(on, case_id, at(7, 4))
    assert not refused_late.verified
    assert f"on {day(6)}" in refused_late.reason


async def test_a_verified_window_lets_arguss_proposer_propose_remediation(
    world: World, api_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    from argus.cases import proposer, watchrun
    from argus.cases.service import CaseService as Service

    asha = people["asha"]
    first = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(asha, [first], [H1], at(0, 10))
    ctx = context(FakeAsker())
    for n in range(1, 6):
        await world.run(ctx, at(n, 3))
    applied = await world.contain(ctx, asha, case_id, at(5, 4))
    assert applied.case.state == "contained"
    await world.run(ctx, at(6, 3))
    async with world.runtime.begin() as conn:
        finder = watchrun.Finder(conn, ctx, lambda: at(6, 4))
        found = await proposer.candidates(conn, windows=finder)
        assert [(c.number, c.reason) for c in found] == [
            (applied.case.number, "remediated_verified")
        ]
        assert "whole UTC days" in found[0].evidence
        assert Service  # the service is built with the same finder by the CLI
    async with world.runtime.begin() as conn:  # without the finder nothing is ever proposed
        assert await proposer.candidates(conn) == []


async def test_a_refusal_is_remembered_and_a_refusal_for_one_address_does_not_stop_the_rest(
    world: World, people: dict[str, Person]
) -> None:
    first = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(people["asha"], [first], [H1], at(0, 10), c2=DESTINATIONS[:2])
    asker = FakeAsker()
    ctx = context(asker)
    asker.refuse = "too_common"  # a property of the address: asking another still makes sense
    report = await world.run(ctx, at(2, 3))  # D1 only (D0 alerts are active)
    assert len(asker.asked) == 2
    assert {v for k, v in (await world.rows(case_id)).items() if k[1] == CONTACT} == {"unverified"}
    async with world.owner.connect() as conn:
        reason = (
            await conn.execute(
                text("SELECT reason FROM case_watch_checks WHERE source = 'proxy.contact' LIMIT 1")
            )
        ).scalar_one()
    assert reason == "could not tell: too common to query"
    assert report.case(1).notes == []  # decided for the day: nothing is waiting
    asker.asked.clear()
    asker.refuse = "deferred"  # a property of the SIEM: the rest wait, one question was enough
    await world.run(ctx, at(3, 3))  # D2
    assert len(asker.asked) == 1
    rows = await world.rows(case_id)
    assert [v for k, v in rows.items() if k[0] == day(2) and k[1] == CONTACT] == ["not_checked"] * 2
    asker.asked.clear()
    asker.refuse = None
    asker.failing = True  # sent, but no usable answer: it counts, and it is asked again
    await world.run(ctx, at(3, 20))
    assert len(asker.asked) == 2
    async with world.owner.connect() as conn:
        spent = (
            await conn.execute(
                text("SELECT sum(requests) FROM case_watch_checks WHERE asked_on = :d"),
                {"d": day(3)},
            )
        ).scalar_one()
    assert spent == 2
    asker.failing = False
    await world.run(ctx, at(3, 21))
    assert {
        v for k, v in (await world.rows(case_id)).items() if k[0] == day(2) and k[1] == CONTACT
    } == {"quiet"}


async def test_proxy_pair_describes_the_rhythm_when_contact_was_seen(
    world: World, people: dict[str, Person]
) -> None:
    first = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(people["asha"], [first], [H1], at(0, 10))
    asker = FakeAsker()
    asker.beacon([3], [H1])
    await world.run(context(asker, pair=True), at(4, 3))
    pair = [a for a in asker.asked if a[0] == "proxy.pair"]
    assert pair == [("proxy.pair", day(3), C2)]
    async with world.owner.connect() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT subject, outcome, detail, requests FROM case_watch_checks"
                    " WHERE source = 'proxy.pair'"
                )
            )
        ).one()
    assert row.subject == f"{H1}>{C2}"
    assert (row.outcome, row.requests, row.detail["period_s"]) == ("active", 1, 360)
    assert row.detail["still_active"] is True
    assert max((await asked_per_day(world)).values()) == 4  # three days' contact, one rhythm
    del case_id


async def test_a_value_in_very_many_investigations_is_neither_joined_nor_suggested(
    world: World, people: dict[str, Person]
) -> None:
    from argus.cases import membership

    popular = "198.51.100.77"
    first = await world.investigation(H1, [at(0, 9)], entities=(("ip", popular),))
    case_id = await world.open_case(people["asha"], [first], [H1], at(0, 10), c2=popular)
    crowd = [
        await world.investigation(f"10.77.0.{n}", [at(1, 7)], entities=(("ip", popular),))
        for n in range(1, membership.COMMON_INVESTIGATIONS + 1)
    ]  # fifty hosts in fifty investigations reach it: it says nothing about who is behind it
    async with world.owner.connect() as conn:
        found = await membership.common_values(conn, {("ip", popular), ("ip", C2)}, at(0))
    assert found == {("ip", popular)}
    report = await world.run(context(None), at(2, 3))
    assert await world.members(case_id) == {first}
    assert await suggestions(world) == []  # not even a suggestion: it would be fifty of them
    assert report.case((await world.case(case_id)).number).joined == 0
    assert len(crowd) == membership.COMMON_INVESTIGATIONS


async def test_a_second_run_cannot_start_while_one_is_going(
    world: World, people: dict[str, Person]
) -> None:
    from argus.cases import watchrun
    from argus.cases.watchrun import LOCK_KEY

    inv = await world.investigation(H1, [at(0, 9)])
    await world.open_case(people["asha"], [inv], [H1], at(0, 10))
    async with world.owner.connect() as holder:
        await holder.execute(text("SELECT pg_advisory_lock(:k)"), {"k": LOCK_KEY})
        try:
            refused = await watchrun.run(world.runtime, context(None), now=at(2, 3))
        finally:
            await holder.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": LOCK_KEY})
            await holder.commit()
    assert refused.problems == ["another run of the watch is in progress: nothing was done"]
    assert await world.rows((await world.case_ids())[0]) == {}  # and it changed nothing
    assert (await world.run(context(None), at(2, 3))).problems == []  # the lock was let go


async def test_the_rhythm_is_read_for_the_address_that_had_contact(
    world: World, people: dict[str, Person]
) -> None:
    first = await world.investigation(H1, [at(2, 9)])
    await world.open_case(people["asha"], [first], [H1], at(2, 10), c2=DESTINATIONS[:2])
    asker = FakeAsker()
    asker.beacon([3], [H1])
    asker.only = {DESTINATIONS[1]}  # the second address, not the first
    await world.run(context(asker, pair=True), at(4, 3))
    assert [a for a in asker.asked if a[0] == "proxy.pair"] == [
        ("proxy.pair", day(3), DESTINATIONS[1])
    ]
