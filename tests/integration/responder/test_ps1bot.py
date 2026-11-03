"""The PS1Bot class through the responder (Q-H2): three campus hosts beacon to one C2, the
network team says it blocked the address, the beacons go on, a second report follows a clean-up,
and only then does the case go quiet. Real tables, the still-active watch run for real over a
fake gateway, no model."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.machine import Open
from argus.cases.model import Actor, Member
from argus.cases.service import CaseService
from argus.responder import store
from argus.responder.machine import ActionRefused
from tests.integration.cases.conftest import Person
from tests.integration.responder.kit import H1, H2, H3, FakeAsker, Scene, at, context

pytestmark = pytest.mark.integration

ISOLATE, BLOCK = "c2_beacon.isolate_host", "c2_beacon.block_destination"


@pytest.fixture
def scene(migrated_engine: AsyncEngine, app_engine: AsyncEngine) -> Scene:
    return Scene(migrated_engine, app_engine)


async def test_the_ps1bot_advice_and_its_four_states(
    scene: Scene, people: dict[str, Person]
) -> None:
    asha: Actor = people["asha"].actor()
    case_id, _ = await scene.beacon_case(people["asha"], at(0, 10))
    # advice is computed from the case alone, before anything is stored
    views = await scene.views(case_id, at(0, 12))
    assert list(views) == [ISOLATE, BLOCK]
    assert {v.state for v in views.values()} == {"recommended"}
    assert {v.stored_state for v in views.values()} == {None}
    assert views[ISOLATE].owner_name == "Network team"
    assert views[ISOLATE].verifier == "proxy.contact"
    assert await scene.stored(case_id) == {}

    assert await scene.do(case_id, at(0, 12)) == [[ISOLATE, BLOCK], []]
    assert await scene.do(case_id, at(0, 13)) == [[], []]  # advice is recorded once
    stored = await scene.stored(case_id)
    assert {r.state for r in stored.values()} == {"recommended"}

    async with scene.runtime.begin() as conn:
        await store.request(conn, case_id, ISOLATE, asha, at(1, 9))
        await store.report_done(conn, case_id, BLOCK, asha, "Blocked it on the firewall", at(1, 15))
    views = await scene.views(case_id, at(1, 16))
    assert (views[ISOLATE].state, views[BLOCK].state) == ("requested", "reported_done")
    assert views[ISOLATE].requested_by == asha.name
    assert views[BLOCK].reported_by == asha.name
    assert views[BLOCK].attestation == "Blocked it on the firewall"
    assert "an attestation: ARGUS cannot see the action" in views[BLOCK].detail
    assert "Waiting" in views[BLOCK].detail  # nothing could verify it yet

    # the order of moves is the machine's: a request after a report, a second report
    async with scene.runtime.begin() as conn:
        with pytest.raises(ActionRefused) as caught:
            await store.request(conn, case_id, BLOCK, asha, at(1, 17))
    assert caught.value.code == "conflict"
    async with scene.runtime.begin() as conn:
        with pytest.raises(ActionRefused) as caught:
            await store.report_done(conn, case_id, BLOCK, asha, "again", at(1, 18))
    assert caught.value.code == "conflict"


async def test_beacons_after_the_block_are_not_verified_then_the_clean_up_verifies_it(
    scene: Scene, people: dict[str, Person]
) -> None:
    asha: Actor = people["asha"].actor()
    asker = FakeAsker()
    ctx = context(asker)
    asker.beacon(range(0, 3), [H1, H2, H3])  # D0 to D2; the hosts are cleaned on D3
    case_id, _ = await scene.beacon_case(people["asha"], at(0, 10))
    await scene.do(case_id, at(0, 12))
    async with scene.runtime.begin() as conn:
        await store.report_done(conn, case_id, BLOCK, asha, "The address is blocked", at(1, 15))
    for n in (1, 2, 3):
        await scene.run(ctx, at(n, 3))

    # D1's last beat (3:00 PM IST) was before the block at 8:30 PM IST; D2's was after it
    views = await scene.views(case_id, at(3, 4), ctx)
    assert views[BLOCK].state == "not_verified"
    assert views[BLOCK].last_beat == at(2, 12, 30)
    assert "Not verified: still beaconing, last beat 6:00 PM IST on 16 Oct 2026." in (
        views[BLOCK].detail
    )
    assert views[BLOCK].stored_state == "reported_done"  # reading does not write
    assert (await scene.stored(case_id))[BLOCK].state == "reported_done"

    # ARGUS records it
    assert (await scene.do(case_id, at(3, 4), ctx))[1] == [(BLOCK, "not_verified")]
    row = (await scene.stored(case_id))[BLOCK]
    assert (row.state, row.last_beat, row.verdict) == (
        "not_verified",
        at(2, 12, 30),
        "still beaconing",
    )
    assert (await scene.do(case_id, at(3, 5), ctx))[1] == []  # the same sign: nothing to add

    # a person cleans the hosts and reports again; the old verdict is gone with the new report
    async with scene.runtime.begin() as conn:
        await store.report_done(
            conn, case_id, BLOCK, asha, "The three hosts were rebuilt", at(3, 10)
        )
    row = (await scene.stored(case_id))[BLOCK]
    assert (row.state, row.verdict, row.last_beat) == ("reported_done", None, None)
    for n in range(4, 8):
        await scene.run(ctx, at(n, 3))

    # three whole UTC days must pass after the report's day (D3): D4, D5, D6; today is D7
    early = await scene.views(case_id, at(6, 5), ctx)
    assert early[BLOCK].state == "reported_done"
    assert "whole UTC days must pass" in early[BLOCK].detail
    views = await scene.views(case_id, at(7, 5), ctx)
    assert views[BLOCK].state == "verified"
    assert "Verified: no activity of the case's addresses for 3 whole UTC days" in (
        views[BLOCK].detail
    )
    assert (await scene.do(case_id, at(7, 5), ctx))[1] == [(BLOCK, "verified")]
    final = await scene.stored(case_id)
    assert (final[BLOCK].state, final[BLOCK].last_beat) == ("verified", None)
    assert final[ISOLATE].state == "recommended"  # nobody reported it: ARGUS does not guess

    # and if the beacons come back, ARGUS says so: verified -> not verified
    asker.beacon([8], [H1])
    await scene.run(ctx, at(9, 3))
    back = await scene.views(case_id, at(9, 4), ctx)
    assert back[BLOCK].state == "not_verified"
    assert (await scene.do(case_id, at(9, 4), ctx))[1] == [(BLOCK, "not_verified")]


async def test_coverage_that_is_unknown_is_never_verified_even_with_quiet_days(
    scene: Scene, people: dict[str, Person]
) -> None:
    """The same quiet days, three ways to leave coverage unknown: Q-F1's verified zeros off, no
    watch settings to list the case's addresses, an outage in the middle."""
    asha: Actor = people["asha"].actor()
    asker = FakeAsker()
    asker.beacon(range(0, 1), [H1, H2, H3])
    case_id, _ = await scene.beacon_case(people["asha"], at(0, 10))
    await scene.do(case_id, at(0, 12))
    async with scene.runtime.begin() as conn:
        await store.report_done(conn, case_id, BLOCK, asha, "Blocked", at(1, 2))
    on = context(asker)
    for n in range(2, 8):
        await scene.run(on, at(n, 3))
    assert (await scene.views(case_id, at(7, 5), on))[BLOCK].state == "verified"  # the control

    no_zeros = context(asker, fresh="off")
    assert (await scene.views(case_id, at(7, 5), no_zeros))[BLOCK].state == "reported_done"
    without_settings = await scene.views(case_id, at(7, 5), None)
    assert without_settings[BLOCK].state == "reported_done"
    assert "cannot be listed" in without_settings[BLOCK].detail
    assert await scene.do(case_id, at(7, 5), no_zeros) == [[], []]  # nothing is written either
    assert (await scene.stored(case_id))[BLOCK].state == "reported_done"


async def test_an_outage_leaves_days_unchecked_so_the_case_is_not_verified(
    scene: Scene, people: dict[str, Person]
) -> None:
    asha: Actor = people["asha"].actor()
    asker = FakeAsker()
    ctx = context(asker)
    asker.beacon(range(0, 1), [H1, H2, H3])
    case_id, _ = await scene.beacon_case(people["asha"], at(0, 10))
    await scene.do(case_id, at(0, 12))
    async with scene.runtime.begin() as conn:
        await store.report_done(conn, case_id, BLOCK, asha, "Blocked", at(1, 2))
    await scene.run(ctx, at(2, 3))
    await scene.run(ctx, at(3, 3))
    asker.refuse = "stopped"  # the SIEM is stopped for D3 and D4
    scene.skip_readings(at(5, 12))
    await scene.run(ctx, at(4, 3), live=False)
    await scene.run(ctx, at(5, 3), live=False)
    asker.refuse = None
    await scene.run(ctx, at(6, 3))
    await scene.run(ctx, at(7, 3))
    views = await scene.views(case_id, at(7, 5), ctx)
    assert views[BLOCK].state == "reported_done"
    assert views[BLOCK].verdict is not None
    assert views[BLOCK].verdict.kind == "waiting"
    assert "cannot be vouched for" in views[BLOCK].detail  # a zero nobody could verify


async def test_a_suspected_case_gets_no_advice_until_a_person_confirms_it(
    scene: Scene, people: dict[str, Person]
) -> None:
    """ARGUS's own proposal is not a confirmed incident: no advice is given, recorded or
    asked for until it is confirmed."""
    asha: Actor = people["asha"].actor()
    inv = await scene.investigation(H1, [at(0, 9)])
    async with scene.owner.begin() as conn:
        assessment = (
            await conn.execute(
                text(
                    "INSERT INTO assessments (investigation_id, version, pack, dossier_hash,"
                    " view_hash, assessor, run_after, status, outcome) VALUES (:i, 1, 'p',"
                    " repeat('a', 64), repeat('b', 64), 'agent', now(), 'proposed',"
                    " 'true_positive') RETURNING id"
                ),
                {"i": inv},
            )
        ).scalar_one()
    async with scene.runtime.begin() as conn:
        applied = await CaseService(conn, at(0, 10)).open(
            Actor.argus("opener"),
            Open("Proposed beacon", "medium", "proposal", (Member(inv, "proposal"),),
                 suspected=True, cause_assessment_id=assessment),
        )  # fmt: skip
    case_id = applied.case.id
    assert applied.case.state == "suspected"
    assert await scene.views(case_id, at(0, 11)) == {}
    async with scene.runtime.begin() as conn:
        with pytest.raises(ActionRefused) as caught:
            await store.recommend(conn, case_id, at(0, 11))
    assert caught.value.code == "conflict"
    assert "this one is suspected" in caught.value.message
    async with scene.runtime.begin() as conn:
        with pytest.raises(ActionRefused) as caught:
            await store.request(conn, case_id, ISOLATE, asha, at(0, 12))
    assert caught.value.code == "conflict"
    async with scene.runtime.begin() as conn:
        with pytest.raises(ActionRefused) as caught:
            await store.request(conn, uuid.uuid4(), ISOLATE, asha, at(0, 12))
    assert caught.value.code == "not_found"
    assert await scene.stored(case_id) == {}


async def test_a_person_without_the_right_cannot_record_what_was_done(
    scene: Scene, people: dict[str, Person]
) -> None:
    case_id, _ = await scene.beacon_case(people["asha"], at(0, 10))
    viewer = Actor.person(people["ravi"].user_id, frozenset({"view"}), via="test")
    async with scene.runtime.begin() as conn:
        with pytest.raises(ActionRefused) as caught:
            await store.report_done(conn, case_id, ISOLATE, viewer, "I did", at(1, 9))
    assert caught.value.code == "forbidden"
    async with scene.runtime.begin() as conn:
        with pytest.raises(ActionRefused) as caught:
            await store.request(conn, case_id, ISOLATE, Actor.argus("responder"), at(1, 9))
    assert caught.value.code == "forbidden"  # ARGUS does not attest for a person
    async with scene.runtime.begin() as conn:
        with pytest.raises(ActionRefused) as caught:
            await store.request(conn, case_id, "c2_beacon.nope", people["asha"].actor(), at(1, 9))
    assert caught.value.code == "invalid"
    async with scene.runtime.begin() as conn:
        with pytest.raises(ActionRefused) as caught:  # not one the case is advised
            await store.request(
                conn, case_id, "brute_force.block_source", people["asha"].actor(), at(1, 9)
            )
    assert caught.value.code == "conflict"
    assert await scene.stored(case_id) == {}
