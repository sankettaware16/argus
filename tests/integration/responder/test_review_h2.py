"""Independent review of Q-H2 (the responder), integration: each test fails on the build under
review."""

from __future__ import annotations

import json
import uuid
from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import watch
from argus.cases.model import Actor
from argus.responder import store
from argus.responder.machine import ActionRefused
from tests.integration.cases.conftest import Person
from tests.integration.responder.kit import C2, ENV, GIT, H1, H2, H3, FakeAsker, Scene, at, context

pytestmark = pytest.mark.integration

BLOCK = "c2_beacon.block_destination"
REMOVE = "exposed_file.remove_file"


@pytest.fixture
def scene(migrated_engine: AsyncEngine, app_engine: AsyncEngine) -> Scene:
    return Scene(migrated_engine, app_engine)


async def test_r6_verified_while_the_approved_finder_says_the_address_is_too_common(
    scene: Scene, people: dict[str, Person]
) -> None:
    """Q-C2's finder passes ``blocked=TOO_COMMON`` when the case's key is in 50 or more
    investigations (activity cannot be searched: never quiet). The responder's verdict does not
    pass it (and does not scan for unjoined investigations), so the same days are "verified"."""
    asha: Actor = people["asha"].actor()
    asker = FakeAsker()
    ctx = context(asker)
    asker.beacon(range(0, 1), [H1, H2, H3])
    case_id, _ = await scene.beacon_case(people["asha"], at(0, 10))
    await scene.do(case_id, at(0, 12))
    async with scene.runtime.begin() as conn:
        await store.report_done(conn, case_id, BLOCK, asha, "Blocked", at(1, 2))
    for n in range(2, 8):
        await scene.run(ctx, at(n, 3))
    assert (await scene.views(case_id, at(7, 5), ctx))[BLOCK].state == "verified"  # control
    for n in range(1, 51):  # the address turns up in 50 other investigations afterwards
        await scene.investigation(f"10.77.0.{n}", [at(6, 7)], entities=(("ip", C2),))
    window = await scene.finder_window(ctx, case_id, at(7, 5))
    assert (window.verified, window.reason) == (False, watch.TOO_COMMON)  # the approved rule
    views = await scene.views(case_id, at(7, 5), ctx)
    assert views[BLOCK].state != "verified"
    assert (await scene.do(case_id, at(7, 5), ctx))[1] == []


async def test_r7_fifty_one_stored_checks_after_the_removal_hide_the_newest(
    scene: Scene, people: dict[str, Person]
) -> None:
    """``_readings`` reads the OLDEST 50 answers asked after the report (ORDER BY asked_at ASC
    LIMIT 50), so a path served again by the 51st check is never seen and the removal is
    "verified"."""
    asha: Actor = people["asha"].actor()
    case_id, inv = await scene.exposed_env_case(people["asha"], at(0, 12))
    async with scene.runtime.begin() as conn:
        await store.report_done(conn, case_id, REMOVE, asha, "Deleted .env", at(1, 9))
    base = at(1, 10)
    for k in range(50):
        await scene.web_answer(
            inv, [ENV, GIT], {ENV: (4, None), GIT: (1, None)},
            start=at(1, 10), asked=base + timedelta(minutes=k),
        )  # fmt: skip
    await scene.web_answer(
        inv, [ENV, GIT], {ENV: (3, 1523), GIT: (2, None)}, start=at(2, 9), asked=at(2, 10)
    )  # served again
    view = (await scene.views(case_id, at(2, 11)))[REMOVE]
    assert view.state == "not_verified", view.detail


async def test_r8_a_malformed_stored_answer_takes_the_whole_advice_down(
    scene: Scene, people: dict[str, Person]
) -> None:
    """``paths.outcomes`` is given ``snapshot["aggregations"]`` unchecked: a stored answer whose
    aggregations are not an object raises AttributeError out of ``actions_for`` (every page and
    ``actions-sync`` of that case)."""
    case_id, _ = await scene.exposed_env_case(people["asha"], at(0, 12))
    async with scene.owner.begin() as conn:
        await conn.execute(
            text(
                "UPDATE evidence SET snapshot = CAST(:s AS jsonb)"
                " WHERE template = 'web.path_outcomes'"
            ),
            {"s": json.dumps({"aggregations": [1]})},
        )
    assert "exposed_file.remove_file" not in await scene.views(case_id, at(0, 13))


async def _case(scene: Scene, people: dict[str, Person]) -> uuid.UUID:
    return (await scene.beacon_case(people["asha"], at(0, 10)))[0]


async def test_r9_the_web_login_can_date_a_report_in_the_future(
    scene: Scene, web_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """No CHECK or trigger bounds ``reported_at``: a report dated a century ahead is accepted
    and then no verdict of ARGUS can ever be recorded for it ("a verdict comes after the report
    it judges"), nor any newer report short of a later date."""
    case_id = await _case(scene, people)
    async with web_engine.begin() as conn:
        with pytest.raises(DBAPIError):
            await conn.execute(
                text(
                    "INSERT INTO case_actions (case_id, action, family, owner, catalogue_version,"
                    " state, reported_at, reported_by, attestation) VALUES (:c, 'x.y', 'x', 'o', 1,"
                    " 'reported_done', now() + interval '100 years', 'user:7', 'done')"
                ),
                {"c": case_id},
            )


async def test_r10_the_web_login_can_insert_a_requested_row_that_already_holds_a_report(
    scene: Scene, web_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """A ``requested`` row with report columns filled (the trigger's "only a new report changes
    who reported it" is checked on update only)."""
    case_id = await _case(scene, people)
    async with web_engine.begin() as conn:
        with pytest.raises(DBAPIError):
            await conn.execute(
                text(
                    "INSERT INTO case_actions (case_id, action, family, owner, catalogue_version,"
                    " state, requested_at, requested_by, reported_at, reported_by, attestation)"
                    " VALUES (:c, 'x.z', 'x', 'o', 1, 'requested', now(), 'user:7', now(),"
                    " 'user:7', 'done')"
                ),
                {"c": case_id},
            )


# --------------------------------------------------------------------------- the fixes' own tests


async def _reported_and_quiet(
    scene: Scene, people: dict[str, Person], ctx: Any
) -> tuple[uuid.UUID, Actor]:
    """A PS1Bot case whose block was reported at 2 AM on day 1 and has been quiet on days 2-4."""
    asha: Actor = people["asha"].actor()
    asker = ctx.asker
    asker.beacon(range(0, 1), [H1, H2, H3])
    case_id, _ = await scene.beacon_case(people["asha"], at(0, 10))
    await scene.do(case_id, at(0, 12))
    async with scene.runtime.begin() as conn:
        await store.report_done(conn, case_id, BLOCK, asha, "Blocked", at(1, 2))
    for n in range(2, 8):
        await scene.run(ctx, at(n, 3))
    return case_id, asha


async def test_r1_an_investigation_not_yet_joined_that_matches_is_activity_for_the_verdict(
    scene: Scene, people: dict[str, Person]
) -> None:
    """The verdict is the watch's own finder's: a matching investigation that joined no case is
    seen, as it is when the case is closed."""
    asker = FakeAsker()
    ctx = context(asker)
    case_id, _ = await _reported_and_quiet(scene, people, ctx)
    assert (await scene.views(case_id, at(7, 5), ctx))[BLOCK].state == "verified"  # control
    await scene.investigation("10.77.0.1", [at(6, 7)], entities=(("ip", C2),))
    window = await scene.finder_window(ctx, case_id, at(7, 5))
    assert not window.verified, window.reason
    views = await scene.views(case_id, at(7, 5), ctx)
    assert views[BLOCK].state == "reported_done"
    assert (await scene.do(case_id, at(7, 5), ctx))[1] == []


async def test_r1_without_the_watchs_settings_nothing_is_verified(
    scene: Scene, people: dict[str, Person]
) -> None:
    asker = FakeAsker()
    ctx = context(asker)
    case_id, _ = await _reported_and_quiet(scene, people, ctx)
    blind = (await scene.views(case_id, at(7, 5)))[BLOCK]
    assert blind.state == "reported_done"
    assert "cannot vouch" in blind.detail


async def test_r2_the_served_sighting_survives_sixty_later_checks(
    scene: Scene, people: dict[str, Person]
) -> None:
    """``served_paths`` read the newest 50 answers, so after 50 later checks the original
    "served" one fell out, the family stopped matching and the row waited for ever."""
    asha: Actor = people["asha"].actor()
    case_id, inv = await scene.exposed_env_case(people["asha"], at(0, 12))
    async with scene.runtime.begin() as conn:
        await store.report_done(conn, case_id, REMOVE, asha, "Deleted .env", at(1, 9))
    for k in range(60):
        await scene.web_answer(
            inv, [ENV, GIT], {ENV: (4, None), GIT: (1, None)},
            start=at(1, 10), asked=at(1, 10) + timedelta(minutes=k),
        )  # fmt: skip
    view = (await scene.views(case_id, at(2, 11)))[REMOVE]
    assert view.advised
    assert view.state == "verified", view.detail


async def test_r4_a_removal_is_not_verified_by_an_older_refusal_when_the_newest_check_serves_it(
    scene: Scene, people: dict[str, Person]
) -> None:
    asha: Actor = people["asha"].actor()
    case_id, inv = await scene.exposed_env_case(people["asha"], at(0, 12))
    async with scene.runtime.begin() as conn:
        await store.report_done(conn, case_id, REMOVE, asha, "Deleted .env", at(1, 9))
    await scene.web_answer(
        inv, [ENV, GIT], {ENV: (4, None), GIT: (1, None)}, start=at(1, 10), asked=at(1, 11)
    )
    assert (await scene.views(case_id, at(1, 12)))[REMOVE].state == "verified"
    await scene.web_answer(
        inv, [ENV, GIT], {ENV: (3, 1523), GIT: (2, None)}, start=at(2, 9), asked=at(2, 10)
    )
    assert (await scene.views(case_id, at(2, 11)))[REMOVE].state == "not_verified"


async def test_r10_a_verdict_made_on_an_older_report_does_not_land_on_a_newer_one(
    scene: Scene, people: dict[str, Person], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two refreshes and a person's re-report between them: the stale verdict is for the first
    report (the UPDATE names it), so it lands on nothing."""
    asker = FakeAsker()
    ctx = context(asker)
    case_id, asha = await _reported_and_quiet(scene, people, ctx)
    async with scene.runtime.connect() as conn:
        stale = await store.actions_for(conn, case_id, ctx=ctx, now=at(7, 5))
    assert [v.state for v in stale if v.action == BLOCK] == ["verified"]
    async with scene.owner.begin() as conn:  # the other refresh found it active again
        await conn.execute(
            text(
                "UPDATE case_actions SET state = 'not_verified', verdict_at = :t, verdict = 'v',"
                " last_beat = :t WHERE case_id = :c AND action = :a"
            ),
            {"t": at(7, 5), "c": case_id, "a": BLOCK},
        )
    async with scene.runtime.begin() as conn:  # and the person tried again
        await store.report_done(conn, case_id, BLOCK, asha, "Blocked it again", at(7, 6))

    async def old_views(*args: Any, **kw: Any) -> Any:
        return stale

    monkeypatch.setattr(store, "actions_for", old_views)
    async with scene.runtime.begin() as conn:
        assert await store.refresh(conn, case_id, at(7, 7), ctx=ctx) == []
    row = (await scene.stored(case_id))[BLOCK]
    assert (row.state, row.verdict) == ("reported_done", None)


async def test_r10_a_person_whose_insert_loses_the_race_gets_a_refusal_not_a_database_error(
    scene: Scene, people: dict[str, Person], monkeypatch: pytest.MonkeyPatch
) -> None:
    asha: Actor = people["asha"].actor()
    case_id, _ = await scene.beacon_case(people["asha"], at(0, 10))
    await scene.do(case_id, at(0, 12))  # the row is there, but this person's read missed it

    async def missed(*args: Any, **kw: Any) -> Any:
        return None

    monkeypatch.setattr(store, "_row", missed)
    async with scene.runtime.begin() as conn:
        with pytest.raises(ActionRefused) as caught:
            await store.request(conn, case_id, BLOCK, asha, at(1, 2))
    assert caught.value.code == "conflict"
    async with scene.runtime.begin() as conn:
        with pytest.raises(ActionRefused) as caught:
            await store.report_done(conn, case_id, BLOCK, asha, "Blocked", at(1, 2))
    assert caught.value.code == "conflict"
    assert (await scene.stored(case_id))[BLOCK].state == "recommended"


async def test_r11_a_verified_record_is_shown_as_not_re_checked_when_it_cannot_be_checked_now(
    scene: Scene, people: dict[str, Person]
) -> None:
    asker = FakeAsker()
    ctx = context(asker)
    case_id, _ = await _reported_and_quiet(scene, people, ctx)
    assert (await scene.do(case_id, at(7, 5), ctx))[1] == [(BLOCK, "verified")]
    before = (await scene.stored(case_id))[BLOCK]
    blind = (await scene.views(case_id, at(8, 5)))[BLOCK]  # a page that cannot ask the watch
    assert blind.state == "verified"  # the record stands
    assert "Verified on 21 Oct 2026 (IST), not re-checked since." in blind.detail
    assert (await scene.do(case_id, at(8, 5)))[1] == []  # and nothing is promoted or rewritten
    after = (await scene.stored(case_id))[BLOCK]
    assert (after.state, after.verdict) == (before.state, before.verdict)


async def test_r7_the_web_login_dates_a_report_within_ten_minutes_of_the_databases_clock(
    scene: Scene, web_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case_id = await _case(scene, people)
    insert = (
        "INSERT INTO case_actions (case_id, action, family, owner, catalogue_version, state,"
        " reported_at, reported_by, attestation) VALUES (:c, :a, 'x', 'o', 1, 'reported_done',"
        " now() {shift}, 'user:7', 'done')"
    )
    for n, shift in enumerate(("- interval '2 days'", "+ interval '11 minutes'",
                               "- interval '11 minutes'", "+ interval '1 day'")):  # fmt: skip
        async with web_engine.begin() as conn:
            with pytest.raises(DBAPIError, match="dated now"):
                await conn.execute(text(insert.format(shift=shift)), {"c": case_id, "a": f"x.r{n}"})
    for n, shift in enumerate(("", "- interval '9 minutes'", "+ interval '9 minutes'")):
        async with web_engine.begin() as conn:
            await conn.execute(text(insert.format(shift=shift)), {"c": case_id, "a": f"x.ok{n}"})
    # the same bound on a new report over an old row (an update)
    async with web_engine.begin() as conn:
        await conn.execute(
            text(insert.format(shift="")), {"c": case_id, "a": "x.up"}
        )  # a row the web can later report on again once ARGUS has judged it
    async with scene.owner.begin() as conn:
        await conn.execute(
            text(
                "UPDATE case_actions SET state = 'not_verified', verdict_at = now()"
                " + interval '1 second', verdict = 'v' WHERE action = 'x.up'"
            )
        )
    async with web_engine.begin() as conn:
        with pytest.raises(DBAPIError, match="dated now"):
            await conn.execute(
                text(
                    "UPDATE case_actions SET state = 'reported_done', reported_at = now() +"
                    " interval '5 days', reported_by = 'user:7', attestation = 'again'"
                    " WHERE action = 'x.up'"
                )
            )


async def test_r8_a_new_web_row_holds_only_its_own_states_columns(
    scene: Scene, web_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    case_id = await _case(scene, people)
    async with web_engine.begin() as conn:
        with pytest.raises(DBAPIError, match="only its own state"):
            await conn.execute(
                text(
                    "INSERT INTO case_actions (case_id, action, family, owner, catalogue_version,"
                    " state, requested_at, requested_by, reported_at, reported_by, attestation)"
                    " VALUES (:c, 'x.q', 'x', 'o', 1, 'reported_done', now(), 'user:7', now(),"
                    " 'user:7', 'done')"
                ),
                {"c": case_id},
            )
