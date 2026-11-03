"""An exposed ``.env`` file and a brute-force case through the responder (Q-H2), with the
verifiers that need no proxy: the web server's stored answers, and ARGUS's own alerts."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.model import Actor
from argus.responder import store
from tests.integration.cases.conftest import Person
from tests.integration.responder.kit import ENV, GIT, Scene, at, context

pytestmark = pytest.mark.integration

REMOVE, ROTATE = "exposed_file.remove_file", "exposed_file.rotate_secrets"
BLOCK, CHECK = "brute_force.block_source", "brute_force.check_accounts"


@pytest.fixture
def scene(migrated_engine: AsyncEngine, app_engine: AsyncEngine) -> Scene:
    return Scene(migrated_engine, app_engine)


async def test_an_exposed_env_file_is_advised_from_the_stored_answer_that_served_it(
    scene: Scene, people: dict[str, Person]
) -> None:
    case_id, _ = await scene.exposed_env_case(people["asha"], at(0, 12))
    views = await scene.views(case_id, at(0, 13))
    assert list(views) == [REMOVE, ROTATE]
    assert {v.family for v in views.values()} == {"exposed_file"}
    assert views[REMOVE].owner_name == "Website owner"
    assert views[REMOVE].verifier == "web.path_outcomes"
    assert views[ROTATE].verifier == "none"
    assert "Take" not in views[REMOVE].say  # plain words, no commands
    assert "http" not in views[REMOVE].say


async def test_removal_is_verified_only_by_a_logged_refusal_after_it(
    scene: Scene, people: dict[str, Person]
) -> None:
    asha: Actor = people["asha"].actor()
    case_id, inv = await scene.exposed_env_case(people["asha"], at(0, 12))
    await scene.do(case_id, at(0, 13))
    async with scene.runtime.begin() as conn:
        await store.report_done(
            conn, case_id, REMOVE, asha, "Deleted .env from the web root", at(1, 9)
        )
        await store.report_done(
            conn, case_id, ROTATE, asha, "Changed the database password", at(1, 9)
        )
    # nothing was asked after the removal yet: waiting, not "removed"
    views = await scene.views(case_id, at(1, 12))
    assert views[REMOVE].state == "reported_done"
    assert "no check of the web server's answers was made after the action" in views[REMOVE].detail
    # a check after it that logged no request at all proves nothing (a zero is never "gone")
    await scene.web_answer(inv, [ENV, GIT], {}, start=at(1, 10), asked=at(1, 12))
    views = await scene.views(case_id, at(1, 13))
    assert views[REMOVE].state == "reported_done"
    assert "no logged refusal" in views[REMOVE].detail
    # a check whose window began before the removal does not count either
    await scene.web_answer(inv, [ENV, GIT], {ENV: (2, None)}, start=at(1, 8), asked=at(1, 12, 5))
    assert (await scene.views(case_id, at(1, 13)))[REMOVE].state == "reported_done"
    # the site refused it after the removal: verified
    await scene.web_answer(
        inv, [ENV, GIT], {ENV: (4, None), GIT: (1, None)}, start=at(1, 10), asked=at(1, 14)
    )
    views = await scene.views(case_id, at(1, 15))
    assert views[REMOVE].state == "verified"
    assert "the site refused every path that was served" in views[REMOVE].detail
    assert (await scene.do(case_id, at(1, 15)))[1] == [(REMOVE, "verified")]
    # a person's word about secrets cannot be verified in Phase 3: it stays reported done
    assert views[ROTATE].state == "reported_done"
    assert views[ROTATE].detail.endswith(
        "Not verifiable in Phase 3: ARGUS cannot see whether a secret was changed."
    )
    assert (await scene.stored(case_id))[ROTATE].state == "reported_done"
    # served again: verified -> not verified, with the check that saw it
    await scene.web_answer(
        inv, [ENV, GIT], {ENV: (3, 1523), GIT: (1, None)}, start=at(1, 15), asked=at(1, 17)
    )
    assert (await scene.do(case_id, at(1, 18)))[1] == [(REMOVE, "not_verified")]
    row = (await scene.stored(case_id))[REMOVE]
    assert (row.state, row.verdict, row.last_beat) == (
        "not_verified",
        "still being served",
        at(1, 17),
    )
    views = await scene.views(case_id, at(1, 19))
    assert "Not verified: still being served, last seen by the check of 10:30 PM IST" in (
        views[REMOVE].detail
    )


async def test_brute_force_is_advised_and_verified_on_the_cases_own_alerts(
    scene: Scene, people: dict[str, Person]
) -> None:
    asha: Actor = people["asha"].actor()
    case_id, inv = await scene.brute_force_case(people["asha"], at(0, 12))
    views = await scene.views(case_id, at(0, 13))
    assert list(views) == [BLOCK, CHECK]
    assert views[BLOCK].verifier == "alerts"
    assert views[CHECK].verifier == "none"
    await scene.do(case_id, at(0, 13))
    async with scene.runtime.begin() as conn:
        await store.report_done(conn, case_id, BLOCK, asha, "Blocked the address", at(1, 9))
    ctx = context(None)  # ARGUS's own alerts only
    await scene.add_alert(inv, at(2, 5))  # the guessing went on after the block
    await scene.run(ctx, at(3, 3))
    views = await scene.views(case_id, at(3, 4))
    assert views[BLOCK].state == "not_verified"
    assert "Not verified: still raising alerts, last alert 10:30 AM IST on 16 Oct 2026." in (
        views[BLOCK].detail
    )
    assert (await scene.do(case_id, at(3, 4)))[1] == [(BLOCK, "not_verified")]


async def test_brute_force_goes_quiet_only_after_three_whole_days_of_covered_alerts(
    scene: Scene, people: dict[str, Person]
) -> None:
    asha: Actor = people["asha"].actor()
    case_id, _ = await scene.brute_force_case(people["asha"], at(0, 12))
    await scene.do(case_id, at(0, 13))
    async with scene.runtime.begin() as conn:
        await store.report_done(conn, case_id, BLOCK, asha, "Blocked the address", at(1, 9))
    ctx = context(None)
    for n in range(2, 5):
        await scene.run(ctx, at(n, 3))
    assert (await scene.views(case_id, at(4, 4), ctx))[BLOCK].state == "reported_done"  # D2, D3
    await scene.run(ctx, at(5, 3))
    views = await scene.views(case_id, at(5, 4), ctx)
    assert views[BLOCK].state == "verified"
    assert "alerts only" in views[BLOCK].detail
    # without the watch's settings (a page's default) nothing can be vouched for
    blind = await scene.views(case_id, at(5, 4))
    assert blind[BLOCK].state == "reported_done"
    assert "settings are not available here" in blind[BLOCK].detail
    # a day the collector did not provably see is not quiet: coverage unknown
    other, _ = await scene.brute_force_case(people["asha"], at(0, 12))
    await scene.do(other, at(0, 13))
    async with scene.runtime.begin() as conn:
        await store.report_done(conn, other, BLOCK, asha, "Blocked the address", at(1, 9))
    await scene.gap(at(3, 0), at(3, 23))
    await scene.run(ctx, at(5, 3))
    assert (await scene.views(other, at(5, 4), ctx))[BLOCK].state == "reported_done"
