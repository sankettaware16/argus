"""Q-E2: the route test in ELK mode (plan §5 Q-E2): every state-changing route, classic or v1,
has a capability; a view-only ELK session gets 403 on every one, with nothing written; nobody
signed in gets 401 (a form is sent to the sign-in page); the pages, the rules and "Your access"
read from the same declarations as in local mode."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web.capabilities import Capability
from argus.web.deps import Surface
from tests.integration.web.elk_rig import Rig, make_rig
from tests.integration.web.test_routes_declared import (
    CHANGES,
    EXPECTED,
    SESSION,
    concrete,
    declared,
    digest,
    fixture_ids,
    surface,
)
from tests.unit.web.fake_identity import REVIEWER, VIEWER

pytestmark = pytest.mark.integration


@pytest.fixture
async def rig(seeded: AsyncEngine, web_engine: AsyncEngine) -> AsyncIterator[Rig]:
    made = await make_rig(web_engine, seeded)
    try:
        yield made
    finally:
        await made.aclose()


async def test_the_routes_declare_the_same_in_elk_mode(rig: Rig) -> None:
    assert declared(rig.app) == EXPECTED  # one declaration per route, ELK mode or not


async def test_every_change_refuses_nobody_and_a_view_only_session(rig: Rig) -> None:
    ids = await fixture_ids(rig.owner)
    changes = {k: v for k, v in EXPECTED.items() if k[0] in CHANGES and v != "open"}
    assert len(changes) >= 15
    before = await digest(rig.owner)
    async with rig.browser() as nobody:  # no session
        for (method, path), _ in changes.items():
            got = await nobody.request(method, concrete(path, ids))
            if surface(path) is Surface.FORM:
                assert (got.status_code, got.headers["location"].startswith("/signin")) == (
                    303,
                    True,
                )
            else:
                assert got.status_code == 401, path
    http, csrf = await rig.signed_in("vera.elk", capabilities=VIEWER)  # view only
    for (method, path), need in changes.items():
        if need in (SESSION, Capability.VIEW):  # a person's own marks (seen, caught up) need view
            continue
        data = {"csrf_token": csrf} if surface(path) is Surface.FORM else None
        got = await http.request(method, concrete(path, ids), headers={"X-CSRF-Token": csrf},
                                 data=data)  # fmt: skip
        assert got.status_code == 403, path
        if surface(path) is Surface.V1:
            assert f"needs the {need.value} capability" in got.json()["detail"], path
    after = await digest(rig.owner)
    changed = {t for t in before if before[t] != after[t]}
    assert changed <= {"audit_events", "chain_heads", "user_devices", "user_sessions", "users",
                       "identity_checks", "siem_requests"}, changed  # fmt: skip
    assert await rig.scalar("SELECT count(*) FROM review_events") == 0
    assert rig.lane.requests("verify") == 0  # a refused person asks ELK nothing


async def test_every_read_needs_view_and_a_review_session_may_change_exactly_what_it_has(
    rig: Rig,
) -> None:
    ids = await fixture_ids(rig.owner)
    http, csrf = await rig.signed_in("rev.elk", capabilities=REVIEWER)
    for (method, path), need in EXPECTED.items():
        if method != "GET" or need == "open":
            continue
        got = await http.get(concrete(path, ids))
        assert got.status_code < 500, path
    # the reviewer's changes work, the case/approval/admin kind would not
    assert (await rig.review(http, csrf)).status_code == 201
    review_routes = {
        k for k, v in EXPECTED.items() if k[0] in CHANGES and v not in ("open", SESSION)
    }
    needs = {EXPECTED[k].value for k in review_routes}
    # Q-B3 added the case kind (manage_cases, approve, reopen): a reviewer holds none of them;
    # UI v2 a person's own marks (seen, caught up), which need only view
    assert needs <= {"review", "answer_gold", "manage_cases", "approve", "reopen", "view"}
    assert needs & {c.value for c in REVIEWER} == {"review", "view"}
