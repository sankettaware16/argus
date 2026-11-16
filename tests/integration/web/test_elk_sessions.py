"""Q-E2: ELK sessions kept in step with ELK (plan §7.2): pages from the snapshot and a background
re-check after 5 minutes; every change waits for a live check unless the snapshot is at most 30
seconds old; a 401 or 403 ends the session; what happens when ARGUS cannot verify (a verified
the SIEM outage, ARGUS's own refusal, three people failing at once); slow and partial answers."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from datetime import timedelta

import pytest
from fastapi import Depends
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.identity.lane import Kind
from argus.web import elk
from argus.web.capabilities import Capability
from argus.web.deps import Surface, need
from tests.integration.web.elk_rig import Rig, make_rig
from tests.unit.web.fake_identity import ANALYST, PASSWORD

pytestmark = pytest.mark.integration
C = Capability


@pytest.fixture
async def rig(seeded: AsyncEngine, web_engine: AsyncEngine) -> AsyncIterator[Rig]:
    made = await make_rig(web_engine, seeded)

    @made.app.post(
        "/api/v1/_test/write", dependencies=[Depends(need(C.MANAGE_CASES, Surface.V1, csrf=True))]
    )
    async def write() -> dict[str, bool]:  # a write-class change (cases, approvals, settings)
        return {"done": True}

    try:
        yield made
    finally:
        await made.aclose()


def rechecks(rig: Rig) -> int:
    return sum(1 for _r, _n, kind in rig.lane.calls if kind is Kind.RECHECK)


async def reviews(rig: Rig) -> int:
    return int(await rig.scalar("SELECT count(*) FROM review_events"))


async def write(rig: Rig, http: object, csrf: str) -> int:
    got = await http.post("/api/v1/_test/write", headers={"X-CSRF-Token": csrf})  # type: ignore[attr-defined]
    return int(got.status_code)


# --------------------------------------------------------------------------- reads


async def test_the_plans_numbers() -> None:
    assert timedelta(minutes=5) == elk.RECHECK_AFTER
    assert timedelta(seconds=30) == elk.CHANGE_FRESH
    assert timedelta(seconds=6) == elk.CHANGE_WAIT
    assert (
        timedelta(minutes=60), timedelta(minutes=15), timedelta(minutes=60),
    ) == (elk.OUTAGE_REVIEWS, elk.REFUSED_REVIEWS, elk.REFUSED_END)  # fmt: skip


@pytest.mark.parametrize(
    ("after", "due"), [(299, False), (299.999999, False), (300, True), (301, True)]
)
async def test_pages_come_from_the_snapshot_and_recheck_in_the_background_after_five_minutes(
    rig: Rig, after: float, due: bool
) -> None:
    http, _ = await rig.signed_in("asha.elk")
    rig.clock.advance(seconds=after)
    began = time.perf_counter()
    rig.lane.delay = 0.4  # a slow Elasticsearch: the page does not wait for it
    assert (await http.get("/api/investigations")).status_code == 200
    assert time.perf_counter() - began < 0.3
    await rig.settle()
    assert rechecks(rig) == (1 if due else 0)
    checked = await rig.scalar("SELECT checked_at FROM user_sessions")
    assert (checked == rig.clock.now) is due


@pytest.mark.parametrize("change", ["disabled", "password", "view", "forbidden"])
async def test_a_removal_in_elk_ends_reading_within_five_minutes_plus_one_read(
    rig: Rig, change: str
) -> None:
    http, _ = await rig.signed_in("asha.elk")
    account = rig.lane.accounts["asha.elk"]
    rig.clock.advance(minutes=1)
    if change == "disabled":
        account.enabled = False
    elif change == "password":
        account.password = "the password was changed 1"
    elif change == "view":
        account.capabilities = frozenset()
    else:
        account.forbidden = True
    rig.clock.advance(minutes=3)
    assert (await http.get("/api/investigations")).status_code == 200  # not known yet: +4 min
    await rig.settle()
    assert rechecks(rig) == 0
    rig.clock.advance(minutes=1)  # +5 min: this read is served, and the check it starts finds out
    assert (await http.get("/api/investigations")).status_code == 200
    await rig.settle()
    assert (await http.get("/api/investigations")).status_code == 401  # reading has ended
    row = await rig.one("SELECT ended_why, credential FROM user_sessions")
    assert tuple(row) == ("denied", None)  # and the credential is wiped
    assert await rig.scalar("SELECT count(*) FROM identity_checks WHERE outcome = 'denied'") == 1
    assert (
        await rig.scalar("SELECT count(*) FROM audit_events WHERE action = 'session.denied'") == 1
    )


async def test_a_signed_out_page_goes_to_the_sign_in_page(rig: Rig) -> None:
    http, _ = await rig.signed_in("asha.elk")
    rig.lane.accounts["asha.elk"].enabled = False
    rig.clock.advance(minutes=5)
    await http.get("/api/investigations")
    await rig.settle()
    page = await http.get("/access")
    assert (page.status_code, page.headers["location"]) == (303, "/signin?next=%2Faccess&why=ended")


# --------------------------------------------------------------------------- changes


@pytest.mark.parametrize(
    ("after", "checked"),
    [(29, False), (30, False), (30.000001, True), (31, True)],
)
async def test_a_change_waits_for_a_live_check_unless_the_snapshot_is_thirty_seconds_old(
    rig: Rig, after: float, checked: bool
) -> None:
    http, csrf = await rig.signed_in("asha.elk")
    rig.clock.advance(seconds=after)
    assert (await rig.review(http, csrf)).status_code == 201
    assert rechecks(rig) == (1 if checked else 0)
    row = await rig.one("SELECT kibana_ok FROM review_events")
    assert row.kibana_ok is True  # a live ELK check showed the alert-status privileges


@pytest.mark.parametrize("change", ["disabled", "password", "view"])
async def test_a_removal_in_elk_refuses_changes_after_thirty_seconds_and_writes_nothing(
    rig: Rig, change: str
) -> None:
    http, csrf = await rig.signed_in("asha.elk")
    account = rig.lane.accounts["asha.elk"]
    if change == "disabled":
        account.enabled = False
    elif change == "password":
        account.password = "the password was changed 1"
    else:
        account.capabilities = frozenset()
    rig.clock.advance(seconds=29)
    assert (await rig.review(http, csrf)).status_code == 201  # inside the 30 s: the snapshot
    rig.clock.advance(seconds=2)  # 31 s after the check
    refused = await rig.review(http, csrf)
    assert refused.status_code == 401
    assert await reviews(rig) == 1  # nothing more was written
    assert (await http.get("/api/investigations")).status_code == 401  # the session ended
    assert await rig.scalar("SELECT count(*) FROM identity_checks WHERE outcome = 'denied'") == 1


async def test_losing_the_review_privilege_refuses_reviews_and_keeps_reading(rig: Rig) -> None:
    http, csrf = await rig.signed_in("asha.elk", capabilities=ANALYST)
    rig.lane.accounts["asha.elk"].capabilities = frozenset({C.VIEW, C.SEE_LOGS})
    rig.clock.advance(seconds=31)
    refused = await rig.review(http, csrf)
    assert refused.status_code == 403
    assert "needs the review capability" in refused.json()["detail"]
    assert (await http.get("/api/investigations")).status_code == 200
    assert await rig.scalar("SELECT count(*) FROM audit_events WHERE action = 'access'") == 1


async def test_a_change_the_person_may_not_make_asks_elk_nothing(rig: Rig) -> None:
    http, csrf = await rig.signed_in("asha.elk")  # reviewer: no manage_cases
    rig.clock.advance(minutes=1)
    before = rig.lane.requests()
    assert await write(rig, http, csrf) == 403
    assert rig.lane.requests() == before


async def test_no_answer_in_six_seconds_fails_plainly(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    http, csrf = await rig.signed_in("asha.elk")
    monkeypatch.setattr(elk, "CHANGE_WAIT", timedelta(milliseconds=300))  # six seconds, scaled
    rig.lane.delay = 5.0
    rig.clock.advance(seconds=31)
    began = time.perf_counter()
    got = await rig.review(http, csrf)
    assert time.perf_counter() - began < 1.0
    assert got.status_code == 503
    assert "could not check your access in ELK" in got.json()["detail"]
    assert await reviews(rig) == 0
    rig.lane.delay = 0
    assert (await http.get("/api/investigations")).status_code == 200  # reading goes on


async def test_slow_identity_answers_create_no_session_and_pages_stay_fast(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    from argus.web import signin

    monkeypatch.setattr(signin, "SIGNIN_TOTAL", timedelta(milliseconds=300))
    rig.lane.add("slow.one")
    rig.lane.delay = 5.0
    began = time.perf_counter()
    got = await rig.sign_in(rig.browser(), "slow.one")
    assert time.perf_counter() - began < 1.0
    assert got.status_code == 503
    assert "could not ask ELK" in got.text
    assert await rig.scalar("SELECT count(*) FROM user_sessions") == 0
    assert await rig.scalar("SELECT count(*) FROM users WHERE elk_username = 'slow.one'") == 0
    assert (
        await rig.scalar("SELECT count(*) FROM audit_events WHERE details->>'counted' = 'true'")
        == 0
    )


async def test_many_sessions_checked_at_once_slowly_leave_pages_fast_and_the_pool_alone(
    rig: Rig,
) -> None:
    people = [await rig.signed_in(f"user{k}.elk") for k in range(8)]
    rig.lane.delay = 0.5
    rig.clock.advance(minutes=6)
    began = time.perf_counter()
    got = await asyncio.gather(*[http.get("/api/investigations") for http, _ in people])
    assert [g.status_code for g in got] == [200] * 8
    assert time.perf_counter() - began < 0.4  # the pages did not wait for any check
    await rig.settle()
    assert rig.lane.max_in_flight <= elk.CONCURRENT_CHECKS
    rig.lane.delay = 0
    rig.clock.advance(minutes=6)
    again = [await http.get("/api/investigations") for http, _ in people]
    assert [g.status_code for g in again] == [200] * 8


# --------------------------------------------------------------------------- cannot verify


async def test_in_an_outage_sessions_read_and_review_for_an_hour_and_nothing_goes_to_kibana(
    rig: Rig,
) -> None:
    http, csrf = await rig.signed_in("asha.elk", capabilities=ANALYST)
    rig.lane.down = "unreachable"
    rig.clock.advance(minutes=5)
    assert (await http.get("/api/investigations")).status_code == 200
    await rig.settle()
    row = await rig.one("SELECT unverified_since, unverified_why FROM user_sessions")
    assert (row.unverified_since, row.unverified_why) == (rig.clock.now, "outage")
    banner = (await http.get("/access")).text
    assert "cannot confirm your access in ELK" in banner
    # the app's banner reads the same from the session answer (Q-B4 review 2)
    session = (await http.get("/api/v1/session")).json()
    assert (session["mode"], session["break_glass"]) == ("elk", False)
    assert session["unverified"] == {
        "since": rig.clock.now.isoformat().replace("+00:00", "Z"),
        "why": "outage",
    }
    assert (await rig.review(http, csrf)).status_code == 201  # reviews continue ...
    assert (await rig.one("SELECT kibana_ok FROM review_events")).kibana_ok is False  # ... unsent
    assert await write(rig, http, csrf) == 503  # approvals and writes wait
    await rig.elapse(http, minutes=59, seconds=58)
    rig.clock.advance(seconds=1)
    assert (await rig.review(http, csrf)).status_code == 201
    rig.clock.advance(seconds=2)  # an hour after the first failed check
    refused = await rig.review(http, csrf)
    assert refused.status_code == 503
    assert (await http.get("/api/investigations")).status_code == 200  # reading goes on
    assert (
        await rig.scalar("SELECT count(*) FROM audit_events WHERE details->>'counted' = 'true'")
        == 0
    )
    # The SIEM is back: the next check renews everything
    rig.lane.down = None
    rig.clock.advance(minutes=1)
    await http.get("/api/investigations")
    await rig.settle()
    assert await rig.scalar("SELECT unverified_since FROM user_sessions") is None
    assert (await http.get("/api/v1/session")).json()["unverified"] is None  # the banner ends
    assert (await rig.review(http, csrf)).status_code == 201
    assert (await rig.one("SELECT kibana_ok FROM review_events ORDER BY id DESC")).kibana_ok is True


async def test_in_an_outage_nobody_new_signs_in_but_break_glass(rig: Rig) -> None:
    from argus.web import breakglass

    rig.lane.add("asha.elk")
    rig.lane.down = "unreachable"
    assert (await rig.sign_in(rig.browser(), "asha.elk")).status_code == 503
    async with rig.owner.begin() as conn:
        password, _ends = await breakglass.open_window(
            conn, reason="the SIEM is unreachable since last night", enabled_by="test", minutes=60,
            override=False,
        )  # fmt: skip
    http = rig.browser()
    got = await rig.sign_in(http, breakglass.NAME, password)
    assert got.status_code == 303
    session = (await http.get("/api/v1/session")).json()
    assert (session["mode"], session["break_glass"], session["unverified"]) == ("local", True, None)


async def test_after_arguss_own_refusal_a_session_reviews_for_fifteen_minutes_then_reads_then_ends(
    rig: Rig,
) -> None:
    http, csrf = await rig.signed_in("asha.elk")
    rig.lane.down = "stopped"  # the identity switch (ARGUS's own)
    rig.clock.advance(minutes=5)
    await http.get("/api/investigations")
    await rig.settle()
    assert await rig.scalar("SELECT unverified_why FROM user_sessions") == "refused"
    assert (await http.get("/api/v1/session")).json()["unverified"]["why"] == "refused"
    assert (await rig.review(http, csrf)).status_code == 201
    rig.clock.advance(minutes=14, seconds=59)
    assert (await rig.review(http, csrf)).status_code == 201
    rig.clock.advance(seconds=2)  # more than fifteen minutes
    assert (await rig.review(http, csrf)).status_code == 503
    assert (await http.get("/api/investigations")).status_code == 200
    await rig.elapse(http, minutes=44, seconds=56)  # just under an hour since it began
    rig.clock.advance(seconds=1)
    assert (await http.get("/api/investigations")).status_code == 200
    rig.clock.advance(seconds=3)
    assert (await http.get("/api/investigations")).status_code == 401  # ended after sixty minutes


async def test_the_security_index_down_ends_nothing_and_counts_nothing(rig: Rig) -> None:
    http, csrf = await rig.signed_in("asha.elk")
    rig.lane.add("late.one")
    rig.lane.down = "security_index"  # every native user would get a 401: the lane says so
    rig.clock.advance(minutes=6)
    await http.get("/api/investigations")
    await rig.settle()
    assert (await http.get("/api/investigations")).status_code == 200
    assert (await rig.sign_in(rig.browser(), "late.one")).status_code == 503
    assert await rig.scalar("SELECT count(*) FROM identity_checks WHERE outcome = 'denied'") == 0
    assert (
        await rig.scalar("SELECT count(*) FROM audit_events WHERE details->>'counted' = 'true'")
        == 0
    )
    assert csrf


async def test_three_people_failing_together_are_an_outage_not_three_revocations(rig: Rig) -> None:
    people = [await rig.signed_in(f"user{k}.elk") for k in range(3)]
    for name in ("user0.elk", "user1.elk", "user2.elk"):
        rig.lane.accounts[name].password = "everyone fails at once"  # ELK 401s for all three
    rig.clock.advance(minutes=6)
    for http, _ in people:
        await http.get("/api/investigations")
        await rig.settle()
    codes = [(await http.get("/api/investigations")).status_code for http, _ in people]
    assert codes == [401, 401, 200]  # two ended; the third was taken for an outage
    row = await rig.one("SELECT unverified_why FROM user_sessions s JOIN users u"
                        " ON u.id = s.user_id"
                        " WHERE u.elk_username = 'user2.elk'")  # fmt: skip
    assert row.unverified_why == "outage"
    assert await rig.scalar("SELECT count(*) FROM identity_checks WHERE outcome = 'denied'") == 2


async def test_a_session_whose_credential_cannot_be_opened_asks_for_a_new_sign_in(rig: Rig) -> None:
    http, csrf = await rig.signed_in("asha.elk")
    async with rig.owner.begin() as conn:
        await conn.execute(
            text("UPDATE user_sessions SET credential = :c"), {"c": b"\x01" + bytes(40)}
        )
    rig.clock.advance(seconds=31)
    assert (await rig.review(http, csrf)).status_code == 401
    assert await rig.scalar("SELECT ended_why FROM user_sessions") == "no_credential"


# --------------------------------------------------------------------------- the database's rule


async def test_the_database_will_not_let_an_unverified_or_emergency_session_approve(
    rig: Rig, migrated_engine: AsyncEngine
) -> None:
    http, _ = await rig.signed_in("asha.elk")
    token = http.cookies.get("argus_session")

    async def who() -> object:
        async with migrated_engine.connect() as conn:
            return await conn.scalar(text("SELECT argus_approval_session_user(:t)"), {"t": token})

    assert await who() is not None  # a verified ELK session is a person's
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE user_sessions SET unverified_since = now(),"
                                " unverified_why = 'outage'"))  # fmt: skip
    with pytest.raises(DBAPIError, match="no live session of a person"):
        await who()
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE user_sessions SET unverified_since = NULL"))
    assert await who() is not None
    async with migrated_engine.begin() as conn:  # owner: stands in for a break-glass or service row
        await conn.execute(
            text("UPDATE users SET kind = 'service' WHERE elk_username = 'asha.elk'")
        )
    with pytest.raises(DBAPIError, match="no live session of a person"):
        await who()


# --------------------------------------------------------------------------- the approvals' seam


async def test_the_identity_provider_for_approvals_checks_the_person_live(rig: Rig) -> None:
    """``argus.cases.identity.IdentityProvider`` for an ELK session (Q-B3 uses it): a live check
    with the kept credential; a revoked person is denied (their session ends, their approvals
    stop counting); an outage is "unavailable"; an admin account answers only from a step-up
    at most 30 s old; and the Kibana privileges come from the capabilities."""
    from argus.web.elk import ElkIdentityProvider

    http, _csrf = await rig.signed_in("asha.elk", capabilities=ANALYST)
    token = http.cookies.get("argus_session")
    assert token is not None
    user_id = await rig.scalar("SELECT id FROM users WHERE elk_username = 'asha.elk'")
    provider = ElkIdentityProvider(rig.elk, token)

    async def check(purpose: str = "approval") -> object:
        async with rig.engine.begin() as conn:
            return await provider.check(conn, user_id, purpose=purpose)  # type: ignore[arg-type]

    good = await check()
    assert (good.outcome, good.kind, good.provider) == ("ok", "person", "elk")  # type: ignore[attr-defined]
    assert good.kibana >= {"createCase", "updateCase", "createComment", "reopenCase"}  # type: ignore[attr-defined]
    assert "manage_cases" in good.capabilities  # type: ignore[attr-defined]
    assert good.argus_uid == rig.lane.accounts["asha.elk"].argus_uid  # type: ignore[attr-defined]
    assert rechecks(rig) == 1
    rig.lane.down = "unreachable"
    assert (await check()).outcome == "unavailable"  # type: ignore[attr-defined]
    rig.lane.down = None
    rig.lane.accounts["asha.elk"].enabled = False
    gone = await check()
    assert gone.outcome == "denied"  # type: ignore[attr-defined]
    assert await rig.scalar("SELECT ended_at IS NOT NULL FROM user_sessions") is True
    assert await rig.scalar("SELECT count(*) FROM identity_checks WHERE outcome = 'denied'") == 1
    other = ElkIdentityProvider(rig.elk, "not-a-token")  # no such session: nobody
    async with rig.engine.begin() as conn:
        assert (await other.check(conn, user_id, purpose="approval")).outcome == "denied"


async def test_an_admin_accounts_check_is_only_as_fresh_as_its_step_up(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    from argus.web.elk import ElkIdentityProvider

    rig = await make_rig(web_engine, seeded)
    try:
        rig.lane.admin_accounts_allowed = True
        http, csrf = await rig.signed_in("root.like", admin=True, capabilities=ANALYST)
        token = http.cookies.get("argus_session")
        user_id = await rig.scalar("SELECT id FROM users WHERE elk_username = 'root.like'")
        provider = ElkIdentityProvider(rig.elk, token)

        async def outcome() -> str:
            async with rig.engine.begin() as conn:
                return str((await provider.check(conn, user_id, purpose="approval")).outcome)

        assert await outcome() == "ok"  # inside 30 s of the sign-in
        rig.clock.advance(seconds=31)
        assert await outcome() == "unavailable"  # no copy of the password to ask with
        await http.post("/stepup", data={"password": PASSWORD, "csrf_token": csrf})
        assert await outcome() == "ok"
        assert rig.lane.requests("verify") == 1  # ELK was asked by the step-up only
    finally:
        await rig.aclose()
