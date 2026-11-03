"""Q-E2's drills (plan §5 gate): the rollback to local mode, "Your access", the "not verified"
state, the login-failure alarm in ``argus doctor``, and the throttle's properties."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from datetime import timedelta

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import doctor
from argus.config.settings import Settings
from argus.web import throttle
from argus.web.app import create_app
from tests.integration.web.conftest import BASE, FAST, SAME_ORIGIN
from tests.integration.web.conftest import PASSWORD as LOCAL_PASSWORD
from tests.integration.web.elk_rig import Rig, make_rig
from tests.integration.web.test_session_contract import form_token
from tests.unit.web.fake_identity import ANALYST, PASSWORD, REVIEWER, FakeLane

pytestmark = pytest.mark.integration


@pytest.fixture
async def rig(seeded: AsyncEngine, web_engine: AsyncEngine) -> AsyncIterator[Rig]:
    made = await make_rig(web_engine, seeded)
    try:
        yield made
    finally:
        await made.aclose()


# --------------------------------------------------------------------------- the rollback


async def test_the_rollback_drill_back_to_local_mode_and_forward_again(
    rig: Rig, seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with (
        seeded.begin() as conn
    ):  # asha is linked; ravi is not; vera signs in through ELK only
        await conn.execute(text("UPDATE users SET elk_username = 'Asha.Elk', realm = 'native'"
                                " WHERE username = 'asha'"))  # fmt: skip
    rig.lane.add("Asha.Elk")
    rig.lane.add("vera.elk")
    elk_asha, _ = await rig.signed_in("Asha.Elk")
    elk_vera, _ = await rig.signed_in("vera.elk")
    hash_before = await rig.scalar("SELECT password_hash FROM users WHERE username = 'asha'")
    assert (
        hash_before is not None
    )  # each local hash is kept until the ELK sign-in worked, and after

    # the one gate: web.elk_signin off, the app started again
    local = create_app(web_engine, FAST, clock=rig.clock)
    transport = httpx.ASGITransport(app=local, client=("127.0.0.1", 51000))  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url=BASE, headers=SAME_ORIGIN) as http:
        for cookie in elk_asha.cookies.jar:  # an ELK session is no session in local mode
            http.cookies.set(cookie.name, cookie.value)
        assert (await http.get("/api/v1/session")).status_code == 401
        http.cookies.clear()
        # linked and local accounts sign in with their local passwords again
        form = await http.get("/signin")
        got = await http.post("/signin", data={"username": "asha", "password": LOCAL_PASSWORD,
                                               "signin_token": form_token(form.text)})  # fmt: skip
        assert got.status_code == 303
        assert (await http.get("/api/v1/session")).json()["mode"] == "local"
        # an ELK-only account has no local password: it cannot sign in locally, whatever it types
        for secret in (PASSWORD, LOCAL_PASSWORD, ""):
            other = await http.post("/api/login", json={"username": "vera.elk",
                                                       "password": secret or "x" * 10})  # fmt: skip
            assert other.status_code == 401
    assert (
        await rig.scalar("SELECT password_hash FROM users WHERE username = 'asha'") == hash_before
    )
    # forward again: the ELK app still has its accounts
    assert elk_vera is not None
    again = rig.browser()
    assert (await rig.sign_in(again, "vera.elk")).status_code == 303
    assert (await rig.sign_in(rig.browser(), "Asha.Elk")).status_code == 303


async def test_local_mode_is_the_default_and_asks_elk_nothing(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    from argus.config.settings import WebSettings

    assert WebSettings().elk_signin is False
    assert Settings().web.elk_signin is False
    lane = FakeLane()
    lane.add("asha")
    app = create_app(web_engine, FAST, lane=lane)  # a lane given, ELK sign-in off: unused
    assert app.state.elk is None
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=BASE, headers=SAME_ORIGIN) as http:
        made = await http.post("/api/login", json={"username": "asha", "password": LOCAL_PASSWORD})
        assert made.status_code == 200
    assert lane.calls == []


def test_elk_sign_in_cannot_start_without_what_it_needs() -> None:
    from pydantic import ValidationError

    from argus.config.settings import WebSettings

    for kw, message in (
        ({}, "needs web.secret_file"),
        ({"secret_file": "/x/secret"}, "database_role: api"),
        ({"secret_file": "/x/secret", "database_role": "api", "host": "0.0.0.0"}, "TLS"),  # noqa: S104
    ):
        with pytest.raises(ValidationError, match=message):
            WebSettings(elk_signin=True, **kw)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- Your access


async def test_your_access_says_what_you_may_and_what_to_ask_for(rig: Rig) -> None:
    http, _ = await rig.signed_in("asha.elk", capabilities=REVIEWER)
    page = (await http.get("/access")).text
    assert "Your access" in page
    assert "your own ELK account" in page
    assert "asha.elk" in page
    assert "checked your access in ELK" in page
    assert "your ELK account needs Kibana" in page  # what is missing, in words
    assert "approver" in page  # how to get approve
    rig.clock.advance(minutes=3)
    assert "3 minutes ago" in (await http.get("/access")).text


async def test_your_access_is_there_for_a_person_without_access_and_for_local_accounts(
    rig: Rig, web_engine: AsyncEngine
) -> None:
    http, _ = await rig.signed_in("asha.elk")
    rig.lane.accounts["asha.elk"].capabilities = frozenset()
    rig.clock.advance(minutes=6)
    await http.get("/api/investigations")
    await rig.settle()
    assert (await http.get("/access")).status_code in (303, 401)  # ended: back to sign in
    local = create_app(web_engine, FAST, clock=rig.clock)
    transport = httpx.ASGITransport(app=local, client=("127.0.0.1", 51000))  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url=BASE, headers=SAME_ORIGIN) as lo:
        made = await lo.post("/api/login", json={"username": "asha", "password": LOCAL_PASSWORD})
        assert made.status_code == 200
        page = (await lo.get("/access")).text
        assert "a local ARGUS account" in page
        assert "argus user grant" in page


async def test_not_verified_says_so_on_every_page_and_in_your_access(rig: Rig) -> None:
    http, _ = await rig.signed_in("asha.elk")
    rig.lane.down = "unreachable"
    rig.clock.advance(minutes=6)
    await http.get("/api/investigations")
    await rig.settle()
    for path in ("/", "/rules", "/access"):
        assert "cannot confirm your access in ELK" in (await http.get(path)).text, path
    access = (await http.get("/access")).text
    assert "not sent to Kibana" in access
    assert "approvals" in access
    rig.lane.down = None
    rig.clock.advance(minutes=6)
    await http.get("/api/investigations")
    await rig.settle()
    assert "cannot confirm your access" not in (await http.get("/")).text


async def test_the_page_of_an_admin_account_says_it_keeps_no_copy(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    rig = await make_rig(web_engine, seeded)
    try:
        rig.lane.admin_accounts_allowed = True
        http, _ = await rig.signed_in("root.like", admin=True, capabilities=ANALYST)
        assert "keeps no copy of your password" in (await http.get("/access")).text
    finally:
        await rig.aclose()


# --------------------------------------------------------------------------- the alarm


async def test_the_login_failure_alarm_shows_in_doctor(rig: Rig, seeded: AsyncEngine) -> None:
    settings_ = Settings()
    quiet = await doctor.signin_check(seeded, settings_)
    assert (quiet.ok, "no alarm" in quiet.detail) == (True, True)
    for client in range(4):
        spray = rig.browser(f"10.5.0.{client}")
        for k in range(15):
            await rig.sign_in(spray, f"guess{client}-{k}", "a wrong password")
    loud = await doctor.signin_check(seeded, settings_)
    assert not loud.ok
    assert "ALARM: 60 refused sign-in checks within an hour" in loud.detail


# --------------------------------------------------------------------------- properties


@given(st.lists(st.sampled_from(["wrong", "down", "no_access", "forbidden", "right"]),
                min_size=1, max_size=14))  # fmt: skip
@settings(
    max_examples=25, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
async def test_only_elks_refusals_count_and_a_locked_name_asks_nobody(
    seeded: AsyncEngine, web_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch,
    events: list[str],
) -> None:  # fmt: skip
    """Whatever mix of wrong passwords, outages and ARGUS's own refusals comes in one after
    another: the counted refusals are exactly ELK's (a wrong password or a 403) up to the lock,
    every attempt after the lock asks ELK nothing, and a right password signs in only while
    the name is not locked."""
    import uuid

    # the examples share one database: the hour's spray limit is the other test's, not this one's
    monkeypatch.setattr(throttle, "SPRAY_LIMIT", 10**6)
    suffix = uuid.uuid4().hex[:8]
    name = f"prop.{suffix}"
    rig = await make_rig(web_engine, seeded)
    try:
        lane = rig.lane
        lane.add(name)
        http = rig.browser(f"10.7.{int(suffix[:2], 16)}.{int(suffix[2:4], 16)}")
        refusals, requests, signed = 0, 0, 0
        has_device = False
        for event in events:
            lane.down = "unreachable" if event == "down" else None
            lane.accounts[name].capabilities = REVIEWER if event != "no_access" else frozenset()
            lane.accounts[name].forbidden = event == "forbidden"
            password = PASSWORD if event in ("right", "down", "no_access", "forbidden") else "no"
            if event == "wrong":
                password = "a wrong password"
            locked = refusals >= 5 and not has_device
            http.cookies.delete("argus_session")  # signed out; the device cookie stays
            got = await rig.sign_in(http, name, password)
            if locked:
                assert got.status_code == 429
                continue
            requests += 1
            if event in ("wrong", "forbidden"):
                refusals += 1
                assert got.status_code == 401
            elif event == "right":
                signed += 1
                has_device = True  # this browser signed in well: a device cookie passes the lock
                assert got.status_code == 303
        assert lane.requests() == requests
        key = rig.elk.custody.name_hmac(name)
        stored = await rig.scalar(
            "SELECT count(*) FROM audit_events WHERE details->>'name_hmac' = :k"
            " AND details->>'counted' = 'true'", k=key)  # fmt: skip
        assert stored == refusals
    finally:
        await rig.aclose()


async def test_the_throttle_windows_end_exactly_when_they_are_over(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """±1 s at the database: a refusal counts for a name and a client for 15 minutes (not at
    exactly 15:00), and towards the hour's 60 for an hour."""
    from datetime import UTC, datetime

    start = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
    async with migrated_engine.begin() as conn:
        for key, client in (("k1", "10.0.0.1"), ("k2", "10.0.0.1")):  # one client, two names:
            await conn.execute(
                text("INSERT INTO audit_events (occurred_at, actor, action, outcome, details)"
                     " VALUES (:t, 'web', 'login', 'denied', CAST(:d AS jsonb))"),
                {"t": start,
                 "d": json.dumps({"name_hmac": key, "client": client, "counted": True})},
            )  # fmt: skip
        await conn.execute(  # a refusal that is not counted is not counted
            text("INSERT INTO audit_events (occurred_at, actor, action, outcome, details)"
                 " VALUES (:t, 'web', 'login', 'denied', CAST(:d AS jsonb))"),
            {"t": start, "d": json.dumps({"name_hmac": "k1", "client": "10.0.0.1",
                                          "counted": False})},
        )  # fmt: skip
    async with migrated_engine.connect() as conn:

        async def at(
            seconds: float, key: str = "k1", client: str = "10.0.0.1"
        ) -> throttle.Standing:
            return await throttle.read_standing(conn, key, client,
                                                now=start + timedelta(seconds=seconds))  # fmt: skip

        assert (await at(0)).name == 1
        assert (await at(15 * 60 - 1)).name == 1  # a second before the window ends
        assert (await at(15 * 60)).name == 0  # exactly over
        assert (await at(15 * 60 + 1)).name == 0
        assert (await at(15 * 60 - 1)).client == 2  # the client's count is of all names
        assert (await at(60 * 60 - 1)).hour == 2  # the hour still holds both
        assert (await at(60 * 60)).hour == 0
        assert (await at(60 * 60 + 1)).hour == 0
        assert (await at(10)).pair_age_s == pytest.approx(10.0)  # for the waits
        assert (await at(0, key="other")).name == 0
