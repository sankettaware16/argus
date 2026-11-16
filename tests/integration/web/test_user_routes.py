"""``/api/v1/admin/users`` (P4-H, D-327) on the web's own login: an administrator who confirmed
their password makes an account and gets a one-time link, changes what an account may do,
switches one off; the database functions check the administrator's session themselves, so the
web's login alone makes no account and sets no password; a link sets a password once."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web import auth
from argus.web.app import create_app
from tests.integration.web.conftest import BASE, PASSWORD, SAME_ORIGIN
from tests.integration.web.test_admin_routes import admin
from tests.integration.web.test_routes_declared import signed

pytestmark = pytest.mark.integration
V1 = "/api/v1/admin/users"
NEW_PASSWORD = "a new long password 42"


def client(engine: AsyncEngine) -> httpx.AsyncClient:
    """The app on the real clock: the database's own checks read the database's clock."""
    app = create_app(engine)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE,
                             headers=SAME_ORIGIN)  # fmt: skip


async def step_up(seeded: AsyncEngine, who: str = "asha") -> None:
    async with seeded.begin() as conn:
        sql = "UPDATE user_sessions SET stepped_up_at = now() WHERE user_id = (SELECT id FROM users"
        await conn.execute(text(sql + " WHERE username = :u)"), {"u": who})


@pytest.fixture(autouse=True)
async def vera(seeded: AsyncEngine) -> None:
    async with seeded.begin() as conn:
        await auth.add_user(conn, "vera", "Vera", PASSWORD)


async def run(engine: AsyncEngine, sql: str, params: dict[str, object]) -> None:
    async with engine.begin() as conn:
        await conn.execute(text(sql), params)


async def use_link(engine: AsyncEngine, token: str, password: str) -> int:
    async with engine.begin() as conn:
        found = await conn.scalar(text("SELECT argus_link_use(:t, :h)"),
                                  {"t": token, "h": auth.hash_password(password)})  # fmt: skip
        return int(found)


async def signs_in(engine: AsyncEngine, username: str, password: str) -> bool:
    async with engine.connect() as conn:
        return (await auth.check_password(conn, username, password)).user_id is not None


async def test_an_account_is_made_with_a_link_its_person_uses_once(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    await admin(seeded)
    async with client(web_engine) as http:
        csrf = await signed(http, "asha")
        head = {"X-CSRF-Token": csrf}
        body = {"username": "ravi.ta", "display_name": "Ravi (TA)", "role": "analyst"}
        early = await http.post(V1, json=body, headers=head)
        assert (early.status_code, early.json()["code"]) == (403, "step_up_required")
        await step_up(seeded)
        made = await http.post(V1, json=body, headers=head)
        assert made.status_code == 201, made.text
        out = made.json()
        assert out["user"]["role"] == "analyst"
        assert "manage_cases" in out["user"]["capabilities"]
        assert out["user"]["link_open"] is True
        token = out["link"].removeprefix("/welcome?token=")
        again = await http.post(V1, json=body, headers=head)
        assert again.status_code == 409
        listed = (await http.get(V1)).json()
        assert {r["key"] for r in listed["roles"]} == {"viewer", "analyst", "lead", "admin"}
        assert "ravi.ta" in {u["username"] for u in listed["users"]}
    assert not (await signs_in(seeded, "ravi.ta", "!"))
    assert await use_link(web_engine, token, NEW_PASSWORD) == out["user"]["id"]
    assert await signs_in(seeded, "ravi.ta", NEW_PASSWORD)
    with pytest.raises(DBAPIError, match="used, ended or never made"):
        await use_link(web_engine, token, "another one 1234")


async def test_capabilities_change_and_an_administrator_keeps_their_own(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    await admin(seeded)
    async with seeded.connect() as conn:
        vera = await conn.scalar(text("SELECT id FROM users WHERE username = 'vera'"))
        asha = await conn.scalar(text("SELECT id FROM users WHERE username = 'asha'"))
    async with client(web_engine) as http:
        head = {"X-CSRF-Token": await signed(http, "asha")}
        await step_up(seeded)
        changed = await http.put(f"{V1}/{vera}/capabilities", headers=head,
                                 json={"capabilities": ["approve"]})  # fmt: skip
        assert changed.status_code == 200, changed.text
        assert changed.json()["capabilities"] == ["view", "manage_cases", "approve"]
        assert changed.json()["role"] == "custom"
        mine = await http.put(f"{V1}/{asha}/capabilities", headers=head, json={"role": "viewer"})
        assert (mine.status_code, "own admin" in mine.json()["detail"]) == (409, True)
        both = await http.put(f"{V1}/{vera}/capabilities", headers=head,
                              json={"role": "viewer", "capabilities": ["view"]})  # fmt: skip
        assert both.status_code == 422


async def test_switching_off_ends_every_session_and_never_ones_own(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    await admin(seeded)
    async with seeded.connect() as conn:
        vera = await conn.scalar(text("SELECT id FROM users WHERE username = 'vera'"))
        asha = await conn.scalar(text("SELECT id FROM users WHERE username = 'asha'"))
    async with client(web_engine) as other:
        await signed(other, "vera")
        async with client(web_engine) as http:
            head = {"X-CSRF-Token": await signed(http, "asha")}
            await step_up(seeded)
            off = await http.put(f"{V1}/{vera}/access", headers=head, json={"disabled": True})
            assert (off.status_code, off.json()["disabled"], off.json()["open_sessions"]) == (
                200, True, 0)  # fmt: skip
            assert (await other.get("/api/v1/session")).status_code == 401
            self_off = await http.put(f"{V1}/{asha}/access", headers=head, json={"disabled": True})
            assert self_off.status_code == 409


async def test_the_web_login_alone_makes_no_account_and_sets_no_password(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    for sql, params in (
        ("SELECT argus_user_create('no-session', 'mallory', 'M', '{admin}', :h, :e)",
         {"h": "0" * 64, "e": datetime.now(UTC) + timedelta(days=1)}),
        ("UPDATE users SET password_hash = 'x' WHERE username = 'asha'", {}),
        ("UPDATE users SET capabilities = '{admin}' WHERE username = 'vera'", {}),
        ("INSERT INTO user_links (token_hash, user_id, purpose, created_at, expires_at)"
         " SELECT repeat('a', 64), id, 'reset', now(), now() + interval '1 day' FROM users"
         " WHERE username = 'asha'", {}),
    ):  # fmt: skip
        with pytest.raises(DBAPIError):
            await run(web_engine, sql, params)
    async with client(web_engine) as http:  # a session that is not an administrator's
        await signed(http, "vera")
        token = http.cookies["argus_session"]
    later = datetime.now(UTC) + timedelta(days=1)
    create = "SELECT argus_user_create(:s, 'mallory', 'M', '{admin}', :h, :e)"
    with pytest.raises(DBAPIError, match="only an administrator"):
        await run(web_engine, create, {"s": token, "h": "0" * 64, "e": later})
