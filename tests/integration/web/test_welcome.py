"""``/welcome`` (D-327): a person opens their one-time link, sets a password (twice, 10 to 256
characters) and signs in with it; the link works once; a page without a link says so."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web import auth
from tests.integration.web.test_user_routes import client, signs_in

pytestmark = pytest.mark.integration
PASSWORD = "my own new password"


async def a_link(owner: AsyncEngine) -> str:
    token = secrets.token_urlsafe(32)
    now = datetime.now(UTC)
    async with owner.begin() as conn:
        user = await conn.scalar(text(
            "INSERT INTO users (username, display_name, password_hash, capabilities) VALUES"
            " ('nina', 'Nina', '!', '{view}') RETURNING id"))  # fmt: skip
        await conn.execute(
            text("INSERT INTO user_links (token_hash, user_id, purpose, created_at, expires_at)"
                 " VALUES (:h, :u, 'welcome', :t, :e)"),
            {"h": auth.token_hash(token), "u": user, "t": now, "e": now + timedelta(hours=1)},
        )  # fmt: skip
    return token


async def test_a_link_sets_a_password_once(
    seeded: AsyncEngine, migrated_engine: AsyncEngine, web_engine: AsyncEngine
) -> None:
    token = await a_link(migrated_engine)  # the owner: only the database's functions make one
    async with client(web_engine) as http:
        form = await http.get("/welcome", params={"token": token})
        assert form.status_code == 200
        assert "Set my password" in form.text
        assert "<script" not in form.text
        differ = await http.post("/welcome", data={"token": token, "password": PASSWORD,
                                                   "again": PASSWORD + "!"})  # fmt: skip
        assert (differ.status_code, "differ" in differ.text) == (422, True)
        short = await http.post("/welcome", data={"token": token, "password": "short",
                                                  "again": "short"})  # fmt: skip
        assert short.status_code == 422
        done = await http.post("/welcome", data={"token": token, "password": PASSWORD,
                                                 "again": PASSWORD})  # fmt: skip
        assert (done.status_code, done.headers["location"]) == (303, "/signin?why=password_set")
        notice = await http.get("/signin", params={"why": "password_set"})
        assert "Your password is set" in notice.text
        again = await http.post("/welcome", data={"token": token, "password": PASSWORD,
                                                  "again": PASSWORD})  # fmt: skip
        assert (again.status_code, "ask an ARGUS administrator" in again.text) == (410, True)
        bare = await http.get("/welcome")
        assert "needs the link" in bare.text
    assert await signs_in(seeded, "nina", PASSWORD)
