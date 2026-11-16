"""``/welcome`` (D-327): a person opens their one-time link, sets a password (twice, 10 to 256
characters) and signs in with it; the link works once; a page without a link says so."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web import auth
from tests.integration.web.test_user_routes import client, signs_in

pytestmark = pytest.mark.integration
PASSWORD = "my own new password"
CONFIG = Path(__file__).resolve().parents[3] / "config" / "argus.yaml"


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


async def test_a_rerun_of_the_install_gives_an_unused_first_link_a_new_one(
    migrated_engine: AsyncEngine, test_database: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``./install.sh`` again after the 72 hours: the first administrator, still without a
    password, gets a new link (the old one ends) instead of "sign in" that nobody can."""
    import asyncio

    from argus.install import run
    from argus.install.answers import InitError

    monkeypatch.setenv("ARGUS_DATABASE__NAME", test_database)
    config = CONFIG
    first = await asyncio.to_thread(run._welcome, config, "admin")
    assert await asyncio.to_thread(run._people, config) == 0  # invited, never signed in
    second = await asyncio.to_thread(run._welcome, config, "admin")
    async with migrated_engine.connect() as conn:
        rows = (await conn.execute(text(
            "SELECT l.token_hash, l.used_at IS NULL AS open FROM user_links l JOIN users u"
            " ON u.id = l.user_id WHERE u.username = 'admin'"))).all()  # fmt: skip
        assert await conn.scalar(text("SELECT count(*) FROM users")) == 1
    assert {(r.token_hash, r.open) for r in rows} == {
        (auth.token_hash(first), False), (auth.token_hash(second), True)}  # fmt: skip
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE users SET password_hash = :h WHERE username = 'admin'"),
                           {"h": auth.hash_password(PASSWORD)})  # fmt: skip
    assert await asyncio.to_thread(run._people, config) == 1
    with pytest.raises(InitError, match="already has a password"):
        await asyncio.to_thread(run._welcome, config, "admin")
