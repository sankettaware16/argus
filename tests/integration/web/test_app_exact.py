"""The Inbox pages' R15 behaviour, exactly (mutation testing): pattern reviews (every refusal,
the counts, the note), the column choice (defaults, cookie), error messages."""

from __future__ import annotations

import hashlib
import re
import uuid
from typing import Any

import httpx
import pytest
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web.app import _columns_cookie
from tests.integration.context.test_generic import alert
from tests.integration.web.test_columns import headers
from tests.integration.web.test_r15 import (  # noqa: F401 - fixtures
    client,
    empty,
    investigate,
    saver,
    three_hosts,
)

pytestmark = pytest.mark.integration


def message(page: str) -> str:
    found = re.search(r'<p class="message" role="alert">(.*?)</p>', page)
    if found:
        return found.group(1)
    found = re.search(r"<main[^>]*>(.*?)</main>", page, re.S)
    return re.sub(r"<[^>]+>", " ", found.group(1) if found else page).split()[0:20].__str__()


def csrf_of(page: str) -> str:
    return page.split('name="csrf_token" value="')[1].split('"')[0]


async def test_pattern_reviews_exactly(empty: AsyncEngine, saver: AsyncPostgresSaver) -> None:  # noqa: F811
    await investigate(empty, saver, three_hosts())
    async with client(empty) as http:
        page = (await http.get("/patterns")).text
        items = [v.split('"')[0] for v in page.split('name="items" value="')[1:]]
        csrf = csrf_of(page)
        expired = await http.post("/patterns/review", data={"items": items, "csrf_token": "x"})
        assert expired.status_code == 403
        assert "The form expired; reload the page and try again." in expired.text
        guilty = {"items": items, "csrf_token": csrf, "outcome": "guilty"}
        odd = await http.post("/patterns/review", data=guilty)
        assert odd.status_code == 422
        assert "Unknown outcome." in odd.text
        undecided = await http.post("/patterns/review", data={"items": items, "csrf_token": csrf})
        assert undecided.status_code == 422
        assert "Choose an outcome for the group." in undecided.text
        for bad in (["nope"], [f"{uuid.uuid4()}"], [f"{uuid.uuid4()}:x"], ["x:1"]):
            form = {"items": bad, "csrf_token": csrf, "outcome": "benign_expected"}
            refused = await http.post("/patterns/review", data=form)
            assert refused.status_code == 422, bad
            assert "A malformed item." in refused.text
        unknown = {"items": [f"{uuid.uuid4()}:1"], "csrf_token": csrf,
                   "outcome": "benign_expected"}  # fmt: skip
        gone = await http.post("/patterns/review", data=unknown)
        assert gone.status_code == 200
        assert "0 reviewed. 1 changed since you looked and were left as they are." in gone.text
        first, *rest = items
        inv, version = first.split(":")[:2]
        stale_latest = f"{inv}:{version}:999"  # a review it never had: changed meanwhile
        one = await http.post("/patterns/review", data={"items": [stale_latest], "csrf_token": csrf,
                                                        "outcome": "benign_expected"})  # fmt: skip
        assert "0 reviewed. 1 changed" in one.text
        done = await http.post("/patterns/review", data={"items": [first, *rest],
                                                          "csrf_token": csrf,
                                                          "outcome": "benign_policy"})  # fmt: skip
        assert done.status_code == 200
        assert "3 reviewed." in done.text
        assert "changed since you looked" not in done.text
        assert "3 investigations" not in done.text  # the group is gone: all reviewed
    async with empty.connect() as conn:
        rows = (await conn.execute(text(
            "SELECT action, outcome, note FROM review_events ORDER BY id"))).all()  # fmt: skip
    assert [tuple(r) for r in rows] == [
        ("reviewed", "benign_policy", "Reviewed with its pattern.")
    ] * 3


async def test_patterns_and_glossary_need_a_login(
    empty: AsyncEngine,  # noqa: F811
    web_engine: AsyncEngine,
) -> None:
    from argus.web.app import create_app
    from tests.integration.web.conftest import BASE, SAME_ORIGIN, to_signin

    app = create_app(web_engine)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=BASE, headers=SAME_ORIGIN
    ) as http:
        for path in ("/patterns", "/glossary"):
            got = await http.get(path)
            assert (got.status_code, got.headers["location"]) == (303, to_signin(path))
        got = await http.post("/patterns/review", data={"items": ["x"]})
        assert (got.status_code, got.headers["location"]) == (303, to_signin("/patterns"))
    async with client(empty) as http:
        glossary = (await http.get("/glossary")).text
        assert "Distinct values" in glossary
        assert "{part}" not in glossary


async def test_columns_default_to_the_steps_fields_and_the_cookie_is_strict(
    empty: AsyncEngine,  # noqa: F811
    saver: AsyncPostgresSaver,  # noqa: F811
) -> None:
    note = "### Investigation Steps\n1. Check `source.ip` and `host.name`.\n2. See `nope.field`."
    await investigate(empty, saver, [alert(1, note=note), alert(2, note=note)])
    async with client(empty) as http:
        (inv,) = (await http.get("/api/investigations", params={"view": "all"})).json()
        url = f"/investigations/{inv['id']}"
        page = await http.get(url)
        assert headers(page.text)[:3] == ["Event time", "source.ip", "host.name"]
        assert "set-cookie" not in page.headers  # a default is not remembered
        chosen = await http.get(url, params=[("columns", "set"), ("cols", "host.name")])
        cookie = chosen.headers["set-cookie"]
        name = "argus_cols_" + hashlib.sha256(inv["rule_id"].encode()).hexdigest()[:12]
        assert name == _columns_cookie(inv["rule_id"])
        assert cookie.startswith(f"{name}=host.name;")
        assert "HttpOnly" in cookie
        assert "Max-Age=15552000" in cookie  # 180 days
        assert "Path=/investigations" in cookie
        assert "SameSite=strict" in cookie
        assert "open" in chosen.text.split('<details class="columns"', 1)[1].split(">", 1)[0]
        assert (
            " open"
            not in (await http.get(url))
            .text.split('<details class="columns"', 1)[1]
            .split(">", 1)[0]
        )
        assert "The newest" not in page.text  # 2 of 2 shown


async def test_error_messages(empty: AsyncEngine, saver: AsyncPostgresSaver) -> None:  # noqa: F811
    await investigate(empty, saver, three_hosts())
    async with client(empty) as http:
        missing = await http.get(f"/investigations/{uuid.uuid4()}")
        assert missing.status_code == 404
        assert "No such investigation." in missing.text
        (inv, *_) = (await http.get("/api/investigations", params={"view": "all"})).json()
        raw = await http.get(f"/investigations/{inv['id']}/alerts/{'x' * 600}")
        assert raw.status_code == 404
        assert "No such alert here." in raw.text
        page = (await http.get(f"/investigations/{inv['id']}")).text
        form: dict[str, Any] = {"action": "reviewed", "seen_version": inv["version"],
                                "seen_review": "", "csrf_token": csrf_of(page),
                                "outcome": "benign_expected"}  # fmt: skip
        bad = await http.post(f"/investigations/{inv['id']}/review", data={**form, "outcome": "x"})
        assert (bad.status_code, "Unknown outcome." in bad.text) == (422, True)
        expired = await http.post(f"/investigations/{inv['id']}/review",
                                  data={**form, "csrf_token": "x"})  # fmt: skip
        assert expired.status_code == 403
        assert "The form expired; reload the page and try again." in expired.text
        gone = await http.post(f"/investigations/{uuid.uuid4()}/review", data=form)
        assert (gone.status_code, "No such investigation." in gone.text) == (404, True)
        stale = await http.post(f"/investigations/{inv['id']}/review",
                                data={**form, "seen_version": inv["version"] + 5})  # fmt: skip
        assert stale.status_code == 409
        assert "Someone else reviewed this, or new alerts arrived, while you were reading." in (
            stale.text)  # fmt: skip
