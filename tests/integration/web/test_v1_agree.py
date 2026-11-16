"""Q-A1's gate (plan §5 Q-A1): ``/api/v1`` and the classic pages and API agree on generated
data. Hypothesis makes reviews (verdicts, follow-ups, notes; current or stale; through v1 or
through the classic API) and, after each batch, every view in every order, the counts, the
details, the dashboard and the classic Inbox page are compared. The state builds up across
examples: the agreement must hold in every state reached."""

from __future__ import annotations

import re
import uuid
from datetime import timedelta
from typing import Any

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web.app import create_app
from tests.integration.web.conftest import BASE, NOW, PASSWORD, SAME_ORIGIN

pytestmark = pytest.mark.integration
OUTCOMES = ["benign_expected", "benign_policy", "rule_false_positive", "true_positive",
            "inconclusive"]  # fmt: skip
OP = st.tuples(
    st.integers(0, 11),  # which investigation
    st.sampled_from(["reviewed", "follow_up", "note"]),
    st.sampled_from([*OUTCOMES, None]),
    st.booleans(),  # through v1, or the classic API
    st.booleans(),  # stale: what the reviewer saw has moved on
    st.sampled_from(["asha", "ravi"]),
)
VIEWS = ["attention", "open", "reviewed", "all"]
SORTS = ["newest", "oldest", "urgent", "reviewed"]
SAME = ("id", "rule_id", "rule_name", "bucket_start", "alert_count", "duplicate_count",
        "first_event_at", "last_event_at", "severity", "risk_score", "version", "human_state",
        "latest_review", "reasons")  # fmt: skip
LINK = re.compile(r'<a href="/investigations/([0-9a-f-]{36})">')


async def sign_in(http: httpx.AsyncClient, user: str) -> str:
    made = await http.post("/api/login", json={"username": user, "password": PASSWORD})
    assert made.status_code == 200, made.text
    token: str = made.json()["csrf_token"]
    return token


async def apply(http: dict[str, httpx.AsyncClient], tokens: dict[str, str],
                op: tuple[int, str, str | None, bool, bool, str]) -> None:  # fmt: skip
    which, action, outcome, v1, stale, user = op
    client, token = http[user], tokens[user]
    items = (await client.get("/api/v1/investigations", params={"view": "all"})).json()["items"]
    inv = sorted(items, key=lambda i: i["id"])[which % len(items)]
    seen = {"seen_review": inv["latest_review"],
            "seen_version": inv["version"] + (1 if stale else 0)}  # fmt: skip
    if action == "note":
        body: dict[str, Any] = {"action": "note", "note": f"note {which}", **seen}
    elif action == "reviewed":
        body = {"action": "reviewed", "outcome": outcome or "inconclusive", **seen}
    else:
        body = {"action": "follow_up", "outcome": outcome, **seen}
    path = f"/investigations/{inv['id']}/reviews"
    got = await client.post(("/api/v1" if v1 else "/api") + path, json=body,
                            headers={"X-CSRF-Token": token})  # fmt: skip
    assert got.status_code == (409 if stale else 201), got.text


async def agree(http: httpx.AsyncClient) -> None:
    for view in VIEWS:
        classic = (await http.get("/api/investigations", params={"view": view})).json()
        default = "reviewed" if view == "reviewed" else "urgent"
        same_order = (await http.get("/api/v1/investigations",
                                     params={"view": view, "sort": default})).json()  # fmt: skip
        assert [i["id"] for i in same_order["items"]] == [i["id"] for i in classic], view
        for mine, theirs in zip(same_order["items"], classic, strict=True):
            assert {k: mine[k] for k in SAME} == {k: theirs[k] for k in SAME}
            assert [[k["field"], k["value"]] for k in mine["key_fields"]] == theirs["key"]
        for sort in SORTS:
            got = (await http.get("/api/v1/investigations",
                                  params={"view": view, "sort": sort})).json()  # fmt: skip
            assert got["sort"] == sort
            assert len(got["items"]) == len(classic)  # the same investigations, re-ordered
            assert {i["id"] for i in got["items"]} == {i["id"] for i in classic}
    counts = (await http.get("/api/v1/counts")).json()
    for view, key in (("attention", "attention"), ("open", "open"), ("all", "all")):
        listed = (await http.get("/api/investigations", params={"view": view})).json()
        assert counts[key] == len(listed), view
    everything = (await http.get("/api/investigations", params={"view": "all"})).json()
    for inv in everything:
        mine = (await http.get(f"/api/v1/investigations/{inv['id']}")).json()
        theirs = (await http.get(f"/api/investigations/{inv['id']}")).json()
        assert [(r["id"], r["action"], r["outcome"], r["note"], r["version"], r["reviewer"])
                for r in mine["reviews"]] == [
            (r["id"], r["action"], r["outcome"], r["note"], r["version"], r["display_name"])
            for r in theirs["reviews"]]  # fmt: skip
        assert mine["investigation"]["human_state"] == theirs["investigation"]["human_state"]
    for filters in ({"range": "30d"}, {"range": "30d", "state": "reviewed"},
                    {"range": "30d", "verdict": "true_positive"},
                    {"range": "30d", "state": ["follow_up", "changed_since_review"]}):  # fmt: skip
        board = (await http.get("/api/v1/dashboard", params=filters)).json()
        classic_board = (await http.get("/api/dashboard", params=filters)).json()
        kpis = dict(board["kpis"])
        assert kpis.pop("investigations") == classic_board["kpis"]["cases"]
        assert kpis == {k: v for k, v in classic_board["kpis"].items() if k != "cases"}
        assert [i["id"] for i in board["open_investigations"]] == classic_board["open_cases"]
        assert board["states"] == classic_board["states"]
        assert board["verdicts"] == classic_board["verdicts"]


@settings(
    max_examples=max(10, settings().max_examples // 10),
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
@given(ops=st.lists(OP, max_size=8))
async def test_v1_and_the_json_api_agree_on_generated_reviews(
    ops: list[tuple[int, str, str | None, bool, bool, str]],
    seeded: AsyncEngine,
    web_engine: AsyncEngine,
) -> None:
    app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1))
    transport = httpx.ASGITransport(app=app)
    async with (
        httpx.AsyncClient(transport=transport, base_url=BASE, headers=SAME_ORIGIN) as asha,
        httpx.AsyncClient(transport=transport, base_url=BASE, headers=SAME_ORIGIN) as ravi,
    ):
        tokens = {"asha": await sign_in(asha, "asha"), "ravi": await sign_in(ravi, "ravi")}
        for op in ops:
            await apply({"asha": asha, "ravi": ravi}, tokens, op)
        await agree(asha)


async def test_an_unknown_investigation_is_404_in_both(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    app = create_app(web_engine, clock=lambda: NOW)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE,
                                 headers=SAME_ORIGIN) as http:  # fmt: skip
        await sign_in(http, "asha")
        missing = uuid.uuid4()
        assert (await http.get(f"/api/v1/investigations/{missing}")).status_code == 404
        assert (await http.get(f"/api/investigations/{missing}")).status_code == 404
