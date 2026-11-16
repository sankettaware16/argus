"""The engine's API contract (P4-F E5, ``docs/p4f-ui-spec.md`` §2) on the web's own database
login: ``GET /api/v1/today`` (needs you, more waiting, new activity, the gray band, what ARGUS
handled with one audit item), the ``engine`` block on ``GET /api/v1/cases`` and
``/api/v1/cases/{id}`` (null for a case the engine did not make), and Needs you as one set with
``GET /api/v1/cases?view=queue``. Made-up addresses and names (the ACME site)."""

from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.machine import Confirm, Open, Take
from argus.cases.model import LOCAL_CAPABILITIES, Actor, Member
from argus.cases.service import CaseService
from argus.config.settings import WebSettings
from argus.risk import present
from argus.risk import run as risk_run
from argus.web import auth
from argus.web.app import create_app
from argus.web.capabilities import Capability
from tests.integration.risk.conftest import NOW, all_rows, group, scalar
from tests.integration.risk.test_incidents import linked
from tests.integration.risk.test_present import OUTSIDE, world
from tests.integration.web.conftest import BASE, PASSWORD, SAME_ORIGIN

pytestmark = pytest.mark.integration
V1 = "/api/v1"
LATER = NOW + timedelta(minutes=5)
ENGINE_KEYS = {
    "incident_id", "priority", "band", "lane", "certainty", "why", "why_line", "checks",
    "alternatives", "objects", "raised_by_ai", "active", "first_seen", "last_seen", "version",
    "changed", "alert_groups", "alerts", "ai_story", "ai_second_opinion", "disagreement",
}  # fmt: skip
CARD_KEYS = {
    "kind", "id", "number", "title", "state", "version", "engine", "taken_by", "notified_at",
    "in_kibana", "kibana_wait", "waiting_since",
}  # fmt: skip
TODAY_KEYS = {"mode", "needs_you", "more_waiting", "new_activity", "gray", "handled"}
C = Capability
MANAGER = [C.VIEW, C.SEE_LOGS, C.REVIEW, C.MANAGE_CASES]


def presenting(on: bool, per_day: int = 10) -> risk_run.Setup:
    return replace(linked(), presenter=present.Options(on, per_day))


def client(engine: AsyncEngine) -> httpx.AsyncClient:
    app = create_app(engine, WebSettings(failure_delay_s=0, signin_delay_s=0), clock=lambda: LATER)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE,
                             headers=SAME_ORIGIN)  # fmt: skip


async def signed_in(http: httpx.AsyncClient, user: str = "mina") -> None:
    made = await http.post("/api/login", json={"username": user, "password": PASSWORD})
    assert made.status_code == 200, made.text


async def people(owner: AsyncEngine) -> int:
    async with owner.begin() as conn:
        await auth.add_user(conn, "vera", "Vera Viewer", PASSWORD, capabilities=[C.VIEW])
        return int(await auth.add_user(conn, "mina", "Mina Manager", PASSWORD,
                                       capabilities=MANAGER))  # fmt: skip


def check_engine(block: dict[str, Any]) -> None:
    assert set(block) == ENGINE_KEYS
    assert 0 <= block["priority"] <= 100
    assert block["band"] in ("P1", "P2", "P3", "P4")
    assert block["lane"] in ("decisive", "burst", "slow", "campaign", "exposure")
    assert block["certainty"] in ("Likely", "Suspected", "Unclear", "Likely harmless")
    assert block["why"]
    assert all(set(w) == {"op", "points", "text"} for w in block["why"])
    assert all(c["state"] in ("checked", "ruled_out", "unknown") for c in block["checks"])
    assert all(a["state"] in ("ruled_out", "fits", "unknown") and a["test"]
               for a in block["alternatives"])  # fmt: skip
    assert all(o["kind"] in ("device", "account", "site") and o["role"] in ("affected", "actor")
               for o in block["objects"])  # fmt: skip
    assert block["first_seen"] <= block["last_seen"]


async def test_today_and_the_cases_carry_the_engines_view_when_it_presents(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, web_engine: AsyncEngine
) -> None:
    made = await world(migrated_engine)
    user = await people(migrated_engine)
    await risk_run.step(app_engine, presenting(True), NOW)
    async with app_engine.begin() as conn:  # a person's own case: the engine did not make it
        service = await CaseService.start(conn)
        own = await service.open(
            Actor.person(user, LOCAL_CAPABILITIES, via="test"),
            Open("A person's case", "low", "person", (Member(made["quiet"].id, "person"),)),  # type: ignore[attr-defined]
        )  # fmt: skip
    async with client(web_engine) as http:
        await signed_in(http)
        today = (await http.get(f"{V1}/today")).json()
        assert set(today) == TODAY_KEYS
        assert today["mode"] == "present"
        # the three possible incidents, and the person's confirmed case nobody has taken (spec
        # §3.1 #4), last: the engine did not make it, so it carries no engine block
        assert len(today["needs_you"]) == 4
        assert today["more_waiting"] == 0
        *cards, theirs = today["needs_you"]
        assert theirs["id"] == str(own.case.id)
        assert (theirs["kind"], theirs["state"], theirs["engine"]) == ("incident", "open", None)
        assert theirs["waiting_since"]
        bands = [c["engine"]["band"] for c in cards]
        assert bands == sorted(bands)
        kibana = {str(r.id): r.kibana_wait for r in await all_rows(
            migrated_engine, "SELECT id, kibana_wait FROM cases")}  # fmt: skip
        for c in cards:
            assert set(c) == CARD_KEYS
            assert c["kind"] == "incident"
            assert c["id"] in kibana
            assert c["state"] == "suspected"
            assert c["version"] == 1
            assert c["number"] is not None
            assert (c["taken_by"], c["notified_at"], c["in_kibana"]) == (None, None, False)
            assert c["kibana_wait"] == kibana[c["id"]]
            assert c["waiting_since"]
            check_engine(c["engine"])
        assert today["new_activity"] == []
        assert len(today["gray"]) <= 5
        assert all(c["kind"] == "gray" and c["id"].startswith("gray:") for c in today["gray"])
        handled = today["handled"]
        assert set(handled) == {"since", "count", "categories", "audit"}
        assert handled["count"] == sum(c["count"] for c in handled["categories"])
        assert all(c["label"] for c in handled["categories"])
        assert handled["audit"] is None or set(handled["audit"]) == {
            "id", "kind", "title", "closed_as", "category", "at"}  # fmt: skip
        # Needs you and the queue's cases are one set (Q-2)
        queue = (await http.get(f"{V1}/cases", params={"view": "queue"})).json()
        in_queue = {c["id"] for c in queue["items"]}
        assert {c["id"] for c in today["needs_you"]} == in_queue
        assert queue["counts"]["queue"] == len(today["needs_you"]) + today["more_waiting"]
        engine_cases = {c["id"] for c in queue["items"] if c["engine"] is not None}
        assert engine_cases == {c["id"] for c in cards}
        page = (await http.get(f"{V1}/cases", params={"view": "all"})).json()
        engines = {c["id"]: c["engine"] for c in page["items"]}
        assert engines[str(own.case.id)] is None
        assert sum(e is not None for e in engines.values()) == 3
        card = today["needs_you"][0]
        detail = (await http.get(f"{V1}/cases/{card['id']}")).json()
        check_engine(detail["engine"])
        assert detail["case"]["engine"] == detail["engine"]
        assert detail["engine"]["incident_id"] == card["engine"]["incident_id"]
        mine = (await http.get(f"{V1}/cases/{own.case.id}")).json()
        assert mine["engine"] is None
        assert mine["case"]["engine"] is None


async def test_a_confirmed_incident_with_new_activity_comes_back_on_today(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, web_engine: AsyncEngine
) -> None:
    await world(migrated_engine)
    user = await people(migrated_engine)
    await risk_run.step(app_engine, presenting(True), NOW)
    case = await scalar(
        migrated_engine,
        "SELECT r.case_id FROM risk_incidents r JOIN risk_incident_objects o ON o.incident_id ="
        " r.id JOIN risk_objects b ON b.id = o.object_id WHERE b.key = 'ip:10.1.1.1'",
    )
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        mina = Actor.person(user, LOCAL_CAPABILITIES, via="test")
        await service.apply(mina, case, Confirm(), expected_version=None)
        await service.apply(mina, case, Take(), expected_version=None)
    async with client(web_engine) as http:
        await signed_in(http)
        today = (await http.get(f"{V1}/today")).json()
        assert str(case) not in {c["id"] for c in today["needs_you"]}
        assert today["new_activity"] == []
    # an outside detection on the confirmed device: a material change
    await group(migrated_engine, "r-beacon", actor="10.1.1.1", hours_ago=-0.05, flags=(OUTSIDE,),
                signals={"proxy.regularity": 0.1})  # fmt: skip
    await risk_run.step(app_engine, presenting(True), NOW + timedelta(minutes=4))
    async with client(web_engine) as http:
        await signed_in(http, "vera")  # a view-only account reads Today too
        today = (await http.get(f"{V1}/today")).json()
        cards = {c["id"]: c for c in today["new_activity"]}
        assert str(case) in cards
        assert set(cards[str(case)]) == CARD_KEYS
        assert cards[str(case)]["taken_by"] == {"username": "mina", "name": "Mina Manager"}
        assert cards[str(case)]["state"] == "assigned"
        assert cards[str(case)]["kibana_wait"] == await scalar(
            migrated_engine, "SELECT kibana_wait FROM cases WHERE id = :c", c=case
        )
        block = cards[str(case)]["engine"]
        # the evidence's word, never "Confirmed": the case's state says that (spec §2.1, §3.2)
        assert block["certainty"] in ("Likely", "Suspected", "Unclear", "Likely harmless")
        assert block["version"] == 2
        assert any("new evidence: outside" in c for c in block["changed"])
        detail = (await http.get(f"{V1}/cases/{case}")).json()
        assert detail["case"]["state"] == "assigned"
        assert detail["engine"]["certainty"] == block["certainty"]


async def test_in_shadow_today_shows_the_engines_own_cards_without_cases(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, web_engine: AsyncEngine
) -> None:
    await world(migrated_engine)
    await people(migrated_engine)
    await risk_run.step(app_engine, presenting(False), NOW)
    async with client(web_engine) as http:
        assert (await http.get(f"{V1}/today")).status_code == 401
        await signed_in(http)
        today = (await http.get(f"{V1}/today")).json()
    assert today["mode"] == "shadow"
    assert len(today["needs_you"]) == 3
    assert all(c["state"] is None and c["number"] is None for c in today["needs_you"])
    assert all(c["title"] and c["id"].isdigit() for c in today["needs_you"])
    # the engine's own incident, not a case: a UI never acts on it as one (spec §2.2)
    assert all(c["kind"] == "shadow" for c in today["needs_you"])
    for c in today["needs_you"]:
        check_engine(c["engine"])


async def stored(owner: AsyncEngine, band: str, state: str, priority: int, *,
                 shown: bool = True, n: int = 1) -> None:  # fmt: skip
    """``n`` root incidents as the linker and the presenter store them (no case: shadow)."""
    async with owner.begin() as conn:
        for _ in range(n):
            await conn.execute(
                text(
                    "INSERT INTO risk_incidents (state, created_at, first_seen, last_seen,"
                    " updated_at, version, material, material_hash, material_at, changed,"
                    " priority, band, view, recommended, title, certainty, shown, shown_day,"
                    " queued_at) VALUES (:s, :t, :t, :t, :t, 1, '{}', :h, :t, '{new incident}',"
                    " :p, :b, '{\"lane\": \"burst\"}', '[]', 'Possible incident', 'Suspected',"
                    " :shown, :d, :t)"
                ),
                {"s": state, "p": priority, "b": band, "shown": shown, "t": NOW, "h": "0" * 32,
                 "d": NOW.date()},
            )  # fmt: skip


async def test_today_holds_every_p1_and_p2_and_counts_what_it_leaves_out(
    migrated_engine: AsyncEngine, web_engine: AsyncEngine
) -> None:
    """Needs you: every P1 and P2 by band, a quiet one after the active ones of its band, then
    P3 and P4 up to 50; more_waiting counts the held-back and the P3 and P4 past the list, so
    the two add up to every possible incident that waits for a person."""
    await people(migrated_engine)
    await stored(migrated_engine, "P1", "quiet", 90)
    await stored(migrated_engine, "P4", "active", 10, n=50)
    await stored(migrated_engine, "P2", "quiet", 70)
    await stored(migrated_engine, "P2", "active", 60)
    await stored(migrated_engine, "P3", "active", 40, shown=False, n=2)
    async with client(web_engine) as http:
        await signed_in(http)
        today = (await http.get(f"{V1}/today")).json()
        order = [(c["engine"]["band"], c["engine"]["priority"]) for c in today["needs_you"]]
        assert order[:3] == [("P1", 90), ("P2", 60), ("P2", 70)]
        assert order[3:] == [("P4", 10)] * 47
        assert today["more_waiting"] == 2 + 3
        await stored(migrated_engine, "P1", "quiet", 80, n=55)
        today = (await http.get(f"{V1}/today")).json()
    bands = [c["engine"]["band"] for c in today["needs_you"]]
    assert bands == ["P1"] * 56 + ["P2"] * 2
    assert today["more_waiting"] == 2 + 50


async def presented(
    owner: AsyncEngine, band: str, priority: int, *, shown: bool, confirm: int | None = None,
) -> str:  # fmt: skip
    """A root incident presented as the engine stores it: its suspected case (confirmed by the
    person ``confirm``, who does not take it) and its row, a Today card when ``shown``."""
    made = await group(owner, "r-beacon", actor=f"10.9.{priority}.{int(shown)}", hours_ago=1)
    async with owner.begin() as conn:
        service = await CaseService.start(conn)
        applied = await service.open(Actor.argus("engine"), Open(
            f"Possible incident {band}", "medium", "raised", (Member(made.id, "actor"),),
            suspected=True, attention="ARGUS suggests this case: a test",
        ))  # fmt: skip
        if confirm is not None:
            await service.apply(Actor.person(confirm, LOCAL_CAPABILITIES, via="test"),
                                applied.case.id, Confirm(), expected_version=None)  # fmt: skip
        await conn.execute(
            text(
                "INSERT INTO risk_incidents (state, created_at, first_seen, last_seen, updated_at,"
                " version, material, material_hash, material_at, changed, priority, band, view,"
                " recommended, title, certainty, shown, shown_day, queued_at, case_id)"
                " VALUES ('active', :t, :t, :t, :t, 1, '{}', :h, :t, '{new incident}', :p, :b,"
                " CAST(:view AS jsonb), '[]', 'Possible incident', 'Suspected', :shown, :d, :t,"
                " :c)"
            ),
            {"p": priority, "b": band, "shown": shown, "t": NOW, "h": "0" * 32, "d": NOW.date(),
             "c": applied.case.id,
             "view": '{"lane": "burst", "shown_in": ' + ('"present"' if shown else "null") + "}"},
        )  # fmt: skip
        await conn.execute(text("INSERT INTO risk_mode (id, present, at) VALUES (1, true, :t)"
                                " ON CONFLICT (id) DO NOTHING"), {"t": NOW})  # fmt: skip
    return str(applied.case.id)


async def test_presenting_needs_you_and_the_queue_are_one_set(
    migrated_engine: AsyncEngine, web_engine: AsyncEngine
) -> None:
    """Q-2 (spec §6.3) with the daily room holding a P3 back and a confirmed case nobody has
    taken: the queue's count is ``needs_you.length + more_waiting``, the held case is in the
    queue but not a card, and the confirmed unowned case is a card (spec §3.1 #4)."""
    from tests.integration.risk.test_present import rule

    await rule(migrated_engine, "r-beacon", "Beacon rule")
    user = await people(migrated_engine)
    urgent = await presented(migrated_engine, "P1", 90, shown=True)
    card = await presented(migrated_engine, "P3", 40, shown=True)
    held = await presented(migrated_engine, "P3", 30, shown=False)
    confirmed = await presented(migrated_engine, "P2", 60, shown=True, confirm=user)
    async with client(web_engine) as http:
        await signed_in(http)
        today = (await http.get(f"{V1}/today")).json()
        assert today["mode"] == "present"
        assert [c["id"] for c in today["needs_you"]] == [urgent, confirmed, card]
        assert today["more_waiting"] == 1
        by_id = {c["id"]: c for c in today["needs_you"]}
        assert by_id[confirmed]["state"] == "open"
        assert by_id[confirmed]["taken_by"] is None
        assert by_id[confirmed]["engine"]["certainty"] != "Confirmed"
        queue = (await http.get(f"{V1}/cases", params={"view": "queue"})).json()
        assert {c["id"] for c in queue["items"]} == {urgent, confirmed, card, held}
        assert queue["counts"]["queue"] == len(today["needs_you"]) + today["more_waiting"]
        # taken: it leaves Needs you on both, and the two still agree
        async with migrated_engine.begin() as conn:
            service = await CaseService.start(conn)
            await service.apply(Actor.person(user, LOCAL_CAPABILITIES, via="test"),
                                uuid.UUID(confirmed), Take(), expected_version=None)  # fmt: skip
        today = (await http.get(f"{V1}/today")).json()
        queue = (await http.get(f"{V1}/cases", params={"view": "queue"})).json()
        assert confirmed not in {c["id"] for c in today["needs_you"]}
        assert queue["counts"]["queue"] == len(today["needs_you"]) + today["more_waiting"] == 3
