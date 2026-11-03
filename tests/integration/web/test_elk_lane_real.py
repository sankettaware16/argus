"""Q-E2 with the real identity lane (Q-E1) instead of the fake: it runs on the web's own database
login (argus_web's grants, migration 0036: the gate state, the switches, the request ledger), asks
a scripted Elasticsearch, and the ledger never holds a name or a password."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import Settings
from argus.gateway.pgstore import PgStore
from argus.gateway.service import collector_config, lane_plan
from argus.gateway.transport import WireResponse
from argus.identity.service import build_identity_lane
from argus.identity.transport import IdentityRequest, Route
from argus.web.app import create_app
from tests.integration.web.conftest import BASE, SAME_ORIGIN
from tests.integration.web.elk_rig import elk_settings, form_token
from tests.unit.gateway.fakes import FakeClock  # noqa: F401
from tests.unit.identity.test_lane import DENIED, answer, privileges_body, whoami_body
from tests.unit.web.fake_identity import Clock

pytestmark = pytest.mark.integration
PASSWORD = "an elk password 1234"


@dataclass
class ScriptedElasticsearch:
    """Elasticsearch's answers to the identity lane's two routes."""

    accounts: dict[str, str] = field(default_factory=dict)  # name -> password
    status: int = 200
    sent: list[tuple[Route, str]] = field(default_factory=list)

    async def send(self, request: IdentityRequest, auth: SecretStr) -> WireResponse:
        header = auth.get_secret_value()
        import base64

        name, _, password = base64.b64decode(header.split(" ", 1)[1]).decode().partition(":")
        self.sent.append((request.route, name))
        if self.status != 200 or self.accounts.get(name) != password:
            return answer(DENIED, self.status if self.status != 200 else 401)
        if request.route is Route.WHOAMI:
            return answer(whoami_body(name))
        return answer(
            privileges_body(name, alerts=("read", "index", "maintenance"), logs=("read",))
        )


@pytest.fixture
async def real(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> AsyncIterator[tuple[httpx.AsyncClient, ScriptedElasticsearch, Clock, AsyncEngine]]:
    settings = Settings()
    store = PgStore(web_engine, collector_config(settings.siem), lane_plan(settings.siem))
    es = ScriptedElasticsearch({"asha.elk": PASSWORD})
    lane = build_identity_lane(settings, store, sender=es)
    clock = Clock()
    app = create_app(web_engine, elk_settings(), clock=clock, lane=lane)
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 51000))  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url=BASE, headers=SAME_ORIGIN) as http:
        yield http, es, clock, seeded
    await app.state.elk.settle()


async def sign_in(http: httpx.AsyncClient, name: str, password: str) -> httpx.Response:
    form = await http.get("/signin")
    return await http.post("/signin", data={"username": name, "password": password,
                                            "signin_token": form_token(form.text)})  # fmt: skip


async def ledger(engine: AsyncEngine) -> list[tuple[str, str, str]]:
    async with engine.connect() as conn:
        rows = await conn.execute(text("SELECT template, lane, outcome FROM siem_requests"
                                       " ORDER BY id"))  # fmt: skip
        return [tuple(r) for r in rows]  # type: ignore[misc]


async def test_the_real_lane_signs_a_person_in_and_re_checks_on_the_webs_own_login(real) -> None:  # type: ignore[no-untyped-def]
    http, es, clock, engine = real
    assert (await sign_in(http, "asha.elk", PASSWORD)).status_code == 303
    session = (await http.get("/api/v1/session")).json()
    assert {c["name"] for c in session["capabilities"]} == {"view", "see_logs", "review"}
    assert [r for r, _ in es.sent] == [Route.WHOAMI, Route.VERIFY]
    clock.advance(seconds=31)
    listed = (await http.get("/api/investigations", params={"view": "all"})).json()
    first = listed[0]
    got = await http.post(
        f"/api/investigations/{first['id']}/reviews",
        json={"action": "note", "note": "seen", "seen_review": first["latest_review"],
              "seen_version": first["version"]},
        headers={"X-CSRF-Token": session["csrf_token"]},
    )  # fmt: skip
    assert got.status_code == 201
    assert [r for r, _ in es.sent] == [Route.WHOAMI, Route.VERIFY, Route.VERIFY]
    rows = await ledger(engine)
    assert [(t, lane) for t, lane, _ in rows] == [
        ("identity.whoami", "identity"), ("identity.verify", "identity"),
        ("identity.verify", "identity"),
    ]  # fmt: skip
    async with engine.connect() as conn:
        everything = json.dumps([
            [str(v) for v in r] for r in await conn.execute(text("SELECT * FROM siem_requests"))
        ])  # fmt: skip
    assert "asha" not in everything
    assert PASSWORD not in everything


async def test_without_the_reader_key_a_401_is_unavailable_and_counts_for_nothing(real) -> None:  # type: ignore[no-untyped-def]
    http, es, _clock, engine = real
    for _ in range(2):  # the lane cannot tell a wrong password from an index outage
        got = await sign_in(http, "asha.elk", "a wrong password 12")
        assert got.status_code == 503
    async with engine.connect() as conn:
        counted = await conn.scalar(text("SELECT count(*) FROM audit_events"
                                         " WHERE details->>'counted' = 'true'"))  # fmt: skip
    assert counted == 0
    assert (await sign_in(http, "asha.elk", PASSWORD)).status_code == 303
    assert es.sent
