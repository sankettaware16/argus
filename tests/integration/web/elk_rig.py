"""The Inbox in ELK mode for tests (Q-E2): the real app on a throwaway database as the web's own
login, a fake identity lane (tests/unit/web/fake_identity.py), a clock the test moves, and the
sign-in/step-up helpers a browser would do. Background re-checks are awaited
(``rig.settle()``), so a test is deterministic."""

from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import WebSettings
from argus.web.app import create_app
from argus.web.elk import Elk
from tests.integration.web.conftest import BASE, SAME_ORIGIN
from tests.unit.web.fake_identity import PASSWORD, Clock, FakeLane

SECRET = "ab" * 32
SECRET_FILE = Path(tempfile.mkdtemp(prefix="argus-test-secret-")) / "web-secret"
SECRET_FILE.write_text(SECRET + "\n")
SECRET_FILE.chmod(0o600)
FAST_ELK: dict[str, Any] = {
    "elk_signin": True, "secret_file": SECRET_FILE, "database_role": "api",
    "failure_delay_s": 0, "signin_delay_s": 0, "allowed_networks": ("10.0.0.0/8",),
}  # fmt: skip


def elk_settings(**kw: Any) -> WebSettings:
    return WebSettings(**{**FAST_ELK, **kw})


def form_token(page: str) -> str:
    found = re.search(r'name="signin_token" value="([^"]+)"', page)
    assert found is not None, page
    return found.group(1)


@dataclass
class Rig:
    engine: AsyncEngine  # the web's own login
    owner: AsyncEngine  # the runtime login, for seeding and reading
    lane: FakeLane
    clock: Clock
    app: Any
    elk: Elk
    settings: WebSettings
    browsers: list[httpx.AsyncClient] = field(default_factory=list)

    def browser(self, client: str = "127.0.0.1") -> httpx.AsyncClient:
        transport = httpx.ASGITransport(app=self.app, client=(client, 51000))  # type: ignore[arg-type]
        http = httpx.AsyncClient(transport=transport, base_url=BASE, headers=SAME_ORIGIN)
        self.browsers.append(http)
        return http

    async def settle(self) -> None:
        await self.elk.settle()

    async def sign_in(
        self, http: httpx.AsyncClient, name: str, password: str = PASSWORD, next_: str | None = None
    ) -> httpx.Response:
        form = await http.get("/signin")
        assert form.status_code == 200, form.text
        data = {"username": name, "password": password, "signin_token": form_token(form.text)}
        if next_ is not None:
            data["next"] = next_
        return await http.post("/signin", data=data)

    async def signed_in(self, name: str = "asha", **account: Any) -> tuple[httpx.AsyncClient, str]:
        """A browser signed in as ELK account ``name`` (made if the lane lacks it); its
        session's CSRF token."""
        if name not in self.lane.accounts:
            self.lane.add(name, **account)
        http = self.browser()
        made = await self.sign_in(http, name, self.lane.accounts[name].password)
        assert made.status_code == 303, made.text
        return http, await self.csrf(http)

    async def csrf(self, http: httpx.AsyncClient) -> str:
        got = await http.get("/api/v1/session")
        assert got.status_code == 200, got.text
        token: str = got.json()["csrf_token"]
        return token

    async def review(self, http: httpx.AsyncClient, csrf: str) -> httpx.Response:
        """A change that needs ``review``: a note on the first investigation."""
        listed = await http.get("/api/investigations", params={"view": "all"})
        first = listed.json()[0]
        return await http.post(
            f"/api/investigations/{first['id']}/reviews",
            json={"action": "note", "note": "seen", "seen_review": first["latest_review"],
                  "seen_version": first["version"]},
            headers={"X-CSRF-Token": csrf},
        )  # fmt: skip

    async def elapse(self, http: httpx.AsyncClient, **span: float) -> None:
        """Time passes while the person keeps clicking (a page every 20 minutes at most), so the
        idle limit of 30 minutes never ends the session; background checks are let finish."""
        left = timedelta(**span)
        step = timedelta(minutes=20)
        while left > timedelta(0):
            gone = min(left, step)
            self.clock.now += gone
            left -= gone
            await http.get("/api/investigations")
            await self.settle()

    async def one(self, sql: str, **params: Any) -> Any:
        async with self.owner.connect() as conn:
            return (await conn.execute(text(sql), params)).first()

    async def scalar(self, sql: str, **params: Any) -> Any:
        row = await self.one(sql, **params)
        return None if row is None else row[0]

    async def aclose(self) -> None:
        await self.elk.settle()
        for http in self.browsers:
            await http.aclose()


async def make_rig(
    web_engine: AsyncEngine, app_engine: AsyncEngine, lane: FakeLane | None = None, **settings: Any
) -> Rig:
    clock = Clock()
    lane = lane or FakeLane()
    config = elk_settings(**settings)
    app = create_app(web_engine, config, clock=clock, lane=lane)
    return Rig(web_engine, app_engine, lane, clock, app, app.state.elk, config)


def minutes(n: float) -> timedelta:
    return timedelta(minutes=n)
