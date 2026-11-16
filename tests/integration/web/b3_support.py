"""What Q-B3's tests share: the app on the web's own database login with a signing key, people
with the capabilities cases ask for (a manager, two approvers, a reviewer, a view-only account),
cases opened over the seeded investigations, and the calls a page makes."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import signing
from argus.cases.machine import Open
from argus.cases.model import KIBANA_TO_OPEN, Actor, Indicator, Member
from argus.cases.service import CaseService
from argus.config.settings import WebSettings
from argus.web import auth, queries
from argus.web.app import create_app
from argus.web.capabilities import Capability
from tests.integration.web.conftest import BASE, PASSWORD, SAME_ORIGIN

C = Capability
V1 = "/api/v1"
MANAGER = [C.VIEW, C.SEE_LOGS, C.REVIEW, C.MANAGE_CASES, C.REOPEN]
APPROVER = [*MANAGER, C.APPROVE]
PEOPLE: dict[str, tuple[str, list[Capability]]] = {
    "mina": ("Mina Manager", MANAGER),
    "nora": ("Nora NoReopen", [C.VIEW, C.SEE_LOGS, C.REVIEW, C.MANAGE_CASES]),
    "sven": ("Sven NoLogs", [C.VIEW, C.REVIEW, C.MANAGE_CASES]),
    "omar": ("Omar Approver", APPROVER),
    "oona": ("Oona Approver", APPROVER),
    "vera": ("Vera Viewer", [C.VIEW]),
    "rita": ("Rita Reviewer", [C.VIEW, C.REVIEW]),
}


@dataclass
class World:
    runtime: AsyncEngine  # ARGUS's own login: seeds cases, reads records
    web: AsyncEngine  # the web's login: the app under test
    investigations: list[uuid.UUID]
    key_file: Path
    owner: AsyncEngine  # the schema's owner: for rows ARGUS's own login may not write

    def app(
        self,
        *,
        signing: bool = True,
        team: Any = None,
        signins: Any = None,
        switches_root: Path | None = None,
        **settings: Any,
    ) -> httpx.AsyncClient:
        key = self.key_file if signing else None
        web = WebSettings(approval_key_file=key, failure_delay_s=0, signin_delay_s=0, **settings)
        # the case team's switches file is read from the test's own folder, never the checkout's
        root = switches_root or self.key_file.parent
        app = create_app(self.web, web, team=team, signins=signins, switches_root=root)
        transport = httpx.ASGITransport(app=app)
        return httpx.AsyncClient(transport=transport, base_url=BASE, headers=SAME_ORIGIN)

    async def user_id(self, username: str) -> int:
        async with self.runtime.connect() as conn:
            return int(
                (await conn.execute(text("SELECT id FROM users WHERE username = :u"),
                                    {"u": username})).scalar_one()
            )  # fmt: skip

    async def open_case(
        self,
        members: int = 1,
        *,
        by: str = "mina",
        title: str = "Regular beaconing from 10.0.0.1",
        severity: str = "high",
        indicators: tuple[Indicator, ...] = (),
        start: int = 0,
        kibana: bool = False,
    ) -> uuid.UUID:
        """A confirmed case over the next ``members`` investigations (from ``start``), opened
        by a person who may manage cases (it waits for someone to open it in Kibana, unless
        ``kibana``: then their check showed they may, and a Kibana create is planned)."""
        who = Actor.person(
            await self.user_id(by), frozenset(c.value for c in MANAGER), via="test",
            kibana=KIBANA_TO_OPEN if kibana else frozenset(),
            kibana_checked_at=datetime.now(UTC) if kibana else None,
        )  # fmt: skip
        chosen = self.investigations[start : start + members]
        async with self.runtime.begin() as conn:
            service = await CaseService.start(conn)
            applied = await service.open(
                who,
                Open(title, severity, "person", tuple(Member(i, "person") for i in chosen),  # type: ignore[arg-type]
                     indicators),
            )  # fmt: skip
        return applied.case.id

    async def open_suspected(self, index: int, title: str = "Proposed beacon") -> uuid.UUID:
        """A suspected case from ARGUS's own proposal over one investigation."""
        inv = self.investigations[index]
        async with self.owner.begin() as conn:
            assessment = (
                await conn.execute(
                    text(
                        "INSERT INTO assessments (investigation_id, version, pack, dossier_hash,"
                        " view_hash, assessor, run_after, status, outcome) VALUES (:i, 1, 'p',"
                        " repeat('a', 64), repeat('b', 64), 'agent', now(), 'proposed',"
                        " 'true_positive') RETURNING id"
                    ),
                    {"i": inv},
                )
            ).scalar_one()
        async with self.runtime.begin() as conn:
            service = await CaseService.start(conn)
            applied = await service.open(
                Actor.argus("opener"),
                Open(title, "low", "proposal", (Member(inv, "proposal"),), suspected=True,
                     cause_assessment_id=assessment),
            )  # fmt: skip
        return applied.case.id

    async def rows(self, query: str, **params: Any) -> list[Any]:
        async with self.runtime.connect() as conn:
            return list((await conn.execute(text(query), params)).all())


async def make_world(
    seeded: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> World:
    """The fixture of each B3 test module: the people, the investigations and a signing key."""
    async with seeded.begin() as conn:
        for name, (display, caps) in PEOPLE.items():
            await auth.add_user(conn, name, display, PASSWORD, capabilities=caps)
    async with seeded.connect() as conn:
        found = await queries.inbox(conn, "all", limit=100, sort="oldest")
    key = signing.new_key()
    path = tmp_path / "approval.key"
    signing.write_key(path, key)
    return World(seeded, web_engine, [i.id for i in found], path, migrated_engine)


async def sign_in(http: httpx.AsyncClient, user: str) -> str:
    made = await http.post("/api/login", json={"username": user, "password": PASSWORD})
    assert made.status_code == 200, made.text
    token: str = made.json()["csrf_token"]
    return token


async def step_up(http: httpx.AsyncClient, csrf: str) -> None:
    """The person types their password again on /stepup (what a page sends them to)."""
    done = await http.post("/stepup", data={"password": PASSWORD, "csrf_token": csrf, "next": "/"})
    assert done.status_code == 303, done.text


def headers(csrf: str) -> dict[str, str]:
    return {"X-CSRF-Token": csrf}


Post = Callable[..., Awaitable[httpx.Response]]


async def post(
    http: httpx.AsyncClient, csrf: str, path: str, body: dict[str, Any] | None = None
) -> httpx.Response:
    return await http.post(V1 + path, headers=headers(csrf), json=body or {})


async def request_closure(
    http: httpx.AsyncClient,
    csrf: str,
    case: object,
    reason: str,
    *,
    version: int = 1,
    note: str | None = None,
) -> httpx.Response:
    """What the page does: read the preview, then ask with its hash."""
    seen = await http.get(f"{V1}/cases/{case}/closure-preview",
                          params={"reason": reason, "expected_version": version})  # fmt: skip
    assert seen.status_code == 200, seen.text
    return await post(http, csrf, f"/cases/{case}/closure-requests",
                      {"expected_version": version, "reason": reason, "note": note,
                       "payload_hash": seen.json()["payload_hash"]})  # fmt: skip


@asynccontextmanager
async def stepped(
    world: World, user: str, **settings: Any
) -> AsyncIterator[tuple[httpx.AsyncClient, str]]:
    """A signed-in client for ``user`` who has just typed their password again."""
    async with world.app(**settings) as http:
        csrf = await sign_in(http, user)
        await step_up(http, csrf)
        yield http, csrf


# --------------------------------------------------------------------------- the real server


@dataclass
class Live:
    """``argus web`` as a process on the web's own database login (the production shape: its
    login records approvals and runs the case commands), with a signing key."""

    url: str
    world: World
    test_database: str


async def start_server(
    world: World,
    test_database: str,
    login: Any,
    tmp_path: Path,
) -> AsyncIterator[Live]:
    import os
    import subprocess
    import tempfile

    from tests.integration.web.test_external import BIN, ROOT, free_port, plant_dossiers, started

    await plant_dossiers(world.runtime)
    port = free_port()
    env = {k: v for k, v in os.environ.items() if not k.startswith("ARGUS_")}
    env.update(
        ARGUS_DATABASE__NAME=test_database,
        ARGUS_WEB__PORT=str(port),
        ARGUS_WEB__DATABASE_ROLE="api",
        ARGUS_DATABASE__API_USER=login.api_user,
        ARGUS_DATABASE__API_PASSWORD=login.api_password.get_secret_value(),
        ARGUS_WEB__APPROVAL_KEY_FILE=str(world.key_file),
        ARGUS_CASE_TEAM__AUTO="true",  # AR8's pages read an ARGUS-verdict case (here off, D-214)
        ARGUS_WEB__SWITCHES_ROOT=str(tmp_path),  # never this checkout's case team switches
    )
    from tests.conftest import suite_config

    env["ARGUS_CONFIG"] = str(suite_config())  # the suite's site, not this checkout's
    log = tempfile.TemporaryFile()  # noqa: SIM115 - closed below
    process = subprocess.Popen(  # noqa: S603, ASYNC220 - our own CLI, started once
        [str(BIN / "argus"), "web"], cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=log
    )
    url = f"http://127.0.0.1:{port}"
    try:
        started(url, process, log)
        yield Live(url, world, test_database)
    finally:
        process.terminate()
        process.wait(timeout=10)
        log.close()
