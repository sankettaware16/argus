"""The Inbox on the campus network (D-104): only allowed client networks and host names, a
secure cookie under TLS, logins throttled after repeated failures, and a real HTTPS server."""

from __future__ import annotations

import asyncio
import os
import shutil
import ssl
import subprocess
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import WebSettings
from argus.web import throttle
from argus.web.app import TOO_MANY, client_allowed, create_app
from tests.integration.web.conftest import BASE, FAST, NOW, PASSWORD
from tests.integration.web.test_external import BIN, ROOT, free_port, started

pytestmark = pytest.mark.integration
LAN = WebSettings.model_validate({
    "host": "0.0.0.0", "tls_cert": "c.crt", "tls_key": "c.key",  # noqa: S104 - the test
    "allowed_hosts": ["10.13.171.247"], "allowed_networks": ["10.13.171.0/24"],
    "failure_delay_s": 0, "signin_delay_s": 0,
})  # fmt: skip


def client(app: object, address: str, base: str = BASE) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app, client=(address, 51000))  # type: ignore[arg-type]
    return httpx.AsyncClient(transport=transport, base_url=base, headers={"Origin": base})


def test_which_clients_are_allowed() -> None:
    nets = (*LAN.allowed_networks,)
    from argus.web.app import LOOPBACK_NETS

    allowed = (*LOOPBACK_NETS, *nets)
    assert client_allowed("127.0.0.1", allowed)
    assert client_allowed("127.8.9.1", allowed)
    assert client_allowed("::1", allowed)
    assert client_allowed("10.13.171.5", allowed)
    assert not client_allowed("10.13.172.5", allowed)
    assert not client_allowed("172.17.0.2", allowed)  # a container on this machine
    assert not client_allowed("fe80::1", allowed)
    assert not client_allowed(None, allowed)
    assert not client_allowed("testclient", allowed)  # not an address: refused
    assert not client_allowed("10.13.171.5", LOOPBACK_NETS)  # the default: loopback only


async def test_only_allowed_networks_and_hosts_reach_the_app(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    lan = create_app(web_engine, LAN, clock=lambda: NOW)
    async with client(lan, "10.13.171.9", "https://10.13.171.247") as http:
        assert (await http.get("/signin")).status_code == 200
    async with client(lan, "10.13.172.9", "https://10.13.171.247") as http:
        refused = await http.get("/signin")
        assert (refused.status_code, refused.json()) == (
            403,
            {"detail": "not from an allowed network"},
        )
        assert (await http.post("/api/login", json={"username": "asha", "password": PASSWORD})
                ).status_code == 403  # fmt: skip
    async with client(lan, "10.13.171.9", "https://evil.example") as http:
        assert (await http.get("/signin")).status_code == 400  # not an allowed host name
    default = create_app(web_engine, clock=lambda: NOW)
    async with client(default, "10.13.171.9") as http:
        assert (await http.get("/signin")).status_code == 403  # loopback only by default
    async with client(default, "127.0.0.1", "http://10.13.171.247") as http:
        assert (await http.get("/signin")).status_code == 400  # that name is not allowed here


async def test_the_session_cookie_is_secure_under_tls(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    lan = create_app(web_engine, LAN, clock=lambda: NOW)
    async with client(lan, "10.13.171.9", "https://10.13.171.247") as http:
        made = await http.post("/api/login", json={"username": "asha", "password": PASSWORD})
        assert made.status_code == 200
        cookie = made.headers["set-cookie"].lower()
        assert "secure" in cookie
        assert "httponly" in cookie
        assert "samesite=strict" in cookie
    plain = create_app(web_engine, clock=lambda: NOW)
    async with client(plain, "127.0.0.1") as http:
        made = await http.post("/api/login", json={"username": "asha", "password": PASSWORD})
        assert "secure" not in made.headers["set-cookie"].lower()  # http on the loopback


async def failures(engine: AsyncEngine) -> list[tuple[str, str, str | None]]:
    async with engine.connect() as conn:
        rows = await conn.execute(text(
            "SELECT details->>'username', details->>'client', details->>'why' FROM audit_events"
            " WHERE action = 'login' AND outcome = 'denied' ORDER BY id"))  # fmt: skip
        return [tuple(r) for r in rows]  # type: ignore[misc]


async def test_logins_are_throttled_per_name(seeded: AsyncEngine, web_engine: AsyncEngine) -> None:
    app = create_app(web_engine, FAST, clock=lambda: NOW)
    async with client(app, "127.0.0.1") as http:
        for _ in range(throttle.NAME_LIMIT):
            bad = await http.post(
                "/api/login", json={"username": "asha", "password": "wrong-pass1"}
            )
            assert bad.status_code == 401
        right = await http.post("/api/login", json={"username": "asha", "password": PASSWORD})
        assert (right.status_code, right.json()) == (429, {"detail": TOO_MANY})
        assert TOO_MANY == "too many failed logins; try again in 15 minutes"
        form = await http.post("/login", data={"username": "asha", "password": PASSWORD})
        assert form.status_code == 429
        assert "Too many failed logins; try again in 15 minutes." in form.text
        other = await http.post("/api/login", json={"username": "ravi", "password": PASSWORD})
        assert other.status_code == 200  # another name is not held back
    got = await failures(seeded)
    assert got[: throttle.NAME_LIMIT] == [("asha", "127.0.0.1", None)] * throttle.NAME_LIMIT
    assert got[throttle.NAME_LIMIT :] == [("asha", "127.0.0.1", "throttled")] * 2
    assert (throttle.NAME_LIMIT, throttle.CLIENT_LIMIT, throttle.WINDOW.total_seconds()) == (
        5,
        20,
        900,
    )


async def test_logins_are_throttled_per_client_and_the_window_passes(
    seeded: AsyncEngine, web_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = create_app(web_engine, LAN, clock=lambda: NOW)
    async with client(app, "10.13.171.66", "https://10.13.171.247") as http:
        for k in range(throttle.CLIENT_LIMIT):  # a spray of names, each failing once
            await http.post("/api/login", json={"username": f"user{k}", "password": "wrong-pass1"})
        held = await http.post("/api/login", json={"username": "asha", "password": PASSWORD})
        assert held.status_code == 429
    async with client(app, "10.13.171.67", "https://10.13.171.247") as http:
        ok = await http.post("/api/login", json={"username": "asha", "password": PASSWORD})
        assert ok.status_code == 200  # another client is not held back
    monkeypatch.setattr(throttle, "WINDOW", throttle.WINDOW / 900)  # one second
    await asyncio.sleep(1.2)
    async with client(app, "10.13.171.66", "https://10.13.171.247") as http:
        again = await http.post("/api/login", json={"username": "asha", "password": PASSWORD})
        assert again.status_code == 200


@pytest.fixture
async def tls_server(seeded: AsyncEngine, test_database: str) -> AsyncIterator[tuple[str, Path]]:
    if shutil.which("openssl") is None:
        pytest.skip("openssl is not installed")
    folder = Path(tempfile.mkdtemp())
    cert, key = folder / "c.crt", folder / "c.key"
    subprocess.run(  # noqa: S603, ASYNC221 - a throwaway certificate for this test
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",  # noqa: S607
         "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
         "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True,
    )  # fmt: skip
    port = free_port()
    env = {k: v for k, v in os.environ.items() if not k.startswith("ARGUS_")}
    env.update(ARGUS_DATABASE__NAME=test_database, ARGUS_WEB__PORT=str(port),
               ARGUS_WEB__TLS_CERT=str(cert), ARGUS_WEB__TLS_KEY=str(key))  # fmt: skip
    from tests.conftest import suite_config

    env["ARGUS_CONFIG"] = str(suite_config())  # the suite's site, not this checkout's
    log = tempfile.TemporaryFile()  # noqa: SIM115 - closed below
    process = subprocess.Popen(  # noqa: S603, ASYNC220 - our own CLI
        [str(BIN / "argus"), "web"], cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=log,
    )  # fmt: skip
    url = f"https://127.0.0.1:{port}"
    trust = ssl.create_default_context(cafile=str(cert))
    try:
        started(url, process, log, verify=trust)
        yield url, cert
    finally:
        process.terminate()
        process.wait(timeout=10)
        log.close()
        shutil.rmtree(folder)


async def test_argus_web_serves_https(tls_server: tuple[str, Path]) -> None:
    url, cert = tls_server
    trust = ssl.create_default_context(cafile=str(cert))
    async with httpx.AsyncClient(base_url=url, verify=trust, headers={"Origin": url}) as http:
        assert (await http.get("/signin")).status_code == 200
        made = await http.post("/login", data={"username": "asha", "password": PASSWORD})
        assert made.status_code == 303
        assert "secure" in made.headers["set-cookie"].lower()
        assert (await http.get("/dashboard")).status_code == 200  # the secure cookie came back
    with pytest.raises(httpx.HTTPError):  # plain http to the TLS port is no answer
        httpx.get(url.replace("https", "http") + "/login", timeout=3)  # noqa: ASYNC210
