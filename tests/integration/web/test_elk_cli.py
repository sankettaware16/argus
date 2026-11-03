"""Q-E2 at the terminal: ``argus user link``, ``argus sessions end-all`` and ``keygen``, and the
break-glass drill (``argus break-glass on|off|status``) with the web."""

from __future__ import annotations

import asyncio
import re
import stat
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web import auth, breakglass
from argus.web import cli as web_cli
from tests.integration.test_cli_db import _invoke, cli_env  # noqa: F401
from tests.integration.web.elk_rig import SECRET_FILE, Rig, make_rig
from tests.unit.web.fake_identity import PASSWORD

pytestmark = pytest.mark.integration
REASON = "the SIEM has been unreachable since last night\n"


@pytest.fixture
def elk_on(cli_env: Path, monkeypatch: pytest.MonkeyPatch) -> Path:  # noqa: F811
    monkeypatch.setenv("ARGUS_WEB__ELK_SIGNIN", "true")
    monkeypatch.setenv("ARGUS_WEB__SECRET_FILE", str(SECRET_FILE))
    monkeypatch.setenv("ARGUS_WEB__DATABASE_ROLE", "api")
    monkeypatch.setattr(web_cli, "_at_a_terminal", lambda: True)
    return cli_env


@pytest.fixture
async def rig(seeded: AsyncEngine, web_engine: AsyncEngine) -> AsyncIterator[Rig]:
    made = await make_rig(web_engine, seeded)
    try:
        yield made
    finally:
        await made.aclose()


def run_now(config: Path, *args: str, text_in: str | None = None) -> tuple[int, str]:
    from tests.integration import test_cli_db as base

    result = base.runner.invoke(base.app, [*args, "-c", str(config)], input=text_in)
    return result.exit_code, result.output + result.stderr


async def run(config: Path, *args: str, text_in: str | None = None) -> tuple[int, str]:
    """A terminal command, in a thread (the commands start an event loop of their own)."""
    return await asyncio.to_thread(run_now, config, *args, text_in=text_in)


# --------------------------------------------------------------------------- link


async def test_user_link_ties_a_local_account_to_its_elk_account(rig: Rig, elk_on: Path) -> None:
    code, out = await run(elk_on, "user", "link", "asha", "Asha.Rao")
    assert code == 0, out
    assert "stays until their first ELK sign-in has worked" in out
    row = await rig.one("SELECT elk_username, realm, password_hash IS NOT NULL AS hash"
                        " FROM users WHERE username = 'asha'")  # fmt: skip
    assert tuple(row) == ("Asha.Rao", "native", True)
    assert await rig.scalar("SELECT count(*) FROM audit_events WHERE action = 'user.link'") == 1
    rig.lane.add("Asha.Rao")
    assert (await rig.sign_in(rig.browser(), "Asha.Rao")).status_code == 303
    listed = (await run(elk_on, "user", "list"))[1]
    assert "asha (Asha), ELK account 'Asha.Rao'" in listed


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (("nobody", "N.Body"), "no account nobody"),
        (("asha", "elastic"), "cannot be linked (reserved_name)"),
        (("asha", "argus"), "cannot be linked (service_name)"),
        (("asha", "has:colon"), "cannot be linked (not_a_name)"),
        (("ravi", "Taken.Name"), "is already linked to asha"),
    ],
)
async def test_user_link_refuses_what_cannot_be_linked(
    rig: Rig, elk_on: Path, args: tuple[str, str], message: str
) -> None:
    assert (await run(elk_on, "user", "link", "asha", "Taken.Name"))[0] == 0
    code, out = await run(elk_on, "user", "link", *args)
    assert code in (1, 2)
    assert message in out
    assert "Traceback" not in out


async def test_user_link_will_not_link_twice_or_a_service_or_a_disabled_account(
    rig: Rig, elk_on: Path
) -> None:
    assert (await run(elk_on, "user", "link", "asha", "One.Name"))[0] == 0
    code, out = await run(elk_on, "user", "link", "asha", "Two.Name")
    assert code == 1
    assert "already linked to 'One.Name'" in out
    async with rig.owner.begin() as conn:
        await conn.execute(text("UPDATE users SET disabled = true WHERE username = 'ravi'"))
    assert "is disabled" in (await run(elk_on, "user", "link", "ravi", "Three.Name"))[1]


# --------------------------------------------------------------------------- sessions


async def test_sessions_end_all_ends_every_session_and_wipes_every_credential(
    rig: Rig, elk_on: Path
) -> None:
    people = [await rig.signed_in(f"user{k}.elk") for k in range(3)]
    assert await rig.scalar("SELECT count(*) FROM user_sessions WHERE credential IS NOT NULL") == 3
    code, out = await run(elk_on, "sessions", "end-all")
    assert code == 0
    assert "3 session(s) ended" in out
    for http, _ in people:
        assert (await http.get("/api/investigations")).status_code == 401
    assert await rig.scalar("SELECT count(*) FROM user_sessions WHERE credential IS NOT NULL") == 0
    assert await rig.scalar("SELECT count(DISTINCT ended_why) FROM user_sessions") == 1
    assert (
        await rig.scalar("SELECT count(*) FROM audit_events WHERE action = 'sessions.end_all'") == 1
    )
    assert "0 session(s) ended" in (await run(elk_on, "sessions", "end-all"))[1]


async def test_keygen_makes_a_secret_only_its_owner_can_read(tmp_path: Path, cli_env: Path) -> None:  # noqa: F811
    target = tmp_path / "web-secret"
    code, out = await run(cli_env, "sessions", "keygen", str(target))
    assert code == 0, out
    assert re.fullmatch(r"[0-9a-f]{64}\n", target.read_text())
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert target.read_text().strip() not in out  # never printed
    code, out = await run(cli_env, "sessions", "keygen", str(target))
    assert code == 1
    assert "never overwritten" in out


# --------------------------------------------------------------------------- break-glass


def password_of(out: str) -> str:
    found = re.search(r"one-time password:\s+(\S+)", out)
    assert found is not None, out
    return found.group(1)


async def test_the_break_glass_drill(rig: Rig, elk_on: Path) -> None:
    assert "break-glass is OFF" in (await run(elk_on, "break-glass", "status"))[1]
    # not at a terminal / ELK sign-in off / no outage / a short reason
    code, out = await run(elk_on, "break-glass", "on", text_in=REASON)
    assert code == 1
    assert "does not see an SIEM outage" in out
    assert "--override" in out
    code, out = await run(elk_on, "break-glass", "on", "--override", text_in="short\nOVERRIDE\n")
    assert code == 2
    assert "needs at least 10 characters" in out
    code, out = await run(elk_on, "break-glass", "on", "--override", text_in=REASON + "no\n")
    assert code == 1
    assert "not switched on" in out
    assert await rig.scalar("SELECT count(*) FROM break_glass") == 0
    # switched on, with the typed override
    code, out = await run(elk_on, "break-glass", "on", "--override", "--minutes", "90",
                    text_in=REASON + "OVERRIDE\n")  # fmt: skip
    assert code == 0, out
    password = password_of(out)
    assert "ON until" in out
    assert password not in await rig.scalar(
        "SELECT string_agg(details::text, ' ') FROM audit_events"
    )
    again_on = await run(elk_on, "break-glass", "on", "--override", text_in=REASON + "OVERRIDE\n")
    assert "is already on" in again_on[1]
    assert "ON until" in (await run(elk_on, "break-glass", "status"))[1]
    window = await rig.one(
        "SELECT reason, override, expires_at - enabled_at AS span FROM break_glass"
    )
    assert window.reason.startswith("the SIEM has been unreachable")
    assert window.override is True
    assert window.span.total_seconds() == 90 * 60
    # a wrong password counts; the right one signs in once
    http = rig.browser()
    assert (
        await rig.sign_in(http, breakglass.NAME, "not the one-time password")
    ).status_code == 401
    assert (await rig.sign_in(http, breakglass.NAME, password)).status_code == 303
    again = rig.browser()
    assert (await rig.sign_in(again, breakglass.NAME, password)).status_code == 401  # used up
    session = (await http.get("/api/v1/session")).json()
    assert {c["name"] for c in session["capabilities"]} == {"view", "review"}
    assert "Emergency (break-glass) session" in (await http.get("/")).text
    assert "view and review only" in (await http.get("/access")).text or "emergency" in (
        await http.get("/access")).text.lower()  # fmt: skip
    csrf = session["csrf_token"]
    assert (await rig.review(http, csrf)).status_code == 201
    assert (await rig.one("SELECT kibana_ok FROM review_events")).kibana_ok is False  # never sent
    assert (
        await http.post("/stepup", data={"password": password, "csrf_token": csrf})
    ).status_code == 403
    assert rig.lane.calls == []  # ELK was never asked
    signin = await rig.one("SELECT actor FROM audit_events WHERE action = 'break_glass.signin'")
    assert signin.actor == "user:break-glass"
    on = await rig.one("SELECT actor, details FROM audit_events WHERE action = 'break_glass.on'")
    assert on.actor.startswith("host:")
    assert on.details["override"] is True
    # switched off: the session ends, the account is disabled
    code, out = await run(elk_on, "break-glass", "off")
    assert code == 0
    assert "break-glass is OFF" in out
    assert (await http.get("/api/investigations")).status_code == 401
    assert await rig.scalar("SELECT disabled FROM users WHERE username = 'break-glass'") is True
    assert "break-glass is OFF" in (await run(elk_on, "break-glass", "status"))[1]
    late = rig.browser()
    assert (await rig.sign_in(late, breakglass.NAME, password)).status_code == 401


async def test_break_glass_can_do_nothing_but_view_and_review(rig: Rig, elk_on: Path) -> None:
    from fastapi import Depends

    from argus.web.capabilities import Capability
    from argus.web.deps import Surface, need

    for capability in (Capability.MANAGE_CASES, Capability.APPROVE, Capability.ADMIN,
                       Capability.REOPEN):  # fmt: skip
        path = f"/api/v1/_test/{capability.value}"
        rig.app.post(path, dependencies=[Depends(need(capability, Surface.V1, csrf=True))])(
            lambda: {"done": True}
        )
    code, out = await run(elk_on, "break-glass", "on", "--override", text_in=REASON + "OVERRIDE\n")
    assert code == 0, out
    http = rig.browser()
    assert (await rig.sign_in(http, breakglass.NAME, password_of(out))).status_code == 303
    csrf = (await http.get("/api/v1/session")).json()["csrf_token"]
    for capability in ("manage_cases", "approve", "admin", "reopen"):
        got = await http.post(f"/api/v1/_test/{capability}", headers={"X-CSRF-Token": csrf})
        assert got.status_code == 403, capability


async def test_an_expired_window_signs_nobody_in(
    rig: Rig, elk_on: Path, migrated_engine: AsyncEngine
) -> None:
    _, out = await run(elk_on, "break-glass", "on", "--override", text_in=REASON + "OVERRIDE\n")
    password = password_of(out)
    async with migrated_engine.begin() as conn:  # the window ran out (the owner may move time)
        await conn.execute(text("UPDATE break_glass SET expires_at = now() - interval '1 second',"
                                " enabled_at = now() - interval '1 hour'"))  # fmt: skip
    assert (await rig.sign_in(rig.browser(), breakglass.NAME, password)).status_code == 401
    assert "break-glass is OFF" in (await run(elk_on, "break-glass", "status"))[1]


async def test_a_confirmed_outage_needs_no_override(rig: Rig, elk_on: Path) -> None:
    http, _ = await rig.signed_in("asha.elk")
    rig.lane.down = "unreachable"
    rig.clock.advance(minutes=6)
    await http.get("/api/investigations")
    await rig.settle()  # the session could not be verified: an outage ARGUS itself saw
    code, out = await run(elk_on, "break-glass", "on", text_in=REASON)
    assert code == 0, out
    assert await rig.scalar("SELECT override FROM break_glass") is False


async def test_break_glass_is_off_in_local_mode(
    seeded: AsyncEngine,
    cli_env: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(web_cli, "_at_a_terminal", lambda: True)
    code, out = await run(cli_env, "break-glass", "on", text_in=REASON)
    assert code == 2
    assert "web.elk_signin is off" in out
    async with seeded.begin() as conn:  # even a row named break-glass cannot sign in locally
        await conn.execute(
            text(
                "INSERT INTO users (username, display_name, password_hash, kind) VALUES"
                " ('break-glass', 'B', :h, 'break_glass')"
            ),
            {"h": auth.hash_password(PASSWORD)},
        )
        assert (
            await auth.login(
                conn,
                "break-glass",
                PASSWORD,
                __import__("datetime").datetime.now(__import__("datetime").UTC),
            )
            is None
        )
