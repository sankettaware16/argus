"""Q-E3, the cutover at the terminal: ``argus identity link``, ``identity cutover status``,
``identity disable-local`` and ``enable-local``, with the web in local and in ELK mode (a fake
identity lane; the SIEM is never contacted).

Linked accounts sign in through ELK and keep their id and history; a disabled local password is
refused; disabling before an ELK sign-in is refused (also when the sign-in came before the link);
break-glass is untouched and listed apart; the break-glass drill works while ELK is unreachable;
first sign-ins raise no warning."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.identity import cli as identity_cli
from argus.web import auth, breakglass
from argus.web.app import create_app
from tests.integration.test_cli_db import cli_env  # noqa: F401
from tests.integration.web.conftest import BASE, NOW, SAME_ORIGIN, first_investigation, log_in
from tests.integration.web.conftest import PASSWORD as LOCAL_PASSWORD
from tests.integration.web.elk_rig import Rig
from tests.integration.web.test_elk_cli import (  # noqa: F401
    REASON,
    elk_on,
    password_of,
    rig,
    run,
)
from tests.unit.web.fake_identity import PASSWORD, REVIEWER

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def at_a_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(identity_cli, "_at_a_terminal", lambda: True)


async def link(elk_on: Path, user: str, elk: str) -> None:  # noqa: F811
    code, out = await run(elk_on, "identity", "link", user, "--elk", elk)
    assert code == 0, out


async def status(elk_on: Path) -> str:  # noqa: F811
    code, out = await run(elk_on, "identity", "cutover", "status")
    assert code == 0, out
    return out


def line_of(out: str, user: str) -> str:
    return next(line for line in out.splitlines() if line.startswith(f"  {user} "))


async def local_app_login(web_engine: AsyncEngine, user: str, password: str) -> int:
    """A sign-in at the web in local mode (the rollback), as its status code."""
    app = create_app(web_engine, clock=lambda: NOW)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=BASE, headers=SAME_ORIGIN) as http:
        got = await http.post("/api/login", json={"username": user, "password": password})
        return got.status_code


async def signed_in_elk(world: Rig, name: str) -> httpx.AsyncClient:
    world.lane.add(name, capabilities=REVIEWER)
    http = world.browser()
    assert (await world.sign_in(http, name)).status_code == 303
    return http


# --------------------------------------------------------------------------- link


async def test_identity_link_is_user_link(rig: Rig, elk_on: Path) -> None:  # noqa: F811
    before = await rig.one("SELECT id, password_hash FROM users WHERE username = 'asha'")
    code, out = await run(elk_on, "identity", "link", "asha", "--elk", "Asha.Rao")
    assert code == 0, out
    assert "stays until their first ELK sign-in has worked" in out
    row = await rig.one("SELECT id, elk_username, realm, password_hash FROM users"
                        " WHERE username = 'asha'")  # fmt: skip
    assert (row.id, row.elk_username, row.realm) == (before.id, "Asha.Rao", "native")
    assert row.password_hash == before.password_hash
    audit = await rig.one("SELECT actor, target_id, details FROM audit_events"
                          " WHERE action = 'user.link'")  # fmt: skip
    assert (audit.actor, audit.target_id, audit.details["elk"]) == ("cli", "asha", "Asha.Rao")
    # the older spelling is the same command
    assert (await run(elk_on, "user", "link", "ravi", "Ravi.Rao"))[0] == 0
    assert await rig.scalar("SELECT count(*) FROM audit_events WHERE action = 'user.link'") == 2


@pytest.mark.parametrize(
    ("args", "code", "message"),
    [
        (("nobody", "--elk", "N.Body"), 1, "no account nobody"),
        (("asha", "--elk", "elastic"), 2, "cannot be linked (reserved_name)"),
        (("asha", "--elk", "argus"), 2, "cannot be linked (service_name)"),
        (("ravi", "--elk", "Taken.Name"), 1, "is already linked to asha"),
        (("asha", "--elk", "Other.Name"), 1, "already linked to 'Taken.Name'"),
        (("asha",), 2, "Missing option '--elk'"),
    ],
)
async def test_identity_link_refuses_what_cannot_be_linked(
    rig: Rig,  # noqa: F811
    elk_on: Path,  # noqa: F811
    args: tuple[str, ...],
    code: int,
    message: str,
) -> None:
    await link(elk_on, "asha", "Taken.Name")
    got, out = await run(elk_on, "identity", "link", *args)
    assert (got, message in out) == (code, True), out
    assert "Traceback" not in out


async def test_a_service_and_the_break_glass_account_cannot_be_linked(
    rig: Rig,  # noqa: F811
    elk_on: Path,  # noqa: F811
) -> None:
    async with rig.owner.begin() as conn:
        await auth.add_user(conn, "argus-assistant", "Assistant", PASSWORD, kind="service")
    await run(elk_on, "break-glass", "on", "--override", text_in=REASON + "OVERRIDE\n")
    for name in ("argus-assistant", breakglass.NAME):
        code, out = await run(elk_on, "identity", "link", name, "--elk", "Some.One")
        assert code == 1
        assert "is not a person's account" in out
    assert await rig.scalar("SELECT count(*) FROM users WHERE elk_username IS NOT NULL") == 0


async def test_an_elk_sign_in_before_the_link_makes_a_separate_account(
    rig: Rig,  # noqa: F811
    elk_on: Path,  # noqa: F811
) -> None:
    """Why the runbook says: link first. The refusal names the account that holds the name."""
    await signed_in_elk(rig, "Asha.Rao")
    code, out = await run(elk_on, "identity", "link", "asha", "--elk", "Asha.Rao")
    assert code == 1
    assert "is already linked to asha.rao" in out
    assert await rig.scalar("SELECT elk_username FROM users WHERE username = 'asha'") is None


# --------------------------------------------------------------------------- the whole way


async def test_a_linked_account_signs_in_through_elk_and_keeps_its_history(
    rig: Rig,  # noqa: F811
    elk_on: Path,  # noqa: F811
    client: httpx.AsyncClient,
) -> None:
    # asha reviews as a local account, before anything is linked
    csrf = await log_in(client, "asha")
    first = await first_investigation(client)
    made = await client.post(
        f"/api/investigations/{first['id']}/reviews",
        json={"action": "note", "note": "seen before the cutover",
              "seen_review": first["latest_review"], "seen_version": first["version"]},
        headers={"X-CSRF-Token": csrf},
    )  # fmt: skip
    assert made.status_code == 201, made.text
    before = await rig.one("SELECT id FROM users WHERE username = 'asha'")
    held = await rig.scalar("SELECT count(*) FROM review_events WHERE user_id = :u", u=before.id)
    assert held == 1

    await link(elk_on, "asha", "Asha.Rao")
    http = await signed_in_elk(rig, "Asha.Rao")
    me = (await http.get("/api/v1/session")).json()["user"]
    assert (me["id"], me["username"]) == (before.id, "asha")  # the same person, the same row
    # the old note is still hers, and she can add a new one in her ELK session
    shown = (await http.get(f"/api/investigations/{first['id']}")).json()
    notes = [r for r in shown["reviews"] if r.get("note") == "seen before the cutover"]
    assert len(notes) == 1
    assert await rig.scalar("SELECT user_id FROM review_events WHERE note = :n",
                            n="seen before the cutover") == before.id  # fmt: skip
    csrf_elk = await rig.csrf(http)
    assert (await rig.review(http, csrf_elk)).status_code == 201
    assert await rig.scalar("SELECT count(DISTINCT user_id) FROM review_events") == 1
    # the trail names her by the same handle before and after: local login, then ELK login
    logins = await rig.scalar(
        "SELECT string_agg(details->>'mode', ',' ORDER BY id) FROM audit_events"
        " WHERE actor = 'user:asha' AND action = 'login'"
    )
    assert logins == "local,elk"
    out = await status(elk_on)
    assert "signed in through ELK" in line_of(out, "asha")
    assert "local password on" in line_of(out, "asha")

    # her local password goes; her id, her notes and the trail stay
    code, out = await run(elk_on, "identity", "disable-local", "asha")
    assert code == 0, out
    assert "the local password is off" in out
    after = await rig.one("SELECT id, password_hash, elk_username FROM users"
                          " WHERE username = 'asha'")  # fmt: skip
    assert (after.id, after.password_hash, after.elk_username) == (before.id, None, "Asha.Rao")
    assert await rig.scalar("SELECT count(*) FROM review_events WHERE user_id = :u",
                            u=before.id) == 2  # fmt: skip
    assert await rig.scalar("SELECT count(*) FROM audit_events WHERE actor = 'user:asha'") >= 3
    again = rig.browser()
    assert (await rig.sign_in(again, "Asha.Rao")).status_code == 303  # ELK still lets her in
    assert "signs in through ELK only" in line_of(await status(elk_on), "asha")


async def test_a_disabled_local_password_is_refused_and_its_sessions_end(
    rig: Rig,  # noqa: F811
    elk_on: Path,  # noqa: F811
    web_engine: AsyncEngine,
    client: httpx.AsyncClient,
) -> None:
    await log_in(client, "asha")  # an open local session
    assert await local_app_login(web_engine, "asha", LOCAL_PASSWORD) == 200
    await link(elk_on, "asha", "Asha.Rao")
    await signed_in_elk(rig, "Asha.Rao")
    assert (await run(elk_on, "identity", "disable-local", "asha"))[0] == 0
    # in local mode (the rollback) the old password is a wrong password, like any other
    assert await local_app_login(web_engine, "asha", LOCAL_PASSWORD) == 401
    assert await local_app_login(web_engine, "asha", "some other password") == 401
    assert await local_app_login(web_engine, "ravi", LOCAL_PASSWORD) == 200  # not linked: unchanged
    assert (await client.get("/api/investigations")).status_code == 401  # her local session ended
    assert (
        await rig.scalar(
            "SELECT string_agg(DISTINCT coalesce(s.ended_why, 'open'), ',') FROM user_sessions s"
            " JOIN users u ON u.id = s.user_id WHERE u.username = 'asha' AND s.mode = 'local'"
        )
        == "local_password_disabled"
    )  # both of her local sessions
    # in ELK mode a local password never signed anybody in; ravi's is not asked for either
    assert (await rig.sign_in(rig.browser(), "asha", LOCAL_PASSWORD)).status_code == 401
    # again: already off
    code, out = await run(elk_on, "identity", "disable-local", "asha")
    assert (code, "was already off" in out) == (0, True)
    assert await rig.scalar("SELECT count(*) FROM audit_events"
                            " WHERE action = 'user.local_disabled'") == 1  # fmt: skip


async def test_enable_local_is_the_way_back_for_a_rollback(
    rig: Rig,  # noqa: F811
    elk_on: Path,  # noqa: F811
    web_engine: AsyncEngine,
) -> None:
    await link(elk_on, "asha", "Asha.Rao")
    await signed_in_elk(rig, "Asha.Rao")
    code, out = await run(elk_on, "identity", "enable-local", "asha", text_in="newpass-12345\n"
                          "newpass-12345\n")  # fmt: skip
    assert code == 1  # still has one
    assert "still has a local password" in out
    assert (await run(elk_on, "identity", "disable-local", "asha"))[0] == 0
    short = await run(elk_on, "identity", "enable-local", "asha", text_in="short\nshort\n")
    assert (short[0], "at least 10 characters" in short[1]) == (1, True)
    code, out = await run(elk_on, "identity", "enable-local", "asha",
                          text_in="newpass-12345\nnewpass-12345\n")  # fmt: skip
    assert code == 0, out
    assert "newpass-12345" not in out
    assert await local_app_login(web_engine, "asha", "newpass-12345") == 200
    assert await local_app_login(web_engine, "asha", LOCAL_PASSWORD) == 401  # the old one is gone
    details = await rig.scalar("SELECT string_agg(details::text, ' ') FROM audit_events")
    assert "newpass-12345" not in details
    assert await rig.scalar("SELECT count(*) FROM audit_events"
                            " WHERE action = 'user.local_enabled'") == 1  # fmt: skip


async def test_enable_local_will_not_touch_a_service_or_a_disabled_account(
    rig: Rig,  # noqa: F811
    elk_on: Path,  # noqa: F811
) -> None:
    async with rig.owner.begin() as conn:
        await auth.add_user(conn, "argus-assistant", "Assistant", PASSWORD, kind="service")
        await conn.execute(text("UPDATE users SET disabled = true WHERE username = 'ravi'"))
    for name, message in (("argus-assistant", "not a person's account"), ("ravi", "is disabled"),
                          ("nobody", "no account nobody")):  # fmt: skip
        got = await run(elk_on, "identity", "enable-local", name,
                        text_in="newpass-12345\nnewpass-12345\n")  # fmt: skip
        assert (got[0], message in got[1]) == (1, True), got


# --------------------------------------------------------------------------- refusals


async def test_disabling_before_an_elk_sign_in_is_refused(rig: Rig, elk_on: Path) -> None:  # noqa: F811
    await link(elk_on, "asha", "Asha.Rao")
    code, out = await run(elk_on, "identity", "disable-local", "asha")
    assert code == 1
    assert "has not signed in through ELK since the link" in out
    assert "stays until that sign-in has worked" in out
    # somebody else's ELK sign-in is no proof for her
    await signed_in_elk(rig, "Ravi.Rao")
    assert (await run(elk_on, "identity", "disable-local", "asha"))[0] == 1
    # a refused ELK sign-in is none
    assert (await rig.sign_in(rig.browser(), "Asha.Rao", "wrong password")).status_code == 401
    assert (await run(elk_on, "identity", "disable-local", "asha"))[0] == 1
    hashed = await rig.scalar("SELECT password_hash IS NOT NULL FROM users WHERE username='asha'")
    assert hashed is True
    assert await rig.scalar("SELECT count(*) FROM audit_events"
                            " WHERE action = 'user.local_disabled'") == 0  # fmt: skip
    out = await status(elk_on)
    assert "waiting for their first ELK sign-in" in line_of(out, "asha")
    assert "local password on" in line_of(out, "asha")


async def test_an_elk_sign_in_from_before_the_link_is_no_proof(
    rig: Rig,  # noqa: F811
    elk_on: Path,  # noqa: F811
    migrated_engine: AsyncEngine,
) -> None:
    # the audit trail has an ELK login of 'asha' and the column says so, but both are older than
    # the link (only the owner can set the column; the trail is append-only)
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE users SET elk_first_signin_at = now() - interval '1 day'"
                                " WHERE username = 'asha'"))  # fmt: skip
        await conn.execute(text(
            "INSERT INTO audit_events (actor, action, details)"
            " VALUES ('user:asha', 'login', '{\"mode\": \"elk\"}')"))  # fmt: skip
    await link(elk_on, "asha", "Asha.Rao")
    code, out = await run(elk_on, "identity", "disable-local", "asha")
    assert code == 1
    assert "has not signed in through ELK since the link" in out
    # a local login after the link is none either
    async with rig.owner.begin() as conn:
        await conn.execute(text(
            "INSERT INTO audit_events (actor, action, details)"
            " VALUES ('user:asha', 'login', '{\"mode\": \"local\"}')"))  # fmt: skip
    assert (await run(elk_on, "identity", "disable-local", "asha"))[0] == 1
    # a real one after the link is
    await signed_in_elk(rig, "Asha.Rao")
    assert (await run(elk_on, "identity", "disable-local", "asha"))[0] == 0


async def test_a_link_missing_from_the_trail_is_refused(
    rig: Rig,  # noqa: F811
    elk_on: Path,  # noqa: F811
    migrated_engine: AsyncEngine,
) -> None:
    async with migrated_engine.begin() as conn:  # linked by hand, not by the command
        await conn.execute(text("UPDATE users SET elk_username = 'Asha.Rao', realm = 'native'"
                                " WHERE username = 'asha'"))  # fmt: skip
    await signed_in_elk(rig, "Asha.Rao")
    code, out = await run(elk_on, "identity", "disable-local", "asha")
    assert code == 1
    assert "is not in the audit trail" in out
    assert "no link: argus" not in out


async def test_an_unlinked_account_is_not_disabled(rig: Rig, elk_on: Path) -> None:  # noqa: F811
    code, out = await run(elk_on, "identity", "disable-local", "ravi")
    assert code == 1
    assert "is not linked to an ELK account" in out
    assert "argus identity link ravi --elk" in out
    assert (await run(elk_on, "identity", "disable-local", "nobody"))[0] == 1


async def test_nothing_is_disabled_while_elk_sign_in_is_off(
    rig: Rig,  # noqa: F811
    elk_on: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await link(elk_on, "asha", "Asha.Rao")
    await signed_in_elk(rig, "Asha.Rao")
    monkeypatch.setenv("ARGUS_WEB__ELK_SIGNIN", "false")  # this host is in local mode again
    monkeypatch.delenv("ARGUS_WEB__SECRET_FILE")
    monkeypatch.delenv("ARGUS_WEB__DATABASE_ROLE")
    code, out = await run(elk_on, "identity", "disable-local", "asha")
    assert code == 1
    assert "web.elk_signin is off here" in out
    assert await rig.scalar("SELECT password_hash IS NOT NULL FROM users"
                            " WHERE username = 'asha'") is True  # fmt: skip
    assert "ELK sign-in is OFF" in await status(elk_on)


async def test_the_database_itself_keeps_a_hash_until_an_elk_sign_in_worked(
    rig: Rig,  # noqa: F811
    elk_on: Path,  # noqa: F811
) -> None:
    from sqlalchemy.exc import IntegrityError

    await link(elk_on, "asha", "Asha.Rao")
    with pytest.raises(IntegrityError, match="password_or_elk"):
        async with rig.owner.begin() as conn:  # not even a bug in the command could do this
            await conn.execute(text("UPDATE users SET password_hash = NULL"
                                    " WHERE username = 'asha'"))  # fmt: skip


# --------------------------------------------------------------------------- break-glass


async def test_break_glass_is_never_disabled_and_is_listed_apart(
    rig: Rig,  # noqa: F811
    elk_on: Path,  # noqa: F811
) -> None:
    assert "no account yet" in await status(elk_on)
    code, out = await run(elk_on, "break-glass", "on", "--override", text_in=REASON + "OVERRIDE\n")
    assert code == 0, out
    one_time = password_of(out)
    hash_before = await rig.scalar("SELECT password_hash FROM users WHERE username = 'break-glass'")
    code, out = await run(elk_on, "identity", "disable-local", breakglass.NAME)
    assert code == 1
    assert "never disabled by the cutover" in out
    assert (await run(elk_on, "identity", "enable-local", breakglass.NAME,
                      text_in="newpass-12345\nnewpass-12345\n"))[0] == 1  # fmt: skip
    row = await rig.one("SELECT disabled, password_hash, kind FROM users"
                        " WHERE username = 'break-glass'")  # fmt: skip
    assert (row.disabled, row.password_hash, row.kind) == (False, hash_before, "break_glass")
    out = await status(elk_on)
    assert "break-glass" not in "\n".join(
        line for line in out.splitlines() if line.startswith("  ") and "ELK" in line
    )  # not among the people
    glass = next(line for line in out.splitlines() if line.startswith("  break-glass:"))
    assert "ON until" in glass
    assert "never used" in glass
    assert "Break-glass (never disabled here" in out
    # the one-time password still works after every cutover command
    assert (await run(elk_on, "identity", "link", "asha", "--elk", "Asha.Rao"))[0] == 0
    assert (await rig.sign_in(rig.browser(), breakglass.NAME, one_time)).status_code == 303


async def test_the_break_glass_drill_while_elk_is_unreachable(
    rig: Rig,  # noqa: F811
    elk_on: Path,  # noqa: F811
) -> None:
    """The drill of the runbook (elk-signin.md, "The cutover drill"), step by step."""
    await link(elk_on, "asha", "Asha.Rao")
    asha = await signed_in_elk(rig, "Asha.Rao")
    assert (await run(elk_on, "identity", "disable-local", "asha"))[0] == 0
    # 1. ELK cannot be asked: nobody signs in through it, and ARGUS sees the outage
    rig.lane.down = "unreachable"
    assert (await rig.sign_in(rig.browser(), "Asha.Rao")).status_code == 503
    rig.clock.advance(minutes=6)
    await asha.get("/api/investigations")
    await rig.settle()
    # 2. at the host, with the reason typed: no override is needed, the outage is confirmed
    code, out = await run(elk_on, "break-glass", "on", text_in=REASON)
    assert code == 0, out
    asked = len(rig.lane.calls)
    # 3. the one-time password signs in once, while ELK is still down
    glass = rig.browser()
    assert (await rig.sign_in(glass, breakglass.NAME, password_of(out))).status_code == 303
    assert "Emergency (break-glass) session" in (await glass.get("/access")).text
    csrf = await rig.csrf(glass)
    assert (await rig.review(glass, csrf)).status_code == 201  # view and review
    assert (await rig.one("SELECT kibana_ok FROM review_events")).kibana_ok is False
    assert len(rig.lane.calls) == asked  # the drill asked ELK nothing
    # 4. the cutover list shows it apart, in use, and Asha's account is as the cutover left it
    out = await status(elk_on)
    assert "ON until" in out
    assert "last sign-in" in out
    assert "signs in through ELK only" in line_of(out, "asha")
    # 5. off: the session ends, the account is disabled again, nobody else was touched
    assert (await run(elk_on, "break-glass", "off"))[0] == 0
    assert (await glass.get("/api/investigations")).status_code == 401
    rig.lane.down = None
    assert (await rig.sign_in(rig.browser(), "Asha.Rao")).status_code == 303
    assert await rig.scalar("SELECT password_hash IS NULL FROM users"
                            " WHERE username = 'asha'") is True  # fmt: skip
    drill = await rig.scalar("SELECT string_agg(action, ',' ORDER BY id) FROM audit_events"
                             " WHERE action LIKE 'break_glass.%'")  # fmt: skip
    assert drill == "break_glass.on,break_glass.signin,break_glass.off"


# --------------------------------------------------------------------------- status, first sign-ins


async def test_status_lists_every_account_with_the_reason_it_stays_local(
    rig: Rig,  # noqa: F811
    elk_on: Path,  # noqa: F811
    migrated_engine: AsyncEngine,
) -> None:
    async with rig.owner.begin() as conn:
        await auth.add_user(conn, "argus-assistant", "Assistant", PASSWORD, kind="service")
        await auth.add_user(conn, "leaver", "Leaver", PASSWORD)
        await auth.add_user(conn, "waits", "Waits", PASSWORD)
        await conn.execute(text("UPDATE users SET disabled = true WHERE username = 'leaver'"))
    await link(elk_on, "asha", "Asha.Rao")
    await link(elk_on, "waits", "Waits.Elk")
    await signed_in_elk(rig, "Asha.Rao")
    await signed_in_elk(rig, "Native.Elk")  # an account that began with ELK: no hash at all
    out = await status(elk_on)
    assert out.startswith("ELK sign-in is ON")
    assert "5 account(s): 1 ELK only, 1 ready to switch off, 1 waiting for a first ELK" in out
    assert "1 not linked, 1 disabled" in out
    asha = line_of(out, "asha")
    assert "ELK Asha.Rao" in asha
    assert "linked yes" in asha
    assert "local password on" in asha
    assert "IST" in asha
    assert "argus identity disable-local asha" in asha
    ravi = line_of(out, "ravi")
    assert "linked no" in ravi
    assert "ELK sign-in not yet" in ravi
    assert "argus identity link ravi --elk <name>" in ravi
    assert "waiting for their first ELK sign-in" in line_of(out, "waits")
    assert "disabled" in line_of(out, "leaver")
    native = line_of(out, "native.elk")
    assert "local password off" in native
    assert "signs in through ELK only" in native
    assert "argus-assistant (service): a service identity: it never signs in" in out
    assert "Break-glass (never disabled here" in out
    # the same list is the evidence of the production step: it reads, it writes nothing
    assert await rig.scalar("SELECT count(*) FROM audit_events WHERE action LIKE 'user.local%'"
                            ) == 0  # fmt: skip


async def test_first_elk_sign_ins_raise_no_warning(rig: Rig, elk_on: Path) -> None:  # noqa: F811
    await link(elk_on, "asha", "Asha.Rao")
    rig.lane.add("Asha.Rao", capabilities=REVIEWER)
    rig.lane.add("New.Person", capabilities=REVIEWER)
    for name in ("Asha.Rao", "New.Person"):  # a linked account's first sign-in, and a new one's
        http = rig.browser()
        made = await rig.sign_in(http, name)
        assert made.status_code == 303, made.text
        for path in ("/access",):
            page = await http.get(path)
            assert page.status_code == 200, path
            assert 'role="alert"' not in page.text, path
            assert "cannot confirm your access" not in page.text, path
            assert "Emergency (break-glass)" not in page.text, path
    assert await rig.scalar("SELECT count(*) FROM audit_events"
                            " WHERE outcome <> 'success' OR action IN ('signin.alarm',"
                            " 'session.denied', 'session.suspected_outage')") == 0  # fmt: skip
    assert await rig.scalar("SELECT count(*) FROM user_sessions WHERE unverified_since IS NOT NULL"
                            ) == 0  # fmt: skip
    assert await rig.scalar("SELECT count(*) FROM identity_checks WHERE outcome <> 'ok'"
                            ) == 0  # fmt: skip
