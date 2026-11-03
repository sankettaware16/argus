"""Q-E2: ELK sign-in end to end with a fake identity lane (plan §7.2): every login path through
one provider and one throttle; accounts made, linked and frozen; custody of the credential; the
throttle counting only ELK's refusals; the same answer after the same time for every failure."""

from __future__ import annotations

import asyncio
import hashlib
import json
import statistics
import time
from collections.abc import AsyncIterator
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web import throttle
from argus.web.custody import Custody
from tests.integration.web.conftest import BASE
from tests.integration.web.conftest import PASSWORD as LOCAL_PASSWORD
from tests.integration.web.elk_rig import SECRET, Rig, form_token, make_rig
from tests.unit.web.fake_identity import ANALYST, PASSWORD, REVIEWER, VIEWER, uid

pytestmark = pytest.mark.integration


@pytest.fixture
async def rig(seeded: AsyncEngine, web_engine: AsyncEngine) -> AsyncIterator[Rig]:
    made = await make_rig(web_engine, seeded)
    try:
        yield made
    finally:
        await made.aclose()


async def counted(rig: Rig) -> int:
    return int(await rig.scalar(
        "SELECT count(*) FROM audit_events WHERE action IN ('login', 'stepup')"
        " AND outcome = 'denied' AND details->>'counted' = 'true'"
    ))  # fmt: skip


async def wrong(
    rig: Rig,
    http: httpx.AsyncClient,
    name: str,
    password: str = "not it at all",  # noqa: S107
) -> int:
    return (await rig.sign_in(http, name, password)).status_code


# --------------------------------------------------------------------------- the account


async def test_a_person_signs_in_with_their_elk_account(rig: Rig) -> None:
    http, _ = await rig.signed_in("Asha.Rao", full_name="Asha Rao", email="asha@example.org")
    session = (await http.get("/api/v1/session")).json()
    assert session["mode"] == "elk"
    assert {c["name"] for c in session["capabilities"]} == {"view", "see_logs", "review"}
    row = await rig.one(
        "SELECT username, display_name, email, elk_username, realm, kind, password_hash,"
        " argus_uid, elk_first_signin_at, last_good_check_at FROM users"
        " WHERE elk_username = 'Asha.Rao'"
    )
    assert (row.username, row.display_name, row.email) == (
        "asha.rao",
        "Asha Rao",
        "asha@example.org",
    )
    assert (row.elk_username, row.realm, row.kind) == ("Asha.Rao", "native", "person")
    assert row.password_hash is None  # no local password: ELK is the only proof
    assert row.argus_uid == rig.lane.accounts["Asha.Rao"].argus_uid
    assert row.elk_first_signin_at is not None
    stored = await rig.one("SELECT mode, capabilities, no_custody, credential FROM user_sessions")
    assert stored.mode == "elk"
    assert sorted(stored.capabilities) == ["review", "see_logs", "view"]
    assert stored.credential is not None
    assert not stored.no_custody
    check = await rig.one("SELECT outcome, provider, purpose FROM identity_checks")
    assert tuple(check) == ("ok", "elk", "signin")
    login = await rig.one("SELECT actor, details->>'mode' FROM audit_events WHERE action = 'login'")
    assert tuple(login) == ("user:asha.rao", "elk")


async def test_the_handle_is_arguss_own_and_never_a_service_name(rig: Rig) -> None:
    rig.lane.add("Asha.Rao")
    rig.lane.add("ASHA.RAO")  # another ELK name with the same handle
    rig.lane.add("9lives")
    rig.lane.add("x")
    rig.lane.add("A B C")
    for name in rig.lane.accounts:
        http = rig.browser()
        assert (await rig.sign_in(http, name)).status_code == 303, name
    handles = {
        r[0]
        for r in await rig_rows(
            rig, "SELECT username FROM users WHERE kind = 'person' AND elk_username IS NOT NULL"
        )
    }
    assert handles == {"asha.rao", "asha.rao-2", "u9lives", "x-2", "a-b-c"}


async def rig_rows(rig: Rig, sql: str) -> list[tuple[object, ...]]:
    async with rig.owner.connect() as conn:
        return [tuple(r) for r in await conn.execute(text(sql))]


async def test_every_login_path_goes_through_the_one_provider(rig: Rig) -> None:
    rig.lane.add("asha.elk")
    http = rig.browser()
    gone = await http.post("/api/login", json={"username": "asha.elk", "password": PASSWORD})
    assert gone.status_code == 410
    assert "sign in at /signin" in gone.json()["detail"]
    assert rig.lane.calls == []  # /api/login asked nobody
    form = await http.post("/login", data={"username": "asha.elk", "password": PASSWORD})
    assert (form.status_code, form.headers["location"]) == (303, "/")  # the old form still works
    assert [r for r, *_ in rig.lane.calls] == ["whoami"]
    assert (await http.get("/api/v1/session")).json()["mode"] == "elk"
    again = rig.browser()
    assert (await rig.sign_in(again, "asha.elk")).status_code == 303
    assert len(rig.lane.calls) == 2


async def test_local_passwords_do_not_sign_in_while_elk_sign_in_is_on(rig: Rig) -> None:
    http = rig.browser()
    got = await rig.sign_in(http, "asha", LOCAL_PASSWORD)  # a local account of the seed
    assert got.status_code == 401  # the lane (ELK) said no: asha is not an ELK account here
    assert rig.lane.requests() == 1


async def test_the_old_sessions_of_local_mode_are_no_session_in_elk_mode(rig: Rig) -> None:
    async with rig.owner.begin() as conn:
        await conn.execute(text(
            "INSERT INTO user_sessions (token_hash, user_id, csrf_token, last_seen_at, expires_at)"
            " SELECT :h, id, 'c', now(), now() + interval '1 hour' FROM users"
            " WHERE username = 'asha'"
        ), {"h": hashlib.sha256(b"old-token").hexdigest()})  # fmt: skip
    http = rig.browser()
    http.cookies.set("argus_session", "old-token")
    assert (await http.get("/api/v1/session")).status_code == 401


# --------------------------------------------------------------------------- refusals


@pytest.mark.parametrize(
    "name",
    ["elastic", "Elastic", "kibana_system", "remote_monitoring_user", "argus", "ARGUS",
     "argus-assistant", "Argus-Assistant", "kibana.service_user", "has:colon", " lead", "x" * 509],
)  # fmt: skip
async def test_reserved_and_service_names_are_refused_with_no_request(rig: Rig, name: str) -> None:
    http = rig.browser()
    got = await rig.sign_in(http, name)
    assert got.status_code == 401
    assert "Wrong name or password." in got.text
    assert rig.lane.calls == []
    assert await counted(rig) == 0


async def test_the_longest_elk_name_signs_in(rig: Rig) -> None:
    name = "n" * 507  # ELK holds names up to 507 characters; ARGUS's own handle is shorter
    rig.lane.add(name)
    assert (await rig.sign_in(rig.browser(), name)).status_code == 303
    assert (
        await rig.scalar("SELECT username FROM users WHERE elk_username = :n", n=name) == "n" * 28
    )


async def test_a_short_password_is_refused_with_no_request(rig: Rig) -> None:
    rig.lane.add("asha.elk")
    http = rig.browser()
    assert (await rig.sign_in(http, "asha.elk", "short")).status_code == 401
    assert rig.lane.calls == []


@pytest.mark.parametrize("who", ["wrong", "unknown", "disabled", "other"])
async def test_every_failure_reads_alike(rig: Rig, who: str) -> None:
    rig.lane.add("known")
    rig.lane.add("off", enabled=False)
    rig.lane.add("viewer", capabilities=frozenset())  # right password, no view: refused by ARGUS
    http = rig.browser()
    name = {"wrong": "known", "unknown": "nobody-here", "disabled": "off", "other": "viewer"}[who]
    password = PASSWORD if who == "other" else "not the password"
    got = await rig.sign_in(http, name, password)
    assert (got.status_code, "Wrong name or password." in got.text) == (401, True)


async def test_superusers_and_admin_accounts_are_refused_after_a_right_password(rig: Rig) -> None:
    rig.lane.add("boss", admin=True)
    http = rig.browser()
    got = await rig.sign_in(http, "boss")
    assert got.status_code == 401
    assert "Wrong name or password." in got.text
    row = await rig.one("SELECT details->>'why', details->>'counted' FROM audit_events"
                        " WHERE action = 'login' AND outcome = 'denied'")  # fmt: skip
    assert tuple(row) == ("admin_account", "false")  # recorded, never counted
    assert await rig.scalar("SELECT count(*) FROM users WHERE elk_username = 'boss'") == 0


async def test_failures_are_recorded_by_hmac_never_by_the_name_typed(rig: Rig) -> None:
    http = rig.browser()
    await wrong(rig, http, "Secret.Typed.Name")
    blob = await rig.scalar("SELECT string_agg(details::text, ' ') FROM audit_events"
                            " WHERE action = 'login'")  # fmt: skip
    assert "Secret.Typed.Name" not in blob
    assert "secret.typed" not in blob.lower()
    assert Custody(bytes.fromhex(SECRET)).name_hmac("Secret.Typed.Name") in blob


# --------------------------------------------------------------------------- the throttle


async def test_only_elks_refusals_count(rig: Rig) -> None:
    rig.lane.add("asha.elk")
    rig.lane.add("viewer", capabilities=frozenset())
    http = rig.browser()
    rig.lane.down = "unreachable"  # ARGUS could not ask: never counted
    for _ in range(10):
        assert await wrong(rig, http, "asha.elk", PASSWORD) == 503
    rig.lane.down = None
    for _ in range(10):  # ARGUS refuses after a right password: never counted
        assert await wrong(rig, http, "viewer", PASSWORD) == 401
    for _ in range(10):  # ARGUS's own rules: no request, never counted
        assert await wrong(rig, http, "elastic", PASSWORD) == 401
    assert await counted(rig) == 0
    assert (await rig.sign_in(http, "asha.elk")).status_code == 303  # not locked at all


async def test_five_refusals_lock_a_name_and_the_locked_attempts_count_for_nothing(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    rig.lane.add("asha.elk")
    http = rig.browser()
    for _ in range(throttle.NAME_LIMIT):
        assert await wrong(rig, http, "asha.elk") == 401
    for _ in range(12):  # one request every few minutes used to keep a name locked for ever
        assert (await rig.sign_in(http, "asha.elk")).status_code == 429
    assert await counted(rig) == 5
    asked = rig.lane.requests()
    assert asked == 5  # the locked attempts asked nobody
    monkeypatch.setattr(throttle, "WINDOW", timedelta(seconds=1))
    await asyncio.sleep(1.2)  # the window passes
    assert (await rig.sign_in(http, "asha.elk")).status_code == 303


async def test_a_device_cookie_from_an_earlier_good_sign_in_passes_a_locked_name(rig: Rig) -> None:
    rig.lane.add("asha.elk")
    mine = rig.browser()
    assert (await rig.sign_in(mine, "asha.elk")).status_code == 303  # the device cookie is set
    assert any(
        c.startswith("argus_device")
        for c in mine.cookies.jar.__iter__().__class__.__name__
        and [c.name for c in mine.cookies.jar]
    )
    other = rig.browser()
    for _ in range(throttle.NAME_LIMIT):
        assert await wrong(rig, other, "asha.elk") == 401  # someone else guesses
    stranger = rig.browser()
    assert (await rig.sign_in(stranger, "asha.elk")).status_code == 429  # locked for them
    mine.cookies.delete("argus_session")
    assert (
        await rig.sign_in(mine, "asha.elk")
    ).status_code == 303  # not for the person's own browser


async def test_a_device_cookie_of_another_person_passes_nothing(rig: Rig) -> None:
    rig.lane.add("asha.elk")
    rig.lane.add("ravi.elk")
    ravi = rig.browser()
    assert (await rig.sign_in(ravi, "ravi.elk")).status_code == 303
    for _ in range(throttle.NAME_LIMIT):
        await wrong(rig, rig.browser(), "asha.elk")
    ravi.cookies.delete("argus_session")
    assert (await rig.sign_in(ravi, "asha.elk")).status_code == 429


async def test_twenty_refusals_from_one_client_lock_the_client(rig: Rig) -> None:
    rig.lane.add("asha.elk")
    spray = rig.browser("10.1.1.1")
    for k in range(throttle.CLIENT_LIMIT):
        assert await wrong(rig, spray, f"someone{k}") == 401
    assert (await rig.sign_in(spray, "asha.elk")).status_code == 429
    calm = rig.browser("10.1.1.2")
    assert (await rig.sign_in(calm, "asha.elk")).status_code == 303  # another client is not held


async def test_sixty_refused_checks_an_hour_leave_device_cookie_browsers_and_an_alarm(
    rig: Rig,
) -> None:
    rig.lane.add("asha.elk")
    mine = rig.browser("10.2.0.1")
    assert (await rig.sign_in(mine, "asha.elk")).status_code == 303
    for client in range(4):  # four clients, fifteen refusals each: no client lock yet
        spray = rig.browser(f"10.3.0.{client}")
        for k in range(15):
            assert await wrong(rig, spray, f"x{client}-{k}") == 401
    assert await counted(rig) == 60
    stranger = rig.browser("10.4.0.1")
    assert (await rig.sign_in(stranger, "asha.elk")).status_code == 429
    mine.cookies.delete("argus_session")
    assert (await rig.sign_in(mine, "asha.elk")).status_code == 303  # device cookies may try
    alarms = await rig.one("SELECT count(*), max(details->>'refused_checks_in_an_hour')"
                           " FROM audit_events WHERE action = 'signin.alarm'")  # fmt: skip
    assert tuple(alarms) == (1, "60")  # raised once, at the 60th


async def test_waits_between_checks_double_and_are_not_counted(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    rig = await make_rig(web_engine, seeded, signin_delay_s=60)
    try:
        rig.lane.add("asha.elk")
        http = rig.browser()
        assert await wrong(rig, http, "asha.elk") == 401
        assert await wrong(rig, http, "asha.elk") == 401  # a typo is free: no wait after one
        assert await wrong(rig, http, "asha.elk") == 429  # the second asks for a minute
        assert await counted(rig) == 2
        assert rig.lane.requests() == 2
    finally:
        await rig.aclose()


async def test_step_up_failures_count_and_three_end_the_session(rig: Rig) -> None:
    http, csrf = await rig.signed_in("asha.elk")
    for n in range(3):
        got = await http.post("/stepup", data={"password": "wrong wrong wrong", "csrf_token": csrf})
        assert got.status_code == (401 if n < 2 else 303)
    assert (await http.get("/api/v1/session")).status_code == 401
    assert await counted(rig) == 3
    # they were refused by ELK (the lane denied them), and voided the person's approvals
    assert await rig.scalar("SELECT count(*) FROM identity_checks WHERE outcome = 'denied'") == 3


async def test_a_step_up_that_works_renews_the_snapshot(rig: Rig) -> None:
    http, csrf = await rig.signed_in("asha.elk")
    rig.lane.accounts["asha.elk"].capabilities = ANALYST
    rig.clock.advance(minutes=1)
    got = await http.post(
        "/stepup", data={"password": PASSWORD, "csrf_token": csrf, "next": "/rules"}
    )
    assert (got.status_code, got.headers["location"]) == (303, "/rules")
    names = {c["name"] for c in (await http.get("/api/v1/session")).json()["capabilities"]}
    assert "manage_cases" in names
    assert (await http.get("/api/v1/session")).json()["stepped_up_at"] is not None


# --------------------------------------------------------------------------- one answer, one time


async def test_every_failure_takes_the_same_time(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    """The p95 of the time to answer differs by at most 50 ms between a name that does not exist,
    a wrong password, a name ARGUS refuses before any request, and a locked name (200 tries each,
    in batches), with the padded answer at 0.2 s."""
    rig = await make_rig(web_engine, seeded, failure_delay_s=0.2)
    try:
        for k in range(201):
            rig.lane.add(f"known{k}")
        custody = Custody(bytes.fromhex(SECRET))
        async with rig.owner.begin() as conn:  # 200 names, each locked by five counted refusals
            for k in range(201):
                for _ in range(throttle.NAME_LIMIT):
                    await conn.execute(
                        text("INSERT INTO audit_events (actor, action, outcome, details)"
                             " VALUES ('web', 'login', 'denied', CAST(:d AS jsonb))"),
                        {"d": json.dumps({"name_hmac": custody.name_hmac(f"locked{k}"),
                                          "client": "10.9.9.9", "counted": True})},
                    )  # fmt: skip

        async def timed(client: httpx.AsyncClient, name: str, password: str) -> float:
            form = await client.get("/signin")
            data = {"username": name, "password": password, "signin_token": form_token(form.text)}
            began = time.perf_counter()
            got = await client.post("/signin", data=data)
            assert got.status_code in (401, 429), got.text
            return time.perf_counter() - began

        makers = {
            "unknown": lambda k: (f"nobody{k}", "not a password 1"),
            "wrong": lambda k: (f"known{k}", "not the password"),
            # three names ARGUS refuses, one per job of a batch: two sign-ins for one name at
            # once would be answered "busy" (Q-E2 review F11), which is not what is timed here
            "refused": lambda k: (
                ("elastic", "kibana", "kibana_system")[k % 3],
                "not a password 1",
            ),
            "locked": lambda k: (f"locked{k}", PASSWORD),
        }
        classes: dict[str, list[float]] = {name: [] for name in makers}
        for batch in range(67):  # every batch holds three of each kind, so a busy machine
            jobs = [(name, batch * 3 + i) for name in makers for i in range(3)]  # hits all alike
            clients = [rig.browser(f"10.8.{batch}.{n}") for n in range(len(jobs))]
            pairs = zip(clients, jobs, strict=True)
            took = await asyncio.gather(*[
                timed(client, *makers[name](k)) for client, (name, k) in pairs
            ])  # fmt: skip
            for (name, _), seconds in zip(jobs, took, strict=True):
                classes[name].append(seconds)
        assert all(len(v) == 201 for v in classes.values())
        p95 = {name: statistics.quantiles(values, n=20)[18] for name, values in classes.items()}
        assert min(min(v) for v in classes.values()) >= 0.2 - 0.01  # none answered early
        assert max(p95.values()) - min(p95.values()) <= 0.050, p95
    finally:
        await rig.aclose()


# --------------------------------------------------------------------------- custody


async def test_no_credential_is_kept_anywhere_a_dump_or_the_secret_could_find_it(
    rig: Rig, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("DEBUG")
    password = "my very own ELK password 9"
    http, csrf = await rig.signed_in("asha.elk", password=password)
    token = http.cookies.get("argus_session")
    assert token is not None
    await http.post("/stepup", data={"password": password, "csrf_token": csrf})
    await rig.review(http, csrf)
    # every table of the database, as text
    tables = [r[0] for r in await rig_rows(
        rig, "SELECT tablename FROM pg_tables WHERE schemaname = 'public'")]  # fmt: skip
    everything = ""
    for table in tables:
        everything += str(await rig_rows(rig, f"SELECT to_jsonb(t) FROM {table} t"))  # noqa: S608
    encodings = [password, password.encode().hex(), password.encode().hex().upper()]
    import base64

    encodings += [base64.b64encode(password.encode()).decode(), "".join(password.split())]
    assert not [e for e in encodings if e in everything]
    assert password not in caplog.text
    assert password not in repr(rig.lane.calls)
    # what a dump holds opens with nothing it has: the seal and the token's hash
    sealed = await rig.scalar("SELECT credential FROM user_sessions WHERE ended_at IS NULL")
    row = await rig.one("SELECT token_hash, user_id FROM user_sessions WHERE ended_at IS NULL")
    custody = Custody(bytes.fromhex(SECRET))
    args = {"token_hash": row.token_hash, "user_id": row.user_id, "elk_username": "asha.elk"}
    assert custody.unseal(bytes(sealed), token=row.token_hash, **args) is None  # the dump alone
    assert Custody(bytes(32)).unseal(bytes(sealed), token=token, **args) is None  # the token alone
    assert custody.unseal(bytes(sealed), token=token, **args).get_secret_value() == password  # both


async def test_logging_out_wipes_the_credential(rig: Rig) -> None:
    http, csrf = await rig.signed_in("asha.elk")
    assert await rig.scalar("SELECT credential IS NOT NULL FROM user_sessions") is True
    out = await http.post("/logout", data={"csrf_token": csrf})
    assert out.status_code == 303
    row = await rig.one("SELECT credential, ended_why FROM user_sessions")
    assert tuple(row) == (None, "signed_out")


async def test_a_session_that_lapsed_is_wiped_by_the_next_sign_in(rig: Rig) -> None:
    await rig.signed_in("asha.elk")
    rig.clock.advance(hours=9)  # past the absolute end; the cookie never came back
    other = rig.browser()
    rig.lane.add("ravi.elk")
    assert (await rig.sign_in(other, "ravi.elk")).status_code == 303
    assert (
        await rig.scalar(
            "SELECT credential IS NULL FROM user_sessions s JOIN users u ON u.id = s.user_id"
            " WHERE u.elk_username = 'asha.elk'"
        )
        is True
    )


async def test_an_admin_account_keeps_no_copy_of_its_password(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    lane_rig = await make_rig(web_engine, seeded)
    try:
        lane_rig.lane.admin_accounts_allowed = True  # identity.admin_accounts: without_custody
        http, csrf = await lane_rig.signed_in("root.like", admin=True, capabilities=ANALYST)
        row = await lane_rig.one("SELECT credential, no_custody FROM user_sessions")
        assert tuple(row) == (None, True)
        assert (await lane_rig.review(http, csrf)).status_code == 201  # inside 30 s of sign-in
        lane_rig.clock.advance(seconds=31)
        refused = await lane_rig.review(http, csrf)
        assert refused.status_code == 403
        assert refused.json()["detail"].startswith("ARGUS keeps no copy of your password")
        assert lane_rig.lane.requests() == 1  # nothing could be re-checked
        got = await http.post("/stepup", data={"password": PASSWORD, "csrf_token": csrf})
        assert got.status_code == 303
        assert (await lane_rig.review(http, csrf)).status_code == 201  # a step-up renews it
    finally:
        await lane_rig.aclose()


# --------------------------------------------------------------------------- who is who


async def test_a_new_argus_uid_behind_a_known_name_is_a_new_person(rig: Rig) -> None:
    http, _ = await rig.signed_in("asha.elk")
    old = await rig.scalar("SELECT id FROM users WHERE elk_username = 'asha.elk'")
    rig.lane.accounts["asha.elk"].argus_uid = uid()  # the ELK account was deleted and re-made
    again = rig.browser()
    assert (await rig.sign_in(again, "asha.elk")).status_code == 303
    new = await rig.scalar(
        "SELECT id FROM users WHERE elk_username = 'asha.elk' AND frozen_at IS NULL"
    )
    assert new != old
    frozen = await rig.one("SELECT disabled, frozen_at IS NOT NULL FROM users WHERE id = :i", i=old)
    assert tuple(frozen) == (True, True)
    assert (await http.get("/api/v1/session")).status_code == 401  # the old person's sessions end
    handles = {r[0] for r in await rig_rows(rig, "SELECT username FROM users WHERE elk_username"
                                            " = 'asha.elk'")}  # fmt: skip
    assert handles == {"asha.elk", "asha.elk-2"}


async def test_an_argus_uid_that_belongs_to_another_account_is_refused(rig: Rig) -> None:
    first = rig.lane.add("one.elk")
    rig.lane.add("two.elk", argus_uid=first.argus_uid)
    assert (await rig.sign_in(rig.browser(), "one.elk")).status_code == 303
    assert (await rig.sign_in(rig.browser(), "two.elk")).status_code == 401
    assert await rig.scalar("SELECT details->>'why' FROM audit_events WHERE outcome = 'denied'"
                            " AND action = 'login'") == "uid_in_use"  # fmt: skip


async def test_a_linked_local_account_keeps_its_id_history_and_password(rig: Rig) -> None:
    before = await rig.one("SELECT id, password_hash FROM users WHERE username = 'asha'")
    async with rig.owner.begin() as conn:  # what `argus user link asha asha.elk` does
        await conn.execute(text("UPDATE users SET elk_username = 'asha.elk', realm = 'native'"
                                " WHERE username = 'asha'"))  # fmt: skip
    rig.lane.add("asha.elk", capabilities=REVIEWER)
    http = rig.browser()
    assert (await rig.sign_in(http, "asha.elk")).status_code == 303
    after = await rig.one(
        "SELECT id, password_hash, argus_uid, elk_first_signin_at FROM users"
        " WHERE username = 'asha'"
    )
    assert after.id == before.id
    assert after.password_hash == before.password_hash
    assert after.argus_uid == rig.lane.accounts["asha.elk"].argus_uid
    assert after.elk_first_signin_at is not None
    me = (await http.get("/api/v1/session")).json()
    assert me["user"]["id"] == before.id
    assert me["user"]["username"] == "asha"


async def test_gold_answers_need_review_in_elk_and_a_name_in_argus(rig: Rig) -> None:
    http, _ = await rig.signed_in("asha.elk", capabilities=REVIEWER)
    names = lambda r: {c["name"] for c in r.json()["capabilities"]}  # noqa: E731
    assert "answer_gold" not in names(await http.get("/api/v1/session"))
    async with rig.owner.begin() as conn:  # `argus user grant`: ARGUS names its gold-key owners
        await conn.execute(text("UPDATE users SET capabilities = '{answer_gold}'"
                                " WHERE elk_username = 'asha.elk'"))  # fmt: skip
    again = rig.browser()
    await rig.sign_in(again, "asha.elk")
    assert "answer_gold" in names(await again.get("/api/v1/session"))
    rig.lane.add("view.only", capabilities=VIEWER)
    async with rig.owner.begin() as conn:
        pass
    other = rig.browser()
    await rig.sign_in(other, "view.only")
    async with rig.owner.begin() as conn:
        await conn.execute(text("UPDATE users SET capabilities = '{answer_gold}'"
                                " WHERE elk_username = 'view.only'"))  # fmt: skip
    third = rig.browser()
    await rig.sign_in(third, "view.only")
    assert "answer_gold" not in names(await third.get("/api/v1/session"))  # no review: nothing


async def test_the_sign_in_page_is_still_a_page_without_script(rig: Rig) -> None:
    http = rig.browser()
    page = await http.get("/signin")
    assert "script-src 'none'" in page.headers["content-security-policy"]
    assert BASE


async def test_password_managers_can_fill_the_sign_in_and_step_up_pages(rig: Rig) -> None:
    page = (await rig.browser().get("/signin")).text
    assert 'name="username"' in page
    assert 'autocomplete="username"' in page
    assert 'type="password"' in page
    assert 'autocomplete="current-password"' in page
    assert "<script" not in page  # no script at all on the page that takes a password
    http, _ = await rig.signed_in("asha.elk")
    step = (await http.get("/stepup")).text
    assert 'name="username" value="asha.elk"' in step  # the ELK name a manager saved
    assert 'autocomplete="current-password"' in step
    assert "<script" not in step


async def test_a_person_remembers_at_most_twenty_browsers(rig: Rig) -> None:
    rig.lane.add("asha.elk")
    for _ in range(23):
        assert (await rig.sign_in(rig.browser(), "asha.elk")).status_code == 303
    assert await rig.scalar("SELECT count(*) FROM user_devices") == 20
