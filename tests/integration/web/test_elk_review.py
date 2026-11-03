"""Q-E2's independent review (docs/gates/q-e2.md, Review): every confirmed finding as a test that
failed on the code the reviewer attacked. F1 a device cookie across people, F2 write-back of a
review that was not Kibana-ready, F3 the outage rule keeping revoked sessions open, F4 a clock
stepped back, F5 locking out the break-glass holder, F6 a second window, F7 the downgrade and open
ELK sessions, F8 gold-key owners, F10 the spray alarm, F11 the pool, F12 case-opening candidates,
and the web's reach into ``siem_state``."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assets.classify import IpClassifier
from argus.cases import opener
from argus.db import migrate
from argus.gateway.builtin import SecurityIndexHealth
from argus.gateway.gateway import Gateway, Targets
from argus.gateway.pgstore import PgStore
from argus.gateway.templates import NoParams, Purpose
from argus.web import auth, breakglass, elk, throttle
from argus.writeback import plan
from tests.integration.test_cli_db import cli_env  # noqa: F401
from tests.integration.web.elk_rig import Rig, form_token, make_rig
from tests.integration.web.test_elk_cli import elk_on, run  # noqa: F401
from tests.unit.gateway.fakes import FakeClock, FakeTransport, ok
from tests.unit.web.fake_identity import REVIEWER

pytestmark = pytest.mark.integration


@pytest.fixture
async def rig(seeded: AsyncEngine, web_engine: AsyncEngine) -> AsyncIterator[Rig]:
    made = await make_rig(web_engine, seeded)
    try:
        yield made
    finally:
        await made.aclose()


async def open_window(seeded: AsyncEngine) -> str:
    async with seeded.begin() as conn:
        password, _ = await breakglass.open_window(
            conn, reason="the SIEM down for a drill", enabled_by="t", minutes=60, override=True
        )
    return password


async def review_as(
    rig: Rig,
    http,
    csrf: str,
    outcome: str,  # type: ignore[no-untyped-def]
):  # type: ignore[no-untyped-def]
    first = (await http.get("/api/investigations", params={"view": "all"})).json()[0]
    return await http.post(
        f"/api/investigations/{first['id']}/reviews",
        json={"action": "reviewed", "outcome": outcome, "note": "seen",
              "seen_review": first["latest_review"], "seen_version": first["version"]},
        headers={"X-CSRF-Token": csrf},
    )  # fmt: skip


async def counted(rig: Rig) -> int:
    """Counted refusals in the audit trail (what the throttle counts)."""
    return int(await rig.scalar(
        "SELECT count(*) FROM audit_events WHERE action IN ('login', 'stepup')"
        " AND outcome = 'denied' AND details->>'counted' = 'true'"
    ))  # fmt: skip


async def denied_checks(rig: Rig, elk_name: str) -> int:
    return int(await rig.scalar(
        "SELECT count(*) FROM identity_checks c JOIN users u ON u.id = c.user_id"
        " WHERE u.elk_username = :n AND c.outcome = 'denied'", n=elk_name))  # fmt: skip


# --------------------------------------------------------------------------- F1


async def test_f1_a_device_cookie_of_one_person_passes_no_lock_of_another(rig: Rig) -> None:
    """Person A's ELK name ``Nora`` has the handle ``nora``; person B's ELK name is ``nora``.
    A's device cookie must pass B's lock for nobody, and a wrong guess of it must void nothing."""
    rig.lane.add("Nora", capabilities=REVIEWER)
    rig.lane.add("nora", capabilities=REVIEWER, password="b's own password 99")
    mine = rig.browser("10.1.1.1")
    assert (await rig.sign_in(mine, "Nora")).status_code == 303
    other = rig.browser("10.2.2.2")
    assert (await rig.sign_in(other, "nora", "b's own password 99")).status_code == 303
    spray = rig.browser("10.3.3.3")
    for _ in range(5):
        await rig.sign_in(spray, "nora", "guess number one")
    assert (await rig.sign_in(spray, "nora", "guess number one")).status_code == 429
    calls = rig.lane.requests()
    again = rig.browser("10.1.1.1")
    again.cookies.set("argus_device", mine.cookies["argus_device"])
    got = await rig.sign_in(again, "nora", "another guess here")
    assert got.status_code == 429  # A's cookie is nobody's key to B's name
    assert rig.lane.requests() == calls  # nothing asked of ELK
    assert await denied_checks(rig, "nora") == 0  # B's approvals stand


async def test_f1_a_device_cookie_still_passes_its_own_persons_lock(rig: Rig) -> None:
    rig.lane.add("Nora", capabilities=REVIEWER)
    mine = rig.browser("10.1.1.1")
    assert (await rig.sign_in(mine, "Nora")).status_code == 303
    spray = rig.browser("10.3.3.3")
    for _ in range(5):
        await rig.sign_in(spray, "Nora", "guess number one")
    assert (await rig.sign_in(spray, "Nora", "guess number one")).status_code == 429
    again = rig.browser("10.1.1.1")
    again.cookies.set("argus_device", mine.cookies["argus_device"])
    assert (await rig.sign_in(again, "Nora")).status_code == 303


async def test_f1_the_handle_is_no_key_in_elk_mode(rig: Rig, seeded: AsyncEngine) -> None:
    """A local handle that equals an ELK name (``asha`` is a handle, not that person's ELK
    name) is matched by the ELK name alone."""
    rig.lane.add("asha", capabilities=REVIEWER)
    async with seeded.connect() as conn:
        asha = (
            await conn.execute(text("SELECT id FROM users WHERE username = 'asha'"))
        ).scalar_one()
    async with seeded.begin() as conn:
        await conn.execute(text("INSERT INTO user_devices (user_id, token_hash) VALUES (:u, :t)"),
                           {"u": asha, "t": "a" * 64})  # fmt: skip
        assert not await throttle.device_known(conn, "a" * 64, "asha", elk=True)
        assert await throttle.device_known(conn, "a" * 64, "asha", elk=False)


# --------------------------------------------------------------------------- F2


async def test_f2_a_review_that_was_not_kibana_ready_is_not_planned_for_write_back(
    rig: Rig, seeded: AsyncEngine
) -> None:
    password = await open_window(seeded)
    http = rig.browser("10.1.1.1")
    assert (await rig.sign_in(http, "break-glass", password)).status_code == 303
    r = await review_as(rig, http, await rig.csrf(http), "benign_expected")
    assert r.status_code in (200, 201), r.text
    assert await rig.scalar("SELECT kibana_ok FROM review_events ORDER BY id DESC LIMIT 1") is False
    async with seeded.begin() as conn:
        assert await plan(conn) == 0
    assert await rig.scalar("SELECT count(*) FROM writeback_outbox") == 0


async def test_f2_a_newer_review_that_is_not_ready_still_supersedes_a_planned_older_one(
    rig: Rig, seeded: AsyncEngine
) -> None:
    """The person's verdict was benign (ready); emergency access then said true positive. Kibana
    must not be told the older verdict is the last word: the older one is skipped, not sent."""
    http, csrf = await rig.signed_in("careful")
    assert (await review_as(rig, http, csrf, "benign_expected")).status_code == 201
    async with seeded.begin() as conn:
        assert await plan(conn) == 1
    password = await open_window(seeded)
    glass = rig.browser("10.1.1.2")
    assert (await rig.sign_in(glass, "break-glass", password)).status_code == 303
    assert (await review_as(rig, glass, await rig.csrf(glass), "true_positive")).status_code == 201
    async with seeded.begin() as conn:
        assert await plan(conn) == 0
    assert await rig.scalar("SELECT state FROM writeback_outbox") == "skipped"


# --------------------------------------------------------------------------- F3


async def test_f3_a_batch_disable_ends_every_session_within_minutes(rig: Rig) -> None:
    """Six people disabled in ELK at once and clicking every 35 s: after the first two, the
    next four are held as 'maybe an outage' for 120 s at most, then end like the rest."""
    people = [(f"student{n}", *await rig.signed_in(f"student{n}")) for n in range(6)]
    for name, _http, _csrf in people:
        rig.lane.accounts[name].enabled = False
    rig.clock.advance(minutes=5, seconds=1)
    for _round in range(12):  # 7 minutes of clicking
        for _name, http, _csrf in people:
            await http.get("/api/investigations")
            await rig.settle()
        rig.clock.advance(seconds=35)
    final = [(await http.get("/api/investigations")).status_code for _n, http, _c in people]
    assert final == [401] * 6


async def test_f3_a_held_session_ends_within_the_window_however_the_others_fare(rig: Rig) -> None:
    people = [(f"held{n}", *await rig.signed_in(f"held{n}")) for n in range(4)]
    for name, _http, _csrf in people:
        rig.lane.accounts[name].enabled = False
    rig.clock.advance(minutes=5, seconds=1)
    for _name, http, _csrf in people:
        await http.get("/api/investigations")
        await rig.settle()
    held = await rig.scalar("SELECT count(*) FROM user_sessions WHERE ended_at IS NULL"
                            " AND unverified_since IS NOT NULL")  # fmt: skip
    assert held == 2  # the first two ended, the next two are held as a suspected outage
    rig.clock.advance(seconds=elk.SUSPECT_WINDOW.total_seconds() + 31)
    for _name, http, _csrf in people[2:]:
        assert (await http.get("/api/investigations")).status_code == 200  # served, re-check due
        await rig.settle()
    assert [(await h.get("/api/investigations")).status_code for _n, h, _c in people] == [401] * 4


async def test_f3_role_removals_and_forbidden_answers_are_no_evidence_of_an_outage(
    rig: Rig,
) -> None:
    a, _ = await rig.signed_in("p1")
    b, _ = await rig.signed_in("p2")
    c, _ = await rig.signed_in("p3")
    rig.lane.accounts["p1"].forbidden = True  # a 403: ELK is plainly up
    rig.lane.accounts["p2"].forbidden = True
    rig.lane.accounts["p3"].enabled = False  # a 401
    rig.clock.advance(minutes=5, seconds=1)
    for http in (a, b, c):
        await http.get("/api/investigations")
        await rig.settle()
    assert [(await h.get("/api/investigations")).status_code for h in (a, b, c)] == [401] * 3


async def _denial(conn, user: str, reason: str, action: str = "session.denied") -> None:  # type: ignore[no-untyped-def]
    await auth.audit(conn, actor="web", action=action, outcome="denied", target_type="session",
                     details={"user_id": user, "reason": reason})  # fmt: skip


@pytest.mark.parametrize(
    ("rows", "suspected"),
    [
        ([("1", "unauthenticated"), ("2", "unauthenticated")], True),
        ([("1", "unauthenticated")], False),
        ([("1", "forbidden"), ("2", "forbidden")], False),
        ([("1", "no_access"), ("2", "disabled")], False),
        ([("1", "unauthenticated"), ("2", "forbidden")], False),
        ([("1", "unauthenticated"), ("1", "unauthenticated")], False),  # one person twice
    ],
)
async def test_f3_only_401s_of_two_other_people_make_a_suspected_outage(
    rig: Rig, rows: list[tuple[str, str]], suspected: bool
) -> None:
    async with rig.owner.begin() as conn:
        for user, reason in rows:
            await _denial(conn, user, reason)
    async with rig.owner.begin() as conn:
        assert await rig.elk._suspect_outage(conn, 99) is suspected


async def test_f3_suspected_outage_notes_never_count_so_they_cannot_keep_each_other_alive(
    rig: Rig,
) -> None:
    async with rig.owner.begin() as conn:
        for user in ("1", "2", "3", "4"):
            await _denial(conn, user, "suspected_outage", "session.suspected_outage")
    async with rig.owner.begin() as conn:
        assert await rig.elk._suspect_outage(conn, 99) is False


async def test_f3_the_quorum_expires(rig: Rig, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(elk, "SUSPECT_WINDOW", timedelta(seconds=1))
    async with rig.owner.begin() as conn:
        await _denial(conn, "1", "unauthenticated")
        await _denial(conn, "2", "unauthenticated")
    async with rig.owner.begin() as conn:
        assert await rig.elk._suspect_outage(conn, 99) is True
    await asyncio.sleep(1.3)
    async with rig.owner.begin() as conn:
        assert await rig.elk._suspect_outage(conn, 99) is False


# --------------------------------------------------------------------------- F4


async def test_f4_a_clock_stepped_back_never_makes_a_snapshot_fresh(rig: Rig) -> None:
    http, csrf = await rig.signed_in("clk")
    rig.lane.accounts["clk"].enabled = False  # revoked in ELK
    rig.clock.now -= timedelta(hours=1)  # the web host's clock steps back an hour
    before = rig.lane.requests()
    r = await rig.review(http, csrf)
    assert rig.lane.requests() > before  # asked ELK, did not trust the snapshot
    assert r.status_code == 401


async def test_f4_a_clock_stepped_back_makes_a_recheck_due(rig: Rig) -> None:
    http, _ = await rig.signed_in("clk2")
    rig.lane.accounts["clk2"].enabled = False
    rig.clock.now -= timedelta(hours=1)
    await http.get("/api/investigations")
    await rig.settle()
    assert (await http.get("/api/investigations")).status_code == 401


# --------------------------------------------------------------------------- F5


async def test_f5_a_stranger_cannot_lock_the_break_glass_holder_out(
    rig: Rig, seeded: AsyncEngine
) -> None:
    password = await open_window(seeded)
    spray = rig.browser("10.9.9.9")
    codes = [(await rig.sign_in(spray, "break-glass", "guess number one")).status_code
             for _ in range(8)]  # fmt: skip
    assert codes == [401] * 8  # never 429: the answer says nothing of a window
    holder = rig.browser("10.1.1.1")
    assert (await rig.sign_in(holder, "break-glass", password)).status_code == 303


async def test_f5_guesses_look_the_same_with_the_window_open_or_not(
    rig: Rig, seeded: AsyncEngine
) -> None:
    closed = rig.browser("10.9.9.1")
    shut = [(await rig.sign_in(closed, "break-glass", "guess number one")).status_code
            for _ in range(8)]  # fmt: skip
    await open_window(seeded)
    opened = rig.browser("10.9.9.2")
    wide = [(await rig.sign_in(opened, "break-glass", "guess number one")).status_code
            for _ in range(8)]  # fmt: skip
    assert shut == wide == [401] * 8
    assert await counted(rig) == 0


async def test_f5_break_glass_guesses_stay_out_of_the_name_and_spray_counts(
    rig: Rig, seeded: AsyncEngine
) -> None:
    await open_window(seeded)
    spray = rig.browser("10.9.9.9")
    for _ in range(6):
        await rig.sign_in(spray, "break-glass", "guess number one")
    rig.lane.add("someone", capabilities=REVIEWER)
    other = rig.browser("10.9.9.9")  # the same client: its break-glass guesses count for nothing
    assert (await rig.sign_in(other, "someone")).status_code == 303


async def test_f5_a_locked_client_or_a_sprayed_hour_still_lets_the_holder_try(
    rig: Rig, seeded: AsyncEngine
) -> None:
    password = await open_window(seeded)
    async with seeded.begin() as conn:
        for k in range(throttle.SPRAY_LIMIT):
            await throttle.record(
                conn,
                action="login",
                name_field="name_hmac",
                name_key=f"{k:032x}",
                client=f"10.7.0.{k}",
                counted=True,
            )
    holder = rig.browser("10.1.1.1")
    assert (await rig.sign_in(holder, "break-glass", password)).status_code == 303


# --------------------------------------------------------------------------- F6


async def test_f6_a_window_that_ran_out_does_not_block_the_next(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    async with seeded.begin() as conn:
        await breakglass.open_window(conn, reason="the SIEM down for a drill", enabled_by="t",
                                     minutes=60, override=True)  # fmt: skip
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE break_glass SET enabled_at = now() - interval '3 hours',"
                                " expires_at = now() - interval '1 hour'"))  # fmt: skip
    async with seeded.begin() as conn:
        assert await breakglass.active(conn) is None
    async with seeded.begin() as conn:
        password, _ = await breakglass.open_window(
            conn, reason="a second outage, same night", enabled_by="t", minutes=60, override=True
        )
    assert password
    async with migrated_engine.connect() as conn:
        rows = (
            await conn.execute(
                text("SELECT ended_at IS NOT NULL AS ended FROM break_glass ORDER BY id")
            )
        ).all()
        expired = await conn.scalar(text("SELECT count(*) FROM audit_events"
                                         " WHERE action = 'break_glass.expired'"))  # fmt: skip
    assert [r.ended for r in rows] == [True, False]
    assert expired == 1


async def test_f6_a_window_still_open_is_still_refused(seeded: AsyncEngine) -> None:
    async with seeded.begin() as conn:
        await breakglass.open_window(conn, reason="the SIEM down for a drill", enabled_by="t",
                                     minutes=60, override=True)  # fmt: skip
    with pytest.raises(ValueError, match="already on"):
        async with seeded.begin() as conn:
            await breakglass.open_window(conn, reason="a second one, too soon", enabled_by="t",
                                         minutes=60, override=True)  # fmt: skip


# --------------------------------------------------------------------------- F7


async def test_f7_the_downgrade_ends_the_open_elk_sessions(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    async with migrated_engine.begin() as conn:
        uid = (
            await conn.execute(text("SELECT id FROM users WHERE username = 'asha'"))
        ).scalar_one()
        for token, mode, caps in (("h1", "elk", ["view"]), ("h2", "break_glass", None),
                                  ("h3", "local", None)):  # fmt: skip
            await conn.execute(
                text(
                    "INSERT INTO user_sessions (token_hash, user_id, csrf_token, last_seen_at,"
                    " expires_at, mode, capabilities, checked_at) VALUES (:t, :u, 'c', now(),"
                    " now() + interval '8 hours', :m, CAST(:c AS text[]), now())"
                ),
                {"t": token, "u": uid, "m": mode, "c": caps},
            )
    await migrate.downgrade(migrated_engine, "0035")
    async with migrated_engine.connect() as conn:
        live = (
            (
                await conn.execute(
                    text("SELECT token_hash FROM user_sessions WHERE ended_at IS NULL ORDER BY 1")
                )
            )
            .scalars()
            .all()
        )
    assert live == ["h3"]  # only the local session is the old code's to read


# --------------------------------------------------------------------------- F8


async def test_f8_linking_takes_answer_gold_away_until_it_is_granted_again(
    rig: Rig,
    elk_on: Path,  # noqa: F811
) -> None:
    async with rig.owner.begin() as conn:
        await conn.execute(text("UPDATE users SET capabilities = CAST(:c AS text[])"
                                " WHERE username = 'asha'"),
                           {"c": ["view", "see_logs", "review", "answer_gold"]})  # fmt: skip
    code, out = await run(elk_on, "user", "link", "asha", "asha.k")
    assert code == 0, out
    assert "answer_gold" in out  # said plainly
    rig.lane.add("asha.k", capabilities=REVIEWER)
    http = rig.browser("10.1.1.1")
    assert (await rig.sign_in(http, "asha.k")).status_code == 303
    caps = {c["name"] for c in (await http.get("/api/v1/session")).json()["capabilities"]}
    assert "answer_gold" not in caps
    stored = await rig.scalar("SELECT capabilities FROM users WHERE username = 'asha'")
    assert "answer_gold" not in stored
    assert (await run(elk_on, "user", "grant", "asha", "answer_gold"))[0] == 0
    caps = {c["name"] for c in (await http.get("/api/v1/session")).json()["capabilities"]}
    assert "answer_gold" in caps  # a named owner, by an explicit grant


async def test_f8_a_first_elk_sign_in_creates_an_account_without_answer_gold(rig: Rig) -> None:
    http, _ = await rig.signed_in("fresh.face")
    caps = {c["name"] for c in (await http.get("/api/v1/session")).json()["capabilities"]}
    assert "answer_gold" not in caps


# --------------------------------------------------------------------------- F10


async def seed_refusals(seeded: AsyncEngine, n: int) -> None:
    async with seeded.begin() as conn:
        for i in range(n):
            await throttle.record(conn, action="login", name_field="name_hmac",
                                  name_key=f"{i:032x}", client=f"10.7.{i // 200}.{i % 200}",
                                  counted=True, why=None)  # fmt: skip


async def burst_of_wrong(rig: Rig, k: int) -> list[int]:
    """``k`` people at distinct clients, each typing one wrong password for a name of their own,
    all at once (distinct names and clients: no lock makes them wait for each other)."""
    for i in range(k):
        rig.lane.add(f"v{i}", capabilities=REVIEWER)
    rig.lane.delay = 0.15
    browsers = [rig.browser(f"10.5.0.{i + 1}") for i in range(k)]
    forms = [await b.get("/signin") for b in browsers]
    res = await asyncio.gather(*[
        b.post("/signin", data={"username": f"v{i}", "password": f"wrong guess {i:02d}x",
                                "signin_token": form_token(f.text)})
        for i, (b, f) in enumerate(zip(browsers, forms, strict=True))
    ])  # fmt: skip
    return sorted(r.status_code for r in res)


async def alarms(rig: Rig) -> int:
    return int(await rig.scalar("SELECT count(*) FROM audit_events WHERE action = 'signin.alarm'"))


async def test_f10_the_alarm_is_raised_when_overlapping_checks_cross_the_limit(
    rig: Rig, seeded: AsyncEngine
) -> None:
    await seed_refusals(seeded, 58)
    await burst_of_wrong(rig, 3)  # 61 counted refusals, none saw more than 59
    late = rig.browser("10.6.6.6")
    rig.lane.add("zz", capabilities=REVIEWER)
    assert (await rig.sign_in(late, "zz", "wrong guess zz")).status_code == 429  # the lock
    assert await alarms(rig) == 1


async def test_f10_the_alarm_is_raised_once_when_overlapping_checks_all_cross_it(
    rig: Rig, seeded: AsyncEngine
) -> None:
    await seed_refusals(seeded, 59)
    await burst_of_wrong(rig, 3)
    assert await alarms(rig) == 1
    late = rig.browser("10.6.6.6")
    await rig.sign_in(late, "zz", "wrong guess zz")
    assert await alarms(rig) == 1  # once an hour


async def test_f10_two_raisers_that_overlap_raise_one_alarm(rig: Rig, seeded: AsyncEngine) -> None:
    await seed_refusals(seeded, 60)
    async with seeded.connect() as first, seeded.connect() as second:
        assert await throttle.raise_alarm_if_due(first) is True
        assert await throttle.raise_alarm_if_due(second) is False  # the first is raising it
        await first.commit()
        await second.commit()
    async with seeded.begin() as conn:
        assert await throttle.raise_alarm_if_due(conn) is False  # once an hour
    assert await alarms(rig) == 1


async def test_f10_no_alarm_below_the_limit(rig: Rig, seeded: AsyncEngine) -> None:
    await seed_refusals(seeded, 55)
    await burst_of_wrong(rig, 3)
    assert await alarms(rig) == 0


# --------------------------------------------------------------------------- F11


async def test_f11_a_burst_of_sign_ins_for_one_name_never_stalls_the_pages(rig: Rig) -> None:
    rig.lane.add("target", capabilities=REVIEWER)
    reader, _ = await rig.signed_in("reader1")
    rig.lane.delay = 1.0  # a slow Elasticsearch
    attackers = [rig.browser("10.5.5.5") for _ in range(30)]  # one client, one name
    forms = [await b.get("/signin") for b in attackers]
    burst = asyncio.gather(*[
        b.post("/signin", data={"username": "target", "password": f"wrong guess {i:02d}x",
                                "signin_token": form_token(f.text)})
        for i, (b, f) in enumerate(zip(attackers, forms, strict=True))
    ])  # fmt: skip
    await asyncio.sleep(0.3)
    began = time.perf_counter()
    page = await asyncio.wait_for(reader.get("/api/investigations"), 20)
    took = time.perf_counter() - began
    results = await burst
    codes = sorted(r.status_code for r in results)
    assert page.status_code == 200
    assert took < 0.8, f"a page took {took:.2f} s during the burst"
    assert rig.lane.requests() <= 2  # one check at a time; the rest were told to try again
    assert set(codes) <= {401, 429, 503}
    assert codes.count(503) >= 25


async def test_f11_a_busy_name_does_not_lock_or_count_anyone(rig: Rig) -> None:
    rig.lane.add("target", capabilities=REVIEWER)
    rig.lane.delay = 0.4
    attackers = [rig.browser("10.5.5.5") for _ in range(6)]
    forms = [await b.get("/signin") for b in attackers]
    await asyncio.gather(*[
        b.post("/signin", data={"username": "target", "password": f"wrong guess {i:02d}x",
                                "signin_token": form_token(f.text)})
        for i, (b, f) in enumerate(zip(attackers, forms, strict=True))
    ])  # fmt: skip
    assert await counted(rig) == 1  # the one check that was made; busy answers count for nothing
    rig.lane.delay = 0.0
    assert (await rig.sign_in(rig.browser("10.1.1.1"), "target")).status_code == 303


# --------------------------------------------------------------------------- F12


async def test_f12_a_break_glass_true_positive_opens_no_case(rig: Rig, seeded: AsyncEngine) -> None:
    password = await open_window(seeded)
    http = rig.browser("10.1.1.1")
    assert (await rig.sign_in(http, "break-glass", password)).status_code == 303
    r = await review_as(rig, http, await rig.csrf(http), "true_positive")
    assert r.status_code in (200, 201), r.text
    report = await opener.run(
        seeded, window=timedelta(days=3650), classifier=IpClassifier(None), dry_run=True
    )
    assert report.planned == []


async def test_f12_an_unverified_sessions_true_positive_opens_no_case(
    rig: Rig, seeded: AsyncEngine
) -> None:
    http, csrf = await rig.signed_in("outage.reviewer")
    rig.lane.down = "unreachable"
    rig.clock.advance(minutes=1)
    r = await review_as(rig, http, csrf, "true_positive")
    assert r.status_code == 201, r.text  # reviews continue in an outage (never written back)
    assert await rig.scalar("SELECT kibana_ok FROM review_events ORDER BY id DESC LIMIT 1") is False
    report = await opener.run(
        seeded, window=timedelta(days=3650), classifier=IpClassifier(None), dry_run=True
    )
    assert report.planned == []


async def test_f12_a_verified_persons_true_positive_is_still_a_candidate(
    rig: Rig, seeded: AsyncEngine
) -> None:
    http, csrf = await rig.signed_in("verified.reviewer")
    assert (await review_as(rig, http, csrf, "true_positive")).status_code == 201
    report = await opener.run(
        seeded, window=timedelta(days=3650), classifier=IpClassifier(None), dry_run=True
    )
    assert [p.candidate.source for p in report.planned] == ["review"]


async def test_f12_a_newer_verdict_that_is_not_ready_is_still_the_last_word(
    rig: Rig, seeded: AsyncEngine
) -> None:
    http, csrf = await rig.signed_in("verified.reviewer")
    assert (await review_as(rig, http, csrf, "true_positive")).status_code == 201
    password = await open_window(seeded)
    glass = rig.browser("10.1.1.2")
    assert (await rig.sign_in(glass, "break-glass", password)).status_code == 303
    assert (
        await review_as(rig, glass, await rig.csrf(glass), "benign_expected")
    ).status_code == 201
    report = await opener.run(
        seeded, window=timedelta(days=3650), classifier=IpClassifier(None), dry_run=True
    )
    assert report.planned == []


# --------------------------------------------------------------------------- the web's reach


async def test_the_web_login_changes_only_the_state_rows_the_identity_lane_and_its_index_check_use(
    web_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    update = text("UPDATE siem_state SET updated_at = now() WHERE name = :n")
    for name in ("identity", "health", "budget", "breaker", "lanes"):
        async with web_engine.begin() as conn:  # the gateway's state, for the index check
            assert (await conn.execute(update, {"n": name})).rowcount == 1
    for name in ("kibana", "kibana_breaker"):  # the Kibana lane is none of the web's business
        with pytest.raises(DBAPIError, match="only the identity lane"):
            async with web_engine.begin() as conn:
                await conn.execute(update, {"n": name})
        for engine in (app_engine, migrated_engine):  # the runtime and the owner are unchanged
            async with engine.begin() as conn:
                assert (await conn.execute(update, {"n": name})).rowcount == 1


async def test_the_security_index_check_needs_the_gateway_rows_on_the_webs_own_login(
    web_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """Why the web's reach is five rows and not the identity row alone: the check that makes a
    401 a denial goes through the Elasticsearch gateway on the web's login, which keeps its
    breaker and lane state in ``siem_state`` too."""
    clock = FakeClock()
    health = {"status": "green", "active_primary_shards": 1, "unassigned_primary_shards": 0}
    transport = FakeTransport(clock=clock).on("/_cluster/health/.security", ok(health))
    gateway = Gateway(transport, PgStore(web_engine), targets=Targets(), clock=clock,
                      sleep=clock.sleep)  # fmt: skip

    async def stamps() -> dict[str, object]:
        async with migrated_engine.connect() as conn:
            rows = await conn.execute(text("SELECT name, updated_at FROM siem_state"))
            return dict(rows.all())

    before = await stamps()
    got = await gateway.run(
        SecurityIndexHealth(),
        NoParams(),
        purpose=Purpose.IDENTITY,
        component="identity",
        deadline=clock.now + timedelta(seconds=10),
    )
    after = await stamps()
    changed = {name for name in after if after[name] != before[name]}
    assert SecurityIndexHealth.usable(got.body)
    assert {"breaker", "lanes"} <= changed <= {"identity", "health", "budget", "breaker", "lanes"}
