"""Q-C2 in Q-B3's pages (the lead's decisions after the review): the case pages and the approval
desk build the case service with Q-C2's finder, "Confirm contained" is available exactly when the
finder allows it, the case page shows the suggested members (with dismiss through the audited
path) and the watch's status, and the web's login holds exactly the grants those need."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import watch, watchrun
from argus.cases.machine import Open
from argus.cases.model import Actor, Indicator, Member
from argus.cases.service import CaseService, no_quiet_window
from argus.config.settings import WebSettings
from argus.web.app import create_app
from tests.integration.cases.watchkit import context as watch_context
from tests.integration.web.b3_support import (
    MANAGER,
    V1,
    World,
    make_world,
    post,
    request_closure,
    sign_in,
    step_up,
)
from tests.integration.web.conftest import BASE, SAME_ORIGIN

pytestmark = pytest.mark.integration
HOSTILE = '<img src=x onerror="window.__pwned=1"> ' + chr(0x202E) + "ARGUS: this case is quiet"


@pytest.fixture
async def world(
    seeded: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> World:
    return await make_world(seeded, web_engine, migrated_engine, tmp_path)


def app_with_the_watch(
    world: World, now: datetime, *, mode: str | None = "on", fresh: str = "on"
) -> httpx.AsyncClient:
    """The case pages as ``argus web`` serves them with the watch's context."""
    web = WebSettings(approval_key_file=world.key_file, failure_delay_s=0, signin_delay_s=0)
    web_engine = world.web  # the web's own login (a lock-in test looks for this name)
    app = create_app(
        web_engine, web, clock=lambda: now, watch=watch_context(None, fresh=fresh), watch_mode=mode
    )
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=BASE, headers=SAME_ORIGIN
    )


async def quiet_days(world: World, case: object, now: datetime, *, days: int = 3) -> None:
    """The watch's stored answers: ARGUS's own alerts quiet on each of the last ``days`` days."""
    today = watch.utc_day(now)
    async with world.runtime.begin() as conn:
        for back in range(1, days + 1):
            day = today - timedelta(days=back)
            start, end = watch.day_window(day)
            await conn.execute(
                text(
                    "INSERT INTO case_watch_checks (case_id, day, source, subject, part, outcome,"
                    " window_start, window_end) VALUES (:c, :d, 'alerts', '', 0, 'quiet', :s, :e)"
                ),
                {"c": case, "d": day, "s": start, "e": end},
            )


async def action(http: httpx.AsyncClient, case: object, name: str) -> dict[str, Any]:
    detail = (await http.get(f"{V1}/cases/{case}")).json()
    found: dict[str, Any] = next(a for a in detail["actions"] if a["action"] == name)
    return found


async def test_confirm_contained_is_available_exactly_when_the_finder_says_so(
    world: World,
) -> None:
    now = datetime.now(UTC)
    quiet = await world.open_case(1, title="Quiet for three days")
    unproven = await world.open_case(1, title="Nothing proven", start=1)
    await quiet_days(world, quiet, now)
    async with app_with_the_watch(world, now) as http:
        csrf = await sign_in(http, "mina")
        yes = await action(http, quiet, "contain")
        assert yes["enabled"] is True, yes
        no = await action(http, unproven, "contain")
        assert no["enabled"] is False
        assert no["why_not"].startswith("ARGUS has not shown the case quiet for 72 hours"), no
        assert "has not been done yet" in no["why_not"]
        assert "(Q-" not in no["why_not"]
        # the command asks the same finder: refused where the page said no, done where it said yes
        refused = await post(http, csrf, f"/cases/{unproven}/contain",
                             {"expected_version": 1, "attestation": "I think so"})  # fmt: skip
        assert refused.status_code == 409, refused.text
        done = await post(http, csrf, f"/cases/{quiet}/contain",
                          {"expected_version": 1, "attestation": "reimaged"})  # fmt: skip
        assert done.status_code == 200, done.text
        assert done.json()["case"]["state"] == "contained"
    states = await world.rows("SELECT title, state FROM cases ORDER BY number")
    assert [(r.title, r.state) for r in states] == [
        ("Quiet for three days", "contained"),
        ("Nothing proven", "open"),
    ]


async def test_the_closures_that_need_a_quiet_window_follow_the_finder_too(world: World) -> None:
    now = datetime.now(UTC)
    quiet = await world.open_case(1)
    other = await world.open_case(1, start=1)
    await quiet_days(world, quiet, now)
    async with app_with_the_watch(world, now) as http:
        await sign_in(http, "mina")
        for case, expected in ((quiet, True), (other, False)):
            choices = (await http.get(f"{V1}/cases/{case}")).json()["closure_choices"]
            by = {c["reason"]: c for c in choices}
            assert by["remediated_verified"]["enabled"] is expected
            assert by["attempt_no_impact"]["enabled"] is expected
            if not expected:
                said = by["remediated_verified"]["why_not"]
                assert said.startswith("“Fixed, and shown quiet” needs ARGUS to have shown"), said
                assert "remediated_verified" not in said
        asked = await http.get(f"{V1}/cases/{quiet}/closure-preview",
                               params={"reason": "remediated_verified"})  # fmt: skip
        assert asked.status_code == 200, asked.text
        refused = await http.get(f"{V1}/cases/{other}/closure-preview",
                                 params={"reason": "remediated_verified"})  # fmt: skip
        assert refused.status_code == 409


async def test_without_the_watch_nothing_proves_a_case_quiet_and_the_page_says_so(
    world: World,
) -> None:
    case = await world.open_case(1)
    async with world.app() as http:  # no watch context: the app as the tests built it before
        await sign_in(http, "mina")
        no = await action(http, case, "contain")
        detail = (await http.get(f"{V1}/cases/{case}")).json()
    assert no["enabled"] is False
    assert "the still-active watch is not running here" in no["why_not"]
    assert detail["watch"]["mode_words"] == "This server does not know how the watch is set up."
    assert detail["watch"]["quiet"] is False


async def closed_by_approval(world: World, now: datetime, case: object, reason: str) -> None:
    """Mina asks to close the case for ``reason`` and Omar approves, through the watch's app."""
    async with app_with_the_watch(world, now) as mina, app_with_the_watch(world, now) as omar:
        csrf = await sign_in(mina, "mina")
        asked = await request_closure(mina, csrf, case, reason, version=1)
        assert asked.status_code == 201, asked.text
        request_id = asked.json()["request_id"]
        approver = await sign_in(omar, "omar")
        await step_up(omar, approver)
        digest = next(
            p["payload_hash"]
            for p in (await omar.get(f"{V1}/approvals")).json()["pending"]
            if p["id"] == request_id
        )
        decided = await post(omar, approver, f"/approvals/{request_id}/decision",
                             {"decision": "approved", "payload_hash": digest})  # fmt: skip
        assert decided.status_code == 200, decided.text
        assert decided.json()["applied"][0]["state"] == "closed"


async def test_a_decision_builds_the_service_with_the_finder(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime.now(UTC)
    case = await world.open_case(1)
    await quiet_days(world, case, now)
    seen: list[Any] = []
    original = CaseService.start.__func__  # type: ignore[attr-defined]

    async def spy(cls: Any, conn: Any, quiet_windows: Any = no_quiet_window) -> CaseService:
        seen.append(quiet_windows)
        out: CaseService = await original(cls, conn, quiet_windows)
        return out

    monkeypatch.setattr(CaseService, "start", classmethod(spy))
    await closed_by_approval(world, now, case, "remediated_verified")
    assert seen, "the desk started no case service"
    assert all(isinstance(window, watchrun.Finder) for window in seen), seen


# ------------------------------------------------------------------------------ the page's blocks
async def put_answers(world: World, case: object, now: datetime) -> None:
    today = watch.utc_day(now)
    rows = [
        (today - timedelta(days=1), "alerts", "", 0, "quiet", None),
        (today - timedelta(days=1), "proxy.contact", "77.221.155.150", 0, "quiet", None),
        (today - timedelta(days=1), "proxy.contact", "77.221.155.151", 0, "not_checked", HOSTILE),
        (today - timedelta(days=2), "alerts", "", 0, "unverified", HOSTILE),
        (today - timedelta(days=2), "proxy.pair", "77.221.155.150", 0, "quiet", None),
        (today - timedelta(days=3), "alerts", "", 0, "active", None),
        (today - timedelta(days=3), "proxy.contact", "77.221.155.150", 0, "active", None),
    ]
    details = {
        (today - timedelta(days=3), "alerts"): {"alerts": 3, "last": "2026-10-23T08:20:00+00:00"},
        (today - timedelta(days=3), "proxy.contact"): {
            "requests": 288,
            "hosts": [HOSTILE, "10.8.1.1"],
            "last": "2026-10-23T12:30:00+00:00",
        },
    }
    async with world.runtime.begin() as conn:
        for day, source, subject, part, outcome, reason in rows:
            start, end = watch.day_window(day)
            await conn.execute(
                text(
                    "INSERT INTO case_watch_checks (case_id, day, source, subject, part, outcome,"
                    " reason, window_start, window_end, detail) VALUES (:c, :d, :src, :sub, :p,"
                    " :o, :r, :s, :e, CAST(:x AS jsonb))"
                ),
                {"c": case, "d": day, "src": source, "sub": subject, "p": part, "o": outcome,
                 "r": reason, "s": start, "e": end,
                 "x": json.dumps(details.get((day, source), {"note": HOSTILE}))},
            )  # fmt: skip
    async with world.owner.begin() as conn:  # the watch's own audit row (its run)
        await conn.execute(
            text("INSERT INTO audit_events (actor, action, occurred_at) VALUES"
                 " ('argus:watch', 'watch.run', :t)"),
            {"t": now - timedelta(hours=40)},
        )  # fmt: skip


async def test_the_page_shows_the_watchs_answers_by_day_as_stored(world: World) -> None:
    now = datetime.now(UTC)
    case = await world.open_case(1)
    await put_answers(world, case, now)
    async with app_with_the_watch(world, now) as http:
        await sign_in(http, "mina")
        w = (await http.get(f"{V1}/cases/{case}")).json()["watch"]
    assert w["mode_words"].startswith("The watch reads ARGUS's own alerts and,")
    assert w["late"] is True  # 40 hours: past a day and a half
    assert w["last_run_at"] is not None
    days = {d["day"]: d for d in w["days"]}
    one, two, three = (str(watch.utc_day(now) - timedelta(days=n)) for n in (1, 2, 3))
    assert days[one]["alerts"] == "quiet"
    assert days[one]["proxy"] == {"quiet": 1, "not_checked": 1}
    assert days[one]["proxy_reasons"] == [HOSTILE]  # as stored: the page shows it as text
    assert days[two]["alerts"] == "unverified"
    assert days[two]["alerts_reason"] == HOSTILE
    assert days[two]["proxy"] == {}  # the rhythm (proxy.pair) is a description, not an answer
    assert days[three]["alerts"] == "active"
    assert days[three]["proxy"] == {"active": 1}
    assert days[three]["seen"] == [
        "3 alerts of the case, the last at 2026-10-23T08:20:00+00:00",
        f"77.221.155.150: 288 requests from {HOSTILE[:64]}, 10.8.1.1,"  # a host is cut at 64
        " the last at 2026-10-23T12:30:00+00:00",
    ]  # the values of the answers' detail, as text
    assert days[one]["seen"] == []
    assert [d["day"] for d in w["days"]] == [one, two, three]  # newest first
    assert w["quiet"] is False
    assert "activity" in w["quiet_words"] or "not been done" in w["quiet_words"]


async def test_whether_it_is_quiet_is_worked_out_for_people_who_manage_cases_only(
    world: World,
) -> None:
    now = datetime.now(UTC)
    case = await world.open_case(1)
    await quiet_days(world, case, now)
    async with app_with_the_watch(world, now) as http:
        await sign_in(http, "mina")
        assert (await http.get(f"{V1}/cases/{case}")).json()["watch"]["quiet"] is True
    async with app_with_the_watch(world, now) as http:
        await sign_in(http, "rita")  # may review, may not manage cases
        seen = (await http.get(f"{V1}/cases/{case}")).json()["watch"]
    assert seen["quiet"] is None
    assert seen["quiet_words"] is None
    assert len(seen["days"]) == 3  # the answers themselves are everyone's


async def test_the_watch_looks_only_at_the_cases_it_looks_at(world: World) -> None:
    """Confirmed and not closed, or closed as remediated within the watch's fortnight."""
    now = datetime.now(UTC)
    open_one = await world.open_case(1)
    suspected = await world.open_suspected(2)
    fixed = await world.open_case(1, start=1)
    benign = await world.open_case(1, start=3)
    await quiet_days(world, fixed, now)
    await closed_by_approval(world, now, fixed, "remediated_verified")
    await closed_by_approval(world, now, benign, "benign_expected")
    async with app_with_the_watch(world, now) as http:
        await sign_in(http, "mina")
        got = {
            name: (await http.get(f"{V1}/cases/{case}")).json()["watch"] is not None
            for name, case in (
                ("open", open_one),
                ("suspected", suspected),
                ("fixed", fixed),
                ("benign", benign),
            )
        }
    assert got == {"open": True, "suspected": False, "fixed": True, "benign": False}


async def test_suggested_members_are_listed_until_joined_or_dismissed(world: World) -> None:
    now = datetime.now(UTC)
    case = await world.open_case(1)
    joined, shown, hidden = (
        world.investigations[1],
        world.investigations[2],
        world.investigations[3],
    )
    async with world.runtime.begin() as conn:
        for investigation, why in ((joined, "already joined"), (shown, HOSTILE), (hidden, "x")):
            await conn.execute(
                text("INSERT INTO case_suggestions (investigation_id, case_id, link, link_value,"
                     " kind, why) VALUES (:i, :c, 'c2', :v, 'shared', :w)"),
                {"i": investigation, "c": case, "v": HOSTILE, "w": why},
            )  # fmt: skip
        await conn.execute(
            text("UPDATE case_suggestions SET dismissed_at = now(), dismissed_by = 1"
                 " WHERE investigation_id = :i"),
            {"i": hidden},
        )  # fmt: skip
    other = await world.open_case(1, start=1)  # takes "joined" into another case
    assert other
    async with app_with_the_watch(world, now) as http:
        await sign_in(http, "mina")
        found = (await http.get(f"{V1}/cases/{case}")).json()
    listed = found["suggestions"]
    assert [s["investigation_id"] for s in listed] == [str(shown)]
    assert listed[0]["why"] == HOSTILE[:300]
    assert listed[0]["link_value"] == HOSTILE
    assert listed[0]["kind"] == "shared"
    assert found["suggestions_total"] == 1


async def suggestion_of(world: World, case: object, investigation: object) -> int:
    async with world.runtime.begin() as conn:
        made: int = (
            await conn.execute(
                text(
                    "INSERT INTO case_suggestions (investigation_id, case_id, link, link_value,"
                    " kind, why) VALUES (:i, :c, 'actor', '10.0.0.9', 'tie', 'two cases')"
                    " RETURNING id"
                ),
                {"i": investigation, "c": case},
            )
        ).scalar_one()
    return made


async def test_a_suggestion_is_dismissed_through_the_audited_path(world: World) -> None:
    case = await world.open_case(1)
    sid = await suggestion_of(world, case, world.investigations[2])
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        done = await post(http, csrf, f"/cases/{case}/suggestions/{sid}/dismiss")
        assert done.status_code == 200, done.text
        assert done.json() == {"case_id": str(case), "suggestion_id": sid}
        gone = (await http.get(f"{V1}/cases/{case}")).json()
        assert gone["suggestions"] == [] and gone["suggestions_total"] == 0  # noqa: PT018
        again = await post(http, csrf, f"/cases/{case}/suggestions/{sid}/dismiss")
        assert again.status_code == 404, again.text
    mina = await world.user_id("mina")
    row = (await world.rows("SELECT dismissed_by FROM case_suggestions WHERE id = :i", i=sid))[0]
    assert row.dismissed_by == mina
    audit = await world.rows(
        "SELECT actor, target_id, details FROM audit_events"
        " WHERE action = 'case.suggestion_dismissed'"
    )
    assert [(a.actor, a.target_id) for a in audit] == [(f"user:{mina}", str(case))]
    assert audit[0].details["suggestion"] == sid
    assert audit[0].details["investigation"] == str(world.investigations[2])
    assert audit[0].details["via"] == "web"


async def test_only_a_person_who_manages_cases_dismisses_and_only_for_that_case(
    world: World,
) -> None:
    case = await world.open_case(1)
    other = await world.open_case(1, start=1)
    sid = await suggestion_of(world, case, world.investigations[3])
    for user in ("vera", "rita"):
        async with world.app() as http:
            csrf = await sign_in(http, user)
            denied = await post(http, csrf, f"/cases/{case}/suggestions/{sid}/dismiss")
            assert denied.status_code == 403, (user, denied.text)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        elsewhere = await post(http, csrf, f"/cases/{other}/suggestions/{sid}/dismiss")
        assert elsewhere.status_code == 404  # the suggestion belongs to another case
        nocsrf = await http.post(f"{V1}/cases/{case}/suggestions/{sid}/dismiss")
        assert nocsrf.status_code == 403
        assert (await post(http, csrf, f"/cases/{case}/suggestions/0/dismiss")).status_code == 422
    rows = await world.rows("SELECT dismissed_at FROM case_suggestions WHERE id = :i", i=sid)
    assert rows[0].dismissed_at is None


async def test_the_web_login_reads_the_watch_tables_and_dismisses_only(world: World) -> None:
    case = await world.open_case(1)
    sid = await suggestion_of(world, case, world.investigations[2])
    async with world.web.begin() as conn:
        await conn.execute(text("SELECT * FROM case_suggestions"))
        await conn.execute(text("SELECT * FROM case_watch_checks"))
        await conn.execute(
            text("UPDATE case_suggestions SET dismissed_at = now(), dismissed_by = 1"
                 " WHERE id = :i"),
            {"i": sid},
        )  # fmt: skip
    for statement in (
        "UPDATE case_suggestions SET why = 'changed'",
        "UPDATE case_suggestions SET kind = 'tie'",
        "DELETE FROM case_suggestions",
        "INSERT INTO case_suggestions (investigation_id, case_id, link, kind, why) VALUES"
        " (gen_random_uuid(), gen_random_uuid(), 'c2', 'shared', 'x')",
        "UPDATE case_watch_checks SET outcome = 'quiet'",
        "DELETE FROM case_watch_checks",
        "INSERT INTO case_watch_checks (case_id, day, source, outcome, reason, window_start,"
        " window_end) VALUES (gen_random_uuid(), current_date, 'alerts', 'quiet', NULL, now(),"
        " now())",
    ):
        with pytest.raises(DBAPIError) as info:
            async with world.web.begin() as conn:
                await conn.execute(text(statement))
        assert "permission denied" in str(info.value.orig), statement


async def test_the_finder_reads_only_what_the_web_login_may_read(world: World) -> None:
    """A case opened early, over investigations that alerted after it (so every read of the
    finder's scan runs), asked as the web's login: no permission is missing."""
    early = datetime(2026, 10, 1, 6, 0, tzinfo=UTC)
    who = Actor.person(await world.user_id("mina"), frozenset(c.value for c in MANAGER), via="test")
    async with world.runtime.begin() as conn:
        service = CaseService(conn, early)
        applied = await service.open(
            who,
            Open("Early", "high", "person", (Member(world.investigations[0], "person"),),
                 (Indicator("ip", "10.0.0.1", "actor"), Indicator("ip", "203.0.113.7", "c2"))),
        )  # fmt: skip
    now = datetime.now(UTC)
    finder: Callable[..., Any] = watchrun.Finder
    async with world.web.connect() as conn:
        window = await finder(conn, watch_context(None), lambda: now)(
            await (await CaseService.start(conn)).get(applied.case.id)
        )
    assert window.verified is False
    assert "has not been done yet" in window.reason
