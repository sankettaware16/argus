"""P4-F Track 2A (U1, U3, U4, U13): a possible incident (a suspected case) is decided in the app.

What this file holds the routes to: ``/cases/{id}/confirm`` and ``/dismiss`` are the terminal's
``argus case confirm`` and ``dismiss``: the same command through the same service (a version
check, one transaction, the event audited as the person), so the rows they leave are the rows the
terminal leaves, and a confirmed case waits for Kibana as it always did. A view-only account and
a reviewer without the case capability are refused before anything is read; a case that moved is
409 and nothing is written; a double submit is one change. The case page carries the decision
bar only on a suspected case, each part with the refusal the command would give. One meaning of
"incident": the dashboard counts cases; the queue never calls an outside address a device; a true
positive is never confirmed with its group."""

from __future__ import annotations

import ipaddress
import uuid
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assets.classify import IpClassifier
from argus.cases.machine import CaseRefused, Confirm, Dismiss, Notify
from argus.cases.model import LOCAL_CAPABILITIES, WAITING_FOR_KIBANA, Actor, Indicator
from argus.cases.service import CaseService
from argus.web import auth, casepages, queuepage
from argus.web.capabilities import Capability
from tests.integration.web.b3_support import V1, World, make_world, post, sign_in
from tests.integration.web.conftest import PASSWORD

pytestmark = pytest.mark.integration
C = Capability
BAR_REASONS = ["benign_expected", "attempt_no_impact", "benign_policy", "rule_false_positive",
               "duplicate"]  # fmt: skip


@pytest.fixture
async def world(
    seeded: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> World:
    made = await make_world(seeded, web_engine, migrated_engine, tmp_path)
    async with seeded.begin() as conn:  # may manage cases, may not review
        await auth.add_user(conn, "max", "Max Manager", PASSWORD,
                            capabilities=[C.VIEW, C.MANAGE_CASES])  # fmt: skip
    return made


async def case_row(w: World, case: uuid.UUID) -> Any:
    rows = await w.rows(
        "SELECT state, version, closure_reason, opened_at, closed_at, kibana_wait, attention,"
        " merged_into_id FROM cases WHERE id = :c",
        c=case,
    )
    return rows[0]


async def events(w: World, case: uuid.UUID) -> list[tuple[str, str, str | None, str]]:
    rows = await w.rows(
        "SELECT kind, actor, from_state, to_state FROM case_events WHERE case_id = :c"
        " ORDER BY case_version",
        c=case,
    )
    return [(r.kind, r.actor, r.from_state, r.to_state) for r in rows]


async def outbox(w: World, case: uuid.UUID) -> int:
    rows = await w.rows("SELECT count(*) AS n FROM kibana_outbox WHERE case_id = :c", c=case)
    return int(rows[0].n)


# --------------------------------------------------------------------------- confirm


async def test_confirm_makes_the_possible_incident_an_open_case_as_the_terminal_does(
    world: World,
) -> None:
    by_web = await world.open_suspected(4, "Web confirm")
    by_cli = await world.open_suspected(5, "Terminal confirm")
    mina = await world.user_id("mina")
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        done = await post(http, csrf, f"/cases/{by_web}/confirm",
                          {"expected_version": 1, "note": "the lab PC beacons"})  # fmt: skip
        assert done.status_code == 200, done.text
        body = done.json()
        assert body["result"] == "done"
        assert (body["case"]["state"], body["case"]["version"]) == ("open", 2)
    # the terminal's command, as `argus case confirm` gives it
    async with world.runtime.begin() as conn:
        service = await CaseService.start(conn)
        await service.apply(Actor.person(mina, LOCAL_CAPABILITIES, via="cli"), by_cli,
                            Confirm("the lab PC beacons"), expected_version=1)  # fmt: skip
    web, cli = await case_row(world, by_web), await case_row(world, by_cli)
    for row in (web, cli):
        assert (row.state, row.version) == ("open", 2)
        assert row.opened_at is not None
        # downstream as today: nothing goes to Kibana from the command; the case waits for
        # someone who may open cases there (the case team posts it by its own rules)
        assert row.kibana_wait == WAITING_FOR_KIBANA
    assert (
        await events(world, by_web)
        == await events(world, by_cli)
        == [
            ("suspected", "argus:opener", None, "suspected"),
            ("confirmed", f"user:{mina}", "suspected", "open"),
        ]
    )
    assert await outbox(world, by_web) == await outbox(world, by_cli) == 0
    notes = await world.rows(
        "SELECT details ->> 'note' AS note FROM case_events WHERE case_id = :c AND kind ="
        " 'confirmed'",
        c=by_web,
    )
    assert notes[0].note == "the lab PC beacons"


async def test_a_case_that_moved_is_refused_and_a_double_submit_is_one_change(
    world: World,
) -> None:
    case = await world.open_suspected(4)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        stale = await post(http, csrf, f"/cases/{case}/confirm", {"expected_version": 7})
        assert stale.status_code == 409, stale.text
        assert stale.json()["code"] == "conflict"
        assert (await case_row(world, case)).state == "suspected"
        first = await post(http, csrf, f"/cases/{case}/confirm", {"expected_version": 1})
        again = await post(http, csrf, f"/cases/{case}/confirm", {"expected_version": 1})
        assert (first.status_code, again.status_code) == (200, 409)
    assert [e[0] for e in await events(world, case)] == ["suspected", "confirmed"]


async def test_only_a_suspected_case_is_confirmed_or_dismissed_and_says_so(world: World) -> None:
    case = await world.open_case(1)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        confirm = await post(http, csrf, f"/cases/{case}/confirm", {"expected_version": 1})
        dismiss = await post(http, csrf, f"/cases/{case}/dismiss",
                             {"expected_version": 1, "reason": "benign_expected"})  # fmt: skip
        missing = await post(http, csrf, f"/cases/{uuid.uuid4()}/confirm",
                             {"expected_version": 1})  # fmt: skip
    assert confirm.status_code == dismiss.status_code == 409
    assert confirm.json()["detail"] == (
        "Only a possible incident (a suspected case) can be confirmed; this one is open."
    )
    assert dismiss.json()["detail"] == (
        "Only a possible incident (a suspected case) can be dismissed; this one is open."
    )
    assert missing.status_code == 404
    assert [e[0] for e in await events(world, case)] == ["opened"]


async def test_who_may_decide(world: World) -> None:
    case = await world.open_suspected(4)
    other = await world.open_suspected(5)
    async with world.app() as http:
        for user in ("vera", "rita"):  # view only; a reviewer without the case capability
            csrf = await sign_in(http, user)
            for path, body in (
                ("confirm", {"expected_version": 1}),
                ("dismiss", {"expected_version": 1, "reason": "benign_expected"}),
            ):
                got = await post(http, csrf, f"/cases/{case}/{path}", body)
                assert got.status_code == 403, (user, path, got.text)
            await http.post("/api/logout", headers={"X-CSRF-Token": csrf})
        # may manage cases, may not review: a confirm yes, a dismissal no (the machine's rule)
        csrf = await sign_in(http, "max")
        dismiss = await post(http, csrf, f"/cases/{other}/dismiss",
                             {"expected_version": 1, "reason": "benign_expected"})  # fmt: skip
        assert dismiss.status_code == 403, dismiss.text
        assert "review" in dismiss.json()["detail"]
        confirm = await post(http, csrf, f"/cases/{other}/confirm", {"expected_version": 1})
        assert confirm.status_code == 200, confirm.text
    assert [e[0] for e in await events(world, case)] == ["suspected"]


# --------------------------------------------------------------------------- dismiss


@pytest.mark.parametrize("reason", [*BAR_REASONS, "created_in_error"])
async def test_dismiss_closes_the_possible_incident_for_its_reason(
    world: World, reason: str
) -> None:
    case = await world.open_suspected(4)
    note = "a test, said the lab" if reason == "created_in_error" else None
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        done = await post(http, csrf, f"/cases/{case}/dismiss",
                          {"expected_version": 1, "reason": reason, "note": note})  # fmt: skip
        assert done.status_code == 200, done.text
        assert done.json()["case"]["state"] == "closed"
    row = await case_row(world, case)
    assert (row.state, row.closure_reason, row.version) == ("closed", reason, 2)
    assert row.opened_at is None
    assert row.closed_at is not None
    assert row.merged_into_id is None
    assert await outbox(world, case) == 0
    mina = await world.user_id("mina")
    assert (await events(world, case))[-1] == ("dismissed", f"user:{mina}", "suspected", "closed")


async def test_dismiss_reasons_outside_the_list_are_refused_before_anything(world: World) -> None:
    case = await world.open_suspected(4)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        for reason in ("risk_accepted", "remediated_verified", "stopped_after_notice", "x", ""):
            got = await post(http, csrf, f"/cases/{case}/dismiss",
                             {"expected_version": 1, "reason": reason})  # fmt: skip
            assert got.status_code == 422, (reason, got.text)
        no_reason = await post(http, csrf, f"/cases/{case}/dismiss", {"expected_version": 1})
        assert no_reason.status_code == 422
        long_note = await post(http, csrf, f"/cases/{case}/dismiss",
                               {"expected_version": 1, "reason": "benign_expected",
                                "note": "x" * 4001})  # fmt: skip
        assert long_note.status_code == 422
    assert (await case_row(world, case)).state == "suspected"


async def test_dismiss_is_the_terminals_dismissal(world: World) -> None:
    by_web = await world.open_suspected(4)
    by_cli = await world.open_suspected(5)
    mina = await world.user_id("mina")
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        done = await post(http, csrf, f"/cases/{by_web}/dismiss",
                          {"expected_version": 1, "reason": "attempt_no_impact"})  # fmt: skip
        assert done.status_code == 200, done.text
    async with world.runtime.begin() as conn:
        service = await CaseService.start(conn)
        await service.apply(Actor.person(mina, LOCAL_CAPABILITIES, via="cli"), by_cli,
                            Dismiss("attempt_no_impact"), expected_version=1)  # fmt: skip
    web, cli = await case_row(world, by_web), await case_row(world, by_cli)
    assert (web.state, web.closure_reason, web.attention) == (cli.state, cli.closure_reason,
                                                              cli.attention)  # fmt: skip
    assert await events(world, by_web) == await events(world, by_cli)


# --------------------------------------------------------------------------- the page


async def test_the_case_page_carries_the_decision_bar_only_on_a_possible_incident(
    world: World,
) -> None:
    alone = await world.open_suspected(4)
    async with world.app() as http:
        await sign_in(http, "mina")
        page = (await http.get(f"{V1}/cases/{alone}")).json()
        bar = page["decision"]
        assert [r["reason"] for r in bar["reasons"]] == BAR_REASONS
        assert all(r["label"] and r["meaning"] and "{" not in r["meaning"] for r in bar["reasons"])
        assert bar["confirm"] == {"enabled": True, "why_not": None}
        assert bar["dismiss"] == {"enabled": True, "why_not": None}
        assert bar["merge"] == {
            "enabled": False,
            "why_not": "There is no other case that is not closed to merge into.",
        }
        assert "confirm" in bar["after"]
        assert page["incident_id"] is None  # no report written yet
        other = await world.open_case(1, start=6)
        page = (await http.get(f"{V1}/cases/{alone}")).json()
        assert page["decision"]["merge"] == {"enabled": True, "why_not": None}
        assert (await http.get(f"{V1}/cases/{other}")).json()["decision"] is None
        # the closure list says how a possible incident is decided, never the command line
        why = {c["why_not"] for c in page["closure_choices"]}
        assert why == {casepages.SUSPECTED_CLOSURE}
        assert "argus case" not in casepages.SUSPECTED_CLOSURE


async def test_the_decision_bar_says_what_each_account_lacks(world: World) -> None:
    case = await world.open_suspected(4)
    async with world.app() as http:
        await sign_in(http, "vera")
        bar = (await http.get(f"{V1}/cases/{case}")).json()["decision"]
        for part in ("confirm", "dismiss", "merge"):
            assert bar[part]["enabled"] is False
            assert "manage_cases" in bar[part]["why_not"]
        await http.post("/api/logout")
    async with world.app() as http:
        await sign_in(http, "max")
        bar = (await http.get(f"{V1}/cases/{case}")).json()["decision"]
        assert bar["confirm"]["enabled"] is True
        assert bar["dismiss"]["enabled"] is False
        assert "review" in bar["dismiss"]["why_not"]


async def test_the_case_carries_one_ir_number(world: World) -> None:
    case = await world.open_suspected(4)
    async with world.owner.begin() as conn:
        await conn.execute(
            text("INSERT INTO case_team_posts (case_id, incident_id) VALUES (:c, :i)"),
            {"c": case, "i": "ACME-IR-2026-1106-02"},
        )
    async with world.app() as http:
        await sign_in(http, "mina")
        page = (await http.get(f"{V1}/cases/{case}")).json()
    assert page["incident_id"] == "ACME-IR-2026-1106-02"


# --------------------------------------------------------------------------- in Kibana already


async def post_to_kibana(
    w: World, case: uuid.UUID, kibana_case_id: str | None, step: str | None = None
) -> None:
    """The case team's post of the case, as its writer leaves it (the owner writes it here): its
    Kibana case read back, or a request of it in the given state."""
    async with w.owner.begin() as conn:
        await conn.execute(
            text("INSERT INTO case_team_posts (case_id, incident_id, kibana_case_id)"
                 " VALUES (:c, :i, :k)"),
            {"c": case, "i": "ACME-IR-2026-1106-02", "k": kibana_case_id},
        )  # fmt: skip
        if step is not None:
            await conn.execute(
                text("INSERT INTO case_team_steps (case_id, gen, seq, key, kind, author, part,"
                     " report_version, request_hash, state) VALUES (:c, 1, 1, 'tags', 'tag',"
                     " 'argus-lead', 'open', 1, repeat('a', 64), :s)"),
                {"c": case, "s": step},
            )  # fmt: skip


@pytest.mark.parametrize(("kibana_case_id", "step"), [("kb-case-1", None), (None, "sent"),
                                                      (None, "ambiguous")])  # fmt: skip
async def test_a_possible_incident_the_case_team_posted_is_never_dismissed(
    world: World, kibana_case_id: str | None, step: str | None
) -> None:
    """Review (major): a suspected case the case team posted to Kibana (a person confirmed its
    report) was dismissed as if nothing were there, and its Kibana case was left open for good.
    The bar says why not, the route and the terminal refuse it, nothing changes; confirming it
    stays open."""
    case = await world.open_suspected(4)
    await post_to_kibana(world, case, kibana_case_id, step)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        page = (await http.get(f"{V1}/cases/{case}")).json()
        dismiss = page["decision"]["dismiss"]
        assert dismiss["enabled"] is False
        assert "ACME-IR-2026-1106-02" in dismiss["why_not"]
        assert "confirm it as an incident, then ask for its closure" in dismiss["why_not"]
        assert page["decision"]["confirm"] == {"enabled": True, "why_not": None}
        assert "Kibana has nothing" not in page["mirror"]["words"]
        got = await post(http, csrf, f"/cases/{case}/dismiss",
                         {"expected_version": 1, "reason": "rule_false_positive"})  # fmt: skip
        assert got.status_code == 409, got.text
        assert got.json()["detail"] == dismiss["why_not"]
    mina = await world.user_id("mina")
    async with world.runtime.begin() as conn:
        service = await CaseService.start(conn)
        with pytest.raises(CaseRefused) as refused:
            await service.apply(Actor.person(mina, LOCAL_CAPABILITIES, via="cli"), case,
                                Dismiss("benign_expected"), expected_version=1)  # fmt: skip
    assert refused.value.code == "conflict"
    row = await case_row(world, case)
    assert (row.state, row.version, row.closed_at) == ("suspected", 1, None)
    assert [e[0] for e in await events(world, case)] == ["suspected"]


@pytest.mark.parametrize("step", [None, "planned", "skipped", "held"])
async def test_a_post_that_never_left_argus_does_not_stop_a_dismissal(
    world: World, step: str | None
) -> None:
    case = await world.open_suspected(4)
    await post_to_kibana(world, case, None, step)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        bar = (await http.get(f"{V1}/cases/{case}")).json()["decision"]
        assert bar["dismiss"] == {"enabled": True, "why_not": None}
        done = await post(http, csrf, f"/cases/{case}/dismiss",
                          {"expected_version": 1, "reason": "benign_expected"})  # fmt: skip
        assert done.status_code == 200, done.text


# --------------------------------------------------------------------------- one meaning


async def test_the_dashboard_counts_incidents_as_cases(world: World) -> None:
    await world.open_suspected(4)
    await world.open_suspected(5)
    await world.open_case(1, start=6)
    closed = await world.open_suspected(7)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        done = await post(http, csrf, f"/cases/{closed}/dismiss",
                          {"expected_version": 1, "reason": "benign_expected"})  # fmt: skip
        assert done.status_code == 200
        kpis = (await http.get(f"{V1}/dashboard", params={"range": "30d"})).json()["kpis"]
    assert (kpis["incident_cases"], kpis["possible_incidents"]) == (1, 2)
    # the investigation-level figures stay, under their own names
    assert {"incidents", "suspected"} <= set(kpis)


async def test_the_dashboards_incidents_open_the_list_they_count(world: World) -> None:
    """Review (minor): the number counted notified incidents, and its link opened the Open view,
    which leaves them out. It opens the incidents view now, whose rows and count are the
    number."""
    told = await world.open_case(1, start=0)
    await world.open_case(1, start=1)
    await world.open_suspected(4)
    mina = await world.user_id("mina")
    async with world.runtime.begin() as conn:
        service = await CaseService.start(conn)
        await service.apply(Actor.person(mina, LOCAL_CAPABILITIES, via="cli"), told,
                            Notify("the lab's owner", "email"), expected_version=1)  # fmt: skip
    async with world.app() as http:
        await sign_in(http, "mina")
        kpis = (await http.get(f"{V1}/dashboard", params={"range": "30d"})).json()["kpis"]
        listed = (await http.get(f"{V1}/cases", params={"view": "incidents"})).json()
        classic = (await http.get("/dashboard")).text
    assert kpis["incident_cases"] == 2
    assert (listed["view"], len(listed["items"]), listed["counts"]["incidents"]) == (
        "incidents", 2, 2)  # fmt: skip
    assert (listed["counts"]["active"], listed["counts"]["notified"]) == (1, 1)
    assert str(told) in {c["id"] for c in listed["items"]}
    assert 'href="/app/cases?view=incidents"' in classic
    assert "view=active" not in classic


async def test_the_classic_dashboard_keeps_one_meaning_of_incident(world: World) -> None:
    """Review (minor): the classic page called investigations "Incidents" and "Suspected"
    under the heading "Investigations called real"; it uses the app's words now."""
    async with world.app() as http:
        await sign_in(http, "mina")
        span = {"start": "2026-10-01", "end": "2026-10-31"}  # the seeded investigations' days
        page = (await http.get("/dashboard", params=span)).text
    assert "Top rules by alerts" in page
    assert "No rule in this span." not in page
    assert ">Real (a person)</th>" in page
    assert ">Real (ARGUS)</th>" in page
    assert ">Incidents</th>" not in page
    assert ">Suspected</th>" not in page
    assert "No incident in this span" not in page
    assert "By a person: their decision is" in page


async def test_the_queue_never_calls_an_outside_address_a_device(world: World) -> None:
    marks = (
        Indicator("ip", "10.0.0.1", "actor"),
        Indicator("ip", "91.121.5.50", "actor"),
        Indicator("host", "lab-pc-7", "actor"),
        Indicator("domain", "bad.example", "c2"),
    )
    case = await world.open_case(1, start=4, indicators=marks, title="Mixed actors")
    async with world.app() as http:
        await sign_in(http, "mina")
        queue = (await http.get(f"{V1}/queue")).json()
    found = next(c for c in queue["cases"] if c["id"] == str(case))
    assert (found["devices"], found["devices_total"]) == (["lab-pc-7", "10.0.0.1"], 2)
    assert (found["outside"], found["outside_total"]) == (["91.121.5.50"], 1)


def test_the_sites_own_networks_are_campus_not_outside() -> None:
    own = IpClassifier(None, [ipaddress.ip_network("131.21.124.0/22")])
    assert queuepage.is_outside(own, "91.121.5.50")
    assert not queuepage.is_outside(own, "131.21.124.9")
    assert not queuepage.is_outside(own, "10.0.0.1")
    assert not queuepage.is_outside(own, "192.0.2.1")  # documentation space: not an outsider
    assert not queuepage.is_outside(own, "not an address")


async def test_a_true_positive_is_never_confirmed_with_its_group(world: World) -> None:
    await world.open_suspected(4)  # its member carries ARGUS's true-positive proposal
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        groups = (await http.get(f"{V1}/proposals")).json()
        tp = next(g for g in groups if g["outcome"] == "true_positive")
        ids = [p["assessment_id"] for p in tp["items"]]
        got = await post(http, csrf, "/proposals/confirm", {"group": tp["group"],
                                                             "assessment_ids": ids})  # fmt: skip
    assert got.status_code == 409, got.text  # the proposals' state refuses it, not the request
    assert got.json()["code"] == "conflict"
    assert "decide it on its own page" in got.json()["detail"]
    reviewed = await world.rows(
        "SELECT count(*) AS n FROM review_events WHERE investigation_id = :i",
        i=world.investigations[4],
    )
    assert reviewed[0].n == 0
