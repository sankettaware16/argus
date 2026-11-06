"""Q-B3: the case list, a case in analyst order, and the commands a person gives from the page
(take, assign, release, contain, reopen), through ``/api/v1`` on the web's own database login.

What the gate asks of this file: a view-only account gets 403 on every action; a case that moved
on is refused with 409 and nothing is written; a double submit is one change; untrusted text
(a Kibana comment, a title) comes back as it was stored, never reshaped into ARGUS's own words;
every action says why it is unavailable in the words of the refusal the command would give."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.model import Indicator
from tests.integration.web.b3_support import V1, World, make_world, post, sign_in

pytestmark = pytest.mark.integration


@pytest.fixture
async def world(
    seeded: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> World:
    return await make_world(seeded, web_engine, migrated_engine, tmp_path)


async def events_of(w: World, case: object) -> list[str]:
    rows = await w.rows("SELECT kind FROM case_events WHERE case_id = :c ORDER BY case_version",
                        c=case)  # fmt: skip
    return [r.kind for r in rows]


# --------------------------------------------------------------------------- the list


async def test_the_list_puts_the_most_severe_first_and_counts_each_view(world: World) -> None:
    low = await world.open_case(1, title="Low one", severity="low")
    crit = await world.open_case(1, title="Critical one", severity="critical", start=1)
    sus = await world.open_suspected(5)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        taken = await post(http, csrf, f"/cases/{low}/take", {"expected_version": 1})
        assert taken.status_code == 200, taken.text
        page = (await http.get(f"{V1}/cases", params={"view": "active"})).json()
        assert [c["title"] for c in page["items"]] == ["Critical one", "Low one"]
        assert page["counts"] == {"active": 2, "notified": 0, "attention": 0, "mine": 1,
                                  "suspected": 1, "closed": 0, "queue": 2, "work": 2,
                                  "all": 3, "incidents": 2}  # fmt: skip
        mine = (await http.get(f"{V1}/cases", params={"view": "mine"})).json()
        assert [c["title"] for c in mine["items"]] == ["Low one"]
        assert mine["items"][0]["owner"]["username"] == "mina"
        suspected = (await http.get(f"{V1}/cases", params={"view": "suspected"})).json()
        assert [c["id"] for c in suspected["items"]] == [str(sus)]
        everything = (await http.get(f"{V1}/cases", params={"view": "all"})).json()
        # suspected cases come after the confirmed ones, whatever their severity
        assert [c["title"] for c in everything["items"]] == ["Critical one", "Low one",
                                                             "Proposed beacon"]  # fmt: skip
        assert str(crit) in {c["id"] for c in everything["items"]}


async def test_a_case_is_found_by_its_number_or_a_word_of_its_title(world: World) -> None:
    await world.open_case(1, title="Beacon 100% of the time")
    await world.open_case(1, title="Something else", start=1)
    async with world.app() as http:
        await sign_in(http, "mina")
        by_number = (await http.get(f"{V1}/cases", params={"number": 2})).json()
        assert [c["title"] for c in by_number["items"]] == ["Something else"]
        by_word = (await http.get(f"{V1}/cases", params={"q": "beacon"})).json()
        assert [c["title"] for c in by_word["items"]] == ["Beacon 100% of the time"]
        # % and _ are letters, not wildcards: "%" alone matches the one title that has it
        literal = (await http.get(f"{V1}/cases", params={"q": "%"})).json()
        assert [c["title"] for c in literal["items"]] == ["Beacon 100% of the time"]
        underscore = (await http.get(f"{V1}/cases", params={"q": "_"})).json()
        assert underscore["items"] == []
        assert (await http.get(f"{V1}/cases", params={"q": "\x00"})).status_code == 422
        assert (await http.get(f"{V1}/cases", params={"view": "bogus"})).status_code == 422
        assert (await http.get(f"{V1}/cases", params={"limit": 101})).status_code == 422


async def test_a_case_needing_attention_is_listed_as_such(world: World) -> None:
    quiet = await world.open_case(1, title="Quiet")
    loud = await world.open_case(1, title="Loud", start=1)
    async with world.runtime.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO kibana_findings (found_at, kind, severity, case_id, dedupe_key,"
                " details) VALUES (now(), 'closed_in_kibana', 'attention', :c, 'k1',"
                ' \'{"by": "someone"}\')'
            ),
            {"c": loud},
        )
    async with world.app() as http:
        await sign_in(http, "mina")
        page = (await http.get(f"{V1}/cases", params={"view": "attention"})).json()
        assert [c["id"] for c in page["items"]] == [str(loud)]
        assert page["items"][0]["needs_attention"] is True
        every = (await http.get(f"{V1}/cases", params={"view": "active"})).json()
        flags = {c["id"]: c["needs_attention"] for c in every["items"]}
        assert flags == {str(quiet): False, str(loud): True}


# --------------------------------------------------------------------------- one case


async def test_a_case_page_has_each_part_in_the_analysts_order(world: World) -> None:
    marks = (Indicator("ip", "10.0.0.1", "actor"), Indicator("domain", "bad.example", "c2"))
    case = await world.open_case(3, indicators=marks)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        note = await post(http, csrf, f"/cases/{case}/notes", {"body": "called the lab admin"})
        assert note.status_code == 201, note.text
        marked = await post(
            http,
            csrf,
            "/entity-notes",
            {"kind": "ip", "value": "10.0.0.1", "body": "a lab printer"},
        )
        assert marked.status_code == 201, marked.text
        got = await http.get(f"{V1}/cases/{case}")
        assert got.status_code == 200, got.text
        body = got.json()
        assert list(body)[:8] == ["case", "cause_words", "parent", "children", "children_total",
                                  "summary", "whats_new", "timeline"]  # fmt: skip
        assert body["case"]["investigations"] == body["summary"]["investigations"] == 3
        assert body["investigations_total"] == len(body["investigations"]) == 3
        assert all(i["version"] >= 1 for i in body["investigations"])
        assert body["summary"]["alerts"] == body["case"]["alerts"] > 0
        assert body["summary"]["reviewed"] == 0
        assert body["summary"]["unreviewed"] == 3
        assert body["lead_investigation_id"] == body["investigations"][0]["investigation_id"]
        assert body["cause_words"] == "Opened by a person."
        assert [(i["kind"], i["role"], i["note_count"]) for i in body["indicators"]] == [
            ("domain", "c2", 0), ("ip", "actor", 1)]  # fmt: skip
        assert body["indicators"][1]["notes"][0]["body"] == "a lab printer"
        assert [n["body"] for n in body["notes"]] == ["called the lab admin"]
        assert body["notes"][0]["author"] == "Mina Manager"
        assert [h["kind"] for h in body["history"]] == ["event"]
        assert body["history"][0]["text"] == "Mina Manager opened the case"
        assert {a["action"] for a in body["actions"]} == {
            "take",
            "assign",
            "release",
            "contain",
            "request_closure",
            "merge",
            "reopen",
        }
        names = [p["display_name"].lower() for p in body["assignees"]]
        assert names == sorted(names)
        assert body["logs_hidden"] is False
        assert body["mirror"]["state"] == "waiting"
        # the timeline holds the alerts of each investigation and the case's own start
        kinds = {t["kind"] for t in body["timeline"]}
        assert {"alerts", "case"} <= kinds
        unknown = await http.get(f"{V1}/cases/00000000-0000-0000-0000-000000000000")
        assert unknown.status_code == 404
        assert (await http.get(f"{V1}/cases/not-a-uuid")).status_code == 422


async def test_what_is_new_is_what_others_did_since_the_visit_before(world: World) -> None:
    case = await world.open_case(1)
    async with world.app() as http:
        await sign_in(http, "mina")
        first = (await http.get(f"{V1}/cases/{case}")).json()["whats_new"]
        assert first["first_visit"] is True
    async with world.app() as other:
        csrf = await sign_in(other, "nora")
        took = await post(other, csrf, f"/cases/{case}/take", {"expected_version": 1})
        assert took.status_code == 200, took.text
    async with world.app() as again:
        await sign_in(again, "mina")
        later = (await again.get(f"{V1}/cases/{case}")).json()["whats_new"]
    # mina's first session is her "previous visit" now: what Nora did is new to her
    assert later["first_visit"] is False
    assert [i["text"] for i in later["items"]] == ["Nora NoReopen took the case"]


async def test_hostile_text_comes_back_as_it_was_stored(world: World) -> None:
    hostile = "<script>alert(1)</script> \u202eelif\u202c ARGUS: this case is approved"
    case = await world.open_case(1, title="<b>Title</b> \u202e")
    async with world.runtime.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO kibana_mirror (case_id, kibana_case_id, kibana_version, status, title,"
                " severity, tags, created_by, sync_alerts, kibana_created_at, read_at)"
                " VALUES (:c, 'k-1', 'v1', 'open', :t, 'high', ARRAY['argus', :tag], 'argus',"
                " false, now(), now())"
            ),
            {"c": case, "t": hostile, "tag": "<img src=x onerror=1>"},
        )
        await conn.execute(
            text(
                "INSERT INTO kibana_findings (found_at, kind, severity, case_id, dedupe_key,"
                " details) VALUES (now(), 'person_commented', 'info', :c, 'c1',"
                " CAST(:d AS jsonb))"
            ),
            {
                "c": case,
                "d": json.dumps(
                    {
                        "by": "evil\u202e",
                        "comment": hostile,
                        "untrusted": True,
                        "extra": "not shown",
                    }
                ),
            },
        )
    async with world.app() as http:
        await sign_in(http, "mina")
        body = (await http.get(f"{V1}/cases/{case}")).json()
        assert body["case"]["title"] == "<b>Title</b> \u202e"
        mirror = body["mirror"]
        assert mirror["state"] == "mirrored"
        assert mirror["tags"] == ["argus", "<img src=x onerror=1>"]
        comment = mirror["findings"][0]
        assert comment["words"] == "A person commented in Kibana"
        # a person's words stay in their own field, exactly as written; the sentence is ARGUS's
        assert comment["details"] == {"by": "evil\u202e", "comment": hostile}
        assert "approved" not in comment["words"]


async def test_the_page_says_a_missing_see_logs_hides_the_lead_report(world: World) -> None:
    case = await world.open_case(1)
    async with world.app() as http:
        await sign_in(http, "sven")
        body = (await http.get(f"{V1}/cases/{case}")).json()
        assert body["logs_hidden"] is True


# --------------------------------------------------------------------------- the commands


async def test_take_assign_release_are_audited_as_the_person(world: World) -> None:
    case = await world.open_case(1)
    omar = await world.user_id("omar")
    mina = await world.user_id("mina")
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        taken = await post(http, csrf, f"/cases/{case}/take", {"expected_version": 1})
        assert taken.status_code == 200, taken.text
        assert taken.json()["result"] == "done"
        assert taken.json()["case"]["state"] == "assigned"
        assert taken.json()["case"]["owner"]["username"] == "mina"
        again = await post(http, csrf, f"/cases/{case}/take", {"expected_version": 2})
        assert (again.status_code, again.json()["detail"]) == (409, "You own this case already.")
        gave = await post(http, csrf, f"/cases/{case}/assign",
                          {"expected_version": 2, "user_id": omar})  # fmt: skip
        assert gave.status_code == 200, gave.text
        assert gave.json()["case"]["owner"]["username"] == "omar"
        released = await post(http, csrf, f"/cases/{case}/release", {"expected_version": 3})
        assert released.status_code == 200, released.text
        assert (released.json()["case"]["state"], released.json()["case"]["owner"]) == (
            "open",
            None,
        )
        nobody = await post(http, csrf, f"/cases/{case}/release", {"expected_version": 4})
        assert nobody.status_code == 409
        assert nobody.json()["detail"] == "Only an assigned case can be released; this one is open."
    assert await events_of(world, case) == ["opened", "taken", "assigned", "released"]
    actors = await world.rows(
        "SELECT actor, action FROM audit_events WHERE action LIKE 'case.%' AND target_id = :c"
        " ORDER BY id", c=str(case))  # fmt: skip
    assert [(a.actor, a.action) for a in actors] == [
        (f"user:{mina}", "case.opened"), (f"user:{mina}", "case.taken"),
        (f"user:{mina}", "case.assigned"), (f"user:{mina}", "case.released")]  # fmt: skip


async def test_a_confirmed_case_is_reopened_only_after_it_is_closed(world: World) -> None:
    case = await world.open_case(1)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        refused = await post(http, csrf, f"/cases/{case}/reopen",
                             {"expected_version": 1, "reason": "again"})  # fmt: skip
        assert refused.status_code == 409
        assert refused.json()["detail"] == "Only a closed case can be reopened; this one is open."
        blank = await post(http, csrf, f"/cases/{case}/reopen",
                           {"expected_version": 1, "reason": ""})  # fmt: skip
        assert blank.status_code == 422


async def test_containing_a_case_is_refused_until_a_quiet_window_can_be_shown(
    world: World,
) -> None:
    case = await world.open_case(1)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        refused = await post(http, csrf, f"/cases/{case}/contain",
                             {"expected_version": 1, "attestation": "it is quiet"})  # fmt: skip
        assert refused.status_code == 409
        assert refused.json()["code"] == "not_ready"
        assert "has not shown the case quiet for 72 hours" in refused.json()["detail"]
        actions = {a["action"]: a for a in (await http.get(f"{V1}/cases/{case}")).json()["actions"]}
        assert actions["contain"]["enabled"] is False
        assert actions["contain"]["why_not"] == refused.json()["detail"]
    assert await events_of(world, case) == ["opened"]


async def test_a_case_goes_only_to_an_active_person(world: World) -> None:
    case = await world.open_case(1)
    omar = await world.user_id("omar")
    async with world.runtime.begin() as conn:
        assistant = (
            await conn.execute(
                text("INSERT INTO users (username, display_name, password_hash, kind)"
                     " VALUES ('argus-assistant', 'Assistant', 'x', 'service') RETURNING id")
            )
        ).scalar_one()  # fmt: skip
        await conn.execute(text("UPDATE users SET disabled = true WHERE id = :u"), {"u": omar})
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        for user in (assistant, omar, 999999):
            refused = await post(http, csrf, f"/cases/{case}/assign",
                                 {"expected_version": 1, "user_id": user})  # fmt: skip
            assert refused.status_code == 422, (user, refused.text)
            assert refused.json()["detail"] == "The case can only go to an active person."
        names = {p["username"] for p in (await http.get(f"{V1}/cases/{case}")).json()["assignees"]}
        assert "argus-assistant" not in names
        assert "omar" not in names
        assert "mina" in names
    assert await events_of(world, case) == ["opened"]


# ------------------------------------------------------------ stale, double, view-only


async def test_a_command_on_a_version_that_moved_is_refused_and_writes_nothing(
    world: World,
) -> None:
    case = await world.open_case(1)
    async with world.app() as mina, world.app() as nora:
        csrf = await sign_in(mina, "mina")
        csrf_n = await sign_in(nora, "nora")
        took = await post(nora, csrf_n, f"/cases/{case}/take", {"expected_version": 1})
        assert took.status_code == 200
        stale = await post(
            mina,
            csrf,
            f"/cases/{case}/assign",
            {"expected_version": 1, "user_id": await world.user_id("omar")},
        )
        assert stale.status_code == 409
        assert stale.json()["code"] == "conflict"
        assert "it is at version 2, you saw 1" in stale.json()["detail"]
        for path, body in (("take", {}), ("release", {}), ("contain", {"attestation": "x"}),
                           ("reopen", {"reason": "x"})):  # fmt: skip
            got = await post(mina, csrf, f"/cases/{case}/{path}", {"expected_version": 1, **body})
            assert got.status_code == 409, (path, got.text)
    assert await events_of(world, case) == ["opened", "taken"]


async def test_two_submits_at_once_make_one_change(world: World) -> None:
    case = await world.open_case(1)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        both = await asyncio.gather(
            post(http, csrf, f"/cases/{case}/take", {"expected_version": 1}),
            post(http, csrf, f"/cases/{case}/take", {"expected_version": 1}),
        )
        assert sorted(r.status_code for r in both) == [200, 409]
    assert await events_of(world, case) == ["opened", "taken"]


_COUNTS = (
    "SELECT (SELECT count(*) FROM case_events) AS e, (SELECT count(*) FROM case_notes) AS n,"
    " (SELECT count(*) FROM entity_notes) AS en, (SELECT count(*) FROM approval_requests) AS a,"
    " (SELECT count(*) FROM approval_decisions) AS d"
)


async def test_a_view_only_account_gets_403_on_every_action(world: World) -> None:
    case = await world.open_case(2)
    omar = await world.user_id("omar")
    actions = [
        ("take", {"expected_version": 1}),
        ("assign", {"expected_version": 1, "user_id": omar}),
        ("release", {"expected_version": 1}),
        ("contain", {"expected_version": 1, "attestation": "x"}),
        ("reopen", {"expected_version": 1, "reason": "x"}),
        ("closure-requests", {"expected_version": 1, "reason": "benign_expected",
                              "payload_hash": "0" * 64}),
        ("merge", {"expected_version": 1, "target_case_id": str(case)}),
        ("notes", {"body": "x"}),
    ]  # fmt: skip
    before = await world.rows(_COUNTS)
    async with world.app() as http:
        csrf = await sign_in(http, "vera")
        for path, body in actions:
            got = await post(http, csrf, f"/cases/{case}/{path}", body)
            assert got.status_code == 403, (path, got.text)
            assert got.json()["code"] == "forbidden", path
        extra = [
            ("/entity-notes", {"kind": "ip", "value": "10.0.0.1", "body": "x"}),
            ("/approvals/1/decision", {"decision": "approved", "payload_hash": "0" * 64}),
            ("/approvals/group", {"items": [{"request_id": 1, "payload_hash": "0" * 64},
                                            {"request_id": 2, "payload_hash": "0" * 64}]}),
        ]  # fmt: skip
        for path, body in extra:
            got = await post(http, csrf, path, body)
            assert got.status_code == 403, (path, got.text)
        # a missing CSRF token is refused before anything else
        bare = await http.post(f"{V1}/cases/{case}/take", json={"expected_version": 1})
        assert (bare.status_code, bare.json()["code"]) == (403, "csrf")
    after = await world.rows(_COUNTS)
    assert tuple(before[0]) == tuple(after[0])


async def test_each_action_needs_its_own_capability(world: World) -> None:
    case = await world.open_case(1)
    async with world.app() as http:
        csrf = await sign_in(http, "rita")  # may review (notes), not manage cases
        for path, body in (("take", {"expected_version": 1}),
                           ("closure-requests", {"expected_version": 1, "reason": "benign_policy",
                                                 "payload_hash": "0" * 64})):  # fmt: skip
            got = await post(http, csrf, f"/cases/{case}/{path}", body)
            assert got.status_code == 403, path
            assert "manage_cases" in got.json()["detail"]
        noted = await post(http, csrf, f"/cases/{case}/notes", {"body": "ok"})
        assert noted.status_code == 201
        actions = {a["action"]: a for a in (await http.get(f"{V1}/cases/{case}")).json()["actions"]}
        assert not any(a["enabled"] for a in actions.values())
        assert "manage_cases" in actions["take"]["why_not"]
        assert "reopen" in actions["reopen"]["why_not"]
    async with world.app() as http:
        csrf = await sign_in(http, "nora")  # manages cases, may not reopen
        got = await post(
            http, csrf, f"/cases/{case}/reopen", {"expected_version": 1, "reason": "x"}
        )
        assert got.status_code == 403
        assert "reopen" in got.json()["detail"]
        took = await post(http, csrf, f"/cases/{case}/take", {"expected_version": 1})
        assert took.status_code == 200


async def test_the_previews_are_readable_by_anyone_who_may_view(world: World) -> None:
    case = await world.open_case(1)
    async with world.app() as http:
        await sign_in(http, "vera")
        got = await http.get(f"{V1}/cases/{case}/closure-preview",
                             params={"reason": "benign_expected"})  # fmt: skip
        assert got.status_code == 200, got.text
        assert got.json()["bound_version"] == 2
        none = await http.get(f"{V1}/cases/{case}/merge-preview", params={"target": str(case)})
        assert none.status_code == 422  # a case is not merged into itself
        assert none.json()["detail"] == "A case cannot be merged into itself."


async def test_a_suspected_case_cannot_be_closed_with_an_approval(world: World) -> None:
    sus = await world.open_suspected(0)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        body = (await http.get(f"{V1}/cases/{sus}")).json()
        actions = {a["action"]: a for a in body["actions"]}
        assert actions["request_closure"]["enabled"] is False
        assert "the decision at the top of its page" in actions["request_closure"]["why_not"]
        assert all(not c["enabled"] for c in body["closure_choices"])
        got = await http.get(f"{V1}/cases/{sus}/closure-preview",
                             params={"reason": "benign_expected"})  # fmt: skip
        assert got.status_code == 409
        refused = await post(http, csrf, f"/cases/{sus}/closure-requests",
                             {"expected_version": 1, "reason": "benign_expected",
                              "payload_hash": "0" * 64})  # fmt: skip
        assert refused.status_code == 409
        assert body["cause_words"] == "Suspected from ARGUS's own proposal."
    assert await events_of(world, sus) == ["suspected"]


async def test_the_permanent_link_of_a_case_leads_to_its_page(world: World) -> None:
    case = await world.open_case(1)
    async with world.app() as http:
        await sign_in(http, "mina")
        same = await http.get(f"/go/case/{case}", headers={"Sec-Fetch-Site": "same-origin"})
        assert (same.status_code, same.headers["location"]) == (303, f"/app/cases/{case}")
        # from Kibana (another site) the cookie is not sent: a bounce page opens it from this site
        across = await http.get(f"/go/case/{case}", headers={"Sec-Fetch-Site": "cross-site"})
        assert across.status_code == 200
        assert f"/app/cases/{case}" in across.text
        mangled = await http.get(f"/go/case/{str(case)[:-1]}")
        assert mangled.status_code == 404
