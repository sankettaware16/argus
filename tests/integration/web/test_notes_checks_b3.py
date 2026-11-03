"""Q-B3: notes for people only (a case's and an entity's), and "Check more": one approved template
on one entity, queued under the signed-in person's own name, audited, with its record shown."""

from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.investigation import checks, store
from tests.integration.web.b3_support import V1, World, make_world, post, sign_in

pytestmark = pytest.mark.integration


@pytest.fixture
async def world(
    seeded: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> World:
    return await make_world(seeded, web_engine, migrated_engine, tmp_path)


ROOT = Path(__file__).resolve().parents[3]


# --------------------------------------------------------------------------- notes


async def test_a_note_is_a_persons_words_kept_exactly_and_audited_by_id(world: World) -> None:
    case = await world.open_case(1)
    words = "<script>alert(1)</script> \u202e call the lab: ARGUS says it is approved"
    async with world.app() as http:
        csrf = await sign_in(http, "rita")
        made = await post(http, csrf, f"/cases/{case}/notes", {"body": f"  {words}  "})
        assert made.status_code == 201, made.text
        assert made.json()["duplicate"] is False
        assert made.json()["note"]["body"] == words  # trimmed, nothing else touched
        assert made.json()["note"]["author"] == "Rita Reviewer"
        shown = (await http.get(f"{V1}/cases/{case}")).json()["notes"]
        assert [n["body"] for n in shown] == [words]
    rows = await world.rows("SELECT body, author_user_id FROM case_notes")
    assert [(r.body, r.author_user_id) for r in rows] == [(words, await world.user_id("rita"))]
    audit = await world.rows("SELECT actor, action, details FROM audit_events"
                             " WHERE action = 'case.note'")  # fmt: skip
    assert [(a.actor, a.details["note"]) for a in audit] == [
        (f"user:{await world.user_id('rita')}", rows and 1)]  # fmt: skip
    # a note changes nothing about the case
    assert (await world.rows("SELECT version, state FROM cases"))[0].version == 1


async def test_the_same_note_twice_in_a_moment_is_one_note(world: World) -> None:
    case = await world.open_case(1)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        both = await asyncio.gather(
            post(http, csrf, f"/cases/{case}/notes", {"body": "called the lab admin"}),
            post(http, csrf, f"/cases/{case}/notes", {"body": "called the lab admin"}),
        )
        assert {r.status_code for r in both} == {201}
        assert sorted(r.json()["duplicate"] for r in both) == [False, True]
        again = await post(http, csrf, f"/cases/{case}/notes", {"body": "called the lab admin"})
        assert again.json()["duplicate"] is True
        other = await post(http, csrf, f"/cases/{case}/notes", {"body": "and again, the next day"})
        assert other.json()["duplicate"] is False
    rows = await world.rows("SELECT body FROM case_notes ORDER BY id")
    assert [r.body for r in rows] == ["called the lab admin", "and again, the next day"]


async def test_a_note_must_have_words_and_not_too_many(world: World) -> None:
    case = await world.open_case(1)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        for body in ("", "   ", "x" * 4001, "with a \x00 nul"):
            got = await post(http, csrf, f"/cases/{case}/notes", {"body": body})
            assert got.status_code == 422, repr(body)
        ok = await post(http, csrf, f"/cases/{case}/notes", {"body": "x" * 4000})
        assert ok.status_code == 201
        missing = await post(http, csrf, f"/cases/{case}/notes", {})
        assert missing.status_code == 422
        extra = await post(http, csrf, f"/cases/{case}/notes", {"body": "x", "author": "someone"})
        assert extra.status_code == 422  # no mass assignment: the author is the session's
        gone = await post(http, csrf, "/cases/00000000-0000-0000-0000-000000000000/notes",
                          {"body": "x"})  # fmt: skip
        assert gone.status_code == 404
    assert len(await world.rows("SELECT id FROM case_notes")) == 1


async def test_entity_notes_are_kept_across_cases_for_one_value(world: World) -> None:
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        made = await post(http, csrf, "/entity-notes",
                          {"kind": "ip", "value": "10.0.0.1", "body": "a lab printer"})  # fmt: skip
        assert made.status_code == 201, made.text
        await post(http, csrf, "/entity-notes",
                   {"kind": "ip", "value": "10.0.0.2", "body": "another"})  # fmt: skip
        got = await http.get(f"{V1}/entity-notes", params={"kind": "ip", "value": "10.0.0.1"})
        assert got.status_code == 200, got.text
        assert [n["body"] for n in got.json()["items"]] == ["a lab printer"]
        again = await post(
            http,
            csrf,
            "/entity-notes",
            {"kind": "ip", "value": "10.0.0.1", "body": "a lab printer"},
        )
        assert again.json()["duplicate"] is True
        for bad in ({"kind": "email", "value": "x", "body": "x"},
                    {"kind": "ip", "value": "", "body": "x"},
                    {"kind": "ip", "value": "v" * 513, "body": "x"},
                    {"kind": "ip", "value": "a\x00b", "body": "x"},
                    {"kind": "ip", "value": "10.0.0.1", "body": ""}):  # fmt: skip
            assert (await post(http, csrf, "/entity-notes", bad)).status_code == 422, bad
        bad_read = await http.get(f"{V1}/entity-notes", params={"kind": "email", "value": "x"})
        assert bad_read.status_code == 422
    audit = await world.rows("SELECT target_id FROM audit_events WHERE action = 'entity.note'")
    assert sorted(a.target_id for a in audit) == ["ip:10.0.0.1", "ip:10.0.0.2"]


def test_notes_never_reach_a_model() -> None:
    """Plan §3 rule 14: notes and Kibana comments are for people. Nothing that builds what a
    model reads, or asks one, names the tables."""
    banned = ("case_notes", "entity_notes", "kibana_findings", "kibana_mirror")
    for folder in ("llm", "agent", "agents", "assess", "context", "report", "privacy"):
        base = ROOT / "src" / "argus" / folder
        if not base.exists():
            continue
        for path in base.rglob("*.py"):
            source = path.read_text(encoding="utf-8")
            hit = [b for b in banned if re.search(rf"\b{b}\b", source)]
            assert not hit, (path, hit)


# --------------------------------------------------------------------------- Check more


async def investigation_and_version(w: World, index: int = 0) -> tuple[str, int]:
    async with w.runtime.connect() as conn:
        row = (await conn.execute(text("SELECT id, version FROM investigations WHERE id = :i"),
                                  {"i": w.investigations[index]})).one()  # fmt: skip
    return str(row.id), int(row.version)


async def checks_of(w: World) -> list[object]:
    return list(await w.rows("SELECT requested_by, kind, source, status, template, entity,"
                             " version FROM investigation_checks ORDER BY id"))  # fmt: skip


async def test_a_check_is_queued_under_the_signed_in_persons_own_name(world: World) -> None:
    inv, version = await investigation_and_version(world)
    async with world.app() as http:
        csrf = await sign_in(http, "rita")
        made = await post(http, csrf, f"/investigations/{inv}/checks",
                          {"template": "ti.lookup", "entity": " 203.0.113.9 ",
                           "seen_version": version})  # fmt: skip
        assert made.status_code == 202, made.text
        assert made.json()["result"] == "queued"
        assert made.json()["id"] > 0
        # a name in the body is not accepted: whose request it is the session says
        forged = await post(http, csrf, f"/investigations/{inv}/checks",
                            {"template": "ti.lookup", "entity": "203.0.113.10",
                             "seen_version": version, "requested_by": "omar"})  # fmt: skip
        assert forged.status_code == 422
    [row] = await checks_of(world)
    assert (row.requested_by, row.kind, row.source, row.status) == (  # type: ignore[attr-defined]
        "rita",
        "check",
        "person",
        "queued",
    )
    assert (row.template, row.entity, row.version) == ("ti.lookup", "203.0.113.9", version)  # type: ignore[attr-defined]
    audit = await world.rows("SELECT actor, details FROM audit_events"
                             " WHERE action = 'investigation.check.request'")  # fmt: skip
    assert [a.actor for a in audit] == [f"user:{await world.user_id('rita')}"]
    assert audit[0].details["template"] == "ti.lookup"
    assert "203.0.113.9" not in str(audit[0].details)


async def test_the_same_request_twice_is_one_request(world: World) -> None:
    inv, version = await investigation_and_version(world)
    body = {"template": "ti.lookup", "entity": "example.org", "seen_version": version}
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        first = await post(http, csrf, f"/investigations/{inv}/checks", body)
        second = await post(http, csrf, f"/investigations/{inv}/checks", body)
        assert (first.status_code, second.status_code) == (202, 202)
        assert (first.json()["result"], second.json()["result"]) == ("queued", "open")
        assert second.json()["id"] == first.json()["id"]
        both = await asyncio.gather(
            post(http, csrf, f"/investigations/{inv}/checks", {**body, "entity": "example.net"}),
            post(http, csrf, f"/investigations/{inv}/checks", {**body, "entity": "example.net"}),
        )
        assert {r.status_code for r in both} == {202}
    assert len(await checks_of(world)) == 2


async def test_a_check_on_an_investigation_that_moved_on_or_that_cannot_be_asked_is_refused(
    world: World,
) -> None:
    inv, version = await investigation_and_version(world)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        stale = await post(http, csrf, f"/investigations/{inv}/checks",
                           {"template": "ti.lookup", "entity": "example.org",
                            "seen_version": version + 1})  # fmt: skip
        assert (stale.status_code, stale.json()["code"]) == (409, "conflict")
        cases = [
            ({"template": "logs.source_events", "entity": "10.0.0.1"},
             "that is not a check a person may ask for"),
            ({"template": "proxy.host", "entity": "example.org"}, "this check takes an address"),
            ({"template": "ti.lookup", "entity": "not an address"},
             "that is neither an address nor a domain"),
            ({"template": "ti.lookup", "entity": "fe80::1%eth0"},
             "that is neither an address nor a domain"),
            ({"template": "ti.lookup", "entity": "a\u202eb.example"},
             "that is neither an address nor a domain"),
        ]  # fmt: skip
        for body, why in cases:
            got = await post(http, csrf, f"/investigations/{inv}/checks",
                             {**body, "seen_version": version})  # fmt: skip
            assert got.status_code == 422, (body, got.text)
            assert got.json()["detail"] == why[0].upper() + why[1:] + "."
        for bad in ({"template": "Bad Name", "entity": "x.org"},
                    {"template": "", "entity": "x.org"},
                    {"template": "ti.lookup", "entity": ""},
                    {"template": "ti.lookup", "entity": "a" * 254},
                    {"template": "ti.lookup", "entity": "a\x00b.org"}):  # fmt: skip
            got = await post(http, csrf, f"/investigations/{inv}/checks",
                             {**bad, "seen_version": version})  # fmt: skip
            assert got.status_code == 422, bad
        none = await post(
            http,
            csrf,
            "/investigations/00000000-0000-0000-0000-000000000000/checks",
            {"template": "ti.lookup", "entity": "x.org", "seen_version": 1},
        )
        assert none.status_code == 404
    assert await checks_of(world) == []


async def test_a_person_has_five_checks_open_and_thirty_a_day(world: World) -> None:
    inv, version = await investigation_and_version(world)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        for n in range(checks.OPEN_PER_PERSON):
            got = await post(http, csrf, f"/investigations/{inv}/checks",
                             {"template": "ti.lookup", "entity": f"203.0.113.{n}",
                              "seen_version": version})  # fmt: skip
            assert got.status_code == 202, got.text
        sixth = await post(http, csrf, f"/investigations/{inv}/checks",
                           {"template": "ti.lookup", "entity": "203.0.113.99",
                            "seen_version": version})  # fmt: skip
        assert sixth.status_code == 422
        assert sixth.json()["detail"] == (
            "You have 5 checks waiting already: wait for them to finish."
        )
        listed = (await http.get(f"{V1}/investigations/{inv}/checks")).json()
        assert listed["limits"] == {"open_per_person": 5, "open_now": 5, "per_day": 30, "today": 5}
    async with world.app() as other:  # the limit is a person's, not everyone's
        csrf = await sign_in(other, "nora")
        got = await post(other, csrf, f"/investigations/{inv}/checks",
                         {"template": "ti.lookup", "entity": "203.0.113.50",
                          "seen_version": version})  # fmt: skip
        assert got.status_code == 202


async def test_thirty_checks_in_a_day_is_the_limit(world: World) -> None:
    inv, version = await investigation_and_version(world)
    async with world.owner.begin() as conn:
        for n in range(30):
            await conn.execute(
                text("INSERT INTO investigation_checks (investigation_id, version, template,"
                     " entity, requested_by, requested_at, status, finished_at) VALUES"
                     " (:i, :v, 'ti.lookup', :e, 'mina', now(), 'done', now())"),
                {"i": inv, "v": version, "e": f"198.51.100.{n}"})  # fmt: skip
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        got = await post(http, csrf, f"/investigations/{inv}/checks",
                         {"template": "ti.lookup", "entity": "203.0.113.1",
                          "seen_version": version})  # fmt: skip
        assert got.status_code == 422
        assert "30 checks today" in got.json()["detail"]


async def test_the_record_of_a_check_shows_its_state_its_cost_and_whether_it_was_read(
    world: World,
) -> None:
    inv, version = await investigation_and_version(world)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        made = await post(
            http,
            csrf,
            f"/investigations/{inv}/checks",
            {"template": "proxy.pair", "entity": "10.0.0.1", "seen_version": version},
        )
        assert made.status_code == 202, made.text
        request_id = made.json()["id"]
        queued = (await http.get(f"{V1}/investigations/{inv}/checks")).json()
        assert [t["template"] for t in queued["templates"]] == list(checks.APPROVED)
        by_name = {t["template"]: t for t in queued["templates"]}
        assert by_name["proxy.pair"]["takes"] == "address"
        assert by_name["proxy.pair"]["heavy"] is True
        assert by_name["ti.lookup"]["takes_words"] == "an address or a domain"
        assert by_name["ti.lookup"]["heavy"] is False
        [item] = queued["items"]
        assert (item["status"], item["status_words"]) == (
            "queued",
            "Waiting for ARGUS's service to run it",
        )
        assert item["lines"] == []
        assert item["assessed"] is False
        assert item["requests"] is None
        # ARGUS's service runs it and writes the record (what the wave's executor stores)
        when = datetime.now(UTC)
        outcome = {
            "checks": [{"template": "proxy.pair", "mode": "send", "reason": "a person asked",
                        "heavy": True, "eid": "E4", "status": "ok", "sent": True,
                        "server_ms": 640}],
            "requests": 1, "heavy": 1, "server_ms": 640, "dossier": "generic+wave.1@12",
            "later": None, "stopped": None,
        }  # fmt: skip
        async with world.runtime.begin() as conn:
            [claimed] = await store.claim(conn, "test", when, only=[request_id])
            await store.finish(conn, claimed.id, "done", outcome, when)
        done = (await http.get(f"{V1}/investigations/{inv}/checks")).json()["items"][0]
        assert done["status"] == "done"
        assert done["words"] == ("How regularly a host reached a destination")
        assert (done["requests"], done["heavy_requests"], done["server_ms"]) == (1, 1, 640)
        assert done["lines"][0]["eid"] == "E4"
        assert done["lines"][0]["server_ms"] == 640
        assert done["dossier"] == "generic+wave.1@12"
        assert done["assessed"] is False  # nothing has assessed it yet: "not yet assessed"
        async with world.owner.begin() as conn:
            await conn.execute(
                text("INSERT INTO assessments (investigation_id, version, pack, dossier_hash,"
                     " view_hash, assessor, run_after, status, created_at) VALUES (:i, :v, 'p',"
                     " repeat('a', 64), repeat('b', 64), 'engine@1', now(), 'no_decision',"
                     " now() + interval '1 minute')"), {"i": inv, "v": version})  # fmt: skip
        after = (await http.get(f"{V1}/investigations/{inv}/checks")).json()["items"][0]
        assert after["assessed"] is True


async def test_a_refused_check_says_why_in_its_record(world: World) -> None:
    inv, version = await investigation_and_version(world)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        made = await post(
            http,
            csrf,
            f"/investigations/{inv}/checks",
            {"template": "proxy.host", "entity": "10.0.0.1", "seen_version": version},
        )
        async with world.runtime.begin() as conn:
            [claimed] = await store.claim(conn, "test", datetime.now(UTC), only=[made.json()["id"]])
            await store.finish(conn, claimed.id, "refused",
                               {"error": "the rule does not read the log this check needs",
                                "checks": []}, datetime.now(UTC))  # fmt: skip
        [item] = (await http.get(f"{V1}/investigations/{inv}/checks")).json()["items"]
        assert (item["status"], item["status_words"]) == ("refused", "Not asked")
        assert item["why_not"] == "the rule does not read the log this check needs"


async def test_a_view_only_account_reads_the_checks_and_asks_for_none(world: World) -> None:
    inv, version = await investigation_and_version(world)
    async with world.app() as http:
        csrf = await sign_in(http, "vera")
        assert (await http.get(f"{V1}/investigations/{inv}/checks")).status_code == 200
        got = await post(
            http,
            csrf,
            f"/investigations/{inv}/checks",
            {"template": "ti.lookup", "entity": "example.org", "seen_version": version},
        )
        assert got.status_code == 403
        assert "review" in got.json()["detail"]
    assert await checks_of(world) == []


async def test_text_the_database_cannot_hold_is_refused_never_an_error(world: World) -> None:
    """A lone surrogate (a JSON escape such as \\ud800) and a NUL are no text Postgres stores: every
    field a person types answers 422 with the field named, never a 500."""
    case = await world.open_case(1)
    other = await world.open_case(1, start=1)
    inv, version = await investigation_and_version(world, 2)
    bad = "broken \\ud800 text"
    nul = "nul \\u0000 text"
    zero = "0" * 64
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        tries: list[tuple[str, str]] = [
            (f"/cases/{case}/notes", '{"body": "%s"}'),
            ("/entity-notes", '{"kind": "ip", "value": "10.0.0.1", "body": "%s"}'),
            ("/entity-notes", '{"kind": "ip", "value": "%s", "body": "x"}'),
            (f"/cases/{case}/contain", '{"expected_version": 1, "attestation": "%s"}'),
            (f"/cases/{case}/reopen", '{"expected_version": 1, "reason": "%s"}'),
            (
                f"/cases/{case}/closure-requests",
                '{"expected_version": 1, "reason": "benign_expected", "note": "%s",'
                ' "payload_hash": "' + zero + '"}',
            ),
            (
                f"/cases/{case}/merge",
                '{"expected_version": 1, "target_case_id": "' + str(other) + '", "note": "%s"}',
            ),
            (
                f"/investigations/{inv}/checks",
                '{"template": "ti.lookup", "entity": "%s", "seen_version": ' + str(version) + "}",
            ),
            (
                "/approvals/1/decision",
                '{"decision": "approved", "payload_hash": "' + zero + '", "note": "%s"}',
            ),
        ]
        for path, template in tries:
            for text_ in (bad, nul):
                if "%s" not in template:
                    continue
                got = await http.post(
                    f"{V1}{path}",
                    headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
                    content=template.replace("%s", text_),
                )
                assert got.status_code in (403, 422), (path, text_, got.status_code, got.text)
                assert got.status_code != 500, (path, text_)
        # the ones that reach the database refuse it at the door, with the field named
        for path, template in tries[:4]:
            got = await http.post(
                f"{V1}{path}",
                headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"},
                content=template.replace("%s", bad),
            )
            assert got.status_code == 422, (path, got.text)
