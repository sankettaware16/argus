"""The incident report through ``/api/v1`` (AR7, D-190) on the web's own database login: a viewer
reads it, an account without log access sees what the logs said hidden, the files download (the PDF
needs ``see_logs``), a reviewer confirms or rejects it with a reason, a view-only account and a
request without the CSRF token are refused, a stale version is a conflict, and the decision becomes
a label through the review path (and the gold set's answer where the member is a gold item)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.machine import Dismiss
from argus.cases.model import Actor, Capability
from argus.cases.service import CaseService
from argus.incident import gather, run
from argus.web import auth
from argus.web.capabilities import Capability as WebCap
from tests.integration.incident import kit
from tests.integration.web.b3_support import (
    PASSWORD,
    V1,
    World,
    headers,
    make_world,
    post,
    sign_in,
)

pytestmark = pytest.mark.integration


@pytest.fixture
async def world(
    seeded: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> World:
    made = await make_world(seeded, web_engine, migrated_engine, tmp_path)
    async with seeded.begin() as conn:
        await auth.add_user(
            conn, "gwen", "Gwen Gold", PASSWORD,
            capabilities=[WebCap.VIEW, WebCap.REVIEW, WebCap.ANSWER_GOLD],
        )  # fmt: skip
    return made


async def a_case(world: World, members: int = 3, *, verdict: bool = True) -> uuid.UUID:
    case = await world.open_case(members, title="Regular beaconing from 10.0.0.1")
    if verdict:
        for inv in world.investigations[:members]:
            await kit.propose(world.owner, inv)
    return case


async def write_report(world: World, case: uuid.UUID) -> int:
    now = datetime.now(UTC)
    ctx = run.context_for(kit.settings(), now)
    async with world.runtime.connect() as conn:
        signal = (await gather.signals(conn, [case]))[case]
    made = await run.make(world.runtime, case, ctx)
    assert made is not None
    stored, _ = await run.write(world.runtime, made, run.key_of(signal, ctx), now)
    assert stored is not None
    return stored.version


async def get(http, case: object, **params: object):  # type: ignore[no-untyped-def]
    return await http.get(f"{V1}/cases/{case}/report", params=params)


# --------------------------------------------------------------------------- reading


async def test_a_viewer_reads_the_report_and_is_told_when_there_is_none(world: World) -> None:
    case = await a_case(world)
    async with world.app() as http:
        await sign_in(http, "vera")
        none = (await get(http, case)).json()
        assert none["report"] is None
        assert none["version"] is None
        assert none["versions"] == []
        assert "next assessment pass" in none["note"]
        assert none["confirm"]["enabled"] is False
        assert none["reject"]["enabled"] is False
        assert (await get(http, uuid.uuid4())).status_code == 404

        await write_report(world, case)
        got = (await get(http, case)).json()
    assert got["version"] == got["newest"] == 1
    assert got["case_number"] >= 1
    report = got["report"]
    assert report["header"]["incident_id"].startswith("ACME-IR-")
    assert report["verdict"]["outcome"] == "true_positive"
    assert report["evidence"][0]["id"] == "E1"
    assert all(e["query"]["url"].startswith("https://") for e in report["evidence"])
    assert [f["kind"] for f in got["files"]] == ["pdf", "indicators_csv", "affected_csv"]
    assert got["logs_hidden"] is True  # a view-only account may not read the logs
    assert got["stale"] is False
    assert got["decision"] is None
    assert got["confirm"]["enabled"] is False  # a view-only account: why in plain words
    assert "review capability" in got["confirm"]["why_not"]


async def test_an_account_without_log_access_sees_what_the_logs_said_hidden(world: World) -> None:
    case = await a_case(world)
    owner_facts = world.investigations[0]
    await kit.pair_evidence(world.owner, owner_facts, "77.221.155.150", 42, datetime.now(UTC))
    await write_report(world, case)
    async with world.app() as http:
        await sign_in(http, "sven")  # may review and manage cases, but not read the logs
        hidden = (await get(http, case)).json()
        await sign_in(http, "mina")
        shown = (await get(http, case)).json()
    assert hidden["logs_hidden"] is True
    assert shown["logs_hidden"] is False
    pair_hidden = [e for e in hidden["report"]["evidence"] if e["from_logs"]]
    pair_shown = [e for e in shown["report"]["evidence"] if e["from_logs"]]
    assert pair_shown
    assert len(pair_hidden) == len(pair_shown)
    assert all(e["count"] is None for e in pair_hidden)
    facts = {f["id"]: f for f in hidden["report"]["facts"]}
    assert all(facts[e["fact"]]["text"] == "Hidden: needs log access in ELK." for e in pair_hidden)
    assert next(f for f in hidden["files"] if f["kind"] == "pdf")["available"] is False
    assert next(f for f in shown["files"] if f["kind"] == "pdf")["available"] is True


async def test_the_files_download_and_the_pdf_needs_log_access(world: World) -> None:
    case = await a_case(world)
    await write_report(world, case)
    async with world.app() as http:
        await sign_in(http, "vera")
        csv = await http.get(f"{V1}/cases/{case}/report/files/indicators.csv")
        assert csv.status_code == 200
        assert csv.content.startswith(b"\xef\xbb\xbf")
        assert csv.headers["content-type"].startswith("text/csv")
        assert 'filename="ACME-IR-' in csv.headers["content-disposition"]
        assert csv.text.lstrip("﻿").startswith("indicator,type,role,evidence")
        aff = await http.get(f"{V1}/cases/{case}/report/files/affected-devices.csv")
        assert aff.status_code == 200
        assert "device_ip,domain,days_with_alert" in aff.text
        refused = await http.get(f"{V1}/cases/{case}/report/files/report.pdf")
        assert refused.status_code == 403
        assert refused.json()["code"] == "forbidden"
        await sign_in(http, "mina")
        pdf = await http.get(f"{V1}/cases/{case}/report/files/report.pdf")
        assert pdf.status_code == 200
        assert pdf.content.startswith(b"%PDF-")
        assert (
            await http.get(f"{V1}/cases/{case}/report/files/report.pdf", params={"version": 9})
        ).status_code == 404
        assert (
            await http.get(f"{V1}/cases/{uuid.uuid4()}/report/files/report.pdf")
        ).status_code == 404
        assert (await http.get(f"{V1}/cases/{case}/report/files/other.txt")).status_code == 422


# --------------------------------------------------------------------------- deciding


async def test_confirming_labels_the_members_through_the_review_path_and_closes_nothing(
    world: World,
) -> None:
    case = await a_case(world, 3)
    await write_report(world, case)
    before = await world.rows("SELECT state, version FROM cases WHERE id = :c", c=case)
    async with world.app() as http:
        viewer = await sign_in(http, "vera")
        refused = await post(http, viewer, f"/cases/{case}/report/confirm", {"expected_version": 1})
        assert refused.status_code == 403
        assert refused.json()["code"] == "forbidden"
        reviewer = await sign_in(http, "rita")
        nothing = await http.post(f"{V1}/cases/{case}/report/confirm", json={"expected_version": 1})
        assert nothing.status_code == 403
        assert nothing.json()["code"] == "csrf"
        wrong = await http.post(f"{V1}/cases/{case}/report/confirm", json={"expected_version": 1},
                                headers=headers("not-the-token"))  # fmt: skip
        assert wrong.status_code == 403
        assert (
            await post(http, reviewer, f"/cases/{case}/report/confirm", {"expected_version": 4})
        ).status_code == 409
        assert (await post(http, reviewer, f"/cases/{case}/report/confirm", {})).status_code == 422
        done = await post(http, reviewer, f"/cases/{case}/report/confirm", {"expected_version": 1})
        assert done.status_code == 200, done.text
        shown = (await get(http, case)).json()
    body = done.json()
    assert body["labelled"] == 3
    assert body["kept"] == 0
    assert body["decision"]["decision"] == "confirmed"
    assert "Nothing was closed" in body["words"]
    assert shown["decision"]["by"] == "Rita Reviewer"
    assert shown["decision"]["labelled"] == 3
    reviews = await world.rows(
        "SELECT r.outcome, r.note, r.action FROM review_events r JOIN case_members m"
        " ON m.investigation_id = r.investigation_id WHERE m.case_id = :c", c=case,
    )  # fmt: skip
    assert len(reviews) == 3
    assert {(r.outcome, r.action) for r in reviews} == {("true_positive", "reviewed")}
    assert all("Confirmed with the incident report (version 1)" in r.note for r in reviews)
    after = await world.rows("SELECT state, version FROM cases WHERE id = :c", c=case)
    assert after == before  # confirming closes nothing and changes no case
    assert await world.rows("SELECT id FROM approval_requests WHERE case_id = :c", c=case) == []
    (row,) = await world.rows(
        "SELECT decision, outcome, reason, by_user_id FROM incident_report_decisions"
    )
    assert (row.decision, row.outcome, row.reason) == ("confirmed", "true_positive", None)
    audited = await world.rows(
        "SELECT action FROM audit_events WHERE action = 'incident.report.confirmed'"
    )
    assert len(audited) == 1


async def test_a_confirm_never_overrides_a_person_s_own_review_and_a_reject_does(
    world: World,
) -> None:
    case = await a_case(world, 3)
    first, second, third = world.investigations[:3]
    async with world.runtime.begin() as conn:
        for inv, outcome in ((first, "benign_expected"), (second, "true_positive")):
            await conn.execute(
                text(
                    "INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                    " action, outcome) SELECT i.id, i.version, i.alert_count, (SELECT id FROM"
                    " users WHERE username = 'asha'), 'reviewed', :o FROM investigations i"
                    " WHERE i.id = :i"
                ),
                {"i": inv, "o": outcome},
            )
    await write_report(world, case)
    async with world.app() as http:
        csrf = await sign_in(http, "rita")
        shown = (await get(http, case)).json()
        assert shown["report"]["verdict"]["kind"] == "person"  # people's reviews are the verdict
        assert shown["report"]["verdict"]["outcome"] == "benign_expected"  # the tie: by name
        done = (
            await post(http, csrf, f"/cases/{case}/report/confirm", {"expected_version": 1})
        ).json()
    assert (done["labelled"], done["already"], done["kept"]) == (1, 1, 1)
    state = await world.rows(
        "SELECT investigation_id, outcome FROM review_state WHERE investigation_id = ANY(:i)",
        i=[first, second, third],
    )
    assert {r.investigation_id: r.outcome for r in state} == {
        first: "benign_expected",
        second: "true_positive",  # a person's own, different review is kept
        third: "benign_expected",
    }


async def test_a_rejection_needs_a_reason_and_an_outcome_and_becomes_a_label_with_it(
    world: World,
) -> None:
    case = await a_case(world, 3)
    await write_report(world, case)
    reason = "It is the department's backup tool; the vendor confirmed it."
    async with world.app() as http:
        csrf = await sign_in(http, "rita")
        path = f"/cases/{case}/report/reject"
        for bad in (
            {"expected_version": 1, "outcome": "benign_expected", "reason": ""},
            {"expected_version": 1, "outcome": "benign_expected", "reason": "no"},
            {"expected_version": 1, "outcome": "benign_expected", "reason": "   \t  "},
            {"expected_version": 1, "outcome": "benign_expected"},
            {"expected_version": 1, "reason": reason},
            {"expected_version": 1, "outcome": "malicious", "reason": reason},
            {"expected_version": 1, "outcome": "benign_expected", "reason": "x\x00y z"},
            {"expected_version": 1, "outcome": "benign_expected", "reason": reason, "extra": 1},
        ):
            assert (await post(http, csrf, path, bad)).status_code == 422, bad
        same = await post(
            http, csrf, path, {"expected_version": 1, "outcome": "true_positive", "reason": reason}
        )
        assert same.status_code == 422
        assert "confirm it instead" in same.json()["detail"]
        stale = await post(
            http,
            csrf,
            path,
            {"expected_version": 2, "outcome": "benign_expected", "reason": reason},
        )
        assert stale.status_code == 409
        assert await world.rows("SELECT id FROM review_events") == []  # nothing was saved
        done = await post(
            http,
            csrf,
            path,
            {"expected_version": 1, "outcome": "benign_expected", "reason": reason},
        )
        assert done.status_code == 200, done.text
        shown = (await get(http, case)).json()
    assert shown["decision"]["decision"] == "rejected"
    assert shown["decision"]["reason"] == reason
    assert shown["decision"]["outcome"] == "benign_expected"
    reviews = await world.rows(
        "SELECT r.outcome, r.note FROM review_events r JOIN case_members m"
        " ON m.investigation_id = r.investigation_id WHERE m.case_id = :c", c=case,
    )  # fmt: skip
    assert len(reviews) == 3
    assert {r.outcome for r in reviews} == {"benign_expected"}
    assert all(
        reason in r.note and "Rejected the incident report (version 1)" in r.note for r in reviews
    )
    state = await world.rows(
        "SELECT outcome FROM review_state WHERE investigation_id = ANY(:i)",
        i=world.investigations[:3],
    )
    assert [r.outcome for r in state] == ["benign_expected"] * 3  # what the engine learns from


async def test_a_rejection_saves_the_gold_answer_where_the_member_is_a_gold_item(
    world: World,
) -> None:
    case = await a_case(world, 2)
    gold = world.investigations[0]
    async with world.owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO gold_items (set_name, investigation_id, version, pack, dossier_hash,"
                " rule_name, split, why, suggestion) SELECT 'v2', i.id, i.version, 'generic@12',"
                " repeat('c', 64), 'R', 'dev', '{}', '{}'::jsonb FROM investigations i"
                " WHERE i.id = :i"
            ),
            {"i": gold},
        )
    await write_report(world, case)
    body = {
        "expected_version": 1,
        "outcome": "benign_policy",
        "reason": "Allowed by the lab policy.",
    }
    async with world.app() as http:
        csrf = await sign_in(http, "rita")  # no answer_gold: the review is the label
        plain = (await post(http, csrf, f"/cases/{case}/report/reject", body)).json()
        assert plain["gold_saved"] == 0
        assert plain["labelled"] == 2
        assert await world.rows("SELECT id FROM gold_labels") == []
        assert await write_report(world, case) == 2  # people's reviews changed the verdict
        csrf = await sign_in(http, "gwen")
        again = await post(
            http, csrf, f"/cases/{case}/report/reject",
            body | {"expected_version": 2, "outcome": "rule_false_positive"},
        )  # fmt: skip
    assert again.status_code == 200, again.text
    assert again.json()["gold_saved"] == 1
    labels = await world.rows("SELECT set_name, outcome, note FROM gold_labels")
    assert [(r.set_name, r.outcome) for r in labels] == [("v2", "rule_false_positive")]
    assert "Allowed by the lab policy." in labels[0].note


async def test_a_new_version_makes_an_old_decision_a_conflict_and_a_closed_case_is_not_decided(
    world: World,
) -> None:
    case = await a_case(world, 2)
    await write_report(world, case)
    await kit.pair_evidence(
        world.owner, world.investigations[0], "77.221.155.150", 9, datetime.now(UTC)
    )
    assert await write_report(world, case) == 2
    async with world.app() as http:
        csrf = await sign_in(http, "rita")
        old = await post(http, csrf, f"/cases/{case}/report/confirm", {"expected_version": 1})
        assert old.status_code == 409
        assert "version 2" in old.json()["detail"]
        shown = (await get(http, case, version=1)).json()
        assert shown["version"] == 1
        assert shown["newest"] == 2
        assert shown["confirm"]["enabled"] is False
        assert "decide the newest" in shown["confirm"]["why_not"]
        assert (await get(http, case, version=7)).status_code == 404

    suspected = await world.open_suspected(2, "Proposed beacon")
    for inv in world.investigations[2:3]:
        await kit.propose(world.owner, inv)
    await write_report(world, suspected)
    async with world.runtime.begin() as conn:
        service = await CaseService.start(conn)
        actor = Actor.person(
            await world.user_id("mina"), frozenset(c.value for c in Capability), via="test"
        )
        await service.apply(actor, suspected, Dismiss("created_in_error"), expected_version=None)
    async with world.app() as http:
        csrf = await sign_in(http, "rita")
        closed = await post(
            http, csrf, f"/cases/{suspected}/report/confirm", {"expected_version": 1}
        )
        assert closed.status_code == 409
        assert "closed" in closed.json()["detail"]
        shown = (await get(http, suspected)).json()
    assert shown["confirm"]["enabled"] is False
    assert "closed" in shown["confirm"]["why_not"]


async def test_a_reading_cannot_be_confirmed_but_can_be_rejected_with_an_outcome(
    world: World,
) -> None:
    case = await a_case(world, 2, verdict=False)
    reading = '[{"answer": {"outcome": "true_positive", "confidence": 0.6, "cites": []},'
    reading += ' "reading": {"kind": "undecided", "checked": []}}]'
    async with world.owner.begin() as conn:
        for inv in world.investigations[:2]:
            await conn.execute(
                text(
                    "INSERT INTO assessments (investigation_id, version, pack, dossier_hash,"
                    " view_hash, assessor, run_after, status, reasons, finished_at) SELECT i.id,"
                    " i.version, 'generic@12', repeat('a', 64), repeat('b', 64), 'agent@1', now(),"
                    " 'no_decision', CAST(:r AS jsonb), now() FROM investigations i WHERE i.id = :i"
                ),
                {"i": inv, "r": reading},
            )
    await write_report(world, case)
    async with world.app() as http:
        csrf = await sign_in(http, "rita")
        got = (await get(http, case)).json()
        assert got["report"]["verdict"]["kind"] == "reading"
        assert got["confirm"]["enabled"] is False
        assert "only a reading" in got["confirm"]["why_not"]
        assert got["reject"]["enabled"] is True
        refused = await post(http, csrf, f"/cases/{case}/report/confirm", {"expected_version": 1})
        assert refused.status_code == 422
        assert "no verdict" in refused.json()["detail"]
        mine = {
            "expected_version": 1,
            "outcome": "true_positive",
            "reason": "I checked: it is real.",
        }
        done = await post(http, csrf, f"/cases/{case}/report/reject", mine)
        assert done.status_code == 200, done.text  # the reading's own outcome: a person's verdict
    assert done.json()["labelled"] == 2


async def test_the_runtime_and_the_web_logins_are_held_to_their_grants(world: World) -> None:
    await a_case(world)
    async with world.web.connect() as conn:
        assert await conn.scalar(text("SELECT count(*) FROM incident_reports")) == 0  # may read
    with pytest.raises(Exception, match="permission denied"):  # but not write a report
        async with world.web.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO incident_report_checks (case_id, signal, checked_at)"
                    " VALUES (gen_random_uuid(), 'x', now())"
                )
            )
