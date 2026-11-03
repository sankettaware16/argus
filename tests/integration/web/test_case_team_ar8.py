"""The Kibana case preview and the canary's approval through ``/api/v1`` (AR8, D-195) on the web's
own database login: a viewer sees the steps but not what the logs said, a log reader sees every
comment and request, posting off is said and nothing is written; an approver with a fresh
step-up approves exactly the plan they read (signed with the approval key, checked again by the
writer), a stale hash is a conflict, and everyone else is refused."""

from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import signing
from argus.caseteam import approvals
from argus.caseteam.sender import ALL_USERS, PostConfig
from argus.incident import gather, run
from tests.integration.incident import kit
from tests.integration.web.b3_support import (
    V1,
    World,
    headers,
    make_world,
    post,
    sign_in,
    step_up,
    stepped,
)

pytestmark = pytest.mark.integration
CONFIG = PostConfig(
    post=False, canary=1, keys=ALL_USERS, kibana_prefixes=("https://kibana.example",)
)


@pytest.fixture
async def world(
    seeded: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> World:
    return await make_world(seeded, web_engine, migrated_engine, tmp_path)


async def a_case(world: World, *, report: bool = True) -> uuid.UUID:
    case = await world.open_case(3, title="Regular beaconing from 10.0.0.1")
    for inv in world.investigations[:3]:
        await kit.propose(world.owner, inv)
    if report:
        now = datetime.now(UTC)
        ctx = run.context_for(kit.settings(), now)
        async with world.runtime.connect() as conn:
            signal = (await gather.signals(conn, [case]))[case]
        made = await run.make(world.runtime, case, ctx)
        assert made is not None
        await run.write(world.runtime, made, run.key_of(signal, ctx), now)
    return case


async def team(http, case: object):  # type: ignore[no-untyped-def]
    return await http.get(f"{V1}/cases/{case}/team")


# --------------------------------------------------------------------------- the preview


async def test_a_log_reader_sees_every_comment_and_request_and_that_posting_is_off(
    world: World,
) -> None:
    case = await a_case(world)
    async with world.app(team=CONFIG) as http:
        await sign_in(http, "mina")
        found = (await team(http, case)).json()
    assert found["post_enabled"] is False
    assert found["logs_hidden"] is False
    assert found["incident_id"].startswith("ACME-IR-")
    assert found["report_version"] == 1
    assert found["decision"]["action"] == "none"
    assert found["decision"]["dry_run"] is True
    assert found["decision"]["would"] == "open"
    assert "switched off" in found["note"]
    steps = found["steps"]
    assert steps[0]["author"] == "argus-lead"
    assert steps[0]["kind"] == "open"
    assert steps[-1]["key"] == "comment:verdict"
    assert steps[-1]["author"] == "argus-lead"
    assert steps[-1]["text"].endswith("Confirm or reject in a comment.")
    assert steps[0]["request"]["method"] == "POST"
    assert steps[0]["request"]["path"].endswith("/api/cases")
    assert steps[0]["request"]["content_type"] == "application/json"
    assert all(s["request"] is not None for s in steps)
    assert [s["author"] for s in steps if s["kind"] == "file"] == ["argus-reporter"] * 4
    assert [s["author"] for s in steps if s["part"] == "glance"] == ["argus-visualiser"]  # AR10
    assert len(found["plan_hash"]) == 64
    assert found["post"] is None
    assert found["authors"] == [
        "argus-lead",
        "argus-evidence",
        "argus-intel",
        "argus-responder",
        "argus-hunter",
        "argus-reporter",
        "argus-visualiser",
    ]
    assert found["problems"] == []


async def test_an_account_without_log_access_sees_the_steps_but_not_the_words(
    world: World,
) -> None:
    case = await a_case(world)
    async with world.app(team=CONFIG) as http:
        await sign_in(http, "vera")
        found = (await team(http, case)).json()
    assert found["logs_hidden"] is True
    assert found["steps"], "the steps are the plan: they say who, not what the logs said"
    assert all(s["request"] is None for s in found["steps"])
    assert all(s["text"] in (None, "Hidden: needs log access in ELK.") for s in found["steps"])
    assert found["steps"][0]["text"] == "Hidden: needs log access in ELK."
    assert "Evidence" not in str(found["steps"])


async def test_without_a_report_there_is_nothing_to_post_and_an_unknown_case_is_404(
    world: World,
) -> None:
    case = await a_case(world, report=False)
    async with world.app(team=CONFIG) as http:
        await sign_in(http, "mina")
        none = (await team(http, case)).json()
        assert none["steps"] == []
        assert none["plan_hash"] is None
        assert "has not written" in none["decision"]["why"]
        assert (await team(http, uuid.uuid4())).status_code == 404


async def test_an_anonymous_request_and_a_server_without_a_config_are_handled(
    world: World,
) -> None:
    case = await a_case(world)
    async with world.app() as anonymous:
        assert (await team(anonymous, case)).status_code == 401
    async with world.app() as http:  # no case team config: the defaults, which post nothing
        await sign_in(http, "mina")
        found = (await team(http, case)).json()
    assert found["post_enabled"] is False
    assert found["decision"]["dry_run"] is True


# --------------------------------------------------------------------------- the approval


async def test_the_canary_shows_who_may_approve_and_why_not(world: World) -> None:
    case = await a_case(world)
    on = replace(CONFIG, post=True)
    async with world.app(team=on) as http:
        await sign_in(http, "mina")  # may manage cases, not approve
        mina = (await team(http, case)).json()["approval"]
        await sign_in(http, "omar")
        omar = (await team(http, case)).json()["approval"]
    assert mina["required"] is True
    assert mina["given"] is False
    assert mina["can_approve"] is False
    assert "approve capability" in mina["approve_why_not"]
    assert omar["required"] is True
    assert omar["can_approve"] is False
    assert omar["needs_step_up"] is True
    assert "confirm your password" in omar["approve_why_not"]
    assert omar["step_up_url"] == f"/stepup?next=/app/cases/{case}"
    assert mina["needs_step_up"] is False
    assert mina["step_up_url"] is None
    async with stepped(world, "omar", team=on) as (http, _):
        again = (await team(http, case)).json()["approval"]
    assert again["can_approve"] is True
    assert again["approve_why_not"] is None
    assert again["needs_step_up"] is False


async def test_an_approver_approves_exactly_the_plan_they_read(world: World) -> None:
    case = await a_case(world)
    on = replace(CONFIG, post=True)
    async with stepped(world, "omar", team=on) as (http, csrf):
        read = (await team(http, case)).json()
        sent = await post(
            http, csrf, f"/cases/{case}/team/approve", {"plan_hash": read["plan_hash"]}
        )
        assert sent.status_code == 200, sent.text
        made = sent.json()
        after = (await team(http, case)).json()
    assert made["plan_hash"] == read["plan_hash"]
    assert "exactly the plan you read" in made["words"]
    assert after["approval"]["given"] is True
    assert after["approval"]["can_approve"] is False
    assert after["decision"]["action"] == "open"
    assert after["decision"]["dry_run"] is False

    # recorded, signed, and the writer's check accepts it for this plan and no other
    async with world.runtime.connect() as conn:
        verifier = signing.Verifier([signing.load_key(world.key_file)])
        now = datetime.now(UTC)
        assert await approvals.problem(conn, verifier, case, read["plan_hash"], now) is None
        other = await approvals.problem(conn, verifier, case, "0" * 64, now)
        assert other == "no person has approved this plan yet"
        [row] = (
            await conn.execute(text("SELECT approver_user_id, signature FROM case_team_approvals"))
        ).all()
        audited = (
            await conn.execute(
                text("SELECT count(*) FROM audit_events WHERE action = 'case_team.approve'")
            )
        ).scalar_one()
    assert row.approver_user_id == await world.user_id("omar")
    assert row.signature.startswith("hmac-sha256:")
    assert audited == 1


async def test_a_plan_that_changed_since_the_person_read_it_is_a_conflict(world: World) -> None:
    case = await a_case(world)
    async with stepped(world, "omar", team=replace(CONFIG, post=True)) as (http, csrf):
        refused = await post(http, csrf, f"/cases/{case}/team/approve", {"plan_hash": "f" * 64})
    assert refused.status_code == 409
    assert refused.json()["code"] == "conflict"
    assert "changed while you read it" in refused.json()["detail"]
    assert await world.rows("SELECT 1 FROM case_team_approvals") == []


async def test_nobody_else_can_approve(world: World) -> None:
    case = await a_case(world)
    on = replace(CONFIG, post=True)
    async with world.app(team=on) as http:
        csrf = await sign_in(http, "omar")
        plan_hash = (await team(http, case)).json()["plan_hash"]
        body = {"plan_hash": plan_hash}
        # no step-up
        needs = await post(http, csrf, f"/cases/{case}/team/approve", body)
        assert needs.status_code == 403
        assert needs.json()["code"] == "step_up_required"
        await step_up(http, csrf)
        # no CSRF token
        bare = await http.post(f"{V1}/cases/{case}/team/approve", json=body)
        assert bare.status_code == 403
        assert bare.json()["code"] == "csrf"
        # a body that is not a hash
        assert (
            await post(http, csrf, f"/cases/{case}/team/approve", {"plan_hash": "x"})
        ).status_code == 422
        assert (
            await post(http, csrf, f"/cases/{case}/team/approve", {**body, "x": 1})
        ).status_code == 422
        # another case
        assert (
            await post(http, csrf, f"/cases/{uuid.uuid4()}/team/approve", body)
        ).status_code == 404
    for user in ("mina", "vera"):  # may manage cases / may only view: not approve
        async with stepped(world, user, team=on) as (http, csrf):
            no = await post(http, csrf, f"/cases/{case}/team/approve", body)
            assert no.status_code == 403, user
            assert no.json()["code"] == "forbidden", user
    assert await world.rows("SELECT 1 FROM case_team_approvals") == []


async def test_no_approval_is_asked_when_the_canary_is_over_or_there_is_no_plan(
    world: World,
) -> None:
    case = await a_case(world)
    plain = await world.open_case(1, start=3, title="Another")
    async with stepped(world, "omar", team=replace(CONFIG, post=True, canary=0)) as (http, csrf):
        h = (await team(http, case)).json()
        assert h["approval"]["required"] is False
        no = await post(http, csrf, f"/cases/{case}/team/approve", {"plan_hash": h["plan_hash"]})
        assert no.status_code == 409
        assert "needs no approval" in no.json()["detail"]
    async with stepped(world, "omar", team=replace(CONFIG, post=True)) as (http, csrf):
        no_report = await post(http, csrf, f"/cases/{plain}/team/approve", {"plan_hash": "a" * 64})
        assert no_report.status_code == 409
        assert no_report.json()["code"] == "not_ready"


async def test_a_missing_key_is_said_and_blocks_the_approval(world: World) -> None:
    case = await a_case(world)
    thin = replace(CONFIG, post=True, keys=frozenset(ALL_USERS - {"argus-hunter"}))
    async with stepped(world, "omar", team=thin) as (http, csrf):
        h = (await team(http, case)).json()
        assert any("argus-hunter" in p for p in h["problems"])
        assert h["approval"]["can_approve"] is False
        refused = await post(
            http, csrf, f"/cases/{case}/team/approve", {"plan_hash": h["plan_hash"]}
        )
        assert refused.status_code == 409
        assert "stops this plan" in refused.json()["detail"]


async def test_a_server_without_a_signing_key_cannot_record_an_approval(world: World) -> None:
    case = await a_case(world)
    async with world.app(signing=False, team=replace(CONFIG, post=True)) as http:
        csrf = await sign_in(http, "omar")
        await step_up(http, csrf)
        h = (await team(http, case)).json()
        assert h["approval"]["can_approve"] is False
        assert "no key to sign approvals" in h["approval"]["approve_why_not"]
        refused = await http.post(
            f"{V1}/cases/{case}/team/approve",
            headers=headers(csrf),
            json={"plan_hash": h["plan_hash"]},
        )
        assert refused.status_code == 503


async def test_an_approver_must_be_able_to_read_every_word_of_what_is_sent(world: World) -> None:
    """D-201 point 6: the approval covers a plan whose comments say what the logs said, so an
    account with ``approve`` but not ``see_logs`` cannot give it (and is told why)."""
    from argus.web import auth
    from argus.web.capabilities import Capability
    from tests.integration.web.conftest import PASSWORD

    async with world.owner.begin() as conn:
        await auth.add_user(
            conn,
            "olga",
            "Olga NoLogs",
            PASSWORD,
            capabilities=[
                Capability.VIEW,
                Capability.REVIEW,
                Capability.MANAGE_CASES,
                Capability.REOPEN,
                Capability.APPROVE,
            ],
        )
    case = await a_case(world)
    on = replace(CONFIG, post=True)
    async with stepped(world, "olga", team=on) as (http, csrf):
        read = (await team(http, case)).json()
        assert read["logs_hidden"] is True
        approval = read["approval"]
        assert approval["can_approve"] is False
        assert "see_logs" in approval["approve_why_not"]
        refused = await post(
            http, csrf, f"/cases/{case}/team/approve", {"plan_hash": read["plan_hash"]}
        )
    assert refused.status_code == 403
    assert refused.json()["code"] == "forbidden"
    assert "see_logs" in refused.json()["detail"]
    assert await world.rows("SELECT 1 FROM case_team_approvals") == []
    assert await world.rows("SELECT 1 FROM audit_events WHERE action = 'case_team.approve'") == []

    async with stepped(world, "omar", team=on) as (http, csrf):  # the one who reads can
        ok = await post(http, csrf, f"/cases/{case}/team/approve", {"plan_hash": read["plan_hash"]})
    assert ok.status_code == 200, ok.text
