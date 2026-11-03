"""Q-B3: asking to close or merge a case, the preview a person reads first (the same builder as the
request), and the approvals queue: the exact writes, the alerts then and now, a step-up, groups
with their sample first. The gate: the preview equals Q-C3's builder byte for byte; fake
previews, double submits and stale versions are refuted."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import closure, kibana
from argus.cases.service import CaseService
from argus.normalize.canon import canonical_json
from tests.integration.web.b3_support import (
    V1,
    World,
    make_world,
    post,
    request_closure,
    sign_in,
    stepped,
)

pytestmark = pytest.mark.integration


@pytest.fixture
async def world(
    seeded: AsyncEngine, web_engine: AsyncEngine, migrated_engine: AsyncEngine, tmp_path: Path
) -> World:
    return await make_world(seeded, web_engine, migrated_engine, tmp_path)


HEX = "0" * 64


async def queue(http: httpx.AsyncClient) -> dict[str, object]:
    got = await http.get(f"{V1}/approvals")
    assert got.status_code == 200, got.text
    body: dict[str, object] = got.json()
    return body


async def decide(
    http: httpx.AsyncClient, csrf: str, request_id: int, payload_hash: str, **extra: object
) -> httpx.Response:
    return await post(http, csrf, f"/approvals/{request_id}/decision",
                      {"decision": "approved", "payload_hash": payload_hash, **extra})  # fmt: skip


async def pending(http: httpx.AsyncClient) -> list[dict[str, object]]:
    found: list[dict[str, object]] = (await queue(http))["pending"]  # type: ignore[assignment]
    return found


# --------------------------------------------------------------------------- the preview


async def test_the_preview_is_the_builders_and_the_request_stores_the_same(world: World) -> None:
    case = await world.open_case(2, kibana=True)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        seen = await http.get(
            f"{V1}/cases/{case}/closure-preview",
            params={"reason": "benign_expected", "expected_version": 1},
        )
        assert seen.status_code == 200, seen.text
        shown = seen.json()
        assert (shown["case_version"], shown["bound_version"], shown["in_kibana"]) == (1, 2, True)
        assert len(shown["payload"]["writes"]) == 2  # the closing change and its comment
        # Q-C3's builder, called on its own: the case as the request event leaves it
        async with world.runtime.connect() as conn:
            found = await (await CaseService.start(conn)).get(case)
        assert found is not None
        built = closure.build(replace(found, version=found.version + 1), "benign_expected",
                              found.opened_at)  # fmt: skip
        assert canonical_json(shown["payload"]) == canonical_json(built.payload)
        assert shown["payload_hash"] == built.payload_hash == kibana.payload_hash(built.payload)
        assert shown["payload_hash"] == hashlib.sha256(
            canonical_json(shown["payload"]).encode()).hexdigest()  # fmt: skip
        # and what the request stores is that, byte for byte
        asked = await post(http, csrf, f"/cases/{case}/closure-requests",
                           {"expected_version": 1, "reason": "benign_expected",
                            "payload_hash": shown["payload_hash"]})  # fmt: skip
        assert asked.status_code == 201, asked.text
        assert asked.json()["result"] == "requested"
        request_id = asked.json()["request_id"]
    stored = (
        await world.rows(
            "SELECT payload, payload_hash, case_version, kind, reason"
            " FROM approval_requests WHERE id = :i",
            i=request_id,
        )
    )[0]
    assert canonical_json(stored.payload) == canonical_json(shown["payload"])
    assert (stored.payload_hash, stored.case_version) == (shown["payload_hash"], 2)
    assert (stored.kind, stored.reason) == ("closure", "benign_expected")


async def test_a_preview_made_up_or_out_of_date_is_refused_and_nothing_is_written(
    world: World,
) -> None:
    case = await world.open_case(1, kibana=True)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        real = (await http.get(f"{V1}/cases/{case}/closure-preview",
                               params={"reason": "benign_expected"})).json()  # fmt: skip
        other = (await http.get(f"{V1}/cases/{case}/closure-preview",
                                params={"reason": "benign_policy"})).json()  # fmt: skip
        assert real["payload_hash"] != other["payload_hash"]
        body = {"expected_version": 1, "reason": "benign_expected"}
        for fake in (HEX, other["payload_hash"], real["payload_hash"][:-1] + "0"):
            if fake == real["payload_hash"]:
                continue
            refused = await post(http, csrf, f"/cases/{case}/closure-requests",
                                 {**body, "payload_hash": fake})  # fmt: skip
            assert refused.status_code == 409, refused.text
            assert "not what you read" in refused.json()["detail"]
        for bad in ("zz", real["payload_hash"].upper(), "", real["payload_hash"] + "0"):
            malformed = await post(http, csrf, f"/cases/{case}/closure-requests",
                                   {**body, "payload_hash": bad})  # fmt: skip
            assert malformed.status_code == 422, bad
        stale = await post(http, csrf, f"/cases/{case}/closure-requests",
                           {"expected_version": 7, "reason": "benign_expected",
                            "payload_hash": real["payload_hash"]})  # fmt: skip
        assert stale.status_code == 409
    assert await world.rows("SELECT id FROM approval_requests") == []
    kinds = await world.rows("SELECT kind FROM case_events WHERE case_id = :c", c=case)
    assert [k.kind for k in kinds] == ["opened"]


async def test_a_reason_that_needs_words_cannot_be_asked_without_them(world: World) -> None:
    case = await world.open_case(1)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        choices = {
            c["reason"]: c for c in (await http.get(f"{V1}/cases/{case}")).json()["closure_choices"]
        }
        assert choices["risk_accepted"]["note"] == "required"
        assert choices["risk_accepted"]["approvers"] == 2
        assert choices["benign_expected"]["note"] == "optional"
        assert choices["remediated_verified"]["enabled"] is False
        assert "shown the case quiet for 72 hours" in choices["remediated_verified"]["why_not"]
        assert choices["attempt_no_impact"]["enabled"] is False
        assert "duplicate" not in choices
        bare = await request_closure(http, csrf, case, "risk_accepted")
        assert bare.status_code == 422
        assert "written reason" in bare.json()["detail"]
        preview = await http.get(f"{V1}/cases/{case}/closure-preview",
                                 params={"reason": "remediated_verified"})  # fmt: skip
        assert (preview.status_code, preview.json()["code"]) == (409, "not_ready")
        assert "shown the case quiet for 72 hours" in preview.json()["detail"]
    assert await world.rows("SELECT id FROM approval_requests") == []


# --------------------------------------------------------------------------- asking, deciding


async def ask(world: World, case: object, reason: str = "benign_expected", *, by: str = "mina",
              note: str | None = None, version: int = 1) -> dict[str, object]:  # fmt: skip
    async with world.app() as http:
        csrf = await sign_in(http, by)
        asked = await request_closure(http, csrf, case, reason, version=version, note=note)
        assert asked.status_code == 201, asked.text
        body: dict[str, object] = asked.json()
        return body


async def test_the_queue_shows_what_an_approver_signs_for(world: World) -> None:
    case = await world.open_case(2, title="Beaconing", kibana=True)
    asked = await ask(world, case, "benign_policy", note="the lab does this")
    async with world.app() as http:
        await sign_in(http, "oona")
        q = await queue(http)
        assert q["can_sign"] is True
        assert q["pending_total"] == 1
        assert q["step_up"]["valid"] is False
        assert q["step_up"]["url"] == "/stepup?next=/app/approvals"
        [one] = q["pending"]
        assert one["id"] == asked["request_id"]
        assert one["words"] == "Close case 1: benign: allowed by policy"
        assert (one["status"], one["status_words"]) == ("pending", "0 of 1 approval so far")
        assert one["case"]["title"] == "Beaconing"
        assert one["case_version"] == 2
        assert one["requested_by"]["username"] == "mina"
        assert one["proposed_by"] is None
        assert one["note"] == "the lab does this"
        assert len(one["payload"]["writes"]) == 2
        assert one["alerts_then"] == one["alerts_now"] > 0
        assert one["alerts_same"] is True
        assert one["you"] == {"can_decide": True, "why_not": None, "decided": None}
        assert q["groups"] == []  # one request is no group
        row = (await http.get(f"{V1}/cases", params={"view": "attention"})).json()["items"][0]
        assert (row["waiting_for_approval"], row["needs_attention"]) == (1, False)
        assert (await http.get(f"{V1}/cases", params={"view": "attention"})).json()["counts"][
            "attention"
        ] == 1  # a case that waits for an approver needs attention
    # an alert arrives in the case since it was asked for: the approver is told
    async with world.owner.begin() as conn:
        inv = (
            await conn.execute(
                text("SELECT investigation_id FROM case_members WHERE case_id = :c LIMIT 1"),
                {"c": case},
            )
        ).scalar_one()
        await conn.execute(
            text("INSERT INTO alert_records (alert_id, index, status, normalizer_version, raw,"
                 " content_hash, state_hash, recovered_by, detected_at) VALUES ('late-1', 'alerts',"
                 " 'normalized', 't', '{}', 'h', 'h', 'live', now())"))  # fmt: skip
        await conn.execute(text("INSERT INTO investigation_alerts (alert_id, investigation_id)"
                                " VALUES ('late-1', :i)"), {"i": inv})  # fmt: skip
    async with world.app() as http:
        await sign_in(http, "oona")
        [again] = await pending(http)
        assert again["alerts_same"] is False
        assert again["alerts_now"] == again["alerts_then"] + 1


async def test_a_decision_needs_a_step_up_and_somebody_else(world: World) -> None:
    case = await world.open_case(1)
    asked = await ask(world, case, by="omar")  # an approver who asks cannot approve their own
    request_id = asked["request_id"]
    async with world.app() as omar:
        csrf = await sign_in(omar, "omar")
        [mine] = await pending(omar)
        assert mine["you"]["can_decide"] is False
        assert mine["you"]["why_not"] == "You asked for this, so someone else has to decide it."
        own = await decide(omar, csrf, request_id, mine["payload_hash"])
        assert own.status_code == 403, own.text
    async with world.app() as oona:
        csrf = await sign_in(oona, "oona")
        [one] = await pending(oona)
        no_step_up = await decide(oona, csrf, request_id, one["payload_hash"])
        assert (no_step_up.status_code, no_step_up.json()["code"]) == (403, "step_up_required")
        assert "password" in no_step_up.json()["detail"]
        from tests.integration.web.b3_support import step_up

        await step_up(oona, csrf)
        assert (await queue(oona))["step_up"]["valid"] is True
        # a step-up older than five minutes is no step-up
        async with world.owner.begin() as conn:
            await conn.execute(text("UPDATE user_sessions SET stepped_up_at = now() -"
                                    " interval '6 minutes' WHERE ended_at IS NULL"))  # fmt: skip
        old = await decide(oona, csrf, request_id, one["payload_hash"])
        assert (old.status_code, old.json()["code"]) == (403, "step_up_required")
        await step_up(oona, csrf)
        wrong = await decide(oona, csrf, request_id, HEX)
        assert (wrong.status_code, wrong.json()["code"]) == (409, "conflict")
        made = await decide(oona, csrf, request_id, one["payload_hash"], note="looked at it")
        assert made.status_code == 200, made.text
        assert made.json()["status"] == "approved"
        assert [(a["number"], a["state"]) for a in made.json()["applied"]] == [(1, "closed")]
        again = await decide(oona, csrf, request_id, one["payload_hash"])
        assert again.status_code == 409  # nobody decides twice
        assert (await pending(oona)) == []
        recent = (await queue(oona))["recent"]
        assert [(r["id"], r["status"]) for r in recent] == [(request_id, "approved")]
    closed = (await world.rows("SELECT state, closure_reason, closure_request_id FROM cases"))[0]
    assert tuple(closed) == ("closed", "benign_expected", request_id)
    kinds = await world.rows("SELECT kind, actor FROM case_events WHERE case_id = :c ORDER BY"
                             " case_version", c=case)  # fmt: skip
    oona_id = await world.user_id("oona")
    assert [k.kind for k in kinds] == ["opened", "closure_requested", "closed"]
    assert kinds[-1].actor == f"user:{oona_id}"
    decisions = await world.rows("SELECT decision, signature FROM approval_decisions")
    assert [d.decision for d in decisions] == ["approved"]
    assert decisions[0].signature.startswith("hmac-sha256:")


async def test_a_rejection_keeps_the_case_open_and_ends_the_request(world: World) -> None:
    case = await world.open_case(1)
    asked = await ask(world, case)
    async with world.app() as oona:
        csrf = await sign_in(oona, "oona")
        [one] = await pending(oona)
        from tests.integration.web.b3_support import step_up

        await step_up(oona, csrf)
        no = await post(oona, csrf, f"/approvals/{asked['request_id']}/decision",
                        {"decision": "rejected", "payload_hash": one["payload_hash"],
                         "note": "not benign"})  # fmt: skip
        assert no.status_code == 200
        assert no.json()["status"] == "rejected"
        assert no.json()["applied"] == []
        assert await pending(oona) == []
    async with world.app() as omar:
        csrf = await sign_in(omar, "omar")
        from tests.integration.web.b3_support import step_up

        await step_up(omar, csrf)
        late = await decide(omar, csrf, asked["request_id"], one["payload_hash"])
        assert late.status_code == 409  # a rejected request is over
    assert (await world.rows("SELECT state FROM cases"))[0].state == "open"


async def test_a_two_person_closure_waits_for_a_second_person(world: World) -> None:
    case = await world.open_case(1)
    asked = await ask(world, case, "risk_accepted", note="the lab accepts it, in writing")
    rid = asked["request_id"]
    async with world.app() as oona, world.app() as omar:
        c1 = await sign_in(oona, "oona")
        c2 = await sign_in(omar, "omar")
        from tests.integration.web.b3_support import step_up

        await step_up(oona, c1)
        await step_up(omar, c2)
        [one] = await pending(oona)
        assert one["required"] == 2
        assert one["status_words"] == "0 of 2 approvals so far"
        first = await decide(oona, c1, rid, one["payload_hash"])
        assert first.status_code == 200
        assert first.json()["status"] == "pending"
        assert first.json()["applied"] == []
        [half] = await pending(oona)
        assert half["status_words"] == "1 of 2 approvals so far"
        assert half["you"]["decided"] == "approved"
        assert half["you"]["why_not"] == "You already approved this request."
        twice = await decide(oona, c1, rid, one["payload_hash"])
        assert twice.status_code in (403, 409)
        assert (await world.rows("SELECT state FROM cases"))[0].state == "open"
        second = await decide(omar, c2, rid, one["payload_hash"])
        assert second.status_code == 200
        assert second.json()["status"] == "approved"
        assert second.json()["applied"][0]["state"] == "closed"


async def test_a_case_that_moved_on_voids_its_request(world: World) -> None:
    case = await world.open_case(1)
    asked = await ask(world, case)
    async with world.app() as mina:
        csrf = await sign_in(mina, "mina")
        took = await post(mina, csrf, f"/cases/{case}/take", {"expected_version": 2})
        assert took.status_code == 200
    async with world.app() as oona:
        csrf = await sign_in(oona, "oona")
        q = await queue(oona)
        assert q["pending"] == []
        [stale] = q["recent"]
        assert stale["status"] == "stale"
        assert stale["status_words"] == "The case changed after it was asked for"
        from tests.integration.web.b3_support import step_up

        await step_up(oona, csrf)
        gone = await decide(oona, csrf, asked["request_id"], stale["payload_hash"])
        assert gone.status_code == 409
        assert "case changed" in gone.json()["detail"]
    assert (await world.rows("SELECT state FROM cases"))[0].state == "assigned"


async def test_without_a_signing_key_the_queue_reads_and_no_decision_is_recorded(
    world: World,
) -> None:
    case = await world.open_case(1)
    asked = await ask(world, case)
    async with world.app(signing=False) as oona:
        csrf = await sign_in(oona, "oona")
        from tests.integration.web.b3_support import step_up

        await step_up(oona, csrf)
        q = await queue(oona)
        assert q["can_sign"] is False
        assert len(q["pending"]) == 1
        got = await decide(oona, csrf, asked["request_id"], q["pending"][0]["payload_hash"])  # type: ignore[index]
        assert got.status_code == 503
        assert "no key to sign approvals" in got.json()["detail"]
    assert await world.rows("SELECT id FROM approval_decisions") == []


async def test_a_local_account_cannot_approve_a_closure_that_writes_to_kibana(
    world: World,
) -> None:
    """Plan §3 rule 6: a person makes ARGUS do only what their own ELK account may. A local
    account holds no Kibana privilege, so a closure that writes to Kibana is not theirs to
    approve; the database says so and nothing is recorded."""
    case = await world.open_case(1, kibana=True)
    asked = await ask(world, case)
    async with world.app() as oona:
        csrf = await sign_in(oona, "oona")
        from tests.integration.web.b3_support import step_up

        await step_up(oona, csrf)
        [one] = await pending(oona)
        got = await decide(oona, csrf, asked["request_id"], one["payload_hash"])
        assert got.status_code in (403, 409), got.text
    assert await world.rows("SELECT id FROM approval_decisions") == []
    assert (await world.rows("SELECT state FROM cases"))[0].state == "open"


async def test_two_approvers_at_once_make_one_decision(world: World) -> None:
    case = await world.open_case(1)
    asked = await ask(world, case)
    async with stepped(world, "oona") as (one, c1), stepped(world, "omar") as (two, c2):
        [req] = await pending(one)
        both = await asyncio.gather(
            decide(one, c1, asked["request_id"], req["payload_hash"]),
            decide(two, c2, asked["request_id"], req["payload_hash"]),
        )
        assert sorted(r.status_code for r in both)[0] == 200
        assert sorted(r.status_code for r in both)[1] in (403, 409)
    assert len(await world.rows("SELECT id FROM approval_decisions")) == 1


# --------------------------------------------------------------------------- merges


async def test_a_confirmed_case_is_merged_through_an_approval(world: World) -> None:
    source = await world.open_case(1, title="Source")
    target = await world.open_case(1, title="Target", start=1)
    async with world.app() as mina:
        csrf = await sign_in(mina, "mina")
        seen = await mina.get(f"{V1}/cases/{source}/merge-preview",
                              params={"target": str(target), "expected_version": 1})  # fmt: skip
        assert seen.status_code == 200, seen.text
        assert seen.json()["target"]["title"] == "Target"
        assert seen.json()["reason"] == "duplicate"
        bare = await post(
            mina,
            csrf,
            f"/cases/{source}/merge",
            {"expected_version": 1, "target_case_id": str(target)},
        )
        assert bare.status_code == 422  # a confirmed case asks, with the preview's hash
        fake = await post(mina, csrf, f"/cases/{source}/merge",
                          {"expected_version": 1, "target_case_id": str(target),
                           "payload_hash": HEX})  # fmt: skip
        assert fake.status_code == 409
        asked = await post(
            mina,
            csrf,
            f"/cases/{source}/merge",
            {
                "expected_version": 1,
                "target_case_id": str(target),
                "payload_hash": seen.json()["payload_hash"],
                "note": "same beacon",
            },
        )
        assert asked.status_code == 201, asked.text
        assert asked.json()["result"] == "requested"
    async with world.app() as oona:
        csrf = await sign_in(oona, "oona")
        from tests.integration.web.b3_support import step_up

        await step_up(oona, csrf)
        [req] = await pending(oona)
        assert req["words"] == "Merge case 1 into case 2"
        assert req["target"]["title"] == "Target"
        done = await decide(oona, csrf, req["id"], req["payload_hash"])
        assert done.status_code == 200, done.text
        assert sorted(a["number"] for a in done.json()["applied"]) == [1, 2]
    rows = await world.rows("SELECT number, state, merged_into_id FROM cases ORDER BY number")
    assert [(r.number, r.state) for r in rows] == [(1, "closed"), (2, "open")]
    held = await world.rows("SELECT count(*) AS n FROM case_members WHERE case_id = :t"
                            " AND removed_at IS NULL", t=target)  # fmt: skip
    assert held[0].n == 2


async def test_a_suspected_case_is_merged_at_once_and_has_no_preview(world: World) -> None:
    sus = await world.open_suspected(3)
    target = await world.open_case(1, title="Target")
    async with world.app() as mina:
        csrf = await sign_in(mina, "mina")
        with_hash = await post(mina, csrf, f"/cases/{sus}/merge",
                               {"expected_version": 1, "target_case_id": str(target),
                                "payload_hash": HEX})  # fmt: skip
        assert with_hash.status_code == 422
        done = await post(
            mina,
            csrf,
            f"/cases/{sus}/merge",
            {"expected_version": 1, "target_case_id": str(target)},
        )
        assert done.status_code == 201, done.text
        assert done.json()["result"] == "merged"
        assert done.json()["case"]["state"] == "closed"
        assert done.json()["case"]["merged_into"]["title"] == "Target"
    assert await world.rows("SELECT id FROM approval_requests") == []


# --------------------------------------------------------------------------- groups


async def benign_group(world: World, n: int, reason: str = "benign_expected") -> list[int]:
    ids = []
    for k in range(n):
        case = await world.open_case(1, title=f"Case {k}", start=k)
        ids.append(int((await ask(world, case, reason))["request_id"]))
    return ids


async def test_a_group_is_approved_sample_first_and_all_or_none(world: World) -> None:
    ids = await benign_group(world, 5)
    async with world.app() as oona:
        csrf = await sign_in(oona, "oona")
        from tests.integration.web.b3_support import step_up

        await step_up(oona, csrf)
        q = await queue(oona)
        [group] = q["groups"]
        assert group["reason"] == "benign_expected"
        assert len(group["items"]) == 5
        assert sorted(i["request_id"] for i in group["items"]) == sorted(ids)
        sample = group["sample"]
        assert len(sample) == 3  # max(3, 10 %)
        rest = [i for i in ids if i not in sample]
        hashes = {i["request_id"]: i["payload_hash"] for i in group["items"]}
        assert {p["id"]: p["group"] for p in q["pending"]} == dict.fromkeys(ids, group["key"])
        items = [{"request_id": i, "payload_hash": hashes[i]} for i in ids]
        # the rest before the sample is refused by the database; nothing is recorded
        early = await post(oona, csrf, "/approvals/group", {"items": items})
        assert early.status_code == 409, early.text
        assert "sample" in early.json()["detail"]
        assert await world.rows("SELECT id FROM approval_decisions") == []
        # a hash that is not the one read: all or none
        wrong = [dict(i) for i in items]
        wrong[0]["payload_hash"] = HEX
        assert (await post(oona, csrf, "/approvals/group", {"items": wrong})).status_code == 409
        for rid in sample:
            one = await decide(oona, csrf, rid, hashes[rid], group=ids)
            assert one.status_code == 200, one.text
        assert len(await world.rows("SELECT id FROM approval_decisions")) == 3
        bad = [*items[:-1], {"request_id": items[-1]["request_id"], "payload_hash": HEX}]
        refused = await post(oona, csrf, "/approvals/group", {"items": bad})
        assert refused.status_code == 409
        assert len(await world.rows("SELECT id FROM approval_decisions")) == 3
        done = await post(oona, csrf, "/approvals/group", {"items": items, "note": "sample ok"})
        assert done.status_code == 200, done.text
        assert [d["request_id"] for d in done.json()["decided"]] == sorted(rest)
        assert all(d["status"] == "approved" and d["applied"] for d in done.json()["decided"])
    states = await world.rows("SELECT state FROM cases")
    assert [s.state for s in states] == ["closed"] * 5


async def test_a_group_is_only_what_the_database_allows(world: World) -> None:
    ids = await benign_group(world, 3)
    async with world.app() as oona:
        csrf = await sign_in(oona, "oona")
        from tests.integration.web.b3_support import step_up

        await step_up(oona, csrf)
        q = await queue(oona)
        [group] = q["groups"]
        hashes = {i["request_id"]: i["payload_hash"] for i in group["items"]}
        # a rejection never goes in a group
        no = await post(
            oona,
            csrf,
            f"/approvals/{ids[0]}/decision",
            {"decision": "rejected", "payload_hash": hashes[ids[0]], "group": ids},
        )
        assert no.status_code == 422
        # the request must be in the group named
        outside = await decide(oona, csrf, ids[0], hashes[ids[0]], group=ids[1:])
        assert outside.status_code == 422
        # a made-up group of one real request and one that does not exist
        ghost = await decide(oona, csrf, ids[0], hashes[ids[0]], group=[ids[0], 999999])
        assert ghost.status_code == 409
        # one request twice, and more than twenty
        twice = await decide(oona, csrf, ids[0], hashes[ids[0]], group=[ids[0], ids[0]])
        assert twice.status_code == 422
        many = await decide(oona, csrf, ids[0], hashes[ids[0]], group=list(range(1, 22)))
        assert many.status_code == 422
        lone = await decide(oona, csrf, ids[0], hashes[ids[0]], group=[ids[0]])
        assert lone.status_code == 422
    assert await world.rows("SELECT id FROM approval_decisions") == []


async def test_requests_for_two_reasons_are_two_groups_and_a_two_person_reason_none(
    world: World,
) -> None:
    await benign_group(world, 2, "benign_expected")
    other = await world.open_case(1, title="Policy", start=2)
    await ask(world, other, "benign_policy")
    third = await world.open_case(1, title="Policy two", start=3)
    await ask(world, third, "benign_policy")
    risky = await world.open_case(1, title="Risky", start=4)
    await ask(world, risky, "risk_accepted", note="in writing")
    risky2 = await world.open_case(1, title="Risky two", start=5)
    await ask(world, risky2, "risk_accepted", note="in writing")
    async with world.app() as oona:
        await sign_in(oona, "oona")
        q = await queue(oona)
        assert sorted(g["reason"] for g in q["groups"]) == ["benign_expected", "benign_policy"]
        assert len(q["pending"]) == 6
        assert all(p["group"] is None for p in q["pending"] if p["reason"] == "risk_accepted")
    async with world.app() as mina:  # an account that may not approve sees no group to act on
        await sign_in(mina, "mina")
        q = await queue(mina)
        assert q["groups"] == []
        assert all(p["you"]["can_decide"] is False for p in q["pending"])
        assert "approve" in q["pending"][0]["you"]["why_not"]


async def test_a_denied_identity_check_is_recorded_and_commits_nothing_else(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    from argus.cases.identity import FakeIdentityProvider
    from argus.web.v1 import case_routes

    case = await world.open_case(1)
    fake = FakeIdentityProvider()  # nobody is known to it: every check is denied
    monkeypatch.setattr(case_routes, "provider_for", lambda request, me, token: fake)
    async with world.app() as mina:
        csrf = await sign_in(mina, "mina")
        seen = (await mina.get(f"{V1}/cases/{case}/closure-preview",
                               params={"reason": "benign_expected"})).json()  # fmt: skip
        got = await post(mina, csrf, f"/cases/{case}/closure-requests",
                         {"expected_version": 1, "reason": "benign_expected",
                          "payload_hash": seen["payload_hash"]})  # fmt: skip
        assert got.status_code == 403, got.text
        assert "identity check" in got.json()["detail"]
    checks = await world.rows("SELECT outcome, purpose FROM identity_checks")
    assert [(c.outcome, c.purpose) for c in checks] == [("denied", "request")]
    assert await world.rows("SELECT id FROM approval_requests") == []
    kinds = await world.rows("SELECT kind FROM case_events WHERE case_id = :c", c=case)
    assert [k.kind for k in kinds] == ["opened"]  # the request event rolled back with it


async def test_the_audit_of_a_request_and_a_decision_names_the_person_by_id(world: World) -> None:
    case = await world.open_case(1)
    asked = await ask(world, case)
    async with stepped(world, "oona") as (http, csrf):
        [req] = await pending(http)
        done = await decide(http, csrf, asked["request_id"], req["payload_hash"])
        assert done.status_code == 200
    mina, oona = await world.user_id("mina"), await world.user_id("oona")
    audit = await world.rows("SELECT actor, action FROM audit_events WHERE action LIKE"
                             " 'case.%' AND target_id = :c ORDER BY id", c=str(case))  # fmt: skip
    assert [(a.actor, a.action) for a in audit] == [
        (f"user:{mina}", "case.opened"), (f"user:{mina}", "case.closure_requested"),
        (f"user:{mina}", "case.approval.requested"), (f"user:{oona}", "case.approval.approved"),
        (f"user:{oona}", "case.closed")]  # fmt: skip
    assert json.dumps(audit[0].actor)  # (a plain string: no name, no space, no '#')
    # and the hash chains of the audit trail and of the case events still verify
    from argus.cases import chain

    async with world.runtime.connect() as conn:
        assert [r.problems for r in await chain.verify_all(conn)] == [[], []]


async def test_an_approver_who_may_update_cases_in_kibana_closes_a_mirrored_case(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With ELK sign-in the person's own account is checked live (the seam the fake stands for): a
    closure that writes to Kibana is approved by someone whose account may update cases there, and
    its two writes are then planned in the outbox under that approval, to be sent by the writer."""
    from argus.cases.identity import FakeIdentityProvider
    from argus.web.v1 import case_routes

    mina, omar = await world.user_id("mina"), await world.user_id("omar")
    fake = FakeIdentityProvider()
    kibana = frozenset({"createCase", "createComment", "updateCase"})
    fake.allow(mina, frozenset({"view", "review", "manage_cases", "reopen"}), kibana)
    fake.allow(omar, frozenset({"view", "review", "manage_cases", "reopen", "approve"}), kibana)
    monkeypatch.setattr(case_routes, "provider_for", lambda request, me, token: fake)
    case = await world.open_case(1, kibana=True)
    asked = await ask(world, case)
    async with stepped(world, "omar") as (http, csrf):
        [req] = await pending(http)
        assert len(req["payload"]["writes"]) == 2
        done = await decide(http, csrf, asked["request_id"], req["payload_hash"])
        assert done.status_code == 200, done.text
        assert done.json()["applied"][0]["state"] == "closed"
    rows = await world.rows(
        "SELECT write_class, op, state, approval_request_id FROM kibana_outbox WHERE case_id = :c"
        " AND write_class = 'W3' ORDER BY position", c=case)  # fmt: skip
    assert [(r.write_class, r.op, r.approval_request_id) for r in rows] == [
        ("W3", "close", asked["request_id"]), ("W3", "comment", asked["request_id"])]  # fmt: skip
    checks = await world.rows("SELECT purpose, outcome FROM identity_checks ORDER BY id")
    assert {c.purpose for c in checks} >= {"request", "approval"}
    assert all(c.outcome == "ok" for c in checks)


async def test_a_reconfirmation_is_in_the_queue_and_another_approver_gives_it(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A closure approved, then its approver's account disabled before the write was sent: the
    send-time check holds the write back and asks for a new approval, which is a request of ARGUS's
    own in the queue with the held-back write named; a different approver gives it and the check
    then lets the write go."""
    from argus.cases import sendcheck, signing
    from argus.cases.identity import FakeIdentityProvider
    from argus.web.v1 import case_routes

    verifier = signing.Verifier([signing.load_key(world.key_file)])
    ids = {u: await world.user_id(u) for u in ("mina", "omar", "oona")}
    fake = FakeIdentityProvider()
    kibana = frozenset({"createCase", "createComment", "updateCase"})
    for user, caps in (("mina", {"manage_cases"}), ("omar", {"manage_cases", "approve"}),
                       ("oona", {"manage_cases", "approve"})):  # fmt: skip
        fake.allow(ids[user], frozenset({"view", "review", "reopen", *caps}), kibana)
    monkeypatch.setattr(case_routes, "provider_for", lambda request, me, token: fake)
    case = await world.open_case(1, kibana=True)
    async with world.owner.begin() as conn:  # Kibana has the case, read back
        await conn.execute(
            text(
                "INSERT INTO kibana_mirror (case_id, kibana_case_id, kibana_version, status, title,"
                " severity, tags, created_by, sync_alerts, kibana_created_at, read_at) VALUES"
                " (:c, 'k-1', 'WzEsMV0=', 'open', 't', 'high', '{argus}', 'argus', false, now(),"
                " now())"
            ),
            {"c": case},
        )
    asked = await ask(world, case)
    async with stepped(world, "omar") as (http, csrf):
        [req] = await pending(http)
        assert (
            await decide(http, csrf, asked["request_id"], req["payload_hash"])
        ).status_code == 200
    async with world.runtime.begin() as conn:
        first = [
            (await sendcheck.release(conn, row, verifier)).verdict
            for row in await sendcheck.held(conn)
        ]
    assert first == ["send", "wait"]  # the comment waits until the closing change is read back
    async with world.owner.begin() as conn:
        await conn.execute(
            text("UPDATE users SET disabled = true WHERE id = :u"), {"u": ids["omar"]}
        )
    async with world.runtime.begin() as conn:
        held = [
            (await sendcheck.release(conn, row, verifier)).verdict
            for row in await sendcheck.held(conn)
        ]
    assert "reconfirm" in held
    async with stepped(world, "oona") as (http, csrf):
        q = await queue(http)
        [again] = q["pending"]
        assert again["kind"] == "reconfirm"
        assert again["words"] == "Confirm again a held-back closure of case 1"
        assert again["requested_by"] is None
        assert again["proposed_by"] == "argus:sendcheck"
        assert (again["hold"]["write_class"], again["hold"]["op"], again["hold"]["state"]) == (
            "W3", "close", "paused")  # fmt: skip
        assert again["hold"]["state_reason"].startswith("re-confirm:")
        assert again["you"]["can_decide"] is True
        done = await decide(http, csrf, again["id"], again["payload_hash"])
        assert done.status_code == 200, done.text
        assert (done.json()["status"], done.json()["applied"]) == ("approved", [])
    async with world.runtime.begin() as conn:
        last = [
            (await sendcheck.release(conn, row, verifier)).verdict
            for row in await sendcheck.held(conn)
        ]
    assert last[0] == "send"


async def test_a_merge_into_a_missing_or_closed_case_is_refused_with_the_reason(
    world: World,
) -> None:
    source = await world.open_case(1, title="Source")
    target = await world.open_case(1, title="Target", start=1)
    closing = await ask(world, target, "benign_expected")
    async with stepped(world, "oona") as (http, csrf):
        [req] = await pending(http)
        done = await decide(http, csrf, closing["request_id"], req["payload_hash"])
        assert done.status_code == 200, done.text  # the target is closed now
        closed = await http.get(
            f"{V1}/cases/{source}/merge-preview", params={"target": str(target)}
        )
        assert closed.status_code == 409
        assert closed.json()["detail"] == "The target case is closed."
        nothing = await http.get(
            f"{V1}/cases/{source}/merge-preview",
            params={"target": "00000000-0000-0000-0000-000000000000"},
        )
        assert nothing.status_code == 404
    async with world.app() as mina:
        csrf = await sign_in(mina, "mina")
        refused = await post(
            mina, csrf, f"/cases/{source}/merge",
            {"expected_version": 1, "target_case_id": str(target), "payload_hash": HEX},
        )  # fmt: skip
        assert refused.status_code == 409


async def test_a_group_naming_requests_that_are_not_waiting_is_refused(world: World) -> None:
    ids = await benign_group(world, 3)
    async with stepped(world, "oona") as (http, csrf):
        q = await queue(http)
        [group] = q["groups"]
        items = [
            {"request_id": i["request_id"], "payload_hash": i["payload_hash"]}
            for i in group["items"]
        ]
        ghost = [*items[:2], {"request_id": 999999, "payload_hash": HEX}]
        got = await post(http, csrf, "/approvals/group", {"items": ghost})
        assert got.status_code == 409
        assert "not waiting any more" in got.json()["detail"]
        twice = await post(
            http, csrf, "/approvals/group", {"items": [items[0], items[0], items[1]]}
        )
        assert twice.status_code == 422
        assert sorted(i["request_id"] for i in items) == sorted(ids)
    assert await world.rows("SELECT id FROM approval_decisions") == []


async def test_what_a_request_bound_must_be_what_the_person_read_or_nothing_is_saved(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The preview is made before the case is locked. Were the writes to change in between without
    moving the case's version, the request would bind something the person did not read: it is
    refused and rolled back (the preview is made to agree with the client here, to reach the
    check)."""
    from argus.cases.service import CaseService

    case = await world.open_case(1)
    async with world.app() as http:
        csrf = await sign_in(http, "mina")
        real = (await http.get(f"{V1}/cases/{case}/closure-preview",
                               params={"reason": "benign_expected"})).json()  # fmt: skip
        original = CaseService.preview_closure

        async def agrees(self: CaseService, *args: object, **kwargs: object) -> object:
            built = await original(self, *args, **kwargs)  # type: ignore[arg-type]
            from dataclasses import replace

            return replace(built, payload_hash=HEX)

        monkeypatch.setattr(CaseService, "preview_closure", agrees)
        body = {"expected_version": 1, "reason": "benign_expected", "payload_hash": HEX}
        got = await post(http, csrf, f"/cases/{case}/closure-requests", body)
        assert got.status_code == 409, got.text
        assert "changed while you asked" in got.json()["detail"]
        assert real["payload_hash"] != HEX
    assert await world.rows("SELECT id FROM approval_requests") == []
    kinds = await world.rows("SELECT kind FROM case_events WHERE case_id = :c", c=case)
    assert [k.kind for k in kinds] == ["opened"]  # the request event rolled back with it
