"""CaseService against the real database (Q-C1): each command's case row, event, outbox rows
and audit event in one transaction; versions; approvals through argus_approvals' functions."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import approvals, chain, kibana
from argus.cases.approvals import ApprovalError
from argus.cases.machine import (
    CaseRefused,
    Confirm,
    Contain,
    Dismiss,
    Link,
    Open,
    Publish,
    Release,
    Reopen,
    Take,
    replay,
)
from argus.cases.model import (
    KIBANA_TO_OPEN,
    NO_QUIET_WINDOW,
    WAITING_FOR_KIBANA,
    Actor,
    Indicator,
    Member,
)
from argus.cases.service import CaseService
from tests.integration.cases.conftest import (
    APPROVER,
    Person,
    asking,
    investigation,
    rows,
    signed_for,
)


async def _open(
    engine: AsyncEngine,
    actor: Actor,
    members: list[uuid.UUID],
    *,
    indicators: tuple[Indicator, ...] = (),
    title: str = "Regular beaconing from 10.0.0.1",
) -> uuid.UUID:
    async with engine.begin() as conn:
        service = await CaseService.start(conn)
        applied = await service.open(
            actor,
            Open(title, "high", "person",
                 tuple(Member(m, "person") for m in members), indicators),
        )  # fmt: skip
    return applied.case.id


async def _apply(engine: AsyncEngine, actor: Actor, case_id: uuid.UUID, command, version=None):  # type: ignore[no-untyped-def]
    async with engine.begin() as conn:
        service = await CaseService.start(conn)
        return await service.apply(actor, case_id, command, expected_version=version)


async def _case(engine: AsyncEngine, case_id: uuid.UUID):  # type: ignore[no-untyped-def]
    async with engine.connect() as conn:
        service = await CaseService.start(conn)
        return await service.get(case_id), await service.events(case_id)


async def _chains_ok(engine: AsyncEngine) -> None:
    async with engine.connect() as conn:
        assert [r.problems for r in await chain.verify_all(conn)] == [[], []]


def _kibana_actor(person: Person, caps: frozenset[str] | None = None) -> Actor:
    return person.actor(
        caps or APPROVER, kibana=KIBANA_TO_OPEN, checked_at=datetime.now(UTC) - timedelta(seconds=1)
    )


async def test_a_person_opens_a_case_that_waits_for_kibana(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    inv = await investigation(migrated_engine)
    case_id = await _open(app_engine, people["asha"].actor(), [inv])
    case, events = await _case(app_engine, case_id)
    assert case is not None
    assert (case.state, case.version, case.number, case.kibana_wait, case.mirrored) == (
        "open", 1, 1, WAITING_FOR_KIBANA, False,
    )  # fmt: skip
    assert case.members == {inv}
    assert [e.kind for e in events] == ["opened"]
    assert replay(events) == case
    audit = await rows(
        app_engine,
        "SELECT actor, action, target_type, target_id, details->>'via' AS via FROM audit_events",
    )
    assert [tuple(a) for a in audit] == [
        (f"user:{people['asha'].user_id}", "case.opened", "case", str(case_id), "test")
    ]
    assert await rows(app_engine, "SELECT * FROM kibana_outbox") == []
    await _chains_ok(app_engine)


async def test_a_person_who_may_open_cases_in_kibana_gets_a_planned_create(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    inv = await investigation(migrated_engine)
    case_id = await _open(app_engine, _kibana_actor(people["asha"]), [inv])
    outbox = await rows(
        app_engine,
        "SELECT write_class, op, state, payload, payload_hash, idempotency_key, sent_count,"
        " before_image FROM kibana_outbox",
    )
    assert len(outbox) == 1
    row = outbox[0]
    assert (row.write_class, row.op, row.state, row.sent_count, row.before_image) == (
        "W1", "create", "planned", 0, None,
    )  # fmt: skip
    assert row.payload["title"] == "[ARGUS 1] Regular beaconing from 10.0.0.1"
    assert row.payload["argus_tags"] == sorted(
        ["argus", f"argus:case:{case_id}", "argus:owner:argus", "argus:state:open"]
    )
    assert row.payload_hash == kibana.payload_hash(row.payload)
    assert row.idempotency_key == f"{case_id}:v1:0"
    assert row.payload["settings"] == {"syncAlerts": False}
    params = row.payload["description"]["params"]
    assert params["what"] == "Regular beaconing from 10.0.0.1"
    assert params["link"] == f"/go/case/{case_id}"
    assert (params["investigations"], params["hosts"], params["indicators"]) == (1, [], [])
    assert params["first_alert"] is None  # the seeded investigation has no event times
    case, _ = await _case(app_engine, case_id)
    assert case is not None
    assert case.mirrored
    assert case.kibana_wait is None


async def test_take_release_and_the_version_the_person_saw(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    inv = await investigation(migrated_engine)
    asha = _kibana_actor(people["asha"])
    case_id = await _open(app_engine, asha, [inv])
    applied = await _apply(app_engine, asha, case_id, Take(), 1)
    assert (applied.case.state, applied.case.owner_user_id, applied.case.version) == (
        "assigned", people["asha"].user_id, 2,
    )  # fmt: skip
    writes = await rows(app_engine, "SELECT op, payload FROM kibana_outbox ORDER BY id")
    assert [w.op for w in writes] == ["create", "update", "comment"]
    assert writes[1].payload["status"] == "in-progress"
    assert f"argus:owner:user-{people['asha'].user_id}" in writes[1].payload["argus_tags"]
    with pytest.raises(CaseRefused, match="it is at version 2, you saw 1") as refused:
        await _apply(app_engine, asha, case_id, Release(), 1)
    assert refused.value.code == "conflict"
    await _apply(app_engine, asha, case_id, Release(), 2)
    case, events = await _case(app_engine, case_id)
    assert case is not None
    assert (case.state, case.owner_user_id, case.version) == ("open", None, 3)
    assert [e.kind for e in events] == ["opened", "taken", "released"]
    assert replay(events) == case
    await _chains_ok(app_engine)


async def test_a_refused_command_writes_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    inv = await investigation(migrated_engine)
    case_id = await _open(app_engine, people["asha"].actor(), [inv])
    before = await rows(app_engine, "SELECT count(*) FROM audit_events")
    with pytest.raises(CaseRefused, match=r"not contained: a quiet window cannot be verified"):
        await _apply(app_engine, people["asha"].actor(), case_id,
                     Contain("isolated by IT", NO_QUIET_WINDOW), 1)  # fmt: skip
    with pytest.raises(CaseRefused, match="cannot dismiss a open case"):
        await _apply(app_engine, people["asha"].actor(), case_id, Dismiss("benign_expected"), 1)
    with pytest.raises(CaseRefused, match="needs the manage_cases capability"):
        await _apply(app_engine, people["ravi"].actor(frozenset({"view"})), case_id,
                     Take(), 1)  # fmt: skip
    assert await rows(app_engine, "SELECT count(*) FROM audit_events") == before
    case, events = await _case(app_engine, case_id)
    assert case is not None
    assert case.version == 1
    assert len(events) == 1


async def test_publish_plans_the_create_for_a_waiting_case(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    inv = await investigation(migrated_engine)
    case_id = await _open(app_engine, people["asha"].actor(), [inv])
    with pytest.raises(CaseRefused, match="live Kibana check"):
        await _apply(app_engine, people["ravi"].actor(), case_id, Publish(), 1)
    applied = await _apply(app_engine, _kibana_actor(people["ravi"]), case_id, Publish(), 1)
    assert applied.case.mirrored
    assert applied.case.kibana_wait is None
    assert [r.op for r in await rows(app_engine, "SELECT op FROM kibana_outbox")] == ["create"]
    with pytest.raises(CaseRefused, match="Kibana has this case already"):
        await _apply(app_engine, _kibana_actor(people["ravi"]), case_id, Publish(), 2)


# --------------------------------------------------------------------------- approvals


async def _request(
    api: AsyncEngine,
    person: Person,
    case_id: uuid.UUID,
    version: int,
    reason: str = "benign_expected",
    note: str | None = None,
    *,
    anonymous: bool = False,
) -> int:
    async with api.begin() as conn:
        service = await CaseService.start(conn)
        _, request_id = await service.request_closure(
            person.actor(), case_id, expected_version=version, reason=reason,  # type: ignore[arg-type]
            session_token=person.session_token, note=note,
            check=await asking(conn, person, anonymous=anonymous),
        )  # fmt: skip
    return request_id


async def _decide(api: AsyncEngine, person: Person, request_id: int, decision: str = "approved"):  # type: ignore[no-untyped-def]
    async with api.begin() as conn:
        service = await CaseService.start(conn)
        signed = await signed_for(conn, person, request_id, decision)
        return await service.decide(
            person.actor(APPROVER), request_id, session_token=person.session_token,
            decision=decision, signed=signed,  # type: ignore[arg-type]
        )  # fmt: skip


async def test_a_closure_needs_a_request_and_another_persons_approval(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    asha, ravi = people["asha"], people["ravi"]
    inv = await investigation(migrated_engine, alerts=3)
    case_id = await _open(api_engine, _kibana_actor(asha), [inv])
    request_id = await _request(api_engine, asha, case_id, 1)
    request = (await rows(api_engine, "SELECT * FROM approval_requests"))[0]
    assert (request.case_version, request.kind, request.reason, request.required_approvals) == (
        2, "closure", "benign_expected", 1,
    )  # fmt: skip
    assert request.requested_by_user_id == asha.user_id
    alerts = [f"{inv.hex}-{n}" for n in range(3)]  # the database's own count and digest
    assert (request.alert_count, request.alert_digest) == (3, approvals.alert_digest(alerts))
    assert request.payload_hash == kibana.payload_hash(request.payload)
    with pytest.raises(ApprovalError, match="cannot approve their own request") as own:
        await _decide(api_engine, asha, request_id)
    assert own.value.status == 403
    status, applied = await _decide(api_engine, ravi, request_id)
    assert status == "approved"
    case = applied[0].case
    assert (case.state, case.closure_reason, case.closure_request_id, case.version) == (
        "closed", "benign_expected", request_id, 3,
    )  # fmt: skip
    w3 = await rows(
        api_engine,
        "SELECT write_class, op, approval_request_id, payload FROM kibana_outbox"
        " WHERE write_class = 'W3' ORDER BY position",
    )
    assert [(r.op, r.approval_request_id) for r in w3] == [("close", request_id),
                                                         ("comment", request_id)]  # fmt: skip
    assert [r.payload for r in w3] == [w["payload"] for w in request.payload["writes"]]
    with pytest.raises(ApprovalError, match="already decided") as again:
        await _decide(api_engine, people["meera"], request_id)
    assert again.value.status == 409
    stored, events = await _case(api_engine, case_id)
    assert replay(events) == stored
    await _chains_ok(api_engine)


async def test_two_person_reasons_need_two_approvers(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    inv = await investigation(migrated_engine)
    case_id = await _open(api_engine, people["asha"].actor(), [inv])
    request_id = await _request(api_engine, people["asha"], case_id, 1, "risk_accepted",
                                note="kept for the lab's teaching cluster")  # fmt: skip
    status, applied = await _decide(api_engine, people["ravi"], request_id)
    assert (status, applied) == ("pending", [])
    with pytest.raises(ApprovalError, match="already decided"):
        await _decide(api_engine, people["ravi"], request_id)
    status, applied = await _decide(api_engine, people["meera"], request_id)
    assert status == "approved"
    assert applied[0].case.closure_reason == "risk_accepted"
    inv2 = await investigation(migrated_engine, actor=(("source.ip", "10.0.0.9"),))
    case2 = await _open(api_engine, people["asha"].actor(), [inv2])
    with pytest.raises(CaseRefused, match="a written reason is required"):
        await _request(api_engine, people["asha"], case2, 1, "risk_accepted")


async def test_racing_approvers_give_one_conflict(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    inv = await investigation(migrated_engine)
    case_id = await _open(api_engine, people["asha"].actor(), [inv])
    request_id = await _request(api_engine, people["asha"], case_id, 1)
    results = await asyncio.gather(
        _decide(api_engine, people["ravi"], request_id),
        _decide(api_engine, people["meera"], request_id),
        return_exceptions=True,
    )
    ok = [r for r in results if not isinstance(r, BaseException)]
    failed = [r for r in results if isinstance(r, BaseException)]
    assert len(ok) == 1
    assert ok[0][0] == "approved"
    assert len(failed) == 1
    assert isinstance(failed[0], ApprovalError)
    assert failed[0].status == 409
    decisions = await rows(api_engine, "SELECT count(*) AS n FROM approval_decisions")
    assert decisions[0].n == 1


async def test_a_change_after_the_request_voids_it(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    inv = await investigation(migrated_engine)
    other = await investigation(migrated_engine, actor=(("source.ip", "10.0.0.2"),))
    case_id = await _open(api_engine, people["asha"].actor(), [inv])
    request_id = await _request(api_engine, people["asha"], case_id, 1)
    await _apply(api_engine, Actor.argus("opener"), case_id,
                 Link((Member(other, "actor", "10.0.0.2"),)))  # fmt: skip
    with pytest.raises(ApprovalError, match="the case changed after the request") as voided:
        await _decide(api_engine, people["ravi"], request_id)
    assert voided.value.status == 409


async def test_the_runtime_role_cannot_record_an_approval(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    inv = await investigation(migrated_engine)
    case_id = await _open(app_engine, people["asha"].actor(), [inv])
    with pytest.raises(ApprovalError, match="may not record approvals") as refused:
        await _request(app_engine, people["asha"], case_id, 1)
    assert refused.value.status == 403
    for statement in (
        "INSERT INTO approval_requests (case_id, case_version, kind, reason, payload,"  # noqa: S608 - a test
        f" payload_hash, required_approvals, requested_by_user_id, expires_at) VALUES"
        f" ('{case_id}', 1, 'closure', 'benign_expected', '{{}}', repeat('a', 64), 1,"
        f" {people['asha'].user_id}, now() + interval '1 hour')",
        "INSERT INTO approval_decisions (request_id, approver_user_id, decision, capabilities)"
        " VALUES (1, 1, 'approved', '[]')",
        "SELECT argus_approval_decide('x', 1, 'approved', NULL, now(), '{}', NULL, NULL)",
        "SELECT argus_approval_session_user('x')",
    ):
        with pytest.raises(DBAPIError, match="permission denied"):
            async with app_engine.begin() as conn:
                await conn.execute(text(statement))


async def test_approving_needs_the_capability_and_a_live_session(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    inv = await investigation(migrated_engine)
    case_id = await _open(api_engine, people["asha"].actor(), [inv])
    request_id = await _request(api_engine, people["asha"], case_id, 1)
    async with api_engine.begin() as conn:
        with pytest.raises(CaseRefused, match="the approve capability"):
            await (await CaseService.start(conn)).decide(
                people["ravi"].actor(), request_id, session_token=people["ravi"].session_token,
                decision="approved", signed=await signed_for(conn, people["ravi"], request_id),
            )  # fmt: skip
    async with api_engine.begin() as conn:  # the snapshot handed to the database lacks it
        signed = await signed_for(
            conn, people["ravi"], request_id, capabilities=frozenset({"view"})
        )
        with pytest.raises(ApprovalError, match="approver capability"):
            await approvals.decide(conn, session_token=people["ravi"].session_token,
                                   request_id=request_id, decision="approved",
                                   signed=signed)  # fmt: skip
    async with api_engine.begin() as conn:
        await conn.execute(text("UPDATE user_sessions SET ended_at = now()"))
    with pytest.raises(ApprovalError, match="no live session") as ended:
        await _decide(api_engine, people["ravi"], request_id)
    assert ended.value.status == 401


async def test_confirm_dismiss_and_reopen_of_suspected_cases(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    async with migrated_engine.begin() as conn:
        assessment = (
            await conn.execute(
                text(
                    "INSERT INTO assessments (investigation_id, version, pack, dossier_hash,"
                    " view_hash, assessor, run_after, status, outcome) SELECT id, 1, 'p',"
                    " repeat('a', 64), repeat('b', 64), 'agent', now(), 'proposed',"
                    " 'true_positive' FROM investigations LIMIT 1 RETURNING id"
                )
            )
        ).scalar_one_or_none()
    assert assessment is None  # no investigation yet
    inv = await investigation(migrated_engine)
    async with migrated_engine.begin() as conn:
        assessment = (
            await conn.execute(
                text(
                    "INSERT INTO assessments (investigation_id, version, pack, dossier_hash,"
                    " view_hash, assessor, run_after, status, outcome) VALUES (:i, 1, 'p',"
                    " repeat('a', 64), repeat('b', 64), 'agent', now(), 'proposed',"
                    " 'true_positive') RETURNING id"
                ),
                {"i": inv},
            )
        ).scalar_one()
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        applied = await service.open(
            Actor.argus("opener"),
            Open("Proposed beacon", "medium", "proposal", (Member(inv, "proposal"),),
                 suspected=True, cause_assessment_id=assessment),
        )  # fmt: skip
    case_id = applied.case.id
    assert (applied.case.state, applied.case.opened_at) == ("suspected", None)
    await _apply(app_engine, people["asha"].actor(), case_id, Dismiss("benign_expected", "ok"), 1)
    reopened = await _apply(app_engine, people["asha"].actor(), case_id, Reopen("a second look"), 2)
    assert reopened.case.state == "suspected"
    confirmed = await _apply(app_engine, people["asha"].actor(), case_id, Confirm(), 3)
    assert (confirmed.case.state, confirmed.case.kibana_wait) == ("open", WAITING_FOR_KIBANA)
    case, events = await _case(app_engine, case_id)
    assert [e.kind for e in events] == ["suspected", "dismissed", "reopened", "confirmed"]
    assert replay(events) == case


async def test_the_service_finds_out_windows_and_assignees_itself(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """A caller's word is not evidence: a verified window or an "assignable" flag handed in is
    ignored, the service asks for itself."""
    from argus.cases.machine import Assign
    from argus.cases.model import QuietWindow

    inv = await investigation(migrated_engine)
    case_id = await _open(app_engine, people["asha"].actor(), [inv])
    with pytest.raises(CaseRefused, match="not contained"):
        await _apply(app_engine, people["asha"].actor(), case_id,
                     Contain("isolated", QuietWindow(True, "trust me")), 1)  # fmt: skip
    async with app_engine.begin() as conn:
        await conn.execute(text("UPDATE users SET disabled = true WHERE username = 'meera'"))
    with pytest.raises(CaseRefused, match="only go to an active person"):
        await _apply(app_engine, people["asha"].actor(), case_id,
                     Assign(people["meera"].user_id, True), 1)  # fmt: skip
    applied = await _apply(app_engine, people["asha"].actor(), case_id,
                           Assign(people["ravi"].user_id, False), 1)  # fmt: skip
    assert applied.case.owner_user_id == people["ravi"].user_id
