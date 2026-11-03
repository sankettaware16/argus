"""Q-C3's review findings (F1-F10), each as a test of the safe behaviour (the reviewer's
repros, kept as regression tests): who may approve or re-confirm, `argus approvals apply`, the
runtime's outbox moves, refused writes, step-up records, resends, the ledger, the proposer and
doctor's check of the web login."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from psycopg import sql
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import approvals, autonomy, identity, kibana, proposer, sendcheck
from argus.cases.approvals import ApprovalError
from argus.cases.machine import Open, Reopen
from argus.cases.model import KIBANA_TO_OPEN, Actor, Member
from argus.cases.service import CaseService
from argus.config import DatabaseSettings
from argus.db import roles
from argus.db.engine import create_engine
from tests.integration.cases.conftest import (
    APPROVER,
    KIBANA,
    SIGNER,
    VERIFIER,
    Person,
    _alert,
    investigation,
    make_person,
    rows,
)
from tests.integration.cases.test_closure_approval import (
    FakeWriter,
    _closed,
    _desk_decide,
    _mirror,
    _provider,
    _review,
)
from tests.integration.cases.test_merge_notes import _two_cases
from tests.integration.cases.test_service import _apply, _open, _request
from tests.integration.conftest import admin_connect
from tests.integration.test_cli_db import _run, cli_env  # noqa: F401 - the fixture

pytestmark = pytest.mark.integration


async def _disable(engine: AsyncEngine, person: Person) -> None:
    async with engine.begin() as conn:
        await conn.execute(text("UPDATE users SET disabled = true WHERE id = :u"),
                           {"u": person.user_id})  # fmt: skip


async def _reconfirmation(engine: AsyncEngine) -> int:
    found = await rows(engine, "SELECT id FROM approval_requests WHERE kind = 'reconfirm'")
    return int(found[0].id)


# ------------------------------------------------------------------ F1, F2: who may approve


async def test_f1_the_requester_cannot_reconfirm_their_own_closure_write(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    """asha requests, ravi approves and is then disabled, so the write waits for a
    re-confirmation: asha, who asked for the closure, may not be the one who confirms it."""
    closed = await _closed(api_engine, migrated_engine, people)
    await _disable(app_engine, people["ravi"])
    writer = FakeWriter()
    assert (await writer.run(app_engine))[closed.close_row].verdict == "reconfirm"
    with pytest.raises(ApprovalError, match="own request"):
        await _desk_decide(api_engine, people["asha"], await _reconfirmation(app_engine))
    await writer.run(app_engine)
    assert writer.sent == []
    # a third person may
    assert await _desk_decide(api_engine, people["meera"], await _reconfirmation(app_engine)) == (
        "approved"
    )
    await writer.run(app_engine)
    assert writer.sent == [closed.close_row]


async def test_f1_the_send_time_check_drops_the_requester_from_a_reconfirmation(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    """Should a decision of the requester be on a re-confirmation anyway (the owner wrote
    it), the send-time check does not count it."""
    closed = await _closed(api_engine, migrated_engine, people)
    await _disable(app_engine, people["ravi"])
    await FakeWriter().run(app_engine)
    reconfirm = await _reconfirmation(app_engine)
    assert await _desk_decide(api_engine, people["meera"], reconfirm) == "approved"
    asha = people["asha"]
    async with migrated_engine.begin() as conn:  # meera's decision, re-signed as asha's
        decision = (await conn.execute(text(
            "SELECT id, identity_check FROM approval_decisions WHERE request_id = :r"),
            {"r": reconfirm})).one()  # fmt: skip
        check = dict(decision.identity_check)
        check.update(user_id=str(asha.user_id), argus_uid="uid-asha", email="asha@example.org")
        await conn.execute(text("ALTER TABLE approval_decisions DISABLE TRIGGER"
                                " approval_decisions_append_only_rows"))  # fmt: skip
        await conn.execute(
            text("UPDATE approval_decisions SET approver_user_id = :u,"
                 " identity_check = CAST(:c AS jsonb) WHERE id = :d"),
            {"u": asha.user_id, "c": json.dumps(check), "d": decision.id},
        )  # fmt: skip
        request = await approvals.record(conn, reconfirm)
        assert request is not None
        stored = (await approvals.decisions(conn, reconfirm))[0]
        statement = approvals.stored_statement(request, stored)
        assert statement is not None
        await conn.execute(text("UPDATE approval_decisions SET signature = :s WHERE id = :d"),
                           {"s": SIGNER.sign(statement), "d": decision.id})  # fmt: skip
        await conn.execute(text("ALTER TABLE approval_decisions ENABLE ALWAYS TRIGGER"
                                " approval_decisions_append_only_rows"))  # fmt: skip
    async with app_engine.connect() as conn:
        found = await sendcheck.check(conn, closed.close_row, VERIFIER)
    assert found.verdict == "reconfirm", found
    assert any("asked for this closure" in r for r in found.reasons), found


async def test_f1b_a_two_person_reconfirmation_cannot_include_the_requester(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    closed = await _closed(api_engine, migrated_engine, people)
    await _disable(app_engine, people["ravi"])
    await FakeWriter().run(app_engine)
    with pytest.raises(ApprovalError, match="own request"):
        await _desk_decide(api_engine, people["asha"], await _reconfirmation(app_engine))
    assert closed


async def test_f2_the_requesters_second_account_cannot_approve_without_a_prior_check(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    """asha2 is asha's second account (same argus_uid and e-mail). asha has no identity check
    on record besides her request: her second account may not approve it."""
    asha = people["asha"]
    asha2 = await make_person(app_engine, "asha2")
    inv = await investigation(migrated_engine, actor=(("source.ip", "10.0.7.7"),))
    case_id = await _open(api_engine, asha.actor(), [inv])
    request = await _request(api_engine, asha, case_id, 1)
    alias = _provider(asha2)
    alias.allow(asha2.user_id, APPROVER, KIBANA, argus_uid="uid-asha", email="ASHA@example.org")
    with pytest.raises(ApprovalError, match="own request"):
        await _desk_decide(api_engine, asha2, request, provider=alias)


async def test_f2b_the_send_time_check_compares_approvers_with_the_requester(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    """asha requested with a check that named no argus_uid (a local account), so her second
    account's approval was accepted; her own check recorded later shows the same argus_uid:
    the write is not sent on one person's word."""
    asha = people["asha"]
    asha2 = await make_person(app_engine, "asha2")
    inv = await investigation(migrated_engine, actor=(("source.ip", "10.0.7.8"),))
    async with api_engine.begin() as conn:
        now = (await conn.execute(text("SELECT now()"))).scalar_one()
    case_id = await _open(api_engine, asha.actor(APPROVER, kibana=KIBANA_TO_OPEN,
                                                 checked_at=now), [inv])  # fmt: skip
    await _mirror(migrated_engine, case_id)
    request = await _request(api_engine, asha, case_id, 1, anonymous=True)
    alias = _provider(asha2)
    alias.allow(asha2.user_id, APPROVER, KIBANA, argus_uid="uid-asha", email="asha@example.org")
    assert await _desk_decide(api_engine, asha2, request, provider=alias) == "approved"
    async with api_engine.begin() as conn:  # asha's own check, recorded later
        await identity.record(conn, identity.LiveCheck(
            asha.user_id, "ok", "fake", await identity.database_clock(conn), "person",
            APPROVER, KIBANA, "uid-asha", "asha@example.org"), "signin")  # fmt: skip
    writer = FakeWriter()
    results = await writer.run(app_engine)
    w3 = await rows(app_engine, "SELECT id FROM kibana_outbox WHERE write_class = 'W3'"
                                " AND op = 'close'")  # fmt: skip
    verdict = results[int(w3[0].id)]
    assert verdict.verdict == "reconfirm", verdict
    assert writer.sent == []


# ------------------------------------------------------------------ F3: argus approvals apply


async def test_f3_one_merge_into_a_closed_target_does_not_block_apply(
    cli_env: Path,  # noqa: F811
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    asha, ravi = people["asha"], people["ravi"]
    source, target, _, _ = await _two_cases(api_engine, migrated_engine, asha)
    async with api_engine.begin() as conn:
        service = await CaseService.start(conn)
        _, merge = await service.request_merge(
            asha.actor(), source, target, expected_version=1, session_token=asha.session_token,
            check=_requester_check(asha, await identity.database_clock(conn)),
        )  # fmt: skip
    closing = await _request(api_engine, asha, target, 1)
    assert await _desk_decide(api_engine, ravi, closing) == "approved"
    # the database refuses to approve a merge into a closed case
    with pytest.raises(ApprovalError, match="target case is closed"):
        await _desk_decide(api_engine, ravi, merge, apply=False)
    inv = await investigation(migrated_engine, actor=(("source.ip", "10.6.0.9"),))
    other = await _open(api_engine, asha.actor(), [inv])
    plain = await _request(api_engine, asha, other, 1)
    assert await _desk_decide(api_engine, ravi, plain, apply=False) == "approved"
    # a merge approved before its target closed (as the owner leaves it): reported, not fatal
    third = await investigation(migrated_engine, actor=(("source.ip", "10.6.0.10"),))
    late = await _open(api_engine, asha.actor(), [third])
    async with api_engine.begin() as conn:
        service = await CaseService.start(conn)
        _, early = await service.request_merge(
            asha.actor(), late, other, expected_version=1, session_token=asha.session_token,
            check=_requester_check(asha, await identity.database_clock(conn)),
        )  # fmt: skip
    assert await _desk_decide(api_engine, ravi, early, apply=False) == "approved"
    result = await asyncio.to_thread(_run, "approvals", "apply")
    assert result.exit_code == 0, (result.output, result.stderr)
    state = (await rows(app_engine, "SELECT state FROM cases WHERE id = :c", c=other))[0].state
    assert state == "closed"
    assert f"request {early}: not applied" in result.output, result.output


def _requester_check(person: Person, at: datetime) -> identity.LiveCheck:
    from tests.integration.cases.conftest import live_check

    return live_check(person, at)


# ------------------------------------------------------------------ F4, F7: outbox moves


async def _ambiguous_w1(owner: AsyncEngine, people: dict[str, Person]) -> int:
    """A W1 create that was sent and whose outcome is unknown (ambiguous), as the owner makes it."""
    inv = await investigation(owner, actor=(("source.ip", "10.8.0.1"),))
    async with owner.begin() as conn:
        now = (await conn.execute(text("SELECT now()"))).scalar_one()
    actor = people["asha"].actor(APPROVER, kibana=KIBANA_TO_OPEN, checked_at=now)
    async with owner.begin() as conn:
        service = await CaseService.start(conn)
        applied = await service.open(actor, Open("t", "high", "person",
                                                 (Member(inv, "person"),), ()))  # fmt: skip
    row = (await rows(owner, "SELECT id FROM kibana_outbox WHERE case_id = :c"
                             " AND write_class = 'W1' ORDER BY position LIMIT 1",
                      c=applied.case.id))[0]  # fmt: skip
    async with owner.begin() as conn:
        await conn.execute(text("UPDATE kibana_outbox SET state = 'approved' WHERE id = :r"),
                           {"r": row.id})  # fmt: skip
        await conn.execute(
            text(
                "UPDATE kibana_outbox SET state = 'sending',"
                " sent_count = sent_count + 1 WHERE id = :r"
            ),
            {"r": row.id},
        )
        await conn.execute(text("UPDATE kibana_outbox SET state = 'ambiguous' WHERE id = :r"),
                           {"r": row.id})  # fmt: skip
    return int(row.id)


async def test_f4_the_runtime_role_cannot_settle_an_unknown_outcome(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    row = await _ambiguous_w1(migrated_engine, people)
    with pytest.raises(DBAPIError, match="permission denied"):
        async with app_engine.begin() as conn:
            await conn.execute(text("UPDATE kibana_outbox SET state = 'verified',"
                                    " state_reason = 'ok' WHERE id = :r"), {"r": row})  # fmt: skip


async def test_f4b_the_runtime_role_cannot_resume_a_paused_non_closure_write(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    inv = await investigation(migrated_engine, actor=(("source.ip", "10.8.0.2"),))
    async with migrated_engine.begin() as conn:
        now = (await conn.execute(text("SELECT now()"))).scalar_one()
    case_id = await _open(app_engine, people["asha"].actor(APPROVER, kibana=KIBANA_TO_OPEN,
                                                            checked_at=now), [inv])  # fmt: skip
    row = (await rows(migrated_engine, "SELECT id FROM kibana_outbox WHERE case_id = :c"
                                       " ORDER BY id LIMIT 1", c=case_id))[0].id  # fmt: skip
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE kibana_outbox SET state = 'paused', state_reason ="
                                " 'reconciliation: argus action with no outbox row' WHERE id = :r"),
                           {"r": row})  # fmt: skip
    with pytest.raises(DBAPIError, match="permission denied"):
        async with app_engine.begin() as conn:
            await conn.execute(text("UPDATE kibana_outbox SET state = 'approved',"
                                    " state_reason = NULL WHERE id = :r"), {"r": row})  # fmt: skip
    # nor through the send-time check's function, which moves closure writes only
    with pytest.raises(DBAPIError, match="not a closure write"):
        async with app_engine.begin() as conn:
            await conn.execute(text("SELECT argus_closure_write_move(:r, 'approved', NULL)"),
                               {"r": row})  # fmt: skip


async def _set_signature(owner: AsyncEngine, decision_id: int, signature: str) -> None:
    async with owner.begin() as conn:
        await conn.execute(text("ALTER TABLE approval_decisions DISABLE TRIGGER"
                                " approval_decisions_append_only_rows"))  # fmt: skip
        await conn.execute(text("UPDATE approval_decisions SET signature = :s WHERE id = :i"),
                           {"s": signature, "i": decision_id})  # fmt: skip
        await conn.execute(text("ALTER TABLE approval_decisions ENABLE ALWAYS TRIGGER"
                                " approval_decisions_append_only_rows"))  # fmt: skip


async def test_f7_release_does_not_resume_a_closure_write_paused_for_tampering(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    closed = await _closed(api_engine, migrated_engine, people)
    sig = (await rows(migrated_engine, "SELECT id, signature FROM approval_decisions"))[0]
    await _set_signature(migrated_engine, int(sig.id), "hmac-sha256:" + "0" * 16 + ":" + "0" * 64)
    async with app_engine.begin() as conn:
        assert (await sendcheck.release(conn, closed.close_row, VERIFIER)).verdict == "refuse"
    await _set_signature(migrated_engine, int(sig.id), sig.signature)  # put back
    async with app_engine.begin() as conn:
        again = await sendcheck.release(conn, closed.close_row, VERIFIER)
    state = (await rows(app_engine, "SELECT state, state_reason FROM kibana_outbox"
                                    " WHERE id = :r", r=closed.close_row))[0]  # fmt: skip
    assert (again.verdict, state.state) == ("refuse", "paused"), (again, state)
    assert state.state_reason.startswith("refused:")
    # the runtime cannot resume it either; a reopen of the case still skips it
    with pytest.raises(DBAPIError, match="waits for a person"):
        async with app_engine.begin() as conn:
            await conn.execute(text("SELECT argus_closure_write_move(:r, 'approved', NULL)"),
                               {"r": closed.close_row})  # fmt: skip
    await _apply(app_engine, people["meera"].actor(APPROVER), closed.case_id,
                 Reopen("new beacons"), 3)  # fmt: skip
    async with app_engine.begin() as conn:
        assert (await sendcheck.release(conn, closed.close_row, VERIFIER)).verdict == "skip"
    assert (await rows(app_engine, "SELECT state FROM kibana_outbox WHERE id = :r",
                       r=closed.close_row))[0].state == "skipped"  # fmt: skip


async def test_f7b_a_refused_closure_write_is_audited_once(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    closed = await _closed(api_engine, migrated_engine, people)
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE kibana_mirror SET sync_alerts = true WHERE case_id = :c"),
                           {"c": closed.case_id})  # fmt: skip
    for _ in range(2):
        async with app_engine.begin() as conn:
            assert (await sendcheck.release(conn, closed.close_row, VERIFIER)).verdict == "refuse"
    audited = await rows(app_engine, "SELECT actor, details FROM audit_events"
                                     " WHERE action = 'case.closure_write.refused'")  # fmt: skip
    assert len(audited) == 1, audited
    assert audited[0].actor == "argus:sendcheck"
    assert audited[0].details["outbox"] == closed.close_row
    assert "Sync alerts" in audited[0].details["reason"]


# ------------------------------------------------------------------ F5, F6, F8: minor


async def test_f5_a_later_step_up_does_not_hold_back_an_approved_kibana_closure(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    ravi = people["ravi"]
    closed = await _closed(api_engine, migrated_engine, people)
    async with api_engine.begin() as conn:  # exactly what /stepup does on a right password
        assert await identity.record_if_allowed(
            conn,
            await identity.LocalIdentityProvider().check(conn, ravi.user_id, purpose="stepup"),
            "stepup",
        )
    results = await FakeWriter().run(app_engine)
    assert results[closed.close_row].verdict == "send", results[closed.close_row]


async def test_f5_a_newer_check_of_the_same_provider_without_update_case_still_holds_back(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    ravi = people["ravi"]
    closed = await _closed(api_engine, migrated_engine, people)
    async with api_engine.begin() as conn:
        await identity.record(
            conn,
            identity.LiveCheck(
                ravi.user_id,
                "ok",
                "fake",
                await identity.database_clock(conn),
                "person",
                APPROVER,
                frozenset({"createCase"}),
                "uid-ravi",
                "ravi@example.org",
            ),
            "recheck",
        )
    results = await FakeWriter().run(app_engine)
    assert results[closed.close_row].verdict == "reconfirm", results[closed.close_row]


async def test_f6_a_resend_of_a_kibana_write_needs_the_approvers_kibana_privilege(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    asha, ravi = people["asha"], people["ravi"]
    row = await _ambiguous_w1(migrated_engine, people)
    case = (await rows(app_engine, "SELECT o.case_id, c.version FROM kibana_outbox o"
                                   " JOIN cases c ON c.id = o.case_id WHERE o.id = :r",
                       r=row))[0]  # fmt: skip
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE users SET capabilities = :c WHERE id = :u"),
                           {"c": sorted(APPROVER), "u": ravi.user_id})  # fmt: skip
    payload = {"outbox": row, "op": "create"}
    async with api_engine.begin() as conn:
        now = await identity.database_clock(conn)
        request = await approvals.request(
            conn, session_token=asha.session_token, case_id=case.case_id,
            case_version=int(case.version), kind="resend", reason=None, payload=payload,
            payload_hash=kibana.payload_hash(payload), expires=approvals.expires_at(now),
            outbox_id=row, check=_requester_check(asha, now).snapshot(),
        )  # fmt: skip
    with pytest.raises(ApprovalError, match="createCase"):
        await _desk_decide(api_engine, ravi, request, provider=identity.LocalIdentityProvider())
    # updateCase alone is not createCase either; createCase is
    with pytest.raises(ApprovalError, match="createCase"):
        await _desk_decide(
            api_engine, ravi, request, provider=_provider(ravi, kibana=frozenset({"updateCase"}))
        )
    assert await _desk_decide(api_engine, ravi, request,
                              provider=_provider(ravi, kibana=frozenset({"createCase"}))) == (
        "approved"
    )  # fmt: skip


async def test_f8_an_approved_proposal_stays_approved_in_the_ledger_when_its_approver_leaves(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    asha, ravi = people["asha"], people["ravi"]
    inv = await investigation(migrated_engine, actor=(("source.ip", "10.6.1.1"),))
    case_id = await _open(api_engine, asha.actor(), [inv])
    async with app_engine.begin() as conn:
        _, request = await (await CaseService.start(conn)).propose_closure(
            Actor.argus("proposer"), case_id, reason="rule_false_positive",
            evidence="every member reviewed as a false positive",
        )  # fmt: skip
    assert await _desk_decide(api_engine, ravi, request) == "approved"
    assert (await rows(app_engine, "SELECT state FROM cases"))[0].state == "closed"
    await _disable(app_engine, ravi)
    async with app_engine.connect() as conn:
        later = await autonomy.ledger(conn, await identity.database_clock(conn) + timedelta(days=4))
    (line,) = later.classes
    assert (line.approved, line.revoked, line.expired_undecided, later.expired_undecided) == (
        1, 1, 0, 0
    ), line  # fmt: skip


async def test_f8b_a_closure_write_skipped_by_a_reopen_is_not_an_approval_expired_unsent(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    closed = await _closed(api_engine, migrated_engine, people)
    await _apply(app_engine, people["meera"].actor(APPROVER), closed.case_id,
                 Reopen("new beacons"), 3)  # fmt: skip
    results = await FakeWriter().run(app_engine)
    assert results[closed.close_row].verdict == "skip"
    async with app_engine.connect() as conn:
        later = await autonomy.ledger(conn, await identity.database_clock(conn) + timedelta(days=4))
    assert (later.expired_unsent, later.with_writes, later.skipped_writes) == (0, 0, 1), later


# ------------------------------------------------------------------ F9: the proposer


async def test_f9_argus_does_not_propose_a_closure_on_a_review_older_than_the_alerts(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    asha = people["asha"]
    inv = await investigation(migrated_engine, actor=(("source.ip", "10.4.9.1"),))
    case_id = await _open(api_engine, asha.actor(), [inv])
    await _review(migrated_engine, inv, asha, "benign_expected")
    async with app_engine.connect() as conn:
        assert [c.case_id for c in await proposer.candidates(conn)] == [case_id]
    async with migrated_engine.begin() as conn:  # new activity after the review
        start = datetime(2026, 10, 10, 20, 0, tzinfo=UTC)
        for n in range(40):
            await _alert(conn, f"{inv.hex}-new-{n}", inv, start + timedelta(minutes=n))
        await conn.execute(text("UPDATE investigations SET version = 2, alert_count = 42"
                                " WHERE id = :i"), {"i": inv})  # fmt: skip
    async with app_engine.connect() as conn:
        found = await proposer.candidates(conn)
    assert found == [], [(c.reason, c.evidence) for c in found]


# ------------------------------------------------------------------ F10: doctor


async def test_f10_doctor_flags_admin_option_on_the_webs_approvals_membership(
    make_api_login: Any, make_login: Any, migrated_engine: AsyncEngine, test_database: str,
    db_settings: DatabaseSettings,
) -> None:  # fmt: skip
    login = await make_api_login()
    engine = create_engine(login, database=test_database, role="api")
    try:
        assert await roles.api_role_problems(engine) == []
        with admin_connect(db_settings, test_database) as conn:
            conn.execute(
                sql.SQL("GRANT {} TO {} WITH ADMIN OPTION").format(
                    sql.Identifier(roles.APPROVALS_ROLE), sql.Identifier(login.api_user)
                )
            )
        assert f"can grant {roles.APPROVALS_ROLE} to other roles (ADMIN OPTION)" in (
            await roles.api_role_problems(engine)
        )
        with admin_connect(db_settings, test_database) as conn:
            conn.execute(
                sql.SQL("REVOKE ADMIN OPTION FOR {} FROM {}").format(
                    sql.Identifier(roles.APPROVALS_ROLE), sql.Identifier(login.api_user)
                )
            )
            conn.execute(
                sql.SQL("GRANT {} TO {} WITH INHERIT FALSE").format(
                    sql.Identifier(roles.APPROVALS_ROLE), sql.Identifier(login.api_user)
                )
            )
        found = await roles.api_role_problems(engine)
        assert f"does not inherit the privileges of {roles.APPROVALS_ROLE}" in found, found
    finally:
        await engine.dispose()


# ------------------------------------------------------------------ the fixes' own edges


async def test_a_request_needs_a_fresh_good_check_of_the_requester(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """F2's binding: the database refuses a request without the requester's own live check."""
    asha, ravi = people["asha"], people["ravi"]
    inv = await investigation(migrated_engine, actor=(("source.ip", "10.0.9.1"),))
    case_id = await _open(api_engine, asha.actor(), [inv])
    payload = {"writes": []}

    async def ask(check: dict[str, Any]) -> int:
        async with api_engine.begin() as conn:
            now = await identity.database_clock(conn)
            return await approvals.request(
                conn, session_token=asha.session_token, case_id=case_id, case_version=1,
                kind="closure", reason="benign_expected", payload=payload,
                payload_hash=kibana.payload_hash(payload), expires=approvals.expires_at(now),
                check=check,
            )  # fmt: skip

    async with api_engine.connect() as conn:
        now = await identity.database_clock(conn)
    good = _requester_check(asha, now).snapshot()
    for bad, message in (
        ({**good, "user_id": str(ravi.user_id)}, "live check of the requester"),
        ({**good, "outcome": "denied"}, "live check of the requester"),
        ({**good, "kind": "break_glass"}, "live check of the requester"),
        ({**good, "checked_at": "now"}, "no valid time"),
        ({**good, "checked_at": "2026-10-01T00:00:00.000000+00:00"}, "older than 30 seconds"),
    ):
        with pytest.raises(ApprovalError, match=message):
            await ask(bad)
    async with api_engine.connect() as conn:
        fresh = _requester_check(asha, await identity.database_clock(conn)).snapshot()
    request = await ask(fresh)
    stored = await rows(api_engine, "SELECT requester_check FROM approval_requests WHERE id = :r",
                        r=request)  # fmt: skip
    assert stored[0].requester_check == fresh
    recorded = await rows(api_engine, "SELECT purpose FROM identity_checks WHERE user_id = :u",
                          u=asha.user_id)  # fmt: skip
    assert [r.purpose for r in recorded] == ["request"]


async def test_the_runtimes_closure_write_moves_are_only_the_send_time_checks(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    """F4: argus_closure_write_move() moves a W3 row among planned, approved, paused (held for
    a re-confirmation or refused, the reason says which) and skipped, and nothing else."""
    closed = await _closed(api_engine, migrated_engine, people)

    async def move(state: str, reason: str | None) -> bool:
        async with app_engine.begin() as conn:
            moved: bool = (await conn.execute(
                text("SELECT argus_closure_write_move(:r, :s, :w)"),
                {"r": closed.close_row, "s": state, "w": reason})).scalar_one()  # fmt: skip
        return moved

    for state, reason in (("sending", None), ("verified", None), ("paused", "because"),
                          ("paused", None), ("approved", "why"), ("skipped", None)):  # fmt: skip
        with pytest.raises(DBAPIError, match="not a move of the send-time check"):
            await move(state, reason)
    assert await move("paused", "re-confirm: test") is True
    assert await move("paused", "re-confirm: test") is False  # nothing changed, nothing audited
    assert await move("approved", None) is True
    held = await rows(
        app_engine,
        "SELECT action FROM audit_events WHERE action LIKE 'case.closure_write.%' ORDER BY id",
    )
    assert [h.action for h in held] == ["case.closure_write.held", "case.closure_write.released"]
    async with migrated_engine.begin() as conn:  # the writer's move (Q-D4), as the owner
        await conn.execute(
            text("UPDATE kibana_outbox SET state = 'sending', sent_count = 1 WHERE id = :r"),
            {"r": closed.close_row},
        )
    with pytest.raises(DBAPIError, match="is the writer's"):
        await move("skipped", "too late")
