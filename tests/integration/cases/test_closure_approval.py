"""Q-C3's gate on the real database: approvals need a step-up of the same session within 5
minutes, a fresh live check and the web's signature; the send-time checks refuse tampering and
replay, and hold back a closure write whose approver was disabled or denied, whose approval
expired, whose case was reopened or whose Kibana case moved; groups go sample first; ARGUS
proposes and never approves; the ledger counts what expired unsent.

Nothing here reaches Kibana: a fake writer stands where Q-D4's will (it sends a row only on
the send-time check's ``send``)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import approvals, autonomy, chain, identity, proposer, sendcheck, signing
from argus.cases.approvals import ApprovalError
from argus.cases.desk import ApprovalDesk, Refused, SessionProof
from argus.cases.identity import FakeIdentityProvider, IdentityProvider
from argus.cases.machine import Reopen
from argus.cases.model import KIBANA_TO_OPEN, Actor
from argus.cases.service import CaseService
from tests.integration.cases.conftest import (
    APPROVER,
    KIBANA,
    SIGNER,
    VERIFIER,
    Person,
    investigation,
    rows,
    signed_for,
    step_up,
)
from tests.integration.cases.test_service import _apply, _open, _request

pytestmark = pytest.mark.integration

KIBANA_VERSION = "WzEsMV0="


def _provider(*people: Person, kibana: frozenset[str] = KIBANA) -> FakeIdentityProvider:
    provider = FakeIdentityProvider()
    for person in people:
        provider.allow(person.user_id, APPROVER, kibana, argus_uid=f"uid-{person.username}",
                       email=f"{person.username}@example.org")  # fmt: skip
    return provider


async def _desk_decide(
    engine: AsyncEngine,
    person: Person,
    request_id: int,
    decision: approvals.Decision = "approved",
    *,
    provider: IdentityProvider | None = None,
    batch: dict[str, Any] | None = None,
    stepped: bool = True,
    apply: bool = True,
) -> approvals.Status:
    async with engine.begin() as conn:
        at = await step_up(conn, person) if stepped else None
        desk = ApprovalDesk(conn, identity_provider=provider or _provider(person),
                            signer=SIGNER, apply=apply)  # fmt: skip
        decided = await desk.decide(SessionProof(person.session_token, person.user_id, at),
                                    request_id, decision, batch=batch)  # fmt: skip
    return decided.status


async def _mirror(owner: AsyncEngine, case_id: uuid.UUID, version: str = KIBANA_VERSION) -> None:
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO kibana_mirror (case_id, kibana_case_id, kibana_version, status, title,"
                " severity, tags, created_by, sync_alerts, kibana_created_at, read_at)"
                " VALUES (:c, :k, :v, 'open', 't', 'high', '{argus}', 'argus', false, now(), now())"
                " ON CONFLICT (case_id) DO UPDATE SET kibana_version = :v"
            ),
            {"c": case_id, "k": f"k-{case_id}", "v": version},
        )


@dataclass
class Closed:
    case_id: uuid.UUID
    request_id: int
    close_row: int
    comment_row: int


async def _closed(
    api: AsyncEngine, owner: AsyncEngine, people: dict[str, Person], *, alerts: int = 2
) -> Closed:
    """A mirrored case (its Kibana create planned, its mirror read back) that asha asked to
    close and ravi approved through the desk: closed in ARGUS, its two W3 rows planned."""
    asha, ravi = people["asha"], people["ravi"]
    inv = await investigation(owner, alerts=alerts, actor=(("source.ip", f"10.1.{alerts}.7"),))
    async with api.begin() as conn:
        now = (await conn.execute(text("SELECT now()"))).scalar_one()
    actor = asha.actor(APPROVER, kibana=KIBANA_TO_OPEN, checked_at=now)
    case_id = await _open(api, actor, [inv])
    await _mirror(owner, case_id)
    request_id = await _request(api, asha, case_id, 1)
    assert await _desk_decide(api, ravi, request_id) == "approved"
    w3 = await rows(api, "SELECT id, op FROM kibana_outbox WHERE write_class = 'W3'"
                         " AND case_id = :c ORDER BY position", c=case_id)  # fmt: skip
    assert [r.op for r in w3] == ["close", "comment"]
    return Closed(case_id, request_id, int(w3[0].id), int(w3[1].id))


@dataclass
class FakeWriter:
    """Where Q-D4's writer will be: it releases held closure writes, then sends an approved one
    only when the last check, in the same transaction, says ``send``."""

    verifier: signing.Verifier = VERIFIER
    sent: list[int] = field(default_factory=list)

    async def run(
        self, engine: AsyncEngine, now: datetime | None = None
    ) -> dict[int, sendcheck.SendCheck]:
        """One pass; ``now`` stands for a later time (the database's clock otherwise)."""
        results: dict[int, sendcheck.SendCheck] = {}
        async with engine.begin() as conn:
            for row in await sendcheck.held(conn):
                results[row] = await sendcheck.release(conn, row, self.verifier, now=now)
        async with engine.begin() as conn:
            approved = (await conn.execute(text(
                "SELECT id FROM kibana_outbox WHERE write_class = 'W3' AND state = 'approved'"
                " ORDER BY id"))).scalars().all()  # fmt: skip
            for row in approved:
                last = await sendcheck.admit(conn, int(row), self.verifier, now=now)
                results[int(row)] = last
                if last.verdict == "send":
                    self.sent.append(int(row))
        return results


async def _state(engine: AsyncEngine, row: int) -> tuple[str, str | None]:
    found = await rows(engine, "SELECT state, state_reason FROM kibana_outbox WHERE id = :r", r=row)
    return found[0].state, found[0].state_reason


async def _owner_sql(owner: AsyncEngine, *statements: str, **params: object) -> None:
    async with owner.begin() as conn:
        for statement in statements:
            used = {k: v for k, v in params.items() if f":{k}" in statement}
            await conn.execute(text(statement), used)


async def _check_after(
    owner: AsyncEngine, row: int, *statements: str, verifier: signing.Verifier = VERIFIER
) -> sendcheck.SendCheck:
    """The send-time check of ``row`` after the owner's ``statements``, all rolled back."""
    async with owner.connect() as conn:
        trans = await conn.begin()
        try:
            for statement in statements:
                await conn.execute(text(statement))
            return await sendcheck.check(conn, row, verifier)
        finally:
            await trans.rollback()


def _unguarded(table: str, statement: str) -> tuple[str, str, str]:
    trigger = f"{table}_append_only_rows"
    return (f"ALTER TABLE {table} DISABLE TRIGGER {trigger}", statement,
            f"ALTER TABLE {table} ENABLE ALWAYS TRIGGER {trigger}")  # fmt: skip


# ------------------------------------------------------------------ step-up, checks, signatures


async def test_an_approval_needs_a_step_up_of_this_session_within_five_minutes(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    asha, ravi = people["asha"], people["ravi"]
    inv = await investigation(migrated_engine)
    case_id = await _open(api_engine, asha.actor(), [inv])
    request_id = await _request(api_engine, asha, case_id, 1)
    with pytest.raises(ApprovalError) as none:
        await _desk_decide(api_engine, ravi, request_id, stepped=False)
    assert (none.value.status, none.value.code) == (403, "step_up_required")
    # a step-up six minutes ago
    async with api_engine.begin() as conn:
        old = (await conn.execute(text(
            "UPDATE user_sessions SET stepped_up_at = clock_timestamp() - interval '6 minutes'"
            " WHERE token_hash = :t RETURNING stepped_up_at"), {"t": ravi.session_hash})
        ).scalar_one()  # fmt: skip
        desk = ApprovalDesk(conn, identity_provider=_provider(ravi), signer=SIGNER)
        with pytest.raises(ApprovalError) as stale:
            await desk.decide(SessionProof(ravi.session_token, ravi.user_id, old), request_id,
                              "approved")  # fmt: skip
    assert (stale.value.status, stale.value.code) == (403, "step_up_required")
    # a step-up of another session of the same person does not count
    other = await make_person_session(api_engine, ravi)
    async with api_engine.begin() as conn:
        fresh = await step_up(conn, other)
        desk = ApprovalDesk(conn, identity_provider=_provider(ravi), signer=SIGNER)
        with pytest.raises(ApprovalError, match="step-up within 5 minutes"):
            await desk.decide(SessionProof(ravi.session_token, ravi.user_id, fresh), request_id,
                              "approved")  # fmt: skip
    # naming another time than the session's own step-up
    async with api_engine.begin() as conn:
        at = await step_up(conn, ravi)
        desk = ApprovalDesk(conn, identity_provider=_provider(ravi), signer=SIGNER)
        with pytest.raises(ApprovalError, match="another step-up"):
            await desk.decide(
                SessionProof(ravi.session_token, ravi.user_id, at - timedelta(seconds=1)),
                request_id, "approved",
            )  # fmt: skip
    assert await rows(api_engine, "SELECT 1 FROM approval_decisions") == []
    assert await _desk_decide(api_engine, ravi, request_id) == "approved"
    decision = (await rows(api_engine, "SELECT * FROM approval_decisions"))[0]
    assert decision.stepped_up_at is not None
    assert decision.signature.startswith(f"hmac-sha256:{SIGNER.key_id}:")
    assert decision.identity_check["provider"] == "fake"
    checks = await rows(api_engine, "SELECT user_id, outcome, purpose FROM identity_checks"
                                    " ORDER BY id")  # fmt: skip
    assert [(c.user_id, c.outcome, c.purpose) for c in checks] == [
        (asha.user_id, "ok", "request"), (ravi.user_id, "ok", "approval")
    ]  # fmt: skip


async def make_person_session(engine: AsyncEngine, person: Person) -> Person:
    """A second web session of the same person (another browser)."""
    from argus.web import auth

    async with engine.begin() as conn:
        now = (await conn.execute(text("SELECT now()"))).scalar_one()
        token, _ = await auth.start(conn, person.user_id, now)
    return Person(person.user_id, person.username, token)


async def test_the_live_check_must_be_fresh_good_and_the_approvers_own(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    asha, ravi = people["asha"], people["ravi"]
    inv = await investigation(migrated_engine)
    case_id = await _open(api_engine, asha.actor(), [inv])
    request_id = await _request(api_engine, asha, case_id, 1)

    async def refused(check: dict[str, Any], match: str) -> None:
        async with api_engine.begin() as conn:
            signed = await signed_for(conn, ravi, request_id)
            forged = approvals.Signed(signed.stepped_up_at, check, signed.signature)
            with pytest.raises(ApprovalError, match=match):
                await approvals.decide(conn, session_token=ravi.session_token,
                                       request_id=request_id, decision="approved",
                                       signed=forged)  # fmt: skip

    async with api_engine.connect() as conn:
        base = (await signed_for(conn, ravi, request_id)).check
        await conn.rollback()
    old = identity.LiveCheck(ravi.user_id, "ok", "fake", identity._UNSET).snapshot()
    await refused({**base, "checked_at": old["checked_at"]}, "older than 30 seconds")
    await refused({**base, "outcome": "denied"}, "a live check of the approver")
    await refused({**base, "kind": "break_glass"}, "a live check of the approver")
    await refused({**base, "user_id": str(asha.user_id)}, "a live check of the approver")
    await refused({**base, "capabilities": ["view", "manage_cases"]}, "approver capability")
    for word in ("yesterday", "now", "infinity", "2026-10-23 10:00:00+00", "not a time"):
        await refused({**base, "checked_at": word}, "no valid time")
    await refused("not an object", "a live check")  # type: ignore[arg-type]
    assert await rows(api_engine, "SELECT 1 FROM approval_decisions") == []


async def test_a_kibana_closure_needs_the_approvers_own_update_case_privilege(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """No confused deputy: a local account (no Kibana privileges) may close a case Kibana does
    not hold, never approve a closure ARGUS would write to Kibana."""
    asha, ravi = people["asha"], people["ravi"]
    local = identity.LocalIdentityProvider()
    inv = await investigation(migrated_engine)
    plain = await _open(api_engine, asha.actor(), [inv])
    request = await _request(api_engine, asha, plain, 1)
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE users SET capabilities = :c WHERE id = :u"),
                           {"c": sorted(APPROVER), "u": ravi.user_id})  # fmt: skip
    assert await _desk_decide(api_engine, ravi, request, provider=local) == "approved"
    inv2 = await investigation(migrated_engine, actor=(("source.ip", "10.0.0.8"),))
    async with api_engine.begin() as conn:
        now = (await conn.execute(text("SELECT now()"))).scalar_one()
    mirrored = await _open(api_engine, asha.actor(APPROVER, kibana=KIBANA_TO_OPEN,
                                                  checked_at=now), [inv2])  # fmt: skip
    request2 = await _request(api_engine, asha, mirrored, 1)
    with pytest.raises(ApprovalError, match="updateCase") as deputy:
        await _desk_decide(api_engine, ravi, request2, provider=local)
    assert deputy.value.status == 403
    no_kibana = _provider(ravi, kibana=frozenset({"createCase"}))
    with pytest.raises(ApprovalError, match="updateCase"):
        await _desk_decide(api_engine, ravi, request2, provider=no_kibana)


async def test_a_decision_must_carry_a_signature(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    asha, ravi = people["asha"], people["ravi"]
    inv = await investigation(migrated_engine)
    case_id = await _open(api_engine, asha.actor(), [inv])
    request_id = await _request(api_engine, asha, case_id, 1)
    for bad in ("", "hmac-sha256:abc:def", "sha1:" + "0" * 40):
        async with api_engine.begin() as conn:
            signed = await signed_for(conn, ravi, request_id)
            unsigned = approvals.Signed(signed.stepped_up_at, signed.check, bad)
            with pytest.raises(ApprovalError, match="signature"):
                await approvals.decide(conn, session_token=ravi.session_token,
                                       request_id=request_id, decision="approved",
                                       signed=unsigned)  # fmt: skip


async def test_the_runtime_role_cannot_decide_or_vouch_for_a_person_but_may_propose(
    app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    for statement in (
        "SELECT argus_approval_decide('x', 1, 'approved', NULL, now(), '{}', NULL, NULL)",
        f"SELECT argus_identity_record({people['ravi'].user_id}, 'ok', 'fake', 'recheck', '{{}}')",
        f"INSERT INTO identity_checks (user_id, outcome, provider, purpose) VALUES"  # noqa: S608 - a test
        f" ({people['ravi'].user_id}, 'ok', 'fake', 'recheck')",
        "UPDATE approval_decisions SET signature = NULL",
    ):
        with pytest.raises(DBAPIError, match="permission denied"):
            async with app_engine.begin() as conn:
                await conn.execute(text(statement))
    async with app_engine.begin() as conn:  # it may call the proposal function (and is refused)
        with pytest.raises(ApprovalError, match="no such case"):
            await approvals.propose(
                conn, proposer="argus:proposer", case_id=uuid.uuid4(), case_version=1,
                kind="closure", reason="benign_expected", payload={}, payload_hash="0" * 64,
                expires=(await conn.execute(text("SELECT now() + interval '1 hour'"))).scalar_one(),
            )  # fmt: skip


# ------------------------------------------------------------------ send-time checks


async def test_an_approved_closure_write_is_sent_once_its_checks_hold(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    closed = await _closed(api_engine, migrated_engine, people)
    writer = FakeWriter()
    results = await writer.run(app_engine)
    assert results[closed.close_row].verdict == "send"
    assert results[closed.close_row].basis == closed.request_id
    assert results[closed.comment_row].verdict == "wait"  # after the closing change is verified
    assert writer.sent == [closed.close_row]
    assert await _state(app_engine, closed.close_row) == ("approved", None)


async def test_an_approver_disabled_between_approval_and_send_gets_nothing_sent(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    """The gate: approved and released, then the approver's account is disabled before the
    writer's request: nothing is sent; the write waits for a re-confirmation, which another
    approver gives, and only then is it sent."""
    closed = await _closed(api_engine, migrated_engine, people)
    async with app_engine.begin() as conn:
        assert (await sendcheck.release(conn, closed.close_row, VERIFIER)).verdict == "send"
    async with app_engine.begin() as conn:
        await conn.execute(text("UPDATE users SET disabled = true WHERE id = :u"),
                           {"u": people["ravi"].user_id})  # fmt: skip
    writer = FakeWriter()
    results = await writer.run(app_engine)
    assert writer.sent == []
    assert results[closed.close_row].verdict == "reconfirm"
    assert any("revoked" in r for r in results[closed.close_row].reasons)
    state, reason = await _state(app_engine, closed.close_row)
    assert state == "paused"
    assert reason is not None
    assert reason.startswith("re-confirm:")
    with pytest.raises(DBAPIError, match="no complete, unexpired, signed approval"):
        async with migrated_engine.begin() as conn:  # the guard refuses it whatever code runs
            await conn.execute(text("UPDATE kibana_outbox SET state = 'approved' WHERE id = :r"),
                               {"r": closed.close_row})  # fmt: skip
    with pytest.raises(DBAPIError, match="no complete, unexpired, signed approval"):
        async with app_engine.begin() as conn:  # the runtime's only move: the same guard
            await conn.execute(text("SELECT argus_closure_write_move(:r, 'approved', NULL)"),
                               {"r": closed.close_row})  # fmt: skip
    reconfirm = await rows(app_engine, "SELECT * FROM approval_requests WHERE kind = 'reconfirm'")
    assert len(reconfirm) == 1
    assert (reconfirm[0].outbox_id, reconfirm[0].proposed_by) == (closed.close_row,
                                                                  sendcheck.PROPOSER)  # fmt: skip
    assert reconfirm[0].requested_by_user_id is None
    assert await _desk_decide(api_engine, people["meera"], int(reconfirm[0].id)) == "approved"
    results = await writer.run(app_engine)
    assert results[closed.close_row].verdict == "send"
    assert results[closed.close_row].basis == reconfirm[0].id
    assert writer.sent == [closed.close_row]


async def test_a_denied_check_voids_the_approvers_approvals(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    """Any 401 or 403 voids a person's approvals: a released write is held back, and a
    two-person request does not complete with the revoked person's half."""
    closed = await _closed(api_engine, migrated_engine, people)
    ravi, meera, asha = people["ravi"], people["meera"], people["asha"]
    provider = _provider(ravi)
    provider.deny(ravi.user_id)
    inv = await investigation(migrated_engine, actor=(("source.ip", "10.0.0.3"),))
    other = await _open(api_engine, asha.actor(), [inv])
    two = await _request(api_engine, asha, other, 1, "risk_accepted", note="lab cluster")
    assert await _desk_decide(api_engine, meera, two) == "pending"
    async with api_engine.begin() as conn:  # the desk records the denial, then refuses
        at = await step_up(conn, ravi)
        desk = ApprovalDesk(conn, identity_provider=provider, signer=SIGNER)
        with pytest.raises(Refused) as refused:
            await desk.decide(SessionProof(ravi.session_token, ravi.user_id, at), two,
                              "approved")  # fmt: skip
    assert refused.value.status == 403
    denied = await rows(app_engine, "SELECT outcome FROM identity_checks WHERE user_id = :u"
                                    " ORDER BY id DESC LIMIT 1", u=ravi.user_id)  # fmt: skip
    assert denied[0].outcome == "denied"
    results = await FakeWriter().run(app_engine)
    assert results[closed.close_row].verdict == "reconfirm"
    # meera's half stands; a revoked approver's would not: void a second time and check
    async with api_engine.begin() as conn:
        facts = await approvals.facts(conn, two)
    assert facts is not None
    assert (facts.approved, facts.required) == (1, 2)
    await identity_denial(api_engine, meera)
    async with api_engine.begin() as conn:
        facts = await approvals.facts(conn, two)
    assert facts is not None
    assert facts.approved == 0  # meera's approval is void now
    assert await _desk_decide(api_engine, people["ravi"], two, provider=_provider(ravi)) == (
        "pending"
    )


async def identity_denial(engine: AsyncEngine, person: Person) -> None:
    async with engine.begin() as conn:
        await identity.record(
            conn, identity.LiveCheck(person.user_id, "denied", "fake",
                                     await identity.database_clock(conn)), "recheck",
        )  # fmt: skip


async def test_tampering_with_any_bound_row_is_refused_never_sent(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    closed = await _closed(api_engine, migrated_engine, people)
    async with app_engine.connect() as conn:
        assert (await sendcheck.check(conn, closed.close_row, VERIFIER)).verdict == "send"
    edits = (
        _unguarded("approval_decisions",
                   "UPDATE approval_decisions SET capabilities = capabilities || '[\"admin\"]'"),
        _unguarded("approval_decisions", "UPDATE approval_decisions SET identity_check ="
                   " jsonb_set(identity_check, '{email}', '\"someone@example.org\"')"),
        _unguarded("approval_decisions", "UPDATE approval_decisions SET stepped_up_at ="
                   " stepped_up_at - interval '1 second'"),
        _unguarded("approval_requests", "UPDATE approval_requests SET kibana_version = 'other'"),
        _unguarded("approval_requests", "UPDATE approval_requests SET expires_at ="
                   " expires_at + interval '1 hour'"),
    )  # fmt: skip
    for statements in edits:
        found = await _check_after(migrated_engine, closed.close_row, *statements)
        assert found.verdict == "refuse", (statements[1], found)
        assert any("no valid signature" in r for r in found.reasons)
    # the payloads: the approved one, and the row's own
    for statements in (
        _unguarded("approval_requests",
                   "UPDATE approval_requests SET payload_hash = repeat('b', 64)"),
        ("ALTER TABLE kibana_outbox DISABLE TRIGGER kibana_outbox_guard",
         "UPDATE kibana_outbox SET payload_hash = repeat('c', 64)"),
    ):  # fmt: skip
        found = await _check_after(migrated_engine, closed.close_row, *statements)
        assert found.verdict == "refuse"
        assert any("hash" in r for r in found.reasons)
    # a decision signed by a key the writer does not accept
    other_key = signing.new_key()
    async with app_engine.connect() as conn:
        found = await sendcheck.check(conn, closed.close_row, signing.Verifier([other_key]))
    assert found.verdict == "refuse"


async def test_a_signature_replayed_onto_another_request_is_refused(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    first = await _closed(api_engine, migrated_engine, people, alerts=2)
    second = await _closed(api_engine, migrated_engine, people, alerts=3)
    query = "SELECT signature FROM approval_decisions WHERE request_id = :r"
    signature = (await rows(app_engine, query, r=first.request_id))[0]
    await _owner_sql(
        migrated_engine,
        *_unguarded("approval_decisions",
                    "UPDATE approval_decisions SET signature = :s WHERE request_id = :r"),
        s=signature.signature, r=second.request_id,
    )  # fmt: skip
    async with app_engine.connect() as conn:
        assert (await sendcheck.check(conn, first.close_row, VERIFIER)).verdict == "send"
        found = await sendcheck.check(conn, second.close_row, VERIFIER)
    assert found.verdict == "refuse"
    results = await FakeWriter().run(app_engine)
    assert await _state(app_engine, second.close_row) == ("paused", "refused: " + "; ".join(
        results[second.close_row].reasons))  # fmt: skip


async def test_an_expired_approval_sends_nothing_and_counts_as_expired_unsent(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    closed = await _closed(api_engine, migrated_engine, people)
    async with app_engine.connect() as conn:
        request = await approvals.record(conn, closed.request_id)
        assert request is not None
        late = request.expires_at + timedelta(seconds=1)
        found = await sendcheck.check(conn, closed.close_row, VERIFIER, now=late)
        assert found.verdict == "reconfirm"
        assert found.expired_unsent
        assert any("expired" in r for r in found.reasons)
        before = await autonomy.ledger(conn, request.expires_at - timedelta(seconds=1))
        after = await autonomy.ledger(conn, late)
    assert (before.expired_unsent, after.expired_unsent, after.with_writes) == (0, 1, 1)
    # the guard measures expiry on the clock: an expired approval cannot let the row go
    await _owner_sql(
        migrated_engine,
        *_unguarded(
            "approval_requests",
            "UPDATE approval_requests SET expires_at = clock_timestamp() - interval '1 second',"
            " requested_at = clock_timestamp() - interval '2 seconds' WHERE id = :r",
        ),
        r=closed.request_id,
    )
    with pytest.raises(DBAPIError, match="no complete, unexpired, signed approval"):
        async with migrated_engine.begin() as conn:
            await conn.execute(text("UPDATE kibana_outbox SET state = 'approved' WHERE id = :r"),
                               {"r": closed.close_row})  # fmt: skip


async def test_a_case_reopened_before_the_send_skips_its_closure_write(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    closed = await _closed(api_engine, migrated_engine, people)
    async with app_engine.begin() as conn:
        assert (await sendcheck.release(conn, closed.close_row, VERIFIER)).verdict == "send"
    await _apply(api_engine, people["asha"].actor(), closed.case_id, Reopen("seen again"), 3)
    writer = FakeWriter()
    results = await writer.run(app_engine)
    assert writer.sent == []
    assert results[closed.close_row].verdict == "skip"
    assert (await _state(app_engine, closed.close_row))[0] == "skipped"
    assert (await _state(app_engine, closed.comment_row))[0] == "skipped"


async def test_the_kibana_case_or_its_alerts_moving_needs_a_reconfirmation(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    closed = await _closed(api_engine, migrated_engine, people)
    await _mirror(migrated_engine, closed.case_id, "WzIsMV0=")
    async with app_engine.connect() as conn:
        found = await sendcheck.check(conn, closed.close_row, VERIFIER)
    assert found.verdict == "reconfirm"
    assert any("Kibana case changed" in r for r in found.reasons)
    await _mirror(migrated_engine, closed.case_id)
    await _owner_sql(migrated_engine, "UPDATE kibana_mirror SET sync_alerts = true")
    async with app_engine.connect() as conn:
        found = await sendcheck.check(conn, closed.close_row, VERIFIER)
    assert (found.verdict, found.reasons) == (
        "refuse",
        ("Sync alerts is on in Kibana: nothing is sent while it is",),
    )
    await _owner_sql(migrated_engine, "UPDATE kibana_mirror SET sync_alerts = false")
    member = (await rows(app_engine, "SELECT investigation_id FROM case_members"
                                     " WHERE case_id = :c", c=closed.case_id))[0]  # fmt: skip
    await _owner_sql(
        migrated_engine,
        "INSERT INTO alert_records (alert_id, index, status, normalizer_version, raw,"
        " content_hash, state_hash, recovered_by, detected_at) VALUES ('late-1', 'alerts',"
        " 'normalized', 'test', '{}', 'h', 'h', 'live', now())",
        "INSERT INTO investigation_alerts (alert_id, investigation_id) VALUES ('late-1', :i)",
        i=member.investigation_id,
    )
    async with app_engine.connect() as conn:
        found = await sendcheck.check(conn, closed.close_row, VERIFIER)
    assert found.verdict == "reconfirm"
    assert any("alerts changed" in r for r in found.reasons)


async def test_an_approver_without_a_live_check_for_twelve_hours_needs_a_reconfirmation(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    closed = await _closed(api_engine, migrated_engine, people)
    async with app_engine.connect() as conn:
        now = await identity.database_clock(conn)
        soon = await sendcheck.check(conn, closed.close_row, VERIFIER,
                                     now=now + timedelta(hours=11))  # fmt: skip
        late = await sendcheck.check(conn, closed.close_row, VERIFIER,
                                     now=now + timedelta(hours=12, minutes=1))  # fmt: skip
    request = (await rows(app_engine, "SELECT expires_at FROM approval_requests"))[0]
    if now + timedelta(hours=11) <= request.expires_at:
        assert soon.verdict == "send"
    assert late.verdict == "reconfirm"
    assert any("no good live check within 12 hours" in r for r in late.reasons)


async def test_a_lost_privilege_at_the_last_check_holds_the_write_back(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    closed = await _closed(api_engine, migrated_engine, people)
    ravi = people["ravi"]
    async with api_engine.begin() as conn:  # a later re-check: still a person, no updateCase
        await identity.record(conn, identity.LiveCheck(
            ravi.user_id, "ok", "fake", await identity.database_clock(conn), "person",
            APPROVER, frozenset({"createCase"})), "recheck")  # fmt: skip
    async with app_engine.connect() as conn:
        found = await sendcheck.check(conn, closed.close_row, VERIFIER)
    assert found.verdict == "reconfirm"
    assert any("no longer holds" in r for r in found.reasons)


# ------------------------------------------------------------------ groups


async def _benign_requests(api: AsyncEngine, owner: AsyncEngine, asha: Person, n: int,
                           reason: str = "benign_expected") -> list[int]:  # fmt: skip
    ids = []
    for k in range(n):
        inv = await investigation(owner, actor=(("source.ip", f"10.3.{k}.{n}"),))
        case_id = await _open(api, asha.actor(), [inv])
        ids.append(
            await _request(
                api,
                asha,
                case_id,
                1,
                reason,
                note="a note" if reason == "created_in_error" else None,
            )
        )
    return ids


async def test_a_group_is_approved_sample_first_and_only_for_benign_closures(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    asha, ravi = people["asha"], people["ravi"]
    ids = await _benign_requests(api_engine, migrated_engine, asha, 5)
    batch = approvals.group(ids, seed="g1")
    assert len(batch["sample"]) == 3
    rest = [i for i in ids if i not in batch["sample"]]
    with pytest.raises(ApprovalError, match="sample one by one first") as early:
        await _desk_decide(api_engine, ravi, rest[0], batch=batch)
    assert early.value.status == 409
    for rid in batch["sample"]:
        assert await _desk_decide(api_engine, ravi, rid, batch=batch) == "approved"
    async with api_engine.begin() as conn:
        at = await step_up(conn, ravi)
        desk = ApprovalDesk(conn, identity_provider=_provider(ravi), signer=SIGNER)
        done = await desk.approve_rest(SessionProof(ravi.session_token, ravi.user_id, at), batch)
    assert [d.status for d in done] == ["approved"] * len(rest)
    closed = await rows(api_engine, "SELECT count(*) AS n FROM cases WHERE state = 'closed'")
    assert closed[0].n == 5
    # a rejection never goes in a group; nor a smaller sample; nor a reason outside the list
    more = await _benign_requests(api_engine, migrated_engine, asha, 3)
    with pytest.raises(ApprovalError, match="a group only approves"):
        await _desk_decide(api_engine, ravi, more[0], "rejected",
                           batch=approvals.group(more, seed="g2"))  # fmt: skip
    small = {"requests": more, "sample": more[:2]}
    with pytest.raises(ApprovalError, match="max\\(3, 10 %\\)"):
        await _desk_decide(api_engine, ravi, more[0], batch=small)
    malformed = (
        {"requests": "x", "sample": []},
        {"requests": [*more, 1.5], "sample": more},
        {"requests": [*more, "7"], "sample": more},
        {"requests": [-1, *more], "sample": more},
        {"requests": list(range(1, 22)), "sample": [1, 2, 3]},
        ["not", "an", "object"],
    )
    for bad in malformed:
        with pytest.raises(ApprovalError, match="a group names its requests"):
            await _desk_decide(api_engine, ravi, more[0], batch=bad)  # type: ignore[arg-type]
    errors = await _benign_requests(api_engine, migrated_engine, asha, 3, "created_in_error")
    with pytest.raises(ApprovalError, match="only benign"):
        await _desk_decide(api_engine, ravi, errors[0], batch=approvals.group(errors, seed="g3"))
    with pytest.raises(ApprovalError, match="2 to 20"):
        approvals.group(list(range(1, 22)), seed="big")


async def test_a_two_person_closure_needs_two_different_people(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    """Two accounts of one person (the same argus_uid or e-mail address) are one person: not
    both approvers, and not the requester's approver."""
    asha, ravi, meera = people["asha"], people["ravi"], people["meera"]
    inv = await investigation(migrated_engine)
    case_id = await _open(api_engine, asha.actor(), [inv])
    request = await _request(api_engine, asha, case_id, 1, "risk_accepted", note="kept")
    twin = _provider(ravi, meera)
    twin.allow(meera.user_id, APPROVER, KIBANA, argus_uid="uid-ravi", email="meera@example.org")
    assert await _desk_decide(api_engine, ravi, request, provider=twin) == "pending"
    with pytest.raises(ApprovalError, match="two different people") as twice:
        await _desk_decide(api_engine, meera, request, provider=twin)
    assert twice.value.status == 403
    same_mail = _provider(meera)
    same_mail.allow(meera.user_id, APPROVER, KIBANA, argus_uid="uid-m", email="RAVI@example.org")
    with pytest.raises(ApprovalError, match="two different people"):
        await _desk_decide(api_engine, meera, request, provider=same_mail)
    assert await _desk_decide(api_engine, meera, request) == "approved"
    # the requester's second account
    inv2 = await investigation(migrated_engine, actor=(("source.ip", "10.0.0.4"),))
    other = await _open(api_engine, asha.actor(), [inv2])
    request2 = await _request(api_engine, asha, other, 1)
    async with api_engine.begin() as conn:
        await identity.record(conn, identity.LiveCheck(
            asha.user_id, "ok", "fake", await identity.database_clock(conn), "person",
            APPROVER, KIBANA, "uid-asha", "asha@example.org"), "signin")  # fmt: skip
    alias = _provider(ravi)
    alias.allow(ravi.user_id, APPROVER, KIBANA, argus_uid="uid-asha", email="r@example.org")
    with pytest.raises(ApprovalError, match="cannot approve their own request"):
        await _desk_decide(api_engine, ravi, request2, provider=alias)
    assert await _desk_decide(api_engine, ravi, request2) == "approved"


# ------------------------------------------------------------------ ARGUS's proposals


async def _review(owner: AsyncEngine, inv: uuid.UUID, person: Person, outcome: str) -> None:
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                " action, outcome) VALUES (:i, 1, 2, :u, 'reviewed', :o)"
            ),
            {"i": inv, "u": person.user_id, "o": outcome},
        )


async def test_argus_proposes_a_closure_people_reviewed_benign_and_a_person_approves_it(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    asha, ravi = people["asha"], people["ravi"]
    first = await investigation(migrated_engine, actor=(("source.ip", "10.4.0.1"),))
    second = await investigation(migrated_engine, actor=(("source.ip", "10.4.0.2"),))
    case_id = await _open(api_engine, asha.actor(), [first, second])
    async with app_engine.connect() as conn:
        assert await proposer.candidates(conn) == []  # nothing reviewed since it was opened
    await _review(migrated_engine, first, asha, "benign_expected")
    async with app_engine.connect() as conn:
        assert await proposer.candidates(conn) == []  # one member still unreviewed
    await _review(migrated_engine, second, asha, "benign_policy")
    async with app_engine.connect() as conn:
        assert await proposer.candidates(conn) == []  # two different outcomes
    await _review(migrated_engine, second, asha, "benign_expected")
    async with app_engine.begin() as conn:  # the runtime proposes
        found = await proposer.candidates(conn)
        assert [(c.case_id, c.reason) for c in found] == [(case_id, "benign_expected")]
        done = await proposer.propose(await CaseService.start(conn), found[0])
    assert done.request_id is not None
    request = (await rows(app_engine, "SELECT * FROM approval_requests"))[0]
    assert (request.proposed_by, request.requested_by_user_id, request.required_approvals) == (
        "argus:proposer", None, 1,
    )  # fmt: skip
    async with app_engine.connect() as conn:
        assert await proposer.candidates(conn) == []  # not proposed twice
    assert await _desk_decide(api_engine, ravi, done.request_id) == "approved"
    case = (await rows(app_engine, "SELECT state, closure_reason FROM cases"))[0]
    assert (case.state, case.closure_reason) == ("closed", "benign_expected")
    reports = await chain.verify_snapshot(app_engine)
    assert all(r.ok for r in reports), [r.summary() for r in reports]
    async with app_engine.connect() as conn:
        found_ledger = await autonomy.ledger(conn)
    (line,) = found_ledger.classes
    assert (line.reason, line.proposed, line.approved, line.rejected) == (
        "benign_expected", 1, 1, 0,
    )  # fmt: skip
    assert any("125 audited" in m for m in line.missing())


async def test_argus_never_proposes_what_needs_a_persons_word_and_never_approves(
    app_engine: AsyncEngine, api_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    inv = await investigation(migrated_engine)
    case_id = await _open(api_engine, people["asha"].actor(), [inv])
    async with app_engine.begin() as conn:
        service = await CaseService.start(conn)
        for reason in ("risk_accepted", "remediated_unverified", "created_in_error"):
            with pytest.raises(Exception, match="does not propose"):
                await service.propose_closure(
                    Actor.argus("proposer"), case_id, reason=reason, evidence="x"
                )  # type: ignore[arg-type]
        with pytest.raises(Exception, match="verified evidence"):
            await service.propose_closure(Actor.argus("proposer"), case_id,
                                          reason="remediated_verified")  # fmt: skip
        with pytest.raises(Exception, match="ARGUS's own move"):
            await service.propose_closure(people["asha"].actor(APPROVER), case_id,
                                          reason="benign_expected", evidence="x")  # fmt: skip
    async with app_engine.begin() as conn:  # a proposal with no request event of its own
        case = (await conn.execute(text("SELECT version FROM cases"))).scalar_one()
        with pytest.raises(ApprovalError, match="follows its own request event"):
            await approvals.propose(
                conn, proposer="argus:proposer", case_id=case_id, case_version=case,
                kind="closure", reason="benign_expected", payload={"writes": []},
                payload_hash=__import__("argus.cases.kibana", fromlist=["x"]).payload_hash(
                    {"writes": []}),
                expires=(await conn.execute(text("SELECT now() + interval '1 hour'"))).scalar_one(),
            )  # fmt: skip


async def test_the_webs_login_records_decisions_and_argus_applies_them(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    asha, ravi = people["asha"], people["ravi"]
    inv = await investigation(migrated_engine)
    case_id = await _open(api_engine, asha.actor(), [inv])
    request = await _request(api_engine, asha, case_id, 1)
    assert await _desk_decide(api_engine, ravi, request, apply=False) == "approved"
    assert (await rows(app_engine, "SELECT state FROM cases"))[0].state == "open"
    async with app_engine.begin() as conn:
        applied = await (await CaseService.start(conn)).apply_approved(request)
    assert [a.case.state for a in applied] == ["closed"]
    assert applied[0].step.kind == "closed"
    async with app_engine.begin() as conn:  # once
        assert await (await CaseService.start(conn)).apply_approved(request) == []
    event = (await rows(app_engine, "SELECT actor, details FROM case_events"
                                    " WHERE kind = 'closed'"))[0]  # fmt: skip
    assert event.actor == f"user:{ravi.user_id}"


async def test_a_web_login_may_record_approvals_and_checks_and_nothing_more(
    make_api_login: Any, migrated_engine: AsyncEngine, test_database: str
) -> None:
    from argus.db import roles
    from argus.db.engine import create_engine

    login = await make_api_login()
    engine = create_engine(login, database=test_database, role="api")
    try:
        assert await roles.api_role_problems(engine) == []
        async with engine.connect() as conn:
            held = (await conn.execute(text(
                "SELECT has_function_privilege(to_regprocedure(:f), 'EXECUTE')"),
                {"f": roles.RUNTIME_FUNCTIONS[0]})).scalar_one()  # fmt: skip
        assert held is False
    finally:
        await engine.dispose()


# ------------------------------------------------------------------ edges


async def test_the_send_time_check_on_rows_it_does_not_judge(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    closed = await _closed(api_engine, migrated_engine, people)
    create = (await rows(app_engine, "SELECT id FROM kibana_outbox WHERE op = 'create'"))[0]
    async with app_engine.begin() as conn:
        assert (await sendcheck.check(conn, 10_000, VERIFIER)).reasons == ("no such outbox row",)
        assert (await sendcheck.check(conn, int(create.id), VERIFIER)).reasons == (
            "not a closure write",
        )
        assert (await sendcheck.release(conn, 10_000, VERIFIER)).verdict == "refuse"
    found = await _check_after(migrated_engine, closed.close_row,
                               "DELETE FROM kibana_mirror")  # fmt: skip
    assert (found.verdict, found.reasons) == ("wait", ("the case is not mirrored in Kibana yet",))
    found = await _check_after(migrated_engine, closed.close_row,
                               "UPDATE kibana_mirror SET deleted_at = now()")  # fmt: skip
    assert (found.verdict, found.reasons) == ("skip", ("the Kibana case was deleted",))
    found = await _check_after(
        migrated_engine, closed.close_row,
        "ALTER TABLE kibana_outbox DISABLE TRIGGER kibana_outbox_guard",
        "UPDATE kibana_outbox SET state = 'verified' WHERE op = 'close'",
    )  # fmt: skip
    assert (found.verdict, found.reasons) == ("wait", ("the row is verified",))
    async with migrated_engine.connect() as conn:  # the comment, once the change is verified
        trans = await conn.begin()
        await conn.execute(text("ALTER TABLE kibana_outbox DISABLE TRIGGER kibana_outbox_guard"))
        await conn.execute(text("UPDATE kibana_outbox SET state = 'verified' WHERE op = 'close'"))
        assert (await sendcheck.check(conn, closed.comment_row, VERIFIER)).verdict == "send"
        await trans.rollback()
    assert sendcheck.SendCheck(1, "send").summary == "send: all checks hold"


async def test_the_desk_refuses_what_it_cannot_check(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    asha, ravi = people["asha"], people["ravi"]
    inv = await investigation(migrated_engine)
    case_id = await _open(api_engine, asha.actor(), [inv])
    request = await _request(api_engine, asha, case_id, 1)
    down = _provider(ravi)
    down.deny(ravi.user_id, "unavailable")
    with pytest.raises(ApprovalError, match="could not be made") as unavailable:
        await _desk_decide(api_engine, ravi, request, provider=down)
    assert unavailable.value.status == 503
    service = _provider(ravi)
    service.allow(ravi.user_id, APPROVER, kind="service")
    with pytest.raises(ApprovalError, match="a person's own account") as not_person:
        await _desk_decide(api_engine, ravi, request, provider=service)
    assert not_person.value.status == 403
    with pytest.raises(ApprovalError, match="no such approval request"):
        await _desk_decide(api_engine, ravi, 10_000)
    async with api_engine.begin() as conn:  # a disabled or missing account is denied locally
        await conn.execute(text("UPDATE users SET disabled = true WHERE id = :u"),
                           {"u": ravi.user_id})  # fmt: skip
        local = identity.LocalIdentityProvider()
        assert (await local.check(conn, ravi.user_id, purpose="approval")).outcome == "denied"
        assert (await local.check(conn, 10_000, purpose="approval")).outcome == "denied"
        await conn.rollback()


async def test_a_rejected_reconfirmation_and_the_ledgers_counts(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    closed = await _closed(api_engine, migrated_engine, people)
    await _mirror(migrated_engine, closed.case_id, "WzMsMV0=")
    await FakeWriter().run(app_engine)  # held back, a re-confirmation asked
    asked = await rows(app_engine, "SELECT id FROM approval_requests WHERE kind = 'reconfirm'")
    assert await _desk_decide(api_engine, people["meera"], int(asked[0].id), "rejected") == (
        "rejected"
    )
    async with app_engine.connect() as conn:
        found = await sendcheck.check(conn, closed.close_row, VERIFIER)
    assert (found.verdict, found.reasons) == (
        "skip",
        (f"a person rejected its re-confirmation ({asked[0].id})",),
    )
    await FakeWriter().run(app_engine)  # skipped, and no new re-confirmation asked
    assert (await _state(app_engine, closed.close_row))[0] == "skipped"
    await FakeWriter().run(app_engine)  # the comment follows the change it belongs to
    assert await _state(app_engine, closed.comment_row) == (
        "skipped",
        "the closing change was skipped",
    )
    assert (
        len(await rows(app_engine, "SELECT 1 FROM approval_requests WHERE kind = 'reconfirm'")) == 1
    )
    # ARGUS's proposals, one approved, one rejected, one waiting: counted per class
    asha, ravi = people["asha"], people["ravi"]
    ids = []
    for k in range(3):
        inv = await investigation(migrated_engine, actor=(("source.ip", f"10.6.0.{k}"),))
        case_id = await _open(api_engine, asha.actor(), [inv])
        async with app_engine.begin() as conn:
            _, request = await (await CaseService.start(conn)).propose_closure(
                Actor.argus("proposer"), case_id, reason="rule_false_positive",
                evidence="every member reviewed as a false positive",
            )  # fmt: skip
        ids.append(request)
    assert await _desk_decide(api_engine, ravi, ids[0]) == "approved"
    assert await _desk_decide(api_engine, ravi, ids[1], "rejected") == "rejected"
    async with app_engine.connect() as conn:
        now = await identity.database_clock(conn)
        ledger = await autonomy.ledger(conn, now)
        later = await autonomy.ledger(conn, now + timedelta(days=4))
    (line,) = ledger.classes
    assert (line.proposed, line.approved, line.rejected, line.pending) == (3, 1, 1, 1)
    assert line.wrong == 1
    (aged,) = later.classes
    assert (aged.pending, aged.expired_undecided) == (0, 1)
    assert later.expired_undecided >= 1
    assert sum(w.decided for w in aged.weeks) in (0, 2)  # this week counts once it is over
    assert len(aged.weeks) == autonomy.STABLE_WEEKS


async def test_one_reconfirmation_covers_the_closing_change_and_its_comment(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    closed = await _closed(api_engine, migrated_engine, people)
    await _owner_sql(migrated_engine, "UPDATE users SET disabled = true WHERE id = :u",
                     u=people["ravi"].user_id)  # fmt: skip
    writer = FakeWriter()
    await writer.run(app_engine)
    asked = await rows(app_engine, "SELECT id FROM approval_requests WHERE kind = 'reconfirm'")
    assert len(asked) == 1
    assert await _desk_decide(api_engine, people["meera"], int(asked[0].id)) == "approved"
    assert (await writer.run(app_engine))[closed.close_row].verdict == "send"
    await _owner_sql(  # the writer sent the closing change and read it back
        migrated_engine,
        "ALTER TABLE kibana_outbox DISABLE TRIGGER kibana_outbox_guard",
        "UPDATE kibana_outbox SET state = 'verified' WHERE id = :r",
        "ALTER TABLE kibana_outbox ENABLE ALWAYS TRIGGER kibana_outbox_guard",
        r=closed.close_row,
    )
    results = await writer.run(app_engine)
    assert results[closed.comment_row].verdict == "send"
    assert results[closed.comment_row].basis == asked[0].id
    assert writer.sent.count(closed.comment_row) == 1
    count = await rows(app_engine, "SELECT count(*) AS n FROM approval_requests"
                                   " WHERE kind = 'reconfirm'")  # fmt: skip
    assert count[0].n == 1
