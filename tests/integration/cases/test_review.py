"""The independent adversarial review of Q-C1 (findings F1-F15): each test asserts the correct
behaviour and failed on p3/cases at 0439d8b (16 failed) before its fix.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import approvals, chain, kibana, machine, opener
from argus.cases.machine import Reopen, Take
from argus.cases.model import KIBANA_TO_OPEN
from argus.cases.service import CaseService
from tests.integration.cases.conftest import (
    APPROVER,
    Person,
    asking,
    investigation,
    rows,
    signed_for,
)
from tests.integration.cases.test_guards import _move, _outbox_case
from tests.integration.cases.test_opener import BEACON, CLASSIFIER, WINDOW, _dossier, _review
from tests.integration.cases.test_service import _apply, _case, _decide, _open, _request
from tests.integration.test_cli_db import _run, cli_env  # noqa: F401 - the fixture

pytestmark = pytest.mark.integration


def _kib(person: Person):  # type: ignore[no-untyped-def]
    return person.actor(APPROVER, kibana=KIBANA_TO_OPEN,
                        checked_at=datetime.now(UTC) - timedelta(seconds=1))  # fmt: skip


async def _forge_event_with_rows(
    app_engine: AsyncEngine,
    case_id: uuid.UUID,
    version: int,
    writes: list[dict],
    request: int | None,
) -> None:
    """As the RUNTIME role: a same-state case change (open -> open), its event and outbox rows."""
    async with app_engine.begin() as conn:
        await conn.execute(text("UPDATE cases SET version = :v WHERE id = :c"),
                           {"v": version, "c": case_id})  # fmt: skip
        event = (
            await conn.execute(
                text(
                    "INSERT INTO case_events (case_id, case_version, kind, actor, from_state,"
                    " to_state, kibana_rows) VALUES (:c, :v, 'linked', 'argus:opener', 'open',"
                    " 'open', :n) RETURNING id"
                ),
                {"c": case_id, "v": version, "n": len(writes)},
            )
        ).scalar_one()
        for position, write in enumerate(writes):
            await conn.execute(
                text(
                    "INSERT INTO kibana_outbox (case_id, case_event_id, position, idempotency_key,"
                    " write_class, op, payload, payload_hash, approval_request_id) VALUES (:c, :e,"
                    " :p, :k, :w, :op, CAST(:payload AS jsonb), :h, :r)"
                ),
                {"c": case_id, "e": event, "p": position,
                 "k": f"forged:{case_id}:{version}:{position}",
                 "w": write["class"], "op": write["op"], "payload": json.dumps(write["payload"]),
                 "h": kibana.payload_hash(write["payload"]), "r": request},
            )  # fmt: skip


# ------------------------------------------------------------------ R1: a Kibana closure as W2


async def test_r1_runtime_cannot_plan_a_kibana_closure_as_a_w2_update(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """A confirmed, mirrored, OPEN case: the runtime role plans a W2 'update' whose intent is
    status closed with the closed/reason tags, with no approval at all."""
    inv = await investigation(migrated_engine)
    case_id = await _open(app_engine, _kib(people["asha"]), [inv])
    closed_tags = sorted({"argus", f"argus:case:{case_id}", "argus:state:closed",
                          "argus:closed", "argus:reason:benign_expected"})  # fmt: skip
    write = {"class": "W2", "op": "update",
             "payload": {"status": "closed", "argus_tags": closed_tags}}  # fmt: skip
    with pytest.raises(DBAPIError):  # expected: the outbox guard refuses a closure outside W3
        await _forge_event_with_rows(app_engine, case_id, 2, [write], None)


# ------------------------------------------------------------------ R2: an approval used twice


async def test_r2_a_closure_approval_cannot_plan_w3_rows_for_another_event(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    asha, ravi = people["asha"], people["ravi"]
    inv = await investigation(migrated_engine)
    case_id = await _open(api_engine, _kib(asha), [inv])
    request = await _request(api_engine, asha, case_id, 1)  # v2
    status, _ = await _decide(api_engine, ravi, request)  # closes: v3, W3 rows
    assert status == "approved"
    await _apply(api_engine, asha.actor(), case_id, Reopen("seen again"), 3)  # v4, open
    approved = (await rows(app_engine, "SELECT payload FROM approval_requests WHERE id = :r",
                           r=request))[0].payload  # fmt: skip
    # The runtime role re-plans the SAME approved closure for the reopened (open) case.
    with pytest.raises(DBAPIError):  # expected: W3 rows only with the closure their approval closed
        await _forge_event_with_rows(app_engine, case_id, 5, approved["writes"], request)


async def test_r2b_a_complete_unapplied_approval_cannot_close_kibana_while_argus_stays_open(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    asha, ravi = people["asha"], people["ravi"]
    inv = await investigation(migrated_engine)
    case_id = await _open(api_engine, _kib(asha), [inv])
    request = await _request(api_engine, asha, case_id, 1)
    async with api_engine.begin() as conn:  # approved through the function, not applied
        await approvals.decide(conn, session_token=ravi.session_token, request_id=request,
                               decision="approved",
                               signed=await signed_for(conn, ravi, request))  # fmt: skip
    approved = (await rows(app_engine, "SELECT payload FROM approval_requests WHERE id = :r",
                           r=request))[0].payload  # fmt: skip
    with pytest.raises(DBAPIError):
        await _forge_event_with_rows(app_engine, case_id, 3, approved["writes"], request)


# ------------------------------------------------------------------ R3: unchained case events


async def test_r3_verify_catches_a_case_event_written_with_the_chain_trigger_off(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    inv = await investigation(migrated_engine)
    case_id = await _open(app_engine, people["asha"].actor(), [inv])
    triggers = ("case_events_chain", "case_events_chain_head", "case_events_follow_case")
    for statement in (
        *(f"ALTER TABLE case_events DISABLE TRIGGER {t}" for t in triggers),
        "INSERT INTO case_events (case_id, case_version, kind, actor, actor_user_id,"
        " from_state, to_state) VALUES (:c, 50, 'closed', 'user:2', 2, 'open', 'closed')",
        *(f"ALTER TABLE case_events ENABLE ALWAYS TRIGGER {t}" for t in triggers),
    ):  # the owner, one statement a transaction (as test_chain's _owner for audit_events)
        async with migrated_engine.begin() as conn:
            await conn.execute(text(statement), {"c": case_id})
    unchained = await rows(
        app_engine, "SELECT count(*) AS n FROM case_events WHERE chain_seq IS NULL"
    )
    assert unchained[0].n == 1
    reports = await chain.verify_snapshot(app_engine)
    case_report = next(r for r in reports if r.chain == "case_events")
    assert not case_report.ok, case_report.summary()  # expected: FAIL, like audit_events


# ------------------------------------------------------------------ R4: decisions not audited


async def test_r4_every_approval_decision_is_in_the_chained_audit_trail(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    asha, ravi, meera = people["asha"], people["ravi"], people["meera"]
    inv = await investigation(migrated_engine)
    case_id = await _open(api_engine, asha.actor(), [inv])
    request = await _request(api_engine, asha, case_id, 1, "risk_accepted", note="lab cluster")
    assert (await _decide(api_engine, ravi, request))[0] == "pending"
    assert (await _decide(api_engine, meera, request))[0] == "approved"
    other = await investigation(migrated_engine, actor=(("source.ip", "10.9.9.9"),))
    case2 = await _open(api_engine, asha.actor(), [other])
    request2 = await _request(api_engine, asha, case2, 1)
    assert (await _decide(api_engine, meera, request2, "rejected"))[0] == "rejected"
    by_ravi = await rows(
        api_engine,
        "SELECT (SELECT count(*) FROM audit_events WHERE actor = :a)"
        " + (SELECT count(*) FROM case_events WHERE actor = :a) AS n", a=f"user:{ravi.user_id}",
    )  # fmt: skip
    rejections = await rows(
        api_engine, "SELECT count(*) AS n FROM audit_events WHERE actor = :a AND target_id = :c",
        a=f"user:{meera.user_id}", c=str(case2),
    )  # fmt: skip
    assert (by_ravi[0].n, rejections[0].n) == (1, 1)  # expected: each decision audited once


# ------------------------------------------------------------------ R5: suspected, then a verdict


async def test_r5_a_persons_true_positive_verdict_opens_a_suspected_case(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """The normal order: ARGUS's proposal first (a suspected case), the person's verdict later."""
    inv = await investigation(migrated_engine, rule="c2", actor=(("source.ip", "10.201.7.13"),))
    await _dossier(migrated_engine, inv, BEACON, ["77.221.155.150"])
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO assessments (investigation_id, version, pack, dossier_hash,"
                " view_hash, assessor, run_after, status, outcome) VALUES (:i, 1, 'p',"
                " repeat('a', 64), :v, 'agent@1', now(), 'proposed', 'true_positive')"
            ),
            {"i": inv, "v": uuid.uuid4().hex * 2},
        )
    first = await opener.run(app_engine, window=WINDOW, classifier=CLASSIFIER, dry_run=False)
    assert first.applied == {"suspected": 1}
    await _review(app_engine, people["asha"], inv)  # a person: true positive, with a beacon
    second = await opener.run(app_engine, window=WINDOW, classifier=CLASSIFIER, dry_run=False)
    state = (await rows(app_engine, "SELECT state FROM cases"))[0].state
    # plan §7.1: "new or suspected -> open: a person's true-positive verdict with an impact ..."
    assert (second.applied, state) == ({"opened": 1}, "open"), (second.applied, state)


# ------------------------------------------------------------------ R6: a resend approved early


async def test_r6_a_resend_cannot_be_approved_before_the_row_is_ambiguous(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    row = await _outbox_case(api_engine, migrated_engine, people["asha"])  # 'planned', never sent
    case = (await rows(api_engine, "SELECT id, version FROM cases"))[0]
    payload = {"resend": row}
    try:
        async with api_engine.begin() as conn:
            request = await approvals.request(
                conn, session_token=people["asha"].session_token, case_id=case.id,
                case_version=case.version, kind="resend", reason=None, payload=payload,
                payload_hash=kibana.payload_hash(payload),
                expires=approvals.expires_at(datetime.now(UTC)), outbox_id=row,
                check=(await asking(conn, people["asha"])).snapshot(),
            )  # fmt: skip
    except approvals.ApprovalError:
        return  # expected: refused, the row is not ambiguous
    await _decide(api_engine, people["ravi"], request)
    for sets in ("state = 'approved'", "state = 'sending', sent_count = 1", "state = 'ambiguous'",
                 "state = 'planned', resends = 1", "state = 'approved'"):  # fmt: skip
        await _move(migrated_engine, row, sets)
    # the second send goes through on an approval given before anything was ambiguous
    await _move(migrated_engine, row, "state = 'sending', sent_count = 2")
    pytest.fail("a resend approved while the row was still 'planned' let a second send through")


# ------------------------------------------------------------------ R7: expiry at transaction start


async def test_r7_an_approval_is_not_used_after_it_expired(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person],
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    asha, ravi = people["asha"], people["ravi"]
    inv = await investigation(migrated_engine)
    case_id = await _open(api_engine, asha.actor(), [inv])
    monkeypatch.setattr(approvals, "expires_at", lambda now: now + timedelta(seconds=2))
    request = await _request(api_engine, asha, case_id, 1)
    expires = (await rows(api_engine, "SELECT expires_at FROM approval_requests"))[0].expires_at
    async with api_engine.connect() as conn:
        await conn.begin()
        service = await CaseService.start(conn)  # the transaction starts before the expiry ...
        await asyncio.sleep(3)  # ... and the decision and closure run after it
        refused = False
        try:
            await service.decide(ravi.actor(APPROVER), request,
                                 session_token=ravi.session_token,
                                 decision="approved",
                                 signed=await signed_for(conn, ravi, request))  # fmt: skip
            wall = (await conn.execute(text("SELECT clock_timestamp()"))).scalar_one()
            await conn.commit()
        except Exception:
            refused = True
            await conn.rollback()
    if not refused:
        assert wall > expires
        state = (await rows(api_engine, "SELECT state FROM cases WHERE id = :c", c=case_id))[0]
        pytest.fail(f"closed ({state.state}) at {wall:%H:%M:%S.%f} by an approval that expired at"
                    f" {expires:%H:%M:%S.%f}")  # fmt: skip


# ------------------------------------------------------------------ R8: titles Kibana refuses


async def test_r8_a_planned_kibana_title_fits_kibanas_limit(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    inv = await investigation(migrated_engine)
    await _open(app_engine, _kib(people["asha"]), [inv], title="Regular beaconing " + "x" * 182)
    payload = (await rows(app_engine, "SELECT payload FROM kibana_outbox WHERE op = 'create'"))[0]
    title = payload.payload["title"]
    assert len(title) <= 160, (
        f"{len(title)} characters: {title[:40]}..."
    )  # Kibana's MAX_TITLE_LENGTH


# ------------------------------------------------------------------ R9: an event with no change


async def test_r9_the_runtime_role_cannot_write_an_event_without_its_case_change(
    app_engine: AsyncEngine, api_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    asha = people["asha"]
    inv = await investigation(migrated_engine)
    case_id = await _open(app_engine, asha.actor(), [inv])
    forged = False
    try:
        async with app_engine.begin() as conn:  # a 'closed' event in asha's name; the case stays
            await conn.execute(
                text(
                    "INSERT INTO case_events (case_id, case_version, kind, actor, actor_user_id,"
                    " from_state, to_state) VALUES (:c, 2, 'closed', :a, :u, 'open', 'closed')"
                ),
                {"c": case_id, "a": f"user:{asha.user_id}", "u": asha.user_id},
            )
        forged = True
    except DBAPIError:
        pass
    if forged:
        report = next(
            r for r in await chain.verify_snapshot(app_engine) if r.chain == "case_events"
        )
        blocked = None
        try:
            await _apply(app_engine, people["ravi"].actor(), case_id, Take(), 1)
        except Exception as exc:
            blocked = type(exc).__name__
        pytest.fail(f"a 'closed' event with no change was committed (chain ok: {report.ok}); the"
                    f" case's next real command then fails: {blocked}")  # fmt: skip


# ------------------------------------------------------------------ R10: generic actor fields


async def test_r10_a_shared_user_domain_does_not_link_two_peoples_incidents(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    alice = await investigation(
        migrated_engine, rule="u1", actor=(("user.domain", "ACME"), ("user.name", "alice"))
    )
    bob = await investigation(migrated_engine, rule="u2",
                              actor=(("user.domain", "ACME"), ("user.name", "bob")))  # fmt: skip
    for inv in (alice, bob):
        await _dossier(migrated_engine, inv, BEACON, ["77.221.155.150"])
        await _review(app_engine, people["asha"], inv)
    report = await opener.run(app_engine, window=WINDOW, classifier=CLASSIFIER, dry_run=False)
    cases = await rows(app_engine, "SELECT count(*) AS n FROM cases")
    assert cases[0].n == 2, (report.applied, [opener.describe(o) for o in report.planned])


# ------------------------------------------------------------------ R11: overlapping runs


async def test_r11_overlapping_sync_and_backfill_keep_one_case_per_actor(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person],
    monkeypatch: pytest.MonkeyPatch,
) -> None:  # fmt: skip
    old = await investigation(migrated_engine, rule="c2", actor=(("source.ip", "10.201.7.13"),))
    new = await investigation(migrated_engine, rule="c2b", actor=(("source.ip", "10.201.7.13"),))
    for inv, age in ((old, timedelta(days=7)), (new, timedelta(hours=1))):
        await _dossier(migrated_engine, inv, BEACON, ["77.221.155.150"])
        async with migrated_engine.begin() as conn:  # a person's verdict, given ``age`` ago
            await conn.execute(
                text(
                    "INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                    " action, outcome, created_at, kibana_ok) VALUES (:i, 1, 2, :u,"
                    " 'reviewed', 'true_positive', now() - :a, true)"  # Kibana-ready (Q-E2)
                ),
                {"i": inv, "u": people["asha"].user_id, "a": age},
            )
    original = opener.created_last_hour
    calls = {"n": 0}

    async def hooked(conn):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if calls["n"] == 1:  # the backfill has planned; an hourly sync runs to the end meanwhile
            await opener.run(app_engine, window=WINDOW, classifier=CLASSIFIER, dry_run=False)
        return await original(conn)

    monkeypatch.setattr(opener, "created_last_hour", hooked)
    await opener.run(app_engine, window=WINDOW, classifier=CLASSIFIER, dry_run=False,
                     since=datetime.now(UTC) - timedelta(days=30), part="backfill")  # fmt: skip
    cases = await rows(app_engine, "SELECT number FROM cases ORDER BY number")
    assert len(cases) == 1, f"{len(cases)} cases for one actor"


# ------------------------------------------------------------------ R12: who the approver is


async def test_r12_only_the_approvers_own_live_session_can_record_their_approval(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    """F6: the stored token hashes are readable by every runtime/web login, so the function takes
    the raw token and hashes it; a session idle longer than 12 hours, or past its absolute end
    (Q-A1's expires_at), approves nothing (here ones the runtime role minted for ravi)."""
    import hashlib

    asha, ravi = people["asha"], people["ravi"]
    inv = await investigation(migrated_engine)
    case_id = await _open(api_engine, asha.actor(), [inv])
    request = await _request(api_engine, asha, case_id, 1)
    minted, ended = "minted-by-the-runtime-role", "minted-and-past-its-end"
    async with app_engine.begin() as conn:  # ARGUS's runtime login mints two sessions for ravi
        for token, seen, end in ((minted, "30 days", "1 hour"), (ended, "0 seconds", "-1 second")):
            await conn.execute(
                text(
                    "INSERT INTO user_sessions (token_hash, user_id, csrf_token, last_seen_at,"
                    " expires_at) VALUES (:t, :u, 'x', now() - CAST(:seen AS interval),"
                    " now() + CAST(:end AS interval))"
                ),
                {"t": hashlib.sha256(token.encode()).hexdigest(), "u": ravi.user_id,
                 "seen": seen, "end": end},
            )  # fmt: skip
    stored = (await rows(app_engine, "SELECT token_hash FROM user_sessions WHERE user_id = :u"
                         " AND ended_at IS NULL AND csrf_token <> 'x'",
                         u=ravi.user_id))[0].token_hash  # fmt: skip
    for token in (minted, ended, stored):  # idle; past its end; a live session's readable hash
        with pytest.raises(approvals.ApprovalError, match="no live session") as refused:
            async with api_engine.begin() as conn:
                await approvals.decide(conn, session_token=token, request_id=request,
                                       decision="approved",
                                       signed=await signed_for(conn, ravi, request))  # fmt: skip
        assert refused.value.status == 401
    assert await rows(api_engine, "SELECT 1 FROM approval_decisions") == []
    status, _ = await _decide(api_engine, ravi, request)  # ravi's own live session does
    assert status == "approved"


# ------------------------------------------------------------------ R13: terminal escapes


@pytest.mark.usefixtures("cli_env")
async def test_r13_case_list_and_show_never_print_raw_control_characters(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """A user name from the logs (an attacker picks it in a login attempt) becomes the case's
    actor and title; the operator's terminal then receives the raw escape sequences."""
    hostile = "\x1b]0;owned\x07\x1b[2Jroot"
    inv = await investigation(migrated_engine, rule="ssh", actor=(("user.name", hostile),))
    await _dossier(migrated_engine, inv, BEACON, ["77.221.155.150"])
    await _review(app_engine, people["asha"], inv)
    report = await opener.run(app_engine, window=WINDOW, classifier=CLASSIFIER, dry_run=False)
    assert report.applied == {"opened": 1}
    listed = await asyncio.to_thread(_run, "case", "list")
    shown = await asyncio.to_thread(_run, "case", "show", "1")
    dry = await asyncio.to_thread(_run, "case", "sync", "--dry-run")
    raw = [name for name, out in (("list", listed.output), ("show", shown.output),
                                  ("sync", dry.output)) if "\x1b" in out]  # fmt: skip
    assert raw == [], f"raw ESC printed by: {raw}; list line: {listed.output.strip()!r}"


# ------------------------------------------------------------------ R14: a skipped create


async def test_r14_a_case_whose_create_was_skipped_can_be_published_again(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """The writer skips the W1 create (e.g. Kibana answered 400: the title of R8); nothing is in
    Kibana. 'mirrored' is derived from ANY create row, so the case can never be published again
    and later changes keep planning W2 rows for a Kibana case that does not exist."""
    from argus.cases.machine import Publish

    asha, ravi = people["asha"], people["ravi"]
    inv = await investigation(migrated_engine)
    case_id = await _open(app_engine, _kib(asha), [inv])
    row = (await rows(app_engine, "SELECT id FROM kibana_outbox WHERE op = 'create'"))[0].id
    await _move(migrated_engine, row, "state = 'skipped'")
    taken = await _apply(app_engine, ravi.actor(), case_id, Take(), 1)
    try:
        await _apply(app_engine, _kib(asha), case_id, Publish(), 2)
        published = True
    except Exception as exc:
        published = getattr(exc, "message", str(exc))
    assert (len(taken.outbox_ids), published) == (0, True), (len(taken.outbox_ids), published)
    case, events = await _case(app_engine, case_id)  # its history still rebuilds it
    assert case is not None
    assert machine.same_case(machine.replay(events), case)


# ------------------------------------------------------------------ R15: big cases


async def test_r15_a_case_with_more_than_20000_alerts_can_still_be_closed(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    inv = await investigation(migrated_engine, alerts=1)
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO alert_records (alert_id, index, status, normalizer_version, raw,"
                " content_hash, state_hash, recovered_by, detected_at) SELECT 'big-' || g,"
                " 'alerts', 'normalized', 'test', '{}', 'h', 'h', 'live', now()"
                " FROM generate_series(1, 20000) g"
            )
        )
        await conn.execute(
            text(
                "INSERT INTO investigation_alerts (alert_id, investigation_id)"
                " SELECT 'big-' || g, :i FROM generate_series(1, 20000) g"
            ),
            {"i": inv},
        )
    case_id = await _open(api_engine, people["asha"].actor(), [inv])
    try:
        await _request(api_engine, people["asha"], case_id, 1)
    except approvals.ApprovalError as exc:
        pytest.fail(f"no closure is possible for this case: {exc.status} {exc.message}")


# ------------------------------------------------------------------ the fixes' other paths


async def test_r4b_verify_catches_an_approval_changed_or_written_around_its_function(
    api_engine: AsyncEngine, app_engine: AsyncEngine, migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    """F4: approval rows are not chained, but each one's audit row is; verify compares them."""
    asha, ravi, meera = people["asha"], people["ravi"], people["meera"]
    inv = await investigation(migrated_engine)
    case_id = await _open(api_engine, asha.actor(), [inv])
    request = await _request(api_engine, asha, case_id, 1, "risk_accepted", note="lab cluster")
    assert (await _decide(api_engine, ravi, request))[0] == "pending"
    audit = next(r for r in await chain.verify_snapshot(app_engine) if r.chain == "audit_events")
    assert audit.ok, audit.summary()
    for statement in (  # the owner rewrites who approved, with the append-only guard off
        "ALTER TABLE approval_decisions DISABLE TRIGGER approval_decisions_append_only_rows",
        "UPDATE approval_decisions SET approver_user_id = :meera",
        "ALTER TABLE approval_decisions ENABLE ALWAYS TRIGGER approval_decisions_append_only_rows",
        "INSERT INTO approval_decisions (request_id, approver_user_id, decision, capabilities)"
        " VALUES (:r, :asha, 'approved', '[\"approve\"]')",
    ):
        values = {"meera": meera.user_id, "r": request, "asha": asha.user_id}
        async with migrated_engine.begin() as conn:
            await conn.execute(
                text(statement), {k: v for k, v in values.items() if f":{k}" in statement}
            )
    audit = next(r for r in await chain.verify_snapshot(app_engine) if r.chain == "audit_events")
    assert [p.split(": ", 1)[1] for p in audit.problems] == [
        "approval decision 1 is not in the audit trail as it was made",
        "approval decision 2 is not in the audit trail as it was made",
    ]


async def test_r5b_a_persons_verdict_that_links_to_a_suspected_case_opens_it(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    host = (("source.ip", "10.201.7.13"),)
    proposed = await investigation(migrated_engine, rule="c2", actor=host)
    reviewed = await investigation(migrated_engine, rule="c2-b", actor=host, day=1)
    for inv in (proposed, reviewed):
        await _dossier(migrated_engine, inv, BEACON, ["77.221.155.150"])
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO assessments (investigation_id, version, pack, dossier_hash,"
                " view_hash, assessor, run_after, status, outcome) VALUES (:i, 1, 'p',"
                " repeat('a', 64), :v, 'agent@1', now(), 'proposed', 'true_positive')"
            ),
            {"i": proposed, "v": uuid.uuid4().hex * 2},
        )
    assert (await opener.run(app_engine, window=WINDOW, classifier=CLASSIFIER,
                             dry_run=False)).applied == {"suspected": 1}  # fmt: skip
    review = await _review(app_engine, people["asha"], reviewed)
    second = await opener.run(app_engine, window=WINDOW, classifier=CLASSIFIER, dry_run=False)
    assert second.applied == {"opened": 1}
    case = (await rows(app_engine, "SELECT id, state, kibana_wait, version FROM cases"))[0]
    assert (case.state, case.version) == ("open", 2)
    assert case.kibana_wait == "Waiting for someone who may open cases in Kibana"
    event = (await rows(app_engine, "SELECT kind, actor, details FROM case_events"
                        " WHERE case_version = 2"))[0]  # fmt: skip
    assert (event.kind, event.actor) == ("confirmed", "argus:opener")
    assert event.details["review"] == review
    assert event.details["verdict_by"] == f"user:{people['asha'].user_id}"
    members = await rows(app_engine, "SELECT investigation_id, link FROM case_members"
                         " ORDER BY added_version")  # fmt: skip
    assert [(m.investigation_id, m.link) for m in members] == [
        (proposed, "proposal"), (reviewed, "actor"),
    ]  # fmt: skip


async def test_r9b_a_closing_kind_of_event_must_close_the_case(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    inv = await investigation(migrated_engine)
    case_id = await _open(app_engine, people["asha"].actor(), [inv])
    for kind in ("closed", "dismissed", "merged_into", "reopened", "opened"):
        with pytest.raises(DBAPIError, match="kind_states"):
            await _forge(app_engine, case_id, kind)


async def _forge(app_engine: AsyncEngine, case_id: uuid.UUID, kind: str) -> None:
    """As the runtime role: a same-state change (open -> open) whose event names ``kind``."""
    async with app_engine.begin() as conn:
        await conn.execute(text("UPDATE cases SET version = 2 WHERE id = :c"), {"c": case_id})
        await conn.execute(
            text(
                "INSERT INTO case_events (case_id, case_version, kind, actor, from_state,"
                " to_state) VALUES (:c, 2, :k, 'argus:opener', 'open', 'open')"
            ),
            {"c": case_id, "k": kind},
        )


async def test_r14b_a_create_that_was_sent_before_it_was_skipped_still_counts(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """It may be in Kibana: the case is not published again (Q-D4 reconciles it)."""
    from argus.cases.machine import Publish

    asha = people["asha"]
    inv = await investigation(migrated_engine)
    case_id = await _open(app_engine, _kib(asha), [inv])
    row = (await rows(app_engine, "SELECT id FROM kibana_outbox WHERE op = 'create'"))[0].id
    for sets in ("state = 'approved'", "state = 'sending', sent_count = 1", "state = 'ambiguous'",
                 "state = 'skipped'"):  # fmt: skip
        await _move(migrated_engine, row, sets)
    with pytest.raises(machine.CaseRefused, match="Kibana has this case already"):
        await _apply(app_engine, _kib(asha), case_id, Publish(), 1)


async def test_r15b_a_large_case_binds_its_alert_set_and_closes(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    inv = await investigation(migrated_engine, alerts=1)
    async with migrated_engine.begin() as conn:
        for statement in (
            "INSERT INTO alert_records (alert_id, index, status, normalizer_version, raw,"
            " content_hash, state_hash, recovered_by, detected_at) SELECT 'big-' || g,"
            " 'alerts', 'normalized', 'test', '{}', 'h', 'h', 'live', now()"
            " FROM generate_series(1, 25000) g",
            "INSERT INTO investigation_alerts (alert_id, investigation_id)"
            " SELECT 'big-' || g, :i FROM generate_series(1, 25000) g",
        ):
            await conn.execute(text(statement), {"i": inv})
    case_id = await _open(api_engine, people["asha"].actor(), [inv])
    request = await _request(api_engine, people["asha"], case_id, 1)
    bound = (await rows(api_engine, "SELECT alert_count, alert_digest FROM approval_requests"))[0]
    ids = [f"{inv.hex}-0", *(f"big-{g}" for g in range(1, 25001))]
    assert (bound.alert_count, bound.alert_digest) == (25001, approvals.alert_digest(ids))
    status, applied = await _decide(api_engine, people["ravi"], request)
    assert (status, applied[0].case.state) == ("approved", "closed")
