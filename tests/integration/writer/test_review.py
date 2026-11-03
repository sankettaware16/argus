"""Q-D4's review (R1-R12) through the database and the writer. Each test is the review's repro,
adapted; each failed on the code the review attacked."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import identity
from argus.cases.machine import Link, Release, Take
from argus.cases.model import Member
from argus.config.settings import KibanaSettings, KibanaWriterSettings, Settings, WebSettings
from argus.gateway.kibana import writes
from argus.writer import cli, ramp
from tests.integration.cases.conftest import APPROVER, Person, investigation
from tests.integration.cases.test_service import _apply, _kibana_actor
from tests.integration.writer.fake import Fault, patches, posts
from tests.integration.writer.kit import (
    approve_resend,
    created,
    many_alerts,
    mirrored_case,
    rig,
)
from tests.integration.writer.test_unknown import _doubt_at, _lookups

pytestmark = pytest.mark.integration


# --------------------------------------------------------------------------- R1


async def test_r1_a_severity_a_person_lowered_before_the_next_poll_is_not_overwritten(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id, kid = await created(r, people)
    r.kibana.cases[kid]["severity"] = "low"  # a person; the read-back has not polled yet
    fresh = await investigation(migrated_engine, alerts=1, actor=(("source.ip", "10.9.9.9"),))
    await _apply(
        app_engine, _kibana_actor(people["ravi"]), case_id,
        Link((Member(fresh, "person"),), severity="critical"),
    )  # fmt: skip

    report = await r.run("W2", limit=5)

    assert r.kibana.cases[kid]["severity"] == "low", report.lines()
    assert report.mismatches == 0
    states = [s for _, op, s in await r.outbox(case_id) if op != "create"]
    assert "paused" not in states
    assert "conflict" not in states


async def test_r1_a_tag_of_arguss_kind_a_person_added_is_not_replaced_by_a_take(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id, kid = await created(r, people)
    r.kibana.cases[kid]["tags"].append("argus:owner:bob")  # a person's, before the next poll
    await _apply(app_engine, people["ravi"].actor(), case_id, Take(), 1)

    report = await r.run("W2", limit=5)

    assert "argus:owner:bob" in r.kibana.cases[kid]["tags"], report.lines()
    assert r.kibana.count("PATCH") == 0  # nothing was sent: the poll will pause the case
    assert any("a person changed ARGUS's tags" in held for held in report.held)
    assert report.mismatches == 0


async def test_r1_arguss_own_writes_before_a_poll_are_not_mistaken_for_a_persons(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    """Take then release, with no poll between: the second change finds the tags the first one
    set, which no mirror and no before-image has seen."""
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id, kid = await created(r, people)
    await _apply(app_engine, people["ravi"].actor(), case_id, Take(), 1)
    await _apply(app_engine, people["ravi"].actor(), case_id, Release(), 2)

    report = await r.run("W2", limit=5)

    assert report.stopped is None, report.lines()
    assert "argus:state:open" in r.kibana.cases[kid]["tags"]
    assert [s for _, _, s in await r.outbox(case_id)] == ["verified"] * 5


# --------------------------------------------------------------------------- R2, R6, R11


class Spy:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int, str]] = []

    async def run_class(self, write_class: str, *, limit: int, kind: str, by: str) -> Any:
        self.calls.append((write_class, limit, kind))

        class Report:
            def lines(self) -> list[str]:
                return []

        return Report()


def scheduled_settings() -> Settings:
    return Settings(
        kibana=KibanaSettings(
            enabled=True, write_classes=("W1",), cases_writer_api_key=SecretStr("k" * 20),
            cases_writer_api_key_expires=datetime.now(UTC).date() + timedelta(days=20),
            writer=KibanaWriterSettings(scheduled=("W1",)),
        ),
        web=WebSettings(public_url="https://127.0.0.1:8765"),
    )  # fmt: skip


async def run_row(
    owner: AsyncEngine, write_class: str = "W1", *, kind: str = "canary", step: int = 1,
    units: int = 1, sent: int = 3, verified: int = 3, mismatches: int = 0, ambiguous: int = 0,
    stopped: str | None = None, ago: timedelta = timedelta(hours=1),
) -> None:  # fmt: skip
    started = datetime.now(UTC) - ago
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO kibana_writer_runs (write_class, kind, step, started_at,"
                " finished_at, units, sent, verified, mismatches, ambiguous, stopped, \"by\")"
                " VALUES (:c, :k, :s, :t0, :t1, :u, :n, :v, :m, :a, :st, 'test')"
            ),
            {"c": write_class, "k": kind, "s": step, "t0": started,
             "t1": started + timedelta(minutes=1), "u": units, "n": sent, "v": verified,
             "m": mismatches, "a": ambiguous, "st": stopped},
        )  # fmt: skip


async def set_step(owner: AsyncEngine, write_class: str, step: int) -> None:
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO kibana_writer_ramp (write_class, step, since, changed_by)"
                " VALUES (:c, :s, now() - interval '3 days', 'x')"
                " ON CONFLICT (write_class) DO UPDATE SET step = :s,"
                " since = now() - interval '3 days'"
            ),
            {"c": write_class, "s": step},
        )


async def test_r2_the_service_is_never_a_classes_first_writer(
    migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    settings, spy = scheduled_settings(), Spy()

    await cli._scheduled(settings, spy, writer_engine, "W1")  # type: ignore[arg-type]
    assert spy.calls == []  # no canary run was ever recorded

    await run_row(migrated_engine, kind="canary", sent=0, verified=0)  # a canary that sent nothing
    await run_row(migrated_engine, kind="canary", stopped="refused after sending")
    await cli._scheduled(settings, spy, writer_engine, "W1")  # type: ignore[arg-type]
    assert spy.calls == []

    await run_row(migrated_engine, kind="canary")  # a clean one, but the class is at step 1
    await cli._scheduled(settings, spy, writer_engine, "W1")  # type: ignore[arg-type]
    assert spy.calls == []

    await set_step(migrated_engine, "W1", 5)  # a person raised it
    await cli._scheduled(settings, spy, writer_engine, "W1")  # type: ignore[arg-type]
    assert spy.calls == [("W1", 5, "scheduled")]


async def test_r2_plan_says_why_the_service_would_not_run_a_class(
    migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    lines = await cli.plan_lines(writer_engine, scheduled_settings(), "W1")
    assert any("the service would not run it" in line and "canary" in line for line in lines)


async def test_r6_runs_that_sent_nothing_are_no_evidence_for_the_order_or_the_ramp(
    migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    for day in range(3):  # three days of passes that sent nothing
        await run_row(migrated_engine, kind="scheduled", sent=0, verified=0,
                      ago=timedelta(days=day, hours=1))  # fmt: skip
    async with writer_engine.connect() as conn:
        order = await ramp.first_use_problem(conn, "W2")
        seen = await ramp.evidence(conn, "W1", datetime.now(UTC))
    assert order is not None, "W2 may begin although W1 never wrote anything"
    assert (seen.runs, seen.days) == (0, 0)
    assert not seen.ready


async def test_r6_a_stopped_or_unread_run_does_not_count_and_blocks_the_step(
    migrated_engine: AsyncEngine, writer_engine: AsyncEngine
) -> None:
    for day in range(3):
        await run_row(migrated_engine, kind="ramp", ago=timedelta(days=day, hours=1))
    async with writer_engine.connect() as conn:
        assert (await ramp.evidence(conn, "W1", datetime.now(UTC))).ready
    await run_row(migrated_engine, kind="ramp", stopped="W1 waits: case_gap")
    await run_row(migrated_engine, kind="ramp", sent=2, verified=1)
    async with writer_engine.connect() as conn:
        seen = await ramp.evidence(conn, "W1", datetime.now(UTC))
        order = await ramp.first_use_problem(conn, "W2")
    assert seen.runs == 3  # the two do not count
    assert not seen.clean
    assert not seen.ready
    assert order is None  # W1 has clean runs with writes


async def test_r6_a_scheduled_pass_outside_the_window_reads_nothing_for_a_write_it_cannot_make(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    await mirrored_case(app_engine, migrated_engine, people["asha"], _kibana_actor(people["asha"]))
    r.advance(((20 - r.clock.now.hour) % 24) * 3600)  # 20:xx UTC: after the window (02:30-17:30)
    await r.run("W1", limit=1, kind="scheduled")  # the key's start-up self-test is made once
    before = len(r.kibana.requests)

    report = await r.run("W1", limit=1, kind="scheduled")

    assert len(r.kibana.requests) == before, "a pass read Kibana for a write the window refuses"
    assert report.stopped == "outside the write window"
    assert not r.kibana.writes
    runs = await r.sql("SELECT count(*) AS n FROM kibana_writer_runs")
    assert runs[0].n == 0  # an idle pass leaves no run behind


async def test_r11_the_step_waits_for_findings_a_paused_class_and_writes_in_doubt(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    for day in range(3):
        await run_row(migrated_engine, kind="ramp", ago=timedelta(days=day, hours=1))

    async def seen() -> ramp.Evidence:
        async with writer_engine.connect() as conn:
            return await ramp.evidence(conn, "W1", datetime.now(UTC))

    assert (await seen()).ready

    async with migrated_engine.begin() as conn:  # a case that landed twice, waiting for a person
        await conn.execute(
            text(
                "INSERT INTO kibana_findings (found_at, kind, severity, dedupe_key)"
                " VALUES (now(), 'duplicate_case', 'attention', 'dup-1')"
            )
        )
    waiting = await seen()
    assert not waiting.ready
    assert waiting.unresolved == 1
    assert any("wait for a person" in why for why in waiting.why_not)
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE kibana_findings SET resolved_at = now(), resolved_by = 'a'")
        )
    assert (await seen()).ready

    lane = writes.pause(writes.KibanaLaneState(), writes.WriteClass.W1, "answer_mismatch")
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE siem_state SET state = CAST(:s AS jsonb) WHERE name = 'kibana'"),
            {"s": json.dumps(writes.to_json(lane))},
        )
    paused = await seen()
    assert not paused.ready
    assert paused.paused == "answer_mismatch"
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE siem_state SET state = '{}'::jsonb WHERE name = 'kibana'"))
    assert (await seen()).ready

    case_id = await mirrored_case(
        app_engine, migrated_engine, people["asha"], _kibana_actor(people["asha"])
    )
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("UPDATE kibana_outbox SET state = 'paused' WHERE case_id = :c"), {"c": case_id}
        )
    stuck = await seen()
    assert not stuck.ready
    assert stuck.in_doubt == 1


# --------------------------------------------------------------------------- R3, R4, R5


async def test_r3_a_create_whose_answer_cannot_be_read_is_looked_for_and_adopted(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await mirrored_case(
        app_engine, migrated_engine, people["asha"], _kibana_actor(people["asha"])
    )
    r.kibana.faults.append(Fault(posts("/cases"), "garbage"))  # a 200 that is not JSON

    report = await r.run("W1", limit=1)

    assert (report.sent, report.ambiguous) == (1, 1), report.lines()
    assert await r.outbox(case_id) == [("W1", "create", "ambiguous")]
    findings = await r.sql("SELECT kind FROM kibana_findings")
    assert [f.kind for f in findings] == ["answer_unexpected"]  # a person is told as well
    assert "W1" in (await r.lane.kibana_lane()).paused  # the lane paused the class
    base = await _doubt_at(r)
    await _lookups(r, base, 121)

    rows = await r.sql(
        "SELECT state, kibana_case_id FROM kibana_outbox WHERE case_id = :c", c=case_id
    )
    [case] = r.kibana.ours()
    assert (rows[0].state, rows[0].kibana_case_id) == ("verified", case["id"])
    assert r.kibana.count("POST", "/api/cases") == 1  # never sent again


async def test_r3_a_change_whose_answer_cannot_be_read_is_looked_for_and_found(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id, kid = await created(r, people)
    await _apply(app_engine, people["ravi"].actor(), case_id, Take(), 1)
    r.kibana.faults.append(Fault(patches(), "garbage"))

    report = await r.run("W2", limit=1)

    assert report.ambiguous == 1, report.lines()
    assert [s for _, op, s in await r.outbox(case_id) if op == "update"] == ["ambiguous"]
    assert r.kibana.cases[kid]["status"] == "in-progress"  # it landed
    base = await _doubt_at(r)
    await _lookups(r, base, 121)
    assert [s for _, op, s in await r.outbox(case_id) if op == "update"] == ["verified"]
    assert r.kibana.count("PATCH") == 1


async def test_r4_a_kibana_outage_does_not_crash_the_lookups_or_a_run(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await mirrored_case(
        app_engine, migrated_engine, people["asha"], _kibana_actor(people["asha"])
    )
    r.kibana.faults.append(Fault(posts("/cases"), "timeout", land_after=None))  # never lands
    await r.run("W1", limit=1)
    r.advance(3 * 60)  # the first look is due
    r.kibana.down = True

    await r.writer.run_lookups()  # raised before the fix
    await r.run("W1", limit=1)

    due = await r.sql("SELECT done_at, due_at FROM kibana_lookups ORDER BY attempt")
    assert due[0].done_at is None  # the look was postponed, not made and not counted
    assert due[0].due_at > r.clock.now
    r.kibana.down = False
    r.advance(3 * 60)
    await r.writer.run_lookups()
    assert (await r.sql("SELECT outcome FROM kibana_lookups ORDER BY attempt"))[
        0
    ].outcome == "not_found"
    assert await r.outbox(case_id) == [("W1", "create", "ambiguous")]


async def test_r5_a_connection_refused_before_anything_was_sent_is_a_write_in_doubt(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    case_id = await mirrored_case(
        app_engine, migrated_engine, people["asha"], _kibana_actor(people["asha"])
    )
    r.kibana.faults.append(Fault(posts("/cases"), "lose"))  # nothing reached Kibana

    report = await r.run("W1", limit=1)

    row = (
        await r.sql("SELECT state, state_reason FROM kibana_outbox WHERE case_id = :c", c=case_id)
    )[0]
    assert row.state == "ambiguous"  # not "paused (None)": it is looked for like any other
    assert "(None)" not in (row.state_reason or "")
    assert "no connection" in row.state_reason
    assert "could not be reached" in (report.stopped or "")
    assert await r.sql("SELECT 1 FROM kibana_lookups")
    assert (await r.run("W1", limit=1)).sent == 0  # and it is not sent again on its own
    assert not r.kibana.ours()

    base = await _doubt_at(r)
    for seconds in (121, 301, 901, 1801):  # the four looks find nothing: a person decides
        await _lookups(r, base, seconds)
    reason = (await r.sql("SELECT state_reason FROM kibana_outbox"))[0].state_reason
    assert reason.startswith("resend?")


# --------------------------------------------------------------------------- R7


async def test_r7_sync_alerts_switched_on_while_a_run_waits_between_attaches_is_seen(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, app_engine, writer_engine)
    await set_step(migrated_engine, "W1", 5)  # a person raised W1 (more than five alerts)
    await many_alerts(app_engine, migrated_engine, _kibana_actor(people["asha"]),
                      investigations=6, alerts=2)  # fmt: skip
    flipped: list[int] = []
    real_sleep = r.writer.sleep

    async def sleep(seconds: float) -> None:
        if seconds >= 60 and not flipped:
            for case in r.kibana.cases.values():
                case["settings"] = {"syncAlerts": True}  # a person, while ARGUS waits
            flipped.append(r.kibana.count("POST"))
        await real_sleep(seconds)

    r.writer.sleep = sleep
    report = await r.run("W1", limit=1)

    assert flipped, "no alert-gap wait happened"
    assert r.kibana.count("POST") == flipped[0], report.lines()  # nothing sent after the flip
    findings = await r.sql("SELECT kind FROM kibana_findings")
    assert "settings_changed" in [f.kind for f in findings]  # and a person is told


# --------------------------------------------------------------------------- R8


async def test_r8_the_writers_login_cannot_change_what_the_send_time_checks_rely_on(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    await mirrored_case(app_engine, migrated_engine, people["asha"], _kibana_actor(people["asha"]))
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO users (username, display_name, disabled, password_hash)"
                " VALUES ('mallory', 'Mallory', true, 'x')"
            )
        )
    forbidden = {
        "re-enable a revoked account": "UPDATE users SET disabled = false",
        "grant capabilities": "UPDATE users SET capabilities = '{approve}'",
        "set a session's step-up": "UPDATE user_sessions SET stepped_up_at = now()",
        "read the sessions": "SELECT token_hash FROM user_sessions",
        "clear a mirror pause": "UPDATE kibana_mirror SET paused_reason = NULL",
        "move a case": "UPDATE cases SET state = 'closed'",
        "extend an approval": "UPDATE approval_requests SET expires_at = now() + interval '1 year'",
        "decide an approval": "INSERT INTO approval_decisions (request_id) VALUES (1)",
        "record an identity check": "INSERT INTO identity_checks (user_id) VALUES (1)",
        "write an audit event as someone else": "UPDATE audit_events SET actor = 'x'",
        "delete findings": "DELETE FROM kibana_findings",
        "resolve a finding": "UPDATE kibana_findings SET resolved_at = now()",
        "create a case": "INSERT INTO case_events (case_id) VALUES (gen_random_uuid())",
        "raise the lane's switches": "UPDATE siem_switches SET stopped = false",
        "change the payload of an outbox row": "UPDATE kibana_outbox SET payload = '{}'",
        "insert an outbox row": "INSERT INTO kibana_outbox (case_id) VALUES (gen_random_uuid())",
        "delete a step": "DELETE FROM kibana_steps",
        "decide an approval through its function": "SELECT argus_approval_decide('x', 1,"
        " 'approved', 'x', now(), '{}'::jsonb, 'x', '{}'::jsonb)",
        "record an identity check through its function": "SELECT argus_identity_record(1, 'ok',"
        " 'x', 'x', '{}'::jsonb)",
        "ask for an approval as a person": "SELECT argus_approval_request('x', gen_random_uuid(),"
        " 1, 'closure', 'x', NULL, NULL, '{}'::jsonb, 'x', 'x', now(), 'x', '{}'::jsonb)",
    }  # fmt: skip
    allowed = []
    for what, statement in forbidden.items():
        try:
            async with writer_engine.begin() as conn:
                await conn.execute(text(statement))
        except DBAPIError as exc:
            refused = str(exc.orig).splitlines()[0]
            assert "permission denied" in refused, (what, refused)
        else:
            allowed.append(what)
    assert not allowed, f"the writer's login can: {allowed}"


async def test_r8_the_writers_login_belongs_to_its_group_alone(
    writer_engine: AsyncEngine,
) -> None:
    from argus.db import roles

    async with writer_engine.connect() as conn:
        member_of = (
            (
                await conn.execute(
                    text(
                        "SELECT rolname FROM pg_roles"
                        " WHERE pg_has_role(current_user, oid, 'MEMBER')"
                        " AND rolname <> current_user ORDER BY 1"
                    )
                )
            )
            .scalars()
            .all()
        )
    assert member_of == [roles.WRITER_ROLE]
    assert await roles.writer_role_problems(writer_engine) == []


# --------------------------------------------------------------------------- R9


async def test_r9_an_approver_who_turns_out_to_be_the_requester_cannot_resend(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    r = rig(migrated_engine, api_engine, writer_engine)
    await mirrored_case(api_engine, migrated_engine, people["asha"], _kibana_actor(people["asha"]))
    r.kibana.faults.append(Fault(posts("/cases"), "timeout", land_after=None))
    await r.run("W1", limit=1)
    base = await _doubt_at(r)
    for seconds in (121, 301, 901, 1801):
        await _lookups(r, base, seconds)
    row_id = (await r.sql("SELECT id FROM kibana_outbox"))[0].id
    await approve_resend(r, api_engine, people, row_id)
    snapshot = (await r.sql("SELECT identity_check FROM approval_decisions"))[0].identity_check
    # the requester signs in again: her check now carries the approver's argus_uid and e-mail
    async with api_engine.begin() as conn:
        await identity.record(
            conn,
            identity.LiveCheck(
                people["asha"].user_id, "ok", snapshot.get("provider", "fake"),
                await identity.database_clock(conn), "person", APPROVER,
                frozenset({"createCase", "createComment", "updateCase"}),
                snapshot.get("argus_uid") or "uid-ravi",
                snapshot.get("email") or "ravi@example.org",
            ),
            "signin",
        )  # fmt: skip
    r.advance(80 * 60)

    report = await r.run("W1", limit=1)

    assert r.kibana.attempts("POST", "/api/cases") == 1, "resent on one person's word"
    assert any("the person who asked" in held for held in report.held), report.held
