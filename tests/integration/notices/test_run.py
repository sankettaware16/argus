"""The pass against Postgres and a real SMTP conversation (Q-H4): conditions in, mail out, the
table as the memory. Conditions are written by hand here so each rule is seen alone; the triggers
that find them in the database are tested in test_triggers.py, and the two together in
test_end_to_end.py. Time is passed in; the relay is ``tests/fakesmtp.py`` on the loopback."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases.model import Severity
from argus.db.engine import create_engine
from argus.notices import mail, model, render, run
from argus.notices.model import Condition, Kind, Target
from argus.notices.triggers import Found
from tests.fakesmtp import FakeSmtp
from tests.integration.notices.conftest import BASE, RECIPIENTS, SENDER, config_for

pytestmark = pytest.mark.integration

T0 = datetime(2026, 10, 26, 6, 0, tzinfo=UTC)
CASE = uuid.UUID("11111111-1111-4111-8111-111111111111")


def at(minutes: float = 0, hours: float = 0, days: float = 0) -> datetime:
    return T0 + timedelta(minutes=minutes, hours=hours, days=days)


def cond(
    kind: Kind = "case_active", subject: str = "s1", severity: Severity = "high",
    count: int = 2, since: datetime | None = None, case: uuid.UUID = CASE,
) -> Condition:  # fmt: skip
    target = Target("health") if kind == "outage" else Target("case", case)
    return Condition(kind, subject, severity, count, target, since)


async def go(
    engine: AsyncEngine, cfg: run.Config, conditions: Sequence[Condition], now: datetime,
    *, failed: set[Kind] | None = None, apply: bool = True,
) -> run.Report:  # fmt: skip
    return await run.run(
        engine, cfg, Found(list(conditions), failed or set()), now=now, apply=apply
    )


async def table(engine: AsyncEngine) -> list[Any]:
    async with engine.connect() as conn:
        found = await conn.execute(text("SELECT * FROM notices ORDER BY id"))
        return list(found)


async def audit(engine: AsyncEngine, action: str) -> list[Any]:
    async with engine.connect() as conn:
        found = await conn.execute(
            text("SELECT * FROM audit_events WHERE action = :a ORDER BY id"), {"a": action}
        )
        return list(found)


def subjects(server: FakeSmtp) -> list[str]:
    return [dict(m.headers)["Subject"] for m in server.received]


# --------------------------------------------------------------------------- off by default


async def test_off_stores_and_prints_but_sends_nothing(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    cfg = config_for(smtp, enabled=False)
    report = await go(app_engine, cfg, [cond(), cond("ioc_hit", "inv1")], T0)
    assert report.mode == "not_on"
    assert report.why_not == run.NOT_ON == "not switched on, by your choice"
    assert (report.conditions, report.inserted, report.due, report.sent) == (2, 2, 2, 0)
    assert len(report.lines) == 2
    assert all(line.startswith("would send: [ARGUS High]") for line in report.lines)
    assert smtp.connections == 0
    rows = await table(app_engine)
    assert [(r.kind, r.sent_at, r.notified) for r in rows] == [("case_active", None, 0),
                                                              ("ioc_hit", None, 0)]  # fmt: skip
    assert await audit(app_engine, "notice.sent") == []
    (ran,) = await audit(app_engine, "notice.run")
    assert ran.actor == "system"
    assert ran.details["mode"] == "not_on"
    again = await go(app_engine, cfg, [cond(), cond("ioc_hit", "inv1")], at(minutes=10))
    assert (again.inserted, again.updated, again.due) == (0, 2, 2)  # still due: nothing was told
    assert len(await table(app_engine)) == 2


@pytest.mark.parametrize(
    ("changes", "words"),
    [
        ({"recipients": ()}, "no recipient is named"),
        ({"relay": None}, "relay is incomplete"),
        ({"sender": None}, "relay is incomplete"),
    ],
)
async def test_on_without_a_recipient_or_a_relay_sends_nothing(
    app_engine: AsyncEngine, smtp: FakeSmtp, changes: dict[str, Any], words: str
) -> None:
    cfg = config_for(smtp, **changes)
    assert cfg.sends is False
    report = await go(app_engine, cfg, [cond()], T0)
    assert report.mode == "not_on"
    assert words in (report.why_not or "")
    assert smtp.connections == 0
    assert (await table(app_engine))[0].sent_at is None


async def test_what_was_stored_while_off_is_sent_once_it_is_switched_on(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    await go(app_engine, config_for(smtp, enabled=False), [cond()], T0)
    report = await go(app_engine, config_for(smtp), [cond()], at(hours=5))
    assert (report.mode, report.sent) == ("sent", 1)
    assert subjects(smtp) == ["[ARGUS High] A confirmed case is still active"]
    assert len(await table(app_engine)) == 1


async def test_a_dry_run_stores_sends_and_audits_nothing(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    report = await go(app_engine, config_for(smtp), [cond()], T0, apply=False)
    assert report.mode == "dry_run"
    assert report.lines
    assert await table(app_engine) == []
    assert smtp.connections == 0
    assert await audit(app_engine, "notice.run") == []


# --------------------------------------------------------------------------- the mail itself


async def test_the_message_is_exactly_a_link_a_severity_and_a_count(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    report = await go(app_engine, config_for(smtp), [cond(count=3)], T0)
    assert (report.sent, report.failed) == (1, 0)
    (got,) = smtp.received
    assert got.mail_from == SENDER
    assert got.rcpt_to == list(RECIPIENTS)
    expected = render.render(model.Intent("case_active", "new", "high", 3, Target("case", CASE),
                                          ("case_active", "s1"), T0), BASE)  # fmt: skip
    headers = dict(got.headers)
    assert headers["Subject"] == expected.subject == "[ARGUS High] A confirmed case is still active"
    assert headers["From"] == SENDER
    assert headers["To"] == "ta@example.org, ra@example.org"
    payload = got.message.get_payload(decode=True)
    assert isinstance(payload, bytes)
    body = payload.decode().replace("\r\n", "\n")
    assert body == expected.body
    assert f"{BASE}/go/case/{CASE}" in body
    assert "Severity: High" in body
    assert "Activity seen on 3 days" in body


async def test_nothing_from_the_data_gets_into_the_message_or_the_audit_trail(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    hostile = "ps1bot-lab-07.10.8.235.157"  # a subject key that looks like the data it stands for
    await go(app_engine, config_for(smtp), [cond("ioc_hit", hostile, "critical")], T0)
    (got,) = smtp.received
    wire = got.message.as_string()
    for value in ("ps1bot", "10.8.235.157", "lab-07"):
        assert value not in wire
        assert value not in repr(await audit(app_engine, "notice.sent"))
        assert value not in repr(await audit(app_engine, "notice.run"))


async def test_the_mail_goes_over_one_connection_for_the_whole_pass(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    await go(app_engine, config_for(smtp), [cond(subject=f"s{n}") for n in range(4)], T0)
    assert len(smtp.received) == 4
    assert smtp.connections == 1


# --------------------------------------------------------------------------- deduplication


async def test_a_second_pass_sends_nothing_and_a_restart_changes_nothing(
    app_engine: AsyncEngine, db_settings: Any, test_database: str, smtp: FakeSmtp
) -> None:
    cfg = config_for(smtp)
    first = await go(app_engine, cfg, [cond(), cond("closure_waiting", "c2")], T0)
    assert first.sent == 2
    fresh = create_engine(db_settings, database=test_database)  # the process restarted
    try:
        second = await go(fresh, cfg, [cond(), cond("closure_waiting", "c2")], at(minutes=10))
    finally:
        await fresh.dispose()
    assert (second.sent, second.due, second.updated, second.inserted) == (0, 0, 2, 0)
    assert len(smtp.received) == 2
    assert [r.notified for r in await table(app_engine)] == [1, 1]
    assert len(await audit(app_engine, "notice.sent")) == 2


async def test_a_higher_severity_is_told_once_and_a_lower_one_never(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    cfg = config_for(smtp)
    await go(app_engine, cfg, [cond(severity="medium")], T0)
    await go(app_engine, cfg, [cond(severity="medium")], at(minutes=10))
    assert len(smtp.received) == 1
    raised = await go(app_engine, cfg, [cond(severity="critical")], at(minutes=20))
    assert raised.sent == 1
    assert subjects(smtp)[-1] == "[ARGUS Critical] A confirmed case is still active"
    await go(app_engine, cfg, [cond(severity="high")], at(minutes=30))  # it fell back
    await go(app_engine, cfg, [cond(severity="critical")], at(minutes=40))  # and rose again
    assert len(smtp.received) == 2
    (row,) = await table(app_engine)
    assert (row.severity, row.sent_severity, row.notified) == ("critical", "critical", 2)


async def test_a_reminder_comes_at_most_once_a_day(app_engine: AsyncEngine, smtp: FakeSmtp) -> None:
    cfg = config_for(smtp)
    await go(app_engine, cfg, [cond()], T0)
    for minutes in (10, 60, 12 * 60, 24 * 60 - 1):
        await go(app_engine, cfg, [cond()], at(minutes=minutes))
    assert len(smtp.received) == 1
    await go(app_engine, cfg, [cond()], at(hours=24))
    assert subjects(smtp)[-1] == "[ARGUS High] Still waiting: A confirmed case is still active"
    await go(app_engine, cfg, [cond()], at(hours=30))
    await go(app_engine, cfg, [cond()], at(hours=47))
    assert len(smtp.received) == 2
    await go(app_engine, cfg, [cond()], at(hours=48))
    assert len(smtp.received) == 3


async def test_an_event_is_told_once_and_has_no_reminder(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    cfg = config_for(smtp)
    for day in range(4):
        await go(app_engine, cfg, [cond("ioc_hit", "inv1", "high")], at(days=day))
    assert len(smtp.received) == 1


async def test_what_is_resolved_and_comes_back_is_told_again(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    cfg = config_for(smtp)
    await go(app_engine, cfg, [cond()], T0)
    gone = await go(app_engine, cfg, [], at(hours=1))
    assert gone.resolved == 1
    assert (await table(app_engine))[0].resolved_at == at(hours=1)
    await go(app_engine, cfg, [cond()], at(hours=2))
    assert len(smtp.received) == 2
    rows = await table(app_engine)
    assert len(rows) == 2  # an occurrence a row
    assert [r.resolved_at is None for r in rows] == [False, True]


async def test_a_kind_that_could_not_be_read_is_not_resolved(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    cfg = config_for(smtp)
    await go(app_engine, cfg, [cond("ioc_hit", "inv1"), cond()], T0)
    report = await go(app_engine, cfg, [], at(minutes=10), failed={"ioc_hit"})
    assert report.unreadable == ["ioc_hit"]
    rows = {r.kind: r for r in await table(app_engine)}
    assert rows["ioc_hit"].resolved_at is None  # unknown is not "fine"
    assert rows["case_active"].resolved_at is not None


# --------------------------------------------------------------------------- outages


async def test_an_outage_is_told_after_an_hour_once_and_once_more_when_it_ends(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    cfg = config_for(smtp)
    outage = cond("outage", "siem", "high", count=0)
    first = await go(app_engine, cfg, [outage], T0)
    assert (first.inserted, first.sent) == (1, 0)  # only just begun: held
    await go(app_engine, cfg, [outage], at(minutes=59))
    assert smtp.received == []
    told = await go(app_engine, cfg, [outage], at(minutes=60))
    assert told.sent == 1
    assert subjects(smtp) == ["[ARGUS High] ARGUS cannot watch everything"]
    for later in (at(hours=2), at(hours=30), at(days=3)):
        await go(app_engine, cfg, [outage], later)
    assert len(smtp.received) == 1  # once per outage, no reminder, no matter how long
    ended = await go(app_engine, cfg, [], at(days=3, hours=1))
    assert ended.resolved == 1
    assert subjects(smtp)[-1] == "[ARGUS] The earlier outage is over"
    await go(app_engine, cfg, [], at(days=3, hours=2))
    assert len(smtp.received) == 2
    (row,) = await table(app_engine)
    assert row.ended_at == at(days=3, hours=1)
    payload = smtp.received[-1].message.get_payload(decode=True)
    assert isinstance(payload, bytes)
    assert "It lasted about 73 hours." in payload.decode()


async def test_an_outage_that_was_never_told_has_no_end_notice(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    cfg = config_for(smtp)
    outage = cond("outage", "siem", "high", count=0)
    await go(app_engine, cfg, [outage], T0)
    await go(app_engine, cfg, [], at(minutes=30))  # over before an hour
    assert smtp.received == []
    assert (await table(app_engine))[0].resolved_at is not None


async def test_an_outage_whose_start_is_known_is_told_at_once(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    await go(app_engine, config_for(smtp), [cond("outage", "siem", since=at(hours=-5))], T0)
    (got,) = smtp.received
    payload = got.message.get_payload(decode=True)
    assert isinstance(payload, bytes)
    assert "For about 5 hours so far." in payload.decode()


async def test_an_outage_that_ends_while_the_hour_has_no_room_is_told_later(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    cfg = config_for(smtp)
    outage = cond("outage", "siem", "high", count=0, since=at(hours=-3))
    await go(app_engine, cfg, [outage], T0)  # told (1 e-mail)
    crowd = [cond("case_active", f"c{n:02d}") for n in range(9)]
    await go(app_engine, cfg, [outage, *crowd], at(minutes=1))  # 9 more: the hour is full
    over = await go(app_engine, cfg, [*crowd], at(minutes=2))  # the outage ended
    assert (over.resolved, over.sent, over.deferred) == (1, 0, 1)
    assert [r.ended_at for r in await table(app_engine) if r.kind == "outage"] == [None]
    later = await go(app_engine, cfg, [*crowd], at(minutes=62))
    assert later.sent == 1
    assert subjects(smtp)[-1] == "[ARGUS] The earlier outage is over"


# --------------------------------------------------------------------------- the rate limit


async def test_more_than_ten_are_folded_into_one_n_more_notice(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    cfg = config_for(smtp)
    crowd = [cond("closure_waiting", f"c{n:02d}", "medium") for n in range(25)]
    report = await go(app_engine, cfg, crowd, T0)
    assert (report.due, report.sent, report.folded, report.deferred, report.failed) == (
        25, 9, 16, 0, 0,
    )  # fmt: skip
    assert len(smtp.received) == 10
    assert subjects(smtp)[-1] == "[ARGUS Medium] 16 more notices"
    rows = await table(app_engine)
    assert all(r.sent_at is not None and r.notified == 1 for r in rows)  # told one way or the other
    (folded,) = await audit(app_engine, "notice.folded")
    assert {k: v for k, v in folded.details.items() if k != "at"} == {
        "notices": 16,
        "recipients": 2,
        "severity": "medium",
    }
    assert len(await audit(app_engine, "notice.sent")) == 9
    again = await go(app_engine, cfg, crowd, at(minutes=10))
    assert (again.sent, again.due) == (0, 0)  # folded rows are told: nothing is sent twice


async def test_the_most_urgent_get_their_own_email_and_the_rest_are_folded(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    cfg = config_for(smtp)
    low = [cond("closure_waiting", f"c{n:02d}", "low") for n in range(12)]
    urgent = [cond("case_active", "hot", "critical")]
    await go(app_engine, cfg, [*low, *urgent], T0)
    assert subjects(smtp)[0] == "[ARGUS Critical] A confirmed case is still active"
    assert subjects(smtp)[-1] == "[ARGUS Low] 4 more notices"  # 13 due, 9 sent one by one


async def test_never_more_than_ten_emails_in_any_hour_and_nothing_is_lost(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    cfg = config_for(smtp)
    seen: list[Condition] = []
    for step in range(18):  # a pass every 10 minutes for three hours, 6 new things each time
        seen += [cond("closure_waiting", f"s{step:02d}{n}", "medium") for n in range(6)]
        await go(app_engine, cfg, seen, at(minutes=10 * step))
    async with app_engine.connect() as conn:
        stamps = [
            r.at
            for r in await conn.execute(
                text(
                    f"SELECT {run.WHEN} AS at FROM audit_events"  # noqa: S608
                    " WHERE action IN ('notice.sent', 'notice.folded') ORDER BY 1"
                )
            )
        ]
    assert len(stamps) == len(smtp.received)
    window = timedelta(hours=1)
    assert all(
        sum(1 for t in stamps if start <= t < start + window) <= model.MAX_PER_HOUR
        for start in stamps
    )  # in any hour of the pass clock, at most ten e-mails left
    assert len(stamps) > 10  # and mail did keep flowing as the hours went by
    rows = await table(app_engine)
    assert len(rows) == 108
    assert all(r.sent_at is not None for r in rows[: len(rows) - 6 * 5])  # the early ones are told


async def test_the_hours_count_comes_from_the_audit_trail_not_from_memory(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    cfg = config_for(smtp)
    await go(app_engine, cfg, [cond("closure_waiting", f"c{n:02d}") for n in range(10)], T0)
    assert len(smtp.received) == 10
    async with app_engine.connect() as conn:
        assert await run.sent_last_hour(conn, at(minutes=30)) == 10
        assert await run.sent_last_hour(conn, at(hours=2)) == 0


# --------------------------------------------------------------------------- the relay fails


async def test_a_relay_that_is_down_loses_nothing_and_the_next_pass_sends(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    down = config_for(smtp, relay=mail.Relay("127.0.0.1", 1, False, timeout=2))
    report = await go(app_engine, down, [cond(), cond("ioc_hit", "inv1")], T0)
    assert (report.sent, report.failed) == (0, 2)
    assert any("ConnectionRefusedError" in p for p in report.problems)
    rows = await table(app_engine)
    assert all(r.sent_at is None for r in rows)  # not marked: due again
    failures = await audit(app_engine, "notice.send_failed")
    assert len(failures) == 2
    assert {f.outcome for f in failures} == {"failure"}
    assert all("example.org" not in repr(f.details) for f in failures)  # no address in the trail
    assert await audit(app_engine, "notice.sent") == []
    up = await go(app_engine, config_for(smtp), [cond(), cond("ioc_hit", "inv1")], at(minutes=10))
    assert (up.sent, up.failed) == (2, 0)
    assert len(smtp.received) == 2


async def test_a_relay_that_refuses_the_data_marks_nothing(
    app_engine: AsyncEngine,
) -> None:
    with FakeSmtp(refuse_data=True) as server:
        report = await go(app_engine, config_for(server), [cond()], T0)
    assert (report.sent, report.failed) == (0, 1)
    assert (await table(app_engine))[0].sent_at is None


async def test_a_failed_n_more_notice_leaves_its_rows_unmarked(app_engine: AsyncEngine) -> None:
    crowd = [cond("closure_waiting", f"c{n:02d}", "medium") for n in range(12)]
    with FakeSmtp(refuse_data=True) as server:
        report = await go(app_engine, config_for(server), crowd, T0)
    assert (report.sent, report.folded, report.failed) == (0, 0, 10)
    assert all(r.sent_at is None for r in await table(app_engine))


# --------------------------------------------------------------------------- one pass at a time


async def test_a_pass_that_finds_another_running_does_nothing(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    async with app_engine.connect() as holder:
        holder = await holder.execution_options(isolation_level="AUTOCOMMIT")
        await holder.execute(text("SELECT pg_advisory_lock(:k)"), {"k": run.LOCK_KEY})
        try:
            report = await go(app_engine, config_for(smtp), [cond()], T0)
        finally:
            await holder.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": run.LOCK_KEY})
    assert report.busy
    assert report.problems == []  # not an error: the timer's run and a manual one may meet
    assert await table(app_engine) == []
    assert smtp.connections == 0


# --------------------------------------------------------------------------- the test message


async def test_the_test_message_goes_through_the_same_relay_and_is_audited(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    await run.send_test(app_engine, config_for(smtp), "me@example.org")
    (got,) = smtp.received
    assert got.rcpt_to == ["me@example.org"]
    headers = dict(got.headers)
    assert headers["Subject"] == "ARGUS test notice"
    assert headers["X-ARGUS"] == "test"
    payload = got.message.get_payload(decode=True)
    assert isinstance(payload, bytes)
    assert payload.decode().count("\n") == 1 or payload.decode().count("\r\n") == 1
    (event,) = await audit(app_engine, "notice.test")
    assert (event.actor, event.outcome) == ("system", "success")
    assert {k: v for k, v in event.details.items() if k != "at"} == {"ok": True, "error": None}
    assert "me@example.org" not in repr(event.details)
    assert await audit(app_engine, "notice.sent") == []  # a test is not one of the hour's notices


async def test_the_test_message_is_refused_while_notices_are_off_and_for_a_hostile_address(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    with pytest.raises(run.Refused, match="not switched on, by your choice"):
        await run.send_test(app_engine, config_for(smtp, enabled=False), "me@example.org")
    for hostile in ("me@example.org\r\nBcc: evil@example.org", "a@b.c, d@e.f", "x", ""):
        with pytest.raises(run.Refused, match="one plain e-mail address"):
            await run.send_test(app_engine, config_for(smtp), hostile)
    with pytest.raises(run.Refused, match="relay is incomplete"):
        await run.send_test(app_engine, config_for(smtp, relay=None), "me@example.org")
    assert smtp.connections == 0


async def test_a_failed_test_message_says_so_and_is_audited(app_engine: AsyncEngine) -> None:
    with FakeSmtp(refuse=["me@example.org"]) as server, pytest.raises(run.Refused) as refused:
        await run.send_test(app_engine, config_for(server), "me@example.org")
    assert "SMTPRecipientsRefused" in str(refused.value)
    (event,) = await audit(app_engine, "notice.test")
    assert event.outcome == "failure"


# --------------------------------------------------------------------------- the table


async def test_the_table_holds_one_live_row_a_subject_and_the_runtime_role_cannot_delete(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    await go(app_engine, config_for(smtp), [cond()], T0)
    async with migrated_engine.begin() as conn:
        with pytest.raises(DBAPIError):
            async with conn.begin_nested():
                await conn.execute(
                    text(
                        "INSERT INTO notices (kind, subject, severity, count, first_seen,"
                        " last_seen) VALUES ('case_active', 's1', 'low', 1, now(), now())"
                    )
                )
    async with app_engine.begin() as conn:
        with pytest.raises(DBAPIError, match="permission denied"):
            await conn.execute(text("DELETE FROM notices"))
    async with app_engine.begin() as conn:
        with pytest.raises(DBAPIError, match="permission denied"):
            await conn.execute(text("UPDATE notices SET kind = 'outage'"))


@pytest.mark.parametrize(
    "bad",
    [
        "kind = 'other'", "subject = 'has space'", "subject = ''", "severity = 'urgent'",
        "count = -1", "last_seen = first_seen - interval '1 second'",
        "sent_at = now()",  # sent without a severity and a count of notices
        "ended_at = now()",  # only an outage that was announced and is over has an end
        "resolved_at = first_seen - interval '1 day'",
    ],
)  # fmt: skip
async def test_the_table_refuses_a_row_that_makes_no_sense(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, smtp: FakeSmtp, bad: str
) -> None:
    await go(app_engine, config_for(smtp, enabled=False), [cond()], T0)
    async with migrated_engine.begin() as conn:
        with pytest.raises(DBAPIError):
            await conn.execute(text(f"UPDATE notices SET {bad}"))  # noqa: S608
