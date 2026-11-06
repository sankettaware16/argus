"""The independent reviewer's repros for Q-H4 (docs/gates/q-h4-review.md). Each test is named for
its finding (``test_r<N>_...``) and fails on the reviewed tree (850610e) for the reason the review
gives. Loopback only: a relay is ``tests/fakesmtp.py`` or the small rogue relay below; nothing
here contacts the SIEM or any real host."""

from __future__ import annotations

import contextlib
import socketserver
import threading
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assets.classify import IpClassifier
from argus.cases import approvals
from argus.cases.model import Severity
from argus.notices import mail, model, run, triggers
from argus.notices.model import Condition, Kind, Target
from argus.notices.triggers import Found
from tests.fakesmtp import FakeSmtp
from tests.integration.cases.conftest import Person
from tests.integration.cases.watchkit import C2, H1, World, at, context
from tests.integration.notices.conftest import config_for

pytestmark = pytest.mark.integration

T0 = datetime(2026, 10, 26, 6, 0, tzinfo=UTC)
CASE = uuid.UUID("11111111-1111-4111-8111-111111111111")


def cond(
    kind: Kind = "case_active", subject: str = "s1", severity: Severity = "high",
    count: int = 2, since: datetime | None = None,
) -> Condition:  # fmt: skip
    target = Target("health") if kind == "outage" else Target("case", CASE)
    return Condition(kind, subject, severity, count, target, since)


async def go(
    engine: AsyncEngine, cfg: run.Config, conditions: Sequence[Condition], now: datetime,
    *, deliver: Any = mail.send,
) -> run.Report:  # fmt: skip
    return await run.run(engine, cfg, Found(list(conditions), set()), now=now, deliver=deliver)


class Rogue:
    """A relay that takes a message and then drops the connection without the final 250 (the
    client cannot know whether the message was accepted)."""

    def __init__(self) -> None:
        self.messages: list[bytes] = []
        owner = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                self.wfile.write(b"220 rogue ESMTP\r\n")
                while True:
                    line = self.rfile.readline()
                    if not line:
                        return
                    verb = line.split(b" ", 1)[0].strip().upper()
                    if verb in (b"EHLO", b"HELO"):
                        self.wfile.write(b"250 rogue\r\n")
                    elif verb in (b"MAIL", b"RCPT", b"RSET"):
                        self.wfile.write(b"250 ok\r\n")
                    elif verb == b"DATA":
                        self.wfile.write(b"354 go\r\n")
                        self.wfile.flush()
                        body = b""
                        while True:
                            part = self.rfile.readline()
                            if part in (b".\r\n", b""):
                                break
                            body += part
                        owner.messages.append(body)
                        return  # accepted, and the connection drops before "250 queued"
                    elif verb == b"QUIT":
                        self.wfile.write(b"221 bye\r\n")
                        return
                    else:
                        self.wfile.write(b"500 what\r\n")
                    self.wfile.flush()

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.server = Server(("127.0.0.1", 0), Handler)
        self.host, self.port = "127.0.0.1", self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> Rogue:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()


# --------------------------------------------------------------------------- duplicates


async def test_r2_a_unit_killed_mid_batch_resends_the_whole_batch_at_every_pass(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    """A slow relay (a few seconds a recipient, 20 recipients, 10 messages) outlasts the unit's
    ``TimeoutStartSec=10min``: systemd kills the pass after the relay took some messages and
    before any was marked or audited. Next pass (10 minutes later) the same messages go again,
    and so on: the hour's count (read from the audit trail) never sees them. The fix: each message
    is marked and audited as soon as the relay takes it (``on_result``), so the next pass skips
    the five and the hour's room counts them. (The fake door passes ``on_result`` on, as
    ``mail.send`` does.)"""
    cfg = config_for(smtp)
    conditions = [cond("case_active", f"c{n:02d}") for n in range(12)]

    async def killed_after_five(
        relay: mail.Relay, sender: str, recipients: Sequence[str],
        messages: Sequence[Any], on_result: Any = None,
    ) -> list[mail.Delivery]:  # fmt: skip
        # the relay took five (and the door reported each as it went); the rest never ran
        await mail.send(relay, sender, recipients, list(messages)[:5], on_result=on_result)
        raise SystemExit("killed by systemd after TimeoutStartSec")

    for index in range(6):  # one hour of passes, ten minutes apart
        with contextlib.suppress(SystemExit):  # once the hour's room is used there is no send
            await go(app_engine, cfg, conditions, T0 + timedelta(minutes=10 * index),
                     deliver=killed_after_five)  # fmt: skip
    assert len(smtp.received) <= model.MAX_PER_HOUR, (
        f"{len(smtp.received)} e-mails reached the recipients in one hour"
    )
    async with app_engine.connect() as conn:  # and what the relay took was recorded as it went
        assert await run.sent_last_hour(conn, T0 + timedelta(minutes=55)) == len(smtp.received)


async def test_r7_a_message_the_relay_took_but_did_not_acknowledge_is_bounded_by_the_hours_ten(
    app_engine: AsyncEngine,
) -> None:
    """The relay accepts the message and the connection drops (or the final reply times out)
    before ``250``. The notice is not marked, so it goes again at the next pass: that two-generals
    duplicate cannot be removed, but nothing counted it, so it repeated at every pass for as long
    as the relay did this. The lead's decision: a ``notice.send_failed`` counts in the hour's 10,
    so the same notice reaches the relay at most 10 times an hour (12 passes, 5 minutes apart,
    here; the repro asked for at most once, which no retry can promise)."""
    with Rogue() as rogue:
        cfg = config_for(FakeSmtp(), relay=mail.Relay(rogue.host, rogue.port, False, timeout=5))
        for index in range(12):
            await go(app_engine, cfg, [cond()], T0 + timedelta(minutes=5 * index))
        assert len(rogue.messages) <= model.MAX_PER_HOUR, (
            f"the same notice reached the relay {len(rogue.messages)} times in an hour"
        )


# --------------------------------------------------------------------------- the clock


async def test_r9_a_pass_whose_clock_is_behind_the_last_one_does_not_crash(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    """``last_seen >= first_seen`` and ``ended_at >= resolved_at`` are database constraints; a
    clock set back (an NTP step, a restored VM, a second machine) makes the pass's UPDATE fail
    and the pass raises: nothing is stored, sent or audited until the clock catches up."""
    cfg = config_for(smtp, enabled=False)
    await go(app_engine, cfg, [cond()], T0 + timedelta(hours=2))
    await go(app_engine, cfg, [cond()], T0)  # the clock went back two hours


async def test_r9_a_clock_that_ran_ahead_once_stops_every_pass_until_real_time_catches_up(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    """One pass read a clock a day ahead (a wrong guess of the VM, a second machine): its rows
    have ``first_seen`` and ``details.at`` in the future, so the pass after it, on the right
    clock, raises on ``last_seen >= first_seen`` for a day, and the future audit rows would
    also count as "the last hour" and hold back every e-mail for a day."""
    cfg = config_for(smtp)
    many = [cond("case_active", f"c{n:02d}") for n in range(12)]
    await go(app_engine, cfg, many, T0 + timedelta(days=1))
    await go(app_engine, cfg, many, T0 + timedelta(hours=3))


# --------------------------------------------------------------------------- kind 1


async def test_r3_activity_on_the_verdict_day_after_the_verdict_is_not_news_until_a_day_later(
    world: World, people: dict[str, Person]
) -> None:
    """The watch writes the verdict day's row ``active`` with ``detail.last``, the newest alert
    that day. An alert AFTER the verdict is proof of activity, but ``_ACTIVE`` skips the whole
    verdict day, so the watch's flag at 03:00 the next morning produces no notice."""
    ctx = context(None)
    inv = await world.investigation(H1, [at(0, 8)])
    await world.open_case(people["asha"], [inv], [H1], at(0, 8, 30))  # the verdict
    await world.add_alert(inv, at(0, 12))  # the host beacons again four hours after the verdict
    await world.run(ctx, at(1, 3))  # the daily watch flags day 0 as active
    async with world.owner.connect() as conn:
        row = (
            await conn.execute(
                text("SELECT outcome, detail FROM case_watch_checks WHERE source = 'alerts'")
            )
        ).one()
    assert row.outcome == "active"
    assert row.detail["last"].startswith("2026-10-14T12:00")  # after the verdict (08:30)
    found = await triggers.compute(
        world.runtime, at(1, 3, 10), classifier=IpClassifier(None), watch_mode="local"
    )
    assert [c.kind for c in found.conditions] == ["case_active"]


# --------------------------------------------------------------------------- kind 4


async def test_r5_a_campus_hit_is_missed_when_200_newer_listed_investigations_come_first(
    world: World, app_engine: AsyncEngine
) -> None:
    """``_IOC`` takes the newest 200 investigations with a non-empty ``ti.listed`` BEFORE the
    confidence and campus tests run in Python; inbound scanners from listed outside addresses
    fill the 200 and a campus host's high-confidence hit older than they are is never read."""
    from tests.integration.notices.test_triggers import dossier_body, put_dossier

    now = datetime.now(UTC)
    campus = await world.investigation("10.201.7.13", [now - timedelta(hours=5)])
    await put_dossier(world.owner, campus, dossier_body([C2], {C2: "high"}))
    for n in range(201):  # newer, listed, but from outside addresses (scanners)
        scanner = await world.investigation(
            f"8.8.{n // 250}.{n % 250 + 1}", [now - timedelta(hours=1)]
        )
        await put_dossier(world.owner, scanner, dossier_body([C2], {C2: "high"}))
    async with app_engine.connect() as conn:
        found = await triggers.ioc_hit(conn, now, IpClassifier(None))
    assert [c.subject for c in found] == [str(campus)]


# --------------------------------------------------------------------------- kind 5


async def test_r10_a_watch_that_was_just_switched_on_is_not_an_outage_after_one_hour(
    world: World, smtp: FakeSmtp
) -> None:
    """The watch is "late" after 36 hours (doctor's threshold, ``watch.RUN_LATE``). With no
    ``watch.run`` row at all the condition has no ``since`` and counts from the first pass that
    sees it, so one hour after ``cases.watch: local`` is set the people are told ARGUS "cannot
    watch everything" although the first daily run is hours away."""
    cfg = config_for(smtp)
    for minutes in (0, 70):
        found = await triggers.compute(
            world.runtime, T0 + timedelta(minutes=minutes), classifier=IpClassifier(None),
            watch_mode="local",
        )  # fmt: skip
        await run.run(world.runtime, cfg, found, now=T0 + timedelta(minutes=minutes))
    assert smtp.received == []


# --------------------------------------------------------------------------- kind 3


def test_r4_a_request_made_in_the_evening_is_noticed_at_some_point_of_its_life() -> None:
    """A closure request lives to the end of the next write window (15 to 39 hours); the rule
    "waiting over 24 hours" never holds for one made between 17:30 and 02:30 UTC. Whatever the
    threshold is, every request should be noticed before it expires."""
    base = datetime(2026, 10, 26, 0, 0, tzinfo=UTC)
    never = []
    for half_hours in range(48):
        asked = base + timedelta(minutes=30 * half_hours)
        expires = approvals.expires_at(asked)
        steps = int((expires - asked).total_seconds() // 600)
        seen = any(
            triggers.waiting_condition(CASE, asked, expires, asked + timedelta(minutes=10 * n))
            for n in range(steps)
        )
        if not seen:
            never.append(asked.time().isoformat("minutes"))
    assert never == [], f"requests made at these UTC times are never noticed: {never}"


# --------------------------------------------------------------------------- wording


async def test_r11_the_end_of_one_outage_does_not_say_everything_is_fine_while_another_lasts(
    app_engine: AsyncEngine, smtp: FakeSmtp
) -> None:
    cfg = config_for(smtp)
    both = [cond("outage", "siem", since=T0 - timedelta(hours=3)),
            cond("outage", "kibana", since=T0 - timedelta(hours=3))]  # fmt: skip
    await go(app_engine, cfg, both, T0)
    assert len(smtp.received) == 2
    await go(
        app_engine, cfg, [both[0]], T0 + timedelta(minutes=10)
    )  # kibana is back, the SIEM is not
    ended = smtp.received[-1]
    payload = ended.message.get_payload(decode=True)
    assert isinstance(payload, bytes)
    assert "can watch everything again" not in payload.decode()


# --------------------------------------------------------------------------- odd rows


@pytest.mark.parametrize(
    "ti",
    [
        {"listed": "10.1.1.1"},
        {"listed": 5},
        {"listed": {"a": 1}},
        {"listed": None},
        {"listed": [1, None, ["x"], {"y": 1}], "answers": "none"},
        {"listed": [C2], "answers": {"value": C2}},
        {"listed": [C2], "answers": [{"value": C2, "sources": [1, 2]}]},
        {"listed": [C2], "answers": [{"value": C2, "sources": {"s": {"match": "high"}}}]},
        {
            "listed": [C2],
            "answers": [{"value": C2, "sources": {"s": {"match": [{"confidence": {"a": [1]}}]}}}],
        },
    ],
)
async def test_r6_no_shape_of_threat_intel_in_a_dossier_stops_the_trigger(
    world: World, app_engine: AsyncEngine, ti: dict[str, Any]
) -> None:
    """A dossier is JSON; whatever its ``ti`` holds, ``ioc_hit`` reads it (no exception). Fails for
    a ``listed`` that is not an array: ``jsonb_array_length`` runs on it in the WHERE clause (the
    ``jsonb_typeof`` guard beside it is not evaluated first), the whole trigger raises, and kind 4
    is unreadable for the day that dossier stays in the window."""
    import json

    from tests.integration.notices.test_triggers import put_dossier

    now = datetime.now(UTC)
    odd = await world.investigation(H1, [now - timedelta(hours=1)])
    body = {"context": {"pack": {"ti": ti}}}
    await put_dossier(world.owner, odd, json.loads(json.dumps(body, allow_nan=False, default=str)))
    async with app_engine.connect() as conn:
        await triggers.ioc_hit(conn, now, IpClassifier(None))


# --------------------------------------------------------------------------- the fixes, further


async def test_r5_the_scan_goes_on_page_by_page_and_a_flood_is_held_never_cut(
    world: World, app_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Five campus hits are read with pages of two (every page in turn, newest first); a window
    larger than the scan limit raises, so the kind is held (``Found.failed``), not resolved."""
    from tests.integration.notices.test_triggers import dossier_body, put_dossier

    now = datetime.now(UTC)
    wanted = []
    for n in range(5):
        inv = await world.investigation(f"10.8.235.{n + 1}", [now - timedelta(minutes=10 * n + 5)])
        await put_dossier(world.owner, inv, dossier_body([C2], {C2: "high"}))
        wanted.append(str(inv))
    monkeypatch.setattr(triggers, "IOC_PAGE", 2)
    async with app_engine.connect() as conn:
        found = await triggers.ioc_hit(conn, now, IpClassifier(None))
    assert sorted(c.subject for c in found) == sorted(wanted)
    monkeypatch.setattr(triggers, "IOC_SCAN_LIMIT", 4)
    result = await triggers.compute(app_engine, now, classifier=IpClassifier(None))
    assert "ioc_hit" in result.failed
    assert [c for c in result.conditions if c.kind == "ioc_hit"] == []


async def test_r7_a_message_never_tried_does_not_count_in_the_hour(
    app_engine: AsyncEngine,
) -> None:
    """A dead connection fails the message in flight (counted: the relay may have taken it) and
    leaves the others unsent (not counted: they never reached the relay)."""
    crowd = [cond("closure_waiting", f"c{n}", "medium") for n in range(3)]
    with FakeSmtp(drop_after=1) as server:
        report = await go(app_engine, config_for(server), crowd, T0)
    assert (report.sent, report.failed) == (1, 2)
    async with app_engine.connect() as conn:
        assert await run.sent_last_hour(conn, T0 + timedelta(minutes=1)) == 2


async def test_r10_a_watch_never_run_is_an_outage_after_thirty_six_hours_not_before(
    world: World, smtp: FakeSmtp
) -> None:
    cfg = config_for(smtp)
    for hours, expected in ((0, 0), (35, 0), (36, 1)):
        now = T0 + timedelta(hours=hours)
        found = await triggers.compute(
            world.runtime, now, classifier=IpClassifier(None), watch_mode="local"
        )
        await run.run(world.runtime, cfg, found, now=now)
        assert len(smtp.received) == expected, hours


async def test_r9_the_dates_of_a_row_never_go_back(app_engine: AsyncEngine) -> None:
    """A resolve and an outage's end on a clock behind the row's dates keep the constraints."""
    cfg = config_for(FakeSmtp(), enabled=False)
    await go(app_engine, cfg, [cond("outage", "siem")], T0 + timedelta(hours=2))
    await go(app_engine, cfg, [], T0)  # resolved by a clock two hours behind its first sight
    async with app_engine.connect() as conn:
        row = (await conn.execute(text("SELECT first_seen, resolved_at FROM notices"))).one()
    assert row.resolved_at >= row.first_seen


async def test_r3_a_second_alert_on_the_verdict_day_before_the_verdict_is_no_news(
    world: World, people: dict[str, Person]
) -> None:
    """The other side of R3: an alert before the verdict moment (the alerts that made the case)
    is not activity since it."""
    ctx = context(None)
    inv = await world.investigation(H1, [at(0, 8)])
    await world.open_case(people["asha"], [inv], [H1], at(0, 10))
    await world.run(ctx, at(1, 3))
    found = await triggers.compute(
        world.runtime, at(1, 3, 10), classifier=IpClassifier(None), watch_mode="local"
    )
    assert [c for c in found.conditions if c.kind == "case_active"] == []
