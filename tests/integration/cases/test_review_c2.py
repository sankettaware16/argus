"""Q-C2 independent review: reproductions. Each test fails on the tree it was written against
(72efcfc) for the reason its name and docstring give; the number is the finding's number in
docs/gates/q-c2-review.md. Nothing here reaches the SIEM."""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.cases import proposer, watch, watchrun
from argus.config import DatabaseSettings
from tests.integration.cases.conftest import Person
from tests.integration.cases.watchkit import (
    C2,
    D0,
    H1,
    H2,
    FakeAsker,
    World,
    at,
    context,
)
from tests.integration.test_cli_db import _run, cli_env  # noqa: F401 - the fixture

pytestmark = pytest.mark.integration


def day(n: int) -> date:
    return D0 + timedelta(days=n)


@pytest.fixture
def world(migrated_engine: AsyncEngine, app_engine: AsyncEngine) -> World:
    return World(migrated_engine, app_engine)


async def requests_recorded(world: World, case_id: uuid.UUID) -> int:
    async with world.owner.connect() as conn:
        return int(
            (
                await conn.execute(
                    text(
                        "SELECT coalesce(sum(requests), 0) FROM case_watch_checks"
                        " WHERE case_id = :c"
                    ),
                    {"c": case_id},
                )
            ).scalar_one()
        )


# --------------------------------------------------------------------------------- R1


class Blocking(FakeAsker):
    """An asker that holds the run inside its first question until released."""

    def __init__(self) -> None:
        super().__init__()
        self.inside = asyncio.Event()
        self.release = asyncio.Event()

    async def ask(self, task):  # type: ignore[no-untyped-def]
        self.inside.set()
        await self.release.wait()
        return await super().ask(task)


async def test_r1_the_runs_lock_connection_is_not_left_idle_in_a_transaction(
    world: World, people: dict[str, Person]
) -> None:
    """``run`` takes its session advisory lock on a connection that autobegins a transaction and
    keeps it open for the whole run. The engine sets idle_in_transaction_session_timeout = 60 s
    (db/engine.py), so a run that waits 60 s inside one question (the lane's budget wait is up
    to 60 s each) loses its lock when the server ends the session, and a second run goes ahead
    beside it; the unlock then raises. (Observed once with a 65 s wait: 0 advisory locks held,
    a second run reported no problem, and the first raised IdleInTransactionSessionTimeout.)"""
    asker = Blocking()
    ctx = context(asker)
    i1 = await world.investigation(H1, [at(0, 9)])
    await world.open_case(people["asha"], [i1], [H1], at(0, 10))
    task = asyncio.create_task(world.run(ctx, at(3, 3)))
    await asyncio.wait_for(asker.inside.wait(), 20)
    async with world.owner.connect() as conn:
        idle = (
            await conn.execute(
                text(
                    "SELECT pid FROM pg_stat_activity WHERE datname = current_database()"
                    " AND state = 'idle in transaction'"
                )
            )
        ).all()
    asker.release.set()
    await task
    assert not idle


# --------------------------------------------------------------------------------- R2/R3/R4


async def test_r2_alerts_of_another_cases_member_on_this_cases_c2_are_activity(
    world: World, people: dict[str, Person]
) -> None:
    """``_CANDIDATES`` leaves out every investigation that is a member of any case, so once case
    B holds H2's investigation, H2's alerts on case A's C2 are nobody's activity: A is verified
    quiet for the three days H2 keeps alerting on the C2."""
    asha = people["asha"]
    asker = FakeAsker()
    ctx = context(asker)
    i1 = await world.investigation(H1, [at(0, 9)])
    case_a = await world.open_case(asha, [i1], [H1], at(0, 10))
    i2 = await world.investigation(H2, [at(0, 11)])  # reaches the same C2
    await world.open_case(asha, [i2], [H2], at(0, 12), c2=None)  # case B holds it
    for n in (1, 2, 3, 4):
        await world.run(ctx, at(n, 3))
    for n in (5, 6, 7):
        await world.add_alert(i2, at(n, 9))
    for n in (5, 6, 7, 8):
        await world.run(ctx, at(n, 3))
    window = await world.finder_window(ctx, case_a, at(8, 4))
    assert not window.verified, window.reason


async def test_r3_alerts_that_came_after_a_benign_review_are_activity(
    world: World, people: dict[str, Person]
) -> None:
    """``_CANDIDATES`` drops an investigation a person reviewed as benign whatever the version
    they reviewed (the proposer compares ``s.version = i.version``). New alerts that raise the
    investigation's version after the review are hidden: A is verified quiet while they arrive."""
    asha = people["asha"]
    asker = FakeAsker()
    ctx = context(asker)
    i1 = await world.investigation(H1, [at(0, 9)])
    case_a = await world.open_case(asha, [i1], [H1], at(0, 10))
    y = await world.investigation(H2, [at(0, 11)])  # reaches the C2; a person calls it benign
    async with world.owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO review_events (investigation_id, version, alert_count, user_id,"
                " action, outcome, kibana_ok) VALUES (:i, 1, 1, :u, 'reviewed',"
                " 'benign_expected', true)"
            ),
            {"i": y, "u": asha.user_id},
        )
    for n in (1, 2, 3, 4):
        await world.run(ctx, at(n, 3))
    for n in (5, 6, 7):
        await world.add_alert(y, at(n, 9))
    async with world.owner.begin() as conn:  # grouping bumps the version on a new alert
        await conn.execute(text("UPDATE investigations SET version = 2 WHERE id = :i"), {"i": y})
    for n in (5, 6, 7, 8):
        await world.run(ctx, at(n, 3))
    window = await world.finder_window(ctx, case_a, at(8, 4))
    assert not window.verified, window.reason


async def test_r4_a_busy_actor_host_is_not_quiet_because_it_is_too_common(
    world: World, people: dict[str, Person]
) -> None:
    """``scan`` removes every key found in 50 or more investigations from the search
    (``own -= shared.common``), the case's own actor host included: 55 new investigations of the
    host on three days leave a host-only case (no log check to refuse it) verified quiet."""
    asha = people["asha"]
    asker = FakeAsker()
    ctx = context(asker)
    i1 = await world.investigation(H1, [at(0, 9)], entities=())
    case_a = await world.open_case(asha, [i1], [H1], at(0, 10), c2=None)
    for n in (1, 2, 3, 4):
        await world.run(ctx, at(n, 3))
    for k in range(55):
        await world.investigation(H1, [at(5 + k % 3, 9, k)], entities=(), rule=f"scan-{k}")
    for n in (5, 6, 7, 8):
        await world.run(ctx, at(n, 3))
    window = await world.finder_window(ctx, case_a, at(8, 4))
    assert not window.verified, window.reason


# --------------------------------------------------------------------------------- R6/R7


class PairFails(FakeAsker):
    """The real gateway answers ``failed`` with ``sent=True`` when a search left and broke."""

    def __init__(self) -> None:
        super().__init__()
        self.sent = 0
        self.flaked = False
        self.flake_first_day = False

    async def ask(self, task):  # type: ignore[no-untyped-def]
        from argus.context import beacon

        params = task.params
        if isinstance(params, beacon.PairParams):
            self.asked.append(("proxy.pair", params.start.date(), params.destination))
            self.sent += 1
            return watchrun.Answer(self.now, refused="failed", sent=True)
        if (
            self.flake_first_day
            and not self.flaked
            and isinstance(params, beacon.ContactParams)
            and params.start.date() == day(1)
        ):
            self.flaked = True
            self.sent += 1
            self.asked.append(("proxy.contact", day(1), params.destination))
            return watchrun.Answer(self.now, refused="failed", sent=True)
        answer = await super().ask(task)
        self.sent += int(answer.sent)
        return answer


async def test_r6_a_pair_search_that_left_and_failed_is_counted(
    world: World, people: dict[str, Person]
) -> None:
    """``_describe`` returns without a row when the pair search failed after it was sent."""
    asker = PairFails()
    ctx = context(asker, pair=True)
    asker.beacon([1, 2], [H1])
    i1 = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(people["asha"], [i1], [H1], at(0, 10))
    await world.run(ctx, at(3, 3))
    assert await requests_recorded(world, case_id) == asker.sent


async def test_r6_six_requests_a_case_a_day_hold_when_a_pair_search_fails(
    world: World, people: dict[str, Person]
) -> None:
    """The uncounted pair search leaves room for one more question on a same-day rerun: 7 sent."""
    asker = PairFails()
    asker.flake_first_day = True
    ctx = context(asker, pair=True)
    asker.beacon([1, 2, 3, 4, 5], [H1])
    i1 = await world.investigation(H1, [at(0, 9)])
    await world.open_case(people["asha"], [i1], [H1], at(0, 10))
    await world.run(ctx, at(6, 3))
    await world.run(ctx, at(6, 4))  # the same UTC day
    assert asker.sent <= watch.cap_for(1)  # one address: the least a case may ask in a day


async def test_r7_the_cap_counts_questions_and_the_lanes_ledger_counts_every_attempt(
    world: World, people: dict[str, Person]
) -> None:
    """The gateway retries a 502/503 once. Decision R7 (the lead's): the cap of 6 a case a day
    counts the questions the watch asks, not the HTTP attempts under them; the lane's ledger has
    one row a question with its attempts counted, and the lane's own limits charge every attempt.
    (The review expected the cap to count attempts; the test now pins what was decided.)"""
    from argus.gateway.transport import WireResponse
    from tests.integration.cases.test_watch_lane import Lane400, ProxyTransport

    lane = Lane400(world)

    class Flaky503(ProxyTransport):
        async def send(self, request):  # type: ignore[no-untyped-def]
            if "_resolve" not in request.path and len(self.searches) % 2 == 0:
                self.searches.append({"path": request.path, "at": self.clock.now, "took": 0})
                return WireResponse(503, b"{}", 1.0)
            return await super().send(request)

    flaky = Flaky503(lane.clock)
    lane.gateway.transport = flaky
    i1 = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(people["asha"], [i1], [H1], at(0, 10))
    await lane.run(at(8, 3))
    questions = await requests_recorded(world, case_id)
    ledger = [e for e in lane.store.ledger if e.template == "proxy.contact"]
    assert questions == watch.cap_for(1)  # seven finished days, six questions
    assert len(ledger) == questions  # a row a question ...
    assert sum(e.attempts for e in ledger) == len(flaky.searches) > questions  # ... all attempts


# --------------------------------------------------------------------------------- R8


async def test_r8_the_verdict_does_not_claim_the_proxy_logs_when_none_was_read(
    world: World, people: dict[str, Person]
) -> None:
    """A case with no checkable destination (host only; a domain C2 is the same) is verified on
    ARGUS's alerts alone, and the reason a person reads must not say it read the logs."""
    asker = FakeAsker()
    ctx = context(asker)
    i1 = await world.investigation(H1, [at(0, 9)], entities=())
    case_id = await world.open_case(people["asha"], [i1], [H1], at(0, 10), c2=None)
    for n in range(1, 8):
        await world.run(ctx, at(n, 3))
    window = await world.finder_window(ctx, case_id, at(7, 4))
    assert asker.asked == []
    assert window.verified
    assert "alerts only: no address of this case can be checked in the proxy logs" in window.reason
    assert "01:40" not in window.reason  # (the review expected no mention of the logs at all; the
    # lead's wording names them to say they were not read)


async def test_r8_the_verdict_says_what_it_did_not_read(
    world: World, people: dict[str, Person]
) -> None:
    """The logs of each day are read 01:40-22:59 UTC and today's not at all; the reason says
    only "3 whole days"."""
    asker = FakeAsker()
    ctx = context(asker)
    i1 = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(people["asha"], [i1], [H1], at(0, 10))
    for n in range(1, 8):
        await world.run(ctx, at(n, 3))
    window = await world.finder_window(ctx, case_id, at(7, 4))
    assert window.verified
    assert "22:59" in window.reason or "seam" in window.reason or "nightly" in window.reason


# --------------------------------------------------------------------------------- R11


async def test_r11_the_database_holds_the_cap_per_row_and_the_runner_per_case_and_day(
    world: World, app_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    """Decision R11 (the lead's): words only. ``requests BETWEEN 0 AND 20`` (the most a case may
    ask in a day, ``watch.MAX_REQUESTS_A_DAY``) holds one row; the sum for one case and day is the
    runner's to hold (``watch.cap_for``, ``spent_today``; the month simulation and the same-day
    reruns pin it). Three rows of 20 on one day for one case are accepted by the database, and
    the gate report says so. (The review expected a database rule.)"""
    i1 = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(people["asha"], [i1], [H1], at(0, 10))
    insert = (
        "INSERT INTO case_watch_checks (case_id, day, source, subject, part, outcome, reason,"
        " window_start, window_end, asked_at, asked_on, requests, attempts, detail) VALUES (:c,"
        " :d, 'proxy.contact', :s, 0, 'quiet', NULL, :ws, :we, NULL, :on, :n, 1, '{}')"
    )

    async def rows(count: int, n: int) -> None:
        async with app_engine.begin() as conn:
            for k in range(count):
                await conn.execute(
                    text(insert),
                    {"c": case_id, "d": day(1), "s": f"198.51.100.{k + 1}", "ws": at(1, 1, 40),
                     "we": at(1, 22, 59), "on": day(2), "n": n},
                )  # fmt: skip

    with pytest.raises(DBAPIError):
        await rows(1, 21)  # one row over 20 is the database's rule
    await rows(3, 20)  # the sum per case and day is not
    assert await requests_recorded(world, case_id) == 60


# --------------------------------------------------------------------------------- R12


class BadBody(FakeAsker):
    """Answers the first destination with a body the reader cannot parse."""

    def __init__(self, bad: str) -> None:
        super().__init__()
        self.bad = bad

    async def ask(self, task):  # type: ignore[no-untyped-def]
        if task.params.destination == self.bad:
            self.asked.append(("proxy.contact", task.params.start.date(), self.bad))
            aggs = {"requests": {"value": 1}, "hosts": {"buckets": 5}}
            body = {"timed_out": False, "_shards": {"failed": 0}, "aggregations": aggs}
            return watchrun.Answer(self.now, body=body, sent=True)
        return await super().ask(task)


async def test_r12_one_cases_unexpected_error_does_not_stop_the_watch_of_the_others(
    world: World, people: dict[str, Person]
) -> None:
    """``_run`` isolates a case only for DBAPIError and CaseRefused: any other exception aborts
    the run, so every later case (and the audit row) is skipped, every day, for as long as the
    input stays the same."""
    asker = BadBody("198.51.100.9")
    ctx = context(asker)
    one = await world.investigation(H1, [at(0, 9)], entities=(("ip", "198.51.100.9"),))
    await world.open_case(people["asha"], [one], [H1], at(0, 10), c2="198.51.100.9")
    two = await world.investigation(H2, [at(0, 9)], entities=(("ip", C2),))
    second = await world.open_case(people["ravi"], [two], [H2], at(0, 10, 5))
    raised: Exception | None = None
    try:
        await world.run(ctx, at(3, 3))
    except Exception as exc:
        raised = exc
    assert raised is None, repr(raised)
    assert any(key[1] == watch.ALERTS for key in await world.rows(second))


# --------------------------------------------------------------------------------- R13


def test_r13_dismissing_a_suggestion_is_audited(
    cli_env: Path,  # noqa: F811
    migrated_engine: AsyncEngine,
    app_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    async def plant() -> int:
        world = World(migrated_engine, app_engine)
        first = await world.investigation(H1, [at(0, 9)])
        case_id = await world.open_case(people["asha"], [first], [H1], at(0, 10))
        second = await world.investigation(H2, [at(1, 8)])
        async with migrated_engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO case_suggestions (investigation_id, case_id, link, kind, why)"
                    " VALUES (:i, :c, 'c2', 'shared', 'a content-delivery address')"
                ),
                {"i": second, "c": case_id},
            )
            return int((await conn.execute(text("SELECT count(*) FROM audit_events"))).scalar_one())

    async def audits() -> int:
        async with migrated_engine.connect() as conn:
            return int((await conn.execute(text("SELECT count(*) FROM audit_events"))).scalar_one())

    before = asyncio.run(plant())
    assert _run("case", "suggestions", "--dismiss", "1", "--as", "asha").exit_code == 0
    assert asyncio.run(audits()) > before


# --------------------------------------------------------------------------------- R14


async def test_r14_member_alerts_after_containment_are_seen_after_a_long_gap(
    world: World, people: dict[str, Person]
) -> None:
    """``alerts_check`` visits only the last 7 finished days (BACKLOG_DAYS): an alert of a
    member investigation on the day after containment is never looked at when the watch ran
    again 11 days later, and the case stays contained."""
    asha = people["asha"]
    asker = FakeAsker()
    ctx = context(asker)
    i1 = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(asha, [i1], [H1], at(0, 10))
    for n in (1, 2, 3, 4, 5):
        await world.run(ctx, at(n, 3))
    contained = await world.contain(ctx, asha, case_id, at(5, 4))
    assert contained.case.state == "contained"
    await world.add_alert(i1, at(5, 12))  # a member's alert, after the containment
    await world.run(ctx, at(16, 3))  # the watch was down from D5 to D16
    assert (await world.case(case_id)).state == "open"


# --------------------------------------------------------------------------------- R15


async def test_r15_a_case_contained_a_moment_ago_is_not_proposed_for_closure_at_once(
    world: World, people: dict[str, Person]
) -> None:
    """The proposer asks the same finder: the window that allowed the containment (days before
    it) still verifies a moment later, so ARGUS proposes ``remediated_verified`` (one approver)
    with nothing observed after the containment."""
    asha = people["asha"]
    asker = FakeAsker()
    ctx = context(asker)
    i1 = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(asha, [i1], [H1], at(0, 10))
    for n in (1, 2, 3, 4, 5):
        await world.run(ctx, at(n, 3))
    await world.contain(ctx, asha, case_id, at(5, 4))
    async with world.runtime.begin() as conn:
        finder = watchrun.Finder(conn, ctx, lambda: at(5, 5))
        found = await proposer.candidates(conn, windows=finder)
    assert [c.case_id for c in found] == []


# --------------------------------------------------------------------------------- R10


def test_r10_a_missing_shared_list_is_an_error_line_not_a_traceback(
    cli_env: Path,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``load_shared`` reads ``config/shared_infrastructure.yaml`` relative to the working
    directory and raises ConfigError; ``case backfill`` (and ``_go``: contain, status,
    approvals propose) do not catch it, so it ends as a Python traceback."""
    monkeypatch.setenv("ARGUS_CONFIG", str(cli_env))
    monkeypatch.setenv("ARGUS_DATABASE__PASSWORD", "x")
    monkeypatch.chdir(tmp_path)
    result = _run("case", "backfill")
    assert result.exception is None or isinstance(result.exception, SystemExit), repr(
        result.exception
    )


# ============================================================================ the fixer's tests
# Findings with no repro of their own, and the cases the repros do not reach (numbers as above).


async def advisory_sessions(world: World) -> list[str]:
    """The state of every session holding an advisory lock in this database."""
    async with world.owner.connect() as conn:
        found = await conn.execute(
            text(
                "SELECT a.state FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid"
                " WHERE l.locktype = 'advisory' AND l.granted AND l.database ="
                " (SELECT oid FROM pg_database WHERE datname = current_database())"
            )
        )
        return [str(state) for state in found.scalars()]


async def test_r1_the_lock_is_held_for_the_whole_run_by_an_idle_session_and_let_go(
    world: World, people: dict[str, Person]
) -> None:
    """The lock sits in a session that is idle (not in a transaction), so the engine's 60 s
    limit cannot end it, while a second run is refused; afterwards nobody holds it."""
    asker = Blocking()
    ctx = context(asker)
    i1 = await world.investigation(H1, [at(0, 9)])
    await world.open_case(people["asha"], [i1], [H1], at(0, 10))
    task = asyncio.create_task(world.run(ctx, at(3, 3)))
    await asyncio.wait_for(asker.inside.wait(), 20)
    assert await advisory_sessions(world) == ["idle"]
    refused = await watchrun.run(world.runtime, context(None), now=at(3, 3))
    assert refused.problems == ["another run of the watch is in progress: nothing was done"]
    asker.release.set()
    assert (await task).problems == []
    assert await advisory_sessions(world) == []


async def test_r1_a_lost_lock_connection_does_not_fail_a_finished_run(
    world: World, people: dict[str, Person]
) -> None:
    """The unlock is best effort: when the lock's session is gone (the server ended it) the run
    is still finished, its report returned and its audit row written."""
    asker = Blocking()
    ctx = context(asker)
    i1 = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(people["asha"], [i1], [H1], at(0, 10))
    task = asyncio.create_task(world.run(ctx, at(3, 3)))
    await asyncio.wait_for(asker.inside.wait(), 20)
    async with world.owner.connect() as conn:
        await conn.execute(
            text(
                "SELECT pg_terminate_backend(l.pid) FROM pg_locks l WHERE l.locktype ="
                " 'advisory' AND l.granted AND l.database ="
                " (SELECT oid FROM pg_database WHERE datname = current_database())"
            )
        )
    asker.release.set()
    report = await task  # does not raise
    assert report.problems == []
    assert any(key[1] == watch.ALERTS for key in await world.rows(case_id))
    async with world.owner.connect() as conn:
        audited = (
            await conn.execute(text("SELECT count(*) FROM audit_events WHERE action = 'watch.run'"))
        ).scalar_one()
    assert audited == 1
    assert (await world.run(context(None), at(3, 4))).problems == []  # and the next run goes on


async def test_r2_an_investigation_in_another_case_is_activity_but_never_joined(
    world: World, people: dict[str, Person]
) -> None:
    """Activity is a separate question from joining: B's member alerting on A's C2 keeps A from
    being quiet, and still belongs to B alone."""
    asha = people["asha"]
    ctx = context(FakeAsker())
    i1 = await world.investigation(H1, [at(0, 9)])
    case_a = await world.open_case(asha, [i1], [H1], at(0, 10))
    i2 = await world.investigation(H2, [at(0, 11)])
    case_b = await world.open_case(asha, [i2], [H2], at(0, 12), c2=None)
    for n in (1, 2, 3, 4):
        await world.run(ctx, at(n, 3))
    await world.add_alert(i2, at(4, 9))
    report = await world.run(ctx, at(5, 3))
    assert await world.members(case_a) == {i1}
    assert await world.members(case_b) == {i2}
    assert (await world.rows(case_a))[(day(4), watch.ALERTS, "", 0)] == "active"
    number = (await world.case(case_a)).number
    assert report.case(number).joined == 0
    assert (await world.finder_window(ctx, case_a, at(5, 4))).verified is False


async def test_r2_a_contained_case_reopens_when_another_cases_member_alerts_on_its_c2(
    world: World, people: dict[str, Person]
) -> None:
    asha = people["asha"]
    ctx = context(FakeAsker())
    i1 = await world.investigation(H1, [at(0, 9)])
    case_a = await world.open_case(asha, [i1], [H1], at(0, 10))
    i2 = await world.investigation(H2, [at(0, 11)])
    await world.open_case(asha, [i2], [H2], at(0, 12), c2=None)
    for n in (1, 2, 3, 4, 5):
        await world.run(ctx, at(n, 3))
    assert (await world.contain(ctx, asha, case_a, at(5, 4))).case.state == "contained"
    await world.add_alert(i2, at(5, 12))
    await world.run(ctx, at(6, 3))
    assert (await world.case(case_a)).state == "open"


POPULAR = "198.51.100.77"


async def crowd(world: World, key: str, count: int, when: datetime) -> None:
    for n in range(1, count + 1):
        await world.investigation(f"10.77.0.{n}", [when], entities=(("ip", key),))


async def test_r4_a_c2_in_very_many_investigations_is_cannot_tell_too_common(
    world: World, people: dict[str, Person]
) -> None:
    """Any key but the case's own actors found in 50 investigations makes the window "cannot
    tell: too common" (the alerts rows are unverified, with the reason), never verified, and
    nothing is joined or suggested through it."""
    ctx = context(FakeAsker())
    first = await world.investigation(H1, [at(0, 9)], entities=(("ip", POPULAR),))
    case_id = await world.open_case(people["asha"], [first], [H1], at(0, 10), c2=POPULAR)
    await crowd(world, POPULAR, 50, at(1, 7))
    for n in (2, 3, 4, 5, 6):
        await world.run(ctx, at(n, 3))
    rows = await world.rows(case_id)
    assert {v for k, v in rows.items() if k[1] == watch.ALERTS and k[0] > day(1)} == {"unverified"}
    window = await world.finder_window(ctx, case_id, at(6, 4))
    assert (window.verified, window.reason) == (False, watch.TOO_COMMON)
    assert await world.members(case_id) == {first}
    async with world.owner.connect() as conn:
        count = (await conn.execute(text("SELECT count(*) FROM case_suggestions"))).scalar_one()
    assert count == 0


async def test_r4_the_alerts_of_a_busy_actor_count_but_join_nothing(
    world: World, people: dict[str, Person]
) -> None:
    """55 investigations of the case's own host (a value in 50+ investigations): their alerts
    are the case's activity, and still none of them is joined or suggested."""
    ctx = context(FakeAsker())
    i1 = await world.investigation(H1, [at(0, 9)], entities=())
    case_id = await world.open_case(people["asha"], [i1], [H1], at(0, 10), c2=None)
    for k in range(55):
        await world.investigation(H1, [at(1 + k % 3, 9, k)], entities=(), rule=f"scan-{k}")
    report = await world.run(ctx, at(5, 3))
    rows = await world.rows(case_id)
    assert [rows[(day(n), watch.ALERTS, "", 0)] for n in (1, 2, 3)] == ["active"] * 3
    assert await world.members(case_id) == {i1}
    assert report.case((await world.case(case_id)).number).joined == 0
    async with world.owner.connect() as conn:
        assert (await conn.execute(text("SELECT count(*) FROM case_suggestions"))).scalar_one() == 0


class PairMalformed(FakeAsker):
    """The rhythm search left and came back with an answer that cannot be read."""

    async def ask(self, task):  # type: ignore[no-untyped-def]
        from argus.context import beacon

        if isinstance(task.params, beacon.PairParams):
            self.asked.append(("proxy.pair", task.params.start.date(), task.params.destination))
            body = {"aggregations": {"first": {"value": 10**25}}}
            return watchrun.Answer(self.now, body=body, sent=True)
        return await super().ask(task)


async def test_r6_a_pair_answer_that_cannot_be_read_is_recorded_and_counted(
    world: World, people: dict[str, Person]
) -> None:
    asker = PairMalformed()
    asker.beacon([2], [H1])
    i1 = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(people["asha"], [i1], [H1], at(0, 10))
    await world.run(context(asker, pair=True), at(3, 3))
    async with world.owner.connect() as conn:
        pair = (
            await conn.execute(
                text(
                    "SELECT outcome, reason, requests FROM case_watch_checks"
                    " WHERE source = 'proxy.pair'"
                )
            )
        ).one()
    assert tuple(pair) == ("unverified", watch.MALFORMED, 1)
    contact = len([a for a in asker.asked if a[0] == "proxy.contact"])
    assert await requests_recorded(world, case_id) == contact + 1


async def test_r12_a_malformed_contact_answer_is_not_checked_not_quiet(
    world: World, people: dict[str, Person]
) -> None:
    asker = BadBody("198.51.100.9")
    one = await world.investigation(H1, [at(0, 9)], entities=(("ip", "198.51.100.9"),))
    case_id = await world.open_case(people["asha"], [one], [H1], at(0, 10), c2="198.51.100.9")
    await world.run(context(asker), at(2, 3))
    async with world.owner.connect() as conn:
        row = (
            await conn.execute(
                text(
                    "SELECT outcome, reason, requests FROM case_watch_checks"
                    " WHERE source = 'proxy.contact'"
                )
            )
        ).one()
    assert tuple(row) == ("not_checked", watch.MALFORMED, 1)
    assert (await world.finder_window(context(asker), case_id, at(2, 4))).verified is False


class Exploding(FakeAsker):
    """An asker that breaks on one address with an error nobody planned for."""

    async def ask(self, task):  # type: ignore[no-untyped-def]
        if task.params.destination == "198.51.100.9":
            raise RuntimeError("boom")
        return await super().ask(task)


async def test_r12_one_cases_failure_is_a_problem_and_the_others_and_the_audit_row_go_on(
    world: World, people: dict[str, Person]
) -> None:
    ctx = context(Exploding())
    one = await world.investigation(H1, [at(0, 9)], entities=(("ip", "198.51.100.9"),))
    first = await world.open_case(people["asha"], [one], [H1], at(0, 10), c2="198.51.100.9")
    two = await world.investigation(H2, [at(0, 9)], entities=(("ip", C2),))
    second = await world.open_case(people["ravi"], [two], [H2], at(0, 10, 5))
    report = await world.run(ctx, at(3, 3))
    numbers = {first: (await world.case(first)).number, second: (await world.case(second)).number}
    assert report.problems == [f"case {numbers[first]}: RuntimeError"]
    assert any(key[1] == watch.CONTACT for key in await world.rows(second))  # the other went on
    async with world.owner.connect() as conn:
        audit = (
            await conn.execute(text("SELECT details FROM audit_events WHERE action = 'watch.run'"))
        ).scalar_one()
    assert audit["problems"] == 1
    assert (await world.run(ctx, at(3, 4))).problems == [f"case {numbers[first]}: RuntimeError"]


def test_r13_the_dismissal_is_audited_as_the_person_with_what_it_dismissed(
    cli_env: Path,  # noqa: F811
    migrated_engine: AsyncEngine,
    app_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    async def plant() -> uuid.UUID:
        world = World(migrated_engine, app_engine)
        first = await world.investigation(H1, [at(0, 9)])
        case_id = await world.open_case(people["asha"], [first], [H1], at(0, 10))
        second = await world.investigation(H2, [at(1, 8)])
        async with migrated_engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO case_suggestions (investigation_id, case_id, link, kind, why)"
                    " VALUES (:i, :c, 'c2', 'shared', 'a content-delivery address')"
                ),
                {"i": second, "c": case_id},
            )
        return case_id

    async def audit() -> list[tuple[str, str, str | None, str, str]]:
        async with migrated_engine.connect() as conn:
            found = await conn.execute(
                text(
                    "SELECT actor, action, target_type, target_id, details->>'via' FROM"
                    " audit_events WHERE action = 'case.suggestion_dismissed'"
                )
            )
            return [tuple(r) for r in found]  # type: ignore[misc]

    case_id = asyncio.run(plant())
    assert _run("case", "suggestions", "--dismiss", "1", "--as", "asha").exit_code == 0
    assert asyncio.run(audit()) == [
        (f"user:{people['asha'].user_id}", "case.suggestion_dismissed", "case", str(case_id), "cli")
    ]
    assert _run("case", "suggestions", "--dismiss", "1", "--as", "asha").exit_code == 1
    assert len(asyncio.run(audit())) == 1  # a refused dismissal writes nothing


async def test_r14_a_closed_cases_member_alert_is_seen_after_a_long_gap(
    world: World,
    api_engine: AsyncEngine,
    people: dict[str, Person],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tests.integration.cases.test_watch import closed_case

    parent, member = await closed_case(world, api_engine, people, monkeypatch)
    ctx = context(None)
    await world.run(ctx, at(3, 3))
    await world.add_alert(member, at(3, 12))  # the closed case's own investigation alerts again
    await world.run(ctx, at(13, 3))  # the watch was down for ten days (closed at D2 12:00)
    assert (await world.events(parent))[-1] == "activity_after_closure"
    assert (await world.rows(parent))[(day(3), watch.ALERTS, "", 0)] == "active"


async def test_r15_the_window_must_end_after_the_containment_and_then_it_is_proposed(
    world: World, people: dict[str, Person]
) -> None:
    asha = people["asha"]
    ctx = context(FakeAsker())
    i1 = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(asha, [i1], [H1], at(0, 10))
    for n in (1, 2, 3, 4, 5):
        await world.run(ctx, at(n, 3))
    await world.contain(ctx, asha, case_id, at(5, 4))
    same_day = await world.finder_window(ctx, case_id, at(5, 5))
    assert not same_day.verified
    assert "ends before the case was contained" in same_day.reason
    await world.run(ctx, at(6, 3))
    next_day = await world.finder_window(ctx, case_id, at(6, 4))  # the window now ends D6 00:00
    assert next_day.verified, next_day.reason
    async with world.runtime.begin() as conn:
        found = await proposer.candidates(
            conn, windows=watchrun.Finder(conn, ctx, lambda: at(6, 4))
        )
    assert [c.reason for c in found] == ["remediated_verified"]


async def test_r17_status_tells_when_the_watch_last_ran(
    world: World, people: dict[str, Person]
) -> None:
    ctx = context(None)
    i1 = await world.investigation(H1, [at(0, 9)])
    case_id = await world.open_case(people["asha"], [i1], [H1], at(0, 10))
    async with world.runtime.connect() as conn:
        before = await watchrun.status(conn, ctx, case_id, at(3, 4))
    assert "never run" in before[0]
    await world.run(ctx, at(3, 3))
    now = datetime.now(UTC) + timedelta(hours=5)  # the audit row is stamped with the real time
    async with world.runtime.connect() as conn:
        after = await watchrun.status(conn, ctx, case_id, now)
    assert after[0].startswith("last run of the watch: ")
    assert "(5 hours ago)" in after[0]


async def test_r17_doctor_warns_when_a_watch_that_is_on_has_not_run_for_36_hours(
    world: World, people: dict[str, Person], db_settings: DatabaseSettings, test_database: str
) -> None:
    from argus.config.settings import CasesSettings, Settings
    from argus.ops import checks

    def settings(mode: str) -> Settings:
        return Settings(
            database=db_settings.model_copy(update={"name": test_database}),
            cases=CasesSettings(watch=mode),  # type: ignore[arg-type]
        )

    now = datetime.now(UTC)
    (off,) = await checks.watch_results(settings("off"), now)
    assert (off.label, off.detail) == ("PASS", "off (cases.watch)")
    (never,) = await checks.watch_results(settings("local"), now)
    assert never.label == "WARN"
    assert "never run" in never.detail
    i1 = await world.investigation(H1, [at(0, 9)])
    await world.open_case(people["asha"], [i1], [H1], at(0, 10))
    await world.run(context(None), at(3, 3))
    (fresh,) = await checks.watch_results(settings("local"), now + timedelta(hours=35))
    assert fresh.label == "PASS", fresh.detail
    (late,) = await checks.watch_results(settings("local"), now + timedelta(hours=37))
    assert late.label == "WARN"
    assert "the daily run is late" in late.detail


def public(count: int) -> list[str]:
    return [f"203.0.113.{n}" for n in range(1, count + 1)]


async def test_r18_a_case_with_eight_addresses_asks_a_day_a_run_and_verifies(
    world: World, people: dict[str, Person]
) -> None:
    """The lead's decision on R18: the cap is the number of subjects (8 here), so a case that
    is watched from the start answers each finished day in its run and a three-day window
    fills (it could not at a cap of 6: eight new questions a day against six)."""
    asker = FakeAsker()
    ctx = context(asker)
    i1 = await world.investigation(H1, [at(0, 9)], entities=())
    addresses = public(8)
    case_id = await world.open_case(people["asha"], [i1], [H1], at(0, 10), c2=addresses)
    number = (await world.case(case_id)).number
    for n in (2, 3, 4, 5):
        asker.asked.clear()
        report = await world.run(ctx, at(n, 3))  # D(n-1) is the one new finished day
        assert [(d, c2) for _, d, c2 in asker.asked] == [(day(n - 1), c) for c in addresses]
        assert (report.case(number).asked, report.case(number).cut_off) == (8, 0)
    window = await world.finder_window(ctx, case_id, at(5, 4))
    assert window.verified, window.reason
    assert "checks answered" not in window.reason


async def test_r18_a_backlog_is_cleared_oldest_day_first_and_the_verdict_shows_progress(
    world: World, people: dict[str, Person]
) -> None:
    """Eight addresses ask up to ten a day (two spare): a backlog of three days is cleared oldest
    first, two questions a run faster than the days arrive, and the verdict shows the progress."""
    asker = FakeAsker()
    ctx = context(asker)
    i1 = await world.investigation(H1, [at(0, 9)], entities=())
    addresses = public(8)
    case_id = await world.open_case(people["asha"], [i1], [H1], at(0, 10), c2=addresses)
    await world.run(ctx, at(4, 3))  # D1 to D3 are open
    assert [d for _, d, _ in asker.asked] == [day(1)] * 8 + [day(2)] * 2
    asker.asked.clear()
    await world.run(ctx, at(5, 3))  # D2's other six, then D3's first four
    assert [d for _, d, _ in asker.asked] == [day(2)] * 6 + [day(3)] * 4
    window = await world.finder_window(ctx, case_id, at(5, 4))
    assert not window.verified
    assert "checks answered)" in window.reason
    for n in range(6, 12):  # two questions a run: nothing is left open by the run on D11
        await world.run(ctx, at(n, 3))
    assert (await world.finder_window(ctx, case_id, at(11, 4))).verified


class FailsOnce(FakeAsker):
    """The first question about the first address on the first day is sent and fails."""

    def __init__(self, first: str) -> None:
        super().__init__()
        self.first = first
        self.failed = False

    async def ask(self, task):  # type: ignore[no-untyped-def]
        if (
            not self.failed
            and task.params.destination == self.first
            and (task.params.start.date() == day(1))
        ):
            self.failed = True
            self.asked.append(("proxy.contact", day(1), self.first))
            return watchrun.Answer(self.now, refused="failed", sent=True)
        return await super().ask(task)


async def test_r18_eight_addresses_and_one_failed_question_still_verify_within_fourteen_runs(
    world: World, people: dict[str, Person]
) -> None:
    """The lead's decision on the spare questions: the failed question is asked again with the
    next day's (nine questions of ten), nothing is left over, and the window is verified."""
    addresses = public(8)
    asker = FailsOnce(addresses[0])
    ctx = context(asker)
    i1 = await world.investigation(H1, [at(0, 9)], entities=())
    case_id = await world.open_case(people["asha"], [i1], [H1], at(0, 10), c2=addresses)
    number = (await world.case(case_id)).number
    asked, verdicts = [], []
    for n in range(2, 16):  # fourteen daily runs
        report = await world.run(ctx, at(n, 3))
        asked.append(report.case(number).asked)
        verdicts.append((await world.finder_window(ctx, case_id, at(n, 4))).verified)
    assert asker.failed
    assert asked[:3] == [8, 9, 8]  # the leftover is asked with D2's eight
    assert max(asked) <= watch.cap_for(8) == 10
    assert verdicts[:2] == [False, False]
    assert verdicts[2:] == [True] * 12  # D1 to D3 whole at the run on D4, and it stays so
    rows = await world.rows(case_id)
    assert {v for k, v in rows.items() if k[1] == watch.CONTACT} == {"quiet"}


async def test_r18_a_case_with_more_than_twenty_addresses_stays_incomplete_and_says_so(
    world: World, people: dict[str, Person]
) -> None:
    asker = FakeAsker()
    ctx = context(asker)
    i1 = await world.investigation(H1, [at(0, 9)], entities=())
    addresses = public(25)
    case_id = await world.open_case(people["asha"], [i1], [H1], at(0, 10), c2=addresses)
    for n in range(2, 8):
        report = await world.run(ctx, at(n, 3))
        assert report.case((await world.case(case_id)).number).asked == watch.MAX_REQUESTS_A_DAY
    async with world.owner.connect() as conn:
        most = (
            await conn.execute(
                text(
                    "SELECT max(n) FROM (SELECT sum(requests) AS n FROM case_watch_checks"
                    " WHERE case_id = :c AND asked_on IS NOT NULL GROUP BY asked_on) d"
                ),
                {"c": case_id},
            )
        ).scalar_one()
    assert most == 20  # twenty a day, never more
    window = await world.finder_window(ctx, case_id, at(7, 4))
    assert not window.verified
    assert "checks answered; this case has more addresses than the watch asks in a day)" in (
        window.reason
    )
    async with world.owner.connect() as conn:
        reason = (
            await conn.execute(
                text("SELECT reason FROM case_watch_checks WHERE outcome = 'not_checked' LIMIT 1")
            )
        ).scalar_one()
    assert "has asked its 20 proxy-log questions for today" in reason


async def test_r5_a_tie_opens_one_case_even_across_runs(
    world: World,
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:
    from argus.cases import opener
    from tests.integration.cases.conftest import investigation
    from tests.integration.cases.test_opener import BEACON, _dossier, _review
    from tests.integration.cases.test_opener import _run as run_opener

    asha = people["asha"]
    a = await world.investigation(H1, [at(0, 9)], entities=())
    b = await world.investigation(H1, [at(0, 9, 30)], entities=(), rule="other")
    case_a = await world.open_case(asha, [a], [H1], at(0, 10), c2=None)
    case_b = await world.open_case(people["ravi"], [b], [H1], at(0, 11), c2=None)

    async def verdict(rule: str) -> uuid.UUID:
        inv = await investigation(migrated_engine, rule=rule, actor=(("source.ip", H1),))
        await _dossier(migrated_engine, inv, BEACON)
        await _review(app_engine, asha, inv)
        return inv

    first = await verdict("x")
    assert (await run_opener(app_engine)).applied == {"opened": 1}  # the tie opens one case
    opened = [c for c in await world.case_ids() if c not in (case_a, case_b)]
    assert len(opened) == 1
    second = await verdict("y")
    third = await verdict("z")
    report = await run_opener(app_engine)  # later investigations of the tie open none
    assert report.applied == {"attempt": 2}
    assert opener.TIE_OPENED not in " ".join(report.planned[0].reasons)
    assert len(await world.case_ids()) == 3
    async with world.owner.connect() as conn:
        kinds = (
            await conn.execute(
                text(
                    "SELECT investigation_id, count(*), min(kind) FROM case_suggestions"
                    " GROUP BY investigation_id"
                )
            )
        ).all()
    assert {(r[0], r[1], r[2]) for r in kinds} == {
        (first, 2, "tie"), (second, 3, "tie"), (third, 3, "tie"),
    }  # fmt: skip


@pytest.mark.parametrize(
    "args",
    [
        ("case", "backfill"),
        ("approvals", "propose"),
        ("case", "watch", "status", "1"),
        ("case", "contain", "1", "--as", "asha", "--attest", "cleaned"),
    ],
    ids=["backfill", "propose", "status", "contain"],
)
def test_r10_a_missing_shared_list_is_one_error_line_and_exit_1(
    args: tuple[str, ...],
    cli_env: Path,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from argus.cases import membership
    from tests.integration.test_cli_db import _error_line

    monkeypatch.setattr(membership, "SHARED_PATH", tmp_path / "gone.yaml")
    result = _run(*args)
    assert result.exit_code == 1
    assert "gone.yaml is missing" in _error_line(result)


def test_the_watchs_asker_is_given_the_health_config_like_the_other_batch_callers(
    cli_env: Path,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from argus.cases import cli as cases_cli
    from argus.gateway.health import HealthConfig

    monkeypatch.setenv("ARGUS_CASES__WATCH", "on")
    seen: dict[str, object] = {}

    class Spy:
        def __init__(self, *args: object, **kwargs: object) -> None:
            seen.update(kwargs)

    class Transport:
        async def aclose(self) -> None:
            return None

    class Gateway:
        transport = Transport()

    async def fake_run(engine: object, ctx: object, **kwargs: object) -> watchrun.Report:
        return watchrun.Report("on")

    monkeypatch.setattr(cases_cli, "_gateway", lambda settings, engine: (Gateway(), None))
    monkeypatch.setattr(watchrun, "GatewayAsker", Spy)
    monkeypatch.setattr(watchrun, "run", fake_run)
    assert _run("case", "watch", "run").exit_code == 0
    assert isinstance(seen["health_config"], HealthConfig)
