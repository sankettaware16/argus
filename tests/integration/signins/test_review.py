"""The sign-in pass after the adversarial review (D-222 to D-227) against the real database and a
scripted gateway: an answer the database refuses never makes the same request every pass, a partial
or badly shaped answer stops the pass, two passes do not run at once, the retention holds with the
feature off, a finished day is read again once after its late logs, events with no account name are
not "no one signed in", and a lookup is dated by what it read."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import UTC, date, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.config.settings import Settings, SigninsSettings
from argus.gateway.health import HealthMemory
from argus.signins import model as m
from argus.signins import run, store
from tests.integration.cases.knownkit import make
from tests.integration.signins import kit as k
from tests.integration.signins.test_pass import go, rows
from tests.unit.gateway.fakes import ok
from tests.unit.signins import kit

pytestmark = pytest.mark.integration
D28 = date(2026, 10, 28)
POISON = "poison-user-17"


def again(wire: k.Wire, *replies: Any) -> None:
    """The replies the next requests get."""
    wire.transport.routes[-1][1][:] = list(replies)


def refuse_poison(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """The database refuses any answer that holds the poisoned account (as it would a NUL or a
    surrogate the parser did not clean); the list counts the refusals."""
    real = store.save
    refused: list[int] = []

    async def save(
        conn: AsyncConnection, lookups: Sequence[m.Lookup], sightings: Sequence[m.Sighting]
    ) -> None:
        if any(s.user == POISON for s in sightings):
            refused.append(len(lookups))
            raise RuntimeError(f"cannot store {POISON}")
        await real(conn, lookups, sightings)

    monkeypatch.setattr(store, "save", save)
    return refused


# ---------------------------------------------------------------- M1: the poison pill


async def test_a_nul_and_a_lone_surrogate_from_the_logs_are_stored_cleaned_not_refused(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """Before: the NUL in the browser string (jsonb) or the surrogate in the name (the driver)
    raised out of the pass, nothing was stored, and the same request went out every pass."""
    await k.world(migrated_engine)
    nasty = kit.sighting(
        "al\ud800ice", address=k.HOST_A, hours=(13,), events=3, agent="Moz\x00illa"
    )
    wire = k.Wire(k.reply(nasty))
    report = await go(app_engine, wire)
    assert (report.sent, report.sightings, report.incomplete, report.unstorable) == (1, 1, 0, 0)
    got = await rows(app_engine, "SELECT user_name, user_agents FROM signin_sightings")
    assert [tuple(r) for r in got] == [  # type: ignore[call-overload]
        ("al\ufffdice", [{"text": "Moz\ufffdilla", "events": 3}]),
    ]
    assert (await go(app_engine, wire, now=k.NOW + timedelta(hours=4))).sent == 0


async def test_a_batch_the_database_refuses_costs_that_address_and_the_pass_goes_on(
    app_engine: AsyncEngine,
    migrated_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    await k.world(migrated_engine)
    refused = refuse_poison(monkeypatch)
    wire = k.Wire(
        k.reply(
            kit.sighting(POISON, address=k.HOST_A, hours=(13,)),
            kit.sighting("user02", address=k.HOST_B, hours=(13,)),
        )
    )
    with caplog.at_level(logging.DEBUG):
        report = await go(app_engine, wire)
    # the whole batch was refused once, then address by address: B and C stored, A recorded
    assert refused == [3, 1]
    assert report.unstorable == 1
    assert report.addresses == 2
    got = await rows(
        app_engine,
        "SELECT host(address) a, complete, reason, store_failures FROM signin_lookups ORDER BY 1",
    )
    assert [tuple(r) for r in got] == [  # type: ignore[call-overload]
        (k.HOST_A, False, "store_failed", 1), (k.HOST_B, True, None, 0), (k.HOST_C, True, None, 0),
    ]  # fmt: skip
    users = await rows(app_engine, "SELECT user_name FROM signin_sightings")
    assert [r[0] for r in users] == ["user02"]
    said = "\n".join([*report.said, *report.warned, caplog.text])
    assert POISON not in said  # the refusal's message held the name; the pass says its type only


async def test_the_pass_goes_on_with_the_next_batch_after_one_it_could_not_store(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    await k.world(migrated_engine)
    refuse_poison(monkeypatch)
    wire = k.Wire()
    wire.transport.on(
        "/_search",
        k.reply(kit.sighting(POISON, address=k.HOST_A, hours=(13,))),
        k.reply(kit.sighting("user02", address=k.HOST_B, hours=(13,))),
        k.reply(),
    )  # one reply for each request, in turn
    report = await go(app_engine, wire, batch=1, max_requests_per_pass=3)
    assert report.sent == 3  # A (refused), then B and C
    assert report.unstorable == 1
    got = await rows(
        app_engine, "SELECT reason, count(*) FROM signin_lookups GROUP BY 1 ORDER BY 1"
    )
    assert [tuple(r) for r in got] == [("store_failed", 1), (None, 2)]  # type: ignore[call-overload]


async def test_an_answer_that_cannot_be_stored_is_not_asked_again_for_six_hours_and_after_three_tries_not_at_all(  # noqa: E501
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Before: nothing was stored, so every pass sent the same heavy request first."""
    await k.world(migrated_engine)
    refuse_poison(monkeypatch)
    poisoned = k.reply(kit.sighting(POISON, address=k.HOST_A, hours=(13,)))
    wire = k.Wire(poisoned)
    assert (await go(app_engine, wire)).sent == 1  # all three addresses in one request
    assert (await go(app_engine, wire, now=k.NOW + timedelta(hours=2))).sent == 0  # backed off
    again(wire, poisoned)
    second = await go(app_engine, wire, now=k.NOW + timedelta(hours=7))
    assert second.sent == 1  # only A is left to ask
    assert wire.asked()[-1]["query"]["bool"]["filter"][0]["terms"]["source.ip"] == [k.HOST_A]
    again(wire, poisoned)
    assert (await go(app_engine, wire, now=k.NOW + timedelta(hours=14))).sent == 1
    tries = await rows(app_engine, "SELECT store_failures FROM signin_lookups WHERE NOT complete")
    assert [r[0] for r in tries] == [3]
    again(wire, poisoned)
    stuck = await go(app_engine, wire, now=k.NOW + timedelta(hours=21))
    assert stuck.sent == 0  # three tries: left alone, and said
    assert any("left alone" in w for w in stuck.warned)
    assert len(wire.searches()) == 3


# ---------------------------------------------------------------- m5: the circuit breaker


@pytest.mark.parametrize("bad", ["shape", "timed_out"])
async def test_a_bad_or_partial_answer_stops_the_pass_so_the_next_batches_wait(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, bad: str
) -> None:
    await k.world(migrated_engine)
    body = kit.answer({k.HOST_A: [kit.sighting("user01", address=k.HOST_A)]})
    if bad == "shape":
        body["aggregations"]["ips"]["buckets"][0]["key"] = "10.99.99.99"  # never asked about
    else:
        body["timed_out"] = True
    wire = k.Wire()
    wire.transport.on("/_search", ok(body), k.reply(), k.reply())
    report = await go(app_engine, wire, batch=1, max_requests_per_pass=3)
    assert report.sent == 1  # one request shows the mismatch; six would only repeat it
    assert report.stopped is not None
    assert len(wire.searches()) == 1
    got = await rows(app_engine, "SELECT DISTINCT complete FROM signin_lookups")
    assert [tuple(r) for r in got] == [(False,)]  # type: ignore[call-overload]


# ---------------------------------------------------------------- m7: two passes at once


async def test_a_second_pass_does_nothing_while_another_holds_the_lock(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await k.world(migrated_engine)
    wire = k.Wire(k.reply())
    async with app_engine.connect() as holder:
        await holder.execute(text("SELECT pg_advisory_lock(:k)"), {"k": run.LOCK_KEY})
        await holder.commit()
        blocked = await go(app_engine, wire)
        await holder.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": run.LOCK_KEY})
        await holder.commit()
    assert blocked.sent == 0
    assert wire.searches() == []
    assert any("another pass is running" in line for line in blocked.said)
    assert (await go(app_engine, wire)).sent == 1  # the lock was given back
    assert (
        await go(app_engine, wire, now=k.NOW + timedelta(hours=4))
    ).sent == 0  # and after a pass


async def test_the_lock_is_given_back_when_the_pass_fails(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    await k.world(migrated_engine)
    wire = k.Wire(k.reply())

    async def broken(*a: Any, **kw: Any) -> None:
        raise RuntimeError("the database went away")

    real = run._pass
    monkeypatch.setattr(run, "_pass", broken)
    with pytest.raises(RuntimeError, match="went away"):
        await go(app_engine, wire)
    monkeypatch.setattr(run, "_pass", real)
    assert (await go(app_engine, wire)).sent == 1


# ---------------------------------------------------------------- m6: the retention


async def old_rows(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        for day in (date(2026, 4, 1), date(2026, 10, 27)):
            await conn.execute(
                text(
                    "INSERT INTO signin_sightings (address, day, user_name, first_at, last_at,"
                    " events, successes, failures, hours, user_agents) VALUES ('10.9.9.9', :d,"
                    " 'user01', now(), now(), 1, 1, 0, '{1}', '[]')"
                ),
                {"d": day},
            )
            await conn.execute(
                text(
                    "INSERT INTO signin_lookups (address, day, looked_at, complete, accounts)"
                    " VALUES ('10.9.9.9', :d, now(), true, 1)"
                ),
                {"d": day},
            )


async def left(engine: AsyncEngine) -> list[date]:
    return [r[0] for r in await rows(engine, "SELECT day FROM signin_sightings")]  # type: ignore[index]


@pytest.mark.parametrize("when", ["off", "quiet hours", "no classifier"])
async def test_the_retention_holds_whether_or_not_the_pass_sends(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, when: str
) -> None:
    """Before: the prune ran only after a pass got past every early return, so a host with the
    feature off kept names for ever."""
    await old_rows(app_engine)
    wire = k.Wire(k.reply())
    on = Settings(signins=SigninsSettings(enabled=when != "off"))
    now = datetime(2026, 10, 29, 1, 0, tzinfo=UTC) if when == "quiet hours" else k.NOW
    wire.at(now)
    classifier = None if when == "no classifier" else k.CLASSIFIER
    report = await run.run_pass(
        app_engine, wire.gateway, wire.state, on, classifier, clock=wire.clock,
        sleep=wire.clock.sleep,
    )  # fmt: skip
    assert report.sent == 0
    assert await left(app_engine) == [date(2026, 10, 27)]
    assert any("1 sightings older than 180 days removed" in line for line in report.said)


async def test_a_dry_run_prunes_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await old_rows(app_engine)
    wire = k.Wire(k.reply())
    await run.run_pass(
        app_engine, None, None, k.settings(), k.CLASSIFIER, clock=wire.clock, dry_run=True
    )  # fmt: skip
    assert len(await left(app_engine)) == 2


async def test_the_retention_with_the_feature_off_needs_no_tables(
    empty_engine: AsyncEngine,
) -> None:
    """Before ``argus db upgrade`` there are no tables: a host with the switch off is no error."""
    off = Settings(signins=SigninsSettings(enabled=False))
    report = await run.run_pass(
        empty_engine, None, None, off, k.CLASSIFIER, clock=lambda: k.NOW
    )  # fmt: skip
    assert report.said == ["signins: off (signins.enabled)"]


# ---------------------------------------------------------------- m1: dated by what it read


async def test_a_lookup_is_dated_by_the_end_of_what_it_read_not_by_the_time_of_the_answer(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """Three requests, ten minutes apart, all read to 15:25; before, the rows said 15:40, 15:50
    and 16:00, and a window ending 15:30 read "none seen" with no gap."""
    now = datetime(2026, 10, 29, 15, 40, tzinfo=UTC)
    when = datetime(2026, 10, 29, 15, 20, tzinfo=UTC)
    for host in (k.HOST_A, k.HOST_B, k.HOST_C):
        await make(migrated_engine, when=when, host=host, flags=())
    wire = k.Wire(k.reply(), k.reply(), k.reply(), indices=("acme-logs-sso-2026.10.29",), now=now)

    async def sleep(seconds: float) -> None:
        await wire.clock.sleep(seconds)
        wire.state.memory = HealthMemory(probed_at=wire.clock.now)  # the collector keeps probing

    report = await run.run_pass(
        app_engine, wire.gateway, wire.state,
        k.settings(batch=1, max_requests_per_pass=3, gap=timedelta(minutes=10)), k.CLASSIFIER,
        clock=wire.clock, sleep=sleep, budget=timedelta(hours=12),
    )  # fmt: skip
    assert report.sent == 3
    reads = [b["query"]["bool"]["filter"][2]["range"]["@timestamp"]["lt"] for b in wire.asked()]
    assert len(set(reads)) == 1  # every request read to the same minute
    stamped = await rows(app_engine, "SELECT looked_at FROM signin_lookups")
    assert {r[0] for r in stamped} == {
        datetime(2026, 10, 29, 15, 40, tzinfo=UTC)
    }  # not 15:50, 16:00
    async with app_engine.connect() as conn:
        found = await store.records(
            conn, [k.HOST_A, k.HOST_B, k.HOST_C], date(2026, 10, 29), date(2026, 10, 29)
        )
    assert {r.lookup.covered_until() for r in found.values() if r.lookup} == {
        datetime(2026, 10, 29, 15, 25, tzinfo=UTC)
    }


# ---------------------------------------------------------------- M3: unknown is not none seen


async def test_events_with_no_account_name_make_the_day_incomplete_not_none_seen(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await k.world(migrated_engine)
    body = kit.answer({k.HOST_A: [kit.sighting("user01", address=k.HOST_A, hours=(13,), events=4)]})
    body["aggregations"]["ips"]["buckets"][0]["doc_count"] = 9  # five events by no name
    wire = k.Wire(ok(body))
    report = await go(app_engine, wire)
    assert (report.sightings, report.incomplete) == (1, 1)
    got = await rows(
        app_engine,
        "SELECT host(address) a, complete, reason, unnamed, accounts FROM signin_lookups"
        " ORDER BY 1",
    )
    assert [tuple(r) for r in got] == [  # type: ignore[call-overload]
        (k.HOST_A, False, "unnamed_events", 5, 0), (k.HOST_B, True, None, 0, 0),
        (k.HOST_C, True, None, 0, 0),
    ]  # fmt: skip
    named = await rows(app_engine, "SELECT user_name FROM signin_sightings")
    assert [r[0] for r in named] == ["user01"]  # the named account is kept beside the gap
    # a finished day (made 3 h after its end) is not asked again: the unnamed events stay unnamed
    assert (await go(app_engine, wire, now=k.NOW + timedelta(days=1))).sent == 0


async def test_a_finished_day_is_read_once_more_after_its_late_logs_and_then_it_is_final(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """D-224: ingest lags; a lookup made 1.5 h after the day's end is made again at 3 h, once."""
    await k.world(migrated_engine)
    first = datetime(2026, 10, 29, 1, 35, tzinfo=UTC)  # the quiet hours are over
    wire = k.Wire(k.reply(kit.sighting("user01", address=k.HOST_A, hours=(13,))), now=first)
    assert (await go(app_engine, wire)).sent == 1
    assert (await go(app_engine, wire, now=datetime(2026, 10, 29, 2, 30, tzinfo=UTC))).sent == 0
    again(
        wire,
        k.reply(
            kit.sighting("user01", address=k.HOST_A, hours=(13,)),
            kit.sighting("user02", address=k.HOST_A, hours=(13, 23), agent=kit.SAFARI),
        ),
    )  # the late logs have arrived
    third = await go(app_engine, wire, now=datetime(2026, 10, 29, 3, 5, tzinfo=UTC))
    assert third.sent == 1
    users = await rows(app_engine, "SELECT user_name FROM signin_sightings ORDER BY 1")
    assert [r[0] for r in users] == ["user01", "user02"]
    assert (await go(app_engine, wire, now=datetime(2026, 10, 29, 12, 0, tzinfo=UTC))).sent == 0
    assert len(wire.searches()) == 2
