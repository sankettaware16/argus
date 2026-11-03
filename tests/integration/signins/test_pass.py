"""The sign-in pass end to end (AR6, D-216): the investigations in the database, a gateway that
answers from a script, rows written, and every way the answer or the SIEM can fail."""

from __future__ import annotations

import logging
from datetime import UTC, date, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.gateway.errors import TransportFailedError
from argus.signins import model as m
from argus.signins import run
from tests.integration.cases.conftest import Person
from tests.integration.cases.knownkit import open_case
from tests.integration.signins import kit as k
from tests.unit.gateway.fakes import ok
from tests.unit.signins import kit

pytestmark = pytest.mark.integration
D28 = date(2026, 10, 28)


async def go(
    engine: AsyncEngine, wire: k.Wire, *, now: datetime | None = None, **more: object
) -> run.Report:
    if now is not None:
        wire.at(now)
    knobs = {key: more.pop(key) for key in ("max_requests", "dry_run") if key in more}
    return await run.run_pass(
        engine, wire.gateway, wire.state, k.settings(**more), k.CLASSIFIER,  # type: ignore[arg-type]
        clock=wire.clock, sleep=wire.clock.sleep, **knobs,  # type: ignore[arg-type]
    )  # fmt: skip


async def rows(engine: AsyncEngine, sql: str, **params: object) -> list[object]:
    async with engine.connect() as conn:
        return list((await conn.execute(text(sql), params)).all())


async def test_one_request_looks_up_every_address_and_stores_the_accounts(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await k.world(migrated_engine)
    wire = k.Wire(
        k.reply(
            kit.sighting("user01", address=k.HOST_A, hours=(13, 14), events=6, failures=1),
            kit.sighting("user02", address=k.HOST_A, hours=(9,), events=2, agent=kit.SAFARI),
        )
    )
    report = await go(app_engine, wire)
    (body,) = wire.asked()
    assert body["query"]["bool"]["filter"][0]["terms"]["source.ip"] == [
        k.HOST_A, k.HOST_B, k.HOST_C,
    ]  # fmt: skip
    assert body["size"] == 0
    assert body["track_total_hits"] is False
    (call,) = wire.searches()
    assert call.path == f"/{k.INDEX}/_search"
    assert (report.sent, report.addresses, report.sightings, report.incomplete) == (1, 3, 2, 0)
    lookups = await rows(
        app_engine,
        "SELECT host(address) a, complete, accounts, more_accounts, reason FROM signin_lookups"
        " ORDER BY address",
    )
    assert [tuple(r) for r in lookups] == [  # type: ignore[call-overload]
        (k.HOST_A, True, 2, 0, None), (k.HOST_B, True, 0, 0, None), (k.HOST_C, True, 0, 0, None),
    ]  # fmt: skip
    users = await rows(
        app_engine, "SELECT user_name, events, successes, failures FROM signin_sightings ORDER BY 1"
    )
    assert [tuple(r) for r in users] == [("user01", 6, 5, 1), ("user02", 2, 2, 0)]  # type: ignore[call-overload]
    ledger = wire.state.ledger
    assert [
        (e.template, e.purpose, e.component) for e in ledger if e.template == "signins.day"
    ] == [("signins.day", "investigate", "signins")]


async def test_a_finished_day_is_looked_up_once_and_the_second_pass_sends_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await k.world(migrated_engine)
    wire = k.Wire(k.reply(kit.sighting("user01", address=k.HOST_A)))
    await go(app_engine, wire)
    again = await go(app_engine, wire, now=k.NOW + timedelta(hours=3))
    assert again.sent == 0
    assert len(wire.searches()) == 1


async def test_a_member_of_an_open_case_is_asked_first_then_the_raised_then_the_rest(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, people: dict[str, Person]
) -> None:
    invs = await k.world(migrated_engine)
    await open_case(app_engine, people["asha"], [invs["b"]], host=k.HOST_B, servers=())
    wire = k.Wire(k.reply(), k.reply(), k.reply())
    await go(app_engine, wire, batch=1, max_requests_per_pass=3)
    firsts = [b["query"]["bool"]["filter"][0]["terms"]["source.ip"] for b in wire.asked()]
    assert firsts == [[k.HOST_B], [k.HOST_A], [k.HOST_C]]  # case member, raised, the rest


async def test_the_pass_stops_at_its_cap_and_the_next_pass_goes_on(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await k.world(migrated_engine)
    wire = k.Wire(k.reply(), k.reply(), k.reply())
    first = await go(app_engine, wire, batch=1, max_requests_per_pass=2)
    assert (first.sent, first.waiting) == (2, 1)
    assert len(wire.searches()) == 2
    second = await go(app_engine, wire, batch=1, max_requests_per_pass=2)
    assert second.sent == 1
    third = await go(app_engine, wire, batch=1, max_requests_per_pass=2)
    assert third.sent == 0


async def test_requests_are_at_least_the_gap_apart(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await k.world(migrated_engine)
    wire = k.Wire(k.reply(), k.reply(), k.reply())
    await go(app_engine, wire, batch=1, max_requests_per_pass=3)
    assert wire.clock.slept.count(3.0) == 2  # between three requests, not before the first


@pytest.mark.parametrize(
    "mutate",
    [lambda b: b.update(timed_out=True), lambda b: b["_shards"].update(failed=1)],
    ids=["timed_out", "shard_failed"],
)
async def test_a_partial_answer_is_stored_as_incomplete_never_as_none_seen(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, mutate: object
) -> None:
    await k.world(migrated_engine)
    body = kit.answer({k.HOST_A: [kit.sighting("user01", address=k.HOST_A)]})
    mutate(body)  # type: ignore[operator]
    wire = k.Wire(ok(body))
    report = await go(app_engine, wire)
    assert (report.sightings, report.incomplete) == (0, 3)
    got = await rows(app_engine, "SELECT complete, accounts, reason FROM signin_lookups")
    assert {tuple(r) for r in got} == {(False, 0, "partial")}  # type: ignore[call-overload]
    assert await rows(app_engine, "SELECT 1 FROM signin_sightings") == []
    # not asked again at once, asked again after half an hour
    assert (await go(app_engine, wire, now=k.NOW + timedelta(minutes=10))).sent == 0
    wire.transport.routes[-1][1][:] = [k.reply(kit.sighting("user01", address=k.HOST_A))]
    assert (await go(app_engine, wire, now=k.NOW + timedelta(minutes=45))).sent == 1
    got = await rows(app_engine, "SELECT DISTINCT complete FROM signin_lookups")
    assert [tuple(r) for r in got] == [(True,)]  # type: ignore[call-overload]


async def test_an_answer_that_is_not_the_contracts_shape_is_stored_as_bad(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await k.world(migrated_engine)
    body = kit.answer({k.HOST_A: [kit.sighting("user01", address=k.HOST_A)]})
    body["aggregations"]["ips"]["buckets"][0]["key"] = "10.99.99.99"  # not asked about
    wire = k.Wire(ok(body))
    report = await go(app_engine, wire)
    assert report.incomplete == 3
    assert any("not the contract" in w for w in report.warned)
    got = await rows(app_engine, "SELECT DISTINCT reason FROM signin_lookups")
    assert [tuple(r) for r in got] == [("bad_answer",)]  # type: ignore[call-overload]


async def test_a_missing_index_of_a_day_still_kept_is_retried_not_called_gone(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """D-224: the 28th is inside the five days the logs are kept, so a missing index is a shipper
    outage or a late ILM, not "no longer kept": it is said so and tried again later."""
    await k.world(migrated_engine)
    wire = k.Wire(indices=("acme-logs-sso-2026.10.29",))  # the 28th is not there
    report = await go(app_engine, wire)
    assert report.sent == 1
    assert wire.searches() == []
    got = await rows(app_engine, "SELECT DISTINCT complete, reason FROM signin_lookups")
    assert [tuple(r) for r in got] == [(False, "index_missing")]  # type: ignore[call-overload]
    assert (await go(app_engine, wire, now=k.NOW + timedelta(hours=2))).sent == 0
    assert (await go(app_engine, wire, now=k.NOW + timedelta(hours=7))).sent == 1


async def test_a_request_that_reached_siem_and_failed_is_stored_and_ends_the_pass(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await k.world(migrated_engine)
    boom = TransportFailedError("reset", retriable=False)
    wire = k.Wire(boom, k.reply())
    report = await go(app_engine, wire, batch=1, max_requests_per_pass=3)
    assert report.sent == 1
    assert report.stopped is not None
    got = await rows(app_engine, "SELECT reason, count(*) FROM signin_lookups GROUP BY 1")
    assert [tuple(r) for r in got] == [("failed", 1)]  # type: ignore[call-overload]


@pytest.mark.parametrize("stopped", [{"global"}, {"investigation"}])
async def test_a_kill_switch_sends_and_stores_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, stopped: set[str]
) -> None:
    await k.world(migrated_engine)
    wire = k.Wire(k.reply())
    wire.state.stopped = stopped
    report = await go(app_engine, wire)
    assert wire.searches() == []
    assert report.stopped is not None
    assert await rows(app_engine, "SELECT 1 FROM signin_lookups") == []


async def test_nothing_is_sent_in_the_quiet_hours_or_while_siem_is_not_normal(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await k.world(migrated_engine)
    wire = k.Wire(k.reply())
    quiet = await go(app_engine, wire, now=datetime(2026, 10, 29, 1, 0, tzinfo=UTC))
    assert quiet.sent == 0
    assert "quiet hours" in quiet.said[0]
    from argus.gateway.health import HealthMemory, HealthState

    wire.at(k.NOW)
    wire.state.memory = HealthMemory(state=HealthState.CAUTION, probed_at=k.NOW)
    cautious = await go(app_engine, wire)
    assert wire.searches() == []
    assert cautious.stopped is not None
    assert await rows(app_engine, "SELECT 1 FROM signin_lookups") == []


async def test_a_dry_run_plans_and_validates_and_sends_and_stores_nothing(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await k.world(migrated_engine)
    wire = k.Wire(k.reply())
    report = await run.run_pass(
        app_engine, None, None, k.settings(), k.CLASSIFIER, clock=wire.clock, dry_run=True
    )  # fmt: skip
    assert wire.transport.calls == []
    assert any("would read 2026-10-28 up to 00:00Z for 3 addresses" in line for line in report.said)
    assert any("acme-logs-sso-2026.10.28" in line for line in report.said)
    assert await rows(app_engine, "SELECT 1 FROM signin_lookups") == []


async def test_it_is_off_unless_switched_on(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    from argus.config.settings import Settings

    await k.world(migrated_engine)
    wire = k.Wire(k.reply())
    report = await run.run_pass(
        app_engine, wire.gateway, wire.state, Settings(), k.CLASSIFIER, clock=wire.clock
    )  # fmt: skip
    assert report.said == ["signins: off (signins.enabled)"]
    assert wire.transport.calls == []


async def test_a_second_look_replaces_the_day_and_a_failed_one_keeps_what_was_found(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await k.world(migrated_engine)
    early = datetime(2026, 10, 28, 15, 0, tzinfo=UTC)  # before the window ended: made again later
    wire = k.Wire(k.reply(kit.sighting("user01", address=k.HOST_A, hours=(13,))), now=early)
    await go(app_engine, wire)
    assert [r[0] for r in await rows(app_engine, "SELECT user_name FROM signin_sightings")] == [
        "user01"
    ]
    wire.transport.routes[-1][1][:] = [
        k.reply(kit.sighting("user02", address=k.HOST_A, hours=(14,), agent=kit.SAFARI))
    ]
    await go(app_engine, wire, now=k.NOW)
    assert [r[0] for r in await rows(app_engine, "SELECT user_name FROM signin_sightings")] == [
        "user02"
    ]  # the complete second look replaced the first
    # a later incomplete look (the day was final, so force a try) leaves the sightings alone
    async with app_engine.begin() as conn:
        await conn.execute(
            text("UPDATE signin_lookups SET looked_at = :t"), {"t": early}
        )  # as if the second look had been the early one
    wire.transport.routes[-1][1][:] = [ok({**kit.answer({}), "timed_out": True})]
    await go(app_engine, wire, now=k.NOW + timedelta(hours=2))
    assert [r[0] for r in await rows(app_engine, "SELECT user_name FROM signin_sightings")] == [
        "user02"
    ]
    got = await rows(app_engine, "SELECT DISTINCT complete, reason FROM signin_lookups")
    assert [tuple(r) for r in got] == [(False, "partial")]  # type: ignore[call-overload]


async def test_what_is_older_than_keep_days_is_pruned_by_the_pass(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    async with app_engine.begin() as conn:
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
    wire = k.Wire(k.reply())
    report = await go(app_engine, wire)
    assert any("1 sightings older than 180 days removed" in line for line in report.said)
    left = await rows(app_engine, "SELECT day FROM signin_sightings")
    assert [r[0] for r in left] == [date(2026, 10, 27)]
    assert [r[0] for r in await rows(app_engine, "SELECT day FROM signin_lookups")] == [
        date(2026, 10, 27)
    ]


async def test_an_account_name_is_never_in_what_the_pass_says_or_logs(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, caplog: pytest.LogCaptureFixture
) -> None:
    await k.world(migrated_engine)
    wire = k.Wire(k.reply(kit.sighting("secret-name-17", address=k.HOST_A)))
    with caplog.at_level(logging.DEBUG):
        report = await go(app_engine, wire)
    said = "\n".join([*report.said, *report.warned, caplog.text])
    assert "secret-name-17" not in said
    bad = kit.answer({k.HOST_A: [kit.sighting("secret-name-18", address=k.HOST_A)]})
    bad["aggregations"]["ips"]["buckets"][0]["users"]["buckets"][0]["doc_count"] = 0
    wire2 = k.Wire(ok(bad))
    with caplog.at_level(logging.DEBUG):
        report2 = await go(app_engine, wire2, now=k.NOW + timedelta(days=0, hours=0, minutes=1))
    assert "secret-name-18" not in "\n".join([*report2.said, *report2.warned, caplog.text])
    assert UTC is not None


def test_a_pass_never_asks_for_a_day_older_than_the_logs_are_kept() -> None:
    assert m.oldest_kept(date(2026, 10, 29), 5) == date(2026, 10, 25)


async def test_through_the_real_state_store_the_request_is_in_the_investigation_lane_and_ledger(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """The gateway's state in Postgres (the production shape): the lane's budget is spent, the
    request is on the ledger with its template, purpose and component, and the pass is the same."""
    from argus.config.settings import SiemSettings
    from argus.gateway.gateway import Gateway, Targets
    from argus.gateway.health import HealthMemory
    from argus.gateway.pgstore import PgStore
    from argus.gateway.service import collector_config, lane_plan

    await k.world(migrated_engine)
    wire = k.Wire(k.reply(kit.sighting("user01", address=k.HOST_A)))
    siem = SiemSettings()
    state = PgStore(app_engine, collector_config(siem), lane_plan(siem))
    await state.save_health(HealthMemory(probed_at=k.NOW))
    gateway = Gateway(
        wire.transport,
        state,
        targets=Targets(log_sources=frozenset({"sso"})),
        clock=wire.clock,
        sleep=wire.clock.sleep,
    )
    report = await run.run_pass(
        app_engine,
        gateway,
        state,
        k.settings(),
        k.CLASSIFIER,
        clock=wire.clock,
        sleep=wire.clock.sleep,
    )
    assert (report.sent, report.sightings, report.incomplete) == (1, 1, 0)
    ledger = await rows(
        app_engine, "SELECT template, purpose, component, outcome, lane FROM siem_requests"
    )
    mine = [tuple(r) for r in ledger if r[0] == "signins.day"]  # type: ignore[index, call-overload]
    assert mine == [("signins.day", "investigate", "signins", "ok", "investigation")]
