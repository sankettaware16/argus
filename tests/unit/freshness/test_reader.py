"""The freshness lane's template and reader (Q-F1) on the gateway's fakes: the request is the
validator's, it spends the freshness lane and obeys every switch, the breaker, health and the
quiet hours; the schedule (5 minutes, 15 in DEGRADED, none in STOP or the quiet hours); what
is stored for each answer; the settings and the policy."""

from __future__ import annotations

import itertools
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from argus.config.errors import ConfigError
from argus.config.settings import FreshnessSettings, Settings
from argus.freshness.model import EMPTY, FAILED, OK, REFUSED
from argus.freshness.reader import Reader, jobs, policy_of
from argus.freshness.template import Watermark, WatermarkParams, newest
from argus.gateway.breaker import BreakerState
from argus.gateway.gateway import Gateway
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.lanes import Lane
from argus.gateway.templates import CostClass, Purpose
from argus.gateway.validator import validate
from tests.unit.gateway.fakes import SQUID_TODAY, FakeTransport, listing, make, ok, search_answer

pytestmark = pytest.mark.unit
MIN = timedelta(minutes=1)


def doc(ingested: str = "2026-10-09T11:59:58Z", stamp: str = "2026-10-09T11:59:50Z") -> dict:
    return {
        "_index": SQUID_TODAY,
        "_id": "a",
        "_source": {"@timestamp": stamp, "event": {"ingested": ingested}},
    }


def lane(answer: Any = None) -> tuple[Gateway, FakeTransport, Any, Any]:
    transport = FakeTransport().on("_resolve", ok(listing(SQUID_TODAY)))
    transport.on("_search", ok(answer if answer is not None else search_answer([doc()])))
    return make(transport)


def test_the_request_is_a_light_size_1_search_the_validator_accepts() -> None:
    gateway, *_ = lane()
    now = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
    final = gateway.preview(
        Watermark(), WatermarkParams(source="squid", now=now), deadline=now + 20 * MIN
    )
    validate(final)
    assert Watermark.cost is CostClass.LIGHT
    assert final.indices == (SQUID_TODAY,)
    body = final.body
    assert body["size"] == 1
    assert body["track_total_hits"] is False
    assert body["sort"] == [{"event.ingested": {"order": "desc"}}]
    assert body["_source"] == ["@timestamp", "event.ingested"]
    assert body["query"] == {
        "range": {
            "event.ingested": {"gte": "2026-10-09T11:45:00.000Z", "lte": "2026-10-09T12:00:00.000Z"}
        }
    }  # ``lte`` now: a future ingest time never becomes the newest hit (review F9)
    with pytest.raises(ValidationError):
        WatermarkParams(source="Squid", now=now)


async def test_a_reading_spends_the_freshness_lane() -> None:
    gateway, transport, store, _clock = lane()
    reader = Reader(gateway, None, ("squid",))  # type: ignore[arg-type]
    got = await reader.read("squid", "normal")
    assert got.reading.outcome == OK
    assert got.reading.ingested == datetime(2026, 10, 9, 11, 59, 58, tzinfo=UTC)
    assert got.reading.event_at == datetime(2026, 10, 9, 11, 59, 50, tzinfo=UTC)
    assert got.reading.at >= got.sent_at
    assert got.took_ms == 5
    assert got.health == "normal"
    entry = store.ledger[-1]
    assert (entry.purpose, entry.component, entry.lane) == ("freshness", "freshness", "freshness")
    assert store.lanes.bucket(Lane.FRESHNESS).day_used_ms == 5
    assert [c.path for c in transport.calls][-1].endswith("/_search")


@pytest.mark.parametrize(
    ("setup", "reason"),
    [
        (lambda s, c: s.stopped.add("freshness"), "stopped"),
        (lambda s, c: s.stopped.add("global"), "stopped"),
        (
            lambda s, c: setattr(
                s, "memory", HealthMemory(state=HealthState.STOP, probed_at=c.now)
            ),
            "stopped",
        ),
        (lambda s, c: setattr(c, "now", c.now.replace(hour=0, minute=40)), "deferred"),
        (lambda s, c: setattr(s, "breaker", BreakerState(open_until=c.now + MIN)), "breaker_open"),
    ],
)
async def test_every_switch_health_and_the_breaker_refuse_it_and_nothing_is_sent(
    setup: Any, reason: str
) -> None:
    gateway, transport, store, clock = lane()
    setup(store, clock)
    store.memory = (
        store.memory
        if store.memory.state is HealthState.STOP
        else HealthMemory(probed_at=clock.now)
    )
    got = await Reader(gateway, None, ("squid",)).read("squid")  # type: ignore[arg-type]
    assert got.reading.outcome == REFUSED
    assert got.reason == reason
    assert [c for c in transport.calls if "_search" in c.path] == []


@pytest.mark.parametrize(
    ("answer", "outcome", "reason"),
    [
        (search_answer([]), EMPTY, None),
        (
            search_answer([{"_index": SQUID_TODAY, "_source": {"@timestamp": "x"}}]),
            FAILED,
            "malformed_answer",
        ),
        # the gateway's complete-results check refuses an answer without hits first
        (
            {"took": 1, "timed_out": False, "_shards": {"total": 1, "successful": 1, "failed": 0}},
            FAILED,
            "partial_result",
        ),
        (
            {
                "took": 1,
                "timed_out": True,
                "_shards": {"total": 1, "successful": 1, "failed": 0},
                "hits": {"hits": []},
            },
            FAILED,
            None,
        ),
    ],
)
async def test_what_each_answer_is_stored_as(answer: Any, outcome: str, reason: str | None) -> None:
    gateway, *_ = lane(answer)
    got = await Reader(gateway, None, ("squid",)).read("squid")  # type: ignore[arg-type]
    assert got.reading.outcome == outcome
    if reason is not None:
        assert got.reason == reason


def test_newest_reads_dotted_or_nested_times() -> None:
    flat = {
        "hits": {
            "hits": [
                {
                    "_source": {
                        "@timestamp": "2026-10-09T10:00:00Z",
                        "event.ingested": "2026-10-09T10:00:05Z",
                    }
                }
            ]
        }
    }
    assert newest(flat) == (
        datetime(2026, 10, 9, 10, 0, 5, tzinfo=UTC),
        datetime(2026, 10, 9, 10, 0, tzinfo=UTC),
    )
    assert newest({"hits": {"hits": []}}) is None
    for bad in ({}, {"hits": {}}, {"hits": {"hits": ["x"]}}, None):
        with pytest.raises(ValueError, match=r"\w"):
            newest(bad)


def test_the_schedule() -> None:
    gateway, *_ = lane()
    reader = Reader(
        gateway,
        None,
        ("squid", "dns"),
        interval=5 * MIN,  # type: ignore[arg-type]
        degraded_interval=15 * MIN,
    )
    noon = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
    assert reader.due(HealthState.NORMAL, noon) == ["squid", "dns"]
    reader.last = {"squid": noon, "dns": noon - 5 * MIN}
    assert reader.due(HealthState.NORMAL, noon + 4 * MIN) == ["dns"]
    assert reader.due(HealthState.CAUTION, noon + 5 * MIN) == ["dns", "squid"]  # most overdue first
    assert reader.due(HealthState.DEGRADED, noon + 9 * MIN) == []
    assert reader.due(HealthState.DEGRADED, noon + 10 * MIN) == ["dns"]
    assert reader.due(HealthState.DEGRADED, noon + 15 * MIN) == ["dns", "squid"]
    assert reader.due(HealthState.STOP, noon + 60 * MIN) == []
    night = datetime(2026, 10, 10, 1, 29, 59, tzinfo=UTC)
    assert reader.due(HealthState.NORMAL, night) == []
    assert reader.due(HealthState.NORMAL, night + timedelta(seconds=1)) == ["dns", "squid"]
    with pytest.raises(ValueError, match=r"\w"):
        Reader(gateway, None, ())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match=r"\w"):
        Reader(gateway, None, ("squid",), interval=5 * MIN, degraded_interval=MIN)  # type: ignore[arg-type]


@given(
    minutes=st.lists(st.integers(min_value=0, max_value=24 * 60), max_size=40),
    states=st.lists(st.sampled_from(list(HealthState)), min_size=40, max_size=40),
)
def test_never_two_reads_of_a_source_closer_than_its_interval(
    minutes: list[int], states: list[HealthState]
) -> None:
    gateway, *_ = lane()
    reader = Reader(gateway, None, ("squid",))  # type: ignore[arg-type]
    day = datetime(2026, 10, 9, tzinfo=UTC)
    read: list[tuple[datetime, HealthState]] = []
    for minute, state in zip(sorted(minutes), states, strict=False):
        now = day + minute * MIN
        for source in reader.due(state, now):
            reader.last[source] = now
            read.append((now, state))
    for (earlier, _), (later, state) in itertools.pairwise(read):
        assert later - earlier >= (15 * MIN if state is HealthState.DEGRADED else 5 * MIN)
    assert all(
        s is not HealthState.STOP and not (t.hour == 0 or (t.hour == 1 and t.minute < 30))
        for t, s in read
    )


async def test_a_step_reads_what_is_due_and_stores_it() -> None:
    gateway, _transport, store, clock = lane()
    stored: list[Any] = []

    class Conn:
        async def execute(self, statement: Any, values: Any = None) -> None:
            stored.append(values)

    class Begin:
        async def __aenter__(self) -> Conn:
            return Conn()

        async def __aexit__(self, *exc: object) -> None:
            return None

    class Engine:
        def begin(self) -> Begin:
            return Begin()

    reader = Reader(gateway, Engine(), ("squid",))  # type: ignore[arg-type]
    got = await reader.step()
    assert [g.reading.outcome for g in got] == [OK]
    assert [v["outcome"] for v in stored] == [OK, OK]  # the reading, then the watermark
    assert await reader.step() == []  # not due again within 5 minutes
    clock.now += 5 * MIN
    store.memory = HealthMemory(probed_at=clock.now)
    assert len(await reader.step()) == 1


def test_settings_and_policy() -> None:
    assert FreshnessSettings().mode == "off"
    f = FreshnessSettings(mode="shadow", margins={"squid": "3m"})
    assert f.margins == {"squid": 3 * MIN}
    for bad in (
        {"mode": "on"},  # on needs margins
        {"interval": "10m", "degraded_interval": "5m"},
        {"interval": "15m", "gap": "10m"},
        {"margins": {"Squid": "3m"}},
        {"margins": {"squid": "7h"}},
        {"bridge": "always"},
        {"mode": "maybe"},
    ):
        with pytest.raises(ValidationError):
            FreshnessSettings(**bad)  # type: ignore[arg-type]
    settings = Settings(freshness=FreshnessSettings(mode="shadow", margins={"squid": "3m"}))
    policy = policy_of(settings)
    assert (policy.mode, policy.margins, policy.gap, policy.bridge) == (
        "shadow",
        {"squid": 3 * MIN},
        10 * MIN,
        "none",
    )
    typo = Settings(freshness=FreshnessSettings(margins={"squidd": "3m"}))
    with pytest.raises(ConfigError, match="squidd"):
        policy_of(typo)
    gateway, *_ = lane()
    assert jobs(Settings(), None, gateway) == []  # type: ignore[arg-type]
    with pytest.raises(ConfigError):
        jobs(
            Settings(freshness=FreshnessSettings(mode="shadow", margins={"x": "3m"})), None, gateway
        )  # type: ignore[arg-type]
    ((name, every, _job),) = jobs(settings, None, gateway)  # type: ignore[arg-type]
    assert (name, every) == ("freshness", timedelta(seconds=30))


def test_the_freshness_purpose_is_the_lanes() -> None:
    assert Purpose.FRESHNESS.value == "freshness"


def test_the_first_read_fits_a_live_session_and_needs_one(monkeypatch: pytest.MonkeyPatch) -> None:
    from typer.testing import CliRunner

    from tests.conftest import suite_checkout

    monkeypatch.chdir(suite_checkout(Path.cwd()))  # the test's own folder (tests/unit)

    from argus.cli import app
    from argus.gateway.gateway import LiveLimits

    now = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
    plan = Watermark().plan(WatermarkParams(source="squid", now=now))
    assert plan.window is not None
    assert plan.window.end - plan.window.start <= LiveLimits("s").max_window
    assert plan.body["size"] <= LiveLimits("s").max_size
    runner = CliRunner()
    refused = runner.invoke(app, ["freshness", "read"])
    assert refused.exit_code == 2
    assert "--session" in refused.output
    dry = runner.invoke(app, ["freshness", "read", "--dry-run"])
    assert dry.exit_code == 0, dry.output
    lines = dry.output.strip().splitlines()
    assert len(lines) == 4
    assert all(line.startswith("POST /acme-logs-") for line in lines)


async def test_the_collectors_job_never_waits_for_a_reading() -> None:
    import asyncio

    from argus.freshness.reader import Detached

    started: list[int] = []
    release = asyncio.Event()

    async def slow() -> None:
        started.append(1)
        await release.wait()

    job = Detached(slow)
    await asyncio.wait_for(job(), timeout=1)  # returns at once
    await asyncio.sleep(0)
    await job()  # still running: not started twice
    assert started == [1]
    release.set()
    assert job.task is not None
    await job.task
    await job()
    await asyncio.sleep(0)
    assert started == [1, 1]

    async def broken() -> None:
        raise RuntimeError("down")

    failing = Detached(broken)
    await failing()
    await asyncio.sleep(0)
    await failing()  # the failure is logged, the next step starts
    assert failing.task is not None
    with pytest.raises(RuntimeError, match="down"):
        await failing.task
