"""Collector tests written for mutation survivors (D-040), without a database: constants,
dotted-path helpers, hashes, the two templates' exact requests and answers, and the runner's
schedule (with a fake collector)."""

from __future__ import annotations

import dataclasses
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import pydantic
import pytest

from argus.collector import collector as co
from argus.collector import runner as ru
from argus.collector import store as st
from argus.collector.templates import AlertCounts, AlertStates, CountsParams, StatesParams
from argus.gateway.errors import BreakerOpenError

pytestmark = pytest.mark.unit

T0 = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)
HOUR = timedelta(hours=1)


def test_constants() -> None:
    assert (
        timedelta(minutes=5), 1000, 200, 6, timedelta(seconds=30), 2000,
    ) == (co.OVERLAP, co.PAGE, co.MGET, co.CHUNK_HOURS, co.DEADLINE, co.STATE_REFETCH)  # fmt: skip
    assert (
        timedelta(minutes=1), timedelta(minutes=1), timedelta(minutes=15), timedelta(hours=1),
    ) == (ru.PROBE_EVERY, ru.POLL_EVERY, ru.STATES_EVERY, ru.RECONCILE_EVERY)  # fmt: skip
    assert (
        timedelta(hours=24), 5.0, timedelta(minutes=1),
    ) == (ru.RECONCILE_SPAN, ru.TICK, ru.BACKFILL_RETRY)  # fmt: skip
    assert (ru.GAP_KINDS, ru.SUBJECT) == (("argus_collector_lag", "breaker_open"), "alerts")
    assert ru.log.name == "argus.collector"
    for frozen in (co.PollResult(1, 2, T0), co.CheckResult(1, (), 0, 0), st.Ingested(0, 0, 0)):
        with pytest.raises(dataclasses.FrozenInstanceError):
            frozen.x = 1  # type: ignore[attr-defined]


def test_time_helpers() -> None:
    assert co.floor_hour(T0.replace(minute=59, second=59, microsecond=9)) == T0
    assert co.epoch_ms(T0) == 1_791_547_200_000
    assert co.from_epoch_ms(1_791_547_200_123) == T0 + timedelta(milliseconds=123)
    assert co.written([{"_id": "a", "sort": [1_791_547_200_000, "a"]}, {"_id": "b"}]) == {"a": T0}


@pytest.mark.parametrize(
    ("source", "value"),
    [
        ({"a.b.c": 1}, 1),
        ({"a": {"b": {"c": 2}}}, 2),
        ({"a.b": {"c": 3}}, 3),
        ({"a": {"b.c": 4}}, 4),
        ({"a": {"x": 5}}, None),
        ({"a": 6}, None),
        ({}, None),
    ],
)
def test_dotted_and_nested_paths(source: dict[str, Any], value: Any) -> None:
    assert co.source_value(source, "a.b.c") == value
    copied = {k: (dict(v) if isinstance(v, dict) else v) for k, v in source.items()}
    assert st._pop(copied, "a.b.c") == value


def test_pop_removes_only_the_path() -> None:
    source = {"a": {"b": {"c": 1, "d": 2}}, "a.e": 3}
    assert st._pop(source, "a.b.c") == 1
    assert source == {"a": {"b": {"d": 2}}, "a.e": 3}


TRIAGE = (
    "kibana.alert.workflow_status",
    "kibana.alert.workflow_status_updated_at",
    "kibana.alert.workflow_user",
    "kibana.alert.workflow_reason",
    "kibana.alert.workflow_tags",
    "kibana.alert.workflow_assignee_ids",
    "kibana.alert.case_ids",
    "kibana.alert.status",
)  # fmt: skip  (spelled out: a test reading the code's own list follows its mistakes)


@pytest.mark.parametrize("field", TRIAGE)
def test_every_triage_field_is_state_not_content(field: str) -> None:
    assert st.STATE_FIELDS == TRIAGE
    base = {"@timestamp": "2026-10-09T12:00:00Z", "kibana.alert.workflow_status": "open"}
    content, state, status = st.split_source(base)
    changed = st.split_source({**base, field: "changed"})
    assert changed[0] == content
    assert changed[1] != state
    assert status == "open"
    assert st.split_source({**base, "kibana.alert.workflow_status": 5})[2] is None


@pytest.mark.parametrize(
    ("value", "expected"), [("r1", "r1"), (5, "5"), (2.5, "2.5"), (True, None), ("", None),
                            ({"x": 1}, None), (None, None)],
)  # fmt: skip
def test_rule_id_as_the_terms_aggregation_names_it(value: Any, expected: str | None) -> None:
    assert st._rule_id({"kibana.alert.rule.rule_id": value}) == expected
    assert st._rule_id("not a document") is None


# --------------------------------------------------------------------------- templates


def test_counts_request_and_answer() -> None:
    assert (AlertCounts.name, AlertCounts.version, AlertCounts.RULES) == ("alerts.counts", 1, 100)
    body = AlertCounts().plan(CountsParams(start=T0, hours=6)).body
    assert body == {
        "size": 0,
        "track_total_hits": False,
        "query": {"bool": {"filter": [{"range": {"@timestamp": {
            "gte": "2026-10-09T12:00:00.000Z", "lt": "2026-10-09T18:00:00.000Z"}}}]}},
        "aggs": {"hours": {
            "date_histogram": {"field": "@timestamp", "fixed_interval": "1h", "hard_bounds": {
                "min": "2026-10-09T12:00:00.000Z", "max": "2026-10-09T18:00:00.000Z"}},
            "aggs": {"rules": {"terms": {"field": "kibana.alert.rule.rule_id", "size": 100}}},
        }},
    }  # fmt: skip
    for bad in (0, 7):
        with pytest.raises(pydantic.ValidationError):
            CountsParams(start=T0, hours=bad)
    answer = {"aggregations": {"hours": {"buckets": [
        {"key": 1, "doc_count": 5, "rules": {"sum_other_doc_count": 0,
         "buckets": [{"key": "a", "doc_count": 3}, {"key": 7, "doc_count": 2}]}},
        {"key": 2, "doc_count": 4, "rules": {"sum_other_doc_count": 1, "buckets": []}},
        {"key": 3, "doc_count": 0, "rules": {"buckets": []}},
    ]}}}  # fmt: skip
    assert AlertCounts.counts(answer) == (
        {(1, "a"): 3, (1, "7"): 2}, {1: 5, 2: 4, 3: 0}, {2},
    )  # fmt: skip


def test_states_request() -> None:
    assert (AlertStates.name, AlertStates.version, AlertStates.max_size) == (
        "alerts.states", 1, 1000,
    )  # fmt: skip
    params = StatesParams(start=T0 - HOUR, end=T0)
    assert params.size == 1000
    body = AlertStates().plan(params).body
    assert body == {
        "size": 1000,
        "_source": ["kibana.alert.workflow_status"],
        "track_total_hits": False,
        "query": {"bool": {
            "filter": [{"range": {"@timestamp": {"gte": "2026-10-09T11:00:00.000Z",
                                                 "lt": "2026-10-09T12:00:00.000Z"}}}],
            "must_not": [{"term": {"kibana.alert.workflow_status": "open"}}]}},
        "sort": [{"@timestamp": {"order": "asc"}}, {"kibana.alert.uuid": {"order": "asc"}}],
    }  # fmt: skip
    after = AlertStates().plan(StatesParams(start=T0, end=T0, after=(1, "x"))).body
    assert after["search_after"] == [1, "x"]
    StatesParams(start=T0, end=T0, size=1)
    for bad in ({"size": 0}, {"size": 1001}, {"after": (1,)}, {"after": (1, 2, 3)}):
        with pytest.raises(pydantic.ValidationError):
            StatesParams(start=T0, end=T0, **bad)


# --------------------------------------------------------------------------- the runner


class FakeConn:
    pass


class FakeEngine:
    def begin(self) -> Any:
        engine = self

        class Begin:
            async def __aenter__(self) -> FakeConn:
                return FakeConn()

            async def __aexit__(self, *exc: Any) -> None:
                engine.commits += 1

        return Begin()

    commits = 0


@dataclasses.dataclass
class FakeCollector:
    now: datetime = T0
    window: timedelta = timedelta(days=5)
    engine: FakeEngine = dataclasses.field(default_factory=FakeEngine)
    calls: list[str] = dataclasses.field(default_factory=list)
    poll_error: Exception | None = None
    backfill_left: int = 0
    backfill_error: Exception | None = None
    reconciled: list[tuple[datetime, datetime]] = dataclasses.field(default_factory=list)

    def clock(self) -> datetime:
        return self.now

    async def poll(self) -> Any:
        self.calls.append("poll")
        if self.poll_error is not None:
            raise self.poll_error
        return "polled"

    async def sync_states(self) -> int:
        self.calls.append("states")
        return 0

    async def backfill_step(self) -> Any:
        self.calls.append("backfill")
        if self.backfill_error is not None:
            raise self.backfill_error
        if self.backfill_left:
            self.backfill_left -= 1
            return "chunk"
        return None

    async def reconcile(self, start: datetime, end: datetime) -> Any:
        self.calls.append("reconcile")
        self.reconciled.append((start, end))
        return co.CheckResult(3, (T0,), 2, 1)


@pytest.fixture
def gaps(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, Any]]:
    seen: list[tuple[str, Any]] = []

    async def cursor(conn: Any, name: str) -> datetime:
        return T0 - HOUR

    async def open_gap(conn: Any, kind: str, subject: str, start: datetime, detail: str) -> None:
        seen.append(("open", (kind, subject, start, detail)))

    async def close_gaps(conn: Any, kinds: Any, subject: str, end: datetime) -> int:
        seen.append(("close", (tuple(kinds), subject, end)))
        return 1 if any(s[0] == "open" for s in seen) else 0

    monkeypatch.setattr(ru.store, "cursor", cursor)
    monkeypatch.setattr(ru.store, "open_gap", open_gap)
    monkeypatch.setattr(ru.store, "close_gaps", close_gaps)
    return seen


def runner(collector: FakeCollector, **kw: Any) -> tuple[ru.Runner, list[datetime]]:
    probes: list[datetime] = []

    async def probe() -> None:
        probes.append(collector.now)

    return ru.Runner(collector, probe, **kw), probes  # type: ignore[arg-type]


async def test_the_schedule(gaps: list[Any]) -> None:
    fake = FakeCollector()
    run, probes = runner(fake, backfill_done=True)
    await run.step()
    assert fake.calls == ["poll", "states", "reconcile"]
    assert run.due == {
        "probe": T0 + ru.PROBE_EVERY,
        "poll": T0 + ru.POLL_EVERY,
        "states": T0 + ru.STATES_EVERY,
        "reconcile": T0 + ru.RECONCILE_EVERY,
    }
    fake.calls.clear()
    fake.now = T0 + timedelta(seconds=59)
    await run.step()
    assert fake.calls == []
    fake.now = T0 + timedelta(minutes=1)
    await run.step()
    assert fake.calls == ["poll"]
    assert probes == [T0, T0 + timedelta(minutes=1)]


async def test_a_failed_poll_opens_a_gap_and_recovery_reconciles(
    gaps: list[Any], caplog: pytest.LogCaptureFixture
) -> None:
    fake = FakeCollector(poll_error=BreakerOpenError(None))
    run, _ = runner(fake, backfill_done=True, due={"reconcile": T0 + HOUR})
    with caplog.at_level(logging.WARNING, logger="argus.collector"):
        assert await run.guarded_poll() is None
    assert gaps == [("open", ("breaker_open", "alerts", T0 - HOUR, "breaker_open"))]
    assert run.reconcile_from == T0 - HOUR
    assert [r.getMessage() for r in caplog.records] == ["poll failed: breaker_open"]
    fake.poll_error = RuntimeError("x")
    await run.guarded_poll()
    assert gaps[-1] == ("open", ("argus_collector_lag", "alerts", T0 - HOUR, "RuntimeError"))
    fake.poll_error = None
    fake.now = T0 + timedelta(minutes=5)
    assert await run.guarded_poll() == "polled"
    assert run.due["reconcile"] == fake.now
    await run.reconcile()
    assert fake.reconciled == [(fake.now - ru.RECONCILE_SPAN, fake.now)]
    assert run.reconcile_from is None


async def test_reconcile_covers_the_outage_but_never_beyond_the_window(gaps: list[Any]) -> None:
    fake = FakeCollector()
    run, _ = runner(fake, backfill_done=True)
    run.reconcile_from = T0 - timedelta(hours=30)
    await run.reconcile()
    assert fake.reconciled[-1] == (T0 - timedelta(hours=30), T0)
    run.reconcile_from = T0 - timedelta(days=9)
    await run.reconcile()
    assert fake.reconciled[-1] == (T0 - fake.window, T0)
    run.reconcile_from = T0 - HOUR  # later than a day ago: the day is reconciled anyway
    await run.reconcile()
    assert fake.reconciled[-1] == (T0 - ru.RECONCILE_SPAN, T0)


async def test_reconcile_logs_its_result(gaps: list[Any], caplog: pytest.LogCaptureFixture) -> None:
    run, _ = runner(FakeCollector(), backfill_done=True)
    with caplog.at_level(logging.INFO, logger="argus.collector"):
        await run.reconcile()
    assert [r.getMessage() for r in caplog.records] == [
        "reconciled 3 hours: 1 differed, 2 recovered, 1 gone from the SIEM"
    ]


async def test_backfill_then_a_full_reconcile(gaps: list[Any]) -> None:
    fake = FakeCollector(backfill_left=2)
    run, _ = runner(fake)
    await run.step()
    assert "reconcile" not in fake.calls
    assert fake.calls.count("backfill") == 1
    await run.step()
    await run.step()  # the step that finds nothing left
    assert run.backfill_done
    assert run.reconcile_from == T0 - fake.window
    assert run.due["reconcile"] == T0
    await run.step()
    assert fake.reconciled == [(T0 - fake.window, T0)]


async def test_job_failures_are_logged_and_the_loop_goes_on(
    gaps: list[Any], caplog: pytest.LogCaptureFixture
) -> None:
    fake = FakeCollector(backfill_error=RuntimeError("down"))

    async def broken() -> None:
        raise RuntimeError("probe down")

    run = ru.Runner(fake, broken)  # type: ignore[arg-type]
    with caplog.at_level(logging.INFO, logger="argus.collector"):
        await run.step()
    messages = [r.getMessage() for r in caplog.records]
    assert messages == ["collector job probe failed", "backfill step failed"]
    assert run.due["backfill"] == T0 + ru.BACKFILL_RETRY
    assert "poll" in fake.calls  # one job failing does not stop the others


async def test_run_stops_when_asked(gaps: list[Any]) -> None:
    import asyncio

    fake = FakeCollector()
    run, _ = runner(fake, backfill_done=True)
    stop = asyncio.Event()

    async def stopper() -> None:
        while "poll" not in fake.calls:  # noqa: ASYNC110 - polling a fake, briefly
            await asyncio.sleep(0.001)
        stop.set()

    await asyncio.wait_for(asyncio.gather(run.run(stop, tick=0.01), stopper()), timeout=5)
    assert fake.calls.count("poll") == 1
