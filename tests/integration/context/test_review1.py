"""R8 adversarial review, round 1: each finding as a test, shown failing before its fix."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Any

import pytest
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.context.evidence import extract
from argus.context.packs import StubPack
from argus.context.worker import Worker
from argus.gateway.errors import StoppedError
from argus.gateway.gateway import Result
from argus.gateway.templates import Params, Purpose, Template
from argus.jobs import queue
from tests.integration.context.conftest import NOW, seed
from tests.integration.context.kit import FakeGateway, dossiers, registry, scalar

pytestmark = pytest.mark.integration


def make(engine: AsyncEngine, saver: AsyncPostgresSaver, gateway: Any, at: Any = NOW) -> Worker:
    return Worker(engine, saver, packs=registry(), gateway=gateway, clock=lambda: at)


# 1 (high): the deferral backoff overflowed Postgres intervals after ~38 deferrals.
async def test_a_long_outage_keeps_deferring_and_reaches_the_24h_path(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    async with app_engine.begin() as conn:
        await conn.execute(text("UPDATE jobs SET deferrals = 150, deferred_since = :t"),
                           {"t": NOW - timedelta(hours=23)})  # fmt: skip
    gateway = FakeGateway(fail={n: StoppedError("x") for n in range(200)})
    (result,) = await make(app_engine, saver, gateway).run_once()
    assert result.outcome == "deferred"
    after = await scalar(app_engine, "SELECT run_after FROM jobs")
    assert after == NOW + queue.DEFER_MAX
    later = NOW + timedelta(hours=1, minutes=1)
    (result,) = await make(app_engine, saver, gateway, at=later).run_once()
    assert (result.outcome, result.detail) == ("done", "evidence_failed")
    (d,) = await dossiers(app_engine)
    assert d.partial_reason == "context_partial"


async def test_one_jobs_settle_error_does_not_kill_the_loop(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver, monkeypatch: pytest.MonkeyPatch
) -> None:
    await seed(app_engine, [(1, "r1", "10.0.0.1"), (2, "r2", "10.0.0.2")])
    worker = make(app_engine, saver, FakeGateway(fail={0: StoppedError("x")}))

    async def broken(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("settle failed")

    monkeypatch.setattr(queue, "defer", broken)
    results = await worker.run_once()
    assert sorted(r.outcome for r in results) == ["lost", "lost"]
    stop = asyncio.Event()
    loop = asyncio.create_task(worker.run_forever(stop))
    await asyncio.sleep(0.3)
    assert not loop.done()  # still running
    stop.set()
    await asyncio.wait_for(loop, 5)


# 2 (high): a NUL in a remote document could not be stored; every retry asked the SIEM again.
class NulGateway(FakeGateway):
    async def run(self, template: Template, params: Params, *, purpose: Purpose,
                  component: str, deadline: Any) -> Result:  # fmt: skip
        self.calls.append(0)
        body = {"hits": {"total": {"value": 1}, "hits": [
            {"_index": "i", "_id": "1", "_source": {"url": "http://x/a\x00b\ud800"}}]}}  # fmt: skip
        return Result(body, 5, ("alerts",))


async def test_unstorable_characters_are_stored_once_without_repeating_the_call(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    gateway = NulGateway()
    (result,) = await make(app_engine, saver, gateway).run_once()
    assert result.outcome == "done"
    assert len(gateway.calls) == 6 + 1  # each task once (every count is 1: one wave-2 task)
    url = await scalar(app_engine, "SELECT snapshot -> 'rows' -> 0 -> '_source' ->> 'url'"
                                   " FROM evidence LIMIT 1")  # fmt: skip
    assert url == "http://x/a�b�"


def test_extract_cleans_and_hashes_deterministically() -> None:
    body = {"hits": {"total": {"value": 1}, "hits": [{"_source": {"a\x00": "\ud800x"}}]}}
    got = extract(body, max_rows=5, max_bytes=1000)
    assert got.snapshot["rows"][0]["_source"] == {"a�": "�x"}
    assert got.result_hash == extract(body, max_rows=1, max_bytes=50).result_hash


# 3 (medium): an aggregation-only answer was stored as empty (a known zero).
def test_an_aggregation_answer_without_a_total_is_ok_not_empty() -> None:
    got = extract({"hits": {"hits": []}, "aggregations": {"x": {"value": 7}}},
                  max_rows=5, max_bytes=1000)  # fmt: skip
    assert got.has_data
    nothing = extract({"hits": {"hits": []}}, max_rows=5, max_bytes=1000)
    assert not nothing.has_data
    counted = extract({"hits": {"total": {"value": 0}, "hits": []}, "aggregations": {"x": {}}},
                      max_rows=5, max_bytes=1000)  # fmt: skip
    assert not counted.has_data  # a total of 0 says no matching document


def test_the_snapshot_says_whether_it_holds_every_matching_row() -> None:
    two_of_five = {"hits": {"total": {"value": 5}, "hits": [{"_source": {}}, {"_source": {}}]}}
    got = extract(two_of_five, max_rows=50, max_bytes=10_000)
    assert got.snapshot["total"] == 5
    assert got.snapshot["rows_complete"] is False
    all_of_them = extract({"hits": {"total": {"value": 1}, "hits": [{"_source": {}}]}},
                          max_rows=50, max_bytes=10_000)  # fmt: skip
    assert all_of_them.snapshot["rows_complete"] is True


# 5 (low-medium): a job that kills its worker every time was reclaimed for ever.
async def test_a_job_whose_worker_keeps_dying_is_given_up(app_engine: AsyncEngine) -> None:
    await seed(app_engine, [(1, "r1", "10.0.0.1")])
    now = NOW
    for _ in range(queue.MAX_LOST + 1):
        async with app_engine.begin() as conn:
            claims = await queue.claim(conn, "dies", now)
        if not claims:
            break
        now += queue.LEASE + timedelta(seconds=1)  # the worker died: its lease expires
    async with app_engine.begin() as conn:
        assert await queue.claim(conn, "next", now) == []
    assert await scalar(app_engine, "SELECT status FROM jobs") == "failed"
    error = await scalar(app_engine, "SELECT error FROM jobs")
    assert error == f"gave up: the worker died {queue.MAX_LOST} times while running it"


# 6 (low): related_investigations claimed exact while supernodes hid part of it.
def test_related_count_is_a_lower_bound_when_supernodes_were_left_out() -> None:
    facts = {"alert_count": 1, "duplicate_count": 0, "late_arrivals": 0, "span_minutes": 0,
             "entity_counts": {}}  # fmt: skip
    signals = {s.name: s for s in StubPack().local_signals(
        facts, {"related_total": 3, "continues": None, "supernode_entities": 2})}  # fmt: skip
    assert (
        signals["related_investigations"].completeness,
        signals["related_investigations"].value,
    ) == ("lower_bound", 3)
    signals = {s.name: s for s in StubPack().local_signals(
        facts, {"related_total": 0, "continues": None, "supernode_entities": 2})}  # fmt: skip
    assert signals["related_investigations"].status == "unknown"
    signals = {s.name: s for s in StubPack().local_signals(
        facts, {"related_total": 0, "continues": None, "supernode_entities": 0})}  # fmt: skip
    assert (signals["related_investigations"].status, signals["related_investigations"].value) == (
        "known",
        0,
    )
