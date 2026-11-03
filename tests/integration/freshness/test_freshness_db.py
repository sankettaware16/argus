"""Q-F1 on a throwaway Postgres (migration 0033), as the runtime role: readings append-only,
watermarks that only advance (also against a direct UPDATE), and the context graph in each
mode: off reads nothing, shadow stores the verdict and changes no dossier, on makes a
verified zero known with how far the logs were complete; a gap keeps it "could not tell"."""

from __future__ import annotations

import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any, ClassVar

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.context.evidence import SignalValue, derived, from_logs
from argus.context.packs import Pack, TaskSpec
from argus.context.worker import Worker, WorkerConfig
from argus.freshness import report, store
from argus.freshness.model import FAILED, OK, Reading
from argus.freshness.shadow import Policy
from argus.freshness.store import Stored
from argus.gateway.gateway import Result
from argus.gateway.templates import (
    CostClass,
    Endpoint,
    Family,
    Params,
    Purpose,
    RequestPlan,
    Template,
    Window,
    register,
)
from tests.integration.context.conftest import NOW, seed
from tests.integration.context.kit import registry

pytestmark = pytest.mark.integration
MIN = timedelta(minutes=1)
START, END = NOW - 2 * timedelta(hours=1), NOW - timedelta(hours=1)
MARGIN = 3 * MIN


class LogParams(Params):
    investigation: str
    start: datetime
    end: datetime


@register
class LogCount(Template):
    name = "test.fresh.log_count"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.LOG
    cost = CostClass.LIGHT
    params_model = LogParams

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, LogParams)
        body = {"size": 0, "track_total_hits": False, "query": {"match_all": {}}}
        return RequestPlan(self.spec(), body=body, window=Window("squid", params.start, params.end))


class LogPack(Pack):
    name = "test-fresh"
    version = 1
    family = "test"
    max_waves = 1
    budget: ClassVar[Mapping[CostClass, int]] = {CostClass.LIGHT: 4}

    def local_signals(
        self, facts: Mapping[str, Any], context: Mapping[str, Any]
    ) -> list[SignalValue]:
        return []

    def plan(
        self,
        wave: int,
        facts: Mapping[str, Any],
        context: Mapping[str, Any],
        evidence: Mapping[str, Mapping[str, Any]],
    ) -> Sequence[TaskSpec]:
        inv = str(facts["investigation_id"])
        return [TaskSpec(LogCount(), LogParams(investigation=inv, start=START, end=END))]

    def signals(
        self,
        facts: Mapping[str, Any],
        context: Mapping[str, Any],
        evidence: Mapping[str, Mapping[str, Any]],
        snapshots: Mapping[str, Any],
    ) -> list[SignalValue]:
        refs = list(evidence.values())
        return [from_logs(derived("log.hits", self.version, refs, lambda: 0, counts=True))]


class ZeroGateway:
    """Answers every log search with nothing found."""

    calls: int = 0

    async def run(
        self,
        template: Template,
        params: Params,
        *,
        purpose: Purpose,
        component: str,
        deadline: datetime,
    ) -> Result:
        self.calls += 1
        body = {
            "took": 3,
            "_shards": {"total": 1, "successful": 1, "failed": 0},
            "hits": {"total": {"value": 0, "relation": "eq"}, "hits": []},
        }
        return Result(body, 3, ("acme-logs-squid-2026.10.09",))


def ok_at(at: datetime, lag: timedelta = timedelta(seconds=5)) -> Stored:
    return Stored(Reading("squid", at, OK, at - timedelta(seconds=1), at - lag), at)


async def flowing(engine: AsyncEngine, skip: tuple[datetime, datetime] | None = None) -> None:
    async with engine.begin() as conn:
        t = START - 20 * MIN
        while t <= NOW - 5 * MIN:
            if skip is None or not skip[0] <= t <= skip[1]:
                await store.record(conn, ok_at(t))
            t += 5 * MIN


async def run(engine: AsyncEngine, saver: Any, policy: Policy | None) -> tuple[Any, Any]:
    ids = await seed(engine, [(1, "r1", "10.0.0.1")])
    gateway = ZeroGateway()
    worker = Worker(
        engine,
        saver,
        packs=registry(LogPack()),
        gateway=gateway,  # type: ignore[arg-type]
        clock=lambda: NOW,
        config=WorkerConfig(freshness=policy),
    )
    results = await worker.run_once(limit=5)
    assert {r.outcome for r in results} == {"done"}, results
    async with engine.connect() as conn:
        body = (await conn.execute(text("SELECT body FROM dossiers"))).scalar_one()
        shadow = (await conn.execute(text("SELECT * FROM freshness_shadow"))).mappings().all()
        ev = (await conn.execute(text("SELECT asked_at, source_watermark FROM evidence"))).one()
    assert ids
    signal = next(s for s in body["signals"] if s["name"] == "log.hits")
    return signal, (shadow, ev, body)


async def test_readings_are_append_only_and_watermarks_only_advance(
    app_engine: AsyncEngine,
) -> None:
    async with app_engine.begin() as conn:
        await store.record(conn, ok_at(NOW))
        await store.record(conn, ok_at(NOW - 10 * MIN))  # older ingest time: no change
        await store.record(conn, Stored(Reading("squid", NOW, FAILED), NOW, "timed_out"))
    async with app_engine.connect() as conn:
        marks = await store.watermarks(conn)
        assert marks["squid"][0] == NOW - timedelta(seconds=1)
        assert len(await store.readings(conn, "squid", NOW - MIN, NOW)) == 2
        assert (await store.latest(conn))["squid"].outcome in (OK, FAILED)
        assert (await store.latest_ok(conn))["squid"].at == NOW
    for statement in (
        "UPDATE freshness_watermarks SET ingested = ingested - interval '1 hour'",
        "UPDATE freshness_watermarks SET source = 'dns'",
    ):
        with pytest.raises(DBAPIError):
            async with app_engine.begin() as conn:
                await conn.execute(text(statement))
    for statement in (
        "UPDATE freshness_readings SET outcome = 'ok'",
        "DELETE FROM freshness_readings",
        "DELETE FROM freshness_watermarks",
    ):
        with pytest.raises(DBAPIError, match="permission denied"):
            async with app_engine.begin() as conn:
                await conn.execute(text(statement))
    async with app_engine.begin() as conn:  # moving it forward is allowed
        await conn.execute(
            text("UPDATE freshness_watermarks SET ingested = ingested + interval '1 s'")
        )


async def test_the_database_refuses_inconsistent_readings(app_engine: AsyncEngine) -> None:
    for values in (
        "('squid', now(), now(), 'ok', NULL, NULL)",  # ok without a document
        "('squid', now(), now(), 'failed', now(), now())",  # a document without ok
        "('Squid', now(), now(), 'failed', NULL, NULL)",
        "('squid', now(), now() - interval '1 s', 'failed', NULL, NULL)",
        "('squid', now(), now(), 'maybe', NULL, NULL)",
    ):
        with pytest.raises(DBAPIError):
            async with app_engine.begin() as conn:
                await conn.execute(
                    text(
                        "INSERT INTO freshness_readings (source, sent_at, at, outcome, ingested,"  # noqa: S608 - constant test rows
                        f" event_at) VALUES {values}"
                    )
                )


async def test_off_reads_nothing_and_leaves_the_zero_unknown(
    app_engine: AsyncEngine, saver: Any
) -> None:
    await flowing(app_engine)
    signal, (shadow, ev, _) = await run(
        app_engine, saver, Policy(mode="off", margins={"squid": MARGIN})
    )
    assert (signal["status"], signal["unknown_reason"]) == ("unknown", "ingest_not_verified")
    assert shadow == []
    assert ev.asked_at == NOW
    assert ev.source_watermark is None


async def test_shadow_stores_the_verdict_and_changes_no_dossier(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, saver: Any
) -> None:
    await flowing(app_engine)
    off_signal, (_, _, off_body) = await run(app_engine, saver, None)
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE dossiers, signals, evidence, evidence_requests, jobs,"
                " investigation_entities, investigation_alerts, investigations,"
                " alert_records CASCADE"
            )
        )
    signal, (shadow, ev, body) = await run(
        app_engine, saver, Policy(mode="shadow", margins={"squid": MARGIN})
    )
    assert signal == off_signal
    assert body["signals"] == off_body["signals"]
    assert body["report"] == off_body["report"]
    (row,) = shadow
    assert (row["mode"], row["verdict"], row["reason"], row["bridged_verdict"]) == (
        "shadow",
        "known_zero",
        "complete",
        "known_zero",
    )
    assert row["complete_to"] >= END
    assert row["margins"] == {"squid": 180}
    (ref,) = row["refs"]
    assert ref["source"] == "squid"
    assert ref["known"]
    assert ref["asked_at"] == NOW.isoformat()
    assert ev.source_watermark is None  # nothing on the evidence in shadow


async def test_on_makes_a_verified_zero_known_with_how_far(
    app_engine: AsyncEngine, saver: Any
) -> None:
    await flowing(app_engine)
    signal, (shadow, ev, _) = await run(
        app_engine, saver, Policy(mode="on", margins={"squid": MARGIN})
    )
    assert (signal["status"], signal["value"], signal["unknown_reason"]) == ("known", 0, None)
    assert shadow[0]["mode"] == "on"
    assert ev.source_watermark == shadow[0]["complete_to"] >= END


async def test_on_with_a_gap_or_without_a_margin_says_could_not_tell(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, saver: Any
) -> None:
    await flowing(app_engine, skip=(START + 10 * MIN, START + 25 * MIN))
    signal, (shadow, ev, _) = await run(
        app_engine, saver, Policy(mode="on", margins={"squid": MARGIN})
    )
    assert signal["status"] == "unknown"
    assert (shadow[0]["verdict"], shadow[0]["reason"]) == ("could_not_tell", "gap")
    assert ev.source_watermark is None
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text(
                "TRUNCATE dossiers, signals, evidence, evidence_requests, jobs,"
                " investigation_entities, investigation_alerts, investigations,"
                " alert_records, freshness_shadow CASCADE"
            )
        )
    signal, (shadow, _, _) = await run(
        app_engine, saver, Policy(mode="on", margins={"dns": MARGIN})
    )
    assert signal["status"] == "unknown"
    assert shadow[0]["reason"] == "no_margin"


async def test_a_broken_verdict_leaves_the_zero_unknown(
    app_engine: AsyncEngine, saver: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    await flowing(app_engine)

    async def broken(*a: Any, **k: Any) -> Any:
        raise RuntimeError("boom")

    monkeypatch.setattr(store, "readings", broken)
    signal, (shadow, _, _) = await run(
        app_engine, saver, Policy(mode="on", margins={"squid": MARGIN})
    )
    assert signal["status"] == "unknown"
    assert shadow == []


async def test_the_report_and_the_would_be_proposals(
    app_engine: AsyncEngine, saver: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    await flowing(app_engine)
    _, (_shadow, _, _body) = await run(
        app_engine, saver, Policy(mode="shadow", margins={"squid": MARGIN})
    )
    policy = Policy(mode="shadow", margins={"squid": MARGIN})
    async with app_engine.connect() as conn:
        got = await report.build(conn, policy, NOW - timedelta(days=1), NOW)
    (squid,) = got["sources"]
    assert squid["outcomes"] == {"ok": squid["readings"]}
    assert squid["margin_s"] == 180
    assert got["verdicts"] == {
        "signals": 1,
        "known_zero": 1,
        "known_zero_bridged": 1,
        "reasons": {"complete": 1},
    }

    from argus.assess import engine as engine_module
    from argus.assess.runner import Verdict

    class Fake:
        """Proposes benign exactly when log.hits is a known 0."""

        def __init__(self, learned: Any, now: datetime) -> None:
            pass

        async def assess(self, conn: Any, inv: uuid.UUID, b: Mapping[str, Any]) -> Verdict:
            hits = next(s for s in b["signals"] if s["name"] == "log.hits")
            return Verdict("benign_expected" if hits["status"] == "known" else None, "fake")

    async def no_labels(conn: Any) -> Any:
        return engine_module.Learned()

    monkeypatch.setattr(engine_module, "Engine", Fake)
    monkeypatch.setattr(engine_module, "learn", no_labels)
    async with app_engine.begin() as conn:
        counts = await report.assess(conn, NOW, bridged=False)
    assert counts == {
        "evaluated": 1,
        "benign": 1,
        "new_benign": 1,
        "gold_items": 0,
        "gold_tp_benign": 0,
        "gold_tp_benign_ids": [],
    }
    async with app_engine.connect() as conn:
        (proposal,) = await store.proposals(conn)
    assert (proposal["outcome"], proposal["actual"], proposal["signals"]) == (
        "benign_expected",
        None,
        ["log.hits"],
    )
    async with app_engine.connect() as conn:
        got = await report.build(conn, policy, NOW - timedelta(days=1), NOW)
    assert got["proposals"] == {"evaluated": 1, "benign": 1, "benign_bridged": 0, "new_benign": 1}
