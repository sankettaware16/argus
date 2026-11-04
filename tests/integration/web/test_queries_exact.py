"""The Inbox's R15 read functions, exactly (mutation testing): warnings, alert columns and
fields, coverage windows, the dossier as shown, the glossary, patterns, health."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web import queries
from tests.integration.context.test_generic import alert
from tests.integration.grouping.test_grouping import ingest
from tests.integration.web.conftest import NOW
from tests.integration.web.test_r15 import investigate, saver  # noqa: F401 - fixture

pytestmark = pytest.mark.integration

T = datetime(2026, 10, 13, 0, 16, tzinfo=UTC)


@pytest.mark.parametrize(("code", "words"), list(queries.LAG_WORDS.items()))
def test_every_gap_reason_reads_plainly(code: str, words: str) -> None:
    gap = {"kind": "argus_collector_lag", "start_at": T, "end_at": None, "detail": code}
    (got,) = queries.banners([gap])
    assert got == {"kind": "argus_collector_lag", "start_at": T, "end_at": None,
                   "text": f"ARGUS was not collecting ({words})"}  # fmt: skip


def test_the_words_of_each_reason() -> None:
    assert queries.LAG_WORDS == {
        "deadline_passed": "a request ran out of time",
        "deferred": "the SIEM was busy, so ARGUS waited",
        "breaker_open": "the SIEM was overloaded, so ARGUS waited",
        "overloaded": "the SIEM was overloaded, so ARGUS waited",
        "skipped_budget": "ARGUS's daily SIEM budget was used up",
        "stopped": "collection was stopped by the kill switch",
        "transport_failure": "the SIEM could not be reached",
        "timed_out": "the SIEM did not answer in time",
        "auth_failed": "the SIEM refused ARGUS's key",
        "siem_error": "the SIEM answered with an error",
        "response_error": "the SIEM's answer could not be read",
        "partial_result": "the SIEM's answer was incomplete",
    }
    (breaker,) = queries.banners([{"kind": "breaker_open", "start_at": T, "end_at": T}])
    assert breaker["text"] == "the SIEM was overloaded"
    (bare,) = queries.banners([{"kind": "argus_collector_lag", "start_at": T, "end_at": T}])
    assert bare["text"] == "ARGUS was not collecting"


def test_runs_at_the_limit_keep_order_and_an_open_last_run() -> None:
    runs = [{"kind": "truncated_execution", "start_at": T + timedelta(hours=h),
             "end_at": None if h == 2 else T + timedelta(hours=h), "detail": None}
            for h in range(3)]  # fmt: skip
    lag = {"kind": "argus_collector_lag", "start_at": T + timedelta(hours=5), "end_at": None}
    got = queries.banners([runs[0], lag, runs[1], runs[2]])
    assert [g["kind"] for g in got] == ["argus_collector_lag", "truncated_execution"]
    assert got[1]["start_at"] == T
    assert got[1]["end_at"] == T + timedelta(hours=2)  # the last run's start: still open
    assert got[1]["runs"] == runs
    assert "runs" not in got[0]
    (one,) = queries.banners(runs[:1])
    assert (
        one["text"] == "the rule hit its alert limit in 1 run: more alerts may exist for those runs"
    )


def doc(n: int, **source: Any) -> dict[str, Any]:
    d = alert(n)
    d["_source"].update(source)
    return d


async def only(engine: AsyncEngine) -> uuid.UUID:
    async with engine.connect() as conn:
        found: uuid.UUID = (await conn.execute(text("SELECT id FROM investigations"))).scalar_one()
        return found


async def test_alert_fields_and_columns_exactly(app_engine: AsyncEngine) -> None:
    docs = [
        doc(1, probe={"code": 200}, tags=["a", "b"], zz=None),
        doc(2, probe={"code": 404, "bytes": 3450}, tags=[], zz={"y": 1.5}),
        doc(3, long={"text": "x" * 300}),
    ]
    await ingest(app_engine, docs)
    inv = await only(app_engine)
    async with app_engine.connect() as conn:
        fields = dict(await queries.alert_fields(conn, inv))
        got = await queries.alerts(conn, inv, columns=["probe.code", "tags",
                                                       "zz.y", "long.text", "nope"])  # fmt: skip
        plain = await queries.alerts(conn, inv)
        few = await queries.alerts(conn, inv, limit=2)
    assert fields["probe.code"] == 2
    assert fields["probe.bytes"] == 1
    assert fields["tags"] == 1  # an empty list is no value
    assert fields["zz.y"] == 1
    assert "zz" not in fields  # a null is no value
    names = list(fields)
    assert names == sorted(names, key=lambda n: (n.startswith("kibana."), n))
    assert names[-1].startswith("kibana.")
    by_id = {a["alert_id"]: a["cols"] for a in got}
    first, second, third = (by_id[d["_id"]] for d in docs)
    assert first == {"probe.code": "200", "tags": "a, b", "zz.y": "",
                     "long.text": "", "nope": ""}  # fmt: skip
    assert second["probe.code"] == "404"
    assert second["zz.y"] == "1.5"
    assert third["long.text"] == "x" * 200
    assert [a["cols"] for a in plain] == [{}, {}, {}]
    assert "raw" not in plain[0]
    assert "raw" not in got[0]
    assert len(few) == 2
    assert [a["alert_id"] for a in plain] == [d["_id"] for d in sorted(
        docs, key=lambda d: d["_source"]["@timestamp"], reverse=True)]  # fmt: skip


async def test_alert_fields_read_the_newest_200(app_engine: AsyncEngine) -> None:
    docs = [doc(n, **({"old": 1} if n < 5 else {})) for n in range(205)]
    for n, d in enumerate(docs):  # n = 0 is the oldest
        at = (NOW - timedelta(hours=5) + timedelta(seconds=n)).isoformat()
        d["_source"]["@timestamp"] = d["_source"]["kibana.alert.original_time"] = at
    await ingest(app_engine, docs)
    inv = await only(app_engine)
    async with app_engine.connect() as conn:
        fields = dict(await queries.alert_fields(conn, inv))
    assert queries.FIELD_SAMPLE == 200
    assert "old" not in fields  # only the five oldest have it
    assert fields["source.ip"] == 200


async def gap(owner: AsyncEngine, kind: str, subject: str, start: datetime,
              end: datetime | None, detail: str = "") -> None:  # fmt: skip
    async with owner.begin() as conn:
        await conn.execute(
            text("INSERT INTO coverage_gaps (kind, subject, start_at, end_at, detail)"
                 " VALUES (:k, :s, :a, :b, :d)"),
            {"k": kind, "s": subject, "a": start, "b": end, "d": detail or None},
        )  # fmt: skip


async def test_coverage_takes_the_gaps_over_the_investigations_time(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await ingest(app_engine, [doc(1), doc(2)])
    inv_id = await only(app_engine)
    async with app_engine.connect() as conn:
        inv = await queries.investigation(conn, inv_id)
        assert inv is not None
        written = (await conn.execute(text(
            "SELECT min(detected_at), max(detected_at) FROM alert_records"))).one()  # fmt: skip
    first = min(inv.first_event_at, written[0])  # type: ignore[type-var]
    last = max(inv.last_event_at, written[1])  # type: ignore[type-var]
    hour = timedelta(hours=1)
    await gap(migrated_engine, "argus_collector_lag", "alerts", first - hour, first)  # ends at
    await gap(migrated_engine, "argus_collector_lag", "alerts", last, last + hour, "deferred")
    await gap(migrated_engine, "argus_collector_lag", "alerts", first - 2 * hour,
              first - timedelta(seconds=1))  # before: not shown  # fmt: skip
    await gap(migrated_engine, "truncated_execution", f"rule:{inv.rule_id}:execution:x",
              first, first)  # fmt: skip
    await gap(migrated_engine, "truncated_execution", "rule:other:execution:y", first, first)
    await gap(migrated_engine, "argus_collector_lag", "alerts", last + timedelta(seconds=1),
              None)  # after (and still open): not shown  # fmt: skip
    async with app_engine.connect() as conn:
        shown = await queries.coverage(conn, inv)
    assert [(g["kind"], g["start_at"]) for g in shown] == [
        ("argus_collector_lag", first - hour),
        ("truncated_execution", first),
        ("argus_collector_lag", last),
    ]
    assert shown[2]["detail"] == "deferred"
    assert shown[2]["end_at"] == last + hour


async def test_the_dossier_as_shown(app_engine: AsyncEngine, saver: AsyncPostgresSaver) -> None:  # noqa: F811
    docs = [doc(1), doc(2)]
    other = alert(3, rule="r2")
    await investigate(app_engine, saver, [*docs, other])
    async with app_engine.connect() as conn:
        rows = (await conn.execute(text(
            "SELECT id, rule_id FROM investigations ORDER BY rule_id"))).all()  # fmt: skip
        mine = next(r.id for r in rows if r.rule_id == "r1")
        theirs = next(r.id for r in rows if r.rule_id == "r2")
        shown = await queries.dossier(conn, mine)
        assert await queries.dossier(conn, uuid.uuid4()) is None
    assert shown is not None
    assert shown["pack"].startswith("generic@")
    body = shown["body"]
    assert shown["report"] == body["report"]
    assert shown["fields"] == body["context"]["pack"]["fields"]
    assert shown["ips"] == body["context"]["pack"]["ips"]
    assert len(shown["sentences"]) == len(body["local_signals"]) + len(body["signals"])
    assert any(s.startswith("Distinct IP addresses: ") for s in shown["sentences"])
    (related,) = shown["related"]
    assert related["investigation_id"] == str(theirs)
    assert related["rule_name"] == "Rule r2"
    assert related["key_fields"] == [("source.ip", "10.0.0.1")]
    assert related["shared"] >= 1


def test_the_glossary() -> None:
    got = queries.glossary()
    labels = [g["label"] for g in got]
    assert labels == sorted(labels, key=str.lower)
    assert "Distinct values" in labels
    assert not any("{" in label for label in labels)
    (entities,) = [g for g in got if g["name"] == "entities.*"]
    assert entities["how"].startswith("How many different")


async def test_patterns_group_the_same_findings(
    app_engine: AsyncEngine,
    saver: AsyncPostgresSaver,  # noqa: F811
) -> None:
    hosts = []
    for n in range(3):
        d = doc(n + 1)
        d["_source"]["source"]["ip"] = f"10.0.1.{n}"
        hosts.append(d)
    lone = alert(9, rule="r3")
    await investigate(app_engine, saver, [*hosts, lone])
    async with app_engine.connect() as conn:
        got = await queries.patterns(conn)
        assert await queries.patterns(conn, limit=1) == []  # one investigation: no group
    (group,) = got
    assert group["rule_id"] == "r1"
    assert len(group["members"]) == 3
    assert group["alerts"] == 3
    assert group["listed"] is False
    assert all(m["latest"] is None for m in group["members"])
    async with app_engine.connect() as conn:
        r1 = {str(r.id) for r in await conn.execute(text(
            "SELECT id FROM investigations WHERE rule_id = 'r1'"))}  # fmt: skip
        query = text(
            "SELECT body -> 'report' -> 'steps' FROM dossiers d JOIN investigations i"
            " ON i.id = d.investigation_id WHERE i.rule_id = 'r1' LIMIT 1"
        )
        steps = (await conn.execute(query)).scalar_one()
    assert {m["id"] for m in group["members"]} == r1
    assert group["steps"] == [s["status"] for s in steps]
    assert group["rule_name"] == "Rule r1"


async def test_health_counts(app_engine: AsyncEngine, migrated_engine: AsyncEngine) -> None:
    await ingest(app_engine, [doc(1), doc(2)])
    async with migrated_engine.begin() as conn:
        await conn.execute(text("UPDATE jobs SET status = 'failed'"))
        await conn.execute(text(
            "INSERT INTO coverage_gaps (kind, subject, start_at) VALUES"
            " ('argus_collector_lag', 'alerts', :t)"), {"t": T})  # fmt: skip
    async with app_engine.connect() as conn:
        h = await queries.health(conn, NOW)
    assert (h["alerts"], h["quarantined"], h["investigations"]) == (2, 0, 1)
    assert (h["jobs_waiting"], h["jobs_deferred"], h["jobs_failed"]) == (0, 0, 1)
    assert (h["dossiers"], h["checkpoint_threads"]) == (0, 0)
    assert h["checkpoint_bytes"] >= 0
    assert [g["kind"] for g in h["open_gaps"]] == ["argus_collector_lag"]
    assert h["last_reconciliation"] is None
    assert h["live_cursor"] is None


async def _cycle(engine: AsyncEngine, started: datetime, outcome: str, reason: str | None) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO kibana_sync_cycles (started_at, finished_at, outcome, reason, reads,"
                " changed, findings, stale) VALUES (:s, :f, :o, :r, 3, 0, 0, false)"
            ),
            {"s": started, "f": started + timedelta(seconds=20), "o": outcome, "r": reason},
        )


async def test_health_kibana_sync_from_the_newest_cycle(
    web_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    async with web_engine.connect() as conn:  # the web's own login reads the cycles
        h = await queries.health(conn, NOW)
    assert h["kibana_sync"] == {"state": "none", "last_cycle_at": None, "last_outcome": None,
                                "last_reason": None, "last_complete_at": None}  # fmt: skip
    await _cycle(migrated_engine, NOW - timedelta(minutes=50), "complete", None)
    await _cycle(migrated_engine, NOW - timedelta(minutes=10), "partial", "budget")
    async with web_engine.connect() as conn:
        s = (await queries.health(conn, NOW))["kibana_sync"]
    assert s["state"] == "partial"
    assert (s["last_outcome"], s["last_reason"]) == ("partial", "budget")
    assert s["last_cycle_at"] == NOW - timedelta(minutes=10) + timedelta(seconds=20)
    assert s["last_complete_at"] == NOW - timedelta(minutes=50) + timedelta(seconds=20)
    async with web_engine.connect() as conn:
        late = (await queries.health(conn, NOW + timedelta(hours=2)))["kibana_sync"]
    assert late["state"] == "late"
