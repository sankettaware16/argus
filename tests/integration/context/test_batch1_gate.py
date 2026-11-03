"""Q-F4's gate on Postgres, as the runtime role: the switch, quiet hours, NORMAL only, the
prevalence gate on values ARGUS sees too often (planted popular values are refused before
anything is sent), the daily server-time cap from the gateway's ledger; the first runs with a
fake gateway; the dry run of ``argus worker template-check`` (nothing sent)."""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine
from typer.testing import CliRunner

from argus.cli import app
from argus.context import batch1, beacon, dns, paths, source_events
from argus.context.packs import TaskSpec
from argus.gateway.gateway import Result
from argus.gateway.health import HealthMemory, HealthState
from argus.gateway.state import MemoryStore
from tests.integration.grouping.test_grouping import NOW, doc, ingest
from tests.integration.test_cli_db import cli_env  # noqa: F401

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[3]
T = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)
HISTORY = timedelta(days=5)
ON = set(batch1.TEMPLATES)


def at(h: int, m: int = 0) -> datetime:
    return datetime(2026, 10, 20, h, m, tzinfo=UTC)


def healthy(now: datetime = T, state: HealthState = HealthState.NORMAL) -> MemoryStore:
    return MemoryStore(memory=HealthMemory(state=state, probed_at=now))


def pair(host: str = "10.0.0.5", dest: str = "203.0.113.9") -> TaskSpec:
    return TaskSpec(beacon.ProxyPair(), beacon.PairParams(host=host, destination=dest,
                                                          start=at(3), end=at(8)))  # fmt: skip


def contact(dest: str = "203.0.113.9", hosts: tuple[str, ...] = ()) -> TaskSpec:
    params = beacon.ContactParams(destination=dest, hosts=hosts, start=at(1), end=at(11))
    return TaskSpec(beacon.ProxyContact(), params)


async def plant(owner: AsyncEngine, value: str, investigations: int, campus: int = 0,
                last: datetime = T) -> None:  # fmt: skip
    """``investigations`` investigations naming ``value`` (an ip entity), the first
    ``campus`` of them with one more campus address each."""
    async with owner.begin() as conn:
        for n in range(investigations):
            inv = uuid.uuid4()
            await conn.execute(
                text(
                    "INSERT INTO investigations (id, grouping_version, rule_id, group_key,"
                    " bucket_start, bucket_end, previous_id, last_event_at) VALUES (:id, 'g1',"
                    " 'r1', :k, :s, :e, :id, :last)"
                ),
                {"id": inv, "k": f"k-{value}-{n}", "s": last - timedelta(hours=2),
                 "e": last + timedelta(hours=22), "last": last},
            )  # fmt: skip
            rows = [{"i": inv, "v": value}]
            if n < campus:
                rows.append({"i": inv, "v": f"10.77.{n // 250}.{n % 250 + 1}"})
            rows.append({"i": inv, "v": "8.8.8.8"})  # a public one: never campus
            await conn.execute(
                text(
                    "INSERT INTO investigation_entities (investigation_id, kind, value)"
                    " VALUES (:i, 'ip', :v) ON CONFLICT DO NOTHING"
                ),
                rows,
            )


async def admit(engine: AsyncEngine, task: TaskSpec, **kw: Any) -> batch1.Refusal | None:
    options: dict[str, Any] = {"enabled": ON, "now": T, "history": HISTORY,
                               "is_campus": batch1.private_or(None)}  # fmt: skip
    options.update(kw)
    state = options.pop("state", healthy(options["now"]))
    async with engine.connect() as conn:
        return await batch1.admit(conn, state, task, **options)


async def test_the_switch_quiet_hours_and_health(app_engine: AsyncEngine) -> None:
    assert await admit(app_engine, pair()) is None
    assert await admit(app_engine, pair(), enabled=set()) == batch1.Refusal("off")
    assert await admit(app_engine, pair(), enabled={"proxy.contact"}) == batch1.Refusal("off")
    for quiet in (at(0), at(1, 29)):
        assert await admit(app_engine, pair(), now=quiet) == batch1.Refusal("quiet_hours")
    assert await admit(app_engine, pair(), now=at(1, 30)) is None
    for state in (HealthState.CAUTION, HealthState.DEGRADED, HealthState.STOP):
        refused = await admit(app_engine, pair(), state=healthy(T, state))
        assert refused == batch1.Refusal("not_normal", str(state))
    stale = MemoryStore(memory=HealthMemory(probed_at=T - timedelta(hours=1)))
    refused = await admit(app_engine, pair(), state=stale)
    assert refused is not None
    assert refused.code == "not_normal"
    from argus.context.proxy import ProxyHost, WindowParams

    with pytest.raises(TypeError, match="not a batch-1 template"):
        await admit(app_engine, TaskSpec(ProxyHost(), WindowParams(ip="10.0.0.1", start=at(3),
                                                                   end=at(4))))  # fmt: skip


async def test_planted_popular_values_are_refused(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await plant(migrated_engine, "203.0.113.50", 50)  # a destination in 50 investigations
    await plant(migrated_engine, "203.0.113.60", 30, campus=25)  # 25 campus hosts reach it
    await plant(migrated_engine, "203.0.113.70", 30, campus=24)
    await plant(migrated_engine, "10.0.0.66", 50)  # a shared campus address (a NAT)
    await plant(migrated_engine, "10.0.0.67", 49)
    await plant(migrated_engine, "203.0.113.80", 60, last=T - HISTORY - timedelta(hours=1))
    too = batch1.Refusal("too_common", "destination")
    assert await admit(app_engine, contact("203.0.113.50")) == too
    assert await admit(app_engine, contact("203.0.113.60")) == too
    assert await admit(app_engine, contact("203.0.113.70")) is None
    assert await admit(app_engine, contact("203.0.113.80")) is None  # all before history.window
    # watching named hosts is bounded by them: no gate on the destination
    assert await admit(app_engine, contact("203.0.113.50", ("10.0.0.5",))) is None
    host = batch1.Refusal("too_common", "host")
    assert await admit(app_engine, pair("10.0.0.66", "203.0.113.50")) == host
    assert await admit(app_engine, pair("10.0.0.67", "203.0.113.50")) is None
    domains = TaskSpec(dns.DnsHostDomains(), dns.DomainsParams(ip="10.0.0.66", start=at(2),
                                                               end=at(4)))  # fmt: skip
    assert await admit(app_engine, domains) == host
    tried = paths.PathParams(ip="198.51.100.7", site="s.example.org", paths=("/.env", "/"),
                             start=at(3), end=at(4))  # fmt: skip
    web = TaskSpec(paths.WebPathOutcomes(), tried)
    assert await admit(app_engine, web) == batch1.Refusal("too_common", "path")
    rows = TaskSpec(source_events.LogsSourceEvents(), source_events.SourceParams(
        source="squid", ip="10.0.0.66", start=at(3), end=at(4)))  # fmt: skip
    assert await admit(app_engine, rows) is None  # rows, not an aggregation: no gate
    # with the asset map's classes, only its campus classes count
    public = batch1.private_or(lambda v: "public")
    assert await admit(app_engine, contact("203.0.113.60"), is_campus=public) is None
    async with app_engine.connect() as conn:
        seen = await batch1.prevalence(conn, batch1.Key("destination", "203.0.113.60"),
                                       T - HISTORY, batch1.private_or(None))  # fmt: skip
        path = await batch1.prevalence(conn, batch1.Key("path", "/"), T - HISTORY,
                                       batch1.private_or(None))  # fmt: skip
    assert seen == batch1.Prevalence(30, 25)
    assert path == batch1.Prevalence(0, 0)


async def test_very_many_addresses_beside_a_destination_are_common(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    await plant(migrated_engine, "203.0.113.90", 6, campus=3)  # 3 campus + 8.8.8.8 beside it
    monkeypatch.setattr(batch1, "CO_ADDRESSES", 4)
    async with app_engine.connect() as conn:
        seen = await batch1.prevalence(conn, batch1.Key("destination", "203.0.113.90"),
                                       T - HISTORY, batch1.private_or(None))  # fmt: skip
    assert seen == batch1.Prevalence(6, batch1.HOSTS_LIMIT)
    monkeypatch.setattr(batch1, "CO_ADDRESSES", 5)
    async with app_engine.connect() as conn:
        seen = await batch1.prevalence(conn, batch1.Key("destination", "203.0.113.90"),
                                       T - HISTORY, batch1.private_or(None))  # fmt: skip
    assert seen == batch1.Prevalence(6, 3)
    monkeypatch.setattr(batch1, "HOSTS_LIMIT", 2)  # counting stops at the limit
    async with app_engine.connect() as conn:
        seen = await batch1.prevalence(conn, batch1.Key("destination", "203.0.113.90"),
                                       T - HISTORY, batch1.private_or(None))  # fmt: skip
    assert seen == batch1.Prevalence(6, 2)


async def test_nothing_is_sent_for_a_refused_request(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    """The gate runs before the gateway: a refused task never reaches it (the caller sends
    only on None), so the ledger stays empty."""
    await plant(migrated_engine, "203.0.113.50", 50)
    sent: list[Any] = []

    async def run(task: TaskSpec) -> None:
        refused = await admit(app_engine, task)
        if refused is None:
            sent.append(task)

    await run(contact("203.0.113.50"))
    await run(pair())
    assert [(type(t.template).name, t.params) for t in sent] == [("proxy.pair", pair().params)]


async def ledger(owner: AsyncEngine, template: str, took: int, when: datetime) -> None:
    async with owner.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO siem_requests (at, component, purpose, template, version, indices,"
                " outcome, took_ms, elapsed_ms, response_bytes, attempts) VALUES (:at,"
                " 'enrichment', 'enrich', :t, 1, ARRAY['x'], 'ok', :took, :took, 10, 1)"
            ),
            {"at": when, "t": template, "took": took},
        )


async def test_the_daily_server_time_cap(
    app_engine: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await ledger(migrated_engine, "proxy.pair", 60_000, at(0, 5) - timedelta(days=1))  # yesterday
    await ledger(migrated_engine, "proxy.pair", 89_999, at(2))
    assert await admit(app_engine, pair()) is None
    await ledger(migrated_engine, "proxy.pair", 1, at(3))
    assert await admit(app_engine, pair()) == batch1.Refusal("daily_cap")
    assert await admit(app_engine, contact()) is None  # each template has its own cap
    tomorrow = at(2) + timedelta(days=1)
    assert await admit(app_engine, pair(), now=tomorrow) is None
    async with app_engine.connect() as conn:
        assert await batch1.spent_today(conn, "proxy.pair", T) == 90_000
        assert await batch1.spent_today(conn, "dns.host_domains", T) == 0


# ----------------------------------------------------------------------------- first runs


class Fake:
    def __init__(self, took: int = 120) -> None:
        self.took = took
        self.asked: list[tuple[str, Any]] = []

    async def run(self, template: Any, params: Any) -> Result:
        self.asked.append((template.name, params))
        body = {"aggregations": {"beats": {"buckets": [{"key": 1, "doc_count": 2}]},
                                 "requests": {"value": 2}}}  # fmt: skip
        return Result(body, self.took, ("x",))


def squid(n: int, src: str, dst: str) -> dict[str, Any]:
    d = doc(n, "r1", src, NOW)
    d["_source"]["destination"] = {"ip": dst}
    d["_source"]["kibana.alert.rule.indices"] = ["acme-logs-squid-*"]
    return d


def nginx(n: int, src: str) -> dict[str, Any]:
    d = doc(n, "r2", src, NOW)
    d["_source"]["kibana.alert.rule.indices"] = ["acme-logs-nginx-*"]
    d["_source"]["url"] = {"domain": "s.example.org", "path": "/.env"}
    return d


async def test_the_subject_of_the_source_events_run(app_engine: AsyncEngine) -> None:
    raw = json.loads((ROOT / "tests/fixtures/alerts" /
                      "threshold__proxy_excessive_blocked_requests_from_single_host.json"
                      ).read_text())  # fmt: skip
    raw |= {"_id": raw["_source"]["kibana.alert.uuid"], "found": True}  # stored by its uuid
    await ingest(app_engine, [raw])
    async with app_engine.connect() as conn:
        who = await batch1.subjects(conn)
    assert who["host"] == "10.43.119.92"  # a flat source.ip, as threshold alerts write it
    assert who["destination"] is None
    norm, indices = who["alert"]
    assert (norm["rule_type"], indices) == ("threshold", ["acme-logs-squid*"])
    task = batch1.first_task("logs.source_events", who, NOW)
    assert isinstance(task, TaskSpec)
    assert task.params == source_events.SourceParams(
        source="squid", ip="10.43.119.92", start=datetime(2026, 10, 9, 12, 16, 48, tzinfo=UTC),
        end=datetime(2026, 10, 9, 12, 19, 20, tzinfo=UTC))  # fmt: skip


async def test_subjects_and_first_runs(app_engine: AsyncEngine) -> None:
    await ingest(app_engine, [squid(1, "8.8.4.4", "10.9.9.9"), squid(2, "10.8.0.5", "45.9.9.9"),
                              nginx(3, "45.1.2.3")])  # fmt: skip
    async with app_engine.connect() as conn:
        who = await batch1.subjects(conn)
    assert (who["host"], who["destination"]) == ("10.8.0.5", "45.9.9.9")
    assert who["pair"] == ("10.8.0.5", "45.9.9.9")  # both from one alert (review F4-R6)
    assert who["web"] == ("45.1.2.3", "s.example.org", ["/.env"])
    assert who["alert"] is None  # no threshold or ES|QL alert stored
    fake = Fake()
    async with app_engine.connect() as conn:
        lines = await batch1.first_run(conn, fake.run, "proxy.pair", at(16, 20))
        assert lines == [
            "proxy.pair: squid, 2026-10-20 04:05 to 16:05 UTC (12 h 00 min)",
            "proxy.pair: 120 ms server time (limit 10000 ms); beats 1 buckets, requests set",
            "FIRST RUN PASSED",
        ]
        slow = Fake(3_001)
        lines = await batch1.first_run(conn, slow.run, "web.path_outcomes", at(16, 20))
        assert lines[-2:] == [
            "web.path_outcomes: 3001 ms server time (limit 3000 ms), too slow: it stays off;"
            " beats 1 buckets, requests set",
            "FIRST RUN FAILED",
        ]
        assert await batch1.first_run(conn, fake.run, "logs.source_events", at(16, 20)) == [
            "logs.source_events: there is nothing this check could be asked about (no subject)",
            "FIRST RUN FAILED",
        ]
        assert (await batch1.first_run(conn, fake.run, "dns.host_domains", at(0, 30)))[-1] == (
            "FIRST RUN FAILED")  # fmt: skip

        async def refuse(task: TaskSpec) -> batch1.Refusal:
            return batch1.Refusal("too_common", "host")

        refused = await batch1.first_run(conn, fake.run, "proxy.pair", at(16, 20), refuse)
        assert refused == ["proxy.pair: could not tell: too common to query (host)",
                           "FIRST RUN FAILED"]  # fmt: skip
    assert [name for name, _ in fake.asked] == ["proxy.pair"]  # nothing sent when refused


async def cli(*args: str, given: str | None = None) -> tuple[int, str]:
    def invoke() -> tuple[int, str]:
        result = CliRunner().invoke(app, list(args), input=given)
        return result.exit_code, result.output + result.stderr

    return await asyncio.to_thread(invoke)  # the CLI runs its own event loop


@pytest.mark.usefixtures("cli_env")
async def test_the_dry_run_sends_nothing(app_engine: AsyncEngine) -> None:
    await ingest(app_engine, [squid(1, "10.8.0.5", "45.9.9.9")])
    code, out = await cli("worker", "template-check", "proxy.contact", "--dry-run")
    assert code == 0, out
    assert out.startswith("dry run: nothing sent. proxy.contact@1, cost heavy, limit 10000 ms,"
                          " window squid, ")  # fmt: skip
    assert " 01:00 to 22:59 UTC (21 h 59 min)\nPOST /acme-logs-squid-" in out  # a whole day
    assert '"destination.ip": "45.9.9.9"' in out
    assert '"timeout": "10s"' in out
    code, out = await cli("worker", "template-check", "proxy.host", "--dry-run")
    assert code == 2
    assert "proxy.host is not a batch-1 template" in out
    code, out = await cli("worker", "template-check", "logs.source_events", "--dry-run")
    assert code == 0
    assert out.strip() == (
        "logs.source_events: there is nothing this check could be asked about (no subject)"
    )


@pytest.mark.usefixtures("cli_env")
async def test_the_run_needs_the_confirm_word(app_engine: AsyncEngine) -> None:
    code, out = await cli("worker", "template-check", "proxy.pair", given="nope\n")
    assert code == 2
    assert "not confirmed: nothing was sent" in out
