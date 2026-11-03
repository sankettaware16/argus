"""The log templates' live check (D-068), with a fake gateway: the hour it reads, the subjects
it takes from the stored alerts, passing and failing."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.context import live_check
from argus.gateway.gateway import Result
from tests.integration.grouping.test_grouping import NOW, doc, ingest

pytestmark = pytest.mark.integration


def at(h: int, m: int = 0) -> datetime:
    return datetime(2026, 10, 14, h, m, tzinfo=UTC)


def test_the_hour_it_reads() -> None:
    assert live_check.window(at(16, 20)) == (at(15), at(16))
    assert live_check.window(at(16, 14)) == (at(14), at(15))  # the 15 min ingest margin
    for quiet in (at(0), at(0, 59), at(1, 29)):
        got = live_check.window(quiet)
        assert isinstance(got, str)
        assert got.startswith("00:00 to 01:30 UTC")
    for edge in (at(1, 30), at(2, 14), at(23, 15), at(23, 55)):  # the hour pads into a neighbour
        assert live_check.window(edge) == (
            "the last hour touches midnight's index change: try between 02:15 and 23:14 UTC"
        )
    assert live_check.window(at(2, 15)) == (at(1), at(2))
    assert live_check.window(at(23, 14)) == (at(21), at(22))


class Fake:
    def __init__(self, took: dict[str, int] | None = None) -> None:
        self.took = took or {}
        self.asked: list[tuple[str, Any]] = []

    async def run(self, template: Any, params: Any) -> Result:
        self.asked.append((template.name, params))
        if template.name == "web.followups":
            body: dict[str, Any] = {"hits": {"hits": [{}, {}]}}
        else:
            body = {"aggregations": {"destination_count": {"value": 7},
                                     "destinations": {"buckets": [{}, {}]}}}  # fmt: skip
        return Result(body, self.took.get(template.name, 120), ("x",))


def squid(n: int, src: str, dst: str) -> dict[str, Any]:
    d = doc(n, "r1", src, NOW)
    d["_source"]["destination"] = {"ip": dst}
    d["_source"]["kibana.alert.rule.indices"] = ["acme-logs-squid-*"]
    return d


def nginx(n: int, src: str) -> dict[str, Any]:
    d = doc(n, "r2", src, NOW)
    d["_source"]["kibana.alert.rule.indices"] = ["acme-logs-nginx-*"]
    return d


async def test_subjects_from_the_stored_alerts(app_engine: AsyncEngine) -> None:
    await ingest(app_engine, [squid(1, "8.8.4.4", "10.9.9.9"),  # wrong way round: skipped
                              squid(2, "10.8.0.5", "45.9.9.9"), nginx(3, "45.1.2.3")])  # fmt: skip
    async with app_engine.connect() as conn:
        got = await live_check.subjects(conn)
    assert got == {"host": "10.8.0.5", "destination": "45.9.9.9", "client": "45.1.2.3"}


async def test_passing_and_failing(app_engine: AsyncEngine) -> None:
    await ingest(app_engine, [squid(1, "10.8.0.5", "45.9.9.9"), nginx(2, "45.1.2.3")])
    fake = Fake()
    async with app_engine.connect() as conn:
        web = await live_check.check(conn, fake.run, at(16, 20), part="web")
        proxy = await live_check.check(conn, fake.run, at(16, 20), part="proxy")
    assert web[-1] == proxy[-1] == "LIVE CHECK PASSED"
    assert [name for name, _ in fake.asked] == ["web.followups", "proxy.host",
                                                "proxy.destination"]  # fmt: skip
    (_, follow), (_, host), (_, dest) = fake.asked
    assert (follow.start, follow.end, follow.size) == (at(15, 45), at(16), 10)  # live limits
    assert (host.start, host.end) == (dest.start, dest.end) == (at(15), at(16))
    assert [follow.ip, host.ip, dest.ip] == ["45.1.2.3", "10.8.0.5", "45.9.9.9"]
    assert web[1] == "web.followups: 120 ms server time; 2 rows"
    assert proxy[1] == "proxy.host: 120 ms server time; destination_count 7, destinations 2"
    slow = Fake({"proxy.host": 10_001})
    async with app_engine.connect() as conn:
        failed = await live_check.check(conn, slow.run, at(16, 20), part="proxy")
    assert failed[-1] == "LIVE CHECK FAILED"
    assert failed[1].endswith("(too slow); destination_count 7, destinations 2")
    async with app_engine.connect() as conn:
        quiet = await live_check.check(conn, Fake().run, at(0, 30))
    assert quiet[-1] == "LIVE CHECK FAILED"
    assert quiet[0].startswith("not now: ")


def test_the_live_window_is_fifteen_minutes() -> None:
    assert live_check.window(at(16, 20), live_check.LIVE_WINDOW) == (at(15, 45), at(16))
    assert live_check.window(at(16, 44), live_check.LIVE_WINDOW) == (at(16), at(16, 15))
    assert live_check.window(at(16, 45), live_check.LIVE_WINDOW) == (at(16, 15), at(16, 30))
    assert live_check.LIVE_ROWS == 10


async def test_a_missing_subject_fails_without_a_request(app_engine: AsyncEngine) -> None:
    await ingest(app_engine, [nginx(2, "45.1.2.3")])
    fake = Fake()
    async with app_engine.connect() as conn:
        lines = await live_check.check(conn, fake.run, at(16, 20), part="proxy")
    assert fake.asked == []
    assert "proxy.host: no subject in the stored alerts (skipped)" in lines
    assert lines[-1] == "LIVE CHECK FAILED"


def test_the_follow_up_size_is_bounded() -> None:
    from pydantic import ValidationError

    from argus.context.web import FollowParams, WebFollowups

    t = at(10)
    with pytest.raises(ValidationError):
        FollowParams(ip="1.2.3.4", start=t, end=t, size=21)
    plan = WebFollowups().build(FollowParams(ip="1.2.3.4", start=t, end=t, size=10))
    assert plan.body["size"] == 10
    assert WebFollowups().build(FollowParams(ip="1.2.3.4", start=t, end=t)).body["size"] == 20
