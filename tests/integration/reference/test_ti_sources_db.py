"""The threat-intel sources of a site on Postgres (P4-D4 part b, D-293): a mirror and a lookup
source of each schema, answered under their index names; no source configured; ACME's two are
what they were (tests/integration/reference/test_reference.py)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus import site
from argus.gateway.gateway import Result
from argus.gateway.templates import Params, Template
from argus.reference import jobs, store
from argus.reference.templates import LookupParams, TiLookup, TiMirrorPage, TiNewest
from argus.site import SiteSettings, TiSource

pytestmark = pytest.mark.integration
NOW = datetime(2026, 10, 13, 12, tzinfo=UTC)


def src(index: str, schema: str, mode: str) -> TiSource:
    return TiSource.model_validate({"index": index, "schema": schema, "mode": mode})


FEED = src("acme-feed", "ecs", "mirror")  # a small ECS feed, read whole
ROWS = src("acme-rows", "ioc", "mirror")  # a small ioc table, read whole
ELASTIC = src("logs-ti_*", "ecs", "lookup")  # Elastic's integration, asked per value
OWN = src("acme-ioc", "ioc", "lookup")
FEED_DOCS = [
    {"@timestamp": "2026-10-12T00:00:00Z",
     "threat": {"indicator": {"type": "ipv4-addr", "ip": "77.221.155.150", "confidence": "High"}}},
]  # fmt: skip
ROW_DOCS = [{"@timestamp": "2026-10-12T00:00:00Z", "ioc_type": "domain", "ioc_value": "Bad.EXAMPLE",
             "intel_source": "own"}]  # fmt: skip
ELASTIC_DOCS = [
    {"@timestamp": "2026-10-12T01:00:00Z",
     "threat": {"indicator": {"type": "url", "url": {"full": "http://evil.example/a"}}}},
    {"@timestamp": "2026-10-12T02:00:00Z",
     "threat": {"indicator": {"type": "ipv4-addr", "ip": "45.9.9.9"}}},
]  # fmt: skip
OWN_DOCS = [{"ioc_type": "ip", "ioc_value": "10.5.5.5", "intel_source": "own"}]


class Fake:
    """A SIEM with the documents of each source; records the requests."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, Params]] = []

    async def run(self, template: Template, params: Params) -> Result:
        self.calls.append((template.name, params))
        if isinstance(template, TiMirrorPage):
            docs = {"acme-feed": FEED_DOCS, "acme-rows": ROW_DOCS}[str(params.index)]  # type: ignore[attr-defined]
            hits = [{"_source": d} for d in docs]
            return Result({"hits": {"total": {"value": len(hits), "relation": "eq"}, "hits": hits}},
                          3, ())  # fmt: skip
        if isinstance(template, TiNewest):
            return Result({"hits": {"hits": [{"_source": {"@timestamp": "2026-10-12T00:00:00Z"}}]}},
                          1, ())  # fmt: skip
        assert isinstance(template, TiLookup)
        assert isinstance(params, LookupParams)
        pool: list[dict[str, Any]] = []
        if "logs-ti_*" in params.indices:
            pool += ELASTIC_DOCS
        if not params.indices or "acme-ioc" in params.indices:  # none: the default ioc source
            pool += OWN_DOCS
        asked = set(params.values)
        hits = [{"_source": d} for d in pool if _matches(d, asked)]
        return Result({"hits": {"total": {"value": len(hits)}, "hits": hits}}, 2, ())


def _matches(doc: dict[str, Any], asked: set[str]) -> bool:
    from argus.reference.ti import values_of

    return bool(values_of(doc) & asked)


def sources_site(*sources: TiSource) -> Any:
    return site.using(SiteSettings(ti_sources=sources))


async def test_each_schema_is_mirrored_under_its_index(app_engine: AsyncEngine) -> None:
    fake = Fake()
    with sources_site(FEED, ROWS):
        async with app_engine.begin() as conn:
            a = await store.sync_mirror(conn, fake.run, NOW, FEED)
            b = await store.sync_mirror(conn, fake.run, NOW, ROWS)
            answers = await store.lookup(
                conn, None, [("ip", "77.221.155.150"), ("domain", "bad.example")], NOW
            )
    assert (a["indicators"], b["indicators"]) == (1, 1)
    by = {x["value"]: x["sources"] for x in answers}
    assert by["77.221.155.150"]["acme-feed"]["match"][0]["confidence"] == "High"
    assert set(by["77.221.155.150"]["acme-rows"]) == {"no_match"}  # synced, not listed there
    assert by["bad.example"]["acme-rows"]["match"][0]["description"] == "own"
    stored = await _all(app_engine, "SELECT source, value FROM ti_indicators ORDER BY 1")
    assert stored == [("acme-feed", "77.221.155.150"), ("acme-rows", "bad.example")]
    assert [p.index for n, p in fake.calls if n == "ti.page"] == ["acme-feed", "acme-rows"]  # type: ignore[attr-defined]


async def test_a_mirror_that_was_never_synced_is_not_checked_not_clean(
    app_engine: AsyncEngine,
) -> None:
    with sources_site(FEED):
        async with app_engine.begin() as conn:
            (answer,) = await store.lookup(conn, None, [("ip", "77.221.155.150")], NOW)
    assert set(answer["sources"]["acme-feed"]) == {"not_checked"}


async def test_lookup_sources_are_asked_once_for_all_and_cached_per_source(
    app_engine: AsyncEngine,
) -> None:
    fake = Fake()
    values = [("ip", "45.9.9.9"), ("ip", "10.5.5.5"), ("url", "http://evil.example/a"),
              ("ip", "10.9.9.9")]  # fmt: skip
    with sources_site(ELASTIC, OWN):
        async with app_engine.begin() as conn:
            answers = await store.lookup(conn, fake.run, values, NOW)
        by = {a["value"]: a["sources"] for a in answers}
        assert by["45.9.9.9"]["logs-ti_*"]["match"][0]["kind"] == "ip"
        assert by["http://evil.example/a"]["logs-ti_*"]["match"][0]["kind"] == "url"
        assert by["10.5.5.5"]["acme-ioc"]["match"][0]["description"] == "own"
        assert set(by["10.9.9.9"]["logs-ti_*"]) == {"no_match"}
        assert set(by["10.9.9.9"]["acme-ioc"]) == {"no_match"}
        cached = await _all(app_engine, "SELECT source, count(*) FROM ti_lookups GROUP BY 1")
        assert cached == [("acme-ioc", 4), ("logs-ti_*", 4)]
        asked = [p for n, p in fake.calls if n == "ti.lookup"]
        assert [p.indices for p in asked] == [
            ("logs-ti_*",),
            (),
        ]  # the default ioc source is unnamed  # type: ignore[attr-defined]
        assert [p.shape for p in asked] == ["ecs", "ioc"]  # type: ignore[attr-defined]
        async with app_engine.begin() as conn:  # within a day: no request, misses included
            await store.lookup(conn, fake.run, values, NOW + timedelta(hours=23))
        assert len([n for n, _ in fake.calls if n == "ti.lookup"]) == 2
        async with app_engine.begin() as conn:  # offline after a day: not checked
            (late,) = await store.lookup(conn, None, [("ip", "45.9.9.9")], NOW + timedelta(days=2))
    assert set(late["sources"]["logs-ti_*"]) == {"not_checked"}


async def test_the_newest_row_of_a_lookup_source_is_its_freshness(app_engine: AsyncEngine) -> None:
    fake = Fake()
    with sources_site(ELASTIC, FEED):
        async with app_engine.begin() as conn:
            newest = await store.sync_newest(conn, fake.run, NOW, ELASTIC)
            fresh = await store.freshness(conn)
    assert newest == datetime(2026, 10, 12, tzinfo=UTC)
    assert [(f.source, f.newest) for f in fresh] == [("logs-ti_*", newest), ("acme-feed", None)]


async def test_the_sync_job_runs_each_source_by_its_mode(app_engine: AsyncEngine) -> None:
    fake = Fake()

    class Gate:
        async def run(self, template: Template, params: Params, **kw: Any) -> Result:
            return await fake.run(template, params)

    with sources_site(FEED, ELASTIC):
        got = await jobs.sync_ti(app_engine, Gate())  # type: ignore[arg-type]
    assert got["sources"] == 2
    assert list(got["mirror"]) == ["acme-feed"]
    assert list(got["newest"]) == ["logs-ti_*"]


async def test_no_source_means_no_sources_in_any_answer(app_engine: AsyncEngine) -> None:
    fake = Fake()
    with sources_site():
        async with app_engine.begin() as conn:
            answers = await store.lookup(conn, fake.run, [("ip", "45.9.9.9")], NOW)
            assert await store.freshness(conn) == []
    assert answers[0]["sources"] == {}  # not "clean": there is nothing it was checked against
    assert fake.calls == []  # and nothing was asked


async def _all(engine: AsyncEngine, query: str) -> list[tuple[Any, ...]]:
    async with engine.connect() as conn:
        return [tuple(r) for r in (await conn.execute(text(query))).all()]
