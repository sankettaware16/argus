"""`argus discover` proposes threat-intel sources (P4-D4 part b, D-293): the data streams of
Elastic's Threat Intel integration as one ECS lookup source, an index with `ioc_value` as an `ioc`
lookup source, and nothing for an index that only maps ECS threat fields under an ordinary name."""

from __future__ import annotations

from typing import Any

import pytest
import yaml

from argus.discover import classify
from argus.discover.classify import Candidate, Typed
from argus.discover.propose import Inputs, checked_yaml, propose, render_text, render_yaml
from argus.site import SiteSettings
from tests.unit.discover.fakes import DAYS, EMPTY_LISTING, SQUID, daily_listing, elastic, kibana
from tests.unit.discover.test_discover import discover

pytestmark = pytest.mark.unit
NEWEST = DAYS[-1]
ECS_TI = {
    "@timestamp": ("date", False),
    "threat.indicator.type": ("keyword", False),
    "threat.indicator.ip": ("ip", False),
}
IOC = {
    "@timestamp": ("date", False),
    "ioc_type": ("text", True),
    "ioc_value": ("text", True),
}
FEEDS = ("logs-ti_abusech.url-default", "logs-ti_otx.threat-default", "logs-ti_misp.threat-default")


def stream(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "timestamp_field": "@timestamp",
        "backing_indices": [f".ds-{name}-{NEWEST}-000001"],
    }


def listing(*names: str, aliases: tuple[str, ...] = ()) -> dict[str, Any]:
    return {
        "indices": [],
        "aliases": [{"name": a} for a in aliases],
        "data_streams": [stream(n) for n in names],
    }


def typed(fields: dict[str, tuple[str, bool]]) -> dict[str, Typed]:
    return {name: Typed(kind, keyword) for name, (kind, keyword) in fields.items()}


# ----------------------------------------------------------------------------- the pure parts


def test_the_integrations_streams_are_one_group() -> None:
    assert classify.ti_group("logs-ti_abusech.url-default") == "logs-ti_*"
    assert classify.ti_group("metrics-ti_x-default") == "metrics-ti_*"
    for other in ("logs-nginx.access-default", "logs-tix-default", "ti_logs-default", "logs-ti_"):
        assert classify.ti_group(other) is None


def test_only_the_first_of_a_group_is_examined() -> None:
    found = [
        Candidate(n, "stream", backing=(f".ds-{n}-x",)) for n in (*FEEDS, "logs-nginx-default")
    ]
    kept = classify.collapse_ti(found)
    assert [c.pattern for c in kept] == [FEEDS[0], "logs-nginx-default"]
    alias = Candidate(FEEDS[1], "alias")  # only data streams group
    assert classify.collapse_ti([found[0], alias]) == [found[0], alias]


def test_a_threat_intel_name_is_examined_before_a_dull_one() -> None:
    assert classify.name_score(Candidate("logs-ti_x-default", "stream")) >= classify.NAME_ONLY_SCORE
    assert classify.name_score(Candidate("logs-zzz-default", "stream")) == 0


def test_the_verdict_needs_ioc_value_or_ecs_fields_with_a_name() -> None:
    ecs = typed(ECS_TI)
    assert classify.ti_verdict("logs-ti_x-default", ecs).schema == "ecs"  # type: ignore[union-attr]
    assert (
        classify.ti_verdict("logs-app-default", ecs) is None
    )  # a full ECS template proves nothing
    assert classify.ti_verdict("feeds", typed({"ioc_value": ("text", True)})).schema == "ioc"  # type: ignore[union-attr]
    plain = classify.ti_verdict("anything", typed({"ioc_value": ("keyword", False)}))
    assert plain is not None
    assert plain.schema is None
    assert "ioc_value.keyword" in plain.notes[0]
    assert classify.ti_verdict("logs-ti_x", typed({"@timestamp": ("date", False)})) is None


# ----------------------------------------------------------------------------- end to end


async def test_the_integrations_streams_become_one_ecs_lookup_source() -> None:
    mappings = {f".ds-{FEEDS[0]}-{NEWEST}-000001": ECS_TI}
    transport = elastic(listing(*FEEDS, "logs-nginx.access-default"), mappings)
    p, transport, _ = await discover(transport, kibana())
    (ti,) = p.ti_sources
    assert (ti.source.index, ti.source.schema_, ti.source.mode) == ("logs-ti_*", "ecs", "lookup")
    assert any("3 data streams match logs-ti_*" in e for e in ti.evidence)
    asked = [r.path for r in transport.calls if "_mapping/field" in r.path]
    assert len([a for a in asked if "ti_" in a]) == 1  # one mapping speaks for the group
    assert p.section()["ti_sources"] == [{"index": "logs-ti_*", "schema": "ecs", "mode": "lookup"}]
    assert not p.unclassified or not any("ti_" in u for u in p.unclassified)


async def test_one_threat_intel_stream_is_named_exactly() -> None:
    mappings = {f".ds-{FEEDS[0]}-{NEWEST}-000001": ECS_TI}
    p, *_ = await discover(elastic(listing(FEEDS[0]), mappings), kibana())
    assert [t.source.index for t in p.ti_sources] == [FEEDS[0]]


async def test_an_index_with_ioc_value_is_an_ioc_lookup_source_and_a_keyword_one_is_not() -> None:
    mappings = {"acme-ioc": IOC, "acme-keyed": {"ioc_value": ("keyword", False)}}
    transport = elastic(listing(aliases=("acme-ioc", "acme-keyed")), mappings)
    p, *_ = await discover(transport, kibana())
    assert [(t.source.index, t.source.schema_) for t in p.ti_sources] == [("acme-ioc", "ioc")]
    assert any("acme-keyed" in w and "ioc_value.keyword" in w for w in p.warnings)


async def test_ecs_threat_fields_under_an_ordinary_name_are_not_a_source() -> None:
    mappings = {f".ds-logs-app.events-default-{NEWEST}-000001": ECS_TI}
    p, *_ = await discover(elastic(listing("logs-app.events-default"), mappings), kibana())
    assert p.ti_sources == ()
    assert "Threat-intel sources proposed: none" in render_text(p)


async def test_a_site_with_no_threat_intel_proposes_none_and_says_so() -> None:
    transport = elastic(daily_listing(), {f"acme-logs-squid-{NEWEST}": SQUID})
    p, *_ = await discover(transport, kibana())
    assert p.ti_sources == ()
    assert "ti_sources" not in p.section()
    assert "ti_sources" not in render_yaml(p)
    assert "threat intel stays off" in render_text(p)


async def test_the_yaml_loads_back_as_the_proposal_with_its_sources() -> None:
    mappings = {f".ds-{FEEDS[0]}-{NEWEST}-000001": ECS_TI, "acme-ioc": IOC}
    p, *_ = await discover(elastic(listing(*FEEDS, aliases=("acme-ioc",)), mappings), kibana())
    text = checked_yaml(p)
    loaded = SiteSettings.model_validate(yaml.safe_load(text)["site"])
    assert loaded == p.site()
    assert {t.index for t in loaded.ti_sources} == {"logs-ti_*", "acme-ioc"}
    assert "# logs-ti_*: asked per value (lookup)" in text
    assert "schema: ecs" in text


def test_more_sources_than_a_site_may_name_are_cut_and_said() -> None:
    names = tuple(f"acme-ioc{n}" for n in range(10))
    data = {"indices": [], "data_streams": [], "aliases": [{"name": n} for n in names]}
    mappings = {n: typed(IOC) for n in names}
    p = propose(Inputs(data=data, mappings=mappings))
    assert len(p.ti_sources) == 8
    assert any("10 threat-intel sources were found" in w for w in p.warnings)
    assert p.site().ti_sources  # the proposal still loads


def test_an_empty_elastic_proposes_nothing() -> None:
    assert propose(Inputs(data=EMPTY_LISTING)).ti_sources == ()
