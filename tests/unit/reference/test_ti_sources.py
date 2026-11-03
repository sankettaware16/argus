"""Threat-intel sources as site settings (P4-D4 part b, D-293): the setting, the three templates
for both schemas (and the legacy shape ACME's stored requests have), the validator, the
answers when no source is configured."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from argus import site
from argus.context import display, intel
from argus.gateway.errors import TemplateRejectedError
from argus.gateway.templates import REGISTRY, plan_key
from argus.gateway.validator import FORCED_SEARCH_PARAMS, FinalRequest, validate
from argus.reference.templates import (
    LOOKUP_SIZE,
    LookupParams,
    MirrorParams,
    NewestParams,
    TiLookup,
    TiMirrorPage,
    TiNewest,
    ecs_terms,
    lookup_params,
    mirror_params,
)
from argus.reference.ti import from_document, indicators_of, values_of
from argus.site import SiteSettings, TiSource

pytestmark = pytest.mark.unit
NOW = datetime(2026, 10, 13, 12, tzinfo=UTC)


def source(index: str, schema: str, mode: str) -> TiSource:
    return TiSource.model_validate({"index": index, "schema": schema, "mode": mode})


ELASTIC = source("logs-ti_*", "ecs", "lookup")
OWN = source("acme-ioc", "ioc", "lookup")
SMALL = source("acme-feed", "ecs", "mirror")


def final(template: Any, params: Any) -> FinalRequest:
    plan = template.plan(params)
    body = {**plan.body, "timeout": "10s"}
    return FinalRequest(plan.spec, plan.names, None, tuple(FORCED_SEARCH_PARAMS.items()), body)


# ----------------------------------------------------------------------------- the setting


def test_a_source_is_an_index_a_schema_and_a_mode() -> None:
    s = SiteSettings.model_validate(
        {"ti_sources": [{"index": "logs-ti_*", "schema": "ecs", "mode": "lookup"}]}
    )
    assert s.ti_indices == ("logs-ti_*",)
    assert s.ti_lookups == (ELASTIC,)
    assert s.ti_mirrors == ()
    assert s.ti_default_lookup is None  # only an ioc source was what a legacy request meant
    assert s.ti_source("logs-ti_*") == ELASTIC


def test_the_neutral_site_has_no_source() -> None:
    s = SiteSettings()
    assert (s.ti_sources, s.ti_indices, s.ti_mirrors, s.ti_lookups) == ((), (), (), ())


@pytest.mark.parametrize(
    "entry",
    [
        {"index": "x", "schema": "xml", "mode": "lookup"},
        {"index": "x", "schema": "ecs", "mode": "scan"},
        {"index": "x", "schema": "ecs"},
        {"index": "x", "mode": "lookup"},
        {"index": "UPPER", "schema": "ecs", "mode": "lookup"},
        {"index": ".hidden", "schema": "ecs", "mode": "lookup"},
        {"index": "a b", "schema": "ecs", "mode": "lookup"},
        {"index": "x", "schema": "ecs", "mode": "lookup", "extra": 1},
    ],
)
def test_a_malformed_source_is_refused(entry: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        SiteSettings.model_validate({"ti_sources": [entry]})


def test_two_sources_may_not_share_an_index_and_there_are_at_most_eight() -> None:
    one = {"index": "x", "schema": "ecs", "mode": "lookup"}
    with pytest.raises(ValidationError, match="share an index"):
        SiteSettings.model_validate({"ti_sources": [one, {**one, "mode": "mirror"}]})
    many = [{"index": f"x{n}", "schema": "ecs", "mode": "lookup"} for n in range(9)]
    with pytest.raises(ValidationError):
        SiteSettings.model_validate({"ti_sources": many})
    SiteSettings.model_validate({"ti_sources": many[:8]})


def test_the_old_setting_is_gone() -> None:
    with pytest.raises(ValidationError):
        SiteSettings.model_validate({"ti_indices": ["x"]})


# ----------------------------------------------------------------------------- ACME unchanged


def test_acmes_legacy_lookup_keeps_its_parameters_and_its_content_address() -> None:
    """A request of the ``ioc`` source is dumped as it always was, and so keeps its plan key; a
    stored one without ``index`` loads and means ``acme-threat-intel``."""
    default = site.active().ti_default_lookup
    assert default is not None
    assert default.index == "acme-threat-intel"
    params = lookup_params([default], ("45.9.9.9",))
    assert params.model_dump(mode="json") == {"values": ["45.9.9.9"], "size": LOOKUP_SIZE}
    stored = LookupParams.model_validate_json('{"values":["45.9.9.9"],"size":500}')
    assert stored == params
    plan = TiLookup().plan(stored)
    assert plan.names == ("acme-threat-intel",)
    assert plan.body == {
        "size": 500,
        "track_total_hits": True,
        "_source": sorted(
            ["@timestamp", "ioc_type", "ioc_value", "intel_source", "first_seen", "last_seen",
             "confidence"]
        ),
        "query": {"bool": {"filter": [{"terms": {"ioc_value.keyword": ["45.9.9.9"]}}]}},
    }  # fmt: skip
    assert plan_key(plan, params) == plan_key(TiLookup().plan(params), stored)
    assert "indices" not in params.model_dump(mode="json")


def test_acmes_mirror_and_newest_keep_their_parameters() -> None:
    assert MirrorParams().model_dump(mode="json") == {"size": 1000}
    plan = TiMirrorPage().plan(MirrorParams())
    assert plan.names == ("abuse-ioc",)  # the site's first mirror
    assert NewestParams(index="abuse-ioc").model_dump(mode="json") == {"index": "abuse-ioc"}
    assert TiNewest().plan(NewestParams(index="acme-threat-intel")).names == ("acme-threat-intel",)


def test_a_legacy_request_needs_a_site_with_a_source_to_mean() -> None:
    with site.using(SiteSettings()), pytest.raises(ValueError, match="names no threat-intel"):
        TiLookup().plan(LookupParams(values=("1.2.3.4",)))
    with site.using(SiteSettings()), pytest.raises(ValueError, match="no mirror"):
        TiMirrorPage().plan(MirrorParams())


# ----------------------------------------------------------------------------- the ecs lookup


def test_the_ecs_lookup_asks_each_value_in_the_field_of_its_kind() -> None:
    values = ("1.2.3.4", "::ffff:1.2.3.4", "evil.example", "EVIL.EXAMPLE",
              "http://evil.example/a?b=1", "a" * 64, "x@evil.example")  # fmt: skip
    asked = ecs_terms(values)
    assert asked["threat.indicator.ip"] == ["1.2.3.4", "::ffff:1.2.3.4"]  # addresses only
    assert asked["threat.indicator.url.domain"] == [
        "1.2.3.4", "::ffff:1.2.3.4", "evil.example", "EVIL.EXAMPLE",
    ]  # fmt: skip
    assert asked["threat.indicator.url.full"] == ["http://evil.example/a?b=1"]
    assert asked["threat.indicator.url.original"] == ["http://evil.example/a?b=1"]
    for field in ("sha256", "sha1", "md5"):
        assert asked[f"threat.indicator.file.hash.{field}"] == ["a" * 64]
    assert asked["threat.indicator.email.address"] == ["x@evil.example"]
    assert ecs_terms(("not a value at all",)) == {}


def test_the_ecs_lookup_is_a_bounded_exact_search_the_validator_keeps() -> None:
    params = lookup_params([ELASTIC], ("1.2.3.4", "evil.example"))
    assert params.model_dump(mode="json") == {
        "values": ["1.2.3.4", "evil.example"], "size": LOOKUP_SIZE,
        "indices": ["logs-ti_*"], "shape": "ecs",
    }  # fmt: skip
    plan = TiLookup().plan(params)
    assert plan.names == ("logs-ti_*",)
    body = plan.body
    assert body["size"] == LOOKUP_SIZE
    assert body["track_total_hits"] is True
    (clause,) = body["query"]["bool"]["filter"]
    fields = [next(iter(t["terms"])) for t in clause["bool"]["should"]]
    assert fields == sorted(fields)
    assert clause["bool"]["minimum_should_match"] == 1
    assert "ioc_value.keyword" not in fields
    validate(final(TiLookup(), params))  # the final request passes the gateway's validator


def test_an_ecs_lookup_of_nothing_askable_is_refused_not_sent_empty() -> None:
    with pytest.raises(ValueError, match="none of the values"):
        TiLookup().plan(LookupParams(indices=("logs-ti_*",), shape="ecs", values=("???",)))


def test_one_request_asks_ecs_and_ioc_sources_together() -> None:
    params = lookup_params([ELASTIC, OWN], ("1.2.3.4",))
    assert params.shape == "both"
    plan = TiLookup().plan(params)
    assert plan.names == ("logs-ti_*", "acme-ioc")
    should = plan.body["query"]["bool"]["filter"][0]["bool"]["should"]
    assert {"terms": {"ioc_value.keyword": ["1.2.3.4"]}} in should
    assert {"terms": {"threat.indicator.ip": ["1.2.3.4"]}} in should
    assert set(plan.body["_source"]) >= {"ioc_value", "threat.indicator.ip"}
    validate(final(TiLookup(), params))


def test_a_non_default_ioc_source_is_named_in_its_parameters() -> None:
    params = lookup_params([OWN], ("1.2.3.4",))
    assert params.model_dump(mode="json")["indices"] == ["acme-ioc"]
    assert "shape" not in params.model_dump(mode="json")  # ioc is the default shape
    again = LookupParams.model_validate_json(
        '{"values":["1.2.3.4"],"size":500,"indices":["acme-ioc"]}'
    )
    assert again == params
    assert TiLookup().plan(again).names == ("acme-ioc",)


def test_a_mirror_read_names_its_source_and_schema() -> None:
    params = mirror_params(SMALL)
    plan = TiMirrorPage().plan(params)
    assert plan.names == ("acme-feed",)
    assert "threat.indicator.type" in plan.body["_source"]
    ioc = TiMirrorPage().plan(mirror_params(source("acme-rows", "ioc", "mirror")))
    assert "ioc_value" in ioc.body["_source"]
    validate(final(TiMirrorPage(), params))


def test_the_templates_keep_their_names_and_versions() -> None:
    assert (TiLookup.name, TiLookup.version) == ("ti.lookup", 1)
    assert (TiMirrorPage.name, TiMirrorPage.version) == ("ti.page", 1)
    assert (TiNewest.name, TiNewest.version) == ("ti.newest", 1)
    assert REGISTRY["ti.lookup"] is TiLookup


# ----------------------------------------------------------------------------- the validator


def test_only_a_threat_intel_name_may_be_a_pattern() -> None:
    params = lookup_params([ELASTIC], ("1.2.3.4",))
    validate(final(TiLookup(), params))  # logs-ti_*
    request = final(TiLookup(), params)
    for bad in ("*", "-x*", "UPPER*", "a b*", "", ".x*"):
        with pytest.raises(TemplateRejectedError):
            validate(replace(request, indices=(bad,)))


def test_the_gateway_allows_only_the_sites_own_sources() -> None:
    from argus.gateway.gateway import Targets

    with site.using(SiteSettings(ti_sources=(ELASTIC,))):
        assert Targets().ti == frozenset({"logs-ti_*"})
    assert "logs-ti_*" not in Targets().ti  # ACME's site names other indices


# ----------------------------------------------------------------------------- reading rows


ECS_DOC = {
    "@timestamp": "2026-10-12T00:00:00Z",
    "threat": {"indicator": {"type": "ipv4-addr", "ip": "77.221.155.150", "confidence": "High"}},
}
IOC_DOC = {"ioc_type": "ip", "ioc_value": "45.9.9.9", "intel_source": "feodo"}


def test_a_document_is_read_by_its_sources_schema_and_carries_its_source() -> None:
    (a,) = from_document("ecs", "logs-ti_*", ECS_DOC)
    (b,) = from_document("ioc", "acme-ioc", IOC_DOC)
    assert (a.source, a.value, b.source, b.value) == ("logs-ti_*", "77.221.155.150",
                                                      "acme-ioc", "45.9.9.9")  # fmt: skip
    assert from_document("ioc", "x", ECS_DOC) == []  # the wrong schema reads nothing


def test_a_stored_row_is_read_whichever_schema_its_source_had() -> None:
    assert values_of(ECS_DOC) == {"77.221.155.150"}
    assert values_of(IOC_DOC) == {"45.9.9.9"}
    assert indicators_of({"nothing": "here"}) == []
    assert indicators_of(ECS_DOC)[0].source == ""  # evidence keeps rows, not their source


# ----------------------------------------------------------------------------- no source


def answered(sources: dict[str, Any]) -> dict[str, Any]:
    return {"value": "1.2.3.4", "kind": "ip", "sources": sources}


def test_no_source_is_unknown_never_clean() -> None:
    with site.using(SiteSettings()):
        signals = intel.signals(1, {"values": [["ip", "1.2.3.4"]], "answers": [answered({})]},
                                {}, {})  # fmt: skip
        listed = next(s for s in signals if s.name == "ti.listed")
        assert (listed.status, listed.unknown_reason) == ("unknown", "no_sources")
        assert intel.tasks({"values": [["ip", "1.2.3.4"]], "answers": [answered({})]}) == []
        said = intel.sentence({"answers": [answered({})]}, [listed.as_dict()])
        assert said == intel.NO_SOURCES_SENTENCE
        assert "no source is configured" in said


def test_a_site_with_sources_is_not_told_there_are_none() -> None:
    fresh = {"no_match": {"stale": False}}
    asked_never = {"not_checked": {"stale": False}}
    ti = {
        "values": [["ip", "1.2.3.4"]],
        "answers": [answered({"abuse-ioc": fresh, "acme-threat-intel": asked_never})],
    }
    listed = next(s for s in intel.signals(1, ti, {}, {}) if s.name == "ti.listed")
    assert listed.status == "unknown"  # the lookup source was not asked: not clean
    assert listed.unknown_reason != "no_sources"


def test_the_lookup_tasks_cover_every_lookup_source_in_one_request() -> None:
    due = {"not_checked": None}
    ti = {"values": [["ip", "1.2.3.4"]], "answers": [answered({"logs-ti_*": due, "acme-ioc": due})]}
    with site.using(SiteSettings(ti_sources=(ELASTIC, OWN, SMALL))):
        (task,) = intel.tasks(ti)
        params = task.params
        assert isinstance(params, LookupParams)
        assert params.indices == ("logs-ti_*", "acme-ioc")  # the mirror is not asked
        assert params.shape == "both"
    # ACME: the same request it always made
    acme = {"values": [["ip", "1.2.3.4"]], "answers": [answered({"acme-threat-intel": due})]}
    (legacy,) = intel.tasks(acme)
    assert legacy.params.model_dump(mode="json").keys() == {"values", "size"}  # type: ignore[union-attr]


# ----------------------------------------------------------------------------- the words


def test_the_lookup_signal_names_the_sources_by_index() -> None:
    signal = {"name": "ti.listed_remote", "status": "known", "value": 2, "completeness": "exact"}
    assert display.sentence(signal) == "On acme-threat-intel: 2 found in acme-threat-intel"
    with site.using(SiteSettings(ti_sources=(ELASTIC, OWN))):
        assert display.sentence(signal) == (
            "On logs-ti_*, acme-ioc: 2 found in logs-ti_*, acme-ioc"
        )
    with site.using(SiteSettings()):
        assert "the threat-intel lookup" in display.sentence(signal)
