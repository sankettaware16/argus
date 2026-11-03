"""Validator tests written for mutation survivors (D-040): every refusal's exact message, every
member of the forbidden lists spelled out (never imported from the code), and each limit at its
literal boundary."""

from __future__ import annotations

import dataclasses
from dataclasses import replace
from typing import Any

import pytest

from argus.gateway.errors import TemplateRejectedError
from argus.gateway.templates import CostClass, Endpoint, Family, Spec
from argus.gateway.validator import FORCED_SEARCH_PARAMS, FinalRequest, validate

pytestmark = pytest.mark.unit

FORCED = tuple(FORCED_SEARCH_PARAMS.items())
SPEC = Spec(
    name="t", version=1, endpoint=Endpoint.SEARCH, family=Family.ALERTS, cost=CostClass.LIGHT,
    filter_fields=frozenset({"a", "a.keyword", "@timestamp"}),
    aggregate_fields=frozenset({"a", "@timestamp"}),
    return_fields=frozenset({"a", "b"}),
    sort_fields=frozenset({"@timestamp", "s2", "s3", "s4", "s5"}),
    max_size=10,
    url_params=frozenset({"filter_path", "_source_includes", "_source"}),
    allow_pit=True,
)  # fmt: skip
LOG = replace(SPEC, family=Family.LOG, cost=CostClass.HEAVY)
DAY = ("acme-logs-squid-2026.10.09",)


def req(body: Any = None, spec: Spec = SPEC, **kw: Any) -> FinalRequest:
    kw.setdefault("indices", DAY if spec.family is Family.LOG else (".alerts-x",))
    kw.setdefault("url_params", FORCED if spec.endpoint is Endpoint.SEARCH else ())
    return FinalRequest(spec, body=body, **kw)


def q(clause: Any) -> FinalRequest:
    return req({"size": 0, "query": clause})


def ag(aggs: Any) -> FinalRequest:
    return req({"size": 0, "aggs": aggs})


def message(request: FinalRequest) -> str:
    with pytest.raises(TemplateRejectedError) as info:
        validate(request)
    return str(info.value)


def terms(size: int = 5, field: str = "a") -> dict[str, Any]:
    return {"terms": {"field": field, "size": size}}


def histogram(high: int, interval: str, **extra: Any) -> dict[str, Any]:
    body = {
        "field": "@timestamp",
        "fixed_interval": interval,
        "hard_bounds": {"min": 0, "max": high},
    }
    return {"date_histogram": {**body, **extra}}


MGET = replace(SPEC, endpoint=Endpoint.MGET)
CLUSTER = replace(SPEC, family=Family.CLUSTER, url_params=frozenset())


# --------------------------------------------------------------------------- exact messages


@pytest.mark.parametrize(
    ("request_", "expected"),
    [
        (req({"size": 0, "x": float("nan")}), "bad_shape: the body is not plain JSON"),
        (req({"ids": ["1"]}, replace(MGET, cost=CostClass.PROBE)),
         "cost_mismatch: an mget is never probe-cost"),
        (req(None, replace(CLUSTER, endpoint=Endpoint.RESOLVE_INDEX), indices=("x",)),
         "index_not_allowed: resolve_index takes one family pattern"),
        (req({"size": 0}, pattern="x-*"), "index_not_allowed: only resolve_index takes a pattern"),
        (req(None, replace(CLUSTER, endpoint=Endpoint.INDEX_BLOCKS), indices=()),
         "index_not_allowed: index_blocks needs its indices"),
        (req({"size": 0}, indices=()), "index_not_allowed: no index"),
        (req({"size": 0}, indices=("a", "a")), "index_not_allowed: an index is listed twice"),
        (req({"size": 0}, indices=("a*",)),
         "index_not_allowed: index names must be exact, no patterns"),
        (req({"ids": ["1"]}, replace(MGET, whole_documents=True), indices=("a", "b")),
         "index_not_allowed: mget reads exactly one index"),
        (req({"size": 0}, url_params=(*FORCED, ("x", 1))),
         "forbidden_param: URL parameters are text"),
        (req({"size": 0}, url_params=(*FORCED, ("_source", "true"))),
         "forbidden_param: _source may only be false"),
        (req({"size": 0}, url_params=()),
         "forbidden_param: a search must carry the complete-results parameters"),
        (req([]), "bad_shape: a search body is an object"),
        (req({"size": 0, "zz": 1, "yy": 2}), "unknown_key: yy, zz"),
        (req({"size": 0, "aggs": {"x": terms()}, "aggregations": {"x": terms()}}),
         "bad_shape: aggs given twice"),
        (req({"size": 0, "from": 5}), "from_not_allowed: paging with from; use search_after"),
        (req({"size": 0}, LOG),
         "total_hits_not_allowed: log searches set track_total_hits to false"),
        (req({"size": 0, "track_total_hits": "x"}), "bad_shape: track_total_hits"),
        (req({"size": 1}), "field_not_allowed: a search that returns hits names its _source"),
        (req({"size": 0, "search_after": [1]}),
         "bad_shape: search_after needs a sort and one literal per sort key"),
        (req({"size": 2, "_source": ["a"]}, replace(SPEC, cost=CostClass.PROBE)),
         "cost_mismatch: a probe-cost search reads one document, no aggregation"),
        (req({"size": 0, "track_total_hits": False, "aggs": {"x": terms()}},
             replace(LOG, cost=CostClass.MEDIUM)),
         "cost_mismatch: an aggregation on log indices is heavy"),
        (req({"size": 0, "pit": {"id": "p", "keep_alive": "9m"}}),
         "bad_shape: pit is {id, keep_alive of 1m, 2m or 5m}"),
        (req({"size": 1, "_source": "a"}),
         "field_not_allowed: _source is false or a list of allowed fields"),
        (req({"size": 0, "fields": {}}), "bad_shape: fields is a non-empty list"),
        (req({"size": 0, "fields": [{"x": 1}]}), "bad_shape: fields entries are {field, format}"),
        (req({"size": 0, "fields": [{"field": "a", "format": 1}]}),
         "bad_shape: fields format is text"),
        (req({"size": 0, "sort": []}), "bad_sort: an empty sort"),
        (req({"size": 0, "sort": [1]}), "bad_sort: sort entries are a field or {field: order}"),
        (req({"size": 0, "sort": [{"@timestamp": {"bad": 1}}]}),
         "bad_sort: sort options are order, format, unmapped_type, missing"),
        (req({"size": 0, "sort": [{"@timestamp": {"order": []}}]}),
         "bad_sort: sort options are literals"),
        (req({"size": 0, "sort": [{"@timestamp": {"order": "up"}}]}),
         "bad_sort: order is asc or desc"),
        (req({"size": 0, "sort": ["_id"]}), "bad_sort: never sort on _id"),
        (req({"size": 0, "sort": ["zz"]}), "bad_sort: zz is not a sort field of t"),
        (q([]), "bad_shape: a clause is {type: body}"),
        (q({"bool": []}), "bad_shape: bool is an object"),
        (q({"bool": {"minimum_should_match": -1}}),
         "bad_shape: minimum_should_match is a whole number"),
        (q({"term": {"a": {"x": 1}}}), "bad_shape: term is {field: value} or {field: {value}}"),
        (q({"term": {}}), "bad_shape: term names exactly one field"),
        (q({"terms": {}}), "bad_shape: terms names exactly one field"),
        (q({"range": {}}), "bad_shape: range names exactly one field"),
        (q({"match_phrase": {}}), "bad_shape: match_phrase names exactly one field"),
        (q({"terms": {"a": {"index": "i"}}}), "forbidden_clause: terms lookup is not allowed"),
        (q({"terms": {"a": []}}), "bad_shape: terms takes a non-empty list"),
        (q({"range": {"a": {}}}), "bad_shape: range needs gte, gt, lte or lt"),
        (q({"range": {"a": {"gte": 1, "format": 1}}}), "bad_shape: range format is text"),
        (q({"range": {"a": {"gte": 1, "boost": 2}}}), "bad_shape: range has no boost"),
        (q({"match_phrase": {"a": {"x": "y"}}}),
         "bad_shape: match_phrase is {field: text} or {field: {query}}"),
        (q({"exists": {"field": "a", "x": 1}}), "bad_shape: exists is {field}"),
        (q({"ids": {}}), "bad_shape: ids is {values}"),
        (q({"match_all": {"boost": 1}}), "bad_shape: match_all takes no options"),
        (ag([]), "bad_shape: aggs is a non-empty object"),
        (ag({"": terms()}), "bad_shape: aggregation names are 1-64 characters"),
        (ag({"x": "y"}), "bad_shape: an aggregation is an object"),
        (ag({"x": {}}), "bad_shape: an aggregation has one type and optional sub-aggs"),
        (ag({"x": {"terms": {"field": "a", "size": 5, "order": {"_key": "up"}}}}),
         "bad_shape: terms order is {_count|_key: asc|desc}"),
        (ag({"x": {"terms": {"field": "a", "size": 5, "missing": []}}}),
         "value_not_literal: terms missing is a literal"),
        (ag({"x": {"date_histogram": {"field": "@timestamp"}}}),
         "bad_shape: date_histogram needs fixed_interval and hard_bounds"),
        (ag({"x": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h",
                                      "hard_bounds": {"min": 2, "max": 1}}}}),
         "bad_shape: hard_bounds are two times, min before max"),
        (ag({"x": histogram(3_600_000, "1h", format=1)}),
         "bad_shape: date_histogram format is text"),
        (ag({"x": {"cardinality": {"field": "a", "precision_threshold": -1}}}),
         "bad_shape: precision_threshold is 0..40000"),
        (ag({"x": {"top_hits": {"from": 1}}}), "bad_shape: top_hits takes size, _source and sort"),
        (ag({"x": {"top_hits": {"size": 1}}}), "field_not_allowed: top_hits names its _source"),
        (ag({"x": {"date_histogram": {"field": "@timestamp", "zz": 1}}}),
         "bad_shape: date_histogram has no zz"),
        (req({"docs": []}, MGET), "bad_shape: an mget body is {ids}"),
        (req({"ids": ["1"]}, MGET), "field_not_allowed: an mget names its _source"),
        (req({"x": 1}, replace(CLUSTER, endpoint=Endpoint.HAS_PRIVILEGES), indices=()),
         "bad_shape: has_privileges takes cluster, index and application"),
    ],
)  # fmt: skip
def test_refusal_messages(request_: FinalRequest, expected: str) -> None:
    assert message(request_) == expected


@pytest.mark.parametrize(
    "kind", ["terms", "date_histogram", "cardinality", "min", "max", "sum", "avg", "value_count"]
)
def test_each_aggregation_names_itself_when_its_field_is_missing(kind: str) -> None:
    assert message(ag({"x": {kind: {}}})) == f"bad_shape: {kind} needs a field"


# --------------------------------------------------------------------------- the lists

FORBIDDEN_CLAUSES = (
    "regexp", "wildcard", "prefix", "fuzzy", "query_string", "simple_query_string",
    "script_score", "function_score", "more_like_this", "percolate", "terms_set", "intervals",
    "match", "multi_match", "combined_fields", "match_bool_prefix", "match_phrase_prefix",
    "nested", "has_child", "has_parent", "parent_id", "geo_shape", "distance_feature",
    "rank_feature", "pinned", "wrapper", "span_term", "span_multi",
)  # fmt: skip
FORBIDDEN_AGGS = (
    "significant_terms", "significant_text", "scripted_metric", "composite", "rare_terms",
    "multi_terms", "bucket_script", "bucket_selector", "bucket_sort", "histogram",
    "percentiles", "terms_lookup", "global", "sampler", "diversified_sampler", "nested",
    "reverse_nested", "adjacency_matrix", "auto_date_histogram", "variable_width_histogram",
)  # fmt: skip
METRICS = {
    "cardinality": {"field": "a"}, "min": {"field": "a"}, "max": {"field": "a"},
    "sum": {"field": "a"}, "avg": {"field": "a"}, "value_count": {"field": "a"},
    "top_hits": {"size": 1, "_source": ["a"]},
}  # fmt: skip


@pytest.mark.parametrize("kind", FORBIDDEN_CLAUSES)
def test_every_forbidden_clause_is_named_as_forbidden(kind: str) -> None:
    assert message(q({kind: {}})) == f"forbidden_clause: {kind} queries are not allowed"


def test_script_is_refused_as_a_key_anywhere() -> None:
    assert message(q({"script": {}})) == "forbidden_key: script is not allowed anywhere"


@pytest.mark.parametrize("kind", FORBIDDEN_AGGS)
def test_every_forbidden_aggregation_is_named_as_forbidden(kind: str) -> None:
    assert message(ag({"x": {kind: {}}})) == f"forbidden_aggregation: {kind} is not allowed"


@pytest.mark.parametrize("kind", sorted(METRICS))
def test_metric_aggregations_take_no_sub_aggregations(kind: str) -> None:
    node = {kind: METRICS[kind], "aggs": {"y": terms()}}
    assert message(ag({"x": node})) == f"bad_shape: {kind} takes no sub-aggregations"


@pytest.mark.parametrize("kind", sorted(set(METRICS) - {"top_hits"}))
def test_metric_aggregations_count_no_buckets(kind: str) -> None:
    validate(ag({"t": terms(1000), "m": {kind: METRICS[kind]}}))


# --------------------------------------------------------------------------- boundaries


def test_search_after_takes_at_most_four_sort_keys() -> None:
    sort = ["@timestamp", "s2", "s3", "s4", "s5"]
    validate(req({"size": 0, "sort": sort[:4], "search_after": [1, 2, 3, 4]}))
    five = req({"size": 0, "sort": sort, "search_after": [1, 2, 3, 4, 5]})
    assert message(five).startswith("bad_shape: search_after")


def test_the_final_request_is_frozen() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        req({"size": 0}).body = {}  # type: ignore[misc]


def test_size_defaults_to_ten() -> None:
    validate(req({"_source": ["a"]}))  # max_size 10
    assert message(req({"_source": ["a"]}, replace(SPEC, max_size=9))) == (
        "size_too_large: size must be 0..9"
    )


def test_track_total_hits_zero_is_allowed() -> None:
    validate(req({"size": 0, "track_total_hits": 0}))


@pytest.mark.parametrize("keep_alive", ["1m", "2m", "5m"])
def test_a_one_character_pit_id_and_each_keep_alive(keep_alive: str) -> None:
    validate(req({"size": 0, "pit": {"id": "p", "keep_alive": keep_alive}}))


def test_both_sub_aggregation_keys_are_refused() -> None:
    node = {**terms(), "aggs": {"y": METRICS["min"]}, "aggregations": {"z": METRICS["max"]}}
    assert message(ag({"x": node})) == (
        "bad_shape: an aggregation has one type and optional sub-aggs"
    )


def test_aggregations_is_checked_like_aggs() -> None:
    top = req({"size": 0, "aggregations": {"x": {"composite": {}}}})
    assert message(top) == "forbidden_aggregation: composite is not allowed"
    sub = ag({"x": {**terms(), "aggregations": {"y": {"composite": {}}}}})
    assert message(sub) == "forbidden_aggregation: composite is not allowed"


def test_terms_order_names_one_key() -> None:
    two = {"terms": {"field": "a", "size": 5, "order": {"_count": "desc", "_key": "asc"}}}
    assert message(ag({"x": two})) == "bad_shape: terms order is {_count|_key: asc|desc}"


def test_date_histogram_fields_and_options() -> None:
    other = {"date_histogram": {**histogram(1, "1h")["date_histogram"], "field": "zz"}}
    assert message(ag({"x": other})) == "field_not_allowed: zz may not be aggregated"
    validate(ag({"x": histogram(3_600_000, "1h", format="epoch_millis", min_doc_count=1)}))
    validate(ag({"x": histogram(0, "1h")}))  # min == max: one bucket


def test_date_histogram_buckets_are_whole() -> None:
    """90 minutes in 1h steps are 2 buckets, not 2.5: 2 + 2 x 400 fits, 2.5 + 1,000 does not."""
    node = {**histogram(5_400_000, "1h"), "aggs": {"t": terms(400)}}
    validate(ag({"x": node}))


@pytest.mark.parametrize(("unit", "ms"), [("h", 3_600_000), ("d", 86_400_000)])
def test_interval_units_at_the_bucket_limit(unit: str, ms: int) -> None:
    validate(ag({"x": histogram(ms * 999, f"1{unit}")}))  # 1,000 buckets
    assert message(ag({"x": histogram(ms * 1000, f"1{unit}")})) == (
        "too_many_buckets: up to 1001 buckets (limit 1000)"
    )


def test_precision_threshold_zero_is_allowed() -> None:
    validate(ag({"x": {"cardinality": {"field": "a", "precision_threshold": 0}}}))


def test_a_filter_aggregation_starts_at_clause_depth_one() -> None:
    clause: dict[str, Any] = {"term": {"a": "v"}}
    for _ in range(7):  # the term at depth 8
        clause = {"bool": {"filter": [clause]}}
    validate(ag({"f": {"filter": clause}}))


def test_a_filter_aggregation_is_one_bucket() -> None:
    validate(ag({"f": {"filter": {"term": {"a": "v"}}}, "t": terms(999)}))
    assert message(ag({"f": {"filter": {"term": {"a": "v"}}}, "t": terms(1000)})) == (
        "too_many_buckets: up to 1001 buckets (limit 1000)"
    )


def test_top_hits_default_to_three_per_bucket() -> None:
    hits = {"top_hits": {"_source": ["a"]}}
    validate(ag({"x": {**terms(250), "aggs": {"h": hits}}}))  # 250 + 750
    assert message(ag({"x": {**terms(251), "aggs": {"h": hits}}})).startswith("too_many_buckets")


def test_top_hits_never_sort_on_shard_doc() -> None:
    hits = {"top_hits": {"size": 1, "_source": ["a"], "sort": ["_shard_doc"]}}
    assert message(ag({"x": hits})) == "bad_sort: _shard_doc is not a sort field of t"


def test_source_includes_is_a_comma_separated_list() -> None:
    validate(req({"size": 1}, url_params=(*FORCED, ("_source_includes", "a,b"))))


def test_bool_must_is_a_clause_list() -> None:
    validate(q({"bool": {"must": [{"term": {"a": "v"}}]}}))


def test_id_is_never_aggregated_even_if_listed() -> None:
    spec = replace(SPEC, aggregate_fields=frozenset({"_id"}))
    assert message(req({"size": 0, "aggs": {"x": terms(field="_id")}}, spec)) == (
        "field_not_allowed: _id may not be aggregated"
    )


def test_a_range_with_an_unknown_option_is_refused() -> None:
    assert message(q({"range": {"a": {"gte": 1, "boost": 2}}})) == "bad_shape: range has no boost"
