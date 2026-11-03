"""The validator (plan §5.3): every rule at its boundary, and properties over random bodies."""

from __future__ import annotations

import contextlib
import copy
from dataclasses import replace
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.gateway.errors import TemplateRejectedError, UnsupportedValueError
from argus.gateway.templates import CostClass, Endpoint, Family, Spec
from argus.gateway.validator import FORCED_SEARCH_PARAMS, FinalRequest, encode_body, validate

pytestmark = pytest.mark.unit

FORCED = tuple(FORCED_SEARCH_PARAMS.items())
LOG = Spec(
    name="t.log", version=1, endpoint=Endpoint.SEARCH, family=Family.LOG, cost=CostClass.HEAVY,
    filter_fields=frozenset({"source.ip", "url.domain.keyword", "@timestamp", "http.status"}),
    aggregate_fields=frozenset({"url.domain.keyword", "@timestamp", "source.ip", "bytes"}),
    return_fields=frozenset({"@timestamp", "url.full", "source.ip"}),
    sort_fields=frozenset({"@timestamp"}),
    max_size=500,
)  # fmt: skip
ALERTS = Spec(
    name="t.alerts", version=1, endpoint=Endpoint.SEARCH, family=Family.ALERTS,
    cost=CostClass.LIGHT, filter_fields=frozenset({"@timestamp"}),
    sort_fields=frozenset({"@timestamp", "kibana.alert.uuid"}), max_size=1000, allow_pit=True,
    aggregate_fields=frozenset({"kibana.alert.rule.rule_id"}),
)  # fmt: skip
DAY = ("acme-logs-squid-2026.10.09",)


def search(body: Any, spec: Spec = LOG, **kw: Any) -> FinalRequest:
    """A final search request; a log body without track_total_hits gets it (false)."""
    if spec.family is Family.LOG and isinstance(body, dict) and "track_total_hits" not in body:
        body = {"track_total_hits": False, **body}
    kw.setdefault("indices", DAY if spec.family is Family.LOG else (".alerts-x",))
    kw.setdefault("url_params", FORCED)
    return FinalRequest(spec, body=body, **kw)


def code(request: FinalRequest) -> str:
    with pytest.raises(TemplateRejectedError) as info:
        validate(request)
    return info.value.code


GOOD = {
    "size": 100,
    "track_total_hits": False,
    "timeout": "10s",
    "_source": ["@timestamp", "url.full"],
    "sort": [{"@timestamp": {"order": "desc"}}],
    "query": {
        "bool": {
            "filter": [
                {"term": {"source.ip": "10.0.0.1"}},
                {"terms": {"url.domain.keyword": ["a.example", "b.example"]}},
                {"range": {"@timestamp": {"gte": "2026-10-09T00:00:00Z", "lt": "now"}}},
            ],
            "must_not": {"match_phrase": {"url.domain.keyword": "c.example"}},
            "should": [{"exists": {"field": "http.status"}}],
            "minimum_should_match": 0,
        }
    },
    "aggs": {
        "by_domain": {
            "terms": {"field": "url.domain.keyword", "size": 50, "order": {"_count": "desc"}},
            "aggs": {"bytes": {"sum": {"field": "bytes"}}},
        }
    },
}


def with_(path: list[Any], value: Any, body: Any = None) -> Any:
    body = copy.deepcopy(GOOD if body is None else body)
    node = body
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return body


def test_the_good_body_passes() -> None:
    validate(search(GOOD))


# --------------------------------------------------------------------------- query clauses


@pytest.mark.parametrize(
    "clause",
    [
        {"regexp": {"url.domain.keyword": ".*"}}, {"wildcard": {"url.domain.keyword": "*a"}},
        {"prefix": {"url.domain.keyword": "a"}}, {"fuzzy": {"url.domain.keyword": "a"}},
        {"query_string": {"query": "a"}}, {"simple_query_string": {"query": "a"}},
        {"script": {"script": "1"}}, {"script_score": {}}, {"function_score": {}},
        {"match": {"url.domain.keyword": "a"}}, {"more_like_this": {}}, {"nested": {}},
        {"terms": {"url.domain.keyword": {"index": "i", "id": "1", "path": "p"}}},
    ],
)  # fmt: skip
def test_forbidden_clauses(clause: dict[str, Any]) -> None:
    body = with_(["query"], {"bool": {"filter": [clause]}})
    assert code(search(body)) in {"forbidden_clause", "forbidden_key"}


def test_unknown_clause() -> None:
    assert code(search(with_(["query"], {"geo_polygon": {}}))) == "unknown_clause"


@pytest.mark.parametrize(
    ("clause", "expected"),
    [
        ({"term": {"url.full": "x"}}, "field_not_allowed"),
        ({"term": {"source.ip": {"value": "x", "boost": 2}}}, "bad_shape"),
        ({"term": {"source.ip": None}}, "value_not_literal"),
        ({"term": {"source.ip": ["a"]}}, "value_not_literal"),
        ({"term": {"source.ip": float("nan")}}, "bad_shape"),
        ({"term": {"source.ip": "a", "url.domain.keyword": "b"}}, "bad_shape"),
        ({"terms": {"source.ip": []}}, "bad_shape"),
        ({"terms": {"source.ip": "a"}}, "bad_shape"),
        ({"range": {"@timestamp": {"near": 1}}}, "bad_shape"),
        ({"range": {"@timestamp": {"format": "x"}}}, "bad_shape"),
        ({"range": {"@timestamp": {"gte": True}}}, "value_not_literal"),
        ({"range": {"@timestamp": {"gte": 1, "format": 5}}}, "bad_shape"),
        ({"range": {"@timestamp": "today"}}, "bad_shape"),
        ({"match_phrase": {"url.domain.keyword": 5}}, "value_not_literal"),
        ({"match_phrase": {"url.domain.keyword": {"query": "a", "slop": 2}}}, "bad_shape"),
        ({"exists": {"field": "url.full"}}, "field_not_allowed"),
        ({"exists": {"field": "source.ip", "x": 1}}, "bad_shape"),
        ({"ids": {"values": []}}, "bad_shape"),
        ({"ids": {"values": [1]}}, "value_not_literal"),
        ({"ids": {"values": ["a"], "x": 1}}, "bad_shape"),
        ({"match_all": {"boost": 1}}, "bad_shape"),
        ({"bool": {}}, "bad_shape"),
        ({"bool": {"filter": [], "boost": 1}}, "bad_shape"),
        ({"bool": {"minimum_should_match": "50%"}}, "bad_shape"),
        ({"bool": {"minimum_should_match": -1}}, "bad_shape"),
        ({"bool": {"minimum_should_match": True}}, "bad_shape"),
        ("term", "bad_shape"),
        ({}, "bad_shape"),
        ({"term": {"source.ip": "a"}, "terms": {"source.ip": ["a"]}}, "bad_shape"),
    ],
)  # fmt: skip
def test_clause_shapes(clause: Any, expected: str) -> None:
    assert code(search(with_(["query"], clause))) == expected


def test_accepted_clause_forms() -> None:
    clauses: tuple[dict[str, Any], ...] = (
        {"term": {"source.ip": {"value": "a"}}},
        {"match_phrase": {"url.domain.keyword": {"query": "a"}}},
        {"ids": {"values": ["a"] * 200}},
        {"match_all": {}},
        {"range": {"@timestamp": {"gt": 1, "lte": 2.5, "format": "epoch_millis"}}},
        {"bool": {"minimum_should_match": 1, "should": {"term": {"source.ip": True}}}},
    )
    for clause in clauses:
        validate(search(with_(["query"], clause)))


def test_terms_limit_is_200() -> None:
    validate(search(with_(["query"], {"terms": {"source.ip": [f"{i}" for i in range(200)]}})))
    body = with_(["query"], {"terms": {"source.ip": [f"{i}" for i in range(201)]}})
    assert code(search(body)) == "too_many_values"
    body = with_(["query"], {"ids": {"values": [f"{i}" for i in range(201)]}})
    assert code(search(body)) == "too_many_values"


def test_ids_are_at_most_512_characters() -> None:
    validate(search(with_(["query"], {"ids": {"values": ["i" * 512]}})))
    assert code(search(with_(["query"], {"ids": {"values": ["i" * 513]}}))) == "value_not_literal"
    assert code(search(with_(["query"], {"ids": {"values": [""]}}))) == "value_not_literal"


def test_ignore_above_is_256_on_keyword_fields() -> None:
    validate(search(with_(["query"], {"term": {"url.domain.keyword": "d" * 256}})))
    for clause in (
        {"term": {"url.domain.keyword": "d" * 257}},
        {"terms": {"url.domain.keyword": ["a", "d" * 257]}},
        {"match_phrase": {"url.domain.keyword": "d" * 257}},
    ):
        with pytest.raises(UnsupportedValueError):
            validate(search(with_(["query"], clause)))
    validate(search(with_(["query"], {"term": {"source.ip": "d" * 300}})))  # not a keyword field


def test_bool_depth_limit_is_8() -> None:
    def nest(levels: int) -> dict[str, Any]:
        node: dict[str, Any] = {"term": {"source.ip": "a"}}
        for _ in range(levels):
            node = {"bool": {"filter": node}}
        return node

    validate(search(with_(["query"], nest(7))))  # 7 bools + the term = depth 8
    assert code(search(with_(["query"], nest(8)))) == "too_complex"


def test_clause_count_limit_is_256() -> None:
    def many(count: int) -> dict[str, Any]:
        return {"bool": {"should": [{"term": {"source.ip": str(i)}} for i in range(count)]}}

    validate(search(with_(["query"], many(255))))  # + the bool itself = 256
    assert code(search(with_(["query"], many(256)))) == "too_complex"


# --------------------------------------------------------------------------- body keys


@pytest.mark.parametrize(
    ("path", "value", "expected"),
    [
        (["from"], 10, "from_not_allowed"),
        (["from"], True, "from_not_allowed"),
        (["size"], 501, "size_too_large"),
        (["size"], -1, "size_too_large"),
        (["size"], True, "size_too_large"),
        (["size"], 1.0, "size_too_large"),
        (["track_total_hits"], True, "total_hits_not_allowed"),
        (["track_total_hits"], 100, "total_hits_not_allowed"),
        (["timeout"], "61s", "bad_shape"),
        (["timeout"], "60001ms", "bad_shape"),
        (["timeout"], "1m", "bad_shape"),
        (["timeout"], 10, "bad_shape"),
        (["_source"], True, "field_not_allowed"),
        (["_source"], ["*"], "field_not_allowed"),
        (["_source"], [], "field_not_allowed"),
        (["_source"], {"includes": ["url.full"], "excludes": ["x"]}, "field_not_allowed"),
        (["_source"], ["bytes"], "field_not_allowed"),
        (["fields"], ["bytes"], "field_not_allowed"),
        (["fields"], [], "bad_shape"),
        (["fields"], [{"field": "url.full", "x": 1}], "bad_shape"),
        (["fields"], [{"format": "x"}], "bad_shape"),
        (["fields"], [{"field": "url.full", "format": 1}], "bad_shape"),
        (["highlight"], {}, "unknown_key"),
        (["runtime_mappings"], {}, "forbidden_key"),
        (["pit"], {"id": "x", "keep_alive": "1m"}, "pit_not_allowed"),
    ],
)  # fmt: skip
def test_body_keys(path: list[Any], value: Any, expected: str) -> None:
    assert code(search(with_(path, value))) == expected


def test_accepted_body_forms() -> None:
    validate(search(with_(["timeout"], "60s")))
    validate(search(with_(["timeout"], "60000ms")))
    validate(search(with_(["size"], 500)))
    validate(search(with_(["size"], 0)))
    validate(search(with_(["from"], 0)))
    validate(search(with_(["_source"], False)))
    validate(search(with_(["_source"], {"includes": ["url.full"]})))
    validate(search(with_(["fields"], ["url.full", {"field": "@timestamp", "format": "x"}])))
    validate(search(with_(["search_after"], [1700000000000])))
    body = {k: v for k, v in GOOD.items() if k != "size"}
    validate(search(body))  # the default size, 10, is within 500


def test_forbidden_keys_anywhere() -> None:
    for key in ("script", "scripts", "runtime_mappings", "script_fields"):
        body = with_(["aggs", "by_domain", "terms", key], {})
        assert code(search(body)) == "forbidden_key"


def test_aggs_given_twice() -> None:
    assert code(search(with_(["aggregations"], GOOD["aggs"]))) == "bad_shape"


def test_body_size_limit_is_64_kib() -> None:
    def padded(total: int, n: int = 70) -> dict[str, Any]:
        def body(values: list[str]) -> dict[str, Any]:
            return {"track_total_hits": False, "size": 0, "query": {"terms": {"source.ip": values}}}

        pad = total - len(encode_body(body([""] * n)))
        values = ["x" * (pad // n)] * n
        values[0] += "x" * (pad % n)
        return body(values)

    validate(search(padded(64 * 1024)))
    assert code(search(padded(64 * 1024 + 1))) == "body_too_large"


def test_search_after_needs_a_sort_key_per_value() -> None:
    validate(search(with_(["search_after"], [1])))
    assert code(search(with_(["search_after"], [1, 2]))) == "bad_shape"
    body = {**ALERTS_BODY, "search_after": [1, "a"]}
    validate(search(body, ALERTS))
    assert code(search({**body, "search_after": [1, None]}, ALERTS)) == "bad_shape"
    assert code(search({**body, "search_after": []}, ALERTS)) == "bad_shape"
    assert code(search({**body, "search_after": "x"}, ALERTS)) == "bad_shape"
    no_sort = {k: v for k, v in body.items() if k != "sort"}
    assert code(search(no_sort, ALERTS)) == "bad_shape"


ALERTS_BODY = {
    "size": 1000,
    "_source": False,
    "track_total_hits": True,
    "sort": [{"@timestamp": "asc"}, {"kibana.alert.uuid": "asc"}],
    "query": {"range": {"@timestamp": {"gte": "now-1h"}}},
}


def test_alerts_family_rules() -> None:
    validate(search(ALERTS_BODY, ALERTS))
    validate(search({**ALERTS_BODY, "track_total_hits": 10_000}, ALERTS))
    assert code(search({**ALERTS_BODY, "track_total_hits": 10_001}, ALERTS)) == "bad_shape"
    assert code(search({**ALERTS_BODY, "track_total_hits": -1}, ALERTS)) == "bad_shape"
    assert code(search({**ALERTS_BODY, "track_total_hits": "x"}, ALERTS)) == "bad_shape"
    assert code(search({**ALERTS_BODY, "size": 1001}, ALERTS)) == "size_too_large"


def test_pit_rules() -> None:
    pit = {"id": "p" * 4096, "keep_alive": "5m"}
    body = {**ALERTS_BODY, "pit": pit, "sort": [{"@timestamp": "asc"}, "_shard_doc"]}
    validate(search(body, ALERTS))
    for bad in (
        {"id": "p", "keep_alive": "10m"},
        {"id": "", "keep_alive": "1m"},
        {"id": "p" * 4097, "keep_alive": "1m"},
        {"id": 5, "keep_alive": "1m"},
        {"id": "p"},
        "p",
    ):
        assert code(search({**body, "pit": bad}, ALERTS)) == "bad_shape"
    no_pit = Spec(**{**ALERTS.__dict__, "allow_pit": False})
    assert code(search({**body, "pit": pit}, no_pit)) == "pit_not_allowed"
    assert code(search({**ALERTS_BODY, "sort": ["_shard_doc"]}, ALERTS)) == "bad_sort"


@pytest.mark.parametrize(
    ("sort", "expected"),
    [
        ([], "bad_sort"),
        ([{"_id": "asc"}], "bad_sort"),
        (["_id"], "bad_sort"),
        ([{"url.full": "asc"}], "bad_sort"),
        ([{"@timestamp": "up"}], "bad_sort"),
        ([{"@timestamp": {"order": "asc", "script": 1}}], "forbidden_key"),
        ([{"@timestamp": {"order": "asc", "nested": 1}}], "bad_sort"),
        ([{"@timestamp": {"missing": {"x": 1}}}], "bad_sort"),
        ([{"@timestamp": "asc", "x": "asc"}], "bad_sort"),
        ([5], "bad_sort"),
        (["_score"], "bad_sort"),
    ],
)
def test_sorts(sort: Any, expected: str) -> None:
    assert code(search(with_(["sort"], sort))) == expected


def test_accepted_sorts() -> None:
    for sort in (
        "@timestamp",
        ["@timestamp"],
        [{"@timestamp": "asc"}],
        [{"@timestamp": {"order": "desc", "format": "strict_date", "unmapped_type": "date"}}],
        [{"@timestamp": {"missing": "_last"}}],
    ):
        validate(search(with_(["sort"], sort)))


# --------------------------------------------------------------------------- aggregations


def agg(body: Any, spec: Spec = LOG) -> FinalRequest:
    return search({"size": 0, "aggs": body}, spec)


def terms(field: str = "url.domain.keyword", size: int = 10, **kw: Any) -> dict[str, Any]:
    return {"terms": {"field": field, "size": size, **kw}}


def test_aggregation_depth_on_log_indices_is_2() -> None:
    validate(agg({"a": {**terms(size=10), "aggs": {"b": terms("source.ip", 10)}}}))
    deep = {
        "a": {
            **terms(size=2),
            "aggs": {"b": {**terms("source.ip", 2), "aggs": {"c": terms(size=2)}}},
        }
    }
    assert code(agg(deep)) == "aggregation_too_deep"
    spec = Spec(**{**LOG.__dict__, "family": Family.ALERTS})
    validate(agg(deep, spec))  # 3 levels elsewhere
    deeper = {"a": {**terms(size=2), "aggs": deep}}
    assert code(agg(deeper, spec)) == "aggregation_too_deep"


def test_bucket_limit_is_1000() -> None:
    validate(agg({"a": terms(size=1000)}))
    assert code(agg({"a": terms(size=1001)})) == "too_many_buckets"
    validate(agg({"a": {**terms(size=10), "aggs": {"b": terms("source.ip", 99)}}}))
    product = {"a": {**terms(size=10), "aggs": {"b": terms("source.ip", 100)}}}
    assert code(agg(product)) == "too_many_buckets"  # 10 + 10 x 100
    assert code(agg({"a": terms(size=0)})) == "too_many_buckets"
    assert code(agg({"a": {"terms": {"field": "url.domain.keyword"}}})) == "too_many_buckets"


def histogram(minutes: int, interval: str = "1m") -> dict[str, Any]:
    return {
        "date_histogram": {
            "field": "@timestamp",
            "fixed_interval": interval,
            "hard_bounds": {"min": 0, "max": minutes * 60_000},
        }
    }


def test_date_histogram_buckets() -> None:
    validate(agg({"h": histogram(999)}))  # 0..999 minutes inclusive: 1000 buckets
    assert code(agg({"h": histogram(1000)})) == "too_many_buckets"
    validate(agg({"h": histogram(999 * 60, "1h")}))
    iso = {"min": "2026-10-09T00:00:00+00:00", "max": "2026-10-09T16:39:00+00:00"}
    validate(
        agg(
            {
                "h": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1m",
                        "hard_bounds": iso,
                    }
                }
            }
        )
    )
    for bad in (
        {"field": "@timestamp", "fixed_interval": "1M", "hard_bounds": {"min": 0, "max": 1}},
        {"field": "@timestamp", "calendar_interval": "1d"},
        {"field": "@timestamp", "fixed_interval": "1m"},
        {"field": "@timestamp", "fixed_interval": "1m", "hard_bounds": {"min": 5, "max": 1}},
        {
            "field": "@timestamp",
            "fixed_interval": "1m",
            "hard_bounds": {"min": "2026-10-09", "max": 1},
        },
        {"field": "@timestamp", "fixed_interval": "1m", "hard_bounds": {"min": "bad", "max": 1}},
        {"field": "@timestamp", "fixed_interval": "1m", "hard_bounds": {"min": 0.5, "max": 1}},
        {"field": "@timestamp", "fixed_interval": 5, "hard_bounds": {"min": 0, "max": 1}},
    ):
        assert code(agg({"h": {"date_histogram": bad}})) == "bad_shape"


@pytest.mark.parametrize(
    ("node", "expected"),
    [
        ({"significant_terms": {"field": "source.ip"}}, "forbidden_aggregation"),
        ({"scripted_metric": {}}, "forbidden_aggregation"),
        ({"composite": {}}, "forbidden_aggregation"),
        ({"geohash_grid": {}}, "unknown_aggregation"),
        ({"terms": {"field": "url.full", "size": 1}}, "field_not_allowed"),
        ({"terms": {"field": "_id", "size": 1}}, "field_not_allowed"),
        ({"terms": {"size": 1}}, "bad_shape"),
        ({"terms": {"field": "source.ip", "size": 1, "include": "a.*"}}, "bad_shape"),
        ({"terms": {"field": "source.ip", "size": 1, "order": {"x": "asc"}}}, "bad_shape"),
        ({"terms": {"field": "source.ip", "size": 1, "order": {"_count": "up"}}}, "bad_shape"),
        ({"terms": {"field": "source.ip", "size": 1, "order": "asc"}}, "bad_shape"),
        ({"terms": {"field": "source.ip", "size": 1, "missing": []}}, "value_not_literal"),
        ({"terms": {"field": "source.ip", "size": 1, "min_doc_count": {}}}, "bad_shape"),
        ({"cardinality": {"field": "source.ip", "precision_threshold": 40_001}}, "bad_shape"),
        ({"cardinality": {"field": "source.ip", "precision_threshold": -1}}, "bad_shape"),
        ({"sum": {"field": "bytes", "missing": 0}}, "bad_shape"),
        ({"sum": {"field": "bytes"}, "aggs": {"x": {"sum": {"field": "bytes"}}}}, "bad_shape"),
        ({"top_hits": {"size": 11}}, "size_too_large"),
        ({"top_hits": {"size": 0}}, "size_too_large"),
        ({"top_hits": {"from": 1}}, "bad_shape"),
        ({"top_hits": {"_source": ["bytes"]}}, "field_not_allowed"),
        ({"top_hits": {"_source": ["url.full"], "sort": [{"bytes": "asc"}]}}, "bad_sort"),
        ({"filter": {"wildcard": {"source.ip": "*"}}}, "forbidden_clause"),
        ({"terms": {"field": "source.ip", "size": 1}, "sum": {"field": "bytes"}}, "bad_shape"),
        ({"terms": {"field": "source.ip", "size": 1}, "aggs": {}, "aggregations": {}}, "bad_shape"),
        ({}, "bad_shape"),
        ("x", "bad_shape"),
    ],
)  # fmt: skip
def test_aggregation_shapes(node: Any, expected: str) -> None:
    assert code(agg({"a": node})) == expected


def test_accepted_aggregations() -> None:
    validate(
        agg(
            {
                "c": {"cardinality": {"field": "source.ip", "precision_threshold": 40_000}},
                "m": {"min": {"field": "bytes"}},
                "x": {"max": {"field": "bytes"}},
                "a": {"avg": {"field": "bytes"}},
                "v": {"value_count": {"field": "bytes"}},
                "f": {
                    "filter": {"term": {"source.ip": "a"}},
                    "aggs": {
                        "t": {
                            "top_hits": {
                                "size": 10,
                                "_source": ["url.full"],
                                "sort": ["@timestamp"],
                            }
                        }
                    },
                },
                "k": terms(size=5, order={"_key": "asc"}, missing="none", min_doc_count=1),
                "d": {"top_hits": {"_source": False}},
            }
        )
    )


def test_aggregation_names_and_containers() -> None:
    assert code(agg({"": terms()})) == "bad_shape"
    assert code(agg({"n" * 65: terms()})) == "bad_shape"
    validate(agg({"n" * 64: terms()}))
    assert code(agg({})) == "bad_shape"
    assert code(agg([terms()])) == "bad_shape"
    spec = Spec(**{**LOG.__dict__, "aggregate_fields": frozenset()})
    assert code(agg({"a": terms()}, spec)) == "aggregation_not_allowed"


# --------------------------------------------------------------------------- indices and URL


def test_log_index_count_is_at_most_2() -> None:
    two = ("acme-logs-squid-2026.10.08", "acme-logs-squid-2026.10.09")
    validate(search(GOOD, indices=two))
    assert code(search(GOOD, indices=(*two, "acme-logs-squid-2026.10.10"))) == "too_many_indices"


@pytest.mark.parametrize(
    "indices",
    [(), ("logs-*",), ("a,b",), ("_all",), ("A",), ("a/b",), ("a b",), ("c:remote",), (".",),
     ("..",), ("-a",), ("x" * 256,), ("a", "a")],
)  # fmt: skip
def test_index_names_are_exact(indices: tuple[str, ...]) -> None:
    assert code(search(GOOD, indices=indices)) == "index_not_allowed"


def test_index_name_length_and_characters() -> None:
    validate(search(GOOD, indices=("x" * 255,)))
    validate(search(GOOD, indices=(".alerts-security.alerts-x+1",)))


def test_url_parameters() -> None:
    validate(search(GOOD, url_params=(*FORCED, ("filter_path", "hits.hits._id"))))
    for params, expected in (
        ((*FORCED, ("scroll", "1m")), "forbidden_param"),
        ((*FORCED, ("filter_path", "a"), ("filter_path", "b")), "forbidden_param"),
        (FORCED[:2], "forbidden_param"),
        ((("allow_partial_search_results", "true"), *FORCED[1:]), "forbidden_param"),
        ((*FORCED, ("filter_path", 5)), "forbidden_param"),
    ):
        assert code(search(GOOD, url_params=params)) == expected


def spec_for(endpoint: Endpoint, family: Family = Family.CLUSTER, **kw: Any) -> Spec:
    return Spec(name="t", version=1, endpoint=endpoint, family=family, cost=CostClass.PROBE, **kw)


def test_mget() -> None:
    spec = replace(
        spec_for(
            Endpoint.MGET,
            Family.ALERTS,
            url_params=frozenset({"_source_includes", "_source"}),
            return_fields=frozenset({"a"}),
        ),
        cost=CostClass.LIGHT,
    )
    whole = FinalRequest(spec, indices=("x",), body={"ids": ["1", "2"]})
    assert code(whole) == "field_not_allowed"  # names its _source, or whole_documents
    validate(replace(whole, spec=replace(spec, whole_documents=True)))
    assert code(replace(whole, spec=replace(spec, cost=CostClass.PROBE))) == "cost_mismatch"
    validate(
        FinalRequest(
            spec, indices=("x",), body={"ids": ["1"]}, url_params=(("_source_includes", "a"),)
        )
    )
    validate(
        FinalRequest(spec, indices=("x",), body={"ids": ["1"]}, url_params=(("_source", "false"),))
    )
    for request, expected in (
        (FinalRequest(spec, indices=("x", "y"), body={"ids": ["1"]}), "index_not_allowed"),
        (FinalRequest(spec, indices=("x",), body={"docs": []}), "bad_shape"),
        (FinalRequest(spec, indices=("x",), body={"ids": ["1"] * 201}), "too_many_values"),
        (
            FinalRequest(
                spec, indices=("x",), body={"ids": ["1"]}, url_params=(("_source_includes", "a,b"),)
            ),
            "field_not_allowed",
        ),
        (
            FinalRequest(
                spec, indices=("x",), body={"ids": ["1"]}, url_params=(("_source", "true"),)
            ),
            "forbidden_param",
        ),
    ):
        assert code(request) == expected


def test_bodiless_endpoints() -> None:
    for endpoint in (Endpoint.INFO, Endpoint.NODE_STATS, Endpoint.AUTHENTICATE):
        validate(FinalRequest(spec_for(endpoint)))
        assert code(FinalRequest(spec_for(endpoint), body={})) == "bad_shape"
        assert code(FinalRequest(spec_for(endpoint), indices=("x",))) == "index_not_allowed"
    blocks = spec_for(Endpoint.INDEX_BLOCKS, url_params=frozenset({"flat_settings"}))
    validate(
        FinalRequest(
            blocks,
            indices=(".alerts-x", "logs-2026.10.09"),
            url_params=(("flat_settings", "true"),),
        )
    )
    assert code(FinalRequest(blocks)) == "index_not_allowed"


def test_resolve_index_takes_one_family_pattern() -> None:
    spec = spec_for(Endpoint.RESOLVE_INDEX)
    validate(FinalRequest(spec, pattern="acme-logs-squid-*"))
    for pattern, indices in (
        (None, ()),
        ("*", ()),
        ("acme-logs-*-*", ()),
        ("a,b-*", ()),
        ("acme-logs-squid-*", ("x",)),
    ):
        assert code(FinalRequest(spec, pattern=pattern, indices=indices)) == "index_not_allowed"
    other = FinalRequest(spec_for(Endpoint.INFO), pattern="logs-*")
    assert code(other) == "index_not_allowed"


def test_has_privileges() -> None:
    spec = spec_for(Endpoint.HAS_PRIVILEGES)
    good = {"cluster": ["monitor"], "index": [{"names": ["a"], "privileges": ["read"]}]}
    validate(FinalRequest(spec, body=good))
    validate(FinalRequest(spec, body={"cluster": ["monitor"]}))
    bad: tuple[Any, ...] = (
        {},
        {"cluster": "monitor"},
        {"cluster": [1]},
        {"index": [{"names": ["a"]}]},
        {"index": [{"names": [], "privileges": ["read"]}]},
        {"index": [{"names": ["a"], "privileges": [1]}]},
        {"index": "x"},
        {"application": []},
    )
    for body in bad:
        assert code(FinalRequest(spec, body=body)) == "bad_shape"


def test_a_body_must_be_plain_json() -> None:
    assert code(search({"size": 1, "query": {"term": {"source.ip": object()}}})) == "bad_shape"
    assert (
        code(search({"size": 1, "query": {"range": {"@timestamp": {"gte": float("inf")}}}}))
        == "bad_shape"
    )
    assert code(search(["size"])) == "bad_shape"
    assert code(search(None)) == "bad_shape"


# --------------------------------------------------------------------------- properties

JSON = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=8),
    lambda children: st.lists(children, max_size=4)
    | st.dictionaries(
        st.sampled_from(
            ["query", "bool", "filter", "term", "terms", "range", "size", "aggs", "terms",
             "field", "source.ip", "sort", "_source", "gte", "script", "wildcard", "value",
             "must", "exists", "ids", "values", "from", "pit", "x"]
        ),
        children,
        max_size=4,
    ),
    max_leaves=30,
)  # fmt: skip


@given(JSON)
def test_any_body_is_accepted_or_refused_never_crashes(body: Any) -> None:
    with contextlib.suppress(TemplateRejectedError, UnsupportedValueError):
        validate(search(body))


@given(
    st.sampled_from(sorted(["regexp", "wildcard", "prefix", "fuzzy", "query_string", "script"])),
    st.integers(0, 5),
)
def test_a_forbidden_clause_anywhere_in_the_query_is_refused(kind: str, depth: int) -> None:
    node: dict[str, Any] = {kind: {"source.ip": "a"}}
    for _ in range(depth):
        node = {"bool": {"must": [{"term": {"source.ip": "b"}}, node]}}
    with pytest.raises(TemplateRejectedError):
        validate(search({"size": 1, "query": node}))
