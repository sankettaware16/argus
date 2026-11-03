"""The query contract's validator. It inspects the **final** request, after index
resolution and after the gateway added its own parameters, and refuses anything outside the
contract before a single byte is sent.

Allowlists, not denylists: a clause, aggregation, body key or URL parameter that is not listed
is refused. The forbidden lists only give the clearer reason for shapes known to be dangerous.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from argus import site
from argus.gateway.errors import TemplateRejectedError, UnsupportedValueError
from argus.gateway.templates import CostClass, Endpoint, Family, Spec
from argus.site import DISCOVERY_FIELDS

MAX_TERMS = 200
MAX_IDS = 200
MAX_ID_CHARS = 512
MAX_TOP_HITS = 10
MAX_BUCKETS = 1000
MAX_AGG_DEPTH = 3
MAX_LOG_AGG_DEPTH = 2
MAX_LOG_INDICES = 2
MAX_BOOL_DEPTH = 8
MAX_CLAUSES = 256
MAX_BODY_BYTES = 64 * 1024
MAX_TOTAL_HITS = 10_000
MAX_SEARCH_AFTER = 4
MAX_TIMEOUT_SECONDS = 60
# The limits for a field no log family of the site declares (the alerts index, a field the families
# do not use): dynamic mapping's default for .keyword sub-fields, and ECS's for keyword fields. A
# field of a log family has its family's ``ignore_above`` (``site.value_limit``).
KEYWORD_IGNORE_ABOVE = 256
FIELD_IGNORE_ABOVE = 1024

# The parameters the gateway adds to every search; nothing may change them.
FORCED_SEARCH_PARAMS = {
    "allow_partial_search_results": "false",
    "ignore_unavailable": "false",
    "max_concurrent_shard_requests": "1",
}

ALLOWED_CLAUSES = frozenset(
    {"bool", "term", "terms", "range", "match_phrase", "exists", "ids", "match_all"}
)
FORBIDDEN_CLAUSES = frozenset(
    {
        "regexp", "wildcard", "prefix", "fuzzy", "query_string", "simple_query_string",
        "script", "script_score", "function_score", "more_like_this", "percolate", "terms_set",
        "intervals", "match", "multi_match", "combined_fields", "match_bool_prefix",
        "match_phrase_prefix", "nested", "has_child", "has_parent", "parent_id", "geo_shape",
        "distance_feature", "rank_feature", "pinned", "wrapper", "span_term", "span_multi",
    }
)  # fmt: skip
ALLOWED_AGGS = frozenset(
    {"terms", "date_histogram", "cardinality", "min", "max", "sum", "avg", "value_count",
     "filter", "top_hits"}
)  # fmt: skip
METRIC_AGGS = frozenset({"cardinality", "min", "max", "sum", "avg", "value_count", "top_hits"})
FORBIDDEN_AGGS = frozenset(
    {
        "significant_terms", "significant_text", "scripted_metric", "composite", "rare_terms",
        "multi_terms", "bucket_script", "bucket_selector", "bucket_sort", "histogram",
        "percentiles", "terms_lookup", "global", "sampler", "diversified_sampler", "nested",
        "reverse_nested", "adjacency_matrix", "auto_date_histogram", "variable_width_histogram",
    }
)  # fmt: skip
FORBIDDEN_KEYS = frozenset({"script", "scripts", "runtime_mappings", "script_fields"})
SEARCH_KEYS = frozenset(
    {"query", "size", "from", "_source", "sort", "aggs", "aggregations", "track_total_hits",
     "search_after", "fields", "timeout", "pit"}
)  # fmt: skip
RANGE_OPS = frozenset({"gte", "gt", "lte", "lt"})
_INDEX_NAME = re.compile(r"[a-z0-9.][a-z0-9._+-]{0,254}")
# A threat-intel source may be named by a pattern (``logs-ti_*``, Elastic's own integration): the
# gateway has already checked that it is exactly one the site names (``site.ti_sources``).
_TI_NAME = re.compile(r"[a-z0-9][a-z0-9._+*-]{0,254}")
_MAPPED_INDEX = re.compile(r"(?:\.ds-)?[a-z0-9][a-z0-9._+-]{0,250}")
_FAMILY_PATTERN = re.compile(r"[a-z0-9.][a-z0-9._+-]{0,200}[-._]\*")
# `argus discover` (gateway/discovery.py): the patterns a listing may name, the values of its
# `expand_wildcards`, and how many fields one mapping request asks about.
DISCOVERY_PATTERNS = frozenset({"*", ".alerts-security.alerts-*"})
DISCOVERY_EXPAND = frozenset({"open", "open,hidden"})
MAX_DISCOVERY_FIELDS = 80
_INTERVAL = re.compile(r"([1-9][0-9]{0,5})(ms|s|m|h|d)")
_TIMEOUT = re.compile(r"([1-9][0-9]{0,4})(ms|s)")
_UNIT_MS = {"ms": 1, "s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000}


@dataclass(frozen=True)
class FinalRequest:
    """Exactly what the transport would send, before it is turned into bytes."""

    spec: Spec
    indices: tuple[str, ...] = ()
    pattern: str | None = None  # resolve_index only
    url_params: tuple[tuple[str, str], ...] = ()
    body: Any = None


def encode_body(body: Any) -> bytes:
    """The exact bytes the transport sends (and the validator measures)."""
    return json.dumps(body, allow_nan=False, ensure_ascii=True, separators=(",", ":")).encode()


def reject(code: str, detail: str) -> TemplateRejectedError:
    return TemplateRejectedError(code, detail)


def validate(request: FinalRequest) -> None:
    """Raise TemplateRejectedError or UnsupportedValueError unless ``request`` keeps it."""
    _Check(request).run()


class _Check:
    def __init__(self, request: FinalRequest) -> None:
        self.request = request
        self.spec = request.spec
        self.log = request.spec.family is Family.LOG
        self.clauses = 0
        self.buckets = 0
        self.max_buckets = request.spec.max_buckets or MAX_BUCKETS
        self.url_source = False  # _source or _source_includes given as a URL parameter

    def run(self) -> None:
        self.indices()
        self.url_params()
        body = self.request.body
        endpoint = self.spec.endpoint
        if body is not None:
            try:
                size = len(encode_body(body))
            except (TypeError, ValueError, RecursionError):
                raise reject("bad_shape", "the body is not plain JSON") from None
            if size > MAX_BODY_BYTES:
                raise reject("body_too_large", f"{size} bytes (limit {MAX_BODY_BYTES})")
            self.forbidden_keys(body)
        if self.spec.cost is CostClass.PROBE and endpoint is Endpoint.MGET:
            raise reject("cost_mismatch", "an mget is never probe-cost")
        if endpoint is Endpoint.SEARCH:
            self.search(body)
        elif endpoint is Endpoint.MGET:
            self.mget(body)
        elif endpoint is Endpoint.HAS_PRIVILEGES:
            self.has_privileges(body)
        elif body is not None:
            raise reject("bad_shape", f"{endpoint} takes no body")

    # ---------------------------------------------------------------- indices and URL

    def indices(self) -> None:
        indices = self.request.indices
        family = self.spec.family
        endpoint = self.spec.endpoint
        if endpoint is Endpoint.RESOLVE_INDEX:
            pattern = self.request.pattern
            if indices or pattern is None or not _FAMILY_PATTERN.fullmatch(pattern):
                raise reject("index_not_allowed", "resolve_index takes one family pattern")
            return
        if endpoint is Endpoint.DISCOVER_INDICES:
            if indices or self.request.pattern not in DISCOVERY_PATTERNS:
                raise reject("index_not_allowed", "discover_indices takes one of two patterns")
            return
        if endpoint is Endpoint.FIELD_MAPPING:
            self.mapping_fields()
        elif self.request.pattern is not None:
            raise reject("index_not_allowed", "only resolve_index takes a pattern")
        if family is Family.CLUSTER:
            if indices and endpoint is not Endpoint.INDEX_BLOCKS:
                raise reject("index_not_allowed", f"{endpoint} reads no index")
            if endpoint is Endpoint.INDEX_BLOCKS and not indices:
                raise reject("index_not_allowed", "index_blocks needs its indices")
        elif family is Family.DISCOVERY:
            if len(indices) != (1 if endpoint is Endpoint.FIELD_MAPPING else 0):
                raise reject("index_not_allowed", f"{endpoint} reads exactly its own index")
        elif not indices:
            raise reject("index_not_allowed", "no index")
        if len(set(indices)) != len(indices):
            raise reject("index_not_allowed", "an index is listed twice")
        for name in indices:
            allowed = _TI_NAME if family is Family.TI else _INDEX_NAME
            if not allowed.fullmatch(name) or name in {".", ".."}:
                raise reject("index_not_allowed", "index names must be exact, no patterns")
        mapped = endpoint is Endpoint.FIELD_MAPPING
        if mapped and not all(_MAPPED_INDEX.fullmatch(name) for name in indices):
            raise reject("index_not_allowed", "a mapping is read of a log index, not a system one")
        if self.log and len(indices) > MAX_LOG_INDICES:
            raise reject("too_many_indices", f"{len(indices)} log indices (limit 2)")
        if endpoint is Endpoint.MGET and len(indices) != 1:
            raise reject("index_not_allowed", "mget reads exactly one index")

    def mapping_fields(self) -> None:
        """A field mapping request asks about a few allowlisted fields (carried in ``pattern``)."""
        fields = (self.request.pattern or "").split(",")
        if (
            not self.request.pattern
            or len(fields) > MAX_DISCOVERY_FIELDS
            or len(set(fields)) != len(fields)
            or not set(fields) <= DISCOVERY_FIELDS
        ):
            raise reject("field_not_allowed", "field_mapping asks about allowlisted fields only")

    def url_params(self) -> None:
        seen: set[str] = set()
        search = self.spec.endpoint is Endpoint.SEARCH
        for name, value in self.request.url_params:
            if not isinstance(name, str) or not isinstance(value, str):
                raise reject("forbidden_param", "URL parameters are text")
            if name in seen:
                raise reject("forbidden_param", f"{name} given twice")
            seen.add(name)
            if search and name in FORCED_SEARCH_PARAMS:
                if value != FORCED_SEARCH_PARAMS[name]:
                    raise reject("forbidden_param", f"{name} must be {FORCED_SEARCH_PARAMS[name]}")
                continue
            if name not in self.spec.url_params:
                raise reject("forbidden_param", f"{name} is not allowed for {self.spec.name}")
            if name == "expand_wildcards" and value not in DISCOVERY_EXPAND:
                raise reject("forbidden_param", "expand_wildcards is open or open,hidden")
            if name in {"_source", "_source_includes"}:
                self.url_source = True
            if name == "_source_includes":
                for field in value.split(","):
                    self.return_field(field)
            elif name == "_source" and value != "false":
                raise reject("forbidden_param", "_source may only be false")
        if search and not set(FORCED_SEARCH_PARAMS) <= seen:
            raise reject("forbidden_param", "a search must carry the complete-results parameters")

    # ---------------------------------------------------------------- bodies

    def forbidden_keys(self, node: Any) -> None:
        stack = [node]
        while stack:
            item = stack.pop()
            if isinstance(item, Mapping):
                for key, value in item.items():
                    if key in FORBIDDEN_KEYS:
                        raise reject("forbidden_key", f"{key} is not allowed anywhere")
                    stack.append(value)
            elif isinstance(item, list):
                stack.extend(item)

    def search(self, body: Any) -> None:
        if not isinstance(body, Mapping):
            raise reject("bad_shape", "a search body is an object")
        unknown = set(body) - SEARCH_KEYS
        if unknown:
            raise reject("unknown_key", ", ".join(sorted(map(str, unknown))))
        if "aggs" in body and "aggregations" in body:
            raise reject("bad_shape", "aggs given twice")
        if "from" in body and (not _is_int(body["from"]) or body["from"] != 0):
            raise reject("from_not_allowed", "paging with from; use search_after")
        size = body.get("size", 10)
        if not _is_int(size) or not 0 <= size <= self.spec.max_size:
            raise reject("size_too_large", f"size must be 0..{self.spec.max_size}")
        if self.log and body.get("track_total_hits") is not False:
            raise reject("total_hits_not_allowed", "log searches set track_total_hits to false")
        if "track_total_hits" in body:
            total = body["track_total_hits"]
            if not (
                total is True or total is False or (_is_int(total) and 0 <= total <= MAX_TOTAL_HITS)
            ):
                raise reject("bad_shape", "track_total_hits")
        if "pit" in body:
            self.pit(body["pit"])
        if "timeout" in body:
            self.timeout(body["timeout"])
        if "_source" in body:
            self.source(body["_source"])
        elif size > 0 and not self.url_source:
            raise reject("field_not_allowed", "a search that returns hits names its _source")
        if "fields" in body:
            self.fields(body["fields"])
        sort_keys = self.sort(body["sort"], pit="pit" in body) if "sort" in body else 0
        if "search_after" in body:
            after = body["search_after"]
            if (
                not isinstance(after, list)
                or not 1 <= len(after) <= min(sort_keys, MAX_SEARCH_AFTER)
                or not all(_is_scalar(v) for v in after)
            ):
                raise reject("bad_shape", "search_after needs a sort and one literal per sort key")
        if "query" in body:
            self.clause(body["query"], 1)
        if self.log:
            self.stream_is_bounded(body)
        aggs = body.get("aggs", body.get("aggregations"))
        if self.spec.cost is CostClass.PROBE and (size > 1 or aggs is not None):
            raise reject("cost_mismatch", "a probe-cost search reads one document, no aggregation")
        if self.log and aggs is not None and self.spec.cost is not CostClass.HEAVY:
            raise reject("cost_mismatch", "an aggregation on log indices is heavy")
        if aggs is not None:
            if not self.spec.aggregate_fields:
                raise reject("aggregation_not_allowed", f"{self.spec.name} does not aggregate")
            self.aggs(aggs, 1, 1)

    def stream_is_bounded(self, body: Mapping[str, Any]) -> None:
        """A data stream or alias is one name whatever the time asked for, so its search must say
        which time: a range on the family's time field among the filters, which Elasticsearch
        can use to skip the backing indices outside it. A daily family names its days in
        its index names, which the gateway bounds (``MAX_LOG_INDICES``)."""
        for name in self.request.indices:
            family = next(
                (f for f in site.active().families if not f.daily and f.pattern == name), None
            )
            if family is not None and not _filters_on_range(body.get("query"), family.time_field):
                raise reject(
                    "range_required", f"a search of {name} needs a range on {family.time_field}"
                )

    def pit(self, pit: Any) -> None:
        if self.log or not self.spec.allow_pit:
            raise reject("pit_not_allowed", f"{self.spec.name} may not use a point in time")
        if (
            not isinstance(pit, Mapping)
            or set(pit) != {"id", "keep_alive"}
            or not isinstance(pit["id"], str)
            or not 0 < len(pit["id"]) <= 4096
            or not isinstance(pit["keep_alive"], str)
            or pit["keep_alive"] not in {"1m", "2m", "5m"}
        ):
            raise reject("bad_shape", "pit is {id, keep_alive of 1m, 2m or 5m}")

    def timeout(self, value: Any) -> None:
        match = _TIMEOUT.fullmatch(value) if isinstance(value, str) else None
        if match is None or int(match[1]) * _UNIT_MS[match[2]] > MAX_TIMEOUT_SECONDS * 1000:
            raise reject("bad_shape", f"timeout is at most {MAX_TIMEOUT_SECONDS}s")

    def return_field(self, field: Any) -> None:
        if not isinstance(field, str) or field not in self.spec.return_fields:
            raise reject("field_not_allowed", f"{field!s:.80} may not be returned")

    def source(self, value: Any) -> None:
        if value is False:
            return
        if isinstance(value, Mapping) and set(value) == {"includes"}:
            value = value["includes"]
        if not isinstance(value, list) or not value:
            raise reject("field_not_allowed", "_source is false or a list of allowed fields")
        for field in value:
            self.return_field(field)

    def fields(self, value: Any) -> None:
        if not isinstance(value, list) or not value:
            raise reject("bad_shape", "fields is a non-empty list")
        for item in value:
            if isinstance(item, Mapping):
                if set(item) - {"field", "format"} or "field" not in item:
                    raise reject("bad_shape", "fields entries are {field, format}")
                if "format" in item and not isinstance(item["format"], str):
                    raise reject("bad_shape", "fields format is text")
                item = item["field"]
            self.return_field(item)

    def sort(self, value: Any, *, pit: bool) -> int:
        entries = value if isinstance(value, list) else [value]
        if not entries:
            raise reject("bad_sort", "an empty sort")
        for entry in entries:
            if isinstance(entry, str):
                field, order = entry, None
            elif isinstance(entry, Mapping) and len(entry) == 1:
                field, order = next(iter(entry.items()))
            else:
                raise reject("bad_sort", "sort entries are a field or {field: order}")
            if isinstance(order, Mapping):
                if set(order) - {"order", "format", "unmapped_type", "missing"}:
                    raise reject(
                        "bad_sort", "sort options are order, format, unmapped_type, missing"
                    )
                if not all(_is_scalar(v) for v in order.values()):
                    raise reject("bad_sort", "sort options are literals")
                order = order.get("order")
            if order not in (None, "asc", "desc"):
                raise reject("bad_sort", "order is asc or desc")
            if field == "_id":
                raise reject("bad_sort", "never sort on _id")
            if field == "_shard_doc" and pit:
                continue
            if not isinstance(field, str) or field not in self.spec.sort_fields:
                raise reject("bad_sort", f"{field!s:.80} is not a sort field of {self.spec.name}")
        return len(entries)

    # ---------------------------------------------------------------- query clauses

    def filter_field(self, field: Any) -> str:
        if not isinstance(field, str) or field not in self.spec.filter_fields:
            raise reject("field_not_allowed", f"{field!s:.80} may not be filtered on")
        return field

    def literal(self, field: str, value: Any) -> None:
        if not _is_scalar(value):
            raise reject("value_not_literal", f"{field}: values are JSON literals")
        if isinstance(value, str):
            limit = site.value_limit(self.request.indices, field)
            if limit is None:  # not a keyword of a log family the request reads: the defaults
                limit = KEYWORD_IGNORE_ABOVE if field.endswith(".keyword") else FIELD_IGNORE_ABOVE
            if _utf16_len(value) > limit:
                raise UnsupportedValueError(
                    f"{field}: a value longer than {limit} characters is not indexed"
                )

    def single_field(self, kind: str, body: Any) -> tuple[str, Any]:
        if not isinstance(body, Mapping) or len(body) != 1:
            raise reject("bad_shape", f"{kind} names exactly one field")
        field, value = next(iter(body.items()))
        return self.filter_field(field), value

    def clause(self, node: Any, depth: int) -> None:
        self.clauses += 1
        if self.clauses > MAX_CLAUSES:
            raise reject("too_complex", f"more than {MAX_CLAUSES} query clauses")
        if depth > MAX_BOOL_DEPTH:
            raise reject("too_complex", f"bool nesting deeper than {MAX_BOOL_DEPTH}")
        if not isinstance(node, Mapping) or len(node) != 1:
            raise reject("bad_shape", "a clause is {type: body}")
        kind, body = next(iter(node.items()))
        if kind in FORBIDDEN_CLAUSES:
            raise reject("forbidden_clause", f"{kind} queries are not allowed")
        if kind not in ALLOWED_CLAUSES:
            raise reject("unknown_clause", f"{kind!s:.40} is not an allowed clause")
        getattr(self, f"clause_{kind}")(body, depth)

    def clause_bool(self, body: Any, depth: int) -> None:
        if not isinstance(body, Mapping) or not body:
            raise reject("bad_shape", "bool is an object")
        for key, value in body.items():
            if key == "minimum_should_match":
                if not _is_int(value) or value < 0:
                    raise reject("bad_shape", "minimum_should_match is a whole number")
            elif key in {"must", "filter", "should", "must_not"}:
                for item in value if isinstance(value, list) else [value]:
                    self.clause(item, depth + 1)
            else:
                raise reject("bad_shape", f"bool has no {key!s:.40}")

    def clause_term(self, body: Any, depth: int) -> None:
        field, value = self.single_field("term", body)
        if isinstance(value, Mapping):
            if set(value) != {"value"}:
                raise reject("bad_shape", "term is {field: value} or {field: {value}}")
            value = value["value"]
        self.literal(field, value)

    def clause_terms(self, body: Any, depth: int) -> None:
        field, values = self.single_field("terms", body)
        if isinstance(values, Mapping):
            raise reject("forbidden_clause", "terms lookup is not allowed")
        if not isinstance(values, list) or not values:
            raise reject("bad_shape", "terms takes a non-empty list")
        if len(values) > MAX_TERMS:
            raise reject("too_many_values", f"{len(values)} terms (limit {MAX_TERMS})")
        for value in values:
            self.literal(field, value)

    def clause_range(self, body: Any, depth: int) -> None:
        field, bounds = self.single_field("range", body)
        if not isinstance(bounds, Mapping) or not set(bounds) & RANGE_OPS:
            raise reject("bad_shape", "range needs gte, gt, lte or lt")
        for key, value in bounds.items():
            if key == "format":
                if not isinstance(value, str):
                    raise reject("bad_shape", "range format is text")
            elif key in RANGE_OPS:
                if isinstance(value, bool) or not _is_scalar(value):
                    raise reject("value_not_literal", f"{field}: range bounds are literals")
            else:
                raise reject("bad_shape", f"range has no {key!s:.40}")

    def clause_match_phrase(self, body: Any, depth: int) -> None:
        field, value = self.single_field("match_phrase", body)
        if isinstance(value, Mapping):
            if set(value) != {"query"}:
                raise reject("bad_shape", "match_phrase is {field: text} or {field: {query}}")
            value = value["query"]
        if not isinstance(value, str):
            raise reject("value_not_literal", f"{field}: match_phrase takes text")
        self.literal(field, value)

    def clause_exists(self, body: Any, depth: int) -> None:
        if not isinstance(body, Mapping) or set(body) != {"field"}:
            raise reject("bad_shape", "exists is {field}")
        self.filter_field(body["field"])

    def clause_ids(self, body: Any, depth: int) -> None:
        if not isinstance(body, Mapping) or set(body) != {"values"}:
            raise reject("bad_shape", "ids is {values}")
        _ids(body["values"])

    def clause_match_all(self, body: Any, depth: int) -> None:
        if body != {}:
            raise reject("bad_shape", "match_all takes no options")

    # ---------------------------------------------------------------- aggregations

    def aggs(self, aggs: Any, depth: int, parents: int) -> None:
        """Check an aggs object whose aggregations run in each of ``parents`` buckets. The
        buckets (and top hits) of all aggregations together stay within MAX_BUCKETS."""
        if not isinstance(aggs, Mapping) or not aggs:
            raise reject("bad_shape", "aggs is a non-empty object")
        limit = self.spec.max_agg_depth or (MAX_LOG_AGG_DEPTH if self.log else MAX_AGG_DEPTH)
        if depth > limit:
            raise reject("aggregation_too_deep", f"aggregations nest at most {limit} deep")
        for name, node in aggs.items():
            if not isinstance(name, str) or not 0 < len(name) <= 64:
                raise reject("bad_shape", "aggregation names are 1-64 characters")
            if not isinstance(node, Mapping):
                raise reject("bad_shape", "an aggregation is an object")
            subs = [key for key in node if key in {"aggs", "aggregations"}]
            kinds = [key for key in node if key not in {"aggs", "aggregations"}]
            if len(subs) > 1 or len(kinds) != 1:
                raise reject("bad_shape", "an aggregation has one type and optional sub-aggs")
            kind = kinds[0]
            if kind in FORBIDDEN_AGGS:
                raise reject("forbidden_aggregation", f"{kind} is not allowed")
            if kind not in ALLOWED_AGGS:
                raise reject("unknown_aggregation", f"{kind!s:.40} is not an allowed aggregation")
            own = getattr(self, f"agg_{kind}")(node[kind])
            total = parents * own
            if kind not in METRIC_AGGS or kind == "top_hits":
                self.buckets += total
            if self.buckets > self.max_buckets:
                raise reject(
                    "too_many_buckets", f"up to {self.buckets} buckets (limit {self.max_buckets})"
                )
            if subs:
                if kind in METRIC_AGGS:
                    raise reject("bad_shape", f"{kind} takes no sub-aggregations")
                self.aggs(node[subs[0]], depth + 1, total)

    def agg_field(self, body: Any, allowed: set[str], kind: str) -> Mapping[str, Any]:
        if not isinstance(body, Mapping) or "field" not in body:
            raise reject("bad_shape", f"{kind} needs a field")
        extra = set(body) - allowed - {"field"}
        if extra:
            raise reject("bad_shape", f"{kind} has no {sorted(map(str, extra))[0]:.40}")
        field = body["field"]
        if not isinstance(field, str) or field not in self.spec.aggregate_fields or field == "_id":
            raise reject("field_not_allowed", f"{field!s:.80} may not be aggregated")
        return body

    def agg_terms(self, body: Any) -> int:
        body = self.agg_field(body, {"size", "min_doc_count", "order", "missing"}, "terms")
        size = body.get("size")
        if not _is_int(size) or not 1 <= size <= MAX_BUCKETS:
            raise reject("too_many_buckets", f"terms needs a size of 1..{MAX_BUCKETS}")
        order = body.get("order")
        if order is not None and (
            not isinstance(order, Mapping)
            or len(order) != 1
            or next(iter(order)) not in {"_count", "_key"}
            or not isinstance(next(iter(order.values())), str)
            or next(iter(order.values())) not in {"asc", "desc"}
        ):
            raise reject("bad_shape", "terms order is {_count|_key: asc|desc}")
        if "missing" in body and not _is_scalar(body["missing"]):
            raise reject("value_not_literal", "terms missing is a literal")
        _min_doc_count(body)
        return int(size)

    def agg_date_histogram(self, body: Any) -> int:
        body = self.agg_field(
            body, {"fixed_interval", "hard_bounds", "min_doc_count", "format"}, "date_histogram"
        )
        interval = body.get("fixed_interval")
        match = _INTERVAL.fullmatch(interval) if isinstance(interval, str) else None
        bounds = body.get("hard_bounds")
        if match is None or not isinstance(bounds, Mapping) or set(bounds) != {"min", "max"}:
            raise reject("bad_shape", "date_histogram needs fixed_interval and hard_bounds")
        low, high = _epoch_ms(bounds["min"]), _epoch_ms(bounds["max"])
        if low is None or high is None or high < low:
            raise reject("bad_shape", "hard_bounds are two times, min before max")
        if "format" in body and not isinstance(body["format"], str):
            raise reject("bad_shape", "date_histogram format is text")
        _min_doc_count(body)
        step = int(match[1]) * _UNIT_MS[match[2]]
        return (high - low) // step + 1

    def agg_cardinality(self, body: Any) -> int:
        body = self.agg_field(body, {"precision_threshold"}, "cardinality")
        threshold = body.get("precision_threshold", 3000)
        if not _is_int(threshold) or not 0 <= threshold <= 40_000:
            raise reject("bad_shape", "precision_threshold is 0..40000")
        return 1

    def _metric(self, kind: str, body: Any) -> int:
        self.agg_field(body, set(), kind)
        return 1

    def agg_min(self, body: Any) -> int:
        return self._metric("min", body)

    def agg_max(self, body: Any) -> int:
        return self._metric("max", body)

    def agg_sum(self, body: Any) -> int:
        return self._metric("sum", body)

    def agg_avg(self, body: Any) -> int:
        return self._metric("avg", body)

    def agg_value_count(self, body: Any) -> int:
        return self._metric("value_count", body)

    def agg_filter(self, body: Any) -> int:
        self.clause(body, 1)
        return 1

    def agg_top_hits(self, body: Any) -> int:
        if not isinstance(body, Mapping) or set(body) - {"size", "_source", "sort"}:
            raise reject("bad_shape", "top_hits takes size, _source and sort")
        size = body.get("size", 3)
        if not _is_int(size) or not 1 <= size <= MAX_TOP_HITS:
            raise reject("size_too_large", f"top_hits size is 1..{MAX_TOP_HITS}")
        if "_source" not in body:
            raise reject("field_not_allowed", "top_hits names its _source")
        self.source(body["_source"])
        if "sort" in body:
            self.sort(body["sort"], pit=False)
        return int(size)

    # ---------------------------------------------------------------- other endpoints

    def mget(self, body: Any) -> None:
        if not isinstance(body, Mapping) or set(body) != {"ids"}:
            raise reject("bad_shape", "an mget body is {ids}")
        _ids(body["ids"])
        if not self.spec.whole_documents and not self.url_source:
            raise reject("field_not_allowed", "an mget names its _source")

    def has_privileges(self, body: Any) -> None:
        if (
            not isinstance(body, Mapping)
            or not body
            or set(body) - {"cluster", "index", "application"}
        ):
            raise reject("bad_shape", "has_privileges takes cluster, index and application")
        applications = body.get("application", [])
        if not isinstance(applications, list) or ("application" in body and not applications):
            raise reject("bad_shape", "application privileges are a non-empty list")
        for entry in applications:
            if (
                not isinstance(entry, Mapping)
                or set(entry) != {"application", "resources", "privileges"}
                or not isinstance(entry["application"], str)
                or not _str_list(entry["resources"])
                or not _str_list(entry["privileges"])
            ):
                raise reject(
                    "bad_shape", "application privileges are {application, resources, privileges}"
                )
        cluster = body.get("cluster", [])
        if not isinstance(cluster, list) or not all(isinstance(p, str) for p in cluster):
            raise reject("bad_shape", "cluster privileges are a list of names")
        for entry in body.get("index", []) if isinstance(body.get("index", []), list) else [None]:
            if (
                not isinstance(entry, Mapping)
                or set(entry) != {"names", "privileges"}
                or not _str_list(entry["names"])
                or not _str_list(entry["privileges"])
            ):
                raise reject("bad_shape", "index privileges are {names, privileges}")


def _filters_on_range(query: Any, field: str) -> bool:
    """Whether a query's top-level ``bool.filter`` (or ``must``) holds a ``range`` on ``field``."""
    bool_ = query.get("bool") if isinstance(query, Mapping) else None
    if not isinstance(bool_, Mapping):
        return False
    for key in ("filter", "must"):
        clauses = bool_.get(key)
        for clause in clauses if isinstance(clauses, list) else [clauses]:
            ranged = clause.get("range") if isinstance(clause, Mapping) else None
            if isinstance(ranged, Mapping) and field in ranged:
                return True
    return False


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_scalar(value: Any) -> bool:
    """A JSON literal. NaN and infinities never get here: the whole body was checked to be
    plain JSON first."""
    return isinstance(value, str | int | float | bool)


def _utf16_len(value: str) -> int:
    """Length as Elasticsearch counts it for ignore_above (Java chars, UTF-16 code units)."""
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def _min_doc_count(body: Mapping[str, Any]) -> None:
    if "min_doc_count" in body and (
        not _is_int(body["min_doc_count"]) or body["min_doc_count"] < 0
    ):
        raise reject("bad_shape", "min_doc_count is a whole number")


def _str_list(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(v, str) for v in value)


def _ids(values: Any) -> None:
    if not isinstance(values, list) or not values:
        raise reject("bad_shape", "ids are a non-empty list")
    if len(values) > MAX_IDS:
        raise reject("too_many_values", f"{len(values)} ids (limit {MAX_IDS})")
    for value in values:
        if not isinstance(value, str) or not 0 < len(value) <= MAX_ID_CHARS:
            raise reject("value_not_literal", "ids are non-empty text")


def _epoch_ms(value: Any) -> int | None:
    if _is_int(value):
        return int(value)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return None
        return int(parsed.timestamp() * 1000)
    return None


def scalar_list(values: Sequence[Any]) -> list[Any]:
    """Values for a terms clause, as given (a helper for templates)."""
    return list(values)
