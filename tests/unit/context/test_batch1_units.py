"""Q-F4's five templates, the pure parts, exactly: the requests, the parameters' bounds, the
windows, what the answers mean (D-023: a zero from the logs is unknown), the sentences, the
gate's rules and the catalogue. Hypothesis: build() is valid for random windows (midnight,
IPv4 and IPv6, values at ignore_above), one daily index, at most 1,000 buckets and an answer
within the 16 KiB snapshot."""

from __future__ import annotations

import json
import random
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from argus.config.settings import EnrichmentSettings
from argus.context import batch1, beacon, bounds, dns, paths, source_events
from argus.context.evidence import canonical, extract
from argus.context.packs import SNAPSHOT_BYTES, SNAPSHOT_ROWS, TaskSpec, rebuild
from argus.gateway.errors import TemplateRejectedError
from argus.gateway.gateway import Gateway, Targets
from argus.gateway.state import MemoryStore
from argus.gateway.templates import REGISTRY, CostClass, Window
from argus.gateway.validator import MAX_BUCKETS, _Check

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[3]
IST = timezone(timedelta(hours=5, minutes=30))
TARGETS = Targets()


def at(h: int, m: int = 0, d: int = 20, s: int = 0) -> datetime:
    return datetime(2026, 10, d, h, m, s, tzinfo=UTC)


def window_of(start: datetime, end: datetime) -> dict[str, Any]:
    return {"range": {"@timestamp": {"gte": bounds.iso(start), "lt": bounds.iso(end)}}}


# ----------------------------------------------------------------------------- requests


def test_the_pair_request_is_exactly_this() -> None:
    params = beacon.PairParams(host="10.1.2.3", destination="203.0.113.5", start=at(3),
                               end=at(8))  # fmt: skip
    plan = beacon.ProxyPair().build(params)
    assert plan.body == {
        "size": 0,
        "track_total_hits": False,
        "query": {"bool": {"filter": [
            {"term": {"source.ip": "10.1.2.3"}},
            {"term": {"destination.ip": "203.0.113.5"}},
            window_of(at(3), at(8)),
        ]}},
        "aggs": {
            "requests": {"value_count": {"field": "@timestamp"}},
            "first": {"min": {"field": "@timestamp"}},
            "last": {"max": {"field": "@timestamp"}},
            "bytes": {"sum": {"field": "destination.bytes"}},
            "beats": {"date_histogram": {
                "field": "@timestamp", "fixed_interval": "1m", "min_doc_count": 1,
                "hard_bounds": {"min": "2026-10-20T03:00:00Z", "max": "2026-10-20T08:00:00Z"},
            }},
        },
    }  # fmt: skip
    assert plan.url_params == (("filter_path", "-aggregations.beats.buckets.key_as_string"),)
    assert plan.window == Window("squid", at(3), at(8))
    wide = beacon.ProxyPair().build(params.model_copy(update={"end": at(15)}))
    assert wide.body["aggs"]["beats"]["date_histogram"]["fixed_interval"] == "2m"
    assert beacon.interval(at(3), at(9)) == timedelta(minutes=1)  # 6 h: still 1-minute
    assert beacon.interval(at(3), at(9, 1)) == timedelta(minutes=2)
    with pytest.raises(AssertionError):
        beacon.ProxyPair().build(dns.DomainsParams(ip="10.1.2.3", start=at(3), end=at(4)))


def test_the_contact_request_is_exactly_this() -> None:
    params = beacon.ContactParams(destination="203.0.113.5", start=at(1), end=at(22, 59))
    body = beacon.ProxyContact().build(params).body
    assert body == {
        "size": 0,
        "track_total_hits": False,
        "query": {"bool": {"filter": [
            {"term": {"destination.ip": "203.0.113.5"}}, window_of(at(1), at(22, 59)),
        ]}},
        "aggs": {
            "requests": {"value_count": {"field": "@timestamp"}},
            "first": {"min": {"field": "@timestamp"}},
            "last": {"max": {"field": "@timestamp"}},
            "host_count": {"cardinality": {"field": "source.ip"}},
            "hosts": {
                "terms": {"field": "source.ip", "size": 25},
                "aggs": {"first": {"min": {"field": "@timestamp"}},
                         "last": {"max": {"field": "@timestamp"}}},
            },
        },
    }  # fmt: skip
    watched = params.model_copy(update={"hosts": ("10.0.0.2", "10.0.0.1")})
    watched = beacon.ContactParams.model_validate(watched.model_dump())
    assert watched.hosts == ("10.0.0.1", "10.0.0.2")
    filters = beacon.ProxyContact().build(watched).body["query"]["bool"]["filter"]
    assert filters[1] == {"terms": {"source.ip": ["10.0.0.1", "10.0.0.2"]}}


def test_the_dns_request_is_exactly_this() -> None:
    body = dns.DnsHostDomains().build(dns.DomainsParams(ip="10.9.8.7", start=at(2),
                                                        end=at(4))).body  # fmt: skip
    name = "dns.question.name.keyword"
    assert body == {
        "size": 0,
        "track_total_hits": False,
        "query": {"bool": {"filter": [
            {"bool": {"should": [{"term": {"source.ip": "10.9.8.7"}},
                                 {"term": {"client.ip": "10.9.8.7"}}],
                      "minimum_should_match": 1}},
            window_of(at(2), at(4)),
        ]}},
        "aggs": {
            "queries": {"value_count": {"field": "@timestamp"}},
            "named": {"value_count": {"field": name}},
            "names": {"cardinality": {"field": name}},
            "top": {"terms": {"field": name, "size": 6}},
            "rare": {"terms": {"field": name, "size": 8, "order": {"_count": "asc"}}},
            "types": {"terms": {"field": "dns.question.type.keyword", "size": 2}},
            "codes": {"terms": {"field": "dns.response_code.keyword", "size": 2}},
        },
    }  # fmt: skip


def test_the_paths_request_is_exactly_this() -> None:
    params = paths.PathParams(ip="198.51.100.7", site="a.example.org",
                              paths=("/b", "/a", "/b"), start=at(10), end=at(16))  # fmt: skip
    assert params.paths == ("/a", "/b")
    body = paths.WebPathOutcomes().build(params).body
    ok = {"range": {"http.response.status_code": {"gte": 200, "lt": 300}}}
    assert body == {
        "size": 0,
        "track_total_hits": False,
        "query": {"bool": {"filter": [
            {"term": {"source.ip": "198.51.100.7"}},
            {"term": {"url.domain.keyword": "a.example.org"}},
            {"terms": {"url.path": ["/a", "/b"]}},
            window_of(at(10), at(16)),
        ]}},
        "aggs": {
            "requests": {"value_count": {"field": "@timestamp"}},
            "answered": {"value_count": {"field": "http.response.status_code"}},
            "paths": {"terms": {"field": "url.path", "size": 2}, "aggs": {
                "statuses": {"terms": {"field": "http.response.status_code", "size": 5}}}},
            "ok_0": {"filter": {"bool": {"filter": [{"term": {"url.path": "/a"}}, ok]}},
                     "aggs": {"sizes": {"terms": {"field": "http.response.body.bytes",
                                                  "size": 5}}}},
            "ok_1": {"filter": {"bool": {"filter": [{"term": {"url.path": "/b"}}, ok]}},
                     "aggs": {"sizes": {"terms": {"field": "http.response.body.bytes",
                                                  "size": 5}}}},
        },
    }  # fmt: skip


def test_the_source_events_request_is_exactly_this() -> None:
    params = source_events.SourceParams(
        source="squid", ip="10.43.119.92", start=at(12, 16), end=at(12, 20),
        narrow=(("destination.ip", "198.51.100.9"), ("destination.port", "443")),
    )  # fmt: skip
    body = source_events.LogsSourceEvents().build(params).body
    assert body == {
        "size": 21,
        "track_total_hits": False,
        "_source": list(source_events.returns("squid")),
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {"bool": {"filter": [
            {"term": {"source.ip": "10.43.119.92"}},
            {"term": {"destination.ip": "198.51.100.9"}},
            {"term": {"destination.port": 443}},
            window_of(at(12, 16), at(12, 20)),
        ]}},
    }  # fmt: skip
    dns_body = (
        source_events.LogsSourceEvents()
        .build(
            source_events.SourceParams(source="dns", ip="10.0.0.1", start=at(1), end=at(2), size=3)
        )
        .body
    )
    assert dns_body["size"] == 4
    assert dns_body["query"]["bool"]["filter"][0] == {"bool": {"should": [
        {"term": {"source.ip": "10.0.0.1"}}, {"term": {"client.ip": "10.0.0.1"}}],
        "minimum_should_match": 1}}  # fmt: skip
    plan = source_events.LogsSourceEvents().build(params)
    assert plan.window == Window("squid", at(12, 16), at(12, 20))


def test_the_catalogue() -> None:
    assert set(batch1.TEMPLATES) == set(batch1.FIRST_RUN_MS) == set(batch1.CLOSES)
    assert set(batch1.TEMPLATES) == set(batch1.SOURCES)
    for name, cls in batch1.TEMPLATES.items():
        assert REGISTRY[name] is cls
        assert cls.version == 1
        assert cls.timeout == (
            timedelta(seconds=5) if cls.cost is CostClass.MEDIUM else timedelta(seconds=10)
        )
    heavy = {n for n, c in batch1.TEMPLATES.items() if c.cost is CostClass.HEAVY}
    assert heavy == {"proxy.pair", "proxy.contact", "dns.host_domains", "web.path_outcomes"}
    assert batch1.FIRST_RUN_MS == {"proxy.pair": 10_000, "proxy.contact": 10_000,
                                   "dns.host_domains": 10_000, "web.path_outcomes": 3_000,
                                   "logs.source_events": 3_000}  # fmt: skip
    assert (batch1.DAILY_CAP_MS, batch1.HOSTS_LIMIT, batch1.INVESTIGATIONS_LIMIT) == (
        90_000, 25, 50)  # fmt: skip


# ----------------------------------------------------------------------------- fields


def _field_type(source: str, field: str) -> str | None:
    """The declared type of ``field`` (a ``.keyword`` sub-field: keyword, if its parent has
    one)."""
    declared = batch1.FIELDS[source]
    if field in declared:
        kind = declared[field]
        return "text" if kind == "text+keyword" else kind
    if field.endswith(".keyword") and declared.get(field[: -len(".keyword")]) == "text+keyword":
        return "keyword"
    return None


def test_every_template_field_is_in_its_sources_mapping() -> None:
    for name, cls in batch1.TEMPLATES.items():
        spec = cls.spec()
        used = spec.filter_fields | spec.aggregate_fields | spec.sort_fields | spec.return_fields
        for field in used:
            found = [s for s in batch1.SOURCES[name] if _field_type(s, field) is not None]
            assert found, f"{name}: {field} is in no mapping of {batch1.SOURCES[name]}"
        # filters and aggregations need an indexed, aggregatable type (no text)
        for field in spec.filter_fields | spec.aggregate_fields | spec.sort_fields:
            kinds = {_field_type(s, field) for s in batch1.SOURCES[name]} - {None}
            assert kinds <= {"ip", "date", "long", "integer", "keyword"}, (name, field, kinds)
    for source in ("squid", "nginx", "dns"):
        assert set(source_events.returns(source)) <= set(batch1.FIELDS[source]), source
        for field in source_events.narrow(source).values():
            assert _field_type(source, field) in {"ip", "long", "keyword"}, (source, field)


def _captured(source: str) -> dict[str, Any] | None:
    found = sorted((ROOT / "data" / "corpus").glob(f"*/mappings/acme-logs-{source}-*.json"))
    if not found:
        return None
    mappings = json.loads(found[-1].read_text())
    return dict(next(iter(mappings.values()))["mappings"]["properties"])


@pytest.mark.parametrize("source", ["squid", "dns", "nginx"])
def test_the_declared_fields_match_the_captured_mapping(source: str) -> None:
    """Where the capture exists (data/corpus/<day>/mappings: the main checkout), the declared
    types are the captured ones, ignore_above included."""
    props = _captured(source)
    if props is None:
        pytest.skip("no captured mapping here (data/ is local to the main checkout)")
    for field, kind in batch1.FIELDS[source].items():
        node: Any = {"properties": props}
        for part in field.split("."):
            node = node["properties"][part]
        if kind == "text+keyword":
            assert node["type"] == "text"
            assert node["fields"]["keyword"] == {"type": "keyword", "ignore_above": 256}
        else:
            assert node["type"] == kind, field


def test_the_es_local_mapping_is_built_from_the_declared_fields() -> None:
    built = batch1.mapping("nginx")
    assert built["date_detection"] is False
    props = built["properties"]
    assert props["url"]["properties"]["path"] == {"type": "keyword"}
    assert props["url"]["properties"]["domain"] == {
        "type": "text",
        "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
    }
    assert props["http"]["properties"]["response"]["properties"]["body"]["properties"] == {
        "bytes": {"type": "long"}}  # fmt: skip


# ----------------------------------------------------------------------------- bounds


@pytest.mark.parametrize(
    ("value", "canon"),
    [("10.1.2.3", "10.1.2.3"), ("2001:DB8::1", "2001:db8::1"), ("::ffff:8.8.8.8", "8.8.8.8"),
     ("::1", "::1"), ("0:0:0:0:0:0:0:1", "::1")],
)  # fmt: skip
def test_addresses_are_canonical(value: str, canon: str) -> None:
    assert bounds.address(value) == canon
    assert dns.DomainsParams(ip=value, start=at(2), end=at(3)).ip == canon


@pytest.mark.parametrize("value", ["10.1.2", "fe80::1%eth0", " 10.1.2.3", "10.1.2.3 ", "x" * 10,
                                   "1.2.3.4/32", "", "999.1.1.1"])  # fmt: skip
def test_not_an_address(value: str) -> None:
    with pytest.raises(ValueError):  # noqa: PT011 - ipaddress' own messages
        bounds.address(value)
    with pytest.raises(ValidationError):
        dns.DomainsParams(ip=value, start=at(2), end=at(3))


def test_windows() -> None:
    naive = datetime(2026, 10, 20, 3)  # noqa: DTZ001
    for start, end, why in (
        (naive, naive + timedelta(hours=1), "timezone-aware"),
        (at(3), at(3), "end after"),
        (at(4), at(3), "end after"),
        (at(2), at(4, 1), "longer than"),
        (at(0, 59), at(2), "one daily index"),
        (at(21), at(23), "one daily index"),
    ):
        with pytest.raises(ValidationError, match=why):
            dns.DomainsParams(ip="10.0.0.1", start=start, end=end)
    dns.DomainsParams(ip="10.0.0.1", start=at(1), end=at(3))
    dns.DomainsParams(ip="10.0.0.1", start=at(21), end=at(22, 59))
    # a search for rows may read two daily indices, never three
    source_events.SourceParams(source="squid", ip="10.0.0.1", start=at(23, 30), end=at(23, 59))
    with pytest.raises(ValidationError, match="longer than"):
        source_events.SourceParams(source="squid", ip="10.0.0.1", start=at(1), end=at(2, 1))
    assert bounds.days(at(1), at(22, 59)) == 1
    assert bounds.days(at(0, 59), at(5)) == 2
    assert bounds.days(at(3), at(23)) == 2
    with pytest.raises(ValueError, match="at most two"):
        bounds.check_window(at(0, 30), at(23, 30), timedelta(days=3), one_index=False)


def test_pair_and_contact_bounds() -> None:
    with pytest.raises(ValidationError, match="two addresses"):
        beacon.PairParams(host="10.0.0.1", destination="::ffff:10.0.0.1", start=at(3), end=at(4))
    with pytest.raises(ValidationError, match="longer than"):
        beacon.PairParams(host="10.0.0.1", destination="8.8.8.8", start=at(1), end=at(13, 1))
    beacon.PairParams(host="10.0.0.1", destination="8.8.8.8", start=at(1), end=at(13))
    with pytest.raises(ValidationError, match="not one of the hosts"):
        beacon.ContactParams(destination="8.8.8.8", hosts=("8.8.8.8",), start=at(3), end=at(4))
    with pytest.raises(ValidationError):
        beacon.ContactParams(destination="8.8.8.8", hosts=tuple(f"10.0.0.{i}" for i in range(11)),
                             start=at(3), end=at(4))  # fmt: skip
    with pytest.raises(ValidationError):  # the limit counts what was given
        beacon.ContactParams(destination="8.8.8.8", hosts=("10.0.0.1",) * 11, start=at(3),
                             end=at(4))  # fmt: skip
    many = beacon.ContactParams(destination="8.8.8.8", hosts=("10.0.0.1",) * 10, start=at(3),
                                end=at(4))  # fmt: skip
    assert many.hosts == ("10.0.0.1",)


def test_path_and_site_bounds() -> None:
    base: dict[str, Any] = {"ip": "1.2.3.4", "site": "s.example.org", "paths": ("/a",),
            "start": at(3),
            "end": at(4)}  # fmt: skip
    paths.PathParams(**{**base, "paths": tuple(f"/{i}" for i in range(10))})
    for change, why in (
        ({"paths": tuple(f"/{i}" for i in range(11))}, "at most 10"),
        ({"paths": ()}, "at least 1"),
        ({"paths": ("/" + "a" * 256,)}, "1 to 256"),
        ({"paths": ("",)}, "1 to 256"),
        ({"paths": ("/a\nb",)}, "control"),
        ({"paths": ("/a\x7f",)}, "control"),
        ({"site": "s" * 257}, "1 to 256"),
        ({"site": ""}, "1 to 256"),
        ({"site": "s\tx"}, "control"),
    ):
        with pytest.raises(ValidationError, match=why):
            paths.PathParams(**{**base, **change})
    paths.PathParams(**{**base, "paths": ("/" + "a" * 255,), "site": "s" * 256})
    # UTF-16 units, as Elasticsearch counts ignore_above: an astral character is two
    with pytest.raises(ValidationError, match="1 to 256"):
        paths.PathParams(**{**base, "paths": ("/" + "\U0001f600" * 128,)})
    paths.PathParams(**{**base, "paths": ("/" + "é" * 255,)})


def test_source_bounds() -> None:
    base: dict[str, Any] = {"source": "squid", "ip": "10.0.0.1", "start": at(3), "end": at(4)}
    change: dict[str, Any]
    for change, why in (
        ({"narrow": (("url.domain.keyword", "x"),)}, "narrow only by"),
        ({"narrow": (("destination.ip", "1.1.1.1"), ("destination.ip", "1.1.1.2"))}, "narrow"),
        ({"narrow": (("destination.port", "1"), ("destination.ip", "1.1.1.1"))}, "sorted"),
        ({"narrow": (("destination.ip", "::ffff:1.1.1.1"),)}, "canonical address"),
        ({"narrow": (("destination.port", "65536"),)}, "port number"),
        ({"narrow": (("destination.port", "-1"),)}, "port number"),
        ({"narrow": (("destination.port", "\uff18\uff10"),)}, "port number"),  # fullwidth 80
        ({"narrow": (("destination.port", "0443"),)}, "port number"),
        ({"source": "postfix"}, "not a proxy, web server or DNS log family"),
        ({"size": 21}, "less than or equal"),
        ({"size": 0}, "greater than or equal"),
    ):
        with pytest.raises(ValidationError, match=why):
            source_events.SourceParams(**{**base, **change})
    nginx: dict[str, Any] = {**base, "source": "nginx"}
    with pytest.raises(ValidationError, match="1 to 256"):
        source_events.SourceParams(**{**nginx, "narrow": (("url.domain.keyword", "x" * 257),)})
    with pytest.raises(ValidationError, match="narrow only by"):
        source_events.SourceParams(**{**base, "source": "dns",
                                      "narrow": (("destination.ip", "1.1.1.1"),)})  # fmt: skip


@given(
    st.datetimes(min_value=datetime(2026, 1, 1), max_value=datetime(2027, 12, 31),  # noqa: DTZ001
                 timezones=st.just(UTC)),
    st.integers(min_value=-30, max_value=30 * 60),
    st.integers(min_value=0, max_value=30 * 60),
    st.integers(min_value=-120, max_value=48 * 60),
    st.sampled_from([timedelta(hours=1), timedelta(hours=2), timedelta(hours=6),
                     timedelta(hours=12), timedelta(hours=22)]),
)  # fmt: skip
def test_clamp_keeps_every_rule(
    start: datetime, length: int, late: int, ahead: int, longest: timedelta
) -> None:
    end = start + timedelta(minutes=length)
    now = end + timedelta(minutes=ahead) + timedelta(minutes=late)
    got = bounds.clamp(start, end, now, longest)
    if got is None:
        return
    low, high = got
    assert low < high
    assert high - low <= longest
    assert bounds.days(low, high) == 1  # one daily index
    assert high <= now - bounds.MARGIN
    assert low >= start.replace(second=0, microsecond=0)
    assert low.second == low.microsecond == high.second == high.microsecond == 0
    bounds.check_window(low, high, longest, one_index=True)


def test_clamp_cases() -> None:
    longest = timedelta(hours=22)
    assert bounds.clamp(at(0), at(0, d=21), at(23, 30), longest) == (at(1), at(22, 59))
    assert bounds.clamp(at(0), at(0, d=21), at(12), longest) == (at(1), at(11, 45))
    assert bounds.clamp(at(3), at(5), at(4), longest) == (at(3), at(3, 45))  # the margin
    assert bounds.clamp(at(3), at(5), at(3, 10), longest) is None  # nothing old enough
    assert bounds.clamp(at(3), at(5), at(3, 15), longest) is None
    assert bounds.clamp(at(3), at(5), at(3, 16), longest) == (at(3), at(3, 1))
    # the end in the first hour of a day: the day before holds the window
    assert bounds.clamp(at(22), at(0, 30, d=21), at(5, d=21), longest) == (at(22), at(22, 59))
    assert bounds.clamp(at(0, 10), at(0, 50), at(5), longest) is None
    # seconds round outwards to whole minutes; a long window keeps its newest part
    assert bounds.clamp(at(3, 0, s=30), at(4, 0, s=1), at(9), longest) == (at(3), at(4, 1))
    assert bounds.clamp(at(1), at(9), at(20), timedelta(hours=2)) == (at(7), at(9))
    ist = datetime(2026, 10, 20, 8, 30, tzinfo=IST)  # 03:00 UTC
    assert bounds.clamp(ist, ist + timedelta(hours=1), at(20), longest) == (at(3), at(4))


def test_quiet_hours() -> None:
    assert [bounds.quiet(t) for t in (at(0), at(0, 59), at(1, 29, s=59), at(1, 30), at(23, 59))] \
        == [True, True, True, False, False]  # fmt: skip
    assert bounds.quiet(datetime(2026, 10, 20, 6, 0, tzinfo=IST))  # 00:30 UTC
    assert bounds.utf16_len("a\U0001f600é") == 4


# ----------------------------------------------------------------------------- properties

ADDRESSES = st.one_of(st.ip_addresses(v=4), st.ip_addresses(v=6)).map(str)
TEXT = st.text(min_size=0, max_size=300)


# A keyword at ignore_above (256 UTF-16 units) of characters that take three bytes in UTF-8:
# the largest text key a snapshot can hold (review F4-R7).
WIDE = "\u4e00" * 256


def worst_answer(name: str, body: dict[str, Any]) -> dict[str, Any]:
    """The largest answer the aggregations can give: every bucket filled, every key at its
    longest (text in three-byte characters), eight-digit counts, as Elasticsearch writes
    them."""
    long_ip = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
    count = 99_999_999

    def terms(size: int, key: Any, sub: dict[str, Any] | None = None) -> dict[str, Any]:
        return {"doc_count_error_upper_bound": 0, "sum_other_doc_count": count,
                "buckets": [{"key": key(i), "doc_count": count, **(sub or {})}
                            for i in range(size)]}  # fmt: skip

    stamp = {"value": 1.7609310600e12, "value_as_string": "2026-10-20T03:31:00.000Z"}
    aggs = body["aggs"]
    out: dict[str, Any] = {}
    if name == "proxy.pair":
        h = aggs["beats"]["date_histogram"]
        lo = int(datetime.fromisoformat(h["hard_bounds"]["min"]).timestamp() * 1000)
        hi = int(datetime.fromisoformat(h["hard_bounds"]["max"]).timestamp() * 1000)
        step = int(h["fixed_interval"][:-1]) * 60_000
        out = {"requests": {"value": count}, "first": stamp, "last": stamp,
               "bytes": {"value": 9.99e15},
               "beats": {"buckets": [{"key": k, "doc_count": count}
                                     for k in range(lo, hi + 1, step)]}}  # fmt: skip
    elif name == "proxy.contact":
        out = {"requests": {"value": count}, "host_count": {"value": count},
               "first": stamp, "last": stamp,
               "hosts": terms(25, lambda i: long_ip, {"first": stamp, "last": stamp})}  # fmt: skip
    elif name == "dns.host_domains":
        out = {"queries": {"value": count}, "named": {"value": count}, "names": {"value": count}}
        for key in ("top", "rare", "types", "codes"):  # every name at its largest (F4-R7)
            out[key] = terms(aggs[key]["terms"]["size"], lambda i: WIDE)
    elif name == "web.path_outcomes":
        n = aggs["paths"]["terms"]["size"]
        out = {"requests": {"value": count}, "answered": {"value": count},
               "paths": terms(n, lambda i: WIDE,
                              {"statuses": terms(5, lambda i: 599)})}  # fmt: skip
        for i in range(n):
            out[f"ok_{i}"] = {"doc_count": count, "sizes": terms(5, lambda i: 9_999_999_999)}
    return {"took": 5, "timed_out": False, "_shards": {"total": 1, "successful": 1, "failed": 0},
            "hits": {"max_score": None, "hits": []}, "aggregations": out}  # fmt: skip


def check_final(task: TaskSpec) -> None:
    name = type(task.template).name
    final = batch1.final_request(task, TARGETS, at(12))
    check = _Check(final)
    check.run()
    assert check.buckets <= MAX_BUCKETS
    cls = type(task.template)
    if cls.cost is CostClass.HEAVY:
        assert len(final.indices) == 1  # one daily index per aggregation (D-067)
        got = extract(worst_answer(name, final.body), max_rows=SNAPSHOT_ROWS,
                      max_bytes=SNAPSHOT_BYTES)  # fmt: skip
        assert "dropped" not in got.snapshot, name
        assert len(canonical(got.snapshot).encode()) <= SNAPSHOT_BYTES
    else:
        assert 1 <= len(final.indices) <= 2
    assert dict(final.url_params)["allow_partial_search_results"] == "false"
    assert final.body["timeout"] == f"{int(cls.timeout.total_seconds())}s"
    # the task survives the graph state: rebuilt from its plain reference, the same request
    template, params = rebuild(task.ref())
    assert params == task.params
    assert template.plan(params).body == task.template.plan(task.params).body


def _window(start: datetime, minutes: int) -> tuple[datetime, datetime]:
    return start, start + timedelta(minutes=minutes)


STARTS = st.datetimes(min_value=datetime(2026, 1, 1), max_value=datetime(2027, 12, 31),  # noqa: DTZ001
                      timezones=st.sampled_from([UTC, IST]))  # fmt: skip


@given(ADDRESSES, ADDRESSES, STARTS, st.integers(min_value=-5, max_value=13 * 60))
def test_pair_requests_are_valid_or_refused(host: str, dest: str, start: datetime, n: int) -> None:
    try:
        params = beacon.PairParams(host=host, destination=dest, start=start,
                                   end=start + timedelta(minutes=n))  # fmt: skip
    except ValidationError:
        return
    check_final(TaskSpec(beacon.ProxyPair(), params))


@given(ADDRESSES, st.lists(ADDRESSES, max_size=12), STARTS,
       st.integers(min_value=-5, max_value=23 * 60))  # fmt: skip
def test_contact_requests_are_valid_or_refused(
    dest: str, hosts: list[str], start: datetime, n: int
) -> None:
    try:
        params = beacon.ContactParams(destination=dest, hosts=tuple(hosts), start=start,
                                      end=start + timedelta(minutes=n))  # fmt: skip
    except ValidationError:
        return
    check_final(TaskSpec(beacon.ProxyContact(), params))


@given(ADDRESSES, STARTS, st.integers(min_value=-5, max_value=3 * 60))
def test_dns_requests_are_valid_or_refused(ip: str, start: datetime, n: int) -> None:
    try:
        params = dns.DomainsParams(ip=ip, start=start, end=start + timedelta(minutes=n))
    except ValidationError:
        return
    check_final(TaskSpec(dns.DnsHostDomains(), params))


@given(ADDRESSES, TEXT, st.lists(TEXT, min_size=0, max_size=12), STARTS,
       st.integers(min_value=-5, max_value=7 * 60))  # fmt: skip
def test_path_requests_are_valid_or_refused(
    ip: str, site: str, tried: list[str], start: datetime, n: int
) -> None:
    try:
        params = paths.PathParams(ip=ip, site=site, paths=tuple(tried), start=start,
                                  end=start + timedelta(minutes=n))  # fmt: skip
    except ValidationError:
        return
    check_final(TaskSpec(paths.WebPathOutcomes(), params))


@given(st.sampled_from(["squid", "nginx", "dns"]), ADDRESSES, STARTS,
       st.integers(min_value=-5, max_value=70), st.integers(min_value=0, max_value=22),
       st.lists(st.tuples(st.sampled_from(["destination.ip", "destination.port",
                                           "url.domain.keyword"]), TEXT | ADDRESSES),
                max_size=3))  # fmt: skip
def test_source_requests_are_valid_or_refused(
    source: str, ip: str, start: datetime, n: int, size: int, narrow: list[tuple[str, str]]
) -> None:
    try:
        params = source_events.SourceParams(
            source=source, ip=ip, start=start, end=start + timedelta(minutes=n), size=size,  # type: ignore[arg-type]
            narrow=tuple(sorted(narrow)),
        )  # fmt: skip
    except ValidationError:
        return
    check_final(TaskSpec(source_events.LogsSourceEvents(), params))


def test_the_dry_run_request_is_the_gateways() -> None:
    """``final_request`` builds what the gateway builds (its indices, parameters, body)."""
    gateway = Gateway(None, MemoryStore())  # type: ignore[arg-type]
    task = TaskSpec(dns.DnsHostDomains(), dns.DomainsParams(ip="10.0.0.1", start=at(2),
                                                            end=at(4)))  # fmt: skip
    plan = task.template.plan(task.params)
    indices, _, _ = gateway._wanted(plan)
    far = at(12) + timedelta(hours=1)
    theirs = gateway._final(plan, indices, None, dns.DnsHostDomains.timeout, far, at(12))
    assert batch1.final_request(task, TARGETS, at(12)) == theirs
    with pytest.raises(TemplateRejectedError):
        batch1.final_request(task, Targets(log_sources=frozenset({"squid"})), at(12))


# ----------------------------------------------------------------------------- readings


def beats(keys_min: list[int]) -> dict[str, Any]:
    base = int(at(3).timestamp() * 1000)
    return {"beats": {"buckets": [{"key": base + k * 60_000, "doc_count": 1} for k in keys_min]},
            "requests": {"value": len(keys_min)},
            "first": {"value": base + keys_min[0] * 60_000 if keys_min else None},
            "last": {"value": base + keys_min[-1] * 60_000 + 7_000
                     if keys_min else None}}  # fmt: skip


# A 5-minute beacon over 2 hours (the shortest window a production pair task reads), one
# bucket either way twice.
FIVE = [0, 5, 10, 14, 19, *range(25, 120, 5)]


def test_a_regular_rhythm() -> None:
    keys = FIVE
    got = beacon.cadence(beats(keys), at(3), at(5))
    assert got.period == timedelta(seconds=300)
    assert got.jitter == timedelta(seconds=60)  # never finer than a bucket
    assert got.regular_share == 1.0
    assert got.beats == 24
    assert got.first == at(3)
    assert got.last == at(4, 55, s=7)
    assert got.still_active is True
    late = beacon.cadence(beats(keys), at(3), at(5, 7))  # over two periods and a bucket
    assert late.still_active is False
    assert beacon.cadence(beats(keys), at(3), at(5, 5)).still_active is True
    # a pause (a laptop asleep) is left out of the period, not out of the regularity count
    paused = [*keys, 200, 205, 210, 215, 220]
    got = beacon.cadence(beats(paused), at(3), at(7))
    assert got.period == timedelta(seconds=300)
    assert got.regular_share == round(27 / 28, 3)


def test_rhythms_that_are_not_called() -> None:
    assert beacon.cadence(beats([0, 5, 10, 15, 20]), at(3), at(4)).period is None  # 4 gaps
    few = beacon.cadence(beats([0, 5, 10, 15, 20]), at(3), at(4))
    assert (few.beats, few.regular_share, few.still_active) == (5, None, None)
    every_minute = beacon.cadence(beats(list(range(30))), at(3), at(4))
    assert every_minute.period is None  # a gap of one bucket cannot be measured
    assert every_minute.regular_share == 0.0  # and never counts as a regular gap
    ragged = beacon.cadence(beats([0, 2, 9, 10, 30, 31, 33, 50, 58]), at(3), at(4))
    assert ragged.period is None
    assert ragged.regular_share is not None
    assert ragged.regular_share < 0.8
    # 11 gaps of 5 minutes in one hour: regular, but rhythm-less traffic could show that
    # with a chance of 2.4e-7, above ALPHA: not called (2 hours are needed)
    hour = beacon.cadence(beats(FIVE[:12]), at(3), at(4))
    assert (hour.period, hour.regular_share) == (None, 1.0)
    assert beacon.tail(11, 11, beacon.likeliest(4, 6)) > beacon.ALPHA
    assert beacon.cadence(None, at(3), at(4)) == beacon.Cadence(0, None, None, None, None, None,
                                                                None, None)  # fmt: skip
    junk = {"beats": {"buckets": [{"key": "x"}, {"key": True, "doc_count": 1}, 7,
                                  {"key": 1, "doc_count": 0}]}}  # fmt: skip
    assert beacon.cadence(junk, at(3), at(4)).beats == 0
    dup = {"beats": {"buckets": [{"key": 60_000 * k, "doc_count": 1} for k in (0, 0, 5)]}}
    assert beacon.cadence(dup, at(3), at(4)).beats == 2
    # keys off the bucket grid (gaps of 0 buckets): never regular, never an error
    odd = {"beats": {"buckets": [{"key": 1_000 * k, "doc_count": 1} for k in range(12)]}}
    assert beacon.cadence(odd, at(3), at(4)).period is None


def test_the_chance_of_a_rhythm_by_accident() -> None:
    # the likeliest rate for gaps of 2-3 buckets: u = sqrt(1/3), chance u - u^3
    assert beacon.likeliest(2, 3) == pytest.approx(0.3849, abs=1e-4)
    assert beacon.likeliest(4, 6) == pytest.approx(0.25, abs=1e-9)
    assert beacon.likeliest(2, 2) == pytest.approx(0.25, abs=1e-9)  # p = 1/2: p(1-p)
    assert beacon.tail(10, 0, 0.3) == 1.0
    assert beacon.tail(10, 3, 1.0) == 1.0
    assert beacon.tail(10, 3, 0.0) == 0.0
    assert beacon.tail(3, 2, 0.5) == pytest.approx(0.5)  # 3/8 + 1/8
    assert beacon.tail(360, 360, 0.25) == pytest.approx(0.25**360, rel=1e-6)


@given(share=st.floats(0.05, 0.95), seed=st.integers(0, 2**32 - 1), hours=st.integers(1, 12))
def test_traffic_with_no_rhythm_is_never_a_beacon(share: float, seed: int, hours: int) -> None:
    """Review F4-R1: each bucket busy at random, at any rate, over any window the template
    reads (1-minute buckets up to 6 h, 2-minute ones up to 12 h): never a period."""
    width = 2 if hours > 6 else 1
    rng = random.Random(seed)
    base = int(at(1).timestamp() * 1000)
    keys = [k for k in range(hours * 60 // width) if rng.random() < share]
    aggs = {"beats": {"buckets": [{"key": base + k * width * 60_000, "doc_count": 3}
                                  for k in keys]}}  # fmt: skip
    got = beacon.cadence(aggs, at(1), at(1) + timedelta(hours=hours))
    assert got.period is None, (got.regular_share, len(keys))
    assert got.still_active is None


def test_two_minute_buckets_measure_the_mean_gap() -> None:
    base = int(at(3).timestamp() * 1000)
    steps = [k * 5 // 2 for k in range(41)]  # 300 s in 2-minute buckets: gaps of 2 and 3
    aggs = {"beats": {"buckets": [{"key": base + 120_000 * k, "doc_count": 1} for k in steps]}}
    got = beacon.cadence(aggs, at(1), at(13))
    assert got.period == timedelta(seconds=300)
    assert got.jitter == timedelta(seconds=120)


def test_contacts() -> None:
    stamp = int(at(9).timestamp() * 1000)
    aggs = {"host_count": {"value": 3}, "hosts": {"buckets": [
        {"key": "10.0.0.1", "doc_count": 4, "first": {"value": stamp},
         "last": {"value": stamp + 60_000}},
        {"key": "10.0.0.2", "doc_count": 1, "first": {}, "last": {"value": None}},
        {"key": 5, "doc_count": 1}, "junk",
    ]}}  # fmt: skip
    count, listed = beacon.contacts(aggs)
    assert count == 3
    assert listed == [beacon.Contact("10.0.0.1", 4, at(9), at(9, 1)),
                      beacon.Contact("10.0.0.2", 1, None, None)]  # fmt: skip
    assert beacon.contacts(None) == (None, [])


def ref(status: str = "ok", **extra: Any) -> dict[str, Any]:
    return {"task_key": "k1", "template": "x@1", "status": status, "coverage": {},
            "truncated": False, **extra}  # fmt: skip


def by_name(signals: list[Any]) -> dict[str, Any]:
    return {s.name: s for s in signals}


def test_pair_signals() -> None:
    keys = list(range(0, 120, 5))
    task = TaskSpec(beacon.ProxyPair(), beacon.PairParams(host="10.0.0.1", destination="8.8.8.8",
                                                          start=at(3), end=at(5)))  # fmt: skip
    got = by_name(batch1.read(1, task, ref(), {"aggregations": beats(keys)}))
    assert {n: (s.status, s.value) for n, s in got.items()} == {
        "pair.beats": ("known", 24), "pair.period_s": ("known", 300),
        "pair.jitter_s": ("known", 60), "pair.last_beat": ("known", "2026-10-20T04:55:07Z"),
        "pair.still_active": ("known", True),
    }  # fmt: skip
    assert got["pair.beats"].evidence == ("k1",)
    none = by_name(batch1.read(1, task, ref("empty"), {"aggregations": beats([])}))
    assert none["pair.beats"].unknown_reason == "ingest_not_verified"  # a zero says nothing
    assert none["pair.period_s"].status == "unknown"
    quiet = by_name(batch1.read(1, task.__class__(task.template, task.params.model_copy(
        update={"end": at(5, 30)})), ref(), {"aggregations": beats(keys)}))  # fmt: skip
    assert quiet["pair.still_active"].status == "unknown"  # never "stopped" from the logs alone
    for status in ("timeout", "skipped_budget", "source_lag"):
        failed = by_name(batch1.read(1, task, ref(status), None))
        assert {s.status for s in failed.values()} == {"unknown"}
        assert failed["pair.beats"].unknown_reason == status


def test_contact_signals() -> None:
    task = batch1.contact_task("8.8.8.8", at(20))
    assert isinstance(task, TaskSpec)
    stamp = int(at(9).timestamp() * 1000)
    aggs = {"host_count": {"value": 2}, "last": {"value": stamp + 120_000}, "hosts": {
        "sum_other_doc_count": 0, "buckets": [
            {"key": "10.0.0.1", "doc_count": 1, "last": {"value": stamp}},
            {"key": "10.0.0.2", "doc_count": 1, "last": {"value": stamp + 120_000}}]}}  # fmt: skip
    got = by_name(batch1.read(1, task, ref(), {"aggregations": aggs}))
    assert (got["contact.hosts"].value, got["contact.last"].value) == (2, "2026-10-20T09:02:00Z")
    assert beacon.every_host_listed(aggs)
    assert not beacon.every_host_listed({"hosts": {"sum_other_doc_count": 5}})
    assert not beacon.every_host_listed(None)
    # the newest contact is the answer's own, never the newest listed host's (review F4-R5)
    listed_only = {k: v for k, v in aggs.items() if k != "last"}
    assert by_name(batch1.read(1, task, ref(), {"aggregations": listed_only}))[
        "contact.last"].unknown_reason == "no_value"  # fmt: skip
    cut = by_name(batch1.read(1, task, ref(truncated=True), {"aggregations": aggs}))
    assert (cut["contact.hosts"].value, cut["contact.hosts"].completeness) == (2, "lower_bound")
    assert cut["contact.last"].status == "unknown"
    zero = by_name(
        batch1.read(1, task, ref("empty"), {"aggregations": {"host_count": {"value": 0}}})
    )
    assert zero["contact.hosts"].unknown_reason == "ingest_not_verified"


DATA = "mzxw6ytboi4dqmrt"  # 16 characters of base32: what a tunnel's labels carry


def test_parents_and_tunnels() -> None:
    assert dns.parent("a.b.example.com") == "example.com"
    assert dns.parent("X.Moodle.EXAMPLE.EDU.") == "example.edu"
    assert dns.parent("a.co.uk") == "a.co.uk"
    assert dns.parent("co.uk") == "co.uk"
    assert dns.parent("a.b.comm.in") == "comm.in"
    assert dns.parent("localhost") is None
    assert dns.parent("..") is None
    rare = [{"key": f"{DATA}{i}.t.evil.example", "doc_count": 1} for i in range(11)]
    rare += [{"key": f"x{i}.ok.example", "doc_count": 1} for i in range(9)]
    aggs = {"queries": {"value": 900}, "named": {"value": 890}, "names": {"value": 500},
            "rare": {"buckets": rare},
            "top": {"buckets": [{"key": "a.b", "doc_count": 4}]}}  # fmt: skip
    got = dns.lookups(aggs)
    assert (got.tunnel_parent, got.unreadable, got.names) == ("evil.example", 10, 500)
    assert got.top == [("a.b", 4)]
    assert dns.lookups({**aggs, "names": {"value": 499}}).tunnel_parent is None
    half = rare[:10] + rare[11:]  # 10 of 19 under one parent: still more than half
    assert dns.lookups({**aggs, "rare": {"buckets": half}}).tunnel_parent == "evil.example"
    tie = rare[:9] + rare[11:]  # 9 and 9 of 18: half is enough, the first name wins a tie
    assert dns.lookups({**aggs, "rare": {"buckets": tie}}).tunnel_parent == "evil.example"
    spread = rare[:8] + [{"key": f"x.d{i}.example", "doc_count": 1} for i in range(9)]
    assert dns.lookups({**aggs, "rare": {"buckets": spread}}).tunnel_parent is None  # 8 of 17
    assert dns.lookups(None) == dns.Lookups(None, None, None, [], [], None)
    # review F4-R8: names that carry no data, reverse lookups and blocklist checks: no tunnel
    short = [{"key": f"x{i}.t.evil.example", "doc_count": 1} for i in range(11)]
    assert dns.lookups({**aggs, "rare": {"buckets": short}}).tunnel_parent is None
    for zone in ("in-addr.arpa", "ip6.arpa", "zen.spamhaus.org", "dbl.spamhaus.org"):
        names = [{"key": f"{DATA}{i}.{zone}", "doc_count": 1} for i in range(11)]
        assert dns.lookups({**aggs, "rare": {"buckets": names}}).tunnel_parent is None, zone
    assert dns.carried("4.3.2.1.in-addr.arpa", "in-addr.arpa") == 0
    assert dns.carried("4.3.2.1.zen.spamhaus.org", "spamhaus.org") == 3
    assert dns.carried(f"{DATA}.12.t.evil.example", "evil.example") == len(DATA) + 1
    assert dns.carried("evil.example", "evil.example") == 0
    assert dns.lookups({"queries": {"value": 3}, "named": {"value": 5}}).unreadable == 0


def test_dns_signals() -> None:
    task = batch1.dns_task("10.0.0.1", at(3), at(20))
    assert isinstance(task, TaskSpec)
    rare = [{"key": f"{DATA}{i}.t.evil.example", "doc_count": 1} for i in range(20)]
    aggs = {"queries": {"value": 4101}, "named": {"value": 4100}, "names": {"value": 4000},
            "rare": {"buckets": rare}}  # fmt: skip
    got = by_name(batch1.read(1, task, ref(), {"aggregations": aggs}))
    # lookups are counted on their time: exact even when names could not be read (F4-R12)
    assert (got["dns.lookups"].value, got["dns.lookups"].completeness) == (4101, "exact")
    assert (got["dns.names"].value, got["dns.names"].completeness) == (4000, "lower_bound")
    assert (got["dns.tunnel_suspected"].value, got["dns.tunnel_suspected"].completeness) == (
        True, "exact")  # fmt: skip
    plain = by_name(batch1.read(1, task, ref(), {"aggregations": {
        "queries": {"value": 5}, "named": {"value": 5}, "names": {"value": 2}}}))  # fmt: skip
    assert plain["dns.names"].completeness == "exact"
    assert plain["dns.tunnel_suspected"].status == "unknown"


def path_aggs(spec: dict[str, tuple[dict[int, int], dict[int, int]]]) -> dict[str, Any]:
    """{path: ({status: n}, {2xx size: n})} as the answer gives it (paths sorted)."""
    names = sorted(spec)
    out: dict[str, Any] = {"paths": {"buckets": [
        {"key": p, "doc_count": sum(spec[p][0].values()),
         "statuses": {"buckets": [{"key": k, "doc_count": v} for k, v in spec[p][0].items()]}}
        for p in names if spec[p][0]]}}  # fmt: skip
    for i, p in enumerate(names):
        sizes = spec[p][1]
        out[f"ok_{i}"] = {"doc_count": sum(sizes.values()),
                          "sizes": {"buckets": [{"key": k, "doc_count": v}
                                                for k, v in sizes.items()]}}  # fmt: skip
    return out


def outcome_map(spec: dict[str, tuple[dict[int, int], dict[int, int]]]) -> dict[str, str]:
    return {o.path: o.outcome for o in paths.outcomes(path_aggs(spec), sorted(spec))}


def test_path_outcomes() -> None:
    catch_all = {"/.env": ({200: 2}, {5120: 2}), "/.git/config": ({200: 1}, {5120: 1}),
                 "/x": ({404: 3}, {}), "/y": ({}, {})}  # fmt: skip
    assert outcome_map(catch_all) == {"/.env": "catch_all", "/.git/config": "catch_all",
                                      "/x": "refused", "/y": "unknown"}  # fmt: skip
    real = {"/.env": ({200: 1}, {311: 1}), "/.git/config": ({404: 1}, {})}
    assert outcome_map(real) == {"/.env": "success", "/.git/config": "refused"}
    mixed = {"/.env": ({200: 2}, {5120: 1, 87: 1}), "/a": ({200: 1}, {5120: 1})}
    assert outcome_map(mixed) == {"/.env": "success", "/a": "catch_all"}
    assert outcome_map({"/.env": ({200: 1}, {311: 1})}) == {
        "/.env": "possible"
    }  # nothing to compare
    no_sizes: dict[str, tuple[dict[int, int], dict[int, int]]] = {
        "/.env": ({200: 1}, {}),
        "/a": ({404: 1}, {}),
    }
    no_sizes_aggs = path_aggs(no_sizes)
    no_sizes_aggs["ok_0"] = {"doc_count": 1, "sizes": {"buckets": []}}
    assert [o.outcome for o in paths.outcomes(no_sizes_aggs, sorted(no_sizes))] == [
        "possible", "refused"]  # fmt: skip
    many = path_aggs({"/.env": ({200: 9}, {1: 1, 2: 1}), "/a": ({200: 2}, {1: 1, 2: 1})})
    many["ok_0"]["sizes"]["sum_other_doc_count"] = 7  # more sizes than listed, all shared
    assert [o.outcome for o in paths.outcomes(many, ["/.env", "/a"])] == ["possible", "catch_all"]
    assert paths.outcomes(None, ["/a"])[0] == paths.PathOutcome("/a", "unknown", 0, {}, 0, {})
    junk = {"paths": {"buckets": [{"key": "/a", "doc_count": "x", "statuses": 5}]}, "ok_0": 3}
    assert paths.outcomes(junk, ["/a"])[0].outcome == "unknown"


def test_path_signals() -> None:
    plan = batch1.paths_task("1.2.3.4", "s.example.org", ["/.env", "/a", "/b"], at(10), at(20))
    task = plan.task
    assert isinstance(task, TaskSpec)
    aggs = path_aggs({"/.env": ({200: 1}, {311: 1}), "/a": ({200: 1}, {5120: 1}),
                      "/b": ({200: 1}, {5120: 1})})  # fmt: skip
    aggs |= {"requests": {"value": 3}, "answered": {"value": 3}}
    got = by_name(batch1.read(1, task, ref(), {"aggregations": aggs}))
    assert {n: (s.status, s.value, s.completeness) for n, s in got.items()} == {
        "web.paths_success": ("known", 1, "exact"),
        "web.paths_catch_all": ("known", 2, "exact"),
        "web.paths_possible": ("unknown", None, "exact"),
    }  # fmt: skip
    aggs |= {"requests": {"value": 4}}  # one request logged without a status
    got = by_name(batch1.read(1, task, ref(), {"aggregations": aggs}))
    assert got["web.paths_success"].completeness == "lower_bound"
    assert got["web.paths_possible"].unknown_reason == "partial_coverage"


def test_source_rows_and_signals() -> None:
    params = source_events.SourceParams(source="squid", ip="10.0.0.1", start=at(3), end=at(4),
                                        size=2)  # fmt: skip
    task = TaskSpec(source_events.LogsSourceEvents(), params)
    three = {"rows": [{"_id": "a"}, {"_id": "b"}, {"_id": "c"}, "junk"]}
    assert source_events.rows(three, 2) == ([{"_id": "a"}, {"_id": "b"}], True)
    assert source_events.rows({"rows": [{"_id": "a"}]}, 2) == ([{"_id": "a"}], False)
    assert source_events.rows({}, 2) == ([], False)
    got = batch1.read(1, task, ref(), three)[0]
    assert (got.name, got.value, got.completeness) == ("source_events.rows", 2, "lower_bound")
    exact = batch1.read(1, task, ref(), {"rows": [{"_id": "a"}]})[0]
    assert (exact.value, exact.completeness) == (1, "exact")
    assert batch1.read(1, task, ref("empty"), {"rows": []})[0].unknown_reason == (
        "ingest_not_verified")  # fmt: skip


def test_reading_another_template_is_a_bug() -> None:
    from argus.context.proxy import ProxyHost, WindowParams

    task = TaskSpec(ProxyHost(), WindowParams(ip="10.0.0.1", start=at(3), end=at(4)))
    with pytest.raises(TypeError, match="not a batch-1 template"):
        batch1.read(1, task, ref(), {})
    with pytest.raises(TypeError, match="not a batch-1 template"):
        batch1.keys("proxy.host", task.params)


# ----------------------------------------------------------------------------- sentences


def test_sentences_are_exact_and_carry_no_log_values() -> None:
    derived: list[dict[str, Any]] = [
        {"name": "pair.beats", "status": "known", "value": 59},
        {"name": "pair.period_s", "status": "known", "value": 300},
        {"name": "pair.jitter_s", "status": "known", "value": 60},
        {"name": "pair.last_beat", "status": "known", "value": "2026-10-20T08:28:07Z"},
        {"name": "pair.still_active", "status": "known", "value": True},
        {"name": "contact.hosts", "status": "known", "value": 3},
        {"name": "contact.last", "status": "known", "value": "2026-10-20T10:20:00Z"},
        {"name": "dns.lookups", "status": "known", "value": 4101},
        {"name": "dns.names", "status": "known", "value": 4000},
        {"name": "dns.tunnel_suspected", "status": "known", "value": True},
        {"name": "web.paths_success", "status": "known", "value": 1},
        {"name": "web.paths_catch_all", "status": "known", "value": 2},
        {"name": "source_events.rows", "status": "known", "value": 20,
         "completeness": "lower_bound"},
    ]  # fmt: skip
    told = batch1.answers(derived)
    assert told == {
        "timeline": "Proxy logs: the host reached the destination about every 5 minutes (± 1 min),"
        " in 59 time buckets; the last time at 08:28 UTC, and it is still active.",
        "scope": "Proxy logs: 3 campus hosts reached the destination; the last contact at 10:20"
        " UTC.",
        "log_pivot": "DNS logs: the client made 4101 lookups of 4000 distinct names; most of the"
        " rarely asked names share one parent domain and carry data, as a DNS tunnel's do."
        " nginx logs: 1"
        " attacked path got a successful answer unlike the others; 2 attacked paths got the"
        " same 2xx answer as other paths tried (most likely the site's catch-all page, so not"
        " shown to succeed).",
        "source_events": "Source logs: at least 20 events of the client in the alert's window"
        " (all its events there, not only those the rule counted).",
    }
    assert batch1.answers([{"name": "pair.beats", "status": "known", "value": 4}]) == {
        "timeline": "Proxy logs: the host reached the destination in 4 time buckets, with no"
        " regular rhythm ARGUS can measure."}  # fmt: skip
    assert batch1.answers([{"name": "web.paths_possible", "status": "known", "value": 1}]) == {
        "log_pivot": "nginx logs: 1 attacked path got a 2xx answer ARGUS cannot"
        " compare."}  # fmt: skip
    unknowns = [{**d, "status": "unknown"} for d in derived]
    assert batch1.answers(unknowns) == {}
    one = [{"name": "contact.hosts", "status": "known", "value": 1}]
    assert batch1.answers(one) == {"scope": "Proxy logs: 1 campus host reached the destination."}
    assert batch1.answers([{"name": "dns.lookups", "status": "known", "value": 3}]) == {
        "log_pivot": "DNS logs: the client made 3 lookups."}  # fmt: skip
    # review F4-R12: a count the evidence shows only as a lower bound is said as one
    low = [
        {**d, "completeness": "lower_bound"}
        for d in derived
        if d["name"] in {"pair.beats", "contact.hosts", "dns.names", "web.paths_success"}
    ]
    told = batch1.answers(low + [d for d in derived if d["name"] in {"dns.lookups"}])
    assert told == {
        "timeline": "Proxy logs: the host reached the destination in at least 59 time buckets,"
        " with no regular rhythm ARGUS can measure.",
        "scope": "Proxy logs: at least 3 campus hosts reached the destination.",
        "log_pivot": "DNS logs: the client made 4101 lookups of at least 4000 distinct names."
        " nginx logs: at least 1 attacked path got a successful answer unlike the others.",
    }  # fmt: skip


# ----------------------------------------------------------------------------- the gate


def test_keys_and_commonness() -> None:
    pair = beacon.PairParams(host="10.0.0.1", destination="8.8.8.8", start=at(3), end=at(4))
    assert batch1.keys("proxy.pair", pair) == (batch1.Key("host", "10.0.0.1"),)
    contact = beacon.ContactParams(destination="8.8.8.8", start=at(3), end=at(4))
    assert batch1.keys("proxy.contact", contact) == (batch1.Key("destination", "8.8.8.8"),)
    watched = beacon.ContactParams(destination="8.8.8.8", hosts=("10.0.0.1",), start=at(3),
                                   end=at(4))  # fmt: skip
    # each watched host is gated as a campus host (review F4-R2)
    assert batch1.keys("proxy.contact", watched) == (batch1.Key("host", "10.0.0.1"),)
    domains = dns.DomainsParams(ip="10.0.0.1", start=at(3), end=at(4))
    assert batch1.keys("dns.host_domains", domains) == (batch1.Key("host", "10.0.0.1"),)
    web = paths.PathParams(ip="1.2.3.4", site="s", paths=("/a", "/"), start=at(3), end=at(4))
    assert batch1.keys("web.path_outcomes", web) == (
        batch1.Key("host", "1.2.3.4"), batch1.Key("path", "/"),
        batch1.Key("path", "/a"))  # fmt: skip
    rows = source_events.SourceParams(source="nginx", ip="1.2.3.4", start=at(3), end=at(4))
    assert batch1.keys("logs.source_events", rows) == ()
    prev = batch1.Prevalence
    host, dest, path = (batch1.Key("host", "x"), batch1.Key("destination", "x"),
                        batch1.Key("path", "/"))  # fmt: skip
    assert not batch1.too_common(host, prev(49, 99))  # campus hosts count for destinations only
    assert batch1.too_common(host, prev(50, 0))
    assert not batch1.too_common(dest, prev(49, 24))
    assert batch1.too_common(dest, prev(0, 25))
    assert batch1.too_common(dest, prev(50, 0))
    assert batch1.too_common(path, prev(0, 0))
    assert not batch1.too_common(batch1.Key("path", "/a"), prev(500, 500))
    assert set(paths.COMMON_PATHS) >= {"/", "/favicon.ico", "/robots.txt"}


def test_refusals_read_plainly() -> None:
    assert batch1.Refusal("too_common").sentence == "could not tell: too common to query"
    assert set(batch1.SENTENCES) == {"off", "quiet_hours", "not_normal", "too_common",
                                     "daily_cap", "no_subject"}  # fmt: skip
    for sentence in batch1.SENTENCES.values():
        assert sentence[0].islower()
        assert not sentence.endswith(".")


def test_campus_addresses() -> None:
    plain = batch1.private_or(None)
    assert [plain(v) for v in ("10.0.0.1", "8.8.8.8", "fd00::1", "nope")] == [
        True, False, True, False]  # fmt: skip
    mapped = batch1.private_or(lambda v: "campus" if v == "131.21.124.9" else "public")
    assert mapped("131.21.124.9")
    assert not mapped("10.0.0.1")


# ----------------------------------------------------------------------------- builders


def test_pair_task() -> None:
    facts = {"first_event_at": at(9, 50).isoformat(), "last_event_at": at(10, 20).isoformat()}
    fields = {"source.ip": {"top": [["8.8.8.8", 9], ["10.8.0.5", 5]]},
              "destination.ip": {"top": [["10.1.1.1", 9], ["45.9.9.9", 3]]}}  # fmt: skip
    ips = {"8.8.8.8": {"class": "public"}, "10.8.0.5": {"class": "internal"},
           "10.1.1.1": {"class": "asset"}, "45.9.9.9": {"class": "public"}}  # fmt: skip
    task = batch1.pair_task(facts, fields, ips, at(20))
    assert isinstance(task, TaskSpec)
    p = task.params
    assert isinstance(p, beacon.PairParams)
    assert (p.host, p.destination, p.start, p.end) == ("10.8.0.5", "45.9.9.9", at(8, 50),
                                                       at(11, 20))  # fmt: skip
    assert batch1.pair_task(facts, {}, ips, at(20)) == batch1.Refusal("no_subject")
    assert batch1.pair_task({}, fields, ips, at(20)) == batch1.Refusal("no_subject")
    assert batch1.pair_task(facts, fields, ips, at(9)) == batch1.Refusal("no_subject", "window")
    wide = {"first_event_at": at(1, 10).isoformat(), "last_event_at": at(20).isoformat()}
    got = batch1.pair_task(wide, fields, ips, at(23, 30))
    assert isinstance(got, TaskSpec)
    assert (got.params.start, got.params.end) == (at(9), at(21))  # type: ignore[attr-defined]


def test_contact_task() -> None:
    task = batch1.contact_task("8.8.8.8", at(12))
    assert isinstance(task, TaskSpec)
    assert (task.params.start, task.params.end) == (at(1), at(11, 45))  # type: ignore[attr-defined]
    day = batch1.contact_task("8.8.8.8", at(12), day=at(5, d=18))
    assert isinstance(day, TaskSpec)
    assert (day.params.start, day.params.end) == (at(1, d=18), at(22, 59, d=18))  # type: ignore[attr-defined]
    assert batch1.contact_task("8.8.8.8", at(1, 10)) == batch1.Refusal("no_subject", "window")
    bad = batch1.contact_task("not an ip", at(12))
    assert isinstance(bad, batch1.Refusal)
    assert (bad.code, bad.detail) == ("no_subject", "ValidationError")


def test_dns_task() -> None:
    task = batch1.dns_task("10.0.0.1", at(3, 30), at(20))
    assert isinstance(task, TaskSpec)
    assert (task.params.start, task.params.end) == (at(2, 30), at(4, 30))  # type: ignore[attr-defined]
    assert batch1.dns_task("10.0.0.1", at(3, 30), at(2)) == batch1.Refusal("no_subject", "window")
    near = batch1.dns_task("10.0.0.1", at(23, 30), at(20, d=21))  # the end after midnight
    assert isinstance(near, TaskSpec)
    assert (near.params.start, near.params.end) == (at(22, 30), at(22, 59))  # type: ignore[attr-defined]
    # around midnight itself nothing fits one daily index
    assert batch1.dns_task("10.0.0.1", at(0, d=21), at(20, d=21)) == batch1.Refusal(
        "no_subject", "window")  # fmt: skip


def test_paths_task() -> None:
    tried = ["/", "/.env", "/" + "a" * 99, "/" + "b" * 256, "/.env", "/x\n"] + [
        f"/{i}" for i in range(12)]  # fmt: skip
    plan = batch1.paths_task("1.2.3.4", "s.example.org", tried, at(10), at(20))
    assert plan.left_out == (
        ("/", "too_common"), ("/" + "a" * 99, "maybe_cut"), ("/" + "b" * 256, "too_long"),
        ("/8", "over_limit"), ("/9", "over_limit"), ("/10", "over_limit"), ("/11", "over_limit"),
    )  # fmt: skip
    assert isinstance(plan.task, batch1.Refusal)  # "/x\n" has a control character
    assert plan.task.detail == "ValidationError"
    fine = batch1.paths_task("1.2.3.4", "s.example.org", tried[:3], at(10), at(20),
                             from_field_facts=False)  # fmt: skip
    assert fine.left_out == (("/", "too_common"),)
    assert isinstance(fine.task, TaskSpec)
    assert fine.task.params.paths == ("/.env", "/" + "a" * 99)  # type: ignore[attr-defined]
    assert (fine.task.params.start, fine.task.params.end) == (at(10), at(16))  # type: ignore[attr-defined]
    assert batch1.paths_task("1.2.3.4", "s", ["/"], at(10), at(20)).task == batch1.Refusal(
        "no_subject")  # fmt: skip
    assert batch1.paths_task("1.2.3.4", "s", ["/a"], at(10), at(9)).task == batch1.Refusal(
        "no_subject")  # fmt: skip


def _normalized(name: str) -> dict[str, Any]:
    return dict(json.loads((ROOT / "tests/fixtures/normalized" / name).read_text()))


def test_source_task_from_the_fixture_alerts() -> None:
    threshold = _normalized("threshold__proxy_excessive_blocked_requests_from_single_host.json")
    task = batch1.source_task(threshold, ["acme-logs-squid*"])
    assert isinstance(task, TaskSpec)
    p = task.params
    assert isinstance(p, source_events.SourceParams)
    assert (p.source, p.ip, p.narrow) == ("squid", "10.43.119.92", ())
    assert p.start == datetime(2026, 10, 9, 12, 16, 48, tzinfo=UTC)
    assert p.end == datetime(2026, 10, 9, 12, 19, 20, tzinfo=UTC)  # its last event included
    esql = _normalized("esql__sensitive_path_enumeration.json")
    task = batch1.source_task(esql, ["acme-logs-nginx-*"])
    assert isinstance(task, TaskSpec)
    p = task.params
    assert isinstance(p, source_events.SourceParams)
    assert (p.source, p.ip, p.narrow) == ("nginx", "131.130.27.79", ())
    assert p.end - p.start == timedelta(minutes=11, seconds=1)
    query = _normalized("query__proxy_plain_http_post_to_raw_ip_address_possible_c2_beacon.json")
    assert batch1.source_task(query, ["acme-logs-squid*"]) == batch1.Refusal(
        "no_subject", "only threshold and ES|QL alerts lack their source events")  # fmt: skip


def test_source_params_from_alerts() -> None:
    base = {"rule_type": "threshold",
            "evidence_window": {"start": at(3).isoformat(), "end": at(3, 0, s=30).isoformat()},
            "group_key": {"fields": ["source.ip", "destination.ip", "destination.port",
                                     "event.action"],
                          "values": ["10.0.0.1", "8.8.8.8", 443, "TCP_DENIED"]}}  # fmt: skip
    got = source_events.from_alert(base, ["acme-logs-squid*"])
    assert isinstance(got, source_events.SourceParams)
    assert got.narrow == (("destination.ip", "8.8.8.8"), ("destination.port", "443"))
    assert (got.start, got.end) == (at(3), at(3, 1))  # at least a minute
    squid = ["acme-logs-squid*"]
    for indices in (["acme-logs-squid*", "acme-logs-nginx-*"],
                    ["acme-logs-postfix-*"], []):  # fmt: skip
        assert "exactly one" in str(source_events.from_alert(base, indices))
    no_window = {**base, "evidence_window": {}}
    assert "no evidence window" in str(source_events.from_alert(no_window, squid))
    bad_window = {**base, "evidence_window": {"start": "x", "end": "y"}}
    assert "no evidence window" in str(source_events.from_alert(bad_window, squid))
    nobody = {**base, "group_key": {"fields": ["destination.ip"], "values": ["8.8.8.8"]}}
    assert "no client" in str(source_events.from_alert(nobody, ["acme-logs-squid*"]))
    wrong = {**base, "group_key": {"fields": ["source.ip"], "values": ["host-1"]}}
    assert "cannot be searched" in str(source_events.from_alert(wrong, ["acme-logs-squid*"]))
    long_window = {**base, "evidence_window": {"start": at(1).isoformat(),
                                               "end": at(5).isoformat()}}  # fmt: skip
    got = source_events.from_alert(long_window, ["acme-logs-dns-*"])
    assert isinstance(got, source_events.SourceParams)
    assert (got.source, got.start, got.end) == ("dns", at(4, 0, s=1), at(5, 0, s=1))
    assert source_events.source_of(["a-logs-squid-x", "logs-squid*"]) == "squid"


# ----------------------------------------------------------------------------- first runs


def test_first_tasks() -> None:
    who = {"host": "10.8.0.5", "destination": "45.9.9.9", "pair": ("10.8.0.6", "45.9.9.8"),
           "web": ("45.1.2.3", "s.example.org", ["/.env", "/"]), "alert": None}  # fmt: skip
    now = at(16, 20)

    def span(task: Any) -> tuple[datetime, datetime]:
        assert isinstance(task, TaskSpec)
        return task.params.start, task.params.end  # type: ignore[attr-defined]

    # each as large as production makes it (review F4-R4), the newest such window
    pair = batch1.first_task("proxy.pair", who, now)
    assert span(pair) == (at(4, 5), at(16, 5))  # 12 h, today
    assert (pair.params.host, pair.params.destination) == ("10.8.0.6", "45.9.9.8")  # type: ignore[union-attr]
    contact = batch1.first_task("proxy.contact", who, now)
    assert span(contact) == (at(1, d=19), at(22, 59, d=19))  # yesterday's whole index
    assert contact.params.hosts == ()  # type: ignore[union-attr]
    assert span(batch1.first_task("proxy.contact", who, at(23, 30))) == (at(1), at(22, 59))
    assert span(batch1.first_task("dns.host_domains", who, now)) == (at(14, 5), at(16, 5))
    web = batch1.first_task("web.path_outcomes", who, now)
    assert span(web) == (at(10, 5), at(16, 5))
    assert web.params.paths == ("/.env",)  # type: ignore[union-attr]
    assert span(batch1.first_task("proxy.pair", who, at(1, 10))) == (at(10, 59, d=19),
                                                                     at(22, 59, d=19))  # fmt: skip
    assert batch1.first_task("logs.source_events", who, now) == batch1.Refusal("no_subject")
    empty = dict.fromkeys(who)
    for name in batch1.TEMPLATES:
        assert batch1.first_task(name, empty, now) == batch1.Refusal("no_subject")
    with pytest.raises(ValueError, match="not a batch-1 template"):
        batch1.first_task("proxy.host", who, now)


def test_the_answers_shape_prints_no_value() -> None:
    body = {"aggregations": {"hosts": {"buckets": [{"key": "10.0.0.1"}]}, "host_count":
            {"value": 3}, "first": {"value": None}, "ok_0": {"doc_count": 4}}}  # fmt: skip
    assert batch1._shape(body) == "first none, host_count set, hosts 1 buckets, ok_0 4"
    assert batch1._shape({"hits": {"hits": [{}, {}]}}) == "2 rows"
    assert batch1._shape({"hits": []}) == "0 rows"
    assert batch1._shape(None) == "no answer body"
    assert "10.0.0.1" not in batch1._shape(body)


# ----------------------------------------------------------------------------- the switch


def test_the_switch_is_off_until_its_first_run() -> None:
    assert EnrichmentSettings().templates == ()
    on = EnrichmentSettings(templates="proxy.pair, dns.host_domains")  # type: ignore[arg-type]
    assert on.templates == ("proxy.pair", "dns.host_domains")
    listed = EnrichmentSettings.model_validate({"templates": ["web.path_outcomes"]})
    assert listed.templates == ("web.path_outcomes",)
    with pytest.raises(ValidationError):
        EnrichmentSettings.model_validate({"templates": ["proxy.host"]})


def test_every_batch1_check_has_plain_words_in_the_report() -> None:
    """Q-F2's provenance lines name each check in plain words, never its code (D-095)."""
    from argus.report.facts import CHECKS, CHECKS_OTHER

    for name in batch1.TEMPLATES:
        assert name in CHECKS, name
        assert name in CHECKS_OTHER, name
        assert "." not in CHECKS[name]
        assert "." not in CHECKS_OTHER[name]
