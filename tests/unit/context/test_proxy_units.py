"""R12 (D-060), the pure parts, exactly: the two requests, the window, the cadence of the
timeline, the signals (a zero from logs is unknown, D-063) and the sentences."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from argus.context import proxy

pytestmark = pytest.mark.unit

IST = timezone(timedelta(hours=5, minutes=30))
START = datetime(2026, 10, 13, 9, 30, tzinfo=IST)  # 04:00 UTC
END = datetime(2026, 10, 13, 6, tzinfo=UTC)
WINDOW = {"gte": "2026-10-13T04:00:00Z", "lt": "2026-10-13T06:00:00Z"}


def params(ip: str = "10.8.242.106") -> proxy.WindowParams:
    return proxy.WindowParams(ip=ip, start=START, end=END)


def test_the_host_request_is_exactly_this() -> None:
    plan = proxy.ProxyHost().build(params())
    assert plan.body == {
        "size": 0,
        "track_total_hits": False,
        "query": {"bool": {"filter": [
            {"term": {"source.ip": "10.8.242.106"}},
            {"range": {"@timestamp": WINDOW}},
        ]}},
        "aggs": {
            "destinations": {"terms": {"field": "destination.ip", "size": 10}},
            "destination_count": {"cardinality": {"field": "destination.ip"}},
            "bytes": {"sum": {"field": "destination.bytes"}},
            "statuses": {"terms": {"field": "http.response.status_code", "size": 10}},
            "actions": {"terms": {"field": "event.action.keyword", "size": 10}},
            "timeline": {"date_histogram": {
                "field": "@timestamp", "fixed_interval": "10m", "min_doc_count": 0,
                "hard_bounds": {"min": WINDOW["gte"], "max": WINDOW["lt"]},
            }},
        },
    }  # fmt: skip
    assert plan.window == proxy.Window("squid", START, END)
    assert plan.spec.filter_fields == {"source.ip", "@timestamp"}
    assert plan.spec.aggregate_fields == {
        "destination.ip", "destination.bytes", "http.response.status_code",
        "event.action.keyword", "@timestamp",
    }  # fmt: skip
    assert proxy.ProxyHost.timeout == timedelta(seconds=20)
    with pytest.raises(AssertionError):
        proxy.ProxyHost().build(proxy.Params())


def test_the_destination_request_is_exactly_this() -> None:
    plan = proxy.ProxyDestination().build(params("168.220.248.201"))
    assert plan.body == {
        "size": 0,
        "track_total_hits": False,
        "query": {"bool": {"filter": [
            {"term": {"destination.ip": "168.220.248.201"}},
            {"range": {"@timestamp": WINDOW}},
        ]}},
        "aggs": {
            "host_count": {"cardinality": {"field": "source.ip"}},
            "hosts": {"terms": {"field": "source.ip", "size": 10}},
            "urls": {"terms": {"field": "url.original.keyword", "size": 10}},
        },
    }  # fmt: skip
    assert plan.spec.filter_fields == {"destination.ip", "@timestamp"}
    assert plan.spec.aggregate_fields == {"source.ip", "url.original.keyword"}
    assert proxy.ProxyDestination.timeout == timedelta(seconds=20)
    with pytest.raises(AssertionError):
        proxy.ProxyDestination().build(proxy.Params())


@pytest.mark.parametrize("ip", ["1", "a" * 46])
def test_addresses_are_bounded(ip: str) -> None:
    with pytest.raises(ValidationError):
        params(ip)
    params("::")
    params("a" * 45)


def at(h: int, m: int = 0, d: int = 13) -> datetime:
    return datetime(2026, 10, d, h, m, tzinfo=UTC)


def span(first: datetime, last: datetime, now: datetime) -> Any:
    return proxy.window({"first_event_at": first.isoformat(), "last_event_at": last.isoformat()},
                        now)  # fmt: skip


def test_the_window() -> None:
    assert span(at(9, 50), at(10, 20), at(20)) == (at(8), at(12))  # hours ± 1 h (end +2)
    assert span(at(9, 50), at(10, 20), at(11, 20)) == (at(8), at(11))  # the ingest margin
    assert span(at(9, 50), at(10, 20), at(11, 14)) == (at(8), at(10))
    assert span(at(9, 50), at(10, 20), at(9, 10)) is None  # nothing old enough
    assert span(at(9, 50), at(10, 20), at(9, 15)) == (at(8), at(9))  # the hour before counts
    assert span(at(9, 50), at(10, 20), at(9, 14)) is None  # end == start
    # ≤ 24 h and one daily index (01:00 to 23:00 with the gateway's pad): never two days (D-067)
    assert span(at(1, 10, d=10), at(10, 20), at(20)) == (at(1), at(12))
    assert span(at(23, 10, d=12), at(1, 20), at(20)) == (at(1), at(3))
    assert span(at(22, 10, d=12), at(23, 50, d=12), at(20)) == (at(21, d=12), at(22, d=12))
    assert span(at(23, 10, d=12), at(23, 50, d=12), at(20)) is None  # all of it near midnight
    assert proxy.window({}, at(20)) is None
    assert proxy.window({"first_event_at": at(9).isoformat()}, at(20)) is None
    assert proxy._days(at(1), at(22, 59)) == 1
    assert proxy._days(at(0, 30), at(5)) == 2
    assert proxy._days(at(5), at(23, 30)) == 2


def test_tasks_ask_for_the_internal_host_and_the_outside_destination() -> None:
    facts = {"first_event_at": at(9, 50).isoformat(), "last_event_at": at(10, 20).isoformat()}
    fields = {"source.ip": {"top": [["8.8.8.8", 9], ["10.8.242.106", 5]]},
              "destination.ip": {"top": [["10.1.1.1", 9], ["168.220.248.201", 3]]}}  # fmt: skip
    ips = {"8.8.8.8": {"class": "public"}, "10.8.242.106": {"class": "internal"},
           "10.1.1.1": {"class": "campus"}, "168.220.248.201": {"class": "public"}}  # fmt: skip
    host, dest = proxy.tasks(facts, fields, ips, at(20))
    assert isinstance(host.template, proxy.ProxyHost)
    assert (host.params.ip, host.params.start, host.params.end) == (  # type: ignore[attr-defined]
        "10.8.242.106",
        at(8),
        at(12),
    )
    assert isinstance(dest.template, proxy.ProxyDestination)
    assert dest.params.ip == "168.220.248.201"  # type: ignore[attr-defined]
    for cls in ("asset", "campus", "internal"):
        one = proxy.tasks(facts, {"source.ip": {"top": [["10.0.0.9", 1]]}},
                          {"10.0.0.9": {"class": cls}}, at(20))  # fmt: skip
        assert len(one) == 1
    assert proxy.tasks(facts, fields, {}, at(20)) == []
    assert proxy.tasks(facts, fields, ips, at(9)) == []


def buckets(*counts: int) -> list[dict[str, int]]:
    return [{"doc_count": n} for n in counts]


def test_the_timeline_cadence() -> None:
    assert proxy.cadence(buckets(1, 0, 1, 0, 1, 0, 1)) == (4, 0.0)
    assert proxy.cadence(buckets(1, 1, 0, 0, 1, 1)) == (4, 0.566)  # gaps 1, 3, 1
    assert proxy.cadence(buckets(1, 0, 1, 0, 1)) == (3, None)  # two gaps: too few
    assert proxy.cadence(buckets(0, 0)) == (0, None)
    assert proxy.cadence([{}, {"doc_count": 2}]) == (1, None)


def ref(template: str, **extra: Any) -> dict[str, Any]:
    return {"task_key": template, "status": "ok", "template": f"{template}@1", **extra}


def test_signals_from_the_aggregations() -> None:
    host = {"destination_count": {"value": 7}, "bytes": {"value": 1200.0},
            "timeline": {"buckets": buckets(1, 0, 1, 0, 1, 0, 1)}}  # fmt: skip
    evidence = {"h": ref("proxy.host"), "d": ref("proxy.destination")}
    snaps = {"h": {"aggregations": host}, "d": {"aggregations": {"host_count": {"value": 3}}}}
    got = {s.name: (s.value, s.status) for s in proxy.signals(1, evidence, snaps)}
    assert got == {
        "proxy.destinations": (7, "known"), "proxy.bytes": (1200.0, "known"),
        "proxy.busy_slots": (4, "known"), "proxy.regularity": (0.0, "known"),
        "proxy.hosts_to_destination": (3, "known"),
    }  # fmt: skip
    zeros = {"h": {"aggregations": {"destination_count": {"value": 0}}}}
    by = {s.name: s for s in proxy.signals(1, {"h": ref("proxy.host")}, zeros)}
    assert by["proxy.destinations"].unknown_reason == "ingest_not_verified"
    assert by["proxy.bytes"].unknown_reason == "no_value"
    partial = {"h": ref("proxy.host", truncated=True)}
    lower = {s.name: s for s in proxy.signals(1, partial, {"h": {"aggregations": host}})}
    assert (lower["proxy.destinations"].value, lower["proxy.destinations"].completeness) == (
        7, "lower_bound")  # fmt: skip
    assert lower["proxy.regularity"].status == "unknown"
    assert proxy.signals(1, {"x": ref("web.followups")}, {}) == []
    empty = {s.name for s in proxy.signals(1, {"h": ref("proxy.host")}, {})}
    assert empty == {"proxy.destinations", "proxy.bytes", "proxy.busy_slots", "proxy.regularity"}


def test_what_the_module_tells_the_steps() -> None:
    def known(name: str, value: Any) -> dict[str, Any]:
        return {"name": name, "status": "known", "value": value}

    told = proxy.answers([
        known("proxy.hosts_to_destination", 3), known("proxy.busy_slots", 4),
        known("proxy.regularity", 0.5), known("proxy.destinations", 7),
    ])  # fmt: skip
    assert told == {
        "prevalence": "Proxy logs: 3 internal hosts reached the destination in the window.",
        "timeline": "Proxy logs: traffic in 4 ten-minute slots, regularity 0.5 (0 = even).",
        "log_pivot": "Proxy logs: the host reached 7 destinations in the window.",
    }
    plain = proxy.answers([known("proxy.busy_slots", 2)])
    assert plain == {"timeline": "Proxy logs: traffic in 2 ten-minute slots."}
    gone = [{"name": "proxy.busy_slots", "status": "unknown", "value": None}]
    assert proxy.answers(gone) == {}
    assert proxy.iso(START) == "2026-10-13T04:00:00Z"
