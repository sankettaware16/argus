"""The proxy module of the generic pack: what the proxy logs say around an investigation.

Two bounded aggregations over the investigation's hours (± 1 h, at most 24 h, never past the
ingest margin): one internal host's traffic and one outside destination's prevalence. Both are
heavy: budgeted, deferred like every remote task, and sent only with
``enrichment.proxy_aggregations`` on, after their own first run.
"""

from __future__ import annotations

import itertools
import statistics
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import Field

from argus.context.evidence import SignalValue, canonical, derived, from_logs
from argus.context.packs import TaskSpec
from argus.context.sourced import SourcedParams
from argus.gateway.indices import PAD
from argus.gateway.templates import (
    CostClass,
    Endpoint,
    Family,
    Params,
    RequestPlan,
    Spec,
    Template,
    Window,
    register,
)
from argus.site import (
    Role,
    all_fields,
    fields_for,
    reads,
    source_for,
    source_param,
)

SLOT = timedelta(minutes=10)
MARGIN = timedelta(minutes=15)  # ingest: never read the last minutes
MAX_WINDOW = timedelta(hours=24)
AGG_DAYS = 1  # daily indices one aggregation may read
INTERNAL = frozenset({"asset", "campus", "internal"})


def iso(at: datetime) -> str:
    return at.astimezone(UTC).isoformat().replace("+00:00", "Z")


def source(params: SourcedParams | None = None) -> str:
    """The proxy log family a request reads (its source key): the one its parameters name, else
    the site's first."""
    return source_for(Role.PROXY) if params is None or params.source is None else params.source


class WindowParams(SourcedParams):
    ROLE = Role.PROXY
    ip: str = Field(min_length=2, max_length=45)
    start: datetime
    end: datetime


@register
class ProxyHost(Template):
    """One internal host's proxy traffic in a window."""

    name = "proxy.host"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.LOG
    cost = CostClass.HEAVY
    params_model = WindowParams
    timeout = timedelta(seconds=20)

    @classmethod
    def spec(cls) -> Spec:
        fs = all_fields(Role.PROXY)
        return replace(
            super().spec(),
            filter_fields=frozenset(n for f in fs for n in (f("client_ip"), f.time)),
            aggregate_fields=frozenset(
                n
                for f in fs
                for n in (f("server_ip"), f("bytes"), f("status_code"), f("action"), f.time)
            ),
        )

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, WindowParams)
        f = fields_for(Role.PROXY, params.source)
        window = {"gte": iso(params.start), "lt": iso(params.end)}
        body = {
            "size": 0,
            "track_total_hits": False,  # log searches never count every hit (validator)
            "query": {
                "bool": {
                    "filter": [
                        {"term": {f("client_ip"): params.ip}},
                        {"range": {f.time: window}},
                    ]
                }
            },
            "aggs": {
                "destinations": {"terms": {"field": f("server_ip"), "size": 10}},
                "destination_count": {"cardinality": {"field": f("server_ip")}},
                "bytes": {"sum": {"field": f("bytes")}},
                "statuses": {"terms": {"field": f("status_code"), "size": 10}},
                "actions": {"terms": {"field": f("action"), "size": 10}},
                "timeline": {
                    "date_histogram": {
                        "field": f.time,
                        "fixed_interval": "10m",
                        "min_doc_count": 0,
                        "hard_bounds": {"min": iso(params.start), "max": iso(params.end)},
                    }
                },
            },
        }
        span = Window(source(params), params.start, params.end)
        return RequestPlan(self.spec(), body=body, window=span)


@register
class ProxyDestination(Template):
    """One outside destination's prevalence among internal hosts in a window."""

    name = "proxy.destination"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.LOG
    cost = CostClass.HEAVY
    params_model = WindowParams
    timeout = timedelta(seconds=20)

    @classmethod
    def spec(cls) -> Spec:
        fs = all_fields(Role.PROXY)
        return replace(
            super().spec(),
            filter_fields=frozenset(n for f in fs for n in (f("server_ip"), f.time)),
            aggregate_fields=frozenset(n for f in fs for n in (f("client_ip"), f("url"))),
        )

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, WindowParams)
        f = fields_for(Role.PROXY, params.source)
        window = {"gte": iso(params.start), "lt": iso(params.end)}
        body = {
            "size": 0,
            "track_total_hits": False,  # log searches never count every hit (validator)
            "query": {
                "bool": {
                    "filter": [
                        {"term": {f("server_ip"): params.ip}},
                        {"range": {f.time: window}},
                    ]
                }
            },
            "aggs": {
                "host_count": {"cardinality": {"field": f("client_ip")}},
                "hosts": {"terms": {"field": f("client_ip"), "size": 10}},
                "urls": {"terms": {"field": f("url"), "size": 10}},
            },
        }
        span = Window(source(params), params.start, params.end)
        return RequestPlan(self.spec(), body=body, window=span)


def applies(indices: Sequence[str]) -> bool:
    """The rule reads a proxy log family of the site (the alert's ``kibana.alert.rule.indices``)."""
    return reads(indices, Role.PROXY)


def window(facts: Mapping[str, Any], now: datetime) -> tuple[datetime, datetime] | None:
    """The investigation's hours ± 1 h, at most 24 h back from its last alert, not past the
    ingest margin, within one daily index (with the gateway's 1 h pad: 01:00 to 23:00 UTC);
    None when nothing of it is old enough or fits."""
    first, last = facts.get("first_event_at"), facts.get("last_event_at")
    if not first or not last:
        return None
    start = datetime.fromisoformat(str(first)).replace(minute=0, second=0, microsecond=0)
    end = datetime.fromisoformat(str(last)).replace(minute=0, second=0, microsecond=0)
    start, end = start - timedelta(hours=1), end + timedelta(hours=2)
    end = min(end, (now - MARGIN).replace(minute=0, second=0, microsecond=0))
    start = max(start, end - MAX_WINDOW)
    # One daily index only: an aggregation never spans two days of squid.
    # Near midnight the end is cut back first; the hours before it are kept where possible.
    while end > start and _days(start, end) > AGG_DAYS:
        if _days(end - timedelta(hours=1), end) > AGG_DAYS:
            end -= timedelta(hours=1)
        else:
            start += timedelta(hours=1)
    return (start, end) if end > start else None


def _days(start: datetime, end: datetime) -> int:
    """How many daily indices the gateway would read (it pads 1 h around midnight)."""
    return ((end + PAD).date() - (start - PAD).date()).days + 1


def tasks(
    facts: Mapping[str, Any],
    fields: Mapping[str, Any],
    ips: Mapping[str, Any],
    now: datetime,
    earlier: Mapping[str, Mapping[str, Any]] | None = None,
    indices: Sequence[str] | None = None,
) -> list[TaskSpec]:
    """The host's and the destination's aggregation, each once per investigation: a request
    an earlier version made is planned again as it was (its answer is reused). With
    several proxy families, the one the rule's ``indices`` name is read."""
    before = earlier or {}
    if "proxy.host" in before or "proxy.destination" in before:
        return [
            TaskSpec(template, WindowParams.model_validate_json(canonical(before[template.name])))
            for template in (ProxyHost(), ProxyDestination())
            if template.name in before
        ]
    span = window(facts, now)
    if span is None:
        return []
    start, end = span
    family = source_param(Role.PROXY, indices)
    found: list[TaskSpec] = []
    hosts = [
        v
        for v, _ in fields.get("source.ip", {}).get("top", [])
        if ips.get(v, {}).get("class") in INTERNAL
    ]
    outside = [
        v
        for v, _ in fields.get("destination.ip", {}).get("top", [])
        if ips.get(v, {}).get("class") == "public"
    ]
    if hosts:
        found.append(
            TaskSpec(ProxyHost(), WindowParams(ip=hosts[0], start=start, end=end, source=family))
        )
    if outside:
        found.append(
            TaskSpec(
                ProxyDestination(),
                WindowParams(ip=outside[0], start=start, end=end, source=family),
            )
        )
    return found


def _aggs(snapshots: Mapping[str, Any], evidence: Mapping[str, Any], template: str) -> Any:
    for key, ref in evidence.items():
        if str(ref.get("template", "")).startswith(template + "@"):
            snap = snapshots.get(key) or {}
            return snap.get("aggregations"), ref
    return None, None


def cadence(timeline: Sequence[Mapping[str, Any]]) -> tuple[int, float | None]:
    """(busy 10-minute slots, regularity of the gaps between them: 0 = perfectly even)."""
    busy = [i for i, b in enumerate(timeline) if b.get("doc_count", 0) > 0]
    gaps = [b - a for a, b in itertools.pairwise(busy)]
    if len(gaps) < 3 or statistics.fmean(gaps) == 0:
        return len(busy), None
    return len(busy), round(statistics.pstdev(gaps) / statistics.fmean(gaps), 3)


def signals(
    version: int, evidence: Mapping[str, Any], snapshots: Mapping[str, Any]
) -> list[SignalValue]:
    out: list[SignalValue] = []
    host, href = _aggs(snapshots, evidence, "proxy.host")
    if href is not None:
        a = host or {}
        refs = [href]
        out += [
            from_logs(
                derived(
                    "proxy.destinations",
                    version,
                    refs,
                    lambda: (a.get("destination_count") or {}).get("value"),
                    counts=True,
                )
            ),
            from_logs(
                derived(
                    "proxy.bytes",
                    version,
                    refs,
                    lambda: (a.get("bytes") or {}).get("value"),
                    counts=True,
                )
            ),
            from_logs(
                derived(
                    "proxy.busy_slots",
                    version,
                    refs,
                    lambda: cadence((a.get("timeline") or {}).get("buckets", []))[0],
                    counts=True,
                )
            ),
            derived(
                "proxy.regularity",
                version,
                refs,
                lambda: cadence((a.get("timeline") or {}).get("buckets", []))[1],
            ),
        ]
    dest, dref = _aggs(snapshots, evidence, "proxy.destination")
    if dref is not None:
        d = dest or {}
        out.append(
            from_logs(
                derived(
                    "proxy.hosts_to_destination",
                    version,
                    [dref],
                    lambda: (d.get("host_count") or {}).get("value"),
                    counts=True,
                )
            )
        )
    return out


def answers(derived_: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    """What the module tells the note's steps (prevalence, timeline, log pivots), from the
    derived signals (dicts)."""
    by = {s["name"]: s["value"] for s in derived_ if s.get("status") == "known"}
    told: dict[str, str] = {}
    if "proxy.hosts_to_destination" in by:
        told["prevalence"] = (
            f"Proxy logs: {by['proxy.hosts_to_destination']} internal hosts reached the"
            " destination in the window."
        )
    if "proxy.busy_slots" in by:
        regular = by.get("proxy.regularity")
        how = f", regularity {regular} (0 = even)" if regular is not None else ""
        told["timeline"] = f"Proxy logs: traffic in {by['proxy.busy_slots']} ten-minute slots{how}."
    if "proxy.destinations" in by:
        told["log_pivot"] = (
            f"Proxy logs: the host reached {by['proxy.destinations']} destinations in the window."
        )
    return told
