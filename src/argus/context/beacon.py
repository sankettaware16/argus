"""Two proxy templates of batch 1 (Q-F4, plan §5 WS-F, §7.3): one host to one destination
over time (``proxy.pair``, the PS1Bot detector: period, jitter, last beat) and who reached one
destination when (``proxy.contact``: first and last contact per host in a day, for Q-C2's
still-active watch).

Both are aggregations on squid's logs, so heavy: one daily index, a 10 s timeout, at most 361
buckets, an answer that fits the 16 KiB snapshot (the date histogram's text keys are left out
with ``filter_path``). Field names are the captured squid mapping's: ``source.ip`` and
``destination.ip`` are ``ip``, ``destination.bytes`` is ``long``.

What the answers mean follows D-023: a count from the logs is known when positive, and a zero
or a "not regular" is never negative until ARGUS measures how far ingest has got (Q-F1); a
missing hour of logs also looks like a pause.
"""

from __future__ import annotations

import itertools
import math
import statistics
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import Field, field_validator, model_validator

from argus import site
from argus.context.bounds import address, check_window, iso
from argus.context.evidence import Known, SignalValue, derived, from_logs
from argus.context.sourced import SourcedParams
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
from argus.site import Role, all_fields, fields_for, source_for

PAIR_LONGEST = timedelta(hours=12)
FINE_LONGEST = timedelta(hours=6)  # up to 6 h in 1-minute buckets, up to 12 h in 2-minute ones
CONTACT_LONGEST = timedelta(hours=22)  # one daily index: 01:00 to 22:59 UTC
CONTACT_HOSTS = 25  # hosts listed with their first and last contact
WATCHED_HOSTS = 10  # hosts a contact check may be limited to
MIN_GAPS = 5  # beats - 1 needed to call a cadence regular
REGULAR_SHARE = 0.8  # of the gaps within one bucket of the typical gap
# The largest chance that traffic with no rhythm (busy buckets at random, at any rate) shows
# gaps this regular: a cadence is called only below it (review F4-R1).
ALPHA = 1e-9
TIMEOUT = timedelta(seconds=10)  # heavy templates (plan §7.3)


def _between(start: datetime, end: datetime, source: str | None = None) -> dict[str, Any]:
    return {"range": {fields_for(Role.PROXY, source).time: {"gte": iso(start), "lt": iso(end)}}}


def interval(start: datetime, end: datetime) -> timedelta:
    """The bucket width for a window: 1 minute up to 6 hours, else 2 minutes."""
    return timedelta(minutes=1) if end - start <= FINE_LONGEST else timedelta(minutes=2)


class PairParams(SourcedParams):
    ROLE = Role.PROXY
    host: str = Field(min_length=2, max_length=45)
    destination: str = Field(min_length=2, max_length=45)
    start: datetime
    end: datetime

    @field_validator("host", "destination")
    @classmethod
    def _address(cls, value: str) -> str:
        return address(value)

    @model_validator(mode="after")
    def _window(self) -> PairParams:
        check_window(self.start, self.end, PAIR_LONGEST, one_index=True)
        if self.host == self.destination:
            raise ValueError("a host and its destination are two addresses")
        return self


@register
class ProxyPair(Template):
    """One campus host's requests to one destination over time, in 1- or 2-minute buckets."""

    name = "proxy.pair"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.LOG
    cost = CostClass.HEAVY
    params_model = PairParams
    timeout = TIMEOUT

    @classmethod
    def spec(cls) -> Spec:
        fs = all_fields(Role.PROXY)
        return replace(
            super().spec(),
            filter_fields=frozenset(
                n for f in fs for n in (f("client_ip"), f("server_ip"), f.time)
            ),
            aggregate_fields=frozenset(n for f in fs for n in (f.time, f("bytes"))),
        )

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, PairParams)
        f = fields_for(Role.PROXY, params.source)
        step = int(interval(params.start, params.end).total_seconds() // 60)
        body = {
            "size": 0,
            "track_total_hits": False,
            "query": {
                "bool": {
                    "filter": [
                        {"term": {f("client_ip"): params.host}},
                        {"term": {f("server_ip"): params.destination}},
                        _between(params.start, params.end, params.source),
                    ]
                }
            },
            "aggs": {
                "requests": {"value_count": {"field": f.time}},
                "first": {"min": {"field": f.time}},
                "last": {"max": {"field": f.time}},
                "bytes": {"sum": {"field": f("bytes")}},
                "beats": {
                    "date_histogram": {
                        "field": f.time,
                        "fixed_interval": f"{step}m",
                        "min_doc_count": 1,
                        "hard_bounds": {"min": iso(params.start), "max": iso(params.end)},
                    }
                },
            },
        }
        return RequestPlan(
            self.spec(),
            body=body,
            url_params=(("filter_path", "-aggregations.beats.buckets.key_as_string"),),
            window=Window(params.source or source_for(Role.PROXY), params.start, params.end),
        )


class ContactParams(SourcedParams):
    ROLE = Role.PROXY
    destination: str = Field(min_length=2, max_length=45)
    hosts: tuple[str, ...] = Field(default=(), max_length=WATCHED_HOSTS)
    start: datetime
    end: datetime

    @field_validator("destination")
    @classmethod
    def _address(cls, value: str) -> str:
        return address(value)

    @field_validator("hosts")
    @classmethod
    def _hosts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({address(v) for v in value}))

    @model_validator(mode="after")
    def _window(self) -> ContactParams:
        check_window(self.start, self.end, CONTACT_LONGEST, one_index=True)
        if self.destination in self.hosts:
            raise ValueError("the destination is not one of the hosts")
        return self


@register
class ProxyContact(Template):
    """Who reached one destination in a day, with each host's first and last request."""

    name = "proxy.contact"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.LOG
    cost = CostClass.HEAVY
    params_model = ContactParams
    timeout = TIMEOUT

    @classmethod
    def spec(cls) -> Spec:
        fs = all_fields(Role.PROXY)
        return replace(
            super().spec(),
            filter_fields=frozenset(
                n for f in fs for n in (f("client_ip"), f("server_ip"), f.time)
            ),
            aggregate_fields=frozenset(n for f in fs for n in (f("client_ip"), f.time)),
        )

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, ContactParams)
        f = fields_for(Role.PROXY, params.source)
        filters: list[dict[str, Any]] = [{"term": {f("server_ip"): params.destination}}]
        if params.hosts:
            filters.append({"terms": {f("client_ip"): list(params.hosts)}})
        filters.append(_between(params.start, params.end, params.source))
        body = {
            "size": 0,
            "track_total_hits": False,
            "query": {"bool": {"filter": filters}},
            "aggs": {
                "requests": {"value_count": {"field": f.time}},
                # over every host, not only the listed ones: the newest contact may be a quiet
                # host's (review F4-R5)
                "first": {"min": {"field": f.time}},
                "last": {"max": {"field": f.time}},
                "host_count": {"cardinality": {"field": f("client_ip")}},
                "hosts": {
                    "terms": {"field": f("client_ip"), "size": CONTACT_HOSTS},
                    "aggs": {
                        "first": {"min": {"field": f.time}},
                        "last": {"max": {"field": f.time}},
                    },
                },
            },
        }
        return RequestPlan(
            self.spec(),
            body=body,
            window=Window(params.source or source_for(Role.PROXY), params.start, params.end),
        )


# ----------------------------------------------------------------------------- reading


def _ms(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return int(value)


def _at(ms: int | None) -> datetime | None:
    return None if ms is None else datetime.fromtimestamp(ms / 1000, UTC)


@dataclass(frozen=True)
class Cadence:
    beats: int  # busy buckets
    requests: int | None
    period: timedelta | None  # the regular gaps' mean, when the gaps are regular
    jitter: timedelta | None  # their standard deviation, at least one bucket
    regular_share: float | None  # gaps within one bucket of the typical gap (never 1 bucket)
    first: datetime | None
    last: datetime | None
    still_active: bool | None  # regular, and the last beat within two periods of the end


def likeliest(low: int, high: int) -> float:
    """The largest chance, over every rate, that a gap of traffic with no rhythm (each bucket
    busy at random: a geometric gap) is ``low`` to ``high`` buckets long (``low`` >= 2)."""
    u = ((low - 1) / high) ** (1 / (high - low + 1))  # the rate that makes it likeliest
    return float(u ** (low - 1) - u**high)


def tail(n: int, k: int, q: float) -> float:
    """P(X >= k) for X ~ Binomial(n, q): how likely ``k`` or more of ``n`` such gaps are."""
    if k <= 0 or q >= 1:
        return 1.0
    if q <= 0:
        return 0.0
    lq, lr = math.log(q), math.log1p(-q)
    logs = [
        math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1) + i * lq + (n - i) * lr
        for i in range(k, n + 1)
    ]
    top = max(logs)
    return math.exp(top) * math.fsum(math.exp(v - top) for v in logs)


def cadence(aggs: Mapping[str, Any] | None, start: datetime, end: datetime) -> Cadence:
    """What a ``proxy.pair`` answer says about the pair's rhythm. The resolution is the
    bucket: a period is called only when the typical (median) gap is at least two buckets,
    at least 80 % of the gaps are within one bucket of it (a gap of one bucket never counts:
    a beacon slower than a bucket seldom fills two in a row), and traffic with no rhythm, at
    whatever rate, would show that many such gaps with a chance below ``ALPHA``. Random use
    of a site (busy in 45 % of the minutes, say) is therefore never called a beacon."""
    a = aggs or {}
    step = interval(start, end)
    width = int(step.total_seconds() * 1000)
    buckets = (a.get("beats") or {}).get("buckets") or []
    keys = sorted(
        {
            k
            for b in buckets
            if isinstance(b, Mapping)
            and (k := _ms(b.get("key"))) is not None
            and (_ms(b.get("doc_count")) or 0) > 0
        }
    )
    gaps = [(b - a_) // width for a_, b in itertools.pairwise(keys)]
    first = _at(_ms((a.get("first") or {}).get("value")))
    last = _at(_ms((a.get("last") or {}).get("value")))
    requests = _ms((a.get("requests") or {}).get("value"))
    if len(gaps) < MIN_GAPS:
        return Cadence(len(keys), requests, None, None, None, first, last, None)
    typical = statistics.median_low(gaps)
    low, high = max(2, typical - 1), typical + 1
    steady = [g for g in gaps if low <= g <= high]
    share = round(len(steady) / len(gaps), 3)
    regular = (
        typical >= 2
        and share >= REGULAR_SHARE
        and tail(len(gaps), len(steady), likeliest(low, high)) <= ALPHA
    )
    if not regular:
        return Cadence(len(keys), requests, None, None, share, first, last, None)
    # The regular gaps' mean (a pause, such as a laptop asleep, is left out) and their
    # spread, never below one bucket: the check cannot see finer than its resolution.
    period = timedelta(seconds=round(statistics.fmean(steady) * step.total_seconds()))
    jitter = max(statistics.pstdev(steady), 1.0) * step
    jitter = timedelta(seconds=round(jitter.total_seconds()))
    active = last is not None and end - last <= 2 * period + step
    return Cadence(len(keys), requests, period, jitter, share, first, last, active)


@dataclass(frozen=True)
class Contact:
    host: str
    requests: int
    first: datetime | None
    last: datetime | None


def contacts(aggs: Mapping[str, Any] | None) -> tuple[int | None, list[Contact]]:
    """(hosts that reached the destination, the listed hosts with their first and last
    request, most requests first) from a ``proxy.contact`` answer."""
    a = aggs or {}
    found = []
    for b in (a.get("hosts") or {}).get("buckets") or []:
        if not isinstance(b, Mapping) or not isinstance(b.get("key"), str):
            continue
        found.append(
            Contact(
                b["key"],
                _ms(b.get("doc_count")) or 0,
                _at(_ms((b.get("first") or {}).get("value"))),
                _at(_ms((b.get("last") or {}).get("value"))),
            )
        )
    return _ms((a.get("host_count") or {}).get("value")), found


def every_host_listed(aggs: Mapping[str, Any] | None) -> bool:
    """Whether the answer lists every host (at most 25 reached the destination)."""
    node = (aggs or {}).get("hosts") or {}
    return isinstance(node, Mapping) and node.get("sum_other_doc_count") == 0


def read_pair(
    version: int, params: PairParams, ref: Mapping[str, Any], snapshot: Mapping[str, Any]
) -> list[SignalValue]:
    """The pair's rhythm from one ``proxy.pair`` answer (``ref``: its evidence reference)."""
    got = cadence(snapshot.get("aggregations"), params.start, params.end)
    refs = [ref]
    values = (
        ("pair.period_s", None if got.period is None else int(got.period.total_seconds())),
        ("pair.jitter_s", None if got.jitter is None else int(got.jitter.total_seconds())),
        ("pair.last_beat", None if got.last is None else iso(got.last)),
        # Not regular, or not active: never negative from the logs alone (D-023).
        ("pair.still_active", True if got.still_active else None),
    )
    out = [from_logs(derived("pair.beats", version, refs, _const(got.beats), counts=True))]
    out += [derived(name, version, refs, _const(value)) for name, value in values]
    return out


def read_contact(
    version: int, params: ContactParams, ref: Mapping[str, Any], snapshot: Mapping[str, Any]
) -> list[SignalValue]:
    """How many hosts reached the destination, and the last contact over all of them (the
    answer's own newest request, never the newest of the listed hosts), from one answer."""
    aggs = snapshot.get("aggregations")
    count, _ = contacts(aggs)
    last = _at(_ms(((aggs or {}).get("last") or {}).get("value")))
    refs = [ref]
    return [
        from_logs(derived("contact.hosts", version, refs, _const(count), counts=True)),
        derived("contact.last", version, refs, _const(None if last is None else iso(last))),
    ]


def _const(value: Any) -> Any:
    return lambda: value


def answers(derived_: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    """Plain sentences for the note's steps, from the derived signals (dicts). Numbers and
    times only: no value from the logs enters a sentence. A count known only as a lower
    bound is said as one ("at least")."""
    known = Known(derived_)
    by = known.by
    told: dict[str, str] = {}
    if "pair.period_s" in by and "pair.beats" in by:
        period = round(by["pair.period_s"] / 60, 1)
        jitter = round(by.get("pair.jitter_s", 60) / 60, 1)
        last = str(by.get("pair.last_beat", ""))[11:16]
        active = ", and it is still active" if by.get("pair.still_active") else ""
        told["timeline"] = (
            f"Proxy logs: the host reached the destination about every {period:g} minutes"
            f" (± {jitter:g} min), in {known.count('pair.beats')} time buckets; the last time"
            f" at {last} UTC{active}."
        )
    elif "pair.beats" in by:
        told["timeline"] = (
            f"Proxy logs: the host reached the destination in {known.count('pair.beats')} time"
            " buckets, with no regular rhythm ARGUS can measure."
        )
    if "contact.hosts" in by:
        last = str(by.get("contact.last", ""))[11:16]
        when = f"; the last contact at {last} UTC" if last else ""
        hosts = known.count("contact.hosts", site.own("host"), site.own("hosts"))
        told["scope"] = f"Proxy logs: {hosts} reached the destination{when}."
    return told
