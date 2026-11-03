"""``dns.host_domains``: which names one client looked up in a window of at most 2 hours: its most
and least asked names, how many distinct names, the query types and the answer codes.

A client asking thousands of distinct names under one parent domain looks like a DNS tunnel. An
aggregation on the DNS logs, so heavy: one daily index, a 10 s timeout, a prevalence gate on the
client, 18 buckets at most, an answer within the 16 KiB snapshot. A name too long to index is
counted apart ("could not read"), never dropped silently.
"""

from __future__ import annotations

import statistics
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any

from pydantic import Field, field_validator, model_validator

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

LONGEST = timedelta(hours=2)
TOP = 6  # most asked names
RARE = 8  # least asked names: a tunnel's names are each asked about once
TYPES = 2
CODES = 2
TIMEOUT = timedelta(seconds=10)
# A tunnel: this many distinct names in the window, most of the rare ones under one parent.
TUNNEL_NAMES = 500
TUNNEL_SHARE = 0.5
# A tunnel carries data in its names: the labels under the parent (numbers left out, so a
# reversed address is none) are at least this long, as the median of its rare names.
TUNNEL_DATA = 16
# Lookups that ask very many distinct names by design, never a tunnel: reverse (PTR) lookups
# and the DNS blocklists and reputation services a mail, web or antivirus server asks about
# each address, domain or file it sees.
LOOKUP_ZONES = frozenset(
    {
        "in-addr.arpa", "ip6.arpa", "spamhaus.org", "spamcop.net", "sorbs.net",
        "barracudacentral.org", "surbl.org", "uribl.com", "mailspike.net", "abuseat.org",
        "dnswl.org", "senderscore.com", "spameatingmonkey.net", "sophosxl.net", "mcafee.com",
    }
)  # fmt: skip
# Second-level labels under which a country's registry hands out names (ac.in, co.uk).
SECOND_LEVEL = frozenset({"ac", "co", "com", "edu", "gov", "net", "org", "res", "nic", "mil"})


class DomainsParams(SourcedParams):
    ROLE = Role.DNS
    ip: str = Field(min_length=2, max_length=45)
    start: datetime
    end: datetime

    @field_validator("ip")
    @classmethod
    def _address(cls, value: str) -> str:
        return address(value)

    @model_validator(mode="after")
    def _window(self) -> DomainsParams:
        check_window(self.start, self.end, LONGEST, one_index=True)
        return self


@register
class DnsHostDomains(Template):
    """One client's DNS lookups in at most 2 hours: top and rare names, distinct names,
    query types and answer codes."""

    name = "dns.host_domains"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.LOG
    cost = CostClass.HEAVY
    params_model = DomainsParams
    timeout = TIMEOUT

    @classmethod
    def spec(cls) -> Spec:
        fs = all_fields(Role.DNS)
        return replace(
            super().spec(),
            filter_fields=frozenset(
                n for f in fs for n in (f("client_ip"), f("client_ip_alt"), f.time)
            ),
            aggregate_fields=frozenset(
                n
                for f in fs
                for n in (f("query_name"), f("query_type"), f("response_code"), f.time)
            ),
        )

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, DomainsParams)
        f = fields_for(Role.DNS, params.source)
        name = f("query_name")
        body = {
            "size": 0,
            "track_total_hits": False,
            "query": {
                "bool": {
                    "filter": [
                        {
                            "bool": {
                                "should": [
                                    {"term": {f("client_ip"): params.ip}},
                                    {"term": {f("client_ip_alt"): params.ip}},
                                ],
                                "minimum_should_match": 1,
                            }
                        },
                        {"range": {f.time: {"gte": iso(params.start), "lt": iso(params.end)}}},
                    ]
                }
            },
            "aggs": {
                "queries": {"value_count": {"field": f.time}},
                "named": {"value_count": {"field": name}},
                "names": {"cardinality": {"field": name}},
                "top": {"terms": {"field": name, "size": TOP}},
                "rare": {"terms": {"field": name, "size": RARE, "order": {"_count": "asc"}}},
                "types": {"terms": {"field": f("query_type"), "size": TYPES}},
                "codes": {"terms": {"field": f("response_code"), "size": CODES}},
            },
        }
        return RequestPlan(
            self.spec(),
            body=body,
            window=Window(params.source or source_for(Role.DNS), params.start, params.end),
        )


# ----------------------------------------------------------------------------- reading


def parent(name: str) -> str | None:
    """The registered domain a name is under, by the labels alone: the last two, or the last
    three under a country's second level (``x.example.ac.in`` is under ``example.ac.in``). None
    for a single label."""
    labels = [label for label in name.lower().rstrip(".").split(".") if label]
    if len(labels) < 2:
        return None
    take = 3 if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL else 2
    return ".".join(labels[-take:])


def carried(name: str, under: str) -> int:
    """How many characters a name carries below its parent ``under``: its labels there, less
    the dots and the labels that are only digits (``4.3.2.1.in-addr.arpa`` carries none)."""
    labels = [label for label in name.lower().rstrip(".").split(".") if label]
    below = labels[: len(labels) - len(under.split("."))]
    return sum(len(label) for label in below if not label.isdigit())


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _keys(aggs: Mapping[str, Any], name: str) -> list[tuple[str, int]]:
    out = []
    for b in (aggs.get(name) or {}).get("buckets") or []:
        if isinstance(b, Mapping) and isinstance(b.get("key"), str):
            out.append((b["key"], _int(b.get("doc_count")) or 0))
    return out


@dataclass(frozen=True)
class Lookups:
    queries: int | None  # lookups in the window
    unreadable: int | None  # lookups whose name is not indexed (over ignore_above, or none)
    names: int | None  # distinct names (approximate above 3,000: cardinality)
    top: list[tuple[str, int]]
    rare: list[tuple[str, int]]
    tunnel_parent: str | None  # very many names, most rare ones under one parent, data-like


def lookups(aggs: Mapping[str, Any] | None) -> Lookups:
    a = aggs or {}
    queries = _int((a.get("queries") or {}).get("value"))
    named = _int((a.get("named") or {}).get("value"))
    unreadable = None if queries is None or named is None else max(queries - named, 0)
    names = _int((a.get("names") or {}).get("value"))
    rare = _keys(a, "rare")
    parents = Counter(p for key, _ in rare if (p := parent(key)) is not None)
    tunnel = None
    if names is not None and names >= TUNNEL_NAMES and parents:
        best, count = sorted(parents.items(), key=lambda kv: (-kv[1], kv[0]))[0]
        data = [carried(key, best) for key, _ in rare if parent(key) == best]
        if (
            count >= TUNNEL_SHARE * len(rare)
            and best not in LOOKUP_ZONES
            and statistics.median(data) >= TUNNEL_DATA
        ):
            tunnel = best
    return Lookups(queries, unreadable, names, _keys(a, "top"), rare, tunnel)


def read(
    version: int, params: DomainsParams, ref: Mapping[str, Any], snapshot: Mapping[str, Any]
) -> list[SignalValue]:
    """Signals of one answer. A name that could not be read makes the distinct names a lower
    bound (``coverage``), as a cut answer does: "at least 4,000 names" is still a finding;
    the lookups are counted on their time, so they stay exact. The answer itself cut (the
    snapshot) leaves every signal unknown but a positive count."""
    got = lookups(snapshot.get("aggregations"))
    names = [ref]
    if got.unreadable:
        names = [{**ref, "coverage": {**(ref.get("coverage") or {}), "unreadable": got.unreadable}}]
    return [
        from_logs(derived("dns.lookups", version, [ref], lambda: got.queries, counts=True)),
        from_logs(derived("dns.names", version, names, lambda: got.names, counts=True)),
        # Found among the names that could be read, so it stands whatever else was unreadable;
        # a tunnel's absence is never known from the logs alone.
        derived(
            "dns.tunnel_suspected", version, [ref], lambda: True if got.tunnel_parent else None
        ),
    ]


def answers(derived_: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    known = Known(derived_)
    by = known.by
    told: dict[str, str] = {}
    if "dns.lookups" in by:
        many = f" of {known.count('dns.names')} distinct names" if "dns.names" in by else ""
        tunnel = (
            "; most of the rarely asked names share one parent domain and carry data, as a DNS"
            " tunnel's do"
            if by.get("dns.tunnel_suspected")
            else ""
        )
        told["log_pivot"] = (
            f"DNS logs: the client made {known.count('dns.lookups')} lookups{many}{tunnel}."
        )
    return told
