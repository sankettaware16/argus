"""One evidence row (an ARGUS check that ran) as a sentence and the query behind it (AR7, D-190).

The sentence says what the stored answer showed, with figures read from the answer and nothing
else (a stored answer that cannot be read as the template's shape says only that the check ran);
the query is the template's own, in text (:mod:`argus.incident.discover`). A row whose template has
no query here, or whose parameters cannot be read, is not an evidence line: it is counted among the
report's limits, because a line a person cannot check would only look like evidence.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from argus import site
from argus.incident import discover
from argus.incident.model import ReportQuery
from argus.incident.words import ist_moment, plural, size
from argus.site import Words

TITLES = Words(
    {
        "proxy.host": "{A_own:host}'s proxy traffic",
        "proxy.destination": "Which {own:hosts} reached a destination",
        "proxy.pair": "How a host reached a destination",
        "proxy.contact": "Who reached an outside address",
        "dns.host_domains": "The names a host looked up in DNS",
        "web.followups": "A client's successful web answers",
        "web.path_outcomes": "Whether the attacked paths got a successful answer",
        "logs.source_events": "The client's log events",
        "ti.lookup": "Whether the values are on the threat lists",
    }
)
SOURCES = Words(
    {
        "proxy.host": "the {own:proxy logs} ({source:proxy})",
        "proxy.destination": "the {own:proxy logs} ({source:proxy})",
        "proxy.pair": "the {own:proxy logs} ({source:proxy})",
        "proxy.contact": "the {own:proxy logs} ({source:proxy})",
        "dns.host_domains": "the {own:DNS logs}",
        "web.followups": "the web server logs ({source:web})",
        "web.path_outcomes": "the web server logs ({source:web})",
        "logs.source_events": "the logs of the alert's source",
        "ti.lookup": "the local threat lists",
    }
)


@dataclass(frozen=True)
class Said:
    """What a stored answer shows: the sentence, its figures and the headline count."""

    text: str
    numbers: tuple[float, ...]
    count: int | None  # the number of requests, lookups or rows the answer counted
    empty: bool = False  # the check ran and found nothing


def _val(node: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(node, Mapping):
            return None
        node = node.get(key)
    return node


def _int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return int(value) if value == value and abs(value) < 10**15 else None


def _aggs(snapshot: Any) -> Mapping[str, Any]:
    found = _val(snapshot, "aggregations")
    return found if isinstance(found, Mapping) else {}


def _span(params: Mapping[str, Any]) -> str:
    try:
        start = _moment(params["start"])
        end = _moment(params["end"])
    except (KeyError, ValueError, TypeError):
        return ""
    return f" between {ist_moment(start)} and {ist_moment(end)}"


def _moment(value: Any) -> datetime:
    at = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    if at.tzinfo is None:
        raise ValueError("a time without a zone")
    return at


def _total(snapshot: Any) -> int | None:
    # the stored answer keeps its count at the top ({"rows", "total", ...}); a raw one in hits
    found = _val(snapshot, "total")
    if found is None:
        found = _val(snapshot, "hits", "total")
    if isinstance(found, Mapping):
        return _int(found.get("value"))
    return _int(found)


def rows_total(snapshot: Any) -> int | None:
    """The row count a stored answer holds (``total`` at the top, or a raw ``hits.total``)."""
    return _total(snapshot)


def _timeline_total(aggs: Mapping[str, Any]) -> int | None:
    buckets = _val(aggs, "timeline", "buckets")
    if not isinstance(buckets, list):
        return None
    counts = [_int(b.get("doc_count")) for b in buckets if isinstance(b, Mapping)]
    return sum(c for c in counts if c is not None) if counts else None


def say(template: str, params: Mapping[str, Any], snapshot: Any, status: str) -> Said:
    """The sentence for a stored answer (``status`` ok or empty)."""
    ran = f"ARGUS's {template} check"
    if snapshot is None:
        return Said(f"{ran} ran, and the log rows behind it were deleted after ARGUS's"
                    " retention period.", (), None)  # fmt: skip
    aggs = _aggs(snapshot)
    span = _span(params)
    ip = str(params.get("ip") or params.get("host") or "")
    if template == "proxy.host":
        n = _timeline_total(aggs)
        dests = _int(_val(aggs, "destination_count", "value"))
        total = _val(aggs, "bytes", "value")
        if n is None:
            return Said(f"{ran} ran for {ip}{span} and could not be read.", (), None)
        if n == 0:
            return Said(f"The proxy logged no traffic from {ip}{span}.", (), 0, True)
        where = f" to {plural(dests, 'destination')}" if dests is not None else ""
        data = f", {size(float(total))}" if isinstance(total, int | float) and total > 0 else ""
        nums = tuple(float(x) for x in (n, dests) if x is not None)
        return Said(f"The proxy logged {plural(n, 'request')} from {ip}{where}{data}{span}.",
                    nums, n)  # fmt: skip
    if template == "proxy.destination":
        hosts = _int(_val(aggs, "host_count", "value"))
        if hosts is None:
            return Said(f"{ran} ran for {ip}{span} and could not be read.", (), None)
        if hosts == 0:
            return Said(f"No {site.own('host')} reached {ip}{span}.", (), 0, True)
        return Said(
            f"{plural(hosts, site.own('host'), site.own('hosts'))} reached {ip}{span}.",
            (float(hosts),),
            hosts,
        )
    if template == "proxy.pair":
        n = _int(_val(aggs, "requests", "value"))
        dest = str(params.get("destination") or "")
        if n is None:
            return Said(f"{ran} ran for {ip} and {dest}{span} and could not be read.", (), None)
        if n == 0:
            return Said(f"{ip} made no request to {dest}{span}.", (), 0, True)
        total = _val(aggs, "bytes", "value")
        data = f", {size(float(total))}" if isinstance(total, int | float) and total > 0 else ""
        return Said(f"{ip} made {plural(n, 'request')} to {dest}{data}{span}.", (float(n),), n)
    if template == "proxy.contact":
        n = _int(_val(aggs, "requests", "value"))
        hosts = _int(_val(aggs, "host_count", "value"))
        dest = str(params.get("destination") or "")
        if n is None or hosts is None:
            return Said(f"{ran} ran for {dest}{span} and could not be read.", (), None)
        if n == 0:
            return Said(f"Nobody reached {dest}{span}.", (), 0, True)
        who = plural(hosts, site.own("host"), site.own("hosts"))
        return Said(f"{who} made {plural(n, 'request')} to {dest}{span}.",
                    (float(hosts), float(n)), n)  # fmt: skip
    if template == "dns.host_domains":
        queries = _int(_val(aggs, "queries", "value"))
        names = _int(_val(aggs, "names", "value"))
        if queries is None:
            return Said(f"{ran} ran for {ip}{span} and could not be read.", (), None)
        if queries == 0:
            return Said(f"The DNS logs hold no lookups by {ip}{span}.", (), 0, True)
        many = f" of {plural(names, 'distinct name')}" if names is not None else ""
        nums = tuple(float(x) for x in (queries, names) if x is not None)
        return Said(f"{ip} made {plural(queries, 'DNS lookup')}{many}{span}.", nums, queries)
    if template == "web.followups":
        n = _total(snapshot)
        if n is None:
            return Said(f"{ran} ran for {ip}{span} and could not be read.", (), None)
        if n == 0:
            return Said(f"The web server gave {ip} no successful answer{span}.", (), 0, True)
        return Said(f"The web server gave {ip} {plural(n, 'successful (2xx) answer')}{span}.",
                    (float(n),), n)  # fmt: skip
    if template == "web.path_outcomes":
        return _paths(params, snapshot, aggs, span, ip)
    if template == "logs.source_events":
        n = _total(snapshot)
        if n is None:
            return Said(f"{ran} ran for {ip}{span} and could not be read.", (), None)
        if n == 0:
            return Said(f"The logs hold no event of {ip}{span}.", (), 0, True)
        return Said(f"The logs hold {plural(n, 'event')} of {ip}{span}.", (float(n),), n)
    if template == "ti.lookup":
        n = _total(snapshot)
        asked = len(params.get("values") or [])
        if n is None:
            return Said(f"{ran} ran and could not be read.", (), None)
        if n == 0:
            return Said(f"None of {plural(asked, 'value')} is on the local threat lists.",
                        (float(asked),), 0, True)  # fmt: skip
        records = plural(n, "record")
        verb = "names" if n == 1 else "name"
        return Said(f"{records} on the local threat lists {verb} the {plural(asked, 'value')}"
                    " asked about.", (float(n), float(asked)), n)  # fmt: skip
    return Said(f"{ran} ran.", (), None)


def _paths(
    params: Mapping[str, Any], snapshot: Any, aggs: Mapping[str, Any], span: str, ip: str
) -> Said:
    from argus.context import paths
    from argus.responder.facts import outcomes_of

    n = _int(_val(aggs, "requests", "value"))
    if n is None:
        return Said(f"ARGUS's web.path_outcomes check ran for {ip}{span} and could not be read.",
                    (), None)  # fmt: skip
    if n == 0:
        return Said(f"{ip} made no logged request for the paths asked about{span}.", (), 0, True)
    asked = params.get("paths")
    served = [
        o
        for o in outcomes_of(snapshot, asked if isinstance(asked, list) else [])
        if o.outcome == paths.SUCCESS
    ]
    tried = len(asked) if isinstance(asked, list | tuple) else 0
    if tried:
        return Said(f"{ip} made {plural(n, 'request')} for {plural(tried, 'path')}, "
                    f"{len(served)} of them served{span}.",
                    (float(n), float(tried), float(len(served))),
                    n)  # fmt: skip
    return Said(f"{ip} made {plural(n, 'request')}{span}.", (float(n),), n)


def query_for(
    cfg: discover.Config, template: str, version: int, params: Mapping[str, Any], at: datetime
) -> ReportQuery | None:
    return discover.for_template(cfg, template, version, params, at)


def sort_key(said: Said) -> tuple[int, int]:
    """Informative first: a check that counted something before one that found nothing."""
    return (0 if said.count else 1, -(said.count or 0))
