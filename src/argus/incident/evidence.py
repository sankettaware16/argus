"""One evidence row (an ARGUS check that ran) as a sentence and the query behind it.

The sentence says what the stored answer showed, with figures read from the answer and nothing
else; the query is the template's own, in text (:mod:`argus.incident.discover`). A row whose
template has no query here, or whose parameters cannot be read, is not an evidence line: it is
counted among the report's limits."""

from __future__ import annotations

import contextlib
import itertools
import re
import statistics
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from argus import site
from argus.context import beacon
from argus.incident import discover
from argus.incident.model import ReportQuery
from argus.incident.words import ist_moment, plural, size
from argus.normalize.fields import values as field_values
from argus.site import FIELD_ROLES, Words

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


DETAILS = 6  # values an evidence line shows
DETAIL_CHARS = 200  # characters of one value from the logs
AGENT_CHARS = 120  # of a user agent inside a pattern
# What each detail list is, in ARGUS's words.
SHOWS = {
    "proxy.destination": "The most requested addresses there, without their query strings",
    "logs.source_events": "The kinds of event among the rows ARGUS keeps",
    "proxy.pair": "The rhythm of the requests",
}
# The parts of a log event that make its pattern, by field role: the site's field for the role
# when the alert's source is known, else the ECS name of every log family that has the role.
PATTERN = ("method", "url_path", "url", "query_name", "status_code", "response_code", "action",
           "query_type", "server_port", "user_agent")  # fmt: skip
_SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]{0,15}://)([^/?#]*@)?")


@dataclass(frozen=True)
class Detail:
    """One deciding value of a stored answer (a URL, an event's pattern, a rhythm), with how
    many requests or rows of the answer it counts (None: not a count)."""

    text: str
    count: int | None = None


@dataclass(frozen=True)
class Shown:
    """What an evidence line shows beyond its sentence: a label of ARGUS's and the values."""

    label: str
    details: tuple[Detail, ...]


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


def printable(value: Any, limit: int = DETAIL_CHARS) -> str:
    """A value from the logs as one line: no control, bidirectional or zero-width character,
    whitespace folded, cut at ``limit``."""
    text = " ".join("".join(c if c.isprintable() else " " for c in str(value)).split())
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def bare_url(value: Any) -> str:
    """A URL or path without what may name a person: no query string, fragment or path
    parameters (``;jsessionid=``), no user information before the host."""
    text = printable(value, 4 * DETAIL_CHARS)
    text = re.split(r"[?#;]", text, maxsplit=1)[0]
    text = _SCHEME.sub(lambda m: m.group(1), text)
    return printable(text)


def _path(value: Any) -> str:
    """A URL's path alone (``/api/v1/ext/remote``), or a path as it is."""
    text = bare_url(value)
    found = _SCHEME.match(text)
    if found is None:
        return text
    rest = text[found.end() :]
    return rest[rest.find("/") :] if "/" in rest else "/"


def _top(counts: Counter[str], first: Mapping[str, int]) -> tuple[Detail, ...]:
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], first[kv[0]]))
    return tuple(Detail(text, n) for text, n in ranked[:DETAILS])


def _urls(aggs: Mapping[str, Any]) -> tuple[Detail, ...]:
    """The answer's most requested URLs, query strings left out (two that differ only there are
    one), most requested first."""
    counts: Counter[str] = Counter()
    first: dict[str, int] = {}
    buckets = _val(aggs, "urls", "buckets")
    for i, b in enumerate(buckets if isinstance(buckets, list) else []):
        n = _int(_val(b, "doc_count"))
        url = bare_url(_val(b, "key")) if isinstance(_val(b, "key"), str) else ""
        if n is None or n <= 0 or not url:
            continue
        counts[url] += n
        first.setdefault(url, i)
    return _top(counts, first)


def _pattern_fields(source: Any) -> dict[str, tuple[str, ...]]:
    """Field role -> the fields a row may hold it under."""
    out: dict[str, tuple[str, ...]] = {}
    family = site.active().family(source) if isinstance(source, str) else None
    own = family.resolved() if family is not None else None
    for logical in PATTERN:
        names: list[str] = []
        if own is not None:
            with contextlib.suppress(Exception):  # a role this family does not have
                names.append(own.source(logical))
        names += [roles[logical] for roles in FIELD_ROLES.values() if logical in roles]
        out[logical] = tuple(dict.fromkeys(names))
    return out


def _pattern(row: Mapping[str, Any], fields: Mapping[str, tuple[str, ...]]) -> str:
    def first(logical: str) -> str:
        for name in fields.get(logical, ()):
            found = field_values(row, name)
            if found and found[0] is not None and str(found[0]).strip():
                return printable(found[0])
        return ""

    path = first("url_path") or first("url")
    parts = [
        " ".join(p for p in (first("method"), _path(path) if path else "",
                             printable(first("query_name"), 120)) if p),
        first("status_code") or first("response_code"),
        first("action"),
        first("query_type"),
        f"port {first('server_port')}" if first("server_port") else "",
        f"agent {printable(first('user_agent'), AGENT_CHARS)}" if first("user_agent") else "",
    ]  # fmt: skip
    return printable(" · ".join(p for p in parts if p))


def _patterns(snapshot: Any, params: Mapping[str, Any]) -> tuple[Detail, ...]:
    """The distinct kinds of event among the stored rows (method, path, status, action, port,
    agent), with how many rows each is, most first."""
    rows = _val(snapshot, "rows")
    if not isinstance(rows, list):
        rows = _val(snapshot, "hits", "hits")
    fields = _pattern_fields(params.get("source"))
    counts: Counter[str] = Counter()
    first: dict[str, int] = {}
    for i, r in enumerate(rows if isinstance(rows, list) else []):
        doc = r.get("_source") if isinstance(r, Mapping) else None
        if not isinstance(doc, Mapping):
            continue
        text = _pattern(doc, fields)
        if text:
            counts[text] += 1
            first.setdefault(text, i)
    return _top(counts, first)


def _minutes(span: timedelta) -> str:
    """``45 seconds``, ``1 minute``, ``2.5 minutes``, ``14 minutes``."""
    seconds = int(span.total_seconds())
    if seconds < 60:
        return plural(seconds, "second")
    minutes = seconds / 60
    if minutes >= 10 or minutes == int(minutes):
        return plural(round(minutes), "minute")
    return f"{minutes:.1f} minutes"


def _rhythm(params: Mapping[str, Any], aggs: Mapping[str, Any]) -> tuple[Detail, ...]:
    """A pair's rhythm: the periods it was busy in, the typical (median) gap between them, and
    the period when the gaps are regular (:func:`argus.context.beacon.cadence`)."""
    try:
        start, end = _moment(params["start"]), _moment(params["end"])
    except (KeyError, ValueError, TypeError):
        return ()
    step = beacon.interval(start, end)
    width = int(step.total_seconds() * 1000)
    buckets = _val(aggs, "beats", "buckets")
    keys = sorted(
        {
            k
            for b in (buckets if isinstance(buckets, list) else [])
            if (k := _int(_val(b, "key"))) is not None and (_int(_val(b, "doc_count")) or 0) > 0
        }
    )
    if not keys or width <= 0:
        return ()
    out = [Detail(f"busy in {plural(len(keys), 'period')} of {_minutes(step)}")]
    gaps = [b - a for a, b in itertools.pairwise(keys)]
    if gaps:
        typical = timedelta(milliseconds=statistics.median_low(gaps))
        out.append(Detail(f"typical gap between busy periods: {_minutes(typical)}"))
    got = beacon.cadence(aggs, start, end)
    if got.period is not None and got.jitter is not None:
        out.append(Detail(f"regular: about every {_minutes(got.period)}"
                          f" (\u00b1 {_minutes(got.jitter)})"))  # fmt: skip
    return tuple(out)


def shown(template: str, params: Mapping[str, Any], snapshot: Any) -> Shown | None:
    """The deciding values a stored answer holds beyond its sentence, at most :data:`DETAILS`,
    each read from the stored answer and nothing else (None: none to show)."""
    if not isinstance(snapshot, Mapping):
        return None
    try:
        if template == "proxy.destination":
            found = _urls(_aggs(snapshot))
        elif template == "logs.source_events":
            found = _patterns(snapshot, params)
        elif template == "proxy.pair":
            found = _rhythm(params, _aggs(snapshot))
        else:
            return None
    except Exception:  # a damaged stored answer: the line keeps its sentence alone
        return None
    return Shown(SHOWS[template], found) if found else None


def query_for(
    cfg: discover.Config, template: str, version: int, params: Mapping[str, Any], at: datetime
) -> ReportQuery | None:
    return discover.for_template(cfg, template, version, params, at)


def sort_key(said: Said) -> tuple[int, int]:
    """Informative first: a check that counted something before one that found nothing."""
    return (0 if said.count else 1, -(said.count or 0))
