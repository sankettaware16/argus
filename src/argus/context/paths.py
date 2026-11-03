"""``web.path_outcomes`` (Q-F4, plan §5 WS-F, §7.3): did an attacked path succeed? For one
client, one hosted site and up to 10 of the paths the alerts show it tried, what nginx
answered: the statuses per path, and for each path the sizes of its successful (2xx) answers.

A site that answers every path with the same page (a catch-all: many single-page apps do)
returns 200 for ``/.env`` too, so a 2xx alone is not a success. A path counts as having
succeeded only when one of its 2xx answers differs in size from the 2xx answers of the other
paths tried; a 2xx shared by two or more of them is most likely the site's catch-all. Paths
nginx serves as one file (``/.env``, ``//.env``, ``/%2eenv``) count as one path there, so one
real file asked for under two spellings is never taken for a catch-all. With nothing else
answered to compare with, or without answer sizes, a 2xx is only a possible success.

An aggregation on nginx's logs, so heavy: one daily index, a 10 s timeout, at most 120
buckets, an answer within the 16 KiB snapshot. The client, the site and the paths bound the
work; the prevalence gate refuses the paths every site serves (``/``, ``/favicon.ico`` ...).
Field names are the captured nginx mapping's: ``url.path`` is ``keyword``, ``url.domain`` is
text with ``url.domain.keyword`` (``ignore_above`` 256), ``http.response.status_code`` is
``integer``, ``http.response.body.bytes`` is ``long``. A path longer than 256 characters is not
asked about (ARGUS's own bound, for the snapshot): its outcome cannot be told.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import unquote

from pydantic import Field, field_validator, model_validator

from argus.context.bounds import address, check_window, iso, keyword_chars, utf16_len
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
from argus.site import Fields, Role, all_fields, fields_for, source_for

LONGEST = timedelta(hours=6)
MAX_PATHS = 10
PATH_CHARS = 256  # the captured mapping's ignore_above; a family says its own (path_chars)
STATUSES = 5
SIZES = 5
TIMEOUT = timedelta(seconds=10)
# Paths every site serves: a query on them reads a site's whole traffic (plan §7.3).
COMMON_PATHS = frozenset(
    {"/", "/index.html", "/index.php", "/favicon.ico", "/robots.txt", "/sitemap.xml"}
)


def path_chars(source: str | None = None) -> int:
    """The longest ``url.path`` the web family ``source`` (default: the site's first) indexes: its
    ``ignore_above``. A longer path is not in the index, so no query can find it."""
    return keyword_chars(source or source_for(Role.WEB))


def _text(value: str, limit: int, what: str) -> str:
    if not value or utf16_len(value) > limit:
        raise ValueError(f"a {what} is 1 to {limit} characters")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise ValueError(f"a {what} has no control characters")
    return value


class PathParams(SourcedParams):
    ROLE = Role.WEB
    ip: str = Field(min_length=2, max_length=45)
    site: str
    paths: tuple[str, ...] = Field(min_length=1, max_length=MAX_PATHS)
    start: datetime
    end: datetime

    @field_validator("ip")
    @classmethod
    def _address(cls, value: str) -> str:
        return address(value)

    @model_validator(mode="after")
    def _window(self) -> PathParams:
        check_window(self.start, self.end, LONGEST, one_index=True)
        limit = path_chars(self.source)  # the limit of the family the request reads
        _text(self.site, limit, "site")
        paths = tuple(sorted({_text(v, limit, "path") for v in self.paths}))
        if paths != self.paths:  # the sorted, de-duplicated paths replace what was given
            object.__setattr__(self, "paths", paths)
        return self


def _ok_path(f: Fields, path: str) -> dict[str, Any]:
    return {
        "bool": {
            "filter": [
                {"term": {f("url_path"): path}},
                {"range": {f("status_code"): {"gte": 200, "lt": 300}}},
            ]
        }
    }


@register
class WebPathOutcomes(Template):
    """A client's answers from one site for the paths it tried: statuses per path, and the
    sizes of each path's 2xx answers."""

    name = "web.path_outcomes"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.LOG
    cost = CostClass.HEAVY
    params_model = PathParams
    timeout = TIMEOUT

    @classmethod
    def spec(cls) -> Spec:
        fs = all_fields(Role.WEB)
        return replace(
            super().spec(),
            filter_fields=frozenset(
                n
                for f in fs
                for n in (f("client_ip"), f("domain"), f("url_path"), f("status_code"), f.time)
            ),
            aggregate_fields=frozenset(
                n for f in fs for n in (f("url_path"), f("status_code"), f("bytes"), f.time)
            ),
        )

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, PathParams)
        f = fields_for(Role.WEB, params.source)
        aggs: dict[str, Any] = {
            "requests": {"value_count": {"field": f.time}},
            "answered": {"value_count": {"field": f("status_code")}},
            "paths": {
                "terms": {"field": f("url_path"), "size": len(params.paths)},
                "aggs": {"statuses": {"terms": {"field": f("status_code"), "size": STATUSES}}},
            },
        }
        for i, path in enumerate(params.paths):
            aggs[f"ok_{i}"] = {
                "filter": _ok_path(f, path),
                "aggs": {"sizes": {"terms": {"field": f("bytes"), "size": SIZES}}},
            }
        body = {
            "size": 0,
            "track_total_hits": False,
            "query": {
                "bool": {
                    "filter": [
                        {"term": {f("client_ip"): params.ip}},
                        {"term": {f("domain"): params.site}},
                        {"terms": {f("url_path"): list(params.paths)}},
                        {"range": {f.time: {"gte": iso(params.start), "lt": iso(params.end)}}},
                    ]
                }
            },
            "aggs": aggs,
        }
        return RequestPlan(
            self.spec(),
            body=body,
            window=Window(params.source or source_for(Role.WEB), params.start, params.end),
        )


# ----------------------------------------------------------------------------- reading

SUCCESS = "success"  # a 2xx answer unlike the other paths' 2xx answers
CATCH_ALL = "catch_all"  # 2xx, but the same answer as another path tried
POSSIBLE = "possible"  # 2xx that cannot be compared (one path, no sizes, too many sizes)
REFUSED = "refused"  # answered, never with a 2xx
UNKNOWN = "unknown"  # no logged answer


@dataclass(frozen=True)
class PathOutcome:
    path: str
    outcome: str
    requests: int
    statuses: dict[int, int]  # the most frequent statuses (at most 5)
    ok: int  # 2xx answers
    ok_sizes: dict[int, int]  # sizes of the 2xx answers (at most 5)


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _buckets(node: Any) -> list[Mapping[str, Any]]:
    found = (node or {}).get("buckets") if isinstance(node, Mapping) else None
    return [b for b in found or [] if isinstance(b, Mapping)]


def _node(parent: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    found = parent.get(name)
    return found if isinstance(found, Mapping) else {}


def same_file(path: str) -> str:
    """The path nginx serves for ``path``: percent-escapes decoded, slashes merged, dot
    segments resolved (``//.env``, ``/%2eenv`` and ``/a/../.env`` are all ``/.env``)."""
    decoded = unquote(path, errors="replace")
    parts: list[str] = []
    for segment in decoded.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if parts:
                parts.pop()
            continue
        parts.append(segment)
    trailing = "/" if parts and decoded.endswith("/") else ""
    return "/" + "/".join(parts) + trailing


def outcomes(aggs: Mapping[str, Any] | None, paths: Sequence[str]) -> list[PathOutcome]:
    """Each asked path's outcome, in the order of ``paths`` (the parameters' sorted order,
    which numbers the ``ok_<i>`` aggregations)."""
    a = aggs or {}
    by_path = {b.get("key"): b for b in _buckets(a.get("paths"))}
    rows = []
    for i, path in enumerate(paths):
        bucket = by_path.get(path) or {}
        statuses = {
            k: _int(b.get("doc_count")) or 0
            for b in _buckets(bucket.get("statuses"))
            if (k := _int(b.get("key"))) is not None
        }
        ok_node = _node(a, f"ok_{i}")
        sizes_node = _node(ok_node, "sizes")
        sizes = {
            k: _int(b.get("doc_count")) or 0
            for b in _buckets(sizes_node)
            if (k := _int(b.get("key"))) is not None
        }
        more_sizes = (_int(sizes_node.get("sum_other_doc_count")) or 0) > 0
        requests = _int(bucket.get("doc_count")) or 0
        ok = _int(ok_node.get("doc_count")) or 0
        rows.append((path, requests, statuses, ok, sizes, more_sizes))
    # Sizes compare between files, not spellings: one file under two spellings is one path.
    file_of = {path: same_file(path) for path in paths}
    seen: dict[int, set[str]] = {}
    for path, _, _, ok, sizes, _ in rows:
        for size in sizes if ok else ():
            seen.setdefault(size, set()).add(file_of[path])
    shared = {size for size, where in seen.items() if len(where) >= 2}
    answered = {file_of[path] for path, requests, *_ in rows if requests}
    out = []
    for path, requests, statuses, ok, sizes, more in rows:
        if ok:
            distinct = set(sizes) - shared
            compared = bool(answered - {file_of[path]})  # another file answered at all
            if not compared or not sizes or (more and not distinct):
                outcome = POSSIBLE
            else:
                outcome = SUCCESS if distinct else CATCH_ALL
        else:
            outcome = REFUSED if requests else UNKNOWN
        out.append(PathOutcome(path, outcome, requests, statuses, ok, sizes))
    return out


def read(
    version: int, params: PathParams, ref: Mapping[str, Any], snapshot: Mapping[str, Any]
) -> list[SignalValue]:
    """Counts of the paths by outcome. A zero is never "no success" from the logs alone
    (D-023); requests logged without a status make the counts lower bounds."""
    aggs = snapshot.get("aggregations")
    found = outcomes(aggs, params.paths)
    a = aggs if isinstance(aggs, Mapping) else {}
    requests = _int((a.get("requests") or {}).get("value"))
    answered = _int((a.get("answered") or {}).get("value"))
    refs = [ref]
    if requests is not None and answered is not None and requests > answered:
        unanswered = requests - answered
        refs = [{**ref, "coverage": {**(ref.get("coverage") or {}), "no_status": unanswered}}]
    counts = {
        kind: sum(o.outcome == kind for o in found) for kind in (SUCCESS, CATCH_ALL, POSSIBLE)
    }
    return [
        from_logs(derived(f"web.paths_{kind}", version, refs, _const(n), counts=True))
        for kind, n in counts.items()
    ]


def _const(value: Any) -> Any:
    return lambda: value


def answers(derived_: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    """A sentence for the note's step about the outcome. Never a path: paths are the
    attacker's text (Observations show them, quoted). A lower bound says "at least"."""
    known = Known(derived_)
    by = known.by

    def paths_(name: str) -> str:
        return known.count(name, "attacked path", "attacked paths")

    parts = []
    if by.get("web.paths_success"):
        parts.append(f"{paths_('web.paths_success')} got a successful answer unlike the"
                     " others")  # fmt: skip
    if by.get("web.paths_catch_all"):
        parts.append(f"{paths_('web.paths_catch_all')} got the same 2xx answer as other"
                     " paths tried (most likely the site's catch-all page, so not shown to"
                     " succeed)")  # fmt: skip
    if by.get("web.paths_possible"):
        parts.append(f"{paths_('web.paths_possible')} got a 2xx answer ARGUS cannot compare")
    if not parts:
        return {}
    return {"log_pivot": "nginx logs: " + "; ".join(parts) + "."}
