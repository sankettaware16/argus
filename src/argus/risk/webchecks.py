"""The checking lane's web templates (P4-F E3): three aggregations on the web servers' logs,
each one daily index, a 10 s timeout and a bounded answer. With ``web.path_outcomes`` (batch 1)
they tell whether an inbound attack on an own site got something.

- ``web.source_sites``: for up to 50 outside addresses, which own sites they reached, and
  which of them and which sites had a successful (2xx) answer at all (the site of a thin
  inbound alert, which names only the source);
- ``web.catchall``: the **soft-404 check**: one site's 2xx answers to the probe paths, by body
  size, beside the body sizes of its normal not-found answers, of its home page and of its
  other 2xx answers. A site that answers every path with its error or home page gives about one
  size (within a few bytes: a nonce or a timestamp under gzip; or one size plus the path's
  length, when the page echoes the path) to different files, or about the size of a page it
  serves for anything. Two backup copies of one file (``/.env`` and ``/.env.bak``) may really be
  the same size, so they alone never make a size the catch-all page. One file alone is compared
  with nothing: it is never served;
- ``web.bulk_take``: what one outside address took from one site: how many distinct paths and
  body sizes got a 2xx, and its most frequent paths (their shared sensitive prefix).

Nothing here sends anything: the gateway does, on the checking lane (``risk.checking``). The
readers turn an answer into facts; no value from the logs is ever printed by them.
"""

from __future__ import annotations

from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any

from pydantic import Field, field_validator, model_validator

from argus.context.bounds import address, check_window, iso, utf16_len
from argus.context.paths import path_chars, same_file
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

DAY = timedelta(hours=22)  # one daily index holds 01:00 to 22:59 UTC
SITE_WINDOW = timedelta(hours=6)  # a site's whole traffic: the hours around the probes
MAX_SOURCES = 50
MAX_PROBES = 20
SITES_PER_SOURCE = 8
OK_SITES = 50
SIZES = 5
TOP_PATHS = 25
TIMEOUT = timedelta(seconds=10)
# Two body sizes are one page within a few bytes (a nonce, a timestamp or a session token under
# gzip), or 2 % of a larger page, at most 1 KiB (two real files of megabytes stay two files).
BAND_BYTES = 16
BAND_SHARE = 0.02
BAND_MAX = 1_024
# A backup copy of a file (``/.env.bak``, ``/.env~``): it may really be the same size.
COPY_SUFFIXES = ("~", ".bak", ".backup", ".old", ".orig", ".save", ".copy", ".tmp", ".1")
# The first production run's limit, in server time (over it, the template stays off).
FIRST_RUN_MS = {"web.source_sites": 5_000, "web.catchall": 3_000, "web.bulk_take": 3_000}


def _text(value: str, limit: int, what: str) -> str:
    if not value or utf16_len(value) > limit:
        raise ValueError(f"a {what} is 1 to {limit} characters")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise ValueError(f"a {what} has no control characters")
    return value


def _ok(status: str) -> dict[str, Any]:
    return {"range": {status: {"gte": 200, "lt": 300}}}


def _window(params: Any) -> Window:
    return Window(params.source or source_for(Role.WEB), params.start, params.end)


class SitesParams(SourcedParams):
    ROLE = Role.WEB
    ips: tuple[str, ...] = Field(min_length=1, max_length=MAX_SOURCES)
    start: datetime
    end: datetime

    @field_validator("ips")
    @classmethod
    def _addresses(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({address(v) for v in value}))

    @model_validator(mode="after")
    def _span(self) -> SitesParams:
        check_window(self.start, self.end, DAY, one_index=True)
        return self


@register
class WebSourceSites(Template):
    """Which own sites some outside addresses reached, and where they got a 2xx."""

    name = "web.source_sites"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.LOG
    cost = CostClass.HEAVY
    params_model = SitesParams
    timeout = TIMEOUT

    @classmethod
    def spec(cls) -> Spec:
        fs = all_fields(Role.WEB)
        return replace(
            super().spec(),
            filter_fields=frozenset(
                n for f in fs for n in (f("client_ip"), f("status_code"), f.time)
            ),
            aggregate_fields=frozenset(n for f in fs for n in (f("client_ip"), f("domain"))),
        )

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, SitesParams)
        f = fields_for(Role.WEB, params.source)
        n = len(params.ips)
        body = {
            "size": 0,
            "track_total_hits": False,
            "query": {
                "bool": {
                    "filter": [
                        {"terms": {f("client_ip"): list(params.ips)}},
                        {"range": {f.time: {"gte": iso(params.start), "lt": iso(params.end)}}},
                    ]
                }
            },
            "aggs": {
                "sources": {
                    "terms": {"field": f("client_ip"), "size": n},
                    "aggs": {"sites": {"terms": {"field": f("domain"), "size": SITES_PER_SOURCE}}},
                },
                "ok_sources": {
                    "filter": _ok(f("status_code")),
                    "aggs": {"sources": {"terms": {"field": f("client_ip"), "size": n}}},
                },
                "ok_sites": {
                    "filter": _ok(f("status_code")),
                    "aggs": {"sites": {"terms": {"field": f("domain"), "size": OK_SITES}}},
                },
            },
        }
        return RequestPlan(self.spec(), body=body, window=_window(params))


class CatchallParams(SourcedParams):
    ROLE = Role.WEB
    site: str
    paths: tuple[str, ...] = Field(min_length=1, max_length=MAX_PROBES)
    start: datetime
    end: datetime

    @model_validator(mode="after")
    def _checked(self) -> CatchallParams:
        check_window(self.start, self.end, SITE_WINDOW, one_index=True)
        limit = path_chars(self.source)
        _text(self.site, limit, "site")
        paths = tuple(sorted({_text(v, limit, "path") for v in self.paths}))
        if paths != self.paths:
            object.__setattr__(self, "paths", paths)
        return self


@register
class WebCatchall(Template):
    """The soft-404 check: one site's 2xx answers to the probe paths by body size, and the
    body sizes of its not-found answers."""

    name = "web.catchall"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.LOG
    cost = CostClass.HEAVY
    params_model = CatchallParams
    timeout = TIMEOUT

    @classmethod
    def spec(cls) -> Spec:
        fs = all_fields(Role.WEB)
        return replace(
            super().spec(),
            filter_fields=frozenset(
                n for f in fs for n in (f("domain"), f("url_path"), f("status_code"), f.time)
            ),
            aggregate_fields=frozenset(n for f in fs for n in (f("bytes"), f.time)),
        )

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, CatchallParams)
        f = fields_for(Role.WEB, params.source)
        sizes = {"sizes": {"terms": {"field": f("bytes"), "size": SIZES}}}
        aggs: dict[str, Any] = {
            "requests": {"value_count": {"field": f.time}},
            "not_found": {"filter": {"term": {f("status_code"): 404}}, "aggs": sizes},
            "home": {
                "filter": {"bool": {"filter": [{"term": {f("url_path"): "/"}},
                                               _ok(f("status_code"))]}},
                "aggs": sizes,
            },
            "others": {
                "filter": {"bool": {"filter": [_ok(f("status_code"))],
                                    "must_not": [{"terms": {f("url_path"): list(params.paths)}}]}},
                "aggs": sizes,
            },
        }  # fmt: skip
        for i, path in enumerate(params.paths):
            aggs[f"ok_{i}"] = {
                "filter": {"bool": {"filter": [{"term": {f("url_path"): path}},
                                               _ok(f("status_code"))]}},
                "aggs": {"sizes": {"terms": {"field": f("bytes"), "size": SIZES}}},
            }  # fmt: skip
        body = {
            "size": 0,
            "track_total_hits": False,
            "query": {
                "bool": {
                    "filter": [
                        {"term": {f("domain"): params.site}},
                        {"range": {f.time: {"gte": iso(params.start), "lt": iso(params.end)}}},
                    ]
                }
            },
            "aggs": aggs,
        }
        return RequestPlan(self.spec(), body=body, window=_window(params))


class TakeParams(SourcedParams):
    ROLE = Role.WEB
    ip: str = Field(min_length=2, max_length=45)
    site: str
    start: datetime
    end: datetime

    @field_validator("ip")
    @classmethod
    def _address(cls, value: str) -> str:
        return address(value)

    @model_validator(mode="after")
    def _checked(self) -> TakeParams:
        check_window(self.start, self.end, DAY, one_index=True)
        _text(self.site, path_chars(self.source), "site")
        return self


@register
class WebBulkTake(Template):
    """What one outside address took from one site: distinct 2xx paths and body sizes, the
    bytes, and its most frequent 2xx paths."""

    name = "web.bulk_take"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.LOG
    cost = CostClass.HEAVY
    params_model = TakeParams
    timeout = TIMEOUT

    @classmethod
    def spec(cls) -> Spec:
        fs = all_fields(Role.WEB)
        return replace(
            super().spec(),
            filter_fields=frozenset(
                n for f in fs for n in (f("client_ip"), f("domain"), f("status_code"), f.time)
            ),
            aggregate_fields=frozenset(n for f in fs for n in (f("url_path"), f("bytes"))),
        )

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, TakeParams)
        f = fields_for(Role.WEB, params.source)
        body = {
            "size": 0,
            "track_total_hits": False,
            "query": {
                "bool": {
                    "filter": [
                        {"term": {f("client_ip"): params.ip}},
                        {"term": {f("domain"): params.site}},
                        _ok(f("status_code")),
                        {"range": {f.time: {"gte": iso(params.start), "lt": iso(params.end)}}},
                    ]
                }
            },
            "aggs": {
                "paths": {"cardinality": {"field": f("url_path"), "precision_threshold": 1000}},
                "sizes": {"cardinality": {"field": f("bytes"), "precision_threshold": 1000}},
                "bytes": {"sum": {"field": f("bytes")}},
                "top": {"terms": {"field": f("url_path"), "size": TOP_PATHS}},
            },
        }
        return RequestPlan(self.spec(), body=body, window=_window(params))


TEMPLATES: dict[str, type[Template]] = {
    WebSourceSites.name: WebSourceSites,
    WebCatchall.name: WebCatchall,
    WebBulkTake.name: WebBulkTake,
}


# ----------------------------------------------------------------------------- reading


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _buckets(node: Any) -> list[Mapping[str, Any]]:
    found = node.get("buckets") if isinstance(node, Mapping) else None
    return [b for b in found or [] if isinstance(b, Mapping)]


def _node(parent: Any, name: str) -> Mapping[str, Any]:
    found = parent.get(name) if isinstance(parent, Mapping) else None
    return found if isinstance(found, Mapping) else {}


def _aggs(body: Any) -> Mapping[str, Any]:
    return _node(body, "aggregations")


def _sizes(node: Mapping[str, Any]) -> dict[int, int]:
    return {k: _int(b.get("doc_count")) or 0 for b in _buckets(_node(node, "sizes"))
            if (k := _int(b.get("key"))) is not None}  # fmt: skip


@dataclass(frozen=True)
class SiteHit:
    site: str
    requests: int
    ok: bool | None  # a 2xx between this source and this site is possible (None: cannot tell)


def read_sites(body: Any, ips: Sequence[str]) -> dict[str, list[SiteHit]]:
    """Each asked address's own sites (most requests first). ``ok`` is False when the address
    got no 2xx anywhere or the site gave none to any asked address; True when both did (a 2xx
    between them is then likely, and the checks tell); None when the sites that gave a 2xx were
    more than the answer lists."""
    aggs = _aggs(body)
    ok_sources = {str(b.get("key")) for b in _buckets(_node(_node(aggs, "ok_sources"), "sources"))}
    ok_node = _node(_node(aggs, "ok_sites"), "sites")
    ok_sites = {str(b.get("key")).lower() for b in _buckets(ok_node)}
    more = (_int(ok_node.get("sum_other_doc_count")) or 0) > 0
    out: dict[str, list[SiteHit]] = {ip: [] for ip in ips}
    for bucket in _buckets(_node(aggs, "sources")):
        ip = str(bucket.get("key"))
        if ip not in out:
            continue
        for b in _buckets(_node(bucket, "sites")):
            site = b.get("key")
            if not isinstance(site, str) or not site.strip():
                continue
            site = site.strip().lower()
            ok: bool | None
            if ip not in ok_sources:
                ok = False
            elif site in ok_sites:
                ok = True
            else:
                ok = None if more else False
            out[ip].append(SiteHit(site, _int(b.get("doc_count")) or 0, ok))
    return out


def near(a: int, b: int) -> bool:
    """Whether two body sizes may be one page (see ``BAND_BYTES``)."""
    return abs(a - b) <= max(BAND_BYTES, min(BAND_SHARE * max(a, b), BAND_MAX))


def stem(path: str) -> str:
    """The file ``path`` is a backup copy of (``/.env.bak``, ``/.env~`` -> ``/.env``), or the
    file itself."""
    found = same_file(path).lower()
    changed = True
    while changed:
        changed = False
        for suffix in COPY_SUFFIXES:
            base = found[: -len(suffix)]
            if found.endswith(suffix) and base.rsplit("/", 1)[-1] not in ("", "."):
                found, changed = base, True
                break
    return found


def one_page(path: str, size: int, other: str, other_size: int) -> bool:
    """Whether two 2xx answers of different files (not copies of one file) are one page: about
    the same size, or about the same size less the path each echoed."""
    return stem(path) != stem(other) and (
        near(size, other_size) or near(size - len(path), other_size - len(other))
    )


def _pairs(answered: Mapping[str, Mapping[int, int]]) -> list[tuple[str, int]]:
    return [(p, s) for p, sizes in answered.items() for s in sizes]


@dataclass(frozen=True)
class Catchall:
    """The soft-404 check's facts for one site."""

    requests: int
    answered: dict[str, dict[int, int]]  # probe path -> its 2xx answers' body sizes
    not_found: dict[int, int]  # body sizes of the site's 404 answers
    catch: tuple[tuple[str, int], ...]  # (path, size) pairs that are the catch-all page
    served: tuple[str, ...]  # probe paths with a 2xx unlike the catch-all and the not-found page
    pages: dict[int, int] = field(default_factory=dict)  # its home page's and commonest 2xx sizes

    @property
    def soft_404(self) -> bool:
        return bool(self.catch)

    @property
    def verdict(self) -> str:
        if not self.requests:
            return "unknown"
        return "soft_404" if self.soft_404 else "plain"

    @property
    def files(self) -> frozenset[str]:
        """The probe files that got a 2xx (two or more: the check compared them)."""
        return frozenset(same_file(p) for p in self.answered)

    def sizes(self) -> frozenset[int]:
        """The catch-all page's sizes (and the not-found, home and commonest pages')."""
        return frozenset({s for _, s in self.catch} | set(self.not_found) | set(self.pages))

    def echoes(self) -> frozenset[int]:
        """The catch-all page's size less the path it echoed, for each pair seen."""
        return frozenset(s - len(p) for p, s in self.catch)

    def is_catch_all(self, path: str, size: int, others: Iterable[tuple[str, int]] = ()) -> bool:
        """Whether a 2xx of ``size`` bytes for ``path`` is the site's catch-all page: about a
        size the check found to be one (or one of its pages' sizes), that page less the path it
        echoed, or one page with what another file got here or in ``others`` (other checks'
        2xx answers of the site)."""
        if any(near(size, s) for s in self.sizes()):
            return True
        if any(near(size - len(path), e) for e in self.echoes()):
            return True
        return any(one_page(path, size, q, t) for q, t in [*_pairs(self.answered), *others])


def catch_pairs(answered: Mapping[str, Mapping[int, int]],
                not_found: Collection[int]) -> set[tuple[str, int]]:  # fmt: skip
    """The (path, size) 2xx answers that are a site's catch-all page: one page with what another
    file got (``one_page``), or about the size of a page the site serves anyway (``not_found``:
    its not-found, home and commonest pages)."""
    found = _pairs(answered)
    return {(p, s) for p, s in found
            if any(near(s, page) for page in not_found)
            or any(one_page(p, s, q, t) for q, t in found)}  # fmt: skip


def read_catchall(body: Any, paths: Sequence[str], min_bytes: int) -> Catchall:
    """The soft-404 check's facts (``paths``: the parameters' sorted paths, which number the
    ``ok_<i>`` aggregations). A path is served when it got a 2xx of at least ``min_bytes``
    unlike the catch-all page, and another file got a 2xx to compare it with."""
    aggs = _aggs(body)
    requests = _int(_node(aggs, "requests").get("value")) or 0
    answered = {}
    for i, path in enumerate(paths):
        sizes = _sizes(_node(aggs, f"ok_{i}"))
        if sizes:
            answered[path] = sizes
    not_found = _sizes(_node(aggs, "not_found"))
    pages = {**_sizes(_node(aggs, "others")), **_sizes(_node(aggs, "home"))}
    catch = catch_pairs(answered, set(not_found) | set(pages))
    compared = len({same_file(p) for p in answered}) >= 2
    served = tuple(sorted(
        p for p, sizes in answered.items()
        if compared and any(s >= min_bytes and (p, s) not in catch for s in sizes)
    ))  # fmt: skip
    return Catchall(requests, answered, not_found, tuple(sorted(catch)), served, pages)


@dataclass(frozen=True)
class Take:
    """What one outside address took from one site."""

    paths: int  # distinct 2xx paths (approximate above a thousand)
    sizes: int  # distinct 2xx body sizes
    bytes: int
    top: tuple[tuple[str, int], ...]  # its most frequent 2xx paths


def read_take(body: Any) -> Take:
    aggs = _aggs(body)
    paths = _int(_node(aggs, "paths").get("value")) or 0
    sizes = _int(_node(aggs, "sizes").get("value")) or 0
    total = _node(aggs, "bytes").get("value")
    top = tuple((str(b.get("key")), _int(b.get("doc_count")) or 0)
                for b in _buckets(_node(aggs, "top")) if isinstance(b.get("key"), str))  # fmt: skip
    nbytes = int(total) if isinstance(total, int | float) and not isinstance(total, bool) else 0
    return Take(paths, sizes, nbytes, top)
