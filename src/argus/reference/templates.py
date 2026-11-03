"""The threat-intel templates (plan §5.3, D-057, D-293). Only exact lookups and bounded reads: no
aggregation, no scroll over a source of millions of rows. Each takes the source's index and
schema (``site.ti_sources``); the gateway refuses an index the site does not name."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated, Any, Literal

from pydantic import Field, SerializerFunctionWrapHandler, model_serializer

from argus import site
from argus.gateway.templates import (
    CostClass,
    Endpoint,
    Family,
    Params,
    RequestPlan,
    Template,
    register,
)
from argus.reference.ti import guess_kind

ECS_FIELDS = frozenset(
    {
        "@timestamp",
        "threat.indicator.type",
        "threat.indicator.ip",
        "threat.indicator.domain",
        "threat.indicator.url.full",
        "threat.indicator.url.original",
        "threat.indicator.url.domain",
        "threat.indicator.file.hash.sha256",
        "threat.indicator.file.hash.sha1",
        "threat.indicator.file.hash.md5",
        "threat.indicator.email.address",
        "threat.indicator.name",
        "threat.indicator.first_seen",
        "threat.indicator.last_seen",
        "threat.indicator.confidence",
        "threat.indicator.description",
        "threat.feed.name",
    }
)
IOC_FIELDS = frozenset(
    {
        "@timestamp",
        "ioc_type",
        "ioc_value",
        "intel_source",
        "first_seen",
        "last_seen",
        "confidence",
    }
)
MIRROR_SIZE = 1000  # a mirrored source is small (~500 documents): one page, its total checked
LOOKUP_VALUES = 200  # terms (values and their spellings): the validator's limit
LOOKUP_SIZE = 500  # rows per lookup: a value may have several (sources, types)


_INDEX = r"^[a-z0-9][a-z0-9._+*-]{0,254}$"


def _legacy_mirror(index: str | None, shape: str) -> tuple[str, str]:
    """(index, shape) of a mirror read: what its parameters say, or the site's first mirror."""
    if index is not None:
        return index, shape
    found = next(iter(site.active().ti_mirrors), None)
    if found is None:
        raise ValueError("the request names no threat-intel index and the site has no mirror")
    return found.index, found.schema_


class MirrorParams(Params):
    """One mirror source (``index`` and its ``shape``); none named means the site's first."""

    size: int = Field(default=MIRROR_SIZE, ge=1, le=MIRROR_SIZE)
    index: str | None = Field(default=None, pattern=_INDEX)
    shape: Literal["ecs", "ioc"] = "ecs"

    @model_serializer(mode="wrap")
    def _dump(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        data: dict[str, Any] = handler(self)
        if data.get("index") is None:
            data.pop("index", None)
        if data.get("shape") == "ecs":
            data.pop("shape", None)
        return data


@register
class TiMirrorPage(Template):
    """All of a mirrored source in one bounded read, with the exact total to prove it was all."""

    name = "ti.page"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.TI
    cost = CostClass.MEDIUM
    params_model = MirrorParams
    return_fields = ECS_FIELDS | IOC_FIELDS
    sort_fields = frozenset({"@timestamp"})
    max_size = MIRROR_SIZE

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, MirrorParams)
        index, shape = _legacy_mirror(params.index, params.shape)
        body: dict[str, Any] = {
            "size": params.size,
            "track_total_hits": True,
            "_source": sorted(ECS_FIELDS if shape == "ecs" else IOC_FIELDS),
            "query": {"match_all": {}},
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        }
        return RequestPlan(self.spec(), body=body, names=(index,))


def mirror_params(source: site.TiSource, size: int = MIRROR_SIZE) -> MirrorParams:
    """The parameters that read a mirror source whole (or its first ``size`` documents)."""
    return MirrorParams(index=source.index, shape=source.schema_, size=size)


class LookupParams(Params):
    """The values to look up and the sources to look in: ``indices`` (one request may ask
    several) of schema ``shape`` (``both``: some of each). A stored request from before sources
    were settings names none, with shape ``ioc``: it meant the site's first ``ioc`` lookup
    source, and the two are left out of its dump when they are those defaults, so such a
    request keeps its content address (``plan_key``) and still loads."""

    values: tuple[str, ...] = Field(min_length=1, max_length=LOOKUP_VALUES)
    size: int = Field(default=LOOKUP_SIZE, ge=1, le=LOOKUP_SIZE)
    indices: tuple[Annotated[str, Field(pattern=_INDEX)], ...] = Field(default=(), max_length=8)
    shape: Literal["ecs", "ioc", "both"] = "ioc"

    @model_serializer(mode="wrap")
    def _dump(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        data: dict[str, Any] = handler(self)
        if not data.get("indices"):
            data.pop("indices", None)
        if data.get("shape") == "ioc":
            data.pop("shape", None)
        return data


def lookup_params(
    sources: Sequence[site.TiSource], values: tuple[str, ...], size: int = LOOKUP_SIZE
) -> LookupParams:
    """The parameters that look ``values`` up in lookup ``sources``, one request for all of
    them. The site's default (its first ``ioc`` source, alone) is left unnamed, as every stored
    request of it is."""
    if list(sources) == [site.active().ti_default_lookup]:
        return LookupParams(values=values, size=size)
    shapes = {s.schema_ for s in sources}
    shape = "both" if len(shapes) > 1 else next(iter(shapes))
    return LookupParams(
        indices=tuple(s.index for s in sources), shape=shape, values=values, size=size
    )


# The ECS fields each kind of value is looked up in. An address field is typed ``ip``: it takes
# addresses only (anything else is a parse error), so a domain is never sent to it.
_ECS_LOOKUP_FIELDS = {
    "ip": ("threat.indicator.ip", "threat.indicator.url.domain"),
    "domain": ("threat.indicator.url.domain",),
    "url": ("threat.indicator.url.full", "threat.indicator.url.original"),
    "hash": (
        "threat.indicator.file.hash.sha256",
        "threat.indicator.file.hash.sha1",
        "threat.indicator.file.hash.md5",
    ),
    "email": ("threat.indicator.email.address",),
}
ECS_LOOKUP_FIELDS = frozenset(f for fields in _ECS_LOOKUP_FIELDS.values() for f in fields)


def ecs_terms(values: tuple[str, ...]) -> dict[str, list[str]]:
    """The values by the ECS field they are asked in (each kind to its fields); a value that is
    no IP, domain, URL, hash or email address is not asked."""
    found: dict[str, list[str]] = {}
    for value in values:
        kind = guess_kind(value)
        for field in _ECS_LOOKUP_FIELDS.get(kind or "", ()):
            if value not in found.setdefault(field, []):
                found[field].append(value)
    return found


@register
class TiLookup(Template):
    """Rows of the looked-up sources whose value is one of up to 200 exact values (spellings
    included). An ``ioc`` source is asked on ``ioc_value.keyword``; an ``ecs`` one on the
    ``threat.indicator`` field of each value's kind."""

    name = "ti.lookup"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.TI
    cost = CostClass.LIGHT
    params_model = LookupParams
    filter_fields = frozenset({"ioc_value.keyword"}) | ECS_LOOKUP_FIELDS
    return_fields = IOC_FIELDS | ECS_FIELDS
    max_size = LOOKUP_SIZE

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, LookupParams)
        names = params.indices
        if not names:
            default = site.active().ti_default_lookup
            if default is None:
                raise ValueError("the request names no threat-intel index and the site has none")
            names = (default.index,)
        should: list[dict[str, Any]] = []
        fields: frozenset[str] = frozenset()
        if params.shape in ("ioc", "both"):
            should.append({"terms": {"ioc_value.keyword": list(params.values)}})
            fields |= IOC_FIELDS
        if params.shape in ("ecs", "both"):
            asked = ecs_terms(params.values)
            should += [{"terms": {field: values}} for field, values in sorted(asked.items())]
            fields |= ECS_FIELDS
            if not asked and params.shape == "ecs":
                raise ValueError("none of the values is an IP, domain, URL, hash or email address")
        query = {"bool": {"filter": [{"bool": {"should": should, "minimum_should_match": 1}}]}}
        if params.shape == "ioc":  # the form every stored request has
            query = {"bool": {"filter": [should[0]]}}
        body = {
            "size": params.size,
            "track_total_hits": True,
            "_source": sorted(fields),
            "query": query,
        }
        return RequestPlan(self.spec(), body=body, names=names)


class NewestParams(Params):
    index: str = Field(pattern=r"^[a-z0-9][a-z0-9._+*-]{0,254}$")


@register
class TiNewest(Template):
    """The newest document of a threat-intel source: how fresh the source is (and one known
    indicator, which the live check looks up again)."""

    name = "ti.newest"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.TI
    cost = CostClass.LIGHT
    params_model = NewestParams
    return_fields = ECS_FIELDS | IOC_FIELDS
    sort_fields = frozenset({"@timestamp"})
    max_size = 1

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, NewestParams)
        body = {
            "size": 1,
            "track_total_hits": False,
            "_source": sorted(ECS_FIELDS | IOC_FIELDS),
            "query": {"match_all": {}},
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        }
        return RequestPlan(self.spec(), body=body, names=(params.index,))
