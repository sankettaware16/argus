"""The gateway's discovery templates (P4-D1, D-238): the few metadata reads ``argus discover``
makes to propose a ``site`` section from an Elastic ARGUS is not configured for yet.

They are reads of names and mappings, never of documents: which indices, aliases and data streams
exist (``discover.indices``, two fixed patterns), what a handful of well-known fields are mapped
as in one index (``discover.field_mapping``, the fields allowlisted below, at most
``MAX_FIELDS``), the ILM policies' delete ages (``discover.ilm``, only when the key holds
``read_ilm``: the privilege is asked first, because a 403 would stop ARGUS's access to the SIEM)
and that privilege check (``discover.privileges``). All are light, in the discovery family, sent
with the ``discover`` purpose (NORMAL health only, the collector's budget) and capped in the size
of what they keep: a cluster with thousands of indices is cut, and the cut is said.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import timedelta
from typing import Any, ClassVar, Literal

from pydantic import Field, field_validator

from argus.gateway.templates import (
    CostClass,
    Endpoint,
    Family,
    Params,
    RequestPlan,
    Template,
    register,
)
from argus.site import DISCOVERY_FIELDS

# What `discover.indices` may list: the visible indices, aliases and data streams (the log
# families), or the hidden Security alerts aliases (one for each space).
DISCOVERY_SCOPES: dict[str, str] = {"data": "*", "alerts": ".alerts-security.alerts-*"}
MAX_FIELDS = 80
MAX_NAMES = 5000  # indices, aliases, data streams kept from a listing
MAX_BACKING = 200  # backing indices kept for a data stream (the newest are last)
# One index a mapping may be asked of: a day's index, a data stream's `.ds-` backing index or an
# alias. A name that starts with another "." is a hidden or system index (`.security-7`).
INDEX = Field(pattern=r"^(?:\.ds-)?[a-z0-9][a-z0-9._+-]{0,250}$")


def _cap(items: Any, limit: int) -> tuple[list[Any], bool]:
    found = [i for i in items if isinstance(i, Mapping)] if isinstance(items, list) else []
    return found[:limit], len(found) > limit


class IndicesParams(Params):
    scope: Literal["data", "alerts"]


@register
class DiscoverIndices(Template):
    """The names of indices, aliases and data streams (no document, no count)."""

    name = "discover.indices"
    version = 1
    endpoint = Endpoint.DISCOVER_INDICES
    family = Family.DISCOVERY
    cost = CostClass.LIGHT
    params_model = IndicesParams
    url_param_names = frozenset({"filter_path", "expand_wildcards"})
    timeout = timedelta(seconds=20)
    FILTER: ClassVar[str] = (
        "indices.name,indices.data_stream,aliases.name,aliases.indices,"
        "data_streams.name,data_streams.timestamp_field,data_streams.backing_indices"
    )

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, IndicesParams)
        expand = "open,hidden" if params.scope == "alerts" else "open"
        url = (("expand_wildcards", expand), ("filter_path", self.FILTER))
        return RequestPlan(self.spec(), url_params=url, source=params.scope)

    def answer(self, params: Params, body: Any) -> Any:
        """The listing, cut to ``MAX_NAMES`` of each kind (``truncated`` says it was)."""
        if not isinstance(body, Mapping):
            return body
        out: dict[str, Any] = {}
        cut = False
        for key in ("indices", "aliases", "data_streams"):
            kept, more = _cap(body.get(key), MAX_NAMES)
            cut = cut or more
            if key == "data_streams":
                for stream in kept:
                    backing = stream.get("backing_indices")
                    if isinstance(backing, list) and len(backing) > MAX_BACKING:
                        stream["backing_indices"] = backing[-MAX_BACKING:]
                        cut = True
            out[key] = kept
        return {**out, "truncated": cut}


class MappingParams(Params):
    index: str = INDEX
    fields: tuple[str, ...] = Field(min_length=1, max_length=MAX_FIELDS)

    @field_validator("fields")
    @classmethod
    def _allowed(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        unknown = sorted(set(value) - DISCOVERY_FIELDS)
        if unknown or len(set(value)) != len(value):
            raise ValueError("fields are the discovery fields, each once")
        return tuple(sorted(value))


@register
class DiscoverFieldMapping(Template):
    """How well-known fields are mapped in one index (``text`` with a ``.keyword``, ``keyword``,
    ``ip`` ...); only the fields asked about, none that are not allowlisted."""

    name = "discover.field_mapping"
    version = 1
    endpoint = Endpoint.FIELD_MAPPING
    family = Family.DISCOVERY
    cost = CostClass.LIGHT
    params_model = MappingParams
    url_param_names = frozenset({"filter_path"})
    timeout = timedelta(seconds=15)

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, MappingParams)
        return RequestPlan(
            self.spec(),
            url_params=(("filter_path", "*.mappings.*.mapping"),),
            names=(params.index,),
            fields=params.fields,
        )

    @staticmethod
    def types(body: Any) -> dict[str, tuple[str, bool]]:
        """field -> (type, has a ``keyword`` sub-field) for each field the answer maps; a field
        mapped differently in two indices keeps the first."""
        found: dict[str, tuple[str, bool]] = {}
        for index in body.values() if isinstance(body, Mapping) else ():
            mappings = index.get("mappings") if isinstance(index, Mapping) else None
            for full_name, entry in (mappings if isinstance(mappings, Mapping) else {}).items():
                mapping = entry.get("mapping") if isinstance(entry, Mapping) else None
                leaf = next(iter(mapping.values()), None) if isinstance(mapping, Mapping) else None
                if not isinstance(leaf, Mapping) or not isinstance(leaf.get("type"), str):
                    continue
                sub = leaf.get("fields")
                keyword = isinstance(sub, Mapping) and (
                    isinstance(sub.get("keyword"), Mapping)
                    and sub["keyword"].get("type") == "keyword"
                )
                found.setdefault(str(full_name), (leaf["type"], keyword))
        return found

    @staticmethod
    def limits(body: Any) -> dict[str, int]:
        """field -> the longest value its keyword indexes (``ignore_above``), where the mapping
        says: a longer value is not in the index, so a query for it would find nothing."""
        return _limits(body)


def _limits(body: Any) -> dict[str, int]:
    """field -> the ``ignore_above`` of its keyword (the ``keyword`` sub-field of a text field, or
    the field itself when it is a keyword) for each field the answer maps and limits."""
    found: dict[str, int] = {}
    for index in body.values() if isinstance(body, Mapping) else ():
        mappings = index.get("mappings") if isinstance(index, Mapping) else None
        for full_name, entry in (mappings if isinstance(mappings, Mapping) else {}).items():
            mapping = entry.get("mapping") if isinstance(entry, Mapping) else None
            leaf = next(iter(mapping.values()), None) if isinstance(mapping, Mapping) else None
            if not isinstance(leaf, Mapping):
                continue
            sub = leaf.get("fields")
            sub = sub.get("keyword") if isinstance(sub, Mapping) else None
            keyword = (
                sub if isinstance(sub, Mapping) else (leaf if leaf.get("type") == "keyword" else {})
            )
            limit = keyword.get("ignore_above")
            if isinstance(limit, int) and not isinstance(limit, bool) and limit > 0:
                found.setdefault(str(full_name), limit)
    return found


@register
class DiscoverIlmPolicies(Template):
    """The ILM policies' delete age and what uses them (needs ``read_ilm``)."""

    name = "discover.ilm"
    version = 1
    endpoint = Endpoint.ILM_POLICIES
    family = Family.DISCOVERY
    cost = CostClass.LIGHT
    url_param_names = frozenset({"filter_path"})
    timeout = timedelta(seconds=15)
    FILTER: ClassVar[str] = (
        "*.policy.phases.delete.min_age,*.in_use_by.indices,*.in_use_by.data_streams"
    )

    def build(self, params: Params) -> RequestPlan:
        return RequestPlan(self.spec(), url_params=(("filter_path", self.FILTER),))

    def answer(self, params: Params, body: Any) -> Any:
        """Each policy's delete age and the data streams and indices using it (cut to
        ``MAX_NAMES`` names in all)."""
        if not isinstance(body, Mapping):
            return body
        out: dict[str, Any] = {}
        budget = MAX_NAMES
        for name, policy in body.items():
            if not isinstance(policy, Mapping):
                continue
            use = policy.get("in_use_by")
            streams = (
                list((use or {}).get("data_streams") or []) if isinstance(use, Mapping) else []
            )
            indices = list((use or {}).get("indices") or []) if isinstance(use, Mapping) else []
            streams, indices = streams[:budget], indices[: max(budget - len(streams), 0)]
            budget -= len(streams) + len(indices)
            phases = (policy.get("policy") or {}).get("phases") or {}
            delete = phases.get("delete") if isinstance(phases, Mapping) else None
            age = delete.get("min_age") if isinstance(delete, Mapping) else None
            out[str(name)] = {
                "delete_after": age if isinstance(age, str) else None,
                "data_streams": [s for s in streams if isinstance(s, str)],
                "indices": [i for i in indices if isinstance(i, str)],
            }
        return out


@register
class DiscoverPrivileges(Template):
    """Whether the key holds the cluster privileges the optional reads need (``read_ilm``)."""

    name = "discover.privileges"
    version = 1
    endpoint = Endpoint.HAS_PRIVILEGES
    family = Family.DISCOVERY
    cost = CostClass.LIGHT

    def build(self, params: Params) -> RequestPlan:
        return RequestPlan(self.spec(), body={"cluster": ["monitor", "read_ilm"]})

    @staticmethod
    def holds(body: Any, privilege: str) -> bool:
        cluster = body.get("cluster") if isinstance(body, Mapping) else None
        return isinstance(cluster, Mapping) and cluster.get(privilege) is True
