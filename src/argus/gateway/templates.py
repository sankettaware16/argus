"""Query templates: the only way ARGUS asks the SIEM anything.

A template is a class with a name, a version, an endpoint, an index family, a cost class, a
pydantic parameter model, field allowlists and a body builder. Values from parameters enter the
body only as JSON literals. The gateway builds the URL path itself from the endpoint and the
resolved indices, so no template can reach another API; the validator then inspects the final
body against the template's allowlists and the forbidden shapes.
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict


class Endpoint(StrEnum):
    INFO = "info"  # GET /
    SEARCH = "search"  # POST /<indices>/_search
    MGET = "mget"  # POST /<index>/_mget
    NODE_STATS = "node_stats"  # GET /_nodes/_local/stats/fs,jvm,os,thread_pool,breaker
    INDEX_BLOCKS = "index_blocks"  # GET /<indices>/_settings/index.blocks.*,index.uuid
    RESOLVE_INDEX = "resolve_index"  # GET /_resolve/index/<family pattern>
    AUTHENTICATE = "authenticate"  # GET /_security/_authenticate
    HAS_PRIVILEGES = "has_privileges"  # POST /_security/user/_has_privileges
    LICENSE = "license"  # GET /_license
    SECURITY_HEALTH = "security_health"  # GET /_cluster/health/.security
    # `argus discover`: metadata reads of a SIEM ARGUS has not been configured for yet
    DISCOVER_INDICES = "discover_indices"  # GET /_resolve/index/<one of two fixed patterns>
    FIELD_MAPPING = "field_mapping"  # GET /<one index>/_mapping/field/<allowlisted fields>
    ILM_POLICIES = "ilm_policies"  # GET /_ilm/policy (needs read_ilm: asked only when held)


class Family(StrEnum):
    ALERTS = "alerts"  # the space's alerts alias
    LOG = "log"  # exact daily log indices from the time window
    TI = "ti"  # the threat-intel indices
    CLUSTER = "cluster"  # no index: node stats, identity, info
    DISCOVERY = "discovery"  # `argus discover`: metadata of indices the site does not name yet


class CostClass(StrEnum):
    PROBE = "probe"  # health and identity: own small allowance, runs in every state
    LIGHT = "light"
    MEDIUM = "medium"
    HEAVY = "heavy"  # any aggregation on a log index


class Purpose(StrEnum):
    """Why a request is made; the health state and the kill switches decide by it."""

    PROBE = "probe"
    SELFTEST = "selftest"
    COLLECT = "collect"  # the collector's ids-only poll and mget of new ids
    BACKFILL = "backfill"
    RECONCILE = "reconcile"
    ENRICH = "enrich"
    WRITEBACK = "writeback"  # alert status writes and their read-backs
    # the lanes: each spends its own share of the budget (lanes.py)
    INVESTIGATE = "investigate"  # waves, the agent, the still-active watch, "check more"
    FRESHNESS = "freshness"  # watermarks and verified zeros
    MEASURE = "measure"  # the budget's re-measurement: NORMAL only, a person's session
    IDENTITY = "identity"  # sign-in and capability checks; not stopped by STOP
    KIBANA_READ = "kibana_read"  # the Kibana lane's reads
    KIBANA_WRITE = "kibana_write"  # case writes W1-W3
    DISCOVER = "discover"  # `argus discover`: a person's metadata reads, NORMAL only
    CHECK = "check"  # the incident engine's checking lane (P4-F E3): NORMAL only, no quiet hours


# The kill switch a purpose answers to, besides the global one. The re-measurement has no
# switch of its own: the global one stops it, and its script refuses to start or
# go on while any switch is stopped.
COMPONENT = {
    Purpose.PROBE: None,
    Purpose.SELFTEST: None,
    Purpose.COLLECT: "collector",
    Purpose.BACKFILL: "collector",
    Purpose.RECONCILE: "collector",
    Purpose.ENRICH: "enrichment",
    Purpose.WRITEBACK: "writeback",
    Purpose.INVESTIGATE: "investigation",
    Purpose.FRESHNESS: "freshness",
    Purpose.MEASURE: None,
    Purpose.IDENTITY: "identity",
    Purpose.KIBANA_READ: "kibana",
    Purpose.KIBANA_WRITE: "cases",
    Purpose.DISCOVER: None,
    Purpose.CHECK: "checking",
}
COMPONENTS = (
    "collector",
    "enrichment",
    "kibana",
    "writeback",
    "investigation",
    "freshness",
    "cases",
    "identity",
    "checking",
)


class Params(BaseModel):
    """Base of every template's parameters: strict, frozen, no unknown keys."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class NoParams(Params):
    pass


@dataclass(frozen=True)
class Spec:
    """What the validator holds a template's final request to."""

    name: str
    version: int
    endpoint: Endpoint
    family: Family
    cost: CostClass
    filter_fields: frozenset[str] = frozenset()
    aggregate_fields: frozenset[str] = frozenset()
    return_fields: frozenset[str] = frozenset()
    sort_fields: frozenset[str] = frozenset()
    max_size: int = 0
    url_params: frozenset[str] = frozenset({"filter_path"})
    allow_pit: bool = False
    whole_documents: bool = False  # mget may return whole documents (no _source filter)
    # A template with a larger answer than the contract's usual one names its own bounds, each
    # below what Elasticsearch itself would refuse (the validator's MAX_BUCKETS and
    # MAX_LOG_AGG_DEPTH apply to every template that does not).
    max_buckets: int | None = None
    max_agg_depth: int | None = None


@dataclass(frozen=True)
class Window:
    """The time range a log template reads, and which log source. ``pad`` (the default): the
    indices are those the range can touch with an hour of slack either side, at most two daily
    indices (events near UTC midnight can land in the neighbouring day's index). Not padded: the
    range is half-open and reads exactly the daily indices it overlaps, so a whole UTC day is one
    index."""

    source: str
    start: datetime
    end: datetime
    pad: bool = True


@dataclass(frozen=True)
class RequestPlan:
    """A template's request before index resolution: the endpoint, URL parameters and body."""

    spec: Spec
    body: Any = None
    url_params: tuple[tuple[str, str], ...] = ()
    window: Window | None = None  # log family: the indices come from this window
    names: tuple[str, ...] = ()  # exact indices (mget, TI, index blocks), checked by family
    source: str | None = None  # resolve_index: the log source whose daily indices to list
    fields: tuple[str, ...] = ()  # field_mapping: the fields asked about


class Template(ABC):
    name: ClassVar[str]
    version: ClassVar[int]
    endpoint: ClassVar[Endpoint]
    family: ClassVar[Family]
    cost: ClassVar[CostClass]
    params_model: ClassVar[type[Params]] = NoParams
    filter_fields: ClassVar[frozenset[str]] = frozenset()
    aggregate_fields: ClassVar[frozenset[str]] = frozenset()
    return_fields: ClassVar[frozenset[str]] = frozenset()
    sort_fields: ClassVar[frozenset[str]] = frozenset()
    max_size: ClassVar[int] = 0
    url_param_names: ClassVar[frozenset[str]] = frozenset({"filter_path"})
    allow_pit: ClassVar[bool] = False
    whole_documents: ClassVar[bool] = False
    max_buckets: ClassVar[int | None] = None
    max_agg_depth: ClassVar[int | None] = None
    timeout: ClassVar[timedelta] = timedelta(seconds=10)

    @classmethod
    def spec(cls) -> Spec:
        return Spec(
            name=cls.name,
            version=cls.version,
            endpoint=cls.endpoint,
            family=cls.family,
            cost=cls.cost,
            filter_fields=cls.filter_fields,
            aggregate_fields=cls.aggregate_fields,
            return_fields=cls.return_fields,
            sort_fields=cls.sort_fields,
            max_size=cls.max_size,
            url_params=cls.url_param_names,
            allow_pit=cls.allow_pit,
            whole_documents=cls.whole_documents,
            max_buckets=cls.max_buckets,
            max_agg_depth=cls.max_agg_depth,
        )

    @classmethod
    def opaque_id(cls, component: str) -> str:
        return f"argus-{component}/{cls.name}@{cls.version}"

    def plan(self, params: Params) -> RequestPlan:
        if type(params) is not self.params_model:
            raise TypeError(f"{self.name} takes {self.params_model.__name__}")
        return self.build(params)

    def build(self, params: Params) -> RequestPlan:
        return RequestPlan(self.spec())

    def answer(self, params: Params, body: Any) -> Any:
        """The answer as this template defines it, made from Elasticsearch's (the gateway
        returns this one). Most templates keep it as it came; one that asks for a row more
        than it keeps, to know whether there were more, cuts it here."""
        return body


REGISTRY: dict[str, type[Template]] = {}


def register(template: type[Template]) -> type[Template]:
    """Class decorator: one class per template name, a positive version."""
    name = template.name
    if name in REGISTRY and REGISTRY[name] is not template:
        raise ValueError(f"template {name} is registered twice")
    if not isinstance(template.version, int) or template.version < 1:
        raise ValueError(f"template {name} needs a positive integer version")
    REGISTRY[name] = template
    return template


def plan_key(plan: RequestPlan, params: Params) -> str:
    """A request's content address: sha256 of the template and version, the canonical
    parameters and what the plan reads (window, index names, log source). The daily indices
    the gateway resolves from the window are left out: they follow from the window, and the
    listing can change. The evidence store keys tasks by it, and the ledger records it with
    every request, so a ledger row joins its evidence."""
    window = plan.window
    span: list[str] | None = None
    if window is not None:
        span = [window.source, window.start.isoformat(), window.end.isoformat()]
        if not window.pad:  # a padded window's key stays what it always was
            span.append("exact")
    content = {
        "template": f"{plan.spec.name}@{plan.spec.version}",
        "params": params.model_dump(mode="json"),
        "window": span,
        "names": list(plan.names),
        "source": plan.source,
    }
    canonical = json.dumps(
        content, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def task_key(template: Template, params: Params) -> str:
    """``plan_key`` of the template's plan for ``params``."""
    return plan_key(template.plan(params), params)
