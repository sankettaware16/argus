"""The gateway's own templates: health probes, identity self-test, index listing, and the
collector's two alert reads (a change to a body is a version bump)."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, ClassVar

from pydantic import Field, model_validator

from argus.gateway.templates import (
    CostClass,
    Endpoint,
    Family,
    Params,
    RequestPlan,
    Template,
    Window,
    register,
)

LOG_SOURCE = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")


def iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@register
class ClusterInfo(Template):
    name = "cluster.info"
    version = 1
    endpoint = Endpoint.INFO
    family = Family.CLUSTER
    cost = CostClass.PROBE

    def build(self, params: Params) -> RequestPlan:
        return RequestPlan(self.spec(), url_params=(("filter_path", "version.number"),))


@register
class Authenticate(Template):
    name = "security.authenticate"
    version = 1
    endpoint = Endpoint.AUTHENTICATE
    family = Family.CLUSTER
    cost = CostClass.PROBE

    def build(self, params: Params) -> RequestPlan:
        fields = "username,authentication_type,api_key.name,api_key.id"
        return RequestPlan(self.spec(), url_params=(("filter_path", fields),))


class PrivilegeParams(Params):
    indices: tuple[str, ...] = Field(min_length=1, max_length=64)  # alerts, each family, TI


# Required true for the key to be usable; canaries must be false for it to be read-only.
REQUIRED_INDEX = ("read", "view_index_metadata")
CANARY_INDEX = ("write", "delete", "manage", "delete_index", "create_index")
REQUIRED_CLUSTER = ("monitor",)
CANARY_CLUSTER = ("manage", "manage_security", "manage_api_key", "manage_ilm", "all")


@register
class HasPrivileges(Template):
    name = "security.has_privileges"
    version = 1
    endpoint = Endpoint.HAS_PRIVILEGES
    family = Family.CLUSTER
    cost = CostClass.PROBE
    params_model = PrivilegeParams

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, PrivilegeParams)
        body = {
            "cluster": [*REQUIRED_CLUSTER, *CANARY_CLUSTER],
            "index": [
                {"names": list(params.indices), "privileges": [*REQUIRED_INDEX, *CANARY_INDEX]}
            ],
        }
        return RequestPlan(self.spec(), body=body)

    @staticmethod
    def problems(body: Any) -> list[str]:
        """What is wrong with the key: a required privilege missing or a canary held."""
        if not isinstance(body, Mapping):
            return ["the answer is not a privilege report"]
        out: list[str] = []
        cluster = body.get("cluster")
        index = body.get("index")
        if not isinstance(cluster, Mapping) or not isinstance(index, Mapping):
            return ["the answer is not a privilege report"]
        for name in REQUIRED_CLUSTER:
            if cluster.get(name) is not True:
                out.append(f"lacks cluster privilege {name}")
        for name in CANARY_CLUSTER:
            if cluster.get(name) is not False:
                out.append(f"holds cluster privilege {name}")
        for target, held in sorted(index.items()):
            if not isinstance(held, Mapping):
                out.append(f"no privilege report for {target}")
                continue
            for name in REQUIRED_INDEX:
                if held.get(name) is not True:
                    out.append(f"lacks {name} on {target}")
            for name in CANARY_INDEX:
                if held.get(name) is not False:
                    out.append(f"holds {name} on {target}")
        return out


@register
class NodeStats(Template):
    name = "health.node_stats"
    version = 2
    endpoint = Endpoint.NODE_STATS
    family = Family.CLUSTER
    cost = CostClass.PROBE

    FILTER: ClassVar[str] = ",".join(
        [
            "_nodes.failed",
            "nodes.*.fs.total",
            "nodes.*.jvm.mem.heap_used_percent",
            "nodes.*.os.cpu.load_average",
            "nodes.*.thread_pool.search.queue",
            "nodes.*.thread_pool.search.rejected",
            "nodes.*.thread_pool.write.rejected",
            "nodes.*.breakers.*.tripped",
        ]
    )

    def build(self, params: Params) -> RequestPlan:
        return RequestPlan(self.spec(), url_params=(("filter_path", self.FILTER),))


class BlocksParams(Params):
    indices: tuple[str, ...] = Field(min_length=1, max_length=8)


@register
class IndexBlocks(Template):
    name = "health.index_blocks"
    version = 2
    endpoint = Endpoint.INDEX_BLOCKS
    family = Family.CLUSTER
    cost = CostClass.PROBE
    params_model = BlocksParams
    url_param_names = frozenset({"flat_settings", "ignore_unavailable"})

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, BlocksParams)
        url_params = (("flat_settings", "true"), ("ignore_unavailable", "true"))
        return RequestPlan(self.spec(), url_params=url_params, names=params.indices)

    @staticmethod
    def blocked(body: Any) -> list[str]:
        """Indices with a read_only_allow_delete (or read_only) block set to true."""
        out: list[str] = []
        if not isinstance(body, Mapping):
            return out
        for index, value in sorted(body.items()):
            settings = value.get("settings") if isinstance(value, Mapping) else None
            if not isinstance(settings, Mapping):
                continue
            for key in ("index.blocks.read_only_allow_delete", "index.blocks.read_only"):
                if str(settings.get(key, "false")).lower() == "true":
                    out.append(index)
                    break
        return out


class IndexListingParams(Params):
    source: str = LOG_SOURCE


@register
class IndexListing(Template):
    name = "indices.listing"
    version = 1
    endpoint = Endpoint.RESOLVE_INDEX
    family = Family.CLUSTER
    cost = CostClass.PROBE
    params_model = IndexListingParams

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, IndexListingParams)
        return RequestPlan(
            self.spec(), url_params=(("filter_path", "indices.name"),), source=params.source
        )

    @staticmethod
    def names(body: Any) -> list[str]:
        indices = body.get("indices") if isinstance(body, Mapping) else None
        if not isinstance(indices, list):
            return []
        return [
            i["name"] for i in indices if isinstance(i, Mapping) and isinstance(i.get("name"), str)
        ]


class FreshnessParams(Params):
    source: str = LOG_SOURCE
    now: datetime


@register
class Freshness(Template):
    """The newest ingest time of a log source: size 1, sort event.ingested desc, two fields."""

    name = "health.freshness"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.LOG
    cost = CostClass.PROBE
    params_model = FreshnessParams
    filter_fields = frozenset({"event.ingested"})
    sort_fields = frozenset({"event.ingested"})
    return_fields = frozenset({"@timestamp", "event.ingested"})
    max_size = 1
    LOOKBACK: ClassVar[timedelta] = timedelta(minutes=30)

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, FreshnessParams)
        start = params.now - self.LOOKBACK
        body = {
            "size": 1,
            "track_total_hits": False,
            "_source": ["@timestamp", "event.ingested"],
            "sort": [{"event.ingested": {"order": "desc"}}],
            "query": {"range": {"event.ingested": {"gte": iso(start)}}},
        }
        return RequestPlan(self.spec(), body=body, window=Window(params.source, start, params.now))


class AlertIdsParams(Params):
    start: datetime
    end: datetime
    size: int = Field(default=500, ge=1, le=1000)
    after: tuple[str | int, ...] | None = Field(default=None, min_length=2, max_length=2)


@register
class AlertIds(Template):
    """Ids (and their index) of alerts written in [start, end), oldest first, page by page."""

    name = "alerts.ids"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.ALERTS
    cost = CostClass.LIGHT
    params_model = AlertIdsParams
    filter_fields = frozenset({"@timestamp"})
    sort_fields = frozenset({"@timestamp", "kibana.alert.uuid"})
    max_size = 1000

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, AlertIdsParams)
        body: dict[str, Any] = {
            "size": params.size,
            "_source": False,
            "track_total_hits": False,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": iso(params.start), "lt": iso(params.end)}}}
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "asc"}}, {"kibana.alert.uuid": {"order": "asc"}}],
        }
        if params.after is not None:
            body["search_after"] = list(params.after)
        return RequestPlan(self.spec(), body=body)


class MgetParams(Params):
    index: str = Field(min_length=1, max_length=255)
    ids: tuple[str, ...] = Field(min_length=1, max_length=200)


@register
class AlertsMget(Template):
    """Whole alert documents by id from one exact alerts index."""

    name = "alerts.mget"
    version = 1
    endpoint = Endpoint.MGET
    family = Family.ALERTS
    cost = CostClass.LIGHT
    params_model = MgetParams
    whole_documents = True

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, MgetParams)
        return RequestPlan(self.spec(), body={"ids": list(params.ids)}, names=(params.index,))


# --------------------------------------------------------------------------- Kibana-lane reads
# Elasticsearch reads of the Kibana lane: which alerts list which cases (the discovery of
# people's cases), the licence (before write runs and at the first read) and the
# security index's health (the check before a sign-in's 401 counts).

CASE_ID = Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")
ALERT_ID = Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")


class CaseLinksParams(Params):
    """Exactly one of ``case_ids`` (alerts attached to these cases) or ``alert_ids`` (which of
    these alerts list any case)."""

    case_ids: tuple[Annotated[str, CASE_ID], ...] | None = Field(
        default=None, min_length=1, max_length=100
    )
    alert_ids: tuple[Annotated[str, ALERT_ID], ...] | None = Field(
        default=None, min_length=1, max_length=100
    )
    size: int = Field(default=100, ge=1, le=100)
    after: tuple[str | int, ...] | None = Field(default=None, min_length=2, max_length=2)

    @model_validator(mode="after")
    def _one(self) -> CaseLinksParams:
        if (self.case_ids is None) == (self.alert_ids is None):
            raise ValueError("give exactly one of case_ids and alert_ids")
        return self


@register
class AlertCaseLinks(Template):
    """The case ids alerts carry (``kibana.alert.case_ids``, written by Kibana's internal user
    after an attach) and who last changed their status, oldest first, page by page."""

    name = "alerts.case_links"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.ALERTS
    cost = CostClass.LIGHT
    params_model = CaseLinksParams
    filter_fields = frozenset({"kibana.alert.case_ids"})
    sort_fields = frozenset({"@timestamp", "kibana.alert.uuid"})
    return_fields = frozenset(
        {
            "kibana.alert.case_ids",
            "kibana.alert.workflow_status",
            "kibana.alert.workflow_user",
            "kibana.alert.workflow_status_updated_at",
        }
    )
    max_size = 100

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, CaseLinksParams)
        if params.case_ids is not None:
            match: dict[str, Any] = {"terms": {"kibana.alert.case_ids": list(params.case_ids)}}
            clauses: list[dict[str, Any]] = [match]
        else:
            assert params.alert_ids is not None
            clauses = [
                {"ids": {"values": list(params.alert_ids)}},
                {"exists": {"field": "kibana.alert.case_ids"}},
            ]
        body: dict[str, Any] = {
            "size": params.size,
            "track_total_hits": False,
            "_source": sorted(self.return_fields),
            "query": {"bool": {"filter": clauses}},
            "sort": [{"@timestamp": {"order": "asc"}}, {"kibana.alert.uuid": {"order": "asc"}}],
        }
        if params.after is not None:
            body["search_after"] = list(params.after)
        return RequestPlan(self.spec(), body=body)


@register
class ClusterLicense(Template):
    """The licence's type and status (Basic, active): writes need the licence ARGUS was built
    for. Needs the ``monitor`` cluster privilege (the reader key has it; Kibana's keys do not)."""

    name = "cluster.license"
    version = 1
    endpoint = Endpoint.LICENSE
    family = Family.CLUSTER
    cost = CostClass.LIGHT

    def build(self, params: Params) -> RequestPlan:
        return RequestPlan(
            self.spec(), url_params=(("filter_path", "license.type,license.status"),)
        )

    @staticmethod
    def summary(body: Any) -> tuple[str, str] | None:
        """(type, status), or None if the answer does not say."""
        lic = body.get("license") if isinstance(body, Mapping) else None
        if not isinstance(lic, Mapping):
            return None
        kind, status = lic.get("type"), lic.get("status")
        if not isinstance(kind, str) or not isinstance(status, str):
            return None
        return kind, status


@register
class SecurityIndexHealth(Template):
    """The security index's health. A native user's 401 while it is not green may be the index,
    not the password: a refusal is counted only after this check."""

    name = "health.security_index"
    version = 1
    endpoint = Endpoint.SECURITY_HEALTH
    family = Family.CLUSTER
    cost = CostClass.LIGHT
    FILTER: ClassVar[str] = "status,active_primary_shards,unassigned_primary_shards"

    def build(self, params: Params) -> RequestPlan:
        return RequestPlan(self.spec(), url_params=(("filter_path", self.FILTER),))

    @staticmethod
    def usable(body: Any) -> bool:
        """Green or yellow, every primary shard active: the index answers."""
        if not isinstance(body, Mapping):
            return False
        unassigned = body.get("unassigned_primary_shards")
        return (
            body.get("status") in ("green", "yellow")
            and isinstance(unassigned, int)
            and not isinstance(unassigned, bool)
            and unassigned == 0
        )


@register
class KeyPrivileges(Template):
    """What one of ARGUS's Kibana keys holds (``argus kibana selftest``): Kibana's application
    privileges in the space, the alerts indices and the cluster canaries. Sent by the Kibana
    lane with the key under test, never by this gateway (its key is the reader's)."""

    name = "security.kibana_key_privileges"
    version = 1
    endpoint = Endpoint.HAS_PRIVILEGES
    family = Family.CLUSTER
    cost = CostClass.LIGHT
    timeout = timedelta(seconds=15)
    url_param_names = frozenset()
