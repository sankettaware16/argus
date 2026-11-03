"""The collector's own alert reads besides ``alerts.ids`` and ``alerts.mget`` (D-050): counts
per (hour, rule) for reconciliation, and the workflow status of alerts that are not ``open``."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, ClassVar

from pydantic import Field

from argus.gateway.builtin import iso
from argus.gateway.templates import (
    CostClass,
    Endpoint,
    Family,
    Params,
    RequestPlan,
    Template,
    register,
)

RULE_FIELD = "kibana.alert.rule.rule_id"
STATUS_FIELD = "kibana.alert.workflow_status"
HOUR = timedelta(hours=1)


class CountsParams(Params):
    start: datetime
    hours: int = Field(ge=1, le=6)


@register
class AlertCounts(Template):
    """Alerts per hour and rule over ``hours`` whole hours from ``start``: one bucket per hour,
    up to RULES rules each (an hour with more rules reports ``sum_other_doc_count``)."""

    name = "alerts.counts"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.ALERTS
    cost = CostClass.MEDIUM
    params_model = CountsParams
    filter_fields = frozenset({"@timestamp"})
    aggregate_fields = frozenset({"@timestamp", RULE_FIELD})
    RULES: ClassVar[int] = 100

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, CountsParams)
        end = params.start + params.hours * HOUR
        body = {
            "size": 0,
            "track_total_hits": False,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": iso(params.start), "lt": iso(end)}}}
                    ]
                }
            },
            "aggs": {
                "hours": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "fixed_interval": "1h",
                        # Elasticsearch drops a bucket that does not end by max: max is
                        # the end itself (1 ms less loses the last hour, found on the SIEM)
                        "hard_bounds": {"min": iso(params.start), "max": iso(end)},
                    },
                    "aggs": {"rules": {"terms": {"field": RULE_FIELD, "size": self.RULES}}},
                }
            },
        }
        return RequestPlan(self.spec(), body=body)

    @staticmethod
    def counts(body: Any) -> tuple[dict[tuple[int, str], int], dict[int, int], set[int]]:
        """(count per (hour epoch ms, rule), total per hour, hours whose rules overflowed)."""
        per_rule: dict[tuple[int, str], int] = {}
        totals: dict[int, int] = {}
        overflow: set[int] = set()
        buckets = body["aggregations"]["hours"]["buckets"]
        for bucket in buckets:
            hour = int(bucket["key"])
            totals[hour] = int(bucket["doc_count"])
            rules = bucket["rules"]
            if rules.get("sum_other_doc_count", 0):
                overflow.add(hour)
            for rule in rules["buckets"]:
                per_rule[(hour, str(rule["key"]))] = int(rule["doc_count"])
        return per_rule, totals, overflow


class StatesParams(Params):
    start: datetime
    end: datetime
    size: int = Field(default=1000, ge=1, le=1000)
    after: tuple[str | int, ...] | None = Field(default=None, min_length=2, max_length=2)


@register
class AlertStates(Template):
    """Ids and workflow status of alerts in [start, end) whose status is not ``open``."""

    name = "alerts.states"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.ALERTS
    cost = CostClass.LIGHT
    params_model = StatesParams
    filter_fields = frozenset({"@timestamp", STATUS_FIELD})
    return_fields = frozenset({STATUS_FIELD})
    sort_fields = frozenset({"@timestamp", "kibana.alert.uuid"})
    max_size = 1000

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, StatesParams)
        body: dict[str, Any] = {
            "size": params.size,
            "_source": [STATUS_FIELD],
            "track_total_hits": False,
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"@timestamp": {"gte": iso(params.start), "lt": iso(params.end)}}}
                    ],
                    "must_not": [{"term": {STATUS_FIELD: "open"}}],
                }
            },
            "sort": [{"@timestamp": {"order": "asc"}}, {"kibana.alert.uuid": {"order": "asc"}}],
        }
        if params.after is not None:
            body["search_after"] = list(params.after)
        return RequestPlan(self.spec(), body=body)
