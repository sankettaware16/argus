"""An in-memory the SIEM for the collector's four requests, answered at the wire level so every
test goes through the real gateway (validator, budget, ledger): ``alerts.ids``,
``alerts.counts``, ``alerts.states`` and ``alerts.mget``. Alerts are clones of a sanitized
real fixture with their own id, time, rule and status."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from argus.gateway.transport import WireRequest, WireResponse
from tests.unit.normalize.alerts import QUERY, fixture

ALIAS = ".alerts-security.alerts-acme-soc"
INDEX = ".internal.alerts-security.alerts-acme-soc-000009"
TEMPLATE = fixture(QUERY)


def ms(moment: datetime) -> int:
    return int(moment.timestamp() * 1000)


def parse(value: str) -> datetime:
    return datetime.fromisoformat(value)


def alert(
    alert_id: str, at: datetime, rule: str = "rule-a", status: str = "open"
) -> dict[str, Any]:
    source = copy.deepcopy(TEMPLATE["_source"])
    stamp = at.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    source["@timestamp"] = stamp
    source["kibana.alert.uuid"] = alert_id
    source["kibana.alert.rule.rule_id"] = rule
    source["kibana.alert.workflow_status"] = status
    return source


@dataclass
class Doc:
    index: str
    source: dict[str, Any]
    visible: bool = True

    @property
    def at(self) -> datetime:
        at = parse(self.source["@timestamp"].replace("Z", "+00:00"))
        return at if at.tzinfo is not None else at.replace(tzinfo=UTC)  # as ES reads it

    @property
    def key(self) -> tuple[int, str]:
        return ms(self.at), self.source["kibana.alert.uuid"]


@dataclass
class FakeAlertsES:
    docs: dict[str, Doc] = field(default_factory=dict)
    calls: list[WireRequest] = field(default_factory=list)
    before: Callable[[WireRequest], None] | None = None  # may raise (outages, crashes)

    def add(
        self,
        alert_id: str,
        at: datetime,
        rule: str = "rule-a",
        status: str = "open",
        *,
        index: str = INDEX,
        visible: bool = True,
    ) -> None:
        self.docs[alert_id] = Doc(index, alert(alert_id, at, rule, status), visible)

    def ids(self) -> set[str]:
        return {i for i, d in self.docs.items() if d.visible}

    # ---------------------------------------------------------------- the wire

    async def send(self, request: WireRequest) -> WireResponse:
        self.calls.append(request)
        if self.before is not None:
            self.before(request)
        body = json.loads(request.body or b"null")
        if request.path.endswith("/_mget"):
            answer = self._mget(request.path.split("/")[1], body["ids"])
        elif "aggs" in body:
            answer = self._counts(body)
        else:
            answer = self._search(body)
        return WireResponse(200, json.dumps(answer).encode(), 2.0)

    def _window(self, body: dict[str, Any]) -> tuple[datetime, datetime]:
        bounds = body["query"]["bool"]["filter"][0]["range"]["@timestamp"]
        return parse(bounds["gte"]), parse(bounds["lt"])

    def _in(self, body: dict[str, Any]) -> list[Doc]:
        start, end = self._window(body)
        found = [d for d in self.docs.values() if d.visible and start <= d.at < end]
        if body["query"]["bool"].get("must_not"):
            found = [d for d in found if d.source["kibana.alert.workflow_status"] != "open"]
        return sorted(found, key=lambda d: d.key)

    def _search(self, body: dict[str, Any]) -> dict[str, Any]:
        docs = self._in(body)
        if "search_after" in body:
            after = tuple(body["search_after"])
            docs = [d for d in docs if d.key > after]
        hits = []
        for doc in docs[: body["size"]]:
            hit: dict[str, Any] = {"_index": doc.index, "_id": doc.source["kibana.alert.uuid"],
                                   "sort": list(doc.key)}  # fmt: skip
            if body["_source"] is not False:
                hit["_source"] = {f: doc.source[f] for f in body["_source"]}
            hits.append(hit)
        return {"took": 3, "timed_out": False,
                "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
                "hits": {"hits": hits}}  # fmt: skip

    def _counts(self, body: dict[str, Any]) -> dict[str, Any]:
        start, end = self._window(body)
        bounds = body["aggs"]["hours"]["date_histogram"]["hard_bounds"]
        # As Elasticsearch does (checked on es-local): a bucket is kept only if it ends by max.
        end = min(end, parse(bounds["max"].replace("Z", "+00:00")))
        size = body["aggs"]["hours"]["aggs"]["rules"]["terms"]["size"]
        buckets = []
        hour = start
        while hour + timedelta(hours=1) <= end:
            docs = [d for d in self._in(body) if hour <= d.at < hour + timedelta(hours=1)]
            rules: dict[str, int] = {}
            for doc in docs:
                rule = doc.source.get("kibana.alert.rule.rule_id")
                if rule is not None:  # a terms aggregation skips documents without the field
                    rules[str(rule)] = rules.get(str(rule), 0) + 1
            ranked = sorted(rules.items(), key=lambda item: (-item[1], item[0]))
            if docs:
                buckets.append({
                    "key": ms(hour), "doc_count": len(docs),
                    "rules": {"sum_other_doc_count": sum(n for _, n in ranked[size:]),
                              "buckets": [{"key": r, "doc_count": n} for r, n in ranked[:size]]},
                })  # fmt: skip
            hour += timedelta(hours=1)
        return {"took": 4, "timed_out": False,
                "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
                "hits": {"hits": []}, "aggregations": {"hours": {"buckets": buckets}}}  # fmt: skip

    def _mget(self, index: str, ids: list[str]) -> dict[str, Any]:
        docs = []
        for alert_id in ids:
            doc = self.docs.get(alert_id)
            if doc is None or not doc.visible or doc.index != index:
                docs.append({"_index": index, "_id": alert_id, "found": False})
            else:
                docs.append({"_index": index, "_id": alert_id, "found": True,
                             "_source": copy.deepcopy(doc.source)})  # fmt: skip
        return {"docs": docs}
