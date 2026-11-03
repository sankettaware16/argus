"""The freshness lane's one template: a source's newest document by ingest time.

Like ``health.freshness`` (the probe-cost template, kept for its tests) but a light search on
the freshness lane: it obeys every kill switch (``freshness`` and the global one), the
breaker, the SIEM's health (NORMAL, CAUTION at half, DEGRADED at a tenth, never STOP) and the
quiet hours, and spends the lane's own budget (100 ms a minute, 3 minutes a day). Its timeout
is 1 s: a timeout is charged whole, and 5 s would black the lane out for most of an hour.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any, ClassVar

from argus.freshness.margin import parse_time
from argus.gateway.builtin import LOG_SOURCE, iso
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


class WatermarkParams(Params):
    source: str = LOG_SOURCE
    now: datetime


@register
class Watermark(Template):
    """Size 1, sorted by ``event.ingested`` descending, two fields, the last 15 minutes (a
    person's live-test session reads at most 15 minutes of logs; a source with nothing in
    15 minutes is silent, which breaks continuity: the safe side)."""

    name = "freshness.watermark"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.LOG
    cost = CostClass.LIGHT
    params_model = WatermarkParams
    filter_fields = frozenset({"event.ingested"})
    sort_fields = frozenset({"event.ingested"})
    return_fields = frozenset({"@timestamp", "event.ingested"})
    max_size = 1
    timeout = timedelta(seconds=1)  # charged whole on a timeout: keep the lane alive
    LOOKBACK: ClassVar[timedelta] = timedelta(minutes=15)

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, WatermarkParams)
        start = params.now - self.LOOKBACK
        body = {
            "size": 1,
            "track_total_hits": False,
            "_source": ["@timestamp", "event.ingested"],
            "sort": [{"event.ingested": {"order": "desc"}}],
            # ``lte`` now: a document with a future ingest time (a skewed clock) would stay
            # the newest hit and freeze the watermark
            "query": {"range": {"event.ingested": {"gte": iso(start), "lte": iso(params.now)}}},
        }
        return RequestPlan(self.spec(), body=body, window=Window(params.source, start, params.now))


def newest(body: Any) -> tuple[datetime, datetime] | None:
    """(ingested, event time) of the answer's one document; None when there is none.
    ValueError when the answer has a document whose times cannot be read."""
    hits = body.get("hits") if isinstance(body, Mapping) else None
    rows = hits.get("hits") if isinstance(hits, Mapping) else None
    if not isinstance(rows, list):
        raise ValueError("the answer has no hits")
    if not rows:
        return None
    first = rows[0]
    source = first.get("_source") if isinstance(first, Mapping) else None
    if not isinstance(source, Mapping):
        raise ValueError("the document has no _source")
    event = source.get("event")
    ingested = parse_time(
        source.get("event.ingested", event.get("ingested") if isinstance(event, Mapping) else None)
    )
    stamp = parse_time(source.get("@timestamp"))
    if ingested is None or stamp is None:
        raise ValueError("the document's times cannot be read")
    return ingested, stamp
