"""The gateway template that reads the SSO sign-ins of some addresses on one day.

One request is **one daily index** (never across days): the allowlisted sign-in events of at most
200 internal IPv4 addresses, from the start of the UTC day to an end never past the ingest margin.
It returns no document and aggregates by address (``ips``), then the number of accounts that signed
in (``accounts``, a cardinality, so a shared address is seen even when not all are listed), and the
commonest ten accounts (``users``) with their first and last event, outcome mix, commonest three
browser strings and UTC hours. The answer holds personal data: :mod:`argus.signins.parse` turns it
into sightings and it is never logged. Heavy by the gateway's rule, sent in the investigation lane,
with its own bounds (``max_agg_depth``, ``max_buckets``)."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import replace
from datetime import UTC, date, datetime, timedelta
from typing import Any

from pydantic import Field, field_validator, model_validator

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
from argus.signins import model as m
from argus.site import Role, fields_for

HOUR_AGG = {"fixed_interval": "1h", "min_doc_count": 1}
MAX_ADDRESSES = 200  # the validator's terms limit
ACTION = re.compile(r"[a-z][a-z0-9_]{0,63}")


def iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class DayParams(Params):
    """Addresses and a day. ``end`` is where the read stops: after the day's start and not after
    its end (a day not over is read up to the ingest margin)."""

    day: date
    addresses: tuple[str, ...] = Field(min_length=1, max_length=MAX_ADDRESSES)
    actions: tuple[str, ...] = Field(min_length=1, max_length=40)
    end: datetime

    @field_validator("addresses")
    @classmethod
    def _addresses(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        out: set[str] = set()
        for text in value:
            try:
                address = ipaddress.IPv4Address(text)
            except ValueError:
                raise ValueError("an address is IPv4 text") from None
            if str(address) != text:
                raise ValueError("an address is written in its canonical form")
            out.add(text)
        if len(out) != len(value):
            raise ValueError("an address is asked about once")
        return tuple(sorted(out, key=lambda a: int(ipaddress.IPv4Address(a))))

    @field_validator("actions")
    @classmethod
    def _actions(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not all(ACTION.fullmatch(a) for a in value) or len(set(value)) != len(value):
            raise ValueError("actions are event action names, each once")
        return value

    @model_validator(mode="after")
    def _within_the_day(self) -> DayParams:
        start = m.day_start(self.day)
        if self.end.tzinfo is None:
            raise ValueError("the end is timezone-aware")
        if not start < self.end <= start + m.DAY:
            raise ValueError("the end is inside the day")
        return self


@register
class SigninsDay(Template):
    """The sign-in accounts of some addresses on one UTC day."""

    name = "signins.day"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.LOG
    cost = CostClass.HEAVY
    params_model = DayParams
    max_agg_depth = 3
    max_buckets = (
        64_400  # the worst case for 200 addresses is 64,200; Elasticsearch stops at 65,536
    )
    timeout = timedelta(seconds=30)

    @classmethod
    def spec(cls) -> Spec:
        f = fields_for(Role.AUTH)
        return replace(
            super().spec(),
            filter_fields=frozenset({f("client_ip"), f("action"), f.time}),
            aggregate_fields=frozenset(
                {f("client_ip"), f("user_name"), f("user_agent"), f("outcome"), f.time}
            ),
        )

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, DayParams)
        f = fields_for(Role.AUTH)
        start = m.day_start(params.day)
        # hard_bounds drops an hour whose end passes max (23:59:59.999 loses the 23:00 hour): the
        # bound is the next midnight
        last = start + m.DAY
        body: dict[str, Any] = {
            "size": 0,
            "track_total_hits": False,  # log searches never count every hit (validator)
            "query": {
                "bool": {
                    "filter": [
                        {"terms": {f("client_ip"): list(params.addresses)}},
                        {"terms": {f("action"): list(params.actions)}},
                        {"range": {f.time: {"gte": iso(start), "lt": iso(params.end)}}},
                    ]
                }
            },
            "aggs": {
                "ips": {
                    "terms": {"field": f("client_ip"), "size": len(params.addresses)},
                    "aggs": {
                        "accounts": {"cardinality": {"field": f("user_name")}},
                        "users": {
                            "terms": {"field": f("user_name"), "size": m.MAX_USERS},
                            "aggs": {
                                "first": {"min": {"field": f.time}},
                                "last": {"max": {"field": f.time}},
                                "outcomes": {"terms": {"field": f("outcome"), "size": 3}},
                                "agents": {
                                    "terms": {"field": f("user_agent"), "size": m.MAX_AGENTS}
                                },
                                "hours": {
                                    "date_histogram": {
                                        "field": f.time,
                                        **HOUR_AGG,
                                        "hard_bounds": {"min": iso(start), "max": iso(last)},
                                    }
                                },
                            },
                        },
                    },
                }
            },
        }
        return RequestPlan(
            self.spec(), body=body, window=Window(m.source(), start, params.end, pad=False)
        )
