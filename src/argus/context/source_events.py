"""``logs.source_events`` (Q-F4, plan §5 WS-F, §7.3): the log events behind a threshold or
ES|QL alert, which carry no fetchable ancestor (a threshold alert names the rule's index
pattern, an aggregating ES|QL alert an empty one). At most 20 rows of the alert's own source
(a proxy, web server or DNS family of the site), for the alert's client in the alert's
evidence window (at most an hour), narrowed by the alert's other group-by values where the
field is allowed; the oldest first, so the rows start where the rule began to count.

A search for rows, not an aggregation: medium cost, at most two daily indices, a 5 s timeout.
It asks for 21 rows to know whether there were more than 20, and keeps 20: the answer then says
"at least 21" (``answer``), so every reader of the stored evidence sees the cut. Each source
returns its own fixed fields (by field role, the names the site gives them). The rule's query is
never reused (only ARGUS-built parameters reach the body), so the rows are the client's events in
that window, not necessarily only the ones the rule counted: the report says so.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any

from pydantic import Field, field_validator, model_validator

from argus.context.bounds import address, check_window, iso, keyword_chars, utf16_len
from argus.context.evidence import SignalValue, derived, from_logs
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
from argus.site import Fields, LogFamily, Role, active, fields_of, names_family

LONGEST = timedelta(hours=1)
ROWS = 20
TIMEOUT = timedelta(seconds=5)
SOURCE_ROLES = (Role.PROXY, Role.WEB, Role.DNS)  # the families whose rows an alert can lack
# What each role returns, by field role and in this order ("time" is the family's time field);
# the names are the site's, without any ``.keyword`` (a document holds the field, not its
# sub-field).
RETURNS: dict[Role, tuple[str, ...]] = {
    Role.PROXY: (
        "time", "client_ip", "server_ip", "server_port", "url", "method", "status_code",
        "action", "bytes",
    ),
    Role.WEB: (
        "time", "client_ip", "domain", "url_path", "method", "status_code", "bytes",
        "user_agent",
    ),
    Role.DNS: (
        "time", "client_ip", "client_ip_alt", "query_name", "query_type", "response_code",
    ),
}  # fmt: skip
# Group-by field roles an alert may narrow the rows by, per role.
NARROW: dict[Role, tuple[str, ...]] = {
    Role.PROXY: ("server_ip", "server_port"),
    Role.WEB: ("domain",),
    Role.DNS: (),
}


def family_of(source: str) -> LogFamily:
    """The proxy, web or DNS family a source key names; ValueError for any other."""
    family = active().family(source)
    if family is None or family.role not in SOURCE_ROLES:
        raise ValueError(f"{source[:40]} is not a proxy, web server or DNS log family of the site")
    return family


def _name(f: Fields, logical: str) -> str:
    return f.time if logical == "time" else f.source(logical)


def returns(source: str) -> tuple[str, ...]:
    """The fields a source's rows return (``_source`` paths), in request order."""
    family = family_of(source)
    f = family.resolved()
    return tuple(_name(f, logical) for logical in RETURNS[family.role])


def narrow(source: str) -> dict[str, str]:
    """The group-by fields an alert may narrow a source's rows by: the name the alert has it
    under (the field without a ``.keyword``, or with it) -> the field queried."""
    family = family_of(source)
    f = family.resolved()
    found: dict[str, str] = {}
    for logical in NARROW[family.role]:
        found[f.source(logical)] = f(logical)
        found[f(logical)] = f(logical)
    return found


def _kinds(source: str) -> tuple[frozenset[str], frozenset[str]]:
    """(the queried fields that hold addresses, those that hold port numbers)."""
    family = family_of(source)
    if family.role is not Role.PROXY:
        return frozenset(), frozenset()
    f = family.resolved()
    return frozenset({f("server_ip")}), frozenset({f("server_port")})


class SourceParams(Params):
    source: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    ip: str = Field(min_length=2, max_length=45)
    narrow: tuple[tuple[str, str], ...] = Field(default=(), max_length=3)
    start: datetime
    end: datetime
    size: int = Field(default=ROWS, ge=1, le=ROWS)

    @field_validator("ip")
    @classmethod
    def _address(cls, value: str) -> str:
        return address(value)

    @model_validator(mode="after")
    def _checked(self) -> SourceParams:
        check_window(self.start, self.end, LONGEST, one_index=False)
        allowed = narrow(self.source)
        ip_fields, int_fields = _kinds(self.source)
        fields = [field for field, _ in self.narrow]
        if len(set(fields)) != len(fields) or not set(fields) <= set(allowed.values()):
            raise ValueError(f"{self.source} rows narrow only by {sorted(set(allowed.values()))}")
        if list(self.narrow) != sorted(self.narrow):
            raise ValueError("narrowing values are sorted by field")
        for field, value in self.narrow:
            if field in ip_fields:
                if address(value) != value:
                    raise ValueError(f"{field} is a canonical address")
            elif field in int_fields:
                plain = value.isascii() and value.isdigit() and str(int(value)) == value
                if not plain or int(value) > 65535:
                    raise ValueError(f"{field} is a port number")
            elif not value or utf16_len(value) > keyword_chars(self.source):
                raise ValueError(f"{field} is 1 to {keyword_chars(self.source)} characters")
        return self


@register
class LogsSourceEvents(Template):
    """The first 20 log events of a client in an alert's window, from the alert's source."""

    name = "logs.source_events"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.LOG
    cost = CostClass.MEDIUM
    params_model = SourceParams
    max_size = ROWS + 1
    timeout = TIMEOUT

    @classmethod
    def spec(cls) -> Spec:
        """What the template may filter on, return and sort by: the union over the site's
        proxy, web and DNS families (one request reads one of them)."""
        filters: set[str] = set()
        returned: set[str] = set()
        times: set[str] = set()
        for role in SOURCE_ROLES:
            for family in active().of_role(role):
                f = family.resolved()
                filters |= {f("client_ip"), f.time, *narrow(family.name).values()}
                if role is Role.DNS:
                    filters.add(f("client_ip_alt"))
                returned |= set(returns(family.name))
                times.add(f.time)
        return replace(
            super().spec(),
            filter_fields=frozenset(filters),
            return_fields=frozenset(returned),
            sort_fields=frozenset(times),
        )

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, SourceParams)
        family = family_of(params.source)
        f = fields_of(params.source)
        _, int_fields = _kinds(params.source)
        client: dict[str, Any] = {"term": {f("client_ip"): params.ip}}
        if family.role is Role.DNS:  # the mapping has both; no event says which is filled
            client = {
                "bool": {
                    "should": [
                        {"term": {f("client_ip"): params.ip}},
                        {"term": {f("client_ip_alt"): params.ip}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        filters: list[dict[str, Any]] = [client]
        for field, value in params.narrow:
            filters.append({"term": {field: int(value) if field in int_fields else value}})
        filters.append({"range": {f.time: {"gte": iso(params.start), "lt": iso(params.end)}}})
        body = {
            "size": params.size + 1,
            "track_total_hits": False,
            "_source": list(returns(params.source)),
            "sort": [{f.time: {"order": "asc"}}],
            "query": {"bool": {"filter": filters}},
        }
        return RequestPlan(
            self.spec(), body=body, window=Window(params.source, params.start, params.end)
        )

    def answer(self, params: Params, body: Any) -> Any:
        """At most ``size`` rows. The one more asked for, when found, is left out and the
        total becomes a lower bound (``gte``), so the stored evidence record reads "at least
        21, not every row" rather than a complete answer of 21 (review F4-R11)."""
        assert isinstance(params, SourceParams)
        part = body.get("hits") if isinstance(body, Mapping) else None
        if not isinstance(part, Mapping) or not isinstance(part.get("hits"), list):
            return body
        hits = part["hits"]
        if len(hits) <= params.size:
            return body
        cut = {**part, "hits": hits[: params.size], "total": {"value": len(hits),
                                                              "relation": "gte"}}  # fmt: skip
        return {**body, "hits": cut}


# ----------------------------------------------------------------------------- planning


def source_of(indices: Sequence[str]) -> str | None:
    """The one log source (a proxy, web or DNS family of the site) a rule reads
    (``kibana.alert.rule.indices``), or None when it reads none of them or several."""
    found = {
        family.name
        for role in SOURCE_ROLES
        for family in active().of_role(role)
        if any(names_family(index, family) for index in indices)
    }
    return found.pop() if len(found) == 1 else None


def from_alert(normalized: Mapping[str, Any], indices: Sequence[str]) -> SourceParams | str:
    """The parameters for an alert's source events, from its normalized form (R5: the
    adapter, the evidence window, the group key), or why there are none."""
    if normalized.get("rule_type") not in ("threshold", "esql"):
        return "only threshold and ES|QL alerts lack their source events"
    source = source_of(indices)
    if source is None:
        return "the rule does not read exactly one of squid, nginx or DNS"
    window = normalized.get("evidence_window") or {}
    try:
        start = datetime.fromisoformat(str(window["start"]))
        end = datetime.fromisoformat(str(window["end"]))
    except (KeyError, ValueError):
        return "the alert has no evidence window"
    # whole seconds around it: the window's end is its last event (a threshold bucket's
    # newest), which a search's "lt" would leave out
    start = start.replace(microsecond=0)
    end = max(end.replace(microsecond=0) + timedelta(seconds=1), start + timedelta(minutes=1))
    start = max(start, end - LONGEST)
    group = normalized.get("group_key") or {}
    pairs = dict(zip(group.get("fields") or [], group.get("values") or [], strict=False))
    ip = pairs.get("source.ip")
    if not isinstance(ip, str):
        return "the alert names no client address"
    narrowed: list[tuple[str, str]] = []
    allowed = narrow(source)
    for field, value in pairs.items():
        target = allowed.get(field)
        if target is None or value is None or isinstance(value, bool | list | dict):
            continue
        narrowed.append((target, str(value)))
    try:
        return SourceParams(
            source=source, ip=ip, narrow=tuple(sorted(narrowed)), start=start, end=end
        )
    except ValueError as exc:
        return f"the alert's values cannot be searched for ({type(exc).__name__})"


# ----------------------------------------------------------------------------- reading


def _total(snapshot: Mapping[str, Any]) -> int:
    total = snapshot.get("total")
    return total if isinstance(total, int) and not isinstance(total, bool) else 0


def rows(snapshot: Mapping[str, Any], size: int) -> tuple[list[Mapping[str, Any]], bool]:
    """(the rows, whether there were more than the rows kept: more than ``size``, or a
    total above them)."""
    found = [r for r in snapshot.get("rows") or [] if isinstance(r, Mapping)]
    kept = found[:size]
    return kept, len(found) > size or _total(snapshot) > len(kept)


def read(
    version: int, params: SourceParams, ref: Mapping[str, Any], snapshot: Mapping[str, Any]
) -> list[SignalValue]:
    """How many source events were found: a lower bound when there were more than kept."""
    found, more = rows(snapshot, params.size)
    refs = [ref]
    if more:
        refs = [{**ref, "coverage": {**(ref.get("coverage") or {}), "more_rows": True}}]
    count = max(len(found), _total(snapshot))
    return [from_logs(derived("source_events.rows", version, refs, lambda: count, counts=True))]


def answers(derived_: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    by = {s["name"]: s for s in derived_ if s.get("status") == "known"}
    row = by.get("source_events.rows")
    if row is None:
        return {}
    more = "at least " if row.get("completeness") == "lower_bound" else ""
    return {
        "source_events": f"Source logs: {more}{row['value']} events of the client in the alert's"
        " window (all its events there, not only those the rule counted)."
    }
