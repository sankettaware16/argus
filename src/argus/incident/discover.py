"""The exact query behind a line of evidence, as text a person can paste and a read-only Kibana
Discover link (AR7, D-190).

Built only from the evidence templates that **actually ran** (the ``evidence`` row's template,
version and parameters) and from configuration (the Kibana address, the space, the log index
prefix, the data views). Building a query is string work: nothing here asks the SIEM or Kibana
anything, and a link only opens a page a person already has to be signed in to.

Each query exists in both languages, because the security team uses both: KQL (what Discover's
search bar takes, over a data view) and ES|QL (what it takes with no data view at all). A link is a
KQL link when ``incident.data_views`` names a data view for the index family, else an ES|QL link,
which needs no id. Values enter a query only as quoted literals (``\\`` and ``"`` escaped, control
characters dropped), so a value from a log or an alert can never add a clause.

The mapping from a template to its query lives here, one function each, and a test holds that
every template the investigation can run has one: a template without a query would be an evidence
line a person cannot check.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

from argus import site
from argus.incident.model import Language, ReportQuery
from argus.reference.templates import ecs_terms

TI_RANGE = timedelta(days=400)  # a threat-intel row carries no window: Discover needs one
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")
_ID = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
ALERT_FIELD = "kibana.alert.rule.name"
TAG_FIELD = "kibana.alert.workflow_tags"


@dataclass(frozen=True)
class Config:
    """What building a link needs from the settings (no secrets)."""

    kibana_url: str = "https://kibana.invalid"
    base_path: str = ""
    space: str = "default"
    views: Mapping[str, str] = field(default_factory=dict)  # source -> Kibana data view id

    @property
    def app(self) -> str:
        return f"{self.kibana_url.rstrip('/')}{self.base_path}/s/{self.space}/app"

    def log_index(self, source: str) -> str:
        """The index (pattern) a source's query runs on: its family's pattern in the site."""
        family = site.active().family(source)
        return family.pattern if family is not None else f"{source}-*"

    @property
    def alerts_index(self) -> str:
        return site.active().alerts_index_of(self.space)


# ----------------------------------------------------------------------------- the languages


def clean(value: object) -> str:
    return _CONTROL.sub("", str(value))


def kql_str(value: object) -> str:
    """A KQL quoted string: ``"`` and ``\\`` escaped."""
    return '"' + clean(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def kql_any(field_: str, values: list[str]) -> str:
    """``field : "a"`` or ``field : ("a" or "b")``."""
    if len(values) == 1:
        return f"{field_} : {kql_str(values[0])}"
    return f"{field_} : (" + " or ".join(kql_str(v) for v in values) + ")"


def esql_str(value: object) -> str:
    """An ES|QL string literal: ``"`` and ``\\`` escaped."""
    return '"' + clean(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def stamp(at: datetime) -> str:
    """UTC with milliseconds and ``Z``, as Kibana's own time range is written."""
    utc = at.astimezone(UTC)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def esql_window(start: datetime, end: datetime, field_: str = "@timestamp") -> str:
    return f"{field_} >= {esql_str(stamp(start))} AND {field_} < {esql_str(stamp(end))}"


# ----------------------------------------------------------------------------- rison and links


def rison(value: Any) -> str:
    """Rison, the encoding of Kibana's URL state: objects ``(a:1)``, arrays ``!(1,2)``, strings
    in single quotes with ``!`` and ``'`` escaped by ``!``, ``!t`` ``!f`` ``!n``."""
    if value is None:
        return "!n"
    if value is True:
        return "!t"
    if value is False:
        return "!f"
    if isinstance(value, int | float):
        return repr(value)
    if isinstance(value, str):
        return "'" + value.replace("!", "!!").replace("'", "!'") + "'"
    if isinstance(value, list | tuple):
        return "!(" + ",".join(rison(v) for v in value) + ")"
    if isinstance(value, dict):
        parts = []
        for key, item in value.items():
            name = key if _ID.fullmatch(key) else rison(key)
            parts.append(f"{name}:{rison(item)}")
        return "(" + ",".join(parts) + ")"
    raise TypeError(f"cannot write {type(value).__name__} as rison")


def encode(text: str) -> str:
    """The rison text as a URL component: the characters Kibana leaves bare stay bare."""
    return quote(text, safe="!()*',:~@")


def discover_url(
    cfg: Config, *, language: str, index: str, text: str, esql: str, start: datetime,
    end: datetime, source: str, time_field: str = "@timestamp",
) -> str:  # fmt: skip
    """A Discover link over ``[start, end)``: KQL on the data view configured for ``source``,
    else the ES|QL form (which names the index itself and needs no data view)."""
    window = {"from": stamp(start), "to": stamp(end)}
    g = {"filters": [], "refreshInterval": {"pause": True, "value": 60000}, "time": window}
    view = cfg.views.get(source)
    if view is not None and language == "kql":
        a: dict[str, Any] = {
            "columns": [],
            "dataSource": {"dataViewId": view, "type": "dataView"},
            "filters": [],
            "interval": "auto",
            "query": {"language": "kuery", "query": text},
            "sort": [[time_field, "desc"]],
        }
    else:
        a = {
            "columns": [],
            "dataSource": {"type": "esql"},
            "filters": [],
            "interval": "auto",
            "query": {"esql": esql},
            "sort": [],
        }
    return f"{cfg.app}/discover#/?_g={encode(rison(g))}&_a={encode(rison(a))}"


def make(
    cfg: Config, *, kind: str, source: str, index: str, kql: str, where: str, start: datetime,
    end: datetime, template: str, tail: str = "", time_field: str = "@timestamp",
) -> ReportQuery:  # fmt: skip
    """A query in both languages; ``where`` is its ES|QL filter without the time (the window
    is added here), ``tail`` what follows it (``| SORT @timestamp ASC | LIMIT 100``)."""
    esql = f"FROM {index} | WHERE {esql_window(start, end, time_field)} | WHERE {where}"
    esql += f" {tail}" if tail else " | LIMIT 100"
    has_view = source in cfg.views
    language: Language = "kql" if has_view else "esql"
    shown = kql if has_view else esql
    return ReportQuery(
        kind=kind,  # type: ignore[arg-type]
        language=language,
        index=index,
        text=shown,
        other=esql if has_view else kql,
        time_from=start,
        time_to=end,
        url=discover_url(cfg, language=language, index=index, text=kql, esql=esql, start=start,
                         end=end, source=source, time_field=time_field),
        template=template,
    )  # fmt: skip


# ----------------------------------------------------------------------------- the templates


def _t(params: Mapping[str, Any], key: str) -> datetime:
    value = params[key]
    at = value if isinstance(value, datetime) else datetime.fromisoformat(str(value))
    return at if at.tzinfo is not None else at.replace(tzinfo=UTC)


def _ip_eq(field_: str, value: str) -> str:
    return f"{field_} == {esql_str(value)}"


def _family(p: Mapping[str, Any], role: site.Role) -> tuple[str, site.Fields]:
    """The family a query was run on (the evidence's ``source`` when the site has two or more of
    the role, else the site's one) and its field names."""
    source = str(p.get("source") or site.source_for(role))
    return source, site.fields_for(role, source)


def _either(f: site.Fields, value: str) -> tuple[str, str]:
    """A DNS client is in ``source.ip`` or ``client.ip`` (the captured mapping has both)."""
    one, two = f.source("client_ip"), f.source("client_ip_alt")
    kql = f"({one} : {kql_str(value)} or {two} : {kql_str(value)})"
    esql = f"({one} == {esql_str(value)} OR {two} == {esql_str(value)})"
    return kql, esql


def _proxy_host(cfg: Config, p: Mapping[str, Any]) -> ReportQuery:
    ip = str(p["ip"])
    source, f = _family(p, site.Role.PROXY)
    client = f.source("client_ip")
    return make(cfg, kind="logs", source=source, index=cfg.log_index(source),
                kql=f"{client} : {kql_str(ip)}", where=_ip_eq(client, ip),
                start=_t(p, "start"), end=_t(p, "end"), template="proxy.host@1",
                time_field=f.time)  # fmt: skip


def _proxy_destination(cfg: Config, p: Mapping[str, Any]) -> ReportQuery:
    ip = str(p["ip"])
    source, f = _family(p, site.Role.PROXY)
    server = f.source("server_ip")
    return make(cfg, kind="logs", source=source, index=cfg.log_index(source),
                kql=f"{server} : {kql_str(ip)}", where=_ip_eq(server, ip),
                start=_t(p, "start"), end=_t(p, "end"), template="proxy.destination@1",
                time_field=f.time)  # fmt: skip


def _proxy_pair(cfg: Config, p: Mapping[str, Any]) -> ReportQuery:
    host, dest = str(p["host"]), str(p["destination"])
    source, f = _family(p, site.Role.PROXY)
    client, server = f.source("client_ip"), f.source("server_ip")
    return make(cfg, kind="logs", source=source, index=cfg.log_index(source),
                kql=f"{client} : {kql_str(host)} and {server} : {kql_str(dest)}",
                where=f"{_ip_eq(client, host)} AND {_ip_eq(server, dest)}",
                start=_t(p, "start"), end=_t(p, "end"), template="proxy.pair@1",
                time_field=f.time)  # fmt: skip


def _proxy_contact(cfg: Config, p: Mapping[str, Any]) -> ReportQuery:
    dest = str(p["destination"])
    hosts = [str(h) for h in p.get("hosts") or []]
    source, f = _family(p, site.Role.PROXY)
    client, server = f.source("client_ip"), f.source("server_ip")
    kql = f"{server} : {kql_str(dest)}"
    where = _ip_eq(server, dest)
    if hosts:
        kql += " and " + kql_any(client, hosts)
        where += f" AND {client} IN (" + ", ".join(esql_str(h) for h in hosts) + ")"
    return make(cfg, kind="logs", source=source, index=cfg.log_index(source), kql=kql,
                where=where, start=_t(p, "start"), end=_t(p, "end"),
                template="proxy.contact@1", time_field=f.time)  # fmt: skip


def _dns_host_domains(cfg: Config, p: Mapping[str, Any]) -> ReportQuery:
    source, f = _family(p, site.Role.DNS)
    kql, esql = _either(f, str(p["ip"]))
    return make(cfg, kind="logs", source=source, index=cfg.log_index(source), kql=kql, where=esql,
                start=_t(p, "start"), end=_t(p, "end"), template="dns.host_domains@1",
                time_field=f.time)  # fmt: skip


def _web_followups(cfg: Config, p: Mapping[str, Any]) -> ReportQuery:
    ip = str(p["ip"])
    source, f = _family(p, site.Role.WEB)
    client, code = f.source("client_ip"), f.source("status_code")
    return make(
        cfg, kind="logs", source=source, index=cfg.log_index(source),
        kql=f"{client} : {kql_str(ip)} and {code} >= 200 and {code} < 300",
        where=f"{_ip_eq(client, ip)} AND {code} >= 200 AND {code} < 300",
        start=_t(p, "start"), end=_t(p, "end"), template="web.followups@1",
        tail=f"| SORT {f.time} ASC | LIMIT 100", time_field=f.time,
    )  # fmt: skip


def _web_path_outcomes(cfg: Config, p: Mapping[str, Any]) -> ReportQuery:
    ip, host = str(p["ip"]), str(p["site"])
    paths = [str(x) for x in p.get("paths") or []]
    source, f = _family(p, site.Role.WEB)
    client, domain, path = f.source("client_ip"), f("domain"), f.source("url_path")
    return make(
        cfg, kind="logs", source=source, index=cfg.log_index(source),
        kql=f"{client} : {kql_str(ip)} and {domain} : {kql_str(host)} and "
            + kql_any(path, paths),
        where=f"{_ip_eq(client, ip)} AND {domain} == {esql_str(host)}"
              f" AND {path} IN (" + ", ".join(esql_str(x) for x in paths) + ")",
        start=_t(p, "start"), end=_t(p, "end"), template="web.path_outcomes@1",
        time_field=f.time,
    )  # fmt: skip


def _logs_source_events(cfg: Config, p: Mapping[str, Any]) -> ReportQuery:
    source, ip = str(p["source"]), str(p["ip"])
    family = site.active().family(source)
    role = family.role if family is not None else site.Role.PROXY
    f = family.resolved() if family is not None else site.default_fields(role)
    if role is site.Role.DNS:
        kql, where = _either(f, ip)
    else:
        client = f.source("client_ip")
        kql, where = f"{client} : {kql_str(ip)}", _ip_eq(client, ip)
    for field_, value in p.get("narrow") or []:
        number = str(field_) == "destination.port" and str(value).isdigit()
        kql += f" and {field_} : " + (str(int(value)) if number else kql_str(value))
        where += f" AND {field_} == " + (str(int(value)) if number else esql_str(value))
    return make(cfg, kind="logs", source=source, index=cfg.log_index(source), kql=kql,
                where=where, start=_t(p, "start"), end=_t(p, "end"),
                template="logs.source_events@1", time_field=f.time,
                tail=f"| SORT {f.time} ASC | LIMIT 100")  # fmt: skip


def _ti_lookup(cfg: Config, p: Mapping[str, Any], at: datetime) -> ReportQuery:
    """The look-up as a Discover query over the sources it asked (the stored parameters name
    them; a request from before sources were settings meant the site's default ``ioc`` one)."""
    values = [str(v) for v in p.get("values") or []]
    names = [str(n) for n in p.get("indices") or []]
    if not names:
        default = site.active().ti_default_lookup
        if default is None:
            raise ValueError("no threat-intel source to link to")
        names = [default.index]
    index = ",".join(names)
    shape = str(p.get("shape") or "ioc")
    start, end = at - TI_RANGE, at + timedelta(minutes=1)
    kql_parts: list[str] = []
    esql_parts: list[str] = []
    if shape in ("ioc", "both"):
        kql_parts.append(kql_any("ioc_value.keyword", values))
        esql_parts.append("ioc_value.keyword IN (" + ", ".join(esql_str(v) for v in values) + ")")
    if shape in ("ecs", "both"):
        for field_, asked in sorted(ecs_terms(tuple(values)).items()):
            kql_parts.append(kql_any(field_, asked))
            esql_parts.append(f"{field_} IN (" + ", ".join(esql_str(v) for v in asked) + ")")
    if not kql_parts:
        raise ValueError("no value a threat-intel source can be asked")
    kql = " or ".join(kql_parts)
    esql = f"FROM {index} | WHERE " + " OR ".join(esql_parts) + " | LIMIT 100"
    has_view = "ti" in cfg.views
    return ReportQuery(
        kind="intel", language="kql" if has_view else "esql", index=index,
        text=kql if has_view else esql, other=esql if has_view else kql, time_from=start,
        time_to=end,
        url=discover_url(cfg, language="kql" if has_view else "esql", index=index,
                         text=kql, esql=esql, start=start, end=end, source="ti"),
        template="ti.lookup@1",
    )  # fmt: skip


_BUILDERS: dict[str, Callable[[Config, Mapping[str, Any]], ReportQuery]] = {
    "proxy.host": _proxy_host,
    "proxy.destination": _proxy_destination,
    "proxy.pair": _proxy_pair,
    "proxy.contact": _proxy_contact,
    "dns.host_domains": _dns_host_domains,
    "web.followups": _web_followups,
    "web.path_outcomes": _web_path_outcomes,
    "logs.source_events": _logs_source_events,
}
TEMPLATES = tuple(sorted((*_BUILDERS, "ti.lookup")))


def for_template(
    cfg: Config, template: str, version: int, params: Mapping[str, Any], ran_at: datetime
) -> ReportQuery | None:
    """The query the evidence template ``template`` ran with ``params`` (the stored ones), or
    None when this ARGUS has no query for it or its parameters cannot be read: the line is then
    left out of the report's evidence and counted in its limits, never invented."""
    try:
        if template == "ti.lookup":
            return _ti_lookup(cfg, params, ran_at)
        build = _BUILDERS.get(template)
        if build is None:
            return None
        found = build(cfg, params)
        return found.model_copy(update={"template": f"{template}@{version}"})
    except (KeyError, TypeError, ValueError):
        return None


# ----------------------------------------------------------------------------- alerts


def alerts_query(cfg: Config, rule_names: list[str], start: datetime, end: datetime) -> ReportQuery:
    """The stored alerts of the case's rules in Discover (the alerts index of the space)."""
    names = sorted({n for n in rule_names if n})[:8]
    kql = kql_any(ALERT_FIELD, names) if names else "*"
    where = f"{ALERT_FIELD} IN (" + ", ".join(esql_str(n) for n in names) + ")" if names else "true"
    return make(cfg, kind="alerts", source="alerts", index=cfg.alerts_index, kql=kql,
                where=where, start=start, end=end + timedelta(minutes=1), template="alerts",
                tail="| SORT @timestamp ASC | LIMIT 200")  # fmt: skip


def tag_query(cfg: Config, incident_id: str, start: datetime, end: datetime) -> ReportQuery:
    """The case's alerts by the incident tag (set when the case is posted to Kibana). The tags
    field holds many values, so the ES|QL form expands it before it compares."""
    return make(cfg, kind="alerts", source="alerts", index=cfg.alerts_index,
                kql=f"{TAG_FIELD} : {kql_str(incident_id)}", where="true", start=start,
                end=end + timedelta(minutes=1), template="alerts",
                tail=f"| MV_EXPAND {TAG_FIELD} | WHERE {TAG_FIELD} == {esql_str(incident_id)}"
                     " | LIMIT 200")  # fmt: skip
