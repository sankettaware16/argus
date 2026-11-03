"""The web module of the generic pack: what an attack on the hosted sites tried,
from the alerts (decoded paths, the NAXSI rule's class, scanner user agents, path
categories, sites), and whether the client then got a successful answer (nginx's logs, one
bounded search, only with ``enrichment.log_queries`` on). For any rule that reads nginx's
logs: the alert names its indices; there is no rule list.
"""

from __future__ import annotations

import ipaddress
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import unquote

from pydantic import Field

from argus.context.evidence import SignalValue, canonical, derived, from_logs, local
from argus.context.packs import TaskSpec
from argus.context.sourced import SourcedParams
from argus.gateway.indices import MAX_DAYS, PAD
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
from argus.site import (
    Fields,
    Role,
    all_fields,
    fields_for,
    reads,
    source_for,
    source_param,
)

FOLLOW = timedelta(hours=6)  # after the first alert: did the client succeed anywhere?
MARGIN = timedelta(minutes=15)
ROWS = 20
# NAXSI's core rules by id (its documentation): what a block was about.
NAXSI = (
    (range(1000, 1010), "SQL injection"),
    (range(1010, 1012), "remote file inclusion"),
    (range(1013, 1016), "directory traversal"),
    (range(1100, 1102), "remote file inclusion or XSS"),
    (range(1200, 1201), "evasion tricks"),
    (range(1302, 1316), "XSS or format string"),
    (range(1, 20), "a malformed request"),
)
SCANNERS = re.compile(
    r"sqlmap|nikto|nuclei|zgrab|masscan|nmap|acunetix|wpscan|dirbuster|gobuster|ffuf|"
    r"feroxbuster|whatweb|httpx|python-requests|go-http-client|curl/|wget/|libwww|"
    r"zmeu|censys|shodan|expanse|l9explore",
    re.IGNORECASE,
)
CATEGORIES = (
    ("traversal", re.compile(r"\.\.[/\\]")),
    (
        "config or backup",
        re.compile(
            r"\.env\b|\.git\b|\.svn\b|\.bak\b|\.old\b|\.sql\b|"
            r"config\.php|web\.config|\.ini\b|wp-config",
            re.I,
        ),
    ),
    ("admin pages", re.compile(r"wp-admin|/admin|phpmyadmin|/manager/|/console", re.I)),
    (
        "command injection",
        re.compile(
            r"pearcmd|cmd=|exec=|/bin/sh|;\s*(cat|id|wget)\b|"
            r"\$\{jndi:",
            re.I,
        ),
    ),
    ("cms probes", re.compile(r"wp-|xmlrpc\.php|/joomla|/drupal", re.I)),
)


def iso(at: datetime) -> str:
    return at.astimezone(UTC).isoformat().replace("+00:00", "Z")


def decode(path: str, rounds: int = 3) -> str:
    """Percent-decoding until it stops changing (attacks double-encode: %252f)."""
    for _ in range(rounds):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    return path


def naxsi_class(rule_id: Any) -> str | None:
    try:
        number = int(str(rule_id))
    except ValueError:
        return None
    return next((name for ids, name in NAXSI if number in ids), "another NAXSI rule")


def categories(paths: Sequence[str]) -> list[str]:
    return [name for name, pattern in CATEGORIES if any(pattern.search(p) for p in paths)]


class FollowParams(SourcedParams):
    ROLE = Role.WEB
    ip: str = Field(min_length=2, max_length=45)
    start: datetime
    end: datetime
    size: int = Field(default=ROWS, ge=1, le=ROWS)  # a live test reads at most 10


@register
class WebFollowups(Template):
    """A client's successful (2xx) answers from the hosted sites in a window."""

    name = "web.followups"
    version = 1
    endpoint = Endpoint.SEARCH
    family = Family.LOG
    cost = CostClass.MEDIUM
    params_model = FollowParams
    max_size = ROWS

    @staticmethod
    def returned(fields: Fields | None = None) -> frozenset[str]:
        """The fields a document returns (the paths in ``_source``, never a ``.keyword``): one
        family's, or (no ``fields`` given) every web family's, which the allowlist holds."""
        return frozenset(
            name
            for f in (all_fields(Role.WEB) if fields is None else (fields,))
            for name in (
                f.time,
                f.source("domain"),
                f.source("url_path"),
                f.source("status_code"),
                f.source("method"),
            )
        )

    @classmethod
    def spec(cls) -> Spec:
        fs = all_fields(Role.WEB)
        return replace(
            super().spec(),
            filter_fields=frozenset(
                n for f in fs for n in (f("client_ip"), f.time, f("status_code"))
            ),
            return_fields=cls.returned(),
            sort_fields=frozenset(f.time for f in fs),
        )

    def build(self, params: Params) -> RequestPlan:
        assert isinstance(params, FollowParams)
        f = fields_for(Role.WEB, params.source)
        body = {
            "size": params.size,
            "track_total_hits": False,
            "_source": sorted(self.returned(f)),
            "sort": [{f.time: {"order": "asc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"term": {f("client_ip"): params.ip}},
                        {"range": {f("status_code"): {"gte": 200, "lt": 300}}},
                        {"range": {f.time: {"gte": iso(params.start), "lt": iso(params.end)}}},
                    ]
                }
            },
        }
        return RequestPlan(
            self.spec(),
            body=body,
            window=Window(params.source or source_for(Role.WEB), params.start, params.end),
        )


def applies(indices: Sequence[str]) -> bool:
    """The rule reads a web server log family of the site."""
    return reads(indices, Role.WEB)


def context(docs: Sequence[Mapping[str, Any]], fields: Mapping[str, Any]) -> dict[str, Any]:
    """Local facts of the attack, from the stored alerts."""
    from argus.normalize.fields import values

    paths = [decode(str(v)) for d in docs for v in values(d, "url.path")][:200]
    ids = Counter(str(v) for d in docs for v in values(d, "rule.id"))
    agents = [str(v) for d in docs for v in values(d, "user_agent.original")]
    scanners = sorted({a[:80] for a in agents if SCANNERS.search(a)})[:5]
    return {
        "decoded_paths": sorted(set(paths))[:10],
        "categories": categories(paths),
        "naxsi": [
            {"id": rule_id, "class": naxsi_class(rule_id), "alerts": n}
            for rule_id, n in sorted(ids.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
        ],
        "scanner_agents": scanners,
        "agents": len(set(agents)),
        "sites": [v for v, _ in fields.get("url.domain", {}).get("top", [])],
    }


def _is_ip(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return True


def tasks(
    facts: Mapping[str, Any],
    fields: Mapping[str, Any],
    now: datetime,
    earlier: Mapping[str, Mapping[str, Any]] | None = None,
    indices: Sequence[str] | None = None,
) -> list[TaskSpec]:
    """The client's follow-up search, once per investigation. With several web
    families, the one the rule's ``indices`` name is read."""
    before = (earlier or {}).get(WebFollowups.name)
    if before is not None:
        return [TaskSpec(WebFollowups(), FollowParams.model_validate_json(canonical(before)))]
    clients = [v for v, _ in fields.get("source.ip", {}).get("top", []) if _is_ip(v)]
    span = follow_window(facts, now)
    if span is None or not clients:
        return []
    family = source_param(Role.WEB, indices)
    params = FollowParams(ip=clients[0], start=span[0], end=span[1], source=family)
    return [TaskSpec(WebFollowups(), params)]


def follow_window(facts: Mapping[str, Any], now: datetime) -> tuple[datetime, datetime] | None:
    """From the first alert, ``FOLLOW`` long, not past the ingest margin, within the daily
    indices a search may read; None when nothing of it is old enough."""
    first = facts.get("first_event_at")
    if not first:
        return None
    start = datetime.fromisoformat(str(first)).replace(second=0, microsecond=0)  # not before
    end = min(start + FOLLOW, (now - MARGIN).replace(minute=0, second=0, microsecond=0))
    while end > start and ((end + PAD).date() - (start - PAD).date()).days + 1 > MAX_DAYS:
        end -= timedelta(hours=1)
    return (start, end) if end > start else None


def signals(
    version: int, web: Mapping[str, Any], evidence: Mapping[str, Any], snapshots: Mapping[str, Any]
) -> list[SignalValue]:
    out = [
        local("web.path_categories", version, len(web.get("categories", []))),
        local("web.scanner_agents", version, len(web.get("scanner_agents", []))),
    ]
    for key, ref in evidence.items():
        if str(ref.get("template", "")).startswith("web.followups@"):
            rows: list[Any] = (snapshots.get(key) or {}).get("rows", [])
            found = derived("web.successes_after", version, [ref], rows.__len__, counts=True)
            out.append(from_logs(found))
    return out


def answers(web: Mapping[str, Any], derived_: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    by = {s["name"]: s["value"] for s in derived_ if s.get("status") == "known"}
    told: dict[str, str] = {}
    if "web.successes_after" in by:
        n = by["web.successes_after"]
        told["log_pivot"] = (  # known only when positive (from_logs)
            f"nginx logs: {n} successful (2xx) answers to the client in the hours after the"
            " first alert."
        )
    return told


def summary(web: Mapping[str, Any]) -> list[str]:
    """Plain lines for the Key facts: what was tried, by whom."""
    lines = []
    for item in web.get("naxsi", []):
        lines.append(f"NAXSI rule {item['id']}: {item['class']} ({item['alerts']} alerts)")
    if web.get("categories"):
        lines.append("Paths tried: " + ", ".join(web["categories"]))
    if web.get("scanner_agents"):
        lines.append("Scanner tools: " + ", ".join(web["scanner_agents"]))
    return lines
