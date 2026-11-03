"""Builders for report@2's unit tests: evidence rows, requests and signals as the store and the
packs make them."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from argus.context import proxy, web
from argus.gateway.templates import task_key
from argus.reference.templates import LOOKUP_SIZE, LookupParams, TiLookup
from argus.report.facts import EvidenceRow, Keys, RequestRow

T0 = datetime(2026, 10, 9, 10, 0, tzinfo=UTC)
T1 = T0 + timedelta(hours=3)


def host_params(ip: str = "10.20.3.4") -> proxy.WindowParams:
    return proxy.WindowParams(ip=ip, start=T0, end=T1)


def follow_params(ip: str = "185.220.101.5") -> web.FollowParams:
    return web.FollowParams(ip=ip, start=T0, end=T1)


def lookup_params(*values: str) -> LookupParams:
    return LookupParams(values=tuple(sorted(values or ("45.9.9.9",))), size=LOOKUP_SIZE)


TEMPLATES: dict[str, Any] = {
    "proxy.host": (proxy.ProxyHost, host_params),
    "proxy.destination": (proxy.ProxyDestination, lambda: host_params("45.9.9.9")),
    "web.followups": (web.WebFollowups, follow_params),
    "ti.lookup": (TiLookup, lookup_params),
}


def key_of(name: str) -> str:
    cls, params = TEMPLATES[name]
    return task_key(cls(), params())


def row(name: str, status: str = "ok", **over: Any) -> EvidenceRow:
    cls, params = TEMPLATES[name]
    base: dict[str, Any] = {
        "task_key": key_of(name),
        "version": 1,
        "template": name,
        "template_version": cls.version,
        "params": params().model_dump(mode="json"),
        "status": status,
        "coverage": {},
        "row_count": 0 if status in ("ok", "empty") else None,
        "result_hash": "h" * 64 if status in ("ok", "empty") else None,
        "took_ms": 612 if status in ("ok", "empty") else None,
        "collected_at": T1 + timedelta(hours=1),
    }
    base.update(over)
    return EvidenceRow(**base)


def request(name: str, eid: int, origin: str = "pack", **over: Any) -> RequestRow:
    cls, _ = TEMPLATES[name]
    base: dict[str, Any] = {
        "eid": eid,
        "task_key": key_of(name),
        "template": name,
        "template_version": cls.version,
        "origin": origin,
        "first_version": 1,
        "created_at": T1,
    }
    base.update(over)
    return RequestRow(**base)


def keys(*names: str, status: dict[str, str] | None = None) -> Keys:
    from argus.report.facts import is_log

    eid = {key_of(n): f"E{i}" for i, n in enumerate(names, start=1)}
    template = {key_of(n): n for n in names}
    logs = frozenset(key_of(n) for n in names if is_log(n, TEMPLATES[n][0].version))
    return Keys(eid=eid, template=template, logs=logs,
                status={key_of(k): v for k, v in (status or {}).items()})  # fmt: skip


def signal(
    name: str,
    value: Any = None,
    *,
    status: str = "known",
    reason: str | None = None,
    evidence: tuple[str, ...] = (),
    completeness: str = "exact",
) -> dict[str, Any]:
    return {
        "name": name,
        "definition_version": 12,
        "value": value if status == "known" else None,
        "status": status,
        "unknown_reason": reason if status != "known" else None,
        "completeness": completeness,
        "evidence": list(evidence),
    }
