"""Builders for the gap detector's and the wave's unit tests: a dossier body as the generic pack
stores it (facts, the pack's context, signals, the note's steps, the evidence references)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from argus.investigation import catalogue
from tests.unit.report.kit import signal

NOW = datetime(2026, 10, 24, 14, 0, tzinfo=UTC)
FIRST = NOW - timedelta(hours=5)
LAST = NOW - timedelta(hours=3)
SQUID = ("acme-logs-squid-*",)
NGINX = ("acme-logs-nginx-*",)
DNS = ("acme-logs-dns-*",)
HOST = "10.20.3.4"
C2 = "185.220.101.5"


def facts(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "investigation_id": "00000000-0000-0000-0000-000000000001",
        "version": 1,
        "rule_id": "r1",
        "rule_name": "A rule",
        "alert_count": 4,
        "duplicate_count": 0,
        "late_arrivals": 0,
        "span_minutes": 120,
        "entity_counts": {"ip": 2},
        "first_event_at": FIRST.isoformat(),
        "last_event_at": LAST.isoformat(),
        "severity": "medium",
    }
    base.update(over)
    return base


def pack_context(indices: Sequence[str] = SQUID, **over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "indices": list(indices),
        "fields": {
            "source.ip": {"alerts": 4, "distinct": 1, "top": [[HOST, 4]]},
            "destination.ip": {"alerts": 4, "distinct": 1, "top": [[C2, 4]]},
            "url.domain": {"alerts": 4, "distinct": 1, "top": [["site.example", 4]]},
            "url.path": {"alerts": 4, "distinct": 2, "top": [["/wp-login.php", 3], ["/x", 1]]},
        },
        "ips": {HOST: {"class": "campus", "asset": None}, C2: {"class": "public", "asset": None}},
        "ti": {"values": [], "answers": [], "listed": []},
        "earlier_logs": {},
    }
    base.update(over)
    return base


TEXTS = {
    "timeline": "Is the traffic periodic, a beacon at a regular interval?",
    "prevalence": "How many other hosts reached the same URL?",
    "reputation": "Check the destination's reputation on threat intel.",
    "log_pivot": "Pivot to the access logs for this client.",
}


TI_UNANSWERED = {
    "values": [["ip", "185.220.101.5"]],
    "answers": [{"sources": {"acme-threat-intel": {"not_checked": {}}}}],
    "listed": [],
}  # one value acme-threat-intel has not been asked about: a live lookup could close it


def step(number: int, status: str, needs: Sequence[str] = (), text: str = "") -> dict[str, Any]:
    wording = text or " ".join(TEXTS[n] for n in needs) or f"Look at step {number}."
    return {
        "number": number,
        "text": wording,
        "fields": [],
        "status": status,
        "sentence": "…",
        "needs": list(needs),
    }


def ref(template: str, status: str = "ok", version: int = 1) -> dict[str, Any]:
    return {"task_key": "a" * 64, "template": f"{template}@{version}", "status": status,
            "coverage": {}, "row_count": 1, "truncated": False, "result_hash": None}  # fmt: skip


def body(
    signals: Sequence[Mapping[str, Any]] = (),
    steps: Sequence[Mapping[str, Any]] = (),
    evidence: Sequence[Mapping[str, Any]] = (),
    indices: Sequence[str] = SQUID,
    **context: Any,
) -> dict[str, Any]:
    pack = pack_context(indices, **context)
    pack.setdefault("steps", [{"number": x["number"], "text": x["text"], "fields": []}
                              for x in steps])  # fmt: skip
    return {
        "facts": facts(),
        "context": {"pack": pack, "related_total": 0, "supernode_entities": 0, "continues": None},
        "local_signals": [signal("alert_count", 4)],
        "signals": list(signals),
        "report": {"steps": list(steps), "has_note": bool(steps)},
        "evidence": list(evidence),
        "pack": "generic@12",
    }


def unknown(name: str, reason: str) -> dict[str, Any]:
    return signal(name, status="unknown", reason=reason)


def material(
    indices: Sequence[str] = SQUID,
    rule_type: str | None = None,
    normalized: Mapping[str, Any] | None = None,
    **context: Any,
) -> catalogue.Material:
    return catalogue.Material(
        facts=facts(), pack=pack_context(indices, **context), now=NOW,
        rule_type=rule_type, normalized=normalized,
    )  # fmt: skip


ALL_ON = catalogue.Switches(
    templates=frozenset({"proxy.pair", "proxy.contact", "dns.host_domains", "web.path_outcomes",
                         "logs.source_events"}),
    proxy_aggregations=True, log_queries=True, ti_sync=True,
)  # fmt: skip
