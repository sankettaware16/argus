"""Kibana's costs on the local tier, relative only (Q-A3, plan §7.8, DQ21 (a) under D-110).

The local Kibana 8.19.12 tier (Q-D1) is not the SIEM: its absolute times say nothing about
production, so every call is reported as a multiple of a baseline call (``GET /api/status``)
timed in the same rounds, interleaved so that drift on this shared machine cancels out. The
calls are the ones ARGUS's Kibana lanes will make (case reads, and the case writes of W1 and
W2), against the tier's space (``site.space``), on cases tagged ``argus-measure`` that it
makes itself. Production's own costs are measured during Q-D3's read-only days and each canary
(plan §7.8), and allowances are adopted only then.

Only a loopback ``https`` URL is accepted: this code never reaches the SIEM.
"""

from __future__ import annotations

import contextlib
import ipaddress
import math
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx

from argus import site

TAG = "argus-measure"
OWNER = "securitySolution"
NO_CONNECTOR = {"id": "none", "name": "none", "type": ".none", "fields": None}
BASELINE = "status"
HEADERS = {"kbn-xsrf": "argus-measure", "elastic-api-version": "2023-10-31"}

Kind = Literal["baseline", "read", "write"]


def loopback_url(url: str) -> str:
    """``https://<loopback host>[:<port>]`` only; anything else is refused."""
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError(f"{url!r}: the local tier is reached over https only")
    try:
        loopback = ipaddress.ip_address(parts.hostname).is_loopback
    except ValueError:
        loopback = parts.hostname == "localhost"
    if not loopback:
        raise ValueError(f"{url!r}: Kibana's costs are measured on the local tier only")
    try:
        parts.port  # noqa: B018 - raises ValueError when out of range
    except ValueError:
        raise ValueError(f"{url!r}: not a port") from None
    if "@" in parts.netloc or url.rstrip("/") != f"https://{parts.netloc}":
        raise ValueError(f"{url!r}: give https://<loopback host>:<port> only")
    return url.rstrip("/")


@dataclass
class Context:
    """What earlier calls returned and later ones need."""

    run: str
    case_id: str | None = None
    version: str | None = None
    tags_on: bool = False


@dataclass(frozen=True)
class Call:
    name: str
    kind: Kind
    method: str
    path: str  # {space} and {case_id} are filled in
    body: Callable[[Context], Any] | None = None


def _create(ctx: Context) -> Any:
    return {
        "title": f"ARGUS cost measurement {ctx.run}",
        "description": "Made by measure_capacity.py on the local tier (Q-A3).",
        "tags": [TAG, f"run:{ctx.run}"],
        "owner": OWNER,
        "severity": "low",
        "connector": NO_CONNECTOR,
        "settings": {"syncAlerts": False},
    }


def _comment(ctx: Context) -> Any:
    return {"type": "user", "comment": "Cost measurement comment.", "owner": OWNER}


def _patch(ctx: Context) -> Any:
    ctx.tags_on = not ctx.tags_on
    tags = [TAG, f"run:{ctx.run}", *(["measured"] if ctx.tags_on else [])]
    return {"cases": [{"id": ctx.case_id, "version": ctx.version, "tags": tags}]}


CASES = "/s/{space}/api/cases"
CALLS: tuple[Call, ...] = (
    Call(BASELINE, "baseline", "GET", "/api/status"),
    Call("case.create", "write", "POST", CASES, _create),
    Call("case.get", "read", "GET", CASES + "/{case_id}"),
    Call("cases.find", "read", "GET", CASES + "/_find?perPage=20&tags=" + TAG),
    Call("case.comment", "write", "POST", CASES + "/{case_id}/comments", _comment),
    Call("case.comments", "read", "GET", CASES + "/{case_id}/comments/_find?perPage=20"),
    Call("case.update", "write", "PATCH", CASES, _patch),
)


class TierError(RuntimeError):
    pass


@dataclass(frozen=True)
class Cost:
    name: str
    kind: Kind
    samples: int
    median_ms: float
    p95_ms: float
    relative_median: float
    relative_p95: float


@dataclass
class Measurement:
    costs: list[Cost] = field(default_factory=list)
    rounds: int = 0
    notes: list[str] = field(default_factory=list)


def _nearest(values: Sequence[float], q: float) -> float:
    ordered = sorted(values)
    return ordered[max(math.ceil(q * len(ordered)) - 1, 0)]


def _remember(ctx: Context, body: Any) -> None:
    """Keep the case's id and newest version from an answer that carries the case."""
    case = body[0] if isinstance(body, list) and body else body
    if isinstance(case, dict) and isinstance(case.get("version"), str):
        if ctx.case_id is None and isinstance(case.get("id"), str):
            ctx.case_id = case["id"]
        if case.get("id") == ctx.case_id:
            ctx.version = case["version"]


def measure(
    client: httpx.Client,
    *,
    run: str,
    rounds: int = 5,
    calls: Sequence[Call] = CALLS,
    timer: Callable[[], float] = time.perf_counter,
) -> Measurement:
    """``rounds`` rounds of every call, each round: the baseline, then the calls in order (a
    round makes one case, so the writes measure a fresh case each time)."""
    if rounds < 3:
        raise ValueError("at least 3 rounds: a p95 needs 3 samples")
    if not calls or calls[0].name != BASELINE:
        raise ValueError("the baseline call comes first")
    times: dict[str, list[float]] = {call.name: [] for call in calls}
    result = Measurement(rounds=rounds)
    for _ in range(rounds):
        ctx = Context(run)
        for call in calls:
            if "{case_id}" in call.path and ctx.case_id is None:
                raise TierError(f"{call.name}: no case to work on (case.create did not answer)")
            path = call.path.format(space=site.active().space, case_id=ctx.case_id)
            body = call.body(ctx) if call.body is not None else None
            started = timer()
            reply = client.request(call.method, path, json=body, headers=HEADERS)
            elapsed = (timer() - started) * 1000
            if not 200 <= reply.status_code < 300:
                raise TierError(f"{call.name}: HTTP {reply.status_code}")
            with contextlib.suppress(ValueError):  # a body that is not JSON carries no case
                _remember(ctx, reply.json())
            times[call.name].append(elapsed)
    base = times[BASELINE]
    base_median, base_p95 = _nearest(base, 0.5), _nearest(base, 0.95)
    for call in calls:
        values = times[call.name]
        median, p95 = _nearest(values, 0.5), _nearest(values, 0.95)
        result.costs.append(
            Cost(
                call.name,
                call.kind,
                len(values),
                round(median, 1),
                round(p95, 1),
                round(median / base_median, 2) if base_median > 0 else math.inf,
                round(p95 / base_p95, 2) if base_p95 > 0 else math.inf,
            )
        )
    result.notes.append(
        f"{rounds} cases tagged {TAG} were made in the tier's {site.active().space} space"
        " (the tier is"
        " throwaway: `scripts/kibana_tier.py reset --yes` clears them)"
    )
    return result


def lines(result: Measurement) -> list[str]:
    out = [
        "Kibana call costs on the local tier, relative to GET /api/status (median, p95);"
        " absolute times on this machine say nothing about the SIEM:",
    ]
    for cost in result.costs:
        if cost.kind == "baseline":
            continue
        out.append(f"  {cost.name} ({cost.kind}): x{cost.relative_median:g} median,"
                   f" x{cost.relative_p95:g} p95 over {cost.samples} calls")  # fmt: skip
    out.extend(f"  note: {note}" for note in result.notes)
    return out


def to_json(result: Measurement) -> dict[str, Any]:
    return {
        "format": 1,
        "relative_to": "GET /api/status",
        "rounds": result.rounds,
        "costs": [
            {
                "name": c.name,
                "kind": c.kind,
                "samples": c.samples,
                "relative_median": c.relative_median,
                "relative_p95": c.relative_p95,
            }
            for c in result.costs
            if c.kind != "baseline"
        ],
        "notes": list(result.notes),
    }


def client(url: str, ca_file: str, username: str, password: str) -> httpx.Client:
    """A client for the local tier only: loopback URL, the tier's CA, no proxy, no redirect."""
    return httpx.Client(
        base_url=loopback_url(url),
        verify=ca_file,
        auth=(username, password),
        headers=HEADERS,
        timeout=30.0,
        trust_env=False,
        follow_redirects=False,
    )
