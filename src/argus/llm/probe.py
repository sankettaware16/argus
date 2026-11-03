"""Is a provider there? ``GET /v1/models`` (Q-G1): no prompt, no campus data, the key only.

The local model's machine is sometimes off, its tunnel may be down, a new setup run changes
its certificate and key (D-108), and llama-server answers 503 while it loads the model. The
probe tells these apart, so the gateway defers instead of sending a long call into nothing:

- ``up``: 200 and every configured model is listed;
- ``loading``: 503 (llama-server is loading the model);
- ``unauthorized``: 401 or 403 (the key is not this run's: import the newest hand-over);
- ``tls_failed``: the certificate is not the pinned one (a new run, or someone else);
- ``model_mismatch``: it answers, but without the configured model;
- ``down``: anything else (no connection, a timeout, another status, an unreadable list).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum

from pydantic import SecretStr

from argus.llm.providers import ProviderConfig
from argus.llm.wire import LlmTransport, LlmWire, TransportError

PROBE_TIMEOUT_S = 15.0


class ProbeState(StrEnum):
    UP = "up"
    DOWN = "down"
    LOADING = "loading"
    UNAUTHORIZED = "unauthorized"
    TLS_FAILED = "tls_failed"
    MODEL_MISMATCH = "model_mismatch"


ALARMS = frozenset({ProbeState.UNAUTHORIZED, ProbeState.TLS_FAILED, ProbeState.MODEL_MISMATCH})


@dataclass(frozen=True)
class ProbeResult:
    state: ProbeState
    detail: str
    models: tuple[str, ...] = ()  # the ids the provider listed
    latency_ms: int = 0


def tls_detail(exc: TransportError) -> str:
    """What a ``tls_failed`` means: the served certificate, or the pinned file itself."""
    text = str(exc)
    return "its certificate is not the pinned one" if text == "tls_failed" else text


def _ids(body: bytes) -> tuple[str, ...] | None:
    try:
        data = json.loads(body)
        listed = data["data"]
    except (ValueError, KeyError, TypeError):
        return None
    if not isinstance(listed, list):
        return None
    ids = [m.get("id") for m in listed if isinstance(m, dict)]
    return tuple(i for i in ids if isinstance(i, str))


async def probe(
    provider: ProviderConfig,
    key: SecretStr,
    transport: LlmTransport,
    timeout_s: float = PROBE_TIMEOUT_S,
) -> ProbeResult:
    wire = LlmWire(provider.name, f"{provider.base_url}/models", b"",
                   min(timeout_s, provider.timeout_s))  # fmt: skip
    try:
        reply = await transport.get(wire, key)
    except TransportError as exc:
        if exc.kind == "tls_failed":
            return ProbeResult(ProbeState.TLS_FAILED, tls_detail(exc))
        return ProbeResult(ProbeState.DOWN, f"no answer ({exc})")
    latency = round(reply.elapsed_ms)
    if reply.status in (401, 403):
        return ProbeResult(ProbeState.UNAUTHORIZED, f"the key was refused ({reply.status})",
                           latency_ms=latency)  # fmt: skip
    if reply.status == 503:
        return ProbeResult(ProbeState.LOADING, "loading the model (503)", latency_ms=latency)
    if reply.status != 200:
        return ProbeResult(ProbeState.DOWN, f"answered {reply.status}", latency_ms=latency)
    ids = _ids(reply.body)
    if ids is None:
        return ProbeResult(ProbeState.DOWN, "an unreadable model list", latency_ms=latency)
    wanted = sorted({m.name for m in provider.models.values()})
    missing = [name for name in wanted if name not in ids]
    if missing:
        shown = ", ".join(ids[:5]) or "none"
        return ProbeResult(ProbeState.MODEL_MISMATCH,
                           f"{', '.join(missing)} not listed (it lists {shown[:200]})",
                           ids, latency)  # fmt: skip
    return ProbeResult(ProbeState.UP, f"{', '.join(wanted)} listed", ids, latency)
