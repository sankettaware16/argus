"""Reading the SIEM's answers (plan §5.3): HTTP errors become typed errors, and a search answer
that is not complete is never data (D-023: unknown is not negative).

Error bodies are read for their ``type`` names only; Elasticsearch's ``reason`` texts can quote
the query, so they are never kept.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from argus.gateway.errors import (
    AuthFailedError,
    OverloadedError,
    PartialResultError,
    ResponseError,
    SiemError,
    SourceMissingError,
    TransportFailedError,
)
from argus.gateway.templates import Endpoint

OVERLOAD_TYPES = frozenset(
    {"circuit_breaking_exception", "es_rejected_execution_exception", "too_many_requests"}
)


def error_types(body: Any) -> tuple[str, ...]:
    """The ``type`` of the error and of its root causes, in order, without duplicates."""
    error = body.get("error") if isinstance(body, Mapping) else None
    if not isinstance(error, Mapping):
        return ()
    found: list[str] = []
    for item in [error, *(error.get("root_cause") or [])]:
        kind = item.get("type") if isinstance(item, Mapping) else None
        if isinstance(kind, str) and kind not in found and len(kind) <= 100:
            found.append(kind)
    return tuple(found)


def parse_json(raw: bytes) -> Any:
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return None


def check_status(status: int, body: Any, *, missing: str = "source_expired") -> None:
    """Raise the typed error for a non-2xx answer. A 404 for a missing index is ``missing``:
    ``source_expired`` for a daily family (ILM deleted the day), ``source_missing`` for a data
    stream or alias (it was never there, was renamed or is mistyped: that says nothing about
    retention)."""
    if 200 <= status < 300:
        return
    types = error_types(body)
    if status in (401, 403):
        raise AuthFailedError(f"HTTP {status}")
    if status == 429 or OVERLOAD_TYPES.intersection(types):
        raise OverloadedError(f"HTTP {status} {types[0] if types else ''}".rstrip())
    if status == 404 and "index_not_found_exception" in types:
        raise SourceMissingError(missing, ())
    if status in (502, 503, 504):
        raise TransportFailedError(f"HTTP {status}", retriable=status != 504)
    raise SiemError(status, types[0] if types else None)


def check_complete(endpoint: Endpoint, body: Any) -> None:
    """The complete-results contract: partial answers raise PartialResultError."""
    if not isinstance(body, Mapping):
        raise ResponseError("the answer is not a JSON object")
    if endpoint is Endpoint.SEARCH:
        if body.get("timed_out") is not False:
            raise PartialResultError("the search timed out (or did not say it did not)")
        if body.get("terminated_early"):
            raise PartialResultError("the search terminated early")
        shards = body.get("_shards")
        if not isinstance(shards, Mapping):
            raise PartialResultError("the answer has no shard summary")
        total, ok, skipped, failed = (
            shards.get(key) for key in ("total", "successful", "skipped", "failed")
        )
        skipped = 0 if skipped is None else skipped
        if not all(isinstance(n, int) and n >= 0 for n in (total, ok, skipped, failed)):
            raise PartialResultError("the shard summary is malformed")
        if failed or ok + skipped < total or total == 0:  # type: ignore[operator]
            raise PartialResultError("shards failed or were not searched")
        hits = body.get("hits")
        if not isinstance(hits, Mapping) or not isinstance(hits.get("hits"), list):
            raise PartialResultError("the answer has no hits list")
    elif endpoint is Endpoint.MGET:
        docs = body.get("docs")
        if not isinstance(docs, list):
            raise PartialResultError("the answer has no docs list")
        for doc in docs:
            if not isinstance(doc, Mapping) or "error" in doc or "found" not in doc:
                raise PartialResultError("a document could not be read")


def took_ms(endpoint: Endpoint, body: Any, elapsed_ms: float) -> int:
    """Server time to charge: the search's own ``took``, otherwise the measured round trip
    (an upper bound of the server's work)."""
    if endpoint is Endpoint.SEARCH and isinstance(body, Mapping):
        took = body.get("took")
        if isinstance(took, int) and not isinstance(took, bool) and took >= 0:
            return took
    return max(int(elapsed_ms + 0.999), 0)
