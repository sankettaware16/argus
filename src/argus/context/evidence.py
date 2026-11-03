"""Evidence records and signals: content-addressed task keys, what a
gateway outcome means for one task, the order-independent fan-in, bounded snapshots, and the
rule that a signal is never known (or 0, or false) on evidence that is not complete.

Everything here is pure; the graph state holds only the plain dicts built here.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from argus.gateway.errors import (
    AuthFailedError,
    BreakerOpenError,
    BudgetExhaustedError,
    DeadlinePassedError,
    DeferredError,
    GatewayError,
    LiveSessionError,
    OverloadedError,
    PartialResultError,
    SourceMissingError,
    StoppedError,
    TemplateRejectedError,
    TimedOutError,
    UnsupportedValueError,
)

# The task key's home is the gateway (the ledger records it); re-exported here.
from argus.gateway.templates import task_key as task_key

COMPLETE = frozenset({"ok", "empty"})
# Lower is better: the fan-in keeps the better of two results for one task key.
STATUS_RANK = {
    "ok": 0,
    "empty": 0,
    "source_lag": 1,
    "timeout": 2,
    "failed": 2,
    "skipped_budget": 3,
    "deferred": 3,
    "source_expired": 4,
    "unsupported_value": 4,
}
RUN_LEVEL: tuple[type[GatewayError], ...] = (
    StoppedError,
    DeferredError,
    BreakerOpenError,
    AuthFailedError,
    OverloadedError,
    LiveSessionError,
)


class SourceUnavailable(Exception):  # noqa: N818 - the name the graph uses
    """The run cannot go on now (the SIEM or Postgres unavailable): the job is deferred, not
    failed, and does not use up an attempt."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class PackBug(Exception):  # noqa: N818 - a defect, not an outcome
    """A pack asked for something the framework refuses (a rejected template, too many tasks,
    an unknown template): a bug, dead-lettered at once."""


def canonical(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def sha256(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Outcome:
    """What one task's gateway call came to (nothing raised: a task-level result)."""

    status: str
    coverage: dict[str, Any]
    error: str | None = None


def outcome_of(exc: GatewayError) -> Outcome:
    """The evidence status for a gateway refusal or failure. Run-level unavailability raises
    SourceUnavailable; a rejected template is a pack bug."""
    if isinstance(exc, RUN_LEVEL):
        raise SourceUnavailable(exc.reason) from exc
    if isinstance(exc, TemplateRejectedError):
        raise PackBug(f"template rejected: {exc}") from exc
    if isinstance(exc, UnsupportedValueError):
        return Outcome("unsupported_value", {}, exc.reason)
    if isinstance(exc, BudgetExhaustedError):
        return Outcome("skipped_budget", {}, exc.reason)
    if isinstance(exc, DeadlinePassedError | TimedOutError):
        return Outcome("timeout", {"timed_out": True}, exc.reason)
    if isinstance(exc, SourceMissingError):
        # only a day that ILM deleted is final; a day not made yet and a data stream that is not
        # there (``source_missing``) can come back, so they are "lag", asked again
        status = "source_expired" if exc.reason == "source_expired" else "source_lag"
        return Outcome(status, {"missing_indices": list(exc.days)}, exc.reason)
    if isinstance(exc, PartialResultError):
        return Outcome("failed", {"partial": True}, exc.reason)
    return Outcome("failed", {}, exc.reason)


# ----------------------------------------------------------------------------- snapshots


@dataclass(frozen=True)
class Extract:
    snapshot: dict[str, Any]
    row_count: int
    truncated: bool
    result_hash: str
    exact_total: bool
    has_data: bool  # anything matched: a total above 0, or (without a total) rows/aggregations


_UNSTORABLE = re.compile("[\x00\ud800-\udfff]")  # NUL and lone surrogates: not in JSONB/UTF-8


def clean(value: Any) -> Any:
    """``value`` with every string (keys too) storable: NUL and lone surrogates become U+FFFD."""
    if isinstance(value, str):
        return _UNSTORABLE.sub("\ufffd", value)
    if isinstance(value, dict):
        return {clean(k) if isinstance(k, str) else k: clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [clean(v) for v in value]
    return value


def extract(body: Any, *, max_rows: int, max_bytes: int) -> Extract:
    """A bounded snapshot of a search or mget answer: at most ``max_rows`` rows and
    ``max_bytes`` of canonical JSON. The hash covers the whole answer's content (rows, total,
    aggregations), never ``took`` or shard counts, so the same data hashes the same. Strings
    that Postgres cannot store are cleaned first (``clean``). ``rows_complete`` says whether
    the answer held every matching row (a query's ``size`` may be below its total)."""
    body = clean(body) if isinstance(body, dict) else {}
    hits_part = body.get("hits") if isinstance(body.get("hits"), dict) else {}
    hits: list[Any] = hits_part["hits"] if isinstance(hits_part.get("hits"), list) else []
    docs: list[Any] | None = body["docs"] if isinstance(body.get("docs"), list) else None
    rows = [
        {"_index": h.get("_index"), "_id": h.get("_id"), "_source": h.get("_source")}
        for h in (hits if docs is None else docs)
        if isinstance(h, dict) and (docs is None or h.get("found", True))
    ]
    total = hits_part.get("total")
    exact = True
    counted = True
    if isinstance(total, dict) and isinstance(total.get("value"), int):
        count = total["value"]
        exact = total.get("relation", "eq") == "eq"
    elif isinstance(total, int):
        count = total
    else:
        count, counted = len(rows), False
    aggregations = body.get("aggregations")
    has_data = count > 0 if counted else bool(rows or aggregations)
    content = {"total": count, "exact": exact, "rows": rows, "aggregations": aggregations}
    head = {"total": count, "rows_complete": exact and len(rows) >= count}
    kept = rows[:max_rows]
    truncated = len(kept) < len(rows)
    snapshot: dict[str, Any] = {**head, "rows": kept, "aggregations": aggregations}
    while kept and len(canonical(snapshot).encode("utf-8")) > max_bytes:
        kept = kept[: len(kept) // 2]
        snapshot = {**head, "rows": kept, "aggregations": aggregations}
        truncated = True
    if aggregations is not None and len(canonical(snapshot).encode("utf-8")) > max_bytes:
        snapshot = {**head, "rows": [], "aggregations": None, "dropped": "too_large"}
        truncated = True
    return Extract(snapshot, count, truncated, sha256(content), exact, has_data)


# ----------------------------------------------------------------------------- fan-in


def content(ref: Mapping[str, Any]) -> dict[str, Any]:
    """What a dossier's hash covers of an evidence reference: not whether it was reused."""
    return {k: v for k, v in ref.items() if k != "reused"}


def _rank(ref: Mapping[str, Any]) -> tuple[int, str]:
    return STATUS_RANK.get(ref["status"], 9), canonical(ref)


def merge_evidence(
    left: Mapping[str, Mapping[str, Any]] | None, right: Mapping[str, Mapping[str, Any]] | None
) -> dict[str, Any]:
    """The fan-in reducer: a dict merge keyed by task key. On a clash the better status wins,
    then the canonical form: commutative and associative, so the completion order of the
    evidence tasks cannot change the result."""
    merged: dict[str, Any] = dict(left or {})
    for key, ref in (right or {}).items():
        mine = merged.get(key)
        merged[key] = ref if mine is None else min(mine, ref, key=_rank)
    return merged


# ----------------------------------------------------------------------------- signals


@dataclass(frozen=True)
class SignalValue:
    name: str
    definition_version: int
    value: Any
    status: str  # known | unknown
    unknown_reason: str | None
    completeness: str
    evidence: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "definition_version": self.definition_version,
            "value": self.value,
            "status": self.status,
            "unknown_reason": self.unknown_reason,
            "completeness": self.completeness,
            "evidence": list(self.evidence),
        }


def unknown(name: str, version: int, reason: str, evidence: Iterable[str] = ()) -> SignalValue:
    return SignalValue(name, version, None, "unknown", reason, "exact", tuple(sorted(evidence)))


def local(name: str, version: int, value: Any) -> SignalValue:
    """A signal from ARGUS's own store (the alerts it holds): known, exact."""
    if value is None:
        return unknown(name, version, "no_value")
    return SignalValue(name, version, value, "known", None, "exact", ())


def derived(
    name: str,
    version: int,
    refs: Iterable[Mapping[str, Any]],
    compute: Callable[[], Any],
    *,
    counts: bool = False,
) -> SignalValue:
    """A signal from evidence. Any contributing evidence not ``ok``/``empty`` makes it
    unknown, with that status as the reason. Evidence that is complete in status but partial
    in coverage (truncated rows, an inexact total, a coverage flag) makes it unknown too, except
    a positive count (``counts=True``), which stays known as a lower bound: "at least 5" is a
    finding, "at least 0" is not."""
    refs = sorted(refs, key=lambda r: str(r["task_key"]))
    keys = tuple(str(r["task_key"]) for r in refs)
    if not refs:
        return unknown(name, version, "no_evidence")
    bad = sorted({str(r["status"]) for r in refs} - COMPLETE)
    if bad:
        return unknown(name, version, bad[0], keys)
    partial = any(r.get("truncated") or r.get("coverage") for r in refs)
    value = compute()
    if value is None:
        return unknown(name, version, "no_value", keys)
    if not partial:
        return SignalValue(name, version, value, "known", None, "exact", keys)
    positive = isinstance(value, int | float) and not isinstance(value, bool) and value > 0
    if counts and positive:
        return SignalValue(name, version, value, "known", None, "lower_bound", keys)
    return unknown(name, version, "partial_coverage", keys)


class Known:
    """The known signals among derived signals (dicts), for sentences: ``by`` holds their
    values, and ``count`` says a count as a sentence must ("at least 5" when the evidence
    only shows a lower bound)."""

    def __init__(self, derived_: Iterable[Mapping[str, Any]]) -> None:
        known = [s for s in derived_ if s.get("status") == "known"]
        self.by: dict[str, Any] = {s["name"]: s["value"] for s in known}
        self.low = frozenset(s["name"] for s in known if s.get("completeness") == "lower_bound")

    def count(self, name: str, one: str = "", many: str = "") -> str:
        """``name``'s value, with "at least" for a lower bound, then ``one`` or ``many``."""
        value = self.by[name]
        noun = (one if value == 1 else many) if one or many else ""
        least = "at least " if name in self.low else ""
        return f"{least}{value}{' ' + noun if noun else ''}"


def from_logs(signal: SignalValue) -> SignalValue:
    """A count from a log search: 0 says nothing until ARGUS measures how far the source's
    ingest has got (a gap in ingest also answers 0), so it is unknown; a positive count
    stands."""
    zero = (
        signal.status == "known"
        and isinstance(signal.value, int | float)
        and not isinstance(signal.value, bool)
        and signal.value == 0
    )
    if zero:
        return unknown(signal.name, signal.definition_version, "ingest_not_verified",
                       signal.evidence)  # fmt: skip
    return signal
