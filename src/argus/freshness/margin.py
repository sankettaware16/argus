"""The margin for late logs, derived from each source's lag distribution (Q-F1, DQ19).

Two distributions say how late a source's events arrive:

- **document delays**, ``event.ingested - @timestamp`` of log documents (the captured corpus:
  ``data/corpus/<day>/ancestors.jsonl.gz`` and ``context.jsonl.gz``, one search hit a line);
- **reading lags**, ``at - event_at`` of the freshness lane's readings (``argus freshness
  export``, one reading a line): how far behind the clock the newest arrived event was.

A source's margin is the larger of the two distributions' ``quantile`` (0.999 by default),
times ``factor`` (1.5), never below ``floor`` (2 minutes: Elasticsearch's refresh and the
lane's own timing), rounded up to a whole ``step`` (1 minute). A source with fewer than
``min_n`` values in total gets no margin (it never gets a verified zero) and the reason.
Negative delays (clocks ahead of the ingest node) count as 0. Pure: the script
``scripts/derive_margin.py`` reads the files, and the lead records the result by a decision
(``freshness.margins``).
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from argus.site import source_of_index

QUANTILE = 0.999
FACTOR = 1.5
FLOOR = timedelta(minutes=2)
STEP = timedelta(minutes=1)
MIN_N = 10_000  # review F8: 1,000 let one 4-hour straggler vanish behind p99.9
MIN_DOCUMENTS = 1000  # and the margin rests on documents' delays, never on readings alone
CEILING = timedelta(hours=6)  # freshness.margins' largest value


def quantile(values: Sequence[float], q: float) -> float:
    """The nearest-rank quantile of ``values`` (sorted or not): the smallest value with at
    least ``q`` of them at or below it."""
    if not values:
        raise ValueError("no values")
    if not 0 < q <= 1:
        raise ValueError("a quantile is in (0, 1]")
    ordered = sorted(values)
    rank = max(math.ceil(q * len(ordered)), 1)
    return ordered[rank - 1]


def parse_time(value: Any) -> datetime | None:
    """An Elasticsearch date as ARGUS reads it: ISO 8601 text (no zone is UTC) or epoch
    milliseconds; anything else is None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        if not math.isfinite(value):
            return None
        try:
            return datetime.fromtimestamp(value / 1000, UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, list) and len(value) == 1:
        return parse_time(value[0])
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)


def _field(source: Mapping[str, Any], dotted: str) -> Any:
    if dotted in source:
        return source[dotted]
    value: Any = source
    for part in dotted.split("."):
        if not isinstance(value, Mapping) or part not in value:
            return None
        value = value[part]
    return value


def document_delay(hit: Mapping[str, Any]) -> tuple[str, float] | None:
    """(source, delay in seconds) of one search hit, or None when it is not a log document
    with both times."""
    index = hit.get("_index")
    body = hit.get("_source")
    if not isinstance(index, str) or not isinstance(body, Mapping):
        return None
    source = source_of_index(index)
    if source is None:
        return None
    ingested = parse_time(_field(body, "event.ingested"))
    stamp = parse_time(_field(body, "@timestamp"))
    if ingested is None or stamp is None:
        return None
    return source, max((ingested - stamp).total_seconds(), 0.0)


def reading_lag(row: Mapping[str, Any]) -> tuple[str, float] | None:
    """(source, lag in seconds) of one exported reading with a document, or None."""
    source = row.get("source")
    at = parse_time(row.get("at"))
    event_at = parse_time(row.get("event_at"))
    if row.get("outcome") != "ok" or not isinstance(source, str) or at is None or not event_at:
        return None
    return source, max((at - event_at).total_seconds(), 0.0)


@dataclass(frozen=True)
class Spread:
    n: int
    p50: float
    p90: float
    p99: float
    p999: float
    max: float

    @classmethod
    def of(cls, values: Sequence[float]) -> Spread:
        return cls(
            len(values),
            quantile(values, 0.5),
            quantile(values, 0.9),
            quantile(values, 0.99),
            quantile(values, 0.999),
            max(values),
        )

    def as_dict(self) -> dict[str, float | int]:
        return {
            "n": self.n, "p50_s": self.p50, "p90_s": self.p90, "p99_s": self.p99,
            "p999_s": self.p999, "max_s": self.max,
        }  # fmt: skip


@dataclass(frozen=True)
class Derived:
    source: str
    documents: Spread | None
    readings: Spread | None
    margin: timedelta | None
    reason: str  # "derived", or why there is no margin
    basis_s: float | None = None  # the quantile the margin came from

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "documents": None if self.documents is None else self.documents.as_dict(),
            "readings": None if self.readings is None else self.readings.as_dict(),
            "basis_s": self.basis_s,
            "margin_s": None if self.margin is None else int(self.margin.total_seconds()),
            "reason": self.reason,
        }


@dataclass(frozen=True)
class Parameters:
    quantile: float = QUANTILE
    factor: float = FACTOR
    floor: timedelta = FLOOR
    step: timedelta = STEP
    min_n: int = MIN_N
    min_documents: int = MIN_DOCUMENTS

    def __post_init__(self) -> None:
        if not 0 < self.quantile <= 1:
            raise ValueError("the quantile is in (0, 1]")
        if not 1 <= self.factor <= 10:
            raise ValueError("the factor is between 1 and 10")
        if self.step <= timedelta(0) or self.floor <= timedelta(0):
            raise ValueError("the floor and the step are positive")
        if self.min_n < 1 or self.min_documents < 0:
            raise ValueError("min_n is at least 1 and min_documents at least 0")


@dataclass
class Samples:
    """Delays and lags per source, in seconds."""

    documents: dict[str, list[float]] = field(default_factory=dict)
    readings: dict[str, list[float]] = field(default_factory=dict)
    skipped: int = 0

    def add_hits(self, hits: Iterable[Mapping[str, Any]]) -> None:
        for hit in hits:
            got = document_delay(hit) if isinstance(hit, Mapping) else None
            if got is None:
                self.skipped += 1
            else:
                self.documents.setdefault(got[0], []).append(got[1])

    def add_readings(self, rows: Iterable[Mapping[str, Any]]) -> None:
        for row in rows:
            got = reading_lag(row) if isinstance(row, Mapping) else None
            if got is None:
                self.skipped += 1
            else:
                self.readings.setdefault(got[0], []).append(got[1])


def _round_up(seconds: float, step: timedelta) -> timedelta:
    size = step.total_seconds()
    return timedelta(seconds=math.ceil(seconds / size - 1e-9) * size)


def derive(samples: Samples, parameters: Parameters | None = None) -> dict[str, Derived]:
    """Each source's margin from its samples (see the module's docstring)."""
    p = parameters or Parameters()
    out: dict[str, Derived] = {}
    for source in sorted(set(samples.documents) | set(samples.readings)):
        docs = samples.documents.get(source) or []
        reads = samples.readings.get(source) or []
        documents = Spread.of(docs) if docs else None
        readings = Spread.of(reads) if reads else None
        if len(docs) + len(reads) < p.min_n or len(docs) < p.min_documents:
            out[source] = Derived(source, documents, readings, None, "too_few_values")
            continue
        basis = max(quantile(values, p.quantile) for values in (docs, reads) if values)
        margin = max(
            _round_up(basis * p.factor, p.step), _round_up(p.floor.total_seconds(), p.step)
        )
        if margin > CEILING:
            out[source] = Derived(source, documents, readings, None, "over_ceiling", basis)
            continue
        out[source] = Derived(source, documents, readings, margin, "derived", basis)
    return out


def yaml_margins(derived: Mapping[str, Derived]) -> str:
    """The ``freshness.margins`` block for config/argus.yaml (only derived margins)."""
    lines = ["freshness:", "  margins:"]
    kept = [d for d in derived.values() if d.margin is not None]
    for d in sorted(kept, key=lambda d: d.source):
        assert d.margin is not None
        lines.append(f"    {d.source}: {int(d.margin.total_seconds())}s")
    if not kept:
        lines[-1] = "  margins: {}"
    return "\n".join(lines) + "\n"
