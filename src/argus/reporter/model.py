"""The Reporter's contract: the figures of a report, each with the words that say how it was
counted (Q-H3). Stored as the ``numbers`` of a ``reports`` row and served by ``/api/v1``."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

SCHEMA: Literal["report-numbers@1"] = "report-numbers@1"
Kind = Literal["daily", "weekly"]
KINDS: tuple[Kind, ...] = ("daily", "weekly")
# count: a number of things; percent: 0 to 100; ms and seconds: durations; hours: an age;
# text: words or a hash (never read as a number by the prose check)
Unit = Literal["count", "percent", "ms", "seconds", "hours", "text"]
Value = int | float | str | None
# how a unit is written in text, as ``argus.reporter.figures`` names it (None: a plain count)
FIGURE_UNIT: dict[str, str | None] = {
    "count": None,
    "percent": "percent",
    "ms": "ms",
    "seconds": "second",
    "hours": "hour",
    "text": None,
}


class Metric(BaseModel):
    """One figure: ``key`` is stable (a test and the page depend on it), ``label`` is plain
    words, ``value`` is None when there is nothing to say (the definition says when), and
    ``definition`` says what is counted, over what time and from which table."""

    model_config = ConfigDict(frozen=True)

    key: str = Field(pattern=r"^[a-z][a-z0-9_]*(?:\.\S+)*$", max_length=200)
    label: str = Field(min_length=1, max_length=300)
    value: Value
    unit: Unit
    definition: str = Field(min_length=1, max_length=800)


class Section(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str = Field(pattern=r"^[a-z][a-z_]*$")
    title: str
    metrics: tuple[Metric, ...]
    notes: tuple[str, ...] = ()


class Numbers(BaseModel):
    """Everything a report says in numbers. ``as_at`` is when the report was made: figures of
    what is waiting (cases, approvals, backlog) are as at that moment; figures of what happened
    are for ``[period_start, period_end)``."""

    model_config = ConfigDict(frozen=True)

    schema_version: Literal["report-numbers@1"] = SCHEMA
    kind: Kind
    period_start: AwareDatetime
    period_end: AwareDatetime
    as_at: AwareDatetime
    sections: tuple[Section, ...]

    def metrics(self) -> dict[str, Metric]:
        return {m.key: m for s in self.sections for m in s.metrics}


@dataclass(frozen=True)
class Window:
    """The time a report covers (UTC days, ``end`` exclusive) and the moment it was made."""

    kind: Kind
    start: datetime
    end: datetime
    as_at: datetime

    @property
    def days(self) -> int:
        return (self.end - self.start).days


def window_for(kind: Kind, last_day: date, as_at: datetime) -> Window:
    """The report that ends with ``last_day`` (a UTC date, included): that day alone (daily) or
    it and the six before it (weekly)."""
    end = datetime(last_day.year, last_day.month, last_day.day, tzinfo=UTC) + timedelta(days=1)
    return Window(kind, end - timedelta(days=1 if kind == "daily" else 7), end, as_at)
