"""When a log zero is a verified "nothing found": pure rules.

A **reading** is one size-1 search of a source's newest document by ``event.ingested`` (every 5
minutes): when its answer came (``at``), the newest ingest time and that document's own time. Its
**lag** is ``at - event_at``; within the source's margin it shows the source complete up to
``min(ingested, at) - margin``. A log zero over a window searched at ``asked`` is **verified** only
when a confirming reading before the search shows the source complete to the window's end, and the
readings within the margin from an anchor at or before the window's start to that reading are never
more than ``gap`` apart with none late or silent; otherwise "could not tell" with the first reason
found. The candidate bridge over the nightly pause (``edges``) is measured in the shadow and used
only once adopted. A sub-stream that is late inside a flowing source is invisible to these readings.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from argus import site

OK = "ok"  # the search answered with the source's newest document
EMPTY = "empty"  # it answered: no document in the lookback (the source is silent)
REFUSED = "refused"  # the gateway did not send it (switch, health, breaker, budget)
FAILED = "failed"  # sent, but no usable answer (timeout, error, malformed)
OUTCOMES = (OK, EMPTY, REFUSED, FAILED)

GAP = timedelta(minutes=10)

Bridge = Literal["none", "edges"]
BRIDGES: tuple[Bridge, ...] = ("none", "edges")

# Why a zero is "could not tell" (or "complete" when it is verified).
COMPLETE = "complete"
REASONS = (
    COMPLETE,
    "no_margin",  # the source has no recorded margin
    "not_log_search",  # the evidence is not a log search with a window
    "search_incomplete",  # the search failed, timed out, or its answer was partial
    "not_asked",  # the evidence has no send time (collected before readings existed, or not sent)
    "not_past_end",  # no reading before the search showed the source complete past the end
    "no_anchor",  # no reading within the margin at the window's start
    "late",  # a reading across the window showed the source behind by more than the margin
    "silent",  # a reading across the window found no document at all
    "gap",  # readings more than ``gap`` apart across the window
    "quiet_hours",  # the gap is the nightly pause (no bridge adopted)
)


def _aware(moment: datetime, name: str) -> None:
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")


@dataclass(frozen=True)
class Reading:
    source: str
    at: datetime
    outcome: str
    ingested: datetime | None = None
    event_at: datetime | None = None

    def __post_init__(self) -> None:
        if self.outcome not in OUTCOMES:
            raise ValueError(f"unknown reading outcome {self.outcome!r}")
        _aware(self.at, "a reading's time")
        has_doc = self.ingested is not None and self.event_at is not None
        if has_doc != (self.outcome == OK):
            raise ValueError("a reading has a document exactly when its outcome is ok")
        for moment, name in ((self.ingested, "ingested"), (self.event_at, "event_at")):
            if moment is not None:
                _aware(moment, name)

    @property
    def lag(self) -> timedelta | None:
        """How far behind the clock the newest arrived event was (None without a document)."""
        return None if self.event_at is None else self.at - self.event_at

    def within(self, margin: timedelta) -> bool:
        lag = self.lag
        return self.outcome == OK and lag is not None and lag <= margin

    def complete_to(self, margin: timedelta) -> datetime | None:
        """How far this reading shows the source complete (None without a document)."""
        if self.ingested is None:
            return None
        return min(self.ingested, self.at) - margin


@dataclass(frozen=True)
class Check:
    """A verdict on one log zero (or on one window's coverage)."""

    known: bool
    reason: str
    complete_to: datetime | None = None
    bridged: bool = False  # the quiet-hours bridge was needed for it

    def __post_init__(self) -> None:
        if self.reason not in REASONS:
            raise ValueError(f"unknown reason {self.reason!r}")
        if self.known != (self.reason == COMPLETE):
            raise ValueError("a check is known exactly when its reason is complete")
        if self.known != (self.complete_to is not None):
            raise ValueError("a known check says how far the logs are complete")
        if self.bridged and not self.known:
            raise ValueError("only a known check can have needed the bridge")


def could_not_tell(reason: str) -> Check:
    return Check(False, reason)


def quiet_nights(start: datetime, end: datetime) -> list[tuple[datetime, datetime]]:
    """Every nightly pause (the site's quiet hours, default 00:00-01:30 UTC) that overlaps
    (start, end)."""
    quiet = site.quiet_hours()
    if quiet.none:
        return []
    first = start.astimezone(UTC).date() - timedelta(days=1)  # a pause across midnight
    last = end.astimezone(UTC).date()
    out = []
    day = first
    while day <= last:
        begin = datetime.combine(day, quiet.start_time, UTC)
        stop = begin + quiet.length
        if begin < end and stop > start:
            out.append((begin, stop))
        day += timedelta(days=1)
    return out


def _bridges(earlier: datetime, later: datetime, gap: timedelta) -> bool:
    """Whether the gap (earlier, later) is exactly one nightly pause with both ends close."""
    nights = quiet_nights(earlier, later)
    if len(nights) != 1:
        return False
    begin, stop = nights[0]
    return begin - gap <= earlier < begin and stop <= later <= stop + gap


def verify(
    start: datetime,
    end: datetime,
    asked: datetime,
    readings: Iterable[Reading],
    margin: timedelta | None,
    *,
    gap: timedelta = GAP,
    bridge: Bridge = "none",
) -> Check:
    """Whether a zero over [start, end], searched at ``asked``, is verified by ``readings``
    (one source's). The search's own completeness is the caller's part."""
    for moment, name in ((start, "start"), (end, "end"), (asked, "asked")):
        _aware(moment, name)
    if end < start:
        raise ValueError("the window ends before it starts")
    if gap <= timedelta(0):
        raise ValueError("the gap is positive")
    if bridge not in BRIDGES:
        raise ValueError(f"unknown bridge {bridge!r}")
    if margin is None:
        return could_not_tell("no_margin")
    if margin < timedelta(0):
        raise ValueError("a margin is never negative")
    usable = sorted((r for r in readings if r.at <= asked), key=lambda r: r.at)
    confirm = None
    for index, reading in enumerate(usable):
        to = reading.complete_to(margin)
        if reading.within(margin) and to is not None and to >= end:
            confirm = index
            break
    if confirm is None:
        return could_not_tell("not_past_end")
    anchor = None
    for index, reading in enumerate(usable[: confirm + 1]):
        if reading.at > start:
            break
        if reading.within(margin) and reading.at >= start - gap:
            anchor = index
    if anchor is None:
        return could_not_tell("no_anchor")
    bridged = False
    previous = usable[anchor].at
    for reading in usable[anchor + 1 : confirm + 1]:
        if reading.outcome == EMPTY:
            return could_not_tell("silent")
        if reading.outcome == OK and not reading.within(margin):
            return could_not_tell("late")
        if reading.outcome != OK:
            continue  # no reading: only a gap, if the next one comes too late
        if reading.at - previous > gap:
            if bridge == "edges" and _bridges(previous, reading.at, gap):
                bridged = True
            elif quiet_nights(previous, reading.at):
                return could_not_tell("quiet_hours")
            else:
                return could_not_tell("gap")
        previous = reading.at
    to = usable[confirm].complete_to(margin)
    assert to is not None
    return Check(True, COMPLETE, to, bridged)


def advance(current: Reading | None, new: Reading) -> Reading | None:
    """The source's watermark after ``new``: the reading with the newest ingest time. A
    watermark only advances: an older ingest time, or no document, leaves it as it was."""
    if new.outcome != OK or new.ingested is None:
        return current
    if current is None or current.ingested is None or new.ingested > current.ingested:
        return new
    return current


@dataclass(frozen=True)
class Windows:
    """How many whole windows of ``span`` a source's readings cover (strict and bridged)."""

    judged: int
    strict: int
    bridged: int

    def share(self, bridged: bool) -> float | None:
        if not self.judged:
            return None
        return (self.bridged if bridged else self.strict) / self.judged


def windows(
    readings: Sequence[Reading],
    margin: timedelta | None,
    *,
    span: timedelta = timedelta(hours=72),
    step: timedelta = timedelta(hours=1),
    gap: timedelta = GAP,
) -> Windows:
    """The share of ``span`` windows (starting on each whole ``step``) whose coverage the
    readings prove, with no bridge and with the ``edges`` bridge. Only windows the readings
    can already judge count: those that end at least ``margin + gap`` before the last
    reading."""
    if margin is None or not readings:
        return Windows(0, 0, 0)
    ordered = sorted(readings, key=lambda r: r.at)
    first, last = ordered[0].at, ordered[-1].at
    epoch = datetime(2000, 1, 1, tzinfo=UTC)
    begin = epoch + ((first - epoch) // step + 1) * step
    judged = strict = bridged = 0
    while begin + span + margin + gap <= last:
        end = begin + span
        if verify(begin, end, last, ordered, margin, gap=gap).known:
            strict += 1
        if verify(begin, end, last, ordered, margin, gap=gap, bridge="edges").known:
            bridged += 1
        judged += 1
        begin += step
    return Windows(judged, strict, bridged)


def lags(
    newest: Mapping[str, Reading],
    last_ok: Mapping[str, Reading],
    now: datetime,
    *,
    within: timedelta = timedelta(minutes=30),
) -> dict[str, timedelta]:
    """Each source's ingest lag (the health trip wire's input): how late its newest
    document arrived, ``ingested - event_at`` of the newest reading with a document. A silent
    source (an empty reading) has no lag: silence is not lateness. A refused or
    failed newest reading keeps the last known lag while that last document is within
    ``within``, so a stopped or failing lane neither sets nor releases DEGRADED by itself."""
    out = {}
    for source, reading in sorted(newest.items()):
        if now - reading.at > within:
            continue
        if reading.outcome == OK:
            known = reading
        elif reading.outcome in (REFUSED, FAILED) and source in last_ok:
            known = last_ok[source]
            if now - known.at > within:
                continue
        else:
            continue
        assert known.ingested is not None
        assert known.event_at is not None
        out[source] = max(known.ingested - known.event_at, timedelta(0))
    return out
