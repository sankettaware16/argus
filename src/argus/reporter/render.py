"""The Reporter's deterministic text, written from the figures only. Every figure is shown
exactly: counts as they are, percentages to the one decimal they have, durations in whole units
(``1 h 5 min 3 s``), ages in whole hours. Nothing is rounded here and no word is chosen by a
model. Times are in the site's zone, 12-hour; the period is a UTC day, said so."""

from __future__ import annotations

from datetime import timedelta

from argus.reporter.model import Metric, Numbers, Section
from argus.responder.machine import ist12

UNAVAILABLE = "n/a"


def duration(seconds: int) -> str:
    """``3903`` as ``1 h 5 min 3 s``: exact, zero parts left out (``0 s`` for none)."""
    hours, rest = divmod(max(seconds, 0), 3600)
    minutes, secs = divmod(rest, 60)
    parts = [f"{n} {u}" for n, u in ((hours, "h"), (minutes, "min"), (secs, "s")) if n]
    return " ".join(parts) or "0 s"


def duration_ms(ms: int) -> str:
    """``3903250`` as ``1 h 5 min 3 s 250 ms``: exact, zero parts left out."""
    seconds, rest = divmod(max(ms, 0), 1000)
    parts = [duration(seconds)] if seconds else []
    if rest or not parts:
        parts.append(f"{rest} ms")
    return " ".join(parts)


def shown(m: Metric) -> str:
    """The figure as the text says it."""
    value = m.value
    if value is None:
        return UNAVAILABLE
    if m.unit == "percent":
        return f"{value}%"
    if m.unit == "ms" and isinstance(value, int):
        return duration_ms(value)
    if m.unit == "seconds" and isinstance(value, int):
        return duration(value)
    if m.unit == "hours" and isinstance(value, int):
        return f"{value} hour" + ("" if value == 1 else "s")
    return str(value)


def heading(numbers: Numbers) -> list[str]:
    first = numbers.period_start
    last = numbers.period_end - timedelta(days=1)
    if numbers.kind == "daily":
        title = f"ARGUS daily report for the UTC day {first:%d %b %Y}"
    else:
        title = f"ARGUS weekly report for the UTC days {first:%d %b %Y} to {last:%d %b %Y}"
    return [
        title,
        f"Covers {ist12(numbers.period_start)} to {ist12(numbers.period_end)}.",
        f"Made {ist12(numbers.as_at)}. Figures of what is waiting (cases, actions, approvals, "
        f"the Kibana backlog) are as at {ist12(numbers.as_at)}; figures of what happened are for "
        "the period.",
    ]


def section_lines(section: Section) -> list[str]:
    lines = [f"== {section.title} =="]
    for m in section.metrics:
        lines.append(f"- {m.label}: {shown(m)}")
    lines += [f"Note: {note}" for note in section.notes]
    return lines


def text_of(numbers: Numbers) -> str:
    """The whole report as plain text, definitions last."""
    lines = heading(numbers)
    for section in numbers.sections:
        lines += ["", *section_lines(section)]
    lines += ["", "== How each figure is counted =="]
    for section in numbers.sections:
        for m in section.metrics:
            lines.append(f"{m.key}: {m.definition}")
    return "\n".join(lines) + "\n"
