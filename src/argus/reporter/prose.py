"""The optional prose of a report. Built off: nothing calls a model while ``ENABLED["reporter"]``
is None, and the deterministic text (:mod:`argus.reporter.render`) is the whole of every report.

When switched on, :func:`accept` is the only door for the answer (one JSON object
``{"paragraph": <text>}``): taken whole or not at all, plain text of at most :data:`MAX_CHARS`
characters in which **every number is one it was given** (:mod:`argus.reporter.figures`). The model
sees figures with labels and units, never a host, an address, a hash or a name."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from argus.agent import registry
from argus.reporter import figures
from argus.reporter.model import FIGURE_UNIT, Metric, Numbers
from argus.responder.machine import ist12

AGENT = "reporter"
MAX_CHARS = 1500
_MARKUP = re.compile(r"[<>\[\]{}`*#|\\_~^=@]|https?:|www\.|://")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


@dataclass(frozen=True)
class Fact:
    label: str
    value: int | float
    unit: str | None  # as figures names it (None: a count)


def enabled() -> bool:
    return registry.ENABLED.get(AGENT) is not None


def shown_to_the_model(metric: Metric) -> bool:
    """A figure the model may be given: a number, never a name, an address or a hash."""
    return (
        metric.unit != "text"
        and isinstance(metric.value, int | float)
        and not isinstance(metric.value, bool)
        and not metric.key.startswith("active_hosts.host.")
    )


def facts(numbers: Numbers) -> list[Fact]:
    return [
        Fact(m.label, m.value, FIGURE_UNIT[m.unit])
        for m in numbers.metrics().values()
        if shown_to_the_model(m) and isinstance(m.value, int | float)
    ]


def period_words(numbers: Numbers) -> str:
    return f"{ist12(numbers.period_start)} to {ist12(numbers.period_end)}"


def allowed(numbers: Numbers) -> figures.Allowed:
    """The numbers the model is given: the facts (value, unit and the numbers in their labels)
    and the period as it is worded to it."""
    found = figures.Allowed()
    for fact in facts(numbers):
        found.add_value(fact.value, fact.unit)
        found.add_text(fact.label)
    found.add_text(period_words(numbers))
    found.add_value(7 if numbers.kind == "weekly" else 1, "day")
    return found


def prompt(numbers: Numbers) -> str:
    """What the model is given after its instructions: the period and the facts, as JSON."""
    body = {
        "report": numbers.kind,
        "period": period_words(numbers),
        "facts": [
            {"label": f.label, "value": f.value, "unit": f.unit or "count"} for f in facts(numbers)
        ],
    }
    return json.dumps(body, ensure_ascii=True, separators=(",", ":"))


def accept(numbers: Numbers, answer: Any) -> str | None:
    """The paragraph if the answer is whole, plain and holds no number outside the input; else
    None (the deterministic text stands)."""
    try:
        body = json.loads(answer) if isinstance(answer, str) else answer
    except ValueError:
        return None
    if not isinstance(body, dict) or set(body) != {"paragraph"}:
        return None
    paragraph = body["paragraph"]
    if not isinstance(paragraph, str):
        return None
    paragraph = paragraph.strip()
    if not 1 <= len(paragraph) <= MAX_CHARS or _MARKUP.search(paragraph):
        return None
    # line by line: a newline is the only control character a paragraph may hold, and it waives
    # nothing for the characters around it (bidi overrides, zero-width and tag characters, ...)
    if _CONTROL.search(paragraph) or not all(line.isprintable() for line in paragraph.split("\n")):
        return None
    if figures.unknown(paragraph, allowed(numbers)):
        return None
    return paragraph
