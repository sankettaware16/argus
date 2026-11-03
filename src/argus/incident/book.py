"""The facts of a report and the check that holds a sentence to them (AR7, D-190).

Every sentence of the report's narrative is **a fact's own sentence** (registered here with the
figures it states, then said) or a short connective sentence that cites facts and adds no number.
:class:`Book` numbers the facts in the order they are first said; :func:`uncovered` is the check
a test (and the model's guardian, in a stricter form) applies: the numbers a sentence writes that
none of the facts it cites writes.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from argus.incident import model as m
from argus.incident.model import digits_of


def cut(text: str, limit: int) -> str:
    """``text`` on one line, at most ``limit`` characters."""
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def uncovered(sentence: m.ReportSentence, facts: Mapping[str, m.ReportFact]) -> set[str]:
    """The numbers ``sentence`` writes that none of the facts it cites writes."""
    held: set[str] = set()
    for ident in sentence.cites:
        fact = facts.get(ident)
        if fact is not None:
            held |= digits_of(fact.text)
    return digits_of(sentence.text) - held


class Book:
    """The facts of a report, each registered once, numbered in the order they are first said."""

    def __init__(self) -> None:
        self.facts: list[m.ReportFact] = []
        self._ids: dict[str, str] = {}

    def add(
        self,
        kind: m.FactKind,
        text: str,
        source: str,
        numbers: Iterable[float] = (),
        *,
        from_logs: bool = False,
        safe: str | None = None,
    ) -> str:
        """Register a fact (or find the one already said the same) and return its id."""
        body = cut(text, m.TEXT)
        key = f"{kind}|{body}|{source}"
        if key in self._ids:
            return self._ids[key]
        ident = f"F{len(self.facts) + 1}"
        self.facts.append(
            m.ReportFact(
                id=ident,
                kind=kind,
                text=body,
                source=cut(source, 200),
                numbers=tuple(float(n) for n in numbers),
                from_logs=from_logs,
                safe=None if safe is None else cut(safe, m.TEXT),
            )
        )
        self._ids[key] = ident
        return ident

    def text_of(self, ident: str) -> str:
        return self.facts[int(ident[1:]) - 1].text

    def say(
        self,
        kind: m.FactKind,
        text: str,
        source: str,
        numbers: Iterable[float] = (),
        *,
        from_logs: bool = False,
        safe: str | None = None,
    ) -> m.ReportSentence:
        """A fact and the sentence that says it."""
        ident = self.add(kind, text, source, numbers, from_logs=from_logs, safe=safe)
        return m.ReportSentence(text=self.text_of(ident), cites=(ident,))

    def repeat(self, ident: str) -> m.ReportSentence:
        """The sentence of a fact already registered."""
        return m.ReportSentence(text=self.text_of(ident), cites=(ident,))

    def because(self, text: str, *cites: str) -> m.ReportSentence:
        """A connective sentence over facts already registered; it states no number of its own."""
        return m.ReportSentence(text=cut(text, m.TEXT), cites=tuple(dict.fromkeys(cites)))
