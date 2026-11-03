"""What the responder agent may change about the advice: its order and its words, never its
content. Built off (``ENABLED["responder"]`` is None), so the deterministic advice stands. When
on, :func:`accept` is the only door for its answer (``ranking@1``): taken whole or not at all,
every action one that was given (once), omitted options keep their place after the ranked ones,
and a sentence may use only words of that action's catalogue wording plus a short fixed list
(:data:`FUNCTION_WORDS`): no digit, address, file name, link, command or markup."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from argus.responder.catalogue import Catalogue

SAY = re.compile(r"[A-Za-z][A-Za-z ,'-]{0,198}[.]?")
MAX_ITEMS = 12
WORD = re.compile(r"[a-z]+")
# Joining words only: no negation ("not", "never", "no"), no modal ("must", "can", "do").
FUNCTION_WORDS = frozenset({
    "a", "an", "the", "and", "or", "to", "of", "in", "on", "at", "for", "with", "from", "by",
    "it", "its", "is", "are", "be", "that", "this", "so", "as", "then", "each", "any", "all",
    "other", "also", "first", "them", "their", "if", "when", "than",
})  # fmt: skip


@dataclass(frozen=True)
class Ranked:
    order: tuple[str, ...]  # every option, the agent's order first
    say: Mapping[str, str]  # the agent's sentence for the actions it phrased acceptably


def _words(text: str) -> frozenset[str]:
    return frozenset(WORD.findall(text.lower()))


def wording(catalogue: Catalogue, options: Sequence[str]) -> dict[str, str]:
    """The words each of ``options`` (catalogue ids) may be phrased with: its title and text."""
    found = (catalogue.action(o) for o in options)
    return {a.id: f"{a.title} {a.say}" for a in found if a is not None}


def phrase(text: Any, allowed: str = "") -> str | None:
    """``text`` if it is a plain sentence made of words of ``allowed`` (the action's catalogue
    wording) and :data:`FUNCTION_WORDS` (see the module docstring), else None."""
    if not isinstance(text, str):
        return None
    said = " ".join(text.split())
    if not SAY.fullmatch(said) or "  " in said:
        return None
    return said if _words(said) <= _words(allowed) | FUNCTION_WORDS else None


def accept(
    options: Sequence[str], answer: Any, words: Mapping[str, str] | None = None
) -> Ranked | None:
    """The agent's ranking of ``options`` (the catalogue ids it was given), or None when the
    answer is not acceptable and the deterministic order stands. ``words``: each option's
    catalogue wording (:func:`wording`); a sentence for an option with none uses function words
    only, which is to say it is refused."""
    if not isinstance(answer, Mapping) or set(answer) != {"ranking"}:
        return None
    items = answer["ranking"]
    if not isinstance(items, list) or len(items) > MAX_ITEMS:
        return None
    given = set(options)
    order: list[str] = []
    says: dict[str, str] = {}
    for item in items:
        if not isinstance(item, Mapping) or set(item) != {"action", "say"}:
            return None
        action = item["action"]
        if not isinstance(action, str) or action not in given or action in order:
            return None
        order.append(action)
        sentence = phrase(item["say"], (words or {}).get(action, ""))
        if sentence is not None:
            says[action] = sentence
    order += [o for o in options if o not in order]
    return Ranked(tuple(order), says)
