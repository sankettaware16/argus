"""What the responder agent may change about the advice (Q-H2, plan §7.7): its order and its
words, never its content. Built off: nothing calls a model while ``ENABLED["responder"]`` is
None (``argus.agent.registry``), and the deterministic advice (:func:`argus.responder.store.
actions_for`) is the whole of Phase 3 until the user has reviewed the owners and the wording.

When it is switched on, :func:`accept` is the only door for its answer (``ranking@1``: a list of
``{"action": <id>, "say": <sentence>}``). The answer is taken only whole and only as follows:

* every ``action`` is one of the options given (the catalogue's ids for this case), at most once;
  an id it was not given, a repeat, another key, a wrong type or an answer of the wrong shape
  refuses the whole answer, and the deterministic order stands;
* options it left out keep their place after the ones it ranked (it cannot drop an action);
* a sentence is words only: letters, spaces, commas, apostrophes and hyphens, ending in a full
  stop at most, and **every word of it is a word of that action's own catalogue wording** (its
  title and text) or one of a short fixed list of function words (:data:`FUNCTION_WORDS`, with
  no negation and no modal). Any other word, a digit, an address, a file name, a link, a command
  or any markup refuses that sentence (the catalogue's own wording stands for that action). So
  the agent can reorder and re-join what the catalogue says, but add neither a step, a
  command nor an identifier.
"""

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
