"""The shapes of the agents' answers (json_schema, strict) for providers that take one (Q-G1,
D-112), by the output code binds each agent to (``argus.agent.registry``): ``answer@1`` for a
coordinator, whose ``consult`` names the specialists its file names, and ``notes@1`` for a
specialist. They change no prompt, so cloud bodies and cassettes are unchanged."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from argus.llm.prompts import OUTCOMES, strict_object, strings

if TYPE_CHECKING:
    from argus.agent.loader import Definition

_ASK = {"type": "array", "maxItems": 6,
        "items": strict_object(tool={"type": "string"}, entity={"type": "string"})}  # fmt: skip


def answer(specialists: Sequence[str]) -> dict[str, Any]:
    """A coordinator's answer (``answer@1``); it may consult only ``specialists``."""
    consult: dict[str, Any] = {"type": "array", "maxItems": 3,
                               "items": {"type": "string", "enum": list(specialists)}}  # fmt: skip
    if not specialists:  # an empty enum is no schema: nobody to consult
        consult = {"type": "array", "maxItems": 0, "items": {"type": "string"}}
    return strict_object(
        outcome={"type": "string", "enum": list(OUTCOMES)},
        confidence={"type": "number"},
        reason={"type": "string"},
        hypotheses={"type": "array", "maxItems": 4,
                    "items": strict_object(name={"type": "string"},
                                           **{"for": strings(4), "against": strings(4)})},
        cites=strings(12),
        consult=consult,
        ask=_ASK,
    )  # fmt: skip


NOTES = strict_object(notes={"type": "string"}, cites=strings(12), ask=_ASK)  # notes@1

# ranking@1 (Q-H2): the catalogue's actions in the responder's order, each phrased in a sentence
RANKING = strict_object(
    ranking={
        "type": "array",
        "maxItems": 12,
        "items": strict_object(action={"type": "string"}, say={"type": "string"}),
    }
)

# prose@1 (Q-H3): one paragraph that says a report's figures; argus.reporter.prose checks it
PROSE = strict_object(paragraph={"type": "string", "maxLength": 1500})

# every output a binding may name has its shape here
SHAPES = ("answer@1", "notes@1", "ranking@1", "prose@1")


def of(definition: Definition) -> dict[str, Any]:
    """The shape of ``definition``'s answers, by its bound output."""
    if definition.output == "answer@1":
        return answer(definition.specialists)
    if definition.output == "notes@1":
        return dict(NOTES)
    if definition.output == "ranking@1":
        return dict(RANKING)
    if definition.output == "prose@1":
        return dict(PROSE)
    raise ValueError(f"{definition.name}: no answer shape for the output {definition.output!r}")


# agent@1's, as Q-G1 first sent them: coordinator@3 (web, proxy, intel) and specialist@1
COORDINATOR_SCHEMA = answer(("web", "proxy", "intel"))
SPECIALIST_SCHEMA = NOTES
